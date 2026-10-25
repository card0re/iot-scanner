import json
import logging
import random
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_proxies: list[dict] = []
_strategy: str = "round-robin"
_rr_index: int = 0

_SAVE_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "proxy_pool.json"

MAX_FAIL_BEFORE_AUTO_PURGE = 5
LATENCY_WEIGHT = 0.3


def _save():
    try:
        _SAVE_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "strategy": _strategy,
            "proxies": [
                {
                    "url": p["url"],
                    "alive": p["alive"],
                    "fail_count": p["fail_count"],
                    "country": p.get("country"),
                    "latency_ms": p.get("latency_ms"),
                    "last_checked": p.get("last_checked"),
                    "success_count": p.get("success_count", 0),
                    "tags": p.get("tags", []),
                }
                for p in _proxies
            ],
        }
        _SAVE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning("Failed to save proxy pool: %s", e)


def load():
    global _strategy
    if not _SAVE_PATH.exists():
        return
    try:
        data = json.loads(_SAVE_PATH.read_text(encoding="utf-8"))
        _strategy = data.get("strategy", "round-robin")
        with _lock:
            seen = _host_port_set()
            for entry in data.get("proxies", []):
                parsed = _parse(entry["url"])
                if not parsed:
                    continue
                hp = f"{parsed['host']}:{parsed['port']}"
                if hp in seen:
                    continue
                seen.add(hp)
                parsed["alive"] = entry.get("alive")
                parsed["fail_count"] = entry.get("fail_count", 0)
                parsed["country"] = entry.get("country")
                parsed["latency_ms"] = entry.get("latency_ms")
                parsed["last_checked"] = entry.get("last_checked")
                parsed["success_count"] = entry.get("success_count", 0)
                parsed["tags"] = entry.get("tags", [])
                _proxies.append(parsed)
        logger.info("Loaded %d proxies from %s", len(_proxies), _SAVE_PATH)
    except Exception as e:
        logger.warning("Failed to load proxy pool: %s", e)


def _host_port_set() -> set[str]:
    return {f"{p['host']}:{p['port']}" for p in _proxies}


def _parse(url: str, country: str | None = None) -> dict | None:
    url = url.strip()
    if not url:
        return None
    if "://" not in url:
        url = "socks5://" + url
    p = urlparse(url)
    if not p.hostname or not p.port:
        return None
    return {
        "url": url,
        "scheme": (p.scheme or "socks5").lower(),
        "host": p.hostname,
        "port": p.port,
        "user": p.username,
        "pwd": p.password,
        "alive": None,
        "fail_count": 0,
        "country": country,
        "latency_ms": None,
        "last_checked": None,
        "success_count": 0,
        "tags": [],
    }


def add_proxies(lines: list[str], country: str | None = None, tags: list[str] | None = None) -> int:
    added = 0
    with _lock:
        seen = _host_port_set()
        for line in lines:
            parsed = _parse(line, country=country)
            if not parsed:
                continue
            hp = f"{parsed['host']}:{parsed['port']}"
            if hp in seen:
                continue
            seen.add(hp)
            if tags:
                parsed["tags"] = tags
            _proxies.append(parsed)
            added += 1
        if added:
            _save()
    return added


def remove_proxy(url: str) -> bool:
    with _lock:
        before = len(_proxies)
        _proxies[:] = [p for p in _proxies if p["url"] != url]
        changed = len(_proxies) < before
        if changed:
            _save()
        return changed


def purge_dead(max_fails: int = MAX_FAIL_BEFORE_AUTO_PURGE) -> int:
    with _lock:
        before = len(_proxies)
        _proxies[:] = [p for p in _proxies if p["fail_count"] < max_fails]
        removed = before - len(_proxies)
        if removed:
            _save()
        return removed


def clear_all():
    with _lock:
        _proxies.clear()
        _save()


def get_all() -> list[dict]:
    with _lock:
        return [p.copy() for p in _proxies]


def get_strategy() -> str:
    return _strategy


def set_strategy(s: str):
    global _strategy
    if s in ("round-robin", "random", "fastest"):
        _strategy = s
        with _lock:
            _save()


def get_count(country: str | None = None, alive_only: bool = False) -> int:
    with _lock:
        pool = _proxies
        if country:
            pool = [p for p in pool if p.get("country") == country]
        if alive_only:
            pool = [p for p in pool if p.get("alive") is True]
        return len(pool)


def _filter_pool(
    country: str | None = None,
    scheme: str | None = None,
    alive_only: bool = True,
) -> list[dict]:
    pool = _proxies
    if alive_only:
        pool = [p for p in pool if p.get("alive") is not False and p["fail_count"] < MAX_FAIL_BEFORE_AUTO_PURGE]
    if country:
        country_pool = [p for p in pool if p.get("country") == country]
        if country_pool:
            pool = country_pool
    if scheme:
        scheme_pool = [p for p in pool if p["scheme"] == scheme]
        if scheme_pool:
            pool = scheme_pool
    return pool


def next_proxy(
    country: str | None = None,
    scheme: str | None = None,
    alive_only: bool = True,
) -> dict | None:
    global _rr_index
    with _lock:
        pool = _filter_pool(country, scheme, alive_only)
        if not pool:
            pool = _filter_pool(country=None, scheme=scheme, alive_only=False)
        if not pool:
            return None

        if _strategy == "random":
            return random.choice(pool).copy()
        elif _strategy == "fastest":
            with_latency = [p for p in pool if p.get("latency_ms") is not None]
            if with_latency:
                with_latency.sort(key=lambda p: p["latency_ms"])
                top = with_latency[:max(3, len(with_latency) // 3)]
                return random.choice(top).copy()
            return random.choice(pool).copy()
        else:
            idx = _rr_index % len(pool)
            _rr_index = idx + 1
            return pool[idx].copy()


def get_proxy_for_target(target_country: str | None = None, protocol: str = "socks5") -> dict | None:
    """Get the best proxy for reaching a target. For SSH/Telnet use socks5, for HTTP use http/socks5."""
    scheme = None
    if protocol in ("ssh", "telnet"):
        scheme = "socks5"
    elif protocol == "http":
        pass
    return next_proxy(country=target_country, scheme=scheme)


def mark_proxy(url: str, alive: bool, latency_ms: float | None = None):
    with _lock:
        for p in _proxies:
            if p["url"] == url:
                p["alive"] = alive
                p["last_checked"] = time.time()
                if alive:
                    p["fail_count"] = 0
                    p["success_count"] = p.get("success_count", 0) + 1
                    if latency_ms is not None:
                        old = p.get("latency_ms")
                        if old is not None:
                            p["latency_ms"] = old * (1 - LATENCY_WEIGHT) + latency_ms * LATENCY_WEIGHT
                        else:
                            p["latency_ms"] = latency_ms
                else:
                    p["fail_count"] += 1
                break
        _save()


def get_stats() -> dict:
    with _lock:
        total = len(_proxies)
        alive = sum(1 for p in _proxies if p.get("alive") is True)
        dead = sum(1 for p in _proxies if p.get("alive") is False)
        unchecked = sum(1 for p in _proxies if p.get("alive") is None)
        by_country: dict[str, int] = {}
        by_scheme: dict[str, int] = {}
        for p in _proxies:
            c = p.get("country") or "unknown"
            by_country[c] = by_country.get(c, 0) + 1
            by_scheme[p["scheme"]] = by_scheme.get(p["scheme"], 0) + 1
        latencies = [p["latency_ms"] for p in _proxies if p.get("latency_ms") is not None]
        avg_latency = sum(latencies) / len(latencies) if latencies else None
        return {
            "total": total,
            "alive": alive,
            "dead": dead,
            "unchecked": unchecked,
            "by_country": by_country,
            "by_scheme": by_scheme,
            "avg_latency_ms": round(avg_latency, 1) if avg_latency else None,
            "strategy": _strategy,
        }
