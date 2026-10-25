import json
import logging
import os
import random
import threading
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_proxies: list[dict] = []
_strategy: str = "round-robin"
_rr_index: int = 0

_SAVE_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "proxy_pool.json"


def _save():
    try:
        _SAVE_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "strategy": _strategy,
            "proxies": [
                {"url": p["url"], "alive": p["alive"], "fail_count": p["fail_count"]}
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
        for entry in data.get("proxies", []):
            parsed = _parse(entry["url"])
            if parsed:
                parsed["alive"] = entry.get("alive")
                parsed["fail_count"] = entry.get("fail_count", 0)
                with _lock:
                    existing = {p["url"] for p in _proxies}
                    if parsed["url"] not in existing:
                        _proxies.append(parsed)
        logger.info("Loaded %d proxies from %s", len(_proxies), _SAVE_PATH)
    except Exception as e:
        logger.warning("Failed to load proxy pool: %s", e)


def _parse(url: str) -> dict | None:
    url = url.strip()
    if not url:
        return None
    if "://" not in url:
        url = "socks5://" + url
    p = urlparse(url)
    return {
        "url": url,
        "scheme": (p.scheme or "socks5").lower(),
        "host": p.hostname,
        "port": p.port,
        "user": p.username,
        "pwd": p.password,
        "alive": None,
        "fail_count": 0,
    }


def add_proxies(lines: list[str]) -> int:
    added = 0
    with _lock:
        existing = {p["url"] for p in _proxies}
        for line in lines:
            parsed = _parse(line)
            if parsed and parsed["url"] not in existing:
                _proxies.append(parsed)
                existing.add(parsed["url"])
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
    if s in ("round-robin", "random"):
        _strategy = s
        with _lock:
            _save()


def get_count() -> int:
    with _lock:
        return len(_proxies)


def next_proxy() -> dict | None:
    global _rr_index
    with _lock:
        if not _proxies:
            return None
        if _strategy == "random":
            return random.choice(_proxies).copy()
        else:
            idx = _rr_index % len(_proxies)
            _rr_index = idx + 1
            return _proxies[idx].copy()


def mark_proxy(url: str, alive: bool):
    with _lock:
        for p in _proxies:
            if p["url"] == url:
                p["alive"] = alive
                if not alive:
                    p["fail_count"] += 1
                else:
                    p["fail_count"] = 0
                break
        _save()
