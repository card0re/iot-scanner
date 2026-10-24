import random
import threading
from urllib.parse import urlparse

_lock = threading.Lock()
_proxies: list[dict] = []
_strategy: str = "round-robin"
_rr_index: int = 0


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
    return added


def remove_proxy(url: str) -> bool:
    with _lock:
        before = len(_proxies)
        _proxies[:] = [p for p in _proxies if p["url"] != url]
        return len(_proxies) < before


def clear_all():
    with _lock:
        _proxies.clear()


def get_all() -> list[dict]:
    with _lock:
        return [p.copy() for p in _proxies]


def get_strategy() -> str:
    return _strategy


def set_strategy(s: str):
    global _strategy
    if s in ("round-robin", "random"):
        _strategy = s


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
