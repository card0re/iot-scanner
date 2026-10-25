"""
Auto-discover free RU/anonymous proxies from public lists,
verify them, add alive ones to the pool, purge dead ones.
Runs as a background daemon thread on a configurable interval.
"""
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import httpx
import socks

from app.collector import proxy_pool

logger = logging.getLogger(__name__)

SOURCES = [
    {
        "name": "proxyscrape-socks5",
        "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=RU&anonymity=all",
        "scheme": "socks5",
    },
    {
        "name": "proxyscrape-socks4",
        "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=5000&country=RU&anonymity=all",
        "scheme": "socks4",
    },
    {
        "name": "proxyscrape-http",
        "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=RU&anonymity=all",
        "scheme": "http",
    },
    {
        "name": "geonode-ru-socks5",
        "url": "https://proxylist.geonode.com/api/proxy-list?protocols=socks5&country=RU&limit=200&sort_by=lastChecked&sort_type=desc",
        "scheme": "socks5",
        "parser": "geonode",
    },
    {
        "name": "geonode-ru-http",
        "url": "https://proxylist.geonode.com/api/proxy-list?protocols=http%2Chttps&country=RU&limit=200&sort_by=lastChecked&sort_type=desc",
        "scheme": "http",
        "parser": "geonode",
    },
    {
        "name": "freeproxy-socks",
        "url": "https://www.freeproxy.world/?type=socks5&anonymity=&country=RU&speed=&port=&page=1",
        "scheme": "socks5",
        "parser": "freeproxy",
    },
    {
        "name": "spys-ru-socks",
        "url": "https://spys.me/socks.txt",
        "scheme": "socks5",
        "parser": "spys_socks",
    },
    {
        "name": "spys-ru-http",
        "url": "https://spys.me/proxy.txt",
        "scheme": "http",
        "parser": "spys_http",
    },
    {
        "name": "openproxy-socks5",
        "url": "https://openproxy.space/list/socks5",
        "scheme": "socks5",
        "parser": "openproxy",
    },
]

VERIFY_TIMEOUT = 4
MAX_FAIL_BEFORE_PURGE = 3

_scraper_thread: threading.Thread | None = None
_scraper_running = False
_scraper_interval = 600
_last_run_info: dict = {}

# Live progress tracking
_progress: dict = {
    "active": False,
    "phase": "",          # "scraping" | "verifying" | "purging" | "done"
    "current_source": "",
    "sources_done": 0,
    "sources_total": len(SOURCES),
    "candidates_found": 0,
    "verify_current": 0,
    "verify_total": 0,
    "verified_alive": 0,
    "verified_failed": 0,
    "purged": 0,
    "pool_size": 0,
    "recent_adds": [],    # last 20 added proxy urls
}
_progress_lock = threading.Lock()


def _set_progress(**kw):
    with _progress_lock:
        _progress.update(kw)


def get_progress() -> dict:
    with _progress_lock:
        return _progress.copy()


def _emit(msg: str, level: str = "info"):
    from app.api.scans import _append_log
    _append_log(msg, level)


def _fetch_source(src: dict) -> list[str]:
    try:
        r = httpx.get(src["url"], timeout=10, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        r.raise_for_status()
        text = r.text
    except Exception as e:
        logger.warning("Failed to fetch %s: %s", src["name"], e)
        return []

    parser = src.get("parser", "plain")
    scheme = src["scheme"]
    proxies = []

    if parser == "plain":
        for line in text.splitlines():
            line = line.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
                proxies.append(f"{scheme}://{line}")

    elif parser == "geonode":
        try:
            data = r.json()
            for item in data.get("data", []):
                ip = item.get("ip")
                port = item.get("port")
                proto = item.get("protocols", [scheme])[0] if item.get("protocols") else scheme
                if ip and port:
                    proxies.append(f"{proto}://{ip}:{port}")
        except Exception:
            pass

    elif parser == "freeproxy":
        rows = re.findall(r"(\d+\.\d+\.\d+\.\d+)</td>\s*<td>(\d+)", text)
        for ip, port in rows:
            proxies.append(f"{scheme}://{ip}:{port}")

    elif parser == "spys_socks":
        for line in text.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+:\d+)\s+RU", line)
            if m:
                proxies.append(f"socks5://{m.group(1)}")

    elif parser == "spys_http":
        for line in text.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+:\d+)\s+RU", line)
            if m:
                proxies.append(f"http://{m.group(1)}")

    elif parser == "openproxy":
        ips = re.findall(r'"(\d+\.\d+\.\d+\.\d+:\d+)"', text)
        for addr in ips:
            proxies.append(f"{scheme}://{addr}")

    return proxies


def _verify_proxy(url: str) -> bool:
    p = urlparse(url)
    scheme = (p.scheme or "").lower()
    try:
        if scheme.startswith("socks"):
            stype = socks.SOCKS5 if "5" in scheme else socks.SOCKS4
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(stype, p.hostname, p.port,
                        username=p.username, password=p.password)
            s.settimeout(VERIFY_TIMEOUT)
            s.connect(("1.1.1.1", 80))
            s.close()
            return True
        else:
            r = httpx.get("http://httpbin.org/ip", timeout=VERIFY_TIMEOUT, proxy=url)
            return r.status_code == 200
    except Exception:
        return False


def _purge_dead():
    all_proxies = proxy_pool.get_all()
    removed = 0
    for p in all_proxies:
        if p["fail_count"] >= MAX_FAIL_BEFORE_PURGE:
            proxy_pool.remove_proxy(p["url"])
            removed += 1
    return removed


VERIFY_WORKERS = 20
SCRAPE_WORKERS = 5


def run_scrape_cycle() -> dict:
    global _last_run_info

    _set_progress(
        active=True, phase="scraping", current_source="(parallel)",
        sources_done=0, sources_total=len(SOURCES),
        candidates_found=0, verify_current=0, verify_total=0,
        verified_alive=0, verified_failed=0, purged=0,
        pool_size=proxy_pool.get_count(), recent_adds=[],
    )

    candidates = set()
    source_stats = {}
    sources_done = 0

    with ThreadPoolExecutor(max_workers=SCRAPE_WORKERS) as pool:
        future_map = {pool.submit(_fetch_source, src): src for src in SOURCES}
        for future in as_completed(future_map):
            src = future_map[future]
            try:
                found = future.result()
            except Exception:
                found = []
            source_stats[src["name"]] = len(found)
            candidates.update(found)
            sources_done += 1
            _set_progress(
                current_source=src["name"],
                sources_done=sources_done,
                candidates_found=len(candidates),
            )

    existing = {p["url"] for p in proxy_pool.get_all()}
    new_candidates = [u for u in candidates if u not in existing]

    _set_progress(phase="verifying", verify_total=len(new_candidates))

    verified = 0
    failed = 0
    done_count = 0
    recent_adds = []
    lock = threading.Lock()

    def _check(url):
        nonlocal verified, failed, done_count, recent_adds
        alive = _verify_proxy(url)
        with lock:
            done_count += 1
            if alive:
                proxy_pool.add_proxies([url])
                proxy_pool.mark_proxy(url, True)
                verified += 1
                recent_adds.append(url)
                if len(recent_adds) > 30:
                    recent_adds.pop(0)
            else:
                failed += 1
            _set_progress(
                verify_current=done_count,
                verified_alive=verified,
                verified_failed=failed,
                pool_size=proxy_pool.get_count(),
                recent_adds=list(recent_adds),
            )

    with ThreadPoolExecutor(max_workers=VERIFY_WORKERS) as pool:
        list(pool.map(_check, new_candidates))

    _set_progress(phase="purging")
    purged = _purge_dead()

    info = {
        "scraped_total": len(candidates),
        "new_candidates": len(new_candidates),
        "verified_alive": verified,
        "verify_failed": failed,
        "purged_dead": purged,
        "pool_size": proxy_pool.get_count(),
        "sources": source_stats,
        "timestamp": time.time(),
    }
    _last_run_info = info
    _set_progress(active=False, phase="done", purged=purged, pool_size=proxy_pool.get_count())
    return info


_once_thread: threading.Thread | None = None


def run_once_async():
    global _once_thread
    if get_progress().get("active"):
        return False
    _once_thread = threading.Thread(target=_run_once_bg, daemon=True, name="proxy-scraper-once")
    _once_thread.start()
    return True


def _run_once_bg():
    try:
        _emit(f"[PROXY] Scraping RU proxies from {len(SOURCES)} sources...")
        info = run_scrape_cycle()
        _emit(
            f"[PROXY] Done: {info['scraped_total']} scraped, "
            f"+{info['verified_alive']} alive, "
            f"-{info['purged_dead']} purged, "
            f"pool: {info['pool_size']}",
            "success" if info["verified_alive"] > 0 else "info"
        )
    except Exception as e:
        logger.exception("Proxy scraper error")
        _emit(f"[PROXY] Scraper error: {e}", "error")
        _set_progress(active=False, phase="error")


def _daemon_loop():
    global _scraper_running
    while _scraper_running:
        try:
            _emit(f"[PROXY] Auto-scraping RU proxies from {len(SOURCES)} sources...")
            info = run_scrape_cycle()
            _emit(
                f"[PROXY] Done: {info['scraped_total']} scraped, "
                f"+{info['verified_alive']} alive, "
                f"-{info['purged_dead']} purged, "
                f"pool: {info['pool_size']}",
                "success" if info["verified_alive"] > 0 else "info"
            )
        except Exception as e:
            logger.exception("Proxy scraper error")
            _emit(f"[PROXY] Scraper error: {e}", "error")

        for _ in range(int(_scraper_interval)):
            if not _scraper_running:
                return
            time.sleep(1)


def start_daemon(interval: int = 600):
    global _scraper_thread, _scraper_running, _scraper_interval
    if _scraper_running:
        return False
    _scraper_interval = max(60, interval)
    _scraper_running = True
    _scraper_thread = threading.Thread(target=_daemon_loop, daemon=True, name="proxy-scraper")
    _scraper_thread.start()
    return True


def stop_daemon():
    global _scraper_running
    _scraper_running = False


def is_running() -> bool:
    return _scraper_running


def get_interval() -> int:
    return _scraper_interval


def set_interval(seconds: int):
    global _scraper_interval
    _scraper_interval = max(60, seconds)


def get_last_info() -> dict:
    return _last_run_info.copy() if _last_run_info else {}
