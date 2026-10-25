"""
Auto-discover free SOCKS/HTTP proxies from public lists for RU and IR,
verify them with latency measurement, add alive ones to the pool, purge dead ones.
Supports residential proxy discovery and periodic re-verification.
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
    # ---- RU SOCKS5 ----
    {
        "name": "proxyscrape-socks5-ru",
        "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=RU&anonymity=all",
        "scheme": "socks5",
        "country": "RU",
    },
    {
        "name": "proxyscrape-socks4-ru",
        "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=5000&country=RU&anonymity=all",
        "scheme": "socks4",
        "country": "RU",
    },
    {
        "name": "proxyscrape-http-ru",
        "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=RU&anonymity=all",
        "scheme": "http",
        "country": "RU",
    },
    # ---- IR SOCKS5 ----
    {
        "name": "proxyscrape-socks5-ir",
        "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=IR&anonymity=all",
        "scheme": "socks5",
        "country": "IR",
    },
    {
        "name": "proxyscrape-socks4-ir",
        "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=5000&country=IR&anonymity=all",
        "scheme": "socks4",
        "country": "IR",
    },
    {
        "name": "proxyscrape-http-ir",
        "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=IR&anonymity=all",
        "scheme": "http",
        "country": "IR",
    },
    # ---- Geonode RU ----
    {
        "name": "geonode-ru-socks5",
        "url": "https://proxylist.geonode.com/api/proxy-list?protocols=socks5&country=RU&limit=500&sort_by=lastChecked&sort_type=desc",
        "scheme": "socks5",
        "country": "RU",
        "parser": "geonode",
    },
    {
        "name": "geonode-ru-http",
        "url": "https://proxylist.geonode.com/api/proxy-list?protocols=http%2Chttps&country=RU&limit=500&sort_by=lastChecked&sort_type=desc",
        "scheme": "http",
        "country": "RU",
        "parser": "geonode",
    },
    # ---- Geonode IR ----
    {
        "name": "geonode-ir-socks5",
        "url": "https://proxylist.geonode.com/api/proxy-list?protocols=socks5&country=IR&limit=500&sort_by=lastChecked&sort_type=desc",
        "scheme": "socks5",
        "country": "IR",
        "parser": "geonode",
    },
    {
        "name": "geonode-ir-http",
        "url": "https://proxylist.geonode.com/api/proxy-list?protocols=http%2Chttps&country=IR&limit=500&sort_by=lastChecked&sort_type=desc",
        "scheme": "http",
        "country": "IR",
        "parser": "geonode",
    },
    # ---- Spys (RU) ----
    {
        "name": "spys-ru-socks",
        "url": "https://spys.me/socks.txt",
        "scheme": "socks5",
        "country": "RU",
        "parser": "spys_socks",
        "filter_country": "RU",
    },
    {
        "name": "spys-ir-socks",
        "url": "https://spys.me/socks.txt",
        "scheme": "socks5",
        "country": "IR",
        "parser": "spys_socks",
        "filter_country": "IR",
    },
    {
        "name": "spys-ru-http",
        "url": "https://spys.me/proxy.txt",
        "scheme": "http",
        "country": "RU",
        "parser": "spys_http",
        "filter_country": "RU",
    },
    {
        "name": "spys-ir-http",
        "url": "https://spys.me/proxy.txt",
        "scheme": "http",
        "country": "IR",
        "parser": "spys_http",
        "filter_country": "IR",
    },
    # ---- FreeProxy ----
    {
        "name": "freeproxy-socks-ru",
        "url": "https://www.freeproxy.world/?type=socks5&anonymity=&country=RU&speed=&port=&page=1",
        "scheme": "socks5",
        "country": "RU",
        "parser": "freeproxy",
    },
    {
        "name": "freeproxy-socks-ir",
        "url": "https://www.freeproxy.world/?type=socks5&anonymity=&country=IR&speed=&port=&page=1",
        "scheme": "socks5",
        "country": "IR",
        "parser": "freeproxy",
    },
    # ---- OpenProxy ----
    {
        "name": "openproxy-socks5",
        "url": "https://openproxy.space/list/socks5",
        "scheme": "socks5",
        "parser": "openproxy",
    },
    {
        "name": "openproxy-http",
        "url": "https://openproxy.space/list/http",
        "scheme": "http",
        "parser": "openproxy",
    },
    # ---- ProxyList.download ----
    {
        "name": "proxylist-download-socks5",
        "url": "https://www.proxy-list.download/api/v1/get?type=socks5&anon=elite&country=RU",
        "scheme": "socks5",
        "country": "RU",
    },
    {
        "name": "proxylist-download-http-ru",
        "url": "https://www.proxy-list.download/api/v1/get?type=http&anon=elite&country=RU",
        "scheme": "http",
        "country": "RU",
    },
    {
        "name": "proxylist-download-socks5-ir",
        "url": "https://www.proxy-list.download/api/v1/get?type=socks5&anon=elite&country=IR",
        "scheme": "socks5",
        "country": "IR",
    },
    # ---- GitHub proxy lists (bulk) ----
    {
        "name": "github-theSpeedX-socks5",
        "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "scheme": "socks5",
        "parser": "github_bulk",
    },
    {
        "name": "github-theSpeedX-socks4",
        "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        "scheme": "socks4",
        "parser": "github_bulk",
    },
    {
        "name": "github-theSpeedX-http",
        "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "scheme": "http",
        "parser": "github_bulk",
    },
    {
        "name": "github-monosans-socks5",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "scheme": "socks5",
        "parser": "github_bulk",
    },
    {
        "name": "github-monosans-http",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "scheme": "http",
        "parser": "github_bulk",
    },
    {
        "name": "github-hookzof-socks5",
        "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "scheme": "socks5",
        "parser": "github_bulk",
    },
    # ---- Fate0 (with country info) ----
    {
        "name": "github-fate0",
        "url": "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list",
        "parser": "fate0_jsonl",
    },
]

VERIFY_TIMEOUT = 4
VERIFY_WORKERS = 50
SCRAPE_WORKERS = 8
REVERIFY_WORKERS = 25
REVERIFY_INTERVAL = 300
MAX_VERIFY_PER_CYCLE = 3000

_scraper_thread: threading.Thread | None = None
_scraper_running = False
_scraper_interval = 300
_last_run_info: dict = {}

_progress: dict = {
    "active": False,
    "phase": "",
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
    "recent_adds": [],
    "reverified": 0,
}
_progress_lock = threading.Lock()


def _set_progress(**kw):
    with _progress_lock:
        _progress.update(kw)


def get_progress() -> dict:
    with _progress_lock:
        return _progress.copy()


def _emit(msg: str, level: str = "info"):
    try:
        from app.api.scans import _append_log
        _append_log(msg, level)
    except Exception:
        pass


def _fetch_source(src: dict) -> list[tuple[str, str | None]]:
    """Returns list of (proxy_url, country_code_or_None)."""
    try:
        r = httpx.get(src["url"], timeout=12, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        r.raise_for_status()
        text = r.text
    except Exception as e:
        logger.warning("Failed to fetch %s: %s", src["name"], e)
        return []

    parser = src.get("parser", "plain")
    scheme = src.get("scheme", "socks5")
    country = src.get("country")
    filter_country = src.get("filter_country")
    results: list[tuple[str, str | None]] = []

    if parser == "plain":
        for line in text.splitlines():
            line = line.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
                results.append((f"{scheme}://{line}", country))

    elif parser == "geonode":
        try:
            data = r.json()
            for item in data.get("data", []):
                ip = item.get("ip")
                port = item.get("port")
                proto = (item.get("protocols") or [scheme])[0] if item.get("protocols") else scheme
                cc = item.get("country") or country
                if ip and port:
                    results.append((f"{proto}://{ip}:{port}", cc))
        except Exception:
            pass

    elif parser == "freeproxy":
        rows = re.findall(r"(\d+\.\d+\.\d+\.\d+)</td>\s*<td>(\d+)", text)
        for ip, port in rows:
            results.append((f"{scheme}://{ip}:{port}", country))

    elif parser == "spys_socks":
        for line in text.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+:\d+)\s+(\w{2})", line)
            if m:
                cc = m.group(2).upper()
                if filter_country and cc != filter_country:
                    continue
                results.append((f"socks5://{m.group(1)}", cc))

    elif parser == "spys_http":
        for line in text.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+:\d+)\s+(\w{2})", line)
            if m:
                cc = m.group(2).upper()
                if filter_country and cc != filter_country:
                    continue
                results.append((f"http://{m.group(1)}", cc))

    elif parser == "openproxy":
        ips = re.findall(r'"(\d+\.\d+\.\d+\.\d+:\d+)"', text)
        for addr in ips:
            results.append((f"{scheme}://{addr}", country))

    elif parser == "github_bulk":
        for line in text.splitlines():
            line = line.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", line):
                results.append((f"{scheme}://{line}", None))

    elif parser == "fate0_jsonl":
        import json as _json
        for line in text.splitlines():
            try:
                obj = _json.loads(line)
                host = obj.get("host")
                port = obj.get("port")
                proto = obj.get("type", "http").lower()
                cc = obj.get("country")
                if host and port:
                    results.append((f"{proto}://{host}:{port}", cc))
            except Exception:
                continue

    return results


def _verify_proxy(url: str) -> tuple[bool, float | None]:
    """Returns (alive, latency_ms)."""
    p = urlparse(url)
    scheme = (p.scheme or "").lower()
    start = time.monotonic()
    try:
        if scheme.startswith("socks"):
            stype = socks.SOCKS5 if "5" in scheme else socks.SOCKS4
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(stype, p.hostname, p.port,
                        username=p.username, password=p.password)
            s.settimeout(VERIFY_TIMEOUT)
            s.connect(("1.1.1.1", 80))
            latency = (time.monotonic() - start) * 1000
            s.close()
            return True, latency
        else:
            r = httpx.get("http://httpbin.org/ip", timeout=VERIFY_TIMEOUT, proxy=url)
            latency = (time.monotonic() - start) * 1000
            return r.status_code == 200, latency
    except Exception:
        return False, None


def _reverify_existing():
    """Re-check all existing proxies and update their status."""
    all_proxies = proxy_pool.get_all()
    if not all_proxies:
        return 0

    stale_cutoff = time.time() - REVERIFY_INTERVAL
    to_check = [p for p in all_proxies if (p.get("last_checked") or 0) < stale_cutoff]
    if not to_check:
        return 0

    checked = 0
    lock = threading.Lock()

    def _check(p):
        nonlocal checked
        alive, latency = _verify_proxy(p["url"])
        proxy_pool.mark_proxy(p["url"], alive, latency_ms=latency)
        with lock:
            checked += 1

    with ThreadPoolExecutor(max_workers=REVERIFY_WORKERS) as pool:
        list(pool.map(_check, to_check))

    return checked


def run_scrape_cycle() -> dict:
    global _last_run_info

    _set_progress(
        active=True, phase="scraping", current_source="(parallel)",
        sources_done=0, sources_total=len(SOURCES),
        candidates_found=0, verify_current=0, verify_total=0,
        verified_alive=0, verified_failed=0, purged=0,
        pool_size=proxy_pool.get_count(), recent_adds=[], reverified=0,
    )

    # Phase 1: re-verify existing proxies
    _set_progress(phase="reverifying")
    reverified = _reverify_existing()
    _set_progress(reverified=reverified)

    # Phase 2: purge dead proxies
    _set_progress(phase="purging")
    purged = proxy_pool.purge_dead()
    _set_progress(purged=purged, pool_size=proxy_pool.get_count())

    # Phase 3: scrape new proxies from all sources
    _set_progress(phase="scraping")
    candidates: dict[str, str | None] = {}  # url -> country
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
            for url, cc in found:
                if url not in candidates:
                    candidates[url] = cc
            sources_done += 1
            _set_progress(
                current_source=src["name"],
                sources_done=sources_done,
                candidates_found=len(candidates),
            )

    # Phase 4: filter already-known, prioritize RU/IR, cap total
    existing_hp = set()
    for p in proxy_pool.get_all():
        existing_hp.add(f"{p['host']}:{p['port']}")

    priority_candidates = []
    bulk_candidates = []
    for url, cc in candidates.items():
        parsed = urlparse(url)
        hp = f"{parsed.hostname}:{parsed.port}"
        if hp in existing_hp:
            continue
        existing_hp.add(hp)
        if cc and cc.upper() in ("RU", "IR"):
            priority_candidates.append((url, cc))
        else:
            bulk_candidates.append((url, cc))

    # RU/IR first (all of them), then random sample of bulk up to cap
    import random as _rand
    remaining_slots = max(0, MAX_VERIFY_PER_CYCLE - len(priority_candidates))
    if len(bulk_candidates) > remaining_slots:
        _rand.shuffle(bulk_candidates)
        bulk_candidates = bulk_candidates[:remaining_slots]

    new_candidates = priority_candidates + bulk_candidates
    _set_progress(phase="verifying", verify_total=len(new_candidates))

    # Phase 5: verify new candidates (priority RU/IR first, then sampled bulk)
    verified = 0
    failed = 0
    done_count = 0
    recent_adds: list[str] = []
    lock = threading.Lock()

    def _check(item):
        nonlocal verified, failed, done_count, recent_adds
        url, cc = item
        alive, latency = _verify_proxy(url)
        with lock:
            done_count += 1
            if alive:
                proxy_pool.add_proxies([url], country=cc)
                proxy_pool.mark_proxy(url, True, latency_ms=latency)
                verified += 1
                recent_adds.append(url)
                if len(recent_adds) > 50:
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

    info = {
        "scraped_total": len(candidates),
        "new_candidates": len(new_candidates),
        "verified_alive": verified,
        "verify_failed": failed,
        "reverified": reverified,
        "purged_dead": purged,
        "pool_size": proxy_pool.get_count(),
        "pool_alive": proxy_pool.get_count(alive_only=True),
        "pool_ru": proxy_pool.get_count(country="RU"),
        "pool_ir": proxy_pool.get_count(country="IR"),
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
        _emit(f"[PROXY] Scraping RU/IR proxies from {len(SOURCES)} sources...")
        info = run_scrape_cycle()
        _emit(
            f"[PROXY] Done: {info['scraped_total']} scraped, "
            f"+{info['verified_alive']} alive, "
            f"-{info['purged_dead']} purged, "
            f"pool: {info['pool_size']} (RU:{info['pool_ru']} IR:{info['pool_ir']})",
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
            _emit(f"[PROXY] Auto-scraping RU/IR proxies from {len(SOURCES)} sources...")
            info = run_scrape_cycle()
            _emit(
                f"[PROXY] Done: {info['scraped_total']} scraped, "
                f"+{info['verified_alive']} alive, "
                f"-{info['purged_dead']} purged, "
                f"pool: {info['pool_size']} (RU:{info['pool_ru']} IR:{info['pool_ir']})",
                "success" if info["verified_alive"] > 0 else "info"
            )
        except Exception as e:
            logger.exception("Proxy scraper error")
            _emit(f"[PROXY] Scraper error: {e}", "error")

        for _ in range(int(_scraper_interval)):
            if not _scraper_running:
                return
            time.sleep(1)


def start_daemon(interval: int = 300):
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
