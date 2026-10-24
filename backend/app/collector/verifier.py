import datetime
import logging
import re
import socket
from urllib.parse import urlparse

import httpx
import socks

from app.config import settings

logger = logging.getLogger(__name__)

HTTP_PORTS = {80, 443, 8080, 8443, 8888, 8000, 8081, 9090, 4443}
TIMEOUT = 4


def _emit(msg: str, level: str = "info"):
    from app.api.scans import _append_log
    _append_log(msg, level)


def _parse_proxy():
    url = settings.proxy_url
    if not url:
        return None
    p = urlparse(url)
    scheme = p.scheme.lower()
    host = p.hostname
    port = p.port
    user = p.username
    pwd = p.password
    return {"scheme": scheme, "host": host, "port": port, "user": user, "pwd": pwd}


def check_port(ip: str, port: int, timeout: float = TIMEOUT) -> bool:
    proxy = _parse_proxy()
    try:
        if proxy and proxy["scheme"].startswith("socks"):
            stype = socks.SOCKS5 if "5" in proxy["scheme"] else socks.SOCKS4
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(stype, proxy["host"], proxy["port"],
                        username=proxy.get("user"), password=proxy.get("pwd"))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False


def grab_http_title(ip: str, port: int) -> str | None:
    proto = "https" if port in (443, 8443, 4443) else "http"
    url = f"{proto}://{ip}:{port}"
    proxy_url = settings.proxy_url or None
    try:
        r = httpx.get(url, timeout=TIMEOUT, follow_redirects=True, verify=False,
                      proxy=proxy_url)
        match = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:200]
        return f"HTTP {r.status_code}"
    except Exception:
        return None


def verify_device(ip: str, ports: list[int]) -> dict:
    alive_ports = []
    http_title = None

    for port in ports[:15]:
        if check_port(ip, port):
            alive_ports.append(port)
            if port in HTTP_PORTS and http_title is None:
                http_title = grab_http_title(ip, port)

    return {
        "is_alive": len(alive_ports) > 0,
        "alive_ports": alive_ports,
        "http_title": http_title,
        "last_checked": datetime.datetime.now(datetime.UTC),
    }


def verify_devices_batch(devices_data: list[dict], emit_progress: bool = True) -> list[dict]:
    results = []
    total = len(devices_data)
    alive_count = 0
    proxy = _parse_proxy()

    if proxy and emit_progress:
        _emit(f"[VERIFY] Using proxy: {proxy['scheme']}://{proxy['host']}:{proxy['port']}")

    for i, d in enumerate(devices_data):
        ip = d.get("ip")
        ports = d.get("open_ports") or [d.get("port", 80)]
        result = verify_device(ip, ports)
        result["ip"] = ip
        results.append(result)

        if result["is_alive"]:
            alive_count += 1

        if emit_progress and ((i + 1) % 5 == 0 or i == total - 1):
            _emit(
                f"[VERIFY] Checked {i + 1}/{total} — "
                f"{alive_count} alive ({len(result.get('alive_ports', []))} ports on {ip})"
            )

    return results
