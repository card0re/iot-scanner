"""
Direct port scanner for IoT device discovery.
Scans IP ranges in RU/IR directly on key ports — no Shodan API needed.
Uses proxy pool for connections. Massively parallel.
"""
import asyncio
import logging
import random
import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

import socks
from urllib.parse import urlparse

from app.collector import proxy_pool
from app.collector.shodan_client import IR_RANGES, RU_RANGES

logger = logging.getLogger(__name__)

IOT_PORTS = [23, 22, 80, 8080, 443, 8443, 2323, 2222, 554, 8554, 8888, 81, 82, 85, 88, 9090]
CONNECT_TIMEOUT = 3
SCAN_WORKERS = 100


def _emit(msg: str, level: str = "info"):
    try:
        from app.api.scans import _append_log
        _append_log(msg, level)
    except Exception:
        pass


def _sample_ips_from_ranges(ranges: list[str], count: int, exclude: set[str]) -> list[str]:
    networks = [ipaddress.ip_network(cidr) for cidr in ranges]
    cum_sizes = []
    cum = 0
    for net in networks:
        cum += net.num_addresses
        cum_sizes.append(cum)
    total = cum

    need = min(count * 3, total)
    indices = set()
    while len(indices) < need:
        indices.update(random.sample(range(total), min(need - len(indices), total)))

    result = []
    for idx in sorted(indices):
        for i, c in enumerate(cum_sizes):
            if idx < c:
                offset = idx - (cum_sizes[i - 1] if i > 0 else 0)
                ip_str = str(networks[i].network_address + offset)
                if ip_str not in exclude:
                    result.append(ip_str)
                break
        if len(result) >= count:
            break
    return result[:count]


def _check_port(ip: str, port: int, country: str | None = None) -> bool:
    """Try connecting to ip:port, optionally via proxy."""
    prx = proxy_pool.get_proxy_for_target(country, "ssh")

    try:
        if prx and prx["scheme"].startswith("socks"):
            stype = socks.SOCKS5 if "5" in prx["scheme"] else socks.SOCKS4
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(stype, prx["host"], prx["port"],
                        username=prx.get("user"), password=prx.get("pwd"))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((ip, port))
        s.close()
        if prx:
            proxy_pool.mark_proxy(prx["url"], True)
        return True
    except Exception:
        if prx:
            proxy_pool.mark_proxy(prx["url"], False)
        return False


def _scan_ip(ip: str, ports: list[int], country: str | None = None) -> dict | None:
    """Scan a single IP for open ports. Returns device dict or None."""
    open_ports = []
    for port in ports:
        if _check_port(ip, port, country):
            open_ports.append(port)
            break  # at least one open = this IP is interesting

    if not open_ports:
        return None

    # Found at least one open port — now check the rest quickly
    remaining = [p for p in ports if p not in open_ports]
    for port in remaining[:8]:
        if _check_port(ip, port, country):
            open_ports.append(port)

    return {
        "ip": ip,
        "port": open_ports[0],
        "protocol": "tcp",
        "banner": None,
        "manufacturer": None,
        "firmware_version": None,
        "country_code": country,
        "city": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "org": None,
        "open_ports": sorted(open_ports),
        "raw_data": {"vulns": {}, "cpe": [], "hostnames": [], "tags": ["direct-scan"]},
        "source": "direct",
    }


def direct_scan(
    country_code: str,
    sample_size: int = 2000,
    exclude_ips: set[str] | None = None,
    ports: list[int] | None = None,
) -> list[dict]:
    """Directly scan random IPs in country ranges for open IoT ports."""
    ranges = {"IR": IR_RANGES, "RU": RU_RANGES}.get(country_code, [])
    if not ranges:
        return []

    exclude = exclude_ips or set()
    target_ports = ports or IOT_PORTS
    ips = _sample_ips_from_ranges(ranges, sample_size, exclude)
    if not ips:
        return []

    _emit(f"[DIRECT] Scanning {len(ips)} IPs in {country_code} on ports {target_ports[:6]}...")

    devices = []
    checked = 0
    start = time.monotonic()

    def _worker(ip):
        nonlocal checked
        result = _scan_ip(ip, target_ports, country_code)
        checked += 1
        if checked % 100 == 0:
            elapsed = time.monotonic() - start
            rate = checked / elapsed if elapsed > 0 else 0
            _emit(f"[DIRECT] {country_code}: {checked}/{len(ips)} scanned, {len(devices)} found ({rate:.0f} IPs/s)")
        return result

    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        for result in pool.map(_worker, ips):
            if result:
                devices.append(result)

    elapsed = time.monotonic() - start
    _emit(
        f"[DIRECT] {country_code}: DONE — {len(devices)} devices found from {len(ips)} IPs in {elapsed:.1f}s",
        "success" if devices else "info",
    )
    return devices


def scan_telnet_ssh_focused(
    country_code: str,
    sample_size: int = 3000,
    exclude_ips: set[str] | None = None,
) -> list[dict]:
    """Focused scan for SSH/Telnet — highest chance of getting a shell."""
    return direct_scan(
        country_code,
        sample_size=sample_size,
        exclude_ips=exclude_ips,
        ports=[23, 22, 2323, 2222],
    )
