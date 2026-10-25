import logging
import ipaddress
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
import shodan

from app.config import settings

logger = logging.getLogger(__name__)

IR_RANGES = [
    "2.144.0.0/14", "2.176.0.0/12", "5.22.0.0/17", "5.52.0.0/15",
    "5.160.0.0/16", "5.200.0.0/16", "31.2.0.0/17", "31.40.0.0/16",
    "37.32.0.0/14", "37.98.0.0/17", "37.114.192.0/18", "37.137.0.0/16",
    "37.156.0.0/16", "46.18.248.0/21", "46.21.80.0/20", "46.34.96.0/19",
    "46.62.128.0/17", "46.100.0.0/16", "46.209.0.0/16", "46.224.0.0/15",
    "62.102.128.0/20", "62.220.96.0/19", "78.38.0.0/15", "78.109.192.0/20",
    "80.66.176.0/20", "80.191.0.0/16", "80.210.0.0/16", "80.250.192.0/20",
    "81.12.0.0/17", "81.28.32.0/19", "81.29.240.0/20", "81.31.224.0/19",
    "81.90.144.0/20", "81.91.128.0/17", "82.99.192.0/18",
    "85.133.0.0/16", "85.185.0.0/16", "85.198.0.0/19",
    "86.55.0.0/16", "86.104.32.0/20", "86.106.136.0/21",
    "87.107.0.0/16", "87.236.208.0/22", "87.247.176.0/20",
    "88.135.32.0/20", "89.32.0.0/18", "89.42.32.0/21",
    "89.165.0.0/17", "89.196.0.0/16", "89.219.64.0/18",
    "89.235.64.0/18", "91.92.108.0/22", "91.98.0.0/16",
    "91.108.128.0/17", "91.184.64.0/18", "91.185.128.0/17",
    "91.227.84.0/22", "91.236.168.0/23", "91.243.124.0/22",
    "92.43.160.0/22", "92.114.16.0/20", "93.88.64.0/21",
    "93.110.0.0/16", "93.114.16.0/20", "93.115.224.0/20",
    "94.24.0.0/16", "94.74.128.0/17", "94.101.128.0/20",
    "94.139.160.0/19", "94.176.8.0/21", "94.182.0.0/15",
    "94.232.168.0/21", "95.38.0.0/16", "95.80.0.0/17",
    "95.142.224.0/20", "95.156.220.0/22",
]

RU_RANGES = [
    "2.56.0.0/16", "2.72.0.0/14", "5.3.0.0/16", "5.8.0.0/16",
    "5.16.0.0/16", "5.34.0.0/16", "5.42.192.0/18", "5.44.80.0/20",
    "5.53.0.0/16", "5.59.0.0/18", "5.61.16.0/20", "5.100.64.0/18",
    "5.101.0.0/16", "5.104.64.0/18", "5.136.0.0/13", "5.164.0.0/14",
    "5.187.0.0/17", "5.228.0.0/14", "5.250.168.0/21",
    "31.6.0.0/16", "31.13.16.0/20", "31.28.0.0/16",
    "31.40.112.0/20", "31.44.48.0/20", "31.128.32.0/19",
    "31.130.128.0/17", "31.134.0.0/17", "31.148.0.0/16",
    "31.162.0.0/15", "31.170.48.0/21", "31.173.0.0/16",
    "31.177.64.0/18", "31.180.0.0/14", "31.184.192.0/18",
    "31.186.0.0/17", "37.1.0.0/18", "37.9.0.0/19",
    "37.18.0.0/18", "37.29.0.0/17", "37.44.0.0/19",
    "37.75.128.0/17", "37.110.0.0/16", "37.139.0.0/18",
    "37.140.128.0/17", "37.143.0.0/18", "37.144.0.0/14",
    "37.192.0.0/14", "37.200.64.0/18", "37.220.0.0/18",
    "37.230.112.0/20", "37.235.64.0/18",
    "46.0.0.0/16", "46.8.0.0/15", "46.17.0.0/18",
    "46.20.0.0/19", "46.29.0.0/19", "46.36.0.0/18",
    "46.39.192.0/18", "46.42.0.0/16", "46.46.0.0/17",
    "46.48.0.0/14", "46.146.0.0/15", "46.160.0.0/15",
    "46.172.0.0/15", "46.175.0.0/17", "46.180.0.0/14",
    "46.187.0.0/17", "46.188.0.0/14",
]

COUNTRY_RANGES = {"IR": IR_RANGES, "RU": RU_RANGES}

IOT_PORTS = {23, 80, 443, 554, 1883, 5900, 8080, 8443, 8554, 9100, 502, 161}


def _emit(msg: str, level: str = "info"):
    from app.api.scans import _append_log
    _append_log(msg, level)


class ShodanCollector:
    def __init__(self):
        self.has_paid_key = False
        if settings.shodan_api_key:
            try:
                api = shodan.Shodan(settings.shodan_api_key)
                info = api.info()
                self.has_paid_key = info.get("query_credits", 0) > 0
                self.api = api
            except Exception:
                pass

    def collect_country(self, country_code: str, exclude_ips: set[str] | None = None, sample_size: int = 500) -> list[dict]:
        if self.has_paid_key:
            return self._collect_via_search(country_code)
        return self._collect_via_internetdb(country_code, sample_size=sample_size, exclude_ips=exclude_ips)

    def _collect_via_search(self, country_code: str) -> list[dict]:
        queries = [
            f"webcam country:{country_code}",
            f"Router country:{country_code}",
            f'"default password" country:{country_code}',
        ]
        all_devices = []
        for q in queries:
            try:
                results = self.api.search(q)
                devices = self._normalize_search(results.get("matches", []))
                all_devices.extend(devices)
                _emit(f"[SHODAN] Search '{q}': {len(devices)} devices")
            except shodan.APIError as e:
                _emit(f"[SHODAN] Search '{q}' skipped: {e}", "warn")
        return all_devices

    def _collect_via_internetdb(self, country_code: str, sample_size: int = 500,
                                exclude_ips: set[str] | None = None) -> list[dict]:
        ranges = COUNTRY_RANGES.get(country_code, [])
        if not ranges:
            return []

        all_ips = []
        for cidr in ranges:
            net = ipaddress.ip_network(cidr)
            all_ips.extend(net)

        if exclude_ips:
            all_ips = [ip for ip in all_ips if str(ip) not in exclude_ips]
            _emit(f"[SHODAN] InternetDB: {len(exclude_ips)} known IPs excluded, {len(all_ips)} candidates remain ({country_code})")

        if not all_ips:
            _emit(f"[SHODAN] InternetDB: no new IPs to scan for {country_code}", "warn")
            return []

        sampled = random.sample(all_ips, min(sample_size, len(all_ips)))
        _emit(f"[SHODAN] InternetDB: sampling {len(sampled)} new IPs from {len(all_ips)} total ({country_code})")

        import threading
        devices = []
        checked = 0
        lock = threading.Lock()

        def _check_ip(ip):
            nonlocal checked
            data = self._query_internetdb(str(ip))
            with lock:
                checked += 1
                if data and data.get("ports"):
                    iot_ports = set(data["ports"]) & IOT_PORTS
                    if iot_ports:
                        devices.append(self._normalize_internetdb(data, country_code))
                if checked % 50 == 0 or checked == len(sampled):
                    _emit(f"[SHODAN] InternetDB {country_code}: checked {checked}/{len(sampled)}, found {len(devices)} IoT devices")

        with ThreadPoolExecutor(max_workers=30) as pool:
            list(pool.map(_check_ip, sampled))

        return devices

    def _query_internetdb(self, ip: str) -> dict | None:
        try:
            r = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return None

    def _normalize_internetdb(self, data: dict, country_code: str) -> dict:
        ports = data.get("ports", [])
        return {
            "ip": data.get("ip"),
            "port": ports[0] if ports else 0,
            "protocol": "tcp",
            "banner": None,
            "manufacturer": None,
            "firmware_version": None,
            "country_code": country_code,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "org": None,
            "open_ports": ports,
            "raw_data": {
                "vulns": {v: {} for v in data.get("vulns", [])},
                "cpe": data.get("cpes", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
            },
            "source": "shodan",
        }

    def _normalize_search(self, matches: list[dict]) -> list[dict]:
        devices = []
        for m in matches:
            loc = m.get("location", {})
            devices.append({
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "protocol": m.get("transport", "tcp"),
                "banner": m.get("data", "")[:2000],
                "manufacturer": m.get("product"),
                "firmware_version": m.get("version"),
                "country_code": loc.get("country_code", ""),
                "city": loc.get("city"),
                "latitude": loc.get("latitude"),
                "longitude": loc.get("longitude"),
                "asn": m.get("asn"),
                "org": m.get("org"),
                "open_ports": m.get("ports", []),
                "raw_data": {
                    "vulns": m.get("vulns", {}),
                    "cpe": m.get("cpe23", m.get("cpe", [])),
                    "hostnames": m.get("hostnames", []),
                    "os": m.get("os"),
                    "tags": m.get("tags", []),
                },
                "source": "shodan",
            })
        return devices
