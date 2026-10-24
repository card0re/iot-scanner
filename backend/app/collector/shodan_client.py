import logging

import shodan

from app.config import settings

logger = logging.getLogger(__name__)

IOT_QUERIES = [
    "webcam country:{cc}",
    "Router country:{cc}",
    "NAS country:{cc}",
    "DVR country:{cc}",
    'port:23,80,443,554,8080 "default password" country:{cc}',
    "SCADA country:{cc}",
    'product:"MikroTik" country:{cc}',
    'product:"Hikvision" country:{cc}',
    'product:"Dahua" country:{cc}',
]


class ShodanCollector:
    def __init__(self):
        self.api = shodan.Shodan(settings.shodan_api_key)

    def search(self, query: str, page: int = 1) -> list[dict]:
        try:
            results = self.api.search(query, page=page)
            return self._normalize_results(results.get("matches", []))
        except shodan.APIError as e:
            logger.error("Shodan API error: %s", e)
            raise

    def collect_country(self, country_code: str) -> list[dict]:
        all_devices = []
        for query_tmpl in IOT_QUERIES:
            query = query_tmpl.format(cc=country_code)
            try:
                devices = self.search(query)
                all_devices.extend(devices)
                logger.info("Shodan: %d devices for query '%s'", len(devices), query)
            except shodan.APIError as e:
                logger.warning("Skipping query '%s': %s", query, e)
        return all_devices

    def _normalize_results(self, matches: list[dict]) -> list[dict]:
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
