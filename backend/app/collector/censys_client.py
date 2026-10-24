import logging

from censys.search import CensysHosts

from app.config import settings

logger = logging.getLogger(__name__)

IOT_SERVICES = [
    "services.service_name: HTTP and labels: iot",
    "services.service_name: TELNET",
    "services.service_name: RTSP",
    "services.service_name: UPNP",
    "services.software.vendor: Hikvision",
    "services.software.vendor: Dahua",
    "services.software.vendor: MikroTik",
]


class CensysCollector:
    def __init__(self):
        self.hosts = CensysHosts(
            api_id=settings.censys_api_id,
            api_secret=settings.censys_api_secret,
        )

    def collect_country(self, country_code: str) -> list[dict]:
        all_devices = []
        for base_query in IOT_SERVICES:
            query = f"{base_query} and location.country_code: {country_code}"
            try:
                devices = self._search(query)
                all_devices.extend(devices)
                logger.info("Censys: %d devices for query '%s'", len(devices), query)
            except Exception as e:
                logger.warning("Skipping query '%s': %s", query, e)
        return all_devices

    def _search(self, query: str, per_page: int = 100) -> list[dict]:
        results = []
        for hosts in self.hosts.search(query, per_page=per_page, pages=1):
            for host in hosts if isinstance(hosts, list) else [hosts]:
                results.append(self._normalize(host))
        return results

    def _normalize(self, host: dict) -> dict:
        loc = host.get("location", {})
        coords = loc.get("coordinates", {})
        services = host.get("services", [])
        ports = [s.get("port") for s in services if s.get("port")]
        primary_service = services[0] if services else {}
        software = primary_service.get("software", [])
        vendor = software[0].get("vendor") if software else None
        version = software[0].get("version") if software else None
        banner = primary_service.get("banner", "")

        return {
            "ip": host.get("ip"),
            "port": ports[0] if ports else 0,
            "protocol": primary_service.get("transport_protocol", "tcp"),
            "banner": banner[:2000] if banner else None,
            "manufacturer": vendor,
            "firmware_version": version,
            "country_code": loc.get("country_code", ""),
            "city": loc.get("city"),
            "latitude": coords.get("latitude"),
            "longitude": coords.get("longitude"),
            "asn": host.get("autonomous_system", {}).get("asn"),
            "org": host.get("autonomous_system", {}).get("name"),
            "open_ports": ports,
            "raw_data": {
                "services": [s.get("service_name") for s in services],
                "os": host.get("operating_system", {}),
                "labels": host.get("labels", []),
            },
            "source": "censys",
        }
