import re

from app.models.device import DeviceType

KEYWORD_RULES: list[tuple[DeviceType, list[str]]] = [
    (DeviceType.CAMERA, ["camera", "ipcam", "webcam", "hikvision", "dahua", "rtsp", "onvif", "axis"]),
    (DeviceType.DVR, ["dvr", "nvr", "recorder", "cctv"]),
    (DeviceType.ROUTER, ["router", "mikrotik", "routeros", "openwrt", "dd-wrt", "gateway", "netgear", "tp-link", "asus rt", "linksys"]),
    (DeviceType.NAS, ["nas", "synology", "qnap", "netgear readynas", "wd my cloud", "freenas"]),
    (DeviceType.PRINTER, ["printer", "print", "cups", "laserjet", "epson", "brother"]),
    (DeviceType.SCADA, ["scada", "modbus", "plc", "siemens", "schneider", "ics", "hmi"]),
    (DeviceType.SMART_HOME, ["smart", "home assistant", "tuya", "zigbee", "mqtt", "tasmota"]),
    (DeviceType.INDUSTRIAL, ["industrial", "bacnet", "dnp3", "ethernet/ip", "profinet"]),
]


class DeviceClassifier:
    """Rule-based classifier with a fallback ML hook for future training."""

    def predict(self, raw: dict) -> tuple[DeviceType, float]:
        text = self._extract_text(raw).lower()
        best_type = DeviceType.UNKNOWN
        best_score = 0.0

        for dtype, keywords in KEYWORD_RULES:
            hits = sum(1 for kw in keywords if kw in text)
            if hits > 0:
                score = min(hits / len(keywords) + 0.3, 1.0)
                if score > best_score:
                    best_score = score
                    best_type = dtype

        if best_type == DeviceType.UNKNOWN:
            best_type, best_score = self._port_heuristic(raw)

        return best_type, round(best_score, 3)

    def _extract_text(self, raw: dict) -> str:
        parts = [
            raw.get("banner", ""),
            raw.get("manufacturer", ""),
            raw.get("firmware_version", ""),
            str(raw.get("raw_data", {})),
        ]
        return " ".join(p for p in parts if p)

    def _port_heuristic(self, raw: dict) -> tuple[DeviceType, float]:
        ports = set(raw.get("open_ports", []))
        if ports & {554, 8554}:
            return DeviceType.CAMERA, 0.4
        if ports & {502, 102}:
            return DeviceType.SCADA, 0.4
        if ports & {9100, 515, 631}:
            return DeviceType.PRINTER, 0.4
        if ports & {1883, 8883}:
            return DeviceType.SMART_HOME, 0.35
        return DeviceType.UNKNOWN, 0.0
