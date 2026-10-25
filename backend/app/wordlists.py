"""
Comprehensive IoT default credential wordlist.
Organized: type-specific creds first, then universal IoT defaults.
"""

# ---- Universal IoT defaults (tried for ALL device types) ----
UNIVERSAL_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "pass"),
    ("admin", "default"),
    ("admin", "admin1"),
    ("admin", "1234567890"),
    ("root", "root"),
    ("root", ""),
    ("root", "toor"),
    ("root", "pass"),
    ("root", "password"),
    ("root", "1234"),
    ("root", "12345"),
    ("root", "123456"),
    ("root", "admin"),
    ("root", "default"),
    ("root", "root123"),
    ("user", "user"),
    ("user", ""),
    ("user", "1234"),
    ("user", "password"),
    ("guest", "guest"),
    ("guest", ""),
    ("guest", "1234"),
    ("test", "test"),
    ("support", "support"),
    ("operator", "operator"),
    ("supervisor", "supervisor"),
    ("service", "service"),
    ("tech", "tech"),
    ("monitor", "monitor"),
    ("default", "default"),
    ("default", ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("administrator", "admin"),
    ("Administrator", "admin"),
    ("manager", "manager"),
    ("security", "security"),
    ("ubnt", "ubnt"),
    ("pi", "raspberry"),
    ("pi", "raspberrypi"),
    ("vagrant", "vagrant"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("ftp", "ftp"),
    ("ftpuser", "ftpuser"),
    ("anonymous", ""),
    ("anonymous", "anonymous"),
]

# ---- Type-specific creds (tried BEFORE universal) ----
TYPE_CREDS: dict[str, list[tuple[str, str]]] = {
    "camera": [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "12345"),
        ("admin", "888888"),
        ("admin", "666666"),
        ("admin", "123456"),
        ("admin", "camera"),
        ("admin", "4321"),
        ("admin", "pass"),
        ("admin", "1111"),
        ("admin", "1234567890"),
        ("root", "root"),
        ("root", ""),
        ("root", "pass"),
        ("root", "camera"),
        ("root", "system"),
        ("root", "icatch99"),
        ("root", "juantech"),
        ("root", "vizxv"),
        ("root", "hi3518"),
        ("root", "xmhdipc"),
        ("root", "xc3511"),
        ("root", "klv123"),
        ("root", "klv1234"),
        ("root", "dreambox"),
        ("root", "7ujMko0admin"),
        ("root", "zlxx."),
        ("root", "Zte521"),
        ("root", "anko"),
        ("root", "GM8182"),
        ("888888", "888888"),
        ("666666", "666666"),
        ("default", ""),
        ("default", "OxhlwSG8"),
        ("service", "service"),
        ("supervisor", "supervisor"),
        # Hikvision
        ("admin", "Hikvision"),
        ("admin", "hikvision"),
        ("admin", "abcd1234"),
        # Dahua
        ("admin", "admin123"),
        ("admin", "dahua"),
        # Axis
        ("root", "pass"),
        # Foscam
        ("admin", "ipcam"),
        # Vivotek
        ("root", "vivotek"),
        # Reolink
        ("admin", ""),
    ],
    "router": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", ""),
        ("admin", "admin1"),
        ("admin", "default"),
        ("admin", "motorola"),
        ("admin", "admin123"),
        ("admin", "changeme"),
        ("admin", "connection"),
        ("admin", "michelangelo"),
        ("admin", "smcadmin"),
        ("admin", "abc123"),
        ("admin", "sky"),
        ("admin", "superadmin"),
        ("root", "root"),
        ("root", ""),
        ("root", "admin"),
        ("root", "12345"),
        ("root", "password"),
        ("root", "toor"),
        ("user", "user"),
        ("user", "password"),
        # MikroTik
        ("admin", ""),
        # TP-Link
        ("admin", "admin"),
        # Netgear
        ("admin", "password"),
        ("admin", "1234"),
        # D-Link
        ("admin", ""),
        ("admin", "admin"),
        # Asus
        ("admin", "admin"),
        # Linksys
        ("admin", "admin"),
        ("", "admin"),
        # Cisco
        ("cisco", "cisco"),
        ("admin", "cisco"),
        ("cisco", ""),
        # ZTE
        ("admin", "Zte521"),
        ("zte", "zte"),
        # Huawei
        ("admin", "admin@huawei.com"),
        ("telecomadmin", "admintelecom"),
        ("root", "admin"),
        # Ubiquiti
        ("ubnt", "ubnt"),
        # OpenWrt
        ("root", ""),
        # ZyXEL
        ("admin", "1234"),
        ("supervisor", "zyad1234"),
        # Tenda
        ("admin", "admin"),
        # ASUS
        ("admin", "admin"),
    ],
    "dvr": [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "4321"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", "7ujMko0admin"),
        ("admin", "password"),
        ("admin", "1111111"),
        ("admin", "smcadmin"),
        ("admin", "dvr"),
        ("888888", "888888"),
        ("666666", "666666"),
        ("root", "root"),
        ("root", ""),
        ("root", "vizxv"),
        ("root", "xc3511"),
        ("root", "xmhdipc"),
        ("root", "klv1234"),
        ("root", "hi3518"),
        ("root", "juantech"),
        ("root", "GM8182"),
        ("root", "zlxx."),
        ("root", "7ujMko0admin"),
        ("default", "default"),
        ("default", ""),
        ("default", "OxhlwSG8"),
    ],
    "nas": [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "password"),
        ("admin", "nas"),
        ("admin", "1234"),
        ("root", "root"),
        ("root", ""),
        ("root", "nas"),
        ("root", "admin"),
        # Synology
        ("admin", "synology"),
        ("admin", ""),
        # QNAP
        ("admin", "admin"),
        ("admin", "qnap"),
        # Western Digital
        ("admin", "admin"),
        ("root", "welc0me"),
        # Netgear ReadyNAS
        ("admin", "netgear1"),
        ("admin", "password"),
    ],
    "printer": [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "1234"),
        ("admin", "password"),
        ("root", "root"),
        ("root", ""),
        # HP
        ("admin", ""),
        ("admin", "hp"),
        # Epson
        ("epson", "epson"),
        # Brother
        ("admin", "access"),
        # Xerox
        ("admin", "1111"),
        # Lexmark
        ("admin", "admin"),
        # Samsung
        ("admin", "sec00000"),
        # Ricoh
        ("admin", ""),
        ("supervisor", ""),
    ],
    "scada": [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "password"),
        ("admin", "1234"),
        ("user", "user"),
        ("operator", "operator"),
        ("engineer", "engineer"),
        ("guest", "guest"),
        # Siemens
        ("admin", "admin"),
        ("siemens", "siemens"),
        ("admin", "100"),
        # Schneider Electric
        ("USER", "USER"),
        ("admin", "admin"),
        # ABB
        ("admin", "admin"),
        ("sysadmin", "sysadmin"),
        # GE
        ("admin", "admin"),
        ("engineer", ""),
        # Honeywell
        ("admin", "honeywell"),
    ],
    "smart_home": [
        ("admin", "admin"),
        ("admin", ""),
        ("root", "root"),
        ("root", ""),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", "smarthome"),
        ("user", "user"),
        # Home Assistant
        ("homeassistant", "homeassistant"),
        # Tuya
        ("admin", "tuya"),
    ],
    "industrial": [
        ("admin", "admin"),
        ("admin", ""),
        ("root", "root"),
        ("root", ""),
        ("admin", "password"),
        ("user", "user"),
        ("operator", "operator"),
        ("engineer", "engineer"),
        ("maintenance", "maintenance"),
        ("supervisor", "supervisor"),
        ("service", "service"),
        ("technician", "technician"),
        # Allen-Bradley
        ("admin", "1234"),
        # Omron
        ("admin", "admin"),
    ],
}


def get_creds_for_type(device_type: str) -> list[tuple[str, str]]:
    """Return deduplicated credential list: type-specific first, then universal."""
    type_list = TYPE_CREDS.get(device_type, [])
    seen = set()
    result = []
    for cred in type_list + UNIVERSAL_CREDS:
        if cred not in seen:
            seen.add(cred)
            result.append(cred)
    return result


# Keep backward-compat alias for terminal.py
KNOWN_DEFAULTS = {
    dtype: creds[:6] for dtype, creds in TYPE_CREDS.items()
}
KNOWN_DEFAULTS["unknown"] = UNIVERSAL_CREDS[:6]
