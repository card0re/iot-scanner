"""
Banner grabber for IoT device identification.
Connects to Telnet/SSH ports, reads banners, classifies devices
as IoT vs regular servers for targeted exploitation.
"""
import asyncio
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

IOT_TELNET_KEYWORDS = [
    "busybox", "mikrotik", "routeros", "dahua", "hikvision",
    "d-link", "dlink", "tp-link", "tplink", "zyxel", "openwrt",
    "dd-wrt", "netgear", "ubiquiti", "ubnt", "asus", "huawei",
    "zte", "foscam", "reolink", "qnap", "synology", "axis",
    "avtech", "vivotek", "amcrest", "lorex", "swann",
    "dvr", "nvr", "ipc", "camera", "router",
    "welcome to", "broadcom", "realtek",
    "linux", "embedded", "mips", "arm",
]

IOT_SSH_KEYWORDS = [
    "dropbear", "mikrotik", "routeros", "ubnt", "fortigate",
    "lancom", "draytek", "zyxel", "huawei", "zte",
]

SERVER_SSH_KEYWORDS = [
    "openssh_8", "openssh_9", "openssh-8", "openssh-9",
    "openssh_7.9", "ubuntu", "debian", "centos", "redhat",
]


@dataclass
class BannerResult:
    ip: str
    port: int
    protocol: str
    banner: str
    is_iot: bool
    confidence: float


async def grab_telnet_banner(ip: str, port: int, timeout: float = 4) -> BannerResult | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=3,
        )
        banner = ""
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            banner = data.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not banner.strip():
            return None

        lower = banner.lower()
        iot_hits = sum(1 for kw in IOT_TELNET_KEYWORDS if kw in lower)
        is_iot = iot_hits > 0 or "login" in lower or "username" in lower
        confidence = min(iot_hits * 0.3, 1.0) if iot_hits else (0.4 if "login" in lower else 0.1)

        return BannerResult(
            ip=ip, port=port, protocol="telnet",
            banner=banner[:500], is_iot=is_iot, confidence=confidence,
        )
    except Exception:
        return None


async def grab_ssh_banner(ip: str, port: int, timeout: float = 3) -> BannerResult | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=3,
        )
        banner = ""
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=timeout)
            banner = data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not banner:
            return None

        lower = banner.lower()
        iot_hits = sum(1 for kw in IOT_SSH_KEYWORDS if kw in lower)
        server_hits = sum(1 for kw in SERVER_SSH_KEYWORDS if kw in lower)

        is_iot = iot_hits > 0 or (server_hits == 0 and "dropbear" in lower)
        if server_hits > 0 and iot_hits == 0:
            is_iot = False

        confidence = min(iot_hits * 0.4, 1.0) if iot_hits else (0.2 if not server_hits else 0.0)

        return BannerResult(
            ip=ip, port=port, protocol="ssh",
            banner=banner[:300], is_iot=is_iot, confidence=confidence,
        )
    except Exception:
        return None


async def grab_banners_batch(
    targets: list[dict],
    concurrency: int = 300,
) -> list[BannerResult]:
    sem = asyncio.Semaphore(concurrency)
    results: list[BannerResult] = []

    async def _grab(target: dict):
        async with sem:
            ip = target["ip"]
            port = target["port"]
            proto = target.get("protocol", "telnet")
            if proto == "ssh" or port in (22, 2222, 2022):
                return await grab_ssh_banner(ip, port)
            else:
                return await grab_telnet_banner(ip, port)

    tasks = [_grab(t) for t in targets]
    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result:
            results.append(result)

    return results
