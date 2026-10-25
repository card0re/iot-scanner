import asyncio
import socket
import ssl
import html

import httpx
from fastapi import APIRouter
from sqlalchemy.orm import joinedload

from app.database import SessionLocal
from app.models.device import Device

router = APIRouter(prefix="/probe", tags=["probe"])

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 8

WEB_PORTS = {80, 443, 8080, 8443, 8888, 8000, 8081, 9090, 3000, 4443}
MGMT_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}
SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
    502: "Modbus", 554: "RTSP", 631: "IPP", 1883: "MQTT", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8554: "RTSP-Alt", 9100: "JetDirect",
}


async def _grab_banner(ip: str, port: int, timeout: float = 5) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            return data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            writer.write(b"\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=3)
                return data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                return None
        finally:
            writer.close()
    except Exception:
        return None


async def _http_probe(ip: str, port: int) -> dict:
    scheme = "https" if port in (443, 8443, 4443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    result = {"port": port, "scheme": scheme, "url": url}
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=TIMEOUT, follow_redirects=True,
        ) as client:
            resp = await client.get(url, headers={"User-Agent": UA})
            result["status"] = resp.status_code
            result["headers"] = dict(resp.headers)
            body = resp.text
            if len(body) > 4000:
                body = body[:4000] + f"\n... [{len(resp.text) - 4000} more chars]"
            result["body_preview"] = body
            result["content_type"] = resp.headers.get("content-type", "")
            result["server"] = resp.headers.get("server", "")
    except Exception as e:
        result["error"] = str(e)
    return result


async def _check_port(ip: str, port: int, timeout: float = 3) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        return True
    except Exception:
        return False


def _lookup_device(ip: str) -> dict | None:
    try:
        with SessionLocal() as db:
            dev = (
                db.query(Device)
                .options(joinedload(Device.vulnerabilities))
                .filter(Device.ip == ip)
                .first()
            )
            if not dev:
                return None
            vulns = []
            for v in dev.vulnerabilities:
                vulns.append({
                    "cve": v.cve_id,
                    "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "cvss": v.cvss_score,
                    "desc": v.description or "",
                    "rce": "rce" in (v.description or "").lower()
                           or "remote code" in (v.description or "").lower()
                           or "command injection" in (v.description or "").lower(),
                })
            open_ports = dev.open_ports or []
            if isinstance(open_ports, str):
                open_ports = [int(x) for x in open_ports.strip("{}[]").split(",") if x.strip().isdigit()]
            alive_ports = dev.alive_ports or []
            if isinstance(alive_ports, str):
                alive_ports = [int(x) for x in alive_ports.strip("{}[]").split(",") if x.strip().isdigit()]
            return {
                "ip": dev.ip,
                "port": dev.port,
                "type": dev.device_type.value if hasattr(dev.device_type, "value") else str(dev.device_type),
                "country": dev.country_code,
                "org": dev.org or "",
                "asn": dev.asn or "",
                "manufacturer": dev.manufacturer or "Unknown",
                "firmware": dev.firmware_version or "Unknown",
                "model": dev.model or "Unknown",
                "banner": dev.banner or "",
                "http_title": dev.http_title or "",
                "score": dev.vulnerability_score or 0,
                "open_ports": open_ports,
                "alive_ports": alive_ports,
                "vulns": vulns,
                "first_seen": dev.first_seen.isoformat() if dev.first_seen else None,
                "last_seen": dev.last_seen.isoformat() if dev.last_seen else None,
            }
    except Exception:
        return None


@router.get("/{ip}")
async def probe_device(ip: str):
    device = _lookup_device(ip)
    ports = []
    if device:
        raw = (device.get("open_ports") or []) + (device.get("alive_ports") or [])
        all_ports = sorted({int(p) for p in raw if str(p).isdigit()})
        ports = all_ports[:30]
    if not ports:
        ports = [21, 22, 23, 80, 443, 554, 8080, 8443]

    port_checks = await asyncio.gather(*[_check_port(ip, p) for p in ports])
    alive = [p for p, ok in zip(ports, port_checks) if ok]

    web_ports_alive = [p for p in alive if p in WEB_PORTS]
    other_ports = [p for p in alive if p not in WEB_PORTS]

    banner_tasks = [_grab_banner(ip, p) for p in other_ports[:10]]
    http_tasks = [_http_probe(ip, p) for p in web_ports_alive[:5]]

    banners_raw = await asyncio.gather(*banner_tasks) if banner_tasks else []
    http_results = await asyncio.gather(*http_tasks) if http_tasks else []

    banners = {}
    for p, b in zip(other_ports[:10], banners_raw):
        if b:
            banners[str(p)] = b

    mgmt = []
    for p in alive:
        if p in MGMT_PORTS:
            mgmt.append({"port": p, "service": MGMT_PORTS[p]})

    rce_vulns = []
    if device:
        rce_vulns = [v for v in device.get("vulns", []) if v.get("rce")]

    return {
        "ip": ip,
        "device": device,
        "alive_ports": alive,
        "banners": banners,
        "http_probes": http_results,
        "management_ports": mgmt,
        "rce_vulns": rce_vulns,
        "port_services": {str(p): SERVICE_PORTS.get(p, "unknown") for p in alive},
    }


@router.get("/{ip}/http/{port:int}")
async def probe_http(ip: str, port: int):
    return await _http_probe(ip, port)


@router.get("/{ip}/banner/{port:int}")
async def probe_banner(ip: str, port: int):
    banner = await _grab_banner(ip, port)
    return {"ip": ip, "port": port, "banner": banner}
