import html
import re
from urllib.parse import urlparse

from fastapi import APIRouter, Request, Response
from sqlalchemy.orm import joinedload

import httpx

from app.collector import proxy_pool
from app.database import SessionLocal
from app.models.device import Device

router = APIRouter(prefix="/proxy", tags=["proxy"])

ALLOWED_SCHEMES = {"http", "https"}
TIMEOUT = 10


def _get_proxy_url() -> str | None:
    prx = proxy_pool.next_proxy()
    return prx["url"] if prx else None


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
                    "sev": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "cvss": v.cvss_score,
                    "desc": (v.description or "")[:120],
                })
            return {
                "ip": dev.ip,
                "type": dev.device_type.value if hasattr(dev.device_type, "value") else str(dev.device_type),
                "country": dev.country_code,
                "org": dev.org or "—",
                "score": dev.vulnerability_score or 0,
                "title": dev.http_title or "",
                "manufacturer": dev.manufacturer or "Unknown",
                "firmware": dev.firmware_version or "Unknown",
                "vulns": vulns,
                "alive_ports": dev.alive_ports or [],
            }
    except Exception:
        return None


def _build_info_bar(device: dict, host: str, port: int, scheme: str, base_path: str) -> str:
    d = device
    sev_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e", "info": "#8b8d98"}

    vuln_chips = ""
    for v in d["vulns"][:8]:
        color = sev_colors.get(v["sev"], "#8b8d98")
        desc_attr = html.escape(v["desc"], quote=True) if v["desc"] else ""
        vuln_chips += (
            f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(v["cve"])}" target="_blank" '
            f'style="background:{color}22;color:{color};border:1px solid {color}44;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;text-decoration:none;white-space:nowrap" '
            f'title="{desc_attr}">{html.escape(v["cve"])} '
            f'{"(%.1f)" % v["cvss"] if v["cvss"] else ""}</a> '
        )
    if len(d["vulns"]) > 8:
        vuln_chips += f'<span style="color:#8b8d98;font-size:11px">+{len(d["vulns"]) - 8} more</span>'

    score = d["score"]
    if score >= 50:
        score_color = "#ef4444"
    elif score >= 30:
        score_color = "#f97316"
    elif score >= 10:
        score_color = "#eab308"
    else:
        score_color = "#22c55e"

    proxy_status = ""
    prx_count = proxy_pool.get_count()
    if prx_count:
        proxy_status = f'<span style="color:#22c55e">via proxy pool ({prx_count})</span>'
    else:
        proxy_status = '<span style="color:#f97316">direct (no proxies)</span>'

    port_links = ""
    alive_ports = d.get("alive_ports", [])
    if isinstance(alive_ports, str):
        alive_ports = []
    web_ports = {80, 443, 8080, 8443, 8888, 8000, 8081, 9090, 3000, 4443}
    for p in alive_ports:
        try:
            p = int(p)
        except (ValueError, TypeError):
            continue
        if p in web_ports:
            s = "https" if p in (443, 8443, 4443) else "http"
            active = " background:#3b82f6;color:#fff;" if (p == port and s == scheme) else ""
            port_links += (
                f'<a href="/api/proxy/{s}/{host}/{p}/" '
                f'style="padding:2px 8px;border-radius:4px;font-size:11px;border:1px solid #3b82f644;'
                f'text-decoration:none;color:#3b82f6;{active}" '
                f'>:{p}</a> '
            )

    return f'''<div id="iot-info-bar" style="
        position:fixed;top:0;left:0;right:0;z-index:999999;
        background:#1a1d27;border-bottom:2px solid #2a2d3a;
        font-family:system-ui,sans-serif;color:#e4e4e7;
        padding:8px 16px;font-size:13px;
        display:flex;align-items:center;gap:16px;flex-wrap:wrap;
        box-shadow:0 2px 12px rgba(0,0,0,0.5);">
        <div style="display:flex;align-items:center;gap:8px">
            <span style="font-weight:700;color:#3b82f6">{html.escape(host)}:{port}</span>
            <span style="background:#22252f;padding:2px 6px;border-radius:4px;font-size:11px">{html.escape(d["type"])}</span>
            <span style="font-size:11px;color:#8b8d98">{html.escape(d["country"])}</span>
            <span style="font-size:11px;color:#8b8d98">{html.escape(d["org"])}</span>
        </div>
        <div style="display:flex;align-items:center;gap:4px">
            <span style="font-size:11px;color:#8b8d98">Score:</span>
            <span style="font-weight:700;color:{score_color}">{score:.1f}</span>
        </div>
        <div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap">{vuln_chips if vuln_chips else '<span style="color:#8b8d98;font-size:11px">No CVEs</span>'}</div>
        <div style="display:flex;align-items:center;gap:4px">
            <span style="font-size:11px;color:#8b8d98">Ports:</span>{port_links}
        </div>
        <div style="margin-left:auto;display:flex;align-items:center;gap:8px">
            <span style="font-size:11px">{proxy_status}</span>
            <button onclick="document.getElementById('iot-info-bar').style.display='none'"
                style="background:none;border:1px solid #2a2d3a;color:#8b8d98;
                cursor:pointer;padding:2px 8px;border-radius:4px;font-size:11px">&times; hide</button>
        </div>
    </div>
    <div style="height:42px"></div>'''


def _rewrite_html(body: str, base_path: str, target_origin: str, info_bar: str = "") -> str:
    inject = info_bar
    if "<head" in body.lower():
        base_tag = f'<base href="{base_path}/">'
        body = re.sub(r"(<head[^>]*>)", rf"\1{base_tag}", body, count=1, flags=re.IGNORECASE)
    else:
        base_tag = f'<head><base href="{base_path}/"></head>'
        body = re.sub(r"(<html[^>]*>)", rf"\1{base_tag}", body, count=1, flags=re.IGNORECASE)

    if inject:
        if "<body" in body.lower():
            body = re.sub(r"(<body[^>]*>)", rf"\1{inject}", body, count=1, flags=re.IGNORECASE)
        else:
            body = inject + body

    body = body.replace(target_origin + "/", base_path + "/")
    body = body.replace(target_origin + '"', base_path + '"')
    body = body.replace(target_origin + "'", base_path + "'")
    return body


HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
})


@router.get("/{scheme}/{host}/{port:int}/{path:path}")
@router.post("/{scheme}/{host}/{port:int}/{path:path}")
async def proxy_browse(scheme: str, host: str, port: int, path: str, request: Request):
    if scheme not in ALLOWED_SCHEMES:
        return Response(content="Unsupported scheme", status_code=400)

    port_part = f":{port}" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else ""
    target_origin = f"{scheme}://{host}{port_part}"
    target_url = f"{target_origin}/{path}"

    qs = str(request.query_params)
    if qs:
        target_url += f"?{qs}"

    proxy_url = _get_proxy_url()
    base_path = f"/api/proxy/{scheme}/{host}/{port}"

    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            verify=False,
            timeout=TIMEOUT,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=5),
        ) as client:
            method = request.method.upper()
            body = await request.body() if method == "POST" else None

            resp = await client.request(
                method,
                target_url,
                content=body,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
    except httpx.TimeoutException:
        return Response(content="Proxy timeout — target unreachable", status_code=504)
    except Exception as e:
        proxy_info = f" via {proxy_url}" if proxy_url else " (direct)"
        return Response(content=f"Proxy error{proxy_info}: {e}", status_code=502)

    content_type = resp.headers.get("content-type", "")
    response_body = resp.content

    if "text/html" in content_type:
        try:
            charset = "utf-8"
            ct_lower = content_type.lower()
            if "charset=" in ct_lower:
                charset = ct_lower.split("charset=")[-1].split(";")[0].strip()
            text = response_body.decode(charset, errors="replace")

            info_bar = ""
            is_page = not path or path in ("", "/", "index.html", "index.htm")
            if is_page:
                device = _lookup_device(host)
                if device:
                    info_bar = _build_info_bar(device, host, port, scheme, base_path)

            text = _rewrite_html(text, base_path, target_origin, info_bar)
            response_body = text.encode(charset, errors="replace")
        except Exception:
            pass

    headers = {}
    for k, v in resp.headers.items():
        if k.lower() not in HOP_HEADERS:
            headers[k] = v

    headers.pop("content-security-policy", None)
    headers.pop("x-frame-options", None)

    return Response(
        content=response_body,
        status_code=resp.status_code,
        headers=headers,
        media_type=content_type.split(";")[0].strip() if content_type else None,
    )
