import re
from urllib.parse import urlparse

from fastapi import APIRouter, Request, Response

import httpx

from app.collector import proxy_pool

router = APIRouter(prefix="/proxy", tags=["proxy"])

ALLOWED_SCHEMES = {"http", "https"}
TIMEOUT = 10


def _get_proxy_url() -> str | None:
    prx = proxy_pool.next_proxy()
    return prx["url"] if prx else None


def _rewrite_html(body: str, base_path: str, target_origin: str) -> str:
    if "<head" in body.lower():
        base_tag = f'<base href="{base_path}/">'
        body = re.sub(r"(<head[^>]*>)", rf"\1{base_tag}", body, count=1, flags=re.IGNORECASE)
    else:
        base_tag = f'<head><base href="{base_path}/"></head>'
        body = re.sub(r"(<html[^>]*>)", rf"\1{base_tag}", body, count=1, flags=re.IGNORECASE)

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
            text = _rewrite_html(text, base_path, target_origin)
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
