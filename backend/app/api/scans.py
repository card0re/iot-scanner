import threading
import time
import datetime
import socket
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db, SessionLocal
from app.collector.scheduler import run_collection
from app.collector import proxy_pool
from app.models.device import ScanJob, ScanStatus, Device, Vulnerability
from app.schemas.device import ScanJobOut, ScanRequest
from app.config import settings

router = APIRouter(prefix="/scans", tags=["scans"])

scan_log: list[dict] = []
scan_active = False


def _append_log(msg: str, level: str = "info"):
    scan_log.append({
        "time": datetime.datetime.now(datetime.UTC).isoformat(),
        "message": msg,
        "level": level,
    })
    if len(scan_log) > 200:
        scan_log.pop(0)


@router.get("", response_model=list[ScanJobOut])
def list_scans(limit: int = 20, db: Session = Depends(get_db)):
    return db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit).all()


@router.get("/status")
def scan_status(db: Session = Depends(get_db)):
    running_jobs = (
        db.query(ScanJob)
        .filter(ScanJob.status == ScanStatus.RUNNING)
        .count()
    )
    latest = (
        db.query(ScanJob)
        .order_by(desc(ScanJob.created_at))
        .first()
    )
    total_devices = db.query(Device).count()
    total_vulns = db.query(Vulnerability).count()

    return {
        "active": scan_active or running_jobs > 0,
        "running_jobs": running_jobs,
        "total_devices": total_devices,
        "total_vulns": total_vulns,
        "latest_job": {
            "id": latest.id,
            "status": latest.status.value,
            "source": latest.source,
            "devices_found": latest.devices_found,
            "vulns_found": latest.vulns_found,
            "started_at": latest.started_at.isoformat() if latest.started_at else None,
            "finished_at": latest.finished_at.isoformat() if latest.finished_at else None,
        } if latest else None,
        "log": scan_log[-30:],
    }


@router.post("/trigger", response_model=dict)
def trigger_scan(req: ScanRequest, db: Session = Depends(get_db)):
    global scan_active
    if scan_active:
        return {"status": "already_running", "message": "A scan is already in progress"}

    def _run():
        global scan_active
        scan_active = True
        scan_log.clear()
        _append_log("Scan started — collecting IoT data from Shodan & Censys")
        try:
            with SessionLocal() as session:
                run_collection(session)
            _append_log("Scan completed successfully", "success")
        except Exception as e:
            _append_log(f"Scan failed: {e}", "error")
        finally:
            scan_active = False

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return {"status": "started", "message": "Collection job triggered in background"}


class ProxyAdd(BaseModel):
    proxies: list[str] = []
    strategy: str | None = None


class ProxyRemove(BaseModel):
    url: str


class ProxyTest(BaseModel):
    url: str = ""


@router.get("/proxy")
def get_proxy():
    return {
        "proxies": proxy_pool.get_all(),
        "count": proxy_pool.get_count(),
        "strategy": proxy_pool.get_strategy(),
    }


@router.post("/proxy")
def add_proxies(body: ProxyAdd):
    if body.strategy:
        proxy_pool.set_strategy(body.strategy)
    added = proxy_pool.add_proxies(body.proxies)
    return {
        "status": "ok",
        "added": added,
        "total": proxy_pool.get_count(),
        "strategy": proxy_pool.get_strategy(),
    }


@router.post("/proxy/file")
async def upload_proxy_file(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8", errors="ignore")
    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
    added = proxy_pool.add_proxies(lines)
    return {
        "status": "ok",
        "added": added,
        "total": proxy_pool.get_count(),
        "parsed_lines": len(lines),
    }


@router.delete("/proxy")
def remove_proxy(body: ProxyRemove):
    removed = proxy_pool.remove_proxy(body.url)
    return {"status": "ok", "removed": removed, "total": proxy_pool.get_count()}


@router.delete("/proxy/all")
def clear_proxies():
    proxy_pool.clear_all()
    return {"status": "ok", "total": 0}


@router.post("/proxy/test")
def test_proxy(body: ProxyTest):
    url = body.url.strip()
    if not url:
        prx = proxy_pool.next_proxy()
        if not prx:
            return {"status": "error", "message": "No proxies in pool"}
        url = prx["url"]

    p = urlparse(url)
    scheme = (p.scheme or "").lower()

    if scheme.startswith("socks"):
        try:
            import socks as socks_lib
            stype = socks_lib.SOCKS5 if "5" in scheme else socks_lib.SOCKS4
            s = socks_lib.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(stype, p.hostname, p.port,
                        username=p.username, password=p.password)
            s.settimeout(6)
            s.connect(("1.1.1.1", 80))
            s.close()
            proxy_pool.mark_proxy(url, True)
            return {"status": "ok", "message": f"SOCKS OK — {p.hostname}:{p.port}", "proxy": url}
        except Exception as e:
            proxy_pool.mark_proxy(url, False)
            return {"status": "error", "message": str(e), "proxy": url}
    else:
        try:
            import httpx
            r = httpx.get("http://httpbin.org/ip", timeout=6, proxy=url)
            ip_addr = r.json().get("origin", "?")
            proxy_pool.mark_proxy(url, True)
            return {"status": "ok", "message": f"HTTP OK — exit IP: {ip_addr}", "proxy": url}
        except Exception as e:
            proxy_pool.mark_proxy(url, False)
            return {"status": "error", "message": str(e), "proxy": url}


@router.post("/proxy/test-all")
def test_all_proxies():
    results = []
    for prx in proxy_pool.get_all():
        res = test_proxy(ProxyTest(url=prx["url"]))
        results.append(res)
    alive = sum(1 for r in results if r.get("status") == "ok")
    return {"results": results, "alive": alive, "total": len(results)}
