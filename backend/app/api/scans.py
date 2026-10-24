import threading
import time
import datetime
import socket
from urllib.parse import urlparse

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db, SessionLocal
from app.collector.scheduler import run_collection
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


class ProxyUpdate(BaseModel):
    proxy_url: str = ""


@router.get("/proxy")
def get_proxy():
    url = settings.proxy_url
    return {
        "proxy_url": url,
        "configured": bool(url),
    }


@router.post("/proxy")
def set_proxy(body: ProxyUpdate):
    settings.proxy_url = body.proxy_url.strip()
    return {"status": "ok", "proxy_url": settings.proxy_url}


@router.post("/proxy/test")
def test_proxy(body: ProxyUpdate):
    url = body.proxy_url.strip()
    if not url:
        return {"status": "error", "message": "No proxy URL provided"}

    p = urlparse(url)
    scheme = (p.scheme or "").lower()

    if scheme.startswith("socks"):
        try:
            import socks
            stype = socks.SOCKS5 if "5" in scheme else socks.SOCKS4
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(stype, p.hostname, p.port,
                        username=p.username, password=p.password)
            s.settimeout(6)
            s.connect(("1.1.1.1", 80))
            s.close()
            return {"status": "ok", "message": f"SOCKS proxy reachable via {p.hostname}:{p.port}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    else:
        try:
            import httpx
            r = httpx.get("http://httpbin.org/ip", timeout=6, proxy=url)
            ip = r.json().get("origin", "?")
            return {"status": "ok", "message": f"HTTP proxy working — exit IP: {ip}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
