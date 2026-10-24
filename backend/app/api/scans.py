import threading
import time
import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db, SessionLocal
from app.collector.scheduler import run_collection
from app.models.device import ScanJob, ScanStatus, Device, Vulnerability
from app.schemas.device import ScanJobOut, ScanRequest

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
