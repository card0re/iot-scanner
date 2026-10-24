import threading

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.collector.scheduler import run_collection
from app.models.device import ScanJob
from app.schemas.device import ScanJobOut, ScanRequest

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[ScanJobOut])
def list_scans(limit: int = 20, db: Session = Depends(get_db)):
    return db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit).all()


@router.post("/trigger", response_model=dict)
def trigger_scan(req: ScanRequest, db: Session = Depends(get_db)):
    def _run():
        with SessionLocal() as session:
            run_collection(session)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return {"status": "started", "message": "Collection job triggered in background"}
