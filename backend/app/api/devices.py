from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.device import DeviceOut, DeviceList
from app.services.device_service import get_devices, get_device

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=DeviceList)
def list_devices(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    country_code: str | None = None,
    device_type: str | None = None,
    min_score: float | None = None,
    source: str | None = None,
    search: str | None = None,
    alive_only: bool = False,
    exploited_only: bool = False,
    db: Session = Depends(get_db),
):
    items, total = get_devices(
        db, page, per_page, country_code, device_type, min_score, source, search, alive_only, exploited_only,
    )
    return DeviceList(items=items, total=total, page=page, per_page=per_page)


@router.get("/{device_id}", response_model=DeviceOut)
def read_device(device_id: int, db: Session = Depends(get_db)):
    device = get_device(db, device_id)
    if not device:
        raise HTTPException(404, "Device not found")
    return device
