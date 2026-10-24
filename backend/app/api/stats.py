from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.device import StatsOut
from app.services.device_service import get_stats

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=StatsOut)
def dashboard_stats(db: Session = Depends(get_db)):
    return get_stats(db)
