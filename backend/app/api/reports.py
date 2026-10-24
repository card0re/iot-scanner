from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.reports.generator import ReportGenerator

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/manufacturer", response_class=HTMLResponse)
def manufacturer_report(
    name: str = Query(..., description="Manufacturer name"),
    db: Session = Depends(get_db),
):
    gen = ReportGenerator()
    html = gen.generate_html(db, name)
    return HTMLResponse(content=html)
