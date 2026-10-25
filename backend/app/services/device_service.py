from sqlalchemy import func, desc
from sqlalchemy.orm import Session, joinedload, selectinload

from app.models.device import Device, Vulnerability, ScanJob, DeviceType, Severity


def get_devices(
    db: Session,
    page: int = 1,
    per_page: int = 50,
    country_code: str | None = None,
    device_type: str | None = None,
    min_score: float | None = None,
    source: str | None = None,
    search: str | None = None,
    alive_only: bool = False,
) -> tuple[list[Device], int]:
    q = db.query(Device)

    if alive_only:
        q = q.filter(Device.is_alive == True)
    if country_code:
        q = q.filter(Device.country_code == country_code)
    if device_type:
        q = q.filter(Device.device_type == device_type)
    if min_score is not None:
        q = q.filter(Device.vulnerability_score >= min_score)
    if source:
        q = q.filter(Device.source == source)
    if search:
        q = q.filter(
            Device.ip.ilike(f"%{search}%")
            | Device.manufacturer.ilike(f"%{search}%")
            | Device.org.ilike(f"%{search}%")
        )

    total = q.count()
    items = (
        q.options(selectinload(Device.vulnerabilities))
        .order_by(desc(Device.vulnerability_score))
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return items, total


def get_device(db: Session, device_id: int) -> Device | None:
    return (
        db.query(Device)
        .options(joinedload(Device.vulnerabilities))
        .filter(Device.id == device_id)
        .first()
    )


def get_stats(db: Session) -> dict:
    total_devices = db.query(func.count(Device.id)).scalar() or 0
    total_vulns = db.query(func.count(Vulnerability.id)).scalar() or 0

    by_type = dict(
        db.query(Device.device_type, func.count(Device.id))
        .group_by(Device.device_type)
        .all()
    )
    by_country = dict(
        db.query(Device.country_code, func.count(Device.id))
        .group_by(Device.country_code)
        .all()
    )
    severity_dist = dict(
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )
    top_cves = (
        db.query(
            Vulnerability.cve_id,
            Vulnerability.severity,
            Vulnerability.cvss_score,
            func.count(Vulnerability.id).label("count"),
        )
        .group_by(Vulnerability.cve_id, Vulnerability.severity, Vulnerability.cvss_score)
        .order_by(desc("count"))
        .limit(20)
        .all()
    )
    recent_scans = (
        db.query(ScanJob).order_by(desc(ScanJob.created_at)).limit(10).all()
    )

    return {
        "total_devices": total_devices,
        "total_vulnerabilities": total_vulns,
        "devices_by_type": {k.value if hasattr(k, "value") else k: v for k, v in by_type.items()},
        "devices_by_country": by_country,
        "severity_distribution": {k.value if hasattr(k, "value") else k: v for k, v in severity_dist.items()},
        "top_cves": [
            {"cve_id": c[0], "severity": c[1].value if hasattr(c[1], "value") else c[1], "cvss_score": c[2], "count": c[3]}
            for c in top_cves
        ],
        "recent_scans": recent_scans,
    }
