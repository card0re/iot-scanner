import datetime
import logging

from sqlalchemy.orm import Session

from app.collector.censys_client import CensysCollector
from app.collector.shodan_client import ShodanCollector
from app.config import settings
from app.models.device import Device, ScanJob, ScanStatus
from app.ml.classifier import DeviceClassifier
from app.ml.cve_mapper import CVEMapper
from app.ml.vulnerability_scorer import VulnerabilityScorer

logger = logging.getLogger(__name__)


def run_collection(db: Session):
    classifier = DeviceClassifier()
    scorer = VulnerabilityScorer()
    cve_mapper = CVEMapper()

    for country in settings.target_countries:
        _collect_source(db, "shodan", country, classifier, scorer, cve_mapper)
        _collect_source(db, "censys", country, classifier, scorer, cve_mapper)


def _collect_source(
    db: Session,
    source: str,
    country_code: str,
    classifier: DeviceClassifier,
    scorer: VulnerabilityScorer,
    cve_mapper: CVEMapper,
):
    job = ScanJob(
        status=ScanStatus.RUNNING,
        source=source,
        country_code=country_code,
        started_at=datetime.datetime.now(datetime.UTC),
    )
    db.add(job)
    db.commit()

    try:
        if source == "shodan":
            raw_devices = ShodanCollector().collect_country(country_code)
        else:
            raw_devices = CensysCollector().collect_country(country_code)

        devices_count = 0
        vulns_count = 0

        for raw in raw_devices:
            device = _upsert_device(db, raw)
            device_type, confidence = classifier.predict(raw)
            device.device_type = device_type
            device.device_type_confidence = confidence

            vulns = cve_mapper.map_device(raw)
            for v in vulns:
                v.device_id = device.id
                db.merge(v)
            vulns_count += len(vulns)

            device.vulnerability_score = scorer.score(device, vulns)
            devices_count += 1

        job.status = ScanStatus.COMPLETED
        job.devices_found = devices_count
        job.vulns_found = vulns_count
        job.finished_at = datetime.datetime.now(datetime.UTC)
        db.commit()
        logger.info(
            "Scan complete: source=%s country=%s devices=%d vulns=%d",
            source, country_code, devices_count, vulns_count,
        )
    except Exception as e:
        job.status = ScanStatus.FAILED
        job.error_message = str(e)[:500]
        job.finished_at = datetime.datetime.now(datetime.UTC)
        db.commit()
        logger.error("Scan failed: %s", e)


def _upsert_device(db: Session, raw: dict) -> Device:
    existing = (
        db.query(Device)
        .filter(Device.ip == raw["ip"], Device.port == raw["port"])
        .first()
    )
    if existing:
        for k, v in raw.items():
            if k not in ("source",) and v is not None:
                setattr(existing, k, v)
        return existing
    device = Device(**raw)
    db.add(device)
    db.flush()
    return device
