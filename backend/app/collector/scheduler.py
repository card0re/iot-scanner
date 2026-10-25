import datetime
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from sqlalchemy.orm import Session

from app.collector.shodan_client import ShodanCollector
from app.collector.verifier import verify_device
from app.config import settings
from app.models.device import Device, ScanJob, ScanStatus
from app.ml.classifier import DeviceClassifier
from app.ml.cve_mapper import CVEMapper
from app.ml.vulnerability_scorer import VulnerabilityScorer

logger = logging.getLogger(__name__)


def _emit(msg: str, level: str = "info"):
    from app.api.scans import _append_log
    _append_log(msg, level)
    logger.info(msg)


def run_collection(db: Session):
    classifier = DeviceClassifier()
    scorer = VulnerabilityScorer()
    cve_mapper = CVEMapper()

    for country in settings.target_countries:
        _collect_source(db, "shodan", country, classifier, scorer, cve_mapper)
    _emit("[CENSYS] Skipped — Censys Search API v2 decommissioned Sep 2026, Platform API requires paid org", "warn")


def _collect_source(
    db: Session,
    source: str,
    country_code: str,
    classifier: DeviceClassifier,
    scorer: VulnerabilityScorer,
    cve_mapper: CVEMapper,
):
    _emit(f"[{source.upper()}] Starting scan for country={country_code}")

    job = ScanJob(
        status=ScanStatus.RUNNING,
        source=source,
        country_code=country_code,
        started_at=datetime.datetime.now(datetime.UTC),
    )
    db.add(job)
    db.commit()

    try:
        _emit(f"[{source.upper()}] Querying API for {country_code} IoT devices...")
        raw_devices = ShodanCollector().collect_country(country_code)

        _emit(f"[{source.upper()}] Received {len(raw_devices)} raw results for {country_code}")
        _emit(f"[VERIFY] Starting liveness check on {len(raw_devices)} devices (10 parallel)...")

        devices_count = 0
        alive_count = 0
        vulns_count = 0

        VERIFY_BATCH = 10

        for batch_start in range(0, len(raw_devices), VERIFY_BATCH):
            batch = raw_devices[batch_start:batch_start + VERIFY_BATCH]

            def _verify_one(raw):
                ports = raw.get("open_ports") or [raw.get("port", 80)]
                return raw, verify_device(raw["ip"], ports)

            with ThreadPoolExecutor(max_workers=VERIFY_BATCH) as pool:
                futures = [pool.submit(_verify_one, raw) for raw in batch]
                batch_results = [f.result() for f in futures]

            for raw, check in batch_results:
                device = _upsert_device(db, raw)
                device.is_alive = check["is_alive"]
                device.alive_ports = check["alive_ports"]
                device.http_title = check["http_title"]
                device.last_checked = check["last_checked"]

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
                if check["is_alive"]:
                    alive_count += 1

            db.commit()
            last_raw, last_check = batch_results[-1]
            title_info = f' — "{last_check["http_title"]}"' if last_check["http_title"] else ""
            status = "ALIVE" if last_check["is_alive"] else "dead"
            _emit(
                f"[VERIFY] {country_code} [{devices_count}/{len(raw_devices)}] "
                f"{last_raw['ip']} → {status} ({len(last_check['alive_ports'])} ports){title_info} "
                f"| total alive: {alive_count}/{devices_count}"
            )

        job.status = ScanStatus.COMPLETED
        job.devices_found = devices_count
        job.vulns_found = vulns_count
        job.finished_at = datetime.datetime.now(datetime.UTC)
        db.commit()
        _emit(
            f"[{source.upper()}] DONE {country_code}: {devices_count} devices, "
            f"{alive_count} alive, {vulns_count} CVEs",
            "success",
        )
    except Exception as e:
        job.status = ScanStatus.FAILED
        job.error_message = str(e)[:500]
        job.finished_at = datetime.datetime.now(datetime.UTC)
        db.commit()
        _emit(f"[{source.upper()}] FAILED {country_code}: {e}", "error")


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
