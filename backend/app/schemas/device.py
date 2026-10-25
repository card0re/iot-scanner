import datetime
import re

from pydantic import BaseModel, field_validator

from app.models.device import DeviceType, Severity, ScanStatus


def _parse_pg_array(v) -> list[int] | None:
    if v is None:
        return None
    if isinstance(v, list):
        if not v:
            return []
        if all(isinstance(x, int) for x in v):
            return v
        joined = "".join(str(x) for x in v)
        return _parse_pg_array(joined)
    if isinstance(v, str):
        v = v.strip()
        if v in ("", "{}", "[]"):
            return []
        inner = v.strip("{}[]")
        return [int(x) for x in inner.split(",") if x.strip().lstrip("-").isdigit()]
    return None


class VulnerabilityOut(BaseModel):
    id: int
    cve_id: str
    severity: Severity
    cvss_score: float | None
    description: str | None
    matched_by: str | None

    model_config = {"from_attributes": True}


class DeviceOut(BaseModel):
    id: int
    ip: str
    port: int
    protocol: str | None
    banner: str | None
    device_type: DeviceType
    device_type_confidence: float | None
    manufacturer: str | None
    model: str | None
    firmware_version: str | None
    country_code: str
    city: str | None
    asn: str | None
    org: str | None
    latitude: float | None
    longitude: float | None
    vulnerability_score: float | None
    is_default_creds: bool
    is_alive: bool
    alive_ports: list[int] | None = None
    http_title: str | None = None
    last_checked: datetime.datetime | None = None
    open_ports: list[int] | None = None
    source: str

    @field_validator("alive_ports", "open_ports", mode="before")
    @classmethod
    def coerce_int_array(cls, v):
        return _parse_pg_array(v)
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    vulnerabilities: list[VulnerabilityOut] = []

    model_config = {"from_attributes": True}


class DeviceList(BaseModel):
    items: list[DeviceOut]
    total: int
    page: int
    per_page: int


class ScanJobOut(BaseModel):
    id: int
    status: ScanStatus
    source: str
    query: str | None
    country_code: str | None
    devices_found: int
    vulns_found: int
    error_message: str | None
    started_at: datetime.datetime | None
    finished_at: datetime.datetime | None
    created_at: datetime.datetime

    model_config = {"from_attributes": True}


class StatsOut(BaseModel):
    total_devices: int
    total_vulnerabilities: int
    devices_by_type: dict[str, int]
    devices_by_country: dict[str, int]
    severity_distribution: dict[str, int]
    top_cves: list[dict]
    recent_scans: list[ScanJobOut]


class ScanRequest(BaseModel):
    source: str = "shodan"
    country_code: str = "IR"
    query: str | None = None
