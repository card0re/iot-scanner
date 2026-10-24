import datetime
import enum

from sqlalchemy import (
    Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class DeviceType(str, enum.Enum):
    CAMERA = "camera"
    ROUTER = "router"
    NAS = "nas"
    PRINTER = "printer"
    SCADA = "scada"
    DVR = "dvr"
    SMART_HOME = "smart_home"
    INDUSTRIAL = "industrial"
    UNKNOWN = "unknown"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(20))
    banner: Mapped[str | None] = mapped_column(Text)
    device_type: Mapped[DeviceType] = mapped_column(
        Enum(DeviceType), default=DeviceType.UNKNOWN
    )
    device_type_confidence: Mapped[float | None] = mapped_column(Float)
    manufacturer: Mapped[str | None] = mapped_column(String(255))
    model: Mapped[str | None] = mapped_column(String(255))
    firmware_version: Mapped[str | None] = mapped_column(String(100))
    country_code: Mapped[str] = mapped_column(String(2), index=True)
    city: Mapped[str | None] = mapped_column(String(255))
    asn: Mapped[str | None] = mapped_column(String(50))
    org: Mapped[str | None] = mapped_column(String(255))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    vulnerability_score: Mapped[float | None] = mapped_column(Float, index=True)
    is_default_creds: Mapped[bool] = mapped_column(Boolean, default=False)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    alive_ports: Mapped[list | None] = mapped_column(ARRAY(Integer))
    http_title: Mapped[str | None] = mapped_column(String(500))
    last_checked: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    open_ports: Mapped[list | None] = mapped_column(ARRAY(Integer))
    raw_data: Mapped[dict | None] = mapped_column(JSONB)
    source: Mapped[str] = mapped_column(String(20))
    first_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    cve_id: Mapped[str] = mapped_column(String(20), index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    description: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list | None] = mapped_column(ARRAY(String))
    matched_by: Mapped[str | None] = mapped_column(String(50))  # banner / cpe / version
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    device: Mapped["Device"] = relationship(back_populates="vulnerabilities")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING
    )
    source: Mapped[str] = mapped_column(String(20))
    query: Mapped[str | None] = mapped_column(Text)
    country_code: Mapped[str | None] = mapped_column(String(2))
    devices_found: Mapped[int] = mapped_column(Integer, default=0)
    vulns_found: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
