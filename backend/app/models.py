"""SQLAlchemy ORM models."""
from __future__ import annotations

import datetime as dt
import enum
import uuid
from typing import List, Optional

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Confidence(str, enum.Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    is_wildcard: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    # Optional program scope rules uploaded by the researcher, e.g.
    # ["*.example.com", "api.example.com", "!internal.example.com"].
    # Discovered assets are checked against this list when present so
    # out-of-scope findings can be flagged/excluded instead of silently
    # treated as in-scope.
    scope_rules: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=None)

    scans: Mapped[List["Scan"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"))
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    current_stage: Mapped[str] = mapped_column(String(64), default="queued")
    progress_percent: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    target: Mapped[Target] = relationship(back_populates="scans")
    subdomains: Mapped[List["Subdomain"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    endpoints: Mapped[List["Endpoint"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    parameters: Mapped[List["Parameter"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    secrets: Mapped[List["Secret"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    technologies: Mapped[List["Technology"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    takeover_candidates: Mapped[List["TakeoverCandidate"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    is_alive: Mapped[bool] = mapped_column(default=False)
    status_code: Mapped[Optional[int]] = mapped_column(nullable=True)
    ip_addresses: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    server_header: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    cdn_or_waf: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="bruteforce")
    in_scope: Mapped[bool] = mapped_column(default=True)

    scan: Mapped[Scan] = relationship(back_populates="subdomains")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    url: Mapped[str] = mapped_column(String(2048))
    method: Mapped[str] = mapped_column(String(10), default="GET")
    status_code: Mapped[Optional[int]] = mapped_column(nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="crawler")  # katana/gau/js/bruteforce
    is_api: Mapped[bool] = mapped_column(default=False)

    scan: Mapped[Scan] = relationship(back_populates="endpoints")


class Parameter(Base):
    __tablename__ = "parameters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    name: Mapped[str] = mapped_column(String(255), index=True)
    example_url: Mapped[str] = mapped_column(String(2048))
    reflected_context: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)  # heuristic only

    scan: Mapped[Scan] = relationship(back_populates="parameters")


class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    secret_type: Mapped[str] = mapped_column(String(128))
    source_url: Mapped[str] = mapped_column(String(2048))
    match_redacted: Mapped[str] = mapped_column(String(500))
    severity: Mapped[Confidence] = mapped_column(Enum(Confidence), default=Confidence.MEDIUM)

    scan: Mapped[Scan] = relationship(back_populates="secrets")


class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    hostname: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(128))  # server, framework, waf, cdn, language, cms...
    evidence: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="technologies")


class TakeoverCandidate(Base):
    """A subdomain whose CNAME points at a de-provisioned/unclaimed cloud
    resource -- a passive signal only, never auto-claimed or exploited."""

    __tablename__ = "takeover_candidates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    cname: Mapped[str] = mapped_column(String(500))
    service: Mapped[str] = mapped_column(String(128))
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence), default=Confidence.LOW)
    evidence: Mapped[str] = mapped_column(Text)

    scan: Mapped["Scan"] = relationship(back_populates="takeover_candidates")


class Finding(Base):
    """AI-generated vulnerability *suggestion* (never confirmed, never exploited)."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"))
    vulnerability_class: Mapped[str] = mapped_column(String(64))  # IDOR, XSS, SSRF, SQLi, ...
    confidence: Mapped[Confidence] = mapped_column(Enum(Confidence), default=Confidence.MEDIUM)
    related_asset: Mapped[str] = mapped_column(String(2048))
    reasoning: Mapped[str] = mapped_column(Text)
    recommended_next_step: Mapped[str] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")
