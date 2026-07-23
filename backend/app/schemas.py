"""Pydantic request/response schemas."""
from __future__ import annotations

import datetime as dt
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, field_validator

from app.models import Confidence, ScanStatus


class TargetCreate(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def strip_domain(cls, v: str) -> str:
        return v.strip().lower().rstrip("/")


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    domain: str
    is_wildcard: bool
    scope_rules: Optional[List[str]]
    created_at: dt.datetime


class ScopeUpload(BaseModel):
    """Raw text pasted/uploaded from a program's official scope doc, one rule
    per line. Parsed server-side via app.core.scope.parse_scope_rules."""
    raw_text: str


class ScopeValidationResult(BaseModel):
    hostname: str
    in_scope: bool


class ScanCreate(BaseModel):
    domain: str
    active_recon: bool = True


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target_id: str
    status: ScanStatus
    current_stage: str
    progress_percent: float
    risk_score: Optional[float]
    error_message: Optional[str]
    started_at: Optional[dt.datetime]
    finished_at: Optional[dt.datetime]
    created_at: dt.datetime


class SubdomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    hostname: str
    is_alive: bool
    status_code: Optional[int]
    ip_addresses: Optional[list]
    server_header: Optional[str]
    title: Optional[str]
    cdn_or_waf: Optional[str]
    source: str
    in_scope: bool


class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    url: str
    method: str
    status_code: Optional[int]
    content_type: Optional[str]
    source: str
    is_api: bool


class ParameterOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: str
    example_url: str
    reflected_context: Optional[str]


class SecretOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    secret_type: str
    source_url: str
    match_redacted: str
    severity: Confidence


class TechnologyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    hostname: str
    name: str
    category: str
    evidence: Optional[str]


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    vulnerability_class: str
    confidence: Confidence
    related_asset: str
    reasoning: str
    recommended_next_step: str


class TakeoverCandidateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    hostname: str
    cname: str
    service: str
    confidence: Confidence
    evidence: str


class ScanFullReport(BaseModel):
    scan: ScanOut
    subdomains: List[SubdomainOut]
    endpoints: List[EndpointOut]
    parameters: List[ParameterOut]
    secrets: List[SecretOut]
    technologies: List[TechnologyOut]
    findings: List[FindingOut]
    takeover_candidates: List[TakeoverCandidateOut]
    risk_score: float
    ai_summary: str


class ScanHistoryItem(BaseModel):
    id: str
    created_at: dt.datetime
    status: ScanStatus
    risk_score: Optional[float]


class ScanHistoryOut(BaseModel):
    target_id: str
    domain: str
    scans: List[ScanHistoryItem]


class ScanDiffOut(BaseModel):
    """Delta between two completed scans of the same target -- the core of
    the historical-diffing feature (ongoing bug bounty monitoring vs.
    one-off recon). `baseline` is the earlier scan, `current` the later one.
    """
    target_id: str
    domain: str
    baseline_scan_id: str
    current_scan_id: str
    baseline_created_at: dt.datetime
    current_created_at: dt.datetime

    new_subdomains: List[str]
    removed_subdomains: List[str]
    new_endpoints: List[str]
    removed_endpoints: List[str]
    new_technologies: List[str]
    removed_technologies: List[str]
    new_takeover_candidates: List[str]
    rotated_secrets: List[str]

    baseline_risk_score: Optional[float]
    current_risk_score: Optional[float]
    risk_score_delta: Optional[float]
