"""Scan lifecycle endpoints: start, list, status/progress, cancel, full report."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.scope import ScopeError, is_wildcard, validate_domain
from app.database import get_db
from app.models import (
    Endpoint, Finding, Parameter, Scan, ScanStatus, Secret, Subdomain, TakeoverCandidate,
    Target, Technology,
)
from app.orchestrator.task_queue import cancel_scan, enqueue_scan, is_running
from app.schemas import (
    EndpointOut, FindingOut, ParameterOut, ScanCreate, ScanFullReport,
    ScanOut, SecretOut, SubdomainOut, TakeoverCandidateOut, TechnologyOut,
)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=201)
async def start_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)):
    try:
        normalized = validate_domain(payload.domain)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result = await db.execute(select(Target).where(Target.domain == normalized))
    target = result.scalar_one_or_none()
    if target is None:
        target = Target(domain=normalized, is_wildcard=is_wildcard(normalized))
        db.add(target)
        await db.flush()

    scan = Scan(target_id=target.id)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    enqueue_scan(scan.id, normalized)
    return scan


@router.get("", response_model=list[ScanOut])
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(100))
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/{scan_id}/cancel")
async def cancel(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    cancelled = cancel_scan(scan_id)
    return {"cancelled": cancelled, "was_running": is_running(scan_id)}


@router.get("/{scan_id}/report", response_model=ScanFullReport)
async def get_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def _all(model):
        res = await db.execute(select(model).where(model.scan_id == scan_id))
        return res.scalars().all()

    subdomains = await _all(Subdomain)
    endpoints = await _all(Endpoint)
    parameters = await _all(Parameter)
    secrets = await _all(Secret)
    technologies = await _all(Technology)
    findings = await _all(Finding)
    takeover_candidates = await _all(TakeoverCandidate)

    summary = (
        f"Scan of target completed with risk score {scan.risk_score or 0}/100. "
        f"{sum(1 for s in subdomains if s.is_alive)} live hosts, {len(endpoints)} endpoints, "
        f"{len(secrets)} potential secrets, {len(findings)} AI-flagged areas for manual review."
    )
    if takeover_candidates:
        summary += f" {len(takeover_candidates)} potential subdomain takeover(s) found -- review immediately."

    return ScanFullReport(
        scan=ScanOut.model_validate(scan),
        subdomains=[SubdomainOut.model_validate(s) for s in subdomains],
        endpoints=[EndpointOut.model_validate(e) for e in endpoints],
        parameters=[ParameterOut.model_validate(p) for p in parameters],
        secrets=[SecretOut.model_validate(s) for s in secrets],
        technologies=[TechnologyOut.model_validate(t) for t in technologies],
        findings=[FindingOut.model_validate(f) for f in findings],
        takeover_candidates=[TakeoverCandidateOut.model_validate(t) for t in takeover_candidates],
        risk_score=scan.risk_score or 0.0,
        ai_summary=summary,
    )
