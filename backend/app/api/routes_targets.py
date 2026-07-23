"""Target CRUD, scope validation, scope-doc upload, scan history, and diffing."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.diff import diff_scans
from app.core.scope import ScopeError, in_scope_ruleset, is_wildcard, parse_scope_rules, validate_domain
from app.database import get_db
from app.models import Scan, ScanStatus, Target
from app.schemas import (
    ScanDiffOut, ScanHistoryItem, ScanHistoryOut, ScopeUpload,
    ScopeValidationResult, TargetCreate, TargetOut,
)

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("/validate")
async def validate_scope(payload: TargetCreate):
    """Validate a domain/wildcard without creating anything -- used by the
    frontend to give instant feedback before the user hits 'Start Scan'."""
    try:
        normalized = validate_domain(payload.domain)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"valid": True, "normalized_domain": normalized, "is_wildcard": is_wildcard(normalized)}


@router.post("", response_model=TargetOut)
async def create_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)):
    try:
        normalized = validate_domain(payload.domain)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    target = Target(domain=normalized, is_wildcard=is_wildcard(normalized))
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get("", response_model=list[TargetOut])
async def list_targets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return result.scalars().all()


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.post("/{target_id}/scope", response_model=TargetOut)
async def upload_scope(target_id: str, payload: ScopeUpload, db: AsyncSession = Depends(get_db)):
    """Upload a program's official scope doc (plain text, one rule per line).
    Discovered assets in every *future* scan of this target are checked
    against these rules (see app.core.scope.in_scope_ruleset) instead of just
    the loose root-domain match, so out-of-scope assets get flagged instead
    of silently treated as in-scope."""
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    rules = parse_scope_rules(payload.raw_text)
    if not rules:
        raise HTTPException(status_code=400, detail="No valid scope rules found in the uploaded text.")

    target.scope_rules = rules
    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/{target_id}/scope", response_model=TargetOut)
async def clear_scope(target_id: str, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    target.scope_rules = None
    await db.commit()
    await db.refresh(target)
    return target


@router.post("/{target_id}/scope/check", response_model=list[ScopeValidationResult])
async def check_scope(target_id: str, hostnames: list[str], db: AsyncSession = Depends(get_db)):
    """Ad-hoc check of arbitrary hostnames against a target's uploaded scope
    rules -- handy for the frontend to validate a pasted asset list without
    running a full scan."""
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    return [
        ScopeValidationResult(
            hostname=h, in_scope=in_scope_ruleset(h, target.domain, target.scope_rules)
        )
        for h in hostnames
    ]


@router.get("/{target_id}/scans/history", response_model=ScanHistoryOut)
async def scan_history(target_id: str, db: AsyncSession = Depends(get_db)):
    """Chronological list of completed scans for this target, with risk
    scores -- feeds the frontend's risk-score-over-time sparkline and the
    baseline/current pickers for the diff view."""
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    result = await db.execute(
        select(Scan)
        .where(Scan.target_id == target_id, Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.created_at.asc())
    )
    scans = result.scalars().all()

    return ScanHistoryOut(
        target_id=target.id,
        domain=target.domain,
        scans=[
            ScanHistoryItem(id=s.id, created_at=s.created_at, status=s.status, risk_score=s.risk_score)
            for s in scans
        ],
    )


@router.get("/{target_id}/diff", response_model=ScanDiffOut)
async def scan_diff(
    target_id: str,
    baseline_scan_id: str = Query(..., description="Earlier scan ID to diff from"),
    current_scan_id: str = Query(..., description="Later scan ID to diff to"),
    db: AsyncSession = Depends(get_db),
):
    """Compare two completed scans of the same target and return what changed
    -- the core of ongoing bug-bounty monitoring vs. one-off recon."""
    target = await db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    baseline = await db.get(Scan, baseline_scan_id)
    current = await db.get(Scan, current_scan_id)
    if baseline is None or current is None:
        raise HTTPException(status_code=404, detail="One or both scans not found")
    if baseline.target_id != target_id or current.target_id != target_id:
        raise HTTPException(status_code=400, detail="Both scans must belong to this target")
    if baseline.status != ScanStatus.COMPLETED or current.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Both scans must be completed before diffing")

    delta = await diff_scans(db, baseline, current)

    risk_delta = None
    if baseline.risk_score is not None and current.risk_score is not None:
        risk_delta = round(current.risk_score - baseline.risk_score, 1)

    return ScanDiffOut(
        target_id=target.id,
        domain=target.domain,
        baseline_scan_id=baseline.id,
        current_scan_id=current.id,
        baseline_created_at=baseline.created_at,
        current_created_at=current.created_at,
        new_subdomains=delta.new_subdomains,
        removed_subdomains=delta.removed_subdomains,
        new_endpoints=delta.new_endpoints,
        removed_endpoints=delta.removed_endpoints,
        new_technologies=delta.new_technologies,
        removed_technologies=delta.removed_technologies,
        new_takeover_candidates=delta.new_takeover_candidates,
        rotated_secrets=delta.rotated_secrets,
        baseline_risk_score=baseline.risk_score,
        current_risk_score=current.risk_score,
        risk_score_delta=risk_delta,
    )
