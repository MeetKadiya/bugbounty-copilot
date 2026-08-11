"""Endpoint Intelligence retrieval, with filtering -- the read API for the
Endpoint Intelligence Engine (see app.intelligence.endpoint_intelligence)."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import EndpointIntelligence, Scan
from app.schemas import EndpointIntelligenceOut

router = APIRouter(prefix="/scans/{scan_id}/endpoint-intelligence", tags=["endpoint-intelligence"])

# Maps a friendly `vulnerability_class` query value to the boolean column that
# represents it. All of these are heuristic "potential" signals, never
# confirmed vulnerabilities.
VULN_CLASS_FIELD_MAP = {
    "bola": "potential_bola",
    "idor": "potential_bola",
    "broken_function_auth": "potential_broken_function_auth",
    "broken_function_level_authorization": "potential_broken_function_auth",
    "excessive_data_exposure": "potential_excessive_data_exposure",
    "ssrf": "potential_ssrf",
    "open_redirect": "potential_open_redirect",
    "mass_assignment": "potential_mass_assignment",
    "file_upload": "potential_file_upload",
    "debug_internal": "potential_debug_internal",
}


@router.get("", response_model=List[EndpointIntelligenceOut])
async def list_endpoint_intelligence(
    scan_id: str,
    hostname: Optional[str] = Query(None, description="Filter by exact hostname"),
    method: Optional[str] = Query(None, description="Filter by HTTP method, e.g. GET"),
    category: Optional[str] = Query(None, description="Filter by endpoint category, e.g. 'API', 'Administrative'"),
    risk: Optional[str] = Query(None, description="Filter by risk level: High, Medium, Low"),
    min_confidence: Optional[float] = Query(None, ge=0, le=100, description="Minimum confidence score (0-100)"),
    parameter: Optional[str] = Query(None, description="Filter by an interesting/query parameter name"),
    vulnerability_class: Optional[str] = Query(
        None,
        description=f"Filter by potential OWASP-style concern: {', '.join(sorted(set(VULN_CLASS_FIELD_MAP)))}",
    ),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    stmt = select(EndpointIntelligence).where(EndpointIntelligence.scan_id == scan_id)
    if hostname:
        stmt = stmt.where(EndpointIntelligence.hostname == hostname)
    if method:
        stmt = stmt.where(EndpointIntelligence.method == method.upper())
    if risk:
        stmt = stmt.where(EndpointIntelligence.risk_level == risk.capitalize())
    if min_confidence is not None:
        stmt = stmt.where(EndpointIntelligence.confidence_score >= min_confidence)
    if vulnerability_class:
        field_name = VULN_CLASS_FIELD_MAP.get(vulnerability_class.strip().lower().replace(" ", "_").replace("/", "_"))
        if field_name is None:
            raise HTTPException(status_code=400, detail=f"Unknown vulnerability_class '{vulnerability_class}'")
        stmt = stmt.where(getattr(EndpointIntelligence, field_name).is_(True))

    stmt = stmt.order_by(EndpointIntelligence.confidence_score.desc())
    result = await db.execute(stmt)
    records = list(result.scalars().all())

    # `category` and `parameter` live inside JSON columns, so filter in
    # Python after the SQL-side filters have already narrowed the set.
    if category:
        records = [
            r for r in records
            if category.lower() in [c.lower() for c in (r.endpoint_categories or [])]
        ]
    if parameter:
        records = [
            r for r in records
            if parameter.lower() in [p.lower() for p in (r.query_parameters or [])]
            or any(ip.get("name", "").lower() == parameter.lower() for ip in (r.interesting_parameters or []))
        ]

    return records
