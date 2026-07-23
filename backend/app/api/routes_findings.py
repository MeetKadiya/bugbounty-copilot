"""Findings-only endpoint (useful for a dedicated 'AI Recommendations' panel)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Finding, Scan
from app.schemas import FindingOut

router = APIRouter(prefix="/scans/{scan_id}/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
async def list_findings(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    return result.scalars().all()
