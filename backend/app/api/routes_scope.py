"""Scope-Aware Request Firewall preview / dry-run API.

Lets a researcher (or the frontend) check whether a URL would be allowed or
blocked *without making any outbound HTTP request* -- useful for validating
scope rules before kicking off a scan. DNS resolution still happens (so the
private-IP / DNS-rebinding protection can be previewed accurately), but no
request is ever sent to the destination itself.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.scope_firewall import authorize, evaluate_static
from app.database import get_db
from app.models import Target
from app.schemas import ScopeFirewallCheckRequest, ScopeFirewallDecisionOut

router = APIRouter(prefix="/scope", tags=["scope-firewall"])


@router.post("/check", response_model=ScopeFirewallDecisionOut)
async def check_scope_firewall(payload: ScopeFirewallCheckRequest, db: AsyncSession = Depends(get_db)):
    """Dry-run the Scope Firewall against a single URL. Provide either
    `domain` directly (ad-hoc, no saved target required) or `target_id` to
    check against a saved target's domain + uploaded scope_rules."""
    domain = payload.domain
    scope_rules: list[str] | None = None

    if payload.target_id:
        target = await db.get(Target, payload.target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="Target not found")
        domain = target.domain
        scope_rules = target.scope_rules

    if not domain:
        raise HTTPException(status_code=400, detail="Provide either 'domain' or 'target_id'")

    if payload.resolve_dns:
        decision = await authorize(payload.url, domain, scope_rules)
    else:
        decision = evaluate_static(payload.url, domain, scope_rules)

    return ScopeFirewallDecisionOut(**decision.as_dict())
