"""
Historical diffing.

Compares two completed scans of the same target to surface what changed
between recon runs -- new subdomains, new endpoints, rotated secrets, tech
stack changes, and any new takeover candidates. This is the core of ongoing
bug-bounty monitoring (recurring scans) as opposed to one-off recon: run a
scan today, run it again next week, and get an actionable delta instead of
having to eyeball two full reports side by side.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Endpoint, Scan, Secret, Subdomain, TakeoverCandidate, Technology


@dataclass
class ScanDiff:
    new_subdomains: list[str] = field(default_factory=list)
    removed_subdomains: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)
    new_technologies: list[str] = field(default_factory=list)
    removed_technologies: list[str] = field(default_factory=list)
    new_takeover_candidates: list[str] = field(default_factory=list)
    rotated_secrets: list[str] = field(default_factory=list)


async def _hostnames(db: AsyncSession, scan_id: str) -> set[str]:
    res = await db.execute(select(Subdomain.hostname).where(Subdomain.scan_id == scan_id))
    return {row[0] for row in res.all()}


async def _endpoint_urls(db: AsyncSession, scan_id: str) -> set[str]:
    res = await db.execute(select(Endpoint.url).where(Endpoint.scan_id == scan_id))
    return {row[0] for row in res.all()}


async def _tech_labels(db: AsyncSession, scan_id: str) -> set[str]:
    res = await db.execute(
        select(Technology.hostname, Technology.name).where(Technology.scan_id == scan_id)
    )
    return {f"{hostname}: {name}" for hostname, name in res.all()}


async def _takeover_hostnames(db: AsyncSession, scan_id: str) -> set[str]:
    res = await db.execute(select(TakeoverCandidate.hostname).where(TakeoverCandidate.scan_id == scan_id))
    return {row[0] for row in res.all()}


async def _secret_map(db: AsyncSession, scan_id: str) -> dict[str, str]:
    """source_url -> redacted match string, used to detect rotation (same URL,
    different secret value) rather than just "still present"."""
    res = await db.execute(select(Secret.source_url, Secret.match_redacted).where(Secret.scan_id == scan_id))
    return {url: redacted for url, redacted in res.all()}


async def diff_scans(db: AsyncSession, baseline: Scan, current: Scan) -> ScanDiff:
    """Compute the delta between two completed scans of the same target.
    `baseline` should be the earlier scan, `current` the later one."""
    diff = ScanDiff()

    baseline_hosts = await _hostnames(db, baseline.id)
    current_hosts = await _hostnames(db, current.id)
    diff.new_subdomains = sorted(current_hosts - baseline_hosts)
    diff.removed_subdomains = sorted(baseline_hosts - current_hosts)

    baseline_endpoints = await _endpoint_urls(db, baseline.id)
    current_endpoints = await _endpoint_urls(db, current.id)
    diff.new_endpoints = sorted(current_endpoints - baseline_endpoints)
    diff.removed_endpoints = sorted(baseline_endpoints - current_endpoints)

    baseline_tech = await _tech_labels(db, baseline.id)
    current_tech = await _tech_labels(db, current.id)
    diff.new_technologies = sorted(current_tech - baseline_tech)
    diff.removed_technologies = sorted(baseline_tech - current_tech)

    baseline_takeovers = await _takeover_hostnames(db, baseline.id)
    current_takeovers = await _takeover_hostnames(db, current.id)
    diff.new_takeover_candidates = sorted(current_takeovers - baseline_takeovers)

    baseline_secrets = await _secret_map(db, baseline.id)
    current_secrets = await _secret_map(db, current.id)
    diff.rotated_secrets = sorted(
        url for url, redacted in current_secrets.items()
        if url in baseline_secrets and baseline_secrets[url] != redacted
    )

    return diff
