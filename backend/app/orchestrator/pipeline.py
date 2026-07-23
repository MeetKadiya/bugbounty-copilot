"""
The recon pipeline: a modular, ordered list of scanner stages.

Adding a new scanner = write a BaseScanner subclass + append it to STAGES.
Nothing else needs to change, which satisfies the "easy to extend" requirement.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.analyzer import analyze
from app.core.risk_score import compute_risk_score
from app.logging_config import get_logger
from app.models import (
    Confidence, Endpoint, Finding, Parameter, Scan, ScanStatus, Secret, Subdomain,
    TakeoverCandidate, Target, Technology,
)
from app.scanners.api_extractor import APIExtractorScanner
from app.scanners.dir_bruteforce import DirBruteforceScanner
from app.scanners.framework_fingerprint import FrameworkFingerprintScanner
from app.scanners.headers_tech import HeadersTechScanner
from app.scanners.host_probe import HostProbeScanner
from app.scanners.js_crawler import JSCrawlerScanner
from app.scanners.secrets_detector import SecretsDetectorScanner
from app.scanners.subdomain_enum import SubdomainEnumScanner
from app.scanners.takeover_detector import TakeoverDetectorScanner
from app.scanners.url_params import URLParamsScanner
from app.scanners.waf_cdn import WafCdnScanner
from app.core.scope import in_scope_ruleset

logger = get_logger(__name__)

# Ordered pipeline stages. Each stage name is shown to the user as live progress.
STAGES: list[tuple[str, object]] = [
    ("Enumerating subdomains", SubdomainEnumScanner()),
    ("Probing live hosts", HostProbeScanner()),
    ("Detecting WAF/CDN", WafCdnScanner()),
    ("Collecting headers & tech", HeadersTechScanner()),
    ("Discovering directories/endpoints", DirBruteforceScanner()),
    ("Crawling JavaScript & URLs", JSCrawlerScanner()),
    ("Extracting API endpoints", APIExtractorScanner()),
    ("Fingerprinting frameworks", FrameworkFingerprintScanner()),
    ("Extracting parameters", URLParamsScanner()),
    ("Scanning for secrets", SecretsDetectorScanner()),
    ("Checking for subdomain takeovers", TakeoverDetectorScanner()),
    ("Running AI analysis", None),  # handled specially, see below
]


async def run_pipeline(scan_id: str, target_domain: str, session_factory) -> None:
    """Runs the full pipeline for one scan. `session_factory` is an async context
    manager factory (e.g. AsyncSessionLocal) so this can run as a detached
    background task independent of any single request's DB session."""
    context: dict[str, Any] = {}
    total_stages = len(STAGES)

    scope_rules: list[str] | None = None
    async with session_factory() as session:  # type: AsyncSession
        scan = await session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found, aborting pipeline", scan_id)
            return
        scan.status = ScanStatus.RUNNING
        scan.started_at = dt.datetime.utcnow()
        target = await session.get(Target, scan.target_id)
        if target is not None:
            scope_rules = target.scope_rules
        await session.commit()

    try:
        for idx, (stage_label, scanner) in enumerate(STAGES, start=1):
            async with session_factory() as session:
                scan = await session.get(Scan, scan_id)
                scan.current_stage = stage_label
                scan.progress_percent = round((idx - 1) / total_stages * 100, 1)
                await session.commit()

            if scanner is not None:
                try:
                    result = await scanner.run(target_domain, context)
                    context.update(result)
                except Exception:  # noqa: BLE001
                    logger.exception("Stage '%s' failed; continuing with partial data", stage_label)
            else:
                # AI analysis stage
                ai_result = await analyze(context, target_domain)
                context["ai_summary"] = ai_result.get("summary", "")
                context["ai_findings"] = ai_result.get("findings", [])

        await _persist_results(scan_id, target_domain, context, session_factory, scope_rules)

        async with session_factory() as session:
            scan = await session.get(Scan, scan_id)
            scan.status = ScanStatus.COMPLETED
            scan.current_stage = "completed"
            scan.progress_percent = 100.0
            scan.finished_at = dt.datetime.utcnow()
            await session.commit()

    except Exception as exc:  # noqa: BLE001
        logger.exception("Pipeline failed for scan %s", scan_id)
        async with session_factory() as session:
            scan = await session.get(Scan, scan_id)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            await session.commit()


async def _persist_results(
    scan_id: str, target_domain: str, context: dict[str, Any], session_factory,
    scope_rules: list[str] | None = None,
) -> None:
    async with session_factory() as session:
        for s in context.get("subdomains", []):
            session.add(Subdomain(
                scan_id=scan_id, hostname=s["hostname"], is_alive=s.get("is_alive", False),
                status_code=s.get("status_code"), ip_addresses=s.get("ip_addresses", []),
                server_header=s.get("server_header"), title=s.get("title"),
                cdn_or_waf=s.get("cdn_or_waf"), source=s.get("source", "unknown"),
                in_scope=in_scope_ruleset(s["hostname"], target_domain, scope_rules),
            ))

        for e in context.get("endpoints", []):
            session.add(Endpoint(
                scan_id=scan_id, url=e["url"], method=e.get("method", "GET"),
                status_code=e.get("status_code"), content_type=e.get("content_type"),
                source=e.get("source", "crawler"), is_api=e.get("is_api", False),
            ))

        for p in context.get("parameters", []):
            session.add(Parameter(
                scan_id=scan_id, name=p["name"], example_url=p["example_url"],
                reflected_context=p.get("reflected_context"),
            ))

        for sec in context.get("secrets", []):
            session.add(Secret(
                scan_id=scan_id, secret_type=sec["secret_type"], source_url=sec["source_url"],
                match_redacted=sec["match_redacted"], severity=Confidence(sec["severity"]),
            ))

        for t in context.get("technologies", []):
            session.add(Technology(
                scan_id=scan_id, hostname=t["hostname"], name=t["name"],
                category=t["category"], evidence=t.get("evidence"),
            ))

        for f in context.get("ai_findings", []):
            session.add(Finding(
                scan_id=scan_id, vulnerability_class=f["vulnerability_class"],
                confidence=Confidence(f["confidence"]), related_asset=f["related_asset"],
                reasoning=f["reasoning"], recommended_next_step=f["recommended_next_step"],
            ))

        for tc in context.get("takeover_candidates", []):
            session.add(TakeoverCandidate(
                scan_id=scan_id, hostname=tc["hostname"], cname=tc["cname"],
                service=tc["service"], confidence=Confidence(tc["confidence"]),
                evidence=tc["evidence"],
            ))

        breakdown = compute_risk_score(
            alive_subdomain_count=sum(1 for s in context.get("subdomains", []) if s.get("is_alive")),
            secrets=[type("S", (), sec) for sec in context.get("secrets", [])],
            endpoints=[type("E", (), e) for e in context.get("endpoints", [])],
            technologies=context.get("technologies", []),
            findings=[type("F", (), f) for f in context.get("ai_findings", [])],
            waf_detected=bool(context.get("waf_detected")),
            takeover_candidates=[type("T", (), tc) for tc in context.get("takeover_candidates", [])],
        )
        scan = await session.get(Scan, scan_id)
        scan.risk_score = breakdown.score

        await session.commit()
