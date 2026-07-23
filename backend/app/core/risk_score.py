"""
Attack Surface Risk Score.

A transparent, explainable heuristic (0-100) -- deliberately NOT a black box --
so the researcher can see exactly why a target scored the way it did. This is
a triage aid, not a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

WEIGHTS = {
    "alive_subdomain": 0.6,
    "exposed_secret_high": 8.0,
    "exposed_secret_medium": 4.0,
    "api_endpoint": 0.8,
    "admin_or_sensitive_path": 3.0,
    "outdated_or_risky_tech": 2.5,
    "no_waf_detected": 4.0,
    "finding_high": 5.0,
    "finding_medium": 2.5,
    "finding_low": 1.0,
    "takeover_high": 12.0,
    "takeover_medium": 6.0,
    "takeover_low": 2.0,
}

SENSITIVE_PATH_HINTS = (
    "admin", "wp-admin", "phpmyadmin", "swagger", "graphql", "actuator",
    "debug", "console", "internal", ".git", ".env", "backup", "config",
)


@dataclass
class RiskBreakdown:
    score: float
    components: List[str] = field(default_factory=list)


def compute_risk_score(
    *,
    alive_subdomain_count: int,
    secrets: list,
    endpoints: list,
    technologies: list,
    findings: list,
    waf_detected: bool,
    takeover_candidates: list | None = None,
) -> RiskBreakdown:
    breakdown = RiskBreakdown(score=0.0)

    contrib = min(alive_subdomain_count * WEIGHTS["alive_subdomain"], 20)
    breakdown.score += contrib
    if alive_subdomain_count:
        breakdown.components.append(f"{alive_subdomain_count} live hosts (+{contrib:.1f})")

    high_secrets = sum(1 for s in secrets if getattr(s, "severity", None) and str(s.severity).endswith("High"))
    med_secrets = len(secrets) - high_secrets
    if high_secrets:
        breakdown.score += high_secrets * WEIGHTS["exposed_secret_high"]
        breakdown.components.append(f"{high_secrets} high-severity exposed secret(s)")
    if med_secrets:
        breakdown.score += med_secrets * WEIGHTS["exposed_secret_medium"]
        breakdown.components.append(f"{med_secrets} other exposed secret(s)")

    api_count = sum(1 for e in endpoints if getattr(e, "is_api", False))
    contrib = min(api_count * WEIGHTS["api_endpoint"], 15)
    if api_count:
        breakdown.score += contrib
        breakdown.components.append(f"{api_count} API endpoints discovered (+{contrib:.1f})")

    sensitive = sum(
        1 for e in endpoints
        if any(hint in getattr(e, "url", "").lower() for hint in SENSITIVE_PATH_HINTS)
    )
    if sensitive:
        contrib = min(sensitive * WEIGHTS["admin_or_sensitive_path"], 15)
        breakdown.score += contrib
        breakdown.components.append(f"{sensitive} sensitive/admin-style paths (+{contrib:.1f})")

    if not waf_detected:
        breakdown.score += WEIGHTS["no_waf_detected"]
        breakdown.components.append("No WAF/CDN detected in front of the target (+4.0)")

    for f in findings:
        conf = str(getattr(f, "confidence", "Low"))
        if conf.endswith("High"):
            breakdown.score += WEIGHTS["finding_high"]
        elif conf.endswith("Medium"):
            breakdown.score += WEIGHTS["finding_medium"]
        else:
            breakdown.score += WEIGHTS["finding_low"]
    if findings:
        breakdown.components.append(f"{len(findings)} AI-flagged potential issues")

    for tc in takeover_candidates or []:
        conf = str(getattr(tc, "confidence", "Low"))
        if conf.endswith("High"):
            breakdown.score += WEIGHTS["takeover_high"]
        elif conf.endswith("Medium"):
            breakdown.score += WEIGHTS["takeover_medium"]
        else:
            breakdown.score += WEIGHTS["takeover_low"]
    if takeover_candidates:
        breakdown.components.append(
            f"{len(takeover_candidates)} potential subdomain takeover(s) -- review immediately"
        )

    breakdown.score = round(min(breakdown.score, 100.0), 1)
    return breakdown
