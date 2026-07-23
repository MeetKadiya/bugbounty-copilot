"""
AI analysis layer.

Calls the Anthropic API to turn raw recon data into prioritized, explained
vulnerability *suggestions*. If no API key is configured, falls back to a
transparent rule-based heuristic engine so the product still works end-to-end
without any external dependency -- useful for demos, CI, and offline use.

Nothing in this module executes payloads or makes exploit attempts; it only
reasons over data already collected by the scanners.
"""
from __future__ import annotations

import json
from typing import Any

from app.ai.prompts import ANALYSIS_USER_TEMPLATE, SYSTEM_PROMPT
from app.config import get_settings
from app.logging_config import get_logger

logger = get_logger(__name__)
settings = get_settings()


async def analyze(context: dict[str, Any], target_domain: str) -> dict[str, Any]:
    if settings.ANTHROPIC_API_KEY:
        try:
            return await _analyze_with_claude(context, target_domain)
        except Exception:  # noqa: BLE001
            logger.exception("Claude analysis failed, falling back to heuristic engine")
    return _analyze_with_heuristics(context, target_domain)


async def _analyze_with_claude(context: dict[str, Any], target_domain: str) -> dict[str, Any]:
    import anthropic

    client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)

    endpoints = context.get("endpoints", [])
    params = context.get("parameters", [])
    secrets = context.get("secrets", [])
    technologies = context.get("technologies", [])
    alive = [s for s in context.get("subdomains", []) if s.get("is_alive")]

    prompt = ANALYSIS_USER_TEMPLATE.format(
        target_domain=target_domain,
        alive_count=len(alive),
        endpoint_count=len(endpoints),
        api_count=sum(1 for e in endpoints if e.get("is_api")),
        param_count=len(params),
        secret_count=len(secrets),
        tech_summary=", ".join(sorted({t["name"] for t in technologies})) or "none detected",
        waf_detected=context.get("waf_detected", False),
        sample_endpoints="\n".join(e["url"] for e in endpoints[:40]),
        sample_params="\n".join(f"{p['name']} (hint: {p.get('reflected_context')})" for p in params[:30]),
        sample_secrets="\n".join(f"{s['secret_type']} in {s['source_url']}" for s in secrets[:20]),
    )

    response = await client.messages.create(
        model=settings.AI_MODEL,
        max_tokens=settings.AI_MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text")
    text = text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(text)


def _analyze_with_heuristics(context: dict[str, Any], target_domain: str) -> dict[str, Any]:
    """Deterministic, explainable rule engine used when no AI key is configured."""
    endpoints = context.get("endpoints", [])
    params = context.get("parameters", [])
    secrets = context.get("secrets", [])
    alive = [s for s in context.get("subdomains", []) if s.get("is_alive")]

    findings: list[dict] = []

    for p in params:
        hint = p.get("reflected_context")
        if not hint:
            continue
        vuln_class = hint.split("/")[0]
        findings.append({
            "vulnerability_class": vuln_class,
            "confidence": "Medium",
            "related_asset": p["example_url"],
            "reasoning": f"Parameter '{p['name']}' commonly correlates with {hint} issues based on naming conventions.",
            "recommended_next_step": f"Manually test parameter '{p['name']}' with benign, non-destructive inputs "
                                      f"(e.g. a second authorized test account for IDOR, or a harmless marker string "
                                      f"for reflection) and observe the response -- do not attempt exploitation.",
        })

    for e in endpoints:
        url = e["url"].lower()
        if e.get("is_api") and ("graphql" in url or "swagger" in url or "openapi" in url):
            findings.append({
                "vulnerability_class": "CORS/Authorization Misconfiguration",
                "confidence": "Medium",
                "related_asset": e["url"],
                "reasoning": "Exposed API schema/introspection endpoints often reveal undocumented "
                              "operations and broaden the effective attack surface.",
                "recommended_next_step": "Manually review the exposed schema for sensitive operations and "
                                          "check whether authorization is enforced per-field/per-mutation.",
            })
        if "admin" in url or "console" in url or "actuator" in url:
            findings.append({
                "vulnerability_class": "Broken Access Control",
                "confidence": "Low",
                "related_asset": e["url"],
                "reasoning": "Administrative/management interfaces exposed publicly increase risk if "
                              "authentication or authorization is weak.",
                "recommended_next_step": "Manually verify this path requires proper authentication and that "
                                          "no default credentials are in use; do not attempt brute-force login.",
            })
        if url.endswith(".env") or ".git" in url or "backup" in url:
            findings.append({
                "vulnerability_class": "Sensitive Data Exposure",
                "confidence": "High",
                "related_asset": e["url"],
                "reasoning": "Configuration/backup/version-control artifacts are frequently mistakenly "
                              "left publicly accessible and can leak credentials or source code.",
                "recommended_next_step": "Manually confirm the file is accessible and report it to the "
                                          "program immediately if it contains secrets -- do not download/exfiltrate bulk data.",
            })

    for s in secrets:
        findings.append({
            "vulnerability_class": "Hardcoded Secret Exposure",
            "confidence": "High" if s["severity"] == "High" else "Medium",
            "related_asset": s["source_url"],
            "reasoning": f"A pattern matching '{s['secret_type']}' was found embedded in client-side JavaScript.",
            "recommended_next_step": "Manually confirm the secret is live/valid using read-only checks only, "
                                      "then report responsibly through the program's disclosure channel.",
        })

    # de-dup and cap
    seen = set()
    deduped = []
    for f in findings:
        key = (f["vulnerability_class"], f["related_asset"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    deduped.sort(key=lambda f: {"High": 0, "Medium": 1, "Low": 2}[f["confidence"]])
    deduped = deduped[:15]

    summary = (
        f"{target_domain} exposes {len(alive)} live host(s) and {len(endpoints)} discovered endpoint(s). "
        f"The heuristic engine flagged {len(deduped)} plausible area(s) worth manual review"
        + (f", including {len(secrets)} potential exposed secret(s)" if secrets else "")
        + ". This is a triage aid only -- every item requires manual human verification before reporting."
    )

    return {"summary": summary, "findings": deduped}
