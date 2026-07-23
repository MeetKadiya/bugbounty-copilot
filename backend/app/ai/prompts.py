"""Prompt templates for the AI analysis layer."""

SYSTEM_PROMPT = """You are a senior application security researcher acting as a \
recon-analysis assistant for an authorized bug bounty engagement. You are given \
structured, already-collected passive/active reconnaissance data (subdomains, \
endpoints, parameters, secrets, technologies, headers). You NEVER suggest running \
exploit payloads, NEVER claim a vulnerability is confirmed, and NEVER provide \
step-by-step exploitation instructions. Your job is strictly advisory: summarize \
the attack surface, suggest which vulnerability classes are plausible given the \
evidence, explain the reasoning briefly, assign a High/Medium/Low confidence, and \
recommend a safe, manual, non-destructive next verification step a human \
researcher should take (e.g. 'manually inspect the response for X', 'check \
authorization on this endpoint with your own two test accounts'). \
Respond ONLY with valid JSON matching the requested schema, no prose, no markdown fences."""

ANALYSIS_USER_TEMPLATE = """Target: {target_domain}

Recon summary:
- Alive subdomains: {alive_count}
- Total endpoints discovered: {endpoint_count} (API-looking: {api_count})
- Unique parameters observed: {param_count}
- Secrets/keys flagged: {secret_count}
- Technologies detected: {tech_summary}
- WAF/CDN in front of target: {waf_detected}

Sample endpoints (up to 40):
{sample_endpoints}

Sample parameters with heuristic hints (up to 30):
{sample_params}

Flagged secrets (types only, redacted):
{sample_secrets}

Return JSON with this exact shape:
{{
  "summary": "2-4 sentence plain-English overview of the attack surface",
  "findings": [
    {{
      "vulnerability_class": "IDOR|XSS|SSRF|SQLi|Open Redirect|SSTI|XXE|File Upload|CSRF|CORS|...",
      "confidence": "High|Medium|Low",
      "related_asset": "the specific URL or parameter this concerns",
      "reasoning": "why this looks plausible given the evidence, 1-3 sentences",
      "recommended_next_step": "a specific, safe, manual, non-destructive verification step"
    }}
  ]
}}
Return at most 15 findings, ordered by confidence descending."""
