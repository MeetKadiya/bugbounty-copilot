"""
Secret detection across crawled JS / page content.

Equivalent in spirit to SecretFinder: a curated regex bank covering common
API key / token formats plus Firebase configs. Matches are redacted before
storage/display -- we only ever keep enough of the string to prove a finding
exists, never the full usable secret.
"""
from __future__ import annotations

import re
from typing import Any

from app.scanners.base import BaseScanner

# (secret_type, regex, severity)
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "High"),
    ("AWS Secret Key", re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"), "High"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "High"),
    ("Firebase Config", re.compile(r"AAAA[A-Za-z0-9_-]{7,}:[A-Za-z0-9_-]{100,}"), "High"),
    ("Firebase DB URL", re.compile(r"[a-z0-9-]+\.firebaseio\.com"), "Medium"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), "Medium"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), "High"),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "High"),
    ("Stripe Test Key", re.compile(r"sk_test_[0-9a-zA-Z]{24,}"), "Low"),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "High"),
    ("Generic API Key Assignment", re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), "Medium"),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP)? ?PRIVATE KEY-----"), "High"),
    ("Basic Auth in URL", re.compile(r"https?://[^\s/:@]+:[^\s/:@]+@[^\s/]+"), "Medium"),
]


def _redact(match_text: str) -> str:
    if len(match_text) <= 12:
        return match_text[:2] + "***"
    return match_text[:6] + "..." + match_text[-4:]


class SecretsDetectorScanner(BaseScanner):
    name = "secrets_detector"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        secrets: list[dict] = []
        js_contents: dict[str, str] = context.get("js_contents", {})

        for url, content in js_contents.items():
            for secret_type, pattern, severity in SECRET_PATTERNS:
                for match in pattern.finditer(content):
                    secrets.append({
                        "secret_type": secret_type,
                        "source_url": url,
                        "match_redacted": _redact(match.group(0)),
                        "severity": severity,
                    })

        self.logger.info("Detected %d potential secrets across %d JS files", len(secrets), len(js_contents))
        return {"secrets": secrets}
