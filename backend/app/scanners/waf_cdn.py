"""Detect WAF/CDN presence from response headers -- passive, no active bypass attempts."""
from __future__ import annotations

from typing import Any

from app.scanners.base import BaseScanner

WAF_CDN_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "sucuri": "Sucuri",
    "incapsula": "Imperva Incapsula",
    "x-sucuri-id": "Sucuri",
    "cf-ray": "Cloudflare",
    "x-akamai": "Akamai",
    "x-cdn": "Generic CDN",
    "x-amz-cf-id": "Amazon CloudFront",
    "server: awselb": "AWS ELB",
    "x-fastly": "Fastly",
    "x-sc-cache": "SiteCore",
    "x-azure-ref": "Azure Front Door",
}


class WafCdnScanner(BaseScanner):
    name = "waf_cdn"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        for sub in context.get("subdomains", []):
            headers = {k.lower(): v.lower() for k, v in sub.get("_headers", {}).items()}
            haystack = " ".join(f"{k}:{v}" for k, v in headers.items())
            detected = None
            for signature, label in WAF_CDN_SIGNATURES.items():
                if signature in haystack:
                    detected = label
                    break
            sub["cdn_or_waf"] = detected

        detected_any = any(s.get("cdn_or_waf") for s in context.get("subdomains", []))
        self.logger.info("WAF/CDN detected: %s", detected_any)
        return {"subdomains": context.get("subdomains", []), "waf_detected": detected_any}
