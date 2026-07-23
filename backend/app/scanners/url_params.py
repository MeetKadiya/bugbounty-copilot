"""Extract query parameters from crawled URLs -- useful for XSS/IDOR/SSRF triage."""
from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

from app.scanners.base import BaseScanner

# Parameter names that historically correlate with certain vuln classes.
# Purely a hint for the AI layer / researcher -- never a verdict.
SUSPECT_PARAM_HINTS = {
    "url": "SSRF/Open Redirect", "redirect": "Open Redirect", "next": "Open Redirect",
    "return": "Open Redirect", "callback": "SSRF", "target": "SSRF",
    "id": "IDOR", "user_id": "IDOR", "uid": "IDOR", "account": "IDOR",
    "q": "XSS", "search": "XSS", "query": "XSS", "keyword": "XSS",
    "file": "LFI/Path Traversal", "path": "LFI/Path Traversal", "template": "SSTI",
    "xml": "XXE", "data": "XXE/Deserialization",
}


class URLParamsScanner(BaseScanner):
    name = "url_params"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        parameters: dict[str, dict] = {}

        for endpoint in context.get("endpoints", []):
            url = endpoint.get("url", "")
            query = parse_qs(urlparse(url).query)
            for name in query:
                key = name.lower()
                if key not in parameters:
                    parameters[key] = {
                        "name": name,
                        "example_url": url,
                        "reflected_context": SUSPECT_PARAM_HINTS.get(key),
                    }

        self.logger.info("Extracted %d unique parameters", len(parameters))
        return {"parameters": list(parameters.values())}
