"""Collect HTTP response headers and derive a basic technology fingerprint."""
from __future__ import annotations

from typing import Any

from app.scanners.base import BaseScanner

HEADER_TECH_SIGNATURES = {
    "x-powered-by": ("header-value", "language/framework"),
    "server": ("header-value", "server"),
    "x-drupal-cache": ("Drupal", "cms"),
    "x-generator": ("header-value", "cms"),
    "x-aspnet-version": ("ASP.NET", "framework"),
    "x-runtime": ("Ruby on Rails", "framework"),
    "x-sourcemap": ("JS Sourcemap Enabled", "misc"),
}

COOKIE_TECH_SIGNATURES = {
    "laravel_session": ("Laravel", "framework"),
    "phpsessid": ("PHP", "language"),
    "connect.sid": ("Express/Node.js", "framework"),
    "jsessionid": ("Java/JSP", "language"),
    "csrftoken": ("Django", "framework"),
}


class HeadersTechScanner(BaseScanner):
    name = "headers_tech"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        technologies: list[dict] = []

        for sub in context.get("subdomains", []):
            headers = {k.lower(): v for k, v in sub.get("_headers", {}).items()}
            host = sub["hostname"]

            for header_name, (label, category) in HEADER_TECH_SIGNATURES.items():
                if header_name in headers:
                    value = headers[header_name] if label == "header-value" else label
                    technologies.append({
                        "hostname": host, "name": value, "category": category,
                        "evidence": f"Header '{header_name}: {headers[header_name]}'",
                    })

            set_cookie = headers.get("set-cookie", "").lower()
            for cookie_hint, (label, category) in COOKIE_TECH_SIGNATURES.items():
                if cookie_hint in set_cookie:
                    technologies.append({
                        "hostname": host, "name": label, "category": category,
                        "evidence": f"Cookie hint '{cookie_hint}'",
                    })

            if sub.get("server_header"):
                technologies.append({
                    "hostname": host, "name": sub["server_header"], "category": "server",
                    "evidence": "Server header",
                })

        self.logger.info("Fingerprinted %d technology signals", len(technologies))
        return {"technologies": technologies}
