"""Directory / endpoint discovery via a small curated wordlist.

Kept intentionally lightweight and rate-limited: this is reconnaissance
(finding what exists), never fuzzing for exploitation. Non-2xx/3xx/401/403
responses are dropped to reduce noise.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx

from app.config import get_settings
from app.core.scope import base_domain
from app.scanners.base import BaseScanner
from app.utils.http_client import get_client

settings = get_settings()

DEFAULT_PATHS = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "admin",
    "login", "api", "api/v1", "api/v2", "swagger", "swagger.json",
    "swagger-ui.html", "openapi.json", "graphql", "graphiql", ".env",
    ".git/config", "config.json", "backup.zip", "wp-admin", "wp-login.php",
    "actuator", "actuator/health", "actuator/env", "debug", "console",
    "server-status", ".well-known/openid-configuration", "manifest.json",
    "static/js", "assets/js", "uploads", "files", "docs", "status",
]

INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403}


class DirBruteforceScanner(BaseScanner):
    name = "dir_bruteforce"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        if not settings.ALLOW_ACTIVE_RECON:
            self.logger.info("Active recon disabled; skipping directory discovery.")
            return {"discovered_paths": []}

        alive_hosts = [s["hostname"] for s in context.get("subdomains", []) if s.get("is_alive")]
        # Cap host fanout for directory brute-force to keep it non-intrusive
        alive_hosts = alive_hosts[:10] or [base_domain(target_domain)]

        wordlist_path = Path(settings.DIRECTORY_WORDLIST)
        paths = DEFAULT_PATHS
        if wordlist_path.exists():
            paths = [p.strip() for p in wordlist_path.read_text().splitlines() if p.strip()]

        sem = asyncio.Semaphore(settings.MAX_CONCURRENT_REQUESTS)

        async def check_one(client: httpx.AsyncClient, base_url: str, path: str) -> dict | None:
            url = f"{base_url}/{path}"
            async with sem:
                try:
                    resp = await client.get(url)
                except Exception:  # noqa: BLE001
                    return None
            if resp is not None and resp.status_code in INTERESTING_CODES:
                return {
                    "url": url,
                    "method": "GET",
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("content-type"),
                    "source": "dir_bruteforce",
                    "is_api": "api" in path or "graphql" in path or "swagger" in path or "openapi" in path,
                }
            return None

        async with get_client() as client:
            tasks = [
                check_one(client, f"https://{host}", path)
                for host in alive_hosts
                for path in paths
            ]
            results = await asyncio.gather(*tasks)

        discovered = [r for r in results if r is not None]
        self.logger.info("Directory discovery found %d interesting paths", len(discovered))
        return {"discovered_paths": discovered}
