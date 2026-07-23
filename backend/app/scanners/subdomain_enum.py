"""
Subdomain enumeration.

Tries real tools first (subfinder, assetfinder), then always supplements with
two pure-Python passive sources that need no binaries at all:
  1. crt.sh certificate-transparency search (passive, zero requests to target)
  2. a small built-in wordlist brute-force resolved via DNS (only if
     ALLOW_ACTIVE_RECON is enabled)
Results are de-duplicated and scope-checked before being returned.
"""
from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from typing import Any

import httpx

from app.config import get_settings
from app.core.scope import base_domain, in_scope
from app.scanners.base import BaseScanner
from app.utils.subprocess_utils import run_tool, tool_available

settings = get_settings()

DEFAULT_WORDLIST = [
    "www", "api", "dev", "staging", "test", "admin", "portal", "app", "mail",
    "vpn", "beta", "internal", "m", "mobile", "cdn", "static", "assets",
    "blog", "shop", "store", "support", "help", "docs", "status", "git",
    "gitlab", "jenkins", "ci", "cd", "sso", "auth", "login", "secure",
    "payments", "billing", "dashboard", "console", "grafana", "kibana",
    "prometheus", "s3", "cloud", "ns1", "ns2", "smtp", "imap", "ftp",
    "webmail", "demo", "sandbox", "uat", "qa", "preprod", "prod", "old",
]


class SubdomainEnumScanner(BaseScanner):
    name = "subdomain_enum"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        root = base_domain(target_domain)
        found: dict[str, str] = {}  # hostname -> source

        # 1-3. subfinder, assetfinder, and the crt.sh passive CT-log lookup
        # are all independent sources, so run them concurrently instead of
        # sequentially -- each external tool call can take up to
        # EXTERNAL_TOOL_TIMEOUT_SECONDS, and there's no reason to pay that
        # cost three times in a row.
        async def run_subfinder() -> None:
            result = await run_tool(["subfinder", "-d", root, "-silent", "-json"], timeout=settings.EXTERNAL_TOOL_TIMEOUT_SECONDS)
            if result.ok:
                for line in result.stdout.splitlines():
                    try:
                        host = json.loads(line).get("host")
                        if host:
                            found[host] = "subfinder"
                    except json.JSONDecodeError:
                        continue

        async def run_assetfinder() -> None:
            result = await run_tool(["assetfinder", "--subs-only", root], timeout=settings.EXTERNAL_TOOL_TIMEOUT_SECONDS)
            if result.ok:
                for line in result.stdout.splitlines():
                    host = line.strip()
                    if host:
                        found.setdefault(host, "assetfinder")

        async def run_crtsh() -> None:
            try:
                async with httpx.AsyncClient(timeout=15, verify=False) as client:
                    resp = await client.get(f"https://crt.sh/?q=%25.{root}&output=json")
                    if resp.status_code == 200:
                        for entry in resp.json():
                            for name in entry.get("name_value", "").split("\n"):
                                name = name.strip().lower().lstrip("*.")
                                if name:
                                    found.setdefault(name, "crt.sh")
            except Exception as exc:  # noqa: BLE001
                self.logger.info("crt.sh lookup unavailable: %s", exc)

        await asyncio.gather(run_subfinder(), run_assetfinder(), run_crtsh())

        # 4. lightweight DNS brute-force fallback (only if no external tools ran and active recon allowed)
        if settings.ALLOW_ACTIVE_RECON and not tool_available("subfinder") and not tool_available("assetfinder"):
            wordlist_path = Path(settings.SUBDOMAIN_WORDLIST)
            words = DEFAULT_WORDLIST
            if wordlist_path.exists():
                words = [w.strip() for w in wordlist_path.read_text().splitlines() if w.strip()]

            resolved = await self._brute_resolve(root, words)
            for host in resolved:
                found.setdefault(host, "bruteforce")

        # Scope filter + always include the root domain itself
        found.setdefault(root, "seed")
        in_scope_hosts = {h: src for h, src in found.items() if in_scope(h, target_domain)}

        subdomains = [{"hostname": h, "source": src} for h, src in sorted(in_scope_hosts.items())]
        self.logger.info("Discovered %d in-scope subdomains for %s", len(subdomains), root)
        return {"subdomains": subdomains}

    @staticmethod
    async def _brute_resolve(root: str, words: list[str]) -> list[str]:
        loop = asyncio.get_event_loop()
        sem = asyncio.Semaphore(50)

        async def resolve_one(word: str) -> str | None:
            host = f"{word}.{root}"
            async with sem:
                try:
                    await loop.run_in_executor(None, socket.gethostbyname, host)
                    return host
                except socket.gaierror:
                    return None

        results = await asyncio.gather(*[resolve_one(w) for w in words])
        return [h for h in results if h]
