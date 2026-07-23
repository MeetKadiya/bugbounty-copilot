"""Probe which discovered subdomains are actually alive (httpx-style)."""
from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

import httpx

from app.config import get_settings
from app.scanners.base import BaseScanner
from app.utils.http_client import get_client

settings = get_settings()
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class HostProbeScanner(BaseScanner):
    name = "host_probe"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        subdomains = context.get("subdomains", [])[: settings.MAX_SUBDOMAINS_TO_PROBE]
        hosts = [s["hostname"] for s in subdomains]

        probed: dict[str, dict] = {}

        # NOTE: we deliberately do NOT shell out to the `httpx` binary here.
        # It reads targets from stdin and run_tool() doesn't pipe stdin, so a
        # naive invocation just hangs until EXTERNAL_TOOL_TIMEOUT_SECONDS and
        # the result is unusable anyway. The pure-Python prober below gives
        # identical results with zero external dependencies and no wasted time.

        loop = asyncio.get_event_loop()
        sem = asyncio.Semaphore(settings.MAX_CONCURRENT_REQUESTS)

        async def probe_one(client: httpx.AsyncClient, host: str) -> tuple[str, dict]:
            info = {"is_alive": False, "status_code": None, "server_header": None,
                    "title": None, "ip_addresses": []}
            async with sem:
                try:
                    ip = await loop.run_in_executor(None, socket.gethostbyname, host)
                    info["ip_addresses"] = [ip]
                except socket.gaierror:
                    return host, info

                for scheme in ("https", "http"):
                    try:
                        resp = await client.get(f"{scheme}://{host}/")
                    except Exception:  # noqa: BLE001
                        continue
                    if resp is not None:
                        info["is_alive"] = True
                        info["status_code"] = resp.status_code
                        info["server_header"] = resp.headers.get("server")
                        match = TITLE_RE.search(resp.text or "")
                        info["title"] = match.group(1).strip()[:200] if match else None
                        info["_headers"] = dict(resp.headers)
                        break
            return host, info

        async with get_client() as client:
            results = await asyncio.gather(*[probe_one(client, host) for host in hosts])
        probed = dict(results)

        for s in subdomains:
            data = probed.get(s["hostname"], {})
            s.update({k: v for k, v in data.items() if k != "_headers"})
            s["_headers"] = data.get("_headers", {})

        alive_count = sum(1 for s in subdomains if s.get("is_alive"))
        self.logger.info("%d/%d hosts alive", alive_count, len(subdomains))
        return {"subdomains": subdomains}
