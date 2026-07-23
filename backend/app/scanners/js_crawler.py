"""
Crawl pages + JavaScript files.

Tries katana/hakrawler/gau/waybackurls binaries first (best URL coverage,
including historical Wayback data), and always runs a pure-Python fallback
crawler that fetches the homepage(s), pulls <script src> tags, downloads each
JS file, and regex-extracts absolute/relative URLs referenced inside them.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.core.scope import in_scope
from app.scanners.base import BaseScanner
from app.utils.http_client import get_client
from app.utils.subprocess_utils import run_tool, tool_available

settings = get_settings()

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
URL_IN_JS_RE = re.compile(r'''["'](/[a-zA-Z0-9_\-./?=&%]{2,200}|https?://[a-zA-Z0-9_\-./?=&%]{5,300})["']''')


class JSCrawlerScanner(BaseScanner):
    name = "js_crawler"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        alive_hosts = [s["hostname"] for s in context.get("subdomains", []) if s.get("is_alive")]
        alive_hosts = alive_hosts[:10]
        js_files: set[str] = set()
        raw_urls: set[str] = set()

        # External tool paths (best-effort, optional). Every (host, tool) pair
        # is independent, so run them all concurrently instead of one at a time
        # -- otherwise a single hanging/slow tool call (up to
        # EXTERNAL_TOOL_TIMEOUT_SECONDS each) serializes the whole stage.
        async def run_one_tool(binary: str, args: list[str]) -> list[str]:
            if not tool_available(binary):
                return []
            result = await run_tool(args, timeout=settings.EXTERNAL_TOOL_TIMEOUT_SECONDS)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()] if result.ok else []

        tool_tasks = []
        for host in alive_hosts:
            base_url = f"https://{host}"
            tool_tasks.extend([
                run_one_tool("katana", ["katana", "-u", base_url, "-silent", "-jc"]),
                run_one_tool("gau", ["gau", host]),
                run_one_tool("waybackurls", ["waybackurls", host]),
                run_one_tool("hakrawler", ["hakrawler", "-url", base_url]),
            ])
        for lines in await asyncio.gather(*tool_tasks):
            for line in lines:
                raw_urls.add(line)
                if line.endswith(".js"):
                    js_files.add(line)

        # Pure-python fallback crawl (always runs, cheap and safe).
        # Homepage fetches and JS downloads are each independent, so fetch
        # them concurrently (bounded by MAX_CONCURRENT_REQUESTS) rather than
        # one host / one file at a time.
        sem = asyncio.Semaphore(settings.MAX_CONCURRENT_REQUESTS)

        async def fetch_homepage(client: httpx.AsyncClient, host: str) -> tuple[str, str] | None:
            base_url = f"https://{host}"
            async with sem:
                try:
                    resp = await client.get(base_url + "/")
                except Exception:  # noqa: BLE001
                    return None
            return (base_url, resp.text or "") if resp is not None else None

        async def fetch_js(client: httpx.AsyncClient, js_url: str) -> tuple[str, str] | None:
            async with sem:
                try:
                    resp = await client.get(js_url)
                except Exception:  # noqa: BLE001
                    return None
            if resp is not None and resp.status_code == 200:
                return js_url, resp.text
            return None

        async with get_client() as client:
            homepages = await asyncio.gather(*[fetch_homepage(client, host) for host in alive_hosts])
            for result in homepages:
                if result is None:
                    continue
                base_url, html = result
                for match in SCRIPT_SRC_RE.findall(html):
                    js_files.add(urljoin(base_url, match))

            js_files = {u for u in js_files if u.endswith(".js")}
            # Sort before truncating: slicing an unordered set is
            # non-deterministic across runs (PYTHONHASHSEED is randomized
            # per process), so which files get dropped when over the cap
            # would vary run-to-run on an identical target. Sorting first
            # makes the cap deterministic and reproducible.
            js_files = set(sorted(js_files)[: settings.MAX_JS_FILES_PER_TARGET])

            js_contents: dict[str, str] = {}
            js_results = await asyncio.gather(*[fetch_js(client, js_url) for js_url in js_files])
            for result in js_results:
                if result is None:
                    continue
                js_url, text = result
                js_contents[js_url] = text
                for found in URL_IN_JS_RE.findall(text):
                    raw_urls.add(urljoin(js_url, found))

        # Scope filter
        # NOTE: every URL in raw_urls is already absolute by this point --
        # tool output (katana/gau/waybackurls/hakrawler) emits absolute URLs,
        # and JS-embedded matches are resolved via urljoin(js_url, found)
        # before being added, which fills in scheme+netloc from js_url even
        # for relative paths. So urlparse(u).netloc should never be empty in
        # practice; if it ever is, that URL has no reliable host to check
        # scope against, so skip it rather than guessing. (Previously this
        # fell back to a bare `host` variable left over from the unrelated
        # `for host in alive_hosts:` loop above, which could silently
        # attribute a URL to the wrong subdomain -- removed.)
        in_scope_urls = []
        for u in raw_urls:
            try:
                url_host = urlparse(u).netloc
                if not url_host:
                    continue
                if in_scope(url_host, target_domain):
                    in_scope_urls.append(u)
            except Exception:  # noqa: BLE001
                continue

        # Same determinism concern as js_files above: in_scope_urls was
        # built by iterating raw_urls (a set), so its order is arbitrary
        # per-process. Sort before truncating so the same target always
        # yields the same capped result.
        in_scope_urls = sorted(set(in_scope_urls))[: settings.MAX_URLS_PER_TARGET]
        self.logger.info("Crawled %d JS files, extracted %d in-scope URLs", len(js_files), len(in_scope_urls))
        return {
            "js_files": sorted(js_files),
            "js_contents": js_contents,
            "crawled_urls": sorted(set(in_scope_urls)),
        }
