"""Shared async HTTP client with polite defaults.

Rate limiting + timeouts here are the mechanism that keeps "active recon"
non-intrusive: bounded concurrency, sane timeouts, a descriptive User-Agent,
and no automatic retries against failing hosts.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import httpx

from app.config import get_settings

settings = get_settings()

USER_AGENT = "BugBountyCopilot/1.0 (+passive-recon-assistant; respects robots.txt where configured)"


class RateLimiter:
    """Simple token-bucket-ish limiter, one instance per host."""

    def __init__(self, rps: float):
        self._interval = 1.0 / max(rps, 0.1)
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self) -> None:
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            wait_for = self._last + self._interval - now
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last = loop.time()


_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_REQUESTS)


@asynccontextmanager
async def get_client() -> httpx.AsyncClient:
    limits = httpx.Limits(max_connections=settings.MAX_CONCURRENT_REQUESTS)
    timeout = httpx.Timeout(settings.REQUEST_TIMEOUT_SECONDS)
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        yield client


async def bounded_get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response | None:
    async with _semaphore:
        try:
            return await client.get(url, **kwargs)
        except (httpx.HTTPError, httpx.InvalidURL):
            return None
