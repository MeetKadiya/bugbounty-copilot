"""Shared async HTTP client with polite defaults, gated by the Scope-Aware
Request Firewall.

Rate limiting + timeouts here are the mechanism that keeps "active recon"
non-intrusive: bounded concurrency, sane timeouts, a descriptive User-Agent,
and no automatic retries against failing hosts.

Redirects are handled *manually* (the shared client is built with
follow_redirects=False) so that every hop -- not just the first request --
passes through the Scope Firewall before it's followed. Scanners should call
`firewalled_get()` / `firewalled_request()` below rather than calling
`client.get()` directly, so no code path can accidentally bypass scope
enforcement.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import httpx

from app.config import get_settings
from app.core.scope_firewall import authorize, authorize_redirect, log_decision
from app.logging_config import get_logger

settings = get_settings()
logger = get_logger("http_client")

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
        # Redirects are followed manually by firewalled_request() below so
        # every hop can be scope-checked individually -- see module docstring.
        follow_redirects=False,
        verify=False,
    ) as client:
        yield client


async def bounded_get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response | None:
    """Legacy unfirewalled helper, kept only for callers with no target/scope
    context available (e.g. fixed, non-target third-party lookups like
    crt.sh). Never use this for a URL derived from target/discovered data --
    use `firewalled_get()` instead."""
    async with _semaphore:
        try:
            return await client.get(url, **kwargs)
        except (httpx.HTTPError, httpx.InvalidURL):
            return None


async def firewalled_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    target_domain: str,
    scope_rules: list[str] | None = None,
    source: str = "unknown",
    max_redirects: int | None = None,
    **kwargs,
) -> httpx.Response | None:
    """The one, obvious way every scanner should make a request.

    Request -> Scope Firewall -> Allow/Block -> Network -> (redirect?) ->
    Scope Firewall -> ... up to `max_redirects` hops.

    Returns None (and logs why) if the URL -- or any redirect hop -- is
    blocked, times out, or otherwise fails. Never raises for
    scope/network errors, matching the rest of the scanner error-handling
    convention (log + return None/partial data, don't crash the pipeline).
    """
    max_redirects = settings.MAX_REDIRECTS if max_redirects is None else max_redirects
    current_url = url
    redirected_from: str | None = None

    for hop in range(max_redirects + 1):
        if redirected_from is None:
            decision = await authorize(current_url, target_domain, scope_rules)
        else:
            decision = await authorize_redirect(redirected_from, current_url, target_domain, scope_rules)

        log_decision(source, decision, redirect_of=redirected_from)

        if not decision.allowed:
            logger.info(
                "[BLOCKED] %s -> %s (reason: %s)", source, decision.normalized_url, decision.reason,
            )
            return None

        async with _semaphore:
            try:
                resp = await client.request(method, decision.normalized_url, **kwargs)
            except (httpx.HTTPError, httpx.InvalidURL) as exc:
                logger.info("%s request to %s failed: %s", source, decision.normalized_url, exc)
                return None

        if resp.is_redirect and resp.headers.get("location"):
            if hop >= max_redirects:
                logger.info(
                    "%s: redirect chain from %s exceeded MAX_REDIRECTS=%d, stopping",
                    source, url, max_redirects,
                )
                return resp
            redirected_from = decision.normalized_url
            current_url = resp.headers["location"]
            continue

        return resp

    return None


async def firewalled_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    target_domain: str,
    scope_rules: list[str] | None = None,
    source: str = "unknown",
    **kwargs,
) -> httpx.Response | None:
    return await firewalled_request(
        client, "GET", url, target_domain=target_domain, scope_rules=scope_rules,
        source=source, **kwargs,
    )
