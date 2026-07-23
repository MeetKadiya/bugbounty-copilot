"""
Subdomain takeover detection.

Checks each subdomain's CNAME chain against a curated fingerprint database of
services known to allow "dangling CNAME" takeovers (the target CNAME points
to a de-provisioned cloud resource that anyone can re-claim). This is the
same fingerprint-matching approach used in Shloka, ported here as a pipeline
stage.

Detection is 100% passive: DNS lookups + an HTTP GET to read the response
body for a known "not claimed" fingerprint string. No claiming/registration
of the resource is ever attempted -- that would be an active exploit, which
this tool never does.
"""
from __future__ import annotations

import socket
from typing import Any

from app.scanners.base import BaseScanner
from app.utils.http_client import get_client

try:
    import dns.resolver  # dnspython, optional
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

# (cname_hint, service_label, body_fingerprint_or_None)
# body_fingerprint is a substring expected in the HTTP response body when the
# resource is unclaimed/de-provisioned. None means CNAME hint alone is enough
# to flag it as "worth manual review" (Low confidence).
TAKEOVER_FINGERPRINTS: list[tuple[str, str, str | None]] = [
    ("s3.amazonaws.com", "Amazon S3", "NoSuchBucket"),
    ("s3-website", "Amazon S3 (static site)", "NoSuchBucket"),
    ("cloudfront.net", "Amazon CloudFront", "ERROR: The request could not be satisfied"),
    ("azurewebsites.net", "Azure App Service", "Web App - Error 404"),
    ("blob.core.windows.net", "Azure Blob Storage", "BlobNotFound"),
    ("cloudapp.net", "Azure Cloud Service", None),
    ("herokuapp.com", "Heroku", "no-such-app"),
    ("herokudns.com", "Heroku DNS", None),
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("ghost.io", "Ghost.io", "The thing you were looking for is no longer here"),
    ("pantheonsite.io", "Pantheon", "The gods are wise"),
    ("wordpress.com", "WordPress.com", "Do you want to register"),
    ("fastly.net", "Fastly", "Fastly error: unknown domain"),
    ("shopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("statuspage.io", "Statuspage.io", "You are being"),
    ("surge.sh", "Surge.sh", "project not found"),
    ("bitbucket.io", "Bitbucket Pages", "Repository not found"),
    ("readme.io", "ReadMe.io", "Project doesnt exist"),
    ("tilda.ws", "Tilda", "Please renew your subscription"),
    ("webflow.io", "Webflow", "The page you are looking for doesn't exist"),
    ("netlify.app", "Netlify", "Not Found - Request ID"),
    ("wpengine.com", "WP Engine", "The site you were looking for couldn't be found"),
    ("unbounce.com", "Unbounce", "The requested URL was not found on this server"),
    ("uservoice.com", "UserVoice", "This UserVoice subdomain is currently available"),
    ("desk.com", "Desk.com", "Sorry, we couldn't find that page"),
    ("helpjuice.com", "Helpjuice", "We could not find what you're looking for"),
    ("helpscoutdocs.com", "Help Scout Docs", "No settings were found for this company"),
    ("proposify.biz", "Proposify", "If you are seeing this error"),
    ("simplebooklet.com", "Simplebooklet", "we can't find this page"),
    ("get.freshdesk.com", "Freshdesk", "not been claimed"),
]


class TakeoverDetectorScanner(BaseScanner):
    name = "takeover_detector"

    async def run(self, target_domain: str, context: dict[str, Any]) -> dict[str, Any]:
        subdomains = context.get("subdomains", [])
        candidates: list[dict] = []

        async with get_client() as client:
            for sub in subdomains:
                hostname = sub["hostname"]
                cname = await self._resolve_cname(hostname)
                if not cname:
                    continue

                for hint, service, fingerprint in TAKEOVER_FINGERPRINTS:
                    if hint not in cname.lower():
                        continue

                    confidence = "Low"
                    evidence = f"CNAME '{cname}' matches {service} pattern"

                    if fingerprint:
                        try:
                            resp = await client.get(f"https://{hostname}/")
                        except Exception:  # noqa: BLE001
                            resp = None
                        if resp is not None and fingerprint.lower() in (resp.text or "").lower():
                            confidence = "High"
                            evidence += f"; response body matched unclaimed-resource fingerprint '{fingerprint}'"
                        else:
                            confidence = "Medium"
                            evidence += "; fingerprint not confirmed via HTTP (resource may still be live)"

                    candidates.append({
                        "hostname": hostname,
                        "cname": cname,
                        "service": service,
                        "confidence": confidence,
                        "evidence": evidence,
                    })
                    break  # one match per host is enough

        self.logger.info("Found %d potential subdomain takeover candidate(s)", len(candidates))
        return {"takeover_candidates": candidates}

    @staticmethod
    async def _resolve_cname(hostname: str) -> str | None:
        if HAVE_DNSPYTHON:
            try:
                answer = dns.resolver.resolve(hostname, "CNAME", lifetime=5)
                return str(answer[0].target).rstrip(".")
            except Exception:  # noqa: BLE001
                return None
        # Fallback without dnspython: socket doesn't expose CNAME directly,
        # so we can only confirm the host resolves at all -- real CNAME
        # matching requires dnspython. Skip silently if unavailable.
        try:
            socket.gethostbyname(hostname)
        except socket.gaierror:
            pass
        return None
