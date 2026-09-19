"""
Scope-Aware Request Firewall.

Every outbound network request BugBounty-Copilot makes is meant to pass
through this module first:

    Request -> normalize_url() -> ScopeFirewall -> ScopeDecision -> Allow/Block -> Network

No scanner, crawler, redirect handler, or HTTP client call site should reach
the network without going through `authorize()` (network-aware, used right
before a request/redirect is made) or `evaluate_static()` (no DNS/network,
used for CLI/API dry-run previews). The firewall is **deny-by-default**: any
ambiguity -- a malformed URL, an unresolved hostname, an unsupported scheme,
ports outside the allow-list, or a target domain that isn't configured --
results in BLOCK, never ALLOW.

This module enforces *scope*, not *authorization*. It cannot know whether a
researcher is actually enrolled in a bug-bounty program for a given target;
that responsibility remains with the human. What it guarantees is that the
tool never silently reaches outside the scope the researcher explicitly
configured, and never touches private/loopback/reserved network ranges
unless the operator has explicitly opted in.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from app.config import get_settings
from app.core.scope import base_domain, match_scope_rule
from app.logging_config import get_logger

settings = get_settings()
logger = get_logger("scope_firewall")
audit_logger = get_logger("scope_firewall.audit")

DEFAULT_PORTS = {"http": 80, "https": 443}

# ipaddress's built-in `is_private` does NOT cover every range we care
# about (notably 100.64.0.0/10, RFC 6598 carrier-grade NAT space, which is
# routable-looking but never a legitimate public bug-bounty target). Extra
# ranges are checked explicitly on top of the stdlib private/loopback/
# link-local/reserved/multicast/unspecified flags.
_EXTRA_BLOCKED_NETWORKS = [ipaddress.ip_network("100.64.0.0/10")]


@dataclass
class ScopeDecision:
    """Structured result of a scope check -- never just True/False."""

    allowed: bool
    reason: str
    decision_type: str
    normalized_url: str
    hostname: str = ""
    port: int | None = None
    scheme: str = ""
    rule: str | None = None
    resolved_ips: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "decision_type": self.decision_type,
            "normalized_url": self.normalized_url,
            "hostname": self.hostname,
            "port": self.port,
            "scheme": self.scheme,
            "rule": self.rule,
            "resolved_ips": self.resolved_ips,
        }


def _block(decision_type: str, reason: str, normalized_url: str = "", **kw) -> ScopeDecision:
    return ScopeDecision(
        allowed=False, reason=reason, decision_type=decision_type,
        normalized_url=normalized_url, **kw,
    )


def normalize_url(raw_url: str) -> tuple[str, str, str, int, str]:
    """Parse and normalize a URL into (normalized_url, scheme, hostname, port, path).

    Raises ValueError for anything that cannot be safely/unambiguously
    parsed -- callers must treat that as BLOCK, never ALLOW.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("empty or non-string URL")

    parts = urlsplit(raw_url.strip())

    scheme = (parts.scheme or "").lower()
    if not scheme:
        raise ValueError("missing URL scheme")

    # Reject embedded userinfo/credentials outright. This is the classic
    # "https://example.com@evil.com" confusion: the real host is evil.com,
    # and 'example.com' is just misleading userinfo -- never trust it.
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs with embedded credentials (userinfo) are not supported")

    try:
        hostname = parts.hostname
    except ValueError as exc:
        raise ValueError(f"unparseable host: {exc}") from exc
    if not hostname:
        raise ValueError("missing hostname")
    hostname = hostname.lower().rstrip(".")

    try:
        hostname.encode("idna")
    except UnicodeError as exc:
        raise ValueError(f"hostname fails IDNA validation: {exc}") from exc

    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid port: {exc}") from exc
    port = port or DEFAULT_PORTS.get(scheme)
    if port is None:
        raise ValueError(f"no default port for scheme '{scheme}' and none specified")

    path = parts.path or "/"

    # Reassemble a canonical URL. The fragment is intentionally dropped: it
    # is never sent to the server, and tricks like
    # "https://evil.com#@example.com" must not be mistaken for the real
    # host (urlsplit already parses the host correctly as evil.com here --
    # dropping the fragment on re-serialization just avoids it leaking
    # into logs/downstream code as if it were meaningful).
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = display_host if port == DEFAULT_PORTS.get(scheme) else f"{display_host}:{port}"
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))

    return normalized, scheme, hostname, port, path


def _is_ip_literal(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _is_blocked_ip(ip) -> bool:
    """True if `ip` is loopback/private/link-local/reserved/multicast/
    unspecified, an IPv4-mapped IPv6 address wrapping one of those, or in
    an extra blocked range (e.g. CGNAT 100.64.0.0/10)."""
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved \
            or ip.is_multicast or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return _is_blocked_ip(mapped)
    for net in _EXTRA_BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


async def resolve_host(hostname: str) -> list[str]:
    """Resolve a hostname to all of its IPv4/IPv6 addresses (A + AAAA).
    Returns [] on any resolution failure/timeout -- callers must treat an
    empty result as fail-closed (BLOCK / DNS_RESOLUTION_FAILED), never as
    "no restrictions apply"."""
    loop = asyncio.get_event_loop()
    try:
        infos = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, hostname, None),
            timeout=settings.SCOPE_FIREWALL_DNS_TIMEOUT_SECONDS,
        )
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return []
    ips: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips


def evaluate_static(
    raw_url: str, target_domain: str, scope_rules: list[str] | None = None,
) -> ScopeDecision:
    """Scheme/port/domain/path scope checks that require **no** network
    access -- safe for CLI/API dry-run previews (`scope check <url>`).

    Does NOT protect against private-IP destinations or DNS rebinding since
    it never resolves DNS. Use `authorize()` for the full, network-aware
    decision that must gate an actual request or redirect hop.
    """
    if not settings.SCOPE_FIREWALL_ENABLED:
        return ScopeDecision(
            allowed=True, reason="Scope firewall disabled by configuration",
            decision_type="FIREWALL_DISABLED", normalized_url=raw_url or "",
        )

    try:
        normalized, scheme, hostname, port, path = normalize_url(raw_url)
    except ValueError as exc:
        return _block("INVALID_URL", f"Could not safely parse URL: {exc}", raw_url or "")

    if scheme not in settings.ALLOWED_SCHEMES:
        return _block(
            "UNSUPPORTED_SCHEME",
            f"Scheme '{scheme}' is not allowed (allowed: {settings.ALLOWED_SCHEMES})",
            normalized, hostname=hostname, port=port, scheme=scheme,
        )

    if port not in settings.ALLOWED_PORTS:
        return _block(
            "PORT_NOT_ALLOWED",
            f"Port {port} is not in the allowed port list {settings.ALLOWED_PORTS}",
            normalized, hostname=hostname, port=port, scheme=scheme,
        )

    if not target_domain:
        return _block(
            "SCOPE_UNCERTAIN", "No target domain configured for this request",
            normalized, hostname=hostname, port=port, scheme=scheme,
        )

    allowed, rule = match_scope_rule(hostname, path, target_domain, scope_rules)
    if not allowed:
        if rule and rule.startswith("!"):
            reason = f"Explicit scope exclusion: {rule[1:]}"
            decision_type = "EXPLICITLY_EXCLUDED"
        else:
            reason = (
                f"Host '{hostname}' is not within configured scope for "
                f"'{base_domain(target_domain)}'"
            )
            decision_type = "OUT_OF_SCOPE_DOMAIN" if not path.strip("/") else "OUT_OF_SCOPE_PATH"
        return _block(decision_type, reason, normalized, hostname=hostname, port=port,
                      scheme=scheme, rule=rule)

    return ScopeDecision(
        allowed=True,
        reason=f"Host matches scope rule '{rule}'" if rule else f"Host matches target '{target_domain}'",
        decision_type="ALLOW", normalized_url=normalized, hostname=hostname, port=port,
        scheme=scheme, rule=rule,
    )


async def authorize(
    raw_url: str,
    target_domain: str,
    scope_rules: list[str] | None = None,
    *,
    resolve_dns: bool = True,
) -> ScopeDecision:
    """The full, network-aware Scope Decision. Every outbound HTTP request
    -- and every individual redirect hop -- must be authorized here
    immediately before it is made. Fail-closed: any resolution failure or
    remaining ambiguity blocks the request rather than allowing it.
    """
    decision = evaluate_static(raw_url, target_domain, scope_rules)
    if not decision.allowed or not resolve_dns or not settings.SCOPE_FIREWALL_ENABLED:
        return decision

    literal_ip = _is_ip_literal(decision.hostname)
    if literal_ip is not None:
        resolved_ips = [decision.hostname]
        addr_objs = [literal_ip]
    else:
        resolved_ips = await resolve_host(decision.hostname)
        if not resolved_ips:
            return _block(
                "DNS_RESOLUTION_FAILED", f"Could not resolve hostname '{decision.hostname}'",
                decision.normalized_url, hostname=decision.hostname, port=decision.port,
                scheme=decision.scheme, rule=decision.rule,
            )
        try:
            addr_objs = [ipaddress.ip_address(ip) for ip in resolved_ips]
        except ValueError:
            return _block(
                "DNS_RESOLUTION_FAILED", f"Resolver returned an unparseable address for '{decision.hostname}'",
                decision.normalized_url, hostname=decision.hostname, port=decision.port,
                scheme=decision.scheme, rule=decision.rule,
            )

    decision.resolved_ips = resolved_ips

    if settings.ALLOW_PRIVATE_NETWORKS:
        # Operator has explicitly opted into scanning private ranges
        # (e.g. authorized internal / on-prem engagement). Still resolve
        # and record the IPs above for DNS-rebinding audit visibility.
        return decision

    for ip_obj in addr_objs:
        if _is_blocked_ip(ip_obj):
            decision_type = "LOOPBACK_IP_BLOCKED" if ip_obj.is_loopback else \
                ("RESERVED_IP_BLOCKED" if (ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified)
                 else "PRIVATE_IP_BLOCKED")
            # Don't leak the specific internal address into the human-facing
            # reason string beyond what's already exposed via resolved_ips.
            return _block(
                decision_type, "Destination resolves to a private/loopback/reserved IP address",
                decision.normalized_url, hostname=decision.hostname, port=decision.port,
                scheme=decision.scheme, rule=decision.rule, resolved_ips=resolved_ips,
            )

    return decision


# `check` is an alias for `authorize` so callers can use either
# `scope_firewall.check(url, ...)` or `scope_firewall.authorize(url, ...)`
# per the "one obvious API" requirement.
check = authorize


async def authorize_redirect(
    current_url: str, location: str, target_domain: str, scope_rules: list[str] | None = None,
) -> ScopeDecision:
    """Resolve a `Location` header (absolute or relative) against the
    current URL, then run the full `authorize()` check on the result. Used
    by the HTTP client to gate every redirect hop individually -- a
    same-scope response is never allowed to silently redirect the scanner
    off-scope."""
    try:
        absolute = urljoin(current_url, location)
    except ValueError as exc:
        return _block("INVALID_URL", f"Could not resolve redirect Location header: {exc}", current_url)
    return await authorize(absolute, target_domain, scope_rules)


def log_decision(
    source: str, decision: ScopeDecision, *, redirect_of: str | None = None,
) -> None:
    """Structured, secret-safe audit log entry for a scope decision.

    ScopeDecision never carries headers, cookies, tokens, or bodies, so
    there is nothing sensitive to redact here by construction -- only URL/
    host/port/scheme/rule/reason are ever logged.
    """
    msg = (
        f"MODULE={source} DECISION={'ALLOW' if decision.allowed else 'BLOCK'} "
        f"URL={decision.normalized_url} HOSTNAME={decision.hostname} PORT={decision.port} "
        f"SCHEME={decision.scheme} RULE={decision.rule} TYPE={decision.decision_type} "
        f"REASON=\"{decision.reason}\""
    )
    if redirect_of:
        msg += f" REDIRECT_OF={redirect_of}"
    if decision.allowed:
        audit_logger.info(msg)
    else:
        audit_logger.warning(msg)


class ScopeFirewall:
    """Thin object-oriented facade over the module-level functions, bound
    to one target's scope, for callers that prefer method-call syntax:

        firewall = ScopeFirewall(target_domain, scope_rules)
        decision = firewall.check_static(url)          # no network
        decision = await firewall.authorize(url)        # full check
    """

    def __init__(self, target_domain: str, scope_rules: list[str] | None = None):
        self.target_domain = target_domain
        self.scope_rules = scope_rules

    def check_static(self, url: str) -> ScopeDecision:
        return evaluate_static(url, self.target_domain, self.scope_rules)

    async def authorize(self, url: str) -> ScopeDecision:
        return await authorize(url, self.target_domain, self.scope_rules)

    async def authorize_redirect(self, current_url: str, location: str) -> ScopeDecision:
        return await authorize_redirect(current_url, location, self.target_domain, self.scope_rules)
