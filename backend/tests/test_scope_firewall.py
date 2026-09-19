"""Tests for the Scope-Aware Request Firewall (app.core.scope_firewall)."""
from __future__ import annotations

import pytest

from app.core.scope_firewall import (
    ScopeDecision,
    authorize,
    authorize_redirect,
    evaluate_static,
    normalize_url,
)


# --- URL normalization / parsing edge cases -----------------------------

def test_normalize_url_basic():
    normalized, scheme, hostname, port, path = normalize_url("https://example.com/foo")
    assert scheme == "https"
    assert hostname == "example.com"
    assert port == 443
    assert path == "/foo"


def test_normalize_url_default_port_omitted_from_normalized():
    normalized, *_ = normalize_url("https://example.com")
    assert normalized == "https://example.com/"


def test_normalize_url_nondefault_port_kept():
    normalized, scheme, hostname, port, path = normalize_url("http://example.com:8080/x")
    assert port == 8080
    assert "8080" in normalized


def test_normalize_url_rejects_userinfo_credentials():
    with pytest.raises(ValueError):
        normalize_url("https://example.com@evil.com")


def test_normalize_url_fragment_host_confusion_parses_real_host():
    # https://evil.com#@example.com -- the real host is evil.com; the
    # "@example.com" is just a fragment and must never be treated as host.
    normalized, scheme, hostname, port, path = normalize_url("https://evil.com#@example.com")
    assert hostname == "evil.com"


def test_normalize_url_rejects_missing_scheme():
    with pytest.raises(ValueError):
        normalize_url("example.com/foo")


def test_normalize_url_rejects_empty():
    with pytest.raises(ValueError):
        normalize_url("")


# --- Domain matching (exact) ---------------------------------------------

def test_exact_domain_allowed():
    d = evaluate_static("https://example.com/", "example.com")
    assert d.allowed


def test_exact_domain_apex_covers_subdomains_by_existing_semantics():
    # Matches the existing app.core.scope.in_scope() behavior (see
    # test_scope.py): a bare 'example.com' target already covers
    # subdomains, same as '*.example.com'. This preserves backward
    # compatibility with existing single-target scans.
    d = evaluate_static("https://api.example.com/", "example.com")
    assert d.allowed


def test_exact_include_rule_restricts_to_that_host_only():
    # Explicit scope_rules with a single exact-host include IS apex-only:
    # this is how a researcher expresses "only this exact host is in scope".
    rules = ["example.com"]
    assert evaluate_static("https://example.com/", "example.com", rules).allowed
    assert not evaluate_static("https://api.example.com/", "example.com", rules).allowed


def test_exact_domain_blocks_lookalike_suffix():
    d = evaluate_static("https://example.com.evil.com/", "example.com")
    assert not d.allowed


def test_exact_domain_blocks_lookalike_prefix():
    d = evaluate_static("https://evil-example.com/", "example.com")
    assert not d.allowed


# --- Wildcard scope --------------------------------------------------------

def test_wildcard_allows_subdomains():
    for host in ("api.example.com", "app.example.com", "dev.example.com"):
        d = evaluate_static(f"https://{host}/", "*.example.com")
        assert d.allowed, host


def test_wildcard_does_not_allow_unrelated_domain():
    d = evaluate_static("https://unrelated.com/", "*.example.com")
    assert not d.allowed


def test_wildcard_includes_apex_by_default():
    d = evaluate_static("https://example.com/", "*.example.com")
    assert d.allowed


# --- Explicit exclusions ----------------------------------------------------

def test_exclusion_overrides_wildcard_include():
    rules = ["*.example.com", "!internal.example.com"]
    blocked = evaluate_static("https://internal.example.com/", "example.com", rules)
    allowed = evaluate_static("https://api.example.com/", "example.com", rules)
    assert not blocked.allowed
    assert blocked.decision_type == "EXPLICITLY_EXCLUDED"
    assert allowed.allowed


def test_path_level_exclusion():
    rules = ["*.example.com", "!example.com/private/*"]
    blocked = evaluate_static("https://example.com/private/data", "example.com", rules)
    allowed = evaluate_static("https://example.com/public/data", "example.com", rules)
    assert not blocked.allowed
    assert allowed.allowed


# --- URL-level validation --------------------------------------------------

def test_url_allowed_plain_https():
    d = evaluate_static("https://example.com", "example.com")
    assert d.allowed


def test_url_blocked_userinfo():
    d = evaluate_static("https://example.com@evil.com", "example.com")
    assert not d.allowed
    assert d.decision_type == "INVALID_URL"


def test_url_blocked_fragment_trick_out_of_scope_host():
    # Real host is evil.com, which is not in example.com's scope.
    d = evaluate_static("https://evil.com#@example.com", "example.com")
    assert not d.allowed


# --- Ports -------------------------------------------------------------------

def test_port_443_allowed_by_default():
    d = evaluate_static("https://example.com:443", "example.com")
    assert d.allowed


def test_port_80_allowed_by_default():
    d = evaluate_static("http://example.com:80", "example.com")
    assert d.allowed


def test_nonstandard_port_blocked_by_default():
    d = evaluate_static("http://example.com:8080", "example.com")
    assert not d.allowed
    assert d.decision_type == "PORT_NOT_ALLOWED"


# --- Schemes -------------------------------------------------------------------

@pytest.mark.parametrize("scheme", ["http", "https"])
def test_allowed_schemes(scheme):
    port = 80 if scheme == "http" else 443
    d = evaluate_static(f"{scheme}://example.com:{port}/", "example.com")
    assert d.allowed


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/file",
    "javascript:alert(1)",
    "data:text/html,hi",
    "gopher://example.com/",
])
def test_disallowed_schemes_blocked(url):
    d = evaluate_static(url, "example.com")
    assert not d.allowed
    assert d.decision_type in ("UNSUPPORTED_SCHEME", "INVALID_URL")


# --- Private / loopback / reserved network protection (needs DNS) ----------

@pytest.mark.parametrize("ip_literal", [
    "127.0.0.1",
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "169.254.1.1",
    "100.64.0.1",
])
async def test_private_ipv4_literal_blocked(ip_literal):
    d = await authorize(f"http://{ip_literal}/", ip_literal)
    assert not d.allowed
    assert "PRIVATE" in d.decision_type or "LOOPBACK" in d.decision_type or "RESERVED" in d.decision_type


async def test_loopback_ipv6_literal_blocked():
    d = await authorize("http://[::1]/", "::1")
    assert not d.allowed
    assert d.decision_type == "LOOPBACK_IP_BLOCKED"


async def test_ipv4_mapped_ipv6_loopback_blocked():
    d = await authorize("http://[::ffff:127.0.0.1]/", "::ffff:127.0.0.1")
    assert not d.allowed


async def test_dns_resolution_to_private_ip_blocked(monkeypatch):
    async def fake_resolve(hostname):
        return ["127.0.0.1"]

    monkeypatch.setattr("app.core.scope_firewall.resolve_host", fake_resolve)
    d = await authorize("https://evil-example.com/", "*.evil-example.com")
    assert not d.allowed
    assert d.decision_type == "LOOPBACK_IP_BLOCKED"


async def test_dns_resolution_failure_blocks(monkeypatch):
    async def fake_resolve(hostname):
        return []

    monkeypatch.setattr("app.core.scope_firewall.resolve_host", fake_resolve)
    d = await authorize("https://example.com/", "example.com")
    assert not d.allowed
    assert d.decision_type == "DNS_RESOLUTION_FAILED"


async def test_dns_resolution_to_public_ip_allowed(monkeypatch):
    async def fake_resolve(hostname):
        return ["93.184.216.34"]  # example.com's real public IP historically

    monkeypatch.setattr("app.core.scope_firewall.resolve_host", fake_resolve)
    d = await authorize("https://example.com/", "example.com")
    assert d.allowed
    assert d.resolved_ips == ["93.184.216.34"]


# --- Redirect handling -------------------------------------------------------

async def test_redirect_in_scope_to_in_scope_allowed(monkeypatch):
    async def fake_resolve(hostname):
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.scope_firewall.resolve_host", fake_resolve)
    d = await authorize_redirect("https://example.com/a", "/b", "*.example.com")
    assert d.allowed
    assert d.hostname == "example.com"


async def test_redirect_in_scope_to_out_of_scope_blocked(monkeypatch):
    async def fake_resolve(hostname):
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.scope_firewall.resolve_host", fake_resolve)
    d = await authorize_redirect("https://example.com/a", "https://evil.com/b", "*.example.com")
    assert not d.allowed


async def test_redirect_to_private_ip_blocked(monkeypatch):
    async def fake_resolve(hostname):
        return ["127.0.0.1"]

    monkeypatch.setattr("app.core.scope_firewall.resolve_host", fake_resolve)
    d = await authorize_redirect("https://example.com/a", "https://example.com/internal", "*.example.com")
    assert not d.allowed
    assert d.decision_type == "LOOPBACK_IP_BLOCKED"


# --- Fail-closed behavior ----------------------------------------------------

def test_missing_target_domain_blocks():
    d = evaluate_static("https://example.com/", "")
    assert not d.allowed
    assert d.decision_type == "SCOPE_UNCERTAIN"


def test_malformed_url_blocks():
    d = evaluate_static("not a url!!", "example.com")
    assert not d.allowed
    assert d.decision_type == "INVALID_URL"


# --- ScopeDecision structure --------------------------------------------------

def test_scope_decision_is_structured_not_boolean():
    d = evaluate_static("https://example.com/", "example.com")
    assert isinstance(d, ScopeDecision)
    as_dict = d.as_dict()
    for key in ("allowed", "reason", "decision_type", "normalized_url", "hostname", "port", "scheme"):
        assert key in as_dict
