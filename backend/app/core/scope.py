"""
Scope validation.

This module enforces that the tool only ever operates against a syntactically
valid domain / wildcard domain the researcher explicitly typed in. It does not
and cannot verify bug-bounty program authorization -- that responsibility
stays with the human researcher -- but it blocks obviously out-of-scope input
such as raw IPs, localhost, internal ranges, or non-domain garbage, and it is
the single choke point every scanner must pass through before making a
network request.
"""
from __future__ import annotations

import ipaddress
import re

DOMAIN_RE = re.compile(
    r"^(\*\.)?(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)

BLOCKED_SUFFIXES = (".local", ".internal", ".test", ".localhost")
BLOCKED_EXACT = {"localhost"}


class ScopeError(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    return raw.strip().lower().rstrip("/").removeprefix("http://").removeprefix("https://")


def is_wildcard(domain: str) -> bool:
    return domain.startswith("*.")


def validate_domain(raw: str) -> str:
    """Validate a user-supplied domain/wildcard. Raises ScopeError if invalid.

    Returns the normalized domain (without the leading '*.' if wildcard,
    callers can re-check `is_wildcard` on the original normalized string).
    """
    domain = normalize_domain(raw)

    if domain in BLOCKED_EXACT or any(domain.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
        raise ScopeError(f"'{domain}' is not an allowed public recon target.")

    # Reject raw IP addresses / CIDR ranges - this tool targets domains only.
    bare = domain.lstrip("*.")
    try:
        ipaddress.ip_network(bare, strict=False)
        raise ScopeError("Raw IP addresses / CIDR ranges are out of scope for this tool.")
    except ValueError:
        pass

    if not DOMAIN_RE.match(domain):
        raise ScopeError(f"'{raw}' is not a valid domain or wildcard domain (*.example.com).")

    return domain


def base_domain(domain: str) -> str:
    """Strip a leading wildcard marker, e.g. '*.example.com' -> 'example.com'."""
    return domain[2:] if domain.startswith("*.") else domain


def in_scope(hostname: str, target_domain: str) -> bool:
    """Check whether a discovered hostname falls within the target's scope."""
    root = base_domain(target_domain)
    hostname = hostname.lower().rstrip(".")
    return hostname == root or hostname.endswith("." + root)


def parse_scope_rules(raw_text: str) -> list[str]:
    """Parse an uploaded program scope doc (plain text, one rule per line)
    into a normalized rule list for storage on Target.scope_rules.

    Supported line formats:
      example.com            -- exact-host include
      *.example.com          -- wildcard include (matches the apex too)
      !internal.example.com  -- exact/wildcard exclude, always wins
      # a comment            -- ignored

    Blank lines and '#' comments are ignored. This is intentionally forgiving
    since researchers often paste scope tables copied straight from a
    HackerOne/Bugcrowd page.
    """
    rules: list[str] = []
    for line in raw_text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        # Strip common copy-paste noise (wildcard markup, surrounding asterisks
        # used as markdown bold, trailing commentary after a tab/space table).
        line = line.split("\t")[0].strip()
        rules.append(line)
    return rules


def _pattern_matches(hostname: str, pattern: str) -> bool:
    pattern = pattern.strip().lower().rstrip("/")
    pattern = pattern.removeprefix("http://").removeprefix("https://")
    if pattern.startswith("*."):
        root = pattern[2:]
        return hostname == root or hostname.endswith("." + root)
    return hostname == pattern


def in_scope_ruleset(hostname: str, target_domain: str, scope_rules: list[str] | None) -> bool:
    """Check a discovered hostname against a program's uploaded scope rules.

    Rules may include wildcard includes ("*.example.com"), exact includes
    ("api.example.com"), and exclusions ("!internal.example.com") -- an
    exclusion always wins regardless of any matching include. Falls back to
    plain root-domain matching via `in_scope()` when no scope_rules are
    configured for the target, so single-target scans behave exactly as
    before this feature existed.
    """
    hostname = hostname.lower().rstrip(".")

    if not scope_rules:
        return in_scope(hostname, target_domain)

    excludes = [r[1:] for r in scope_rules if r.startswith("!")]
    includes = [r for r in scope_rules if not r.startswith("!")]

    if any(_pattern_matches(hostname, pattern) for pattern in excludes):
        return False

    if not includes:
        # Only exclusion rules were supplied -- anything else within the
        # base target domain is still in scope.
        return in_scope(hostname, target_domain)

    return any(_pattern_matches(hostname, pattern) for pattern in includes)
