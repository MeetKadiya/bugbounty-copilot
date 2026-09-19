"""
Command-line entry point for BugBounty-Copilot utilities that don't need the
full API server -- currently just the Scope Firewall preview/dry-run.

Usage:
    python -m app.cli scope check <url> --domain example.com
    python -m app.cli scope check <url> --domain example.com --scope-file scope.txt
    python -m app.cli scope check <url> --domain example.com --no-dns

This performs **no outbound HTTP request** to the checked URL -- it only
runs the same normalize -> match-scope -> (optional) DNS-resolve ->
private-IP-check pipeline that gates real scanner requests, and prints the
resulting ScopeDecision.
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from app.core.scope import parse_scope_rules
from app.core.scope_firewall import ScopeDecision, authorize, evaluate_static


def _print_decision(decision: ScopeDecision) -> None:
    if decision.allowed:
        print("Scope Decision: ALLOW")
    else:
        print(f"Scope Decision: BLOCK  [{decision.decision_type}]")
    print(f"URL:      {decision.normalized_url}")
    print(f"Hostname: {decision.hostname}")
    if decision.port:
        print(f"Port:     {decision.port}")
    if decision.scheme:
        print(f"Scheme:   {decision.scheme}")
    if decision.rule:
        print(f"Rule:     {decision.rule}")
    if decision.resolved_ips:
        print(f"Resolved: {', '.join(decision.resolved_ips)}")
    print(f"Reason:   {decision.reason}")


async def _cmd_scope_check(args: argparse.Namespace) -> int:
    scope_rules = None
    if args.scope_file:
        with open(args.scope_file, encoding="utf-8") as fh:
            scope_rules = parse_scope_rules(fh.read())

    if args.no_dns:
        decision = evaluate_static(args.url, args.domain, scope_rules)
    else:
        decision = await authorize(args.url, args.domain, scope_rules)

    _print_decision(decision)
    return 0 if decision.allowed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bugbounty-copilot")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scope_parser = subparsers.add_parser("scope", help="Scope Firewall utilities")
    scope_sub = scope_parser.add_subparsers(dest="scope_command", required=True)

    check_parser = scope_sub.add_parser(
        "check", help="Preview a Scope Firewall decision for a URL (no request is made)",
    )
    check_parser.add_argument("url", help="The URL to check, e.g. https://api.example.com/users")
    check_parser.add_argument(
        "--domain", required=True,
        help="Target root/wildcard domain, e.g. example.com or *.example.com",
    )
    check_parser.add_argument(
        "--scope-file", default=None,
        help="Optional path to a scope rules file (one rule per line: includes, "
             "wildcards, and !exclusions -- same format as the program-scope upload)",
    )
    check_parser.add_argument(
        "--no-dns", action="store_true",
        help="Skip DNS resolution / private-IP checking (scheme/port/domain/path checks only)",
    )
    check_parser.set_defaults(func=_cmd_scope_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return asyncio.run(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
