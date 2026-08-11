"""Endpoint Intelligence Engine.

Transforms raw discovered URLs/endpoints (from the crawler, API extractor,
directory bruteforce, etc.) into structured, security-relevant endpoint
intelligence: normalized path templates, parameter classification, and
heuristic OWASP-oriented signals for manual researcher review.

Everything in this package is HEURISTIC ANALYSIS ONLY. Nothing here confirms
a vulnerability, sends a request, or performs exploitation -- it only reasons
over data already collected by the existing (safety-controlled) scanners.
"""
