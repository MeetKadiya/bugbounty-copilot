"""Heuristic classification of URL/API parameter names into security-relevant
categories.

These are HEURISTICS ONLY. A parameter classified here is flagged as
"interesting", "potentially sensitive", or "requires review" for a human
researcher -- never as a confirmed vulnerability.

Matching is token-based (parameters are split on `_`, `-`, `.` and
camelCase boundaries) rather than raw substring matching, so compound names
like "returnUrl" or "user_id" are caught while unrelated words that merely
*contain* a keyword as a substring (e.g. "hourly" containing "url") are not.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

_CAMEL_BOUNDARY_RE = re.compile(r"(?<!^)(?=[A-Z])")
_SPLIT_RE = re.compile(r"[_\-.\s]+")

OBJECT_ID_TOKENS = {"id", "uid", "uuid", "guid", "pk"}
OBJECT_ID_NAMES = {
    "user_id", "account_id", "customer_id", "order_id", "invoice_id",
    "document_id", "file_id", "record_id", "item_id", "product_id",
    "object_id",
}

URL_TOKENS = {
    "url", "uri", "redirect", "callback", "next", "return", "target",
    "destination", "dest", "goto", "forward", "redir", "continue", "link",
}
OPEN_REDIRECT_TOKENS = {"redirect", "return", "next", "callback", "dest", "goto", "forward", "redir"}

PRIVILEGE_TOKENS = {"role", "permission", "permissions", "admin", "privilege", "group"}
PRIVILEGE_NAMES = {"is_admin", "isadmin", "user_type", "usertype", "access_level"}

FILE_TOKENS = {"file", "filename", "upload", "attachment", "path", "filepath"}

SENSITIVE_TOKENS = {
    "token", "secret", "password", "passwd", "pwd", "email", "phone",
    "ssn", "cvv", "session", "auth", "authorization",
}
SENSITIVE_COMPOUND_TOKENS = {("api", "key")}  # api_key / apiKey

SEARCH_TOKENS = {"q", "search", "query", "keyword", "term"}

SensitivityLevel = str  # "interesting" | "potentially sensitive" | "requires review"


@dataclass
class ParameterClassification:
    name: str
    categories: List[str] = field(default_factory=list)
    owasp_hints: List[str] = field(default_factory=list)
    sensitivity: SensitivityLevel = "requires review"
    reasons: List[str] = field(default_factory=list)


def _tokenize(name: str) -> List[str]:
    snake = _CAMEL_BOUNDARY_RE.sub("_", name)
    parts = _SPLIT_RE.split(snake)
    return [p.lower() for p in parts if p]


def _dedupe(items: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def classify_parameter(name: str) -> ParameterClassification:
    key = name.strip().lower()
    tokens = _tokenize(name)
    token_set = set(tokens)

    categories: List[str] = []
    owasp_hints: List[str] = []
    reasons: List[str] = []

    is_object_id = key in OBJECT_ID_NAMES or bool(token_set & OBJECT_ID_TOKENS)
    if is_object_id:
        categories.append("Object Identifier")
        owasp_hints.append("potential BOLA / IDOR")
        reasons.append(f"Parameter '{name}' looks like an object identifier.")

    matched_url_tokens = token_set & URL_TOKENS
    if matched_url_tokens:
        categories.append("URL-Related")
        owasp_hints.append("potential SSRF-related input")
        if token_set & OPEN_REDIRECT_TOKENS:
            owasp_hints.append("potential open redirect")
        reasons.append(f"Parameter '{name}' accepts a URL/redirect-style value.")

    is_privilege = key in PRIVILEGE_NAMES or bool(token_set & PRIVILEGE_TOKENS)
    if is_privilege:
        categories.append("Privilege-Related")
        owasp_hints.append("potential mass-assignment input")
        owasp_hints.append("potential broken function-level authorization")
        reasons.append(f"Parameter '{name}' may control roles/permissions.")

    matched_file_tokens = token_set & FILE_TOKENS
    if matched_file_tokens:
        categories.append("File-Related")
        owasp_hints.append("potential file-upload surface")
        reasons.append(f"Parameter '{name}' references a file/path value.")

    is_sensitive = bool(token_set & SENSITIVE_TOKENS) or any(
        compound.issubset(token_set) for compound in (set(c) for c in SENSITIVE_COMPOUND_TOKENS)
    )
    if is_sensitive:
        categories.append("Sensitive")
        owasp_hints.append("potential excessive data exposure")
        reasons.append(f"Parameter '{name}' may carry sensitive/authentication data.")

    if token_set & SEARCH_TOKENS:
        categories.append("Search/Query")

    if not categories:
        return ParameterClassification(name=name, sensitivity="requires review")

    if "Sensitive" in categories or "Privilege-Related" in categories:
        sensitivity: SensitivityLevel = "potentially sensitive"
    else:
        sensitivity = "interesting"

    return ParameterClassification(
        name=name,
        categories=_dedupe(categories),
        owasp_hints=_dedupe(owasp_hints),
        sensitivity=sensitivity,
        reasons=reasons,
    )


def classify_parameters(names: List[str]) -> List[ParameterClassification]:
    return [classify_parameter(n) for n in dict.fromkeys(names)]
