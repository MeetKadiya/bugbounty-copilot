"""Endpoint Intelligence Engine -- the core service.

Takes the raw `endpoints` (from api_extractor / dir_bruteforce / js_crawler)
and `parameters` (from url_params) already collected by the existing scan
pipeline, groups them into normalized endpoint templates, and derives
structured, security-relevant intelligence for each one:

  * normalized path + path/query parameters
  * parameter classification (via app.intelligence.parameter_classifier)
  * API classification / endpoint category
  * sensitive-resource / administrative / debug indicators
  * heuristic OWASP-oriented signals (BOLA, SSRF, open redirect, ...)
  * a 0-100 confidence score with human-readable reasons

Every signal here is a HEURISTIC for a human researcher to review -- this
module never confirms a vulnerability and never sends a network request.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.intelligence.normalizer import normalize_url
from app.intelligence.parameter_classifier import classify_parameter

ADMIN_PATH_HINTS = ("admin", "manage", "management", "backoffice", "dashboard", "console", "cpanel")
AUTH_PATH_HINTS = ("login", "logout", "auth", "signin", "signup", "register", "sso", "oauth", "session", "password", "reset")
DEBUG_PATH_HINTS = (
    "debug", "internal", "trace", "actuator", "swagger", "openapi", "graphiql",
    "backup", "phpinfo", ".git", "wp-admin", "healthcheck", "metrics", "env", "status",
)
UPLOAD_PATH_HINTS = ("upload", "import", "attachment", "media")
SENSITIVE_RESOURCE_HINTS = (
    "user", "account", "profile", "payment", "billing", "invoice", "order",
    "card", "wallet", "transaction", "secret", "config", "settings", "export",
    "backup", "credential", "admin", "internal",
)
API_PATH_HINTS = ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/", "/gateway/", "/service/")

MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class EndpointIntelligenceRecord:
    hostname: str
    method: str
    normalized_path: str
    example_url: str
    example_urls: List[str]
    occurrence_count: int
    query_parameters: List[str]
    path_parameters: List[Dict[str, Any]]
    interesting_parameters: List[Dict[str, Any]]
    api_classification: str
    endpoint_categories: List[str]
    sensitive_resource_indicators: List[str]
    administrative: bool
    auth_related: bool
    potential_bola: bool
    potential_broken_function_auth: bool
    potential_excessive_data_exposure: bool
    potential_ssrf: bool
    potential_open_redirect: bool
    potential_mass_assignment: bool
    potential_file_upload: bool
    potential_debug_internal: bool
    confidence_score: float
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "method": self.method,
            "normalized_path": self.normalized_path,
            "url": self.example_url,
            "example_urls": self.example_urls,
            "occurrence_count": self.occurrence_count,
            "query_parameters": self.query_parameters,
            "path_parameters": self.path_parameters,
            "interesting_parameters": self.interesting_parameters,
            "api_classification": self.api_classification,
            "endpoint_categories": self.endpoint_categories,
            "sensitive_resource_indicators": self.sensitive_resource_indicators,
            "administrative": self.administrative,
            "auth_related": self.auth_related,
            "potential_bola": self.potential_bola,
            "potential_broken_function_auth": self.potential_broken_function_auth,
            "potential_excessive_data_exposure": self.potential_excessive_data_exposure,
            "potential_ssrf": self.potential_ssrf,
            "potential_open_redirect": self.potential_open_redirect,
            "potential_mass_assignment": self.potential_mass_assignment,
            "potential_file_upload": self.potential_file_upload,
            "potential_debug_internal": self.potential_debug_internal,
            "confidence_score": self.confidence_score,
            "reasons": self.reasons,
        }


def _matches(path: str, hints: tuple) -> List[str]:
    lowered = path.lower()
    return [h for h in hints if h in lowered]


def compute_risk_level(record: Dict[str, Any]) -> str:
    """Roll the individual OWASP-style signals + confidence into a simple
    High/Medium/Low triage bucket for filtering/sorting -- not a severity
    rating, just a way to prioritize manual review."""
    concern_flags = [
        record.get("potential_bola"),
        record.get("potential_broken_function_auth"),
        record.get("potential_excessive_data_exposure"),
        record.get("potential_ssrf"),
        record.get("potential_open_redirect"),
        record.get("potential_mass_assignment"),
        record.get("potential_file_upload"),
        record.get("potential_debug_internal"),
    ]
    concern_count = sum(1 for f in concern_flags if f)
    score = record.get("confidence_score", 0)

    if concern_count >= 2 or (concern_count >= 1 and score >= 70):
        return "High"
    if concern_count == 1 or score >= 55:
        return "Medium"
    return "Low"


def build_endpoint_intelligence(
    endpoints: List[Dict[str, Any]],
    parameters: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Group raw discovered endpoints by (hostname, method, normalized_path)
    and derive structured intelligence for each group. Returns plain dicts
    ready to persist as `app.models.EndpointIntelligence` rows."""
    parameters = parameters or []
    groups: Dict[tuple, Dict[str, Any]] = {}

    for ep in endpoints:
        url = ep.get("url", "")
        if not url:
            continue
        method = (ep.get("method") or "GET").upper()
        norm = normalize_url(url)
        key = (norm.hostname, method, norm.normalized_path)

        group = groups.setdefault(key, {
            "hostname": norm.hostname,
            "method": method,
            "normalized_path": norm.normalized_path,
            "example_urls": [],
            "path_params_by_index": {},
            "query_param_names": set(),
            "is_api_votes": [],
            "raw_count": 0,
        })
        if url not in group["example_urls"]:
            group["example_urls"].append(url)
        group["is_api_votes"].append(bool(ep.get("is_api")))
        group["raw_count"] += 1

        for pp in norm.path_params:
            group["path_params_by_index"].setdefault(pp.index, pp)
        group["query_param_names"].update(norm.query_param_names)

    # Fold in query params already extracted by the url_params scanner,
    # matched back to a group via the example URL they were seen on.
    params_by_url: Dict[str, List[str]] = defaultdict(list)
    for p in parameters:
        params_by_url[p.get("example_url", "")].append(p.get("name", ""))

    records: List[Dict[str, Any]] = []

    for (hostname, method, normalized_path), group in groups.items():
        example_urls = group["example_urls"]
        example_url = example_urls[0]

        query_param_names = set(group["query_param_names"])
        for u in example_urls:
            query_param_names.update(params_by_url.get(u, []))

        path_params = sorted(group["path_params_by_index"].values(), key=lambda pp: pp.index)
        path_param_dicts = [
            {"placeholder": pp.placeholder, "example_value": pp.example_value, "kind": pp.kind}
            for pp in path_params
        ]
        has_path_object_id = len(path_params) > 0

        interesting_parameters: List[Dict[str, Any]] = []
        param_categories: set = set()
        param_owasp_hints: set = set()
        for name in sorted(query_param_names):
            c = classify_parameter(name)
            if c.categories:
                interesting_parameters.append({
                    "name": c.name,
                    "categories": c.categories,
                    "sensitivity": c.sensitivity,
                    "owasp_hints": c.owasp_hints,
                })
                param_categories.update(c.categories)
                param_owasp_hints.update(c.owasp_hints)

        categories: List[str] = []
        reasons: List[str] = []

        is_api = any(group["is_api_votes"]) or bool(_matches(normalized_path, API_PATH_HINTS))
        if is_api:
            categories.append("API")
            reasons.append("URL structure matches common API path conventions.")
            if "graphql" in normalized_path.lower():
                api_classification = "GraphQL"
            elif has_path_object_id or method != "GET":
                api_classification = "REST-style API"
            else:
                api_classification = "API"
        else:
            api_classification = "Web Page/Asset"

        admin_hits = _matches(normalized_path, ADMIN_PATH_HINTS)
        administrative = bool(admin_hits)
        if administrative:
            categories.append("Administrative")
            reasons.append(f"Path contains administrative indicator(s): {', '.join(admin_hits)}.")

        auth_hits = _matches(normalized_path, AUTH_PATH_HINTS)
        auth_related = bool(auth_hits)
        if auth_related:
            categories.append("Authentication")
            reasons.append(f"Path relates to authentication/session flows: {', '.join(auth_hits)}.")

        debug_hits = _matches(normalized_path, DEBUG_PATH_HINTS)
        potential_debug_internal = bool(debug_hits)
        if potential_debug_internal:
            categories.append("Debug/Internal")
            reasons.append(f"Path suggests a debug/internal surface: {', '.join(debug_hits)}.")

        sensitive_hits = _matches(normalized_path, SENSITIVE_RESOURCE_HINTS)
        if sensitive_hits:
            categories.append("Sensitive Resource")
            reasons.append(f"Path references a sensitive resource type: {', '.join(sensitive_hits)}.")

        if has_path_object_id:
            categories.append("Object Identifier")
            categories.append("Authenticated Resource")
            reasons.append(
                f"Endpoint has {len(path_params)} path-based identifier(s) "
                f"(e.g. '{path_params[0].example_value}') and appears to access a specific resource."
            )

        upload_hits = _matches(normalized_path, UPLOAD_PATH_HINTS)
        potential_file_upload = bool(upload_hits) or "File-Related" in param_categories
        if potential_file_upload:
            categories.append("File Upload Surface")
            reasons.append("Endpoint appears to accept file uploads or file-path input.")

        potential_ssrf = "URL-Related" in param_categories
        if potential_ssrf:
            reasons.append("Query parameter accepts a URL-like value -- review for SSRF potential.")

        potential_open_redirect = "potential open redirect" in param_owasp_hints
        if potential_open_redirect:
            reasons.append("Query parameter resembles a redirect target -- review for open redirect.")

        potential_mass_assignment = "Privilege-Related" in param_categories and method in MUTATING_METHODS
        if potential_mass_assignment:
            reasons.append("Privilege/role-like parameter on a state-changing request -- review for mass assignment.")

        potential_excessive_data_exposure = "Sensitive" in param_categories or (
            is_api and method == "GET" and bool(sensitive_hits)
        )
        if potential_excessive_data_exposure:
            reasons.append("Endpoint may return sensitive fields -- review response payload for over-exposure.")

        potential_bola = has_path_object_id and (is_api or method in {"GET", "PUT", "PATCH", "DELETE"})
        if potential_bola:
            reasons.append("Object identifier combined with an authorization-sensitive method -- review access control (BOLA/IDOR).")

        potential_broken_function_auth = administrative or (auth_related and method in MUTATING_METHODS)
        if potential_broken_function_auth:
            reasons.append("Administrative or auth-adjacent function -- review function-level authorization.")

        if not categories:
            categories.append("General")
            reasons.append("No strong security-relevant signals detected; classified as a general endpoint.")

        # Confidence score: additive evidence-weighted heuristic, capped
        # below 100 -- this is a triage aid, never a certainty claim.
        score = 30.0
        score += 15 if is_api else 0
        score += 20 if has_path_object_id else 0
        score += 10 if administrative else 0
        score += 8 if auth_related else 0
        score += 10 if potential_debug_internal else 0
        score += 6 * min(len(interesting_parameters), 4)
        score += 6 if sensitive_hits else 0
        confidence_score = round(min(score, 97.0), 1)

        record = EndpointIntelligenceRecord(
            hostname=hostname,
            method=method,
            normalized_path=normalized_path,
            example_url=example_url,
            example_urls=example_urls,
            occurrence_count=group["raw_count"],
            query_parameters=sorted(query_param_names),
            path_parameters=path_param_dicts,
            interesting_parameters=interesting_parameters,
            api_classification=api_classification,
            endpoint_categories=_dedupe_preserve(categories),
            sensitive_resource_indicators=sensitive_hits,
            administrative=administrative,
            auth_related=auth_related,
            potential_bola=potential_bola,
            potential_broken_function_auth=potential_broken_function_auth,
            potential_excessive_data_exposure=potential_excessive_data_exposure,
            potential_ssrf=potential_ssrf,
            potential_open_redirect=potential_open_redirect,
            potential_mass_assignment=potential_mass_assignment,
            potential_file_upload=potential_file_upload,
            potential_debug_internal=potential_debug_internal,
            confidence_score=confidence_score,
            reasons=reasons,
        ).to_dict()

        record["risk_level"] = compute_risk_level(record)
        records.append(record)

    records.sort(key=lambda r: r["confidence_score"], reverse=True)
    return records


def _dedupe_preserve(items: List[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
