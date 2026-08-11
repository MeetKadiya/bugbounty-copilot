"""Tests for the Endpoint Intelligence Engine: normalization, parameter
classification, confidence scoring, dedup, and false-positive avoidance."""
from __future__ import annotations

from app.intelligence.endpoint_intelligence import build_endpoint_intelligence, compute_risk_level
from app.intelligence.normalizer import normalize_url
from app.intelligence.parameter_classifier import classify_parameter, classify_parameters


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------

def test_normalizes_numeric_ids():
    a = normalize_url("https://example.com/api/users/1")
    b = normalize_url("https://example.com/api/users/2")
    c = normalize_url("https://example.com/api/users/100")
    assert a.normalized_path == b.normalized_path == c.normalized_path == "/api/users/{id}"


def test_normalizes_uuid_path_segment():
    n = normalize_url("https://example.com/api/orders/550e8400-e29b-41d4-a716-446655440000")
    assert n.normalized_path == "/api/orders/{id}"
    assert n.path_params[0].kind == "uuid"


def test_normalizes_mongo_style_object_id():
    n = normalize_url("https://example.com/api/docs/507f1f77bcf86cd799439011")
    assert n.normalized_path == "/api/docs/{id}"
    assert n.path_params[0].kind == "mongo_id"


def test_multiple_path_parameters():
    n = normalize_url("https://example.com/api/users/42/orders/99")
    assert n.normalized_path == "/api/users/{id}/orders/{id2}"
    assert len(n.path_params) == 2
    assert n.path_params[0].example_value == "42"
    assert n.path_params[1].example_value == "99"


def test_query_parameters_are_extracted():
    n = normalize_url("https://example.com/search?q=test&page=2")
    assert set(n.query_param_names) == {"q", "page"}


def test_static_looking_segments_are_not_templated():
    n = normalize_url("https://example.com/api/v2/health")
    assert n.normalized_path == "/api/v2/health"
    assert n.path_params == []


def test_hostname_is_lowercased_and_extracted():
    n = normalize_url("https://API.Example.com/api/users/1")
    assert n.hostname == "api.example.com"


# --------------------------------------------------------------------------
# Parameter classification
# --------------------------------------------------------------------------

def test_classifies_object_identifier_params():
    for name in ["id", "user_id", "account_id", "order_id", "file_id"]:
        c = classify_parameter(name)
        assert "Object Identifier" in c.categories
        assert "potential BOLA / IDOR" in c.owasp_hints


def test_classifies_url_related_params():
    for name in ["url", "redirect_url", "next", "callback", "return_url"]:
        c = classify_parameter(name)
        assert "URL-Related" in c.categories
        assert "potential SSRF-related input" in c.owasp_hints


def test_classifies_open_redirect_subset():
    c = classify_parameter("redirect_url")
    assert "potential open redirect" in c.owasp_hints
    c2 = classify_parameter("url")
    # generic "url" is SSRF-flavoured but not necessarily a redirect target
    assert "potential SSRF-related input" in c2.owasp_hints


def test_classifies_privilege_params():
    c = classify_parameter("is_admin")
    assert "Privilege-Related" in c.categories
    assert c.sensitivity == "potentially sensitive"


def test_classifies_file_params():
    for name in ["file", "filename", "upload", "attachment"]:
        c = classify_parameter(name)
        assert "File-Related" in c.categories


def test_classifies_sensitive_params():
    for name in ["token", "api_key", "password", "email"]:
        c = classify_parameter(name)
        assert "Sensitive" in c.categories
        assert c.sensitivity == "potentially sensitive"


def test_never_reports_confirmed_vulnerability_language():
    """A hard safety requirement: classifications must always be phrased as
    heuristics for review, never as a confirmed vulnerability."""
    for name in ["id", "url", "is_admin", "token", "file"]:
        c = classify_parameter(name)
        for hint in c.owasp_hints:
            assert hint.startswith("potential")
        assert c.sensitivity in {"interesting", "potentially sensitive", "requires review"}


def test_false_positive_avoidance_on_benign_params():
    """Common benign parameter names must not be misclassified due to naive
    substring matching (e.g. 'hourly' containing 'url')."""
    benign = ["page", "limit", "offset", "sort", "color", "hourly", "world", "held", "grid"]
    for name in benign:
        c = classify_parameter(name)
        assert c.categories == [], f"'{name}' was unexpectedly classified as {c.categories}"


def test_classify_parameters_dedupes_by_name():
    results = classify_parameters(["id", "id", "ID", "user_id"])
    # "id" and "ID" collapse to the same key via dict.fromkeys order-preserving dedupe
    names = [r.name for r in results]
    assert names.count("id") == 1


# --------------------------------------------------------------------------
# Endpoint intelligence: grouping / normalization across raw endpoints
# --------------------------------------------------------------------------

def test_duplicate_raw_endpoints_collapse_into_one_group():
    endpoints = [
        {"url": "https://example.com/api/users/1", "method": "GET", "is_api": True},
        {"url": "https://example.com/api/users/2", "method": "GET", "is_api": True},
        {"url": "https://example.com/api/users/100", "method": "GET", "is_api": True},
    ]
    records = build_endpoint_intelligence(endpoints, [])
    assert len(records) == 1
    record = records[0]
    assert record["normalized_path"] == "/api/users/{id}"
    assert record["occurrence_count"] == 3
    assert len(record["example_urls"]) == 3


def test_different_methods_produce_separate_groups():
    endpoints = [
        {"url": "https://example.com/api/users/1", "method": "GET", "is_api": True},
        {"url": "https://example.com/api/users/1", "method": "DELETE", "is_api": True},
    ]
    records = build_endpoint_intelligence(endpoints, [])
    assert len(records) == 2
    methods = {r["method"] for r in records}
    assert methods == {"GET", "DELETE"}


def test_object_identifier_endpoint_flags_bola_for_review():
    endpoints = [{"url": "https://example.com/api/users/1", "method": "GET", "is_api": True}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    assert record["potential_bola"] is True
    assert "Object Identifier" in record["endpoint_categories"]
    assert any("BOLA" in r or "IDOR" in r for r in record["reasons"])


def test_admin_path_flags_administrative_and_function_auth():
    endpoints = [{"url": "https://example.com/admin/settings", "method": "POST", "is_api": False}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    assert record["administrative"] is True
    assert record["potential_broken_function_auth"] is True


def test_url_query_param_flags_ssrf_and_redirect():
    endpoints = [{"url": "https://example.com/go?redirect_url=https://evil.example", "method": "GET", "is_api": False}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    assert record["potential_ssrf"] is True
    assert record["potential_open_redirect"] is True
    assert "redirect_url" in record["query_parameters"]


def test_privilege_param_on_mutating_request_flags_mass_assignment():
    endpoints = [{"url": "https://example.com/api/users/1?role=admin", "method": "PUT", "is_api": True}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    assert record["potential_mass_assignment"] is True


def test_privilege_param_on_get_does_not_flag_mass_assignment():
    endpoints = [{"url": "https://example.com/api/users/1?role=admin", "method": "GET", "is_api": True}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    assert record["potential_mass_assignment"] is False


def test_upload_path_flags_file_upload_surface():
    endpoints = [{"url": "https://example.com/api/upload", "method": "POST", "is_api": True}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    assert record["potential_file_upload"] is True


def test_debug_path_flags_debug_internal():
    endpoints = [{"url": "https://example.com/actuator/health", "method": "GET", "is_api": False}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    assert record["potential_debug_internal"] is True


def test_plain_static_asset_has_no_security_flags():
    endpoints = [{"url": "https://example.com/assets/logo.png", "method": "GET", "is_api": False}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    concerning = [
        record["potential_bola"], record["potential_broken_function_auth"],
        record["potential_excessive_data_exposure"], record["potential_ssrf"],
        record["potential_open_redirect"], record["potential_mass_assignment"],
        record["potential_file_upload"], record["potential_debug_internal"],
    ]
    assert not any(concerning)
    assert "General" in record["endpoint_categories"]


def test_url_params_scanner_output_is_folded_in():
    """Query params discovered separately by the url_params scanner (keyed by
    example_url) should still be picked up even if the raw endpoint dict
    itself didn't carry a querystring."""
    endpoints = [{"url": "https://example.com/api/search", "method": "GET", "is_api": True}]
    parameters = [{"name": "q", "example_url": "https://example.com/api/search"}]
    record = build_endpoint_intelligence(endpoints, parameters)[0]
    assert "q" in record["query_parameters"]


# --------------------------------------------------------------------------
# Confidence scoring
# --------------------------------------------------------------------------

def test_confidence_score_is_bounded():
    endpoints = [{"url": "https://example.com/admin/api/users/1?token=abc&role=admin&file=x", "method": "POST", "is_api": True}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    assert 0 <= record["confidence_score"] <= 100


def test_higher_signal_endpoint_scores_higher_than_plain_endpoint():
    rich = build_endpoint_intelligence(
        [{"url": "https://example.com/admin/api/users/1?token=abc", "method": "POST", "is_api": True}], [],
    )[0]
    plain = build_endpoint_intelligence(
        [{"url": "https://example.com/about", "method": "GET", "is_api": False}], [],
    )[0]
    assert rich["confidence_score"] > plain["confidence_score"]


def test_risk_level_high_for_multi_signal_endpoint():
    record = build_endpoint_intelligence(
        [{"url": "https://example.com/admin/api/users/1?redirect_url=https://evil.com", "method": "GET", "is_api": True}], [],
    )[0]
    assert record["risk_level"] == "High"


def test_risk_level_low_for_plain_endpoint():
    record = build_endpoint_intelligence(
        [{"url": "https://example.com/about", "method": "GET", "is_api": False}], [],
    )[0]
    assert compute_risk_level(record) == "Low"


def test_every_record_has_reasons():
    endpoints = [{"url": "https://example.com/api/users/1", "method": "GET", "is_api": True}]
    record = build_endpoint_intelligence(endpoints, [])[0]
    assert len(record["reasons"]) > 0
    assert all(isinstance(r, str) and r for r in record["reasons"])


def test_empty_endpoints_returns_empty_list():
    assert build_endpoint_intelligence([], []) == []


def test_endpoint_missing_url_is_skipped():
    endpoints = [{"method": "GET", "is_api": True}, {"url": "https://example.com/x", "method": "GET"}]
    records = build_endpoint_intelligence(endpoints, [])
    assert len(records) == 1
