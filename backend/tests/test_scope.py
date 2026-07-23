import pytest

from app.core.scope import ScopeError, base_domain, in_scope, is_wildcard, validate_domain


def test_valid_domain():
    assert validate_domain("example.com") == "example.com"


def test_valid_wildcard():
    domain = validate_domain("*.example.com")
    assert domain == "*.example.com"
    assert is_wildcard(domain)


def test_strips_scheme_and_slashes():
    assert validate_domain("https://example.com/") == "example.com"


def test_rejects_localhost():
    with pytest.raises(ScopeError):
        validate_domain("localhost")


def test_rejects_ip_address():
    with pytest.raises(ScopeError):
        validate_domain("192.168.1.1")


def test_rejects_invalid_domain():
    with pytest.raises(ScopeError):
        validate_domain("not a domain!!")


def test_base_domain_strips_wildcard():
    assert base_domain("*.example.com") == "example.com"
    assert base_domain("example.com") == "example.com"


def test_in_scope_matches_subdomains():
    assert in_scope("api.example.com", "example.com")
    assert in_scope("example.com", "example.com")
    assert not in_scope("example.com.evil.com", "example.com")
    assert not in_scope("notexample.com", "example.com")
