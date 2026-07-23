from app.core.scope import in_scope_ruleset, parse_scope_rules


def test_parse_scope_rules_basic():
    raw = """
    *.example.com
    api.example.com
    !internal.example.com
    # a comment
    """
    rules = parse_scope_rules(raw)
    assert "*.example.com" in rules
    assert "api.example.com" in rules
    assert "!internal.example.com" in rules
    assert not any(r.startswith("#") for r in rules)


def test_parse_scope_rules_strips_table_noise():
    raw = "example.com\tIn Scope\tCritical"
    rules = parse_scope_rules(raw)
    assert rules == ["example.com"]


def test_in_scope_ruleset_falls_back_without_rules():
    assert in_scope_ruleset("api.example.com", "example.com", None)
    assert not in_scope_ruleset("api.evil.com", "example.com", None)


def test_in_scope_ruleset_wildcard_include():
    rules = ["*.example.com"]
    assert in_scope_ruleset("api.example.com", "example.com", rules)
    assert in_scope_ruleset("example.com", "example.com", rules)
    assert not in_scope_ruleset("api.evil.com", "example.com", rules)


def test_in_scope_ruleset_exact_include_excludes_other_subdomains():
    rules = ["api.example.com"]
    assert in_scope_ruleset("api.example.com", "example.com", rules)
    assert not in_scope_ruleset("www.example.com", "example.com", rules)


def test_in_scope_ruleset_exclusion_always_wins():
    rules = ["*.example.com", "!internal.example.com"]
    assert in_scope_ruleset("api.example.com", "example.com", rules)
    assert not in_scope_ruleset("internal.example.com", "example.com", rules)


def test_in_scope_ruleset_exclusion_only_still_covers_base_domain():
    rules = ["!internal.example.com"]
    assert in_scope_ruleset("api.example.com", "example.com", rules)
    assert not in_scope_ruleset("internal.example.com", "example.com", rules)
