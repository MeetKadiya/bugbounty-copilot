import asyncio

from app.scanners.secrets_detector import SecretsDetectorScanner


def test_detects_aws_key():
    scanner = SecretsDetectorScanner()
    js = "const cfg = { key: 'AKIAABCDEFGHIJKLMNOP' };"
    result = asyncio.run(scanner.run("example.com", {"js_contents": {"https://example.com/a.js": js}}))
    types = [s["secret_type"] for s in result["secrets"]]
    assert "AWS Access Key" in types


def test_detects_jwt():
    scanner = SecretsDetectorScanner()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    js = f"var token = '{jwt}';"
    result = asyncio.run(scanner.run("example.com", {"js_contents": {"https://example.com/b.js": js}}))
    types = [s["secret_type"] for s in result["secrets"]]
    assert "JWT" in types


def test_redacts_matches():
    scanner = SecretsDetectorScanner()
    js = "const cfg = { key: 'AKIAABCDEFGHIJKLMNOP' };"
    result = asyncio.run(scanner.run("example.com", {"js_contents": {"https://example.com/a.js": js}}))
    for secret in result["secrets"]:
        assert "AKIAABCDEFGHIJKLMNOP" not in secret["match_redacted"]


def test_no_false_positive_on_clean_js():
    scanner = SecretsDetectorScanner()
    js = "function add(a, b) { return a + b; } console.log(add(1, 2));"
    result = asyncio.run(scanner.run("example.com", {"js_contents": {"https://example.com/c.js": js}}))
    assert result["secrets"] == []
