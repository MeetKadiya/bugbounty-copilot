from types import SimpleNamespace

from app.core.risk_score import compute_risk_score


def test_zero_score_for_empty_scan():
    breakdown = compute_risk_score(
        alive_subdomain_count=0, secrets=[], endpoints=[], technologies=[],
        findings=[], waf_detected=True,
    )
    assert breakdown.score == 0.0


def test_score_increases_with_live_hosts():
    low = compute_risk_score(
        alive_subdomain_count=1, secrets=[], endpoints=[], technologies=[],
        findings=[], waf_detected=True,
    )
    high = compute_risk_score(
        alive_subdomain_count=20, secrets=[], endpoints=[], technologies=[],
        findings=[], waf_detected=True,
    )
    assert high.score > low.score


def test_score_capped_at_100():
    secrets = [SimpleNamespace(severity="Confidence.High") for _ in range(50)]
    findings = [SimpleNamespace(confidence="Confidence.High") for _ in range(50)]
    breakdown = compute_risk_score(
        alive_subdomain_count=500, secrets=secrets, endpoints=[], technologies=[],
        findings=findings, waf_detected=False,
    )
    assert breakdown.score <= 100.0


def test_no_waf_adds_penalty():
    with_waf = compute_risk_score(
        alive_subdomain_count=5, secrets=[], endpoints=[], technologies=[],
        findings=[], waf_detected=True,
    )
    without_waf = compute_risk_score(
        alive_subdomain_count=5, secrets=[], endpoints=[], technologies=[],
        findings=[], waf_detected=False,
    )
    assert without_waf.score > with_waf.score


def test_takeover_candidate_significantly_raises_score():
    without = compute_risk_score(
        alive_subdomain_count=5, secrets=[], endpoints=[], technologies=[],
        findings=[], waf_detected=True,
    )
    takeovers = [SimpleNamespace(confidence="Confidence.High")]
    with_takeover = compute_risk_score(
        alive_subdomain_count=5, secrets=[], endpoints=[], technologies=[],
        findings=[], waf_detected=True, takeover_candidates=takeovers,
    )
    assert with_takeover.score - without.score >= 12.0
