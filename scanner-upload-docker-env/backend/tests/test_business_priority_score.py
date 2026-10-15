"""Tests for ai_analysis.compute_business_priority_score — the deterministic
scoring function that drives finding order across the whole app (sorting in
/api/analyze, the Excel export column, the frontend's criticality band).
It's pure and independent of the LLM, so every combination of survey inputs
can be exhaustively table-tested here rather than only spot-checked by hand.
"""
import pytest

from ai_analysis import (
    ACSC_ADVISORY_SCORE_MULTIPLIER,
    ACSC_ALERT_SCORE_MULTIPLIER,
    SEVERITY_BASE_SCORE,
    _TIER_MULTIPLIER,
    compute_business_priority_score,
)


def _ctx(**overrides):
    """A complete, neutral business-context dict, overridden per test so
    each test only asserts on the one axis it cares about."""
    base = {
        "criticalityTier": 3,
        "internetFacing": "internal",
        "airGapped": False,
        "dataSensitivity": [],
        "complianceScope": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# No business context — collapses to plain CVSS/severity
# ---------------------------------------------------------------------------
def test_no_business_context_uses_raw_cvss():
    assert compute_business_priority_score({"cvss": 7.2}, None) == 7.2


def test_no_business_context_falls_back_to_severity_when_cvss_missing():
    assert compute_business_priority_score({"severity": "Critical"}, None) == SEVERITY_BASE_SCORE["Critical"]


def test_no_business_context_unknown_severity_defaults_lowest():
    assert compute_business_priority_score({"severity": "Nonsense"}, None) == SEVERITY_BASE_SCORE["Unknown"]


# ---------------------------------------------------------------------------
# Criticality tier multiplier — every tier, on its own (neutral exposure)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("tier", [1, 2, 3, 4, 5])
def test_tier_multiplier_applied_alone(tier):
    vuln = {"cvss": 8.0}
    expected = round(8.0 * _TIER_MULTIPLIER[tier], 2)
    assert compute_business_priority_score(vuln, _ctx(criticalityTier=tier)) == expected


def test_unrecognised_tier_defaults_to_neutral_multiplier():
    # criticalityTier missing/invalid shouldn't crash or silently zero the score.
    assert compute_business_priority_score({"cvss": 8.0}, _ctx(criticalityTier=None)) == 8.0
    assert compute_business_priority_score({"cvss": 8.0}, _ctx(criticalityTier=99)) == 8.0


def test_tier_1_life_safety_scores_higher_than_tier_5_no_impact():
    vuln = {"cvss": 8.0}
    tier1 = compute_business_priority_score(vuln, _ctx(criticalityTier=1))
    tier5 = compute_business_priority_score(vuln, _ctx(criticalityTier=5))
    assert tier1 > tier5


# ---------------------------------------------------------------------------
# Internet-facing exposure bonus — every level, on its own
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("exposure,bonus", [("public", 1.5), ("mixed", 0.75), ("internal", 0.0)])
def test_internet_facing_bonus(exposure, bonus):
    vuln = {"cvss": 6.0}
    expected = round(6.0 * (1 + bonus), 2)
    assert compute_business_priority_score(vuln, _ctx(internetFacing=exposure)) == expected


def test_unrecognised_internet_facing_value_treated_as_no_bonus():
    assert compute_business_priority_score({"cvss": 6.0}, _ctx(internetFacing="something-else")) == 6.0


def test_public_facing_scores_higher_than_internal():
    vuln = {"cvss": 6.0}
    public = compute_business_priority_score(vuln, _ctx(internetFacing="public"))
    internal = compute_business_priority_score(vuln, _ctx(internetFacing="internal"))
    assert public > internal


# ---------------------------------------------------------------------------
# Sensitive data bonus — only sensitive types should trigger it
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("data_type", ["credentials", "financial", "medical", "pii", "intellectual_property"])
def test_each_sensitive_data_type_adds_bonus(data_type):
    vuln = {"cvss": 5.0}
    with_data = compute_business_priority_score(vuln, _ctx(dataSensitivity=[data_type]))
    without_data = compute_business_priority_score(vuln, _ctx(dataSensitivity=[]))
    assert with_data == round(5.0 * 2.0, 2)  # +1.0 bonus -> multiplier of (1 + 1.0)
    assert with_data > without_data


def test_non_sensitive_data_type_does_not_add_bonus():
    vuln = {"cvss": 5.0}
    assert compute_business_priority_score(vuln, _ctx(dataSensitivity=["none"])) == 5.0


def test_multiple_sensitive_data_types_dont_stack_the_bonus():
    # Bonus is a flat +1.0 if ANY sensitive type is present, not additive per type.
    vuln = {"cvss": 5.0}
    one = compute_business_priority_score(vuln, _ctx(dataSensitivity=["pii"]))
    many = compute_business_priority_score(vuln, _ctx(dataSensitivity=["pii", "medical", "financial"]))
    assert one == many


# ---------------------------------------------------------------------------
# Compliance scope bonus
# ---------------------------------------------------------------------------
def test_compliance_scope_adds_bonus():
    vuln = {"cvss": 4.0}
    with_scope = compute_business_priority_score(vuln, _ctx(complianceScope=["pci"]))
    without_scope = compute_business_priority_score(vuln, _ctx(complianceScope=[]))
    assert with_scope == round(4.0 * 1.75, 2)  # +0.75 bonus
    assert with_scope > without_scope


def test_compliance_scope_of_none_only_does_not_add_bonus():
    vuln = {"cvss": 4.0}
    assert compute_business_priority_score(vuln, _ctx(complianceScope=["none"])) == 4.0


# ---------------------------------------------------------------------------
# Air-gapped halves the exposure bonus (not the tier multiplier)
# ---------------------------------------------------------------------------
def test_air_gapped_halves_exposure_bonus_but_keeps_tier_multiplier():
    vuln = {"cvss": 8.0}
    ctx = _ctx(criticalityTier=1, internetFacing="public", airGapped=True)
    # base 8.0 * tier1(1.5) * (1 + 1.5*0.5 exposure) = 8.0*1.5*1.75
    expected = round(8.0 * 1.5 * 1.75, 2)
    assert compute_business_priority_score(vuln, ctx) == expected


def test_air_gapped_scores_lower_than_equivalent_non_air_gapped():
    vuln = {"cvss": 8.0}
    exposed = compute_business_priority_score(vuln, _ctx(internetFacing="public", airGapped=False))
    air_gapped = compute_business_priority_score(vuln, _ctx(internetFacing="public", airGapped=True))
    assert air_gapped < exposed


# ---------------------------------------------------------------------------
# Full combined scenario, worked out by hand
# ---------------------------------------------------------------------------
def test_full_combined_scenario_matches_hand_calculation():
    vuln = {"cvss": 9.0}
    ctx = _ctx(
        criticalityTier=1,
        internetFacing="public",
        dataSensitivity=["pii"],
        complianceScope=["hipaa"],
        airGapped=False,
    )
    # score = 9.0 * 1.5 (tier1) * (1 + 1.5 (public) + 1.0 (pii) + 0.75 (hipaa))
    expected = round(9.0 * 1.5 * (1 + 1.5 + 1.0 + 0.75), 2)
    assert compute_business_priority_score(vuln, ctx) == expected


def test_severity_fallback_still_applies_business_context_when_cvss_missing():
    vuln = {"severity": "High"}  # no numeric cvss
    ctx = _ctx(criticalityTier=1)
    expected = round(SEVERITY_BASE_SCORE["High"] * _TIER_MULTIPLIER[1], 2)
    assert compute_business_priority_score(vuln, ctx) == expected


# ---------------------------------------------------------------------------
# ACSC (recent-incidents) multiplier — optional 3rd param, backward compatible
# ---------------------------------------------------------------------------

def test_acsc_entries_defaults_to_none_and_is_backward_compatible():
    # Every existing 2-arg call site/test above must keep working unchanged.
    assert compute_business_priority_score({"cvss": 7.2}, None) == 7.2


def test_no_acsc_entries_leaves_score_unchanged():
    vuln = {"cvss": 6.0}
    assert compute_business_priority_score(vuln, None, []) == 6.0
    assert compute_business_priority_score(vuln, None, None) == 6.0


def test_acsc_alert_multiplier_applied_with_no_business_context():
    vuln = {"cvss": 6.0}
    entries = [{"source": "alert", "link": "https://a"}]
    expected = round(6.0 * ACSC_ALERT_SCORE_MULTIPLIER, 2)
    assert compute_business_priority_score(vuln, None, entries) == expected


def test_acsc_advisory_only_multiplier_applied_with_no_business_context():
    vuln = {"cvss": 6.0}
    entries = [{"source": "advisory", "link": "https://a"}]
    expected = round(6.0 * ACSC_ADVISORY_SCORE_MULTIPLIER, 2)
    assert compute_business_priority_score(vuln, None, entries) == expected


def test_acsc_alert_outweighs_advisory_only():
    vuln = {"cvss": 6.0}
    alert_score = compute_business_priority_score(vuln, None, [{"source": "alert"}])
    advisory_score = compute_business_priority_score(vuln, None, [{"source": "advisory"}])
    assert alert_score > advisory_score


def test_acsc_multiplier_stacks_on_top_of_business_context():
    vuln = {"cvss": 8.0}
    ctx = _ctx(criticalityTier=1, internetFacing="public")
    without_acsc = compute_business_priority_score(vuln, ctx)
    with_acsc = compute_business_priority_score(vuln, ctx, [{"source": "alert"}])
    assert with_acsc == round(without_acsc * ACSC_ALERT_SCORE_MULTIPLIER, 2)
    assert with_acsc > without_acsc
