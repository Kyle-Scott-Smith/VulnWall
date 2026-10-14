"""Tests for ai_analysis.compute_business_priority_score — the deterministic
scoring function that drives finding order across the whole app (sorting in
/api/analyze, the Excel export column, the frontend's criticality band).
It's pure and independent of the LLM, so every combination of survey inputs
can be exhaustively table-tested here rather than only spot-checked by hand.
"""
import pytest
from ai_analysis import SEVERITY_BASE_SCORE, _TIER_MULTIPLIER, compute_business_priority_score


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
# Added coverage: exposed systems, top-concern amplifiers, revenue, breach history
# (see docs/PRIORITISATION.md for the rules these encode)
# ---------------------------------------------------------------------------
from ai_analysis import _EXPOSED_SYSTEM_WEIGHTS  # noqa: E402


@pytest.mark.parametrize("system,weight", sorted(_EXPOSED_SYSTEM_WEIGHTS.items()))
def test_each_exposed_system_adds_its_weight_on_top_of_public_exposure(system, weight):
    ctx = _ctx(internetFacing="public", exposedSystems=[system])
    assert compute_business_priority_score({"cvss": 6.0}, ctx) == round(6.0 * (1 + 1.5 + weight), 2)


def test_exposed_systems_documented_weights():
    assert _EXPOSED_SYSTEM_WEIGHTS == {"admin_panel": 1.0, "remote_access": 1.0, "api": 0.75, "website": 0.4, "other": 0.5}


def test_only_the_heaviest_exposed_system_counts_not_the_sum():
    ctx = _ctx(internetFacing="public", exposedSystems=["website", "api", "admin_panel"])
    assert compute_business_priority_score({"cvss": 6.0}, ctx) == round(6.0 * (1 + 1.5 + 1.0), 2)


def test_mixed_exposure_also_uses_exposed_systems():
    ctx = _ctx(internetFacing="mixed", exposedSystems=["api"])
    assert compute_business_priority_score({"cvss": 8.0}, ctx) == round(8.0 * (1 + 0.75 + 0.75), 2)


def test_exposed_systems_are_ignored_for_internal_networks():
    ctx = _ctx(internetFacing="internal", exposedSystems=["admin_panel"])
    assert compute_business_priority_score({"cvss": 6.0}, ctx) == 6.0


def test_an_unrecognised_exposed_system_gets_the_default_weight():
    ctx = _ctx(internetFacing="public", exposedSystems=["mainframe"])
    assert compute_business_priority_score({"cvss": 6.0}, ctx) == round(6.0 * (1 + 1.5 + 0.5), 2)


def test_public_with_no_exposed_systems_listed_gets_only_the_base_public_bonus():
    ctx = _ctx(internetFacing="public", exposedSystems=[])
    assert compute_business_priority_score({"cvss": 6.0}, ctx) == round(6.0 * 2.5, 2)


@pytest.mark.parametrize("concern", ["physical_safety", "operational_downtime"])
def test_availability_concerns_push_further_in_the_direction_of_the_tier(concern):
    base = 8.0
    tier1 = compute_business_priority_score({"cvss": base}, _ctx(criticalityTier=1, topConcern=concern))
    assert tier1 == round(base * 1.5 + base * (1.5 - 1.0) * 0.5, 2)  # 12.0 + 2.0
    tier5 = compute_business_priority_score({"cvss": base}, _ctx(criticalityTier=5, topConcern=concern))
    assert tier5 == round(base * 0.7 + base * (0.7 - 1.0) * 0.5, 2)  # discount deepens too
    assert tier5 < compute_business_priority_score({"cvss": base}, _ctx(criticalityTier=5))


def test_availability_concern_changes_nothing_at_the_neutral_tier():
    assert compute_business_priority_score({"cvss": 8.0}, _ctx(criticalityTier=3, topConcern="physical_safety")) == 8.0


def test_customer_trust_doubles_the_sensitive_data_bonus_only_when_there_is_sensitive_data():
    vuln = {"cvss": 5.0}
    with_data = compute_business_priority_score(vuln, _ctx(dataSensitivity=["pii"], topConcern="customer_trust"))
    assert with_data == round(5.0 * (1 + 2.0), 2)
    without = compute_business_priority_score(vuln, _ctx(dataSensitivity=[], topConcern="customer_trust"))
    assert without == 5.0


def test_legal_regulatory_doubles_the_compliance_bonus_only_when_in_scope():
    vuln = {"cvss": 4.0}
    assert compute_business_priority_score(vuln, _ctx(complianceScope=["gdpr"], topConcern="legal_regulatory")) == round(4.0 * (1 + 1.5), 2)
    assert compute_business_priority_score(vuln, _ctx(complianceScope=["none"], topConcern="legal_regulatory")) == 4.0


def test_revenue_generating_adds_half_a_point_and_revenue_loss_doubles_it():
    vuln = {"cvss": 6.0}
    assert compute_business_priority_score(vuln, _ctx(revenueGenerating=True)) == round(6.0 * 1.5, 2)
    assert compute_business_priority_score(vuln, _ctx(revenueGenerating=True, topConcern="revenue_loss")) == round(6.0 * 2.0, 2)
    assert compute_business_priority_score(vuln, _ctx(revenueGenerating=False, topConcern="revenue_loss")) == 6.0
    assert compute_business_priority_score(vuln, _ctx(revenueGenerating=None)) == 6.0


@pytest.mark.parametrize("had_breach,bonus", [("yes", 0.5), ("no", 0.0), ("not_sure", 0.0), (None, 0.0)])
def test_only_a_confirmed_breach_adds_urgency(had_breach, bonus):
    assert compute_business_priority_score({"cvss": 6.0}, _ctx(hadBreach=had_breach)) == round(6.0 * (1 + bonus), 2)


def test_air_gap_discount_applies_to_compliance_revenue_and_breach_bonuses_too():
    ctx = _ctx(complianceScope=["gdpr"], revenueGenerating=True, hadBreach="yes", airGapped=True)
    assert compute_business_priority_score({"cvss": 8.0}, ctx) == round(8.0 * (1 + (0.75 + 0.5 + 0.5) * 0.5), 2)


def test_documented_worked_example_with_availability_concern():
    # docs/PRIORITISATION.md: CVSS 8.0, tier 2, internal, GDPR, top concern operational_downtime -> 19.25
    ctx = _ctx(criticalityTier=2, internetFacing="internal", complianceScope=["gdpr"], topConcern="operational_downtime")
    assert compute_business_priority_score({"cvss": 8.0}, ctx) == 19.25


def test_documented_worked_example_rounds_to_two_decimals():
    ctx = _ctx(criticalityTier=1, internetFacing="public", dataSensitivity=["pii"], complianceScope=["hipaa"])
    assert compute_business_priority_score({"cvss": 9.0}, ctx) == round(57.375, 2)


def test_a_cvss_of_zero_is_a_real_score_not_a_missing_one():
    assert compute_business_priority_score({"cvss": 0, "severity": "Critical"}, None) == 0.0


def test_a_string_cvss_is_not_trusted_and_falls_back_to_severity():
    assert compute_business_priority_score({"cvss": "9.8", "severity": "Low"}, None) == SEVERITY_BASE_SCORE["Low"]


def test_missing_everything_scores_as_unknown():
    assert compute_business_priority_score({}, None) == SEVERITY_BASE_SCORE["Unknown"]


def test_an_empty_business_context_dict_behaves_like_no_context():
    assert compute_business_priority_score({"cvss": 7.0}, {}) == 7.0


def test_every_bonus_switched_on_never_scores_below_the_plain_cvss():
    ctx = _ctx(criticalityTier=3, internetFacing="public", exposedSystems=["admin_panel"], dataSensitivity=["pii"],
               complianceScope=["hipaa"], revenueGenerating=True, hadBreach="yes")
    assert compute_business_priority_score({"cvss": 5.0}, ctx) > 5.0
