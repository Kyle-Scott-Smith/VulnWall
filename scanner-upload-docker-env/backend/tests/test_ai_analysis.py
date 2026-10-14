"""Tests for the non-scoring parts of ai_analysis.py: prompt construction,
parsing/validating the model's reply, retries, the template fallback and the
cache. The scoring function has its own file (test_business_priority_score.py).

The LLM is replaced by a scripted fake `ollama_chat`; nothing touches Ollama."""
import json

import pytest

import ai_analysis as aa
from ollama_client import OllamaError

GOOD = {"why": "RCE via crafted input.", "business_impact": "Hits patient data.", "fixes": ["Patch it", "Segment it"],
        "confidence": 80, "priority_tier": "P2"}

CONTEXT = {
    "sector": "healthcare", "sectorOther": None, "criticalityTier": 1, "dataSensitivity": ["medical", "pii"],
    "complianceScope": ["hipaa"], "internetFacing": "public", "exposedSystems": ["admin_panel"],
    "airGapped": False, "revenueGenerating": True, "hadBreach": "yes", "topConcern": "physical_safety",
}


class Script:
    """Feeds replies to ollama_chat one call at a time and records the calls."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, system_prompt, messages, model=None, json_mode=False):
        self.calls.append({"system": system_prompt, "user": messages[0]["content"], "model": model, "json_mode": json_mode})
        reply = self.replies.pop(0) if self.replies else "not json"
        if isinstance(reply, Exception):
            raise reply
        return reply if isinstance(reply, str) else json.dumps(reply)


@pytest.fixture()
def llm(monkeypatch):
    def install(*replies):
        script = Script(*replies)
        monkeypatch.setattr(aa, "ollama_chat", script)
        return script
    return install


def _analyzer(**kw):
    return aa.OllamaVulnerabilityAnalyzer(**kw)


VULN = {"cve": "CVE-2024-1", "title": "Heap overflow", "severity": "High", "cvss": 8.1, "description": "Bad things.",
        "package": "libfoo", "installedVersion": "1.2.3"}


# ---------------------------------------------------------------------------
# Cache signature
# ---------------------------------------------------------------------------
def test_signature_is_none_without_a_context():
    assert aa._business_context_signature(None) is None
    assert aa._business_context_signature({}) is None


def test_signature_ignores_list_order_and_is_hashable():
    a = aa._business_context_signature({**CONTEXT, "dataSensitivity": ["pii", "medical"]})
    b = aa._business_context_signature({**CONTEXT, "dataSensitivity": ["medical", "pii"]})
    assert a == b
    hash(a)


@pytest.mark.parametrize("field,other", [
    ("criticalityTier", 5), ("internetFacing", "internal"), ("airGapped", True), ("complianceScope", ["gdpr"]),
    ("exposedSystems", ["api"]), ("topConcern", "revenue_loss"), ("hadBreach", "no"), ("revenueGenerating", False),
    ("dataSensitivity", ["credentials"]),
])
def test_signature_changes_when_any_scored_field_changes(field, other):
    assert aa._business_context_signature(CONTEXT) != aa._business_context_signature({**CONTEXT, field: other})


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------
def test_prompt_without_business_context_has_only_finding_facts():
    p = _analyzer()._build_user_prompt(VULN)
    assert "CVE ID: CVE-2024-1" in p and "CVSS score: 8.1" in p and "Reported severity: High" in p
    assert "Affected package: libfoo (installed: 1.2.3)" in p
    assert "Business context" not in p


def test_prompt_copes_with_a_sparse_finding():
    p = _analyzer()._build_user_prompt({"title": "Odd finding"})
    assert "N/A (no CVE mapped" in p and "CVSS score: unknown" in p and "Reported severity: Unknown" in p
    assert "Affected package" not in p


def test_prompt_marks_unknown_installed_version():
    p = _analyzer()._build_user_prompt({"cve": "C", "package": "p"})
    assert "(installed: unknown)" in p


def test_prompt_truncates_very_long_descriptions():
    p = _analyzer()._build_user_prompt({"cve": "C", "description": "x" * 5000})
    assert p.count("x") == 3000


def test_prompt_includes_the_business_context_block():
    p = _analyzer()._build_user_prompt(VULN, CONTEXT)
    for expected in ("Business context for this organisation", "Sector: healthcare", "criticality tier: 1",
                     "Data handled: medical, pii", "Compliance scope: hipaa", "Internet-facing: public",
                     "Specific internet-facing systems: admin_panel", "Air-gapped systems present: no",
                     "directly generates revenue: yes", "Prior security incident/breach at this organisation: yes",
                     "physical/life-safety impact"):
        assert expected in p


def test_context_block_defaults_and_optional_lines():
    block = aa._business_context_prompt_block({"sector": "legal", "criticalityTier": 3, "internetFacing": "internal",
                                                "airGapped": True, "hadBreach": "not_sure", "revenueGenerating": None})
    assert "Data handled: none reported" in block and "Compliance scope: none reported" in block
    assert "Air-gapped systems present: yes" in block
    assert "revenue" not in block and "breach" not in block and "Specific internet-facing" not in block


def test_context_block_prefers_free_text_sector_and_other_system_description():
    block = aa._business_context_prompt_block({
        "sector": "other", "sectorOther": "Space tourism", "exposedSystems": ["other", "api"],
        "exposedSystemsOther": "booking kiosk"})
    assert "Sector: Space tourism" in block
    assert "Specific internet-facing systems: booking kiosk, api" in block


def test_context_block_unknown_concern_is_shown_raw_and_breach_no_is_shown():
    block = aa._business_context_prompt_block({"topConcern": "something_new", "hadBreach": "no"})
    assert "concern them most if compromised: something_new" in block
    assert "breach at this organisation: no" in block


def test_context_block_unspecified_sector():
    assert "Sector: unspecified" in aa._business_context_prompt_block({})


# ---------------------------------------------------------------------------
# Parsing and validating the model's reply (_call_ollama)
# ---------------------------------------------------------------------------
def test_a_well_formed_reply_is_returned_as_is(llm):
    llm(GOOD)
    assert _analyzer()._call_ollama("sys", "user") == GOOD


def test_the_call_asks_for_json_mode_and_passes_the_model_through(llm):
    script = llm(GOOD)
    _analyzer(model="qwen2")._call_ollama("sys", "user")
    assert script.calls[0]["json_mode"] is True and script.calls[0]["model"] == "qwen2"


@pytest.mark.parametrize("wrap", [
    lambda body: f"```json\n{body}\n```",
    lambda body: f"```\n{body}\n```",
    lambda body: f"  \n{body}\n  ",
])
def test_markdown_fences_and_whitespace_are_tolerated(llm, wrap):
    llm(wrap(json.dumps(GOOD)))
    assert _analyzer()._call_ollama("s", "u") == GOOD


def test_ollama_errors_become_none(llm):
    llm(OllamaError("down"))
    assert _analyzer()._call_ollama("s", "u") is None


def test_invalid_json_becomes_none(llm):
    llm("I'm sorry, I can't do that.")
    assert _analyzer()._call_ollama("s", "u") is None


@pytest.mark.parametrize("field", list(GOOD))
def test_every_required_field_is_enforced(llm, field):
    reply = {k: v for k, v in GOOD.items() if k != field}
    llm(reply)
    assert _analyzer()._call_ollama("s", "u") is None


@pytest.mark.parametrize("field,bad", [("why", 5), ("business_impact", None), ("fixes", "one fix"), ("confidence", "80"),
                                       ("confidence", 85.5), ("priority_tier", 2)])
def test_wrong_field_types_are_rejected(llm, field, bad):
    llm({**GOOD, field: bad})
    assert _analyzer()._call_ollama("s", "u") is None


@pytest.mark.parametrize("tier", ["P0", "P5", "p1", "High", ""])
def test_priority_tier_must_be_one_of_p1_to_p4(llm, tier):
    llm({**GOOD, "priority_tier": tier})
    assert _analyzer()._call_ollama("s", "u") is None


@pytest.mark.parametrize("tier", ["P1", "P2", "P3", "P4"])
def test_all_four_tiers_are_accepted(llm, tier):
    llm({**GOOD, "priority_tier": tier})
    assert _analyzer()._call_ollama("s", "u")["priority_tier"] == tier


def test_extra_fields_from_the_model_are_passed_through(llm):
    llm({**GOOD, "extra": 1})
    assert _analyzer()._call_ollama("s", "u")["extra"] == 1


def test_a_json_array_reply_is_rejected_not_crashed_on(llm):
    llm("[1, 2, 3]")
    assert _analyzer()._call_ollama("s", "u") is None


@pytest.mark.xfail(strict=True, reason="BUG: a JSON scalar/null reply (e.g. `null`) raises TypeError at "
                                        "`field not in parsed`, which would 500 the whole /api/analyze batch. "
                                        "Guard with isinstance(parsed, dict) in _call_ollama, then remove this marker.")
@pytest.mark.parametrize("reply", ["null", "42", "true"])
def test_a_json_scalar_reply_is_treated_as_a_failed_attempt(llm, reply):
    llm(reply)
    assert _analyzer()._call_ollama("s", "u") is None


def test_a_json_string_reply_is_rejected(llm):
    llm('"just some text"')
    assert _analyzer()._call_ollama("s", "u") is None


# ---------------------------------------------------------------------------
# analyze(): success, caching, retries, fallback
# ---------------------------------------------------------------------------
def test_analyze_merges_ai_fields_flags_and_score(llm):
    llm(GOOD)
    out = _analyzer().analyze(VULN)
    assert out == {**GOOD, "ai_generated": True, "from_cache": False, "business_priority_score": 8.1}


def test_analyze_uses_the_business_context_for_the_score(llm):
    llm(GOOD)
    out = _analyzer().analyze(VULN, CONTEXT)
    assert out["business_priority_score"] == aa.compute_business_priority_score(VULN, CONTEXT) > 8.1


def test_second_analysis_of_the_same_cve_is_served_from_cache_without_calling_the_model(llm):
    script = llm(GOOD)
    a = _analyzer()
    a.analyze(VULN)
    again = a.analyze(VULN)
    assert again["from_cache"] is True and len(script.calls) == 1
    assert again["why"] == GOOD["why"]


def test_cached_results_still_get_a_freshly_computed_score(llm):
    llm(GOOD)
    a = _analyzer()
    a.analyze({**VULN, "cvss": 5.0})
    assert a.analyze({**VULN, "cvss": 9.0})["business_priority_score"] == 9.0


def test_cache_does_not_leak_between_different_business_contexts(llm):
    script = llm(GOOD, GOOD)
    a = _analyzer()
    a.analyze(VULN, CONTEXT)
    other = a.analyze(VULN, {**CONTEXT, "criticalityTier": 5})
    assert other["from_cache"] is False and len(script.calls) == 2
    assert a.analyze(VULN, None)["from_cache"] is False  # no-context is its own entry too


def test_cache_is_per_analyzer_instance(llm):
    script = llm(GOOD, GOOD)
    _analyzer().analyze(VULN)
    _analyzer().analyze(VULN)
    assert len(script.calls) == 2


def test_findings_with_no_cve_are_cached_by_title(llm):
    script = llm(GOOD)
    a = _analyzer()
    a.analyze({"title": "Unmapped", "severity": "Low"})
    assert a.analyze({"title": "Unmapped", "severity": "Low"})["from_cache"] is True
    assert len(script.calls) == 1


def test_findings_with_neither_cve_nor_title_are_never_cached(llm):
    script = llm(GOOD, GOOD)
    a = _analyzer()
    a.analyze({"severity": "Low"})
    a.analyze({"severity": "Low"})
    assert len(script.calls) == 2


def test_a_malformed_first_reply_is_retried_with_the_full_prompt(llm):
    script = llm("garbage", GOOD)
    out = _analyzer().analyze(VULN)
    assert out["ai_generated"] is True and len(script.calls) == 2
    assert all(c["system"] == aa.SYSTEM_PROMPT for c in script.calls)


def test_after_all_retries_the_simplified_prompt_gets_one_last_try(llm, monkeypatch):
    monkeypatch.setattr(aa, "MAX_RETRIES", 2)
    script = llm("bad", "bad", "bad", GOOD)
    out = _analyzer().analyze(VULN)
    assert out["ai_generated"] is True
    assert [c["system"] for c in script.calls] == [aa.SYSTEM_PROMPT] * 3 + [aa._SIMPLIFIED_SYSTEM_PROMPT]


def test_retry_count_follows_max_retries(llm, monkeypatch):
    monkeypatch.setattr(aa, "MAX_RETRIES", 0)
    script = llm("bad", "bad")
    _analyzer().analyze(VULN)
    assert len(script.calls) == 2  # 1 normal attempt + the simplified one


def test_total_failure_returns_the_template_fallback(llm, monkeypatch):
    monkeypatch.setattr(aa, "MAX_RETRIES", 1)
    script = llm(*(["bad"] * 3))
    out = _analyzer().analyze(VULN)
    assert len(script.calls) == 3
    assert out["ai_generated"] is False and out["from_cache"] is False and out["confidence"] == 30
    assert out["why"] == "Bad things." and out["priority_tier"] == "P2"
    assert out["fixes"][0] == "Upgrade libfoo beyond 1.2.3" and "Manual review required" in out["fixes"][1]
    assert out["business_impact"] == "" and out["business_priority_score"] == 8.1


def test_fallback_is_not_cached_so_a_later_call_can_succeed(llm, monkeypatch):
    monkeypatch.setattr(aa, "MAX_RETRIES", 0)
    llm("bad", "bad", GOOD)
    a = _analyzer()
    assert a.analyze(VULN)["ai_generated"] is False
    assert a.analyze(VULN)["ai_generated"] is True


def test_fallback_wording_when_the_finding_is_thin(llm, monkeypatch):
    monkeypatch.setattr(aa, "MAX_RETRIES", 0)
    llm(*(["bad"] * 2))
    out = _analyzer().analyze({"cve": "C-1", "severity": "Critical"})
    assert out["why"] == "Automated analysis unavailable for this finding."
    assert out["fixes"][0] == "Review vendor advisory and apply the recommended patch."
    assert out["priority_tier"] == "P1"


def test_fallback_for_a_package_without_a_version(llm, monkeypatch):
    monkeypatch.setattr(aa, "MAX_RETRIES", 0)
    llm(*(["bad"] * 2))
    out = _analyzer().analyze({"cve": "C-1", "package": "openssl"})
    assert out["fixes"][0] == "Upgrade openssl beyond the installed version"


def test_fallback_still_explains_business_context(llm, monkeypatch):
    monkeypatch.setattr(aa, "MAX_RETRIES", 0)
    llm(*(["bad"] * 2))
    out = _analyzer().analyze(VULN, CONTEXT)
    assert "HIPAA" in out["business_impact"] and "AI analysis was unavailable" in out["business_impact"]


@pytest.mark.parametrize("severity,tier", [("Critical", "P1"), ("High", "P2"), ("Medium", "P3"), ("Low", "P4"),
                                           ("Unknown", "P3"), ("", "P3"), ("weird", "P3")])
def test_severity_to_tier(severity, tier):
    assert aa.OllamaVulnerabilityAnalyzer._severity_to_tier(severity) == tier


def test_fallback_tier_for_a_missing_severity_is_p3(llm, monkeypatch):
    monkeypatch.setattr(aa, "MAX_RETRIES", 0)
    llm(*(["bad"] * 2))
    assert _analyzer().analyze({"cve": "C"})["priority_tier"] == "P3"


def test_old_class_name_still_works():
    assert aa.ClaudeVulnerabilityAnalyzer is aa.OllamaVulnerabilityAnalyzer


# ---------------------------------------------------------------------------
# _template_business_impact
# ---------------------------------------------------------------------------
def test_template_impact_is_empty_without_context_or_usable_details():
    assert aa._template_business_impact(None, "High") == ""
    assert aa._template_business_impact({}, "High") == ""
    assert aa._template_business_impact({"internetFacing": "internal", "dataSensitivity": ["none"],
                                          "complianceScope": ["none"]}, "High") == ""


def test_template_impact_mentions_each_detail():
    text = aa._template_business_impact({**CONTEXT, "sector": "banking_finance", "complianceScope": ["pci_dss", "gdpr"]}, "Critical")
    for part in ("your banking finance environment", "an internet-facing system", "data including medical, pii",
                 "scope under PCI-DSS, GDPR", "a revenue-generating system", "prior security incident"):
        assert part in text
    assert "a Critical severity finding" in text


def test_template_impact_exposure_wording_and_free_text_sector():
    mixed = aa._template_business_impact({"sectorOther": "Space tourism", "internetFacing": "mixed"}, "Low")
    assert "your Space tourism environment" in mixed and "a partially internet-facing system" in mixed


@pytest.mark.parametrize("tier,word", [(1, "elevated"), (2, "elevated"), (3, "standard"), (5, "standard"), (None, "standard")])
def test_template_impact_urgency_follows_the_tier(tier, word):
    text = aa._template_business_impact({"sector": "legal", "criticalityTier": tier}, "High")
    assert f"carries {word} business risk" in text


def test_template_impact_copes_with_a_missing_severity():
    assert "this severity finding" in aa._template_business_impact({"sector": "legal"}, None)
