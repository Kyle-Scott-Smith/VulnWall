"""Tests for scanners/utils.py — the shared normalize/dedupe/sort helpers
every scanner plugin's parse() output goes through before it reaches the
rest of the app. Pure functions, no I/O, no mocking needed."""
from scanners.utils import dedupe_by_cve, normalize_vuln, sort_by_severity, title_case_severity


# ---------------------------------------------------------------------------
# title_case_severity
# ---------------------------------------------------------------------------
def test_title_case_severity_normalizes_casing():
    assert title_case_severity("CRITICAL") == "Critical"
    assert title_case_severity("high") == "High"
    assert title_case_severity("MeDiUm") == "Medium"


def test_title_case_severity_defaults_to_unknown():
    assert title_case_severity(None) == "Unknown"
    assert title_case_severity("") == "Unknown"


# ---------------------------------------------------------------------------
# normalize_vuln
# ---------------------------------------------------------------------------
def test_normalize_vuln_fills_in_defaults():
    v = normalize_vuln(cve="CVE-2024-0001", severity="high", cvss=7.5)
    assert v["asset"] == "unknown"
    assert v["references"] == []
    assert v["severity"] == "High"
    # No title given — falls back to the CVE id.
    assert v["title"] == "CVE-2024-0001"


def test_normalize_vuln_title_falls_back_to_untitled_when_no_cve_either():
    v = normalize_vuln(severity="Low", cvss=2.0)
    assert v["title"] == "Untitled finding"


def test_normalize_vuln_prefers_explicit_title_over_cve():
    v = normalize_vuln(cve="CVE-2024-0002", title="OpenSSL heap overflow")
    assert v["title"] == "OpenSSL heap overflow"


def test_normalize_vuln_keeps_explicit_asset_and_references():
    v = normalize_vuln(cve="CVE-2024-0003", asset="db-prod-01", references=["https://nvd.nist.gov/x"])
    assert v["asset"] == "db-prod-01"
    assert v["references"] == ["https://nvd.nist.gov/x"]


# ---------------------------------------------------------------------------
# dedupe_by_cve
# ---------------------------------------------------------------------------
def test_dedupe_by_cve_keeps_highest_cvss_among_duplicates():
    low = {"cve": "CVE-2024-0001", "cvss": 4.0, "asset": "host-a"}
    high = {"cve": "CVE-2024-0001", "cvss": 9.8, "asset": "host-b"}
    result = dedupe_by_cve([low, high])
    assert result == [high]


def test_dedupe_by_cve_keeps_first_when_scores_tie():
    first = {"cve": "CVE-2024-0001", "cvss": 5.0, "asset": "host-a"}
    second = {"cve": "CVE-2024-0001", "cvss": 5.0, "asset": "host-b"}
    result = dedupe_by_cve([first, second])
    assert result == [first]


def test_dedupe_by_cve_never_collapses_entries_without_a_cve():
    a = {"cve": None, "title": "Unmapped finding A", "cvss": 5.0}
    b = {"cve": None, "title": "Unmapped finding B", "cvss": 6.0}
    result = dedupe_by_cve([a, b])
    assert a in result and b in result
    assert len(result) == 2


def test_dedupe_by_cve_passes_through_unrelated_cves_untouched():
    a = {"cve": "CVE-2024-0001", "cvss": 5.0}
    b = {"cve": "CVE-2024-0002", "cvss": 5.0}
    result = dedupe_by_cve([a, b])
    assert result == [a, b]


def test_dedupe_by_cve_handles_missing_cvss_as_zero():
    no_score = {"cve": "CVE-2024-0001", "cvss": None}
    has_score = {"cve": "CVE-2024-0001", "cvss": 1.0}
    result = dedupe_by_cve([no_score, has_score])
    assert result == [has_score]


# ---------------------------------------------------------------------------
# sort_by_severity
# ---------------------------------------------------------------------------
def test_sort_by_severity_orders_by_rank_descending():
    low = {"severity": "Low", "cvss": 3.0}
    critical = {"severity": "Critical", "cvss": 9.0}
    medium = {"severity": "Medium", "cvss": 5.0}
    high = {"severity": "High", "cvss": 7.0}
    result = sort_by_severity([low, critical, medium, high])
    assert result == [critical, high, medium, low]


def test_sort_by_severity_breaks_ties_on_cvss():
    critical_low_cvss = {"severity": "Critical", "cvss": 9.0}
    critical_high_cvss = {"severity": "Critical", "cvss": 9.9}
    result = sort_by_severity([critical_low_cvss, critical_high_cvss])
    assert result == [critical_high_cvss, critical_low_cvss]


def test_sort_by_severity_treats_unknown_severity_as_lowest():
    unknown = {"severity": "Unknown", "cvss": 8.0}
    low = {"severity": "Low", "cvss": 0.1}
    result = sort_by_severity([unknown, low])
    assert result == [low, unknown]


def test_sort_by_severity_handles_missing_cvss():
    # A missing cvss shouldn't blow up the sort — treated as 0.
    result = sort_by_severity([{"severity": "High", "cvss": None}, {"severity": "High", "cvss": 5.0}])
    assert result[0]["cvss"] == 5.0


# ---------------------------------------------------------------------------
# Added coverage
# ---------------------------------------------------------------------------
import pytest  # noqa: E402

from scanners.utils import SEVERITY_RANK  # noqa: E402


def test_title_case_severity_strips_whitespace_and_coerces_non_strings():
    assert title_case_severity("  high  ") == "High"
    assert title_case_severity(3) == "3"


def test_severity_rank_covers_every_label_the_app_uses():
    assert SEVERITY_RANK == {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def test_normalize_vuln_always_returns_the_same_keys():
    expected = {"cve", "package", "installedVersion", "severity", "cvss", "title", "description", "references",
                "publishedDate", "asset", "source"}
    assert set(normalize_vuln()) == expected
    assert set(normalize_vuln(cve="CVE-1", severity="low", cvss=1.0, extra="ignored")) == expected


def test_normalize_vuln_replaces_falsy_title_asset_and_references():
    v = normalize_vuln(title="", asset="", references=None)
    assert (v["title"], v["asset"], v["references"]) == ("Untitled finding", "unknown", [])


def test_normalize_vuln_keeps_a_zero_cvss():
    assert normalize_vuln(cvss=0)["cvss"] == 0


def test_dedupe_by_cve_does_not_mutate_its_input_or_lose_order():
    a = {"cve": "CVE-1", "cvss": 1.0}
    b = {"cve": "CVE-2", "cvss": 2.0}
    c = {"cve": "CVE-1", "cvss": 3.0}
    original = [a, b, c]
    result = dedupe_by_cve(original)
    assert original == [a, b, c] and result == [c, b]


def test_dedupe_by_cve_empty_input():
    assert dedupe_by_cve([]) == []


def test_sort_by_severity_is_stable_for_complete_ties():
    first = {"severity": "High", "cvss": 7.0, "id": 1}
    second = {"severity": "High", "cvss": 7.0, "id": 2}
    assert [v["id"] for v in sort_by_severity([first, second])] == [1, 2]


def test_sort_by_severity_does_not_mutate_its_input():
    items = [{"severity": "Low"}, {"severity": "Critical"}]
    sort_by_severity(items)
    assert items[0]["severity"] == "Low"


def test_sort_by_severity_puts_an_unrecognised_label_last():
    result = sort_by_severity([{"severity": "Bogus", "cvss": 10}, {"severity": "Low", "cvss": 0.1}])
    assert [v["severity"] for v in result] == ["Low", "Bogus"]
