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
