"""Tests for tenable_client.py — the CVE cross-reference lookup against
Tenable.io's inventory. pyTenable is replaced by a fake client."""
import pytest


@pytest.fixture()
def tc(app_env):
    return app_env.tenable_client


class FakeWorkbenches:
    def __init__(self, table):
        self.table, self.queries = table, []

    def vulns(self, *filters):
        self.queries.append(filters)
        (_field, _op, cve), = filters
        result = self.table.get(cve, [])
        if isinstance(result, Exception):
            raise result
        return iter(result)  # pyTenable returns an iterator, not a list


class FakeTio:
    def __init__(self, table):
        self.workbenches = FakeWorkbenches(table)


def test_get_client_requires_both_keys(tc, monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    with pytest.raises(EnvironmentError, match="not set"):
        tc.get_client()
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "AK")
    with pytest.raises(EnvironmentError):
        tc.get_client()


def test_get_client_builds_a_tenable_client_from_the_environment(tc, monkeypatch):
    seen = []
    monkeypatch.setattr(tc, "TenableIO", lambda a, s: seen.append((a, s)) or "client")
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "AK")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "SK")
    assert tc.get_client() == "client" and seen == [("AK", "SK")]


def test_a_matching_cve_is_summarised(tc):
    tio = FakeTio({"CVE-1": [
        {"plugin_id": 10, "plugin_name": "P1", "severity": {"name": "High"}, "count": 3},
        {"plugin_id": 11, "plugin_name": "P2", "severity": "Medium", "count": 2},
    ]})
    out = tc.lookup_findings_by_cve(tio, ["CVE-1"])
    assert out == {"CVE-1": {
        "matched": True, "instance_count": 5,
        "matches": [
            {"plugin_id": 10, "plugin_name": "P1", "severity": "High", "instance_count": 3},
            {"plugin_id": 11, "plugin_name": "P2", "severity": "Medium", "instance_count": 2},
        ]}}


def test_a_cve_with_no_matches_is_reported_as_not_matched(tc):
    out = tc.lookup_findings_by_cve(FakeTio({}), ["CVE-NONE"])
    assert out == {"CVE-NONE": {"matched": False, "instance_count": 0, "matches": []}}


def test_each_cve_is_queried_separately_with_an_eq_filter(tc):
    tio = FakeTio({})
    tc.lookup_findings_by_cve(tio, ["CVE-1", "CVE-2"])
    assert tio.workbenches.queries == [(("cve", "eq", "CVE-1"),), (("cve", "eq", "CVE-2"),)]


def test_empty_cve_ids_are_skipped(tc):
    tio = FakeTio({})
    out = tc.lookup_findings_by_cve(tio, [None, "", "CVE-1"])
    assert list(out) == ["CVE-1"] and len(tio.workbenches.queries) == 1


def test_no_cves_means_no_calls(tc):
    tio = FakeTio({})
    assert tc.lookup_findings_by_cve(tio, []) == {}
    assert tio.workbenches.queries == []


def test_a_failed_lookup_is_recorded_without_stopping_the_rest(tc):
    tio = FakeTio({"CVE-BAD": RuntimeError("rate limited"), "CVE-OK": [{"plugin_id": 1, "count": 1}]})
    out = tc.lookup_findings_by_cve(tio, ["CVE-BAD", "CVE-OK"])
    assert out["CVE-BAD"] == {"matched": False, "instance_count": 0, "matches": [], "error": "rate limited"}
    assert out["CVE-OK"]["matched"] is True


def test_missing_counts_and_severities_are_handled(tc):
    out = tc.lookup_findings_by_cve(FakeTio({"CVE-1": [{"plugin_id": 1}, {"plugin_id": 2, "count": None}]}), ["CVE-1"])
    assert out["CVE-1"]["instance_count"] == 0 and out["CVE-1"]["matched"] is True
    assert out["CVE-1"]["matches"][0]["severity"] is None
