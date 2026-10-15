"""Tests for scanners/tenable.py (upload parsing + the live-scan workflow),
scanners/registry.py (detection/lookup) and scanners/base.py (the plugin
contract). Tenable's HTTP API is replaced by a scripted fake."""
import pytest

from scanners import tenable as tenable_module
from scanners.base import BaseScanner
from scanners.registry import SCANNERS, detect_scanner, get_scanner
from scanners.tenable import TenableScanner
from scanners.trivy import TrivyScanner

T = TenableScanner()


def _finding(**over):
    f = {
        "severity": "high",
        "plugin": {"id": 1234, "name": "OpenSSL flaw", "cve": ["CVE-2024-1", "CVE-2024-2"], "description": "desc",
                   "cvss3_base_score": 8.1, "cvss_base_score": 6.0, "see_also": ["https://a.example"],
                   "publication_date": "2024-01-01", "risk_factor": "Medium"},
        "asset": {"hostname": "web-01", "ipv4": "10.0.0.1", "uuid": "u-1"},
    }
    f.update(over)
    return f


# ---------------------------------------------------------------------------
# can_parse / parse
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("data,expected", [
    ({"vulnerabilities": []}, True),
    ({"vulnerabilities": [{}]}, True),
    ([{"plugin": {}}], True),
    ([{"other": 1}], False),
    ([], False),
    ([5], False),
    ({"vulnerabilities": None}, False),
    ({"Results": []}, False),
    (None, False),
    ("x", False),
])
def test_can_parse(data, expected):
    assert T.can_parse(data) is expected


def test_parse_maps_a_full_finding():
    (out,) = T.parse({"vulnerabilities": [_finding()]})
    assert out == {
        "cve": "CVE-2024-1", "package": None, "installedVersion": None, "severity": "High", "cvss": 8.1,
        "title": "OpenSSL flaw", "description": "desc", "references": ["https://a.example"],
        "publishedDate": "2024-01-01", "asset": "web-01", "source": "tenable",
    }


def test_parse_accepts_a_bare_list_export():
    assert len(T.parse([_finding(), _finding()])) == 2


def test_cve_falls_back_to_a_plugin_id_and_then_none():
    no_cve = _finding()
    no_cve["plugin"] = {**no_cve["plugin"], "cve": []}
    assert T.parse([no_cve])[0]["cve"] == "PLUGIN-1234"
    no_id = _finding()
    no_id["plugin"] = {"name": "x"}
    assert T.parse([no_id])[0]["cve"] is None


def test_cvss_prefers_v3_then_v2():
    f = _finding()
    f["plugin"] = {**f["plugin"], "cvss3_base_score": None}
    assert T.parse([f])[0]["cvss"] == 6.0
    f["plugin"] = {**f["plugin"], "cvss_base_score": None}
    assert T.parse([f])[0]["cvss"] is None


def test_severity_falls_back_to_the_plugin_risk_factor():
    f = _finding(severity=None)
    assert T.parse([f])[0]["severity"] == "Medium"


@pytest.mark.parametrize("asset,expected", [
    ({"hostname": "h", "ipv4": "1.1.1.1", "uuid": "u"}, "h"),
    ({"ipv4": "1.1.1.1", "uuid": "u"}, "1.1.1.1"),
    ({"uuid": "u"}, "u"),
    ({}, "unknown"),
    (None, "unknown"),
])
def test_asset_preference_order(asset, expected):
    assert T.parse([_finding(asset=asset)])[0]["asset"] == expected


def test_parse_tolerates_missing_plugin_and_non_dict_entries():
    out = T.parse({"vulnerabilities": [{}, "junk", None, {"plugin": None, "asset": None}]})
    assert len(out) == 2 and all(v["title"] == "Untitled finding" for v in out)


def test_parse_of_empty_input():
    assert T.parse({"vulnerabilities": []}) == [] and T.parse({"vulnerabilities": None}) == []


# ---------------------------------------------------------------------------
# run(): the live-scan workflow
# ---------------------------------------------------------------------------
@pytest.fixture()
def tio(monkeypatch, fake_response):
    """Scripted Tenable.io. Override `tio.scan_statuses` / `tio.export_statuses` to change the story."""
    class Tio:
        calls = []
        scan_statuses = ["completed"]
        export_statuses = [{"status": "FINISHED", "chunks_available": [1, 2]}]
        chunks = {1: [{"id": "a"}], 2: [{"id": "b"}, {"id": "c"}]}

    def post(url, **kw):
        Tio.calls.append(("POST", url, kw))
        if url.endswith("/launch"):
            return fake_response(200, {})
        if url.endswith("/vulns/export"):
            return fake_response(200, {"export_uuid": "exp-1"})
        raise AssertionError(url)

    def get(url, **kw):
        Tio.calls.append(("GET", url, kw))
        if "/chunks/" in url:
            return fake_response(200, Tio.chunks[int(url.rsplit("/", 1)[1])])
        if url.endswith("/status"):
            return fake_response(200, Tio.export_statuses.pop(0) if len(Tio.export_statuses) > 1 else Tio.export_statuses[0])
        return fake_response(200, {"info": {"status": Tio.scan_statuses.pop(0) if len(Tio.scan_statuses) > 1 else Tio.scan_statuses[0]}})

    Tio.calls = []
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "AK")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "SK")
    monkeypatch.setattr(tenable_module.requests, "post", post)
    monkeypatch.setattr(tenable_module.requests, "get", get)
    monkeypatch.setattr(tenable_module.time, "sleep", lambda s: None)
    monkeypatch.setattr(tenable_module, "TENABLE_BASE_URL", "https://tenable.test")
    return Tio


def test_run_requires_both_api_keys(tio, monkeypatch):
    monkeypatch.delenv("TENABLE_SECRET_KEY")
    with pytest.raises(RuntimeError, match="credentials not configured"):
        T.run("42")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "SK")
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "")
    with pytest.raises(RuntimeError, match="credentials not configured"):
        T.run("42")
    assert tio.calls == []


def test_run_launches_waits_exports_and_merges_every_chunk(tio):
    result = T.run("42")
    assert result == {"vulnerabilities": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}
    urls = [(m, u) for m, u, _ in tio.calls]
    assert urls[0] == ("POST", "https://tenable.test/scans/42/launch")
    assert ("POST", "https://tenable.test/vulns/export") in urls
    assert ("GET", "https://tenable.test/vulns/export/exp-1/chunks/1") in urls
    export_call = [c for c in tio.calls if c[1].endswith("/vulns/export")][0]
    assert export_call[2]["json"] == {"filters": {"scan_id": "42"}}


def test_run_authenticates_every_request_with_the_api_keys(tio):
    T.run("42")
    assert all(kw["headers"]["X-ApiKeys"] == "accessKey=AK;secretKey=SK" for _, _, kw in tio.calls)


def test_run_output_feeds_straight_into_parse(tio):
    tio.chunks = {1: [_finding()], 2: []}
    assert [v["cve"] for v in T.parse(T.run("42"))] == ["CVE-2024-1"]


def test_run_polls_until_the_scan_completes(tio):
    tio.scan_statuses = ["running", "running", "completed"]
    T.run("42")
    assert len([c for c in tio.calls if c[1] == "https://tenable.test/scans/42"]) == 3


@pytest.mark.parametrize("status", ["aborted", "canceled", "error"])
def test_a_failed_scan_raises(tio, status):
    tio.scan_statuses = [status]
    with pytest.raises(RuntimeError, match=f"ended with status: {status}"):
        T.run("42")
    assert not any(u.endswith("/vulns/export") for _, u, _ in tio.calls)  # never tries to export


def test_a_scan_that_never_finishes_times_out(tio):
    tio.scan_statuses = ["running"]
    with pytest.raises(RuntimeError, match="did not complete within 600s"):
        T.run("42")


def test_export_polling_and_failure(tio):
    tio.export_statuses = [{"status": "PROCESSING"}, {"status": "FINISHED", "chunks_available": [1]}]
    assert T.run("42")["vulnerabilities"] == [{"id": "a"}]
    tio.export_statuses = [{"status": "ERROR"}]
    with pytest.raises(RuntimeError, match="export failed"):
        T.run("42")


def test_export_that_never_finishes_times_out(tio):
    tio.export_statuses = [{"status": "PROCESSING"}]
    with pytest.raises(RuntimeError, match="did not finish within 300s"):
        T.run("42")


def test_http_failures_surface_as_exceptions(tio, monkeypatch, fake_response):
    monkeypatch.setattr(tenable_module.requests, "post", lambda *a, **k: fake_response(403, {}))
    with pytest.raises(Exception):
        T.run("42")


def test_wait_helpers_respect_custom_timeouts(tio):
    tio.scan_statuses = ["running"]
    with pytest.raises(RuntimeError, match="within 20s"):
        TenableScanner._wait_for_scan_completion("1", {}, timeout=20, poll_interval=10)


# ---------------------------------------------------------------------------
# registry.py
# ---------------------------------------------------------------------------
def test_registry_contains_both_scanners():
    assert set(SCANNERS) == {"trivy", "tenable"}
    assert all(s.name == name for name, s in SCANNERS.items())


def test_detect_scanner_by_shape():
    assert detect_scanner({"Results": []}).name == "trivy"
    assert detect_scanner({"vulnerabilities": []}).name == "tenable"
    assert detect_scanner([{"plugin": {}}]).name == "tenable"


@pytest.mark.parametrize("data", [{}, [], None, "text", 5, {"something": "else"}])
def test_detect_scanner_returns_none_for_unrecognised_data(data):
    assert detect_scanner(data) is None


def test_when_a_file_matches_two_scanners_the_first_registered_wins():
    assert detect_scanner({"Results": [], "vulnerabilities": []}).name == "trivy"


def test_get_scanner():
    assert get_scanner("trivy") is SCANNERS["trivy"]
    with pytest.raises(ValueError, match="Unknown scanner 'nessus'. Available: trivy, tenable"):
        get_scanner("nessus")


# ---------------------------------------------------------------------------
# base.py — the plugin contract
# ---------------------------------------------------------------------------
def test_base_scanner_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        BaseScanner()


def test_a_minimal_plugin_works_and_defaults_to_upload_only():
    class Minimal(BaseScanner):
        name = "minimal"

        def can_parse(self, data):
            return True

        def parse(self, data):
            return []

    m = Minimal()
    assert m.supports_run() is False
    with pytest.raises(NotImplementedError, match="minimal scanner does not support"):
        m.run("target")


def test_supports_run_is_true_only_for_plugins_that_override_run():
    assert TrivyScanner().supports_run() is True
    assert TenableScanner().supports_run() is True
