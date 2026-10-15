"""Tests for the HTTP API defined in scanner.py: health/status endpoints,
scan upload and live scans, AI analysis, chat, and the Excel export.

External systems (Ollama, Tenable, Trivy) are replaced by fakes."""
import json
from io import BytesIO

import pytest
from openpyxl import load_workbook


@pytest.fixture(autouse=True)
def _no_real_tenable_keys(monkeypatch):
    """A developer's real Tenable keys must never leak into tests."""
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)


def _trivy_report():
    def v(cve, sev, cvss=None, pkg="pkg"):
        d = {"VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": "1.0", "Severity": sev, "Title": f"{cve} t"}
        if cvss is not None:
            d["CVSS"] = {"nvd": {"V3Score": cvss}}
        return d

    return {"Results": [
        {"Target": "app (debian 12)", "Vulnerabilities": [v("CVE-LOW", "LOW", 3.0), v("CVE-DUP", "HIGH", 7.0),
                                                         v("CVE-CRIT", "CRITICAL", 9.8)]},
        {"Target": "app/package-lock.json", "Vulnerabilities": [v("CVE-DUP", "HIGH", 8.2), {"Severity": "MEDIUM", "Title": "no id"}]},
    ]}


def _upload(client, payload, filename="scan.json"):
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return client.post("/api/upload-scan", data={"file": (BytesIO(raw), filename)}, content_type="multipart/form-data")


# ---------------------------------------------------------------------------
# Health, Ollama status, scanner catalogue
# ---------------------------------------------------------------------------
def test_health(app_env):
    assert app_env.client().get("/api/health").get_json() == {"status": "ok"}


def test_ollama_status_reports_models_when_reachable(app_env, monkeypatch):
    oc = app_env.ollama_client
    monkeypatch.setattr(oc, "list_models", lambda: [{"name": "llama3.1:latest"}, {"model": "qwen2:7b"}])
    monkeypatch.setattr(oc, "resolve_model", lambda name: "llama3.1:latest")
    body = app_env.client().get("/api/ollama-status").get_json()
    assert body["resolved_model"] == "llama3.1:latest" and body["available_models"] == ["llama3.1:latest", "qwen2:7b"]
    assert set(body) == {"ollama_host", "requested_model", "resolved_model", "available_models"}


def test_ollama_status_is_503_with_the_reason_when_unreachable(app_env, monkeypatch):
    oc = app_env.ollama_client

    def down():
        raise oc.OllamaError("Could not reach Ollama")

    monkeypatch.setattr(oc, "list_models", down)
    r = app_env.client().get("/api/ollama-status")
    assert r.status_code == 503 and r.get_json()["error"] == "Could not reach Ollama"
    assert "requested_model" in r.get_json()


def test_scanner_catalogue(app_env):
    assert app_env.client().get("/api/scanners").get_json() == {
        "trivy": {"supportsLiveScan": True}, "tenable": {"supportsLiveScan": True}}


# ---------------------------------------------------------------------------
# /api/upload-scan
# ---------------------------------------------------------------------------
def test_upload_requires_sign_in_and_a_writable_role(app_env):
    assert _upload(app_env.client(), _trivy_report()).status_code == 401
    viewer, _ = app_env.login_as(role="viewer")
    assert _upload(viewer, _trivy_report()).status_code == 403


def test_upload_trivy_report_is_parsed_deduped_and_sorted(app_env):
    client, _ = app_env.login_as()
    body = _upload(client, _trivy_report()).get_json()
    assert body["status"] == "processed" and body["scanner"] == "trivy"
    vulns = body["vulnerabilities"]
    assert body["vulnerabilitiesFound"] == len(vulns) == 4
    # CVE-DUP appears twice -> only the higher-CVSS copy survives; worst severity first; no-CVE finding is kept
    by_cve = {v["cve"]: v for v in vulns}
    assert by_cve["CVE-DUP"]["cvss"] == 8.2 and by_cve["CVE-DUP"]["asset"] == "app/package-lock.json"
    assert [v["severity"] for v in vulns] == ["Critical", "High", "Medium", "Low"]
    assert any(v["cve"] is None for v in vulns)


def test_upload_does_not_record_scan_history(app_env):
    """A scan only counts once the user confirms in the wizard (POST /api/scans)."""
    client, _ = app_env.login_as()
    _upload(client, _trivy_report())
    assert app_env.query("SELECT COUNT(*) AS n FROM scans")[0]["n"] == 0


def test_upload_tenable_export(app_env):
    client, _ = app_env.login_as()
    payload = {"vulnerabilities": [{"severity": "critical", "plugin": {"id": 1, "name": "P", "cve": ["CVE-1"], "cvss3_base_score": 9.0},
                                    "asset": {"hostname": "h"}}]}
    body = _upload(client, payload).get_json()
    assert body["scanner"] == "tenable" and body["vulnerabilities"][0]["cve"] == "CVE-1"


def test_upload_clean_scan_is_fine(app_env):
    client, _ = app_env.login_as()
    body = _upload(client, {"Results": []}).get_json()
    assert body["vulnerabilitiesFound"] == 0 and body["vulnerabilities"] == []


def test_upload_file_validation(app_env):
    client, _ = app_env.login_as()
    r = client.post("/api/upload-scan", data={}, content_type="multipart/form-data")
    assert r.status_code == 400 and r.get_json()["error"] == "No file uploaded"
    assert "No file selected" in _upload(client, b"{}", filename="").get_json()["error"]
    assert "Only .json" in _upload(client, b"{}", filename="scan.txt").get_json()["error"]
    assert _upload(client, _trivy_report(), filename="SCAN.JSON").status_code == 200  # extension check is case-insensitive


def test_upload_size_limit(app_env, monkeypatch):
    monkeypatch.setattr(app_env.scanner, "MAX_FILE_SIZE_BYTES", 100)
    client, _ = app_env.login_as()
    big = json.dumps({"Results": [], "padding": "x" * 200}).encode()
    r = _upload(client, big)
    assert r.status_code == 400 and "20MB" in r.get_json()["error"]
    ok = json.dumps({"Results": []}).encode()
    assert len(ok) <= 100 and _upload(client, ok).status_code == 200


def test_upload_rejects_invalid_json(app_env):
    client, _ = app_env.login_as()
    r = _upload(client, b"{not json")
    assert r.status_code == 400 and r.get_json()["error"].startswith("Invalid JSON")


@pytest.mark.parametrize("payload", [{"hello": "world"}, [], [1, 2], "just a string", 42, None])
def test_upload_unrecognised_formats_list_the_supported_scanners(app_env, payload):
    client, _ = app_env.login_as()
    r = _upload(client, payload)
    assert r.status_code == 400 and "Supported scanners: trivy, tenable" in r.get_json()["error"]


# ---------------------------------------------------------------------------
# Tenable cross-reference during upload
# ---------------------------------------------------------------------------
def test_without_tenable_keys_the_cross_reference_is_silently_skipped(app_env):
    client, _ = app_env.login_as()
    vulns = _upload(client, _trivy_report()).get_json()["vulnerabilities"]
    assert all("tenable_exposure" not in v for v in vulns)


def test_with_tenable_keys_findings_gain_an_exposure_summary(app_env, monkeypatch):
    tc = app_env.tenable_client
    monkeypatch.setattr(tc, "get_client", lambda: object())
    seen = {}

    def lookup(tio, cve_ids):
        seen["cves"] = list(cve_ids)
        return {"CVE-CRIT": {"matched": True, "instance_count": 4, "matches": []}}

    monkeypatch.setattr(tc, "lookup_findings_by_cve", lookup)
    client, _ = app_env.login_as()
    vulns = {v["cve"]: v for v in _upload(client, _trivy_report()).get_json()["vulnerabilities"]}
    assert sorted(seen["cves"]) == ["CVE-CRIT", "CVE-DUP", "CVE-LOW"]  # deduped, no None
    assert vulns["CVE-CRIT"]["tenable_exposure"]["instance_count"] == 4
    assert vulns["CVE-LOW"]["tenable_exposure"] is None  # looked up, not found


def test_a_tenable_outage_does_not_fail_the_upload(app_env, monkeypatch):
    tc = app_env.tenable_client
    monkeypatch.setattr(tc, "get_client", lambda: object())

    def boom(*a, **k):
        raise RuntimeError("tenable down")

    monkeypatch.setattr(tc, "lookup_findings_by_cve", boom)
    client, _ = app_env.login_as()
    r = _upload(client, _trivy_report())
    assert r.status_code == 200 and r.get_json()["vulnerabilitiesFound"] == 4


# ---------------------------------------------------------------------------
# /api/scan (live scan)
# ---------------------------------------------------------------------------
class FakeScanner:
    name = "fake"

    def __init__(self, raw=None, error=None):
        self.raw, self.error, self.calls = raw if raw is not None else {"Results": []}, error, []

    def supports_run(self):
        return True

    def can_parse(self, data):
        return True

    def run(self, target, **kwargs):
        self.calls.append((target, kwargs))
        if self.error:
            raise self.error
        return self.raw

    def parse(self, raw):
        return [{"cve": "CVE-F", "severity": "High", "cvss": 7.0, "title": "t"}]


@pytest.fixture()
def fake_scanner(app_env, monkeypatch):
    fs = FakeScanner()
    monkeypatch.setitem(app_env.scanner.SCANNERS, "fake", fs)
    return fs


def _scan(client, **body):
    return client.post("/api/scan", json=body)


def test_scan_requires_sign_in_and_a_writable_role(app_env):
    assert _scan(app_env.client(), scanner="trivy", target="x").status_code == 401
    viewer, _ = app_env.login_as(role="viewer")
    assert _scan(viewer, scanner="trivy", target="x").status_code == 403


@pytest.mark.parametrize("body,fragment", [
    ({}, "Missing 'scanner'"), ({"target": "x"}, "Missing 'scanner'"),
    ({"scanner": "trivy"}, "Missing 'target'"), ({"scanner": "trivy", "target": ""}, "Missing 'target'"),
    ({"scanner": "nessus", "target": "x"}, "Unknown scanner 'nessus'"),
])
def test_scan_input_validation(app_env, body, fragment):
    client, _ = app_env.login_as()
    r = _scan(client, **body)
    assert r.status_code == 400 and fragment in r.get_json()["error"]


def test_scan_runs_the_scanner_and_returns_normalised_results(app_env, fake_scanner):
    client, _ = app_env.login_as()
    body = _scan(client, scanner="fake", target="myapp:1").get_json()
    assert body == {"status": "processed", "scanner": "fake", "vulnerabilitiesFound": 1,
                    "vulnerabilities": [{"cve": "CVE-F", "severity": "High", "cvss": 7.0, "title": "t"}]}
    assert fake_scanner.calls == [("myapp:1", {})]
    assert app_env.query("SELECT COUNT(*) AS n FROM scans")[0]["n"] == 0  # recorded at confirmation, not here


def test_scan_forwards_extra_options_but_not_its_own_routing_fields(app_env, fake_scanner):
    client, _ = app_env.login_as()
    _scan(client, scanner="fake", target="t", scan_type="fs", mode="docker", usePrivateRegistry=True)
    assert fake_scanner.calls == [("t", {"scan_type": "fs", "mode": "docker"})]  # not trivy -> registry flag ignored


@pytest.mark.parametrize("error,status", [
    (NotImplementedError("upload only"), 400), (ValueError("bad target"), 502), (RuntimeError("trivy exploded"), 502),
])
def test_scan_errors_map_to_http_statuses(app_env, fake_scanner, error, status):
    fake_scanner.error = error
    client, _ = app_env.login_as()
    r = _scan(client, scanner="fake", target="t")
    assert r.status_code == status and r.get_json()["error"] == str(error)


def test_private_registry_requires_a_stored_connection(app_env, monkeypatch):
    trivy = app_env.scanner.SCANNERS["trivy"]
    monkeypatch.setattr(trivy, "run", lambda *a, **k: pytest.fail("must not run"))
    client, _ = app_env.login_as()
    r = _scan(client, scanner="trivy", target="reg.io/app:1", usePrivateRegistry=True)
    assert r.status_code == 400 and "No private registry connected" in r.get_json()["error"]


def test_private_registry_credentials_are_injected_server_side(app_env, monkeypatch):
    trivy = app_env.scanner.SCANNERS["trivy"]
    calls = []
    monkeypatch.setattr(trivy, "run", lambda target, **kw: calls.append((target, kw)) or {"Results": []})
    client, uid = app_env.login_as()
    client.post("/api/registry/connect", json={"url": "ghcr.io", "username": "bot", "password": "pw"})
    # Even if the client tries to supply its own credentials, the stored ones win
    r = _scan(client, scanner="trivy", target="ghcr.io/org/app:1", usePrivateRegistry=True, registry_password="attacker")
    assert r.status_code == 200
    assert calls == [("ghcr.io/org/app:1", {"registry_url": "ghcr.io", "registry_username": "bot", "registry_password": "pw"})]


# ---------------------------------------------------------------------------
# /api/analyze
# ---------------------------------------------------------------------------
class FakeAnalyzer:
    def __init__(self):
        self.calls = []

    def analyze(self, vuln, business_context=None):
        self.calls.append((vuln["cve"], business_context))
        return {"why": f"why {vuln['cve']}", "business_priority_score": vuln.get("cvss") or 0, "ai_generated": True}


@pytest.fixture()
def analyzer(app_env, monkeypatch):
    a = FakeAnalyzer()
    monkeypatch.setattr(app_env.scanner, "_get_analyzer", lambda: a)
    return a


def test_analyze_requires_sign_in_and_a_writable_role(app_env, analyzer):
    assert app_env.client().post("/api/analyze", json={"vulnerabilities": []}).status_code == 401
    viewer, _ = app_env.login_as(role="viewer")
    assert viewer.post("/api/analyze", json={"vulnerabilities": []}).status_code == 403


@pytest.mark.parametrize("body", [{}, {"vulnerabilities": "x"}, {"vulnerabilities": {"a": 1}}, {"vulnerabilities": None}])
def test_analyze_needs_a_vulnerabilities_array(app_env, analyzer, body):
    client, _ = app_env.login_as()
    assert client.post("/api/analyze", json=body).status_code == 400


def test_analyze_merges_results_and_sorts_by_business_priority(app_env, analyzer):
    client, _ = app_env.login_as()
    vulns = [{"cve": "CVE-A", "cvss": 3.0, "title": "a"}, {"cve": "CVE-B", "cvss": 9.0, "title": "b"},
             {"cve": "CVE-C", "cvss": 6.0, "title": "c"}]
    body = client.post("/api/analyze", json={"vulnerabilities": vulns}).get_json()
    assert body["status"] == "analyzed" and body["businessContextApplied"] is False
    assert [v["cve"] for v in body["vulnerabilities"]] == ["CVE-B", "CVE-C", "CVE-A"]
    first = body["vulnerabilities"][0]
    assert first["title"] == "b" and first["why"] == "why CVE-B" and first["ai_generated"] is True  # original + AI fields


def test_analyze_skips_non_object_entries(app_env, analyzer):
    client, _ = app_env.login_as()
    body = client.post("/api/analyze", json={"vulnerabilities": ["junk", None, 5, {"cve": "CVE-A", "cvss": 1.0}]}).get_json()
    assert [v["cve"] for v in body["vulnerabilities"]] == ["CVE-A"]


def test_analyze_of_an_empty_list_is_an_empty_result(app_env, analyzer):
    client, _ = app_env.login_as()
    body = client.post("/api/analyze", json={"vulnerabilities": []}).get_json()
    assert body["vulnerabilities"] == [] and analyzer.calls == []


def test_analyze_applies_the_signed_in_users_business_context(app_env, analyzer):
    client, uid = app_env.login_as()
    client.post("/api/business-context", json={
        "sector": "legal", "dataSensitivity": ["pii"], "availabilityImpact": "major_disruption", "internetFacing": "internal",
        "complianceScope": ["gdpr"], "airGapped": False, "topConcern": "customer_trust", "hadBreach": "no", "revenueGenerating": True})
    body = client.post("/api/analyze", json={"vulnerabilities": [{"cve": "CVE-A", "cvss": 5.0}]}).get_json()
    assert body["businessContextApplied"] is True
    (cve, ctx), = analyzer.calls
    assert ctx["sector"] == "legal" and ctx["criticalityTier"] == 2


def test_analyze_does_not_use_another_users_business_context(app_env, analyzer):
    other, _ = app_env.login_as()
    other.post("/api/business-context", json={
        "sector": "legal", "dataSensitivity": ["pii"], "availabilityImpact": "no_impact", "internetFacing": "internal",
        "complianceScope": ["none"], "airGapped": False, "topConcern": "customer_trust", "hadBreach": "no", "revenueGenerating": False})
    client, _ = app_env.login_as()
    client.post("/api/analyze", json={"vulnerabilities": [{"cve": "CVE-A"}]})
    assert analyzer.calls == [("CVE-A", None)]


def test_analyze_reports_503_when_the_analyzer_cannot_be_created(app_env, monkeypatch):
    def broken():
        raise EnvironmentError("Ollama not configured")

    monkeypatch.setattr(app_env.scanner, "_get_analyzer", broken)
    client, _ = app_env.login_as()
    r = client.post("/api/analyze", json={"vulnerabilities": []})
    assert r.status_code == 503 and "Ollama not configured" in r.get_json()["error"]


def test_analyze_with_the_real_analyzer_and_a_scripted_llm(app_env, monkeypatch):
    """No fakes inside ai_analysis: scoring, prompt building and JSON validation all run for real."""
    reply = json.dumps({"why": "w", "business_impact": "b", "fixes": ["f"], "confidence": 70, "priority_tier": "P1"})
    monkeypatch.setattr(app_env.ai_analysis, "ollama_chat", lambda *a, **k: reply)
    client, _ = app_env.login_as()
    body = client.post("/api/analyze", json={"vulnerabilities": [{"cve": "CVE-1", "cvss": 9.1, "severity": "Critical"}]}).get_json()
    v = body["vulnerabilities"][0]
    assert v["ai_generated"] is True and v["priority_tier"] == "P1" and v["business_priority_score"] == 9.1


def test_analyzer_and_chatbot_are_created_once_and_reused(app_env, monkeypatch):
    s = app_env.scanner
    made = []
    monkeypatch.setattr(s, "OllamaVulnerabilityAnalyzer", lambda: made.append("a") or object())
    monkeypatch.setattr(s, "ScanChatbot", lambda: made.append("c") or object())
    assert s._get_analyzer() is s._get_analyzer() and s._get_chatbot() is s._get_chatbot()
    assert made == ["a", "c"]


# ---------------------------------------------------------------------------
# /api/chat
# ---------------------------------------------------------------------------
class FakeBot:
    def __init__(self, answer="42", error=None):
        self.answer, self.error, self.calls = answer, error, []

    def ask(self, question, vulns, history):
        self.calls.append((question, vulns, history))
        if self.error:
            raise self.error
        return self.answer


@pytest.fixture()
def bot(app_env, monkeypatch):
    b = FakeBot()
    monkeypatch.setattr(app_env.scanner, "_get_chatbot", lambda: b)
    return b


def test_chat_returns_the_answer_and_passes_context_through(app_env, bot):
    r = app_env.login_as()[0].post("/api/chat", json={"question": "  What first?  ", "vulnerabilities": [{"cve": "C"}],
                                                      "history": [{"role": "user", "content": "hi"}]})
    assert r.get_json() == {"answer": "42"}
    assert bot.calls == [("What first?", [{"cve": "C"}], [{"role": "user", "content": "hi"}])]


@pytest.mark.parametrize("body,fragment", [
    ({"vulnerabilities": []}, "Missing 'question'"),
    ({"question": "   ", "vulnerabilities": []}, "Missing 'question'"),
    ({"question": "q"}, "'vulnerabilities' array"),
    ({"question": "q", "vulnerabilities": "x"}, "'vulnerabilities' array"),
    ({"question": "q", "vulnerabilities": [], "history": "x"}, "'history' must be an array"),
])
def test_chat_validation(app_env, bot, body, fragment):
    r = app_env.client().post("/api/chat", json=body)
    assert r.status_code == 400 and fragment in r.get_json()["error"]
    assert bot.calls == []


def test_chat_history_is_optional(app_env, bot):
    assert app_env.client().post("/api/chat", json={"question": "q", "vulnerabilities": []}).status_code == 200
    assert bot.calls[0][2] is None


def test_chat_model_failures_are_502_and_setup_failures_503(app_env, bot, monkeypatch):
    bot.error = RuntimeError("model crashed")
    r = app_env.client().post("/api/chat", json={"question": "q", "vulnerabilities": []})
    assert r.status_code == 502 and "model crashed" in r.get_json()["error"]

    def broken():
        raise EnvironmentError("no ollama")

    monkeypatch.setattr(app_env.scanner, "_get_chatbot", broken)
    r = app_env.client().post("/api/chat", json={"question": "q", "vulnerabilities": []})
    assert r.status_code == 503


@pytest.mark.xfail(strict=True, reason="DESIGN GAP: /api/chat (and /api/export) have no @require_role, so anyone who can reach "
                                        "the server can drive the local LLM without an account. If chat is meant to be "
                                        "members-only, add @require_role('admin','analyst','viewer') and remove this marker.")
def test_chat_requires_sign_in(app_env, bot):
    assert app_env.client().post("/api/chat", json={"question": "q", "vulnerabilities": []}).status_code == 401


# ---------------------------------------------------------------------------
# /api/export
# ---------------------------------------------------------------------------
def _export(client, vulns):
    return client.post("/api/export", json={"vulnerabilities": vulns})


def _sheet(resp):
    return load_workbook(BytesIO(resp.data)).active


FULL = {"cve": "CVE-1", "title": "Heap bug", "severity": "Critical", "cvss": 9.8, "business_priority_score": 14.7,
        "asset": "web-01", "package": "openssl", "installedVersion": "1.1", "why": "RCE", "business_impact": "Bad",
        "fixes": ["Patch", "Restart"], "confidence": 85, "tenable_exposure": {"matched": True}, "source": "trivy",
        "publishedDate": "2024-01-01", "references": ["https://a", "https://b"]}


def test_export_returns_an_xlsx_attachment(app_env):
    r = _export(app_env.client(), [FULL])
    assert r.status_code == 200
    assert r.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert "attachment" in r.headers["Content-Disposition"]
    assert r.headers["Content-Disposition"].count("vulnerability-report-") == 1 and ".xlsx" in r.headers["Content-Disposition"]
    assert r.data[:2] == b"PK"  # xlsx files are zip archives


def test_export_sheet_layout(app_env):
    ws = _sheet(_export(app_env.client(), [FULL]))
    headers = [c.value for c in ws[1]]
    assert ws.title == "Vulnerabilities" and headers[:5] == ["CVE", "Title", "Severity", "CVSS", "Business Priority"]
    assert len(headers) == 15 and ws.freeze_panes == "A2" and ws.auto_filter.ref == "A1:O2"
    assert ws["A1"].font.bold and ws["A1"].fill.start_color.rgb.endswith("2563EB")


def test_export_row_values_and_reshaping(app_env):
    ws = _sheet(_export(app_env.client(), [FULL]))
    row = {ws.cell(1, c).value: ws.cell(2, c).value for c in range(1, 16)}
    assert row["CVE"] == "CVE-1" and row["CVSS"] == 9.8 and row["Business Priority"] == 14.7
    assert row["Suggested Fixes"] == "Patch; Restart"
    assert row["Tenable Exposure"] == "Confirmed in inventory"
    assert row["AI Confidence (%)"] == 85 and row["Installed Version"] == "1.1"


def test_export_blank_cells_for_missing_data_and_unmatched_exposure(app_env):
    ws = _sheet(_export(app_env.client(), [{"cve": "CVE-2", "severity": "Low", "tenable_exposure": {"matched": False}}]))
    row = {ws.cell(1, c).value: ws.cell(2, c).value for c in range(1, 16)}
    assert row["Tenable Exposure"] == "Not found in inventory"
    assert row["Why It Matters"] in (None, "") and row["Suggested Fixes"] in (None, "")


def test_export_cell_value_helper_cases(app_env):
    f = app_env.scanner._export_cell_value
    assert f({"fixes": "just text"}, "fixes") == "just text"
    assert f({}, "fixes") == ""
    assert f({"tenable_exposure": None}, "tenable_exposure") == ""
    assert f({"references": ["a", "b"]}, "references") == '["a", "b"]'
    assert f({"cvss": 0}, "cvss") == 0
    assert f({"cvss": None}, "cvss") == ""


def test_export_colours_only_the_severity_cell(app_env):
    vulns = [{"severity": s} for s in ("Critical", "High", "Medium", "Low", "Unknown")]
    ws = _sheet(_export(app_env.client(), vulns))
    colours = [ws.cell(r, 3).fill.start_color.rgb[-6:] for r in range(2, 7)]
    assert colours[:4] == ["FEE2E2", "FFEDD5", "FEF9C3", "DCFCE7"]
    assert ws.cell(6, 3).fill.fill_type is None and ws.cell(2, 1).fill.fill_type is None


def test_export_skips_non_object_entries_and_handles_an_empty_list(app_env):
    ws = _sheet(_export(app_env.client(), ["junk", None, 3, {"cve": "CVE-1"}]))
    assert ws.max_row == 2
    empty = _sheet(_export(app_env.client(), []))
    assert empty.max_row == 1 and empty.auto_filter.ref == "A1:O1"


@pytest.mark.parametrize("body", [{}, {"vulnerabilities": "x"}, {"vulnerabilities": None}])
def test_export_needs_a_vulnerabilities_array(app_env, body):
    assert app_env.client().post("/api/export", json=body).status_code == 400
