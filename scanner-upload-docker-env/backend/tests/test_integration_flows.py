"""End-to-end journeys through the real app (all blueprints, real SQLite, real
parsing/scoring) with only the outside world faked: the LLM, email, Jira.

Each test is one realistic user story. They exist to catch wiring problems
that the focused unit tests can't see — e.g. a module reading the wrong
session key, or a response shape one module produces that another can't use."""
import json
from io import BytesIO

import pytest

PASSWORD = "Str0ng!pass"

QUESTIONNAIRE = {
    "sector": "healthcare", "dataSensitivity": ["medical"], "availabilityImpact": "life_safety",
    "internetFacing": "public", "exposedSystems": ["api"], "complianceScope": ["hipaa"], "airGapped": False,
    "topConcern": "legal_regulatory", "hadBreach": "no", "revenueGenerating": True,
}

TRIVY = {"Results": [{"Target": "api:1.0 (debian 12)", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1", "Severity": "CRITICAL",
     "Title": "OpenSSL RCE", "CVSS": {"nvd": {"V3Score": 9.8}}},
    {"VulnerabilityID": "CVE-2024-0002", "PkgName": "zlib", "InstalledVersion": "1.2", "Severity": "MEDIUM",
     "Title": "zlib overflow", "CVSS": {"nvd": {"V3Score": 5.5}}},
]}]}

LLM_REPLY = json.dumps({"why": "Remote code execution.", "business_impact": "Patient data at risk.",
                        "fixes": ["Upgrade openssl"], "confidence": 85, "priority_tier": "P1"})


@pytest.fixture()
def world(app_env, monkeypatch):
    """Fakes for everything outside the app; returns the list of emails 'sent'."""
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    monkeypatch.setattr(app_env.ai_analysis, "ollama_chat", lambda *a, **k: LLM_REPLY)
    emails = []
    monkeypatch.setattr(app_env.email_notifications, "send_scan_notification", lambda *a, **k: emails.append((a, k)))
    return emails


def _signup(client, email, name="Ada"):
    r = client.post("/api/auth/signup", json={"name": name, "email": email, "password": PASSWORD})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()


def test_a_full_analyst_journey_from_signup_to_dashboard(app_env, world):
    client = app_env.client()
    assert _signup(client, "ada@example.com")["role"] == "admin"

    # Onboarding questionnaire
    assert client.post("/api/business-context", json=QUESTIONNAIRE).get_json()["criticalityTier"] == 1
    assert client.get("/api/business-context/me").get_json()["completed"] is True

    # Opt in to critical-finding emails
    client.patch("/api/auth/notifications", json={"enabled": True, "level": "critical"})

    # Upload a Trivy report
    up = client.post("/api/upload-scan", data={"file": (BytesIO(json.dumps(TRIVY).encode()), "trivy.json")},
                     content_type="multipart/form-data").get_json()
    assert up["scanner"] == "trivy" and up["vulnerabilitiesFound"] == 2

    # AI analysis, with the business context applied to the score
    analysed = client.post("/api/analyze", json={"vulnerabilities": up["vulnerabilities"]}).get_json()
    assert analysed["businessContextApplied"] is True
    top = analysed["vulnerabilities"][0]
    assert top["cve"] == "CVE-2024-0001" and top["ai_generated"] is True
    assert top["business_priority_score"] > top["cvss"]  # healthcare + tier 1 + public + HIPAA all amplify it

    # Create tickets from the analysed findings, the way the wizard does: no ids are sent, the
    # server numbers them. Doing it twice must add tickets, not overwrite the first batch.
    tickets = [{"cve": v["cve"], "title": v["title"], "priority": v["priority_tier"], "status": "Open",
                "cvss": v["cvss"], "confidence": v["confidence"], "fixes": v["fixes"], "why": v["why"]}
               for v in analysed["vulnerabilities"]]
    first = client.post("/api/tickets", json=tickets)
    assert first.status_code == 201
    assert [t["id"] for t in first.get_json()["created"]] == ["T-106", "T-107"]
    second = client.post("/api/tickets", json=tickets)
    assert [t["id"] for t in second.get_json()["created"]] == ["T-108", "T-109"]
    assert len(client.get("/api/tickets").get_json()) == 4
    # ...then confirm the scan
    done = client.post("/api/scans", json={"scanner": "trivy", "source": "upload", "target": "api:1.0",
                                           "vulnerabilities": analysed["vulnerabilities"]})
    assert done.get_json() == {"status": "recorded"}

    # The critical finding triggered exactly one email, containing only that finding
    (args, kwargs), = world
    assert [v["cve"] for v in args[2]] == ["CVE-2024-0001"] and kwargs["scan_context"]["target"] == "api:1.0"

    # Dashboard, history and trend all reflect the work
    summary = client.get("/api/dashboard/summary").get_json()
    assert summary["hasScans"] and summary["totalVulnerabilities"] == 2 and summary["critical"] == 1
    assert summary["newSinceLastScan"] == 2
    assert any(a["tag"] == "Ticket" for a in summary["recentActivity"])
    assert len(client.get("/api/scans").get_json()) == 1
    assert client.get("/api/scans/analysis").get_json()["totals"]["scanCount"] == 1

    # Export what the user saw
    xlsx = client.post("/api/export", json={"vulnerabilities": analysed["vulnerabilities"]})
    assert xlsx.status_code == 200 and xlsx.data[:2] == b"PK"


def test_rescanning_only_alerts_on_what_is_new(app_env, world, fake_clock):
    fake_clock(app_env.scans)
    client, uid = app_env.login_as()
    app_env.execute("UPDATE users SET notify_on_critical = 1, notify_level = 'critical' WHERE id = ?", (uid,))
    first = [{"cve": "CVE-A", "severity": "Critical", "title": "a"}]
    second = first + [{"cve": "CVE-B", "severity": "Critical", "title": "b"}]
    client.post("/api/scans", json={"scanner": "trivy", "target": "t", "vulnerabilities": first})
    client.post("/api/scans", json={"scanner": "trivy", "target": "t", "vulnerabilities": second})
    assert [[v["cve"] for v in args[2]] for args, _ in world] == [["CVE-A"], ["CVE-B"]]
    summary = client.get("/api/dashboard/summary").get_json()
    assert summary["newSinceLastScan"] == 1 and summary["totalDeltaPct"] == 100


def test_roles_are_enforced_across_the_whole_api(app_env, world):
    admin = app_env.client()
    _signup(admin, "boss@example.com")            # first account -> admin
    analyst = app_env.client()
    assert _signup(analyst, "analyst@example.com")["role"] == "analyst"

    viewer_id = app_env.make_user(email="viewer@example.com", role="viewer")
    viewer = app_env.client(viewer_id)

    def upload_kwargs():  # a fresh file object per request, since a request consumes it
        return {"data": {"file": (BytesIO(b"{}"), "x.json")}, "content_type": "multipart/form-data"}

    writes = [
        ("post", "/api/upload-scan", upload_kwargs),
        ("post", "/api/scan", lambda: {"json": {"scanner": "trivy", "target": "x"}}),
        ("post", "/api/analyze", lambda: {"json": {"vulnerabilities": []}}),
        ("post", "/api/tickets", lambda: {"json": []}),
        ("post", "/api/scans", lambda: {"json": {"vulnerabilities": []}}),
        ("post", "/api/business-context", lambda: {"json": QUESTIONNAIRE}),
        ("post", "/api/registry/connect", lambda: {"json": {"url": "u", "username": "u", "password": "p"}}),
        ("get", "/api/jira/connect", dict),
    ]
    for method, path, kwargs in writes:
        assert getattr(viewer, method)(path, **kwargs()).status_code == 403, f"viewer was allowed: {method.upper()} {path}"
        assert getattr(app_env.client(), method)(path, **kwargs()).status_code == 401, f"signed-out user was allowed: {path}"

    # Read-only surfaces still work for a viewer
    for path in ("/api/tickets", "/api/scans", "/api/dashboard/summary", "/api/scans/analysis", "/api/auth/me"):
        assert viewer.get(path).status_code == 200, path

    # Only admins manage users
    assert analyst.get("/api/auth/users").status_code == 403
    assert admin.get("/api/auth/users").status_code == 200
    assert admin.patch(f"/api/auth/users/{viewer_id}/role", json={"role": "analyst"}).status_code == 200
    assert viewer.post("/api/scans", json={"vulnerabilities": []}).status_code == 200  # promotion is live immediately


def test_each_accounts_data_is_isolated_end_to_end(app_env, world):
    a, b = app_env.client(), app_env.client()
    _signup(a, "a@example.com")
    _signup(b, "b@example.com")
    a.post("/api/business-context", json=QUESTIONNAIRE)
    a.post("/api/tickets", json=[{"id": "T-1", "title": "mine"}])
    a.post("/api/scans", json={"scanner": "trivy", "target": "t", "vulnerabilities": [{"cve": "CVE-1", "severity": "High"}]})
    a.post("/api/registry/connect", json={"url": "u", "username": "u", "password": "p"})

    assert b.get("/api/tickets").get_json() == []
    assert b.get("/api/scans").get_json() == []
    assert b.get("/api/business-context/me").get_json() == {"completed": False}
    assert b.get("/api/registry/status").get_json() == {"connected": False}
    assert b.get("/api/dashboard/summary").get_json()["hasScans"] is False
    assert b.patch("/api/tickets/T-1", json={"status": "Closed"}).status_code == 404


def test_logging_out_locks_every_protected_endpoint_again(app_env, world):
    client = app_env.client()
    _signup(client, "ada@example.com")
    assert client.post("/api/analyze", json={"vulnerabilities": []}).status_code == 200
    client.post("/api/auth/logout")
    assert client.post("/api/analyze", json={"vulnerabilities": []}).status_code == 401
    assert client.get("/api/tickets").get_json() == []
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}


def test_mfa_login_end_to_end_through_the_real_endpoints(app_env, monkeypatch):
    import re
    sent = []
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: True)
    monkeypatch.setattr(app_env.email_notifications, "send_plain_email", lambda to, subject, body: sent.append(body))
    client = app_env.client()
    _signup(client, "ada@example.com")
    client.patch("/api/auth/mfa", json={"enabled": True})
    client.post("/api/auth/logout")

    r = client.post("/api/auth/login", json={"email": "ada@example.com", "password": PASSWORD})
    assert r.get_json()["status"] == "mfa_required"
    assert client.get("/api/tickets").get_json() == []  # not signed in yet
    code = re.search(r"(\d{6})", sent[-1]).group(1)
    assert client.post("/api/auth/mfa/verify", json={"code": code}).get_json()["status"] == "signed_in"
    assert client.get("/api/auth/me").get_json()["authenticated"] is True
