"""Tests for scans.py — recording completed scans, the "new since last scan"
diff that drives email alerts, notification gating, scan history, and the
long-term analysis view."""
import json

import pytest


def _vuln(cve, severity="High", **kw):
    return {"cve": cve, "severity": severity, "title": f"{cve} title", "cvss": 7.5, **kw}


def _insert_scan(env, uid, created_at, cves=(), scanner="trivy", **counts):
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    c.update(counts)
    env.execute(
        "INSERT INTO scans (user_id, scanner, source, target, total, critical, high, medium, low, unknown, cve_ids, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (uid, scanner, "upload", "img:1", sum(c.values()), c["critical"], c["high"], c["medium"], c["low"],
         c["unknown"], json.dumps(list(cves)), created_at),
    )


def _enable_email(env, uid, level="critical", jira=0):
    env.execute("UPDATE users SET notify_on_critical = 1, notify_level = ?, notify_on_jira = ? WHERE id = ?",
                (level, jira, uid))


@pytest.fixture()
def sent(app_env, monkeypatch):
    """Capture scan notification emails instead of sending them."""
    calls = []
    monkeypatch.setattr(app_env.email_notifications, "send_scan_notification",
                        lambda *a, **k: calls.append((a, k)))
    return calls


# ---------------------------------------------------------------------------
# record_scan
# ---------------------------------------------------------------------------
def test_record_scan_is_a_no_op_without_a_user(app_env):
    assert app_env.scans.record_scan(None, "trivy", "upload", "x", [_vuln("CVE-1", "Critical")]) == []
    assert app_env.query("SELECT COUNT(*) AS n FROM scans")[0]["n"] == 0


def test_record_scan_counts_each_severity_and_stores_cve_ids(app_env):
    uid = app_env.make_user()
    vulns = [_vuln("CVE-1", "Critical"), _vuln("CVE-2", "High"), _vuln("CVE-3", "high"), _vuln("CVE-4", "MEDIUM"),
             _vuln("CVE-5", "Low"), _vuln("CVE-6", "Unknown"), _vuln("CVE-7", "bogus"), _vuln("CVE-8", None),
             {"severity": "High"}]  # no CVE -> counted but not listed
    app_env.scans.record_scan(uid, "trivy", "upload", "img:1", vulns)
    row = app_env.query("SELECT * FROM scans")[0]
    assert (row["total"], row["critical"], row["high"], row["medium"], row["low"], row["unknown"]) == (9, 1, 3, 1, 1, 3)
    assert json.loads(row["cve_ids"]) == [f"CVE-{i}" for i in range(1, 9)]
    assert (row["scanner"], row["source"], row["target"]) == ("trivy", "upload", "img:1")


def test_record_scan_accepts_an_empty_or_missing_list(app_env):
    uid = app_env.make_user()
    assert app_env.scans.record_scan(uid, "trivy", "upload", "t", []) == []
    assert app_env.scans.record_scan(uid, "trivy", "upload", "t", None) == []
    assert [r["total"] for r in app_env.query("SELECT total FROM scans")] == [0, 0]


def test_first_scan_treats_every_finding_at_or_above_the_threshold_as_new(app_env):
    uid = app_env.make_user()
    new = app_env.scans.record_scan(uid, "trivy", "upload", "t",
                                    [_vuln("CVE-1", "Critical"), _vuln("CVE-2", "High")], min_severity="critical")
    assert [v["cve"] for v in new] == ["CVE-1"]


@pytest.mark.parametrize("level,expected", [
    ("critical", {"CVE-C"}),
    ("high", {"CVE-C", "CVE-H"}),
    ("medium", {"CVE-C", "CVE-H", "CVE-M"}),
])
def test_min_severity_threshold(app_env, level, expected):
    uid = app_env.make_user()
    vulns = [_vuln("CVE-C", "Critical"), _vuln("CVE-H", "High"), _vuln("CVE-M", "Medium"), _vuln("CVE-L", "Low")]
    new = app_env.scans.record_scan(uid, "trivy", "upload", "t", vulns, min_severity=level)
    assert {v["cve"] for v in new} == expected


def test_unknown_min_severity_falls_back_to_critical(app_env):
    uid = app_env.make_user()
    new = app_env.scans.record_scan(uid, "t", "upload", "t", [_vuln("A", "Critical"), _vuln("B", "High")], min_severity="whatever")
    assert [v["cve"] for v in new] == ["A"]


def test_only_findings_absent_from_the_previous_scan_count_as_new(app_env, fake_clock):
    fake_clock(app_env.scans)
    uid = app_env.make_user()
    app_env.scans.record_scan(uid, "trivy", "upload", "t", [_vuln("CVE-OLD", "Critical")])
    new = app_env.scans.record_scan(uid, "trivy", "upload", "t",
                                    [_vuln("CVE-OLD", "Critical"), _vuln("CVE-NEW", "Critical")])
    assert [v["cve"] for v in new] == ["CVE-NEW"]


def test_diff_is_against_the_immediately_previous_scan_only(app_env, fake_clock):
    fake_clock(app_env.scans)
    uid = app_env.make_user()
    rec = app_env.scans.record_scan
    rec(uid, "t", "upload", "t", [_vuln("CVE-A", "Critical")])
    rec(uid, "t", "upload", "t", [])  # A is "fixed"
    new = rec(uid, "t", "upload", "t", [_vuln("CVE-A", "Critical")])  # ...and regresses
    assert [v["cve"] for v in new] == ["CVE-A"]


def test_diff_ignores_other_users_scans(app_env):
    a, b = app_env.make_user(), app_env.make_user()
    _insert_scan(app_env, a, "2026-01-01T00:00:00+00:00", cves=["CVE-1"])
    new = app_env.scans.record_scan(b, "t", "upload", "t", [_vuln("CVE-1", "Critical")])
    assert [v["cve"] for v in new] == ["CVE-1"]


def test_findings_without_a_cve_are_never_reported_as_new(app_env):
    uid = app_env.make_user()
    assert app_env.scans.record_scan(uid, "t", "upload", "t", [{"severity": "Critical", "title": "no id"}]) == []


# ---------------------------------------------------------------------------
# _notification_prefs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("enabled,level,jira,expected", [
    (0, "critical", 1, (None, False)),   # master switch off wins over everything
    (1, "critical", 0, ("critical", False)),
    (1, "high", 1, ("high", True)),
    (1, "medium", 0, ("medium", False)),
    (1, "none", 1, (None, True)),        # jira emails only
    (1, "bogus", 0, (None, False)),
])
def test_notification_prefs(app_env, enabled, level, jira, expected):
    uid = app_env.make_user(notify_on_critical=enabled, notify_level=level, notify_on_jira=jira)
    assert app_env.scans._notification_prefs(app_env.auth.get_user_by_id(uid)) == expected


def test_notification_prefs_for_no_user(app_env):
    assert app_env.scans._notification_prefs(None) == (None, False)


# ---------------------------------------------------------------------------
# POST /api/scans
# ---------------------------------------------------------------------------
def _complete(client, **body):
    payload = {"scanner": "trivy", "source": "upload", "target": "img:1", "vulnerabilities": [_vuln("CVE-1", "Critical")]}
    payload.update(body)
    return client.post("/api/scans", json=payload)


def test_complete_scan_records_it(app_env, sent):
    client, uid = app_env.login_as()
    assert _complete(client).get_json() == {"status": "recorded"}
    row = app_env.query("SELECT * FROM scans WHERE user_id = ?", (uid,))[0]
    assert row["critical"] == 1 and row["scanner"] == "trivy" and row["target"] == "img:1"


def test_complete_scan_validates_input_and_role(app_env, sent):
    client, _ = app_env.login_as()
    assert client.post("/api/scans", json={}).status_code == 400
    assert client.post("/api/scans", json={"vulnerabilities": "x"}).status_code == 400
    assert client.post("/api/scans", data="not json").status_code == 400
    assert _complete(app_env.client()).status_code == 401
    viewer, _ = app_env.login_as(role="viewer")
    assert _complete(viewer).status_code == 403
    assert app_env.query("SELECT COUNT(*) AS n FROM scans")[0]["n"] == 0


def test_no_email_when_notifications_are_off(app_env, sent):
    client, _ = app_env.login_as()
    _complete(client)
    assert sent == []


def test_email_goes_out_for_new_findings_at_the_users_level(app_env, sent):
    client, uid = app_env.login_as(email="me@example.com", name="Me")
    _enable_email(app_env, uid, "high")
    _complete(client, vulnerabilities=[_vuln("CVE-1", "Critical"), _vuln("CVE-2", "High"), _vuln("CVE-3", "Medium")])
    (args, kwargs), = sent
    assert args[0] == "me@example.com" and args[1] == "Me"
    assert {v["cve"] for v in args[2]} == {"CVE-1", "CVE-2"}
    assert kwargs["min_severity"] == "high" and kwargs["scan_context"] == {"scanner": "trivy", "target": "img:1"}
    assert kwargs["jira_tickets"] == []


def test_no_email_when_nothing_new_appears(app_env, sent):
    client, uid = app_env.login_as()
    _enable_email(app_env, uid)
    _complete(client)
    sent.clear()
    _complete(client)  # identical scan -> nothing new
    assert sent == []


def test_jira_only_email_and_ticket_filtering(app_env, sent):
    client, uid = app_env.login_as()
    _enable_email(app_env, uid, level="none", jira=1)
    _complete(client, jiraTickets=[{"issueKey": "V-1", "title": "t"}, {"title": "no key"}, "junk", 5])
    (args, kwargs), = sent
    assert args[2] == []  # severity emails are off
    assert kwargs["jira_tickets"] == [{"issueKey": "V-1", "title": "t"}]


def test_jira_tickets_are_ignored_unless_the_user_opted_in(app_env, sent):
    client, uid = app_env.login_as()
    _enable_email(app_env, uid, level="none", jira=0)
    _complete(client, jiraTickets=[{"issueKey": "V-1"}])
    assert sent == []


def test_findings_and_jira_tickets_travel_in_one_combined_email(app_env, sent):
    client, uid = app_env.login_as()
    _enable_email(app_env, uid, level="critical", jira=1)
    _complete(client, jiraTickets=[{"issueKey": "V-1"}])
    assert len(sent) == 1
    (args, kwargs), = sent
    assert len(args[2]) == 1 and len(kwargs["jira_tickets"]) == 1


def test_non_list_jira_tickets_are_tolerated(app_env, sent):
    client, uid = app_env.login_as()
    _enable_email(app_env, uid, level="none", jira=1)
    assert _complete(client, jiraTickets="nope").status_code == 200
    assert sent == []


def test_email_failures_never_fail_the_request(app_env, monkeypatch):
    client, uid = app_env.login_as()
    _enable_email(app_env, uid)

    def not_configured(*a, **k):
        raise EnvironmentError("no smtp")

    monkeypatch.setattr(app_env.email_notifications, "send_scan_notification", not_configured)
    assert _complete(client).status_code == 200

    def exploded(*a, **k):
        raise RuntimeError("provider down")

    monkeypatch.setattr(app_env.email_notifications, "send_scan_notification", exploded)
    app_env.execute("DELETE FROM scans")
    assert _complete(client).status_code == 200
    assert app_env.query("SELECT COUNT(*) AS n FROM scans")[0]["n"] == 1  # scan still recorded


# ---------------------------------------------------------------------------
# GET /api/scans
# ---------------------------------------------------------------------------
def test_list_scans_empty_when_signed_out_or_no_history(app_env):
    assert app_env.client().get("/api/scans").get_json() == []
    client, _ = app_env.login_as()
    assert client.get("/api/scans").get_json() == []


def test_list_scans_is_newest_first_and_private(app_env):
    client, uid = app_env.login_as()
    other = app_env.make_user()
    _insert_scan(app_env, uid, "2026-01-01T00:00:00+00:00", cves=["CVE-1"], high=1)
    _insert_scan(app_env, uid, "2026-02-01T00:00:00+00:00", cves=["CVE-2"], critical=2)
    _insert_scan(app_env, other, "2026-03-01T00:00:00+00:00")
    scans = client.get("/api/scans").get_json()
    assert [s["createdAt"][:7] for s in scans] == ["2026-02", "2026-01"]
    assert scans[0] == {
        "id": scans[0]["id"], "scanner": "trivy", "source": "upload", "target": "img:1", "total": 2,
        "critical": 2, "high": 0, "medium": 0, "low": 0, "unknown": 0, "cveIds": ["CVE-2"],
        "createdAt": "2026-02-01T00:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# GET /api/scans/analysis
# ---------------------------------------------------------------------------
def test_analysis_without_history_has_the_empty_shape(app_env):
    empty = {"hasScans": False, "totals": {}, "trend": [], "recurring": [], "scans": []}
    assert app_env.client().get("/api/scans/analysis").get_json() == empty
    client, _ = app_env.login_as()
    assert client.get("/api/scans/analysis").get_json() == empty


def test_analysis_trend_is_oldest_first_and_scans_table_newest_first(app_env):
    client, uid = app_env.login_as()
    _insert_scan(app_env, uid, "2026-01-05T00:00:00+00:00", critical=1)
    _insert_scan(app_env, uid, "2026-02-10T00:00:00+00:00", high=2)
    body = client.get("/api/scans/analysis").get_json()
    assert [t["label"] for t in body["trend"]] == ["Jan 5", "Feb 10"]
    assert [t["total"] for t in body["trend"]] == [1, 2]
    assert [s["createdAt"][:10] for s in body["scans"]] == ["2026-02-10", "2026-01-05"]


def test_analysis_recurring_cves_still_open_vs_resolved(app_env):
    client, uid = app_env.login_as()
    _insert_scan(app_env, uid, "2026-01-01T00:00:00+00:00", cves=["CVE-STAY", "CVE-FIXED", "CVE-ONCE"])
    _insert_scan(app_env, uid, "2026-02-01T00:00:00+00:00", cves=["CVE-STAY", "CVE-FIXED"])
    _insert_scan(app_env, uid, "2026-03-01T00:00:00+00:00", cves=["CVE-STAY", "CVE-NEW"])
    body = client.get("/api/scans/analysis").get_json()
    recurring = {r["cve"]: r for r in body["recurring"]}
    assert set(recurring) == {"CVE-STAY", "CVE-FIXED"}  # CVE-ONCE and CVE-NEW appeared once
    assert recurring["CVE-STAY"] == {"cve": "CVE-STAY", "occurrences": 3, "firstSeen": "2026-01-01T00:00:00+00:00",
                                     "lastSeen": "2026-03-01T00:00:00+00:00", "stillOpen": True}
    assert recurring["CVE-FIXED"]["stillOpen"] is False and recurring["CVE-FIXED"]["occurrences"] == 2
    # most occurrences first
    assert [r["cve"] for r in body["recurring"]] == ["CVE-STAY", "CVE-FIXED"]


def test_analysis_recurring_ties_put_open_first_then_alphabetical(app_env):
    client, uid = app_env.login_as()
    _insert_scan(app_env, uid, "2026-01-01T00:00:00+00:00", cves=["CVE-B", "CVE-A", "CVE-Z", "CVE-Y"])
    _insert_scan(app_env, uid, "2026-02-01T00:00:00+00:00", cves=["CVE-B", "CVE-A", "CVE-Z", "CVE-Y"])
    _insert_scan(app_env, uid, "2026-03-01T00:00:00+00:00", cves=["CVE-B", "CVE-Y"])
    order = [r["cve"] for r in client.get("/api/scans/analysis").get_json()["recurring"]]
    # All four recur; B and Y occur 3x and are still open (alphabetical), A and Z occur 2x and are resolved
    assert order == ["CVE-B", "CVE-Y", "CVE-A", "CVE-Z"]


def test_analysis_totals(app_env):
    client, uid = app_env.login_as()
    _insert_scan(app_env, uid, "2026-01-01T00:00:00+00:00", cves=["CVE-1", "CVE-2"], scanner="trivy", high=2)
    _insert_scan(app_env, uid, "2026-02-01T00:00:00+00:00", cves=["CVE-1", "CVE-3", "CVE-4"], scanner="tenable", high=3)
    _insert_scan(app_env, uid, "2026-03-01T00:00:00+00:00", cves=["CVE-1"], scanner="trivy", high=1)
    _insert_scan(app_env, uid, "2026-04-01T00:00:00+00:00", cves=[], scanner=None)
    totals = client.get("/api/scans/analysis").get_json()["totals"]
    assert totals["scanCount"] == 4
    assert totals["avgFindingsPerScan"] == 1.5  # (2+3+1+0)/4
    assert totals["uniqueCvesSeen"] == 4
    assert totals["resolvedCves"] == 4  # latest scan has no CVEs
    assert totals["recurringCveCount"] == 1  # only CVE-1
    assert totals["scannerBreakdown"] == {"trivy": 2, "tenable": 1, "unknown": 1}


def test_analysis_caps_the_recurring_list_at_25(app_env):
    client, uid = app_env.login_as()
    cves = [f"CVE-{i:03d}" for i in range(40)]
    _insert_scan(app_env, uid, "2026-01-01T00:00:00+00:00", cves=cves)
    _insert_scan(app_env, uid, "2026-02-01T00:00:00+00:00", cves=cves)
    body = client.get("/api/scans/analysis").get_json()
    assert len(body["recurring"]) == 25 and body["totals"]["recurringCveCount"] == 40


def test_analysis_only_uses_the_callers_scans(app_env):
    client, uid = app_env.login_as()
    other = app_env.make_user()
    _insert_scan(app_env, other, "2026-01-01T00:00:00+00:00", cves=["CVE-OTHER"])
    assert client.get("/api/scans/analysis").get_json()["hasScans"] is False


def test_analysis_tolerates_a_row_with_null_cve_ids(app_env):
    client, uid = app_env.login_as()
    app_env.execute("INSERT INTO scans (user_id, total, created_at) VALUES (?, 0, '2026-01-01T00:00:00+00:00')", (uid,))
    body = client.get("/api/scans/analysis").get_json()
    assert body["hasScans"] is True and body["totals"]["uniqueCvesSeen"] == 0


# ---------------------------------------------------------------------------
# _short_date
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("iso,expected", [
    ("2026-08-09T10:00:00+00:00", "Aug 9"),
    ("2026-12-25T00:00:00+00:00", "Dec 25"),
    ("2026-01-01", "Jan 1"),
    ("garbage-timestamp", "garbage-ti"),
])
def test_short_date(app_env, iso, expected):
    assert app_env.scans._short_date(iso) == expected
