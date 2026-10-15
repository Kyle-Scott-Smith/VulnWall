"""Tests for dashboard.py — the numbers on the Security Overview page,
computed from scans + tickets."""
import json

import pytest


def _scan(env, uid, created_at, total=0, critical=0, medium=0, cves=()):
    env.execute(
        "INSERT INTO scans (user_id, scanner, source, target, total, critical, medium, cve_ids, created_at) "
        "VALUES (?, 'trivy', 'upload', 't', ?, ?, ?, ?, ?)",
        (uid, total, critical, medium, json.dumps(list(cves)), created_at),
    )


def _ticket(env, uid, ref, status="Open", priority="P1", title=None, updated="2026-05-01T00:00:00+00:00"):
    env.execute(
        "INSERT INTO tickets (user_id, ticket_ref, title, priority, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
        (uid, ref, title or f"Ticket {ref}", priority, status, updated, updated),
    )


def _summary(client):
    r = client.get("/api/dashboard/summary")
    assert r.status_code == 200
    return r.get_json()


def test_signed_out_users_get_the_empty_summary(app_env):
    s = _summary(app_env.client())
    assert s["hasScans"] is False and s["totalVulnerabilities"] == 0 and s["totalDeltaPct"] is None
    assert s["chart"] == [] and s["recentActivity"] == [] and "Upload or run a scan" in s["aiInsight"]


def test_a_new_account_with_nothing_yet_gets_the_empty_summary(app_env):
    client, _ = app_env.login_as()
    s = _summary(client)
    assert s["hasScans"] is False and s["newSinceLastScan"] == 0


def test_tickets_without_any_scan_still_show_activity(app_env):
    client, uid = app_env.login_as()
    _ticket(app_env, uid, "T-1")
    s = _summary(client)
    assert s["hasScans"] is False
    assert s["recentActivity"][0] == {"tag": "Ticket", "label": "1 ticket(s) created"}


def test_single_scan_everything_counts_as_new_and_there_is_no_delta(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=7, critical=2, medium=3, cves=["CVE-1"])
    s = _summary(client)
    assert s["hasScans"] is True
    assert (s["totalVulnerabilities"], s["critical"], s["medium"]) == (7, 2, 3)
    assert s["totalDeltaPct"] is None and s["newSinceLastScan"] == 7


def test_delta_is_percentage_change_against_the_previous_scan(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=40)
    _scan(app_env, uid, "2026-05-02T00:00:00+00:00", total=50)
    assert _summary(client)["totalDeltaPct"] == 25
    _scan(app_env, uid, "2026-05-03T00:00:00+00:00", total=25)
    assert _summary(client)["totalDeltaPct"] == -50


def test_delta_rounds_to_a_whole_percent(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=3)
    _scan(app_env, uid, "2026-05-02T00:00:00+00:00", total=4)
    assert _summary(client)["totalDeltaPct"] == 33


def test_delta_is_none_when_the_previous_scan_found_nothing(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=0)
    _scan(app_env, uid, "2026-05-02T00:00:00+00:00", total=5)
    assert _summary(client)["totalDeltaPct"] is None


def test_new_since_last_scan_diffs_cve_ids(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=2, cves=["CVE-1", "CVE-2"])
    _scan(app_env, uid, "2026-05-02T00:00:00+00:00", total=3, cves=["CVE-2", "CVE-3", "CVE-4"])
    assert _summary(client)["newSinceLastScan"] == 2


def test_new_since_last_scan_is_zero_when_nothing_was_added(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=2, cves=["CVE-1", "CVE-2"])
    _scan(app_env, uid, "2026-05-02T00:00:00+00:00", total=1, cves=["CVE-1"])
    assert _summary(client)["newSinceLastScan"] == 0


def test_headline_numbers_come_from_the_latest_scan_by_date_not_insert_order(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-09T00:00:00+00:00", total=9)
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=1)
    assert _summary(client)["totalVulnerabilities"] == 9


def test_chart_shows_the_last_six_scans_oldest_first_with_short_labels(app_env):
    client, uid = app_env.login_as()
    for day in range(1, 9):
        _scan(app_env, uid, f"2026-06-{day:02d}T00:00:00+00:00", total=day)
    chart = _summary(client)["chart"]
    assert [c["label"] for c in chart] == ["Jun 3", "Jun 4", "Jun 5", "Jun 6", "Jun 7", "Jun 8"]
    assert [c["count"] for c in chart] == [3, 4, 5, 6, 7, 8]


def test_data_is_private_to_each_user(app_env):
    client, uid = app_env.login_as()
    other = app_env.make_user()
    _scan(app_env, other, "2026-05-01T00:00:00+00:00", total=99)
    _ticket(app_env, other, "T-9")
    s = _summary(client)
    assert s["hasScans"] is False and s["recentActivity"] == []


# ---------------------------------------------------------------------------
# Insight text
# ---------------------------------------------------------------------------
def test_insight_when_there_are_no_critical_findings(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=3, critical=0)
    assert "No critical findings" in _summary(client)["aiInsight"]


def test_insight_names_an_open_p1_ticket(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=3, critical=2)
    _ticket(app_env, uid, "T-1", title="Patch openssl", priority="P1", status="Open")
    insight = _summary(client)["aiInsight"]
    assert "2 critical" in insight and "Patch openssl" in insight and "still open" in insight


def test_insight_prompts_to_ticket_criticals_when_none_are_tracked(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=3, critical=1)
    _ticket(app_env, uid, "T-1", priority="P1", status="Closed")  # closed P1s don't count
    _ticket(app_env, uid, "T-2", priority="P2", status="Open")    # neither do P2s
    assert "Upload Scan flow" in _summary(client)["aiInsight"]


# ---------------------------------------------------------------------------
# Recent activity
# ---------------------------------------------------------------------------
def test_activity_lists_scans_tickets_closed_and_critical(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=1)
    _ticket(app_env, uid, "T-1", status="Closed", priority="P2")
    _ticket(app_env, uid, "T-2", status="Open", priority="P1", title="Urgent one")
    activity = _summary(client)["recentActivity"]
    assert activity == [
        {"tag": "Scan", "label": "1 new scan(s) processed"},
        {"tag": "Ticket", "label": "2 ticket(s) created"},
        {"tag": "Resolved", "label": "1 ticket(s) closed"},
        {"tag": "Critical", "label": "Urgent one"},
    ]


def test_activity_is_capped_at_four_tiles(app_env):
    client, uid = app_env.login_as()
    _scan(app_env, uid, "2026-05-01T00:00:00+00:00", total=1)
    _ticket(app_env, uid, "T-1", status="Closed")
    _ticket(app_env, uid, "T-2", status="Open")
    assert len(_summary(client)["recentActivity"]) <= 4


def test_scan_activity_counts_at_most_the_five_most_recent_scans(app_env):
    client, uid = app_env.login_as()
    for day in range(1, 9):
        _scan(app_env, uid, f"2026-06-{day:02d}T00:00:00+00:00", total=1)
    assert _summary(client)["recentActivity"][0]["label"] == "5 new scan(s) processed"


def test_closed_and_resolved_statuses_are_both_treated_as_done(app_env):
    dash = app_env.dashboard
    rows = [{"status": "Closed", "priority": "P1", "title": "a"}, {"status": "resolved", "priority": "P1", "title": "b"},
            {"status": "Open", "priority": "p1", "title": "c"}, {"status": None, "priority": None, "title": "d"}]
    acts = dash._ticket_activity(rows)
    assert {"tag": "Resolved", "label": "2 ticket(s) closed"} in acts
    assert {"tag": "Critical", "label": "c"} in acts


def test_ticket_activity_is_empty_for_no_tickets(app_env):
    assert app_env.dashboard._ticket_activity([]) == []
    assert app_env.dashboard._scan_activity([]) == []


@pytest.mark.parametrize("iso,expected", [("2026-07-04T12:00:00+00:00", "Jul 4"), ("2026-10-10", "Oct 10"), ("oops", "oops")])
def test_short_date_label(app_env, iso, expected):
    assert app_env.dashboard._short_date(iso) == expected
