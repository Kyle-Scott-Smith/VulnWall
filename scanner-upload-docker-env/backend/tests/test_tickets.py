"""Tests for tickets.py — saving, listing, editing and syncing tickets.

test_ticket_jira_sync.py covers the Jira-push guarantees in depth and
test_ticket_numbering.py covers server-side T-### numbering; this file covers
the rest: bulk create/upsert semantics, validation, per-user isolation, role
gating, and the sync status mapping.

POST /api/tickets answers {"tickets": <caller's full list>, "created": <what
this request added/updated>}. `_saved()` below returns the full list."""
import json

import pytest


def _ticket(ref="T-1", **overrides):
    t = {
        "id": ref, "cve": "CVE-2024-0001", "title": "Fix openssl", "priority": "P1",
        "status": "Open", "assigned": "Security Team", "date": "2026-09-01",
        "cvss": 9.8, "confidence": 90, "fixes": ["Upgrade", "Re-scan"], "why": "RCE",
    }
    t.update(overrides)
    return t


def _save(client, tickets):
    return client.post("/api/tickets", json=tickets)


def _saved(client, tickets):
    """Save, assert success, and return the caller's full ticket list."""
    r = _save(client, tickets)
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()["tickets"]


JIRA = {"cloud_id": "c", "access_token": "t"}


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------
def test_listing_while_signed_out_is_an_empty_list_not_an_error(app_env):
    r = app_env.client().get("/api/tickets")
    assert r.status_code == 200 and r.get_json() == []


def test_list_is_oldest_first(app_env, fake_clock):
    fake_clock(app_env.tickets)
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-2")])
    _save(client, [_ticket("T-1")])
    assert [t["id"] for t in client.get("/api/tickets").get_json()] == ["T-2", "T-1"]


# ---------------------------------------------------------------------------
# Bulk create
# ---------------------------------------------------------------------------
def test_create_saves_every_field_and_returns_201_with_all_tickets(app_env):
    client, _ = app_env.login_as()
    r = _save(client, [_ticket("T-1"), _ticket("T-2", cve=None, fixes=[])])
    assert r.status_code == 201
    body = r.get_json()
    assert set(body) == {"tickets", "created"}
    saved = {t["id"]: t for t in body["tickets"]}
    assert set(saved) == {"T-1", "T-2"}
    assert saved["T-1"] == {
        "id": "T-1", "cve": "CVE-2024-0001", "title": "Fix openssl", "priority": "P1", "status": "Open",
        "assigned": "Security Team", "date": "2026-09-01", "cvss": 9.8, "confidence": 90,
        "fixes": ["Upgrade", "Re-scan"], "why": "RCE", "jiraIssueKey": None, "jiraUrl": None,
        "jiraLinked": False, "jiraSyncedAt": None,
    }
    assert saved["T-2"]["fixes"] == [] and saved["T-2"]["cve"] is None
    # `created` is what this request touched, in request order.
    assert [t["id"] for t in body["created"]] == ["T-1", "T-2"]


def test_a_missing_confidence_is_stored_as_null_not_zero(app_env):
    """The wizard sends confidence: null when the AI gave none (the UI then says
    'Not assessed'); the server must keep that distinct from a real 0."""
    client, _ = app_env.login_as()
    tickets = _saved(client, [_ticket("T-1", confidence=None), _ticket("T-2", confidence=0)])
    by_id = {t["id"]: t for t in tickets}
    assert by_id["T-1"]["confidence"] is None
    assert by_id["T-2"]["confidence"] == 0


def test_create_requires_sign_in_and_a_json_array(app_env):
    assert _save(app_env.client(), [_ticket()]).status_code == 401
    client, _ = app_env.login_as()
    for bad in ({"id": "T-1"}, "text", 5, None):
        r = client.post("/api/tickets", json=bad)
        assert r.status_code == 400, bad


def test_create_skips_entries_that_are_not_tickets_without_failing_the_batch(app_env):
    """Skipped: non-objects and anything without a title. An entry with a title
    but no id is NOT malformed any more - it is a new ticket the server numbers."""
    client, _ = app_env.login_as()
    r = _save(client, [_ticket("T-1"), "junk", 7, {"title": "no id"}, {"id": "T-X"}, {"id": "", "title": "t"}, _ticket("T-2")])
    assert r.status_code == 201
    body = r.get_json()
    assert [t["id"] for t in body["created"]] == ["T-1", "T-106", "T-107", "T-2"]
    assert sorted(t["id"] for t in body["tickets"]) == ["T-1", "T-106", "T-107", "T-2"]
    assert "T-X" not in {t["id"] for t in body["tickets"]}


def test_create_defaults_status_to_open(app_env):
    client, _ = app_env.login_as()
    body = _saved(client, [_ticket(status=None)])
    assert body[0]["status"] == "Open"


def test_saving_the_same_ticket_again_updates_it_instead_of_duplicating(app_env):
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-1", title="Old", status="Open")])
    body = _saved(client, [_ticket("T-1", title="New", status="In Progress", cvss=5.0)])
    assert len(body) == 1
    assert (body[0]["title"], body[0]["status"], body[0]["cvss"]) == ("New", "In Progress", 5.0)


def test_resaving_without_jira_fields_keeps_the_existing_jira_link(app_env):
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-1", jiraIssueKey="VULN-7", jiraUrl="https://x.atlassian.net/browse/VULN-7")])
    body = _save(client, [_ticket("T-1", title="Edited")]).get_json()["created"][0]
    assert body["jiraIssueKey"] == "VULN-7" and body["jiraUrl"].endswith("VULN-7")
    assert body["jiraLinked"] is True and body["jiraSyncedAt"]


def test_tickets_created_with_a_jira_key_are_stamped_as_in_sync(app_env):
    client, _ = app_env.login_as()
    body = _saved(client, [_ticket("T-1", jiraIssueKey="VULN-1"), _ticket("T-2")])
    by_id = {t["id"]: t for t in body}
    assert by_id["T-1"]["jiraSyncedAt"] and by_id["T-2"]["jiraSyncedAt"] is None


def test_viewers_cannot_create_tickets(app_env):
    viewer, _ = app_env.login_as(role="viewer")
    assert _save(viewer, [_ticket()]).status_code == 403
    assert viewer.get("/api/tickets").get_json() == []


# ---------------------------------------------------------------------------
# Per-user isolation
# ---------------------------------------------------------------------------
def test_users_only_see_and_edit_their_own_tickets(app_env):
    a, _ = app_env.login_as()
    b, _ = app_env.login_as()
    _save(a, [_ticket("T-1")])
    assert b.get("/api/tickets").get_json() == []
    r = b.patch("/api/tickets/T-1", json={"status": "Closed"})
    assert r.status_code == 404
    assert a.get("/api/tickets").get_json()[0]["status"] == "Open"


def test_two_users_can_use_the_same_ticket_reference(app_env):
    a, _ = app_env.login_as()
    b, _ = app_env.login_as()
    _save(a, [_ticket("T-1", title="A's")])
    _save(b, [_ticket("T-1", title="B's")])
    assert a.get("/api/tickets").get_json()[0]["title"] == "A's"
    assert b.get("/api/tickets").get_json()[0]["title"] == "B's"


# ---------------------------------------------------------------------------
# PATCH
# ---------------------------------------------------------------------------
def test_patch_requires_sign_in_and_a_writable_role(app_env):
    assert app_env.client().patch("/api/tickets/T-1", json={"status": "Closed"}).status_code == 401
    viewer, _ = app_env.login_as(role="viewer")
    assert viewer.patch("/api/tickets/T-1", json={"status": "Closed"}).status_code == 403


def test_patch_validation_and_not_found(app_env):
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-1")])
    assert client.patch("/api/tickets/T-1", json={}).status_code == 400
    r = client.patch("/api/tickets/T-1", json={"status": "Done"})
    assert r.status_code == 400 and "Unknown status" in r.get_json()["error"]
    assert client.patch("/api/tickets/NOPE", json={"status": "Closed"}).status_code == 404


@pytest.mark.parametrize("status", ["Open", "In Progress", "Closed"])
def test_every_status_the_ui_offers_can_be_set_on_an_unlinked_ticket(app_env, status):
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-1", status="Open")])
    body = client.patch("/api/tickets/T-1", json={"status": status}).get_json()
    assert body["status"] == status and body["jiraLinked"] is False


def test_patch_can_change_status_and_assignee_together(app_env):
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-1")])
    body = client.patch("/api/tickets/T-1", json={"status": "In Progress", "assigned": "IT Operations"}).get_json()
    assert (body["status"], body["assigned"]) == ("In Progress", "IT Operations")


def test_patch_leaves_untouched_fields_alone(app_env):
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-1", assigned="Security Team")])
    body = client.patch("/api/tickets/T-1", json={"status": "Closed"}).get_json()
    assert body["assigned"] == "Security Team" and body["title"] == "Fix openssl"
    assert body["fixes"] == ["Upgrade", "Re-scan"]


def test_resending_the_current_status_does_not_call_jira(app_env, monkeypatch):
    client, uid = app_env.login_as()
    _save(client, [_ticket("T-1", jiraIssueKey="VULN-1")])
    monkeypatch.setattr(app_env.tickets, "get_connection_record", lambda: pytest.fail("Jira must not be consulted"))
    monkeypatch.setattr(app_env.tickets, "transition_issue_to_category", lambda *a: pytest.fail("no push"))
    assert client.patch("/api/tickets/T-1", json={"status": "Open"}).status_code == 200


def test_patch_with_assigned_only_leaves_a_linked_ticket_unsynced_timestamp_alone(app_env, monkeypatch):
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-1", jiraIssueKey="VULN-1")])
    before = client.get("/api/tickets").get_json()[0]["jiraSyncedAt"]
    body = client.patch("/api/tickets/T-1", json={"assigned": "Ops"}).get_json()
    assert body["jiraSyncedAt"] == before


# ---------------------------------------------------------------------------
# /sync status mapping
# ---------------------------------------------------------------------------
def _linked(client, *keys, status="Open"):
    _save(client, [_ticket(f"T-{i}", jiraIssueKey=k, status=status) for i, k in enumerate(keys, start=1)])


@pytest.mark.parametrize("category,local_before,local_after", [
    ("done", "Open", "Closed"),
    ("indeterminate", "Open", "In Progress"),
    ("new", "Closed", "Open"),
])
def test_sync_maps_jira_status_categories_to_local_statuses(app_env, monkeypatch, category, local_before, local_after):
    client, _ = app_env.login_as()
    _linked(client, "VULN-1", status=local_before)
    monkeypatch.setattr(app_env.tickets, "get_connection_record", lambda: JIRA)
    monkeypatch.setattr(app_env.tickets, "fetch_issue_status_category", lambda rec, key: category)
    body = client.post("/api/tickets/sync").get_json()
    assert body["updated"] == 1 and body["checked"] == 1 and body["failed"] == []
    assert body["tickets"][0]["status"] == local_after and body["tickets"][0]["jiraSyncedAt"]


def test_sync_that_finds_no_difference_updates_nothing_but_stamps_the_check(app_env, monkeypatch):
    client, _ = app_env.login_as()
    _linked(client, "VULN-1", status="Closed")
    app_env.execute("UPDATE tickets SET jira_synced_at = NULL")
    monkeypatch.setattr(app_env.tickets, "get_connection_record", lambda: JIRA)
    monkeypatch.setattr(app_env.tickets, "fetch_issue_status_category", lambda rec, key: "done")
    body = client.post("/api/tickets/sync").get_json()
    assert body["updated"] == 0 and body["tickets"][0]["jiraSyncedAt"] == body["syncedAt"]


def test_sync_ignores_an_unrecognised_category_but_still_counts_it_as_checked(app_env, monkeypatch):
    client, _ = app_env.login_as()
    _linked(client, "VULN-1", status="In Progress")
    monkeypatch.setattr(app_env.tickets, "get_connection_record", lambda: JIRA)
    monkeypatch.setattr(app_env.tickets, "fetch_issue_status_category", lambda rec, key: "undefined")
    body = client.post("/api/tickets/sync").get_json()
    assert body["updated"] == 0 and body["failed"] == [] and body["tickets"][0]["status"] == "In Progress"


def test_sync_handles_a_mix_of_successes_and_failures_and_skips_unlinked_tickets(app_env, monkeypatch):
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-1", jiraIssueKey="VULN-1"), _ticket("T-2", jiraIssueKey="VULN-2"), _ticket("T-3")])
    monkeypatch.setattr(app_env.tickets, "get_connection_record", lambda: JIRA)
    monkeypatch.setattr(app_env.tickets, "fetch_issue_status_category",
                        lambda rec, key: {"VULN-1": "done"}.get(key))
    body = client.post("/api/tickets/sync").get_json()
    assert body["checked"] == 2 and body["updated"] == 1 and body["failed"] == ["VULN-2"]
    by_id = {t["id"]: t for t in body["tickets"]}
    assert by_id["T-1"]["status"] == "Closed"
    assert by_id["T-2"]["status"] == "Open"
    assert by_id["T-3"]["jiraSyncedAt"] is None  # never linked, never touched
    assert len(body["tickets"]) == 3  # response carries every ticket, linked or not


def test_sync_only_touches_the_callers_tickets(app_env, monkeypatch):
    a, _ = app_env.login_as()
    b, _ = app_env.login_as()
    _linked(a, "VULN-1")
    _linked(b, "VULN-9")
    seen = []
    monkeypatch.setattr(app_env.tickets, "get_connection_record", lambda: JIRA)
    monkeypatch.setattr(app_env.tickets, "fetch_issue_status_category", lambda rec, key: seen.append(key) or "done")
    a.post("/api/tickets/sync")
    assert seen == ["VULN-1"]
    assert b.get("/api/tickets").get_json()[0]["status"] == "Open"


def test_sync_requires_sign_in_but_not_a_writable_role(app_env, monkeypatch):
    assert app_env.client().post("/api/tickets/sync").status_code == 401
    viewer, _ = app_env.login_as(role="viewer")
    monkeypatch.setattr(app_env.tickets, "get_connection_record", lambda: JIRA)
    r = viewer.post("/api/tickets/sync")
    assert r.status_code == 200 and r.get_json()["checked"] == 0


def test_fixes_are_stored_as_json_text(app_env):
    client, _ = app_env.login_as()
    _save(client, [_ticket("T-1", fixes=["a", "b"])])
    raw = app_env.query("SELECT fixes FROM tickets")[0]["fixes"]
    assert json.loads(raw) == ["a", "b"]
