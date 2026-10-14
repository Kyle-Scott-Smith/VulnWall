"""Endpoint tests for the honest Jira sync behaviour in tickets.py.
Uses a throwaway SQLite file and a stubbed Jira layer — no network. The key
guarantee under test: a status change on a Jira-linked ticket is only saved
locally if Jira accepted it.
"""
import pytest


@pytest.fixture()
def env(app_env):
    """One analyst with two tickets: T-1 linked to Jira issue VULN-1, T-2 not linked."""
    uid = app_env.make_user(email="a@b.co", name="A", role="analyst")
    now = "2026-09-29T00:00:00+00:00"
    for ref, key in (("T-1", "VULN-1"), ("T-2", None)):
        app_env.execute(
            "INSERT INTO tickets (user_id, ticket_ref, cve, title, status, jira_issue_key, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)", (uid, ref, "CVE-2024-1", "t", "Open", key, now, now))
    return app_env.client(uid), app_env.tickets


def test_jira_refusal_blocks_local_change(env, monkeypatch):
    client, tickets = env
    monkeypatch.setattr(tickets, "get_connection_record", lambda: {"cloud_id": "c", "access_token": "t"})
    monkeypatch.setattr(tickets, "transition_issue_to_category", lambda *a: (False, "Jira refused."))
    r = client.patch("/api/tickets/T-1", json={"status": "Closed"})
    assert r.status_code == 502 and "Nothing was changed" in r.get_json()["error"]
    assert client.get("/api/tickets").get_json()[0]["status"] == "Open"


def test_jira_success_saves_and_stamps_sync_time(env, monkeypatch):
    client, tickets = env
    monkeypatch.setattr(tickets, "get_connection_record", lambda: {"cloud_id": "c", "access_token": "t"})
    calls = []
    monkeypatch.setattr(tickets, "transition_issue_to_category", lambda rec, key, cat: calls.append((key, cat)) or (True, None))
    body = client.patch("/api/tickets/T-1", json={"status": "Closed"}).get_json()
    assert calls == [("VULN-1", "done")]
    assert body["status"] == "Closed" and body["jiraLinked"] is True and body["jiraSyncedAt"]


def test_linked_ticket_without_jira_connection_is_rejected(env, monkeypatch):
    client, tickets = env
    monkeypatch.setattr(tickets, "get_connection_record", lambda: None)
    r = client.patch("/api/tickets/T-1", json={"status": "In Progress"})
    assert r.status_code == 409
    assert client.get("/api/tickets").get_json()[0]["status"] == "Open"


def test_unlinked_ticket_updates_locally_and_says_so(env):
    client, _ = env
    body = client.patch("/api/tickets/T-2", json={"status": "Closed"}).get_json()
    assert body["status"] == "Closed" and body["jiraLinked"] is False and body["jiraSyncedAt"] is None


def test_assignee_change_never_calls_jira(env, monkeypatch):
    client, tickets = env
    monkeypatch.setattr(tickets, "transition_issue_to_category", lambda *a: pytest.fail("must not call Jira"))
    assert client.patch("/api/tickets/T-1", json={"assigned": "IT Operations"}).status_code == 200


def test_sync_reports_tickets_it_could_not_check(env, monkeypatch):
    client, tickets = env
    monkeypatch.setattr(tickets, "get_connection_record", lambda: {"cloud_id": "c", "access_token": "t"})
    monkeypatch.setattr(tickets, "fetch_issue_status_category", lambda rec, key: None)
    body = client.post("/api/tickets/sync").get_json()
    assert body["failed"] == ["VULN-1"] and body["checked"] == 1
    assert [t for t in body["tickets"] if t["id"] == "T-1"][0]["jiraSyncedAt"] is None


def test_sync_without_jira_is_an_error_not_a_success(env, monkeypatch):
    client, tickets = env
    monkeypatch.setattr(tickets, "get_connection_record", lambda: None)
    r = client.post("/api/tickets/sync")
    assert r.status_code == 400 and r.get_json()["code"] == "jira_not_connected"
