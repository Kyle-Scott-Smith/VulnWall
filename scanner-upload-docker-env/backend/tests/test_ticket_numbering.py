"""Tests for server-side ticket numbering in POST /api/tickets.

Regression coverage for the "ticket ids are reused" bug: the frontend used to
number every batch T-106, T-107, ... and the upsert on (user, ticket_ref)
meant a second batch overwrote the first. Numbering now happens in the
backend, against what is already stored.

(Ported onto the shared `app_env` fixture from conftest.py so every test gets
a fresh database and freshly imported modules like the rest of the suite; the
assertions in the first block are unchanged.)
"""
import pytest


@pytest.fixture()
def env(app_env):
    """(client_for, [uid_a, uid_b]) - two analysts, each with their own client."""
    ids = [app_env.make_user(email="a@b.co", name="A", role="analyst"),
           app_env.make_user(email="c@d.co", name="C", role="analyst")]
    return app_env.client, ids


def _batch(*cves):
    return [{"cve": c, "title": f"Fix {c}", "priority": "P1", "why": f"why {c}"} for c in cves]


# ---------------------------------------------------------------------------
# Core behaviour
# ---------------------------------------------------------------------------
def test_new_tickets_without_id_are_numbered_by_the_server(env):
    client_for, (uid, _) = env
    r = client_for(uid).post("/api/tickets", json=_batch("CVE-1", "CVE-2"))
    assert r.status_code == 201
    assert [t["id"] for t in r.get_json()["created"]] == ["T-106", "T-107"]


def test_second_batch_does_not_overwrite_the_first(env):
    client_for, (uid, _) = env
    c = client_for(uid)
    c.post("/api/tickets", json=_batch("CVE-1", "CVE-2"))
    body = c.post("/api/tickets", json=_batch("CVE-3")).get_json()
    assert [t["id"] for t in body["created"]] == ["T-108"]
    # Nothing from the first batch was overwritten or lost.
    assert [(t["id"], t["cve"]) for t in body["tickets"]] == [
        ("T-106", "CVE-1"), ("T-107", "CVE-2"), ("T-108", "CVE-3"),
    ]
    assert [t["cve"] for t in c.get("/api/tickets").get_json()] == ["CVE-1", "CVE-2", "CVE-3"]


def test_numbering_continues_past_the_highest_existing_ref(env):
    client_for, (uid, _) = env
    c = client_for(uid)
    c.post("/api/tickets", json=[{"id": "T-250", "cve": "CVE-9", "title": "manual"}])
    created = c.post("/api/tickets", json=_batch("CVE-1")).get_json()["created"]
    assert created[0]["id"] == "T-251"


def test_numbering_is_per_user(env):
    client_for, (a, b) = env
    client_for(a).post("/api/tickets", json=_batch("CVE-1", "CVE-2"))
    created = client_for(b).post("/api/tickets", json=_batch("CVE-1")).get_json()["created"]
    assert created[0]["id"] == "T-106"


def test_explicit_id_still_updates_that_ticket(env):
    client_for, (uid, _) = env
    c = client_for(uid)
    c.post("/api/tickets", json=_batch("CVE-1"))
    body = c.post("/api/tickets", json=[{"id": "T-106", "cve": "CVE-1", "title": "Renamed"}]).get_json()
    assert [t["title"] for t in body["tickets"]] == ["Renamed"]
    assert body["created"][0]["id"] == "T-106"


def test_edited_fields_are_stored_exactly_as_sent(env):
    client_for, (uid, _) = env
    c = client_for(uid)
    sent = {"cve": "CVE-1", "title": "My own title", "priority": "P3", "assigned": "Infrastructure",
            "why": "My own description"}
    t = c.post("/api/tickets", json=[sent]).get_json()["created"][0]
    assert (t["title"], t["priority"], t["assigned"], t["why"]) == (
        "My own title", "P3", "Infrastructure", "My own description")


def test_malformed_entries_are_skipped_without_burning_numbers(env):
    client_for, (uid, _) = env
    created = client_for(uid).post("/api/tickets", json=[{"cve": "x"}, "junk", *_batch("CVE-1")]).get_json()["created"]
    assert [t["id"] for t in created] == ["T-106"]


def test_requires_array_and_login(env, app_env):
    client_for, (uid, _) = env
    assert client_for(uid).post("/api/tickets", json={"a": 1}).status_code == 400
    # No session -> the role check rejects before the handler runs.
    assert app_env.client().post("/api/tickets", json=_batch("CVE-1")).status_code in (401, 403)


# ---------------------------------------------------------------------------
# Added coverage
# ---------------------------------------------------------------------------
def test_the_first_ticket_is_t_106_because_the_demo_tickets_occupy_101_to_105(env, app_env):
    client_for, (uid, _) = env
    assert app_env.tickets.FIRST_TICKET_NUMBER == 106
    assert client_for(uid).post("/api/tickets", json=_batch("CVE-1")).get_json()["created"][0]["id"] == "T-106"


def test_low_manual_refs_never_pull_numbering_below_106(env):
    client_for, (uid, _) = env
    c = client_for(uid)
    c.post("/api/tickets", json=[{"id": "T-1", "cve": "CVE-9", "title": "manual"}])
    assert c.post("/api/tickets", json=_batch("CVE-1")).get_json()["created"][0]["id"] == "T-106"


def test_refs_that_are_not_t_numbers_are_ignored_when_finding_the_highest(env):
    client_for, (uid, _) = env
    c = client_for(uid)
    c.post("/api/tickets", json=[
        {"id": "JIRA-9999", "title": "a"}, {"id": "T-abc", "title": "b"}, {"id": "t-900", "title": "c"},
        {"id": "T-12-3", "title": "d"},
    ])
    assert c.post("/api/tickets", json=_batch("CVE-1")).get_json()["created"][0]["id"] == "T-106"


def test_numbers_are_zero_padded_to_three_digits_but_grow_past_999(env):
    client_for, (uid, _) = env
    c = client_for(uid)
    c.post("/api/tickets", json=[{"id": "T-999", "title": "manual"}])
    assert c.post("/api/tickets", json=_batch("CVE-1")).get_json()["created"][0]["id"] == "T-1000"
    assert c.post("/api/tickets", json=_batch("CVE-2")).get_json()["created"][0]["id"] == "T-1001"


def test_a_blank_id_counts_as_no_id(env):
    client_for, (uid, _) = env
    created = client_for(uid).post("/api/tickets", json=[{"id": "", "title": "x"}, {"id": None, "title": "y"}]).get_json()["created"]
    assert [t["id"] for t in created] == ["T-106", "T-107"]


def test_created_holds_only_this_requests_tickets_in_request_order_with_final_ids(env):
    client_for, (uid, _) = env
    c = client_for(uid)
    c.post("/api/tickets", json=_batch("CVE-1"))
    body = c.post("/api/tickets", json=[
        {"id": "T-106", "cve": "CVE-1", "title": "updated"},   # existing, updated
        {"cve": "CVE-2", "title": "new one"},                   # new, numbered
    ]).get_json()
    assert [(t["id"], t["title"]) for t in body["created"]] == [("T-106", "updated"), ("T-107", "new one")]
    assert len(body["tickets"]) == 2


def test_a_viewer_cannot_create_tickets_so_no_numbers_are_consumed(app_env):
    viewer_id = app_env.make_user(email="v@b.co", role="viewer")
    viewer = app_env.client(viewer_id)
    assert viewer.post("/api/tickets", json=_batch("CVE-1")).status_code == 403
    analyst_id = app_env.make_user(email="a@b.co", role="analyst")
    created = app_env.client(analyst_id).post("/api/tickets", json=_batch("CVE-1")).get_json()["created"]
    assert created[0]["id"] == "T-106"


def test_the_saved_jira_link_travels_with_a_numbered_ticket(env):
    """What the wizard sends after Jira accepted the issue (see draftToSavedTicket)."""
    client_for, (uid, _) = env
    t = client_for(uid).post("/api/tickets", json=[
        {"cve": "CVE-1", "title": "t", "jiraIssueKey": "VULN-7", "jiraUrl": "https://x/VULN-7"},
    ]).get_json()["created"][0]
    assert (t["id"], t["jiraIssueKey"], t["jiraLinked"]) == ("T-106", "VULN-7", True)
    assert t["jiraSyncedAt"]


# ---------------------------------------------------------------------------
# Documents a problem (strict xfail - see TESTING.md)
# ---------------------------------------------------------------------------
@pytest.mark.xfail(strict=True, reason=(
    "create_tickets() reads the highest stored number once, before the loop. An explicit id in the same "
    "batch that equals the next free number (e.g. T-106) is therefore also handed out to a new ticket, "
    "and the upsert makes the second overwrite the first - the very bug numbering was added to prevent. "
    "The shipped frontend never sends ids, so only direct API callers can hit it."))
def test_an_explicit_id_in_the_same_batch_is_never_reused_for_a_new_ticket(env):
    client_for, (uid, _) = env
    c = client_for(uid)
    body = c.post("/api/tickets", json=[
        {"id": "T-106", "cve": "CVE-A", "title": "explicit"},
        {"cve": "CVE-B", "title": "new"},
    ]).get_json()
    assert sorted(t["cve"] for t in body["tickets"]) == ["CVE-A", "CVE-B"]
