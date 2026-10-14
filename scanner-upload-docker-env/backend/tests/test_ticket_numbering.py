"""Tests for server-side ticket numbering in POST /api/tickets.

Regression coverage for the "ticket ids are reused" bug: the frontend used to
number every batch T-106, T-107, ... and the upsert on (user, ticket_ref)
meant a second batch overwrote the first. Numbering now happens in the
backend, against what is already stored.
"""
import importlib
import os
import sqlite3
import sys
import tempfile

import pytest
from flask import Flask


@pytest.fixture()
def env(monkeypatch):
    tmp = tempfile.mkdtemp()
    monkeypatch.setenv("AUTH_DB_PATH", os.path.join(tmp, "test.db"))
    for m in ("auth", "tickets", "jira_integration"):
        sys.modules.pop(m, None)
    auth = importlib.import_module("auth")
    auth.init_db()
    tickets = importlib.import_module("tickets")

    conn = sqlite3.connect(auth.DB_PATH)
    conn.row_factory = sqlite3.Row
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)")]
    base = {"email": "a@b.co", "name": "A", "password_hash": "x", "role": "analyst", "created_at": "2026-01-01"}
    ids = []
    for email in ("a@b.co", "c@d.co"):
        vals = {**base, "email": email}
        use = {k: v for k, v in vals.items() if k in cols}
        conn.execute(f"INSERT INTO users ({','.join(use)}) VALUES ({','.join('?' * len(use))})", list(use.values()))
        ids.append(conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"])
    conn.commit()
    conn.close()

    app = Flask(__name__)
    app.secret_key = "t"
    app.register_blueprint(tickets.tickets_bp)

    def client_for(uid):
        c = app.test_client()
        with c.session_transaction() as s:
            s["user_id"] = uid
        return c

    return client_for, ids


def _batch(*cves):
    return [{"cve": c, "title": f"Fix {c}", "priority": "P1", "why": f"why {c}"} for c in cves]


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


def test_requires_array_and_login(env):
    client_for, (uid, _) = env
    assert client_for(uid).post("/api/tickets", json={"a": 1}).status_code == 400
    # No session -> the role check rejects before the handler runs.
    import tickets
    app = Flask(__name__)
    app.secret_key = "t"
    app.register_blueprint(tickets.tickets_bp)
    assert app.test_client().post("/api/tickets", json=_batch("CVE-1")).status_code in (401, 403)
