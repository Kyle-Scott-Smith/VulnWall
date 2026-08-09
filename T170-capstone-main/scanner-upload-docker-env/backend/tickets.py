"""
Ticket persistence — isolated module, same shape as jira_integration.py /
registry_credentials.py / business_context.py.

Why this exists: tickets created in the "Review & Send" step only ever
lived in the frontend's React state (liveTickets in App.jsx) — nothing was
saved server-side at all. That meant tickets vanished on every page
refresh, every sign-out, and every backend restart, regardless of which
account created them. This gives tickets a real home in the same SQLite
database as everything else (auth.py's DB_PATH), keyed by user_id, so a
signed-in user sees the same tickets no matter which browser/device they
sign in from, and they survive a restart the same way the account does.

This does NOT persist raw scan/vulnerability findings (the full Trivy/
Tenable output) — only the tickets a user actually reviewed and sent.
Full scan-history persistence is a separate, bigger piece of work
(deferred deliberately — see conversation).

Endpoints registered by this blueprint (mounted at /api/tickets):
  GET   /api/tickets              -> list the signed-in user's tickets
  POST  /api/tickets              -> body: array of ticket objects; bulk-saves them
  PATCH /api/tickets/<ticket_ref> -> body: {status, assigned}; updates one ticket
"""

import json
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

from auth import _get_db

tickets_bp = Blueprint("tickets", __name__, url_prefix="/api/tickets")


def init_tickets_db():
    """Creates the tickets table if it doesn't exist yet. Called once at
    import time (see bottom of file), same as auth.init_db()."""
    conn = _get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tickets (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id      INTEGER NOT NULL REFERENCES users(id),
                ticket_ref   TEXT NOT NULL,
                cve          TEXT,
                title        TEXT NOT NULL,
                priority     TEXT,
                status       TEXT NOT NULL DEFAULT 'Open',
                assigned     TEXT,
                date         TEXT,
                cvss         REAL,
                confidence   INTEGER,
                fixes        TEXT,
                why          TEXT,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL,
                UNIQUE(user_id, ticket_ref)
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _require_login():
    return session.get("user_id")


def _row_to_json(row):
    return {
        "id": row["ticket_ref"],
        "cve": row["cve"],
        "title": row["title"],
        "priority": row["priority"],
        "status": row["status"],
        "assigned": row["assigned"],
        "date": row["date"],
        "cvss": row["cvss"],
        "confidence": row["confidence"],
        "fixes": json.loads(row["fixes"]) if row["fixes"] else [],
        "why": row["why"],
    }


@tickets_bp.route("", methods=["GET"])
def list_tickets():
    user_id = _require_login()
    if not user_id:
        return jsonify([])

    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at", (user_id,)
        ).fetchall()
    finally:
        conn.close()

    return jsonify([_row_to_json(r) for r in rows])


@tickets_bp.route("", methods=["POST"])
def create_tickets():
    """Bulk-save tickets. Body: array of {id, cve, title, priority, status,
    assigned, date, cvss, confidence, fixes, why} — the exact shape
    ReviewSendStep already builds in the frontend before this call."""
    user_id = _require_login()
    if not user_id:
        return jsonify({"error": "You must be signed in"}), 401

    body = request.get_json(silent=True)
    if not isinstance(body, list):
        return jsonify({"error": "Expected a JSON array of tickets"}), 400

    now = datetime.now(timezone.utc).isoformat()
    conn = _get_db()
    try:
        for t in body:
            if not isinstance(t, dict) or not t.get("id") or not t.get("title"):
                continue  # skip malformed entries rather than failing the whole batch
            conn.execute(
                """
                INSERT INTO tickets (
                    user_id, ticket_ref, cve, title, priority, status,
                    assigned, date, cvss, confidence, fixes, why,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, ticket_ref) DO UPDATE SET
                    cve=excluded.cve,
                    title=excluded.title,
                    priority=excluded.priority,
                    status=excluded.status,
                    assigned=excluded.assigned,
                    date=excluded.date,
                    cvss=excluded.cvss,
                    confidence=excluded.confidence,
                    fixes=excluded.fixes,
                    why=excluded.why,
                    updated_at=excluded.updated_at
                """,
                (
                    user_id, t.get("id"), t.get("cve"), t.get("title"),
                    t.get("priority"), t.get("status") or "Open", t.get("assigned"),
                    t.get("date"), t.get("cvss"), t.get("confidence"),
                    json.dumps(t.get("fixes") or []), t.get("why"),
                    now, now,
                ),
            )
        conn.commit()

        rows = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at", (user_id,)
        ).fetchall()
    finally:
        conn.close()

    return jsonify([_row_to_json(r) for r in rows]), 201


@tickets_bp.route("/<ticket_ref>", methods=["PATCH"])
def update_ticket(ticket_ref):
    """Body: {status, assigned} — either or both. Matches the fields
    TicketList's edit form actually lets a user change."""
    user_id = _require_login()
    if not user_id:
        return jsonify({"error": "You must be signed in"}), 401

    body = request.get_json(silent=True) or {}
    status = body.get("status")
    assigned = body.get("assigned")
    if status is None and assigned is None:
        return jsonify({"error": "Nothing to update"}), 400

    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? AND ticket_ref = ?",
            (user_id, ticket_ref),
        ).fetchone()
        if not row:
            return jsonify({"error": "Ticket not found"}), 404

        conn.execute(
            """
            UPDATE tickets SET
                status = COALESCE(?, status),
                assigned = COALESCE(?, assigned),
                updated_at = ?
            WHERE user_id = ? AND ticket_ref = ?
            """,
            (status, assigned, datetime.now(timezone.utc).isoformat(), user_id, ticket_ref),
        )
        conn.commit()

        row = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? AND ticket_ref = ?",
            (user_id, ticket_ref),
        ).fetchone()
    finally:
        conn.close()

    return jsonify(_row_to_json(row))


init_tickets_db()
