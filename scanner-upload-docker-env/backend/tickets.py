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
  PATCH /api/tickets/<ticket_ref> -> body: {status, assigned}; updates one ticket.
                                      Status changes on Jira-linked tickets are
                                      pushed to Jira first and rejected if Jira
                                      refuses (see update_ticket).
  POST  /api/tickets/sync         -> pulls current status from Jira for every
                                      ticket linked to a Jira issue (jira_issue_key
                                      set) and updates the local status to match.
                                      See jira_integration.fetch_issue_status_category.
"""

import json
import re
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

from auth import _get_db, require_role
from jira_integration import (
    STATUS_TO_JIRA_CATEGORY,
    fetch_issue_status_category,
    get_connection_record,
    transition_issue_to_category,
)

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
        # Migration: these two columns were added after the tickets table
        # already shipped (Jira sync feature) — add them to any existing
        # database instead of requiring a fresh one. jira_issue_key is what
        # ties a local ticket to the Jira issue it was pushed to, so a
        # status change on the Jira side can be looked up and reflected
        # back locally (see /api/tickets/sync).
        existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(tickets)").fetchall()}
        if "jira_issue_key" not in existing_cols:
            conn.execute("ALTER TABLE tickets ADD COLUMN jira_issue_key TEXT")
        if "jira_url" not in existing_cols:
            conn.execute("ALTER TABLE tickets ADD COLUMN jira_url TEXT")
        # When this ticket's state was last confirmed to match Jira (a
        # successful sync check or a successful push). NULL = never
        # confirmed, which the UI shows as such rather than "synced".
        if "jira_synced_at" not in existing_cols:
            conn.execute("ALTER TABLE tickets ADD COLUMN jira_synced_at TEXT")
        conn.commit()
    finally:
        conn.close()


def _require_login():
    return session.get("user_id")


# New tickets are numbered T-106, T-107, ... The first free number is 106
# because the frontend's built-in demo tickets occupy T-101..T-105.
FIRST_TICKET_NUMBER = 106
_TICKET_REF_RE = re.compile(r"^T-(\d+)$")


def _next_ticket_number(conn, user_id):
    """Next unused ticket number for this user: one above the highest
    existing T-### ref (never below FIRST_TICKET_NUMBER).

    Previously the frontend numbered every batch from T-106, and because
    saving is an upsert on (user, ticket_ref), a second batch silently
    overwrote the first batch's rows. Numbering now happens here, against
    what is actually stored. Callers must hold a write lock (BEGIN
    IMMEDIATE) so two concurrent requests can't read the same maximum.
    """
    highest = FIRST_TICKET_NUMBER - 1
    for row in conn.execute("SELECT ticket_ref FROM tickets WHERE user_id = ?", (user_id,)):
        m = _TICKET_REF_RE.match(row["ticket_ref"] or "")
        if m:
            highest = max(highest, int(m.group(1)))
    return highest + 1


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
        "jiraIssueKey": row["jira_issue_key"],
        "jiraUrl": row["jira_url"],
        "jiraLinked": bool(row["jira_issue_key"]),
        "jiraSyncedAt": row["jira_synced_at"],
    }


@tickets_bp.route("", methods=["GET"])
def list_tickets():
    user_id = _require_login()
    if not user_id:
        return jsonify([])

    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at, id", (user_id,)
        ).fetchall()
    finally:
        conn.close()

    return jsonify([_row_to_json(r) for r in rows])


@tickets_bp.route("", methods=["POST"])
@require_role("admin", "analyst")
def create_tickets():
    """Bulk-save tickets. Body: array of {id?, cve, title, priority, status,
    assigned, date, cvss, confidence, fixes, why}.

    `id` is optional. A ticket without one is a NEW ticket: the server
    assigns the next free T-### number (so a second batch can never
    overwrite the first). A ticket with an `id` is upserted under that id,
    which is how an existing ticket is updated.

    Response (201): {"tickets": [the caller's full list, oldest first],
                     "created": [only the tickets this request added/updated,
                                 in request order, with their final ids]}.
    """
    user_id = _require_login()
    if not user_id:
        return jsonify({"error": "You must be signed in"}), 401

    body = request.get_json(silent=True)
    if not isinstance(body, list):
        return jsonify({"error": "Expected a JSON array of tickets"}), 400

    now = datetime.now(timezone.utc).isoformat()
    conn = _get_db()
    try:
        # Take the write lock before reading the current maximum so that
        # numbering + inserting is atomic with respect to other requests.
        conn.execute("BEGIN IMMEDIATE")
        next_number = _next_ticket_number(conn, user_id)
        saved_refs = []
        for t in body:
            if not isinstance(t, dict) or not t.get("title"):
                continue  # skip malformed entries rather than failing the whole batch
            ref = t.get("id")
            if not ref:
                ref = f"T-{next_number:03d}"
                next_number += 1
            conn.execute(
                """
                INSERT INTO tickets (
                    user_id, ticket_ref, cve, title, priority, status,
                    assigned, date, cvss, confidence, fixes, why,
                    jira_issue_key, jira_url, jira_synced_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    jira_issue_key=COALESCE(excluded.jira_issue_key, tickets.jira_issue_key),
                    jira_url=COALESCE(excluded.jira_url, tickets.jira_url),
                    jira_synced_at=COALESCE(excluded.jira_synced_at, tickets.jira_synced_at),
                    updated_at=excluded.updated_at
                """,
                (
                    user_id, ref, t.get("cve"), t.get("title"),
                    t.get("priority"), t.get("status") or "Open", t.get("assigned"),
                    t.get("date"), t.get("cvss"), t.get("confidence"),
                    json.dumps(t.get("fixes") or []), t.get("why"),
                    t.get("jiraIssueKey"), t.get("jiraUrl"),
                    now if t.get("jiraIssueKey") else None,  # just created in Jira = in sync
                    now, now,
                ),
            )
            saved_refs.append(ref)
        conn.commit()

        rows = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at, id", (user_id,)
        ).fetchall()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    all_tickets = [_row_to_json(r) for r in rows]
    by_ref = {t["id"]: t for t in all_tickets}
    return jsonify({
        "tickets": all_tickets,
        "created": [by_ref[r] for r in saved_refs if r in by_ref],
    }), 201


@tickets_bp.route("/<ticket_ref>", methods=["PATCH"])
@require_role("admin", "analyst")
def update_ticket(ticket_ref):
    """Body: {status, assigned} — either or both.

    Status changes on a ticket linked to a Jira issue are applied in Jira
    FIRST; only if Jira accepts the change is it saved locally. If Jira
    can't be reached / refuses, nothing is saved and the caller gets an
    error (502/409) — previously the change was saved locally only and
    silently reverted on the next sync, while the UI implied it had synced.

    `assigned` is a team name in this app and has no Jira equivalent, so it
    is always local-only (the UI says so).

    Tickets that were never pushed to Jira are updated locally, and the
    response's jiraLinked=false tells the UI that's all that happened."""
    user_id = _require_login()
    if not user_id:
        return jsonify({"error": "You must be signed in"}), 401

    body = request.get_json(silent=True) or {}
    status = body.get("status")
    assigned = body.get("assigned")
    if status is None and assigned is None:
        return jsonify({"error": "Nothing to update"}), 400
    if status is not None and status not in STATUS_TO_JIRA_CATEGORY:
        return jsonify({"error": f"Unknown status '{status}'"}), 400

    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? AND ticket_ref = ?",
            (user_id, ticket_ref),
        ).fetchone()
        if not row:
            return jsonify({"error": "Ticket not found"}), 404

        now = datetime.now(timezone.utc).isoformat()
        synced_at = None  # set only if this request confirmed the state with Jira

        if status is not None and status != row["status"] and row["jira_issue_key"]:
            record = get_connection_record()
            if not record:
                return jsonify({
                    "error": f"This ticket is linked to {row['jira_issue_key']} in Jira, but Jira isn't "
                             f"connected. Reconnect Jira in Profile to change its status. Nothing was changed.",
                }), 409
            ok, error = transition_issue_to_category(
                record, row["jira_issue_key"], STATUS_TO_JIRA_CATEGORY[status]
            )
            if not ok:
                return jsonify({"error": f"{error} Nothing was changed."}), 502
            synced_at = now

        conn.execute(
            """
            UPDATE tickets SET
                status = COALESCE(?, status),
                assigned = COALESCE(?, assigned),
                jira_synced_at = COALESCE(?, jira_synced_at),
                updated_at = ?
            WHERE user_id = ? AND ticket_ref = ?
            """,
            (status, assigned, synced_at, now, user_id, ticket_ref),
        )
        conn.commit()

        row = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? AND ticket_ref = ?",
            (user_id, ticket_ref),
        ).fetchone()
    finally:
        conn.close()

    return jsonify(_row_to_json(row))


# Maps a Jira status *category* (stable across projects, unlike the status
# name itself which teams can rename) to the status values this app already
# uses. "done" -> Closed per the user's choice: a ticket closed in Jira
# stays visible here but its status flips to Closed, rather than vanishing.
_JIRA_CATEGORY_TO_STATUS = {
    "done": "Closed",
    "indeterminate": "In Progress",
    "new": "Open",
}


@tickets_bp.route("/sync", methods=["POST"])
def sync_with_jira():
    """Pulls the current status of every ticket that has a linked Jira
    issue (jira_issue_key set — i.e. it was pushed to Jira from the Review
    & Send step) and updates the local status to match. This is a
    poll-on-demand sync, not a live webhook: call it whenever the Tickets
    page loads / on a refresh button, not continuously.

    Only tickets already linked to a Jira issue are touched — tickets
    created without pushing to Jira are left alone.

    Deliberately NOT role-gated like create_tickets()/update_ticket()
    above, even though it does write to the DB: TicketList calls this
    automatically every time the Tickets page loads (see App.jsx), and it
    only ever mirrors Jira's own status back locally rather than letting
    the caller set anything themselves — so a Viewer refreshing the page
    should still see accurate, current statuses rather than a stale view
    or a sync-failed error on every visit."""
    user_id = _require_login()
    if not user_id:
        return jsonify({"error": "You must be signed in"}), 401

    record = get_connection_record()
    if not record:
        return jsonify({"error": "No Jira account connected.", "code": "jira_not_connected"}), 400

    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? AND jira_issue_key IS NOT NULL",
            (user_id,),
        ).fetchall()

        updated = 0
        failed = []  # issue keys we couldn't check — reported to the UI, never hidden
        now = datetime.now(timezone.utc).isoformat()
        for row in rows:
            category = fetch_issue_status_category(record, row["jira_issue_key"])
            if category is None:
                # Lookup failed (deleted issue, permissions, network). Leave
                # the local status alone, but say so — and don't stamp it
                # as freshly synced.
                failed.append(row["jira_issue_key"])
                continue
            mapped_status = _JIRA_CATEGORY_TO_STATUS.get(category)
            if mapped_status and mapped_status != row["status"]:
                conn.execute(
                    "UPDATE tickets SET status = ?, jira_synced_at = ?, updated_at = ? WHERE id = ?",
                    (mapped_status, now, now, row["id"]),
                )
                updated += 1
            else:
                conn.execute("UPDATE tickets SET jira_synced_at = ? WHERE id = ?", (now, row["id"]))
        conn.commit()

        all_rows = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at, id", (user_id,)
        ).fetchall()
    finally:
        conn.close()

    return jsonify({
        "updated": updated,
        "checked": len(rows),
        "failed": failed,
        "syncedAt": now,
        "tickets": [_row_to_json(r) for r in all_rows],
    })


init_tickets_db()
