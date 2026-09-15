"""
Private container registry credentials — isolated module, same shape as
jira_integration.py.

Why this exists: scanning a private image with Trivy needs a
username/password for that registry. Earlier this lived in backend/.env
(TRIVY_REGISTRY_URL/USERNAME/PASSWORD), which meant editing a server file
and restarting the container every time you wanted to point at a
different registry. This moves it into the app itself — a "Connect
registry" form on the Profile page, same pattern as "Connect Jira" — so
it's configured at runtime through the UI instead of through code.

Storage: same SQLite database as auth.py (DB_PATH import below), one row
per user in a registry_connections table, keyed by users.id. This used to
be a plain in-memory dict, which meant a connection vanished on every
`docker compose up --build` even though the account itself (stored in
SQLite) survived the restart — that mismatch was the actual bug. Moving
this into the same database as the account fixes it: a connection now
persists exactly as long as the account does. Password is stored in
plain text in this SQLite file (not encrypted) — fine for a local
dev/demo tool, not something to expose beyond localhost as-is.

Endpoints registered by this blueprint (mounted at /api/registry):
  GET  /api/registry/status      -> is a private registry currently connected?
  POST /api/registry/connect     -> body {url, username, password}; stores it
  POST /api/registry/disconnect  -> forget the stored connection

get_credentials() is what scanner.py calls when a live Trivy scan requests
usePrivateRegistry=True, to fetch the (url, username, password) tuple for
the signed-in account without the scan-triggering code needing to know
anything about how/where it's stored.
"""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

from auth import _get_db, require_role

registry_bp = Blueprint("registry", __name__, url_prefix="/api/registry")


def init_registry_db():
    """Creates the registry_connections table if it doesn't exist yet.
    Called once at import time (see bottom of file), same as
    auth.init_db() / business_context.init_business_context_db()."""
    conn = _get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS registry_connections (
                user_id     INTEGER PRIMARY KEY REFERENCES users(id),
                url         TEXT NOT NULL,
                username    TEXT NOT NULL,
                password    TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _session_key():
    """Returns the logged-in account's user_id (set by auth.py on
    signup/login), or None if nobody's signed in. Credentials are keyed by
    this instead of a random per-browser session id, so a connection
    follows the account rather than disappearing when the session cookie
    changes."""
    return session.get("user_id")


def _get_record(user_id):
    if not user_id:
        return None
    conn = _get_db()
    try:
        return conn.execute(
            "SELECT * FROM registry_connections WHERE user_id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()


def get_credentials():
    """Returns (url, username, password) for the signed-in account's
    connected registry, or (None, None, None) if nothing is connected.
    Called by scanner.py when a scan requests usePrivateRegistry=True —
    keeps the "where are credentials stored" question out of scanner.py
    and out of scanners/trivy.py entirely."""
    record = _get_record(_session_key())
    if not record:
        return None, None, None
    return record["url"], record["username"], record["password"]


@registry_bp.route("/status", methods=["GET"])
def status():
    """Lets the frontend show 'Connect registry' vs 'Connected to <url>'
    — never returns the password."""
    record = _get_record(_session_key())
    if not record:
        return jsonify({"connected": False})
    return jsonify({"connected": True, "url": record["url"], "username": record["username"]})


@registry_bp.route("/connect", methods=["POST"])
@require_role("admin", "analyst")
def connect():
    """Store the signed-in account's private registry credentials.
    Body: {"url": "ghcr.io", "username": "...", "password": "..."}"""
    user_id = _session_key()

    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not url or not username or not password:
        return jsonify({"error": "url, username, and password are all required"}), 400

    now = datetime.now(timezone.utc).isoformat()
    conn = _get_db()
    try:
        conn.execute(
            """
            INSERT INTO registry_connections (user_id, url, username, password, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                url=excluded.url,
                username=excluded.username,
                password=excluded.password,
                updated_at=excluded.updated_at
            """,
            (user_id, url, username, password, now, now),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "connected", "url": url, "username": username})


@registry_bp.route("/disconnect", methods=["POST"])
@require_role("admin", "analyst")
def disconnect():
    user_id = _session_key()
    if user_id:
        conn = _get_db()
        try:
            conn.execute("DELETE FROM registry_connections WHERE user_id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()
    return jsonify({"status": "disconnected"})


init_registry_db()
