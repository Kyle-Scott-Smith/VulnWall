"""
Account signup/login backend — SQLite storage, hashed passwords, session-cookie
auth. Same blueprint pattern as jira_integration.py / registry_credentials.py.

Storage: a single SQLite database file (DB_PATH, backend/data/auth.db by
default). Created automatically on first run. Passwords are never stored in
plain text — only a salted hash (werkzeug's generate_password_hash, which
uses PBKDF2) is written to disk.

Session: on successful signup or login we store the user's id in the Flask
session cookie (session["user_id"]); /api/auth/me reads it back to tell the
frontend who's currently signed in on page load/refresh. This relies on the
same app.secret_key already set up in scanner.py for the Jira/registry
blueprints.

Endpoints registered by this blueprint (mounted at /api/auth):
  POST /api/auth/signup    -> body {name, email, password}; creates account, signs in
  POST /api/auth/login     -> body {email, password}; checks credentials, signs in
  POST /api/auth/logout    -> clears the session
  GET  /api/auth/me        -> {authenticated, name, email} for the current session

This is a demo-scale setup (single SQLite file, no email verification, no
password reset, no rate limiting on login attempts) — enough to show real
account creation and credential checking backed by a database, not meant as
a production auth system as-is.
"""

import os
import re
import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

DB_PATH = os.environ.get(
    "AUTH_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "auth.db"),
)

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates the users table if it doesn't exist yet. Called once at
    import time (see bottom of file) so the table is always there before
    any request hits this blueprint."""
    conn = _get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _password_error(password):
    """Mirrors the frontend's password rules (SignUp's passwordError) so a
    request that somehow skips the client-side check still gets rejected
    server-side instead of creating a weak-password account."""
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[a-z]", password):
        return "Password must include a lowercase letter"
    if not re.search(r"[A-Z]", password):
        return "Password must include an uppercase letter"
    if not re.search(r"[0-9]", password):
        return "Password must include a number"
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include a symbol (e.g. ! @ # $)"
    return None


def _user_to_json(row):
    return {"name": row["name"], "email": row["email"]}


@auth_bp.route("/signup", methods=["POST"])
def signup():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not name or not email or not password:
        return jsonify({"error": "name, email, and password are all required"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"error": "Please enter a valid email address"}), 400
    pw_error = _password_error(password)
    if pw_error:
        return jsonify({"error": pw_error}), 400

    password_hash = generate_password_hash(password)

    conn = _get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (name, email, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "An account with this email already exists"}), 409
    finally:
        conn.close()

    session.clear()
    session["user_id"] = user_id
    return jsonify({"status": "signed_up", "name": name, "email": email})


@auth_bp.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Please fill in all fields"}), 400

    conn = _get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    finally:
        conn.close()

    # Same generic error either way (unknown email vs. wrong password) so a
    # failed login doesn't reveal whether the email is registered.
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid email or password"}), 401

    session.clear()
    session["user_id"] = row["id"]
    return jsonify({"status": "signed_in", **_user_to_json(row)})


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "signed_out"})


@auth_bp.route("/me", methods=["GET"])
def me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"authenticated": False})

    conn = _get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()

    if not row:
        session.clear()
        return jsonify({"authenticated": False})

    return jsonify({"authenticated": True, **_user_to_json(row)})


init_db()
