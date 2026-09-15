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

Also handles the columns Google Sign-In (google_auth.py) and critical-
finding email alerts (email_notifications.py, triggered from scanner.py)
need on top of the base users table: auth_provider/google_sub (who a
Google-linked account belongs to) and notify_on_critical (the Profile
page's "Email notifications" toggle, persisted here so scanner.py can
check it server-side rather than trusting client-only state).

Also owns the columns email-OTP MFA (mfa.py) needs: mfa_enabled (the
Profile page's "Two-factor authentication" toggle -- opt-in, same shape
as notify_on_critical) plus mfa_code_hash/mfa_code_expires_at/
mfa_code_attempts, which hold the *current* one-time code for a user with
MFA turned on (hashed, never stored in plaintext -- see mfa.py). login()
and google_auth.py's callback() check mfa_enabled after a password/Google
check succeeds: if it's on, they don't set session["user_id"] yet, they
hand off to mfa.start_mfa_challenge() and set session["mfa_pending_user_id"]
instead, and only /api/auth/mfa/verify (mfa.py) promotes that to a real
signed-in session.

Also owns role-based access control: the `role` column (one of
VALID_ROLES) and the require_role() decorator every other blueprint
imports from here to gate its mutating endpoints. Three roles:
  - viewer  : read-only. Can see the dashboard, scan history, and
              tickets, but can't run a scan, generate/edit/sync
              tickets, or connect Jira/a registry.
  - analyst : viewer's access plus everything scan/ticket-related --
              the "normal" working account. This app's original
              (pre-RBAC) behavior for a signed-in user.
  - admin   : analyst's access plus the account directory
              (GET/PATCH /api/auth/users*) -- the only role that can see
              every account on this server and change what role they
              have.
Assignment: there's no invite flow -- an account gets a role at
signup/first-Google-sign-in, and only an Admin can change it afterwards
(see update_user_role() below). Bootstrapping who that first Admin even
is works two ways: on a brand new database, whichever account is created
first (signup or Google) is automatically made Admin (see
_bootstrap_role()); on a database that already existed before this
feature shipped, init_db()'s migration promotes whichever account is
oldest, so there's never a moment where a real install has zero Admins
and no way back in.
"""

import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

DB_PATH = os.environ.get(
    "AUTH_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "auth.db"),
)

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

VALID_ROLES = ("admin", "analyst", "viewer")
DEFAULT_ROLE = "analyst"


def _get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates the users table if it doesn't exist yet, and migrates it
    forward if it already exists from before Google Sign-In / email alerts
    were added — same ALTER-TABLE-if-missing pattern tickets.py uses for
    its jira_issue_key/jira_url columns. Called once at import time (see
    bottom of file) so the table is always there before any request hits
    this blueprint."""
    conn = _get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'analyst',
                created_at    TEXT NOT NULL
            )
            """
        )
        existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "role" not in existing_cols:
            conn.execute(f"ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT '{DEFAULT_ROLE}'")
            # This is a database that existed before RBAC shipped, so
            # every row just landed as a plain Analyst -- including
            # whoever's been using this server as if they owned it.
            # Promote the oldest account (first ever created) to Admin so
            # there's always at least one account that can reach the new
            # Manage Users screen, instead of everyone being downgraded
            # with no way to change anyone's role, including their own.
            conn.execute(
                """
                UPDATE users SET role = 'admin' WHERE id = (
                    SELECT id FROM users ORDER BY created_at ASC, id ASC LIMIT 1
                )
                """
            )
        if "auth_provider" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local'")
        if "google_sub" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        if "notify_on_critical" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN notify_on_critical INTEGER NOT NULL DEFAULT 0")
        if "mfa_enabled" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
        if "mfa_code_hash" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN mfa_code_hash TEXT")
        if "mfa_code_expires_at" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN mfa_code_expires_at TEXT")
        if "mfa_code_attempts" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN mfa_code_attempts INTEGER NOT NULL DEFAULT 0")
        # Partial unique index (only enforced where google_sub is actually
        # set) so two different Google accounts can never silently collide
        # onto the same local user row.
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub "
            "ON users(google_sub) WHERE google_sub IS NOT NULL"
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
    return {
        "name": row["name"],
        "email": row["email"],
        "authProvider": row["auth_provider"],
        "notifyOnCritical": bool(row["notify_on_critical"]),
        "mfaEnabled": bool(row["mfa_enabled"]),
        "role": row["role"],
    }


def _bootstrap_role(conn):
    """What role a brand new account should get, using the SAME open
    connection the caller is about to INSERT with (so the COUNT below and
    the insert that follows it can't race against a concurrent signup and
    both see zero rows). The very first account ever created on this
    database becomes Admin -- otherwise nobody could ever reach the
    account directory to promote anyone. Every account after that is a
    plain Analyst until an Admin changes it from the Manage Users screen."""
    count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    return "admin" if count == 0 else DEFAULT_ROLE


def require_role(*roles):
    """Decorator for routes that need not just a signed-in session but a
    specific role on the account. Usage: @require_role("admin") or
    @require_role("admin", "analyst"). Returns 401 if nobody's signed in,
    403 if their role isn't one of `roles`, otherwise calls the wrapped
    view normally.

    Centralizes what tickets.py/business_context.py/registry_credentials.py/
    jira_integration.py's own `_require_login()` helpers already do for
    the "not signed in" half of this check, so every blueprint that also
    needs a role check shares one implementation and one error shape
    instead of re-deriving it per file."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user_id = session.get("user_id")
            if not user_id:
                return jsonify({"error": "You must be signed in"}), 401
            row = get_user_by_id(user_id)
            if not row:
                session.clear()
                return jsonify({"error": "You must be signed in"}), 401
            if row["role"] not in roles:
                return jsonify({"error": "Your account role doesn't have permission to do this"}), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def get_user_by_id(user_id):
    """Fetches a user row by id, or None. Used by scanner.py to look up the
    signed-in user's email/name/notify_on_critical preference when deciding
    whether to send a critical-finding alert email."""
    if not user_id:
        return None
    conn = _get_db()
    try:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()


def get_user_by_email(email):
    """Fetches a user row by email (case-insensitive, matching the column's
    COLLATE NOCASE), or None. Used by google_auth.py to find an existing
    account — local or previously Google-linked — before deciding whether
    to sign into it or create a new one."""
    if not email:
        return None
    conn = _get_db()
    try:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
    finally:
        conn.close()


def create_google_user(name, email, google_sub):
    """Creates a new account for a first-time Google sign-in. There's no
    local password to check, so password_hash is set to a random,
    never-typed placeholder run through the same hasher local passwords
    use — check_password_hash will never match it, so a login attempt
    against this email with an actual password is safely rejected by the
    normal /api/auth/login flow rather than needing special-casing there."""
    now = datetime.now(timezone.utc).isoformat()
    placeholder_hash = generate_password_hash(secrets.token_urlsafe(32))
    conn = _get_db()
    try:
        role = _bootstrap_role(conn)
        cur = conn.execute(
            """
            INSERT INTO users (name, email, password_hash, created_at, auth_provider, google_sub, notify_on_critical, role)
            VALUES (?, ?, ?, ?, 'google', ?, 0, ?)
            """,
            (name, email, placeholder_hash, now, google_sub, role),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def link_google_sub(user_id, google_sub):
    """Attaches a Google identity to an existing (possibly local-password)
    account, e.g. someone who signed up with email+password originally and
    later uses 'Continue with Google' with the same email."""
    conn = _get_db()
    try:
        conn.execute("UPDATE users SET google_sub = ? WHERE id = ?", (google_sub, user_id))
        conn.commit()
    finally:
        conn.close()


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
        role = _bootstrap_role(conn)
        cur = conn.execute(
            "INSERT INTO users (name, email, password_hash, created_at, notify_on_critical, role) VALUES (?, ?, ?, ?, 0, ?)",
            (name, email, password_hash, datetime.now(timezone.utc).isoformat(), role),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "An account with this email already exists"}), 409
    finally:
        conn.close()

    session.clear()
    session["user_id"] = user_id
    # role wasn't returned here pre-RBAC (there was nothing to return) —
    # now that every account has one, echo it back the same way login()
    # already does via _user_to_json, so the frontend knows immediately
    # whether this brand new account is an Admin (the very first account
    # on this server) or an Analyst (everyone after), without a second
    # round trip to /api/auth/me.
    return jsonify({"status": "signed_up", "name": name, "email": email, "role": role})


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

    # An account that signed up via Google has no real password (see
    # create_google_user) — check_password_hash would just fail on it like
    # any wrong password, but telling them to use Google instead is much
    # more useful than a generic "invalid credentials".
    if row and row["auth_provider"] == "google":
        return jsonify({"error": "This account uses Google Sign-In. Use the \u201cContinue with Google\u201d button instead."}), 401

    # Same generic error either way (unknown email vs. wrong password) so a
    # failed login doesn't reveal whether the email is registered.
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid email or password"}), 401

    if row["mfa_enabled"]:
        # Password checked out, but this account has the Profile page's
        # "Two-factor authentication" toggle on -- don't sign them in yet.
        # Lazy import: avoids a circular import at module load time (mfa.py
        # reaches back into this module for DB access), see mfa.py's header.
        import mfa
        try:
            mfa.start_mfa_challenge(row)
        except EnvironmentError as e:
            # SMTP isn't configured on this server, so we can't actually
            # deliver a code -- degrade to signing them straight in rather
            # than locking the account out entirely (same "not configured
            # -> skip, don't fail the request" pattern as everywhere else
            # in this app that reads on an env-var-gated integration).
            print(f"[auth] MFA enabled for {row['email']} but couldn't send a code: {e}")
            session.clear()
            session["user_id"] = row["id"]
            return jsonify({"status": "signed_in", **_user_to_json(row)})

        session.clear()
        session["mfa_pending_user_id"] = row["id"]
        return jsonify({"status": "mfa_required", "email": row["email"]})

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


@auth_bp.route("/notifications", methods=["PATCH"])
def update_notifications():
    """Body: {"enabled": bool} — backs the Profile page's "Email
    notifications" toggle. Persisted server-side (rather than just in the
    browser) because scanner.py needs to check this on the server, at scan
    time, to decide whether a critical-finding alert email should go out."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "You must be signed in"}), 401

    body = request.get_json(silent=True) or {}
    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"error": "'enabled' must be true or false"}), 400

    conn = _get_db()
    try:
        conn.execute("UPDATE users SET notify_on_critical = ? WHERE id = ?", (1 if enabled else 0, user_id))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"notifyOnCritical": enabled})


@auth_bp.route("/mfa", methods=["PATCH"])
def update_mfa():
    """Body: {"enabled": bool} -- backs the Profile page's "Two-factor
    authentication" toggle. Same shape as /notifications above. Turning
    this on doesn't require proving a code right away (there's no session
    to re-verify mid-request) -- the first real test of it is simply the
    next time this account signs in, which will now ask for one."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "You must be signed in"}), 401

    body = request.get_json(silent=True) or {}
    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"error": "'enabled' must be true or false"}), 400

    conn = _get_db()
    try:
        conn.execute("UPDATE users SET mfa_enabled = ? WHERE id = ?", (1 if enabled else 0, user_id))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"mfaEnabled": enabled})


def _admin_user_to_json(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "authProvider": row["auth_provider"],
        "createdAt": row["created_at"],
    }


@auth_bp.route("/users", methods=["GET"])
@require_role("admin")
def list_users():
    """Admin-only account directory -- every account on this server and
    its current role, backing the Profile page's 'Manage users' panel."""
    conn = _get_db()
    try:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at ASC").fetchall()
    finally:
        conn.close()
    return jsonify([_admin_user_to_json(r) for r in rows])


@auth_bp.route("/users/<int:target_id>/role", methods=["PATCH"])
@require_role("admin")
def update_user_role(target_id):
    """Body: {"role": "admin"|"analyst"|"viewer"}. Refuses to demote the
    last remaining Admin (whether that's someone else or the caller
    themselves) -- doing so would strand the account directory with
    nobody left who can open it to fix the mistake."""
    body = request.get_json(silent=True) or {}
    role = body.get("role")
    if role not in VALID_ROLES:
        return jsonify({"error": f"role must be one of {', '.join(VALID_ROLES)}"}), 400

    conn = _get_db()
    try:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (target_id,)).fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        if target["role"] == "admin" and role != "admin":
            admin_count = conn.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin'"
            ).fetchone()["n"]
            if admin_count <= 1:
                return jsonify({"error": "Can't remove the last Admin. Promote someone else first."}), 400

        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, target_id))
        conn.commit()
        updated = conn.execute("SELECT * FROM users WHERE id = ?", (target_id,)).fetchone()
    finally:
        conn.close()

    return jsonify(_admin_user_to_json(updated))


init_db()
