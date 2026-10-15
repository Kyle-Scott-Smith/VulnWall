"""
Email-OTP multi-factor authentication — a second-factor step layered on
top of auth.py's password check and google_auth.py's OAuth callback. Same
"isolated module, plain stdlib/werkzeug" shape as email_notifications.py /
google_auth.py, but unlike those, this one fails CLOSED rather than open
when it can't reach the outside world (see below) — an account is only
opted into MFA on purpose, so a broken mail server should never turn into
a silent way around it.

Opt-in only: gated per-account by users.mfa_enabled, which is flipped from
the Profile page's "Two-factor authentication" toggle (PATCH /api/auth/mfa
in auth.py) — exactly the same pattern notify_on_critical already uses for
"Email notifications". Accounts that never turn it on are completely
unaffected; nothing here runs for them.

Flow: once a user with mfa_enabled=1 clears their normal first factor
(password in auth.py's login(), or Google's OAuth callback in
google_auth.py), that caller does NOT set session["user_id"] yet. It calls
start_mfa_challenge(row) — which generates a 6-digit code, hashes it into
the users table, and emails it — and sets session["mfa_pending_user_id"]
instead. The frontend shows a "enter the code we emailed you" screen and
POSTs it to /api/auth/mfa/verify, which is what actually promotes
mfa_pending_user_id to user_id and finishes signing them in.

Codes: 6 digits, 10 minute expiry, hashed at rest with the exact same
werkzeug generate_password_hash/check_password_hash pair auth.py uses for
passwords — the plaintext code only ever exists in memory for the length
of one request and in the body of the email itself, never written to disk
or logged. Capped at 5 verify attempts before the code is invalidated and
the user has to request a new one (via /resend or by signing in again).

If SMTP isn't configured, a code can't actually be delivered, and
start_mfa_challenge() raises EnvironmentError to say so. If SMTP *is*
configured but the send itself fails (bad credentials, connection
refused, timeout, the provider rejecting the login — e.g. Gmail's "less
secure app" style 534/5.7.9 response), smtplib raises its own
SMTPException — which, handily, is defined as a subclass of OSError (and
OSError is EnvironmentError; they're the same class in Python 3), so a
single `except EnvironmentError` in auth.py / google_auth.py catches both
cases without needing to know smtplib's exception hierarchy. Either way
the caller REFUSES the sign-in — no session is created, password or
Google OAuth notwithstanding. That's a deliberate departure from how the
rest of this app treats an unconfigured integration
(tenable_client.get_client() / OllamaVulnerabilityAnalyzer() skip
gracefully): those are optional enrichment, but MFA being unreachable is
exactly the situation a fail-open design would defeat the point of.

Endpoints registered by this blueprint (mounted at /api/auth/mfa):
  POST /api/auth/mfa/verify  -> body {code}; completes a pending sign-in
  POST /api/auth/mfa/resend  -> re-sends a fresh code to the pending user

Note on imports: this module reaches back into auth.py for DB access
(_get_db) and the user-shaping helper (_user_to_json), but only inside
function bodies, not at module load time. auth.py's login() in turn does
`import mfa` inside its own function body for the same reason. That keeps
neither module needing the other to be fully loaded first — a plain
top-level `from auth import ...` here would fail at import time, since
scanner.py loads auth.py (and auth.py would load this module) before
auth.py has finished defining those names.
"""

import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import email_notifications

mfa_bp = Blueprint("mfa", __name__, url_prefix="/api/auth/mfa")

CODE_LENGTH = 6
CODE_TTL_MINUTES = 10
MAX_ATTEMPTS = 5
# Each resend issues a fresh code and resets the attempt counter, so without
# a cap, resend + 5 guesses could repeat forever. Counted per pending
# sign-in (stored in the session, which login()/Google's callback clear
# when a new sign-in starts).
MAX_RESENDS = 3


def _generate_code():
    return "".join(secrets.choice("0123456789") for _ in range(CODE_LENGTH))


def start_mfa_challenge(user_row):
    """Generates a fresh code for user_row, stores its hash + expiry, resets
    the attempt counter, and emails it. Raises EnvironmentError if SMTP
    isn't configured on this server (see module docstring) — the caller
    decides how to degrade."""
    if not email_notifications.is_configured():
        raise EnvironmentError(
            "MFA is enabled on this account but email delivery isn't "
            "configured on the server (SMTP_HOST/SMTP_FROM_EMAIL)."
        )

    import auth  # lazy — see module docstring

    code = _generate_code()
    code_hash = generate_password_hash(code)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=CODE_TTL_MINUTES)).isoformat()

    conn = auth._get_db()
    try:
        conn.execute(
            "UPDATE users SET mfa_code_hash = ?, mfa_code_expires_at = ?, mfa_code_attempts = 0 WHERE id = ?",
            (code_hash, expires_at, user_row["id"]),
        )
        conn.commit()
    finally:
        conn.close()

    subject = "Your sign-in code"
    body = (
        f"Hi {user_row['name'] or 'there'},\n\n"
        f"Your sign-in verification code is: {code}\n\n"
        f"This code expires in {CODE_TTL_MINUTES} minutes. If you didn't just "
        f"try to sign in, you can ignore this email — your account is still "
        f"protected, since nobody else has this code.\n"
    )
    email_notifications.send_plain_email(user_row["email"], subject, body)


def _clear_code(user_id):
    import auth  # lazy — see module docstring

    conn = auth._get_db()
    try:
        conn.execute(
            "UPDATE users SET mfa_code_hash = NULL, mfa_code_expires_at = NULL, mfa_code_attempts = 0 WHERE id = ?",
            (user_id,),
        )
        conn.commit()
    finally:
        conn.close()


def _get_pending_row():
    """Returns the user row for session["mfa_pending_user_id"], or None
    (clearing the dangling session key if the account no longer exists)."""
    import auth  # lazy — see module docstring

    pending_id = session.get("mfa_pending_user_id")
    if not pending_id:
        return None

    conn = auth._get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (pending_id,)).fetchone()
    finally:
        conn.close()

    if not row:
        session.pop("mfa_pending_user_id", None)
    return row


@mfa_bp.route("/verify", methods=["POST"])
def verify():
    """Body: {"code": "123456"}. Completes a sign-in that
    start_mfa_challenge() left half-finished in
    session["mfa_pending_user_id"]."""
    import auth  # lazy — see module docstring

    row = _get_pending_row()
    if not row:
        return jsonify({"error": "No sign-in is waiting for a code. Please sign in again."}), 400

    body = request.get_json(silent=True) or {}
    code = (body.get("code") or "").strip()
    if not code:
        return jsonify({"error": "Please enter the code we emailed you"}), 400

    if not row["mfa_code_hash"]:
        session.pop("mfa_pending_user_id", None)
        return jsonify({"error": "No code is pending. Please sign in again."}), 400

    if row["mfa_code_attempts"] >= MAX_ATTEMPTS:
        _clear_code(row["id"])
        session.pop("mfa_pending_user_id", None)
        return jsonify({"error": "Too many incorrect attempts. Please sign in again to get a new code."}), 429

    expires_at = row["mfa_code_expires_at"]
    if not expires_at or datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
        _clear_code(row["id"])
        session.pop("mfa_pending_user_id", None)
        return jsonify({"error": "That code has expired. Please sign in again to get a new one."}), 400

    if not check_password_hash(row["mfa_code_hash"], code):
        conn = auth._get_db()
        try:
            conn.execute("UPDATE users SET mfa_code_attempts = mfa_code_attempts + 1 WHERE id = ?", (row["id"],))
            conn.commit()
        finally:
            conn.close()
        return jsonify({"error": "Incorrect code"}), 401

    _clear_code(row["id"])
    session.pop("mfa_pending_user_id", None)
    session.pop("mfa_resend_count", None)
    session["user_id"] = row["id"]

    return jsonify({"status": "signed_in", **auth._user_to_json(row)})


@mfa_bp.route("/resend", methods=["POST"])
def resend():
    """Lets the frontend offer a 'resend code' button on the MFA screen
    without making the user restart the whole sign-in flow."""
    row = _get_pending_row()
    if not row:
        return jsonify({"error": "No sign-in is waiting for a code. Please sign in again."}), 400

    resends = session.get("mfa_resend_count", 0)
    if resends >= MAX_RESENDS:
        _clear_code(row["id"])
        session.pop("mfa_pending_user_id", None)
        session.pop("mfa_resend_count", None)
        return jsonify({"error": "Too many codes requested. Please sign in again."}), 429

    try:
        start_mfa_challenge(row)
    except EnvironmentError as e:
        return jsonify({"error": str(e)}), 503

    session["mfa_resend_count"] = resends + 1
    return jsonify({"status": "code_resent"})
