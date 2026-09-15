"""
Google Sign-In (OAuth 2.0 / OpenID Connect) — isolated module, same shape
as jira_integration.py: a plain `requests`-based OAuth flow (no new
dependency, no OAuth library), config from env vars only, nothing
sensitive hardcoded, and every route degrades to a clear 503 "not
configured" if GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET aren't set rather
than crashing the app on import. Safe to commit and run the rest of the
app fine without ever configuring it.

Unlike jira_integration.py / registry_credentials.py, this isn't "connect
an extra integration for an already-signed-in account" — it's an
alternative way to sign in/sign up in the first place, sitting next to
auth.py's email+password flow. Sign-in and sign-up share one flow: Google
tells us the user's verified email, and:
  - if an account with that email already exists (local or previously
    Google-linked), we sign into that same account, linking google_sub
    onto it if it wasn't already
  - otherwise we create a brand new account for them (see
    auth.create_google_user), same outcome as /api/auth/signup but with
    no local password to set

Endpoints registered by this blueprint (mounted at /api/auth/google):
  GET /api/auth/google/status    -> is Google Sign-In configured on this server?
  GET /api/auth/google/login     -> redirect to Google's OAuth consent screen
  GET /api/auth/google/callback  -> Google redirects here after the user approves/denies
"""

import os
import secrets

import requests
from flask import Blueprint, jsonify, redirect, request, session

from auth import create_google_user, get_user_by_email, link_google_sub

google_auth_bp = Blueprint("google_auth", __name__, url_prefix="/api/auth/google")

# --- Config: env vars only, nothing sensitive ever hardcoded ------------
CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
CALLBACK_URL = os.environ.get("GOOGLE_CALLBACK_URL", "http://localhost:5000/api/auth/google/callback")
# Where the browser lands after a successful sign-in. The frontend's
# existing GET /api/auth/me check-on-load (see App.jsx) picks up the new
# session cookie automatically once it's back here — no separate
# "?google=connected" handshake needed like the Jira integration has.
FRONTEND_RETURN_URL = os.environ.get("GOOGLE_FRONTEND_RETURN_URL", "http://localhost:5173/")

SCOPES = "openid email profile"
AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


def _not_configured():
    if not CLIENT_ID or not CLIENT_SECRET:
        return jsonify({
            "error": "Google Sign-In is not configured on this server. "
                     "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to enable it."
        }), 503
    return None


@google_auth_bp.route("/status", methods=["GET"])
def status():
    """Lets the frontend hide the 'Continue with Google' button entirely
    when it's not configured, instead of showing one that always errors."""
    return jsonify({"configured": bool(CLIENT_ID and CLIENT_SECRET)})


@google_auth_bp.route("/login", methods=["GET"])
def login():
    """Entry point for the 'Continue with Google' button. This has to be a
    normal browser navigation (window.location, not fetch) — the OAuth
    dance needs real page redirects to Google and back, the same reason
    jira_integration.py's /connect route works this way."""
    error = _not_configured()
    if error:
        return error

    state = secrets.token_urlsafe(24)
    session["google_oauth_state"] = state

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": CALLBACK_URL,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    query = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
    return redirect(f"{AUTHORIZE_URL}?{query}")


def _redirect_with_error(message):
    """Sends the browser back to the frontend with ?authError=... so the
    sign-in screen can show what went wrong, instead of stranding the user
    on a bare JSON error page mid-redirect."""
    separator = "&" if "?" in FRONTEND_RETURN_URL else "?"
    return redirect(f"{FRONTEND_RETURN_URL}{separator}authError={requests.utils.quote(message)}")


@google_auth_bp.route("/callback", methods=["GET"])
def callback():
    """Google redirects here after the user approves (or denies) access."""
    error = _not_configured()
    if error:
        return error

    if request.args.get("error"):
        return _redirect_with_error("Google sign-in was cancelled.")

    returned_state = request.args.get("state")
    expected_state = session.pop("google_oauth_state", None)
    if not returned_state or returned_state != expected_state:
        return _redirect_with_error("Google sign-in failed (state mismatch). Please try again.")

    code = request.args.get("code")
    if not code:
        return _redirect_with_error("Google sign-in failed. Please try again.")

    token_resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "redirect_uri": CALLBACK_URL,
        },
        timeout=10,
    )
    if token_resp.status_code != 200:
        print(f"[google_auth] token exchange failed ({token_resp.status_code}): {token_resp.text}")
        return _redirect_with_error("Google sign-in failed during token exchange.")

    access_token = token_resp.json().get("access_token")

    userinfo_resp = requests.get(
        USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    if userinfo_resp.status_code != 200:
        print(f"[google_auth] userinfo lookup failed ({userinfo_resp.status_code}): {userinfo_resp.text}")
        return _redirect_with_error("Google sign-in failed while fetching your profile.")

    profile = userinfo_resp.json()
    google_sub = profile.get("sub")
    email = (profile.get("email") or "").strip().lower()
    email_verified = profile.get("email_verified", False)
    name = profile.get("name") or (email.split("@")[0] if email else "Google User")

    if not email or not google_sub:
        return _redirect_with_error("Google didn't return an email address for this account.")
    if not email_verified:
        return _redirect_with_error("Please verify your email address with Google before signing in.")

    row = get_user_by_email(email)
    if row:
        user_id = row["id"]
        if row["google_sub"] != google_sub:
            link_google_sub(user_id, google_sub)
        is_new_account = False
    else:
        user_id = create_google_user(name, email, google_sub)
        is_new_account = True

    # A brand new account can't have turned MFA on yet, so this only ever
    # applies to an existing account signing in (or linking Google onto an
    # existing local-password account) with the Profile page's "Two-factor
    # authentication" toggle already on. Same hand-off auth.py's login()
    # uses: don't set session["user_id"] yet, send a code, and let
    # /api/auth/mfa/verify (mfa.py) finish the sign-in.
    if not is_new_account and row["mfa_enabled"]:
        import mfa  # lazy — see mfa.py's module docstring on why
        try:
            mfa.start_mfa_challenge(row)
        except EnvironmentError as e:
            print(f"[google_auth] MFA enabled for {email} but couldn't send a code: {e}")
        else:
            session.clear()
            session["mfa_pending_user_id"] = user_id
            separator = "&" if "?" in FRONTEND_RETURN_URL else "?"
            return redirect(
                f"{FRONTEND_RETURN_URL}{separator}mfaRequired=1&email={requests.utils.quote(email)}"
            )
        # SMTP not configured on this server — fall through and sign them
        # in directly rather than stranding the account, same degrade as
        # auth.py's login().

    session.clear()
    session["user_id"] = user_id

    if not is_new_account:
        return redirect(FRONTEND_RETURN_URL)

    # First-time Google sign-up: flag it in the redirect (same "tell the
    # frontend via query param" pattern _redirect_with_error uses) so
    # App.jsx knows to route this person into the business-context
    # questionnaire instead of straight to the dashboard, matching what
    # /api/auth/signup + SignUp's onSignUp already do for local accounts.
    separator = "&" if "?" in FRONTEND_RETURN_URL else "?"
    return redirect(f"{FRONTEND_RETURN_URL}{separator}newAccount=1")
