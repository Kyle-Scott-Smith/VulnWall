"""
Jira integration — isolated module.

Everything Jira-related lives in this one file: the OAuth 2.0 (3LO)
connect/callback routes, token storage, and the "push ticket to Jira"
endpoint. It's a self-contained Flask Blueprint so wiring it into the
main app is a single import + one `register_blueprint()` call in
scanner.py — nothing else in the app needs to know Jira exists.

Why isolated like this (safe to push to git):
  - No secrets are hardcoded anywhere in this file. Everything sensitive
    (JIRA_CLIENT_ID, JIRA_CLIENT_SECRET) is read from environment
    variables at request time, never written to disk, never logged.
  - If those env vars aren't set, every route here returns a clear
    503/"not configured" response instead of crashing the app on import.
    You can commit this file and run the rest of the app fine without
    ever configuring Jira.
  - Token storage is a single in-memory dict for demo purposes (see
    _TOKENS below.) Swap it for a real database before using this with
    more than one concurrent demo user — that's the one thing this file
    deliberately does NOT solve, flagged clearly so it isn't mistaken
    for production-ready auth storage.

Endpoints registered by this blueprint (mounted at /api/jira):
  GET  /api/jira/status              -> is a Jira account currently connected?
  GET  /api/jira/connect             -> redirect to Atlassian's OAuth screen
  GET  /api/jira/callback            -> Atlassian redirects here after approval
  POST /api/jira/disconnect          -> forget the stored connection
  POST /api/jira/create-ticket       -> push one ticket to the connected Jira,
                                         auto-creating the target project/board
                                         (JIRA_DEFAULT_PROJECT_KEY) the first
                                         time if it doesn't exist yet
"""

import os
import secrets

import requests
from flask import Blueprint, jsonify, redirect, request, session

jira_bp = Blueprint("jira", __name__, url_prefix="/api/jira")

# --- Config: env vars only, nothing sensitive ever hardcoded ------------
CLIENT_ID = os.environ.get("JIRA_CLIENT_ID")
CLIENT_SECRET = os.environ.get("JIRA_CLIENT_SECRET")
CALLBACK_URL = os.environ.get("JIRA_CALLBACK_URL", "http://localhost:5000/api/jira/callback")
# Where the frontend should be sent back to after connecting, e.g. the
# Profile page. Configurable so this works whether the frontend runs on
# :5173 (docker-compose dev) or somewhere else.
FRONTEND_RETURN_URL = os.environ.get("JIRA_FRONTEND_RETURN_URL", "http://localhost:5173/?jira=connected")

SCOPES = (
    "read:jira-work write:jira-work manage:jira-project read:jira-user "
    "write:project:jira read:project:jira offline_access"
)
# NOTE: POST /rest/api/3/project (create a new project) only has a
# GRANULAR scope, no classic equivalent — per Atlassian's REST API
# reference it needs write:project:jira *and* read:project:jira. The
# classic manage:jira-project scope only covers editing existing
# project settings / creating versions & components, not creating the
# project itself. Missing read:project:jira here is what was causing
# 401 "Unauthorized; scope does not match" on auto-create even though
# manage:jira-project was checked in the console.
AUTHORIZE_URL = "https://auth.atlassian.com/authorize"
TOKEN_URL = "https://auth.atlassian.com/oauth/token"
ACCESSIBLE_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"

# --- Token storage (DEMO ONLY — see module docstring) -------------------
# Keyed by Flask session id so multiple browser sessions don't clobber
# each other during a demo. Not persisted, not encrypted, gone on
# process restart. Replace with a real database + encryption before any
# real multi-user use.
_TOKENS = {}


def _session_key():
    # Flask's session cookie already gives each browser a stable id once
    # something is written to session; force that to exist.
    session.setdefault("_jira_sid", secrets.token_urlsafe(16))
    return session["_jira_sid"]


def _not_configured():
    if not CLIENT_ID or not CLIENT_SECRET:
        return jsonify({
            "error": "Jira integration is not configured on this server. "
                     "Set JIRA_CLIENT_ID and JIRA_CLIENT_SECRET to enable it."
        }), 503
    return None


@jira_bp.route("/status", methods=["GET"])
def status():
    """Lets the frontend show 'Connect Jira' vs 'Connected to <site>'."""
    if not CLIENT_ID or not CLIENT_SECRET:
        return jsonify({"configured": False, "connected": False})

    record = _TOKENS.get(_session_key())
    if not record:
        return jsonify({"configured": True, "connected": False})

    return jsonify({
        "configured": True,
        "connected": True,
        "site": record["site_name"],
    })


@jira_bp.route("/connect", methods=["GET"])
def connect():
    """Entry point for the 'Connect Jira' button — redirects the browser
    to Atlassian's real authorization screen."""
    error = _not_configured()
    if error:
        return error

    state = secrets.token_urlsafe(24)
    session["jira_oauth_state"] = state

    params = {
        "audience": "api.atlassian.com",
        "client_id": CLIENT_ID,
        "scope": SCOPES,
        "redirect_uri": CALLBACK_URL,
        "state": state,
        "response_type": "code",
        "prompt": "consent",
    }
    query = "&".join(f"{k}={requests.utils.quote(v)}" for k, v in params.items())
    return redirect(f"{AUTHORIZE_URL}?{query}")


@jira_bp.route("/callback", methods=["GET"])
def callback():
    """Atlassian redirects here after the user approves access."""
    error = _not_configured()
    if error:
        return error

    returned_state = request.args.get("state")
    expected_state = session.pop("jira_oauth_state", None)
    if not returned_state or returned_state != expected_state:
        return jsonify({"error": "State mismatch — possible CSRF, aborting."}), 400

    code = request.args.get("code")
    if not code:
        return jsonify({
            "error": request.args.get("error_description", "Authorization failed: no code returned.")
        }), 400

    token_resp = requests.post(
        TOKEN_URL,
        json={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "redirect_uri": CALLBACK_URL,
        },
        timeout=10,
    )
    if token_resp.status_code != 200:
        return jsonify({"error": "Token exchange failed", "detail": token_resp.text}), 400

    tokens = token_resp.json()
    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token")

    resources_resp = requests.get(
        ACCESSIBLE_RESOURCES_URL,
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        timeout=10,
    )
    resources = resources_resp.json() if resources_resp.status_code == 200 else []
    if not resources:
        return jsonify({"error": "No accessible Jira sites found for this account."}), 400

    site = resources[0]  # first accessible site; see note in README re: multi-site accounts

    # Needed later if we have to auto-create the project: Jira requires
    # every project to have a lead, specified by accountId.
    myself_resp = requests.get(
        f"https://api.atlassian.com/ex/jira/{site['id']}/rest/api/3/myself",
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        timeout=10,
    )
    account_id = None
    if myself_resp.status_code == 200:
        account_id = myself_resp.json().get("accountId")
    else:
        # Don't fail the whole connection over this — ticket creation into
        # an EXISTING project still works without an account_id. But log
        # loudly so a failed project auto-create later is traceable back
        # to this, instead of silently defaulting to None.
        print(f"[jira_integration] /myself lookup failed ({myself_resp.status_code}): {myself_resp.text}")

    _TOKENS[_session_key()] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "cloud_id": site["id"],
        "site_name": site["name"],
        "account_id": account_id,
    }

    # Send the user back into the app's UI (Profile screen) rather than
    # showing a bare API response.
    return redirect(FRONTEND_RETURN_URL)


@jira_bp.route("/disconnect", methods=["POST"])
def disconnect():
    _TOKENS.pop(_session_key(), None)
    return jsonify({"status": "disconnected"})


def _ensure_project_exists(record, project_key):
    """Return (True, None) if `project_key` exists (or was just created)
    in the connected Jira site, or (False, error_message) otherwise.

    Auto-creation requires the granular scopes write:project:jira AND
    read:project:jira — POST /rest/api/3/project has no classic-scope
    equivalent, so checking manage:jira-project alone is not enough.
    See SCOPES above.
    """
    base = f"https://api.atlassian.com/ex/jira/{record['cloud_id']}/rest/api/3"
    headers = {
        "Authorization": f"Bearer {record['access_token']}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    search_resp = requests.get(
        f"{base}/project/search",
        params={"keys": project_key},
        headers=headers,
        timeout=10,
    )
    if search_resp.status_code == 200 and search_resp.json().get("values"):
        return True, None  # exists, good to go

    print(f"[jira_integration] project '{project_key}' not found ({search_resp.status_code}): {search_resp.text}")

    if not record.get("account_id"):
        return False, (
            f"Project '{project_key}' doesn't exist and it can't be auto-created "
            f"because no lead accountId was captured when this Jira account was "
            f"connected. Disconnect and reconnect Jira from the Profile page, then "
            f"try again."
        )

    create_resp = requests.post(
        f"{base}/project",
        json={
            "key": project_key,
            "name": project_key,
            "projectTypeKey": "software",
            "leadAccountId": record["account_id"],
            # Team-managed Kanban template — gives the new project a
            # default board automatically (boards always belong to a
            # project; there's no "board with no project" concept).
            "projectTemplateKey": "com.pyxis.greenhopper.jira:gh-simplified-kanban-classic",
        },
        headers=headers,
        timeout=10,
    )
    if create_resp.status_code in (200, 201):
        return True, None

    # project/search only returns projects the connected account has
    # Browse permission on, so it can miss a project that already
    # exists (e.g. created by someone else, or manually earlier). The
    # create call's key-uniqueness check is site-wide regardless of
    # permissions, so a "this key is already in use" response here
    # actually means the project is fine to use — just not creatable
    # (or visible) by this account. Treat that as success rather than
    # a hard failure.
    try:
        create_errors = create_resp.json().get("errors", {})
    except ValueError:
        create_errors = {}
    key_conflict = "projectKey" in create_errors and "uses this project key" in create_errors["projectKey"]
    if create_resp.status_code == 400 and key_conflict:
        print(
            f"[jira_integration] project '{project_key}' already exists on the site "
            f"(hidden from this account's project/search, likely a permissions gap) "
            f"— proceeding to create the ticket in it anyway."
        )
        return True, None

    print(f"[jira_integration] auto-create '{project_key}' failed ({create_resp.status_code}): {create_resp.text}")
    return False, (
        f"Couldn't auto-create project '{project_key}': {create_resp.text}. "
        f"If this is a 401 'scope does not match', make sure both "
        f"write:project:jira AND read:project:jira are granted in the Developer "
        f"Console and reconnect Jira (old tokens keep the old scopes). If it's a "
        f"403, the connected Jira account doesn't have permission to create "
        f"projects on this site."
    )


@jira_bp.route("/create-ticket", methods=["POST"])
def create_ticket():
    """Push one ticket to the connected Jira site.

    Expected JSON body:
        {
            "title": "...",
            "description": "...",
            "priority": "P1 - Critical" | "P2 - High" | "P3 - Medium",
            "projectKey": "VULN"   # optional; falls back to JIRA_DEFAULT_PROJECT_KEY
        }

    The target project is auto-created (Kanban template) on first use
    if it doesn't already exist — see _ensure_project_exists.
    """
    error = _not_configured()
    if error:
        return error

    record = _TOKENS.get(_session_key())
    if not record:
        return jsonify({"error": "No Jira account connected. Connect one first."}), 401

    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Missing 'title'"}), 400

    description = body.get("description") or ""
    project_key = body.get("projectKey") or os.environ.get("JIRA_DEFAULT_PROJECT_KEY")
    if not project_key:
        return jsonify({
            "error": "No project specified. Pass 'projectKey', or set "
                     "JIRA_DEFAULT_PROJECT_KEY on the server."
        }), 400

    project_ok, project_error = _ensure_project_exists(record, project_key)
    if not project_ok:
        return jsonify({"error": project_error}), 502

    # Jira Cloud requires the description in Atlassian Document Format
    # (ADF) — a plain string is rejected. This wraps it minimally.
    adf_description = {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": description or "(no description provided)"}]}
        ],
    }

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": title,
            "description": adf_description,
            "issuetype": {"name": "Task"},
        }
    }

    create_resp = requests.post(
        f"https://api.atlassian.com/ex/jira/{record['cloud_id']}/rest/api/3/issue",
        json=payload,
        headers={
            "Authorization": f"Bearer {record['access_token']}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        timeout=10,
    )

    if create_resp.status_code not in (200, 201):
        return jsonify({"error": "Jira rejected the ticket", "detail": create_resp.text}), 502

    created = create_resp.json()
    issue_key = created.get("key")
    return jsonify({
        "status": "created",
        "issueKey": issue_key,
        "url": f"https://{record['site_name']}.atlassian.net/browse/{issue_key}" if issue_key else None,
    })
