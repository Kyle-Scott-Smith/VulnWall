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

Storage: a single in-memory dict keyed by Flask session id, same demo-only
caveat as jira_integration.py's _TOKENS — not persisted, not encrypted,
gone on process restart, and not safe as-is for more than one concurrent
user. Good enough for a local dev/demo tool; swap for a real (encrypted)
store before this is ever exposed beyond localhost.

Endpoints registered by this blueprint (mounted at /api/registry):
  GET  /api/registry/status      -> is a private registry currently connected?
  POST /api/registry/connect     -> body {url, username, password}; stores it
  POST /api/registry/disconnect  -> forget the stored connection

get_credentials() is what scanner.py calls when a live Trivy scan requests
usePrivateRegistry=True, to fetch the (url, username, password) tuple for
the current browser session without the scan-triggering code needing to
know anything about how/where it's stored.
"""

import secrets

from flask import Blueprint, jsonify, request, session

registry_bp = Blueprint("registry", __name__, url_prefix="/api/registry")

# --- Credential storage (DEMO ONLY — see module docstring) ---------------
_CREDENTIALS = {}


def _session_key():
    session.setdefault("_registry_sid", secrets.token_urlsafe(16))
    return session["_registry_sid"]


def get_credentials():
    """Returns (url, username, password) for the current session's
    connected registry, or (None, None, None) if nothing is connected.
    Called by scanner.py when a scan requests usePrivateRegistry=True —
    keeps the "where are credentials stored" question out of scanner.py
    and out of scanners/trivy.py entirely."""
    record = _CREDENTIALS.get(_session_key())
    if not record:
        return None, None, None
    return record["url"], record["username"], record["password"]


@registry_bp.route("/status", methods=["GET"])
def status():
    """Lets the frontend show 'Connect registry' vs 'Connected to <url>'
    — never returns the password."""
    record = _CREDENTIALS.get(_session_key())
    if not record:
        return jsonify({"connected": False})
    return jsonify({"connected": True, "url": record["url"], "username": record["username"]})


@registry_bp.route("/connect", methods=["POST"])
def connect():
    """Store this browser session's private registry credentials.
    Body: {"url": "ghcr.io", "username": "...", "password": "..."}"""
    body = request.get_json(silent=True) or {}
    url = (body.get("url") or "").strip()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not url or not username or not password:
        return jsonify({"error": "url, username, and password are all required"}), 400

    _CREDENTIALS[_session_key()] = {"url": url, "username": username, "password": password}
    return jsonify({"status": "connected", "url": url, "username": username})


@registry_bp.route("/disconnect", methods=["POST"])
def disconnect():
    _CREDENTIALS.pop(_session_key(), None)
    return jsonify({"status": "disconnected"})
