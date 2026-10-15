"""Tests for google_auth.py — the Google OAuth sign-in/sign-up flow. Google's
token and userinfo endpoints are replaced by a scripted fake, so nothing
touches the network."""
from urllib.parse import parse_qs, quote, urlparse

import pytest

FRONTEND = "http://localhost:5173/"


@pytest.fixture()
def google(app_env, monkeypatch, fake_response):
    """Google configured; `script` controls what the fake endpoints answer."""
    g = app_env.google_auth
    monkeypatch.setattr(g, "CLIENT_ID", "client-id")
    monkeypatch.setattr(g, "CLIENT_SECRET", "client-secret")
    monkeypatch.setattr(g, "FRONTEND_RETURN_URL", FRONTEND)
    script = {
        "token": fake_response(200, {"access_token": "tok"}),
        "userinfo": fake_response(200, {"sub": "sub-1", "email": "Gina@Example.com",
                                        "email_verified": True, "name": "Gina G"}),
        "calls": [],
    }

    def post(url, **kw):
        script["calls"].append(("POST", url, kw))
        return script["token"]

    def get(url, **kw):
        script["calls"].append(("GET", url, kw))
        return script["userinfo"]

    monkeypatch.setattr(g.requests, "post", post)
    monkeypatch.setattr(g.requests, "get", get)
    return script


def _begin(client):
    """Run /login so the session holds a state, and return that state."""
    client.get("/api/auth/google/login")
    with client.session_transaction() as s:
        return s["google_oauth_state"]


def _callback(client, state=None, **params):
    state = _begin(client) if state is None else state
    query = {"state": state, "code": "auth-code", **params}
    query = {k: v for k, v in query.items() if v is not None}
    return client.get("/api/auth/google/callback", query_string=query)


def _location(resp):
    return resp.headers["Location"]


# ---------------------------------------------------------------------------
# Configuration / status / login redirect
# ---------------------------------------------------------------------------
def test_status_reflects_configuration(app_env, monkeypatch):
    g = app_env.google_auth
    monkeypatch.setattr(g, "CLIENT_ID", None)
    monkeypatch.setattr(g, "CLIENT_SECRET", None)
    assert app_env.client().get("/api/auth/google/status").get_json() == {"configured": False}
    monkeypatch.setattr(g, "CLIENT_ID", "id")
    assert app_env.client().get("/api/auth/google/status").get_json() == {"configured": False}  # secret still missing
    monkeypatch.setattr(g, "CLIENT_SECRET", "secret")
    assert app_env.client().get("/api/auth/google/status").get_json() == {"configured": True}


def test_login_and_callback_are_503_when_not_configured(app_env, monkeypatch):
    g = app_env.google_auth
    monkeypatch.setattr(g, "CLIENT_ID", None)
    client = app_env.client()
    for path in ("/api/auth/google/login", "/api/auth/google/callback"):
        r = client.get(path)
        assert r.status_code == 503 and "not configured" in r.get_json()["error"]


def test_login_redirects_to_google_with_state_and_required_params(app_env, google):
    client = app_env.client()
    r = client.get("/api/auth/google/login")
    assert r.status_code == 302
    url = urlparse(_location(r))
    assert f"{url.scheme}://{url.netloc}{url.path}" == "https://accounts.google.com/o/oauth2/v2/auth"
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert q["client_id"] == "client-id" and q["response_type"] == "code"
    assert q["scope"] == "openid email profile" and q["prompt"] == "select_account"
    with client.session_transaction() as s:
        assert q["state"] == s["google_oauth_state"] and len(q["state"]) >= 24


def test_each_login_attempt_gets_a_fresh_state(app_env, google):
    assert _begin(app_env.client()) != _begin(app_env.client())


# ---------------------------------------------------------------------------
# Callback: failure paths (all redirect back to the frontend with authError)
# ---------------------------------------------------------------------------
def test_user_cancelling_at_google_redirects_with_an_error(app_env, google):
    client = app_env.client()
    r = client.get("/api/auth/google/callback", query_string={"error": "access_denied"})
    assert r.status_code == 302 and f"{FRONTEND}?authError=" in _location(r) and "cancelled" in _location(r)


def test_state_mismatch_is_rejected_and_no_google_calls_are_made(app_env, google):
    client = app_env.client()
    _begin(client)
    r = _callback(client, state="forged-state")
    assert "state%20mismatch" in _location(r)
    assert google["calls"] == []


def test_callback_without_ever_starting_login_is_rejected(app_env, google):
    r = app_env.client().get("/api/auth/google/callback", query_string={"state": "x", "code": "y"})
    assert "authError" in _location(r) and google["calls"] == []


def test_state_can_only_be_used_once(app_env, google):
    client = app_env.client()
    state = _begin(client)
    assert "newAccount=1" in _location(_callback(client, state=state))
    second = _callback(client, state=state)
    assert "authError" in _location(second)


def test_missing_authorization_code_is_rejected(app_env, google):
    r = _callback(app_env.client(), code=None)
    assert "authError" in _location(r) and google["calls"] == []


def test_token_exchange_failure_is_reported_and_creates_no_account(app_env, google, fake_response):
    google["token"] = fake_response(400, {"error": "invalid_grant"}, text="invalid_grant")
    r = _callback(app_env.client())
    assert "token%20exchange" in _location(r)
    assert app_env.query("SELECT COUNT(*) AS n FROM users")[0]["n"] == 0


def test_userinfo_failure_is_reported(app_env, google, fake_response):
    google["userinfo"] = fake_response(401, {}, text="unauthorized")
    assert "fetching%20your%20profile" in _location(_callback(app_env.client()))


@pytest.mark.parametrize("profile", [
    {"sub": "s", "email": ""},
    {"sub": "s"},
    {"email": "x@example.com", "email_verified": True},
])
def test_profile_missing_email_or_subject_is_rejected(app_env, google, fake_response, profile):
    google["userinfo"] = fake_response(200, {"email_verified": True, **profile})
    assert "authError" in _location(_callback(app_env.client()))
    assert app_env.query("SELECT COUNT(*) AS n FROM users")[0]["n"] == 0


def test_unverified_google_email_is_refused(app_env, google, fake_response):
    google["userinfo"] = fake_response(200, {"sub": "s", "email": "x@example.com", "email_verified": False})
    r = _callback(app_env.client())
    assert "verify%20your%20email" in _location(r)
    assert app_env.query("SELECT COUNT(*) AS n FROM users")[0]["n"] == 0


def test_error_redirect_uses_ampersand_when_return_url_already_has_a_query(app_env, google, monkeypatch):
    monkeypatch.setattr(app_env.google_auth, "FRONTEND_RETURN_URL", FRONTEND + "?x=1")
    r = app_env.client().get("/api/auth/google/callback", query_string={"error": "denied"})
    assert _location(r).startswith(FRONTEND + "?x=1&authError=")


# ---------------------------------------------------------------------------
# Callback: success paths
# ---------------------------------------------------------------------------
def test_token_exchange_sends_the_expected_form(app_env, google):
    _callback(app_env.client())
    method, url, kw = google["calls"][0]
    assert url == "https://oauth2.googleapis.com/token"
    assert kw["data"]["grant_type"] == "authorization_code" and kw["data"]["code"] == "auth-code"
    assert kw["data"]["client_secret"] == "client-secret"
    _, info_url, info_kw = google["calls"][1]
    assert info_url == "https://www.googleapis.com/oauth2/v3/userinfo"
    assert info_kw["headers"]["Authorization"] == "Bearer tok"


def test_first_time_google_signin_creates_an_admin_account_and_flags_it_new(app_env, google):
    client = app_env.client()
    r = _callback(client)
    assert _location(r) == f"{FRONTEND}?newAccount=1"
    row = app_env.query("SELECT * FROM users")[0]
    assert row["email"] == "gina@example.com" and row["name"] == "Gina G"
    assert row["auth_provider"] == "google" and row["google_sub"] == "sub-1" and row["role"] == "admin"
    assert client.get("/api/auth/me").get_json()["authenticated"] is True


def test_google_signup_after_the_first_account_is_an_analyst(app_env, google):
    app_env.make_user(email="existing@example.com", role="admin")
    _callback(app_env.client())
    assert app_env.query("SELECT role FROM users WHERE email = 'gina@example.com'")[0]["role"] == "analyst"


def test_name_falls_back_to_email_local_part(app_env, google, fake_response):
    google["userinfo"] = fake_response(200, {"sub": "s9", "email": "nobody@example.com", "email_verified": True})
    _callback(app_env.client())
    assert app_env.query("SELECT name FROM users")[0]["name"] == "nobody"


def test_existing_local_account_is_signed_into_and_linked(app_env, google):
    uid = app_env.make_user(email="gina@example.com", role="viewer")
    client = app_env.client()
    r = _callback(client)
    assert _location(r) == FRONTEND  # not a new account -> no newAccount flag
    row = app_env.query("SELECT * FROM users WHERE id = ?", (uid,))[0]
    assert row["google_sub"] == "sub-1" and row["role"] == "viewer"
    assert app_env.query("SELECT COUNT(*) AS n FROM users")[0]["n"] == 1
    with client.session_transaction() as s:
        assert s["user_id"] == uid


def test_returning_google_user_signs_in_without_creating_a_duplicate(app_env, google):
    _callback(app_env.client())
    r = _callback(app_env.client())
    assert _location(r) == FRONTEND
    assert app_env.query("SELECT COUNT(*) AS n FROM users")[0]["n"] == 1


def test_callback_replaces_any_prior_session_data(app_env, google):
    client = app_env.client()
    state = _begin(client)
    with client.session_transaction() as s:
        s["leftover"] = "stale"
    _callback(client, state=state)
    with client.session_transaction() as s:
        assert "leftover" not in s


# ---------------------------------------------------------------------------
# Callback + MFA
# ---------------------------------------------------------------------------
def test_google_signin_for_an_mfa_account_holds_back_the_session(app_env, google, monkeypatch):
    uid = app_env.make_user(email="gina@example.com", mfa_enabled=1)
    sent = []
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: True)
    monkeypatch.setattr(app_env.email_notifications, "send_plain_email", lambda *a: sent.append(a))
    client = app_env.client()
    r = _callback(client)
    assert _location(r) == f"{FRONTEND}?mfaRequired=1&email={quote('gina@example.com')}"
    assert len(sent) == 1
    with client.session_transaction() as s:
        assert "user_id" not in s and s["mfa_pending_user_id"] == uid
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}


def test_google_signin_for_an_mfa_account_fails_closed_when_email_cannot_be_sent(app_env, google, monkeypatch):
    """No code delivered -> no sign-in (same as password login): the user is sent back
    to the app with an error message and no session of any kind."""
    app_env.make_user(email="gina@example.com", mfa_enabled=1)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: False)
    client = app_env.client()
    r = _callback(client)
    location = _location(r)
    assert location.startswith(f"{FRONTEND}?authError=") and "sign-in%20code" in location
    assert "mfaRequired" not in location
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}
    with client.session_transaction() as s:
        assert "user_id" not in s and "mfa_pending_user_id" not in s


def test_google_signin_fails_closed_when_the_smtp_send_itself_fails(app_env, google, monkeypatch):
    app_env.make_user(email="gina@example.com", mfa_enabled=1)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: True)

    def boom(*a, **k):
        raise OSError("SMTP down")

    monkeypatch.setattr(app_env.email_notifications, "send_plain_email", boom)
    client = app_env.client()
    assert "authError" in _location(_callback(client))
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}


def test_google_signin_without_mfa_is_unaffected_by_email_being_down(app_env, google, monkeypatch):
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: False)
    client = app_env.client()
    assert _location(_callback(client)) == f"{FRONTEND}?newAccount=1"
    assert client.get("/api/auth/me").get_json()["authenticated"] is True
