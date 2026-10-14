"""Tests for auth.py — signup/login/logout/session, password rules, the
bootstrap-admin rule, role-based access control, profile and notification
settings, the admin user directory, and the schema migrations in init_db().

Everything runs against a throwaway SQLite file (see conftest.app_env)."""
import sqlite3

import pytest

GOOD_PASSWORD = "Str0ng!pass"


def _signup(client, **overrides):
    body = {"name": "Ada Lovelace", "email": "ada@example.com", "password": GOOD_PASSWORD}
    body.update(overrides)
    return client.post("/api/auth/signup", json=body)


# ---------------------------------------------------------------------------
# Signup
# ---------------------------------------------------------------------------
def test_signup_creates_account_signs_in_and_returns_role(app_env):
    client = app_env.client()
    r = _signup(client)
    assert r.status_code == 200
    assert r.get_json() == {"status": "signed_up", "name": "Ada Lovelace", "email": "ada@example.com", "role": "admin"}
    me = client.get("/api/auth/me").get_json()
    assert me["authenticated"] is True and me["email"] == "ada@example.com"


def test_first_account_is_admin_and_later_accounts_are_analysts(app_env):
    first = _signup(app_env.client(), email="first@example.com").get_json()
    second = _signup(app_env.client(), email="second@example.com").get_json()
    third = _signup(app_env.client(), email="third@example.com").get_json()
    assert [first["role"], second["role"], third["role"]] == ["admin", "analyst", "analyst"]


def test_signup_never_stores_the_plaintext_password(app_env):
    _signup(app_env.client())
    stored = app_env.query("SELECT password_hash FROM users")[0]["password_hash"]
    assert stored != GOOD_PASSWORD and GOOD_PASSWORD not in stored


@pytest.mark.parametrize("field", ["name", "email", "password"])
def test_signup_requires_every_field(app_env, field):
    r = _signup(app_env.client(), **{field: ""})
    assert r.status_code == 400
    assert "required" in r.get_json()["error"]


def test_signup_with_no_json_body_is_a_400(app_env):
    assert app_env.client().post("/api/auth/signup", data="not json").status_code == 400


@pytest.mark.parametrize("email", ["plainaddress", "no@tld", "two@@example.com", "spaces in@example.com", "@example.com"])
def test_signup_rejects_malformed_emails(app_env, email):
    r = _signup(app_env.client(), email=email)
    assert r.status_code == 400
    assert "valid email" in r.get_json()["error"]


@pytest.mark.parametrize("password,expected", [
    ("Sh1!", "at least 8"),
    ("alllower1!", "uppercase"),
    ("ALLUPPER1!", "lowercase"),
    ("NoNumber!!", "number"),
    ("NoSymbol11", "symbol"),
])
def test_signup_enforces_each_password_rule_server_side(app_env, password, expected):
    r = _signup(app_env.client(), password=password)
    assert r.status_code == 400
    assert expected in r.get_json()["error"]
    assert app_env.query("SELECT COUNT(*) AS n FROM users")[0]["n"] == 0


def test_signup_duplicate_email_is_409_and_case_insensitive(app_env):
    assert _signup(app_env.client(), email="dup@example.com").status_code == 200
    r = _signup(app_env.client(), email="DUP@Example.com")
    assert r.status_code == 409
    assert "already exists" in r.get_json()["error"]


def test_signup_normalises_email_case_and_whitespace_and_trims_name(app_env):
    body = _signup(app_env.client(), name="  Ada  ", email="  Ada@Example.COM ").get_json()
    assert body["name"] == "Ada" and body["email"] == "ada@example.com"


def test_signup_replaces_any_previous_session(app_env):
    client = app_env.client()
    with client.session_transaction() as s:
        s["mfa_pending_user_id"] = 999
        s["stale"] = "value"
    _signup(client)
    with client.session_transaction() as s:
        assert "stale" not in s and "mfa_pending_user_id" not in s
        assert s["user_id"]


# ---------------------------------------------------------------------------
# Login / logout / me
# ---------------------------------------------------------------------------
def test_login_success_returns_full_user_and_signs_in(app_env):
    app_env.make_user(email="l@example.com", name="Lee", password=GOOD_PASSWORD, role="viewer")
    client = app_env.client()
    r = client.post("/api/auth/login", json={"email": "L@Example.com", "password": GOOD_PASSWORD})
    body = r.get_json()
    assert r.status_code == 200 and body["status"] == "signed_in"
    assert body["role"] == "viewer" and body["notifyOnCritical"] is False
    assert body["notifyLevel"] == "critical" and body["mfaEnabled"] is False
    assert client.get("/api/auth/me").get_json()["authenticated"] is True


def test_login_failure_message_is_identical_for_unknown_email_and_wrong_password(app_env):
    app_env.make_user(email="real@example.com", password=GOOD_PASSWORD)
    wrong_pw = app_env.client().post("/api/auth/login", json={"email": "real@example.com", "password": "Wrong!pass1"})
    unknown = app_env.client().post("/api/auth/login", json={"email": "ghost@example.com", "password": GOOD_PASSWORD})
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.get_json() == unknown.get_json()


def test_failed_login_does_not_create_a_session(app_env):
    client = app_env.client()
    client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "x"})
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}


@pytest.mark.parametrize("body", [{}, {"email": "a@b.co"}, {"password": "x"}, {"email": "", "password": ""}])
def test_login_requires_email_and_password(app_env, body):
    assert app_env.client().post("/api/auth/login", json=body).status_code == 400


def test_google_accounts_are_pointed_at_google_sign_in_instead(app_env):
    app_env.make_user(email="g@example.com", auth_provider="google", password=GOOD_PASSWORD)
    r = app_env.client().post("/api/auth/login", json={"email": "g@example.com", "password": GOOD_PASSWORD})
    assert r.status_code == 401
    assert "Google" in r.get_json()["error"]


def test_logout_clears_the_session(app_env):
    client, _ = app_env.login_as()
    assert client.post("/api/auth/logout").get_json() == {"status": "signed_out"}
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}


def test_me_reports_unauthenticated_without_a_session(app_env):
    assert app_env.client().get("/api/auth/me").get_json() == {"authenticated": False}


def test_me_for_a_deleted_account_clears_the_session(app_env):
    client, uid = app_env.login_as()
    app_env.execute("DELETE FROM users WHERE id = ?", (uid,))
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}
    with client.session_transaction() as s:
        assert "user_id" not in s


def test_me_never_exposes_password_hash_or_mfa_secrets(app_env):
    client, _ = app_env.login_as(password=GOOD_PASSWORD)
    text = client.get("/api/auth/me").get_data(as_text=True)
    for leaked in ("password_hash", "mfa_code_hash", "google_sub"):
        assert leaked not in text


# ---------------------------------------------------------------------------
# require_role
# ---------------------------------------------------------------------------
def test_require_role_401_when_signed_out_403_when_role_too_low_200_when_allowed(app_env):
    # /api/auth/users is @require_role("admin")
    assert app_env.client().get("/api/auth/users").status_code == 401
    for role in ("viewer", "analyst"):
        client, _ = app_env.login_as(role=role)
        assert client.get("/api/auth/users").status_code == 403
    admin, _ = app_env.login_as(role="admin")
    assert admin.get("/api/auth/users").status_code == 200


def test_require_role_treats_a_deleted_user_as_signed_out(app_env):
    client, uid = app_env.login_as(role="admin")
    app_env.execute("DELETE FROM users WHERE id = ?", (uid,))
    assert client.get("/api/auth/users").status_code == 401
    with client.session_transaction() as s:
        assert "user_id" not in s


def test_a_role_change_takes_effect_on_the_next_request(app_env):
    client, uid = app_env.login_as(role="admin")
    app_env.make_user(role="admin")  # keep a second admin around
    assert client.get("/api/auth/users").status_code == 200
    app_env.execute("UPDATE users SET role = 'viewer' WHERE id = ?", (uid,))
    assert client.get("/api/auth/users").status_code == 403


# ---------------------------------------------------------------------------
# PATCH /api/auth/profile
# ---------------------------------------------------------------------------
def test_profile_requires_sign_in(app_env):
    assert app_env.client().patch("/api/auth/profile", json={"name": "x"}).status_code == 401


def test_profile_with_empty_body_is_nothing_to_update(app_env):
    client, _ = app_env.login_as()
    r = client.patch("/api/auth/profile", json={})
    assert r.status_code == 400 and "Nothing to update" in r.get_json()["error"]


def test_profile_name_is_trimmed_and_saved(app_env):
    client, _ = app_env.login_as()
    r = client.patch("/api/auth/profile", json={"name": "  New Name  "})
    assert r.status_code == 200 and r.get_json()["name"] == "New Name"


def test_profile_rejects_blank_and_overlong_names(app_env):
    client, _ = app_env.login_as()
    assert client.patch("/api/auth/profile", json={"name": "   "}).status_code == 400
    assert client.patch("/api/auth/profile", json={"name": "x" * 101}).status_code == 400
    assert client.patch("/api/auth/profile", json={"name": "x" * 100}).status_code == 200


def test_profile_email_change_is_normalised_validated_and_unique(app_env):
    client, _ = app_env.login_as(email="me@example.com")
    app_env.make_user(email="taken@example.com")
    assert client.patch("/api/auth/profile", json={"email": "nope"}).status_code == 400
    assert client.patch("/api/auth/profile", json={"email": "TAKEN@example.com"}).status_code == 409
    ok = client.patch("/api/auth/profile", json={"email": "  New@Example.COM "})
    assert ok.status_code == 200 and ok.get_json()["email"] == "new@example.com"


def test_profile_resubmitting_the_same_email_is_a_harmless_no_op(app_env):
    client, _ = app_env.login_as(email="same@example.com")
    r = client.patch("/api/auth/profile", json={"email": "SAME@example.com"})
    assert r.status_code == 200 and r.get_json()["email"] == "same@example.com"


def test_google_account_cannot_change_its_email(app_env):
    uid = app_env.make_user(email="g@example.com", auth_provider="google")
    r = app_env.client(uid).patch("/api/auth/profile", json={"email": "other@example.com"})
    assert r.status_code == 400 and "Google" in r.get_json()["error"]


def test_only_an_admin_can_change_the_shared_organisation(app_env):
    admin, _ = app_env.login_as(role="admin")
    analyst, _ = app_env.login_as(role="analyst")
    assert admin.patch("/api/auth/profile", json={"organisation": "  Acme Ltd "}).get_json()["organisation"] == "Acme Ltd"
    # Everyone inherits it...
    assert analyst.get("/api/auth/me").get_json()["organisation"] == "Acme Ltd"
    # ...but can't change it
    r = analyst.patch("/api/auth/profile", json={"organisation": "Evil Corp"})
    assert r.status_code == 403
    assert admin.get("/api/auth/me").get_json()["organisation"] == "Acme Ltd"


def test_non_admin_echoing_back_the_inherited_organisation_is_not_rejected(app_env):
    admin, _ = app_env.login_as(role="admin")
    analyst, _ = app_env.login_as(role="analyst")
    admin.patch("/api/auth/profile", json={"organisation": "Acme"})
    r = analyst.patch("/api/auth/profile", json={"name": "Renamed", "organisation": "Acme"})
    assert r.status_code == 200 and r.get_json()["name"] == "Renamed"


def test_organisation_length_limit_and_clearing(app_env):
    admin, _ = app_env.login_as(role="admin")
    assert admin.patch("/api/auth/profile", json={"organisation": "x" * 121}).status_code == 400
    admin.patch("/api/auth/profile", json={"organisation": "Acme"})
    assert admin.patch("/api/auth/profile", json={"organisation": ""}).get_json()["organisation"] == ""


def test_non_admin_cannot_promote_themselves(app_env):
    client, uid = app_env.login_as(role="analyst")
    r = client.patch("/api/auth/profile", json={"role": "admin"})
    assert r.status_code == 403
    assert app_env.query("SELECT role FROM users WHERE id = ?", (uid,))[0]["role"] == "analyst"


def test_profile_role_must_be_a_known_role(app_env):
    admin, _ = app_env.login_as(role="admin")
    r = admin.patch("/api/auth/profile", json={"role": "superuser"})
    assert r.status_code == 400 and "role must be one of" in r.get_json()["error"]


def test_the_last_admin_cannot_demote_themselves_via_profile(app_env):
    admin, uid = app_env.login_as(role="admin")
    r = admin.patch("/api/auth/profile", json={"role": "viewer"})
    assert r.status_code == 400 and "last Admin" in r.get_json()["error"]
    assert app_env.query("SELECT role FROM users WHERE id = ?", (uid,))[0]["role"] == "admin"


def test_an_admin_can_demote_themselves_when_another_admin_exists(app_env):
    admin, _ = app_env.login_as(role="admin")
    app_env.make_user(role="admin")
    assert admin.patch("/api/auth/profile", json={"role": "analyst"}).get_json()["role"] == "analyst"


# ---------------------------------------------------------------------------
# PATCH /api/auth/notifications and /api/auth/mfa
# ---------------------------------------------------------------------------
def test_notification_defaults_are_off_critical_and_no_jira_email(app_env):
    client, _ = app_env.login_as()
    me = client.get("/api/auth/me").get_json()
    assert (me["notifyOnCritical"], me["notifyLevel"], me["notifyOnJira"]) == (False, "critical", False)


def test_notifications_require_sign_in(app_env):
    assert app_env.client().patch("/api/auth/notifications", json={"enabled": True}).status_code == 401


def test_notifications_support_partial_updates_and_return_full_state(app_env):
    client, _ = app_env.login_as()
    assert client.patch("/api/auth/notifications", json={"enabled": True}).get_json() == {
        "notifyOnCritical": True, "notifyLevel": "critical", "notifyOnJira": False}
    assert client.patch("/api/auth/notifications", json={"level": "medium"}).get_json() == {
        "notifyOnCritical": True, "notifyLevel": "medium", "notifyOnJira": False}
    assert client.patch("/api/auth/notifications", json={"jira": True, "enabled": False}).get_json() == {
        "notifyOnCritical": False, "notifyLevel": "medium", "notifyOnJira": True}


@pytest.mark.parametrize("level", ["none", "critical", "high", "medium"])
def test_every_documented_notify_level_is_accepted(app_env, level):
    client, _ = app_env.login_as()
    assert client.patch("/api/auth/notifications", json={"level": level}).get_json()["notifyLevel"] == level


@pytest.mark.parametrize("body", [
    {"enabled": "true"}, {"enabled": 1}, {"jira": "yes"}, {"level": "low"}, {"level": None}, {},
])
def test_notifications_reject_bad_values(app_env, body):
    client, _ = app_env.login_as()
    assert client.patch("/api/auth/notifications", json=body).status_code == 400


def test_mfa_toggle_requires_a_real_boolean_and_persists(app_env):
    client, _ = app_env.login_as()
    assert app_env.client().patch("/api/auth/mfa", json={"enabled": True}).status_code == 401
    for bad in ({}, {"enabled": "true"}, {"enabled": 1}, {"enabled": None}):
        assert client.patch("/api/auth/mfa", json=bad).status_code == 400
    assert client.patch("/api/auth/mfa", json={"enabled": True}).get_json() == {"mfaEnabled": True}
    assert client.get("/api/auth/me").get_json()["mfaEnabled"] is True
    assert client.patch("/api/auth/mfa", json={"enabled": False}).get_json() == {"mfaEnabled": False}


# ---------------------------------------------------------------------------
# Admin user directory
# ---------------------------------------------------------------------------
def test_user_directory_lists_everyone_without_secrets(app_env):
    admin, _ = app_env.login_as(role="admin", email="admin@example.com")
    app_env.make_user(email="v@example.com", role="viewer")
    users = admin.get("/api/auth/users").get_json()
    assert [u["email"] for u in users] == ["admin@example.com", "v@example.com"]
    assert set(users[0]) == {"id", "name", "email", "role", "authProvider", "createdAt"}


def test_admin_can_change_another_users_role(app_env):
    admin, _ = app_env.login_as(role="admin")
    target = app_env.make_user(role="analyst")
    r = admin.patch(f"/api/auth/users/{target}/role", json={"role": "viewer"})
    assert r.status_code == 200 and r.get_json()["role"] == "viewer"
    assert app_env.query("SELECT role FROM users WHERE id = ?", (target,))[0]["role"] == "viewer"


def test_role_change_validation_and_missing_user(app_env):
    admin, _ = app_env.login_as(role="admin")
    target = app_env.make_user()
    assert admin.patch(f"/api/auth/users/{target}/role", json={"role": "root"}).status_code == 400
    assert admin.patch(f"/api/auth/users/{target}/role", json={}).status_code == 400
    assert admin.patch("/api/auth/users/9999/role", json={"role": "viewer"}).status_code == 404


def test_role_change_is_admin_only(app_env):
    analyst, _ = app_env.login_as(role="analyst")
    target = app_env.make_user()
    assert analyst.patch(f"/api/auth/users/{target}/role", json={"role": "admin"}).status_code == 403
    assert app_env.client().patch(f"/api/auth/users/{target}/role", json={"role": "admin"}).status_code == 401


def test_the_last_admin_cannot_be_demoted_by_the_directory_either(app_env):
    admin, uid = app_env.login_as(role="admin")
    r = admin.patch(f"/api/auth/users/{uid}/role", json={"role": "analyst"})
    assert r.status_code == 400 and "last Admin" in r.get_json()["error"]


def test_with_two_admins_one_can_be_demoted_and_the_other_is_then_protected(app_env):
    admin, uid = app_env.login_as(role="admin")
    other = app_env.make_user(role="admin")
    assert admin.patch(f"/api/auth/users/{other}/role", json={"role": "analyst"}).status_code == 200
    assert admin.patch(f"/api/auth/users/{uid}/role", json={"role": "analyst"}).status_code == 400


def test_promoting_to_admin_is_always_allowed(app_env):
    admin, _ = app_env.login_as(role="admin")
    target = app_env.make_user(role="viewer")
    assert admin.patch(f"/api/auth/users/{target}/role", json={"role": "admin"}).get_json()["role"] == "admin"


# ---------------------------------------------------------------------------
# Helpers used by google_auth.py
# ---------------------------------------------------------------------------
def test_get_user_helpers(app_env):
    uid = app_env.make_user(email="find@example.com")
    auth = app_env.auth
    assert auth.get_user_by_id(uid)["email"] == "find@example.com"
    assert auth.get_user_by_id(None) is None and auth.get_user_by_id(0) is None
    assert auth.get_user_by_id(12345) is None
    assert auth.get_user_by_email("  FIND@example.com ")["id"] == uid
    assert auth.get_user_by_email("") is None and auth.get_user_by_email(None) is None


def test_create_google_user_has_unusable_password_and_bootstrap_role(app_env):
    auth = app_env.auth
    first = auth.create_google_user("G One", "g1@example.com", "sub-1")
    second = auth.create_google_user("G Two", "g2@example.com", "sub-2")
    rows = {r["id"]: r for r in app_env.query("SELECT * FROM users")}
    assert rows[first]["role"] == "admin" and rows[second]["role"] == "analyst"
    assert rows[first]["auth_provider"] == "google" and rows[first]["google_sub"] == "sub-1"
    from werkzeug.security import check_password_hash
    assert not check_password_hash(rows[first]["password_hash"], "")


def test_google_sub_is_unique_across_accounts(app_env):
    auth = app_env.auth
    auth.create_google_user("A", "a@example.com", "same-sub")
    with pytest.raises(sqlite3.IntegrityError):
        auth.create_google_user("B", "b@example.com", "same-sub")


def test_link_google_sub_attaches_identity_to_existing_account(app_env):
    uid = app_env.make_user(email="local@example.com")
    app_env.auth.link_google_sub(uid, "sub-xyz")
    assert app_env.query("SELECT google_sub FROM users WHERE id = ?", (uid,))[0]["google_sub"] == "sub-xyz"


# ---------------------------------------------------------------------------
# init_db(): creating and migrating the schema
# ---------------------------------------------------------------------------
def test_init_db_creates_the_current_schema(app_env):
    cols = {r["name"] for r in app_env.query("PRAGMA table_info(users)")}
    assert {"role", "auth_provider", "google_sub", "notify_on_critical", "notify_level", "notify_on_jira",
            "organisation", "mfa_enabled", "mfa_code_hash", "mfa_code_expires_at", "mfa_code_attempts"} <= cols
    assert app_env.query("SELECT value FROM app_settings WHERE key = 'organisation'")[0]["value"] == ""


def test_init_db_is_idempotent(app_env):
    app_env.make_user(role="admin")
    app_env.auth.init_db()
    app_env.auth.init_db()
    assert app_env.query("SELECT COUNT(*) AS n FROM users")[0]["n"] == 1


def test_migrating_a_pre_rbac_database_promotes_the_oldest_account_and_keeps_its_organisation(tmp_path, import_fresh):
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, "
        "email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL, "
        "organisation TEXT NOT NULL DEFAULT '')"
    )
    conn.execute("INSERT INTO users (name,email,password_hash,created_at,organisation) VALUES "
                 "('Newer','new@example.com','x','2025-06-01','Other Org')")
    conn.execute("INSERT INTO users (name,email,password_hash,created_at,organisation) VALUES "
                 "('Oldest','old@example.com','x','2024-01-01','Acme Ltd')")
    conn.commit()
    conn.close()

    auth = import_fresh("auth", db)

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    roles = {r["email"]: r["role"] for r in conn.execute("SELECT email, role FROM users")}
    org = conn.execute("SELECT value FROM app_settings WHERE key='organisation'").fetchone()["value"]
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
    conn.close()

    assert roles == {"old@example.com": "admin", "new@example.com": "analyst"}
    assert org == "Acme Ltd"
    assert {"auth_provider", "notify_level", "mfa_enabled"} <= cols
    assert auth.get_organisation() == "Acme Ltd"
