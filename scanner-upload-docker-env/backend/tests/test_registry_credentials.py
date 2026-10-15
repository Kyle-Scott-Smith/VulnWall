"""Tests for registry_credentials.py — storing a private container registry
login per account, and handing it to scanner.py."""


def _connect(client, **overrides):
    body = {"url": "ghcr.io", "username": "bot", "password": "s3cret"}
    body.update(overrides)
    return client.post("/api/registry/connect", json=body)


def test_status_is_disconnected_when_signed_out_or_nothing_stored(app_env):
    assert app_env.client().get("/api/registry/status").get_json() == {"connected": False}
    client, _ = app_env.login_as()
    assert client.get("/api/registry/status").get_json() == {"connected": False}


def test_connect_stores_credentials_and_status_never_returns_the_password(app_env):
    client, _ = app_env.login_as()
    r = _connect(client, url="  ghcr.io ", username=" bot ")
    assert r.get_json() == {"status": "connected", "url": "ghcr.io", "username": "bot"}
    status = client.get("/api/registry/status")
    assert status.get_json() == {"connected": True, "url": "ghcr.io", "username": "bot"}
    assert "s3cret" not in status.get_data(as_text=True) and "s3cret" not in r.get_data(as_text=True)


def test_connect_requires_url_username_and_password(app_env):
    client, _ = app_env.login_as()
    for field in ("url", "username", "password"):
        r = _connect(client, **{field: "   " if field != "password" else ""})
        assert r.status_code == 400 and "required" in r.get_json()["error"]
    assert client.get("/api/registry/status").get_json() == {"connected": False}


def test_connecting_again_replaces_the_stored_registry(app_env):
    client, _ = app_env.login_as()
    _connect(client)
    _connect(client, url="registry.example.com", username="other", password="pw2")
    assert app_env.query("SELECT COUNT(*) AS n FROM registry_connections")[0]["n"] == 1
    assert client.get("/api/registry/status").get_json()["url"] == "registry.example.com"


def test_disconnect_forgets_the_connection_and_is_safe_to_repeat(app_env):
    client, _ = app_env.login_as()
    _connect(client)
    assert client.post("/api/registry/disconnect").get_json() == {"status": "disconnected"}
    assert client.get("/api/registry/status").get_json() == {"connected": False}
    assert client.post("/api/registry/disconnect").status_code == 200


def test_connect_and_disconnect_are_blocked_for_viewers_and_signed_out_users(app_env):
    viewer, _ = app_env.login_as(role="viewer")
    assert _connect(viewer).status_code == 403
    assert viewer.post("/api/registry/disconnect").status_code == 403
    anon = app_env.client()
    assert _connect(anon).status_code == 401
    assert anon.post("/api/registry/disconnect").status_code == 401


def test_a_viewers_stored_registry_survives_a_disconnect_attempt(app_env):
    analyst, uid = app_env.login_as()
    _connect(analyst)
    viewer = app_env.client(app_env.make_user(role="viewer"))
    viewer.post("/api/registry/disconnect")
    assert app_env.query("SELECT COUNT(*) AS n FROM registry_connections WHERE user_id = ?", (uid,))[0]["n"] == 1


def test_connections_are_private_to_each_account(app_env):
    a, _ = app_env.login_as()
    b, _ = app_env.login_as()
    _connect(a)
    assert b.get("/api/registry/status").get_json() == {"connected": False}
    b.post("/api/registry/disconnect")
    assert a.get("/api/registry/status").get_json()["connected"] is True


def test_get_credentials_returns_the_signed_in_accounts_login(app_env):
    client, uid = app_env.login_as()
    _connect(client)
    with app_env.app.test_request_context():
        from flask import session
        session["user_id"] = uid
        assert app_env.registry_credentials.get_credentials() == ("ghcr.io", "bot", "s3cret")


def test_get_credentials_is_all_none_when_signed_out_or_not_connected(app_env):
    _, uid = app_env.login_as()
    with app_env.app.test_request_context():
        assert app_env.registry_credentials.get_credentials() == (None, None, None)
    with app_env.app.test_request_context():
        from flask import session
        session["user_id"] = uid
        assert app_env.registry_credentials.get_credentials() == (None, None, None)
