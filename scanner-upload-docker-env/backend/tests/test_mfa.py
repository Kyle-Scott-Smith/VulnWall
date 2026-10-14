"""Tests for email-OTP MFA (mfa.py + auth.py's login hand-off).

Uses a throwaway SQLite file and a stubbed email layer -- no SMTP, no
network. Key guarantees under test:
  - MFA fails CLOSED: if the sign-in code can't be sent, the user is NOT
    signed in (previously a mail failure silently skipped the second factor).
  - The code must be verified before a session is created.
  - Resending a code is capped, so resend + guess can't repeat forever.
"""
import importlib
import os
import sys
import tempfile

import pytest
from flask import Flask

PASSWORD = "Correct-horse-9"


@pytest.fixture()
def env(monkeypatch):
    tmp = tempfile.mkdtemp()
    monkeypatch.setenv("AUTH_DB_PATH", os.path.join(tmp, "test.db"))
    for m in ("auth", "mfa", "email_notifications"):
        sys.modules.pop(m, None)
    auth = importlib.import_module("auth")
    auth.init_db()
    mfa = importlib.import_module("mfa")
    email_notifications = importlib.import_module("email_notifications")

    sent = []
    state = {"smtp_ok": True}
    monkeypatch.setattr(email_notifications, "is_configured", lambda: state["smtp_ok"])

    def fake_send(to, subject, body):
        if not state["smtp_ok"]:
            raise OSError("SMTP down")
        sent.append(body)

    monkeypatch.setattr(email_notifications, "send_plain_email", fake_send)

    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(mfa.mfa_bp)
    client = app.test_client()

    # Create an account, then switch MFA on for it.
    r = client.post("/api/auth/signup", json={"name": "Kyle", "email": "k@example.com", "password": PASSWORD})
    assert r.status_code == 200, r.get_json()
    assert client.patch("/api/auth/mfa", json={"enabled": True}).status_code == 200
    client.post("/api/auth/logout")
    return client, sent, state


def _login(client):
    return client.post("/api/auth/login", json={"email": "k@example.com", "password": PASSWORD})


def _code_from(body):
    return "".join(ch for ch in body.split("code is:")[1].split("\n")[0] if ch.isdigit())


def test_login_requires_code_before_signed_in(env):
    client, sent, _ = env
    r = _login(client)
    assert r.get_json()["status"] == "mfa_required"
    assert client.get("/api/auth/me").get_json().get("authenticated") is not True


def test_correct_code_signs_in(env):
    client, sent, _ = env
    _login(client)
    r = client.post("/api/auth/mfa/verify", json={"code": _code_from(sent[-1])})
    assert r.status_code == 200 and r.get_json()["status"] == "signed_in"
    assert client.get("/api/auth/me").get_json().get("authenticated") is True


def test_wrong_code_rejected(env):
    client, sent, _ = env
    _login(client)
    wrong = "000000" if _code_from(sent[-1]) != "000000" else "111111"
    assert client.post("/api/auth/mfa/verify", json={"code": wrong}).status_code == 401


def test_fails_closed_when_code_cannot_be_sent(env):
    client, sent, state = env
    state["smtp_ok"] = False
    r = _login(client)
    assert r.status_code == 503
    assert r.get_json().get("status") != "signed_in"
    assert client.get("/api/auth/me").get_json().get("authenticated") is not True


def test_resend_is_capped(env):
    client, sent, _ = env
    _login(client)
    codes = [client.post("/api/auth/mfa/resend").status_code for _ in range(4)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429
    # The pending sign-in is cancelled, so verifying now fails.
    assert client.post("/api/auth/mfa/verify", json={"code": _code_from(sent[-1])}).status_code == 400
