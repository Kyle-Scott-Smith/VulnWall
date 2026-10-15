"""Tests for mfa.py — the email one-time-code second factor — and for how
auth.py's login() hands off to it.

Email delivery is replaced by a stub that records every message, so tests can
read the 6-digit code the same way a real user would.

Two guarantees matter most: MFA fails CLOSED (no code delivered -> no sign-in),
and resending codes is capped (MAX_RESENDS) so resend + guess can't repeat forever."""
import re
import smtplib
from datetime import datetime, timedelta, timezone

import pytest

PASSWORD = "Str0ng!pass"


@pytest.fixture()
def mail(app_env, monkeypatch):
    """SMTP 'configured'; every email sent is appended to `sent`."""
    sent = []
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: True)
    monkeypatch.setattr(
        app_env.email_notifications, "send_plain_email",
        lambda to, subject, body: sent.append({"to": to, "subject": subject, "body": body}),
    )
    return sent


def _code(sent):
    return re.search(r"code is: (\d{6})", sent[-1]["body"]).group(1)


def _mfa_user(app_env, **kw):
    return app_env.make_user(email="m@example.com", password=PASSWORD, mfa_enabled=1, **kw)


def _start_login(app_env):
    client = app_env.client()
    r = client.post("/api/auth/login", json={"email": "m@example.com", "password": PASSWORD})
    return client, r


# ---------------------------------------------------------------------------
# Login hand-off
# ---------------------------------------------------------------------------
def test_login_with_mfa_withholds_the_session_and_emails_a_code(app_env, mail):
    uid = _mfa_user(app_env)
    client, r = _start_login(app_env)
    assert r.get_json() == {"status": "mfa_required", "email": "m@example.com"}
    # Password alone must NOT sign the user in
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}
    with client.session_transaction() as s:
        assert "user_id" not in s and s["mfa_pending_user_id"] == uid
    assert len(mail) == 1 and mail[0]["to"] == "m@example.com"
    assert re.fullmatch(r"\d{6}", _code(mail))


def test_login_without_mfa_is_unaffected_and_sends_nothing(app_env, mail):
    app_env.make_user(email="plain@example.com", password=PASSWORD)
    r = app_env.client().post("/api/auth/login", json={"email": "plain@example.com", "password": PASSWORD})
    assert r.get_json()["status"] == "signed_in" and mail == []


def test_wrong_password_never_triggers_a_code(app_env, mail):
    _mfa_user(app_env)
    r = app_env.client().post("/api/auth/login", json={"email": "m@example.com", "password": "Wrong!pass1"})
    assert r.status_code == 401 and mail == []


def test_the_code_is_stored_hashed_with_a_ten_minute_expiry(app_env, mail):
    _mfa_user(app_env)
    _start_login(app_env)
    row = app_env.query("SELECT * FROM users WHERE email = 'm@example.com'")[0]
    code = _code(mail)
    assert row["mfa_code_hash"] and code not in row["mfa_code_hash"]
    assert row["mfa_code_attempts"] == 0
    remaining = datetime.fromisoformat(row["mfa_code_expires_at"]) - datetime.now(timezone.utc)
    assert timedelta(minutes=9) < remaining <= timedelta(minutes=10)


def test_generated_codes_are_six_digits_and_vary(app_env):
    codes = {app_env.mfa._generate_code() for _ in range(30)}
    assert all(re.fullmatch(r"\d{6}", c) for c in codes)
    assert len(codes) > 1


# ---------------------------------------------------------------------------
# /verify
# ---------------------------------------------------------------------------
def test_correct_code_completes_sign_in_and_burns_the_code(app_env, mail):
    uid = _mfa_user(app_env)
    client, _ = _start_login(app_env)
    r = client.post("/api/auth/mfa/verify", json={"code": _code(mail)})
    assert r.status_code == 200
    assert r.get_json()["status"] == "signed_in" and r.get_json()["email"] == "m@example.com"
    me = client.get("/api/auth/me").get_json()
    assert me["authenticated"] is True
    with client.session_transaction() as s:
        assert s["user_id"] == uid and "mfa_pending_user_id" not in s
    row = app_env.query("SELECT * FROM users WHERE id = ?", (uid,))[0]
    assert row["mfa_code_hash"] is None and row["mfa_code_expires_at"] is None


def test_a_used_code_cannot_be_replayed(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    code = _code(mail)
    assert client.post("/api/auth/mfa/verify", json={"code": code}).status_code == 200
    client.post("/api/auth/logout")
    # Same code again, e.g. a captured email: there is no pending sign-in and no stored code
    r = client.post("/api/auth/mfa/verify", json={"code": code})
    assert r.status_code == 400
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}


def test_wrong_code_is_401_and_counts_an_attempt(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    wrong = "000000" if _code(mail) != "000000" else "111111"
    r = client.post("/api/auth/mfa/verify", json={"code": wrong})
    assert r.status_code == 401 and r.get_json()["error"] == "Incorrect code"
    assert app_env.query("SELECT mfa_code_attempts FROM users")[0]["mfa_code_attempts"] == 1
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}


def test_five_wrong_attempts_lock_the_code_out_even_for_the_right_answer(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    right = _code(mail)
    wrong = "000000" if right != "000000" else "111111"
    for _ in range(5):
        assert client.post("/api/auth/mfa/verify", json={"code": wrong}).status_code == 401
    r = client.post("/api/auth/mfa/verify", json={"code": right})
    assert r.status_code == 429
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}
    # the pending sign-in is gone; a retry has to start over
    assert client.post("/api/auth/mfa/verify", json={"code": right}).status_code == 400


def test_expired_code_is_rejected_and_cleared(app_env, mail):
    uid = _mfa_user(app_env)
    client, _ = _start_login(app_env)
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    app_env.execute("UPDATE users SET mfa_code_expires_at = ? WHERE id = ?", (past, uid))
    r = client.post("/api/auth/mfa/verify", json={"code": _code(mail)})
    assert r.status_code == 400 and "expired" in r.get_json()["error"]
    assert app_env.query("SELECT mfa_code_hash FROM users WHERE id = ?", (uid,))[0]["mfa_code_hash"] is None


def test_verify_without_a_pending_sign_in_is_a_400(app_env, mail):
    r = app_env.client().post("/api/auth/mfa/verify", json={"code": "123456"})
    assert r.status_code == 400 and "waiting for a code" in r.get_json()["error"]


def test_a_signed_in_session_without_a_pending_challenge_cannot_use_verify(app_env, mail):
    client, _ = app_env.login_as()
    assert client.post("/api/auth/mfa/verify", json={"code": "123456"}).status_code == 400


def test_verify_requires_a_code(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    assert client.post("/api/auth/mfa/verify", json={}).status_code == 400
    assert client.post("/api/auth/mfa/verify", json={"code": "   "}).status_code == 400


def test_verify_when_no_code_is_stored_asks_to_sign_in_again(app_env, mail):
    uid = _mfa_user(app_env)
    client, _ = _start_login(app_env)
    app_env.execute("UPDATE users SET mfa_code_hash = NULL WHERE id = ?", (uid,))
    r = client.post("/api/auth/mfa/verify", json={"code": "123456"})
    assert r.status_code == 400 and "No code is pending" in r.get_json()["error"]


def test_code_is_trimmed_before_checking(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    assert client.post("/api/auth/mfa/verify", json={"code": f"  {_code(mail)}  "}).status_code == 200


def test_pending_session_for_a_deleted_user_is_dropped(app_env, mail):
    uid = _mfa_user(app_env)
    client, _ = _start_login(app_env)
    app_env.execute("DELETE FROM users WHERE id = ?", (uid,))
    assert client.post("/api/auth/mfa/verify", json={"code": "123456"}).status_code == 400
    with client.session_transaction() as s:
        assert "mfa_pending_user_id" not in s


# ---------------------------------------------------------------------------
# /resend
# ---------------------------------------------------------------------------
def test_resend_issues_a_new_code_and_invalidates_the_old_one(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    old = _code(mail)
    assert client.post("/api/auth/mfa/resend").get_json() == {"status": "code_resent"}
    new = _code(mail)
    assert len(mail) == 2
    if new != old:  # (1-in-a-million collision would make this check meaningless)
        assert client.post("/api/auth/mfa/verify", json={"code": old}).status_code == 401
    assert client.post("/api/auth/mfa/verify", json={"code": new}).status_code == 200


def test_resend_resets_the_attempt_counter(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    wrong = "000000" if _code(mail) != "000000" else "111111"
    for _ in range(3):
        client.post("/api/auth/mfa/verify", json={"code": wrong})
    client.post("/api/auth/mfa/resend")
    assert app_env.query("SELECT mfa_code_attempts FROM users")[0]["mfa_code_attempts"] == 0


def test_resend_without_a_pending_sign_in_is_a_400(app_env, mail):
    assert app_env.client().post("/api/auth/mfa/resend").status_code == 400


def test_resend_reports_503_when_email_is_not_configured(app_env, monkeypatch):
    uid = _mfa_user(app_env)
    client = app_env.client()
    with client.session_transaction() as s:
        s["mfa_pending_user_id"] = uid
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: False)
    r = client.post("/api/auth/mfa/resend")
    assert r.status_code == 503 and "email delivery" in r.get_json()["error"].lower()


def test_start_mfa_challenge_raises_when_smtp_is_not_configured(app_env, monkeypatch):
    uid = _mfa_user(app_env)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: False)
    row = app_env.auth.get_user_by_id(uid)
    with pytest.raises(EnvironmentError):
        app_env.mfa.start_mfa_challenge(row)
    # and nothing was written
    assert app_env.query("SELECT mfa_code_hash FROM users WHERE id = ?", (uid,))[0]["mfa_code_hash"] is None


# ---------------------------------------------------------------------------
# Fail CLOSED: no code delivered -> no sign-in
# ---------------------------------------------------------------------------
def _assert_not_signed_in(client):
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}
    with client.session_transaction() as s:
        assert "user_id" not in s and "mfa_pending_user_id" not in s


def test_login_is_refused_with_503_when_smtp_is_not_configured(app_env, monkeypatch):
    _mfa_user(app_env)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: False)
    client, r = _start_login(app_env)
    assert r.status_code == 503
    body = r.get_json()
    assert body.get("status") != "signed_in" and "sign-in code" in body["error"]
    _assert_not_signed_in(client)


def test_login_is_refused_with_503_when_the_smtp_send_fails(app_env, monkeypatch):
    _mfa_user(app_env)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: True)

    def boom(*a, **k):
        raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    monkeypatch.setattr(app_env.email_notifications, "send_plain_email", boom)
    client, r = _start_login(app_env)
    assert r.status_code == 503 and r.get_json().get("status") != "signed_in"
    _assert_not_signed_in(client)


@pytest.mark.parametrize("error", [OSError("SMTP down"), ConnectionRefusedError("refused"), TimeoutError("slow")])
def test_any_delivery_failure_is_treated_the_same(app_env, monkeypatch, error):
    _mfa_user(app_env)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: True)

    def boom(*a, **k):
        raise error

    monkeypatch.setattr(app_env.email_notifications, "send_plain_email", boom)
    client, r = _start_login(app_env)
    assert r.status_code == 503
    _assert_not_signed_in(client)


def test_a_failed_delivery_error_message_does_not_leak_server_details(app_env, monkeypatch):
    _mfa_user(app_env)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: True)

    def boom(*a, **k):
        raise OSError("535 auth failed for smtp-user@internal.example")

    monkeypatch.setattr(app_env.email_notifications, "send_plain_email", boom)
    _, r = _start_login(app_env)
    assert "internal.example" not in r.get_data(as_text=True)


def test_a_wrong_password_still_gets_the_normal_401_even_when_email_is_down(app_env, monkeypatch):
    _mfa_user(app_env)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: False)
    r = app_env.client().post("/api/auth/login", json={"email": "m@example.com", "password": "Wrong!pass1"})
    assert r.status_code == 401  # 503 would reveal that the password was right


def test_users_without_mfa_can_still_sign_in_when_email_is_down(app_env, monkeypatch):
    app_env.make_user(email="plain@example.com", password=PASSWORD)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: False)
    r = app_env.client().post("/api/auth/login", json={"email": "plain@example.com", "password": PASSWORD})
    assert r.status_code == 200 and r.get_json()["status"] == "signed_in"


# ---------------------------------------------------------------------------
# Resend cap (MAX_RESENDS): resend + 5 guesses can't repeat forever
# ---------------------------------------------------------------------------
def test_the_cap_is_three_resends(app_env):
    assert app_env.mfa.MAX_RESENDS == 3


def test_the_fourth_resend_is_refused_and_cancels_the_pending_sign_in(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    statuses = [client.post("/api/auth/mfa/resend").status_code for _ in range(4)]
    assert statuses == [200, 200, 200, 429]
    assert len(mail) == 1 + 3  # the login code + three resends; the refused one sent nothing
    with client.session_transaction() as s:
        assert "mfa_pending_user_id" not in s and "mfa_resend_count" not in s
    assert app_env.query("SELECT mfa_code_hash FROM users")[0]["mfa_code_hash"] is None


def test_after_hitting_the_cap_even_the_latest_code_no_longer_works(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    for _ in range(4):
        client.post("/api/auth/mfa/resend")
    latest = _code(mail)
    assert client.post("/api/auth/mfa/verify", json={"code": latest}).status_code == 400
    assert client.post("/api/auth/mfa/resend").status_code == 400  # nothing pending any more
    assert client.get("/api/auth/me").get_json() == {"authenticated": False}


def test_total_guesses_per_sign_in_are_bounded(app_env, mail):
    """The point of the cap: without it, (resend -> 5 guesses) could repeat forever."""
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    wrong_guesses = 0
    for _ in range(10):  # far more rounds than the cap allows
        right = _code(mail)
        wrong = "000000" if right != "000000" else "111111"
        for _ in range(5):
            if client.post("/api/auth/mfa/verify", json={"code": wrong}).status_code == 401:
                wrong_guesses += 1
        if client.post("/api/auth/mfa/resend").status_code != 200:
            break
    assert wrong_guesses == 5 * (app_env.mfa.MAX_RESENDS + 1)  # 20, then the sign-in is dead
    with client.session_transaction() as s:
        assert "mfa_pending_user_id" not in s


def test_a_resend_that_fails_to_send_does_not_use_up_the_allowance(app_env, mail, monkeypatch):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: False)
    assert client.post("/api/auth/mfa/resend").status_code == 503
    with client.session_transaction() as s:
        assert s.get("mfa_resend_count", 0) == 0
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: True)
    assert [client.post("/api/auth/mfa/resend").status_code for _ in range(3)] == [200, 200, 200]


def test_wrong_guesses_do_not_consume_resends(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    wrong = "000000" if _code(mail) != "000000" else "111111"
    for _ in range(3):
        client.post("/api/auth/mfa/verify", json={"code": wrong})
    with client.session_transaction() as s:
        assert s.get("mfa_resend_count", 0) == 0


def test_a_successful_verify_clears_the_resend_counter(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    client.post("/api/auth/mfa/resend")
    client.post("/api/auth/mfa/resend")
    assert client.post("/api/auth/mfa/verify", json={"code": _code(mail)}).status_code == 200
    with client.session_transaction() as s:
        assert "mfa_resend_count" not in s


def test_a_new_sign_in_starts_with_a_fresh_resend_allowance(app_env, mail):
    _mfa_user(app_env)
    client, _ = _start_login(app_env)
    for _ in range(4):
        client.post("/api/auth/mfa/resend")  # burn through the cap
    client.post("/api/auth/login", json={"email": "m@example.com", "password": PASSWORD})
    assert [client.post("/api/auth/mfa/resend").status_code for _ in range(3)] == [200, 200, 200]


def test_resend_allowance_is_per_session_not_per_account(app_env, mail):
    """Cancelling one sign-in doesn't lock the account; a second device starts clean."""
    _mfa_user(app_env)
    first, _ = _start_login(app_env)
    for _ in range(4):
        first.post("/api/auth/mfa/resend")
    second, _ = _start_login(app_env)
    assert second.post("/api/auth/mfa/resend").status_code == 200


# ---------------------------------------------------------------------------
# Consequence of failing closed
# ---------------------------------------------------------------------------
@pytest.mark.xfail(strict=True, reason="GAP: now that login fails closed, PATCH /api/auth/mfa still lets a user switch MFA on "
                                        "while email isn't configured (or before they've confirmed they can receive the "
                                        "email). Their next sign-in is then refused with 503 and nothing in the app can "
                                        "turn MFA back off for them (the toggle is self-service only). Reject enabling "
                                        "when email_notifications.is_configured() is False (e.g. 503), then remove this marker.")
def test_mfa_cannot_be_enabled_while_email_delivery_is_not_configured(app_env, monkeypatch):
    client, _ = app_env.login_as()
    monkeypatch.setattr(app_env.email_notifications, "is_configured", lambda: False)
    r = client.patch("/api/auth/mfa", json={"enabled": True})
    assert r.status_code in (400, 409, 503)
    assert client.get("/api/auth/me").get_json()["mfaEnabled"] is False
