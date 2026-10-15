"""Makes `backend/` importable as a plain module root (e.g. `import
scanners.utils`, `from ai_analysis import ...`) regardless of the directory
pytest is invoked from. The app's modules use flat imports that assume
backend/ itself is on sys.path (see scanner.py's `from ai_analysis import
...`), so tests need the same thing without relying on cwd.

This file also holds the fixtures shared by the endpoint/integration tests:

  app_env        a brand-new copy of the WHOLE app (scanner.py + every
                 blueprint) wired to a throwaway SQLite file. Every test gets
                 its own database and freshly imported modules, so nothing
                 leaks between tests. Exposes helpers for creating users and
                 signing clients in without going through the signup flow.
  import_fresh   import a module against a database file you prepared first
                 (for migration tests).
  fake_response  factory for stand-in `requests` responses.
  fake_clock     makes a module's `datetime.now()` tick forward one minute per
                 call, so tests that insert several rows get a stable order.
"""
import importlib
import itertools
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import pytest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Every module that either owns DB state or captured `auth._get_db` at import
# time. They must be thrown away together: if `scans` kept a reference to an
# old `auth._get_db`, it would keep writing to the previous test's database.
APP_MODULES = (
    "scanner", "auth", "mfa", "google_auth", "jira_integration",
    "registry_credentials", "business_context", "tickets", "scans",
    "dashboard", "email_notifications", "tenable_client", "ai_analysis",
    "chatbot", "ollama_client",
)


def purge_app_modules():
    for name in APP_MODULES:
        sys.modules.pop(name, None)


class AppEnv:
    """Handle on one freshly built copy of the app."""

    def __init__(self, db_path):
        self.db_path = db_path
        self.scanner = importlib.import_module("scanner")
        self.app = self.scanner.app
        self.app.config["TESTING"] = True
        self._counter = itertools.count(1)

    # -- modules, by name: env.auth, env.tickets, env.scans, ... ------------
    def __getattr__(self, name):
        if name in APP_MODULES:
            return importlib.import_module(name)
        raise AttributeError(name)

    # -- database -------------------------------------------------------------
    def db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def query(self, sql, params=()):
        conn = self.db()
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def execute(self, sql, params=()):
        conn = self.db()
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    # -- users and sessions ---------------------------------------------------
    def make_user(self, email=None, role="analyst", name="Test User", password=None, **columns):
        """Insert a user row directly. `password` (optional) is stored hashed so
        the login endpoint accepts it; without it the hash is a placeholder.
        Extra keyword args are written to same-named columns
        (e.g. auth_provider="google", mfa_enabled=1)."""
        from werkzeug.security import generate_password_hash

        n = next(self._counter)
        email = email or f"user{n}@example.com"
        password_hash = generate_password_hash(password, method="pbkdf2:sha256:1000") if password else "x"
        row = {
            "name": name, "email": email.lower(), "password_hash": password_hash,
            "role": role, "created_at": f"2026-01-{n:02d}T00:00:00+00:00",
            **columns,
        }
        conn = self.db()
        try:
            cur = conn.execute(
                f"INSERT INTO users ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                list(row.values()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def client(self, user_id=None):
        """A test client, optionally already signed in as `user_id`."""
        client = self.app.test_client()
        if user_id is not None:
            with client.session_transaction() as s:
                s["user_id"] = user_id
        return client

    def login_as(self, role="analyst", **kwargs):
        """Shortcut: create a user with `role` and return (client, user_id)."""
        uid = self.make_user(role=role, **kwargs)
        return self.client(uid), uid


@pytest.fixture()
def app_env(monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("AUTH_DB_PATH", db_path)
    purge_app_modules()
    env = AppEnv(db_path)
    yield env
    purge_app_modules()


@pytest.fixture()
def import_fresh(monkeypatch):
    """`import_fresh("auth", db_path)` imports a module as if the server had
    just started with AUTH_DB_PATH=db_path. For tests that need to prepare the
    database file BEFORE the app (and its migrations) run."""
    def _import(name, db_path):
        monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
        purge_app_modules()
        return importlib.import_module(name)
    yield _import
    purge_app_modules()


class FakeResponse:
    """The slice of requests.Response the app actually touches."""

    def __init__(self, status_code=200, json_data=None, text=""):
        import requests

        self._requests = requests
        self.status_code = status_code
        self._json = json_data
        self.text = text or ("" if json_data is None else str(json_data))

    def json(self):
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise self._requests.HTTPError(f"{self.status_code} error", response=self)


@pytest.fixture()
def fake_response():
    def make(status=200, json=None, text=""):
        return FakeResponse(status, json, text)
    return make


@pytest.fixture()
def fake_clock(monkeypatch):
    """Call `fake_clock(module)` to make `module.datetime.now()` return
    2026-03-01 00:00, 00:01, 00:02 ... on successive calls."""
    def install(*modules, start=datetime(2026, 3, 1, tzinfo=timezone.utc)):
        ticks = itertools.count()

        class Ticking(datetime):
            @classmethod
            def now(cls, tz=None):
                return start + timedelta(minutes=next(ticks))

        for module in modules:
            monkeypatch.setattr(module, "datetime", Ticking)
    return install
