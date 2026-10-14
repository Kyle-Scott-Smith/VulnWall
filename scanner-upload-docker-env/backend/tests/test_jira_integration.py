"""Tests for jira_integration.py beyond the pure status-mapping helpers
(see test_jira_transitions.py): the OAuth connect flow, issue lookups and
transitions, project auto-creation, and ticket creation.

Atlassian's APIs are replaced by a small router: each test declares which
URLs answer what, and any request it did NOT declare fails the test loudly."""
from urllib.parse import parse_qs, urlparse

import pytest
import requests

RECORD = {"cloud_id": "cloud-1", "access_token": "tok", "site_name": "acme", "account_id": "acct-1"}


class Net:
    """Routes fake HTTP calls by (method, substring-of-url); the most specific match wins."""

    def __init__(self, fake_response):
        self.fake_response = fake_response
        self.routes = []
        self.calls = []

    def on(self, method, url_part, response=None, *, status=200, json=None, text="", raises=None):
        if response is None:
            response = self.fake_response(status, json, text)
        self.routes.append((method, url_part, raises or response))
        return self

    def _handle(self, method, url, **kw):
        self.calls.append({"method": method, "url": url, **kw})
        # Most specific (longest) matching route wins, so "/issue/V-1/transitions"
        # is not swallowed by a route declared for "/issue/V-1".
        matches = [(part, result) for m, part, result in self.routes if m == method and part in url]
        if not matches:
            raise AssertionError(f"unexpected {method} {url}")
        _, result = max(matches, key=lambda pr: len(pr[0]))
        if isinstance(result, Exception):
            raise result
        return result

    def calls_to(self, method, url_part):
        return [c for c in self.calls if c["method"] == method and url_part in c["url"]]


@pytest.fixture()
def net(app_env, monkeypatch, fake_response):
    n = Net(fake_response)
    monkeypatch.setattr(app_env.jira_integration.requests, "get", lambda url, **kw: n._handle("GET", url, **kw))
    monkeypatch.setattr(app_env.jira_integration.requests, "post", lambda url, **kw: n._handle("POST", url, **kw))
    return n


@pytest.fixture()
def jira(app_env, monkeypatch):
    j = app_env.jira_integration
    monkeypatch.setattr(j, "CLIENT_ID", "jira-client")
    monkeypatch.setattr(j, "CLIENT_SECRET", "jira-secret")
    monkeypatch.setattr(j, "CALLBACK_URL", "http://localhost:5000/api/jira/callback")
    monkeypatch.setattr(j, "FRONTEND_RETURN_URL", "http://localhost:5173/?jira=connected")
    return j


def _connect_user(app_env, **over):
    """Signed-in analyst that already has a stored Jira connection."""
    client, uid = app_env.login_as()
    row = {"user_id": uid, "access_token": "tok", "refresh_token": "ref", "cloud_id": "cloud-1",
           "site_name": "acme", "account_id": "acct-1", "created_at": "t", "updated_at": "t", **over}
    app_env.execute(
        f"INSERT INTO jira_connections ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})", list(row.values()))
    return client, uid


# ---------------------------------------------------------------------------
# fetch_issue_status_category
# ---------------------------------------------------------------------------
def test_fetch_status_category_success(app_env, net):
    net.on("GET", "/issue/V-1", json={"fields": {"status": {"statusCategory": {"key": "done"}}}})
    assert app_env.jira_integration.fetch_issue_status_category(RECORD, "V-1") == "done"
    call = net.calls[0]
    assert call["url"] == "https://api.atlassian.com/ex/jira/cloud-1/rest/api/3/issue/V-1"
    assert call["headers"]["Authorization"] == "Bearer tok" and call["params"] == {"fields": "status"}


@pytest.mark.parametrize("record,key", [(None, "V-1"), ({}, "V-1"), (RECORD, None), (RECORD, "")])
def test_fetch_status_category_needs_a_record_and_a_key(app_env, net, record, key):
    assert app_env.jira_integration.fetch_issue_status_category(record, key) is None
    assert net.calls == []


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_fetch_status_category_non_200_is_none(app_env, net, status):
    net.on("GET", "/issue/", status=status, json={})
    assert app_env.jira_integration.fetch_issue_status_category(RECORD, "V-1") is None


@pytest.mark.parametrize("body", [{}, {"fields": {}}, {"fields": {"status": {}}}, {"fields": {"status": {"statusCategory": {}}}}])
def test_fetch_status_category_malformed_payload_is_none(app_env, net, body):
    net.on("GET", "/issue/", json=body)
    assert app_env.jira_integration.fetch_issue_status_category(RECORD, "V-1") is None


def test_fetch_status_category_network_error_and_bad_json_are_none(app_env, net):
    net.on("GET", "/issue/", raises=requests.ConnectionError("down"))
    assert app_env.jira_integration.fetch_issue_status_category(RECORD, "V-1") is None
    net.routes.clear()
    net.on("GET", "/issue/", json=None)  # .json() raises ValueError
    assert app_env.jira_integration.fetch_issue_status_category(RECORD, "V-1") is None


# ---------------------------------------------------------------------------
# transition_issue_to_category
# ---------------------------------------------------------------------------
def _issue_route(net, category):
    net.on("GET", "/issue/V-1", json={"fields": {"status": {"statusCategory": {"key": category}}}})


def _transitions(*pairs):
    return {"transitions": [{"id": tid, "to": {"statusCategory": {"key": cat}}} for tid, cat in pairs]}


def test_transition_requires_a_linked_issue(app_env, net):
    ok, msg = app_env.jira_integration.transition_issue_to_category(None, "V-1", "done")
    assert ok is False and "isn't linked" in msg
    ok, msg = app_env.jira_integration.transition_issue_to_category(RECORD, "", "done")
    assert ok is False and net.calls == []


def test_transition_is_a_no_op_when_jira_is_already_there(app_env, net):
    _issue_route(net, "done")
    assert app_env.jira_integration.transition_issue_to_category(RECORD, "V-1", "done") == (True, None)
    assert not net.calls_to("POST", "/transitions") and not net.calls_to("GET", "/transitions")


def test_transition_posts_the_matching_transition_id(app_env, net):
    _issue_route(net, "new")
    net.on("GET", "/transitions", json=_transitions(("11", "new"), ("31", "done")))
    net.on("POST", "/transitions", status=204, json={})
    assert app_env.jira_integration.transition_issue_to_category(RECORD, "V-1", "done") == (True, None)
    (post,) = net.calls_to("POST", "/transitions")
    assert post["json"] == {"transition": {"id": "31"}} and post["headers"]["Content-Type"] == "application/json"


@pytest.mark.parametrize("status,expected", [
    (401, "Reconnect Jira"), (403, "Reconnect Jira"), (404, "no longer exists"), (500, "error (500)"),
])
def test_transition_lookup_failures_have_plain_english_messages(app_env, net, status, expected):
    _issue_route(net, "new")
    net.on("GET", "/transitions", status=status, json={})
    ok, msg = app_env.jira_integration.transition_issue_to_category(RECORD, "V-1", "done")
    assert ok is False and expected in msg
    assert not net.calls_to("POST", "/transitions")


def test_transition_when_the_workflow_has_no_route(app_env, net):
    _issue_route(net, "new")
    net.on("GET", "/transitions", json=_transitions(("21", "indeterminate")))
    ok, msg = app_env.jira_integration.transition_issue_to_category(RECORD, "V-1", "done")
    assert ok is False and "doesn't allow" in msg


def test_transition_refused_by_jira(app_env, net):
    _issue_route(net, "new")
    net.on("GET", "/transitions", json=_transitions(("31", "done")))
    net.on("POST", "/transitions", status=400, json={})
    ok, msg = app_env.jira_integration.transition_issue_to_category(RECORD, "V-1", "done")
    assert ok is False and "refused" in msg and "400" in msg


def test_transition_network_failure(app_env, net):
    _issue_route(net, "new")
    net.on("GET", "/transitions", raises=requests.Timeout("slow"))
    ok, msg = app_env.jira_integration.transition_issue_to_category(RECORD, "V-1", "done")
    assert ok is False and "Couldn't reach Jira" in msg


# ---------------------------------------------------------------------------
# /status, /connect, /disconnect
# ---------------------------------------------------------------------------
def test_status_when_jira_is_not_configured(app_env, monkeypatch):
    j = app_env.jira_integration
    monkeypatch.setattr(j, "CLIENT_ID", None)
    assert app_env.client().get("/api/jira/status").get_json() == {"configured": False, "connected": False}


def test_status_configured_but_not_connected(app_env, jira):
    client, _ = app_env.login_as()
    assert client.get("/api/jira/status").get_json() == {"configured": True, "connected": False}
    assert app_env.client().get("/api/jira/status").get_json() == {"configured": True, "connected": False}


def test_status_connected_shows_the_site(app_env, jira):
    client, _ = _connect_user(app_env, site_name="acme")
    assert client.get("/api/jira/status").get_json() == {"configured": True, "connected": True, "site": "acme"}


def test_connect_is_role_gated_and_503_when_unconfigured(app_env, jira, monkeypatch):
    assert app_env.client().get("/api/jira/connect").status_code == 401
    viewer, _ = app_env.login_as(role="viewer")
    assert viewer.get("/api/jira/connect").status_code == 403
    monkeypatch.setattr(jira, "CLIENT_SECRET", None)
    analyst, _ = app_env.login_as()
    r = analyst.get("/api/jira/connect")
    assert r.status_code == 503 and "not configured" in r.get_json()["error"]


def test_connect_redirects_to_atlassian_with_state_and_scopes(app_env, jira):
    client, _ = app_env.login_as()
    r = client.get("/api/jira/connect")
    assert r.status_code == 302
    url = urlparse(r.headers["Location"])
    assert f"{url.scheme}://{url.netloc}{url.path}" == "https://auth.atlassian.com/authorize"
    q = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert q["client_id"] == "jira-client" and q["audience"] == "api.atlassian.com" and q["response_type"] == "code"
    assert q["redirect_uri"] == "http://localhost:5000/api/jira/callback" and q["prompt"] == "consent"
    assert "write:jira-work" in q["scope"]
    with client.session_transaction() as s:
        assert s["jira_oauth_state"] == q["state"]


def test_disconnect_removes_only_the_callers_connection(app_env, jira):
    a, a_id = _connect_user(app_env)
    _, b_id = _connect_user(app_env)
    assert a.post("/api/jira/disconnect").get_json() == {"status": "disconnected"}
    remaining = [r["user_id"] for r in app_env.query("SELECT user_id FROM jira_connections")]
    assert remaining == [b_id]


def test_disconnect_is_role_gated_and_idempotent(app_env, jira):
    assert app_env.client().post("/api/jira/disconnect").status_code == 401
    viewer, _ = app_env.login_as(role="viewer")
    assert viewer.post("/api/jira/disconnect").status_code == 403
    analyst, _ = app_env.login_as()
    assert analyst.post("/api/jira/disconnect").status_code == 200


def test_get_connection_record_follows_the_signed_in_account(app_env, jira):
    client, uid = _connect_user(app_env, site_name="acme")
    with app_env.app.test_request_context():
        assert app_env.jira_integration.get_connection_record() is None  # nobody signed in
    with app_env.app.test_request_context():
        from flask import session
        session["user_id"] = uid
        assert app_env.jira_integration.get_connection_record()["site_name"] == "acme"


# ---------------------------------------------------------------------------
# /callback
# ---------------------------------------------------------------------------
def _start(client):
    client.get("/api/jira/connect")
    with client.session_transaction() as s:
        return s["jira_oauth_state"]


def _happy_net(net, resources=None, myself_status=200):
    net.on("POST", "oauth/token", json={"access_token": "A", "refresh_token": "R"})
    net.on("GET", "accessible-resources", json=resources if resources is not None else [{"id": "cloud-9", "name": "acme"}])
    net.on("GET", "/myself", status=myself_status, json={"accountId": "acct-9"} if myself_status == 200 else {}, text="nope")


def _callback(client, state=None, **params):
    state = _start(client) if state is None else state
    q = {"state": state, "code": "the-code", **params}
    return client.get("/api/jira/callback", query_string={k: v for k, v in q.items() if v is not None})


def test_callback_is_503_when_unconfigured_and_401_when_signed_out(app_env, jira, monkeypatch):
    assert app_env.client().get("/api/jira/callback").status_code == 401
    monkeypatch.setattr(jira, "CLIENT_ID", None)
    assert app_env.client().get("/api/jira/callback").status_code == 503


def test_callback_rejects_a_state_mismatch_before_talking_to_atlassian(app_env, jira, net):
    client, _ = app_env.login_as()
    r = _callback(client, state="forged")
    assert r.status_code == 400 and "State mismatch" in r.get_json()["error"] and net.calls == []


def test_callback_state_is_single_use(app_env, jira, net):
    _happy_net(net)
    client, _ = app_env.login_as()
    state = _start(client)
    assert _callback(client, state=state).status_code == 302
    assert _callback(client, state=state).status_code == 400


def test_callback_without_a_code_reports_atlassians_reason(app_env, jira, net):
    client, _ = app_env.login_as()
    r = _callback(client, code=None, error_description="User denied access")
    assert r.status_code == 400 and r.get_json()["error"] == "User denied access"
    r2 = _callback(client, code=None)
    assert "no code returned" in r2.get_json()["error"]


def test_callback_token_exchange_failure(app_env, jira, net):
    net.on("POST", "oauth/token", status=400, text="invalid_grant")
    client, _ = app_env.login_as()
    r = _callback(client)
    assert r.status_code == 400 and r.get_json() == {"error": "Token exchange failed", "detail": "invalid_grant"}
    assert app_env.query("SELECT COUNT(*) AS n FROM jira_connections")[0]["n"] == 0


@pytest.mark.parametrize("resources", [[], None])
def test_callback_with_no_accessible_sites(app_env, jira, net, resources):
    net.on("POST", "oauth/token", json={"access_token": "A"})
    if resources is None:
        net.on("GET", "accessible-resources", status=401, json={})
    else:
        net.on("GET", "accessible-resources", json=resources)
    client, _ = app_env.login_as()
    r = _callback(client)
    assert r.status_code == 400 and "No accessible Jira sites" in r.get_json()["error"]


def test_callback_stores_the_connection_and_returns_to_the_app(app_env, jira, net):
    _happy_net(net)
    client, uid = app_env.login_as()
    r = _callback(client)
    assert r.status_code == 302 and r.headers["Location"] == "http://localhost:5173/?jira=connected"
    row = app_env.query("SELECT * FROM jira_connections WHERE user_id = ?", (uid,))[0]
    assert (row["access_token"], row["refresh_token"], row["cloud_id"], row["site_name"], row["account_id"]) == (
        "A", "R", "cloud-9", "acme", "acct-9")
    token_call = net.calls_to("POST", "oauth/token")[0]["json"]
    assert token_call["code"] == "the-code" and token_call["grant_type"] == "authorization_code"
    assert client.get("/api/jira/status").get_json()["connected"] is True


def test_callback_uses_the_first_site_when_there_are_several(app_env, jira, net):
    _happy_net(net, resources=[{"id": "first", "name": "one"}, {"id": "second", "name": "two"}])
    client, uid = app_env.login_as()
    _callback(client)
    assert app_env.query("SELECT cloud_id FROM jira_connections")[0]["cloud_id"] == "first"


def test_callback_survives_a_failed_myself_lookup_with_no_account_id(app_env, jira, net):
    _happy_net(net, myself_status=403)
    client, _ = app_env.login_as()
    assert _callback(client).status_code == 302
    assert app_env.query("SELECT account_id FROM jira_connections")[0]["account_id"] is None


def test_reconnecting_replaces_the_old_tokens_instead_of_duplicating(app_env, jira, net):
    _happy_net(net)
    client, uid = _connect_user(app_env, access_token="OLD", site_name="old-site")
    _callback(client)
    rows = app_env.query("SELECT * FROM jira_connections")
    assert len(rows) == 1 and rows[0]["access_token"] == "A" and rows[0]["site_name"] == "acme"


# ---------------------------------------------------------------------------
# _ensure_project_exists
# ---------------------------------------------------------------------------
def test_existing_project_is_used_as_is(app_env, net):
    net.on("GET", "/project/search", json={"values": [{"key": "VULN"}]})
    assert app_env.jira_integration._ensure_project_exists(RECORD, "VULN") == (True, None)
    assert net.calls[0]["params"] == {"keys": "VULN"} and not net.calls_to("POST", "/project")


def test_missing_project_is_created_as_a_kanban_software_project(app_env, net):
    net.on("GET", "/project/search", json={"values": []})
    net.on("POST", "/project", status=201, json={})
    assert app_env.jira_integration._ensure_project_exists(RECORD, "VULN") == (True, None)
    body = net.calls_to("POST", "/project")[0]["json"]
    assert body["key"] == "VULN" and body["leadAccountId"] == "acct-1" and body["projectTypeKey"] == "software"
    assert "kanban" in body["projectTemplateKey"]


def test_project_creation_needs_a_lead_account_id(app_env, net):
    net.on("GET", "/project/search", json={"values": []})
    ok, msg = app_env.jira_integration._ensure_project_exists({**RECORD, "account_id": None}, "VULN")
    assert ok is False and "Disconnect and reconnect Jira" in msg and not net.calls_to("POST", "/project")


def test_a_search_error_falls_through_to_creation(app_env, net):
    net.on("GET", "/project/search", status=500, json={})
    net.on("POST", "/project", status=200, json={})
    assert app_env.jira_integration._ensure_project_exists(RECORD, "VULN") == (True, None)


def test_key_already_in_use_counts_as_success(app_env, net):
    """project/search hides projects the account can't browse; Jira's 'key in use' 400 means it exists."""
    net.on("GET", "/project/search", json={"values": []})
    net.on("POST", "/project", status=400, json={"errors": {"projectKey": "Another project uses this project key."}})
    assert app_env.jira_integration._ensure_project_exists(RECORD, "VULN") == (True, None)


@pytest.mark.parametrize("status,body", [
    (400, {"errors": {"projectName": "bad name"}}),
    (400, {"errors": {"projectKey": "Project key is invalid."}}),
    (403, {"errors": {"projectKey": "uses this project key"}}),   # key-conflict wording only counts on a 400
    (401, {"message": "scope does not match"}),
])
def test_other_creation_failures_are_reported_with_guidance(app_env, net, status, body):
    net.on("GET", "/project/search", json={"values": []})
    net.on("POST", "/project", status=status, json=body)
    ok, msg = app_env.jira_integration._ensure_project_exists(RECORD, "VULN")
    assert ok is False and "Couldn't auto-create project 'VULN'" in msg and "write:project:jira" in msg


def test_non_json_creation_error_is_reported_not_crashed_on(app_env, net):
    net.on("GET", "/project/search", json={"values": []})
    net.on("POST", "/project", status=400, json=None, text="<html>oops</html>")
    ok, msg = app_env.jira_integration._ensure_project_exists(RECORD, "VULN")
    assert ok is False and "<html>oops</html>" in msg


# ---------------------------------------------------------------------------
# /create-ticket
# ---------------------------------------------------------------------------
def _create(client, **body):
    return client.post("/api/jira/create-ticket", json={"title": "Fix openssl", "projectKey": "VULN", **body})


def _issue_ok(net, key="VULN-12"):
    net.on("GET", "/project/search", json={"values": [{"key": "VULN"}]})
    net.on("POST", "/rest/api/3/issue", status=201, json={"key": key})


def test_create_ticket_is_role_gated_and_requires_configuration(app_env, jira, monkeypatch):
    assert _create(app_env.client()).status_code == 401
    viewer, _ = app_env.login_as(role="viewer")
    assert _create(viewer).status_code == 403
    monkeypatch.setattr(jira, "CLIENT_ID", None)
    analyst, _ = app_env.login_as()
    assert _create(analyst).status_code == 503


def test_create_ticket_needs_a_connection(app_env, jira):
    client, _ = app_env.login_as()
    r = _create(client)
    assert r.status_code == 401 and "No Jira account connected" in r.get_json()["error"]


@pytest.mark.parametrize("title", [None, "", "   "])
def test_create_ticket_needs_a_title(app_env, jira, net, title):
    client, _ = _connect_user(app_env)
    assert _create(client, title=title).status_code == 400 and net.calls == []


def test_create_ticket_needs_a_project_key_from_the_body_or_the_environment(app_env, jira, net, monkeypatch):
    client, _ = _connect_user(app_env)
    monkeypatch.delenv("JIRA_DEFAULT_PROJECT_KEY", raising=False)
    r = client.post("/api/jira/create-ticket", json={"title": "t"})
    assert r.status_code == 400 and "No project specified" in r.get_json()["error"]
    monkeypatch.setenv("JIRA_DEFAULT_PROJECT_KEY", "ENVKEY")
    net.on("GET", "/project/search", json={"values": [{"key": "ENVKEY"}]})
    net.on("POST", "/rest/api/3/issue", status=201, json={"key": "ENVKEY-1"})
    assert client.post("/api/jira/create-ticket", json={"title": "t"}).status_code == 200
    assert net.calls_to("POST", "/rest/api/3/issue")[0]["json"]["fields"]["project"] == {"key": "ENVKEY"}


def test_create_ticket_success_returns_key_and_browse_url(app_env, jira, net):
    _issue_ok(net)
    client, _ = _connect_user(app_env, site_name="acme")
    assert _create(client).get_json() == {"status": "created", "issueKey": "VULN-12", "url": "https://acme.atlassian.net/browse/VULN-12"}


def test_create_ticket_sends_adf_description_and_task_issue_type(app_env, jira, net):
    _issue_ok(net)
    client, _ = _connect_user(app_env)
    _create(client, description="Upgrade to 3.0.14")
    fields = net.calls_to("POST", "/rest/api/3/issue")[0]["json"]["fields"]
    assert fields["summary"] == "Fix openssl" and fields["issuetype"] == {"name": "Task"}
    assert fields["description"] == {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": "Upgrade to 3.0.14"}]}]}


def test_create_ticket_without_a_description_uses_a_placeholder(app_env, jira, net):
    _issue_ok(net)
    client, _ = _connect_user(app_env)
    _create(client)
    text = net.calls_to("POST", "/rest/api/3/issue")[0]["json"]["fields"]["description"]["content"][0]["content"][0]["text"]
    assert text == "(no description provided)"


def test_create_ticket_trims_the_title_and_authenticates_with_the_stored_token(app_env, jira, net):
    _issue_ok(net)
    client, _ = _connect_user(app_env, access_token="STORED")
    _create(client, title="  Padded  ")
    call = net.calls_to("POST", "/rest/api/3/issue")[0]
    assert call["json"]["fields"]["summary"] == "Padded" and call["headers"]["Authorization"] == "Bearer STORED"


def test_create_ticket_stops_if_the_project_cannot_be_ensured(app_env, jira, net):
    net.on("GET", "/project/search", json={"values": []})
    net.on("POST", "/project", status=403, json={})
    client, _ = _connect_user(app_env)
    r = _create(client)
    assert r.status_code == 502 and "Couldn't auto-create" in r.get_json()["error"]
    assert not net.calls_to("POST", "/rest/api/3/issue")


def test_create_ticket_reports_a_jira_rejection(app_env, jira, net):
    net.on("GET", "/project/search", json={"values": [{"key": "VULN"}]})
    net.on("POST", "/rest/api/3/issue", status=400, text="field 'summary' is required")
    client, _ = _connect_user(app_env)
    r = _create(client)
    assert r.status_code == 502 and r.get_json() == {"error": "Jira rejected the ticket", "detail": "field 'summary' is required"}


def test_create_ticket_with_no_key_in_the_response_has_no_url(app_env, jira, net):
    net.on("GET", "/project/search", json={"values": [{"key": "VULN"}]})
    net.on("POST", "/rest/api/3/issue", status=201, json={})
    client, _ = _connect_user(app_env)
    assert _create(client).get_json() == {"status": "created", "issueKey": None, "url": None}


def test_one_users_connection_is_never_used_for_another(app_env, jira, net):
    _connect_user(app_env)
    other, _ = app_env.login_as()
    assert _create(other).status_code == 401 and net.calls == []
