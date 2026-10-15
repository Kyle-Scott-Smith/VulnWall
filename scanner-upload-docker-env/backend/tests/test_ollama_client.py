"""Tests for ollama_client.py — model-name resolution and the /api/chat call.
`requests` is replaced by a scripted fake, so no Ollama server is needed."""
import pytest
import requests


@pytest.fixture()
def oc(app_env):
    mod = app_env.ollama_client
    mod._resolved_model_cache.clear()
    return mod


@pytest.fixture()
def net(oc, monkeypatch, fake_response):
    """Scriptable network: set net.tags / net.chat to a response or an exception."""
    class Net:
        tags = fake_response(200, {"models": [{"name": "llama3.1:latest"}]})
        chat = fake_response(200, {"message": {"content": "  hello  "}})
        calls = []

    def get(url, **kw):
        Net.calls.append(("GET", url, kw))
        if isinstance(Net.tags, Exception):
            raise Net.tags
        return Net.tags

    def post(url, **kw):
        Net.calls.append(("POST", url, kw))
        if isinstance(Net.chat, Exception):
            raise Net.chat
        return Net.chat

    Net.calls = []
    monkeypatch.setattr(oc.requests, "get", get)
    monkeypatch.setattr(oc.requests, "post", post)
    return Net


# ---------------------------------------------------------------------------
# list_models
# ---------------------------------------------------------------------------
def test_list_models_returns_the_servers_list(oc, net):
    assert oc.list_models() == [{"name": "llama3.1:latest"}]
    assert net.calls[0][1].endswith("/api/tags")


def test_list_models_wraps_connection_problems(oc, net):
    net.tags = requests.ConnectionError("refused")
    with pytest.raises(oc.OllamaError, match="Could not reach Ollama"):
        oc.list_models()


def test_list_models_wraps_http_errors_and_bad_json(oc, net, fake_response):
    net.tags = fake_response(500, {})
    with pytest.raises(oc.OllamaError):
        oc.list_models()
    net.tags = fake_response(200, None)  # .json() raises ValueError
    with pytest.raises(oc.OllamaError, match="non-JSON"):
        oc.list_models()


def test_list_models_with_no_models_key_is_an_empty_list(oc, net, fake_response):
    net.tags = fake_response(200, {"other": 1})
    assert oc.list_models() == []


# ---------------------------------------------------------------------------
# resolve_model
# ---------------------------------------------------------------------------
def test_exact_match_wins(oc, net, fake_response):
    net.tags = fake_response(200, {"models": [{"name": "llama3.1:8b"}, {"name": "llama3.1:latest"}]})
    assert oc.resolve_model("llama3.1:8b") == "llama3.1:8b"


def test_untagged_name_resolves_to_the_installed_tag(oc, net):
    assert oc.resolve_model("llama3.1") == "llama3.1:latest"


def test_resolution_accepts_the_model_key_as_well_as_name(oc, net, fake_response):
    net.tags = fake_response(200, {"models": [{"model": "qwen2:7b"}]})
    assert oc.resolve_model("qwen2") == "qwen2:7b"


def test_a_partial_prefix_is_not_a_match(oc, net):
    with pytest.raises(oc.OllamaError, match="not installed"):
        oc.resolve_model("llama3")  # only "llama3.1:latest" is installed


def test_not_installed_error_lists_what_is_installed(oc, net):
    with pytest.raises(oc.OllamaError) as e:
        oc.resolve_model("mistral")
    assert "llama3.1:latest" in str(e.value) and "ollama pull mistral" in str(e.value)


def test_no_models_pulled_gives_a_pull_hint(oc, net, fake_response):
    net.tags = fake_response(200, {"models": []})
    with pytest.raises(oc.OllamaError, match="No models are pulled"):
        oc.resolve_model("llama3.1")


def test_resolution_is_cached_for_the_process(oc, net):
    oc.resolve_model("llama3.1")
    oc.resolve_model("llama3.1")
    assert [c for c in net.calls if c[0] == "GET"] == net.calls[:1]


# ---------------------------------------------------------------------------
# chat
# ---------------------------------------------------------------------------
def test_chat_sends_system_prompt_first_and_returns_stripped_text(oc, net):
    out = oc.chat("be brief", [{"role": "user", "content": "hi"}], model="llama3.1")
    assert out == "hello"
    method, url, kw = net.calls[-1]
    assert url.endswith("/api/chat") and kw["timeout"] == oc.OLLAMA_TIMEOUT_SECONDS
    assert kw["json"] == {
        "model": "llama3.1:latest", "stream": False,
        "messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}],
    }


def test_json_mode_adds_the_format_flag(oc, net):
    oc.chat("s", [], model="llama3.1")
    assert "format" not in net.calls[-1][2]["json"]
    oc.chat("s", [], model="llama3.1", json_mode=True)
    assert net.calls[-1][2]["json"]["format"] == "json"


def test_chat_uses_the_configured_default_model(oc, net, monkeypatch):
    monkeypatch.setattr(oc, "OLLAMA_MODEL", "llama3.1")
    oc.chat("s", [])
    assert net.calls[-1][2]["json"]["model"] == "llama3.1:latest"


def test_chat_errors_are_wrapped(oc, net, fake_response):
    oc.resolve_model("llama3.1")
    net.chat = requests.ConnectionError("refused")
    with pytest.raises(oc.OllamaError, match="Is it running"):
        oc.chat("s", [], model="llama3.1")
    net.chat = requests.Timeout("slow")
    with pytest.raises(oc.OllamaError, match="timed out"):
        oc.chat("s", [], model="llama3.1")


def test_http_error_includes_the_servers_detail(oc, net, fake_response):
    net.chat = fake_response(500, {"error": "out of memory"})
    with pytest.raises(oc.OllamaError, match="out of memory"):
        oc.chat("s", [], model="llama3.1")


def test_a_model_not_found_error_clears_the_cached_resolution(oc, net, fake_response):
    oc.resolve_model("llama3.1")
    assert "llama3.1" in oc._resolved_model_cache
    net.chat = fake_response(404, {"error": "model 'llama3.1:latest' not found"})
    with pytest.raises(oc.OllamaError):
        oc.chat("s", [], model="llama3.1")
    assert "llama3.1" not in oc._resolved_model_cache


def test_other_http_errors_keep_the_cache(oc, net, fake_response):
    oc.resolve_model("llama3.1")
    net.chat = fake_response(500, {"error": "boom"})
    with pytest.raises(oc.OllamaError):
        oc.chat("s", [], model="llama3.1")
    assert "llama3.1" in oc._resolved_model_cache


def test_non_json_reply_is_an_error(oc, net, fake_response):
    net.chat = fake_response(200, None)
    with pytest.raises(oc.OllamaError, match="non-JSON"):
        oc.chat("s", [], model="llama3.1")


@pytest.mark.parametrize("payload", [{}, {"message": None}, {"message": {}}])
def test_missing_message_content_gives_an_empty_string(oc, net, fake_response, payload):
    net.chat = fake_response(200, payload or {"x": 1})
    assert oc.chat("s", [], model="llama3.1") == ""


def test_chat_fails_early_when_the_model_cannot_be_resolved(oc, net):
    with pytest.raises(oc.OllamaError, match="not installed"):
        oc.chat("s", [], model="missing")
    assert not any(c[0] == "POST" for c in net.calls)
