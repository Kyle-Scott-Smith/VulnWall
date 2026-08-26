"""
Thin HTTP wrapper around a local/self-hosted Ollama server.

Uses Ollama's /api/chat endpoint (https://github.com/ollama/ollama/blob/main/docs/api.md),
which takes the same system+messages shape the Claude client used, so
ai_analysis.py and chatbot.py needed minimal changes to swap providers —
that's the whole point of keeping this behind one small module.

No API key is needed for a local Ollama instance. What CAN fail instead:
the server not running, the requested model not actually pulled, or (if
you opt back into one — see OLLAMA_TIMEOUT_SECONDS below) a timed-out
generation — all raised here as OllamaError so callers have one exception
type to handle instead of guessing which requests.* exception showed up.

TIMEOUT: there is NO timeout by default. A small/weak local model can
legitimately take minutes to generate a response on modest hardware,
especially for /api/analyze's strict-JSON prompt — the original 120s
default was cutting those off before they could finish, which is worse
than just waiting. Requests now block until Ollama actually responds (or
the connection itself drops, which raises immediately — that path is NOT
timeout-gated). Set OLLAMA_TIMEOUT_SECONDS to a positive number of seconds
in backend/.env if you want a ceiling back (e.g. to fail fast against a
hung server instead of hanging the request indefinitely).

MODEL NAME RESOLUTION — this is the part that broke before:
`ollama pull llama3.1` registers the model on the server as
"llama3.1:latest", not bare "llama3.1". Ollama's /api/chat wants an exact
match against what's actually pulled, so sending the untagged name can
fail with "model 'llama3.1' not found" even though the model IS there —
that's exactly the bug reported. resolve_model() below fixes this by
checking GET /api/tags for what's actually installed and matching the
requested name against it (exact match, or "name" matching the part
before ":" in an installed "name:tag"), then sending Ollama the REAL
installed name — never the raw config string unchecked. If nothing
matches, it fails loudly with the actual list of installed models instead
of a bare "not found".
"""
import os

import requests

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")

# No timeout unless explicitly set. requests.* accepts timeout=None to mean
# "wait forever" — that's the default here on purpose (see module
# docstring). Empty/unset/"0" all mean "no timeout"; any other integer is
# used as a real ceiling in seconds.
_raw_timeout = os.getenv("OLLAMA_TIMEOUT_SECONDS", "").strip()
OLLAMA_TIMEOUT_SECONDS = int(_raw_timeout) if _raw_timeout and _raw_timeout != "0" else None


class OllamaError(RuntimeError):
    """Raised when the Ollama server can't be reached or returns an error."""


# Cache the resolved model name for the process lifetime so normal chat
# calls don't hit /api/tags every time. Cleared automatically if a chat
# call ever comes back "model not found" (e.g. the server was restarted
# with a different model pulled), so the next call re-resolves instead of
# repeating a stale, now-wrong guess forever.
_resolved_model_cache = {}


def list_models() -> list:
    """Raw list of model dicts from GET /api/tags — each has at least a
    'name' (or 'model') field like "llama3.1:latest"."""
    try:
        resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=OLLAMA_TIMEOUT_SECONDS)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise OllamaError(f"Could not reach Ollama at {OLLAMA_HOST} to list models: {e}") from e
    try:
        return resp.json().get("models", [])
    except ValueError as e:
        raise OllamaError("Ollama returned a non-JSON response listing models") from e


def resolve_model(requested: str) -> str:
    """
    Turns a requested model name (e.g. "llama3.1" from OLLAMA_MODEL) into
    the EXACT name Ollama has it registered under (e.g. "llama3.1:latest"),
    by checking what's actually installed rather than trusting the config
    string blindly.

    Match order: exact name match first, then "requested" matching the
    part before ":" in an installed "name:tag" (handles the untagged ->
    :latest case that caused the original bug). Raises OllamaError with
    the real list of installed models if nothing matches, so a mismatch
    is immediately diagnosable instead of a bare "not found".
    """
    if requested in _resolved_model_cache:
        return _resolved_model_cache[requested]

    models = list_models()
    if not models:
        raise OllamaError(
            f"No models are pulled on the Ollama server at {OLLAMA_HOST} yet. "
            f"Run `docker compose exec ollama ollama pull {requested}` "
            f"(or wait for the ollama-pull service in docker-compose.yml to finish)."
        )

    installed_names = [m.get("name") or m.get("model") for m in models]

    if requested in installed_names:
        _resolved_model_cache[requested] = requested
        return requested

    for name in installed_names:
        if name and name.split(":", 1)[0] == requested:
            _resolved_model_cache[requested] = name
            return name

    raise OllamaError(
        f"Model '{requested}' is not installed on the Ollama server at {OLLAMA_HOST}. "
        f"Installed models: {installed_names or '(none)'}. "
        f"Run `docker compose exec ollama ollama pull {requested}`, or set "
        f"OLLAMA_MODEL in backend/.env to one of the installed names above."
    )


def chat(system_prompt: str, messages: list, model: str = None, json_mode: bool = False) -> str:
    """
    messages: [{"role": "user"|"assistant", "content": "..."}] — no system
    entry in this list, it's passed separately and prepended here.

    json_mode=True sets Ollama's "format": "json", which constrains the
    model's output to valid JSON (supported by Ollama >= 0.1.9 for most
    models). It guarantees parseable JSON, not any particular schema —
    ai_analysis.py still validates the actual fields afterward.

    Returns the assistant's reply text (raises OllamaError on failure —
    callers decide whether that means "retry" or "fail the request").
    """
    requested_model = model or OLLAMA_MODEL
    resolved_model = resolve_model(requested_model)

    payload = {
        "model": resolved_model,
        "messages": [{"role": "system", "content": system_prompt}] + messages,
        "stream": False,
    }
    if json_mode:
        payload["format"] = "json"

    try:
        resp = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, timeout=OLLAMA_TIMEOUT_SECONDS)
        resp.raise_for_status()
    except requests.ConnectionError as e:
        raise OllamaError(
            f"Could not reach Ollama at {OLLAMA_HOST}. Is it running? "
            f"(`ollama serve` locally, or check the `ollama` service in docker-compose.yml)"
        ) from e
    except requests.Timeout as e:
        raise OllamaError(
            f"Ollama request timed out after {OLLAMA_TIMEOUT_SECONDS}s "
            f"(set via OLLAMA_TIMEOUT_SECONDS in backend/.env)"
        ) from e
    except requests.HTTPError as e:
        detail = ""
        try:
            detail = resp.json().get("error", "")
        except Exception:
            pass
        if "not found" in detail.lower():
            # The resolved model no longer exists on the server (removed,
            # or server restarted with different models pulled) — drop the
            # cached resolution so the next call re-checks instead of
            # repeating the same now-stale name forever.
            _resolved_model_cache.pop(requested_model, None)
        raise OllamaError(f"Ollama returned an error: {detail or e} (model requested: '{resolved_model}')") from e

    try:
        data = resp.json()
    except ValueError as e:
        raise OllamaError("Ollama returned a non-JSON response") from e

    return (data.get("message") or {}).get("content", "").strip()
