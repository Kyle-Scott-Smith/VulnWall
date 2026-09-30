# AI Analysis + Chatbot — swapped from Claude API to a local Ollama model

Both AI features (`/api/analyze` and `/api/chat`) previously called the
Anthropic Claude API. They now call a local Ollama model instead — no
API key needed, no data leaving your machine/network.

## Why

Same reasoning laid out in the capstone's LLM-integration notes for a
local-model tier: no data leaves the environment, no per-call API cost,
and it's a real option to offer alongside a cloud provider for clients
with data-sovereignty requirements. This swap makes it the *only* backend
for now; see "Swapping back or adding another provider" below if you want
Claude available again alongside it.

## New files

- **`ollama_client.py`** — the only file that knows how to talk to Ollama
  (HTTP calls via `requests`, which was already a dependency). Exposes
  `chat(system_prompt, messages, ...)` (used by both AI features),
  `list_models()`, and `resolve_model(requested)` — the last one is what
  fixes the model-name bug described below. Raises `OllamaError` on any
  failure (server not running, model not installed, timeout) — callers
  decide what to do with that.

## Changed files

- **`ai_analysis.py`** — `ClaudeVulnerabilityAnalyzer` renamed to
  `OllamaVulnerabilityAnalyzer` (a `ClaudeVulnerabilityAnalyzer` alias is
  kept pointing at the same class, in case anything still imports the old
  name). No API key check anymore — Ollama doesn't need one. Same
  retry → simplified-prompt → template-fallback behavior as before;
  `_call_ollama()` catches `OllamaError` internally so a down/unreachable
  Ollama server (or, before the fix below, a model-name mismatch) degrades
  to the template fallback exactly like a failed Claude call used to,
  rather than raising.
- **`chatbot.py`** — same swap, `ScanChatbot` interface unchanged.
  `.ask()` now lets `OllamaError` propagate (same as it let Claude's
  `APIError` propagate before) — `scanner.py`'s `/api/chat` route already
  catches that and returns a 502.
- **`scanner.py`** — import updated to `OllamaVulnerabilityAnalyzer`. Also
  has a `GET /api/ollama-status` diagnostic route — see "Verifying it's
  working" below. Nothing else changed; both AI routes have the exact
  same request/response shape as before.
- **`requirements.txt`** — removed `anthropic`. `requests` was already
  there (used by `jira_integration.py` and `scanners/tenable.py`) and now
  also carries the Ollama HTTP calls, so no new dependency was needed.
- **`docker-compose.yml`** — added an `ollama` service (official
  `ollama/ollama` image, port `11434`, a named volume so pulled models
  survive `docker compose down`, a healthcheck) and an `ollama-pull`
  service that pulls the model automatically on `docker compose up` — see
  "One-time setup" below. The `backend` service gets
  `OLLAMA_HOST=http://ollama:11434` and waits on both.
- **`backend/.env.example`** — added `OLLAMA_MODEL` (set to `llama3.2:3b`;
  the code's fallback if it's unset is `llama3.1`, which is *not* pulled —
  so keep this line in your `.env`),
  `OLLAMA_TIMEOUT_SECONDS`, `AI_MAX_RETRIES`, `CHAT_MAX_CONTEXT_VULNS`.
  `OLLAMA_HOST` is set in `docker-compose.yml` directly since it's just
  the compose network's service name — only override it in `.env` if
  you're pointing at Ollama running somewhere else.

## Known issue we hit: "model 'llama3.1' not found" even after pulling it

*(Historical — at the time the project used `llama3.1`; it now uses
`llama3.2:3b`. The fix below still applies to any model name.)*

`ollama pull llama3.1` registers the model on the Ollama server as
**`llama3.1:latest`**, not bare `llama3.1`. Ollama's `/api/chat` endpoint
wants an exact name match — it does not resolve the untagged name to the
tagged one for you. With `OLLAMA_MODEL=llama3.1` in `.env`, every
`/api/analyze` and `/api/chat` call was sending the literal string
`"llama3.1"`, which Ollama correctly reported as not found, even though
the model was genuinely installed under a slightly different name.

Fixed in `ollama_client.py`: `resolve_model(requested)` checks
`GET /api/tags` for what's actually installed and matches the requested
name against it — exact match first, then matching the part before `:`
in an installed `name:tag` (this is what catches the untagged-vs-`:latest`
case). It sends Ollama the **real installed name**, never the raw
`OLLAMA_MODEL` string unchecked. Resolution is cached per-process and
cleared automatically if a later call comes back "not found" (e.g. server
restarted with different models pulled).

If a requested model genuinely isn't installed at all, `resolve_model`
now fails with the actual list of what IS installed, e.g.:

```
Model 'mistral' is not installed on the Ollama server at http://ollama:11434.
Installed models: ['llama3.1:latest']. Run `docker compose exec ollama ollama
pull mistral`, or set OLLAMA_MODEL in backend/.env to one of the installed
names above.
```

— instead of a bare "not found" with no indication of what to do about it.

## One-time setup: pull a model

`docker-compose.yml` now includes an `ollama-pull` service that pulls
`llama3.2:3b` automatically on `docker compose up` — the `backend` service
won't start until it finishes, so there's no manual step to forget or get
wrong. This only needs to happen once per machine; the model persists in
the `ollama_models` volume across restarts (`ollama-pull` runs again on
every `up`, but it's a no-op — Ollama skips a re-download of a model
that's already present).

If you'd rather pull manually (or need a different model — see below),
that still works too:

```bash
docker compose exec ollama ollama pull llama3.2:3b
```

**Changing the model**: `OLLAMA_MODEL` in `backend/.env` and the
hardcoded pull command in `docker-compose.yml`'s `ollama-pull` service are
two separate, hardcoded places — update both if you switch models. Kept
deliberately simple (no shared variable between them) rather than wiring
up compose-file variable substitution for one string, since you don't
need the two names to match *exactly* anyway — `resolve_model` matches
`OLLAMA_MODEL` against whatever's actually installed regardless of exact
tag, so just make sure whatever you set it to is something `ollama-pull`
(or a manual pull) actually brings down.

The default `llama3.2:3b` (~2 GB) is chosen to run acceptably on CPU-only
laptops. Larger/stronger if you have a GPU or more RAM: `llama3.1` (8B),
`llama3.1:70b`, `mixtral`. Whatever you pick, structured-JSON reliability
(needed for `/api/analyze`'s strict field contract) varies more between
models than with Claude — if you see a lot of `ai_generated: false`
(template fallback) in practice, that's usually the model failing the
JSON schema check in `ai_analysis.py`, not a bug; try a larger model or
increase the retry count via `AI_MAX_RETRIES`.

## Verifying it's working

```bash
curl http://localhost:5000/api/ollama-status
```

Returns exactly what's requested, what's installed, and what it resolved
to — check this first for any "model not found" style error instead of
guessing:

```json
{
  "ollama_host": "http://ollama:11434",
  "requested_model": "llama3.2:3b",
  "resolved_model": "llama3.2:3b",
  "available_models": ["llama3.2:3b"]
}
```

Then run a scan through the upload flow and check a finding's
`ai_generated` field in the response — `true` means Ollama answered
successfully; `false` means it fell back to the template (check
`docker compose logs backend` for the specific `OllamaError`, or hit
`/api/ollama-status` again).

## Swapping back or adding another provider

`ollama_client.chat()` is the entire integration surface. To reintroduce
Claude (e.g. as a second option, or a fallback), the change is isolated:
add an equivalent `claude_client.py` (or restore the old inline
`anthropic` calls), then choose which one `ai_analysis.py` /
`chatbot.py` call based on an env var. Neither `scanner.py` nor the
frontend need to know which provider is behind `/api/analyze` or
`/api/chat` — that boundary was kept deliberately thin for exactly this
kind of swap.
