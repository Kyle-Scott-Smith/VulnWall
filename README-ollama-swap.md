# AI Analysis + Chatbot — local Ollama model

Both AI features — `POST /api/analyze` (per-finding analysis) and
`POST /api/chat` (scan-scoped chatbot) — call a **local Ollama model**. No API
key is needed and no data leaves your machine or network. They previously called
the Anthropic Claude API; this document also explains that swap and how to add a
provider back.

## Why a local model

No data leaves the environment, there is no per-call API cost, and it is a real
option for clients with data-sovereignty requirements. It is currently the
*only* backend; see [Adding another provider](#adding-another-provider).

## Files

- **`backend/ollama_client.py`** — the only file that talks to Ollama (HTTP via
  `requests`). Exposes:
  - `chat(system_prompt, messages, model=None, json_mode=False)` — used by both AI features;
  - `list_models()` — raw list from `GET /api/tags`;
  - `resolve_model(requested)` — turns a configured name into the exact installed name (see below).

  Every failure — server down, model missing, timeout, bad response — is raised
  as `OllamaError`, so callers have one exception type to handle.
- **`backend/ai_analysis.py`** — `OllamaVulnerabilityAnalyzer` (the old
  `ClaudeVulnerabilityAnalyzer` name is kept as an alias). Builds the grounded
  prompt, validates the JSON, retries, falls back to a template, caches, and
  computes the business priority score. Details: [`docs/PRIORITISATION.md`](docs/PRIORITISATION.md).
- **`backend/chatbot.py`** — `ScanChatbot.ask()`. Puts the current findings (first
  `CHAT_MAX_CONTEXT_VULNS`, default 300) in the system prompt, keeps the last 6
  history turns, and tells the model to answer only from that data. `OllamaError`
  propagates, and `/api/chat` returns it as a 502.
- **`backend/scanner.py`** — creates the analyzer/chatbot lazily on first use, runs
  analysis across findings with a thread pool (`AI_ANALYSIS_CONCURRENCY`), and
  exposes `GET /api/ollama-status`.
- **`docker-compose.yml`** — the `ollama` service (official `ollama/ollama` image,
  port `11434`, a named `ollama_models` volume so models survive
  `docker compose down`, a healthcheck) and the `ollama-pull` one-shot service.
  The `backend` service gets `OLLAMA_HOST=http://ollama:11434` and waits for
  Ollama to be healthy **and** `ollama-pull` to finish.
- **`backend/.env.example`** — `OLLAMA_MODEL`, `OLLAMA_TIMEOUT_SECONDS`,
  `AI_MAX_RETRIES`, `AI_ANALYSIS_CONCURRENCY`, `CHAT_MAX_CONTEXT_VULNS`.
- **`backend/requirements.txt`** — no `anthropic` package; `requests` (already
  needed by Jira and Tenable) carries the Ollama calls.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OLLAMA_HOST` | `http://ollama:11434` (compose); code fallback `http://localhost:11434` | Only override in `.env` if Ollama runs somewhere else. |
| `OLLAMA_MODEL` | `llama3.2:3b` in `.env.example`; code fallback `llama3.1` | **Keep this line in your `.env`** — the code's fallback model is *not* the one `ollama-pull` downloads. |
| `OLLAMA_TIMEOUT_SECONDS` | `120` | Per request. On timeout the finding falls back to the template. |
| `AI_MAX_RETRIES` | `2` | Extra full-prompt attempts per finding (3 total), then 1 simplified-prompt attempt, then the template. |
| `AI_ANALYSIS_CONCURRENCY` | `4` | Findings analysed in parallel. |
| `CHAT_MAX_CONTEXT_VULNS` | `300` | Findings included in the chatbot prompt. |

## Behaviour summary

**`/api/analyze`** takes `{vulnerabilities: [...]}` and returns
`{status: "analyzed", businessContextApplied, vulnerabilities: [...]}`. Each
finding gains `why`, `business_impact`, `fixes`, `confidence`, `priority_tier`,
`ai_generated`, `from_cache` and `business_priority_score`, and the list is
**sorted by `business_priority_score`**. The model is called in JSON mode and
the fields are validated; a down or unreachable Ollama server degrades to the
template fallback (`ai_generated: false`) instead of raising an error. Results are
cached in memory per CVE + questionnaire answers until the backend restarts.

**`/api/chat`** takes `{question, vulnerabilities, history?}` and returns
`{answer}`. It needs no sign-in.

## One-time setup: the model

`docker-compose.yml` includes an `ollama-pull` service that runs
`ollama pull llama3.2:3b` on every `docker compose up`; the backend won't start
until it finishes, so there is no manual step to forget. The first run downloads
~2 GB; afterwards it is a no-op because the model persists in the `ollama_models`
volume.

You can still pull manually:

```bash
docker compose exec ollama ollama pull llama3.2:3b
```

### Changing the model

`OLLAMA_MODEL` in `backend/.env` and the hard-coded pull command in the
`ollama-pull` service are **two separate places** — update both, then run
`docker compose up -d --force-recreate backend ollama-pull`. They don't need to
match character for character: `resolve_model` matches `OLLAMA_MODEL` against
whatever is installed, so just make sure what you set is something `ollama-pull`
(or a manual pull) actually downloads.

`llama3.2:3b` (~2 GB) is chosen to run acceptably on CPU-only machines. Larger
or stronger options if you have a GPU or more RAM: `llama3.1` (8B),
`llama3.1:70b`, `mixtral`. An optional NVIDIA GPU block is included, commented
out, under the `ollama` service. Structured-JSON reliability varies a lot between
models: if you see many findings with `ai_generated: false`, the model is
usually failing the JSON schema check — try a larger model or raise `AI_MAX_RETRIES`.

Expect analysis time to grow with the number of unique findings. Each finding is
a separate model call, and on a CPU-only machine Ollama may handle them mostly
one at a time regardless of `AI_ANALYSIS_CONCURRENCY`.

## Verifying it's working

```bash
curl http://localhost:5000/api/ollama-status
```

Returns what is requested, what is installed, and what it resolved to:

```json
{
  "ollama_host": "http://ollama:11434",
  "requested_model": "llama3.2:3b",
  "resolved_model": "llama3.2:3b",
  "available_models": ["llama3.2:3b"]
}
```

If Ollama is unreachable or the model isn't installed it returns HTTP 503 with
an `error` message listing what *is* installed. Check this first for any "model
not found" style problem.

Then run a scan through the upload flow and look at a finding's `ai_generated`
field: `true` means Ollama answered; `false` means the template fallback was used
(check `docker compose logs backend` for the specific `OllamaError`).

## Model-name resolution (the "model 'llama3.1' not found" fix)

*(Historical: the project originally used `llama3.1`; it now uses `llama3.2:3b`.
The fix applies to any model name.)*

`ollama pull llama3.1` registers the model as **`llama3.1:latest`**, not bare
`llama3.1`, and Ollama's `/api/chat` needs an exact name. With
`OLLAMA_MODEL=llama3.1`, every call sent the literal `"llama3.1"` and Ollama
correctly reported it as not found even though the model was installed.

`resolve_model(requested)` fixes this by reading `GET /api/tags` and matching:
exact name first, then the part before `:` in an installed `name:tag` (this
catches untagged-vs-`:latest`). It always sends Ollama the **real installed
name**. The resolution is cached for the process and cleared automatically if a
later call comes back "not found" (for example the server restarted with a
different model). If the model genuinely isn't installed it fails with the actual
list of what is:

```
Model 'mistral' is not installed on the Ollama server at http://ollama:11434.
Installed models: ['llama3.1:latest']. Run `docker compose exec ollama ollama
pull mistral`, or set OLLAMA_MODEL in backend/.env to one of the installed
names above.
```

If no models are installed at all, the error says so and mentions waiting for
the `ollama-pull` service.

## Adding another provider

`ollama_client.chat()` is the entire integration surface. To reintroduce Claude
(as a second option or a fallback), add an equivalent `claude_client.py` with the
same `chat(system_prompt, messages, ...)` signature, then choose between the two
in `ai_analysis.py` and `chatbot.py` based on an environment variable. Neither
`scanner.py` nor the frontend needs to know which provider is behind
`/api/analyze` or `/api/chat`.
