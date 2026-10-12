# T170 Vulnerability Scanner — Docker Environment

A self-hostable, AI-assisted vulnerability management platform for small
businesses. Upload a scan report (or trigger a live scan), get an AI write-up
and a **business-impact priority** for every finding, chat about the results,
export them to Excel, and turn the findings that matter into tickets — optionally
pushed straight into Jira.

- **Frontend:** Vite + React (`frontend/`)
- **Backend:** Flask API (`backend/scanner.py` + blueprints), SQLite database
- **AI:** a local Ollama model (no API key, no data leaves your machine)
- **Scan sources:** Trivy (upload or live) and Tenable.io (upload or live, plus CVE cross-reference)

> **Documentation map**
>
> | File | What it covers |
> |---|---|
> | `SETUP_INSTRUCTIONS.txt` | Step-by-step Windows install for non-developers |
> | **README.md** (this file) | Overview, configuration, features, roles, schema, development, known issues |
> | [`docs/API.md`](docs/API.md) | Full endpoint reference: access rules, request bodies, responses, errors |
> | [`docs/PRIORITISATION.md`](docs/PRIORITISATION.md) | Exactly how the business-priority score and AI analysis work |
> | [`README-jira-integration.md`](README-jira-integration.md) | Jira OAuth, ticket push, two-way status sync |
> | [`README-ollama-swap.md`](README-ollama-swap.md) | The local Ollama AI backend and how to change models |

---

## Contents

1. [Quick start](#quick-start)
2. [Configuration](#configuration)
3. [Services](#services)
4. [Architecture overview](#architecture-overview)
5. [Using the app](#using-the-app)
6. [Roles and permissions](#roles-and-permissions)
7. [Scan sources](#scan-sources)
8. [AI analysis and prioritisation (summary)](#ai-analysis-and-prioritisation-summary)
9. [Email notifications and two-factor authentication](#email-notifications-and-two-factor-authentication)
10. [API endpoints](#api-endpoints)
11. [Database schema](#database-schema)
12. [Development workflow](#development-workflow)
13. [Running the tests](#running-the-tests)
14. [Security and production notes](#security-and-production-notes)
15. [Known issues and limitations](#known-issues-and-limitations)
16. [Project layout](#project-layout)

---

## Quick start

Requirements: Docker Desktop (or Docker Engine + Compose v2). Nothing else —
Node, Python and Trivy all run inside the containers. On Windows, follow
`SETUP_INSTRUCTIONS.txt` instead.

```bash
# 1. Create your environment file from the template
cp backend/.env.example backend/.env           # macOS/Linux
Copy-Item backend/.env.example backend/.env    # Windows PowerShell

# 2. Set FLASK_SECRET_KEY in backend/.env (see "Configuration" below)

# 3. Build and start everything
docker compose up --build
```

The `.env` file is **required**: `docker-compose.yml` loads `backend/.env` into
the backend container, so create it before the first `up`.

Then open:

| URL | What |
|---|---|
| http://localhost:5173 | The app (sign up to create an account) |
| http://localhost:5000/api/health | Backend health check |
| http://localhost:5000/api/ollama-status | Which AI model is requested / installed / resolved |
| http://localhost:8025 | Mailpit — dev inbox that catches alert emails and MFA codes |

**The first account you create becomes the Admin.** Every account created after
that starts as a Security Analyst until an Admin changes its role (see
[Roles and permissions](#roles-and-permissions)). Right after sign-up you are
asked to fill in a short business-context questionnaire (see
[Using the app](#using-the-app)).

**First run takes a while.** Besides the npm/pip installs, the `ollama-pull`
service downloads the `llama3.2:3b` model (~2 GB), and the backend does not
start until that finishes. The model is kept in the `ollama_models` volume, so
later runs start quickly. After the first build, `docker compose up` is enough —
code changes don't need a rebuild.

The template `.env` works for the core features (accounts, scan upload, AI
analysis, chatbot, dashboard, email via Mailpit). Jira, Google sign-in and
Tenable are optional and report "not configured" until their keys are filled in.

---

## Configuration

All backend configuration comes from environment variables. `docker-compose.yml`
loads `backend/.env` (copy it from `backend/.env.example`; **never commit
`backend/.env`**) and sets a few variables itself (`FLASK_DEBUG=1`,
`OLLAMA_HOST`, `PYTHONUNBUFFERED=1`).

Variables are read when the backend starts, so after editing `backend/.env`
recreate the container: `docker compose up -d --force-recreate backend`.

### Core

| Variable | Default | Purpose |
|---|---|---|
| `FLASK_SECRET_KEY` | random per start, **only if the variable is unset** | Signs the session cookie. Set a fixed, long random value, e.g. `python -c "import secrets; print(secrets.token_hex(32))"`. Without a fixed key everyone is signed out whenever the backend reloads. An empty `FLASK_SECRET_KEY=` line is *not* treated as unset by the code, so fill it in. |
| `AUTH_DB_PATH` | `backend/data/auth.db` | Location of the SQLite database (not in `.env.example`). |

### AI (Ollama)

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_HOST` | `http://ollama:11434` (set by compose; code fallback `http://localhost:11434`) | Where the Ollama server is. Only override if Ollama runs elsewhere. |
| `OLLAMA_MODEL` | `llama3.2:3b` in `.env.example` (code fallback `llama3.1`) | Model used for analysis and chat. Keep in sync with the `ollama-pull` service. |
| `OLLAMA_TIMEOUT_SECONDS` | `120` | Per-request timeout to Ollama. |
| `AI_MAX_RETRIES` | `2` | Extra attempts per finding with the full prompt before the simplified prompt / template fallback. |
| `AI_ANALYSIS_CONCURRENCY` | `4` | How many findings `/api/analyze` analyses in parallel. |
| `CHAT_MAX_CONTEXT_VULNS` | `300` | Max findings included in the chatbot's prompt. |

### Tenable.io (optional)

| Variable | Default | Purpose |
|---|---|---|
| `TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY` | — | Enables live Tenable scans and the CVE cross-reference on every scan. |
| `TENABLE_BASE_URL` | `https://cloud.tenable.com` | Tenable API base URL (used by the live-scan scanner plugin). |

### Jira (optional) — see [`README-jira-integration.md`](README-jira-integration.md)

| Variable | Default | Purpose |
|---|---|---|
| `JIRA_CLIENT_ID`, `JIRA_CLIENT_SECRET` | — | Atlassian OAuth 2.0 (3LO) app credentials. |
| `JIRA_CALLBACK_URL` | `http://localhost:5000/api/jira/callback` | Must match the callback URL registered in the Atlassian Developer Console. |
| `JIRA_FRONTEND_RETURN_URL` | `http://localhost:5173/?jira=connected` | Where the browser lands after connecting. |
| `JIRA_DEFAULT_PROJECT_KEY` | `VULN` in `.env.example` (no code default) | Project every pushed ticket goes into (auto-created on first use). |

### Google sign-in (optional)

| Variable | Default | Purpose |
|---|---|---|
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | — | OAuth client. The "Continue with Google" button is hidden until both are set. |
| `GOOGLE_CALLBACK_URL` | `http://localhost:5000/api/auth/google/callback` | Must match the redirect URI registered with Google. |
| `GOOGLE_FRONTEND_RETURN_URL` | `http://localhost:5173/` | Where the browser lands after sign-in. Also used as the "go review this" link in alert emails. |

### Email (scan alerts and MFA codes)

| Variable | Default | Purpose |
|---|---|---|
| `SMTP_HOST` | — (`mailpit` in `.env.example`) | SMTP server. If unset, email features are "not configured". |
| `SMTP_PORT` | `587` (`1025` in `.env.example`) | SMTP port. |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | — | Login, if the server needs one. |
| `SMTP_FROM_EMAIL` | `SMTP_USERNAME` | Sender address. Required when using Mailpit. |
| `SMTP_USE_TLS` | `true` (`false` in `.env.example`) | STARTTLS. Mailpit does not use TLS by default — keep `false` for it. For a real provider use `smtp.gmail.com` / `587` / `true` plus a username and app password. |

Email counts as "configured" only when `SMTP_HOST` **and** `SMTP_FROM_EMAIL` (or `SMTP_USERNAME`) are set.

### Frontend

The React app calls the backend at `API_BASE = "http://localhost:5000"`, hard-coded
at the top of `frontend/src/App.jsx`. Change it there if the backend is served
from somewhere else.

---

## Services

`docker compose up` starts five containers on one shared network:

| Service | Port | Purpose |
|---|---|---|
| `frontend` | 5173 | Vite dev server for the React app (hot reload) |
| `backend` | 5000 | Flask API (`python scanner.py`, debug mode); includes the Trivy CLI for live image scans |
| `ollama` | 11434 | Local LLM server used for AI analysis and the chatbot (has a healthcheck) |
| `ollama-pull` | — | One-shot job that pulls `llama3.2:3b`, then exits. The backend waits for it to succeed. |
| `mailpit` | 8025 (UI), 1025 (SMTP) | Fake mail server that catches all outgoing email (dev only) |

Start-up order: `ollama` (healthy) → `ollama-pull` (completed) → `backend`
(also waits for `mailpit`) → `frontend`.

Containers reach each other by service name (`http://ollama:11434`,
`mailpit:1025`). The React app runs in your browser, so it calls the backend
through the published port (`http://localhost:5000`).

An optional NVIDIA GPU block for the `ollama` service is included, commented
out, in `docker-compose.yml`.

---

## Architecture overview

```
Browser (React, :5173)
   │  fetch + session cookie
   ▼
Flask API (:5000) ── scanner.py registers the blueprints below
   ├── auth / google_auth / mfa ─── accounts, sessions, roles, email codes
   ├── business_context ─────────── questionnaire → business-impact weighting
   ├── scanner.py routes ────────── upload/trigger scans, AI analysis, chat, Excel export
   │      ├── scanners/ (trivy, tenable) ─ pluggable parsers / live scanners
   │      ├── ai_analysis.py, chatbot.py ─→ ollama_client.py ─→ Ollama (:11434)
   │      └── tenable_client.py ─────────→ Tenable.io (optional CVE cross-reference)
   ├── scans / dashboard ────────── scan history, recurring findings, overview stats
   ├── tickets / jira_integration ─ in-app tickets, Jira OAuth + push + status sync ─→ Atlassian
   ├── registry_credentials ─────── private container registry login for Trivy
   └── email_notifications ──────── scan alerts + MFA codes ─→ SMTP (Mailpit in dev)
   │
   ▼
SQLite: backend/data/auth.db (created automatically on first start)
```

Every feature is a Flask **blueprint** in its own file; `scanner.py` just
creates the app, enables CORS with credentials, and registers them. Each
blueprint creates (and migrates) its own tables at import time.

**Request pipeline for a scan** (`/api/upload-scan` and `/api/scan`):
parse with the matching scanner plugin → de-duplicate by CVE (keep the highest
CVSS; findings without a CVE are never merged) → cross-reference Tenable.io if
keys are set → sort by severity then CVSS → return. The scan is **not**
recorded to history at this point (see [Using the app](#using-the-app)).
`/api/analyze` is a separate call that adds AI text and the business priority score.

---

## Using the app

### 1. Sign up / sign in

Email + password, or "Continue with Google" if configured. Passwords need 8+
characters with a lowercase letter, an uppercase letter, a number and a symbol
(checked in both the UI and the API). Accounts with two-factor authentication
enabled must enter an emailed code after the first factor.

After a **first-time sign-up** (email or Google) the app shows a one-off
**business-context questionnaire** — sector, data sensitivity, how bad an outage
would be, internet exposure (and which systems are exposed), compliance scope,
air-gapped systems, revenue impact, prior breaches, and "what would concern you
most if compromised". The answers drive prioritisation (see
[`docs/PRIORITISATION.md`](docs/PRIORITISATION.md)). It can be edited later from
the Profile page. There is no skip button during onboarding.

A short **guided tutorial** starts automatically the first time a browser signs
in (stored in `localStorage`, so it is per browser, not per account) and can be
restarted from the Profile page. Technical terms throughout the UI have hover
glossary tooltips (`Glossary.jsx`).

### 2. The Upload Scan wizard (Admin / Analyst only)

| Step | What happens |
|---|---|
| **1. Upload Scan** | Drag in a `.json` report (Trivy or Tenable, max 20 MB) **or** switch to "Run a live scan". When results arrive the app shows how many findings were found (and how many are also confirmed in Tenable.io), then automatically runs AI analysis. **Next stays disabled ("Analyzing…") until analysis finishes.** |
| **2. AI Summary** | Headline numbers, a ranked risk list (top 3, expandable) you can filter by severity and sort (None / Business Priority / CVE / Severity / CVSS), and an **Export to Excel** button. Click a finding for its detail page. |
| **3. Select** | Table of all findings, **all selected by default**. Search, filter, sort and tick the ones to ticket. At least one must be selected. |
| **4. Validation** | Shows only the selected findings as **Validated** or **Needs Review**. A finding needs review if AI analysis fell back to the template, or its confidence is below 60%, or (when no AI result exists) the scanner gave no CVSS score or description. You can remove findings individually or "Remove All Non-Validated". |
| **5. Generate Ticket** | One draft ticket per selected finding. Approve or reject each (bulk approve/reject applies to whatever the current filters show). Every ticket must be decided before continuing; only approved tickets move on. |
| **6. Review & Send** | Final list of approved tickets. **Send to Jira** pushes each ticket to Jira if connected, saves all tickets to your account, records the scan to history (this is what triggers alert emails), and shows how many tickets reached Jira. If Jira isn't connected (or a push fails) tickets are still saved in the app and marked "Not in Jira". |

**The finding detail page** has tabs: *Why This Matters*, *Business Impact*
(only if non-empty, i.e. business context was available), and *Suggested Fix*
(first step shown, rest behind "Read more"); a criticality label; AI confidence
(highlighted when below 60%); and evidence links to the NVD and CVE.org records
(real CVE ids only) plus up to five scanner-supplied references. These are
plain links — the app does not claim to have verified anything against them.

A scan only counts as **completed** — and only then appears in Scan History and
the Dashboard — when it reaches step 6 and **Send** is pressed. Abandoned wizard
runs are never recorded. Wizard state lives in browser memory, so refreshing the
page loses it.

### 3. Dashboard, Scan History, Tickets, Profile

- **Dashboard** — Security Overview computed from the signed-in account's own
  history: totals and critical/medium counts from the latest scan, % change vs
  the previous scan, "new since last scan" (CVE ids not in the previous scan;
  everything counts as new for a first scan), a bar chart of the last 6 scans,
  a rule-based insight sentence, and up to 4 recent-activity tiles. Empty-state
  messages show before the first scan.
- **Scan History** — the full history: a severity trend across all scans,
  **recurring CVEs** (seen in more than one scan, with first/last seen and whether
  they are still open in the latest scan; top 25), headline totals (scan count,
  average findings, unique CVEs, resolved CVEs, scanners used) and a scan table.
- **Tickets** — your saved tickets (they follow your account across browsers and
  survive restarts). Opening the page automatically syncs statuses from Jira for
  Jira-linked tickets (statuses are hidden until that first sync finishes); a
  **Sync with Jira** button re-checks on demand. Filter by status
  (Open / In Progress / Closed) and priority. Analysts/Admins can edit status and
  assignee: a status change on a Jira-linked ticket is applied in Jira first and
  only saved if Jira accepts it; assignee is always local-only. Viewers see
  tickets read-only.
- **Profile** — account details (name; email unless the account signs in with
  Google; organisation and role are Admin-only), email notification settings,
  two-factor toggle, a "Default assign to" preference, the business-context
  summary (editable by Admin/Analyst), integrations (Connect Jira, Connect
  private registry — hidden for Viewers), restart-tutorial, and sign out.
- **Users** (Admin only) — list every account and change roles. The last
  remaining Admin cannot be demoted.
- **Chat widget** — a floating, scan-scoped assistant on every page. It answers
  only from the findings in the current scan (up to `CHAT_MAX_CONTEXT_VULNS`) and
  the last 6 conversation turns. It is empty until a scan has been loaded.

---

## Roles and permissions

Every account has a role: **`admin`**, **`analyst`** (default for new accounts)
or **`viewer`**. The first account created on a new database becomes Admin; on a
database that predates roles, the oldest account is promoted. Roles are enforced
server-side (`require_role`) — hiding tabs in the UI is only cosmetic.

| Capability | Viewer | Analyst | Admin |
|---|:-:|:-:|:-:|
| Sign in, edit own name/email, notification and MFA settings | ✓ | ✓ | ✓ |
| View Dashboard, Scan History, Tickets, business-context summary | ✓ | ✓ | ✓ |
| Sync ticket statuses from Jira | ✓ | ✓ | ✓ |
| Upload / run scans, run AI analysis, record completed scans | ✗ | ✓ | ✓ |
| Create tickets, edit ticket status / assignee | ✗ | ✓ | ✓ |
| Submit or edit the business-context questionnaire | ✗ | ✓ | ✓ |
| Connect/disconnect Jira and private registry; push tickets to Jira | ✗ | ✓ | ✓ |
| Change the organisation name (shared by every account) | ✗ | ✗ | ✓ |
| List all users and change their roles | ✗ | ✗ | ✓ |

Not gated at all (no sign-in needed): `/api/health`, `/api/ollama-status`,
`/api/scanners`, `/api/chat`, `/api/export`. Per-user "read" endpoints return an
empty result rather than an error when nobody is signed in. See
[`docs/API.md`](docs/API.md) for the exact rule on every route.

The organisation name is **one server-wide value** (stored in `app_settings`)
that all accounts inherit; it is not stored per user.

---

## Scan sources

Scanners are plugins in `backend/scanners/`. Every scanner turns its own format
into the same normalised finding, so the rest of the app never needs to know
which tool produced it.

**Normalised finding:** `cve`, `package`, `installedVersion`, `severity`
(title-cased: Critical / High / Medium / Low / Unknown), `cvss`, `title`,
`description`, `references`, `publishedDate`, `asset`, `source`. Later stages add
`tenable_exposure` (Tenable cross-reference) and the AI fields (`why`,
`business_impact`, `fixes`, `confidence`, `priority_tier`, `ai_generated`,
`from_cache`, `business_priority_score`).

### Trivy

- **Upload:** a Trivy JSON report (a top-level `Results` array).
- **Live scan** (`POST /api/scan`): `scan_type` = `image` (default), `fs` or `repo`;
  `mode` = `local` (Trivy CLI inside the backend container — the default and the
  one that works in this setup) or `docker` (see below); optional `timeout`
  (seconds, default 300).
- **Target rules:** the target must start with a letter or digit, be at most 512
  characters, and contain only letters, digits and `. _ / : @ -`. Image refs
  (`nginx:1.25`, `ghcr.io/team/app:latest`) and repo URLs work; **paths that
  start with `/` or `.` are rejected**, and `fs` scans run against paths inside
  the *backend container*, not your host.
- **Private registries:** connect one from the Profile page (host, username,
  password/token), then tick "Scan a private image from …" on the live-scan form
  (image scans only). In `local` mode the app runs `trivy registry login` with
  the password on stdin before scanning. The target must be the full image
  reference including the registry host.
- **`docker` mode** runs the official `aquasec/trivy` image via `docker run`,
  which needs the Docker CLI and socket inside the backend container. The
  bundled backend image has neither, so use `local`.

### Tenable.io

- **Upload:** a Tenable vulnerability export — either an object with a
  `vulnerabilities` array or a bare array whose items have a `plugin` object.
- **Live scan:** the target is an **existing Tenable scan ID**. The app launches
  that scan, polls until completed (up to 600 s), starts a vulnerability export
  and collects the chunks. Needs `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY`.
  The code notes this flow was written against Tenable's documented API but not
  exercised against a live account — check field names against a real export
  before relying on it.
- **CVE cross-reference (any scan):** when Tenable keys are set, every CVE is
  looked up in Tenable's workbench ("is this also in our scanned inventory?",
  one request per CVE) and the result is attached as `tenable_exposure`
  (`matched`, `instance_count`, `matches`). Without keys this step is silently
  skipped; a failed lookup never fails the scan.
- Findings with no CVE get an id like `PLUGIN-<id>`; no NVD/CVE.org links are
  offered for those.

### Excel export

`POST /api/export` (the **Export to Excel** button) returns a formatted `.xlsx`
with one row per finding: CVE, Title, Severity (colour-coded), CVSS, Business
Priority, Asset, Package, Installed Version, Why It Matters, Business Impact,
Suggested Fixes, AI Confidence (%), Tenable Exposure, Source, Published Date.
Works with or without AI analysis (AI columns are blank when absent).

### Adding a scanner

Subclass `BaseScanner` (`scanners/base.py`): implement `can_parse()` and
`parse()` (returning findings built with `normalize_vuln`), optionally `run()` for
live scans, and register an instance in `scanners/registry.py`. Nothing else
changes — upload detection, `/api/scan` and the UI pick it up.

---

## AI analysis and prioritisation (summary)

Two separate things happen to every finding — full details are in
[`docs/PRIORITISATION.md`](docs/PRIORITISATION.md):

1. **A deterministic `business_priority_score`** — CVSS (or a severity-based
   stand-in when CVSS is missing) multiplied by factors from the questionnaire:
   criticality tier, internet exposure, exposed systems, sensitive data,
   compliance, revenue impact, prior breach, and an air-gap discount. It is
   computed in code, not by the model, so ordering stays sensible even when
   Ollama is down. `/api/analyze` returns findings sorted by it. With no
   questionnaire it collapses to plain CVSS ordering.
2. **An AI write-up from the local Ollama model**: `why` (technical mechanism),
   `business_impact` (tailored to the questionnaire; empty without it), 2–4
   `fixes`, a `confidence` (0–100) and a `priority_tier` (P1–P4). The prompt is
   grounded in the scan data only, forbids inventing patched version numbers, and
   demands strict JSON. Each finding is retried (`AI_MAX_RETRIES`), then tried with
   a simplified prompt, then falls back to a template (`ai_generated: false`,
   confidence 30). Results are cached in memory per CVE + questionnaire answers.

If many findings come back with `ai_generated: false`, the model is usually
failing the JSON check — try a larger model (see
[`README-ollama-swap.md`](README-ollama-swap.md)).

---

## Email notifications and two-factor authentication

### Scan alert emails

Off by default; configured per user on the Profile page. When a scan is
**recorded** (end of the wizard) the app can send **one combined email** if:

- the master toggle is on **and** the scan has **new findings** at or above the
  chosen level — *Critical only*, *High and above* or *Medium and above*; or
- the master toggle is on **and** *Every scan sent to Jira* is chosen and tickets
  from the scan were actually created in Jira.

The Profile page presents these four as mutually exclusive radio options.
"New" means at or above the threshold **and** not present in that user's
immediately previous recorded scan (on a first scan everything above the
threshold counts as new). Each section of the email lists at most 20 items. A mail
failure or missing SMTP configuration is logged and never fails the request.

### Two-factor authentication (email code)

Opt-in per account from the Profile page. After the password (or Google) check,
a 6-digit code is emailed (valid 10 minutes, hashed at rest, 5 attempts, with a
resend button). Only after the code is verified is the session created.

> **If SMTP is not configured, sign-in skips the code and signs the user straight
> in** (for both password and Google logins). This is a deliberate "don't lock
> people out" fallback in `auth.py` / `google_auth.py` — note that the header
> comment in `mfa.py` still describes it as failing closed. Configure SMTP
> before relying on MFA.

---

## API endpoints

All routes are under `/api`. The frontend authenticates with a Flask session
cookie set at sign-in and sends `credentials: "include"`. Errors are
`{"error": "..."}` with 400/401/403/404/409/429/502/503 as appropriate.
**Access** column: *none* = no sign-in needed; *signed in* = any role;
*A/An* = Admin or Analyst; *Admin* = Admin only. Request/response details are in
[`docs/API.md`](docs/API.md).

**Core (`scanner.py`)**

| Method | Route | Access | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness check |
| GET | `/ollama-status` | none | Requested vs. installed vs. resolved AI model |
| GET | `/scanners` | none | List scan sources and whether each supports live scans |
| POST | `/upload-scan` | A/An | Upload a `.json` scan report; auto-detects the scanner |
| POST | `/scan` | A/An | Trigger a live scan (`scanner`, `target`, plus Trivy options) |
| POST | `/analyze` | A/An | AI analysis + business priority for a list of findings |
| POST | `/chat` | none | Scan-scoped chatbot question |
| POST | `/export` | none | Download findings as a formatted `.xlsx` |

**Accounts (`auth.py`, `google_auth.py`, `mfa.py`)**

| Method | Route | Access | Purpose |
|---|---|---|---|
| POST | `/auth/signup` | none | Create account (first account → Admin) and sign in |
| POST | `/auth/login` | none | Sign in (may return `mfa_required`) |
| POST | `/auth/logout` | none | Sign out |
| GET | `/auth/me` | none | Current user (or `authenticated: false`) |
| PATCH | `/auth/profile` | signed in | Edit name, email; organisation and role are Admin-only |
| PATCH | `/auth/notifications` | signed in | Email alert preferences (`enabled`, `level`, `jira`) |
| PATCH | `/auth/mfa` | signed in | Turn email MFA on/off |
| GET | `/auth/users` | Admin | List all users |
| PATCH | `/auth/users/<id>/role` | Admin | Change a user's role |
| GET | `/auth/google/status` | none | Is Google sign-in configured? |
| GET | `/auth/google/login` | none | Start Google OAuth (browser redirect) |
| GET | `/auth/google/callback` | none | Google OAuth redirect target |
| POST | `/auth/mfa/verify` | pending sign-in | Submit the emailed one-time code |
| POST | `/auth/mfa/resend` | pending sign-in | Resend the code |

**Business context, scans, dashboard**

| Method | Route | Access | Purpose |
|---|---|---|---|
| POST | `/business-context` | A/An | Save the questionnaire (overwrites) |
| GET | `/business-context/me` | none* | Saved answers, or `{completed: false}` |
| POST | `/scans` | A/An | Record a completed scan (and send alert emails) |
| GET | `/scans` | none* | Scan history, newest first |
| GET | `/scans/analysis` | none* | Long-term trend and recurring-CVE analysis |
| GET | `/dashboard/summary` | none* | Security Overview data |

**Tickets and integrations**

| Method | Route | Access | Purpose |
|---|---|---|---|
| GET | `/tickets` | none* | List the user's tickets |
| POST | `/tickets` | A/An | Bulk-save tickets (upsert by `id`) |
| PATCH | `/tickets/<ticket_ref>` | A/An | Update status / assignee (status pushed to Jira first) |
| POST | `/tickets/sync` | signed in | Pull current statuses from Jira |
| GET | `/jira/status` | none* | Is Jira configured / connected? |
| GET | `/jira/connect` | A/An | Start Atlassian OAuth |
| GET | `/jira/callback` | signed in | Atlassian OAuth redirect target |
| POST | `/jira/disconnect` | A/An | Remove the stored Jira connection |
| POST | `/jira/create-ticket` | A/An | Push one ticket into Jira |
| GET | `/registry/status` | none* | Is a private registry connected? |
| POST | `/registry/connect` | A/An | Save private registry credentials |
| POST | `/registry/disconnect` | A/An | Remove them |

\* Returns an empty / "not connected" result (HTTP 200) when nobody is signed in.
`/tickets/sync` and `/jira/callback` return 401 when signed out.

---

## Database schema

SQLite at `backend/data/auth.db` (override with `AUTH_DB_PATH`), shared by every
blueprint. Tables are created — and new columns added with `ALTER TABLE` —
automatically on startup, so there is no migration step. The file is local
runtime data and must not be committed. JSON columns hold JSON-encoded text;
timestamps are ISO-8601 UTC strings.

| Table | Columns |
|---|---|
| `users` | `id` PK, `name`, `email` (unique, case-insensitive), `password_hash` (PBKDF2 via werkzeug), `role` (`admin`/`analyst`/`viewer`, default `analyst`), `created_at`, `auth_provider` (`local`/`google`), `google_sub` (unique where set), `notify_on_critical` (master email toggle, default 0), `notify_level` (`none`/`critical`/`high`/`medium`, default `critical`), `notify_on_jira` (default 0), `mfa_enabled`, `mfa_code_hash`, `mfa_code_expires_at`, `mfa_code_attempts`, `organisation` (**legacy — no longer read or written**; see `app_settings`) |
| `app_settings` | `key` PK, `value` — server-wide settings; currently `organisation` (the shared organisation name) |
| `business_context` | `user_id` PK → users, `sector`, `sector_other`, `data_sensitivity` (JSON), `availability_impact`, `criticality_tier` (1–5), `internet_facing`, `compliance_scope` (JSON), `air_gapped`, `air_gapped_details`, `has_security_team`, `had_breach`, `top_concern`, `revenue_generating`, `exposed_systems` (JSON), `exposed_systems_other`, `created_at`, `updated_at` |
| `scans` | `id` PK, `user_id` → users, `scanner`, `source` (`upload`/`live`), `target`, `total`, `critical`, `high`, `medium`, `low`, `unknown`, `cve_ids` (JSON array), `created_at`. Only counts and CVE ids are stored — never the full findings. |
| `tickets` | `id` PK, `user_id` → users, `ticket_ref` (unique per user), `cve`, `title`, `priority` (`P1`/`P2`/`P3`), `status` (`Open`/`In Progress`/`Closed`), `assigned`, `date`, `cvss`, `confidence`, `fixes` (JSON), `why`, `jira_issue_key`, `jira_url`, `jira_synced_at`, `created_at`, `updated_at` |
| `jira_connections` | `user_id` PK → users, `access_token`, `refresh_token`, `cloud_id`, `site_name`, `account_id`, `created_at`, `updated_at` — **tokens stored in plain text** |
| `registry_connections` | `user_id` PK → users, `url`, `username`, `password`, `created_at`, `updated_at` — **password stored in plain text** |

The demo and dev database is a single file; deleting it wipes all accounts,
history and tickets (the next sign-up becomes Admin again).

---

## Development workflow

- **Live reload.** `frontend/` and `backend/` are bind-mounted into their
  containers. Vite hot-reloads the UI and Flask's debug reloader restarts the
  API on save — no rebuild for code changes.
- **`node_modules` stays in the container** (anonymous volume), so you don't
  need Node installed on your machine.
- **Adding or changing dependencies** — only manifest changes need a rebuild:

  ```bash
  # Backend: edit backend/requirements.txt, then
  docker compose up --build backend

  # Frontend: add the package inside the container (updates package.json)...
  docker compose exec frontend npm install <package>
  # ...or, after editing/pulling package.json / package-lock.json on the host,
  # rebuild and recreate the node_modules volume so the old one doesn't hide it:
  docker compose up --build -V frontend
  ```

  (`-V` renews anonymous volumes — the `node_modules` volume belongs to the
  *frontend* service.)
- **Changing the AI model:** update `OLLAMA_MODEL` in `backend/.env` *and* the
  model in the `ollama-pull` service in `docker-compose.yml` (two separate,
  hard-coded places), then `docker compose up -d --force-recreate backend ollama-pull`.
- **Resetting everything:** `docker compose down` keeps data. Delete
  `backend/data/auth.db` to wipe accounts/history; `docker compose down -v`
  also deletes the downloaded model (~2 GB re-download).
- **Useful checks:** `docker compose logs backend`, `docker compose logs ollama-pull`,
  http://localhost:5000/api/ollama-status, and the Mailpit inbox on :8025.

---

## Running the tests

```bash
# Backend (pytest, with coverage)
docker compose exec backend pip install -r requirements-dev.txt
docker compose exec backend pytest --cov=. --cov-report=term-missing

# Frontend (Vitest)
docker compose exec frontend npm test
```

**Backend** (`backend/tests/`, config in `pytest.ini`):

| File | Covers |
|---|---|
| `test_business_priority_score.py` | `compute_business_priority_score`: no-context fallback, tier multipliers, internet exposure, sensitive data, compliance, air-gap, a hand-calculated combined case. **Does not yet cover** `topConcern`, `exposedSystems`, `revenueGenerating` or `hadBreach`. |
| `test_jira_transitions.py` | Status → Jira-category map and `pick_transition` |
| `test_scanner_utils.py` | `normalize_vuln`, `dedupe_by_cve`, `sort_by_severity`, severity casing |
| `test_ticket_jira_sync.py` | `PATCH /api/tickets/<ref>` and `POST /api/tickets/sync` behaviour (Jira refusal, success, no connection, local-only edits, partial sync failures) using a temporary database |

**Frontend** (`frontend/src/__tests__/`, Vitest in `node` environment, no DOM):

| File | Covers |
|---|---|
| `applyScanResults.test.js` | Turning backend findings into the wizard's state, AI vs placeholder fields, Needs Review rules |
| `criticalityBand.test.js` | Criticality label thresholds (and documents the quirk described under Known issues) |
| `evidence.test.js` | NVD / CVE.org / reference links, `formatSyncedAt` |
| `splitSummary.test.js` | Lead-sentence splitting for "Read more" |

There are currently no automated tests for authentication, MFA, scan history,
the dashboard, business-context validation, the scanner plugins' parsers, or the
AI analyser/chatbot.

---

## Security and production notes

This setup is for development and demos: Flask runs with `debug=True` (the
interactive Werkzeug debugger is enabled and the server listens on
`0.0.0.0` — never expose it beyond localhost), Vite runs its dev server, and
Mailpit swallows all email.

For a real deployment:

- Serve the frontend as a static build (`npm run build`) and run Flask under a
  WSGI server such as gunicorn; set `API_BASE` accordingly.
- Set a fixed `FLASK_SECRET_KEY`, serve over HTTPS, and point `SMTP_*` at a real
  mail provider. CORS is currently `CORS(app, supports_credentials=True)` with
  Flask-CORS defaults (all origins) — restrict it to your frontend's origin.
- **Secrets at rest:** Jira access/refresh tokens and private-registry passwords
  are stored **unencrypted** in SQLite. Encrypt them or move them to a secrets
  store first.
- There is no login rate limiting, e-mail verification or password reset. MFA
  codes are limited to 5 attempts and 10 minutes.
- Session cookies use Flask defaults (no explicit `Secure` / `SameSite` settings).
- AI and scan inputs: scan targets are validated against a conservative pattern
  and passed to Trivy as a list (no shell), and the Trivy registry password is
  passed on stdin, never on the command line.
- `/api/chat` and `/api/export` accept any client-supplied findings without
  authentication.

What must never be committed (keep these in the repository `.gitignore`; the
real file uses repo-relative paths such as `<project>/backend/.env`):

```
backend/.env
.env
backend/data/auth.db
frontend/node_modules/
__pycache__/
*.pyc
```

`backend/.env.example` **is** committed — it holds no secrets.

---

## Known issues and limitations

These describe the code as it currently stands (found while auditing it against
this documentation). Items 1–4 are the most likely to surprise users.

1. **Ticket ids are reused.** The Review & Send step numbers new tickets
   `T-106`, `T-107`, … *every time*. Because tickets are saved with an upsert on
   `(user, ticket id)`, sending a second batch overwrites the earlier batch's
   rows with the same ids (and, until the page is reloaded, the Tickets list can
   show duplicates).
2. **Edits made in the Generate Ticket step are not carried forward.** Only the
   approve/reject decision moves on. Review & Send rebuilds each ticket from the
   finding: title = the finding's title, description = the AI "why" text,
   priority = P1/P2/P3 from severity (Critical → P1, High → P2, otherwise P3),
   assignee = Security Team for Critical, otherwise IT Operations.
3. **"Default assign to" (Profile) has no effect.** It is saved in
   `localStorage` but nothing reads it.
4. **Jira push is minimal:** the `priority` field is accepted but ignored (every
   issue is a plain `Task`), the Jira description contains only the AI "why"
   text, access tokens expire after ~1 hour with no refresh (reconnect from
   Profile), only the *first* accessible Jira site is used, and the issue URL
   assumes `https://<site name>.atlassian.net`. See
   [`README-jira-integration.md`](README-jira-integration.md).
5. **The criticality label ignores business context.** The detail page's
   High/Medium/Low criticality label is computed from `score ÷ ceiling` where the
   business multiplier cancels out algebraically, so it always equals the plain
   CVSS band (≥ 7.0 High, ≥ 4.0 Medium, else Low). Business context only changes
   the score and the ordering. A regression test documents this.
6. **Some collected or returned data is not used:** the questionnaire's
   "air-gapped details" and "has security team" answers are stored but never
   used (the form hint about excluding systems from scans is not implemented),
   and the AI's `priority_tier` is returned but never displayed — ticket
   priority comes from severity alone.
7. **The dashboard's "AI insight" is a fixed, rule-based sentence**, not model
   output. Ticket activity tiles are based on the 20 most recently updated tickets.
8. **Chat duplicates the latest question.** The frontend sends the new question
   both as `question` and as the last entry of `history`, so the model sees it twice.
9. **Trivy limits:** targets starting with `/` or `.` are rejected, and
   `mode: "docker"` cannot work inside the bundled backend container.
10. **AI analysis is one blocking request.** `/api/analyze` analyses every
    finding in a single HTTP call (4 at a time by default), with no cap or
    progress indicator, and Next stays disabled until it returns. Large scans on
    a CPU-only machine can take a long time; a per-call Ollama timeout falls
    back to the template for that finding. Tenable cross-referencing is also one
    sequential request per CVE.
11. **MFA fails open** when SMTP isn't configured (see above).
12. **Wizard and chat state are in-memory.** Refreshing the page discards an
    in-progress scan; the app also contains hard-coded demo findings that show
    before the first real scan is loaded.
13. **Product naming is inconsistent** across the project (README "T170
    Vulnerability Scanner", `package.json` "security-dashboard-demo", the
    tutorial "P972", the Jira doc "VulnScanner", the browser-storage prefix
    "vulnwiz-profile-prefs:").

---

## Project layout

```
.
├── docker-compose.yml
├── SETUP_INSTRUCTIONS.txt          # Windows install guide
├── README.md
├── README-jira-integration.md
├── README-ollama-swap.md
├── docs/
│   ├── API.md                      # endpoint reference
│   └── PRIORITISATION.md           # scoring + AI analysis details
├── frontend/
│   ├── Dockerfile                  # node:20-alpine, runs the Vite dev server
│   ├── package.json / package-lock.json
│   ├── vite.config.js              # dev server (0.0.0.0:5173, polling) + Vitest config
│   ├── index.html
│   └── src/
│       ├── main.jsx                # mounts <App />
│       ├── App.jsx                 # everything else: wizard, dashboard, tickets, profile, chat
│       ├── Tutorial.jsx            # in-app spotlight walkthrough
│       ├── Glossary.jsx            # plain-language glossary + <Term> tooltips
│       ├── evidence.js             # NVD / CVE.org links, reference cleaning, sync-time text
│       └── __tests__/              # Vitest unit tests
└── backend/
    ├── Dockerfile                  # Python 3.12 + Trivy CLI; runs `python scanner.py`
    ├── .env.example                # copy to .env (never commit .env)
    ├── requirements.txt / requirements-dev.txt / pytest.ini
    ├── scanner.py                  # Flask app + core routes (scan, analyze, chat, export), registers blueprints
    ├── auth.py                     # accounts, sessions, roles (require_role), notification/MFA settings, DB setup
    ├── google_auth.py              # Google sign-in
    ├── mfa.py                      # email one-time-code MFA
    ├── business_context.py         # questionnaire + validation + lookup
    ├── scans.py                    # scan history, completion + alert trigger, recurring-finding analysis
    ├── dashboard.py                # Security Overview data
    ├── tickets.py                  # in-app tickets + Jira status sync
    ├── jira_integration.py         # Jira OAuth, project auto-create, ticket push, status transitions
    ├── registry_credentials.py     # private container registry credentials for Trivy
    ├── email_notifications.py      # SMTP sending: scan alerts, MFA codes
    ├── ai_analysis.py              # AI analysis + business priority score
    ├── chatbot.py                  # scan-scoped chatbot
    ├── ollama_client.py            # Ollama HTTP client + model-name resolution
    ├── tenable_client.py           # Tenable.io CVE cross-reference
    ├── scanners/
    │   ├── base.py                 # BaseScanner interface
    │   ├── registry.py             # registered scanners + auto-detection
    │   ├── trivy.py                # Trivy parser + live scan
    │   ├── tenable.py              # Tenable parser + live scan
    │   └── utils.py                # normalize_vuln, dedupe_by_cve, sort_by_severity
    ├── tests/                      # pytest unit tests
    └── data/auth.db                # SQLite DB (created at runtime, not committed)
```
