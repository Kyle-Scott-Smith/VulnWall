# T170 Vulnerability Scanner — Docker Environment

A self-hostable, AI-assisted vulnerability management platform for small
businesses. Upload (or trigger) a scan, get AI analysis and a business-impact
priority for every finding, chat about the results, and push tickets to Jira.

- **Frontend:** Vite + React (`frontend/`)
- **Backend:** Flask API (`backend/scanner.py` + blueprints), SQLite database
- **AI:** local Ollama model (no API key, no data leaves the machine)

Feature-specific notes: [README-jira-integration.md](README-jira-integration.md),
[README-ollama-swap.md](README-ollama-swap.md).

## Quick start

Requirements: Docker Desktop (or Docker Engine + Compose v2). Nothing else —
Node, Python and Trivy all run inside the containers.

```bash
# 1. Create your environment file from the template
cp backend/.env.example backend/.env           # macOS/Linux
Copy-Item backend/.env.example backend/.env    # Windows PowerShell

# 2. Build and start everything
docker compose up --build
```

Then open:

| URL | What |
|---|---|
| http://localhost:5173 | The app (sign up to create an account) |
| http://localhost:5000/api/health | Backend health check |
| http://localhost:5000/api/ollama-status | Which AI model is requested / installed |
| http://localhost:8025 | Mailpit — dev inbox for alert emails and MFA codes |

**First run takes a while.** Besides the npm/pip installs, the `ollama-pull`
service downloads the `llama3.2:3b` model (~2 GB), and the backend does not
start until that finishes. The model is kept in the `ollama_models` volume,
so later runs start quickly. After the first build, `docker compose up` is
enough — code changes don't need a rebuild.

The template `.env` works out of the box for the core features (accounts,
scan upload, AI analysis, chatbot, dashboard, email via Mailpit). Jira,
Google sign-in and Tenable are optional and report "not configured" until
their keys are filled in — see the comments in `backend/.env.example`.

## Services

`docker compose up` starts five containers on one shared network:

| Service | Port | Purpose |
|---|---|---|
| `frontend` | 5173 | Vite dev server for the React app (hot reload) |
| `backend` | 5000 | Flask API; includes the Trivy CLI for live image scans |
| `ollama` | 11434 | Local LLM server used for AI analysis and the chatbot |
| `ollama-pull` | — | One-shot job that pulls `llama3.2:3b`, then exits |
| `mailpit` | 8025 (UI), 1025 (SMTP) | Fake mail server that catches all outgoing email (dev only) |

Containers reach each other by service name (`http://backend:5000`,
`http://ollama:11434`, `mailpit:1025`). The React app runs in your browser,
so it calls the backend through the published port
(`API_BASE = "http://localhost:5000"` in `frontend/src/App.jsx`).

## Architecture overview

```
Browser (React, :5173)
   │  fetch + session cookie
   ▼
Flask API (:5000) ── scanner.py registers the blueprints below
   ├── auth / google_auth / mfa ─── accounts, sessions, roles, MFA codes
   ├── business_context ─────────── questionnaire → business-impact weighting
   ├── scanner.py routes ────────── upload/trigger scans, AI analysis, chat, export
   │      ├── scanners/ (trivy, tenable) ─ pluggable parsers / live scanners
   │      ├── ai_analysis.py, chatbot.py ─→ ollama_client.py ─→ Ollama (:11434)
   │      └── tenable_client.py ─────────→ Tenable.io (optional)
   ├── scans / dashboard ────────── scan history, recurring findings, overview stats
   ├── tickets / jira_integration ─ in-app tickets, Jira OAuth + push/sync ─→ Atlassian
   ├── registry_credentials ─────── private container registry login for Trivy
   └── email_notifications ──────── scan alerts + MFA codes ─→ SMTP (Mailpit in dev)
   │
   ▼
SQLite: backend/data/auth.db (created automatically on first start)
```

Access control: every user has a role — `admin`, `analyst` (default) or
`viewer`. Endpoints that change data (upload/trigger scans, run analysis,
etc.) require `admin` or `analyst`; admins can change other users' roles.

## API endpoints

All routes are prefixed with `/api`. The frontend authenticates with a
session cookie set by `/api/auth/login` (or Google/MFA sign-in); routes that
read or change user data require a signed-in user, and some require a
specific role as noted.

**Core (`scanner.py`)**

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | Liveness check |
| GET | `/ollama-status` | Requested vs. installed vs. resolved AI model |
| GET | `/scanners` | List available scan sources (trivy, tenable) |
| POST | `/upload-scan` | Upload a scan report file (e.g. Trivy JSON) and parse it |
| POST | `/scan` | Trigger a live scan (`scanner`, `target`) |
| POST | `/analyze` | AI analysis for a list of vulnerabilities |
| POST | `/chat` | Scan-scoped chatbot question |
| POST | `/export` | Download findings as a formatted `.xlsx` report |

**Accounts (`auth.py`, `google_auth.py`, `mfa.py`)**

| Method | Route | Purpose |
|---|---|---|
| POST | `/auth/signup` | Create account (email format + password ≥ 8 chars validated) |
| POST | `/auth/login` | Sign in (may return an MFA challenge) |
| POST | `/auth/logout` | Sign out |
| GET | `/auth/me` | Current user |
| PATCH | `/auth/profile` | Edit profile (name, email; organisation is admin-only) |
| PATCH | `/auth/notifications` | Email alert preferences |
| PATCH | `/auth/mfa` | Turn email MFA on/off |
| GET | `/auth/users` | List users (admin) |
| PATCH | `/auth/users/<id>/role` | Change a user's role (admin) |
| GET | `/auth/google/status` | Is Google sign-in configured? |
| GET | `/auth/google/login` | Start Google OAuth |
| GET | `/auth/google/callback` | Google OAuth redirect target |
| POST | `/auth/mfa/verify` | Submit emailed one-time code |
| POST | `/auth/mfa/resend` | Resend the code |

**Business context, scans, dashboard**

| Method | Route | Purpose |
|---|---|---|
| POST | `/business-context` | Save the business-context questionnaire |
| GET | `/business-context/me` | Current user's saved answers |
| POST | `/scans` | Record a completed scan (triggers email alerts) |
| GET | `/scans` | Scan history |
| GET | `/scans/analysis` | Long-term / recurring-vulnerability analysis |
| GET | `/dashboard/summary` | Security Overview dashboard data |

**Tickets and integrations**

| Method | Route | Purpose |
|---|---|---|
| GET | `/tickets` | List the user's tickets |
| POST | `/tickets` | Create an in-app ticket |
| PATCH | `/tickets/<ticket_ref>` | Update status, assignee, etc. |
| POST | `/tickets/sync` | Sync ticket status with Jira |
| GET | `/jira/status` | Is Jira configured / connected? |
| GET | `/jira/connect` | Start Atlassian OAuth |
| GET | `/jira/callback` | Atlassian OAuth redirect target |
| POST | `/jira/disconnect` | Remove the stored Jira connection |
| POST | `/jira/create-ticket` | Push a ticket into Jira |
| GET | `/registry/status` | Is a private registry connected? |
| POST | `/registry/connect` | Save private registry credentials |
| POST | `/registry/disconnect` | Remove them |

## Database schema

SQLite at `backend/data/auth.db` (override with `AUTH_DB_PATH`). Tables are
created — and new columns added — automatically on startup, so there is no
migration step. This file is local runtime data and should not be committed.

| Table | Key columns |
|---|---|
| `users` | `id` PK, `name`, `email` (unique), `password_hash`, `role`, `organisation`, `auth_provider`, `google_sub`, notification prefs (`notify_on_critical`, `notify_level`, `notify_on_jira`), MFA fields (`mfa_enabled`, `mfa_code_hash`, `mfa_code_expires_at`, `mfa_code_attempts`), `created_at` |
| `app_settings` | `key` PK, `value` — server-wide settings (e.g. the shared organisation name) |
| `business_context` | `user_id` PK → users, `sector`, `data_sensitivity` (JSON), `availability_impact`, `criticality_tier`, `internet_facing`, `compliance_scope` (JSON), `air_gapped`, `has_security_team`, `had_breach`, `top_concern`, `revenue_generating`, `exposed_systems` (JSON), timestamps |
| `scans` | `id` PK, `user_id` → users, `scanner`, `source`, `target`, severity counts (`total`, `critical`, `high`, `medium`, `low`, `unknown`), `cve_ids`, `created_at` |
| `tickets` | `id` PK, `user_id` → users, `ticket_ref` (unique per user), `cve`, `title`, `priority`, `status`, `assigned`, `cvss`, `confidence`, `fixes`, `why`, `jira_issue_key`, `jira_url`, `jira_synced_at`, timestamps |
| `jira_connections` | `user_id` PK → users, `access_token`, `refresh_token`, `cloud_id`, `site_name`, `account_id`, timestamps |
| `registry_connections` | `user_id` PK → users, `url`, `username`, `password`, timestamps |

## Development workflow

- **Live reload.** `frontend/` and `backend/` are bind-mounted into their
  containers. Vite hot-reloads the UI and Flask's debug reloader restarts
  the API on save — no rebuild for code changes.
- **`node_modules` stays in the container** (anonymous volume), so you don't
  need Node installed on your machine.
- **Adding a dependency** — only manifest changes need a rebuild:
  ```bash
  # Frontend
  docker compose exec frontend npm install <package>
  # Backend: add the package to backend/requirements.txt, then
  docker compose up --build -V backend
  ```
  `-V` recreates the `node_modules` volume so newly installed packages
  aren't hidden by the old one.
- **Changing the AI model:** update `OLLAMA_MODEL` in `backend/.env` *and*
  the model in the `ollama-pull` service in `docker-compose.yml`.

## Running the tests

```bash
# Backend (pytest, with coverage)
docker compose exec backend pip install -r requirements-dev.txt
docker compose exec backend pytest --cov=. --cov-report=term-missing

# Frontend (Vitest)
docker compose exec frontend npm test
```

## What must never be committed

Keep these in the repository-root `.gitignore`:

```
backend/.env
backend/data/*.db
frontend/node_modules/
__pycache__/
```

`backend/.env.example` **is** committed — it holds no secrets.

## Production notes

This setup is for development and demos: Flask runs with `debug=True`, Vite
runs its dev server, and Mailpit swallows all email. For a real deployment,
serve the frontend as a static build (`npm run build`), run Flask under a
WSGI server such as gunicorn, point `SMTP_*` at a real mail provider, and
use a fixed `FLASK_SECRET_KEY`.

## Project layout

```
.
├── docker-compose.yml
├── README.md
├── README-jira-integration.md
├── README-ollama-swap.md
├── frontend/
│   ├── Dockerfile
│   ├── package.json / package-lock.json
│   ├── vite.config.js          # dev server + Vitest config
│   ├── index.html
│   └── src/
│       ├── main.jsx            # mounts <App />
│       ├── App.jsx             # main app: wizard, dashboard, profile, tickets
│       ├── Tutorial.jsx        # in-app walkthrough
│       ├── Glossary.jsx        # security terms glossary
│       ├── evidence.js         # finding-evidence helpers
│       └── __tests__/          # Vitest unit tests
└── backend/
    ├── Dockerfile              # Python 3.12 + Trivy CLI
    ├── .env.example            # copy to .env (never commit .env)
    ├── requirements.txt / requirements-dev.txt / pytest.ini
    ├── scanner.py              # Flask app + core routes, registers blueprints
    ├── auth.py                 # accounts, sessions, roles, DB setup
    ├── google_auth.py          # Google sign-in
    ├── mfa.py                  # email one-time-code MFA
    ├── business_context.py     # questionnaire + business-impact weighting
    ├── scans.py                # scan history + recurring-finding analysis
    ├── dashboard.py            # Security Overview data
    ├── tickets.py              # in-app tickets + Jira sync
    ├── jira_integration.py     # Jira OAuth + ticket push
    ├── registry_credentials.py # private registry credentials for Trivy
    ├── email_notifications.py  # scan alert emails
    ├── ai_analysis.py          # AI vulnerability analysis (Ollama)
    ├── chatbot.py              # scan-scoped chatbot (Ollama)
    ├── ollama_client.py        # Ollama HTTP client + model-name resolution
    ├── tenable_client.py       # Tenable.io CVE cross-reference
    ├── scanners/               # pluggable scan sources (trivy, tenable)
    ├── tests/                  # pytest unit tests
    └── data/auth.db            # SQLite DB (created at runtime, not committed)
```
