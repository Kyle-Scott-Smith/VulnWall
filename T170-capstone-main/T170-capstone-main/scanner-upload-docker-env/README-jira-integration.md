# Jira Integration — what was added

This adds real Jira account-linking + ticket-pushing to the app. It's
built to be as isolated as possible so it's safe to commit and push:

## New files (self-contained, no edits needed elsewhere to remove them)

- **`jira_integration.py`** — a Flask Blueprint containing *everything*
  Jira-related: OAuth connect/callback routes, in-memory token storage,
  and the ticket-creation endpoint. No other backend file needs to know
  it exists beyond the two lines added to `scanner.py` below.
- **`.env.example`** — documents every env var this feature reads.
  Contains no real secrets, safe to commit. Copy it to `.env` (gitignored)
  and fill in real values.

## Changes to existing files (minimal, additive)

**`scanner.py`** — 3 additions, nothing removed or restructured:
```python
from jira_integration import jira_bp
...
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
CORS(app, supports_credentials=True)   # was CORS(app) — now allows cookies
app.register_blueprint(jira_bp)
```
The `secret_key` and `supports_credentials=True` are needed because the
Jira routes use session cookies to remember which browser is connected
to which Jira account.

**`App.jsx`** — two additions:
1. A new `JiraConnect` component (self-contained, own state, only talks
   to `/api/jira/*`) rendered inside the existing `Profile` page under a
   new "Integrations" section, right above the sign-out button.
2. The `ReviewSendStep`'s existing "Send to Jira" button now actually
   calls the backend. If no Jira account is connected (or the server
   isn't configured), it **falls back to the old local-only demo
   behavior** rather than blocking the wizard — so the app still works
   exactly as before for anyone who hasn't set up Jira.

## New backend endpoints (all under `/api/jira/`)

| Route | Method | Purpose |
|---|---|---|
| `/api/jira/status` | GET | Is Jira configured on this server? Is this browser connected? |
| `/api/jira/connect` | GET | Redirects to Atlassian's real OAuth screen |
| `/api/jira/callback` | GET | Atlassian redirects here after approval; exchanges code for token, stores the user's accountId (needed to auto-create a project later) |
| `/api/jira/disconnect` | POST | Forgets the stored connection for this browser session |
| `/api/jira/create-ticket` | POST | Ensures the fixed project (`JIRA_DEFAULT_PROJECT_KEY`) exists — creating it with a default Kanban board on first use if it doesn't — then pushes one ticket (`title`, `description`, `priority`, optional `projectKey` to override the default) into it |

### How the project/board auto-creation works

Every `create-ticket` call always targets one **fixed** project key
(`JIRA_DEFAULT_PROJECT_KEY`, e.g. `VULN`) — not a new project per
session. On each call:

1. Search the connected Jira for a project with that key.
2. If found, use it immediately.
3. If not found, create it once — using a team-managed Kanban template,
   which gives it a default board automatically (Jira boards always
   belong to a project; there's no "board with no project" concept).
4. All future tickets reuse the same project/board — nothing new gets
   created after the first time.

This requires the connected Jira account to have permission to create
projects on that site. If it doesn't, project creation fails with a
clear error rather than silently doing nothing — that's a real
permission limitation on the Jira side, not something this code can
route around.

## ⚠️ Scope requirement — action needed in Developer Console

Auto-creating a project requires the **`manage:jira-project`** classic
scope in addition to the two you already added
(`read:jira-work`, `write:jira-work`). Go back to:

**Developer Console → VulnScanner → Permissions → Jira API → Edit Scopes**

and check the box for **"Manage project settings"** (`manage:jira-project`)
alongside the two you already have. Without this, project auto-creation
will fail with a 403 the first time a new `JIRA_DEFAULT_PROJECT_KEY` is used
(existing-project lookups will still work fine either way).

## Setup

1. Copy `.env.example` to `.env`, fill in your real `JIRA_CLIENT_ID` /
   `JIRA_CLIENT_SECRET` (from the Atlassian Developer Console app you
   already registered) and a real `JIRA_DEFAULT_PROJECT_KEY`.
2. Make sure `.env` is in `.gitignore` (see below — it currently isn't
   listed anywhere, so add it before committing).
3. Wire `.env` into `docker-compose.yml`'s `backend` service, e.g.:
   ```yaml
   backend:
     env_file:
       - .env
   ```
   (Not added automatically here since it touches a shared file outside
   this feature's own files — add it yourself, or ask and it can be
   done as a separate, clearly-labeled change.)
4. Add `http://localhost:5000/api/jira/callback` to the app's Callback
   URLs list in the Developer Console (Authorization tab) if it isn't
   already there.
5. Rebuild/restart the backend so it picks up the new env vars and the
   new blueprint.

## Important: add this to `.gitignore` before committing

```
.env
```

`.env.example` is safe to commit (no real values). `.env` itself must
never be committed — it will contain your real client secret.

## What's intentionally NOT included (by design, for isolation/safety)

- **Token storage is in-memory** (`_TOKENS` dict in `jira_integration.py`),
  keyed by Flask session — fine for a single-demo-user setup, gone on
  restart, not encrypted. Flagged clearly in that file's docstring.
  Swap for a real database before any multi-user/production use.
- **No token refresh logic** — access tokens expire in ~1 hour. The
  demo flow doesn't auto-refresh yet; reconnecting via the Profile page
  fixes it.
- **No revocation call to Atlassian on disconnect** — "Disconnect" only
  forgets the token locally, it doesn't tell Atlassian to invalidate it.
- **Project creation only handles one fixed project key at a time** —
  designed to always reuse `JIRA_DEFAULT_PROJECT_KEY` rather than
  creating a new project per user/session (avoids cluttering a real
  Jira site with duplicate empty projects). If you want per-user
  projects instead, that's a deliberate different design, not a bug fix.
