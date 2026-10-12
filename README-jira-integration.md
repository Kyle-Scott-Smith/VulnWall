# Jira Integration

Real Jira account linking, ticket pushing, and two-way status sync. The OAuth
flow, token storage and Jira API calls live in one Flask Blueprint,
`backend/jira_integration.py`, but other modules use it: `tickets.py` imports
its status helpers, and `scanner.py` registers the blueprint. The integration is
optional — without Jira keys the app works fully, and tickets are simply saved
in the app only.

## What it does

1. **Connect** — a user links their Atlassian account from the Profile page
   (OAuth 2.0 3LO). The connection is stored per **app user** (not per browser).
2. **Push** — on *Review & Send*, every approved ticket is created as a Jira
   `Task` in one fixed project (auto-created on first use).
3. **Status sync** — ticket statuses are kept in step with Jira in both directions:
   - **Jira → app:** `POST /api/tickets/sync` runs when the Tickets page opens and
     when "Sync with Jira" is clicked.
   - **App → Jira:** changing a Jira-linked ticket's status in the app moves the
     Jira issue first; the local change is saved only if Jira accepts it.
4. **Email** — if the user chose "Every scan sent to Jira" in Profile, a summary
   email lists the tickets created in Jira.

## Files

- **`backend/jira_integration.py`** — OAuth connect/callback, token storage
  (`jira_connections` table in the shared SQLite DB), project auto-creation,
  ticket creation, and the helpers `get_connection_record`,
  `fetch_issue_status_category`, `pick_transition`, `transition_issue_to_category`
  and the `STATUS_TO_JIRA_CATEGORY` map.
- **`backend/tickets.py`** — saves tickets and implements `PATCH /api/tickets/<ref>`
  and `POST /api/tickets/sync` using those helpers.
- **`backend/.env.example`** — documents every variable. Contains no secrets;
  copy it to `backend/.env` (gitignored).
- **`frontend/src/App.jsx`** — `JiraConnect` (Profile → Integrations), the push
  in `ReviewSendStep`, and the sync/edit logic in `TicketList`.

## Endpoints

| Route | Method | Access | Purpose |
|---|---|---|---|
| `/api/jira/status` | GET | none (empty when signed out) | Is Jira configured? Is this user connected? Which site? |
| `/api/jira/connect` | GET | Admin/Analyst | Redirects to Atlassian's consent screen |
| `/api/jira/callback` | GET | signed in | Atlassian redirects here; exchanges the code, stores tokens, site and the user's `accountId`, then redirects to the frontend |
| `/api/jira/disconnect` | POST | Admin/Analyst | Forgets the stored connection locally |
| `/api/jira/create-ticket` | POST | Admin/Analyst | Ensures the project exists, then creates one `Task` |
| `/api/tickets/sync` | POST | signed in | Pulls the status of every Jira-linked ticket |
| `/api/tickets/<ref>` | PATCH | Admin/Analyst | Status changes are applied in Jira first |

Viewers cannot connect Jira or push tickets (the Integrations section is hidden for them), but can sync statuses.
Request and response details: [`docs/API.md`](docs/API.md).

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `JIRA_CLIENT_ID`, `JIRA_CLIENT_SECRET` | — | From your app in the Atlassian Developer Console. If unset, every Jira route reports "not configured" (503) and `/status` says `configured: false`. |
| `JIRA_CALLBACK_URL` | `http://localhost:5000/api/jira/callback` | Must exactly match a Callback URL in the Console (Authorization tab). |
| `JIRA_FRONTEND_RETURN_URL` | `http://localhost:5173/?jira=connected` | Where the browser lands after connecting. |
| `JIRA_DEFAULT_PROJECT_KEY` | `VULN` in `.env.example` (no code default) | Project every ticket is pushed into. A request may override it with `projectKey`; with neither, the push fails with 400. |

## Setup

1. In the [Atlassian Developer Console](https://developer.atlassian.com/console/myapps/),
   open (or create) an **OAuth 2.0 (3LO)** app.
2. **Permissions → Jira API → Edit Scopes:** grant the following. The app requests
   all of them, and Atlassian rejects the authorisation if the app hasn't been granted them:

   | Scope | Why |
   |---|---|
   | `read:jira-work`, `write:jira-work` | Look up issues, create issues, read/transition statuses |
   | `read:jira-user` | Read the connecting user (`/myself`) to get their `accountId` |
   | `manage:jira-project` | Project settings |
   | `write:project:jira`, `read:project:jira` | **Creating a project** — Atlassian's create-project API only has these *granular* scopes; the classic `manage:jira-project` is not enough |
   | `offline_access` | Return a refresh token |

3. **Authorization tab:** add `http://localhost:5000/api/jira/callback` to the
   Callback URLs (or your `JIRA_CALLBACK_URL`).
4. Copy `backend/.env.example` to `backend/.env` and fill in `JIRA_CLIENT_ID`,
   `JIRA_CLIENT_SECRET` and `JIRA_DEFAULT_PROJECT_KEY`. `docker-compose.yml`
   already loads that file.
5. Recreate the backend: `docker compose up -d --force-recreate backend`.
6. Sign in as an Admin or Analyst → **Profile → Integrations → Connect Jira**.

**After changing scopes, disconnect and reconnect Jira** — tokens keep the scopes
they were issued with. A `401 "scope does not match"` when auto-creating a
project means a granular scope is missing or the token is old.

## How a ticket is pushed

On *Send to Jira*, for each approved ticket the frontend:

1. checks `/api/jira/status`; if Jira isn't connected, nothing is pushed and a
   banner explains the tickets were saved in the app only;
2. calls `/api/jira/create-ticket` with the finding's title and the AI "why" text;
3. records the returned `issueKey` and `url` on the ticket;
4. saves all tickets to the account (`POST /api/tickets`) — pushed or not — and
   records the scan (`POST /api/scans`).

The success screen reports *N of M tickets created in Jira*. Tickets that
weren't pushed show a **Not in Jira** badge on the Tickets page; changes to them
stay local.

### Project and board auto-creation

Every push targets one **fixed** project key. On each call the backend:

1. searches the connected site for that key — if found, uses it;
2. if not found, creates it once, as a team-managed **Kanban** software project
   (which comes with a default board), with the connecting user as lead;
3. if creation fails because the key is already in use but invisible to this
   account (project search only shows projects the account can browse), proceeds
   anyway — the key exists, so issues can be created in it.

Auto-creation needs the granular scopes above, a captured `accountId`, and
permission to create projects on the site. Otherwise the push fails with a
clear message (reconnect Jira if `accountId` is missing).

### What gets created

An issue of type **`Task`** with the finding's title as summary and a minimal
Atlassian Document Format description containing the AI "why" text (or "(no
description provided)"). The `priority` the frontend sends is currently **ignored**,
and the business impact and suggested fixes are **not** included. The returned
URL is built as `https://<site name>.atlassian.net/browse/<KEY>`.

## Status sync

App statuses map to Jira **status categories**, not status names (teams rename
statuses per project; categories are stable):

| App status | Jira category |
|---|---|
| Open | `new` |
| In Progress | `indeterminate` |
| Closed | `done` |

- **Jira → app (`POST /api/tickets/sync`):** for every ticket with a
  `jira_issue_key`, reads the issue's category and sets the local status to
  match. Issues that can't be read (deleted, no permission, network) are listed
  in `failed`, their local status is left alone, and they are **not** stamped as
  freshly synced. It is poll-on-demand, not a webhook. The Tickets page waits for
  the first sync before showing statuses so a stale "Open" never flashes.
- **App → Jira (`PATCH /api/tickets/<ref>`):** looks up the issue's available
  transitions and performs one that lands in the target category. If Jira's
  workflow doesn't allow that move from the current status, the request fails
  (502) and **nothing is saved**. If the ticket is Jira-linked but Jira isn't
  connected, the request fails (409). `jira_synced_at` is updated whenever the
  state is confirmed.
- **Assignee** is a team name in this app with no Jira equivalent; it is always local-only.
- Tickets never pushed to Jira are only ever updated locally.

## Limitations (by design or not yet done)

- **Tokens are stored unencrypted** in the `jira_connections` table (one row per
  app user, keyed by `users.id`; connections survive restarts). Encrypt them or
  use a secrets store before production use.
- **No token refresh.** Access tokens last about an hour; a refresh token is
  stored but never used. Reconnect from Profile when pushes start failing.
- **No revocation.** *Disconnect* only deletes the local record; Atlassian isn't told.
- **One site:** if the account can access several Jira sites, the first one
  returned is used.
- **One fixed project key** per deployment (or per request) — it never creates a
  project per user or per scan, on purpose.
- **Fixed issue type** `Task`; it must exist in the target project.
- **No priority, labels, components or assignee** are sent.
- **No webhooks:** Jira changes appear only after a sync.
- **Never commit `backend/.env`.** `backend/.env.example` is safe to commit.
