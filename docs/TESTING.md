# Testing guide

## Run everything

```bash
# Backend (from backend/)
pip install -r requirements.txt -r requirements-dev.txt
pytest                       # add --cov=. --cov-report=term-missing for coverage

# Frontend (from frontend/) — one-time setup, then run
sh scripts/export-test-helpers.sh   # REQUIRED before npm test: exports 9 small helpers from App.jsx; no behaviour change (safe to re-run)
npm test
```

No test touches the network, a real Ollama, Jira, Google, Tenable, Trivy, Docker or an SMTP server. Tests that use the `app_env`
fixture (in `tests/conftest.py`) each get their own throwaway SQLite file and freshly imported modules, so they can run in any order.
A few older pure-logic files import app modules at the top of the file; `conftest.py` points `AUTH_DB_PATH` at a temporary file
before any of them load, so running the suite never touches `backend/data/auth.db`.

## Backend: `backend/tests/`

| File | Covers |
|---|---|
| `conftest.py` | Shared fixtures: `app_env` (whole app + temp DB + user/session helpers), `fake_response`, `fake_clock`, `import_fresh` |
| `test_auth.py` | Signup/login/logout/session, password rules, first-user-is-admin, RBAC, profile + notification settings, admin user directory, DB migrations |
| `test_mfa.py` | Email one-time codes: hashing, expiry, 5-attempt lockout, resend, replay, login hand-off |
| `test_google_auth.py` | OAuth state/CSRF checks, token exchange failures, account creation/linking, MFA hand-off |
| `test_business_context.py` | Questionnaire validation, availability→tier mapping, conditional fields, upsert, role gating, migration |
| `test_business_priority_score.py` | The scoring formula: every multiplier, amplifier, cap and the documented worked examples |
| `test_ai_analysis.py` | Prompt building, reply validation, retries, template fallback, caching |
| `test_ollama_client.py` | Model-name resolution, chat payloads, every error path |
| `test_chatbot.py` | Context building/truncation, history trimming and sanitising |
| `test_scanners_trivy.py` | Trivy parsing, CVSS selection, target validation (shell-injection guard), CLI/Docker commands, private-registry login |
| `test_scanners_tenable.py` | Tenable parsing, live-scan polling/timeouts, scanner registry/detection, plugin contract |
| `test_tenable_client.py` | CVE cross-reference lookups |
| `test_scanner_utils.py` | Normalisation, dedupe, severity sorting |
| `test_scanner_app.py` | HTTP API: upload, live scan, analyze, chat, export (.xlsx contents), status endpoints |
| `test_jira_transitions.py` | Status → Jira-category map and `pick_transition` (pure logic) |
| `test_tickets.py`, `test_ticket_jira_sync.py` | Ticket CRUD/upsert (`POST` returns `{tickets, created}`), isolation, Jira-honest status changes, sync mapping |
| `test_ticket_numbering.py` | Server-side `T-###` numbering: first is T-106, never reused across batches, per-user, explicit ids still update, malformed entries don't burn numbers |
| `test_jira_integration.py` | OAuth flow, issue lookup/transition, project auto-create, ticket creation |
| `test_registry_credentials.py` | Private-registry connection storage |
| `test_scans.py` | Scan recording, "new since last scan" diff, notification gating, history, long-term analysis |
| `test_dashboard.py` | Dashboard numbers, insight text, activity feed |
| `test_email_notifications.py` | Alert content/subjects, header-injection safety, SMTP sending |
| `test_integration_flows.py` | End-to-end journeys: signup → questionnaire → upload → analyze → tickets → dashboard; RBAC across the API; per-user isolation |

## Frontend: `frontend/src/__tests__/`

`applyScanResults` (confidence is `null` when the AI gave none; statuses are "No flags" / "Needs Review" with a reason for each flag), `criticalityBand`,
`splitSummary`, `evidence`, `confidence` ("Not assessed" and the 60% low-confidence rule), `ticketDrafts` (default priority/assignee, edits carried from the
Generate Ticket draft into the saved ticket, no id sent so the server numbers it, restoring drafts), plus `appHelpers` (nav tabs per role, password rules,
sorting/search, checkbox logic), `profilePrefs` (localStorage load/save), `tutorial`, and `glossary` (checks every `<Term k="…">` used in `App.jsx`, including
keys chosen inside a `k={…}` expression, exists in `Glossary.jsx`).

## Ticket guarantees (test_ticket_numbering.py, ticketDrafts.test.js, confidence.test.js)

* **Numbers are assigned by the server** and continue past the highest stored `T-###` for that user (never below T-106, which follows the demo tickets).
  A second batch can't overwrite the first. The wizard never sends an `id`.
* **Edits are carried forward:** the title, description, priority and assignee edited in Generate Ticket are what get saved and pushed.
* **No invented confidence:** a missing AI confidence is `null` end to end and displays as "Not assessed"; a real 0 is kept and counts as low.

## Tests that document problems (read these)

`xfail` (strict) tests describe behaviour that looks like a bug. They show as "xfailed" today and turn into failures the moment the bug
is fixed, telling you to delete the marker:

* `test_ai_analysis.py::test_a_json_scalar_reply_is_treated_as_a_failed_attempt`: a JSON `null`/number/`true` from the LLM raises `TypeError`.
* `test_scanners_trivy.py::test_absolute_filesystem_paths_are_valid_targets`: absolute paths like `/app` are rejected as scan targets.
* `test_scanner_app.py::test_chat_requires_sign_in`: `/api/chat` (and `/api/export`) need no login.
* `test_ticket_numbering.py::test_an_explicit_id_in_the_same_batch_is_never_reused_for_a_new_ticket`: an explicit id equal to the next free number
  (e.g. `T-106`) in the same batch as a new ticket is handed out twice, and the upsert makes the second overwrite the first. The shipped frontend never sends ids.
* `test_mfa.py::test_mfa_cannot_be_enabled_while_email_delivery_is_not_configured`: MFA is fail-closed now, but a user can still switch it on
  when email isn't configured and be locked out at their next sign-in, with no admin way to turn it off.

## MFA guarantees (test_mfa.py, test_google_auth.py)

* **Fails closed:** if the sign-in code can't be delivered (SMTP not configured or the send fails), password login returns 503 and Google
  login redirects back with `?authError=`; no session and no pending-MFA state is created. A wrong password still gets the plain 401.
* **Resend is capped** at `MAX_RESENDS` (3): the 4th request returns 429 and cancels the pending sign-in; total guesses per sign-in are bounded
  (4 codes x 5 attempts). A failed resend doesn't use up the allowance; a new sign-in starts fresh.
