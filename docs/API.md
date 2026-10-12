# API Reference

All routes are prefixed with `/api` and served by the Flask backend on port 5000.

## Conventions

- **Format:** JSON request and response bodies, except `/upload-scan` (multipart) and `/export` (returns an `.xlsx` file).
- **Authentication:** a signed Flask session cookie set at sign-in. Browsers must send credentials (`fetch(..., { credentials: "include" })`).
- **Errors:** `{"error": "message"}` with an HTTP status code.
  - `401 {"error": "You must be signed in"}` — no valid session.
  - `403 {"error": "Your account role doesn't have permission to do this"}` — signed in, wrong role.
- **Access levels used below:**
  - **none** — no sign-in needed.
  - **signed in** — any role.
  - **A/An** — Admin or Analyst (Viewers get 403).
  - **Admin** — Admin only.
- **"Empty when signed out":** several read endpoints return an empty or "not connected" result (HTTP 200) instead of 401 when nobody is signed in. Each is marked.

---

## Core (`scanner.py`)

### `GET /health` — none
`{"status": "ok"}`

### `GET /ollama-status` — none
Diagnostic for the AI model.
- 200: `{"ollama_host", "requested_model", "resolved_model", "available_models": [...]}`
- 503: `{"ollama_host", "requested_model", "error"}` if Ollama is unreachable or the model isn't installed.

### `GET /scanners` — none
`{"trivy": {"supportsLiveScan": true}, "tenable": {"supportsLiveScan": true}}`.
`supportsLiveScan` only means the plugin implements `run()`; it does not check that Tenable keys are set.

### `POST /upload-scan` — A/An
Multipart form with a `file` field.
- Must end in `.json`, max 20 MB. The scanner is auto-detected (Trivy: top-level `Results` array; Tenable: `vulnerabilities` array or a list whose first item has `plugin`).
- 200: `{"status": "processed", "scanner": "trivy", "vulnerabilitiesFound": N, "vulnerabilities": [...]}`
- 400: `No file uploaded`, `No file selected`, `Only .json scan files are supported`, `File exceeds 20MB upload limit`, `Invalid JSON: ...`, `Unrecognized scan format. Supported scanners: ...`

Findings are de-duplicated by CVE (highest CVSS kept), cross-referenced with Tenable.io when configured, and sorted by severity then CVSS. **The scan is not recorded to history here** (see `POST /scans`).

### `POST /scan` — A/An
Trigger a live scan.
```json
{
  "scanner": "trivy",
  "target": "nginx:1.25",
  "scan_type": "image",
  "mode": "local",
  "timeout": 300,
  "usePrivateRegistry": false
}
```
- `scanner` and `target` are required. For Tenable, `target` is an existing Tenable scan ID.
- Trivy-only options: `scan_type` (`image` | `fs` | `repo`, default `image`), `mode` (`local` | `docker`, default `local`), `timeout` seconds (default 300), `usePrivateRegistry` (uses the credentials saved via `/registry/connect`).
- Trivy target rules: starts with a letter or digit, max 512 chars, only letters, digits and `. _ / : @ -`.
- 200: same shape as `/upload-scan`.
- 400: missing `scanner`/`target`, unknown scanner, no private registry connected, scanner doesn't support live scans.
- 502: the scan failed (invalid target, Trivy error or timeout, Tenable error or timeout).

### `POST /analyze` — A/An
```json
{ "vulnerabilities": [ { "cve": "CVE-2024-0001", "severity": "High", "cvss": 7.5, "...": "..." } ] }
```
Runs AI analysis on each finding (up to `AI_ANALYSIS_CONCURRENCY` at once), using the signed-in user's saved business context if any. Non-object entries are dropped.
- 200: `{"status": "analyzed", "businessContextApplied": true, "vulnerabilities": [...]}` — each finding gets `why`, `business_impact`, `fixes`, `confidence`, `priority_tier`, `ai_generated`, `from_cache`, `business_priority_score`. The list is **sorted by `business_priority_score`, highest first**.
- 400: `Expected a 'vulnerabilities' array`.
- Ollama failures never produce an error; the affected finding falls back to a template with `ai_generated: false`.

### `POST /chat` — none
```json
{ "question": "Which CVEs affect host X?", "vulnerabilities": [ ... ], "history": [ {"role": "user", "content": "..."} ] }
```
`history` is optional (last 6 turns used). Answers only from the supplied findings (first `CHAT_MAX_CONTEXT_VULNS`).
- 200: `{"answer": "..."}`
- 400: missing `question`, `vulnerabilities` not an array, `history` not an array.
- 502: `Chat request failed: ...` (e.g. Ollama unreachable).

### `POST /export` — none
`{"vulnerabilities": [ ... ]}` → downloads `vulnerability-report-YYYY-MM-DD.xlsx` (sheet "Vulnerabilities", frozen header, filters, severity colouring). Columns: CVE, Title, Severity, CVSS, Business Priority, Asset, Package, Installed Version, Why It Matters, Business Impact, Suggested Fixes, AI Confidence (%), Tenable Exposure, Source, Published Date. 400 if `vulnerabilities` isn't an array.

---

## Accounts (`auth.py`, `google_auth.py`, `mfa.py`)

User object used in several responses:
```json
{ "name", "email", "authProvider": "local|google", "notifyOnCritical": false,
  "notifyLevel": "critical", "notifyOnJira": false, "mfaEnabled": false,
  "role": "admin|analyst|viewer", "organisation": "" }
```

### `POST /auth/signup` — none
`{"name", "email", "password"}`. Password: 8+ chars with lowercase, uppercase, number and symbol. The **first account on a database becomes Admin**; others are Analysts. Signs the user in immediately.
- 200: `{"status": "signed_up", "name", "email", "role"}`
- 400: missing fields, invalid email, weak password. 409: email already registered.

### `POST /auth/login` — none
`{"email", "password"}`
- 200: `{"status": "signed_in", ...user}` or `{"status": "mfa_required", "email"}` (a code was emailed; no session yet).
- If MFA is on but SMTP isn't configured, the response is `signed_in` (MFA is skipped).
- 401: invalid credentials (same message for unknown email), or a Google-only account (told to use Google).

### `POST /auth/logout` — none
`{"status": "signed_out"}` (also clears a pending MFA sign-in).

### `GET /auth/me` — none
`{"authenticated": false}` or `{"authenticated": true, ...user}`.

### `PATCH /auth/profile` — signed in
Any of `name` (≤100 chars), `email`, `organisation` (≤120 chars), `role`.
- `email`: valid and unique (409 if taken); refused (400) for Google accounts.
- `organisation`: Admin only (403) — one value shared by every account.
- `role`: Admin only; changes the **caller's own** role; refuses to remove the last Admin (400). Use `/auth/users/<id>/role` to change others.
- Returns the updated user. 400 `Nothing to update` for an empty body.

### `PATCH /auth/notifications` — signed in
Any of `enabled` (bool, master switch), `level` (`none` | `critical` | `high` | `medium`), `jira` (bool).
Returns `{"notifyOnCritical", "notifyLevel", "notifyOnJira"}`. 400 for invalid values or an empty body.

### `PATCH /auth/mfa` — signed in
`{"enabled": true}` → `{"mfaEnabled": true}`. Takes effect at the next sign-in.

### `GET /auth/users` — Admin
`[{"id", "name", "email", "role", "authProvider", "createdAt"}, ...]` oldest first.

### `PATCH /auth/users/<id>/role` — Admin
`{"role": "admin|analyst|viewer"}` → the updated user. 400 invalid role or last Admin; 404 unknown user.

### Google sign-in
- `GET /auth/google/status` — none → `{"configured": bool}`.
- `GET /auth/google/login` — none. Browser redirect to Google (503 JSON if not configured). Must be a real navigation, not `fetch`.
- `GET /auth/google/callback` — none. Redirects to `GOOGLE_FRONTEND_RETURN_URL` with:
  - nothing extra — signed in;
  - `?newAccount=1` — a new account was created (the app then shows the questionnaire);
  - `?mfaRequired=1&email=...` — MFA code sent, finish at `/auth/mfa/verify`;
  - `?authError=...` — cancelled, state mismatch, token/profile failure, unverified Google email.
  An existing local account with the same email is linked to the Google identity.

### Email MFA
- `POST /auth/mfa/verify` — requires a pending sign-in. `{"code": "123456"}` → `{"status": "signed_in", ...user}`. 400 no pending sign-in / no code / expired; 401 incorrect; 429 after 5 wrong attempts (the code is invalidated).
- `POST /auth/mfa/resend` — requires a pending sign-in → `{"status": "code_resent"}`. 503 if SMTP isn't configured.

Codes: 6 digits, valid 10 minutes, stored hashed.

---

## Business context (`business_context.py`)

### `POST /business-context` — A/An
Creates or overwrites the caller's answers.

| Field | Required | Allowed values |
|---|---|---|
| `sector` | yes | `healthcare`, `banking_finance`, `government_public_sector`, `education`, `technology_saas`, `retail_ecommerce`, `manufacturing_industrial`, `energy_utilities`, `legal`, `other` |
| `sectorOther` | if sector is `other` | free text |
| `dataSensitivity` | yes (list) | `credentials`, `financial`, `medical`, `pii`, `intellectual_property`, `none` (`none` can't be combined) |
| `availabilityImpact` | yes | `life_safety`(tier 1), `major_disruption`(2), `moderate_disruption`(3), `minor_inconvenience`(4), `no_impact`(5) |
| `internetFacing` | yes | `public`, `internal`, `mixed` |
| `exposedSystems` | if `public`/`mixed` (list) | `website`, `admin_panel`, `remote_access`, `api`, `other` |
| `exposedSystemsOther` | if list contains `other` | free text |
| `complianceScope` | yes (list) | `hipaa`, `pci_dss`, `gdpr`, `soc2`, `iso27001`, `fedramp_nist`, `none` (`none` can't be combined) |
| `airGapped` | yes | boolean |
| `airGappedDetails` | no | free text (stored, not otherwise used) |
| `hasSecurityTeam` | no | boolean or omitted (stored, not otherwise used) |
| `revenueGenerating` | yes | boolean |
| `hadBreach` | yes | `yes`, `no`, `not_sure` |
| `topConcern` | yes | `revenue_loss`, `customer_trust`, `legal_regulatory`, `physical_safety`, `operational_downtime` |

200: `{"status": "saved", "criticalityTier": 1-5}`. 400 with a specific message on validation failure.

### `GET /business-context/me` — empty when signed out
`{"completed": false}` or `{"completed": true, ...all fields above...}`.

---

## Scan history and dashboard (`scans.py`, `dashboard.py`)

### `POST /scans` — A/An
Records a scan as **completed** and sends alert emails if the user's preferences match. Called by the Review & Send step.
```json
{ "scanner": "trivy", "source": "upload", "target": "report.json",
  "vulnerabilities": [ ... ],
  "jiraTickets": [ { "issueKey": "VULN-1", "url": "...", "title": "...", "priority": "P1", "cve": "CVE-..." } ] }
```
`jiraTickets` is optional (entries without `issueKey` are ignored). Stores severity counts and the CVE id list only. 200 `{"status": "recorded"}`; 400 if `vulnerabilities` isn't an array.

### `GET /scans` — empty when signed out
Array, newest first: `{"id", "scanner", "source", "target", "total", "critical", "high", "medium", "low", "unknown", "cveIds", "createdAt"}`.

### `GET /scans/analysis` — empty when signed out
```json
{ "hasScans": true,
  "totals": { "scanCount", "avgFindingsPerScan", "uniqueCvesSeen", "resolvedCves", "recurringCveCount", "scannerBreakdown": {"trivy": 3} },
  "trend": [ { "label": "Aug 9", "date", "total", "critical", "high", "medium", "low", "unknown" } ],
  "recurring": [ { "cve", "occurrences", "firstSeen", "lastSeen", "stillOpen" } ],
  "scans": [ ...same rows as GET /scans... ] }
```
`trend` is oldest first (all scans); `recurring` lists CVEs seen in more than one scan, most occurrences first, still-open ahead of resolved, capped at 25. Signed out or no scans: `{"hasScans": false, "totals": {}, "trend": [], "recurring": [], "scans": []}`.

### `GET /dashboard/summary` — empty when signed out
```json
{ "totalVulnerabilities", "totalDeltaPct", "critical", "medium", "newSinceLastScan",
  "chart": [ { "label", "count" } ],
  "aiInsight": "...", "recentActivity": [ { "tag", "label" } ], "hasScans": true }
```
Figures come from the latest scan; `totalDeltaPct` is the % change vs the previous scan (`null` if none); `chart` is the last 6 scans, oldest first; `recentActivity` has at most 4 tiles (tags `Scan`, `Ticket`, `Resolved`, `Critical`). `aiInsight` is a rule-based sentence, not model output.

---

## Tickets (`tickets.py`)

Ticket object:
```json
{ "id": "T-106", "cve", "title", "priority": "P1|P2|P3", "status": "Open|In Progress|Closed",
  "assigned", "date", "cvss", "confidence", "fixes": [], "why",
  "jiraIssueKey", "jiraUrl", "jiraLinked": true, "jiraSyncedAt": "ISO or null" }
```

### `GET /tickets` — empty when signed out
Array of the caller's tickets, oldest first.

### `POST /tickets` — A/An
Body: an **array** of ticket objects (`id` and `title` required; malformed entries are skipped). Upserts on `(user, id)`. 201 with the caller's full ticket list. 401 if signed out; 400 if not an array.

### `PATCH /tickets/<ticket_ref>` — A/An
`{"status"?: "Open|In Progress|Closed", "assigned"?: "..."}`.
- For a ticket **linked to Jira**, a status change is applied in Jira first (via the status category: Open → *new*, In Progress → *indeterminate*, Closed → *done*) and saved locally only if Jira accepts it.
- `assigned` is always local-only.
- 200 with the updated ticket. 400 nothing to update / unknown status; 404 not found; 409 ticket is Jira-linked but Jira isn't connected; 502 Jira refused or was unreachable (nothing is changed).

### `POST /tickets/sync` — signed in (any role)
Pulls the current status of every Jira-linked ticket (Jira status category → Open / In Progress / Closed).
- 200: `{"updated", "checked", "failed": ["VULN-3"], "syncedAt", "tickets": [...]}` — `failed` lists issues that couldn't be checked; their local status is left alone.
- 400 `{"error": "No Jira account connected.", "code": "jira_not_connected"}`; 401 if signed out.

---

## Jira (`jira_integration.py`)

### `GET /jira/status` — empty when signed out
`{"configured": false, "connected": false}`, `{"configured": true, "connected": false}` or `{"configured": true, "connected": true, "site": "my-site"}`.

### `GET /jira/connect` — A/An
Browser redirect to Atlassian's consent screen (503 JSON if `JIRA_CLIENT_ID`/`SECRET` are unset).

### `GET /jira/callback` — signed in
Atlassian's redirect target. Verifies the OAuth `state`, exchanges the code, stores the tokens, site and the user's Atlassian `accountId`, then redirects to `JIRA_FRONTEND_RETURN_URL`. 400 on state mismatch, missing code, token failure or no accessible site; 401 if signed out.

### `POST /jira/disconnect` — A/An
Deletes the stored connection locally (Atlassian is not told). `{"status": "disconnected"}`.

### `POST /jira/create-ticket` — A/An
`{"title": "...", "description": "...", "priority": "P1", "projectKey": "VULN"}` — `title` required; `projectKey` defaults to `JIRA_DEFAULT_PROJECT_KEY`; `priority` is accepted but **not used**.
Ensures the project exists (auto-creating a Kanban project the first time), then creates a `Task`.
- 200: `{"status": "created", "issueKey": "VULN-1", "url": "https://<site>.atlassian.net/browse/VULN-1"}`
- 400 missing title / no project key; 401 no Jira connected; 502 project creation failed or Jira rejected the issue; 503 Jira not configured.

---

## Private registry (`registry_credentials.py`)

- `GET /registry/status` — empty when signed out → `{"connected": false}` or `{"connected": true, "url", "username"}` (never the password).
- `POST /registry/connect` — A/An. `{"url": "ghcr.io", "username", "password"}` (all required) → `{"status": "connected", "url", "username"}`.
- `POST /registry/disconnect` — A/An → `{"status": "disconnected"}`.

One registry per user; credentials are stored unencrypted and used for Trivy image scans when `usePrivateRegistry` is true.
