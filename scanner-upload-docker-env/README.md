# Scanner Upload Integration — Docker Demo Environment

A minimal, general-purpose Docker environment for the scan-upload wizard:
a **Vite + React** frontend (`frontend/`) and a **Flask** backend
(`backend/scanner.py`) that parses uploaded Trivy JSON scan reports. It's
intentionally "dumb" (no hardcoded routes/pages, no assumptions about
`App.jsx`'s internals) so you can keep building both sides without the
environment breaking.

## Run it

```bash
docker compose up --build
```

Then open:
- **http://localhost:5173** — the React dashboard/wizard
- **http://localhost:5000/api/health** — Flask backend health check

First run will be a bit slower (npm install + pip install inside the
images). After that, `docker compose up` alone is enough — no rebuild
needed for code changes on either side.

## How it stays "unbreakable" as the app grows

- **Live bind mounts, not baked-in copies.** `docker-compose.yml` mounts
  `frontend/` and `backend/` straight into their containers. Add new
  components, new files under `frontend/src/`, or new `.py` modules in
  `backend/` — Vite's dev server hot-reloads the frontend, and Flask's
  debug-mode reloader restarts the backend automatically. You never need
  to touch the Dockerfiles for this.

- **`node_modules` is isolated in the frontend container**, not your
  host, via the anonymous volume trick (`- /app/node_modules` after the
  bind mount). Your host doesn't need Node installed at all, and
  stale/incompatible local `node_modules` can't leak in and conflict with
  the container's.

- **Only dependency-manifest changes trigger a rebuild.** Each Dockerfile
  copies its dependency file (`package*.json` / `requirements.txt`) and
  installs in its own layer, before copying any source. So:
  - Editing `App.jsx` or `scanner.py`, adding a component or endpoint →
    just refresh the browser / let HMR + the Flask reloader do it. No
    rebuild.
  - Adding a new npm package or pip package → run
    `docker compose up --build` once to pick up the new dependency, then
    back to normal.

- **No app-specific assumptions.** Neither container knows or cares that
  this is a "security scanner dashboard" — the frontend container just
  serves whatever's in `frontend/src/` via Vite, and the backend
  container just runs whatever's in `backend/`. You can add routes,
  rename components, add more services, etc., without editing Docker
  files, as long as it's still a Vite frontend + Flask backend.

## Two services, one network

Compose gives the two containers a shared network and built-in DNS, so
they can always reach each other as `http://frontend:5173` and
`http://backend:5000` from *inside* the containers. The React app,
however, runs in your **browser** (outside any container), so it talks to
the backend via the port published on your host:

```js
// frontend/src/App.jsx
const API_BASE = "http://localhost:5000";
```

If you ever move the backend call into server-side code (e.g. a Vite
SSR/proxy layer running inside the frontend container), you'd switch that
one call to `http://backend:5000` instead — everything else stays the
same.

## Adding a dependency

Frontend:
```bash
docker compose exec frontend npm install <package-name>
docker compose restart frontend
```

Backend:
```bash
docker compose exec backend pip install <package-name>
# Then add it to backend/requirements.txt so it survives a rebuild,
# and run:
docker compose up --build backend
```
(or just stop and re-run `docker compose up --build`)

## Production-style build (optional)

The dev setup above is for demoing/iterating. If you eventually want a
static production build of the frontend to test:

```bash
docker compose exec frontend npm run build
docker compose exec frontend npm run preview
```

The Flask backend as configured (`debug=True`) is dev-only; swap in a
production WSGI server (e.g. gunicorn) before deploying it for real.

## Project layout

```
.
├── docker-compose.yml
├── frontend/
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx      # mounts <App />
│       └── App.jsx       # the wizard/dashboard — edit freely
└── backend/
    ├── Dockerfile
    ├── .dockerignore
    ├── requirements.txt
    └── scanner.py         # Flask API: /api/health, /api/upload-scan
```
Upload → Tenable cross-reference → Claude analysis → chat
`POST /api/upload-scan` parses the uploaded Trivy JSON as before,
then sends every CVE ID it finds to the Tenable.io API (workbench
vulnerability search, filtered by CVE) to check whether that CVE also
shows up anywhere in your org's already-scanned asset inventory. Each
finding gets a `tenable_exposure: { matched, instance_count, matches }`
field merged in. This is a read-only lookup against Tenable's existing
data — it does not launch a scan or touch any assets. If Tenable keys
aren't configured, upload still works; findings just won't have
`tenable_exposure` attached.
`POST /api/analyze` — unchanged: runs each finding through Claude,
returning `why`, `fixes`, `confidence`, `priority_tier` merged in. Feeds
`CveDetailStep` in the frontend.
`POST /api/chat` — new. Body: `{"question": "...", "vulnerabilities": [...], "history": [...]}`.
Powers the chat bubble in the bottom-right of the UI — answers questions
grounded only in the current scan's findings (e.g. "which CVEs affect
host X", "what's our most severe finding"). It has no access to anything
outside the current report.
Setup:
```bash
cp .env.example .env
# fill in TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY, ANTHROPIC_API_KEY
docker compose up --build
```
All three keys are optional independently — the app degrades gracefully:
no Tenable keys → uploads work, just without `tenable_exposure`; no
Anthropic key → uploads work, `/api/analyze` and `/api/chat` return a
clear 503 instead of crashing the backend.
Verified: `backend/scanner.py`'s routes were exercised end-to-end with
stubbed Tenable/Claude SDKs (Flask test client, no live credentials needed)
covering upload → Tenable cross-reference merge → Claude analysis → chat,
plus the error-handling paths (missing file, bad body, missing question).
Swap in real API keys and it's the same code path.
