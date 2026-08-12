"""
Scan history persistence — same shape as tickets.py / business_context.py.

Why this exists: the dashboard ("Security Overview") previously showed
hardcoded placeholder numbers (47 total, 8 critical, 13 medium, a Jan-May
bar chart that never changed) no matter what a user actually scanned. This
gives every completed scan a real row in the same SQLite database as
accounts, keyed by user_id, so those numbers can be computed from what an
account has actually scanned instead of being fixed in the frontend.

What gets stored per scan: severity counts (critical/high/medium/low/
unknown + total) and the list of CVE ids found, not the full raw findings
(those already live transiently in the wizard / get turned into tickets —
duplicating the whole payload here isn't needed for dashboard stats and
would bloat the DB for no benefit). The CVE id list is what "new
vulnerabilities from the last scan" is computed from (see dashboard.py):
diff this scan's CVE ids against the previous scan's.

Endpoints registered by this blueprint (mounted at /api/scans):
  GET /api/scans -> the signed-in user's scan history, most recent first
"""

import json
from datetime import datetime, timezone

from flask import Blueprint, jsonify, session

from auth import _get_db

scans_bp = Blueprint("scans", __name__, url_prefix="/api/scans")

SEVERITIES = ("critical", "high", "medium", "low", "unknown")


def init_scans_db():
    """Creates the scans table if it doesn't exist yet. Called once at
    import time (see bottom of file), same as auth.init_db()."""
    conn = _get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id),
                scanner    TEXT,
                source     TEXT,
                target     TEXT,
                total      INTEGER NOT NULL DEFAULT 0,
                critical   INTEGER NOT NULL DEFAULT 0,
                high       INTEGER NOT NULL DEFAULT 0,
                medium     INTEGER NOT NULL DEFAULT 0,
                low        INTEGER NOT NULL DEFAULT 0,
                unknown    INTEGER NOT NULL DEFAULT 0,
                cve_ids    TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def record_scan(user_id, scanner_name, source, target, vulnerabilities):
    """Inserts one scan-history row for user_id, computed from the finalized
    vulnerability list (post-dedupe/cross-reference, same list the frontend
    receives). Call this once per completed upload or live scan; a no-op if
    nobody's signed in, since scan history is meaningless without an
    account to attach it to.

    scanner_name: which scanner produced the findings (e.g. "trivy").
    source: "upload" or "live", so the history can distinguish them later
    if needed.
    target: filename (upload) or scan target (live), for context only.
    """
    if not user_id:
        return

    counts = {sev: 0 for sev in SEVERITIES}
    cve_ids = []
    for v in vulnerabilities or []:
        sev = str(v.get("severity") or "unknown").strip().lower()
        counts[sev if sev in counts else "unknown"] += 1
        if v.get("cve"):
            cve_ids.append(v["cve"])

    conn = _get_db()
    try:
        conn.execute(
            """
            INSERT INTO scans (
                user_id, scanner, source, target, total,
                critical, high, medium, low, unknown, cve_ids, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id, scanner_name, source, target, len(vulnerabilities or []),
                counts["critical"], counts["high"], counts["medium"], counts["low"],
                counts["unknown"], json.dumps(cve_ids),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _row_to_json(row):
    return {
        "id": row["id"],
        "scanner": row["scanner"],
        "source": row["source"],
        "target": row["target"],
        "total": row["total"],
        "critical": row["critical"],
        "high": row["high"],
        "medium": row["medium"],
        "low": row["low"],
        "unknown": row["unknown"],
        "cveIds": json.loads(row["cve_ids"]) if row["cve_ids"] else [],
        "createdAt": row["created_at"],
    }


@scans_bp.route("", methods=["GET"])
def list_scans():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify([])

    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
        ).fetchall()
    finally:
        conn.close()

    return jsonify([_row_to_json(r) for r in rows])


init_scans_db()
