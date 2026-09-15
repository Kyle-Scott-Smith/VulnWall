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
  GET  /api/scans          -> the signed-in user's scan history, most recent first
  POST /api/scans          -> records a scan as completed (see complete_scan()
                               below) and, if warranted, sends the critical-
                               finding email alert. Called by the frontend
                               from the Review & Send step, once tickets have
                               actually been confirmed/sent — NOT right after
                               a scan is uploaded or run — so an abandoned
                               scan never shows up in history/dashboard.
  GET  /api/scans/analysis -> long-term trend/analysis view over the FULL scan
                               history (not just the last few) — see
                               scan_analysis() below for the exact shape.
"""

import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

import email_notifications
from auth import _get_db, get_user_by_id, require_role

scans_bp = Blueprint("scans", __name__, url_prefix="/api/scans")

logger = logging.getLogger(__name__)

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

    Returns the list of full vulnerability dicts that are BOTH Critical
    severity AND weren't present in this user's immediately previous scan
    — this is what scanner.py checks to decide whether a "new critical
    findings" email alert is warranted (see email_notifications.py). On a
    user's very first scan, everything Critical counts as new (there's
    nothing to diff against, same convention dashboard.py uses for "new
    since last scan"). Returns an empty list if nobody's signed in.
    """
    if not user_id:
        return []

    counts = {sev: 0 for sev in SEVERITIES}
    cve_ids = []
    for v in vulnerabilities or []:
        sev = str(v.get("severity") or "unknown").strip().lower()
        counts[sev if sev in counts else "unknown"] += 1
        if v.get("cve"):
            cve_ids.append(v["cve"])

    conn = _get_db()
    try:
        previous = conn.execute(
            "SELECT cve_ids FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        previous_cves = set(json.loads(previous["cve_ids"])) if previous and previous["cve_ids"] else set()

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

    return [
        v for v in (vulnerabilities or [])
        if str(v.get("severity") or "").strip().lower() == "critical"
        and v.get("cve")
        and v.get("cve") not in previous_cves
    ]


def _maybe_send_critical_alert(user_id, scanner_name, target, new_critical_vulns):
    """Fires off the "new Critical findings" email (see
    email_notifications.py) if — and only if — someone's signed in, this
    scan actually turned up new Criticals (record_scan already did the
    "new since last scan" diffing), and that user has the Profile page's
    Email notifications toggle on (off by default — see auth.py's
    notify_on_critical column). Never lets an email problem (SMTP not
    configured, provider rejects the send, network hiccup) fail the request
    that triggered it — the scan/ticket flow already succeeded by the time
    this runs. Moved here (from scanner.py) alongside record_scan() now
    that both fire together from POST /api/scans, once the wizard is
    actually complete rather than right after parsing."""
    if not user_id or not new_critical_vulns:
        return

    user = get_user_by_id(user_id)
    if not user or not user["notify_on_critical"]:
        return

    try:
        email_notifications.send_critical_alert(
            user["email"], user["name"], new_critical_vulns,
            scan_context={"scanner": scanner_name, "target": target},
        )
    except EnvironmentError:
        logger.info("Email alerts not configured - skipping critical-finding email")
    except Exception:
        logger.exception("Failed to send critical-finding email alert")


@scans_bp.route("", methods=["POST"])
@require_role("admin", "analyst")
def complete_scan():
    """Records a scan as completed — and, if warranted, fires the critical-
    finding email alert (see _maybe_send_critical_alert above).

    Deliberately NOT called right after a scan is uploaded/run (compare:
    it used to be called from scanner.py's /api/upload-scan and /api/scan).
    Instead, the frontend calls this from the Review & Send step, only
    once the user has gone through the full wizard and confirmed sending
    tickets (see ReviewSendStep's "Send to Jira" handler in App.jsx). A
    scan someone uploads or runs and then abandons partway through — closes
    the tab, never reviews the findings, never sends anything — should NOT
    show up in scan history or the dashboard as a completed scan.

    Body: {scanner, source, target, vulnerabilities} — the same finalized
    vulnerability list (post-dedupe/Tenable-cross-reference/AI-analysis)
    the frontend has been holding onto since upload/scan, same shape
    /api/upload-scan, /api/scan, and /api/analyze already return.
    Gated to Admin/Analyst (see auth.require_role) — a Viewer can't reach
    this because the whole upload/scan wizard that leads here is already
    blocked for them at /api/upload-scan and /api/scan.
    """
    body = request.get_json(force=True, silent=True) or {}
    vulnerabilities = body.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return jsonify({"error": "Expected a 'vulnerabilities' array"}), 400

    user_id = session.get("user_id")
    scanner_name = body.get("scanner")
    source = body.get("source")
    target = body.get("target")

    new_critical = record_scan(user_id, scanner_name, source, target, vulnerabilities)
    _maybe_send_critical_alert(user_id, scanner_name, target, new_critical)

    return jsonify({"status": "recorded"})


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


def _short_date(iso_ts):
    """Same formatting dashboard.py uses for chart labels, duplicated here
    (rather than imported) to avoid a scans.py <-> dashboard.py import
    cycle — dashboard.py already imports from this module indirectly via
    the scans table."""
    try:
        dt = datetime.fromisoformat(iso_ts)
    except ValueError:
        return iso_ts[:10]
    return dt.strftime("%b %d").replace(" 0", " ")


@scans_bp.route("/analysis", methods=["GET"])
def scan_analysis():
    """Long-term view across a user's ENTIRE scan history (dashboard.py's
    chart only ever shows the last 6 scans). Computes, from every stored
    scan row:

      - trend: severity counts per scan, oldest first, for a full history
        chart
      - recurring: CVEs that have shown up in more than one scan, with how
        many scans they've appeared in, when first/last seen, and whether
        they're still present in the most recent scan (stillOpen) or seem
        to have been remediated (stillOpen: false)
      - totals: a handful of headline numbers for the page (scan count,
        average findings per scan, unique CVEs ever seen, how many of
        those look resolved, how many are recurring, and a breakdown of
        which scanners were used)

    Returns {hasScans: false} with empty collections if the user has no
    scan history yet, same "empty but valid shape" pattern as
    dashboard.py's _empty_summary().
    """
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"hasScans": False, "totals": {}, "trend": [], "recurring": [], "scans": []})

    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at ASC", (user_id,)
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return jsonify({"hasScans": False, "totals": {}, "trend": [], "recurring": [], "scans": []})

    trend = [
        {
            "label": _short_date(r["created_at"]),
            "date": r["created_at"],
            "total": r["total"],
            "critical": r["critical"],
            "high": r["high"],
            "medium": r["medium"],
            "low": r["low"],
            "unknown": r["unknown"],
        }
        for r in rows
    ]

    # Tally how many scans each CVE has shown up in, and its first/last
    # seen dates. Rows are ascending by created_at, so the last write for
    # a given CVE naturally ends up holding its most recent sighting.
    occurrence = {}
    for r in rows:
        cve_ids = json.loads(r["cve_ids"]) if r["cve_ids"] else []
        for cve in cve_ids:
            entry = occurrence.setdefault(
                cve, {"count": 0, "firstSeen": r["created_at"], "lastSeen": r["created_at"]}
            )
            entry["count"] += 1
            entry["lastSeen"] = r["created_at"]

    latest_cves = set(json.loads(rows[-1]["cve_ids"]) if rows[-1]["cve_ids"] else [])

    recurring = [
        {
            "cve": cve,
            "occurrences": data["count"],
            "firstSeen": data["firstSeen"],
            "lastSeen": data["lastSeen"],
            "stillOpen": cve in latest_cves,
        }
        for cve, data in occurrence.items()
        if data["count"] > 1
    ]
    # Worst offenders first (most occurrences), then still-open ones ahead
    # of ones that look resolved, so the page leads with what still needs
    # attention.
    recurring.sort(key=lambda x: (-x["occurrences"], x["stillOpen"] is False, x["cve"]))

    scanner_breakdown = {}
    for r in rows:
        name = r["scanner"] or "unknown"
        scanner_breakdown[name] = scanner_breakdown.get(name, 0) + 1

    total_scans = len(rows)
    resolved_cves = sum(1 for cve in occurrence if cve not in latest_cves)

    totals = {
        "scanCount": total_scans,
        "avgFindingsPerScan": round(sum(r["total"] for r in rows) / total_scans, 1),
        "uniqueCvesSeen": len(occurrence),
        "resolvedCves": resolved_cves,
        "recurringCveCount": len(recurring),
        "scannerBreakdown": scanner_breakdown,
    }

    # Newest-first for the table, matching GET /api/scans.
    scans_desc = [_row_to_json(r) for r in reversed(rows)]

    return jsonify({
        "hasScans": True,
        "totals": totals,
        "trend": trend,
        "recurring": recurring[:25],
        "scans": scans_desc,
    })


init_scans_db()
