"""
Dashboard summary — combines scans.py + tickets.py into the numbers the
"Security Overview" splash actually shows. Nothing new is stored here; this
just reads the two tables that already exist and shapes them into what the
frontend renders (see Dashboard() in App.jsx).

Endpoints registered by this blueprint (mounted at /api/dashboard):
  GET /api/dashboard/summary -> {
    totalVulnerabilities, totalDeltaPct, critical, medium, newSinceLastScan,
    chart: [{label, count}, ...]   (up to the last 6 scans, oldest first)
    aiInsight: str
    recentActivity: [{tag, label}, ...]
    hasScans: bool   (frontend uses this to show an empty state pre-first-scan)
  }
"""

import json
from datetime import datetime, timezone

from flask import Blueprint, jsonify, session

from auth import _get_db

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

ACTIVITY_WINDOW_SCANS = 5     # how many recent scans count toward "N new scans processed"
ACTIVITY_WINDOW_TICKETS = 20  # how many recent tickets to scan for the activity feed
CHART_HISTORY = 6             # how many past scans the "over time" chart shows


def _empty_summary():
    return {
        "totalVulnerabilities": 0,
        "totalDeltaPct": None,
        "critical": 0,
        "medium": 0,
        "newSinceLastScan": 0,
        "chart": [],
        "aiInsight": "Upload or run a scan to get AI-prioritized insights about your findings.",
        "recentActivity": [],
        "hasScans": False,
    }


@dashboard_bp.route("/summary", methods=["GET"])
def summary():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify(_empty_summary())

    conn = _get_db()
    try:
        scans = conn.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, max(CHART_HISTORY, ACTIVITY_WINDOW_SCANS)),
        ).fetchall()
        tickets = conn.execute(
            "SELECT * FROM tickets WHERE user_id = ? ORDER BY updated_at DESC LIMIT ?",
            (user_id, ACTIVITY_WINDOW_TICKETS),
        ).fetchall()
    finally:
        conn.close()

    if not scans:
        result = _empty_summary()
        # Still worth surfacing ticket activity even with zero scans on
        # record, e.g. tickets created before this feature existed.
        result["recentActivity"] = _ticket_activity(tickets)
        return jsonify(result)

    latest = scans[0]
    previous = scans[1] if len(scans) > 1 else None

    total_delta_pct = None
    if previous and previous["total"]:
        total_delta_pct = round(((latest["total"] - previous["total"]) / previous["total"]) * 100)

    new_since_last = 0
    if previous:
        prev_cves = set(json.loads(previous["cve_ids"]) if previous["cve_ids"] else [])
        latest_cves = set(json.loads(latest["cve_ids"]) if latest["cve_ids"] else [])
        new_since_last = len(latest_cves - prev_cves)
    else:
        # No prior scan to diff against — every finding in the first scan
        # is "new" by definition.
        new_since_last = latest["total"]

    # Chart: oldest -> newest so the bars read left-to-right like the old
    # placeholder did, labelled by scan date rather than a fixed Jan-May.
    chart_scans = list(reversed(scans[:CHART_HISTORY]))
    chart = [
        {"label": _short_date(s["created_at"]), "count": s["total"]}
        for s in chart_scans
    ]

    insight = _build_insight(latest, tickets)

    activity = _scan_activity(scans[:ACTIVITY_WINDOW_SCANS]) + _ticket_activity(tickets)

    return jsonify({
        "totalVulnerabilities": latest["total"],
        "totalDeltaPct": total_delta_pct,
        "critical": latest["critical"],
        "medium": latest["medium"],
        "newSinceLastScan": new_since_last,
        "chart": chart,
        "aiInsight": insight,
        "recentActivity": activity[:4],  # dashboard only has room for 4 tiles
        "hasScans": True,
    })


def _short_date(iso_ts):
    try:
        dt = datetime.fromisoformat(iso_ts)
    except ValueError:
        return iso_ts[:10]
    return dt.strftime("%b %d").replace(" 0", " ")  # "Aug 09" -> "Aug 9", no platform-specific %-d


def _scan_activity(recent_scans):
    if not recent_scans:
        return []
    return [{"tag": "Scan", "label": f"{len(recent_scans)} new scan(s) processed"}]


def _ticket_activity(tickets):
    if not tickets:
        return []
    items = []

    created = len(tickets)
    items.append({"tag": "Ticket", "label": f"{created} ticket(s) created"})

    closed = [t for t in tickets if (t["status"] or "").lower() in ("closed", "resolved")]
    if closed:
        items.append({"tag": "Resolved", "label": f"{len(closed)} ticket(s) closed"})

    critical_open = [
        t for t in tickets
        if (t["priority"] or "").upper() == "P1" and (t["status"] or "").lower() not in ("closed", "resolved")
    ]
    if critical_open:
        items.append({"tag": "Critical", "label": critical_open[0]["title"]})

    return items


def _build_insight(latest_scan, tickets):
    if latest_scan["critical"] == 0:
        return "No critical findings in your latest scan. Keep an eye on the medium-severity items to stay ahead of them."

    open_critical = [
        t for t in tickets
        if (t["priority"] or "").upper() == "P1" and (t["status"] or "").lower() not in ("closed", "resolved")
    ]
    if open_critical:
        return (
            f"{latest_scan['critical']} critical finding(s) in your latest scan. "
            f"\"{open_critical[0]['title']}\" is still open — consider prioritizing it first."
        )
    return (
        f"{latest_scan['critical']} critical finding(s) in your latest scan. "
        "Review and ticket them from the Upload Scan flow to start tracking remediation."
    )
