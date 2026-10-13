"""
Recent-incident / active-exploitation awareness for the AI analysis and
chatbot prompts — cross-references each finding's CVE against the
Australian Signals Directorate's Australian Cyber Security Centre (ASD's
ACSC) Alerts and Advisories RSS feeds: real, publicly maintained
communications about threats currently relevant to Australian
organisations.

  https://www.cyber.gov.au/rss/alerts
  https://www.cyber.gov.au/rss/advisories

Why RSS and not ACSC's Annual Cyber Threat Report: the Annual Cyber Threat
Report is a yearly narrative document (statistics, trends, case studies)
with no per-CVE structure, so there's nothing to reliably cross-reference a
specific finding against. The Alerts/Advisories feeds are the live,
CVE-referencing counterpart — each item is a short bulletin about a
specific threat/vulnerability, often naming one or more CVE IDs directly.

ALERT vs ADVISORY — these are not the same strength of signal:
  - An ACSC *Alert* is their highest-urgency communication, typically
    issued for active/imminent exploitation or a very high-impact
    vulnerability organisations need to act on immediately.
  - An ACSC *Advisory* is broader guidance/awareness content — it may
    reference a CVE without asserting it is being actively exploited
    right now.

ai_analysis.py treats these differently: a CVE with an Alert match is
forced to priority_tier P1/P2 (hard floor, independent of CVSS/business
context); a CVE with only Advisory matches folds into the normal "at most
one tier" business-context style adjustment instead, and is never
presented as confirmed active exploitation.

Design mirrors the rest of this app's external-dependency handling
(tenable_client.py, ollama_client.py): network/parse failures are caught,
logged, and degrade gracefully — a feed being down must never crash
/api/analyze or /api/chat. A TTL cache avoids hitting the feeds on every
single request.
"""
import logging
import os
import re
import threading
import time
import xml.etree.ElementTree as ET

import requests

logger = logging.getLogger(__name__)

ACSC_ALERTS_FEED_URL = os.getenv("ACSC_ALERTS_FEED_URL", "https://www.cyber.gov.au/rss/alerts")
ACSC_ADVISORIES_FEED_URL = os.getenv("ACSC_ADVISORIES_FEED_URL", "https://www.cyber.gov.au/rss/advisories")
ACSC_CACHE_TTL_SECONDS = int(os.getenv("ACSC_CACHE_TTL_SECONDS", str(6 * 3600)))  # 6 hours
ACSC_FETCH_TIMEOUT_SECONDS = int(os.getenv("ACSC_FETCH_TIMEOUT_SECONDS", "15"))

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_lock = threading.Lock()
_cache = {
    "by_cve": {},       # "CVE-YYYY-NNNNN" -> list[entry dict]
    "fetched_at": 0.0,
    "alert_count": 0,
    "advisory_count": 0,
    "errors": [],        # list[str], most recent fetch's errors (empty on success)
}


def _parse_rss_items(xml_text: str, source: str) -> list:
    """Standard RSS 2.0 <channel><item> parsing. Defensive on purpose: ACSC's
    exact feed schema wasn't independently verifiable from this environment
    (their site blocks automated fetches), so this assumes the RSS 2.0 spec
    rather than a verified exact schema, and a single malformed <item> is
    skipped rather than failing the whole feed."""
    items = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        logger.warning("ACSC %s feed: XML parse error: %s", source, e)
        return items

    channel = root.find("channel")
    nodes = channel.findall("item") if channel is not None else root.findall(".//item")

    for node in nodes:
        try:
            title = (node.findtext("title") or "").strip()
            link = (node.findtext("link") or "").strip()
            description = (node.findtext("description") or "").strip()
            pub_date = (node.findtext("pubDate") or "").strip()

            cve_ids = set(m.upper() for m in _CVE_RE.findall(f"{title} {description}"))
            if not cve_ids:
                continue

            for cve_id in cve_ids:
                items.append({
                    "cve": cve_id,
                    "source": source,  # "alert" | "advisory"
                    "title": title,
                    "link": link,
                    "pub_date": pub_date,
                })
        except Exception:
            logger.exception("ACSC %s feed: skipping malformed item", source)
            continue

    return items


def _fetch_feed(url: str, source: str):
    """Returns (items, error) — error is None on success, else a short
    string describing what went wrong (and items is [])."""
    try:
        resp = requests.get(
            url,
            timeout=ACSC_FETCH_TIMEOUT_SECONDS,
            headers={"User-Agent": "T170-capstone-vuln-scanner/1.0 (+security research tool)"},
        )
        resp.raise_for_status()
    except Exception as e:
        logger.warning("ACSC %s feed fetch failed (%s): %s", source, url, e)
        return [], str(e)

    return _parse_rss_items(resp.text, source), None


def _refresh_if_stale():
    """TTL-gated refresh of both feeds. If BOTH feeds fail on a refresh
    attempt, the previous (possibly still useful) cache is kept rather than
    being wiped to empty — a transient outage shouldn't silently erase
    every Alert/Advisory match the app already knew about."""
    with _lock:
        if time.time() - _cache["fetched_at"] < ACSC_CACHE_TTL_SECONDS and _cache["fetched_at"] > 0:
            return

        alert_items, alert_err = _fetch_feed(ACSC_ALERTS_FEED_URL, "alert")
        advisory_items, advisory_err = _fetch_feed(ACSC_ADVISORIES_FEED_URL, "advisory")
        errors = [e for e in (alert_err, advisory_err) if e]

        if alert_err and advisory_err:
            logger.error("ACSC feeds: both alerts and advisories failed — keeping previous cache")
            _cache["errors"] = errors
            _cache["fetched_at"] = time.time()  # still bump, so we don't hammer a down feed every call
            return

        by_cve = {}
        for item in alert_items + advisory_items:
            by_cve.setdefault(item["cve"], []).append(item)

        _cache["by_cve"] = by_cve
        _cache["alert_count"] = len(alert_items)
        _cache["advisory_count"] = len(advisory_items)
        _cache["errors"] = errors
        _cache["fetched_at"] = time.time()


def get_acsc_entries(cve_id):
    """Returns the list of ACSC Alert/Advisory entries referencing this CVE
    (alerts sorted first), or [] if there's no CVE, no match, or the feeds
    are unreachable."""
    if not cve_id:
        return []
    try:
        _refresh_if_stale()
    except Exception:
        logger.exception("ACSC feed refresh failed unexpectedly — continuing without threat intel")
        return []

    entries = _cache["by_cve"].get(cve_id.upper(), [])
    return sorted(entries, key=lambda e: e["source"] != "alert")


def has_alert(acsc_entries) -> bool:
    return any(e.get("source") == "alert" for e in (acsc_entries or []))


def status() -> dict:
    """Diagnostic shape, mirrors ollama_status() in scanner.py."""
    try:
        _refresh_if_stale()
    except Exception:
        logger.exception("ACSC feed refresh failed unexpectedly")
    return {
        "alerts_feed_url": ACSC_ALERTS_FEED_URL,
        "advisories_feed_url": ACSC_ADVISORIES_FEED_URL,
        "alert_items": _cache["alert_count"],
        "advisory_items": _cache["advisory_count"],
        "distinct_cves_referenced": len(_cache["by_cve"]),
        "last_refreshed": _cache["fetched_at"] or None,
        "cache_ttl_seconds": ACSC_CACHE_TTL_SECONDS,
        "errors": _cache["errors"],
    }


def format_acsc_for_prompt(acsc_entries) -> str:
    """Renders matching ACSC entries as a prompt block. Empty string if
    there's nothing to show. Capped at 3 items (alerts first) to keep
    prompt size bounded; explicitly tells the model not to conflate Alert
    and Advisory strength, since that distinction matters for how
    priority_tier gets set (see ai_analysis.py's SYSTEM_PROMPT)."""
    if not acsc_entries:
        return ""

    lines = [
        "\nRecent ASD ACSC reporting for this CVE (Australian Signals "
        "Directorate / Australian Cyber Security Centre):",
    ]
    for entry in acsc_entries[:3]:
        label = "[ALERT]" if entry["source"] == "alert" else "[ADVISORY]"
        pub = f", published {entry['pub_date']}" if entry.get("pub_date") else ""
        lines.append(f"- {label} \"{entry['title']}\"{pub} — {entry.get('link', 'no link')}")
    lines.append(
        "Note: an [ALERT] is ACSC's highest-urgency designation (typically active/imminent "
        "exploitation). An [ADVISORY] is official guidance referencing this CVE, NOT confirmation "
        "of active exploitation — do not treat it as equivalent to an Alert."
    )
    return "\n".join(lines)
