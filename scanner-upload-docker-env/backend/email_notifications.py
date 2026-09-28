"""
Scan email notifications (new findings by severity, and scans sent to Jira)
— isolated module, same "env vars
only, gracefully not-configured" shape as jira_integration.py /
tenable_client.py / ollama_client.py.

Why this exists: nobody's staring at the dashboard the moment a scan
finishes. A brand new Critical finding is exactly the kind of thing that
shouldn't wait for someone to log back in and notice it. scans.py's
complete_scan() calls send_scan_notification() right after a scan is
recorded. What triggers an email is up to each user (Profile page, stored
in auth.py): new findings at Critical, High-and-above or Medium-and-above,
and/or the scan's tickets having been sent to Jira. "New" comes from
scans.py's record_scan(), which reports which findings meet the user's
severity threshold AND weren't in that user's previous scan, so an alert
fires once per newly-appeared finding, not again on every later scan it
still shows up in (scans.py's own "recurring vulnerabilities" analysis
already covers "is this still around"). A scan that triggers both kinds
produces a single combined email.

Delivery: plain SMTP via the standard library (smtplib + email) — no
extra dependency, works with Gmail/Outlook/any SMTP relay, or a local dev
catcher like MailHog/Mailpit. Configure via backend/.env:
  SMTP_HOST, SMTP_PORT (default 587), SMTP_USERNAME, SMTP_PASSWORD,
  SMTP_FROM_EMAIL (defaults to SMTP_USERNAME), SMTP_USE_TLS (default true)

If SMTP_HOST/SMTP_FROM_EMAIL aren't set, send_critical_alert() raises
EnvironmentError — scanner.py catches that and just logs "not configured"
rather than failing the scan request over it, the same pattern
tenable_client.get_client() and OllamaVulnerabilityAnalyzer() already use.
"""

import os
import smtplib
from email.message import EmailMessage

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL") or SMTP_USERNAME
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").strip().lower() not in ("0", "false", "no")

# Shown in the email as a "go review this" link — reuses the same var
# google_auth.py already reads for where the frontend lives, rather than
# introducing a second "where's the frontend" setting.
FRONTEND_URL = os.environ.get("GOOGLE_FRONTEND_RETURN_URL", "http://localhost:5173/")

# One email gets unreadable fast if a scan has hundreds of new findings or
# tickets -- cap each listed section and summarize the rest.
MAX_LISTED_FINDINGS = 20
MAX_LISTED_TICKETS = 20

# Higher = worse. Shared with scans.py so "at or above this severity" means
# the same thing when a scan is recorded and when the email is written.
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# How each notify_level (see auth.py) reads in the email body.
_LEVEL_PHRASE = {"critical": "Critical", "high": "High or Critical", "medium": "Medium, High or Critical"}


def is_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM_EMAIL)


def _sev(v):
    return str(v.get("severity") or "").strip().lower()


def _one_line(text):
    """Collapses any whitespace/newlines -- scan targets come from the
    client and a newline in an email header makes EmailMessage raise."""
    return " ".join(str(text).split())


def _severity_summary(findings):
    """e.g. "2 Critical, 3 High" -- worst first, Low omitted (never alerted on)."""
    counts = {}
    for v in findings:
        counts[_sev(v)] = counts.get(_sev(v), 0) + 1
    return ", ".join(f"{counts[s]} {s.capitalize()}" for s in ("critical", "high", "medium") if counts.get(s))


def _build_message(to_email, to_name, new_findings, scan_context, jira_tickets=None, min_severity="critical"):
    scanner_name = _one_line((scan_context or {}).get("scanner") or "scan")
    target = _one_line((scan_context or {}).get("target") or "your environment")
    new_findings = new_findings or []
    jira_tickets = jira_tickets or []
    n_find, n_jira = len(new_findings), len(jira_tickets)

    ticket_word = f"ticket{'s' if n_jira != 1 else ''}"
    if n_find and n_jira:
        subject = f"[Security Alert] {_severity_summary(new_findings)} new + {n_jira} {ticket_word} sent to Jira \u2014 {target}"
    elif n_find:
        subject = f"[Security Alert] New findings: {_severity_summary(new_findings)} \u2014 {target}"
    else:
        subject = f"[Scan Complete] {n_jira} {ticket_word} sent to Jira \u2014 {target}"

    lines = [f"Hi {to_name or 'there'},", ""]

    if n_find:
        phrase = _LEVEL_PHRASE.get(min_severity, "Critical")
        lines += [
            f"Your latest {scanner_name} scan of \"{target}\" turned up {n_find} new "
            f"finding{'s' if n_find != 1 else ''} ({phrase} severity) that didn't appear in your previous scan:",
            "",
        ]
        ordered = sorted(new_findings, key=lambda v: (-SEVERITY_RANK.get(_sev(v), 0), -(v.get("cvss") or 0)))
        for v in ordered[:MAX_LISTED_FINDINGS]:
            cve = v.get("cve") or "(no CVE)"
            title = v.get("title") or "Untitled finding"
            cvss = v.get("cvss")
            cvss_part = f" \u2014 CVSS {cvss}" if cvss is not None else ""
            lines.append(f"  - [{_sev(v).capitalize() or 'Unknown'}] {cve}: {title}{cvss_part}")
        if n_find > MAX_LISTED_FINDINGS:
            lines.append(f"  ...and {n_find - MAX_LISTED_FINDINGS} more.")
        lines.append("")

    if n_jira:
        if n_find:
            lines += [f"{n_jira} {ticket_word} from this scan {'was' if n_jira == 1 else 'were'} also sent to Jira:", ""]
        else:
            lines += [f"Your {scanner_name} scan of \"{target}\" is complete and {n_jira} {ticket_word} {'was' if n_jira == 1 else 'were'} sent to Jira:", ""]
        for t in jira_tickets[:MAX_LISTED_TICKETS]:
            key = _one_line(t.get("issueKey") or "(unknown)")
            title = _one_line(t.get("title") or t.get("cve") or "Untitled")
            priority = f" ({_one_line(t['priority'])})" if t.get("priority") else ""
            url = f" \u2014 {_one_line(t['url'])}" if t.get("url") else ""
            lines.append(f"  - {key}: {title}{priority}{url}")
        if n_jira > MAX_LISTED_TICKETS:
            lines.append(f"  ...and {n_jira - MAX_LISTED_TICKETS} more.")
        lines.append("")

    lines += [
        "Sign in to review these, get AI-generated remediation steps, and create tickets:",
        FRONTEND_URL,
        "",
        "You're receiving this because email notifications are enabled in your "
        "Profile settings \u2014 you can change which emails you get, or turn them "
        "off, there at any time.",
    ]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM_EMAIL
    msg["To"] = to_email
    msg.set_content("\n".join(lines))
    return msg


def _send(msg: EmailMessage):
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
        if SMTP_USE_TLS:
            server.starttls()
        if SMTP_USERNAME and SMTP_PASSWORD:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)


def send_plain_email(to_email: str, subject: str, body: str):
    """Sends a single plain-text email. Raises EnvironmentError if SMTP
    isn't configured (see is_configured()), same contract as
    send_critical_alert() below -- callers should catch that the same way.

    Added so mfa.py's one-time sign-in codes can go out through this
    module's existing SMTP configuration/connection handling instead of
    duplicating it in a second module."""
    if not is_configured():
        raise EnvironmentError(
            "Email delivery is not configured on this server. Set SMTP_HOST and "
            "SMTP_FROM_EMAIL (or SMTP_USERNAME) to enable it."
        )
    if not to_email:
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM_EMAIL
    msg["To"] = to_email
    msg.set_content(body)
    _send(msg)


def send_scan_notification(to_email: str, to_name: str, new_findings: list = None,
                           scan_context: dict = None, jira_tickets: list = None,
                           min_severity: str = "critical"):
    """Sends ONE email covering whichever of these apply to a completed scan:
      - new_findings: findings at/above min_severity that weren't in the
        user's previous scan (scans.record_scan already did the diffing)
      - jira_tickets: [{issueKey, url, title, priority, cve}] for tickets
        that were actually created in Jira from this scan
    Combining them means a scan that triggers both produces one email, not two.
    Does nothing if both are empty.

    Raises EnvironmentError if SMTP isn't configured. Raises whatever smtplib
    raises on an actual send failure (auth rejected, connection refused,
    timeout, etc) -- callers should catch broadly and log rather than let a
    notification failure break the request that triggered it (see scans.py's
    _maybe_send_scan_notification)."""
    if not is_configured():
        raise EnvironmentError(
            "Email alerts are not configured on this server. Set SMTP_HOST and "
            "SMTP_FROM_EMAIL (or SMTP_USERNAME) to enable them."
        )
    if not to_email or not (new_findings or jira_tickets):
        return

    _send(_build_message(to_email, to_name, new_findings, scan_context, jira_tickets, min_severity))


def send_critical_alert(to_email: str, to_name: str, critical_vulns: list, scan_context: dict = None):
    """Kept for backwards compatibility -- the Critical-only alert as it
    worked before the fine-grained controls. New code should call
    send_scan_notification()."""
    send_scan_notification(to_email, to_name, critical_vulns, scan_context, min_severity="critical")
