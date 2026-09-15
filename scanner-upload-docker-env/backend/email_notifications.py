"""
Critical-vulnerability email alerts — isolated module, same "env vars
only, gracefully not-configured" shape as jira_integration.py /
tenable_client.py / ollama_client.py.

Why this exists: nobody's staring at the dashboard the moment a scan
finishes. A brand new Critical finding is exactly the kind of thing that
shouldn't wait for someone to log back in and notice it. scanner.py calls
send_critical_alert() right after a scan is recorded — see scans.py's
record_scan(), which reports back which findings are BOTH Critical
severity AND new since that user's previous scan, so the alert fires once
per newly-appeared Critical, not again on every later scan it still shows
up in (scans.py's own "recurring vulnerabilities" analysis already covers
"is this still around").

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

# One email gets unreadable fast if a scan has hundreds of new Criticals —
# cap the listed findings and summarize the rest.
MAX_LISTED_FINDINGS = 20


def is_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM_EMAIL)


def _build_message(to_email, to_name, critical_vulns, scan_context):
    scanner_name = (scan_context or {}).get("scanner") or "scan"
    target = (scan_context or {}).get("target") or "your environment"
    count = len(critical_vulns)

    subject = f"[Security Alert] {count} new Critical finding{'s' if count != 1 else ''} \u2014 {target}"

    lines = [
        f"Hi {to_name or 'there'},",
        "",
        f"Your latest {scanner_name} scan of \"{target}\" turned up {count} new "
        f"Critical-severity vulnerabilit{'ies' if count != 1 else 'y'} that didn't "
        f"appear in your previous scan:",
        "",
    ]
    for v in critical_vulns[:MAX_LISTED_FINDINGS]:
        cve = v.get("cve") or "(no CVE)"
        title = v.get("title") or "Untitled finding"
        cvss = v.get("cvss")
        cvss_part = f" \u2014 CVSS {cvss}" if cvss is not None else ""
        lines.append(f"  - {cve}: {title}{cvss_part}")
    if count > MAX_LISTED_FINDINGS:
        lines.append(f"  ...and {count - MAX_LISTED_FINDINGS} more.")

    lines += [
        "",
        "Sign in to review these, get AI-generated remediation steps, and create tickets:",
        FRONTEND_URL,
        "",
        "You're receiving this because email notifications are enabled in your "
        "Profile settings \u2014 you can turn them off there at any time.",
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


def send_critical_alert(to_email: str, to_name: str, critical_vulns: list, scan_context: dict = None):
    """Sends one email listing newly-found Critical vulnerabilities.

    Raises EnvironmentError if SMTP isn't configured. Raises whatever
    smtplib raises on an actual send failure (auth rejected, connection
    refused, timeout, etc) — callers should catch broadly and log rather
    than let a notification failure break the scan request that triggered
    it (see scanner.py's _maybe_send_critical_alert)."""
    if not is_configured():
        raise EnvironmentError(
            "Email alerts are not configured on this server. Set SMTP_HOST and "
            "SMTP_FROM_EMAIL (or SMTP_USERNAME) to enable them."
        )
    if not to_email or not critical_vulns:
        return

    msg = _build_message(to_email, to_name, critical_vulns, scan_context)
    _send(msg)
