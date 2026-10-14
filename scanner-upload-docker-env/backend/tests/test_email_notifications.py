"""Tests for email_notifications.py — building the scan alert email and
sending through SMTP. The SMTP connection is replaced by a recording fake."""
import pytest

CTX = {"scanner": "trivy", "target": "myapp:1.0"}


@pytest.fixture()
def en(app_env, monkeypatch):
    mod = app_env.email_notifications
    monkeypatch.setattr(mod, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(mod, "SMTP_PORT", 2525)
    monkeypatch.setattr(mod, "SMTP_USERNAME", None)
    monkeypatch.setattr(mod, "SMTP_PASSWORD", None)
    monkeypatch.setattr(mod, "SMTP_FROM_EMAIL", "alerts@test")
    monkeypatch.setattr(mod, "SMTP_USE_TLS", False)
    monkeypatch.setattr(mod, "FRONTEND_URL", "http://frontend.test/")
    return mod


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.events = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        self.events.append("starttls")

    def login(self, u, p):
        self.events.append(("login", u, p))

    def send_message(self, msg):
        self.events.append(("send", msg))


@pytest.fixture()
def smtp(en, monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(en.smtplib, "SMTP", FakeSMTP)
    return FakeSMTP


def _f(cve, sev="Critical", cvss=9.0, title=None):
    return {"cve": cve, "severity": sev, "cvss": cvss, "title": title or f"{cve} title"}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def test_is_configured_needs_host_and_from_address(en, monkeypatch):
    assert en.is_configured() is True
    monkeypatch.setattr(en, "SMTP_HOST", None)
    assert en.is_configured() is False
    monkeypatch.setattr(en, "SMTP_HOST", "h")
    monkeypatch.setattr(en, "SMTP_FROM_EMAIL", "")
    assert en.is_configured() is False


def test_sending_raises_environment_error_when_unconfigured(en, monkeypatch):
    monkeypatch.setattr(en, "SMTP_HOST", None)
    with pytest.raises(EnvironmentError):
        en.send_scan_notification("a@b.co", "A", [_f("CVE-1")], CTX)
    with pytest.raises(EnvironmentError):
        en.send_plain_email("a@b.co", "s", "b")


# ---------------------------------------------------------------------------
# Subject lines
# ---------------------------------------------------------------------------
def test_subject_for_findings_only(en):
    msg = en._build_message("a@b.co", "A", [_f("CVE-1"), _f("CVE-2", "High"), _f("CVE-3", "High")], CTX)
    assert msg["Subject"] == "[Security Alert] New findings: 1 Critical, 2 High \u2014 myapp:1.0"


def test_subject_for_jira_only_pluralises(en):
    one = en._build_message("a@b.co", "A", [], CTX, jira_tickets=[{"issueKey": "V-1"}])
    many = en._build_message("a@b.co", "A", [], CTX, jira_tickets=[{"issueKey": "V-1"}, {"issueKey": "V-2"}])
    assert one["Subject"] == "[Scan Complete] 1 ticket sent to Jira \u2014 myapp:1.0"
    assert many["Subject"] == "[Scan Complete] 2 tickets sent to Jira \u2014 myapp:1.0"


def test_subject_for_both(en):
    msg = en._build_message("a@b.co", "A", [_f("CVE-1")], CTX, jira_tickets=[{"issueKey": "V-1"}, {"issueKey": "V-2"}])
    assert msg["Subject"] == "[Security Alert] 1 Critical new + 2 tickets sent to Jira \u2014 myapp:1.0"


def test_severity_summary_orders_worst_first_and_omits_low(en):
    s = en._severity_summary([_f("a", "Medium"), _f("b", "Low"), _f("c", "Critical"), _f("d", "High"), _f("e", "high")])
    assert s == "1 Critical, 2 High, 1 Medium"


# ---------------------------------------------------------------------------
# Body
# ---------------------------------------------------------------------------
def _body(msg):
    return msg.get_content()


def test_body_greets_by_name_and_lists_findings_worst_first(en):
    msg = en._build_message("a@b.co", "Ada", [_f("CVE-M", "Medium", 5.0), _f("CVE-C", "Critical", 9.8),
                                               _f("CVE-H2", "High", 8.0), _f("CVE-H1", "High", 7.0)], CTX, min_severity="medium")
    text = _body(msg)
    assert text.startswith("Hi Ada,")
    assert text.index("CVE-C") < text.index("CVE-H2") < text.index("CVE-H1") < text.index("CVE-M")
    assert "[Critical] CVE-C: CVE-C title \u2014 CVSS 9.8" in text
    assert "(Medium, High or Critical severity)" in text
    assert "4 new findings" in text
    assert "http://frontend.test/" in text and "Profile settings" in text


@pytest.mark.parametrize("level,phrase", [("critical", "(Critical severity)"), ("high", "(High or Critical severity)"),
                                         ("medium", "(Medium, High or Critical severity)")])
def test_body_describes_the_chosen_level(en, level, phrase):
    assert phrase in _body(en._build_message("a@b.co", "A", [_f("CVE-1")], CTX, min_severity=level))


def test_single_finding_is_singular(en):
    text = _body(en._build_message("a@b.co", "A", [_f("CVE-1")], CTX))
    assert "1 new finding (" in text and "findings" not in text.split("\n")[2]


def test_missing_fields_get_sensible_fallbacks(en):
    msg = en._build_message("a@b.co", None, [{"severity": None}], None)
    text = _body(msg)
    assert text.startswith("Hi there,")
    assert "[Unknown] (no CVE): Untitled finding" in text and "CVSS" not in text
    assert 'scan of "your environment"' in text


def test_a_cvss_of_zero_is_still_shown(en):
    assert "CVSS 0" in _body(en._build_message("a@b.co", "A", [_f("CVE-1", cvss=0)], CTX))


def test_findings_list_is_capped_with_a_summary_line(en):
    findings = [_f(f"CVE-{i:03d}", cvss=9.0 - i / 100) for i in range(25)]
    text = _body(en._build_message("a@b.co", "A", findings, CTX))
    assert text.count("  - [Critical]") == en.MAX_LISTED_FINDINGS == 20
    assert "...and 5 more." in text and "25 new findings" in text


def test_jira_section_lists_key_title_priority_and_url(en):
    tickets = [{"issueKey": "V-1", "title": "Patch it", "priority": "P1", "url": "https://x/browse/V-1"},
               {"issueKey": "V-2", "cve": "CVE-9"}, {"title": "no key given"}]
    text = _body(en._build_message("a@b.co", "A", [], CTX, jira_tickets=tickets))
    assert "3 tickets were sent to Jira" in text
    assert "  - V-1: Patch it (P1) \u2014 https://x/browse/V-1" in text
    assert "  - V-2: CVE-9" in text
    assert "  - (unknown): no key given" in text


def test_combined_email_has_both_sections_with_the_also_phrasing(en):
    text = _body(en._build_message("a@b.co", "A", [_f("CVE-1")], CTX, jira_tickets=[{"issueKey": "V-1"}]))
    assert "turned up 1 new finding" in text and "1 ticket from this scan was also sent to Jira" in text


def test_jira_ticket_list_is_capped(en):
    tickets = [{"issueKey": f"V-{i}"} for i in range(23)]
    text = _body(en._build_message("a@b.co", "A", [], CTX, jira_tickets=tickets))
    assert text.count("  - V-") == en.MAX_LISTED_TICKETS and "...and 3 more." in text


def test_newlines_in_client_supplied_fields_cannot_break_the_headers(en):
    ctx = {"scanner": "tri\nvy", "target": "img\r\nBcc: evil@x.com"}
    msg = en._build_message("a@b.co", "A", [_f("CVE-1")], ctx,
                            jira_tickets=[{"issueKey": "V-1\nX", "title": "t\nu", "priority": "P\n1", "url": "u\nv"}])
    assert "\n" not in msg["Subject"] and msg["Bcc"] is None
    assert "Bcc: evil@x.com" in msg["Subject"]  # flattened into the text, not a header


def test_message_headers(en):
    msg = en._build_message("to@x.co", "A", [_f("CVE-1")], CTX)
    assert msg["From"] == "alerts@test" and msg["To"] == "to@x.co"


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------
def test_send_scan_notification_sends_one_message(en, smtp):
    en.send_scan_notification("to@x.co", "A", [_f("CVE-1")], CTX)
    (conn,) = smtp.instances
    assert (conn.host, conn.port) == ("smtp.test", 2525) and conn.timeout == 15
    sends = [e for e in conn.events if e[0] == "send"]
    assert len(sends) == 1 and sends[0][1]["To"] == "to@x.co"


@pytest.mark.parametrize("findings,tickets,to", [([], [], "a@b.co"), (None, None, "a@b.co"), ([_f("CVE-1")], [], ""), ([_f("CVE-1")], [], None)])
def test_nothing_is_sent_without_content_or_a_recipient(en, smtp, findings, tickets, to):
    en.send_scan_notification(to, "A", findings, CTX, jira_tickets=tickets)
    assert smtp.instances == []


def test_tls_and_login_are_used_only_when_configured(en, smtp, monkeypatch):
    en.send_plain_email("a@b.co", "s", "b")
    assert smtp.instances[-1].events[0][0] == "send"  # no starttls, no login
    monkeypatch.setattr(en, "SMTP_USE_TLS", True)
    monkeypatch.setattr(en, "SMTP_USERNAME", "user")
    monkeypatch.setattr(en, "SMTP_PASSWORD", "pw")
    en.send_plain_email("a@b.co", "s", "b")
    assert [e if isinstance(e, str) else e[0] for e in smtp.instances[-1].events] == ["starttls", "login", "send"]
    assert smtp.instances[-1].events[1] == ("login", "user", "pw")


def test_login_is_skipped_when_only_a_username_is_set(en, smtp, monkeypatch):
    monkeypatch.setattr(en, "SMTP_USERNAME", "user")
    en.send_plain_email("a@b.co", "s", "b")
    assert all(e[0] != "login" for e in smtp.instances[-1].events)


def test_send_plain_email_message_content(en, smtp):
    en.send_plain_email("a@b.co", "Subject here", "Body here")
    msg = [e for e in smtp.instances[-1].events if e[0] == "send"][0][1]
    assert msg["Subject"] == "Subject here" and msg["To"] == "a@b.co" and "Body here" in msg.get_content()


def test_send_plain_email_with_no_recipient_is_a_silent_no_op(en, smtp):
    en.send_plain_email("", "s", "b")
    assert smtp.instances == []


def test_smtp_errors_propagate_to_the_caller(en, monkeypatch):
    class Broken(FakeSMTP):
        def send_message(self, msg):
            raise ConnectionRefusedError("down")

    monkeypatch.setattr(en.smtplib, "SMTP", Broken)
    with pytest.raises(ConnectionRefusedError):
        en.send_scan_notification("a@b.co", "A", [_f("CVE-1")], CTX)


def test_send_critical_alert_is_the_critical_only_wrapper(en, monkeypatch):
    calls = []
    monkeypatch.setattr(en, "send_scan_notification", lambda *a, **k: calls.append((a, k)))
    en.send_critical_alert("a@b.co", "A", [_f("CVE-1")], CTX)
    assert calls == [(("a@b.co", "A", [_f("CVE-1")], CTX), {"min_severity": "critical"})]
