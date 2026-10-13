"""Tests for threat_intel.py — the ASD ACSC Alerts/Advisories RSS
integration. Network calls are never made in tests: _fetch_feed is
monkeypatched so these exercise the parsing, caching, Alert/Advisory
precedence, and prompt-formatting logic in isolation.
"""
import xml.etree.ElementTree as ET

import pytest

import threat_intel


@pytest.fixture(autouse=True)
def _reset_cache():
    """Each test gets a clean in-memory cache so fetch-count/TTL behaviour
    from one test can't leak into the next."""
    threat_intel._cache["by_cve"] = {}
    threat_intel._cache["fetched_at"] = 0.0
    threat_intel._cache["alert_count"] = 0
    threat_intel._cache["advisory_count"] = 0
    threat_intel._cache["errors"] = []
    yield
    threat_intel._cache["by_cve"] = {}
    threat_intel._cache["fetched_at"] = 0.0
    threat_intel._cache["alert_count"] = 0
    threat_intel._cache["advisory_count"] = 0
    threat_intel._cache["errors"] = []


def _rss(items_xml: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<title>Test feed</title>
{items_xml}
</channel></rss>"""


_ALERT_ITEM = """<item>
<title>Critical vulnerability actively exploited - CVE-2021-44228</title>
<link>https://www.cyber.gov.au/alerts/log4shell</link>
<description>ACSC is aware of active exploitation referencing CVE-2021-44228.</description>
<pubDate>Mon, 13 Dec 2021 00:00:00 GMT</pubDate>
</item>"""

_ADVISORY_ITEM = """<item>
<title>Guidance on CVE-2023-12345</title>
<link>https://www.cyber.gov.au/advisories/example</link>
<description>General guidance referencing CVE-2023-12345.</description>
<pubDate>Tue, 01 Aug 2023 00:00:00 GMT</pubDate>
</item>"""

_NO_CVE_ITEM = """<item>
<title>General security update</title>
<link>https://www.cyber.gov.au/alerts/general</link>
<description>No specific CVE referenced here.</description>
<pubDate>Wed, 01 Jan 2025 00:00:00 GMT</pubDate>
</item>"""


# ---------------------------------------------------------------------------
# RSS parsing
# ---------------------------------------------------------------------------

def test_parse_rss_items_extracts_cve_and_fields():
    items = threat_intel._parse_rss_items(_rss(_ALERT_ITEM), "alert")
    assert len(items) == 1
    item = items[0]
    assert item["cve"] == "CVE-2021-44228"
    assert item["source"] == "alert"
    assert item["link"] == "https://www.cyber.gov.au/alerts/log4shell"
    assert "pub_date" in item


def test_parse_rss_items_skips_items_without_a_cve():
    items = threat_intel._parse_rss_items(_rss(_NO_CVE_ITEM), "alert")
    assert items == []


def test_parse_rss_items_handles_multiple_items():
    items = threat_intel._parse_rss_items(_rss(_ALERT_ITEM + _ADVISORY_ITEM), "advisory")
    cves = {i["cve"] for i in items}
    assert cves == {"CVE-2021-44228", "CVE-2023-12345"}


def test_parse_rss_items_returns_empty_list_on_malformed_xml():
    assert threat_intel._parse_rss_items("not xml at all <<<", "alert") == []


def test_parse_rss_items_is_case_insensitive_for_cve_ids():
    xml_text = _rss("""<item>
<title>Issue cve-2022-00001 reported</title>
<link>https://example.invalid</link>
<description></description>
<pubDate></pubDate>
</item>""")
    items = threat_intel._parse_rss_items(xml_text, "advisory")
    assert items[0]["cve"] == "CVE-2022-00001"


# ---------------------------------------------------------------------------
# get_acsc_entries / has_alert — using a monkeypatched fetch to avoid network
# ---------------------------------------------------------------------------

def _patch_fetch(monkeypatch, alert_xml="", advisory_xml=""):
    def _fake_fetch_feed(url, source):
        xml_text = alert_xml if source == "alert" else advisory_xml
        if not xml_text:
            return [], None
        return threat_intel._parse_rss_items(xml_text, source), None

    monkeypatch.setattr(threat_intel, "_fetch_feed", _fake_fetch_feed)


def test_get_acsc_entries_returns_empty_for_no_cve():
    assert threat_intel.get_acsc_entries(None) == []
    assert threat_intel.get_acsc_entries("") == []


def test_get_acsc_entries_returns_matching_alert(monkeypatch):
    _patch_fetch(monkeypatch, alert_xml=_rss(_ALERT_ITEM))
    entries = threat_intel.get_acsc_entries("CVE-2021-44228")
    assert len(entries) == 1
    assert entries[0]["source"] == "alert"


def test_get_acsc_entries_returns_empty_for_unmatched_cve(monkeypatch):
    _patch_fetch(monkeypatch, alert_xml=_rss(_ALERT_ITEM))
    assert threat_intel.get_acsc_entries("CVE-9999-99999") == []


def test_get_acsc_entries_sorts_alerts_before_advisories(monkeypatch):
    # Same CVE referenced by both an advisory and (separately) an alert.
    alert_xml = _rss("""<item>
<title>Alert re CVE-2024-00001</title>
<link>https://www.cyber.gov.au/alerts/a</link>
<description></description>
<pubDate></pubDate>
</item>""")
    advisory_xml = _rss("""<item>
<title>Advisory re CVE-2024-00001</title>
<link>https://www.cyber.gov.au/advisories/a</link>
<description></description>
<pubDate></pubDate>
</item>""")
    _patch_fetch(monkeypatch, alert_xml=alert_xml, advisory_xml=advisory_xml)
    entries = threat_intel.get_acsc_entries("CVE-2024-00001")
    assert [e["source"] for e in entries] == ["alert", "advisory"]


def test_has_alert_true_only_when_an_alert_entry_present():
    assert threat_intel.has_alert([{"source": "alert"}]) is True
    assert threat_intel.has_alert([{"source": "advisory"}]) is False
    assert threat_intel.has_alert([]) is False
    assert threat_intel.has_alert(None) is False


def test_both_feeds_failing_keeps_previous_cache(monkeypatch):
    _patch_fetch(monkeypatch, alert_xml=_rss(_ALERT_ITEM))
    first = threat_intel.get_acsc_entries("CVE-2021-44228")
    assert first  # populated from the first (successful) refresh

    # Force a refresh where both feeds now fail.
    threat_intel._cache["fetched_at"] = 0.0

    def _always_fail(url, source):
        return [], "connection refused"

    monkeypatch.setattr(threat_intel, "_fetch_feed", _always_fail)
    second = threat_intel.get_acsc_entries("CVE-2021-44228")
    assert second == first  # previous cache preserved, not wiped


# ---------------------------------------------------------------------------
# format_acsc_for_prompt
# ---------------------------------------------------------------------------

def test_format_acsc_for_prompt_empty_for_no_entries():
    assert threat_intel.format_acsc_for_prompt([]) == ""
    assert threat_intel.format_acsc_for_prompt(None) == ""


def test_format_acsc_for_prompt_labels_alert_and_advisory_distinctly():
    entries = [
        {"source": "alert", "title": "Alert title", "link": "https://a", "pub_date": "2021"},
        {"source": "advisory", "title": "Advisory title", "link": "https://b", "pub_date": "2023"},
    ]
    text = threat_intel.format_acsc_for_prompt(entries)
    assert "[ALERT]" in text
    assert "[ADVISORY]" in text
    assert "Alert title" in text
    assert "Advisory title" in text
    assert "NOT confirmation of active exploitation" in text


def test_format_acsc_for_prompt_caps_at_three_items():
    entries = [{"source": "advisory", "title": f"Item {i}", "link": "https://x", "pub_date": ""} for i in range(5)]
    text = threat_intel.format_acsc_for_prompt(entries)
    item_lines = [line for line in text.splitlines() if line.startswith("- [ADVISORY]")]
    assert len(item_lines) == 3


# ---------------------------------------------------------------------------
# status()
# ---------------------------------------------------------------------------

def test_status_reports_counts_and_urls(monkeypatch):
    _patch_fetch(monkeypatch, alert_xml=_rss(_ALERT_ITEM), advisory_xml=_rss(_ADVISORY_ITEM))
    result = threat_intel.status()
    assert result["alert_items"] == 1
    assert result["advisory_items"] == 1
    assert result["distinct_cves_referenced"] == 2
    assert result["alerts_feed_url"] == threat_intel.ACSC_ALERTS_FEED_URL
    assert result["advisories_feed_url"] == threat_intel.ACSC_ADVISORIES_FEED_URL
    assert result["errors"] == []
