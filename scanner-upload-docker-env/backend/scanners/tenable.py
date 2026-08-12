import os
import time

import requests

from .base import BaseScanner
from .utils import normalize_vuln

TENABLE_BASE_URL = os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com")


class TenableScanner(BaseScanner):
    """Supports two ways of getting Tenable data in:

    1. Uploading a Tenable vulnerability export (JSON) through /api/upload-scan
       — can_parse()/parse() below handle this today.
    2. Triggering a live scan through /api/scan, if TENABLE_ACCESS_KEY and
       TENABLE_SECRET_KEY are set — run() below drives Tenable.io's
       launch-scan -> poll -> vulnerability-export workflow.

    NOTE: run() and _parse_finding() are written against Tenable.io's
    documented API shape but haven't been exercised against a live account.
    Validate field names against your team's actual export payload (grab one
    JSON export and compare) and adjust _parse_finding() if anything doesn't
    line up — the rest of the app (upload endpoint, live-scan endpoint,
    frontend) won't need to change either way.
    """

    name = "tenable"

    def can_parse(self, data) -> bool:
        if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
            return True
        if isinstance(data, list) and data and isinstance(data[0], dict) and "plugin" in data[0]:
            return True
        return False

    def parse(self, data) -> list:
        findings = data.get("vulnerabilities") if isinstance(data, dict) else data
        return [self._parse_finding(f) for f in (findings or []) if isinstance(f, dict)]

    def _parse_finding(self, finding):
        plugin = finding.get("plugin", {}) or {}
        asset = finding.get("asset", {}) or {}
        cve_list = plugin.get("cve") or []
        return normalize_vuln(
            cve=cve_list[0] if cve_list else (f"PLUGIN-{plugin.get('id')}" if plugin.get("id") else None),
            package=None,
            installedVersion=None,
            severity=finding.get("severity") or plugin.get("risk_factor"),
            cvss=plugin.get("cvss3_base_score") or plugin.get("cvss_base_score"),
            title=plugin.get("name"),
            description=plugin.get("description"),
            references=plugin.get("see_also") or [],
            publishedDate=plugin.get("publication_date"),
            asset=asset.get("hostname") or asset.get("ipv4") or asset.get("uuid"),
            source=self.name,
        )

    def run(self, target: str, **kwargs) -> dict:
        """`target` is treated as an existing Tenable scan ID to launch, wait
        for, then export findings from. Adjust if your team wants to look
        scans up by name instead."""
        access_key = os.environ.get("TENABLE_ACCESS_KEY")
        secret_key = os.environ.get("TENABLE_SECRET_KEY")
        if not access_key or not secret_key:
            raise RuntimeError(
                "Tenable API credentials not configured. Set the "
                "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY environment variables."
            )

        headers = {
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Content-Type": "application/json",
        }

        launch_resp = requests.post(
            f"{TENABLE_BASE_URL}/scans/{target}/launch", headers=headers, timeout=30
        )
        launch_resp.raise_for_status()

        self._wait_for_scan_completion(target, headers)

        export_resp = requests.post(
            f"{TENABLE_BASE_URL}/vulns/export",
            headers=headers,
            json={"filters": {"scan_id": target}},
            timeout=30,
        )
        export_resp.raise_for_status()
        export_uuid = export_resp.json()["export_uuid"]

        chunk_ids = self._wait_for_export(export_uuid, headers)

        findings = []
        for chunk_id in chunk_ids:
            chunk_resp = requests.get(
                f"{TENABLE_BASE_URL}/vulns/export/{export_uuid}/chunks/{chunk_id}",
                headers=headers,
                timeout=30,
            )
            chunk_resp.raise_for_status()
            findings.extend(chunk_resp.json())

        return {"vulnerabilities": findings}

    @staticmethod
    def _wait_for_scan_completion(scan_id, headers, timeout=600, poll_interval=10):
        elapsed = 0
        while elapsed < timeout:
            status_resp = requests.get(f"{TENABLE_BASE_URL}/scans/{scan_id}", headers=headers, timeout=30)
            status_resp.raise_for_status()
            status = status_resp.json().get("info", {}).get("status")
            if status == "completed":
                return
            if status in ("aborted", "canceled", "error"):
                raise RuntimeError(f"Tenable scan ended with status: {status}")
            time.sleep(poll_interval)
            elapsed += poll_interval
        raise RuntimeError(f"Tenable scan did not complete within {timeout}s")

    @staticmethod
    def _wait_for_export(export_uuid, headers, timeout=300, poll_interval=5):
        elapsed = 0
        while elapsed < timeout:
            status_resp = requests.get(
                f"{TENABLE_BASE_URL}/vulns/export/{export_uuid}/status", headers=headers, timeout=30
            )
            status_resp.raise_for_status()
            body = status_resp.json()
            if body.get("status") == "FINISHED":
                return body.get("chunks_available", [])
            if body.get("status") == "ERROR":
                raise RuntimeError("Tenable export failed")
            time.sleep(poll_interval)
            elapsed += poll_interval
        raise RuntimeError(f"Tenable export did not finish within {timeout}s")
