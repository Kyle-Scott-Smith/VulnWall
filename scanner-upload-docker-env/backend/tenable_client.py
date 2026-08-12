"""
Tenable.io CVE cross-reference lookup.

Instead of launching a fresh live scan, the upload flow now sends the CVE
IDs found in the uploaded Trivy report to the Tenable.io API and asks:
"does this CVE also show up anywhere in our scanned asset inventory?"

This uses Tenable.io's workbench vulnerabilities endpoint (via pyTenable),
filtered by CVE, which searches across everything Tenable has already
scanned — it does not launch a new scan or touch any assets.
"""
import logging
import os

from tenable.io import TenableIO

logger = logging.getLogger(__name__)


def get_client() -> TenableIO:
    access_key = os.getenv("TENABLE_ACCESS_KEY")
    secret_key = os.getenv("TENABLE_SECRET_KEY")
    if not access_key or not secret_key:
        raise EnvironmentError("TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY are not set")
    return TenableIO(access_key, secret_key)


def lookup_findings_by_cve(tio: TenableIO, cve_ids: list) -> dict:
    """
    For each CVE ID, query Tenable.io's workbench vulnerabilities filtered
    by that CVE (tio.workbenches.vulns takes filter tuples of
    (field, operator, value) — see pyTenable's WorkbenchesAPI docs).

    Returns {cve_id: {"matched": bool, "instance_count": int, "matches": [...]}}
    so the caller can merge exposure info back into each finding without
    needing to know Tenable's raw response shape.

    Looked up one CVE per call rather than batched, since Tenable's filter
    "eq" operator is documented for single-value matches on this field —
    if your Tenable.io plan supports an "in" style filter for cve, this can
    be batched into fewer calls; check the filter list your account exposes
    via tio.filters.workbench_vuln_filters() before relying on that.
    """
    results = {}
    for cve in cve_ids:
        if not cve:
            continue
        try:
            matches = list(tio.workbenches.vulns(("cve", "eq", cve)))
        except Exception as e:
            logger.warning("Tenable lookup failed for %s: %s", cve, e)
            results[cve] = {"matched": False, "instance_count": 0, "matches": [], "error": str(e)}
            continue

        summarized = [
            {
                "plugin_id": m.get("plugin_id"),
                "plugin_name": m.get("plugin_name"),
                "severity": (m.get("severity") or {}).get("name") if isinstance(m.get("severity"), dict) else m.get("severity"),
                "instance_count": m.get("count", 0),
            }
            for m in matches
        ]
        results[cve] = {
            "matched": len(summarized) > 0,
            "instance_count": sum(m["instance_count"] or 0 for m in summarized),
            "matches": summarized,
        }
    return results
