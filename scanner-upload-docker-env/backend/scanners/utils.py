SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def title_case_severity(severity):
    if not severity:
        return "Unknown"
    return str(severity).strip().capitalize()


def normalize_vuln(**kwargs):
    """Build a vulnerability dict with a consistent shape/defaults regardless
    of which scanner produced it. This is the contract every scanner plugin's
    parse() must honor — it's what the Flask API returns and what App.js
    already knows how to render."""
    return {
        "cve": kwargs.get("cve"),
        "package": kwargs.get("package"),
        "installedVersion": kwargs.get("installedVersion"),
        "severity": title_case_severity(kwargs.get("severity")),
        "cvss": kwargs.get("cvss"),
        "title": kwargs.get("title") or kwargs.get("cve") or "Untitled finding",
        "description": kwargs.get("description"),
        "references": kwargs.get("references") or [],
        "publishedDate": kwargs.get("publishedDate"),
        "asset": kwargs.get("asset") or "unknown",
        "source": kwargs.get("source"),
    }


def dedupe_by_cve(vulnerabilities):
    """If the same CVE shows up more than once (e.g. across targets, or
    reported by more than one scanner), keep the entry with the highest
    CVSS score."""
    best_by_cve = {}
    for vuln in vulnerabilities:
        cve = vuln.get("cve")
        if not cve:
            best_by_cve[id(vuln)] = vuln
            continue
        existing = best_by_cve.get(cve)
        if existing is None or (vuln.get("cvss") or 0) > (existing.get("cvss") or 0):
            best_by_cve[cve] = vuln
    return list(best_by_cve.values())


def sort_by_severity(vulnerabilities):
    return sorted(
        vulnerabilities,
        key=lambda v: (SEVERITY_RANK.get(v.get("severity"), 0), v.get("cvss") or 0),
        reverse=True,
    )
