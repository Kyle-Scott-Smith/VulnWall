from flask import Flask, request, jsonify
from flask_cors import CORS
import json

app = Flask(__name__)

# Allow the React dev server (and any other origin) to call this API during
# local development. Tighten this to your actual frontend origin in production,
# e.g. CORS(app, origins=["https://your-frontend-domain"]).
CORS(app)

MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB safety limit for uploaded scan files


def _extract_cvss(vuln):
    """Trivy nests CVSS scores under a vendor key (nvd, redhat, ghsa, ...).
    Prefer a V3 score from any source, then fall back to V2."""
    cvss_block = vuln.get("CVSS")
    if not isinstance(cvss_block, dict):
        return None

    for source in cvss_block.values():
        if isinstance(source, dict) and source.get("V3Score") is not None:
            return source["V3Score"]

    for source in cvss_block.values():
        if isinstance(source, dict) and source.get("V2Score") is not None:
            return source["V2Score"]

    return None


def _title_case_severity(severity):
    if not severity:
        return "Unknown"
    return str(severity).strip().capitalize()


def normalize_vulnerability(vuln, asset=None):
    return {
        "cve": vuln.get("VulnerabilityID"),
        "package": vuln.get("PkgName"),
        "installedVersion": vuln.get("InstalledVersion"),
        "severity": _title_case_severity(vuln.get("Severity")),
        "cvss": _extract_cvss(vuln),
        "title": vuln.get("Title") or vuln.get("VulnerabilityID"),
        "description": vuln.get("Description"),
        "references": vuln.get("References", []) or [],
        "publishedDate": vuln.get("PublishedDate"),
        "asset": asset or "unknown",
    }


def dedupe_by_cve(vulnerabilities):
    """If the same CVE shows up more than once (e.g. across targets), keep
    the entry with the highest CVSS score so downstream consumers see one
    row per CVE."""
    best_by_cve = {}
    for vuln in vulnerabilities:
        cve = vuln.get("cve")
        if not cve:
            # Keep entries with no CVE id (rare) untouched, keyed by identity.
            best_by_cve[id(vuln)] = vuln
            continue
        existing = best_by_cve.get(cve)
        if existing is None:
            best_by_cve[cve] = vuln
        else:
            existing_score = existing.get("cvss") or 0
            new_score = vuln.get("cvss") or 0
            if new_score > existing_score:
                best_by_cve[cve] = vuln
    return list(best_by_cve.values())


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/upload-scan", methods=["POST"])
def upload_scan():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.lower().endswith(".json"):
        return jsonify({"error": "Only .json scan files are supported"}), 400

    raw = file.read(MAX_FILE_SIZE_BYTES + 1)
    if len(raw) > MAX_FILE_SIZE_BYTES:
        return jsonify({"error": "File exceeds 20MB upload limit"}), 400

    try:
        data = json.loads(raw)
    except Exception as e:
        return jsonify({"error": f"Invalid JSON: {str(e)}"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "Unrecognized scan format: expected a JSON object"}), 400

    results = data.get("Results")
    if not isinstance(results, list):
        return jsonify({"error": "Unrecognized scan format: this doesn't look like a Trivy report (missing 'Results' array)"}), 400

    vulnerabilities = []
    for result in results:
        if not isinstance(result, dict):
            continue
        asset = result.get("Target")
        for vuln in result.get("Vulnerabilities", []) or []:
            if isinstance(vuln, dict):
                vulnerabilities.append(normalize_vulnerability(vuln, asset))

    vulnerabilities = dedupe_by_cve(vulnerabilities)

    # Highest severity/CVSS first so the frontend's "top risks" views are meaningful.
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    vulnerabilities.sort(
        key=lambda v: (severity_rank.get(v["severity"], 0), v["cvss"] or 0),
        reverse=True,
    )

    return jsonify({
        "status": "processed",
        "vulnerabilitiesFound": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    })


if __name__ == "__main__":
    # host=0.0.0.0 so the Flask dev server is reachable from outside the
    # container (from the host machine, or from the frontend container).
    # debug=True keeps the Werkzeug auto-reloader on, so editing scanner.py
    # picks up changes without a rebuild (the file is bind-mounted below).
    app.run(host="0.0.0.0", port=5000, debug=True)
