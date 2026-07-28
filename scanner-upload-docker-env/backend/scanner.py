from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import logging

import tenable_client
from ai_analysis import ClaudeVulnerabilityAnalyzer
from chatbot import ScanChatbot

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Allow the React dev server (and any other origin) to call this API during
# local development. Tighten this to your actual frontend origin in production,
# e.g. CORS(app, origins=["https://your-frontend-domain"]).
CORS(app)

MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB safety limit for uploaded scan files

# Built lazily on first use rather than at import time, so the app still
# starts (upload-scan keeps working) even if ANTHROPIC_API_KEY isn't set yet —
# /api/analyze and /api/chat just return a clear 503 instead of crashing the
# whole backend.
_analyzer = None
_chatbot = None


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        _analyzer = ClaudeVulnerabilityAnalyzer()
    return _analyzer


def _get_chatbot():
    global _chatbot
    if _chatbot is None:
        _chatbot = ScanChatbot()
    return _chatbot


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

    # Send the CVE IDs found in this upload to the Tenable.io API to check
    # whether they also show up anywhere in the org's scanned asset
    # inventory (i.e. real exposure beyond just this Trivy report), and
    # merge that onto each finding. Best-effort: if Tenable isn't
    # configured or the lookup fails, the upload still succeeds — findings
    # just won't have tenable_exposure attached.
    try:
        tio = tenable_client.get_client()
        cve_ids = [v["cve"] for v in vulnerabilities if v.get("cve")]
        tenable_results = tenable_client.lookup_findings_by_cve(tio, cve_ids)
        for v in vulnerabilities:
            v["tenable_exposure"] = tenable_results.get(v.get("cve"))
    except EnvironmentError:
        logger.info("Tenable keys not configured — skipping CVE cross-reference")
    except Exception:
        logger.exception("Tenable CVE lookup failed — continuing without it")

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


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Runs each vulnerability through Claude and merges the result back in.

    Body: {"vulnerabilities": [ ...normalized vuln objects from /api/upload-scan... ]}

    Returns the same list with why/fixes/confidence/priority_tier/ai_generated
    added to each entry — this is what the frontend's CveDetailStep reads.
    """
    body = request.get_json(force=True, silent=True) or {}
    vulnerabilities = body.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return jsonify({"error": "Expected a 'vulnerabilities' array"}), 400

    try:
        analyzer = _get_analyzer()
    except EnvironmentError as e:
        return jsonify({"error": str(e)}), 503

    analyzed = []
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        ai_result = analyzer.analyze(vuln)
        analyzed.append({**vuln, **ai_result})

    return jsonify({
        "status": "analyzed",
        "vulnerabilities": analyzed,
    })


@app.route("/api/chat", methods=["POST"])
def chat():
    """
    Scan-scoped chatbot. Body:
      {
        "question": "which CVEs affect host X",
        "vulnerabilities": [ ...current scan's findings... ],
        "history": [ {"role": "user"|"assistant", "content": "..."}, ... ]  # optional
      }
    Returns {"answer": "..."}.
    """
    body = request.get_json(force=True, silent=True) or {}
    question = (body.get("question") or "").strip()
    vulnerabilities = body.get("vulnerabilities")
    history = body.get("history")

    if not question:
        return jsonify({"error": "Missing 'question'"}), 400
    if not isinstance(vulnerabilities, list):
        return jsonify({"error": "Expected a 'vulnerabilities' array for scan context"}), 400
    if history is not None and not isinstance(history, list):
        return jsonify({"error": "'history' must be an array if provided"}), 400

    try:
        chatbot = _get_chatbot()
    except EnvironmentError as e:
        return jsonify({"error": str(e)}), 503

    try:
        answer = chatbot.ask(question, vulnerabilities, history)
    except Exception as e:
        logger.exception("Chat request failed")
        return jsonify({"error": f"Chat request failed: {str(e)}"}), 502

    return jsonify({"answer": answer})


if __name__ == "__main__":
    # host=0.0.0.0 so the Flask dev server is reachable from outside the
    # container (from the host machine, or from the frontend container).
    # debug=True keeps the Werkzeug auto-reloader on, so editing scanner.py
    # picks up changes without a rebuild (the file is bind-mounted below).
    app.run(host="0.0.0.0", port=5000, debug=True)
