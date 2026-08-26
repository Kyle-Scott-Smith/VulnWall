from flask import Flask, request, jsonify, session
from flask_cors import CORS
import json
import logging
import os
import secrets
from concurrent.futures import ThreadPoolExecutor

import tenable_client
from ai_analysis import OllamaVulnerabilityAnalyzer
from chatbot import ScanChatbot

from scanners.registry import SCANNERS, detect_scanner, get_scanner
from scanners.utils import dedupe_by_cve, sort_by_severity
from jira_integration import jira_bp
from registry_credentials import registry_bp, get_credentials as get_registry_credentials
from auth import auth_bp
from business_context import business_context_bp, get_business_context
from tickets import tickets_bp
from scans import scans_bp, record_scan
from dashboard import dashboard_bp

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Needed for session cookies (Jira OAuth state, registry credential lookup,
# and now the logged-in user id set by auth.py on signup/login). Falls back
# to a random key per process start if unset, which is fine for local demo
# use; set FLASK_SECRET_KEY explicitly for anything longer-lived than a
# single dev session — otherwise everyone gets signed out on every restart.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# Allow the React dev server (and any other origin) to call this API during
# local development. Tighten this to your actual frontend origin in production,
# e.g. CORS(app, origins=["https://your-frontend-domain"]).
CORS(app, supports_credentials=True)

app.register_blueprint(jira_bp)
app.register_blueprint(registry_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(business_context_bp)
app.register_blueprint(tickets_bp)
app.register_blueprint(scans_bp)
app.register_blueprint(dashboard_bp)

MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB safety limit for uploaded scan files

# /api/analyze calls out to Ollama once per finding (more if a finding needs
# retries — see MAX_RETRIES in ai_analysis.py), and each call can take
# several seconds. Doing that in a plain for-loop meant a 15-finding scan
# took 15x as long as a single call, made worse now that the frontend
# blocks its "Next" button on this request finishing (see UploadStep in
# App.jsx) instead of racing ahead with placeholder data. Running findings
# through a small thread pool instead lets Ollama work on several requests
# in parallel - keep this modest, since a single local Ollama instance
# only has so much throughput before concurrent requests just start
# queuing behind each other anyway.
AI_ANALYSIS_CONCURRENCY = int(os.getenv("AI_ANALYSIS_CONCURRENCY", "4"))

# Built lazily on first use rather than at import time. Ollama needs no
# API key, but the server might not be running yet — /api/analyze and
# /api/chat catch that per-request and return a clear error instead of
# crashing the whole backend.
_analyzer = None
_chatbot = None


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        _analyzer = OllamaVulnerabilityAnalyzer()
    return _analyzer


def _get_chatbot():
    global _chatbot
    if _chatbot is None:
        _chatbot = ScanChatbot()
    return _chatbot


def _cross_reference_tenable(vulnerabilities):
    """Best-effort: check each CVE against the org's Tenable.io asset
    inventory and attach tenable_exposure to each finding. Silently skipped
    if Tenable keys aren't configured, or if the lookup fails for any reason
    - scanning should never hard-fail just because this enrichment step did.
    Applied regardless of which scanner produced the findings."""
    try:
        tio = tenable_client.get_client()
        cve_ids = [v["cve"] for v in vulnerabilities if v.get("cve")]
        tenable_results = tenable_client.lookup_findings_by_cve(tio, cve_ids)
        for v in vulnerabilities:
            v["tenable_exposure"] = tenable_results.get(v.get("cve"))
    except EnvironmentError:
        logger.info("Tenable keys not configured - skipping CVE cross-reference")
    except Exception:
        logger.exception("Tenable CVE lookup failed - continuing without it")
    return vulnerabilities


def _finalize(vulnerabilities):
    """Shared post-processing applied no matter which scanner produced the
    findings or whether they came from an upload or a live scan: collapse
    duplicate CVEs, cross-reference against Tenable's asset inventory, then
    sort by severity/CVSS."""
    vulnerabilities = dedupe_by_cve(vulnerabilities)
    vulnerabilities = _cross_reference_tenable(vulnerabilities)
    vulnerabilities = sort_by_severity(vulnerabilities)
    return vulnerabilities


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/ollama-status", methods=["GET"])
def ollama_status():
    """
    Diagnostic endpoint: what model will /api/analyze and /api/chat
    actually use right now, and what's available on the Ollama server.
    Useful for exactly the kind of "model not found" confusion this had
    before — check this instead of guessing at a model name.
    """
    import ollama_client
    requested = ollama_client.OLLAMA_MODEL
    try:
        models = ollama_client.list_models()
        resolved = ollama_client.resolve_model(requested)
        return jsonify({
            "ollama_host": ollama_client.OLLAMA_HOST,
            "requested_model": requested,
            "resolved_model": resolved,
            "available_models": [m.get("name") or m.get("model") for m in models],
        })
    except ollama_client.OllamaError as e:
        return jsonify({"ollama_host": ollama_client.OLLAMA_HOST, "requested_model": requested, "error": str(e)}), 503


@app.route("/api/scanners", methods=["GET"])
def list_scanners():
    """Lets the frontend build a scanner picker without hardcoding names."""
    result = {}
    for name, scanner in SCANNERS.items():
        info = {"supportsLiveScan": scanner.supports_run()}
        if hasattr(scanner, "registries"):
            info["configuredRegistries"] = scanner.registries()
        result[name] = info
    return jsonify(result)


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

    scanner = detect_scanner(data)
    if scanner is None:
        return jsonify({
            "error": f"Unrecognized scan format. Supported scanners: {', '.join(SCANNERS)}"
        }), 400

    vulnerabilities = _finalize(scanner.parse(data))

    # Best-effort dashboard history — only recorded for a signed-in account
    # (see scans.py); an anonymous upload still works, it just won't show
    # up on any account's Security Overview since there's no account to
    # attach it to.
    record_scan(session.get("user_id"), scanner.name, "upload", file.filename, vulnerabilities)

    return jsonify({
        "status": "processed",
        "scanner": scanner.name,
        "vulnerabilitiesFound": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    })


@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    """Trigger a live scan instead of uploading a pre-generated report.
    Body: {"scanner": "trivy", "target": "myapp:latest", ...extra options}
    Extra JSON fields are passed straight through to that scanner's run()
    (e.g. Trivy accepts scan_type/mode; see scanners/trivy.py)."""
    body = request.get_json(silent=True) or {}
    scanner_name = body.get("scanner")
    target = body.get("target")

    if not scanner_name:
        return jsonify({"error": f"Missing 'scanner'. Choose one of: {', '.join(SCANNERS)}"}), 400
    if not target:
        return jsonify({"error": "Missing 'target'"}), 400

    try:
        scanner = get_scanner(scanner_name)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    extra_kwargs = {k: v for k, v in body.items() if k not in ("scanner", "target", "usePrivateRegistry")}

    # "usePrivateRegistry" is a plain bool from the frontend — never actual
    # credentials. The real username/password come from whatever the user
    # connected via the Profile page's "Connect registry" form (see
    # registry_credentials.py), looked up here by browser session so
    # nothing sensitive travels in this request body.
    if scanner_name == "trivy" and body.get("usePrivateRegistry"):
        reg_url, reg_username, reg_password = get_registry_credentials()
        if not reg_url:
            return jsonify({"error": "No private registry connected. Connect one from the Profile page first."}), 400
        extra_kwargs["registry_url"] = reg_url
        extra_kwargs["registry_username"] = reg_username
        extra_kwargs["registry_password"] = reg_password

    try:
        raw = scanner.run(target, **extra_kwargs)
    except NotImplementedError as e:
        return jsonify({"error": str(e)}), 400
    except (ValueError, RuntimeError) as e:
        return jsonify({"error": str(e)}), 502

    vulnerabilities = _finalize(scanner.parse(raw))

    # Same dashboard-history recording as the upload path above.
    record_scan(session.get("user_id"), scanner.name, "live", target, vulnerabilities)

    return jsonify({
        "status": "processed",
        "scanner": scanner.name,
        "vulnerabilitiesFound": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Runs each vulnerability through the AI analyzer and merges the result
    back in.

    Body: {"vulnerabilities": [ ...normalized vuln objects from /api/upload-scan or /api/scan... ]}

    Returns the same list with why/fixes/confidence/priority_tier/
    ai_generated/business_priority_score added to each entry, ORDERED by
    business_priority_score (most important first) rather than raw CVSS -
    this is what the frontend's AI Summary/Select steps render by default.

    If the signed-in user has completed the business-context survey (see
    business_context.py), that record is loaded here by session and fed
    into every analyze() call so both the AI's write-up and the ordering
    reflect real-world business impact (internet-facing? regulated data?
    a life-safety system?) instead of CVSS alone. Anonymous sessions, or
    accounts that haven't filled out the survey yet, still get a sensible
    result - compute_business_priority_score() degrades to a CVSS/severity
    score in that case, same ordering as before.
    """
    body = request.get_json(force=True, silent=True) or {}
    vulnerabilities = body.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return jsonify({"error": "Expected a 'vulnerabilities' array"}), 400

    try:
        analyzer = _get_analyzer()
    except EnvironmentError as e:
        return jsonify({"error": str(e)}), 503

    business_context = get_business_context(session.get("user_id"))

    # Only real dicts get analyzed (mirrors the old loop's skip-if-not-dict
    # guard).
    dict_indices = [i for i, v in enumerate(vulnerabilities) if isinstance(v, dict)]
    results = []

    def _analyze_one(pos):
        vuln = vulnerabilities[dict_indices[pos]]
        ai_result = analyzer.analyze(vuln, business_context=business_context)
        return {**vuln, **ai_result}

    if dict_indices:
        with ThreadPoolExecutor(max_workers=min(AI_ANALYSIS_CONCURRENCY, len(dict_indices))) as pool:
            results = list(pool.map(_analyze_one, range(len(dict_indices))))

    analyzed = results
    analyzed.sort(key=lambda v: v.get("business_priority_score") or 0, reverse=True)

    return jsonify({
        "status": "analyzed",
        "businessContextApplied": business_context is not None,
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
    # or any scanners/*.py file picks up changes without a rebuild (this
    # folder is bind-mounted — see docker-compose.yml).
    app.run(host="0.0.0.0", port=5000, debug=True)
