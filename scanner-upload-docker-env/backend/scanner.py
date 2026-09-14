from flask import Flask, request, jsonify, session, send_file
from flask_cors import CORS
import json
import logging
import os
import secrets
from io import BytesIO
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

import tenable_client
from ai_analysis import OllamaVulnerabilityAnalyzer
from chatbot import ScanChatbot
import email_notifications

from scanners.registry import SCANNERS, detect_scanner, get_scanner
from scanners.utils import dedupe_by_cve, sort_by_severity
from jira_integration import jira_bp
from registry_credentials import registry_bp, get_credentials as get_registry_credentials
from auth import auth_bp, get_user_by_id
from google_auth import google_auth_bp
from business_context import business_context_bp, get_business_context
from tickets import tickets_bp
from scans import scans_bp, record_scan
from dashboard import dashboard_bp

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

CORS(app, supports_credentials=True)

app.register_blueprint(jira_bp)
app.register_blueprint(registry_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(google_auth_bp)
app.register_blueprint(business_context_bp)
app.register_blueprint(tickets_bp)
app.register_blueprint(scans_bp)
app.register_blueprint(dashboard_bp)

MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024

AI_ANALYSIS_CONCURRENCY = int(os.getenv("AI_ANALYSIS_CONCURRENCY", "4"))

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
    vulnerabilities = dedupe_by_cve(vulnerabilities)
    vulnerabilities = _cross_reference_tenable(vulnerabilities)
    vulnerabilities = sort_by_severity(vulnerabilities)
    return vulnerabilities


def _maybe_send_critical_alert(user_id, scanner_name, target, new_critical_vulns):
    """Fires off the "new Critical findings" email (see
    email_notifications.py) if — and only if — someone's signed in, this
    scan actually turned up new Criticals (record_scan already did the
    "new since last scan" diffing), and that user has the Profile page's
    Email notifications toggle on. Never lets an email problem (SMTP not
    configured, provider rejects the send, network hiccup) fail the scan
    request itself — the scan already succeeded by the time this runs."""
    if not user_id or not new_critical_vulns:
        return

    user = get_user_by_id(user_id)
    if not user or not user["notify_on_critical"]:
        return

    try:
        email_notifications.send_critical_alert(
            user["email"], user["name"], new_critical_vulns,
            scan_context={"scanner": scanner_name, "target": target},
        )
    except EnvironmentError:
        logger.info("Email alerts not configured - skipping critical-finding email")
    except Exception:
        logger.exception("Failed to send critical-finding email alert")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/ollama-status", methods=["GET"])
def ollama_status():
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

    new_critical = record_scan(session.get("user_id"), scanner.name, "upload", file.filename, vulnerabilities)
    _maybe_send_critical_alert(session.get("user_id"), scanner.name, file.filename, new_critical)

    return jsonify({
        "status": "processed",
        "scanner": scanner.name,
        "vulnerabilitiesFound": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    })


@app.route("/api/scan", methods=["POST"])
def trigger_scan():
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

    new_critical = record_scan(session.get("user_id"), scanner.name, "live", target, vulnerabilities)
    _maybe_send_critical_alert(session.get("user_id"), scanner.name, target, new_critical)

    return jsonify({
        "status": "processed",
        "scanner": scanner.name,
        "vulnerabilitiesFound": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    body = request.get_json(force=True, silent=True) or {}
    vulnerabilities = body.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return jsonify({"error": "Expected a 'vulnerabilities' array"}), 400

    try:
        analyzer = _get_analyzer()
    except EnvironmentError as e:
        return jsonify({"error": str(e)}), 503

    business_context = get_business_context(session.get("user_id"))

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


# Severity -> row highlight color, same palette as the frontend's severity
# pills (sev-critical/sev-high/sev-medium in App.jsx's css) so the exported
# file visually matches what the person already saw on screen.
_SEVERITY_FILL = {
    "Critical": "FEE2E2",
    "High": "FFEDD5",
    "Medium": "FEF9C3",
    "Low": "DCFCE7",
}

_EXPORT_COLUMNS = [
    ("CVE", "cve", 16),
    ("Title", "title", 42),
    ("Severity", "severity", 11),
    ("CVSS", "cvss", 8),
    ("Business Priority", "business_priority_score", 14),
    ("Asset", "asset", 22),
    ("Package", "package", 18),
    ("Installed Version", "installedVersion", 16),
    ("Why It Matters", "why", 50),
    ("Business Impact", "business_impact", 40),
    ("Suggested Fixes", "fixes", 50),
    ("AI Confidence (%)", "confidence", 14),
    ("Tenable Exposure", "tenable_exposure", 20),
    ("Source", "source", 12),
    ("Published Date", "publishedDate", 16),
]


def _export_cell_value(v, field):
    """Most fields map straight across; a handful need reshaping into
    something a spreadsheet cell can actually hold (lists -> joined text,
    the nested tenable_exposure object -> a short human-readable summary)."""
    if field == "fixes":
        fixes = v.get("fixes")
        return "; ".join(fixes) if isinstance(fixes, list) else (fixes or "")
    if field == "tenable_exposure":
        exposure = v.get("tenable_exposure")
        if not isinstance(exposure, dict):
            return ""
        return "Confirmed in inventory" if exposure.get("matched") else "Not found in inventory"
    value = v.get(field)
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return value if value is not None else ""


@app.route("/api/export", methods=["POST"])
def export_report():
    """
    Exports the current scan's vulnerabilities as a formatted .xlsx file —
    useful for anyone who needs the findings outside the app itself (an
    auditor, a manager, a council member), where Excel's filter/sort/pivot
    beats reading a static list.

    Body: {"vulnerabilities": [ ...normalized vuln objects, same shape as
    /api/upload-scan / /api/scan / /api/analyze return... ]}

    Works with or without AI analysis having run — columns that depend on
    it (Business Priority, Why It Matters, Business Impact, Suggested
    Fixes, AI Confidence) just come back blank for rows that don't have it.
    """
    body = request.get_json(force=True, silent=True) or {}
    vulnerabilities = body.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return jsonify({"error": "Expected a 'vulnerabilities' array"}), 400

    wb = Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="2563EB", end_color="2563EB", fill_type="solid")
    for col_idx, (label, _field, width) in enumerate(_EXPORT_COLUMNS, start=1):
        cell = ws.cell(row=1, column=col_idx, value=label)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(vertical="center")
        ws.column_dimensions[get_column_letter(col_idx)].width = width

    for v in vulnerabilities:
        if not isinstance(v, dict):
            continue
        row_idx = ws.max_row + 1
        for col_idx, (_label, field, _width) in enumerate(_EXPORT_COLUMNS, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=_export_cell_value(v, field))
            cell.alignment = Alignment(vertical="top", wrap_text=field in ("why", "business_impact", "fixes", "title"))
        fill_color = _SEVERITY_FILL.get(v.get("severity"))
        if fill_color:
            ws.cell(row=row_idx, column=3).fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type="solid")

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(_EXPORT_COLUMNS))}{ws.max_row}"

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    filename = f"vulnerability-report-{datetime.now().strftime('%Y-%m-%d')}.xlsx"
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=filename,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)