from flask import Flask, request, jsonify
from flask_cors import CORS
import json

from scanners.registry import SCANNERS, detect_scanner, get_scanner
from scanners.utils import dedupe_by_cve, sort_by_severity

app = Flask(__name__)

# Allow the React dev server (and any other origin) to call this API during
# local development. Tighten this to your actual frontend origin in production,
# e.g. CORS(app, origins=["https://your-frontend-domain"]).
CORS(app)

MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB safety limit for uploaded scan files


def _finalize(vulnerabilities):
    """Shared post-processing applied no matter which scanner produced the
    findings: collapse duplicate CVEs, then sort by severity/CVSS."""
    vulnerabilities = dedupe_by_cve(vulnerabilities)
    vulnerabilities = sort_by_severity(vulnerabilities)
    return vulnerabilities


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/scanners", methods=["GET"])
def list_scanners():
    """Lets the frontend build a scanner picker without hardcoding names."""
    return jsonify({
        name: {"supportsLiveScan": scanner.supports_run()}
        for name, scanner in SCANNERS.items()
    })


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

    extra_kwargs = {k: v for k, v in body.items() if k not in ("scanner", "target")}

    try:
        raw = scanner.run(target, **extra_kwargs)
    except NotImplementedError as e:
        return jsonify({"error": str(e)}), 400
    except (ValueError, RuntimeError) as e:
        return jsonify({"error": str(e)}), 502

    vulnerabilities = _finalize(scanner.parse(raw))

    return jsonify({
        "status": "processed",
        "scanner": scanner.name,
        "vulnerabilitiesFound": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    })


if __name__ == "__main__":
    # host=0.0.0.0 so the Flask dev server is reachable from outside the
    # container (from the host machine, or from the frontend container).
    # debug=True keeps the Werkzeug auto-reloader on, so editing scanner.py
    # or any scanners/*.py file picks up changes without a rebuild (this
    # folder is bind-mounted — see docker-compose.yml).
    app.run(host="0.0.0.0", port=5000, debug=True)
