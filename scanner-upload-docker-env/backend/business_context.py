"""
Business context questionnaire — backend for the short form shown once,
right after signup, that asks a few questions about the user's organisation
so the platform can weight vulnerability priority by real-world business
impact rather than CVSS alone.

Same blueprint pattern as auth.py / jira_integration.py / registry_credentials.py.
Storage: same SQLite database as auth.py (DB_PATH import below), one row per
user in a new `business_context` table, keyed by users.id. Requires an
active session (see auth.py) — this data is meaningless without knowing
which account it belongs to.

Endpoints registered by this blueprint (mounted at /api/business-context):
  POST /api/business-context      -> body: see FIELDS below; creates or
                                      overwrites the current user's context
  GET  /api/business-context/me   -> {completed, ...fields} for the
                                      current session, or {completed: false}
                                      if nothing has been submitted yet

Everything here is intentionally short — deeper business context (asset
inventories, ownership, team structure, etc.) is gathered conversationally
by the scan chatbot later. This form only captures the handful of answers
needed to compute an initial CriticalityTier and give the AI analysis
enough grounding to prioritise sensibly on day one.
"""

import json
import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

# Reuse the exact same DB file and connection helper as auth.py so this
# lives in the same SQLite database as the users table (and so the two
# blueprints can't silently drift onto different files).
from auth import DB_PATH, _get_db  # noqa: F401

business_context_bp = Blueprint(
    "business_context", __name__, url_prefix="/api/business-context"
)

# --- Allowed values -----------------------------------------------------
# Kept server-side (not just enforced in the UI) for the same reason
# password rules are re-checked in auth.py: a request that skips the
# client-side form shouldn't be able to write junk into the database.

# availabilityImpact -> criticalityTier. Five tiers so "how bad is an
# outage" has a middle ground between "major disruption" and "minor
# inconvenience" rather than forcing a binary choice.
AVAILABILITY_TO_TIER = {
    "life_safety": 1,       # Critical / life-safety impact
    "major_disruption": 2,  # Major business disruption
    "moderate_disruption": 3,  # Moderate disruption, workarounds available
    "minor_inconvenience": 4,  # Minor inconvenience
    "no_impact": 5,          # No significant impact
}

DATA_SENSITIVITY_OPTIONS = {
    "credentials",       # passwords, API keys, auth secrets
    "financial",         # banking details, card data, payroll
    "medical",           # medical conditions/records, PHI
    "pii",               # names, addresses, other personal data
    "intellectual_property",
    "none",
}

COMPLIANCE_OPTIONS = {
    "hipaa",
    "pci_dss",
    "gdpr",
    "soc2",
    "iso27001",
    "fedramp_nist",
    "none",
}

INTERNET_FACING_OPTIONS = {"public", "internal", "mixed"}

SECTOR_OPTIONS = {
    "healthcare",
    "banking_finance",
    "government_public_sector",
    "education",
    "technology_saas",
    "retail_ecommerce",
    "manufacturing_industrial",
    "energy_utilities",
    "legal",
    "other",
}


def init_business_context_db():
    """Creates the business_context table if it doesn't exist yet. Called
    once at import time (see bottom of file), same as auth.init_db()."""
    conn = _get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS business_context (
                user_id              INTEGER PRIMARY KEY REFERENCES users(id),
                sector               TEXT NOT NULL,
                sector_other         TEXT,
                data_sensitivity     TEXT NOT NULL,  -- JSON array
                availability_impact  TEXT NOT NULL,
                criticality_tier     INTEGER NOT NULL,
                internet_facing      TEXT NOT NULL,
                compliance_scope     TEXT NOT NULL,  -- JSON array
                air_gapped           INTEGER NOT NULL,  -- 0/1
                air_gapped_details   TEXT,
                has_security_team    INTEGER,  -- 0/1, nullable (optional Q)
                created_at           TEXT NOT NULL,
                updated_at           TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _require_login():
    """Returns the current session's user_id, or None if not signed in."""
    return session.get("user_id")


def get_business_context(user_id):
    """Fetches the saved business-context row for a user_id and returns it
    as a plain dict (same shape as GET /api/business-context/me's payload),
    or None if the user hasn't completed the survey (or user_id is falsy).

    This is the shared lookup used by anything that needs to factor business
    context into its logic without going through the HTTP endpoint — right
    now that's /api/analyze in scanner.py, which uses it to weight AI
    vulnerability analysis and priority ordering by business impact instead
    of CVSS alone.
    """
    if not user_id:
        return None

    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM business_context WHERE user_id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return None

    return {
        "sector": row["sector"],
        "sectorOther": row["sector_other"],
        "dataSensitivity": json.loads(row["data_sensitivity"]),
        "availabilityImpact": row["availability_impact"],
        "criticalityTier": row["criticality_tier"],
        "internetFacing": row["internet_facing"],
        "complianceScope": json.loads(row["compliance_scope"]),
        "airGapped": bool(row["air_gapped"]),
        "airGappedDetails": row["air_gapped_details"],
        "hasSecurityTeam": None
        if row["has_security_team"] is None
        else bool(row["has_security_team"]),
    }


def _validate(body):
    """Mirrors the frontend's form validation. Returns an error string, or
    None if everything checks out."""
    sector = body.get("sector")
    if sector not in SECTOR_OPTIONS:
        return "Please select a valid department/sector"
    if sector == "other" and not (body.get("sectorOther") or "").strip():
        return "Please describe your department/sector"

    data_sensitivity = body.get("dataSensitivity")
    if (
        not isinstance(data_sensitivity, list)
        or not data_sensitivity
        or not set(data_sensitivity).issubset(DATA_SENSITIVITY_OPTIONS)
    ):
        return "Please select at least one option for data sensitivity"
    if "none" in data_sensitivity and len(data_sensitivity) > 1:
        return "'None of the above' can't be combined with other data types"

    availability_impact = body.get("availabilityImpact")
    if availability_impact not in AVAILABILITY_TO_TIER:
        return "Please select an availability impact level"

    internet_facing = body.get("internetFacing")
    if internet_facing not in INTERNET_FACING_OPTIONS:
        return "Please select whether this system is internet-facing"

    compliance_scope = body.get("complianceScope")
    if (
        not isinstance(compliance_scope, list)
        or not compliance_scope
        or not set(compliance_scope).issubset(COMPLIANCE_OPTIONS)
    ):
        return "Please select at least one compliance option (or 'None / not sure')"
    if "none" in compliance_scope and len(compliance_scope) > 1:
        return "'None / not sure' can't be combined with specific frameworks"

    if not isinstance(body.get("airGapped"), bool):
        return "Please answer whether you have air-gapped systems"

    has_security_team = body.get("hasSecurityTeam")
    if has_security_team is not None and not isinstance(has_security_team, bool):
        return "hasSecurityTeam must be true, false, or omitted"

    return None


@business_context_bp.route("", methods=["POST"])
def submit():
    user_id = _require_login()
    if not user_id:
        return jsonify({"error": "You must be signed in"}), 401

    body = request.get_json(silent=True) or {}
    error = _validate(body)
    if error:
        return jsonify({"error": error}), 400

    sector = body["sector"]
    sector_other = (body.get("sectorOther") or "").strip() if sector == "other" else None
    availability_impact = body["availabilityImpact"]
    criticality_tier = AVAILABILITY_TO_TIER[availability_impact]
    air_gapped = body["airGapped"]
    air_gapped_details = (body.get("airGappedDetails") or "").strip() or None
    has_security_team = body.get("hasSecurityTeam")

    now = datetime.now(timezone.utc).isoformat()

    conn = _get_db()
    try:
        conn.execute(
            """
            INSERT INTO business_context (
                user_id, sector, sector_other, data_sensitivity,
                availability_impact, criticality_tier, internet_facing,
                compliance_scope, air_gapped, air_gapped_details,
                has_security_team, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                sector=excluded.sector,
                sector_other=excluded.sector_other,
                data_sensitivity=excluded.data_sensitivity,
                availability_impact=excluded.availability_impact,
                criticality_tier=excluded.criticality_tier,
                internet_facing=excluded.internet_facing,
                compliance_scope=excluded.compliance_scope,
                air_gapped=excluded.air_gapped,
                air_gapped_details=excluded.air_gapped_details,
                has_security_team=excluded.has_security_team,
                updated_at=excluded.updated_at
            """,
            (
                user_id,
                sector,
                sector_other,
                json.dumps(body["dataSensitivity"]),
                availability_impact,
                criticality_tier,
                body["internetFacing"],
                json.dumps(body["complianceScope"]),
                1 if air_gapped else 0,
                air_gapped_details,
                None if has_security_team is None else (1 if has_security_team else 0),
                now,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "saved", "criticalityTier": criticality_tier})


@business_context_bp.route("/me", methods=["GET"])
def me():
    user_id = _require_login()
    context = get_business_context(user_id)
    if context is None:
        return jsonify({"completed": False})
    return jsonify({"completed": True, **context})


init_business_context_db()
