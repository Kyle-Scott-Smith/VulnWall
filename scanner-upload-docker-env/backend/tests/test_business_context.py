"""Tests for business_context.py — the onboarding questionnaire: server-side
validation, the availability -> criticality-tier mapping, upsert behaviour,
role gating, and the get_business_context() lookup that /api/analyze uses."""
import copy
import importlib
import sqlite3

import pytest

VALID = {
    "sector": "healthcare",
    "dataSensitivity": ["medical", "pii"],
    "availabilityImpact": "major_disruption",
    "internetFacing": "public",
    "exposedSystems": ["website", "api"],
    "complianceScope": ["hipaa"],
    "airGapped": False,
    "topConcern": "legal_regulatory",
    "hadBreach": "no",
    "revenueGenerating": True,
}


def _body(**overrides):
    body = copy.deepcopy(VALID)
    body.update(overrides)
    return body


def _post(client, **overrides):
    return client.post("/api/business-context", json=_body(**overrides))


def _error(client, **overrides):
    r = _post(client, **overrides)
    assert r.status_code == 400, r.get_data(as_text=True)
    return r.get_json()["error"]


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------
def test_submit_requires_sign_in(app_env):
    assert _post(app_env.client()).status_code == 401


def test_viewers_cannot_submit_but_analysts_and_admins_can(app_env):
    viewer, _ = app_env.login_as(role="viewer")
    assert _post(viewer).status_code == 403
    for role in ("analyst", "admin"):
        client, _ = app_env.login_as(role=role)
        assert _post(client).status_code == 200


def test_me_is_not_completed_when_signed_out_or_nothing_saved(app_env):
    assert app_env.client().get("/api/business-context/me").get_json() == {"completed": False}
    client, _ = app_env.login_as()
    assert client.get("/api/business-context/me").get_json() == {"completed": False}


# ---------------------------------------------------------------------------
# Happy path and tier mapping
# ---------------------------------------------------------------------------
def test_submit_saves_and_me_returns_everything_back(app_env):
    client, _ = app_env.login_as()
    r = _post(client, airGappedDetails="  lab network  ", hasSecurityTeam=True)
    assert r.get_json() == {"status": "saved", "criticalityTier": 2}
    me = client.get("/api/business-context/me").get_json()
    assert me == {
        "completed": True,
        "sector": "healthcare", "sectorOther": None,
        "dataSensitivity": ["medical", "pii"],
        "availabilityImpact": "major_disruption", "criticalityTier": 2,
        "internetFacing": "public", "complianceScope": ["hipaa"],
        "airGapped": False, "airGappedDetails": "lab network", "hasSecurityTeam": True,
        "hadBreach": "no", "topConcern": "legal_regulatory", "revenueGenerating": True,
        "exposedSystems": ["website", "api"], "exposedSystemsOther": None,
    }


@pytest.mark.parametrize("impact,tier", [
    ("life_safety", 1), ("major_disruption", 2), ("moderate_disruption", 3),
    ("minor_inconvenience", 4), ("no_impact", 5),
])
def test_every_availability_answer_maps_to_its_tier(app_env, impact, tier):
    client, _ = app_env.login_as()
    assert _post(client, availabilityImpact=impact).get_json()["criticalityTier"] == tier


def test_submitting_again_overwrites_instead_of_duplicating(app_env):
    client, uid = app_env.login_as()
    _post(client, sector="legal")
    _post(client, sector="education", availabilityImpact="no_impact")
    assert app_env.query("SELECT COUNT(*) AS n FROM business_context")[0]["n"] == 1
    me = client.get("/api/business-context/me").get_json()
    assert me["sector"] == "education" and me["criticalityTier"] == 5


def test_each_user_has_their_own_context(app_env):
    a, a_id = app_env.login_as()
    b, _ = app_env.login_as()
    _post(a, sector="legal")
    assert b.get("/api/business-context/me").get_json() == {"completed": False}
    assert app_env.business_context.get_business_context(a_id)["sector"] == "legal"


# ---------------------------------------------------------------------------
# Conditional fields
# ---------------------------------------------------------------------------
def test_other_sector_requires_and_keeps_a_description_only_for_other(app_env):
    client, _ = app_env.login_as()
    assert "describe" in _error(client, sector="other")
    assert "describe" in _error(client, sector="other", sectorOther="   ")
    _post(client, sector="other", sectorOther="  Space tourism ")
    assert client.get("/api/business-context/me").get_json()["sectorOther"] == "Space tourism"
    _post(client, sector="legal", sectorOther="ignored")
    assert client.get("/api/business-context/me").get_json()["sectorOther"] is None


def test_internet_facing_systems_are_required_for_public_and_mixed(app_env):
    client, _ = app_env.login_as()
    for exposure in ("public", "mixed"):
        assert "internet-facing" in _error(client, internetFacing=exposure, exposedSystems=[])
        assert "internet-facing" in _error(client, internetFacing=exposure, exposedSystems=["mainframe"])
        assert "internet-facing" in _error(client, internetFacing=exposure, exposedSystems="website")


def test_internal_systems_discard_any_exposed_systems_sent(app_env):
    client, _ = app_env.login_as()
    _post(client, internetFacing="internal", exposedSystems=["admin_panel"], exposedSystemsOther="x")
    me = client.get("/api/business-context/me").get_json()
    assert me["exposedSystems"] == [] and me["exposedSystemsOther"] is None


def test_other_exposed_system_needs_a_description_and_is_stored(app_env):
    client, _ = app_env.login_as()
    assert "other internet-facing" in _error(client, exposedSystems=["other"])
    _post(client, exposedSystems=["other", "api"], exposedSystemsOther="  kiosk ")
    me = client.get("/api/business-context/me").get_json()
    assert me["exposedSystemsOther"] == "kiosk" and me["exposedSystems"] == ["other", "api"]


def test_exposed_systems_other_text_dropped_when_other_not_selected(app_env):
    client, _ = app_env.login_as()
    _post(client, exposedSystems=["api"], exposedSystemsOther="stale")
    assert client.get("/api/business-context/me").get_json()["exposedSystemsOther"] is None


@pytest.mark.parametrize("value,expected", [(None, None), (True, True), (False, False)])
def test_has_security_team_is_optional_and_three_valued(app_env, value, expected):
    client, uid = app_env.login_as()
    body = _body()
    if value is not None:
        body["hasSecurityTeam"] = value
    assert client.post("/api/business-context", json=body).status_code == 200
    assert app_env.business_context.get_business_context(uid)["hasSecurityTeam"] is expected


def test_blank_air_gapped_details_are_stored_as_null(app_env):
    client, uid = app_env.login_as()
    _post(client, airGapped=True, airGappedDetails="   ")
    ctx = app_env.business_context.get_business_context(uid)
    assert ctx["airGapped"] is True and ctx["airGappedDetails"] is None


# ---------------------------------------------------------------------------
# Validation table
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("overrides,message_part", [
    ({"sector": "astrology"}, "sector"),
    ({"sector": None}, "sector"),
    ({"dataSensitivity": []}, "data sensitivity"),
    ({"dataSensitivity": ["pii", "telepathy"]}, "data sensitivity"),
    ({"dataSensitivity": "pii"}, "data sensitivity"),
    ({"dataSensitivity": ["none", "pii"]}, "can't be combined"),
    ({"availabilityImpact": "who_cares"}, "availability"),
    ({"internetFacing": "sometimes"}, "internet-facing"),
    ({"complianceScope": []}, "compliance"),
    ({"complianceScope": ["hipaa", "made_up"]}, "compliance"),
    ({"complianceScope": ["none", "gdpr"]}, "can't be combined"),
    ({"airGapped": "no"}, "air-gapped"),
    ({"airGapped": None}, "air-gapped"),
    ({"topConcern": "boredom"}, "concern"),
    ({"hadBreach": "maybe"}, "breach"),
    ({"revenueGenerating": "yes"}, "revenue"),
    ({"revenueGenerating": None}, "revenue"),
    ({"hasSecurityTeam": "yes"}, "hasSecurityTeam"),
])
def test_invalid_answers_are_rejected_with_a_helpful_message(app_env, overrides, message_part):
    client, _ = app_env.login_as()
    assert message_part.lower() in _error(client, **overrides).lower()
    assert app_env.query("SELECT COUNT(*) AS n FROM business_context")[0]["n"] == 0


@pytest.mark.parametrize("missing", ["sector", "dataSensitivity", "availabilityImpact", "internetFacing",
                                     "complianceScope", "airGapped", "topConcern", "hadBreach", "revenueGenerating"])
def test_every_required_field_must_be_present(app_env, missing):
    client, _ = app_env.login_as()
    body = _body()
    del body[missing]
    assert client.post("/api/business-context", json=body).status_code == 400


def test_none_options_are_valid_on_their_own(app_env):
    client, _ = app_env.login_as()
    assert _post(client, dataSensitivity=["none"], complianceScope=["none"], hadBreach="not_sure",
                 internetFacing="internal").status_code == 200


def test_empty_or_non_json_body_is_a_400(app_env):
    client, _ = app_env.login_as()
    assert client.post("/api/business-context", data="nope").status_code == 400
    assert client.post("/api/business-context", json={}).status_code == 400


# ---------------------------------------------------------------------------
# get_business_context / schema
# ---------------------------------------------------------------------------
def test_get_business_context_returns_none_for_falsy_ids_and_unknown_users(app_env):
    f = app_env.business_context.get_business_context
    assert f(None) is None and f(0) is None and f(424242) is None


def test_stored_json_columns_round_trip_as_lists(app_env):
    client, uid = app_env.login_as()
    _post(client, dataSensitivity=["credentials", "financial"], complianceScope=["pci_dss", "soc2"])
    ctx = app_env.business_context.get_business_context(uid)
    assert ctx["dataSensitivity"] == ["credentials", "financial"]
    assert ctx["complianceScope"] == ["pci_dss", "soc2"]


def test_migration_adds_the_newer_columns_to_an_old_table(tmp_path, import_fresh):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE business_context (user_id INTEGER PRIMARY KEY, sector TEXT NOT NULL, sector_other TEXT, "
        "data_sensitivity TEXT NOT NULL, availability_impact TEXT NOT NULL, criticality_tier INTEGER NOT NULL, "
        "internet_facing TEXT NOT NULL, compliance_scope TEXT NOT NULL, air_gapped INTEGER NOT NULL, "
        "air_gapped_details TEXT, has_security_team INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO business_context VALUES (1,'legal',NULL,'[\"pii\"]','no_impact',5,'internal','[\"none\"]',0,NULL,NULL,'t','t')"
    )
    conn.commit()
    conn.close()
    import_fresh("auth", db)  # runs auth's migrations; business_context imports next, on the same file
    bc = importlib.import_module("business_context")
    ctx = bc.get_business_context(1)
    # an old row still loads, with the new optional answers empty
    assert ctx["sector"] == "legal" and ctx["hadBreach"] is None and ctx["topConcern"] is None
    assert ctx["revenueGenerating"] is None and ctx["exposedSystems"] == []
