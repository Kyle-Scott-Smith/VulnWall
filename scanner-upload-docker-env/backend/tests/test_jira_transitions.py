"""Pure-logic tests for the Jira status push — no network, no Flask app."""
from jira_integration import STATUS_TO_JIRA_CATEGORY, pick_transition


def _t(tid, category):
    return {"id": tid, "to": {"statusCategory": {"key": category}}}


def test_status_map_covers_every_status_the_ui_offers():
    assert STATUS_TO_JIRA_CATEGORY == {"Open": "new", "In Progress": "indeterminate", "Closed": "done"}


def test_picks_transition_landing_in_target_category():
    transitions = [_t("11", "new"), _t("21", "indeterminate"), _t("31", "done")]
    assert pick_transition(transitions, "done") == "31"
    assert pick_transition(transitions, "indeterminate") == "21"


def test_returns_none_when_workflow_cannot_reach_category():
    assert pick_transition([_t("21", "indeterminate")], "done") is None


def test_tolerates_missing_or_malformed_fields():
    assert pick_transition(None, "done") is None
    assert pick_transition([{}, {"id": "5"}, {"id": "6", "to": {}}], "done") is None
