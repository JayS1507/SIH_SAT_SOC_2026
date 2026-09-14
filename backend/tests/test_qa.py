from fastapi.testclient import TestClient

from backend.app.main import Store, app
from backend.app.qa import parse_question


client = TestClient(app)


def setup_function() -> None:
    Store.submissions.clear()
    Store.assessments.clear()
    Store.findings.clear()
    Store.entities.clear()


def assessment(records):
    submission = client.post("/api/v1/submissions", json={"name": "qa", "records": records}).json()
    return client.post("/api/v1/assessments", json={"submission_id": submission["id"]}).json()["id"]


def test_parser_resolves_entity_rule_category_severity_and_metric():
    intent, error = parse_question(
        "How many critical findings for entity-a in execution gap?",
        {"entity-a": {"sector": "banking"}},
    )
    assert error is None
    assert intent == {
        "entity_id": "entity-a", "sector": None, "rule_id": None,
        "rule_category": "execution_gap", "severity": "critical",
        "time_range": None, "metric": "count",
    }


def test_example_question_is_grounded():
    aid = assessment([{"entity_id": "entity-a", "alert_id": "a1", "severity": "critical",
                       "escalated": False, "timestamp": "2026-01-01"}])
    response = client.post(f"/api/v1/assessments/{aid}/ask",
                           json={"question": "which entities have critical alerts closed without escalation"})
    body = response.json()
    assert body["confidence"] == "resolved"
    assert body["intent"]["rule_id"] == "critical_alert_no_escalation"
    assert body["finding_ids"]
    assert body["evidence_ids"]


def test_ambiguous_entity_is_unresolved():
    aid = assessment([{"entity_id": "entity-a", "timestamp": "2026-01-01"},
                       {"entity_id": "entity-b", "timestamp": "2026-01-01"}])
    response = client.post(f"/api/v1/assessments/{aid}/ask", json={"question": "how many findings?"})
    assert response.json()["confidence"] == "resolved"
    intent, error = parse_question("how many findings for entity", {
        "entity-a": {"sector": None}, "entity-b": {"sector": None},
    })
    assert intent is None
    assert error


def test_sector_resolves_only_when_metadata_exists():
    intent, error = parse_question("which banking entities have findings?", {
        "entity-a": {"sector": "banking"},
    })
    assert error is None
    assert intent["sector"] == "banking"
    intent, error = parse_question("which banking entities have findings?", {
        "entity-a": {"sector": None},
    })
    assert intent is None
    assert error
