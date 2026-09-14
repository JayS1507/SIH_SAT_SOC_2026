from fastapi.testclient import TestClient

from backend.app.main import Store, app


client = TestClient(app)


def setup_function() -> None:
    Store.submissions.clear()
    Store.assessments.clear()
    Store.findings.clear()
    Store.entities.clear()
    Store.assets.clear()
    Store.alerts.clear()
    Store.cases.clear()
    Store.workflow_events.clear()
    Store.audit_events.clear()
    Store.reviews.clear()


def _seed_assessment() -> str:
    submission = client.post("/api/v1/submissions", json={
        "name": "SAT API test",
        "records": [
            {"entity_id": "e1", "entity_name": "Entity One", "sector": "Power",
             "alert_id": "a1", "case_id": "c1", "severity": "critical",
             "timestamp": "2026-01-01T00:00:00Z", "escalated": False},
            {"entity_id": "e2", "entity_name": "Entity Two", "sector": "Banking",
             "alert_id": "a2", "severity": "low", "timestamp": "2026-01-02T00:00:00Z"},
        ],
    })
    assert submission.status_code == 201
    assessment = client.post("/api/v1/assessments", json={"submission_id": submission.json()["id"]})
    assert assessment.status_code == 201
    return assessment.json()["id"]


def test_sat_endpoints_and_filters() -> None:
    _seed_assessment()
    assert client.get("/api/v1/sat/overview").status_code == 200
    assert client.get("/api/v1/sat/entities?sector=Power").json()["total"] == 1
    assert client.get("/api/v1/sat/entities/e1").status_code == 200
    assert client.get("/api/v1/sat/entities/missing").status_code == 404
    alert_response = client.get("/api/v1/sat/alerts?severity=critical")
    assert alert_response.status_code == 200
    assert alert_response.json()["total"] == 1
    for path in (
        "/api/v1/sat/investigations",
        "/api/v1/sat/escalations",
        "/api/v1/sat/monitoring",
        "/api/v1/sat/execution-gaps",
        "/api/v1/sat/negative-space",
        "/api/v1/sat/peer-benchmark",
        "/api/v1/sat/findings",
        "/api/v1/sat/data-quality",
        "/api/v1/sat/review-queue",
        "/api/v1/sat/sample",
        "/api/v1/sat/report",
    ):
        assert client.get(path).status_code == 200


def test_sat_review_status_is_persisted_and_audited() -> None:
    _seed_assessment()
    findings = client.get("/api/v1/sat/findings").json()["items"]
    assert findings
    finding_id = findings[0]["id"]
    response = client.patch(f"/api/v1/sat/review-queue/{finding_id}", json={
        "status": "IN_REVIEW", "reviewer": "supervisor-1", "annotation": "Inspect source row",
    })
    assert response.status_code == 200
    assert response.json()["status"] == "IN_REVIEW"
    filtered = client.get("/api/v1/sat/findings?status=IN_REVIEW").json()["items"]
    assert [item["id"] for item in filtered] == [finding_id]
    assert any(event.get("event_type", event.get("type")) in ("finding_status_changed", "sat_review_status",
                                                               "finding_opened", "finding_validated",
                                                               "finding_rejected", "evidence_requested",
                                                               "finding_closed")
               and event["target_id"] == finding_id
               for event in Store.audit_events)
