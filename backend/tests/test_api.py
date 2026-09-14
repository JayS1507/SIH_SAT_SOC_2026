from fastapi.testclient import TestClient
from io import BytesIO
from openpyxl import Workbook
try:
    from backend.app.main import app, Store
except ModuleNotFoundError:
    from app.main import app, Store

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


def test_health_and_vertical_slice() -> None:
    assert client.get("/api/v1/health").status_code == 200
    response = client.post("/api/v1/submissions", json={"name": "test", "records": [
        {"entity_id": "e1", "alert_id": "a1", "severity": "critical", "escalated": False, "timestamp": "2026-01-01"}
    ]})
    assert response.status_code == 201
    sid = response.json()["id"]
    assessment = client.post("/api/v1/assessments", json={"submission_id": sid})
    assert assessment.status_code == 201
    aid = assessment.json()["id"]
    findings = client.get(f"/api/v1/assessments/{aid}/findings").json()
    assert any(f["rule"] == "critical_alert_no_escalation" for f in findings)
    assert client.get("/api/v1/review-queue").json()


def test_csv_and_not_found() -> None:
    response = client.post("/api/v1/submissions", files={"file": ("x.csv", "entity_id,timestamp\nu1,2026-01-01\n", "text/csv")})
    assert response.status_code == 201
    assert client.get("/api/v1/submissions/nope").status_code == 404


def test_paste_submission_creates_lineage_preserving_records() -> None:
    response = client.post("/api/v1/submissions/paste", json={
        "name": "SOC pasted log",
        "text": "entity_id=e-paste alert_id=a-paste severity=critical timestamp=2026-01-01T00:00:00Z",
    })
    assert response.status_code == 201
    body = response.json()
    assert body["metadata"]["ingestion"] == "paste"
    assert body["records"][0]["_row"] == 1


def test_sih_submission_routes_and_report_formats() -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["entity_id", "alert_id", "severity", "escalated", "timestamp"])
    sheet.append(["e-xlsx", "a-xlsx", "critical", False, "2026-01-01"])
    content = BytesIO()
    workbook.save(content)
    response = client.post("/api/v1/submissions", files={"file": ("evidence.xlsx", content.getvalue(),
                                                                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert response.status_code == 201
    submission = response.json()
    assert client.get(f"/api/v1/submissions/{submission['id']}/quality").status_code == 200
    assessment = client.post("/api/v1/assessments", json={"submission_id": submission["id"]}).json()
    aid = assessment["id"]
    assert client.get(f"/api/v1/assessments/{aid}/status").json()["status"] == "completed"
    assert client.get(f"/api/v1/assessments/{aid}/entities").status_code == 200
    finding = client.get(f"/api/v1/assessments/{aid}/findings").json()[0]
    assert finding["rule_version"] == "rules-1.0"
    assert client.get(f"/api/v1/findings/{finding['id']}/evidence").status_code == 200
    assert client.get(f"/api/v1/assessments/{aid}/report?format=html").headers["content-type"].startswith("text/html")
    assert client.get(f"/api/v1/assessments/{aid}/report?format=pdf").headers["content-type"].startswith("application/pdf")


def test_advanced_sih_analytics_rules_and_schema_version() -> None:
    response = client.post("/api/v1/submissions", json={
        "name": "advanced",
        "metadata": {"schema_version": "1.0"},
        "records": [
            {"entity_id": "e1", "asset_id": "a1", "type": "case", "case_id": "c1",
             "status": "closed", "severity": "high", "asset_criticality": "critical",
             "investigated": True, "conclusion": "same copied narrative", "notes": "same copied narrative",
             "response_minutes": 2, "timestamp": "2026-01-05T10:00:00Z"},
            {"entity_id": "e1", "asset_id": "a1", "type": "case", "case_id": "c2",
             "status": "closed", "severity": "high", "asset_criticality": "critical",
             "investigated": True, "conclusion": "same copied narrative", "notes": "same copied narrative",
             "response_minutes": 240, "timestamp": "2026-01-06T10:00:00Z"},
        ],
    })
    assert response.status_code == 201
    assessment = client.post("/api/v1/assessments", json={"submission_id": response.json()["id"]}).json()
    rules = {finding["rule"] for finding in client.get(
        f"/api/v1/assessments/{assessment['id']}/findings"
    ).json()}
    assert "repeated_investigation_template" in rules
    assert "response_time_anomaly" in rules
    assert client.post("/api/v1/submissions", json={
        "name": "unsupported", "metadata": {"schema_version": "9.0"}, "records": []
    }).status_code == 422


def test_quality_hash_rules_review_and_report() -> None:
    response = client.post("/api/v1/submissions", json={"name": "quality", "records": [
        {"entity_id": "e1", "asset_id": "host-1", "case_id": "c1", "status": "closed",
         "investigated": True, "timestamp": "2026-01-01"},
        {"entity_id": "e1", "asset_id": "host-1", "case_id": "c1", "status": "closed",
         "investigated": True, "timestamp": "2026-01-01"},
    ]})
    data = response.json()
    assert len(data["content_sha256"]) == 64
    assert "quality" in data
    assessment = client.post("/api/v1/assessments", json={"submission_id": data["id"]}).json()
    findings = client.get(f"/api/v1/assessments/{assessment['id']}/findings").json()
    assert any(f["rule"] == "duplicate_record" for f in findings)
    review = client.post(f"/api/v1/assessments/{assessment['id']}/review",
                         json={"reviewer": "lead", "decision": "accepted", "annotation": "checked"}).json()
    assert review["decision"] == "accepted"
    report = client.get(f"/api/v1/assessments/{assessment['id']}/report").json()
    assert report["hash_verified"] is True
    assert client.get("/api/v1/audit-events").json()
