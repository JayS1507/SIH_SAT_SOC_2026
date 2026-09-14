from fastapi.testclient import TestClient

from backend.app.analytics import SupervisoryAnalytics
from backend.app.main import Store, app, execute_rules, normalize_records


def _engine(records):
    return SupervisoryAnalytics({"records": records})


def test_negative_space_detects_zero_activity_and_preserves_lineage():
    result = _engine([
        {"entity_id": "quiet", "sector": "banking", "asset_id": "critical-1",
         "criticality": "critical", "timestamp": "2026-01-01"},
        {"entity_id": "peer", "sector": "banking", "alert_id": "a1",
         "asset_id": "peer-1", "severity": "low", "timestamp": "2026-01-01"},
        {"entity_id": "peer", "sector": "banking", "alert_id": "a2",
         "asset_id": "peer-1", "severity": "low", "timestamp": "2026-02-01"},
    ]).all_negative_space()
    rules = {item["rule"] for item in result}
    assert "NS-CRIT-UNMONITORED" in rules
    assert "NS-LOW-VOLUME" in rules
    assert all(item["entity_id"] == "quiet" for item in result)


def test_peer_comparison_is_sector_scoped_and_capability_scores_are_bounded():
    engine = _engine([
        {"entity_id": "bank-a", "sector": "banking", "alert_id": "a1",
         "case_id": "c1", "severity": "high", "timestamp": "2026-01-01"},
        {"entity_id": "bank-b", "sector": "banking", "alert_id": "a2",
         "severity": "low", "timestamp": "2026-01-01"},
        {"entity_id": "power", "sector": "power", "alert_id": "a3",
         "severity": "critical", "timestamp": "2026-01-01"},
    ])
    benchmark = engine.peer_benchmark()
    assert benchmark["sectors"] == {"banking": ["bank-a", "bank-b"], "power": ["power"]}
    assert set(benchmark["entities"]["bank-a"]["peer_comparison"]) >= {"critical_rate", "investigation_coverage"}
    for capabilities in engine.capability_scores().values():
        assert set(capabilities) == {
            "Threat Detection", "Investigation", "Escalation",
            "Incident Response", "Security Operations", "Governance & Oversight",
            "Operational Discipline", "Cyber Resilience",
        }
        assert all(0 <= item["score"] <= 100 for item in capabilities.values())


def test_trends_include_monitoring_direction():
    records = []
    for index, month in enumerate(("01", "02", "03"), start=1):
        records.append({"entity_id": "e", "sector": "banking", "asset_id": "a",
                        "alert_id": f"critical-{index}", "severity": "critical",
                        "timestamp": f"2026-{month}-10"})
    for index, month in enumerate(("04", "05", "06"), start=1):
        records.append({"entity_id": "e", "sector": "banking", "asset_id": "a",
                        "alert_id": f"low-{index}", "severity": "low",
                        "timestamp": f"2026-{month}-10"})
    engine = _engine(records).trend_analysis("e")
    assert len(engine["trends"]["monitoring_coverage"]) == 6
    assert engine["directions"]["critical_rate"] == "improving"
    assert engine["directions"]["monitoring_coverage"] == "stable"


def test_quality_metrics_expose_missing_severity_and_stay_bounded():
    result = _engine([
        {"entity_id": "e", "alert_id": "a", "timestamp": "2026-01-01"},
        {"entity_id": "e", "alert_id": "a", "timestamp": "2026-01-01"},
    ]).data_quality()
    issue_types = {item["type"] for item in result["issues"]}
    assert "missing_severity" in issue_types
    assert "duplicate_alert" in issue_types
    assert 0 <= result["quality_score"] <= 100


def test_findings_are_deduplicated_without_losing_evidence_lineage():
    records, issues = normalize_records([
        {"entity_id": "e", "alert_id": "a", "severity": "critical",
         "escalated": False, "timestamp": "2026-01-01"},
        {"entity_id": "e", "alert_id": "a", "severity": "critical",
         "escalated": False, "timestamp": "2026-01-02"},
    ])
    submission = {"id": "s1", "records": records, "quality_issues": issues}
    findings = execute_rules(submission, "assessment-1")
    matching = [item for item in findings if item["rule"] == "critical_alert_no_escalation"]
    assert len(matching) == 1
    assert matching[0]["evidence"] == ["record:s1#row-1", "record:s1#row-2"]
    assert matching[0]["lineage"] == ["submission:s1", "row:1", "row:2"]


def test_sat_report_formats_and_review_workflow():
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
    client = TestClient(app)
    response = client.post("/api/v1/submissions", json={
        "name": "phase 5", "records": [{
            "entity_id": "e", "sector": "banking", "alert_id": "a",
            "severity": "critical", "escalated": False,
            "timestamp": "2026-01-01T00:00:00Z",
        }],
    })
    assessment = client.post("/api/v1/assessments",
                             json={"submission_id": response.json()["id"]})
    assert assessment.status_code == 201
    findings = client.get("/api/v1/sat/findings").json()["items"]
    assert findings
    finding_id = findings[0]["id"]
    review = client.post(f"/api/v1/sat/review-queue/{finding_id}/status",
                         json={"status": "VALIDATED", "reviewer": "r"})
    assert review.status_code == 200
    assert client.get("/api/v1/sat/findings?status=VALIDATED").json()["total"] == 1
    assert client.get("/api/v1/sat/report?format=html").headers["content-type"].startswith("text/html")
    pdf = client.get("/api/v1/sat/report?format=pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
