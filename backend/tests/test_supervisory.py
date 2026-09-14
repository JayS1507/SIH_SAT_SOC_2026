"""Deterministic supervisory-analytics tests (§34 acceptance).

Uses a small hand-built dataset with known expected numeric outputs —
no randomness, no dependence on the large synthetic seed.
"""
from fastapi.testclient import TestClient

from backend.app import compliance as C
from backend.app.ingestion import ingest_bytes
from backend.app.main import Store, app

client = TestClient(app)


def setup_function() -> None:
    for attr in ("submissions", "assessments", "findings", "entities", "assets",
                 "alerts", "cases", "workflow_events", "audit_events", "reviews"):
        getattr(Store, attr).clear()


def _ctx() -> dict:
    alerts = [
        {"alert_id": "a1", "entity_id": "e1", "asset_id": "as1", "timestamp": "2026-01-05T10:00:00Z",
         "severity": "critical", "status": "closed", "case_id": "c1",
         "escalation_required": True, "escalation_id": "esc1"},
        {"alert_id": "a2", "entity_id": "e1", "asset_id": "as1", "timestamp": "2026-01-06T10:00:00Z",
         "severity": "high", "status": "closed", "case_id": "c2",
         "escalation_required": True, "escalation_id": None},
        {"alert_id": "a3", "entity_id": "e1", "asset_id": "as2", "timestamp": "2026-01-07T10:00:00Z",
         "severity": "medium", "status": "open", "case_id": None,
         "escalation_required": False, "escalation_id": None},
    ]
    cases = [
        {"case_id": "c1", "entity_id": "e1", "status": "closed", "priority": "critical",
         "closed_at": "2026-01-05T14:00:00Z"},
        {"case_id": "c2", "entity_id": "e1", "status": "closed", "priority": "high",
         "closed_at": "2026-01-06T14:00:00Z"},
    ]
    inv = {"c1": {"case_id": "c1", "conclusion": "Contained.", "evidence_count": 3,
                  "start_time": "2026-01-05T11:00:00Z", "end_time": "2026-01-05T13:00:00Z",
                  "duration_minutes": 120, "analyst_id": "an1"}}
    esc = {"c1": {"case_id": "c1", "escalation_time": "2026-01-05T11:30:00Z",
                  "recipient": "mgr-01", "escalation_level": "L2"}}
    resp = {"c1": {"case_id": "c1", "response_time": "2026-01-05T12:30:00Z"}}
    assets = [{"asset_id": "as1", "entity_id": "e1", "criticality": "critical", "expected_monitoring": True},
              {"asset_id": "as2", "entity_id": "e1", "criticality": "medium", "expected_monitoring": True}]
    subs = [{"reporting_period": "2026-01", "status": "submitted", "_entity_ids": ["e1"]}]
    return {"entity_id": "e1", "alerts": alerts, "cases": cases, "inv_by_case": inv,
            "esc_by_case": esc, "resp_by_case": resp, "rem_by_case": {},
            "assets": assets, "submissions": subs, "peer_deviation": 0}


def test_compliance_control_maths() -> None:
    controls = C.evaluate_entity_controls(_ctx())
    by_id = {c["control_id"]: c for c in controls}
    # TD-02: 3/3 valid severity -> COMPLIANT, coverage 100
    assert by_id["TD-02"]["status"] == "COMPLIANT"
    assert by_id["TD-02"]["coverage"] == 100.0
    # TR-01: 2/3 linked -> 66.7% -> PARTIALLY_COMPLIANT (coverage is percent-scale)
    assert by_id["TR-01"]["status"] == "PARTIALLY_COMPLIANT"
    assert by_id["TR-01"]["coverage"] == round(2 / 3 * 100, 1)
    # ES-01: 1/2 escalated -> 50% -> NON_COMPLIANT
    assert by_id["ES-01"]["status"] == "NON_COMPLIANT"
    # Missing evidence is never compliant: empty alerts -> INSUFFICIENT_EVIDENCE
    empty = dict(_ctx(), alerts=[], cases=[], inv_by_case={}, esc_by_case={}, resp_by_case={})
    empty_controls = C.evaluate_entity_controls(empty)
    assert all(c["status"] == "INSUFFICIENT_EVIDENCE" for c in empty_controls if c["control_id"] in ("TD-01", "TR-01", "IN-01", "ES-01"))


def test_compliance_summary_and_evidence_coverage() -> None:
    controls = C.evaluate_entity_controls(_ctx())
    summ = C.compliance_summary(controls)
    assert summ["controls_assessed"] == len(controls) == 18
    assert summ["compliant"] + summ["partially_compliant"] + summ["non_compliant"] + summ["insufficient_evidence"] == len(controls)
    evidenced = summ["controls_assessed"] - summ["insufficient_evidence"]
    assert summ["evidence_coverage"] == round(evidenced / len(controls) * 100, 1)
    # score is weighted avg of evidenced controls only
    num = sum(c["score"] * c["weight"] for c in controls if c["score"] is not None)
    den = sum(c["weight"] for c in controls if c["score"] is not None)
    assert summ["compliance_score"] == round(num / den, 1)


def test_classification_thresholds() -> None:
    base = {"controls_assessed": 18, "compliant": 0, "partially_compliant": 0,
            "non_compliant": 0, "insufficient_evidence": 0,
            "compliance_score": 90.0, "evidence_coverage": 80.0}
    assert C.classify(base, False) == "COMPLIANT"
    assert C.classify({**base, "compliance_score": 90.0}, True) == "NON_COMPLIANT"  # critical finding veto
    assert C.classify({**base, "compliance_score": 70.0}, False) == "PARTIALLY_COMPLIANT"
    assert C.classify({**base, "compliance_score": 40.0}, False) == "NON_COMPLIANT"
    assert C.classify({**base, "compliance_score": 95.0, "evidence_coverage": 30.0}, False) == "INSUFFICIENT_EVIDENCE"


def test_risk_drivers_explainable() -> None:
    ctx = _ctx()
    controls = C.evaluate_entity_controls(ctx)
    # one escalation-required alert (a2) lacks escalation
    risk = C.risk_with_drivers(ctx, controls, [])
    assert risk["risk_score"] > 0
    drivers = {d["driver"] for d in risk["risk_drivers"]}
    assert "Critical escalation failures" in drivers
    assert risk["risk_score"] <= 100
    # clean entity -> zero risk
    clean = dict(ctx, alerts=[a for a in ctx["alerts"] if a["alert_id"] != "a2"])
    clean_controls = C.evaluate_entity_controls(clean)
    r2 = C.risk_with_drivers(clean, clean_controls, [])
    assert r2["risk_score"] < risk["risk_score"]


def test_recommended_action_mapping() -> None:
    assert C.recommended_action("NON_COMPLIANT", 10, 0, 90) == "IMMEDIATE REVIEW"
    assert C.recommended_action("COMPLIANT", 80, 0, 90) == "IMMEDIATE REVIEW"
    assert C.recommended_action("COMPLIANT", 10, 5, 90) == "IMMEDIATE REVIEW"
    assert C.recommended_action("COMPLIANT", 0, 1, 90) == "SUPERVISORY REVIEW"
    assert C.recommended_action("PARTIALLY_COMPLIANT", 10, 0, 90) == "SUPERVISORY REVIEW"
    assert C.recommended_action("INSUFFICIENT_EVIDENCE", 10, 0, 40) == "EVIDENCE REQUEST"
    assert C.recommended_action("COMPLIANT", 10, 0, 40) == "EVIDENCE REQUEST"
    assert C.recommended_action("COMPLIANT", 25, 0, 90) == "ROUTINE REVIEW"
    assert C.recommended_action("COMPLIANT", 5, 0, 90) == "NO ACTION"


def test_workflow_funnel_counts() -> None:
    ctx = _ctx()
    funnel = C.workflow_funnel(ctx["alerts"], ctx["inv_by_case"], ctx["esc_by_case"], ctx["resp_by_case"], ctx["cases"])
    stages = {s["stage"]: s["count"] for s in funnel}
    assert stages["Alerts"] == 3
    assert stages["Cases"] == 2
    assert stages["Investigations"] == 1
    assert stages["Escalation Required"] == 2
    assert stages["Escalations"] == 1
    assert stages["Responses"] == 1


def test_data_quality_formula() -> None:
    ctx = _ctx()
    dq = C.data_quality_score(ctx["alerts"], ctx["cases"], ctx["assets"], ctx["submissions"])
    assert dq["completeness"] == 100.0
    assert dq["validity"] == 100.0
    assert dq["consistency"] == 100.0
    assert dq["uniqueness"] == 100.0
    assert dq["overall"] == 100.0
    assert "0.30" in dq["formula"]
    # duplicate + missing mandatory degrade the score deterministically
    bad = ctx["alerts"] + [dict(ctx["alerts"][0]), {"alert_id": "ax", "entity_id": "e1"}]
    dq2 = C.data_quality_score(bad, ctx["cases"], ctx["assets"], ctx["submissions"])
    assert dq2["duplicate_records"] == 1
    assert dq2["overall"] < 100.0
    assert dq2["overall"] == round(dq2["completeness"] * 0.30 + dq2["validity"] * 0.25 + dq2["consistency"] * 0.20 + dq2["uniqueness"] * 0.15 + dq2["timeliness"] * 0.10, 1)


def test_duplicate_detection_in_controls() -> None:
    ctx = _ctx()
    dup_ctx = dict(ctx, alerts=ctx["alerts"] + [dict(ctx["alerts"][0])])
    by_id = {c["control_id"]: c for c in C.evaluate_entity_controls(dup_ctx)}
    # 4 alerts, 1 dup + 0 missing -> 3/4 good on DQ-01
    assert by_id["DQ-01"]["numerator"] == 3
    assert by_id["DQ-01"]["denominator"] == 4


def test_csv_ingestion_spec_columns() -> None:
    body = ("record_id,timestamp,entity_id,entity_name,sector,asset_id,asset_name,asset_criticality,"
            "alert_id,severity,alert_status,case_id,case_status,investigation_id,investigation_status,"
            "investigation_started,investigation_completed,investigation_conclusion,escalation_id,"
            "escalation_required,escalation_status,escalation_timestamp,response_id,response_status,"
            "response_timestamp,closure_id,closure_status,closure_timestamp,evidence_type,"
            "evidence_present,analyst_id,reporting_period\n"
            "rec-00001,2026-01-09T01:52:58Z,ntpc,NTPC Limited,Power & Energy,ntpc-asset-001,NTPC-SCADA-001,"
            "critical,ntpc-ALR-1,critical,closed,ntpc-CASE-1,closed,ntpc-INV-1,completed,"
            "2026-01-09T02:00:00Z,2026-01-09T04:00:00Z,Contained.,ntpc-ESC-1,true,escalated,"
            "2026-01-09T02:30:00Z,ntpc-RESP-1,completed,2026-01-09T03:00:00Z,ntpc-CASE-1,closed,"
            "2026-01-09T05:00:00Z,investigation,true,ntpc-analyst-01,2026-01\n").encode()
    records, _ = ingest_bytes("demo.csv", body)
    assert len(records) == 1
    r = records[0]
    assert r["entity_id"] == "ntpc" and r["alert_id"] == "ntpc-ALR-1"
    assert r["escalation_required"] in (True, "true")
    # upload through the API and assess
    resp = client.post("/api/v1/submissions", json={"name": "csv-spec", "records": records})
    assert resp.status_code == 201
    sid = resp.json()["id"]
    a = client.post("/api/v1/assessments", json={"submission_id": sid})
    assert a.status_code == 201
    assert client.get("/api/v1/analytics/overview").status_code == 200
    ent = client.get("/api/v1/analytics/entities/ntpc")
    assert ent.status_code == 200
    assert ent.json()["compliance"]["entity_id"] == "ntpc"


def test_audit_event_on_review_and_report() -> None:
    sub = client.post("/api/v1/submissions", json={"name": "audit-t", "records": [
        {"entity_id": "e9", "alert_id": "a9", "severity": "critical", "escalated": False,
         "timestamp": "2026-01-01T00:00:00Z"}]})
    assert sub.status_code == 201
    assess = client.post("/api/v1/assessments", json={"submission_id": sub.json()["id"]}).json()
    findings = client.get(f"/api/v1/sat/findings?entity_id=e9").json()["items"]
    assert findings, "expected a critical finding for e9"
    fid = findings[0]["id"]
    r = client.patch(f"/api/v1/sat/review-queue/{fid}", json={"status": "VALIDATED", "reviewer": "tester"})
    assert r.status_code == 200
    events = client.get("/api/v1/audit-events").json()
    kinds = {(e.get("event_type") or e.get("type")) for e in events}
    assert "finding_validated" in kinds
    validated = [e for e in events if (e.get("event_type") or e.get("type")) == "finding_validated"][0]
    assert validated["previous_state"] == "NEW" and validated["new_state"] == "VALIDATED"
    assert validated.get("event_hash")
    rep = client.get("/api/v1/sat/report?format=json").json()
    assert rep["rule_version"] and rep["dataset_hash"] is not None
    assert rep["compliance_distribution"]
    assert "methodology" in rep and "limitations" in rep
    events2 = client.get("/api/v1/audit-events").json()
    assert any((e.get("event_type") or e.get("type")) == "report_generated" for e in events2)


def test_sector_and_grouped_endpoints() -> None:
    sub = client.post("/api/v1/submissions", json={"name": "sec-t", "records": [
        {"entity_id": "s1", "entity_name": "S One", "sector": "Power & Energy",
         "alert_id": "sa1", "severity": "critical", "escalated": False, "timestamp": "2026-02-01T00:00:00Z"},
        {"entity_id": "s1", "entity_name": "S One", "sector": "Power & Energy",
         "alert_id": "sa1", "severity": "critical", "escalated": False, "timestamp": "2026-02-01T00:00:00Z"},
    ]})
    assert sub.status_code == 201
    client.post("/api/v1/assessments", json={"submission_id": sub.json()["id"]})
    sectors = client.get("/api/v1/analytics/sectors").json()
    assert sectors["total"] >= 1
    assert any(i["sector"] == "Power & Energy" for i in sectors["items"])
    sev = client.get("/api/v1/analytics/severity").json()
    assert sev["total"] >= 2
    grouped = client.get("/api/v1/analytics/findings-grouped").json()
    dup_groups = [g for g in grouped["items"] if g["rule"] == "duplicate_record"]
    assert dup_groups and dup_groups[0]["affected_records"] >= 2
    gaps = client.get("/api/v1/analytics/execution-gaps").json()
    assert gaps["total"] >= 1 and gaps["by_rule"]
    alerts = client.get("/api/v1/analytics/alerts?limit=5").json()
    assert alerts["returned"] <= 5 and alerts["items"]
    assert "compliance_state" in alerts["items"][0]
