"""Compliance, risk, funnel, data-quality and audit tests on a deterministic fixture."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.compliance import (classify, compliance_summary, data_quality_score,
                            evaluate_entity_controls, recommended_action,
                            risk_with_drivers, workflow_funnel)


def _ctx():
    alerts = [
        {"alert_id": "a1", "entity_id": "e1", "asset_id": "as1", "timestamp": "2026-01-05T10:00:00Z",
         "severity": "critical", "status": "closed", "case_id": "c1", "escalation_required": True, "escalation_id": None},
        {"alert_id": "a2", "entity_id": "e1", "asset_id": "as2", "timestamp": "2026-01-06T10:00:00Z",
         "severity": "low", "status": "closed", "case_id": "c2", "escalation_required": False},
    ]
    cases = [
        {"case_id": "c1", "entity_id": "e1", "status": "closed", "priority": "critical", "closed_at": "2026-01-05T14:00:00Z"},
        {"case_id": "c2", "entity_id": "e1", "status": "closed", "priority": "low", "closed_at": "2026-01-06T14:00:00Z"},
    ]
    inv = {"c1": {"case_id": "c1", "start_time": "2026-01-05T11:00:00Z", "end_time": "2026-01-05T13:00:00Z",
                   "duration_minutes": 120, "conclusion": "True positive.", "evidence_count": 3},
           "c2": {"case_id": "c2", "start_time": "2026-01-06T11:00:00Z", "end_time": "2026-01-06T11:05:00Z",
                   "duration_minutes": 5, "conclusion": None, "evidence_count": 0}}
    return {"entity_id": "e1", "alerts": alerts, "cases": cases, "inv_by_case": inv,
            "esc_by_case": {}, "resp_by_case": {}, "rem_by_case": {},
            "assets": [{"asset_id": "as1", "criticality": "critical", "expected_monitoring": True},
                       {"asset_id": "as2", "criticality": "low", "expected_monitoring": True}],
            "submissions": [{"reporting_period": "2026-01", "status": "submitted"}],
            "peer_deviation": 0}


def test_missing_escalation_is_non_compliant_not_compliant():
    controls = evaluate_entity_controls(_ctx())
    es01 = next(c for c in controls if c["control_id"] == "ES-01")
    assert es01["status"] == "NON_COMPLIANT", es01
    assert es01["coverage"] == 0.0
    summ = compliance_summary(controls)
    # insufficient-evidence controls excluded from score but counted
    assert summ["controls_assessed"] == 18
    assert summ["evidence_coverage"] <= 100.0
    assert classify(summ, True) == "NON_COMPLIANT"


def test_insufficient_evidence_when_no_data():
    controls = evaluate_entity_controls({"entity_id": "e9", "alerts": [], "cases": [], "inv_by_case": {},
                                         "esc_by_case": {}, "resp_by_case": {}, "rem_by_case": {},
                                         "assets": [], "submissions": [], "peer_deviation": 0})
    summ = compliance_summary(controls)
    assert summ["evidence_coverage"] == 0.0
    assert classify(summ, False) == "INSUFFICIENT_EVIDENCE"


def test_risk_drivers_explainable():
    ctx = _ctx()
    controls = evaluate_entity_controls(ctx)
    r = risk_with_drivers(ctx, controls, [{"severity": "critical"}])
    assert r["risk_score"] > 0
    assert any("escalation" in d["driver"].lower() for d in r["risk_drivers"])
    assert "method" in r


def test_workflow_funnel_counts():
    ctx = _ctx()
    f = workflow_funnel(ctx["alerts"], ctx["inv_by_case"], {}, {}, ctx["cases"])
    stages = {s["stage"]: s["count"] for s in f}
    assert stages["Alerts"] == 2
    assert stages["Cases"] == 2
    assert stages["Investigations"] == 2
    assert stages["Escalations"] == 0  # gap visible
    assert stages["Escalation Required"] == 1


def test_data_quality_weighted_not_zero():
    ctx = _ctx()
    dq = data_quality_score(ctx["alerts"], ctx["cases"], ctx["assets"], ctx["submissions"])
    assert dq["overall"] > 0
    assert dq["overall"] <= 100
    assert "0.30*completeness" in dq["formula"]


def test_recommended_action_deterministic():
    assert recommended_action("NON_COMPLIANT", 80, 1, 90) == "IMMEDIATE REVIEW"
    assert recommended_action("COMPLIANT", 5, 0, 95) == "NO ACTION"
    assert recommended_action("INSUFFICIENT_EVIDENCE", 10, 0, 40) == "EVIDENCE REQUEST"
