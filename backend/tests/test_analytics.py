from backend.app.analytics import SupervisoryAnalytics


def test_current_submission_records_are_analysed_and_controls_are_complete():
    engine = SupervisoryAnalytics({"submissions": [{
        "id": "s1",
        "records": [
            {"entity_id": "bank-a", "sector": "banking", "asset_id": "a1",
             "alert_id": "al1", "case_id": "c1", "severity": "critical",
             "investigated": True, "escalated": True, "responded": True,
             "timestamp": "2026-01-01T00:00:00Z"},
        ],
    }]})
    detail = engine.entity_detail("bank-a")
    assert detail["operational_metrics"]["total_alerts"] == 1
    assert set(detail["assessment"]["controls"]) == {
        "TD-01", "INV-01", "ES-01", "IR-01", "OP-01", "GOV-01", "RES-01", "MON-01",
    }


def test_analytics_and_control_status_are_deterministic():
    tables = {"records": [{"entity_id": "e", "alert_id": "a", "severity": "high",
                           "timestamp": "2026-02-01"}]}
    first = SupervisoryAnalytics(tables).entity_detail("e")
    second = SupervisoryAnalytics(tables).entity_detail("e")
    assert first == second
