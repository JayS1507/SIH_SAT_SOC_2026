from backend.app.analytics import SupervisoryAnalytics


def test_sample_has_targeted_and_reproducible_control_sets():
    records = [{"entity_id": "e", "case_id": f"c{i}", "severity": "critical",
                "status": "closed", "timestamp": f"2026-01-{i + 1:02d}"}
               for i in range(4)]
    tables = {"records": records}
    first = SupervisoryAnalytics(tables).recommended_sample("e", 2, 1)
    second = SupervisoryAnalytics(tables).recommended_sample("e", 2, 1)
    assert first == second
    assert first["targeted_count"] == 2
    assert first["control_count"] == 1
