from backend.app.analytics import SupervisoryAnalytics


def test_data_quality_reports_missing_timestamp_and_asset_mapping():
    result = SupervisoryAnalytics({"records": [
        {"entity_id": "e", "alert_id": "a", "severity": "high"},
    ]}).data_quality()
    issue_types = {item["type"] for item in result["issues"]}
    assert "missing_timestamp" in issue_types
    assert "missing_asset_mapping" in issue_types
