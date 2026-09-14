from collections import defaultdict

from backend.app.main import Store, execute_rules, index_records, normalize_records
from backend.app.seed.generate_evidence import ENTITIES, generate_records


EXPECTED = {
    "unescalated_critical": "critical_alert_no_escalation",
    "under_reporter": "alert_without_case",
    "templated_notes": "repeated_investigation_template",
    "missing_telemetry": "asset_without_coverage",
    "fast_closer": "response_time_anomaly",
}


def test_seed_archetype_rule_recall_and_typical_precision():
    Store.entities.clear()
    Store.assets.clear()
    Store.alerts.clear()
    Store.cases.clear()
    Store.workflow_events.clear()
    records, quality = normalize_records(generate_records(__import__("random").Random(26157)))
    submission = {"id": "recall-submission", "records": records, "quality_issues": quality}
    index_records(submission)
    findings = execute_rules(submission, "recall-assessment")
    rules_by_entity = defaultdict(set)
    for finding in findings:
        rules_by_entity[finding["entity_id"]].add(finding["rule"])

    rows = []
    for entity_id, _, _, archetype in ENTITIES:
        expected_rule = EXPECTED.get(archetype)
        caught = expected_rule in rules_by_entity[entity_id] if expected_rule else True
        false_positive = bool(rules_by_entity[entity_id]) if archetype == "typical" else False
        rows.append((expected_rule or "none", "pass" if caught else "fail", "pass" if not false_positive else "fail"))
        assert caught, f"{entity_id} ({archetype}) did not trigger {expected_rule}"
        if archetype == "typical":
            assert not false_positive, f"{entity_id} produced unexpected findings"

    print("| Rule | Recall | Typical precision |")
    print("|---|---|---|")
    for rule, recall, precision in sorted(set(rows)):
        print(f"| `{rule}` | {recall} | {precision} |")
