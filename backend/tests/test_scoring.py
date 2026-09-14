import random

from backend.app.scoring import calculate_entity_risk


def finding(entity: str, severity: str, strength: float = 1.0, index: int = 0) -> dict:
    return {
        "id": f"f-{entity}-{index}",
        "entity_id": entity,
        "severity": severity,
        "evidence": [f"record:s#row-{index}"] * max(1, round(strength * 3)),
        "lineage": ["submission:s", f"row:{index}"],
        "calculation": "rule=test",
    }


def test_scores_strictly_increase_with_increasing_severity():
    scores = []
    findings = []
    for index, severity in enumerate(("low", "medium", "high", "critical"), start=1):
        findings.append(finding("e1", severity, index=index))
        scores.append(calculate_entity_risk(findings, {"e1": 20}, {"e1": {"sector": "banking"}})[0]["risk_score"])
    assert scores == sorted(scores)
    assert all(left < right for left, right in zip(scores, scores[1:]))


def test_scores_never_exceed_theoretical_maximum():
    random.seed(42)
    for _ in range(100):
        volume = random.randint(1, 40)
        findings = [
            finding("e1", random.choice(("low", "medium", "high", "critical")),
                    random.random(), index=index)
            for index in range(volume)
        ]
        result = calculate_entity_risk(
            findings, {"e1": random.randint(volume, volume * 3)},
            {"e1": {"sector": "banking"}},
        )[0]
        assert result["risk_score"] <= 100


def test_score_is_stable_when_other_entities_change():
    findings = [finding("e1", "high", index=1), finding("e2", "low", index=2)]
    first = {item["entity_id"]: item for item in calculate_entity_risk(
        findings, {"e1": 10, "e2": 10},
        {"e1": {"sector": "banking"}, "e2": {"sector": "power"}},
    )}["e1"]["risk_score"]
    second = {item["entity_id"]: item for item in calculate_entity_risk(
        findings + [finding("e2", "critical", index=3)] * 20,
        {"e1": 10, "e2": 30},
        {"e1": {"sector": "banking"}, "e2": {"sector": "power"}},
    )}["e1"]["risk_score"]
    assert first == second


def test_peer_group_is_same_sector_only():
    findings = [finding("bank-a", "high", index=1), finding("bank-a", "low", index=4),
                finding("bank-b", "low", index=2),
                finding("power-a", "critical", index=3)]
    results = calculate_entity_risk(
        findings,
        {"bank-a": 10, "bank-b": 10, "power-a": 10},
        {"bank-a": {"sector": "banking"}, "bank-b": {"sector": "banking"},
         "power-a": {"sector": "power"}},
    )
    by_id = {item["entity_id"]: item for item in results}
    assert by_id["power-a"]["raw_z"] == 0
    assert by_id["bank-a"]["raw_z"] > 0


def test_missing_sector_is_excluded_from_peer_groups():
    results = calculate_entity_risk(
        [finding("bank-a", "high", index=1), finding("unknown", "critical", index=2)],
        {"bank-a": 10, "unknown": 10},
        {"bank-a": {"sector": "banking"}, "unknown": {"sector": None}},
    )
    by_id = {item["entity_id"]: item for item in results}
    assert by_id["unknown"]["raw_z"] == 0
    assert by_id["bank-a"]["raw_z"] == 0
