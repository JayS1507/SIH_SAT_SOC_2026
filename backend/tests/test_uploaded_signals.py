"""Signals must fire on uploaded CSV-shaped records, not only on seeded tables."""
from pathlib import Path

from backend.app.analytics import SupervisoryAnalytics
from backend.app.ingestion import ingest_bytes

DEMO_CSV = Path(__file__).resolve().parents[2] / "examples" / "sat_sa_demo_soc.csv"


def _rules(engine: SupervisoryAnalytics, entity_id: str) -> set[str]:
    signals = engine.all_execution_gaps() + engine.all_negative_space()
    return {s["rule"] for s in signals if s["entity_id"] == entity_id}


def _case(entity: str, n: int, **extra: str) -> dict[str, str]:
    row = {"entity_id": entity, "sector": "Power", "asset_id": f"{entity}-a{n % 3}",
           "asset_criticality": "high", "alert_id": f"{entity}-al{n}", "case_id": f"{entity}-c{n}",
           "severity": "critical", "investigation_id": f"{entity}-i{n}",
           "investigation_conclusion": "Benign", "evidence_count": "4",
           "investigation_duration_minutes": "120", "escalation_required": "false",
           "alert_category": "malware", "timestamp": "2026-01-01T00:00:00Z"}
    row.update(extra)
    return row


def test_csv_string_numbers_drive_fast_closure_signals():
    rows = [_case("fast", n, investigation_duration_minutes="5", evidence_count="1") for n in range(8)]
    engine = SupervisoryAnalytics({"records": rows})
    inv = engine.investigations[0]
    assert inv["duration_minutes"] == 5.0 and inv["evidence_count"] == 1.0
    assert {"EG-FAST-CRITICAL", "EG-FAST-LOW-EVIDENCE"} <= _rules(engine, "fast")


def test_duration_is_derived_from_timestamps_when_not_reported():
    row = _case("ts", 1, investigation_duration_minutes="",
                investigation_started="2026-01-01T00:00:00Z", investigation_completed="2026-01-01T00:07:00Z")
    engine = SupervisoryAnalytics({"records": [row]})
    assert engine.investigations[0]["duration_minutes"] == 7.0


def test_template_notes_are_detected_from_free_text():
    boiler = "Reviewed alert, checked telemetry, closed with no further action required."
    rows = [_case("tmpl", n, investigation_notes=boiler) for n in range(6)]
    rows += [_case("tmpl", 100 + n, investigation_notes=f"Unique narrative for host {n} with lateral movement check")
             for n in range(4)]
    engine = SupervisoryAnalytics({"records": rows})
    assert sum(i["template_match"] for i in engine.investigations) == 6
    assert "EG-TEMPLATE" in _rules(engine, "tmpl")


def test_peer_outlier_and_missing_category_are_negative_space():
    rows = []
    for entity in ("p1", "p2", "p3", "p4", "p5"):
        rows += [_case(entity, n, alert_category=("malware", "phishing")[n % 2]) for n in range(30)]
    # "weak" never investigates and never sees phishing.
    rows += [_case("weak", n, investigation_id="", investigation_conclusion="",
                   investigation_duration_minutes="", evidence_count="") for n in range(30)]
    # One peer misses a little coverage so the MAD is non-zero.
    rows += [_case("p1", 999, investigation_id="", investigation_conclusion="",
                   investigation_duration_minutes="", evidence_count="")]
    engine = SupervisoryAnalytics({"records": rows})
    weak = _rules(engine, "weak")
    assert "NS-PEER-OUTLIER-INVESTIGATION-COVERAGE" in weak
    assert "NS-MISSING-CATEGORY" in weak
    assert not any(r.startswith("NS-PEER-OUTLIER") for r in _rules(engine, "p2"))


def test_demo_csv_exercises_illustrative_use_cases():
    records, _ = ingest_bytes(DEMO_CSV.name, DEMO_CSV.read_bytes())
    engine = SupervisoryAnalytics({"submissions": [{"id": "demo", "records": records}]})
    fired = {s["rule"] for s in engine.all_execution_gaps() + engine.all_negative_space()}
    for rule in ("EG-FAST-CRITICAL", "EG-MISSING-ESC", "EG-REPEATED-NO-REM", "EG-TEMPLATE",
                 "NS-LOW-VOLUME"):
        assert rule in fired, rule
    assert "EG-TEMPLATE" in _rules(engine, "gail")


def test_risk_score_separates_weak_from_strong_entities():
    """Ground truth: seeded archetypes. Strong SOCs must rank below failing ones."""
    records, _ = ingest_bytes(DEMO_CSV.name, DEMO_CSV.read_bytes())
    engine = SupervisoryAnalytics({"submissions": [{"id": "demo", "records": records}]})
    risk = {r["entity_id"]: r for r in engine.all_entity_risk_scores()}
    strong, weak = ("hal", "bel", "mbc"), ("gail", "ntpc", "nts", "epl")
    assert max(risk[e]["risk_score"] for e in strong) < min(risk[e]["risk_score"] for e in weak)
    assert all(risk[e]["risk_level"] == "LOW" for e in strong)
    assert all(risk[e]["risk_level"] in ("HIGH", "CRITICAL") for e in weak)


def _demo_engine(with_declarations: bool = True) -> SupervisoryAnalytics:
    import csv
    records, _ = ingest_bytes(DEMO_CSV.name, DEMO_CSV.read_bytes())
    tables = {"submissions": [{"id": "demo", "records": records}]}
    if with_declarations:
        tables["declarations"] = list(csv.DictReader(DEMO_CSV.with_name("sat_sa_self_assessment.csv").open()))
    return SupervisoryAnalytics(tables)


def test_planted_behaviours_are_detected_only_where_planted():
    engine = _demo_engine()
    fired = engine.all_execution_gaps() + engine.all_negative_space()
    for rule, entity in (("EG-SLA-GAMING", "bpcl"), ("NS-OFFHOURS-BLIND", "cpa"),
                         ("EG-ANALYST-CONCENTRATION", "rail")):
        assert sorted({s["entity_id"] for s in fired if s["rule"] == rule}) == [entity], rule


def test_declared_gap_flags_overclaimers_not_honest_entities():
    engine = _demo_engine()
    gaps = {s["entity_id"] for s in engine.all_execution_gaps() if s["rule"] == "EG-DECLARED-GAP"}
    assert {"gail", "ntpc", "bpcl"} <= gaps
    assert not gaps & {"hal", "bel", "mbc", "pgcil"}
    rows = engine.declared_vs_observed("hal")
    assert rows and all(r["verdict"] in ("CONSISTENT", "MINOR_VARIANCE") for r in rows)


def test_examination_plan_is_evidence_linked():
    plan = _demo_engine().examination_plan("bpcl")
    rules = [a["rule"] for a in plan["focus_areas"]]
    assert "EG-SLA-GAMING" in rules
    sla = next(a for a in plan["focus_areas"] if a["rule"] == "EG-SLA-GAMING")
    assert sla["sample_ids"] and sla["question"] and sla["request"]
    assert plan["case_sample"] and plan["control_sample"]


def test_validation_beats_random_sampling_and_matches_ground_truth():
    from backend.app.validation import entity_ground_truth, sampling_efficiency
    engine = _demo_engine()
    sm = sampling_efficiency(engine)
    assert sm["lift_at_5"] >= 2
    assert sm["effort_for_50pct"]["tool"] < sm["effort_for_50pct"]["random"]
    gt = entity_ground_truth(engine)
    assert gt["available"] and gt["auc"] >= 0.9
    assert gt["behaviours_detected"] == gt["behaviours_total"]


def test_declarations_api_validates_and_stores():
    from fastapi.testclient import TestClient
    from backend.app.main import app, Store
    client = TestClient(app)
    bad = client.post("/api/v1/declarations", json=[{"entity_id": "x", "metric": "nope", "declared_value": 50}])
    assert bad.status_code == 422
    ok = client.post("/api/v1/declarations", json=[{"entity_id": "x", "metric": "escalation_rate", "declared_value": 97}])
    assert ok.status_code == 201 and ok.json()["stored"] == 1
    assert "x|escalation_rate" in Store.declarations
    assert client.get("/api/v1/validation/summary").status_code == 200
