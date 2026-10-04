"""Validation of SAT-SA against ground truth and examiner decisions (PS section 8).

Three independent views:

1. Entity ranking vs ground truth: for the synthetic dataset the generator
   knows which entities were built weak and which behaviours were planted.
   Reports ROC-AUC of the risk score and per-behaviour detection.
2. Sampling efficiency vs manual random sampling: a simulated examiner
   checklist is applied to every case; we measure how many deficient cases
   the tool's review order finds per unit of review effort, compared with
   random sampling (the current manual approach).
3. Examiner agreement: live precision per rule from validate/reject
   decisions in the review queue (the calibration loop for real deployments).
"""
from __future__ import annotations

import random
import statistics
from collections import defaultdict
from typing import Any

from .analytics import SupervisoryAnalytics

BUDGETS = (1, 2, 5, 10, 15, 20, 30, 40, 50, 60, 80, 100)


def _auc(positives: list[float], negatives: list[float]) -> float | None:
    if not positives or not negatives:
        return None
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in positives for n in negatives)
    return round(wins / (len(positives) * len(negatives)), 3)


def examiner_checklist(engine: SupervisoryAnalytics, case: dict[str, Any]) -> list[str]:
    """Simulated expert review of one case: the deficiencies an examiner would record."""
    cid = case["case_id"]
    inv = engine._inv_by_case.get(cid)
    alert = engine._alert_by_case.get(cid) or {}
    severe = case.get("priority") in ("critical", "high")
    issues = []
    if severe and not inv:
        issues.append("critical/high case not investigated")
    if inv and not inv.get("conclusion"):
        issues.append("no documented conclusion")
    if alert.get("escalation_required") and not alert.get("escalation_id"):
        issues.append("required escalation not performed")
    if inv and severe and inv.get("duration_minutes", 999) <= 10:
        issues.append("superficial investigation of severe alert")
    if inv and inv.get("evidence_count", 99) < 2:
        issues.append("insufficient evidence")
    if cid in engine._esc_by_case and cid not in engine._resp_by_case:
        issues.append("escalated without response")
    if inv and inv.get("template_match"):
        issues.append("templated narrative")
    return issues


def sampling_efficiency(engine: SupervisoryAnalytics) -> dict[str, Any]:
    risk = {r["entity_id"]: r["risk_score"] for r in engine.all_entity_risk_scores()}
    cases = engine.cases
    if not cases:
        return {"available": False}
    labels = {c["case_id"]: bool(examiner_checklist(engine, c)) for c in cases}
    total_deficient = sum(labels.values())
    # Tool order: case priority, entity risk as tie-breaker (supervisor works riskiest entities first).
    ordered = sorted(cases, key=lambda c: (-engine.case_priority(c)[0], -risk.get(c["entity_id"], 0), c["case_id"]))
    shuffled = list(cases)
    random.Random(26157).shuffle(shuffled)

    def curve(order: list[dict[str, Any]]) -> list[float]:
        points, found, i = [], 0, 0
        for budget in BUDGETS:
            upto = round(len(order) * budget / 100)
            while i < upto:
                found += labels[order[i]["case_id"]]
                i += 1
            points.append(round(100 * found / max(total_deficient, 1), 1))
        return points

    tool, rand = curve(ordered), curve(shuffled)

    def effort_for(target: float, order: list[dict[str, Any]]) -> float:
        found = 0
        for i, c in enumerate(order, 1):
            found += labels[c["case_id"]]
            if found >= target * total_deficient:
                return round(100 * i / len(order), 1)
        return 100.0

    def precision_at(budget: int, order: list[dict[str, Any]]) -> float:
        n = max(1, round(len(order) * budget / 100))
        return round(100 * sum(labels[c["case_id"]] for c in order[:n]) / n, 1)

    return {
        "available": True,
        "cases": len(cases),
        "deficient_cases": total_deficient,
        "base_rate": round(100 * total_deficient / len(cases), 1),
        "curve": [{"budget": b, "tool": t, "random": r} for b, t, r in zip(BUDGETS, tool, rand)],
        "precision_at_5": precision_at(5, ordered),
        "random_precision_at_5": precision_at(5, shuffled),
        "lift_at_5": round(precision_at(5, ordered) / max(precision_at(5, shuffled), 0.1), 2),
        "effort_for_50pct": {"tool": effort_for(0.5, ordered), "random": effort_for(0.5, shuffled)},
        "effort_for_80pct": {"tool": effort_for(0.8, ordered), "random": effort_for(0.8, shuffled)},
        "method": "Simulated examiner checklist applied to every case (7 deficiency tests). "
                  "Tool = SAT-SA review order; random = current manual sampling. The checklist shares "
                  "evidence fields with the prioritiser, so this measures ordering efficiency; the "
                  "independent tests are entity ground truth and live examiner agreement.",
    }


def entity_ground_truth(engine: SupervisoryAnalytics) -> dict[str, Any]:
    from .seed.generate_evidence import ground_truth
    truth = {eid: t for eid, t in ground_truth().items() if eid in engine.entities}
    if len(truth) < 5:
        return {"available": False,
                "reason": "No ground truth for this dataset; use examiner agreement instead."}
    risk = {r["entity_id"]: r for r in engine.all_entity_risk_scores()}
    signals = engine.all_execution_gaps() + engine.all_negative_space()
    case_counts = {eid: len(engine._cases_by_entity.get(eid, [])) for eid in engine.entities}

    # A broad rule only "detects" a behaviour if the entity stands out on it.
    rates: dict[str, dict[str, float]] = defaultdict(dict)
    for s in signals:
        rate = s["affected_count"] / max(case_counts.get(s["entity_id"], 0), 1)
        rates[s["rule"]][s["entity_id"]] = max(rate, rates[s["rule"]].get(s["entity_id"], 0))

    def detected(eid: str, rule: str) -> tuple[bool, str]:
        hits = rates.get(rule, {})
        if eid not in hits:
            return False, "signal not raised"
        if len(hits) <= max(3, len(engine.entities) // 4):
            return True, f"raised for {len(hits)} of {len(engine.entities)} entities"
        median = statistics.median(hits.get(e, 0.0) for e in engine.entities)
        ratio = hits[eid] / median if median else float("inf")
        return ratio >= 1.5, f"rate {round(hits[eid] * 100, 1)}% vs median {round(median * 100, 1)}%"

    entity_rows, behaviour_rows = [], []
    for eid, t in sorted(truth.items(), key=lambda kv: -risk.get(kv[0], {}).get("risk_score", 0)):
        r = risk.get(eid, {})
        flagged = r.get("risk_level") in ("HIGH", "CRITICAL")
        entity_rows.append({"entity_id": eid, "entity_name": engine.entities[eid].get("entity_name", eid),
                            "archetype": t["archetype"], "truth": t["label"],
                            "risk_score": r.get("risk_score"), "risk_level": r.get("risk_level"),
                            "agrees": None if t["label"] == "mixed" else flagged == (t["label"] == "weak")})
        for behaviour, rule in zip(t["behaviours"], t["expected_signals"]):
            hit, why = detected(eid, rule)
            behaviour_rows.append({"entity_id": eid, "behaviour": behaviour, "expected_signal": rule,
                                   "detected": hit, "evidence": why})
    weak = [r["risk_score"] for r in entity_rows if r["truth"] == "weak"]
    strong = [r["risk_score"] for r in entity_rows if r["truth"] == "strong"]
    judged = [r for r in entity_rows if r["agrees"] is not None]
    return {
        "available": True,
        "label": "Synthetic ground truth (planted archetypes and behaviours)",
        "auc": _auc(weak, strong),
        "tier_accuracy": round(100 * sum(r["agrees"] for r in judged) / max(len(judged), 1), 1),
        "separated": bool(weak and strong and min(weak) > max(strong)),
        "behaviours_detected": sum(r["detected"] for r in behaviour_rows),
        "behaviours_total": len(behaviour_rows),
        "entities": entity_rows,
        "behaviours": behaviour_rows,
    }


def examiner_agreement(findings: list[dict[str, Any]]) -> dict[str, Any]:
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {"validated": 0, "rejected": 0, "open": 0})
    for f in findings:
        status = str(f.get("review_status") or "").upper()
        bucket = ("validated" if status in ("VALIDATED", "CLOSED", "ESCALATED")
                  else "rejected" if status in ("REJECTED", "DISMISSED") else "open")
        per_rule[f.get("rule") or "unknown"][bucket] += 1
    rows = []
    for rule, c in sorted(per_rule.items()):
        decided = c["validated"] + c["rejected"]
        rows.append({"rule": rule, **c,
                     "precision": round(100 * c["validated"] / decided, 1) if decided else None})
    decided = sum(r["validated"] + r["rejected"] for r in rows)
    return {"decisions": decided,
            "precision": round(100 * sum(r["validated"] for r in rows) / decided, 1) if decided else None,
            "rules": rows,
            "method": "Precision = findings validated by examiners / findings decided (validated + rejected)."}


def validation_summary(engine: SupervisoryAnalytics, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {"ground_truth": entity_ground_truth(engine),
            "sampling": sampling_efficiency(engine),
            "examiner_agreement": examiner_agreement(findings)}
