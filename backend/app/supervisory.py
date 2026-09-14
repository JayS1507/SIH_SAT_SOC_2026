"""Supervisory analytics layer: compliance assessments, workflow funnels,
sector breakdowns, grouped findings, weighted data quality, reporting
coverage, attention matrix, executive summary. All deterministic."""
from __future__ import annotations

import hashlib
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from . import compliance as C


def _parse_ts(v: Any):
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except (ValueError, TypeError):
        return None


def build_assessments(engine, findings: list[dict[str, Any]],
                      expected_periods: int = 9) -> list[dict[str, Any]]:
    out = []
    for eid, meta in sorted(engine.entities.items()):
        out.append(C.assess_entity(
            entity_id=eid,
            alerts=list(engine._alerts_by_entity.get(eid, [])),
            cases=list(engine._cases_by_entity.get(eid, [])),
            investigations=[i for i in engine.investigations
                            if engine._cases_by_id.get(i.get("case_id"), {}).get("entity_id") == eid],
            escalations=[e for e in engine.escalations
                         if engine._cases_by_id.get(e.get("case_id"), {}).get("entity_id") == eid],
            responses=[r for r in engine.responses
                       if engine._cases_by_id.get(r.get("case_id"), {}).get("entity_id") == eid],
            remediations=[r for r in engine.remediations
                          if engine._cases_by_id.get(r.get("case_id"), {}).get("entity_id") == eid],
            assets=list(engine._assets_by_entity.get(eid, [])),
            submissions=list(engine._subs_by_entity.get(eid, [])),
            entity_meta=dict(meta),
            findings=findings,
            expected_periods=expected_periods,
        ))
    return out


def distribution(assessments: list[dict]) -> dict[str, Any]:
    counts = Counter(a["status"] for a in assessments)
    total = len(assessments) or 1
    return {
        k: {"count": counts.get(k, 0), "pct": round(counts.get(k, 0) / total * 100, 1)}
        for k in [C.COMPLIANT, C.PARTIALLY_COMPLIANT, C.NON_COMPLIANT,
                  C.INSUFFICIENT_EVIDENCE, C.NOT_ASSESSED]
    }


def attention_matrix(assessments: list[dict], peer_pos: dict[str, str] | None = None) -> list[dict]:
    rows = []
    for a in assessments:
        rows.append({
            "entity_id": a["entity_id"],
            "entity_name": a["entity_name"],
            "sector": a["sector"],
            "compliance": a["status"],
            "compliance_score": a["compliance_score"],
            "risk_score": a["risk_score"],
            "critical": a["severity"]["critical"],
            "high": a["severity"]["high"],
            "evidence_coverage": a["evidence_coverage"],
            "peer_position": (peer_pos or {}).get(a["entity_id"], "—"),
            "recommended_action": C.recommended_action(
                a["status"], a["risk_score"], a["severity"], a["evidence_coverage"]),
        })
    rows.sort(key=lambda r: (-r["risk_score"], r["compliance_score"]))
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    return rows


def executive_summary(assessments: list[dict], engine, findings: list[dict]) -> str:
    n = len(assessments)
    sectors = len({a["sector"] for a in assessments if a.get("sector")})
    dist = distribution(assessments)
    need = dist[C.NON_COMPLIANT]["count"] + dist[C.PARTIALLY_COMPLIANT]["count"] + dist[C.INSUFFICIENT_EVIDENCE]["count"]
    weak = C.weakest_domains(assessments)[:2]
    weak_txt = " and ".join(f"{w['domain']} ({w['score']}%)" for w in weak) if weak else "no domain with sufficient evidence"
    missing_esc = sum(1 for f in findings if f.get("rule") == "critical_alert_no_escalation")
    esc_affected = sum(len(f.get("evidence", [])) for f in findings if f.get("rule") == "critical_alert_no_escalation")
    return (
        f"{n} entities were assessed across {sectors} sectors. "
        f"{need} entities require supervisory attention. "
        f"{dist[C.NON_COMPLIANT]['count']} entities are non-compliant. "
        f"{dist[C.INSUFFICIENT_EVIDENCE]['count']} entities have insufficient evidence. "
        f"Weakest control domains: {weak_txt}. "
        f"{missing_esc} escalation-gap findings affect {esc_affected} records."
    )


def workflow_funnel(engine, entity_id: str | None = None) -> dict[str, Any]:
    if entity_id:
        alerts = list(engine._alerts_by_entity.get(entity_id, []))
        cases = list(engine._cases_by_entity.get(entity_id, []))
    else:
        alerts, cases = engine.alerts, engine.cases
    case_ids = {c.get("case_id") for c in cases}
    inv = sum(1 for c in cases if c.get("case_id") in engine._inv_by_case)
    esc = sum(1 for c in cases if c.get("case_id") in engine._esc_by_case)
    resp = sum(1 for c in cases if c.get("case_id") in engine._resp_by_case)
    closed = sum(1 for c in cases if str(c.get("status", "")).lower() == "closed" or c.get("closed_at"))
    n_alerts = len(alerts)
    n_cases = len(cases)
    steps = [
        {"stage": "Alerts", "count": n_alerts, "coverage": 100.0 if n_alerts else 0.0},
        {"stage": "Cases", "count": n_cases, "coverage": round(n_cases / max(n_alerts, 1) * 100, 1)},
        {"stage": "Investigations", "count": inv, "coverage": round(inv / max(n_cases, 1) * 100, 1)},
        {"stage": "Escalations", "count": esc, "coverage": round(esc / max(n_cases, 1) * 100, 1)},
        {"stage": "Responses", "count": resp, "coverage": round(resp / max(n_cases, 1) * 100, 1)},
        {"stage": "Closures", "count": closed, "coverage": round(closed / max(n_cases, 1) * 100, 1)},
    ]
    _ = case_ids
    return {"steps": steps, "entity_id": entity_id}


def sector_breakdown(assessments: list[dict]) -> list[dict]:
    by_sector: dict[str, list[dict]] = defaultdict(list)
    for a in assessments:
        by_sector[str(a.get("sector") or "Unspecified")].append(a)
    out = []
    for sector, items in sorted(by_sector.items()):
        n = len(items)
        out.append({
            "sector": sector,
            "entities": n,
            "compliance_pct": round(sum(a["compliance_score"] for a in items) / max(n, 1), 1),
            "non_compliance_pct": round(sum(1 for a in items if a["status"] == C.NON_COMPLIANT) / n * 100, 1),
            "insufficient_evidence_pct": round(sum(1 for a in items if a["status"] in (C.INSUFFICIENT_EVIDENCE, C.NOT_ASSESSED)) / n * 100, 1),
            "avg_risk": round(statistics.fmean([a["risk_score"] for a in items]), 1),
        })
    return out


def control_performance(assessments: list[dict]) -> list[dict]:
    by_domain: dict[str, list[float]] = defaultdict(list)
    for a in assessments:
        for c in a.get("controls", []):
            if c["denominator"] > 0:
                by_domain[c["domain"]].append(c["score"])
    return [{"domain": d, "score": round(statistics.fmean(v), 1), "controls": len(v)}
            for d, v in sorted(by_domain.items(), key=lambda kv: statistics.fmean(kv[1]))]


def grouped_findings(findings: list[dict], engine=None,
                     entity_meta: dict[str, dict] | None = None) -> list[dict]:
    """Group findings by (rule, entity) with affected counts, assets, rate."""
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in findings:
        groups[(str(f.get("rule")), str(f.get("entity_id")))].append(f)
    out = []
    for (rule, eid), items in groups.items():
        items.sort(key=lambda x: str(x.get("id")))
        base = dict(items[0])
        ev_ids: list[str] = []
        for it in items:
            ev_ids.extend(it.get("evidence", []))
        ev_ids = list(dict.fromkeys(ev_ids))
        # affected alert ids from evidence → source rows
        alert_ids: set[str] = set()
        asset_ids: set[str] = set()
        if engine is not None:
            row_by_ev = _evidence_row_index(engine)
            for ev in ev_ids:
                row = row_by_ev.get(ev)
                if row:
                    if row.get("alert_id"):
                        alert_ids.add(str(row["alert_id"]))
                    if row.get("asset_id"):
                        asset_ids.add(str(row["asset_id"]))
        denom = _group_denominator(rule, engine, eid)
        out.append({
            "group_id": f"{rule}::{eid}",
            "rule": rule,
            "rule_version": base.get("rule_version", C.RULE_VERSION),
            "entity_id": eid,
            "entity_name": (entity_meta or {}).get(eid, {}).get("entity_name", eid),
            "sector": (entity_meta or {}).get(eid, {}).get("sector"),
            "severity": base.get("severity"),
            "domain": base.get("category") or _rule_domain(rule),
            "title": base.get("title"),
            "description": base.get("description"),
            "finding_ids": [i.get("id") for i in items],
            "affected_records": len(ev_ids),
            "affected_alerts": sorted(alert_ids),
            "affected_assets": sorted(asset_ids),
            "rate": round(len(ev_ids) / denom * 100, 1) if denom else None,
            "denominator": denom,
            "calculation": _group_calculation(rule, len(ev_ids), denom),
            "evidence_ids": ev_ids[:200],
            "review_status": base.get("review_status", "NEW"),
        })
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.sort(key=lambda g: (sev_rank.get(str(g["severity"]).lower(), 4), -g["affected_records"]))
    return out


def _rule_domain(rule: str) -> str:
    return {
        "critical_alert_no_escalation": "Escalation",
        "escalation_no_response": "Incident Response",
        "closed_without_evidence": "Closure & Evidence",
        "closure_before_investigation": "Closure & Evidence",
        "invalid_status_order": "Closure & Evidence",
        "investigation_without_conclusion": "Investigation",
        "repeated_investigation_template": "Operational Discipline",
        "response_time_anomaly": "Incident Response",
        "alert_without_case": "Case Management",
        "asset_without_coverage": "Monitoring Coverage",
        "negative_space_period_gap": "Governance & Oversight",
        "duplicate_record": "Data Quality & Reporting",
        "missing_severity": "Data Quality & Reporting",
        "missing_asset_criticality": "Data Quality & Reporting",
        "invalid_status": "Data Quality & Reporting",
    }.get(rule, "Governance & Oversight")


def _group_denominator(rule: str, engine, eid: str) -> int:
    if engine is None:
        return 0
    alerts = engine._alerts_by_entity.get(eid, [])
    cases = engine._cases_by_entity.get(eid, [])
    if rule == "critical_alert_no_escalation":
        return sum(1 for a in alerts if a.get("escalation_required"))
    if rule == "alert_without_case":
        return len(alerts)
    if rule in ("escalation_no_response",):
        return len(engine.escalations)
    if rule in ("investigation_without_conclusion", "repeated_investigation_template"):
        return len(cases)
    if rule == "duplicate_record":
        return len(alerts)
    return max(len(alerts), len(cases))


def _group_calculation(rule: str, affected: int, denom: int) -> str:
    if denom:
        return f"{affected}/{denom} records affected ({round(affected/denom*100,1)}%) for rule {rule}"
    return f"{affected} records affected for rule {rule}"


def _evidence_row_index(engine) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for sub in getattr(engine, "submissions", []):
        sid = sub.get("id", "submission")
        for row in sub.get("records", []):
            if isinstance(row, dict) and "_row" in row:
                index[f"record:{sid}#row-{row['_row']}"] = row
    return index


def data_quality_v2(engine) -> dict[str, Any]:
    """Weighted 5-dimension data quality: completeness, validity, consistency,
    uniqueness, timeliness. Optional fields never penalise the score."""
    alerts = engine.alerts
    n = len(alerts)
    mand = ["alert_id", "timestamp", "severity", "asset_id"]
    comp_cells = 0
    comp_total = max(n * len(mand), 1)
    valid_ts = 0
    valid_sev = 0
    for a in alerts:
        for k in mand:
            v = a.get(k)
            if k == "severity":
                if str(v or "").lower() in {"critical", "high", "medium", "low"}:
                    comp_cells += 1
            elif v:
                comp_cells += 1
        if a.get("timestamp") and _parse_ts(a.get("timestamp")):
            valid_ts += 1
        if str(a.get("severity") or "").lower() in {"critical", "high", "medium", "low"}:
            valid_sev += 1
    completeness = round(comp_cells / comp_total * 100, 1) if n else 0.0
    validity = round(((valid_ts + valid_sev) / max(n * 2, 1)) * 100, 1) if n else 0.0
    # consistency: case links resolve + escalation links resolve
    case_ids = {c.get("case_id") for c in engine.cases}
    linked = [a for a in alerts if a.get("case_id")]
    cons_ok = sum(1 for a in linked if a.get("case_id") in case_ids)
    consistency = round(cons_ok / max(len(linked), 1) * 100, 1) if linked else 100.0
    seen: dict[str, int] = {}
    for a in alerts:
        seen[str(a.get("alert_id"))] = seen.get(str(a.get("alert_id")), 0) + 1
    dups = sum(v - 1 for v in seen.values() if v > 1)
    uniqueness = round((n - dups) / max(n, 1) * 100, 1) if n else 100.0
    # timeliness: records within assessment window (have parseable ts)
    timely = sum(1 for a in alerts if _parse_ts(a.get("timestamp")))
    timeliness = round(timely / max(n, 1) * 100, 1) if n else 0.0
    overall = round(completeness * 0.3 + validity * 0.25 + consistency * 0.2
                    + uniqueness * 0.15 + timeliness * 0.1, 1)
    issues = [
        {"type": "missing_asset_mapping", "count": sum(1 for a in alerts if not a.get("asset_id")),
         "description": "Alerts without asset identifier"},
        {"type": "duplicate_alert", "count": dups, "description": "Duplicate alert identifiers"},
        {"type": "missing_timestamp", "count": sum(1 for a in alerts if not a.get("timestamp")),
         "description": "Alerts with missing timestamps"},
        {"type": "invalid_timestamp", "count": sum(1 for a in alerts if a.get("timestamp") and not _parse_ts(a.get("timestamp"))),
         "description": "Alerts with unparseable timestamps"},
        {"type": "missing_severity", "count": sum(1 for a in alerts if str(a.get("severity") or "").lower() not in {"critical", "high", "medium", "low"}),
         "description": "Alerts without valid severity"},
        {"type": "missing_case_link", "count": sum(1 for a in alerts if not a.get("case_id")),
         "description": "Alerts without linked case"},
        {"type": "missing_entity", "count": 0, "description": "Alerts without entity identifier"},
    ]
    by_entity = {}
    for eid, ea in engine._alerts_by_entity.items():
        en = len(ea)
        ec = sum(sum(1 for k in mand if (str(a.get(k)).lower() in {"critical","high","medium","low"} if k == "severity" else bool(a.get(k)))) for a in ea)
        by_entity[eid] = {
            "total_records": en,
            "completeness": round(ec / max(en * len(mand), 1) * 100, 1),
            "missing_asset_mapping": sum(1 for a in ea if not a.get("asset_id")),
            "missing_timestamp": sum(1 for a in ea if not a.get("timestamp")),
            "missing_severity": sum(1 for a in ea if str(a.get("severity") or "").lower() not in {"critical","high","medium","low"}),
            "missing_case_link": sum(1 for a in ea if not a.get("case_id")),
        }
    return {
        "total_records": n,
        "valid_records": sum(1 for a in alerts if a.get("timestamp") and str(a.get("severity") or "").lower() in {"critical","high","medium","low"}),
        "invalid_records": sum(1 for a in alerts if not a.get("timestamp") or str(a.get("severity") or "").lower() not in {"critical","high","medium","low"}),
        "duplicate_records": dups,
        "dimensions": {"completeness": completeness, "validity": validity,
                       "consistency": consistency, "uniqueness": uniqueness,
                       "timeliness": timeliness},
        "overall_score": overall,
        "formula": "Overall = 0.30*completeness + 0.25*validity + 0.20*consistency + 0.15*uniqueness + 0.10*timeliness. Optional fields excluded.",
        "issues": [i for i in issues if i["count"] > 0],
        "by_entity": by_entity,
    }


def reporting_coverage(engine, expected_periods: list[str] | None = None) -> dict[str, Any]:
    periods = expected_periods or [f"2026-{m:02d}" for m in range(1, 10)]
    by_entity: dict[str, dict] = {}
    for eid in engine.entities:
        received = sorted({s.get("reporting_period") for s in engine._subs_by_entity.get(eid, [])
                           if s.get("status") == "submitted" and s.get("reporting_period")})
        missing = [p for p in periods if p not in received]
        by_entity[eid] = {
            "entity_id": eid,
            "expected": len(periods),
            "received": len(received),
            "missing": missing,
            "coverage_pct": round(len(received) / len(periods) * 100, 1),
            "received_periods": received,
        }
    return {"expected_periods": periods, "by_entity": by_entity}


def audit_hash(prev_hash: str, event: dict[str, Any]) -> str:
    payload = json.dumps({k: event.get(k) for k in sorted(event.keys()) if k != "event_hash"},
                         sort_keys=True, default=str)
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


def dataset_hash(engine) -> str:
    h = hashlib.sha256()
    for a in sorted(engine.alerts, key=lambda x: str(x.get("alert_id"))):
        h.update(json.dumps({k: a.get(k) for k in
                             ("alert_id", "entity_id", "severity", "timestamp", "case_id")},
                            sort_keys=True, default=str).encode())
    return h.hexdigest()
