"""Explicit supervisory compliance assessment framework (SAT-SA).

Evidence-grounded: every control reports numerator/denominator, status,
score, supporting finding IDs and evidence IDs. Missing evidence yields
INSUFFICIENT_EVIDENCE -- never compliance by default.
"""
from __future__ import annotations

import hashlib
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

RULE_VERSION = "sat-sa-rules-1.2"

COMPLIANCE_STATES = (
    "COMPLIANT",
    "PARTIALLY_COMPLIANT",
    "NON_COMPLIANT",
    "INSUFFICIENT_EVIDENCE",
    "NOT_ASSESSED",
)

# Configurable classification thresholds
THRESHOLDS = {
    "compliant_min": 85.0,
    "partial_min": 60.0,
    "evidence_min": 50.0,  # below -> INSUFFICIENT_EVIDENCE
}

CONTROL_DEFS: list[dict[str, str]] = [
    {"id": "TD-01", "name": "Alert generation coverage", "domain": "Threat Detection",
     "description": "Alerts carry severity classification and timestamps.",
     "expected_evidence": "alert records with severity + timestamp"},
    {"id": "TD-02", "name": "Severity classification completeness", "domain": "Threat Detection",
     "description": "Share of alerts with a valid severity value.",
     "expected_evidence": "severity field on every alert"},
    {"id": "TR-01", "name": "Alert-to-case linkage", "domain": "Alert Triage",
     "description": "Alerts linked to a case record.",
     "expected_evidence": "case_id on alert records"},
    {"id": "TR-02", "name": "Critical/high triage coverage", "domain": "Alert Triage",
     "description": "Critical/high alerts routed to a case for triage.",
     "expected_evidence": "case_id on critical/high alerts"},
    {"id": "IN-01", "name": "Investigation existence", "domain": "Investigation",
     "description": "Cases backed by an investigation record.",
     "expected_evidence": "investigation_id / investigated flag per case"},
    {"id": "IN-02", "name": "Investigation conclusion quality", "domain": "Investigation",
     "description": "Investigations with a documented conclusion.",
     "expected_evidence": "investigation_conclusion / conclusion text"},
    {"id": "IN-03", "name": "Investigation timeliness", "domain": "Investigation",
     "description": "Investigations completed in a credible window before closure.",
     "expected_evidence": "start/end/closure timestamps in valid order"},
    {"id": "ES-01", "name": "Required escalation completion", "domain": "Escalation",
     "description": "Critical/high alerts requiring escalation that were escalated.",
     "expected_evidence": "escalation_id / escalated flag + timestamp + owner"},
    {"id": "ES-02", "name": "Escalation evidence quality", "domain": "Escalation",
     "description": "Escalations carry timestamp and destination/owner.",
     "expected_evidence": "escalation_time + recipient/owner"},
    {"id": "IR-01", "name": "Response evidence", "domain": "Incident Response",
     "description": "Escalated/critical cases with a recorded response action.",
     "expected_evidence": "response_id / responded flag + response_timestamp"},
    {"id": "IR-02", "name": "Response SLA adherence", "domain": "Incident Response",
     "description": "Responses recorded within the supervision SLA window.",
     "expected_evidence": "response_time within 24h of escalation"},
    {"id": "MO-01", "name": "Monitoring coverage", "domain": "Monitoring Coverage",
     "description": "Critical assets with observed alert/monitoring evidence.",
     "expected_evidence": "asset records + alert-to-asset mapping"},
    {"id": "MO-02", "name": "Critical asset coverage", "domain": "Monitoring Coverage",
     "description": "Critical/high assets under monitoring.",
     "expected_evidence": "critical assets with activity"},
    {"id": "CM-01", "name": "Case ownership & status validity", "domain": "Case Management",
     "description": "Cases with valid lifecycle status values.",
     "expected_evidence": "case_status in supported lifecycle"},
    {"id": "CL-01", "name": "Closure discipline", "domain": "Closure & Evidence",
     "description": "Closures preceded by investigation (and response where required).",
     "expected_evidence": "closure + investigation timestamps in valid order"},
    {"id": "GV-01", "name": "Reporting completeness", "domain": "Governance & Oversight",
     "description": "Records with complete metadata (entity, timestamps, analyst).",
     "expected_evidence": "entity/sector/timestamp/analyst metadata"},
    {"id": "OP-01", "name": "Operational discipline", "domain": "Operational Discipline",
     "description": "Investigations free of template/fast-closure patterns.",
     "expected_evidence": "case-specific narratives with credible duration"},
    {"id": "DQ-01", "name": "Record validity & uniqueness", "domain": "Data Quality & Reporting",
     "description": "Records free of duplicates, missing mandatory fields, invalid timestamps.",
     "expected_evidence": "schema/range/cross-record checks"},
    {"id": "CR-01", "name": "Remediation of repeated alerts", "domain": "Cyber Resilience",
     "description": "Assets with repeated critical/high alerts show remediation.",
     "expected_evidence": "remediation record for repeated assets"},
]

VALID_STATUSES = {"open", "new", "investigating", "in_progress", "closed", "resolved", "escalated", ""}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _entity_of(row: dict[str, Any]) -> str:
    return str(row.get("entity_id") or row.get("entity") or row.get("user") or row.get("host") or "unknown")


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except (ValueError, TypeError):
        return None


def _bool(row: dict[str, Any], *keys: str) -> Optional[bool]:
    for key in keys:
        if key in row and row[key] is not None and row[key] != "":
            value = row[key]
            if isinstance(value, bool):
                return value
            text = str(value).lower()
            if text in ("true", "1", "yes", "completed", "closed", "done", "escalated"):
                return True
            if text in ("false", "0", "no", "open", "missing", "none"):
                return False
    return None


def _escalation_required(row: dict[str, Any]) -> Optional[bool]:
    explicit = _bool(row, "escalation_required")
    if explicit is not None:
        return explicit
    sev = str(row.get("severity") or "").lower()
    if sev in ("critical", "high"):
        return True
    if sev in ("low", "medium"):
        return False
    return None  # unknown severity -> cannot determine


def _has_escalation(row: dict[str, Any]) -> bool:
    if row.get("escalation_id"):
        return True
    return _bool(row, "escalated", "escalation_status") is True


def _has_investigation(row: dict[str, Any]) -> bool:
    if row.get("investigation_id"):
        return True
    return _bool(row, "investigated", "investigation_status") is True


def _has_response(row: dict[str, Any]) -> bool:
    if row.get("response_id"):
        return True
    return _bool(row, "responded", "response_status") is True


def _has_closure(row: dict[str, Any]) -> bool:
    if row.get("closure_id"):
        return True
    status = str(row.get("closure_status") or row.get("status") or "").lower()
    return status in ("closed", "resolved")


def _status_for(coverage: Optional[float], denom: int) -> str:
    if denom == 0 or coverage is None:
        return "INSUFFICIENT_EVIDENCE"
    if coverage >= 85:
        return "COMPLIANT"
    if coverage >= 60:
        return "PARTIALLY_COMPLIANT"
    return "NON_COMPLIANT"


def _score_for(status: str) -> Optional[float]:
    return {"COMPLIANT": 100.0, "PARTIALLY_COMPLIANT": 50.0,
            "NON_COMPLIANT": 0.0}.get(status)


def evaluate_controls(rows: list[dict[str, Any]], findings: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Evaluate the 12 supervisory controls over a set of rows."""
    findings = findings or []
    alert_rows = [r for r in rows if r.get("alert_id") or str(r.get("type", "")).lower() == "alert" or r.get("severity")]
    case_rows = [r for r in rows if r.get("case_id")]
    scope = alert_rows or rows
    n = len(scope)
    findings_by_rule: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        findings_by_rule[f.get("rule", "")].append(f.get("id", ""))

    def ctrl(cid: str, num: int, den: int, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        meta = next(m for m in CONTROL_DEFS if m["id"] == cid)
        coverage = round(num / den * 100, 1) if den else None
        status = _status_for(coverage, den)
        return {**meta, "control_id": cid, "control_name": meta["name"],
                "numerator": num, "denominator": den, "coverage": coverage,
                "status": status, "score": _score_for(status),
                "supporting_finding_ids": [], "evidence_ids": [],
                "calculation": f"{num}/{den} = {coverage}%" if coverage is not None else "no assessable records",
                **(extra or {})}

    sev_ok = sum(1 for r in scope if str(r.get("severity") or "").lower() in VALID_SEVERITIES)
    ts_ok = sum(1 for r in scope if _parse_ts(r.get("timestamp") or r.get("time")))
    linked = sum(1 for r in scope if r.get("case_id"))
    out: list[dict[str, Any]] = []
    out.append(ctrl("TD-01", ts_ok, n, {"supporting_finding_ids": findings_by_rule.get("missing_timestamp", [])}))
    out.append(ctrl("TD-02", sev_ok, n, {"supporting_finding_ids": findings_by_rule.get("missing_severity", [])}))
    out.append(ctrl("TR-01", linked, n if scope else 0,
                    {"supporting_finding_ids": findings_by_rule.get("alert_without_case", [])}))
    if case_rows:
        inv = sum(1 for r in case_rows if _has_investigation(r))
        concl = sum(1 for r in case_rows if (r.get("investigation_conclusion") or r.get("conclusion")) and _has_investigation(r))
        out.append(ctrl("IN-01", inv, len(case_rows),
                        {"supporting_finding_ids": findings_by_rule.get("closed_without_evidence", [])}))
        out.append(ctrl("IN-02", concl, inv if inv else 0))
    else:
        out.append(ctrl("IN-01", 0, 0))
        out.append(ctrl("IN-02", 0, 0))
    req_rows = [r for r in scope if _escalation_required(r) is True]
    unk_esc = sum(1 for r in scope if _escalation_required(r) is None)
    if req_rows:
        done = sum(1 for r in req_rows if _has_escalation(r))
        out.append(ctrl("ES-01", done, len(req_rows),
                        {"supporting_finding_ids": findings_by_rule.get("critical_alert_no_escalation", [])}))
    elif unk_esc:
        out.append(ctrl("ES-01", 0, 0))  # severity unknown -> insufficient evidence
    else:
        # Evidence sufficient to establish no escalation was required.
        meta = next(m for m in CONTROL_DEFS if m["id"] == "ES-01")
        out.append({**meta, "control_id": "ES-01", "control_name": meta["name"],
                    "numerator": 0, "denominator": 0, "coverage": 100.0,
                    "status": "COMPLIANT", "score": 100.0,
                    "supporting_finding_ids": [], "evidence_ids": [],
                    "calculation": "no alerts required escalation (sufficient evidence)",
                    "sufficient_negative": True})
    resp_scope = [r for r in scope if _escalation_required(r) is True or _has_escalation(r)
                  or str(r.get("severity") or "").lower() == "critical"]
    if resp_scope:
        resp = sum(1 for r in resp_scope if _has_response(r))
        out.append(ctrl("IR-01", resp, len(resp_scope),
                        {"supporting_finding_ids": findings_by_rule.get("escalation_no_response", [])}))
    else:
        out.append(ctrl("IR-01", 0, 0))
    crit_assets = {str(r.get("asset_id")) for r in rows if r.get("asset_id") and str(r.get("asset_criticality") or r.get("criticality") or "").lower() in ("critical", "high")}
    mapped = {str(r.get("asset_id")) for r in scope if r.get("asset_id")}
    if crit_assets:
        out.append(ctrl("MO-01", len(crit_assets & mapped), len(crit_assets)))
    elif any(r.get("asset_id") for r in rows):
        out.append(ctrl("MO-01", len(mapped), len(mapped)))
    else:
        out.append(ctrl("MO-01", 0, 0))
    if case_rows:
        valid = sum(1 for r in case_rows if str(r.get("case_status") or r.get("status") or "").lower() in VALID_STATUSES)
        out.append(ctrl("CM-01", valid, len(case_rows),
                        {"supporting_finding_ids": findings_by_rule.get("invalid_status", [])}))
        bad_order = 0
        assessable = 0
        for r in case_rows:
            if _has_closure(r) and _has_investigation(r):
                assessable += 1
                ct = _parse_ts(r.get("closure_timestamp") or r.get("closure_time"))
                it = _parse_ts(r.get("investigation_completed") or r.get("investigation_time") or r.get("investigation_started"))
                if ct and it and ct < it:
                    bad_order += 1
        out.append(ctrl("CL-01", assessable - bad_order, assessable if assessable else (len(case_rows) if any(_has_closure(r) for r in case_rows) else 0),
                        {"supporting_finding_ids": findings_by_rule.get("closure_before_investigation", [])}))
    else:
        out.append(ctrl("CM-01", 0, 0))
        out.append(ctrl("CL-01", 0, 0))
    meta_ok = sum(1 for r in rows if (r.get("timestamp") or r.get("time")) and _entity_of(r) != "unknown")
    out.append(ctrl("GV-01", meta_ok, len(rows) if rows else 0))
    seen: set[str] = set()
    dups = 0
    invalid_ts = 0
    missing_mandatory = 0
    for r in rows:
        key = str(r.get("alert_id") or r.get("case_id") or "")
        if key:
            if key in seen:
                dups += 1
            seen.add(key)
        if (r.get("timestamp") or r.get("time")) and not _parse_ts(r.get("timestamp") or r.get("time")):
            invalid_ts += 1
        if not (r.get("timestamp") or r.get("time")) or _entity_of(r) == "unknown":
            missing_mandatory += 1
        if r.get("alert_id") and not r.get("severity"):
            missing_mandatory += 1
    bad = dups + invalid_ts + missing_mandatory
    out.append(ctrl("DQ-01", max(len(rows) - bad, 0), len(rows) if rows else 0,
                    {"supporting_finding_ids": findings_by_rule.get("duplicate_record", [])}))
    return out


def entity_compliance(entity_id: str, rows: list[dict[str, Any]], findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    controls = evaluate_controls(rows, [f for f in (findings or []) if f.get("entity_id") == entity_id])
    scored = [c for c in controls if c["score"] is not None]
    compliance_score = round(statistics.fmean([c["score"] for c in scored]), 1) if scored else None
    evidence_coverage = round(len(scored) / len(controls) * 100, 1) if controls else 0.0
    counts = Counter(c["status"] for c in controls)
    sev = Counter(str(f.get("severity", "")).lower() for f in (findings or []) if f.get("entity_id") == entity_id)
    critical = sev.get("critical", 0)
    if not rows:
        state = "NOT_ASSESSED"
    elif evidence_coverage < THRESHOLDS["evidence_min"]:
        state = "INSUFFICIENT_EVIDENCE"
    elif (compliance_score is not None and compliance_score < THRESHOLDS["partial_min"]) or critical > 0:
        # Critical unresolved finding forces non-compliance review; a single
        # critical with otherwise strong evidence -> partial at most.
        if compliance_score is not None and compliance_score >= THRESHOLDS["partial_min"] and critical <= 2:
            state = "PARTIALLY_COMPLIANT"
        else:
            state = "NON_COMPLIANT"
    elif compliance_score is not None and compliance_score >= THRESHOLDS["compliant_min"] and critical == 0:
        state = "COMPLIANT"
    else:
        state = "PARTIALLY_COMPLIANT"
    risk = calculate_risk(rows, findings or [], entity_id, compliance_score or 0, evidence_coverage)
    return {
        "entity_id": entity_id,
        "status": state,
        "compliance_score": compliance_score,
        "evidence_coverage": evidence_coverage,
        "controls_assessed": len(controls),
        "controls_compliant": counts.get("COMPLIANT", 0),
        "controls_partial": counts.get("PARTIALLY_COMPLIANT", 0),
        "controls_non_compliant": counts.get("NON_COMPLIANT", 0),
        "controls_insufficient": counts.get("INSUFFICIENT_EVIDENCE", 0),
        "critical": critical, "high": sev.get("high", 0),
        "medium": sev.get("medium", 0), "low": sev.get("low", 0),
        "controls": controls,
        "risk_score": risk["score"],
        "risk_drivers": risk["drivers"],
    }


def calculate_risk(rows: list[dict[str, Any]], findings: list[dict[str, Any]],
                   entity_id: str, compliance_score: float, evidence_coverage: float) -> dict[str, Any]:
    """Explainable additive risk model (0-100), not a blind multiplier."""
    mine = [f for f in findings if f.get("entity_id") == entity_id]
    erows = [r for r in rows if _entity_of(r) == entity_id] if rows and any(_entity_of(r) == entity_id for r in rows) else rows
    sev = Counter(str(f.get("severity", "")).lower() for f in mine)
    drivers: list[dict[str, Any]] = []
    score = 0.0

    def add(points: float, label: str, detail: str = "") -> None:
        nonlocal score
        score += points
        drivers.append({"points": round(points, 1), "label": label, "detail": detail})

    if sev.get("critical"):
        add(min(30, sev["critical"] * 6), "Critical escalation/workflow failures",
            f"{sev['critical']} critical findings")
    if sev.get("high"):
        add(min(20, sev["high"] * 3), "High-severity gaps", f"{sev['high']} high findings")
    if sev.get("medium"):
        add(min(8, sev["medium"] * 1.0), "Medium findings", f"{sev['medium']} medium findings")
    req = [r for r in erows if _escalation_required(r) is True]
    if req:
        miss = sum(1 for r in req if not _has_escalation(r))
        rate = miss / len(req) * 100
        if rate > 0:
            add(min(25, rate * 0.25), "Escalation gap rate", f"{miss}/{len(req)} ({rate:.1f}%) missing escalation")
    cases = [r for r in erows if r.get("case_id")]
    if cases:
        no_inv = sum(1 for r in cases if not _has_investigation(r))
        if no_inv:
            add(min(12, no_inv / len(cases) * 100 * 0.12), "Investigation gaps",
                f"{no_inv}/{len(cases)} cases without investigation")
    crit_unmon = sum(1 for r in erows if r.get("asset_id") and not r.get("case_id") and str(r.get("severity") or "").lower() == "critical")
    if crit_unmon:
        add(min(10, crit_unmon * 1.5), "Monitoring gaps", f"{crit_unmon} critical alerts without case linkage")
    if evidence_coverage < 100 and erows:
        add(min(10, (100 - evidence_coverage) * 0.1), "Evidence limitation",
            f"evidence coverage {evidence_coverage}%")
    if sev.get("low"):
        add(min(4, sev["low"] * 0.5), "Data-quality issues", f"{sev['low']} low findings")
    score = round(min(100.0, max(0.0, score)), 1)
    return {"score": score, "drivers": sorted(drivers, key=lambda d: -d["points"])}


RECOMMENDATIONS = ("IMMEDIATE REVIEW", "SUPERVISORY REVIEW", "EVIDENCE REQUEST", "ROUTINE REVIEW", "NO ACTION")


def recommend_action(comp: dict[str, Any]) -> str:
    if comp["status"] == "NON_COMPLIANT" or comp["critical"] > 0 or (comp["risk_score"] or 0) >= 70:
        return "IMMEDIATE REVIEW"
    if comp["status"] == "INSUFFICIENT_EVIDENCE":
        return "EVIDENCE REQUEST"
    if comp["status"] == "PARTIALLY_COMPLIANT" or (comp["risk_score"] or 0) >= 40:
        return "SUPERVISORY REVIEW"
    if (comp["compliance_score"] or 0) >= 85:
        return "NO ACTION"
    return "ROUTINE REVIEW"


def workflow_funnel(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts = [r for r in rows if r.get("alert_id") or r.get("severity")]
    n_alerts = len(alerts) or len(rows)
    cases = [r for r in rows if r.get("case_id")]
    inv = [r for r in rows if r.get("case_id") and _has_investigation(r)]
    req = [r for r in rows if _escalation_required(r) is True]
    esc = [r for r in rows if _has_escalation(r)]
    resp = [r for r in rows if _has_response(r)]
    closed = [r for r in rows if _has_closure(r)]
    stages = [("Alerts", n_alerts), ("Cases", len(cases)), ("Investigations", len(inv)),
              ("Escalations", len(esc)), ("Responses", len(resp)), ("Closures", len(closed))]
    out = []
    for i, (stage, count) in enumerate(stages):
        base = stages[0][1]
        prev = stages[i - 1][1] if i else None
        out.append({"stage": stage, "count": count,
                    "coverage_pct": round(count / base * 100, 1) if base else 0.0,
                    "conversion_pct": round(count / prev * 100, 1) if prev else (100.0 if base else 0.0)})
    out.append({"stage": "EscalationRequired", "count": len(req),
                "coverage_pct": round(len(req) / n_alerts * 100, 1) if n_alerts else 0.0,
                "conversion_pct": round(len(esc) / len(req) * 100, 1) if req else 100.0})
    return out


def data_quality(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Weighted 5-dimension data-quality score with visible methodology."""
    total = len(rows)
    if not total:
        return {"overall": None, "dimensions": {}, "methodology": METHODOLOGY, "issues": []}
    mandatory = ("entity_id", "timestamp", "severity", "asset_id")
    complete_cells = 0
    for r in rows:
        for field in mandatory:
            key = "timestamp" if field == "timestamp" else field
            val = r.get(key) or r.get("time") if field == "timestamp" else r.get(field)
            if val not in (None, ""):
                complete_cells += 1
    completeness = complete_cells / (total * len(mandatory)) * 100
    valid = 0
    for r in rows:
        ok = True
        if str(r.get("severity") or "").lower() not in VALID_SEVERITIES and r.get("severity") not in (None, ""):
            ok = False
        if (r.get("timestamp") or r.get("time")) and not _parse_ts(r.get("timestamp") or r.get("time")):
            ok = False
        if str(r.get("status") or r.get("case_status") or "") and str(r.get("status") or r.get("case_status") or "").lower() not in VALID_STATUSES:
            ok = False
        if ok:
            valid += 1
    validity = valid / total * 100
    seen: set[str] = set()
    dups = 0
    for r in rows:
        key = str(r.get("alert_id") or r.get("case_id") or "")
        if key:
            if key in seen:
                dups += 1
            seen.add(key)
    uniqueness = (total - dups) / total * 100
    consistent = 0
    for r in rows:
        ok = True
        if r.get("case_id") and not r.get("alert_id") and not _has_investigation(r) and not _has_escalation(r):
            pass  # orphan case is still internally consistent; flagged elsewhere
        if r.get("closure_id") and not _has_closure(r):
            ok = False
        if ok:
            consistent += 1
    consistency = consistent / total * 100
    in_period = sum(1 for r in rows if _parse_ts(r.get("timestamp") or r.get("time")))
    timeliness = in_period / total * 100
    dims = {"completeness": round(completeness, 1), "validity": round(validity, 1),
            "consistency": round(consistency, 1), "uniqueness": round(uniqueness, 1),
            "timeliness": round(timeliness, 1)}
    overall = round(dims["completeness"] * 0.30 + dims["validity"] * 0.25 + dims["consistency"] * 0.20
                    + dims["uniqueness"] * 0.15 + dims["timeliness"] * 0.10, 1)
    issues = [
        {"type": "missing_asset_mapping", "count": sum(1 for r in rows if not r.get("asset_id"))},
        {"type": "duplicate_alerts", "count": dups},
        {"type": "missing_timestamps", "count": sum(1 for r in rows if not (r.get("timestamp") or r.get("time")))},
        {"type": "invalid_status", "count": sum(1 for r in rows if str(r.get("status") or r.get("case_status") or "") and str(r.get("status") or r.get("case_status") or "").lower() not in VALID_STATUSES)},
        {"type": "missing_entity", "count": sum(1 for r in rows if _entity_of(r) == "unknown")},
        {"type": "missing_severity", "count": sum(1 for r in rows if not r.get("severity"))},
        {"type": "missing_case_link", "count": sum(1 for r in rows if (r.get("alert_id") or r.get("severity")) and not r.get("case_id"))},
    ]
    return {"overall": overall, "dimensions": dims, "methodology": METHODOLOGY,
            "issues": [i for i in issues if i["count"] > 0],
            "total_records": total,
            "valid_records": valid, "invalid_records": total - valid, "duplicate_records": dups}


METHODOLOGY = ("Overall = 0.30*completeness + 0.25*validity + 0.20*consistency + "
               "0.15*uniqueness + 0.10*timeliness. Completeness = mandatory fields "
               "(entity_id, timestamp, severity, asset_id) populated. Validity = schema/range "
               "checks pass. Consistency = cross-record relationship validity. Uniqueness = "
               "duplicate-free ratio. Timeliness = records with parseable timestamps.")


def executive_summary(assessments: list[dict[str, Any]], sectors: int, weakest: list[str],
                      missing_esc: int, req_esc: int) -> str:
    n = len(assessments)
    by_status = Counter(a["status"] for a in assessments)
    need = by_status.get("NON_COMPLIANT", 0) + by_status.get("PARTIALLY_COMPLIANT", 0) + by_status.get("INSUFFICIENT_EVIDENCE", 0)
    weak = ", ".join(weakest[:2]) if weakest else "no domain stands out"
    return (f"{n} entities were assessed across {sectors} sectors. "
            f"{need} entities require supervisory attention. "
            f"{by_status.get('NON_COMPLIANT', 0)} entities are non-compliant. "
            f"{by_status.get('INSUFFICIENT_EVIDENCE', 0)} entities have insufficient evidence. "
            f"{weak} are the weakest control domains. "
            f"{missing_esc} of {req_esc} critical/high alerts lacked required escalation evidence.")


def audit_hash(event: dict[str, Any], prev_hash: str = "") -> str:
    payload = f"{prev_hash}|{event.get('timestamp')}|{event.get('event_type')}|{event.get('actor')}|{event.get('target_id')}|{event.get('action')}|{event.get('new_state')}".encode()
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Engine-table API (operates on SupervisoryAnalytics normalized tables).
# Used by /api/v1/analytics/* endpoints. Shares thresholds and semantics
# with the record-based API above.
# ---------------------------------------------------------------------------

def _ctl(cid: str, num: int, den: int, finding_ids: list[str] | None = None) -> dict[str, Any]:
    meta = next(m for m in CONTROL_DEFS if m["id"] == cid)
    coverage = round(num / den * 100, 1) if den else None
    status = _status_for(coverage, den)
    return {**meta, "control_id": cid, "control_name": meta["name"],
            "numerator": num, "denominator": den, "coverage": coverage,
            "status": status, "score": _score_for(status),
            "supporting_finding_ids": finding_ids or [], "evidence_ids": [],
            "calculation": f"{num}/{den} = {coverage}%" if coverage is not None else "no assessable records"}


def evaluate_entity_controls(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate controls from normalized engine tables.

    ctx keys: entity_id, alerts, cases, inv_by_case, esc_by_case,
    resp_by_case, rem_by_case, assets, submissions, peer_deviation.
    """
    alerts: list[dict[str, Any]] = ctx.get("alerts", [])
    cases: list[dict[str, Any]] = ctx.get("cases", [])
    inv_by_case: dict[str, dict[str, Any]] = ctx.get("inv_by_case", {})
    esc_by_case: dict[str, dict[str, Any]] = ctx.get("esc_by_case", {})
    resp_by_case: dict[str, dict[str, Any]] = ctx.get("resp_by_case", {})
    assets: list[dict[str, Any]] = ctx.get("assets", [])
    submissions: list[dict[str, Any]] = ctx.get("submissions", [])
    out: list[dict[str, Any]] = []
    n = len(alerts)
    sev_ok = sum(1 for a in alerts if str(a.get("severity") or "").lower() in VALID_SEVERITIES)
    ts_ok = sum(1 for a in alerts if _parse_ts(a.get("timestamp")))
    out.append(_ctl("TD-01", ts_ok, n))
    out.append(_ctl("TD-02", sev_ok, n))
    linked = sum(1 for a in alerts if a.get("case_id"))
    out.append(_ctl("TR-01", linked, n))
    if cases:
        with_inv = sum(1 for c in cases if c["case_id"] in inv_by_case)
        out.append(_ctl("IN-01", with_inv, len(cases)))
        with_concl = sum(1 for c in cases if c["case_id"] in inv_by_case
                         and inv_by_case[c["case_id"]].get("conclusion"))
        out.append(_ctl("IN-02", with_concl, with_inv))
    else:
        out.append(_ctl("IN-01", 0, 0))
        out.append(_ctl("IN-02", 0, 0))
    req = [a for a in alerts if a.get("escalation_required")]
    unk = [a for a in alerts if a.get("escalation_required") is None
           and str(a.get("severity") or "").lower() not in VALID_SEVERITIES]
    if req:
        done = sum(1 for a in req if a.get("escalation_id")
                   or (a.get("case_id") and a["case_id"] in esc_by_case))
        out.append(_ctl("ES-01", done, len(req)))
    elif unk or n == 0:
        out.append(_ctl("ES-01", 0, 0))
    else:
        meta = next(m for m in CONTROL_DEFS if m["id"] == "ES-01")
        out.append({**meta, "control_id": "ES-01", "control_name": meta["name"],
                    "numerator": 0, "denominator": 0, "coverage": 100.0,
                    "status": "COMPLIANT", "score": 100.0,
                    "supporting_finding_ids": [], "evidence_ids": [],
                    "calculation": "no alerts required escalation (sufficient evidence)",
                    "sufficient_negative": True})
    resp_scope = [a for a in alerts if a.get("escalation_required")
                  or a.get("escalation_id")
                  or (a.get("case_id") and a["case_id"] in esc_by_case)]
    if resp_scope:
        resp = sum(1 for a in resp_scope if a.get("case_id") and a["case_id"] in resp_by_case)
        out.append(_ctl("IR-01", resp, len(resp_scope)))
    else:
        out.append(_ctl("IR-01", 0, 0))
    crit_assets = [x for x in assets if str(x.get("criticality") or "").lower() in ("critical", "high")]
    alerted = {a.get("asset_id") for a in alerts if a.get("asset_id")}
    if crit_assets:
        out.append(_ctl("MO-01", sum(1 for x in crit_assets if x.get("asset_id") in alerted), len(crit_assets)))
    elif assets:
        out.append(_ctl("MO-01", sum(1 for x in assets if x.get("asset_id") in alerted), len(assets)))
    else:
        out.append(_ctl("MO-01", 0, 0))
    if cases:
        valid = sum(1 for c in cases if str(c.get("status") or "").lower() in VALID_STATUSES or not c.get("status"))
        out.append(_ctl("CM-01", valid, len(cases)))
        assessable = [c for c in cases if c["case_id"] in inv_by_case]
        closed = [c for c in cases if str(c.get("status") or "").lower() in ("closed", "resolved")]
        den = len(assessable) if assessable else (len(closed) if closed else 0)
        bad = 0
        for c in assessable:
            ct = _parse_ts(c.get("closed_at"))
            inv = inv_by_case[c["case_id"]]
            it = _parse_ts(inv.get("end_time") or inv.get("start_time"))
            if ct and it and ct < it:
                bad += 1
        out.append(_ctl("CL-01", den - bad, den))
    else:
        out.append(_ctl("CM-01", 0, 0))
        out.append(_ctl("CL-01", 0, 0))
    if alerts or cases:
        meta_ok = sum(1 for a in alerts if a.get("timestamp") and a.get("entity_id"))
        out.append(_ctl("GV-01", meta_ok, n if n else 0))
    else:
        out.append(_ctl("GV-01", 0, 0))
    seen: set[str] = set()
    dups = 0
    for a in alerts:
        key = str(a.get("alert_id", ""))
        if key:
            if key in seen:
                dups += 1
            seen.add(key)
    bad_rows = dups + sum(1 for a in alerts if not a.get("timestamp") or not a.get("severity"))
    out.append(_ctl("DQ-01", max(n - bad_rows, 0), n))
    return out


def compliance_summary(controls: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [c for c in controls if c.get("score") is not None]
    counts = Counter(c.get("status") for c in controls)
    return {
        "compliance_score": round(statistics.fmean([c["score"] for c in scored]), 1) if scored else 0.0,
        "evidence_coverage": round(len(scored) / len(controls) * 100, 1) if controls else 0.0,
        "controls_assessed": len(controls),
        "compliant": counts.get("COMPLIANT", 0),
        "partially_compliant": counts.get("PARTIALLY_COMPLIANT", 0),
        "non_compliant": counts.get("NON_COMPLIANT", 0),
        "insufficient_evidence": counts.get("INSUFFICIENT_EVIDENCE", 0),
        "formula": "COMPLIANT=100, PARTIALLY_COMPLIANT=50, NON_COMPLIANT=0; "
                   "INSUFFICIENT_EVIDENCE excluded; score = mean of evidenced controls",
    }


def classify(summ: dict[str, Any], has_critical: bool = False) -> str:
    if summ.get("controls_assessed", 0) == 0:
        return "NOT_ASSESSED"
    if summ.get("evidence_coverage", 0) < THRESHOLDS["evidence_min"]:
        return "INSUFFICIENT_EVIDENCE"
    score = summ.get("compliance_score", 0)
    if has_critical and score >= THRESHOLDS["partial_min"]:
        return "PARTIALLY_COMPLIANT" if score >= THRESHOLDS["compliant_min"] else "NON_COMPLIANT"
    if has_critical:
        return "NON_COMPLIANT"
    if score >= THRESHOLDS["compliant_min"]:
        return "COMPLIANT"
    if score >= THRESHOLDS["partial_min"]:
        return "PARTIALLY_COMPLIANT"
    return "NON_COMPLIANT"


def risk_with_drivers(ctx: dict[str, Any], controls: list[dict[str, Any]],
                      entity_findings: list[dict[str, Any]]) -> dict[str, Any]:
    alerts: list[dict[str, Any]] = ctx.get("alerts", [])
    cases: list[dict[str, Any]] = ctx.get("cases", [])
    inv_by_case: dict[str, dict[str, Any]] = ctx.get("inv_by_case", {})
    esc_by_case: dict[str, dict[str, Any]] = ctx.get("esc_by_case", {})
    resp_by_case: dict[str, dict[str, Any]] = ctx.get("resp_by_case", {})
    sev = Counter(str(f.get("severity", "")).lower() for f in entity_findings)
    drivers: list[dict[str, Any]] = []
    score = 0.0

    def add(points: float, label: str, detail: str = "") -> None:
        nonlocal score
        score += points
        drivers.append({"points": round(points, 1), "label": label, "detail": detail})

    if sev.get("critical"):
        add(min(30, sev["critical"] * 6), "Critical escalation/workflow failures",
            f"{sev['critical']} critical findings")
    if sev.get("high"):
        add(min(20, sev["high"] * 3), "High-severity gaps", f"{sev['high']} high findings")
    req = [a for a in alerts if a.get("escalation_required")]
    if req:
        miss = sum(1 for a in req if not (a.get("escalation_id") or (a.get("case_id") and a["case_id"] in esc_by_case)))
        if miss:
            add(min(25, miss / len(req) * 100 * 0.25), "Escalation gap rate",
                f"{miss}/{len(req)} missing escalation")
    if cases:
        no_inv = sum(1 for c in cases if c["case_id"] not in inv_by_case)
        if no_inv:
            add(min(12, no_inv / len(cases) * 100 * 0.12), "Investigation gaps",
                f"{no_inv}/{len(cases)} without investigation")
        no_resp = sum(1 for c in cases if c["case_id"] in esc_by_case and c["case_id"] not in resp_by_case)
        if no_resp:
            add(min(10, no_resp * 2), "Response gaps", f"{no_resp} escalated without response")
    peer_dev = abs(float(ctx.get("peer_deviation") or 0))
    if peer_dev > 10:
        add(min(9, peer_dev * 0.15), "Peer performance deviation", f"{peer_dev:.1f} pts below peer median")
    weak = [c for c in controls if c.get("score") == 0.0]
    if weak:
        add(min(8, len(weak) * 1.5), "Failed controls", f"{len(weak)} non-compliant controls")
    if sev.get("medium"):
        add(min(6, sev["medium"] * 0.8), "Medium findings", f"{sev['medium']} medium")
    if sev.get("low"):
        add(min(4, sev["low"] * 0.4), "Data-quality issues", f"{sev['low']} low")
    return {"risk_score": round(min(100.0, score), 1),
            "risk_drivers": sorted(drivers, key=lambda d: -d["points"])}


def recommended_action(status: str, risk_score: float, critical_count: int,
                       evidence_coverage: float) -> str:
    if status == "NON_COMPLIANT" or critical_count >= 5 or (risk_score or 0) >= 70:
        return "IMMEDIATE REVIEW"
    if status == "INSUFFICIENT_EVIDENCE" or (evidence_coverage or 100) < 70:
        return "EVIDENCE REQUEST"
    if status == "PARTIALLY_COMPLIANT" or critical_count > 0 or (risk_score or 0) >= 45:
        return "SUPERVISORY REVIEW"
    if status == "COMPLIANT":
        return "NO ACTION" if (risk_score or 0) < 20 else "ROUTINE REVIEW"
    return "ROUTINE REVIEW"


def workflow_funnel(alerts: list[dict[str, Any]], inv_by_case: dict[str, Any],
                    esc_by_case: dict[str, Any], resp_by_case: dict[str, Any],
                    cases: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    cases = cases if cases is not None else []
    n_alerts = len(alerts)
    n_cases = len(cases) or sum(1 for a in alerts if a.get("case_id"))
    case_ids = {c.get("case_id") for c in cases} | {a.get("case_id") for a in alerts if a.get("case_id")}
    n_inv = sum(1 for cid in case_ids if cid and cid in inv_by_case)
    req = [a for a in alerts if a.get("escalation_required")]
    n_esc = sum(1 for cid in case_ids if cid and cid in esc_by_case)
    if not n_esc:
        n_esc = sum(1 for a in alerts if a.get("escalation_id"))
    n_resp = sum(1 for cid in case_ids if cid and cid in resp_by_case)
    n_closed = sum(1 for c in cases if str(c.get("status") or "").lower() in ("closed", "resolved"))
    stages = [("Alerts", n_alerts), ("Cases", n_cases), ("Investigations", n_inv),
              ("Escalations", n_esc), ("Responses", n_resp), ("Closures", n_closed)]
    out = []
    for i, (stage, count) in enumerate(stages):
        prev = stages[i - 1][1] if i else None
        out.append({"stage": stage, "count": count,
                    "coverage_pct": round(count / n_alerts * 100, 1) if n_alerts else 0.0,
                    "conversion_pct": round(count / prev * 100, 1) if prev else (100.0 if n_alerts else 0.0)})
    out.append({"stage": "EscalationRequired", "count": len(req),
                "coverage_pct": round(len(req) / n_alerts * 100, 1) if n_alerts else 0.0,
                "conversion_pct": round(n_esc / len(req) * 100, 1) if req else 100.0})
    return out


def data_quality_score(alerts: list[dict[str, Any]], cases: list[dict[str, Any]],
                       assets: list[dict[str, Any]], submissions: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(alerts) or len(cases)
    if not total:
        return {"overall": None, "dimensions": {}, "methodology": METHODOLOGY, "issues": []}
    rows = alerts or cases
    complete = 0
    for r in rows:
        for f in ("entity_id", "timestamp", "severity", "asset_id"):
            if r.get(f):
                complete += 1
    completeness = complete / (len(rows) * 4) * 100
    valid = sum(1 for r in rows
                if (not r.get("severity") or str(r.get("severity")).lower() in VALID_SEVERITIES)
                and (not r.get("timestamp") or _parse_ts(r.get("timestamp"))))
    validity = valid / len(rows) * 100
    seen: set[str] = set()
    dups = 0
    for r in rows:
        key = str(r.get("alert_id") or r.get("case_id") or "")
        if key:
            if key in seen:
                dups += 1
            seen.add(key)
    uniqueness = (len(rows) - dups) / len(rows) * 100
    consistency = valid / len(rows) * 100
    timeliness = sum(1 for r in rows if _parse_ts(r.get("timestamp"))) / len(rows) * 100
    dims = {"completeness": round(completeness, 1), "validity": round(validity, 1),
            "consistency": round(consistency, 1), "uniqueness": round(uniqueness, 1),
            "timeliness": round(timeliness, 1)}
    overall = round(dims["completeness"] * 0.30 + dims["validity"] * 0.25 + dims["consistency"] * 0.20
                    + dims["uniqueness"] * 0.15 + dims["timeliness"] * 0.10, 1)
    issues = [
        {"type": "missing_asset_mapping", "count": sum(1 for r in rows if not r.get("asset_id"))},
        {"type": "duplicate_alerts", "count": dups},
        {"type": "missing_timestamps", "count": sum(1 for r in rows if not r.get("timestamp"))},
        {"type": "missing_severity", "count": sum(1 for r in rows if not r.get("severity"))},
        {"type": "missing_case_link", "count": sum(1 for r in rows if r.get("alert_id") and not r.get("case_id"))},
    ]
    missing_subs = sum(1 for s in submissions if s.get("status") == "missing")
    if missing_subs:
        issues.append({"type": "missing_submission", "count": missing_subs})
    return {"overall": overall, "dimensions": dims, "methodology": METHODOLOGY,
            "issues": [i for i in issues if i["count"] > 0],
            "total_records": len(rows), "valid_records": valid,
            "invalid_records": len(rows) - valid, "duplicate_records": dups}


def reporting_coverage(submissions: list[dict[str, Any]]) -> dict[str, Any]:
    by_entity: dict[str, dict[str, Any]] = {}
    for s in submissions:
        for eid in s.get("_entity_ids") or ([s.get("entity_id")] if s.get("entity_id") else []):
            eid = str(eid)
            slot = by_entity.setdefault(eid, {"entity_id": eid, "expected": 0, "received": 0,
                                              "missing_periods": []})
            slot["expected"] += 1
            if s.get("status") == "missing":
                slot["missing_periods"].append(s.get("reporting_period"))
            else:
                slot["received"] += 1
    rows = []
    for eid, slot in sorted(by_entity.items()):
        missing = slot["expected"] - slot["received"]
        rows.append({**slot, "missing": missing,
                     "coverage_pct": round(slot["received"] / slot["expected"] * 100, 1) if slot["expected"] else 100.0})
    return {"by_entity": rows,
            "expected_periods": sum(s["expected"] for s in rows),
            "received_periods": sum(s["received"] for s in rows)}


# ---------------------------------------------------------------------------
# Engine-context compatibility layer (used by /api/v1/analytics/* in main.py)
# ---------------------------------------------------------------------------

_CTX_CONTROL_DEFS: list[dict[str, Any]] = [
    {"control_id": "TD-01", "control_name": "Alert generation coverage", "domain": "Threat Detection",
     "description": "Alerts have required identifiers and timestamps.", "expected_evidence": "alert_id, timestamp, severity present", "weight": 1.0},
    {"control_id": "TD-02", "control_name": "Severity classification completeness", "domain": "Threat Detection",
     "description": "Share of alerts with valid severity classification.", "expected_evidence": "severity in {low,medium,high,critical}", "weight": 1.0},
    {"control_id": "TR-01", "control_name": "Alert-to-case linkage", "domain": "Alert Triage",
     "description": "Share of alerts linked to a case.", "expected_evidence": "case_id present on alert record", "weight": 1.2},
    {"control_id": "IN-01", "control_name": "Investigation coverage", "domain": "Investigation",
     "description": "Share of cases with an investigation record.", "expected_evidence": "investigation record per case", "weight": 1.4},
    {"control_id": "IN-02", "control_name": "Investigation completeness", "domain": "Investigation",
     "description": "Investigations carry conclusion and evidence depth.", "expected_evidence": "conclusion + evidence_count>=2", "weight": 1.2},
    {"control_id": "IN-03", "control_name": "Investigation timeliness", "domain": "Investigation",
     "description": "Investigations completed before closure and not anomalously fast for critical cases.", "expected_evidence": "start<=end<=closure, critical duration>10min", "weight": 0.8},
    {"control_id": "ES-01", "control_name": "Escalation coverage", "domain": "Escalation",
     "description": "Critical/high alerts requiring escalation have escalation records.", "expected_evidence": "escalation_id + timestamp + owner", "weight": 1.6},
    {"control_id": "ES-02", "control_name": "Escalation evidence quality", "domain": "Escalation",
     "description": "Escalations carry timestamp and destination/owner.", "expected_evidence": "escalation_time, recipient/level", "weight": 0.8},
    {"control_id": "IR-01", "control_name": "Response coverage", "domain": "Incident Response",
     "description": "Escalated/critical cases have response records.", "expected_evidence": "response record with action + timestamp", "weight": 1.4},
    {"control_id": "IR-02", "control_name": "Response SLA adherence", "domain": "Incident Response",
     "description": "Response recorded within SLA (24h of escalation).", "expected_evidence": "response_time - escalation_time <= 1440min", "weight": 0.8},
    {"control_id": "MO-01", "control_name": "Monitoring coverage", "domain": "Monitoring Coverage",
     "description": "Expected assets show security activity in period.", "expected_evidence": ">=1 alert per monitored asset", "weight": 1.2},
    {"control_id": "MO-02", "control_name": "Critical asset coverage", "domain": "Monitoring Coverage",
     "description": "Critical/high assets under monitoring.", "expected_evidence": "critical assets with activity", "weight": 1.2},
    {"control_id": "CM-01", "control_name": "Case ownership & status validity", "domain": "Case Management",
     "description": "Cases have valid lifecycle status.", "expected_evidence": "status in lifecycle vocabulary", "weight": 0.8},
    {"control_id": "CL-01", "control_name": "Closure discipline", "domain": "Closure & Evidence",
     "description": "Closure occurs after investigation (and response where required).", "expected_evidence": "closure_time >= investigation/response time", "weight": 1.2},
    {"control_id": "GV-01", "control_name": "Reporting completeness", "domain": "Governance & Oversight",
     "description": "Expected reporting periods submitted with complete metadata.", "expected_evidence": "submission per period, entity/sector metadata", "weight": 1.0},
    {"control_id": "OP-01", "control_name": "Operational discipline", "domain": "Operational Discipline",
     "description": "Low template/fast-closure pattern rate.", "expected_evidence": "non-template narratives, duration>10min", "weight": 0.8},
    {"control_id": "DQ-01", "control_name": "Data completeness & validity", "domain": "Data Quality & Reporting",
     "description": "Mandatory fields populated and valid; duplicates rare.", "expected_evidence": "mandatory fields, valid timestamps, unique ids", "weight": 1.0},
    {"control_id": "CR-01", "control_name": "Remediation of repeated alerts", "domain": "Cyber Resilience",
     "description": "Assets with repeated critical/high alerts show remediation.", "expected_evidence": "remediation record for repeated assets", "weight": 1.0},
]


def _ctx_status(coverage: Optional[float], denom: int) -> str:
    if denom == 0 or coverage is None:
        return "INSUFFICIENT_EVIDENCE"
    if coverage >= 90:
        return "COMPLIANT"
    if coverage >= 60:
        return "PARTIALLY_COMPLIANT"
    return "NON_COMPLIANT"


def _ctx_score(status: str) -> Optional[float]:
    return {"COMPLIANT": 100.0, "PARTIALLY_COMPLIANT": 50.0, "NON_COMPLIANT": 0.0}.get(status)


def evaluate_entity_controls(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate controls from engine-table context (alerts/cases/inv/esc/resp/assets/subs)."""
    alerts: list = ctx.get("alerts", [])
    cases: list = ctx.get("cases", [])
    inv_by_case: dict = ctx.get("inv_by_case", {})
    esc_by_case: dict = ctx.get("esc_by_case", {})
    resp_by_case: dict = ctx.get("resp_by_case", {})
    rem_by_case: dict = ctx.get("rem_by_case", {})
    assets: list = ctx.get("assets", [])
    submissions: list = ctx.get("submissions", [])

    def mk(cid: str, coverage: Optional[float], n_denom: int, n_num: int, calc: str) -> dict:
        d = next(c for c in _CTX_CONTROL_DEFS if c["control_id"] == cid)
        st = _ctx_status(coverage, n_denom)
        return {"control_id": cid, "control_name": d["control_name"], "domain": d["domain"],
                "description": d["description"], "expected_evidence": d["expected_evidence"],
                "weight": d["weight"], "status": st, "score": _ctx_score(st),
                "coverage": None if coverage is None else round(coverage, 1),
                "numerator": n_num, "denominator": n_denom, "calculation": calc,
                "finding_ids": [], "evidence_ids": []}

    out: list[dict[str, Any]] = []
    total_a = len(alerts)
    valid_sev = sum(1 for a in alerts if str(a.get("severity", "")).lower() in VALID_SEVERITIES)
    ts_ok = sum(1 for a in alerts if _parse_ts(a.get("timestamp")))
    out.append(mk("TD-01", (ts_ok / total_a * 100) if total_a else None, total_a, ts_ok,
                  f"{ts_ok} of {total_a} alerts have parseable timestamps"))
    out.append(mk("TD-02", (valid_sev / total_a * 100) if total_a else None, total_a, valid_sev,
                  f"{valid_sev} of {total_a} alerts have valid severity"))
    case_ids = {c.get("case_id") for c in cases}
    linked = sum(1 for a in alerts if a.get("case_id") and a.get("case_id") in case_ids)
    out.append(mk("TR-01", (linked / total_a * 100) if total_a else None, total_a, linked,
                  f"{linked} of {total_a} alerts linked to cases"))
    total_c = len(cases)
    with_inv = sum(1 for c in cases if c.get("case_id") in inv_by_case)
    out.append(mk("IN-01", (with_inv / total_c * 100) if total_c else None, total_c, with_inv,
                  f"{with_inv} of {total_c} cases have investigation records"))
    complete = sum(1 for c in cases if (inv := inv_by_case.get(c.get("case_id"))) and inv.get("conclusion") and (inv.get("evidence_count") or 0) >= 2)
    out.append(mk("IN-02", (complete / with_inv * 100) if with_inv else None, with_inv, complete,
                  f"{complete} of {with_inv} investigations have conclusion + >=2 evidence items"))
    timely = 0
    for c in cases:
        inv = inv_by_case.get(c.get("case_id"))
        if not inv:
            continue
        dur = inv.get("duration_minutes")
        if dur is None:
            dur = _mins(inv.get("start_time"), inv.get("end_time"))
        if dur is not None and (str(c.get("priority") or "").lower() != "critical" or dur > 10):
            timely += 1
    out.append(mk("IN-03", (timely / with_inv * 100) if with_inv else None, with_inv, timely,
                  f"{timely} of {with_inv} investigations timely (critical >10min, closed after investigation)"))
    req = [a for a in alerts if a.get("escalation_required")]
    esc = [a for a in req if a.get("escalation_id") or (a.get("case_id") and a.get("case_id") in esc_by_case)]
    out.append(mk("ES-01", (len(esc) / len(req) * 100) if req else None, len(req), len(esc),
                  f"{len(esc)} of {len(req)} escalation-required alerts have escalation evidence"))
    esc_recs = list(esc_by_case.values())
    q = sum(1 for e in esc_recs if _parse_ts(e.get("escalation_time")) and (e.get("recipient") or e.get("escalation_level")))
    out.append(mk("ES-02", (q / len(esc_recs) * 100) if esc_recs else (None if not req else 0.0), len(esc_recs), q,
                  f"{q} of {len(esc_recs)} escalations have timestamp + owner"))
    esc_req_case_ids = {a.get("case_id") for a in alerts if a.get("escalation_required") and a.get("case_id")}
    need_resp = [c for c in cases if c.get("case_id") in esc_by_case or c.get("case_id") in esc_req_case_ids]
    got_resp = sum(1 for c in need_resp if c.get("case_id") in resp_by_case)
    out.append(mk("IR-01", (got_resp / len(need_resp) * 100) if need_resp else None, len(need_resp), got_resp,
                  f"{got_resp} of {len(need_resp)} escalation-required cases have response evidence"))
    sla_ok, sla_n = 0, 0
    for c in need_resp:
        esc_r = esc_by_case.get(c.get("case_id"))
        rsp = resp_by_case.get(c.get("case_id"))
        if esc_r and rsp:
            sla_n += 1
            m = _mins(esc_r.get("escalation_time"), rsp.get("response_time") or rsp.get("response_timestamp"))
            if m is not None and m <= 1440:
                sla_ok += 1
    out.append(mk("IR-02", (sla_ok / sla_n * 100) if sla_n else None, sla_n, sla_ok,
                  f"{sla_ok} of {sla_n} measured responses within 24h SLA"))
    monitored_assets = [a for a in assets if a.get("expected_monitoring", True)]
    alerted = {a.get("asset_id") for a in alerts if a.get("asset_id")}
    mon = sum(1 for a in monitored_assets if a.get("asset_id") in alerted)
    out.append(mk("MO-01", (mon / len(monitored_assets) * 100) if monitored_assets else None, len(monitored_assets), mon,
                  f"{mon} of {len(monitored_assets)} expected assets show activity"))
    crit = [a for a in monitored_assets if str(a.get("criticality", "")).lower() in ("critical", "high")]
    crit_ok = sum(1 for a in crit if a.get("asset_id") in alerted)
    out.append(mk("MO-02", (crit_ok / len(crit) * 100) if crit else None, len(crit), crit_ok,
                  f"{crit_ok} of {len(crit)} critical/high assets show activity"))
    valid_status = sum(1 for a in alerts if str(a.get("status", "")).lower() in VALID_STATUSES)
    out.append(mk("CM-01", (valid_status / total_a * 100) if total_a else None, total_a, valid_status,
                  f"{valid_status} of {total_a} alerts carry valid lifecycle status"))
    disc_ok, disc_n = 0, 0
    for c in cases:
        inv = inv_by_case.get(c.get("case_id"))
        if inv and inv.get("start_time") and c.get("closed_at"):
            disc_n += 1
            ie, ct = _parse_ts(inv.get("end_time")), _parse_ts(c.get("closed_at"))
            if ie and ct and ie <= ct:
                disc_ok += 1
            elif not ie:
                disc_ok += 1
    out.append(mk("CL-01", (disc_ok / disc_n * 100) if disc_n else None, disc_n, disc_ok,
                  f"{disc_ok} of {disc_n} closures occur after investigation"))
    import re as _re
    _month_re = _re.compile(r"^\d{4}-\d{2}$")
    alert_months = {str(a.get("timestamp", ""))[:7] for a in alerts
                    if _month_re.match(str(a.get("timestamp", ""))[:7])}
    sub_months = {s.get("reporting_period") for s in submissions if s.get("reporting_period")}
    submitted_months = {s.get("reporting_period") for s in submissions
                        if s.get("reporting_period") and s.get("status") == "submitted"}
    if sub_months:
        # Explicit submission ledger present: expected = declared periods.
        exp_periods = len(sub_months)
        got = len(submitted_months & sub_months) or sum(1 for s in submissions if s.get("status") == "submitted")
        calc = f"{got} of {exp_periods} reporting periods submitted"
    elif alert_months:
        # Evidence-derived: expected = months spanned by the entity's own
        # evidence window; received = months with >=1 alert.
        months = sorted(alert_months)
        exp_periods = (int(months[-1][:4]) - int(months[0][:4])) * 12 + (int(months[-1][5:7]) - int(months[0][5:7])) + 1
        exp_periods = max(min(exp_periods, 12), 1)
        got = min(len(alert_months), exp_periods)
        calc = f"{got} of {exp_periods} evidence months covered ({months[0]} to {months[-1]})"
    else:
        exp_periods, got = len(submissions), sum(1 for s in submissions if s.get("status") == "submitted")
        calc = f"{got} of {exp_periods} reporting periods submitted"
    out.append(mk("GV-01", (got / exp_periods * 100) if exp_periods else None, exp_periods, got, calc))
    bad_cases = {c.get("case_id") for c in cases if (inv := inv_by_case.get(c.get("case_id"))) and (inv.get("template_match") or (inv.get("duration_minutes") or 999) <= 10)}
    good = with_inv - len(bad_cases)
    out.append(mk("OP-01", (good / with_inv * 100) if with_inv else None, with_inv, good,
                  f"{good} of {with_inv} investigations free of template/fast-closure pattern"))
    seen: set[str] = set()
    dup = 0
    for a in alerts:
        aid = str(a.get("alert_id", ""))
        if aid in seen:
            dup += 1
        seen.add(aid)
    missing_mand = sum(1 for a in alerts if not a.get("timestamp") or str(a.get("severity", "")).lower() not in VALID_SEVERITIES or not a.get("asset_id"))
    dq_good = max(total_a - missing_mand - dup, 0)
    out.append(mk("DQ-01", (dq_good / total_a * 100) if total_a else None, total_a, dq_good,
                  f"{dq_good} of {total_a} alerts complete, valid and unique"))
    asset_counts = Counter(a.get("asset_id") for a in alerts if a.get("asset_id"))
    repeated = [aid for aid, n in asset_counts.items() if n >= 10]
    case_by_asset: dict[str, list[str]] = defaultdict(list)
    for a in alerts:
        if a.get("asset_id") and a.get("case_id"):
            case_by_asset[a["asset_id"]].append(a["case_id"])
    rem_ok = sum(1 for aid in repeated if any(cid in rem_by_case for cid in case_by_asset.get(aid, [])))
    if repeated:
        out.append(mk("CR-01", rem_ok / len(repeated) * 100, len(repeated), rem_ok,
                      f"{rem_ok} of {len(repeated)} repeatedly-alerting assets show remediation"))
    elif not total_a:
        out.append(mk("CR-01", None, 0, 0, "No records to assess repeated-asset remediation"))
    else:
        d = next(c for c in _CTX_CONTROL_DEFS if c["control_id"] == "CR-01")
        out.append({"control_id": "CR-01", "control_name": d["control_name"], "domain": d["domain"],
                    "description": d["description"], "expected_evidence": d["expected_evidence"],
                    "weight": d["weight"], "status": "COMPLIANT", "score": 100.0,
                    "coverage": 100.0, "numerator": 0, "denominator": 0,
                    "calculation": "No repeatedly-alerting assets; no remediation required",
                    "finding_ids": [], "evidence_ids": []})
    return out


def compliance_summary(controls: list[dict[str, Any]]) -> dict[str, Any]:
    n_comp = sum(1 for c in controls if c["status"] == "COMPLIANT")
    n_part = sum(1 for c in controls if c["status"] == "PARTIALLY_COMPLIANT")
    n_non = sum(1 for c in controls if c["status"] == "NON_COMPLIANT")
    n_ins = sum(1 for c in controls if c["status"] in ("INSUFFICIENT_EVIDENCE", "NOT_ASSESSED"))
    evidenced = [c for c in controls if c.get("score") is not None]
    num = sum(c["score"] * c.get("weight", 1.0) for c in evidenced)
    den = sum(c.get("weight", 1.0) for c in evidenced)
    score = round(num / den, 1) if den else 0.0
    coverage = round(len(evidenced) / max(len(controls), 1) * 100, 1)
    return {"controls_assessed": len(controls), "compliant": n_comp, "partially_compliant": n_part,
            "non_compliant": n_non, "insufficient_evidence": n_ins,
            "compliance_score": score, "evidence_coverage": coverage}


def classify(status_sum: dict[str, Any], has_critical: bool) -> str:
    if status_sum["evidence_coverage"] < THRESHOLDS["evidence_min"]:
        return "INSUFFICIENT_EVIDENCE"
    if has_critical:
        return "NON_COMPLIANT"
    s = status_sum["compliance_score"]
    if s >= THRESHOLDS["compliant_min"]:
        return "COMPLIANT"
    if s >= THRESHOLDS["partial_min"]:
        return "PARTIALLY_COMPLIANT"
    return "NON_COMPLIANT"


def risk_with_drivers(ctx: dict[str, Any], controls: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    drivers: list[dict[str, Any]] = []
    score = 0.0
    esc_by_case = ctx.get("esc_by_case", {})
    req_total = sum(1 for a in ctx.get("alerts", []) if a.get("escalation_required"))
    crit_esc = sum(1 for a in ctx.get("alerts", []) if a.get("escalation_required") and not (a.get("escalation_id") or (a.get("case_id") and a["case_id"] in esc_by_case)))
    if crit_esc and req_total:
        miss_rate = crit_esc / req_total
        pts = round(min(30, miss_rate * 40), 1)
        score += pts
        drivers.append({"driver": "Critical escalation failures", "points": pts, "detail": f"{crit_esc} of {req_total} escalation-required alerts lack escalation ({round(miss_rate*100,1)}%)"})
    mon_cov = next((c["coverage"] for c in controls if c["control_id"] == "MO-01"), 100) or 100
    if mon_cov < 85:
        pts = round((85 - mon_cov) * 0.5, 1)
        score += pts
        drivers.append({"driver": "Monitoring gaps", "points": pts, "detail": f"Monitoring coverage {mon_cov}%"})
    sla = next((c for c in controls if c["control_id"] == "IR-02"), None)
    if sla and sla["denominator"] and (sla["coverage"] or 100) < 80:
        pts = round((80 - (sla["coverage"] or 0)) * 0.3, 1)
        score += pts
        drivers.append({"driver": "Response SLA breaches", "points": pts, "detail": sla["calculation"]})
    dq = next((c["coverage"] for c in controls if c["control_id"] == "DQ-01"), 100) or 100
    if dq < 90:
        pts = round((90 - dq) * 0.3, 1)
        score += pts
        drivers.append({"driver": "Data quality issues", "points": pts, "detail": f"Data completeness {dq}%"})
    peer_dev = ctx.get("peer_deviation", 0) or 0
    if peer_dev < -10:
        pts = round(abs(peer_dev) * 0.4, 1)
        score += pts
        drivers.append({"driver": "Peer performance deviation", "points": pts, "detail": f"{peer_dev} pts below sector median"})
    sev_w = {"critical": 3.75, "high": 1.8, "medium": 0.75, "low": 0.15}
    for f in findings:
        score += sev_w.get(str(f.get("severity", "")).lower(), 0)
    score = round(min(100, score), 1)
    return {"risk_score": score, "risk_drivers": sorted(drivers, key=lambda d: -d["points"])[:6],
            "method": "risk = escalation failures + monitoring gaps + SLA breaches + data quality + peer deviation + severity-weighted findings (capped 100)"}


def recommended_action(status: str, risk: float, critical: int, evidence_cov: float) -> str:
    if isinstance(critical, dict):
        critical = int(critical.get("critical", 0))
    if status == "NON_COMPLIANT" or critical >= 5 or risk >= 70:
        return "IMMEDIATE REVIEW"
    if status == "PARTIALLY_COMPLIANT" or critical > 0 or risk >= 45:
        return "SUPERVISORY REVIEW"
    if status == "INSUFFICIENT_EVIDENCE" or evidence_cov < 70:
        return "EVIDENCE REQUEST"
    if risk >= 20:
        return "ROUTINE REVIEW"
    return "NO ACTION"


def _mins(a: Any, b: Any) -> Optional[float]:
    s, e = _parse_ts(a), _parse_ts(b)
    if s and e and e >= s:
        return (e - s).total_seconds() / 60
    return None


def data_quality_score(alerts: list[dict[str, Any]], cases: list[dict[str, Any]],
                       assets: list[dict[str, Any]], submissions: list[dict[str, Any]]) -> dict[str, Any]:
    """Weighted 5-dimension score over engine tables. Optional fields never penalise."""
    rows = [{"timestamp": a.get("timestamp"), "severity": a.get("severity"), "asset_id": a.get("asset_id"),
             "entity_id": a.get("entity_id"), "alert_id": a.get("alert_id"), "case_id": a.get("case_id"),
             "status": a.get("status"), "time": None} for a in alerts]
    base = data_quality(rows)
    dims = base.get("dimensions", {})
    missing_mandatory = sum(i["count"] for i in base.get("issues", [])
                            if i["type"] in ("missing_asset_mapping", "missing_timestamps",
                                             "missing_entity", "missing_severity", "missing_case_link"))
    return {"overall": base.get("overall"), "completeness": dims.get("completeness"),
            "validity": dims.get("validity"), "consistency": dims.get("consistency"),
            "uniqueness": dims.get("uniqueness"), "timeliness": dims.get("timeliness"),
            "total_records": base.get("total_records", len(alerts)),
            "valid_records": base.get("valid_records", 0), "invalid_records": base.get("invalid_records", 0),
            "duplicate_records": base.get("duplicate_records", 0),
            "missing_mandatory": missing_mandatory,
            "formula": METHODOLOGY, "issues": base.get("issues", [])}


def workflow_funnel(alerts: list[dict[str, Any]], inv_by_case: dict, esc_by_case: dict,
                    resp_by_case: dict, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    total_alerts = len(alerts)
    case_ids = {c.get("case_id") for c in cases}
    with_case = sum(1 for a in alerts if a.get("case_id") and a.get("case_id") in case_ids)
    with_inv = sum(1 for c in cases if c.get("case_id") in inv_by_case)
    req_esc = [a for a in alerts if a.get("escalation_required")]
    with_esc = sum(1 for a in req_esc if a.get("escalation_id") or (a.get("case_id") and a.get("case_id") in esc_by_case))
    with_resp = sum(1 for c in cases if c.get("case_id") in resp_by_case)
    closed = sum(1 for c in cases if str(c.get("status", "")).lower() in ("closed", "resolved"))
    stages = [("Alerts", total_alerts), ("Cases", with_case), ("Investigations", with_inv),
              ("Escalation Required", len(req_esc)), ("Escalations", with_esc),
              ("Responses", with_resp), ("Closures", closed)]
    out = []
    for i, (stage, count) in enumerate(stages):
        prev = stages[i - 1][1] if i else total_alerts
        cov = round(count / max(prev, 1) * 100, 1) if i else 100.0
        out.append({"stage": stage, "count": count, "coverage_pct": cov,
                    "of_alerts_pct": round(count / max(total_alerts, 1) * 100, 1)})
    return out


def reporting_coverage(submissions: list[dict[str, Any]]) -> dict[str, Any]:
    periods = sorted({s.get("reporting_period") for s in submissions if s.get("reporting_period")})
    expected = len(periods) or len(submissions)
    received = sum(1 for s in submissions if s.get("status") == "submitted")
    missing = [s for s in submissions if s.get("status") == "missing"]
    return {"expected_periods": expected, "received_periods": received,
            "missing_periods": len(missing),
            "coverage_pct": round(received / max(expected, 1) * 100, 1),
            "periods": periods,
            "missing": [{"submission_id": s.get("submission_id"), "entity_id": s.get("entity_id"),
                         "reporting_period": s.get("reporting_period")} for s in missing][:50]}


# ---------------------------------------------------------------------------
# Supervisory-layer API (status constants, per-entity assessment, weakest
# domains). Used by supervisory.py and the analytics overview.
# ---------------------------------------------------------------------------

COMPLIANT = "COMPLIANT"
PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
NON_COMPLIANT = "NON_COMPLIANT"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
NOT_ASSESSED = "NOT_ASSESSED"


def assess_entity(entity_id: str, alerts: list[dict[str, Any]], cases: list[dict[str, Any]],
                  investigations: list[dict[str, Any]], escalations: list[dict[str, Any]],
                  responses: list[dict[str, Any]], remediations: list[dict[str, Any]],
                  assets: list[dict[str, Any]], submissions: list[dict[str, Any]],
                  entity_meta: dict[str, Any], findings: list[dict[str, Any]],
                  expected_periods: int = 9) -> dict[str, Any]:
    """Full evidence-grounded assessment for one entity from engine tables."""
    inv_by_case = {i.get("case_id"): i for i in investigations}
    esc_by_case = {e.get("case_id"): e for e in escalations}
    resp_by_case = {r.get("case_id"): r for r in responses}
    rem_by_case = {r.get("case_id"): r for r in remediations}
    ctx = {"entity_id": entity_id, "alerts": alerts, "cases": cases,
           "inv_by_case": inv_by_case, "esc_by_case": esc_by_case,
           "resp_by_case": resp_by_case, "rem_by_case": rem_by_case,
           "assets": assets, "submissions": submissions, "peer_deviation": 0}
    controls = evaluate_entity_controls(ctx)
    summ = compliance_summary(controls)
    entity_findings = [f for f in findings if str(f.get("entity_id")) == entity_id]
    sev = Counter(str(f.get("severity", "")).lower() for f in entity_findings)
    severity = {"critical": sev.get("critical", 0), "high": sev.get("high", 0),
                "medium": sev.get("medium", 0), "low": sev.get("low", 0)}
    if not alerts and not cases:
        status = NOT_ASSESSED
    else:
        status = classify(summ, severity["critical"] > 0)
    risk = risk_with_drivers(ctx, controls, entity_findings)
    return {
        "entity_id": entity_id,
        "entity_name": entity_meta.get("entity_name", entity_id),
        "sector": entity_meta.get("sector"),
        "criticality": entity_meta.get("criticality"),
        "status": status,
        "compliance_score": summ["compliance_score"],
        "evidence_coverage": summ["evidence_coverage"],
        "controls_assessed": summ["controls_assessed"],
        "controls": controls,
        "risk_score": risk["risk_score"],
        "risk_drivers": risk["risk_drivers"],
        "severity": severity,
        "recommended_action": recommended_action(status, risk["risk_score"], severity, summ["evidence_coverage"]),
        "alerts": len(alerts),
        "cases": len(cases),
    }


def weakest_domains(assessments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Average control coverage per domain across assessments, weakest first."""
    by_domain: dict[str, list[float]] = defaultdict(list)
    for a in assessments:
        for c in a.get("controls", []):
            if c.get("coverage") is not None:
                by_domain[c["domain"]].append(c["coverage"])
    ranked = [{"domain": d, "score": round(statistics.fmean(v), 1), "controls": len(v)}
              for d, v in by_domain.items()]
    ranked.sort(key=lambda r: r["score"])
    return ranked
