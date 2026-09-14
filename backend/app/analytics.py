"""SAT-SA Supervisory Analytics Engine.

Computes all operational metrics, capability scores, execution-gap signals,
negative-space signals, peer benchmarks, and trend analysis from the
relational synthetic dataset.

Every metric is deterministic, explainable, and traceable to source data.
"""
from __future__ import annotations

import math
import random
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from .taxonomy import SUPERVISORY_CONTROLS, SUPERVISORY_STATUSES
from .rowmap import escalation_required as _row_escalation_required
from .rowmap import is_escalated as _row_is_escalated
from .rowmap import is_investigated as _row_is_investigated
from .rowmap import is_responded as _row_is_responded


# ---------------------------------------------------------------------------
# Supervisory Control Framework
# ---------------------------------------------------------------------------

CONTROLS = SUPERVISORY_CONTROLS

CAPABILITY_DIMENSIONS = [
    "Threat Detection",
    "Investigation",
    "Escalation",
    "Incident Response",
    "Security Operations",
    "Governance & Oversight",
    "Operational Discipline",
    "Cyber Resilience",
]


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except (ValueError, TypeError):
        return None


def _minutes_between(start: Any, end: Any) -> Optional[float]:
    s, e = _parse_ts(start), _parse_ts(end)
    if s and e and e >= s:
        return (e - s).total_seconds() / 60
    return None


def _month_key(ts_str: Any) -> Optional[str]:
    dt = _parse_ts(ts_str)
    if dt:
        return dt.strftime("%Y-%m")
    return None


# ---------------------------------------------------------------------------
# Analytics computation from relational tables
# ---------------------------------------------------------------------------

class SupervisoryAnalytics:
    """Computes all SAT-SA analytics from the relational dataset tables."""

    def __init__(self, tables: dict[str, list[dict[str, Any]]]):
        tables = self._adapt_current_store(tables)
        self.entities = {e["entity_id"]: e for e in tables.get("entities", [])}
        self.assets = tables.get("assets", [])
        self.alerts = tables.get("alerts", [])
        self.cases = tables.get("cases", [])
        self.investigations = tables.get("investigations", [])
        self.escalations = tables.get("escalations", [])
        self.responses = tables.get("responses", [])
        self.remediations = tables.get("remediations", [])
        self.submissions = tables.get("submissions", [])

        # Build indexes
        self._alerts_by_entity: dict[str, list] = defaultdict(list)
        for a in self.alerts:
            self._alerts_by_entity[a["entity_id"]].append(a)

        self._cases_by_entity: dict[str, list] = defaultdict(list)
        self._cases_by_id: dict[str, dict] = {}
        for c in self.cases:
            self._cases_by_entity[c["entity_id"]].append(c)
            self._cases_by_id[c["case_id"]] = c

        self._inv_by_case: dict[str, dict] = {}
        for i in self.investigations:
            self._inv_by_case[i["case_id"]] = i

        self._esc_by_case: dict[str, dict] = {}
        for e in self.escalations:
            self._esc_by_case[e["case_id"]] = e

        self._resp_by_case: dict[str, dict] = {}
        for r in self.responses:
            self._resp_by_case[r["case_id"]] = r

        self._rem_by_case: dict[str, dict] = {}
        for r in self.remediations:
            self._rem_by_case[r["case_id"]] = r

        self._assets_by_entity: dict[str, list] = defaultdict(list)
        for a in self.assets:
            self._assets_by_entity[a["entity_id"]].append(a)

        self._subs_by_entity: dict[str, list] = defaultdict(list)
        for s in self.submissions:
            entity_ids = s.get("_entity_ids") or ([s.get("entity_id")] if s.get("entity_id") else [])
            for eid in entity_ids:
                self._subs_by_entity[str(eid)].append(s)

    @staticmethod
    def _adapt_current_store(tables: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
        """Adapt Phase 1 submissions/assessments to the Phase 2 table view.

        The generator's relational tables remain supported.  This adapter is
        deliberately conservative: it only derives an event when the uploaded
        record contains the corresponding identifier/boolean, and never
        invents evidence for missing fields.
        """
        if any(tables.get(name) for name in ("alerts", "cases", "assets", "investigations")):
            return tables
        submissions = list(tables.get("submissions", []) or [])
        # Callers may pass the in-memory Phase 1 store's flat records rather
        # than wrapping them in a submission object.
        if tables.get("records"):
            submissions.append({"id": "records", "records": tables["records"]})
        for item in submissions:
            if isinstance(item.get("payload"), str) and not item.get("records"):
                try:
                    payload = __import__("json").loads(item["payload"])
                    if isinstance(payload, dict):
                        item.update(payload)
                except (TypeError, ValueError):
                    pass
        entities: dict[str, dict[str, Any]] = {}
        assets: dict[str, dict[str, Any]] = {}
        alerts: list[dict[str, Any]] = []
        cases: dict[str, dict[str, Any]] = {}
        investigations: list[dict[str, Any]] = []
        escalations: list[dict[str, Any]] = []
        responses: list[dict[str, Any]] = []
        remediations: list[dict[str, Any]] = []
        for submission in submissions:
            rows = submission.get("records", [])
            if not isinstance(rows, list):
                continue
            sid = str(submission.get("id", "submission"))
            submission_entities = sorted({
                str(r.get("entity_id") or r.get("entity") or r.get("user") or r.get("host"))
                for r in rows if isinstance(r, dict) and (
                    r.get("entity_id") or r.get("entity") or r.get("user") or r.get("host")
                )
            })
            if len(submission_entities) == 1:
                submission["entity_id"] = submission_entities[0]
            for index, raw in enumerate(rows, 1):
                row = dict(raw) if isinstance(raw, dict) else {}
                eid = str(row.get("entity_id") or row.get("entity") or row.get("user")
                          or row.get("host") or "").strip()
                if not eid:
                    continue
                entities.setdefault(eid, {
                    "entity_id": eid,
                    "entity_name": str(row.get("entity_name") or row.get("name") or eid),
                    "sector": row.get("sector") or row.get("entity_sector"),
                    "criticality": row.get("criticality") or row.get("asset_criticality"),
                })
                timestamp = row.get("timestamp") or row.get("time")
                aid = row.get("alert_id")
                asset_id = row.get("asset_id")
                if asset_id:
                    asset_id = str(asset_id)
                    assets.setdefault(asset_id, {
                        "asset_id": asset_id, "entity_id": eid,
                        "criticality": row.get("asset_criticality") or row.get("criticality"),
                        "expected_monitoring": row.get("expected_monitoring", True),
                    })
                if aid or str(row.get("type", "")).lower() == "alert":
                    alerts.append({**row, "alert_id": str(aid or f"{sid}:row:{index}"),
                                   "entity_id": eid, "asset_id": asset_id,
                                   "timestamp": timestamp,
                                   # Preserve missing classifications so data-quality
                                   # metrics do not turn absent evidence into a
                                   # fabricated medium-severity alert.
                                   "severity": str(row.get("severity") or "").lower(),
                                   "escalation_required": _row_escalation_required(row),
                                   "escalation_id": row.get("escalation_id") if _row_is_escalated(row) else None,
                                   "case_id": row.get("case_id")})
                cid = row.get("case_id")
                if cid:
                    cid = str(cid)
                    cases.setdefault(cid, {**row, "case_id": cid, "entity_id": eid,
                                           "created_at": timestamp, "priority": str(
                                               row.get("priority") or row.get("severity") or "medium").lower()})
                    cases[cid]["closed_at"] = row.get("closure_timestamp") or row.get("closed_at") or row.get("closure_time") or cases[cid].get("closed_at")
                    if not cases[cid].get("closure_reason"):
                        cases[cid]["closure_reason"] = row.get("closure_reason") or row.get("evidence_type")
                    if _row_is_investigated(row):
                        ev_count = row.get("evidence_count")
                        if not isinstance(ev_count, (int, float)):
                            if isinstance(row.get("evidence"), list):
                                ev_count = len(row.get("evidence", []))
                            elif str(row.get("evidence_present", "")).lower() in ("true", "1", "yes"):
                                ev_count = 2
                            elif row.get("evidence"):
                                ev_count = 1
                            else:
                                ev_count = 0
                        investigation = {**row, "case_id": cid,
                                         "conclusion": row.get("investigation_conclusion") or row.get("conclusion"),
                                         "end_time": row.get("investigation_completed") or row.get("investigation_time") or row.get("end_time"),
                                         "start_time": row.get("investigation_started") or row.get("start_time"),
                                         "analyst_id": row.get("analyst_id") or row.get("analyst"),
                                         "evidence_count": ev_count,
                                         "template_match": row.get("template_match", False)}
                        duration = row.get("investigation_minutes") or row.get("duration_minutes")
                        if duration is not None:
                            investigation["duration_minutes"] = duration
                        investigations.append(investigation)
                    if _row_is_escalated(row):
                        escalations.append({**row, "case_id": cid,
                                            "escalation_time": row.get("escalation_timestamp") or row.get("escalation_time") or timestamp,
                                            "recipient": row.get("recipient") or row.get("escalation_owner"),
                                            "acknowledged": bool(row.get("acknowledged") or row.get("escalation_id"))})
                    if _row_is_responded(row):
                        responses.append({**row, "case_id": cid,
                                          "response_time": row.get("response_timestamp") or row.get("responded_at") or row.get("response_at")})
                    if row.get("remediation_id") or row.get("root_cause"):
                        remediations.append({**row, "case_id": cid,
                                             "remediation_id": row.get("remediation_id") or f"{cid}-REM",
                                             "asset_id": row.get("asset_id"),
                                             "root_cause": row.get("root_cause"),
                                             "action": row.get("remediation_action"),
                                             "status": "completed"})
            # Preserve the source submission in the normalized view while
            # making its entity association explicit for completeness metrics.
            submission["_entity_ids"] = submission_entities
        derived = dict(tables)
        derived.update({
            "entities": sorted(entities.values(), key=lambda x: x["entity_id"]),
            "assets": sorted(assets.values(), key=lambda x: x["asset_id"]),
            "alerts": alerts,
            "cases": sorted(cases.values(), key=lambda x: x["case_id"]),
            "investigations": investigations,
            "escalations": escalations,
            "responses": responses,
            "remediations": list(tables.get("remediations", []) or []) + remediations,
        })
        return derived

    # -----------------------------------------------------------------------
    # OVERVIEW METRICS
    # -----------------------------------------------------------------------

    def overview(self) -> dict[str, Any]:
        total_alerts = len(self.alerts)
        total_cases = len(self.cases)
        critical_alerts = sum(1 for a in self.alerts if a["severity"] == "critical")
        high_alerts = sum(1 for a in self.alerts if a["severity"] == "high")
        total_investigations = len(self.investigations)
        total_escalations = len(self.escalations)
        total_responses = len(self.responses)

        exec_gaps = self.all_execution_gaps()
        neg_space = self.all_negative_space()

        entity_scores = self.all_entity_risk_scores()
        high_attention = sum(1 for e in entity_scores if e["risk_level"] in ("HIGH", "CRITICAL"))
        entity_capabilities = self.capability_scores()
        capability_scores = []
        for name in CAPABILITY_DIMENSIONS:
            values = [
                details[name]["score"]
                for details in entity_capabilities.values()
                if name in details
            ]
            if values:
                capability_scores.append({"name": name, "score": round(statistics.fmean(values), 1)})

        # Data completeness
        submitted = sum(1 for s in self.submissions if s.get("status") == "submitted")
        total_expected = len(self.submissions)
        completeness = round(submitted / max(total_expected, 1) * 100, 1)

        return {
            "assessment_period": "January 2026 – September 2026",
            "dataset_label": "Synthetic Demonstration Dataset",
            "status": "Ready for supervisory review",
            "entities_assessed": len(self.entities),
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_alerts": high_alerts,
            "cases_analysed": total_cases,
            "investigations": total_investigations,
            "escalations": total_escalations,
            "responses": total_responses,
            "execution_gap_signals": len(exec_gaps),
            "negative_space_signals": len(neg_space),
            "high_attention_entities": high_attention,
            "data_completeness": completeness,
            "total_assets": len(self.assets),
            "capabilities": capability_scores,
        }

    # -----------------------------------------------------------------------
    # ALERT ANALYTICS
    # -----------------------------------------------------------------------

    def alert_analytics(self, entity_id: str | None = None,
                        severity: str | None = None) -> dict[str, Any]:
        alerts = self._alerts_by_entity.get(entity_id, []) if entity_id else self.alerts
        if severity:
            alerts = [alert for alert in alerts if str(alert.get("severity", "")).lower() == severity.lower()]

        total = len(alerts)
        by_severity = Counter(a["severity"] for a in alerts)
        by_category = Counter(a.get("category", "unknown") for a in alerts)
        by_source = Counter(a.get("source", "unknown") for a in alerts)
        by_month: dict[str, int] = Counter()
        severity_by_month: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for a in alerts:
            mk = _month_key(a.get("timestamp"))
            if mk:
                by_month[mk] += 1
                severity_by_month[mk][a["severity"]] += 1

        # Acknowledgement times
        ack_times = []
        for a in alerts:
            mins = _minutes_between(a.get("timestamp"), a.get("acknowledged_at"))
            if mins is not None:
                ack_times.append(mins)

        # By entity
        by_entity = {}
        for eid in self.entities:
            ea = self._alerts_by_entity.get(eid, [])
            by_entity[eid] = {
                "total": len(ea),
                "critical": sum(1 for x in ea if x["severity"] == "critical"),
                "high": sum(1 for x in ea if x["severity"] == "high"),
            }

        # By asset (top 20)
        by_asset = Counter(a.get("asset_id") for a in alerts if a.get("asset_id"))
        top_assets = by_asset.most_common(20)

        critical_pct = round(by_severity.get("critical", 0) / max(total, 1) * 100, 1)
        high_pct = round(by_severity.get("high", 0) / max(total, 1) * 100, 1)

        return {
            "total": total,
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
            "by_source": dict(by_source),
            "by_month": dict(sorted(by_month.items())),
            "severity_by_month": {k: dict(v) for k, v in sorted(severity_by_month.items())},
            "by_entity": by_entity,
            "top_assets": [{"asset_id": a, "count": c} for a, c in top_assets],
            "critical_alert_pct": critical_pct,
            "high_alert_pct": high_pct,
            "ack_time_mean": round(statistics.mean(ack_times), 1) if ack_times else None,
            "ack_time_median": round(statistics.median(ack_times), 1) if ack_times else None,
        }

    # -----------------------------------------------------------------------
    # INVESTIGATION ANALYTICS
    # -----------------------------------------------------------------------

    def investigation_analytics(self, entity_id: str | None = None) -> dict[str, Any]:
        if entity_id:
            cases = self._cases_by_entity.get(entity_id, [])
        else:
            cases = self.cases

        total_cases = len(cases)
        cases_with_inv = sum(1 for c in cases if c["case_id"] in self._inv_by_case)
        coverage = round(cases_with_inv / max(total_cases, 1) * 100, 1)

        durations = []
        evidence_counts = []
        has_conclusion = 0
        template_count = 0
        analyst_workload: dict[str, int] = Counter()

        for c in cases:
            inv = self._inv_by_case.get(c["case_id"])
            if inv:
                if inv.get("duration_minutes"):
                    durations.append(inv["duration_minutes"])
                if inv.get("evidence_count") is not None:
                    evidence_counts.append(inv["evidence_count"])
                if inv.get("conclusion"):
                    has_conclusion += 1
                if inv.get("template_match"):
                    template_count += 1
                analyst_workload[inv.get("analyst_id", "unknown")] += 1

        fast_threshold = 10  # minutes
        very_fast = sum(1 for d in durations if d <= fast_threshold)
        fast_rate = round(very_fast / max(len(durations), 1) * 100, 1)

        conclusion_coverage = round(has_conclusion / max(cases_with_inv, 1) * 100, 1)
        template_rate = round(template_count / max(cases_with_inv, 1) * 100, 1)

        evidence_completeness = round(
            sum(1 for e in evidence_counts if e >= 2) / max(len(evidence_counts), 1) * 100, 1
        )

        # Duration distribution buckets
        duration_buckets = {"0-5": 0, "5-15": 0, "15-30": 0, "30-60": 0, "60-120": 0, "120-240": 0, "240+": 0}
        for d in durations:
            if d <= 5:
                duration_buckets["0-5"] += 1
            elif d <= 15:
                duration_buckets["5-15"] += 1
            elif d <= 30:
                duration_buckets["15-30"] += 1
            elif d <= 60:
                duration_buckets["30-60"] += 1
            elif d <= 120:
                duration_buckets["60-120"] += 1
            elif d <= 240:
                duration_buckets["120-240"] += 1
            else:
                duration_buckets["240+"] += 1

        # By entity
        by_entity = {}
        for eid in self.entities:
            ec = self._cases_by_entity.get(eid, [])
            ec_with_inv = sum(1 for c in ec if c["case_id"] in self._inv_by_case)
            eid_durations = [self._inv_by_case[c["case_id"]]["duration_minutes"]
                            for c in ec if c["case_id"] in self._inv_by_case
                            and self._inv_by_case[c["case_id"]].get("duration_minutes")]
            by_entity[eid] = {
                "coverage": round(ec_with_inv / max(len(ec), 1) * 100, 1),
                "median_duration": round(statistics.median(eid_durations), 1) if eid_durations else None,
                "fast_rate": round(sum(1 for d in eid_durations if d <= fast_threshold) / max(len(eid_durations), 1) * 100, 1),
            }

        # Monthly trend
        inv_by_month: dict[str, dict[str, Any]] = {}
        for c in cases:
            mk = _month_key(c.get("created_at"))
            if mk:
                bucket = inv_by_month.setdefault(mk, {"total": 0, "investigated": 0})
                bucket["total"] += 1
                if c["case_id"] in self._inv_by_case:
                    bucket["investigated"] += 1
        for mk, bucket in inv_by_month.items():
            bucket["coverage"] = round(bucket["investigated"] / max(bucket["total"], 1) * 100, 1)

        return {
            "total_cases": total_cases,
            "cases_with_investigation": cases_with_inv,
            "investigation_coverage": coverage,
            "duration_median": round(statistics.median(durations), 1) if durations else None,
            "duration_mean": round(statistics.mean(durations), 1) if durations else None,
            "fast_investigation_rate": fast_rate,
            "conclusion_coverage": conclusion_coverage,
            "evidence_completeness": evidence_completeness,
            "template_rate": template_rate,
            "duration_distribution": duration_buckets,
            "by_entity": by_entity,
            "by_month": dict(sorted(inv_by_month.items())),
            "analyst_workload": dict(analyst_workload.most_common(20)),
        }

    # -----------------------------------------------------------------------
    # ESCALATION ANALYTICS
    # -----------------------------------------------------------------------

    def escalation_analytics(self, entity_id: str | None = None) -> dict[str, Any]:
        if entity_id:
            alerts = self._alerts_by_entity.get(entity_id, [])
            cases = self._cases_by_entity.get(entity_id, [])
        else:
            alerts = self.alerts
            cases = self.cases

        requiring_escalation = [a for a in alerts if a.get("escalation_required")]
        escalated = [a for a in requiring_escalation if a.get("escalation_id")]

        total_requiring = len(requiring_escalation)
        total_escalated = len(escalated)
        escalation_rate = round(total_escalated / max(total_requiring, 1) * 100, 1)

        # By severity
        by_severity: dict[str, dict[str, int]] = {}
        for sev in ("critical", "high", "medium", "low"):
            req = [a for a in requiring_escalation if a["severity"] == sev]
            esc = [a for a in req if a.get("escalation_id")]
            by_severity[sev] = {
                "requiring": len(req),
                "escalated": len(esc),
                "rate": round(len(esc) / max(len(req), 1) * 100, 1),
            }

        # Escalation latency
        latencies = []
        acknowledged_count = 0
        for esc in self.escalations:
            if entity_id and self._cases_by_id.get(esc["case_id"], {}).get("entity_id") != entity_id:
                continue
            case = self._cases_by_id.get(esc["case_id"])
            if case:
                mins = _minutes_between(case.get("created_at"), esc.get("escalation_time"))
                if mins is not None:
                    latencies.append(mins)
            if esc.get("acknowledged"):
                acknowledged_count += 1

        # Escalation to response
        esc_cases = set()
        resp_cases = set()
        relevant_escs = self.escalations
        if entity_id:
            relevant_escs = [e for e in self.escalations
                           if self._cases_by_id.get(e["case_id"], {}).get("entity_id") == entity_id]
        for esc in relevant_escs:
            esc_cases.add(esc["case_id"])
        for resp in self.responses:
            if entity_id and self._cases_by_id.get(resp["case_id"], {}).get("entity_id") != entity_id:
                continue
            if resp["case_id"] in esc_cases:
                resp_cases.add(resp["case_id"])

        esc_to_resp_rate = round(len(resp_cases) / max(len(esc_cases), 1) * 100, 1)

        # By entity
        by_entity = {}
        for eid in self.entities:
            ea = self._alerts_by_entity.get(eid, [])
            req = [a for a in ea if a.get("escalation_required")]
            esc = [a for a in req if a.get("escalation_id")]
            by_entity[eid] = {
                "requiring": len(req),
                "escalated": len(esc),
                "rate": round(len(esc) / max(len(req), 1) * 100, 1),
            }

        # Funnel for critical alerts
        critical_alerts = [a for a in alerts if a["severity"] == "critical"]
        critical_investigated = [a for a in critical_alerts if a.get("case_id") and a["case_id"] in self._inv_by_case]
        critical_esc_required = [a for a in critical_alerts if a.get("escalation_required")]
        critical_escalated = [a for a in critical_esc_required if a.get("escalation_id")]
        critical_responded = [a for a in critical_escalated
                             if a.get("case_id") and a["case_id"] in self._resp_by_case]

        funnel = [
            {"stage": "Critical Alerts", "count": len(critical_alerts)},
            {"stage": "Investigated", "count": len(critical_investigated)},
            {"stage": "Escalation Required", "count": len(critical_esc_required)},
            {"stage": "Escalated", "count": len(critical_escalated)},
            {"stage": "Response Recorded", "count": len(critical_responded)},
        ]

        return {
            "requiring_escalation": total_requiring,
            "escalated": total_escalated,
            "escalation_rate": escalation_rate,
            "by_severity": by_severity,
            "latency_median": round(statistics.median(latencies), 1) if latencies else None,
            "latency_mean": round(statistics.mean(latencies), 1) if latencies else None,
            "acknowledged_rate": round(acknowledged_count / max(len(relevant_escs), 1) * 100, 1),
            "escalation_to_response_rate": esc_to_resp_rate,
            "by_entity": by_entity,
            "critical_alert_funnel": funnel,
        }

    # -----------------------------------------------------------------------
    # MONITORING / NEGATIVE SPACE ANALYTICS
    # -----------------------------------------------------------------------

    def monitoring_analytics(self, entity_id: str | None = None) -> dict[str, Any]:
        if entity_id:
            entity_assets = self._assets_by_entity.get(entity_id, [])
            entity_alerts = self._alerts_by_entity.get(entity_id, [])
        else:
            entity_assets = self.assets
            entity_alerts = self.alerts

        total_assets = len(entity_assets)
        expected_monitored = sum(1 for a in entity_assets if a.get("expected_monitoring", True))

        # Assets with at least one alert
        alerted_assets = set(a.get("asset_id") for a in entity_alerts if a.get("asset_id"))
        assets_with_activity = sum(1 for a in entity_assets if a["asset_id"] in alerted_assets)

        critical_assets = [a for a in entity_assets if a.get("criticality") in ("critical", "high")]
        critical_with_activity = sum(1 for a in critical_assets if a["asset_id"] in alerted_assets)

        coverage = round(assets_with_activity / max(expected_monitored, 1) * 100, 1)
        critical_coverage = round(critical_with_activity / max(len(critical_assets), 1) * 100, 1)

        zero_activity_assets = [a for a in entity_assets if a["asset_id"] not in alerted_assets]

        # Missing submissions
        missing_subs = []
        for s in self.submissions:
            if entity_id and entity_id not in (s.get("_entity_ids") or [s.get("entity_id")]):
                continue
            if s.get("status") == "missing":
                missing_subs.append(s)

        # By entity
        by_entity = {}
        for eid in self.entities:
            ea = self._assets_by_entity.get(eid, [])
            ea_alerts = set(a.get("asset_id") for a in self._alerts_by_entity.get(eid, []) if a.get("asset_id"))
            ea_monitored = sum(1 for a in ea if a.get("expected_monitoring", True))
            ea_with_act = sum(1 for a in ea if a["asset_id"] in ea_alerts)
            ea_critical = [a for a in ea if a.get("criticality") in ("critical", "high")]
            ea_crit_act = sum(1 for a in ea_critical if a["asset_id"] in ea_alerts)
            by_entity[eid] = {
                "total_assets": len(ea),
                "expected_monitored": ea_monitored,
                "with_activity": ea_with_act,
                "coverage": round(ea_with_act / max(ea_monitored, 1) * 100, 1),
                "critical_assets": len(ea_critical),
                "critical_coverage": round(ea_crit_act / max(len(ea_critical), 1) * 100, 1),
                "zero_activity": len(ea) - ea_with_act,
            }

        return {
            "total_assets": total_assets,
            "expected_monitored": expected_monitored,
            "assets_with_activity": assets_with_activity,
            "coverage": coverage,
            "critical_assets": len(critical_assets),
            "critical_coverage": critical_coverage,
            "zero_activity_count": len(zero_activity_assets),
            "zero_activity_assets": [{"asset_id": a["asset_id"], "asset_type": a.get("asset_type"),
                                      "criticality": a.get("criticality"), "entity_id": a.get("entity_id")}
                                    for a in zero_activity_assets[:50]],
            "missing_submissions": missing_subs,
            "by_entity": by_entity,
        }

    # -----------------------------------------------------------------------
    # EXECUTION GAP SIGNALS
    # -----------------------------------------------------------------------

    def all_execution_gaps(self) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []

        for eid, entity in self.entities.items():
            alerts = self._alerts_by_entity.get(eid, [])
            cases = self._cases_by_entity.get(eid, [])

            # 1. Critical alerts closed unusually quickly
            critical_fast = []
            for c in cases:
                if c.get("priority") == "critical":
                    inv = self._inv_by_case.get(c["case_id"])
                    if inv and inv.get("duration_minutes", 999) <= 10:
                        critical_fast.append(c["case_id"])
            if critical_fast:
                signals.append(self._make_signal(
                    "EG-FAST-CRITICAL", "critical", eid,
                    "Critical alerts closed with unusually short investigation duration",
                    "Investigation", len(critical_fast),
                    f"{len(critical_fast)} critical cases with investigation ≤10 minutes",
                    "Critical cases typically require thorough investigation",
                ))

            # 2. Cases closed without investigation evidence
            no_inv = [c for c in cases if c["case_id"] not in self._inv_by_case]
            if no_inv:
                rate = round(len(no_inv) / max(len(cases), 1) * 100, 1)
                signals.append(self._make_signal(
                    "EG-NO-INV", "high", eid,
                    "Cases closed without investigation evidence",
                    "Investigation", len(no_inv),
                    f"{len(no_inv)} cases ({rate}%) lack investigation records",
                    "Cases should have documented investigation evidence",
                    observed=rate, expected=5.0,
                ))

            # 3. Investigations without conclusion
            no_conclusion = [c for c in cases
                           if c["case_id"] in self._inv_by_case
                           and not self._inv_by_case[c["case_id"]].get("conclusion")]
            if no_conclusion:
                signals.append(self._make_signal(
                    "EG-NO-CONCLUSION", "medium", eid,
                    "Investigations without documented conclusion",
                    "Investigation", len(no_conclusion),
                    f"{len(no_conclusion)} investigations lack a conclusion",
                    "Investigations should document findings and conclusions",
                ))

            # 4. Escalation required but no escalation evidence
            missing_esc = [a for a in alerts
                          if a.get("escalation_required") and not a.get("escalation_id")]
            if missing_esc:
                req_count = sum(1 for a in alerts if a.get("escalation_required"))
                rate = round(len(missing_esc) / max(req_count, 1) * 100, 1)
                sev = "critical" if rate > 25 else "high" if rate > 10 else "medium"
                signals.append(self._make_signal(
                    "EG-MISSING-ESC", sev, eid,
                    "Alerts requiring escalation lack escalation evidence",
                    "Escalation", len(missing_esc),
                    f"{len(missing_esc)} alerts ({rate}%) requiring escalation have no escalation record",
                    "Escalation-required alerts should have escalation evidence",
                    observed=rate, expected=8.0,
                ))

            # 5. Escalation without response
            esc_no_resp = []
            for esc in self.escalations:
                if self._cases_by_id.get(esc["case_id"], {}).get("entity_id") == eid:
                    if esc["case_id"] not in self._resp_by_case:
                        esc_no_resp.append(esc["case_id"])
            if esc_no_resp:
                signals.append(self._make_signal(
                    "EG-ESC-NO-RESP", "high", eid,
                    "Escalated cases without response evidence",
                    "Incident Response", len(esc_no_resp),
                    f"{len(esc_no_resp)} escalated cases lack response records",
                    "Escalated cases should have documented response actions",
                ))

            # 6. Repeated alerts on same asset without remediation
            asset_alerts: dict[str, list] = defaultdict(list)
            for a in alerts:
                if a.get("asset_id"):
                    asset_alerts[a["asset_id"]].append(a)
            repeated = {aid: als for aid, als in asset_alerts.items()
                       if len(als) >= 10 and any(al["severity"] in ("critical", "high") for al in als)}
            unremediated = []
            for aid, als in repeated.items():
                case_ids = [a.get("case_id") for a in als if a.get("case_id")]
                has_rem = any(cid in self._rem_by_case for cid in case_ids)
                if not has_rem:
                    unremediated.append(aid)
            if unremediated:
                signals.append(self._make_signal(
                    "EG-REPEATED-NO-REM", "high", eid,
                    "Repeated alerts on assets without remediation evidence",
                    "Cyber Resilience", len(unremediated),
                    f"{len(unremediated)} assets with repeated critical/high alerts lack remediation",
                    "Recurring alerts should show root-cause remediation",
                ))

            # 7. Template investigation pattern
            template_invs = [i for i in self.investigations
                           if self._cases_by_id.get(i["case_id"], {}).get("entity_id") == eid
                           and i.get("template_match")]
            if template_invs:
                total_invs = sum(1 for i in self.investigations
                               if self._cases_by_id.get(i["case_id"], {}).get("entity_id") == eid)
                rate = round(len(template_invs) / max(total_invs, 1) * 100, 1)
                if rate > 15:
                    signals.append(self._make_signal(
                        "EG-TEMPLATE", "medium", eid,
                        "High rate of template-like investigation narratives",
                        "Operational Discipline", len(template_invs),
                        f"{len(template_invs)} investigations ({rate}%) use identical template text",
                        "Investigation narratives should reflect case-specific analysis",
                        observed=rate, expected=10.0,
                    ))

            # 8. Fast closure combined with low evidence
            fast_low_evidence = []
            for c in cases:
                inv = self._inv_by_case.get(c["case_id"])
                if inv and inv.get("duration_minutes", 999) <= 15 and inv.get("evidence_count", 99) <= 1:
                    fast_low_evidence.append(c["case_id"])
            if len(fast_low_evidence) > 5:
                signals.append(self._make_signal(
                    "EG-FAST-LOW-EVIDENCE", "high", eid,
                    "Fast closure combined with low evidence depth",
                    "Operational Discipline", len(fast_low_evidence),
                    f"{len(fast_low_evidence)} cases closed in ≤15 minutes with ≤1 evidence item",
                    "Quick closures should still contain adequate evidence",
                ))

        return signals

    # -----------------------------------------------------------------------
    # NEGATIVE SPACE SIGNALS
    # -----------------------------------------------------------------------

    def all_negative_space(self) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []

        for eid, entity in self.entities.items():
            alerts = self._alerts_by_entity.get(eid, [])
            assets = self._assets_by_entity.get(eid, [])
            subs = self._subs_by_entity.get(eid, [])

            # 1. Missing submissions
            missing = [s for s in subs if s.get("status") == "missing"]
            if missing:
                signals.append(self._make_signal(
                    "NS-MISSING-SUB", "high", eid,
                    "Expected periodic submissions are missing",
                    "Governance & Oversight", len(missing),
                    f"{len(missing)} reporting periods have no submission",
                    "Entities should submit evidence for all reporting periods",
                ))

            # 2. Critical assets with no monitoring evidence
            alerted_assets = set(a.get("asset_id") for a in alerts if a.get("asset_id"))
            critical_unmonitored = [a for a in assets
                                   if a.get("criticality") in ("critical", "high")
                                   and a["asset_id"] not in alerted_assets
                                   and a.get("expected_monitoring", True)]
            if critical_unmonitored:
                signals.append(self._make_signal(
                    "NS-CRIT-UNMONITORED", "high", eid,
                    "Critical/high assets with no security activity evidence",
                    "Security Operations", len(critical_unmonitored),
                    f"{len(critical_unmonitored)} critical/high assets have zero alert activity",
                    "Critical assets should have observable security telemetry",
                ))

            # 3. Unusually low alert volume compared to peers
            sector = entity.get("sector")
            if sector:
                peer_volumes = [len(self._alerts_by_entity.get(eid2, []))
                               for eid2, e2 in self.entities.items()
                               if e2.get("sector") == sector and eid2 != eid]
                if peer_volumes:
                    peer_median = statistics.median(peer_volumes) if peer_volumes else 0
                    if peer_median > 0 and len(alerts) < peer_median * 0.5:
                        signals.append(self._make_signal(
                            "NS-LOW-VOLUME", "medium", eid,
                            "Alert volume significantly below same-sector peer median",
                            "Security Operations", 1,
                            f"Alert volume {len(alerts)} is {round(len(alerts)/peer_median*100, 1)}% of peer median ({int(peer_median)})",
                            "Unusually low alert volume may indicate monitoring gaps",
                            observed=len(alerts), expected=int(peer_median),
                        ))

            # 4. Low investigation coverage
            cases = self._cases_by_entity.get(eid, [])
            if cases:
                inv_coverage = sum(1 for c in cases if c["case_id"] in self._inv_by_case) / len(cases) * 100
                if inv_coverage < 75:
                    signals.append(self._make_signal(
                        "NS-LOW-INV", "medium", eid,
                        "Investigation coverage below expected threshold",
                        "Investigation", 1,
                        f"Investigation coverage {round(inv_coverage, 1)}% is below 75% threshold",
                        "Most cases should have investigation evidence",
                        observed=round(inv_coverage, 1), expected=75.0,
                    ))

        return signals

    def _make_signal(self, rule: str, severity: str, entity_id: str,
                     finding: str, capability: str, affected_count: int,
                     description: str, expected_behavior: str,
                     observed: Any = None, expected: Any = None) -> dict[str, Any]:
        return {
            "id": f"{rule}-{entity_id}",
            "rule": rule,
            "severity": severity,
            "entity_id": entity_id,
            "entity_name": self.entities.get(entity_id, {}).get("entity_name", entity_id),
            "finding": finding,
            "capability": capability,
            "affected_count": affected_count,
            "description": description,
            "expected_behavior": expected_behavior,
            "observed_value": observed,
            "expected_value": expected,
            "confidence": "high" if affected_count > 10 else "medium" if affected_count > 3 else "low",
            "rule_version": "sat-sa-1.0",
            "category": "execution_gap" if rule.startswith("EG-") else "negative_space",
        }

    # -----------------------------------------------------------------------
    # PEER BENCHMARKING
    # -----------------------------------------------------------------------

    def peer_benchmark(self) -> dict[str, Any]:
        """Compare entities within same sector."""
        entity_metrics: dict[str, dict[str, Any]] = {}
        for eid in self.entities:
            alerts = self._alerts_by_entity.get(eid, [])
            cases = self._cases_by_entity.get(eid, [])
            total_alerts = len(alerts)
            total_cases = len(cases)
            inv_coverage = sum(1 for c in cases if c["case_id"] in self._inv_by_case) / max(total_cases, 1) * 100

            req_esc = [a for a in alerts if a.get("escalation_required")]
            esc_rate = sum(1 for a in req_esc if a.get("escalation_id")) / max(len(req_esc), 1) * 100

            assets = self._assets_by_entity.get(eid, [])
            alerted_assets = set(a.get("asset_id") for a in alerts if a.get("asset_id"))
            mon_cov = sum(1 for a in assets if a["asset_id"] in alerted_assets) / max(len(assets), 1) * 100

            # Median investigation duration
            durations = [self._inv_by_case[c["case_id"]]["duration_minutes"]
                        for c in cases if c["case_id"] in self._inv_by_case
                        and self._inv_by_case[c["case_id"]].get("duration_minutes")]
            med_duration = statistics.median(durations) if durations else None

            # Evidence completeness
            ev_counts = [self._inv_by_case[c["case_id"]].get("evidence_count", 0)
                        for c in cases if c["case_id"] in self._inv_by_case]
            ev_complete = sum(1 for e in ev_counts if e >= 2) / max(len(ev_counts), 1) * 100

            critical_rate = sum(1 for a in alerts if a["severity"] == "critical") / max(total_alerts, 1) * 100

            # Response coverage
            resp_count = sum(1 for c in cases if c["case_id"] in self._resp_by_case)
            resp_cov = resp_count / max(total_cases, 1) * 100

            entity_metrics[eid] = {
                "entity_id": eid,
                "entity_name": self.entities[eid].get("entity_name", eid),
                "sector": self.entities[eid].get("sector"),
                "alert_volume": total_alerts,
                "critical_rate": round(critical_rate, 1),
                "investigation_coverage": round(inv_coverage, 1),
                "escalation_rate": round(esc_rate, 1),
                "response_coverage": round(resp_cov, 1),
                "monitoring_coverage": round(mon_cov, 1),
                "median_closure_time": round(med_duration, 1) if med_duration else None,
                "evidence_completeness": round(ev_complete, 1),
            }

        # Compute sector benchmarks
        sectors: dict[str, list[str]] = defaultdict(list)
        for eid, em in entity_metrics.items():
            s = em.get("sector")
            if s:
                sectors[s].append(eid)

        benchmarks: dict[str, dict[str, Any]] = {}
        metrics_keys = ["investigation_coverage", "escalation_rate", "response_coverage",
                       "monitoring_coverage", "evidence_completeness", "critical_rate"]
        for sector, eids in sectors.items():
            sector_bench = {}
            for mk in metrics_keys:
                values = [entity_metrics[eid][mk] for eid in eids if entity_metrics[eid][mk] is not None]
                if values:
                    sector_bench[mk] = {
                        "median": round(statistics.median(values), 1),
                        "mean": round(statistics.mean(values), 1),
                        "min": round(min(values), 1),
                        "max": round(max(values), 1),
                    }
            benchmarks[sector] = sector_bench

        # Add peer comparison to each entity
        for eid, em in entity_metrics.items():
            sector = em.get("sector")
            if sector and sector in benchmarks:
                peer_comparison = {}
                for mk in metrics_keys:
                    if mk in benchmarks[sector] and em.get(mk) is not None:
                        median = benchmarks[sector][mk]["median"]
                        deviation = round(em[mk] - median, 1)
                        # Percentile
                        peer_vals = sorted([entity_metrics[e][mk] for e in sectors.get(sector, [])
                                          if entity_metrics[e].get(mk) is not None])
                        if peer_vals:
                            rank = sum(1 for v in peer_vals if v <= em[mk])
                            percentile = round(rank / len(peer_vals) * 100, 1)
                        else:
                            percentile = 50.0
                        peer_comparison[mk] = {
                            "value": em[mk],
                            "peer_median": median,
                            "deviation": deviation,
                            "percentile": percentile,
                        }
                em["peer_comparison"] = peer_comparison

        return {
            "entities": entity_metrics,
            "sector_benchmarks": benchmarks,
            "sectors": {s: eids for s, eids in sectors.items()},
        }

    # -----------------------------------------------------------------------
    # CAPABILITY SCORING
    # -----------------------------------------------------------------------

    def capability_scores(self, entity_id: str | None = None) -> dict[str, Any]:
        if entity_id:
            return self._entity_capability(entity_id)

        result = {}
        for eid in self.entities:
            result[eid] = self._entity_capability(eid)
        return result

    def _entity_capability(self, eid: str) -> dict[str, Any]:
        alerts = self._alerts_by_entity.get(eid, [])
        cases = self._cases_by_entity.get(eid, [])
        assets = self._assets_by_entity.get(eid, [])

        total_alerts = len(alerts)
        total_cases = len(cases)

        # Investigation metrics
        inv_coverage = sum(1 for c in cases if c["case_id"] in self._inv_by_case) / max(total_cases, 1)
        durations = [self._inv_by_case[c["case_id"]]["duration_minutes"]
                    for c in cases if c["case_id"] in self._inv_by_case
                    and self._inv_by_case[c["case_id"]].get("duration_minutes")]
        fast_rate = sum(1 for d in durations if d <= 10) / max(len(durations), 1)
        conclusion_count = sum(1 for c in cases
                             if c["case_id"] in self._inv_by_case
                             and self._inv_by_case[c["case_id"]].get("conclusion"))
        conclusion_cov = conclusion_count / max(sum(1 for c in cases if c["case_id"] in self._inv_by_case), 1)
        template_count = sum(1 for i in self.investigations
                           if self._cases_by_id.get(i["case_id"], {}).get("entity_id") == eid
                           and i.get("template_match"))
        total_entity_inv = sum(1 for i in self.investigations
                              if self._cases_by_id.get(i["case_id"], {}).get("entity_id") == eid)
        template_rate = template_count / max(total_entity_inv, 1)
        ev_counts = [self._inv_by_case[c["case_id"]].get("evidence_count", 0)
                    for c in cases if c["case_id"] in self._inv_by_case]
        ev_completeness = sum(1 for e in ev_counts if e >= 2) / max(len(ev_counts), 1)

        # Escalation metrics
        req_esc = [a for a in alerts if a.get("escalation_required")]
        esc_cov = sum(1 for a in req_esc if a.get("escalation_id")) / max(len(req_esc), 1)
        esc_entities = [e for e in self.escalations
                       if self._cases_by_id.get(e["case_id"], {}).get("entity_id") == eid]
        esc_ack = sum(1 for e in esc_entities if e.get("acknowledged")) / max(len(esc_entities), 1)
        esc_latencies = []
        for e in esc_entities:
            case = self._cases_by_id.get(e["case_id"])
            if case:
                mins = _minutes_between(case.get("created_at"), e.get("escalation_time"))
                if mins is not None:
                    esc_latencies.append(mins)

        # Response metrics
        resp_cases = sum(1 for c in cases if c["case_id"] in self._resp_by_case)
        resp_cov = resp_cases / max(total_cases, 1)

        # Monitoring coverage
        alerted_assets = set(a.get("asset_id") for a in alerts if a.get("asset_id"))
        mon_cov = sum(1 for a in assets if a["asset_id"] in alerted_assets) / max(len(assets), 1)
        crit_assets = [a for a in assets if a.get("criticality") in ("critical", "high")]
        crit_cov = sum(1 for a in crit_assets if a["asset_id"] in alerted_assets) / max(len(crit_assets), 1)

        # Remediation
        rem_count = sum(1 for r in self.remediations
                       if self._cases_by_id.get(r["case_id"], {}).get("entity_id") == eid)

        # Submission completeness
        subs = self._subs_by_entity.get(eid, [])
        sub_complete = sum(1 for s in subs if s.get("status") == "submitted") / max(len(subs), 1) if subs else 1.0

        # Repeated alerts without remediation
        asset_alerts_map: dict[str, int] = Counter(a.get("asset_id") for a in alerts if a.get("asset_id"))
        repeated_no_rem = 0
        for aid, count in asset_alerts_map.items():
            if count >= 10:
                case_ids = [a.get("case_id") for a in alerts if a.get("asset_id") == aid and a.get("case_id")]
                if not any(cid in self._rem_by_case for cid in case_ids):
                    repeated_no_rem += 1

        # --- Compute capability scores ---
        capabilities = {}

        # 1. Threat Detection
        alert_to_case = sum(1 for a in alerts if a.get("case_id")) / max(total_alerts, 1)
        td_score = round(min(100, alert_to_case * 100 * 0.6 + (1 - fast_rate) * 100 * 0.4), 1)
        capabilities["Threat Detection"] = {
            "score": td_score,
            "contributors": {
                "Alert-to-case linkage": round(alert_to_case * 100, 1),
                "Non-fast-closure rate": round((1 - fast_rate) * 100, 1),
            }
        }

        # 2. Investigation
        inv_score = round(min(100,
            inv_coverage * 100 * 0.30 +
            ev_completeness * 100 * 0.25 +
            conclusion_cov * 100 * 0.20 +
            (1 - template_rate) * 100 * 0.15 +
            (1 - fast_rate) * 100 * 0.10
        ), 1)
        capabilities["Investigation"] = {
            "score": inv_score,
            "contributors": {
                "Investigation coverage": round(inv_coverage * 100, 1),
                "Evidence completeness": round(ev_completeness * 100, 1),
                "Conclusion coverage": round(conclusion_cov * 100, 1),
                "Non-template rate": round((1 - template_rate) * 100, 1),
                "Non-fast-closure rate": round((1 - fast_rate) * 100, 1),
            }
        }

        # 3. Escalation
        esc_score = round(min(100,
            esc_cov * 100 * 0.40 +
            esc_ack * 100 * 0.30 +
            (100 - min(statistics.median(esc_latencies) if esc_latencies else 60, 120) / 120 * 100) * 0.30
        ), 1)
        capabilities["Escalation"] = {
            "score": esc_score,
            "contributors": {
                "Escalation coverage": round(esc_cov * 100, 1),
                "Acknowledgement rate": round(esc_ack * 100, 1),
                "Latency score": round(100 - min(statistics.median(esc_latencies) if esc_latencies else 60, 120) / 120 * 100, 1),
            }
        }

        # 4. Incident Response
        ir_score = round(min(100,
            resp_cov * 100 * 0.50 +
            esc_cov * 100 * 0.30 +
            (rem_count / max(total_cases * 0.1, 1)) * 100 * 0.20
        ), 1)
        ir_score = min(ir_score, 100)
        capabilities["Incident Response"] = {
            "score": ir_score,
            "contributors": {
                "Response coverage": round(resp_cov * 100, 1),
                "Escalation coverage": round(esc_cov * 100, 1),
                "Remediation activity": round(min(rem_count / max(total_cases * 0.1, 1) * 100, 100), 1),
            }
        }

        # 5. Security Operations
        secops_score = round(min(100,
            mon_cov * 100 * 0.40 +
            crit_cov * 100 * 0.35 +
            alert_to_case * 100 * 0.25
        ), 1)
        capabilities["Security Operations"] = {
            "score": secops_score,
            "contributors": {
                "Monitoring coverage": round(mon_cov * 100, 1),
                "Critical asset coverage": round(crit_cov * 100, 1),
                "Alert-to-case linkage": round(alert_to_case * 100, 1),
            }
        }

        # 6. Governance & Oversight
        gov_score = round(min(100,
            sub_complete * 100 * 0.50 +
            (1 - template_rate) * 100 * 0.25 +
            conclusion_cov * 100 * 0.25
        ), 1)
        capabilities["Governance & Oversight"] = {
            "score": gov_score,
            "contributors": {
                "Submission completeness": round(sub_complete * 100, 1),
                "Non-template rate": round((1 - template_rate) * 100, 1),
                "Conclusion documentation": round(conclusion_cov * 100, 1),
            }
        }

        # 7. Operational Discipline
        od_score = round(min(100,
            (1 - fast_rate) * 100 * 0.30 +
            (1 - template_rate) * 100 * 0.25 +
            ev_completeness * 100 * 0.25 +
            inv_coverage * 100 * 0.20
        ), 1)
        capabilities["Operational Discipline"] = {
            "score": od_score,
            "contributors": {
                "Non-fast-closure rate": round((1 - fast_rate) * 100, 1),
                "Non-template rate": round((1 - template_rate) * 100, 1),
                "Evidence completeness": round(ev_completeness * 100, 1),
                "Investigation coverage": round(inv_coverage * 100, 1),
            }
        }

        # 8. Cyber Resilience
        cr_score = round(min(100,
            crit_cov * 100 * 0.30 +
            (1 - repeated_no_rem / max(len([aid for aid, c in asset_alerts_map.items() if c >= 10]), 1)) * 100 * 0.25 +
            resp_cov * 100 * 0.25 +
            mon_cov * 100 * 0.20
        ), 1)
        capabilities["Cyber Resilience"] = {
            "score": cr_score,
            "contributors": {
                "Critical asset coverage": round(crit_cov * 100, 1),
                "Remediation for repeated alerts": round((1 - repeated_no_rem / max(len([aid for aid, c in asset_alerts_map.items() if c >= 10]), 1)) * 100, 1),
                "Response coverage": round(resp_cov * 100, 1),
                "Monitoring coverage": round(mon_cov * 100, 1),
            }
        }

        return capabilities

    # -----------------------------------------------------------------------
    # ENTITY RISK SCORING
    # -----------------------------------------------------------------------

    def all_entity_risk_scores(self) -> list[dict[str, Any]]:
        exec_gaps = self.all_execution_gaps()
        neg_space = self.all_negative_space()
        peer_data = self.peer_benchmark()
        all_caps = self.capability_scores()

        results = []
        for eid in self.entities:
            entity = self.entities[eid]
            # Count signals
            eg_count = sum(1 for s in exec_gaps if s["entity_id"] == eid)
            ns_count = sum(1 for s in neg_space if s["entity_id"] == eid)

            # Severity-weighted signal burden
            sev_weight = {"critical": 12, "high": 7, "medium": 3, "low": 1}
            eg_burden = sum(sev_weight.get(s["severity"], 1) for s in exec_gaps if s["entity_id"] == eid)
            ns_burden = sum(sev_weight.get(s["severity"], 1) for s in neg_space if s["entity_id"] == eid)

            # Peer deviation penalty
            peer_penalty = 0
            em = peer_data["entities"].get(eid, {})
            pc = em.get("peer_comparison", {})
            for mk, comp in pc.items():
                if mk in ("investigation_coverage", "escalation_rate", "monitoring_coverage", "evidence_completeness"):
                    if comp["deviation"] < -10:
                        peer_penalty += abs(comp["deviation"]) * 0.15

            # Capability weakness penalty
            caps = all_caps.get(eid, {})
            cap_penalty = 0
            for dim, data in caps.items():
                score = data.get("score", 75)
                if score < 60:
                    cap_penalty += (60 - score) * 0.3

            # Normalize each bounded component before combining them. This
            # keeps the ceiling a property of the formula rather than a
            # post-hoc clipping operation.
            execution_component = 100.0 * eg_burden / max(eg_count * 12, 1)
            negative_component = 100.0 * ns_burden / max(ns_count * 12, 1)
            peer_component = peer_penalty / max(len(peer_data["entities"].get(eid, {}).get("peer_comparison", {})), 1)
            capability_component = cap_penalty / max(len(all_caps.get(eid, {})) * 0.3 * 60, 1)
            score = round(
                execution_component * 0.35
                + negative_component * 0.25
                + peer_component * 0.20
                + capability_component * 0.20,
                1,
            )

            if score >= 70:
                risk_level = "CRITICAL"
            elif score >= 45:
                risk_level = "HIGH"
            elif score >= 20:
                risk_level = "MODERATE"
            else:
                risk_level = "LOW"

            results.append({
                "entity_id": eid,
                "entity_name": entity.get("entity_name", eid),
                "sector": entity.get("sector"),
                "risk_score": score,
                "risk_level": risk_level,
                "contributors": {
                    "Execution gaps": round(execution_component * 0.35, 1),
                    "Negative space": round(negative_component * 0.25, 1),
                    "Peer deviation": round(peer_component * 0.20, 1),
                    "Capability weakness": round(capability_component * 0.20, 1),
                },
                "execution_gap_count": eg_count,
                "negative_space_count": ns_count,
                "capabilities": {dim: data["score"] for dim, data in caps.items()} if caps else {},
            })

        results.sort(key=lambda x: -x["risk_score"])
        return results

    # -----------------------------------------------------------------------
    # TREND ANALYSIS
    # -----------------------------------------------------------------------

    def trend_analysis(self, entity_id: str | None = None) -> dict[str, Any]:
        if entity_id:
            alerts = self._alerts_by_entity.get(entity_id, [])
            cases = self._cases_by_entity.get(entity_id, [])
        else:
            alerts = self.alerts
            cases = self.cases

        months = sorted(set(_month_key(a.get("timestamp")) for a in alerts if _month_key(a.get("timestamp"))))

        trends: dict[str, list[dict[str, Any]]] = {
            "alert_volume": [],
            "critical_rate": [],
            "investigation_coverage": [],
            "escalation_coverage": [],
            "monitoring_coverage": [],
        }

        for mk in months:
            month_alerts = [a for a in alerts if _month_key(a.get("timestamp")) == mk]
            month_cases = [c for c in cases if _month_key(c.get("created_at")) == mk]

            vol = len(month_alerts)
            crit = sum(1 for a in month_alerts if a["severity"] == "critical")
            crit_rate = round(crit / max(vol, 1) * 100, 1)

            inv_cov = round(sum(1 for c in month_cases if c["case_id"] in self._inv_by_case) / max(len(month_cases), 1) * 100, 1)

            req_esc = [a for a in month_alerts if a.get("escalation_required")]
            esc_cov = round(sum(1 for a in req_esc if a.get("escalation_id")) / max(len(req_esc), 1) * 100, 1)

            trends["alert_volume"].append({"month": mk, "value": vol})
            trends["critical_rate"].append({"month": mk, "value": crit_rate})
            trends["investigation_coverage"].append({"month": mk, "value": inv_cov})
            trends["escalation_coverage"].append({"month": mk, "value": esc_cov})

            # Monitoring coverage is measured against the assets associated
            # with the entity, not just the assets seen in that month.
            month_asset_ids = {
                a.get("asset_id") for a in month_alerts if a.get("asset_id")
            }
            entity_assets = {
                a.get("asset_id") for a in self._assets_by_entity.get(entity_id, [])
            } if entity_id else {
                a.get("asset_id") for a in self.assets
            }
            monitored = len(month_asset_ids & entity_assets) if entity_assets else 0
            monitoring_cov = round(monitored / max(len(entity_assets), 1) * 100, 1)
            trends["monitoring_coverage"].append({"month": mk, "value": monitoring_cov})

        # Determine direction for each trend
        directions = {}
        for key, series in trends.items():
            if len(series) >= 3:
                recent = [s["value"] for s in series[-3:]]
                earlier = [s["value"] for s in series[:3]]
                avg_recent = statistics.mean(recent)
                avg_earlier = statistics.mean(earlier)
                diff = avg_recent - avg_earlier
                if abs(diff) < 2:
                    directions[key] = "stable"
                elif diff > 0:
                    directions[key] = "improving" if key != "critical_rate" else "deteriorating"
                else:
                    directions[key] = "deteriorating" if key != "critical_rate" else "improving"
            else:
                directions[key] = "insufficient_data"

        return {"trends": trends, "directions": directions, "months": months}

    # -----------------------------------------------------------------------
    # SAMPLE PRIORITIZATION
    # -----------------------------------------------------------------------

    def recommended_sample(self, entity_id: str | None = None, target_size: int = 80, control_size: int = 20) -> dict[str, Any]:
        if entity_id:
            cases = self._cases_by_entity.get(entity_id, [])
        else:
            cases = self.cases

        scored: list[tuple[float, dict[str, Any], list[str]]] = []

        for c in cases:
            priority = 0.0
            reasons: list[str] = []
            case_id = c["case_id"]

            # Severity
            if c.get("priority") == "critical":
                priority += 30
                reasons.append("Critical severity")
            elif c.get("priority") == "high":
                priority += 15
                reasons.append("High severity")

            # Fast investigation
            inv = self._inv_by_case.get(case_id)
            if inv and inv.get("duration_minutes", 999) <= 10:
                priority += 25
                reasons.append(f"Very fast investigation ({inv['duration_minutes']}min)")

            # Missing escalation
            alert = next((a for a in self.alerts if a.get("case_id") == case_id), None)
            if alert and alert.get("escalation_required") and not alert.get("escalation_id"):
                priority += 20
                reasons.append("Missing escalation evidence")

            # No investigation
            if case_id not in self._inv_by_case:
                priority += 15
                reasons.append("No investigation record")

            # Template investigation
            if inv and inv.get("template_match"):
                priority += 10
                reasons.append("Template investigation pattern")

            # Low evidence
            if inv and inv.get("evidence_count", 99) <= 1:
                priority += 10
                reasons.append("Low evidence depth")

            # No response for escalated case
            if case_id in self._esc_by_case and case_id not in self._resp_by_case:
                priority += 15
                reasons.append("Escalated without response")

            if reasons:
                scored.append((priority, c, reasons))

        # Sort by priority descending
        scored.sort(key=lambda x: (-x[0], str(x[1].get("case_id", ""))))

        targeted = []
        for priority_score, case, reasons in scored[:target_size]:
            targeted.append({
                "case_id": case["case_id"],
                "entity_id": case["entity_id"],
                "priority": "HIGH" if priority_score >= 40 else "MEDIUM" if priority_score >= 20 else "LOW",
                "priority_score": round(priority_score, 1),
                "reasons": reasons,
                "severity": case.get("priority"),
            })

        # Control sample (random)
        rng = random.Random(SEED)
        remaining = [c for c in cases if c["case_id"] not in {t["case_id"] for t in targeted}]
        control_cases = rng.sample(remaining, min(control_size, len(remaining))) if remaining else []
        control = [
            {
                "case_id": c["case_id"],
                "entity_id": c["entity_id"],
                "priority": "CONTROL",
                "priority_score": 0,
                "reasons": ["Random control sample — reduces selection bias"],
                "severity": c.get("priority"),
            }
            for c in control_cases
        ]

        return {
            "targeted_sample": targeted,
            "control_sample": control,
            "targeted_count": len(targeted),
            "control_count": len(control),
            "total_cases": len(cases),
            "explanation": "Targeted cases are selected based on severity, investigation anomalies, "
                          "missing escalation evidence, and other supervisory signals. "
                          "Control cases are randomly selected to reduce sampling bias.",
        }

    # -----------------------------------------------------------------------
    # DATA QUALITY
    # -----------------------------------------------------------------------

    def data_quality(self) -> dict[str, Any]:
        issues: list[dict[str, Any]] = []
        total_records = len(self.alerts)

        # Missing timestamps
        missing_ts = sum(1 for a in self.alerts if not a.get("timestamp"))
        if missing_ts:
            issues.append({"type": "missing_timestamp", "count": missing_ts,
                          "description": "Alerts with missing or empty timestamps"})

        # Missing asset mapping
        missing_asset = sum(1 for a in self.alerts if not a.get("asset_id"))
        if missing_asset:
            issues.append({"type": "missing_asset_mapping", "count": missing_asset,
                          "description": "Alerts without asset identifier"})

        # Missing severity
        missing_sev = sum(1 for a in self.alerts if not a.get("severity"))
        if missing_sev:
            issues.append({"type": "missing_severity", "count": missing_sev,
                          "description": "Alerts without severity classification"})

        # Duplicate alerts
        seen_ids: set[str] = set()
        dups = 0
        for a in self.alerts:
            if a["alert_id"] in seen_ids:
                dups += 1
            seen_ids.add(a["alert_id"])
        if dups:
            issues.append({"type": "duplicate_alert", "count": dups,
                          "description": "Duplicate alert identifiers"})

        # Cases without investigation
        no_inv = sum(1 for c in self.cases if c["case_id"] not in self._inv_by_case)
        if no_inv:
            issues.append({"type": "missing_investigation", "count": no_inv,
                          "description": "Cases without linked investigation records"})

        # Missing submissions
        missing_subs = sum(1 for s in self.submissions if s.get("status") == "missing")
        if missing_subs:
            issues.append({"type": "missing_submission", "count": missing_subs,
                          "description": "Expected periodic submissions not received"})

        # By entity
        by_entity = {}
        for eid in self.entities:
            ea = self._alerts_by_entity.get(eid, [])
            entity_issues = []
            mt = sum(1 for a in ea if not a.get("timestamp"))
            ma = sum(1 for a in ea if not a.get("asset_id"))
            if mt:
                entity_issues.append({"type": "missing_timestamp", "count": mt})
            if ma:
                entity_issues.append({"type": "missing_asset_mapping", "count": ma})
            ms = sum(1 for s in self._subs_by_entity.get(eid, []) if s.get("status") == "missing")
            if ms:
                entity_issues.append({"type": "missing_submission", "count": ms})
            issue_count = sum(i.get("count", 0) for i in entity_issues)
            total_entity = len(ea)
            by_entity[eid] = {
                "issues": entity_issues,
                "issue_count": issue_count,
                "total_records": total_entity,
                "quality_score": round(max(0.0, 1 - issue_count / max(total_entity, 1)) * 100, 1),
            }

        return {
            "total_records": total_records,
            "issues": issues,
            "total_issues": sum(i["count"] for i in issues),
            "quality_score": round(max(0.0, 1 - sum(i["count"] for i in issues) / max(total_records, 1)) * 100, 1),
            "by_entity": by_entity,
        }

    # -----------------------------------------------------------------------
    # SUPERVISORY ASSESSMENT (Control status)
    # -----------------------------------------------------------------------

    def supervisory_assessment(self, entity_id: str | None = None) -> dict[str, Any]:
        """Assess supervisory status for each control."""
        if entity_id:
            return self._entity_assessment(entity_id)

        result = {}
        for eid in self.entities:
            result[eid] = self._entity_assessment(eid)
        return result

    def _entity_assessment(self, eid: str) -> dict[str, Any]:
        alerts = self._alerts_by_entity.get(eid, [])
        cases = self._cases_by_entity.get(eid, [])
        assets = self._assets_by_entity.get(eid, [])

        total_cases = len(cases)
        inv_coverage = sum(1 for c in cases if c["case_id"] in self._inv_by_case) / max(total_cases, 1)
        req_esc = [a for a in alerts if a.get("escalation_required")]
        esc_cov = sum(1 for a in req_esc if a.get("escalation_id")) / max(len(req_esc), 1)
        resp_cases = sum(1 for c in cases if c["case_id"] in self._resp_by_case)
        resp_cov = resp_cases / max(total_cases, 1)

        alerted = set(a.get("asset_id") for a in alerts if a.get("asset_id"))
        crit_assets = [a for a in assets if a.get("criticality") in ("critical", "high")]
        crit_cov = sum(1 for a in crit_assets if a["asset_id"] in alerted) / max(len(crit_assets), 1)

        template_invs = sum(1 for i in self.investigations
                          if self._cases_by_id.get(i["case_id"], {}).get("entity_id") == eid
                          and i.get("template_match"))
        total_invs = sum(1 for i in self.investigations
                        if self._cases_by_id.get(i["case_id"], {}).get("entity_id") == eid)
        template_rate = template_invs / max(total_invs, 1)
        conclusion_cov = sum(
            1 for i in self.investigations
            if self._cases_by_id.get(i.get("case_id"), {}).get("entity_id") == eid
            and i.get("conclusion")
        ) / max(total_invs, 1)
        evidence_cov = sum(
            1 for i in self.investigations
            if self._cases_by_id.get(i.get("case_id"), {}).get("entity_id") == eid
            and (i.get("evidence_count") or 0) >= 2
        ) / max(total_invs, 1)
        repeated_assets = {
            a.get("asset_id") for a in alerts if a.get("asset_id")
        }
        resilience = sum(
            1 for aid in repeated_assets
            if sum(1 for a in alerts if a.get("asset_id") == aid) < 10
        ) / max(len(repeated_assets), 1)
        subs = self._subs_by_entity.get(eid, [])
        governance = sum(1 for s in subs if s.get("status", "submitted") == "submitted") / max(len(subs), 1)

        def _status(value: float, thresholds: tuple[float, float, float]) -> str:
            if value >= thresholds[0]:
                return "EVIDENCED"
            elif value >= thresholds[1]:
                return "PARTIALLY_EVIDENCED"
            elif value >= thresholds[2]:
                return "POTENTIAL_GAP"
            elif value > 0:
                return "NOT_EVIDENCED"
            else:
                return "INSUFFICIENT_DATA"

        controls = {
            "TD-01": {"status": _status(inv_coverage, (0.90, 0.75, 0.50)), "value": round(inv_coverage * 100, 1), "metric": "Investigation coverage"},
            "ES-01": {"status": _status(esc_cov, (0.85, 0.70, 0.50)), "value": round(esc_cov * 100, 1), "metric": "Escalation coverage"},
            "IR-01": {"status": _status(resp_cov, (0.80, 0.60, 0.40)), "value": round(resp_cov * 100, 1), "metric": "Response coverage"},
            "OP-01": {"status": _status(1 - template_rate, (0.85, 0.70, 0.50)), "value": round((1 - template_rate) * 100, 1), "metric": "Non-template investigation rate"},
            "MON-01": {"status": _status(crit_cov, (0.90, 0.75, 0.50)), "value": round(crit_cov * 100, 1), "metric": "Critical asset monitoring coverage"},
            "INV-01": {"status": _status((conclusion_cov + evidence_cov) / 2, (0.90, 0.75, 0.50)), "value": round((conclusion_cov + evidence_cov) / 2 * 100, 1), "metric": "Investigation conclusion and evidence coverage"},
            "GOV-01": {"status": _status(governance, (0.90, 0.75, 0.50)), "value": round(governance * 100, 1), "metric": "Submission governance completeness"},
            "RES-01": {"status": _status(resilience, (0.90, 0.75, 0.50)), "value": round(resilience * 100, 1), "metric": "Repeated-asset resilience coverage"},
        }

        # Summary counts
        status_counts = Counter(c["status"] for c in controls.values())

        return {
            "entity_id": eid,
            "controls": controls,
            "status_summary": dict(status_counts),
        }

    # -----------------------------------------------------------------------
    # SUPERVISORY INSIGHTS (natural language)
    # -----------------------------------------------------------------------

    def supervisory_insights(self) -> list[dict[str, Any]]:
        insights: list[dict[str, Any]] = []
        peer_data = self.peer_benchmark()
        risk_scores = self.all_entity_risk_scores()

        for rs in risk_scores:
            eid = rs["entity_id"]
            entity = self.entities.get(eid, {})

            # High-risk entity insight
            if rs["risk_level"] in ("HIGH", "CRITICAL"):
                caps = rs.get("capabilities", {})
                weak_caps = [dim for dim, score in caps.items() if score < 65]
                if weak_caps:
                    insights.append({
                        "entity_id": eid,
                        "severity": "high",
                        "insight": f"{entity.get('entity_name', eid)} requires supervisory attention. "
                                  f"Capability weaknesses detected in: {', '.join(weak_caps)}. "
                                  f"Risk score: {rs['risk_score']}.",
                        "category": "attention",
                    })

            # Peer deviation insight
            em = peer_data["entities"].get(eid, {})
            pc = em.get("peer_comparison", {})
            for mk, comp in pc.items():
                if comp["deviation"] < -15:
                    readable = mk.replace("_", " ").title()
                    insights.append({
                        "entity_id": eid,
                        "severity": "medium",
                        "insight": f"{entity.get('entity_name', eid)}: {readable} ({comp['value']}%) "
                                  f"is {abs(comp['deviation'])} percentage points below same-sector peer median ({comp['peer_median']}%).",
                        "category": "peer_deviation",
                    })

        return insights[:20]  # Top 20 insights

    # -----------------------------------------------------------------------
    # ENTITY DETAIL
    # -----------------------------------------------------------------------

    def entity_detail(self, entity_id: str) -> dict[str, Any]:
        entity = self.entities.get(entity_id)
        if not entity:
            return {}

        alerts = self._alerts_by_entity.get(entity_id, [])
        cases = self._cases_by_entity.get(entity_id, [])

        risk_scores = self.all_entity_risk_scores()
        risk = next((r for r in risk_scores if r["entity_id"] == entity_id), {})

        capabilities = self._entity_capability(entity_id)
        assessment = self._entity_assessment(entity_id)
        trends = self.trend_analysis(entity_id)

        exec_gaps = [s for s in self.all_execution_gaps() if s["entity_id"] == entity_id]
        neg_space = [s for s in self.all_negative_space() if s["entity_id"] == entity_id]

        sample = self.recommended_sample(entity_id, target_size=20, control_size=5)

        alert_analytics = self.alert_analytics(entity_id)
        inv_analytics = self.investigation_analytics(entity_id)
        esc_analytics = self.escalation_analytics(entity_id)
        mon_analytics = self.monitoring_analytics(entity_id)

        # Determine attention level
        attention = risk.get("risk_level", "MODERATE")
        attention_reasons = []
        if risk.get("contributors", {}).get("Execution gaps", 0) > 5:
            attention_reasons.append("Significant execution gap signals")
        if risk.get("contributors", {}).get("Negative space", 0) > 3:
            attention_reasons.append("Negative space indicators")
        if risk.get("contributors", {}).get("Peer deviation", 0) > 3:
            attention_reasons.append("Below peer median on key metrics")
        for dim, data in capabilities.items():
            if data["score"] < 60:
                attention_reasons.append(f"Low {dim} capability ({data['score']})")

        return {
            "entity_id": entity_id,
            "entity_name": entity.get("entity_name", entity_id),
            "sector": entity.get("sector"),
            "criticality": entity.get("criticality"),
            "synthetic_label": "SYNTHETIC DEMONSTRATION DATA — NOT REAL",
            "supervisory_attention": attention,
            "attention_reasons": attention_reasons,
            "risk": risk,
            "capabilities": capabilities,
            "assessment": assessment,
            "operational_metrics": {
                "total_alerts": len(alerts),
                "critical_alerts": sum(1 for a in alerts if a["severity"] == "critical"),
                "high_alerts": sum(1 for a in alerts if a["severity"] == "high"),
                "total_cases": len(cases),
                "investigation_coverage": inv_analytics["investigation_coverage"],
                "escalation_coverage": esc_analytics["escalation_rate"],
                "response_coverage": round(sum(1 for c in cases if c["case_id"] in self._resp_by_case) / max(len(cases), 1) * 100, 1),
                "monitoring_coverage": mon_analytics["coverage"],
            },
            "trends": trends,
            "execution_gaps": exec_gaps,
            "negative_space": neg_space,
            "sample": sample,
            "alert_analytics": alert_analytics,
            "investigation_analytics": inv_analytics,
            "escalation_analytics": esc_analytics,
            "monitoring_analytics": mon_analytics,
        }


# Importable constant
SEED = 26157
