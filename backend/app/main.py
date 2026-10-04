from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import os
import statistics
import uuid
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .database import (init_db, load_state, persist_assessment, persist_review,
                       persist_submission, persist_audit_event, persist_declarations)
from .ingestion import IngestionError, ingest_bytes, parse_pasted_logs
from .artifacts import artifact_store
from .auth import require_roles
from .tasks import submit_assessment
from .metrics import metrics
from .scoring import calculate_entity_risk
from .taxonomy import RULE_CATEGORIES
from .qa import answer_question
from .analytics import SupervisoryAnalytics
from . import compliance as compliance_engine


def now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Submission(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    source: str = Field(default="manual", max_length=100)
    records: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PasteSubmission(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    source: str = Field(default="pasted-log", max_length=100)
    text: str = Field(min_length=1, max_length=10 * 1024 * 1024)


SUPPORTED_SCHEMA_VERSIONS = {"1", "1.0"}


class AssessmentRequest(BaseModel):
    submission_id: str
    requested_by: str = Field(default="system", max_length=100)


class CanonicalEvidence(BaseModel):
    id: str
    kind: str
    source_id: Optional[str] = None
    entity_id: Optional[str] = None
    asset_id: Optional[str] = None
    timestamp: Optional[str] = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class ReviewRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)
    decision: str = Field(min_length=1, max_length=40)
    annotation: str = Field(default="", max_length=2000)
    finding_id: Optional[str] = None


class SATReviewRequest(BaseModel):
    status: str = Field(min_length=1, max_length=32)
    reviewer: str = Field(default="system", min_length=1, max_length=100)
    annotation: str = Field(default="", max_length=2000)


REVIEW_STATUSES = {
    "NEW", "UNDER_REVIEW", "IN_REVIEW", "VALIDATED", "DISMISSED", "REJECTED",
    "REQUIRES_EVIDENCE", "FOLLOW_UP", "CLOSED",
}

# Aliases kept for backward compatibility with earlier prototype statuses.
REVIEW_STATUS_ALIASES = {
    "IN_REVIEW": "UNDER_REVIEW",
    "REJECTED": "DISMISSED",
}


def _normalize_review_status(status: str) -> str:
    upper = status.upper()
    return REVIEW_STATUS_ALIASES.get(upper, upper)

AUDIT_EVENT_TYPES = {
    "assessment_created", "dataset_uploaded", "assessment_executed",
    "finding_generated", "finding_opened", "finding_validated",
    "finding_rejected", "evidence_requested", "reviewer_assigned",
    "finding_closed", "report_generated",
}


STATUS_ALIASES = {"DISMISSED": "REJECTED", "FOLLOW_UP": "IN_REVIEW"}


def _norm_status(s: str) -> str:
    s = (s or "").upper()
    return STATUS_ALIASES.get(s, s)


class Finding(BaseModel):
    id: str
    rule: str
    severity: Severity
    title: str
    description: str
    entity_id: Optional[str] = None
    evidence: list[str] = Field(default_factory=list)
    lineage: list[str] = Field(default_factory=list)
    rule_version: str = "rules-1.0"
    confidence: float = Field(default=0.85, ge=0, le=1)
    calculation: str = ""
    limitations: list[str] = Field(default_factory=list)


class Store:
    submissions: dict[str, dict[str, Any]] = {}
    assessments: dict[str, dict[str, Any]] = {}
    findings: dict[str, list[dict[str, Any]]] = {}
    entities: dict[str, dict[str, Any]] = {}
    assets: dict[str, dict[str, Any]] = {}
    alerts: dict[str, dict[str, Any]] = {}
    cases: dict[str, dict[str, Any]] = {}
    workflow_events: list[dict[str, Any]] = []
    audit_events: list[dict[str, Any]] = []
    reviews: list[dict[str, Any]] = []
    declarations: dict[str, dict[str, Any]] = {}
    _evidence_index: dict[str, dict[str, Any]] | None = None


app = FastAPI(title="SOC-Inspect API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    # The deployed UI is same-origin (nginx proxies /api); CORS only matters for
    # the Vite dev server or a separately hosted UI.
    allow_origins=[o.strip() for o in os.getenv(
        "CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173").split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def correlation_middleware(request: Request, call_next: Any) -> Response:
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        metrics.observe_request(request.method, request.url.path, 500, time.perf_counter() - started)
        raise
    metrics.observe_request(request.method, request.url.path, response.status_code, time.perf_counter() - started)
    response.headers["X-Request-ID"] = request_id
    return response


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException) -> Response:
    detail = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
    return Response(
        content=json.dumps({"error": detail.get("error", "Request failed"), **detail,
                            "request_id": getattr(request.state, "request_id", None)}),
        status_code=exc.status_code, media_type="application/json",
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> Response:
    return Response(
        content=json.dumps({"error": "Validation failed", "details": exc.errors(),
                            "request_id": getattr(request.state, "request_id", None)}),
        status_code=422, media_type="application/json",
    )


def error(status: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": detail})


AUDIT_GENESIS = "0" * 64
AUDIT_HASH_FIELDS = ("id", "timestamp", "event_type", "actor", "role", "target_type", "target_id",
                     "action", "previous_state", "new_state", "assessment_id", "source", "prev_hash")


def _audit_digest(event: dict[str, Any]) -> str:
    core = {k: event.get(k) for k in AUDIT_HASH_FIELDS}
    return hashlib.sha256(json.dumps(core, sort_keys=True, default=str).encode()).hexdigest()


def _seal_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    """Link the event to its predecessor so deletion/reordering/editing is detectable."""
    previous = Store.audit_events[-1] if Store.audit_events else None
    event["prev_hash"] = (previous or {}).get("event_hash") or AUDIT_GENESIS
    event["event_hash"] = _audit_digest(event)
    return event


def verify_audit_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    expected_prev, legacy = None, 0
    for index, event in enumerate(events):
        if "prev_hash" not in event:  # written before chaining was introduced
            legacy += 1
            expected_prev = event.get("event_hash")
            continue
        if expected_prev is not None and event["prev_hash"] != expected_prev:
            return {"valid": False, "checked": index, "legacy_unchained": legacy,
                    "broken_at": event.get("id"), "reason": "prev_hash does not match preceding event"}
        if _audit_digest(event) != event.get("event_hash"):
            return {"valid": False, "checked": index, "legacy_unchained": legacy,
                    "broken_at": event.get("id"), "reason": "event content does not match its hash"}
        expected_prev = event["event_hash"]
    return {"valid": True, "checked": len(events), "legacy_unchained": legacy,
            "head_hash": expected_prev}


def record_audit_event(event_type: str, actor: str, target_type: str, target_id: str,
                       action: str, assessment_id: str | None = None,
                       previous_state: str | None = None, new_state: str | None = None,
                       source: str = "api", role: str | None = None,
                       details: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create an immutable audit event with a content hash."""
    timestamp = now().isoformat()
    core = {"timestamp": timestamp, "event_type": event_type, "actor": actor,
            "target_type": target_type, "target_id": target_id, "action": action,
            "assessment_id": assessment_id, "previous_state": previous_state,
            "new_state": new_state, "source": source, "role": role}
    event = _seal_audit_event({"id": str(uuid.uuid4()), **core})
    event["details"] = details or {}
    # Keep legacy keys used by older clients/tests.
    event["type"] = event_type
    event["timestamp"] = timestamp
    Store.audit_events.append(event)
    try:
        persist_audit_event(event)
    except Exception:
        pass
    return event


def normalize_records(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    quality: list[str] = []
    normalized = []
    for index, item in enumerate(records):
        row = dict(item)
        row["_row"] = index + 1
        if not any(row.get(k) for k in ("entity_id", "entity", "user", "host", "asset_id")):
            quality.append(f"row {index + 1}: missing entity identifier")
        if not row.get("timestamp") and not row.get("time"):
            quality.append(f"row {index + 1}: missing timestamp")
        if row.get("alert_id") and not row.get("severity"):
            quality.append(f"row {index + 1}: missing severity (insufficient evidence)")
        if row.get("asset_id") and not row.get("asset_criticality") and not row.get("criticality"):
            quality.append(f"row {index + 1}: missing asset criticality (insufficient evidence)")
        normalized.append(row)
    return normalized, quality


def content_hash(records: list[dict[str, Any]]) -> str:
    data = json.dumps(records, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(data).hexdigest()


def build_demo() -> None:
    if Store.submissions:
        return
    raw_records = [
        {"entity_id": "alice", "asset_id": "endpoint-01", "type": "alert", "severity": "critical",
         "alert_id": "a-1", "escalated": False, "status": "open", "timestamp": "2026-01-10T10:00:00Z"},
        {"entity_id": "bob", "asset_id": "endpoint-02", "type": "case", "case_id": "c-1",
         "status": "closed", "evidence": False, "investigated": True, "timestamp": "2026-01-10T11:00:00Z"},
        {"entity_id": "carol", "asset_id": "endpoint-03", "type": "alert", "severity": "high",
         "alert_id": "a-3", "escalated": True, "responded": False, "timestamp": "2026-01-10T12:00:00Z"},
        {"entity_id": "dave", "asset_id": "endpoint-04", "type": "case", "case_id": "c-4",
         "status": "closed", "investigated": False, "closure_time": "2026-01-10T10:00:00Z",
         "investigation_time": "2026-01-10T11:00:00Z", "timestamp": "2026-01-10T13:00:00Z"},
    ]
    records, quality_issues = normalize_records(raw_records)
    sid = str(uuid.uuid4())
    Store.submissions[sid] = {"id": sid, "name": "Synthetic SOC demo", "source": "demo",
                              "records": records, "content_sha256": content_hash(records),
                              "quality_issues": quality_issues, "quality": {"issue_count": len(quality_issues),
                              "rows": len(records)}, "created_at": now().isoformat()}
    invalidate_caches()


def index_records(submission: dict[str, Any]) -> None:
    for row in submission["records"]:
        entity_id = str(row.get("entity_id") or row.get("entity") or row.get("user") or row.get("host") or "unknown")
        entity_name = str(row.get("entity_name") or row.get("name") or entity_id)
        sector = row.get("sector") or row.get("entity_sector") or row.get("sector_name")
        entity = Store.entities.setdefault(
            entity_id, {"id": entity_id, "name": entity_name, "sector": sector, "alerts": 0, "cases": 0}
        )
        if entity["name"] == entity_id and entity_name != entity_id:
            entity["name"] = entity_name
        if entity.get("sector") is None and sector:
            entity["sector"] = str(sector)
        if row.get("asset_id"):
            Store.assets[str(row["asset_id"])] = {"id": str(row["asset_id"]), "entity_id": entity_id}
        if row.get("alert_id"):
            Store.alerts[str(row["alert_id"])] = {**row, "id": str(row["alert_id"]), "entity_id": entity_id}
            Store.entities[entity_id]["alerts"] += 1
        if row.get("case_id"):
            Store.cases[str(row["case_id"])] = {**row, "id": str(row["case_id"]), "entity_id": entity_id}
            Store.entities[entity_id]["cases"] += 1
        Store.workflow_events.append(CanonicalEvidence(id=str(uuid.uuid4()), kind="workflow_event",
                                      entity_id=entity_id, asset_id=row.get("asset_id"),
                                      timestamp=row.get("timestamp"),
                                      attributes={"type": row.get("type", "record")}).model_dump())


def execute_rules(submission: dict[str, Any], assessment_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    def add(rule: str, severity: Severity, title: str, description: str, row: dict[str, Any], evidence: list[str]) -> None:
        fid = str(uuid.uuid4())
        findings.append(Finding(id=fid, rule=rule, severity=severity, title=title,
                                description=description, entity_id=str(row.get("entity_id") or row.get("entity") or "unknown"),
                                evidence=evidence, lineage=[f"submission:{submission['id']}", f"row:{row['_row']}"],
                                calculation=f"rule={rule}; category={RULE_CATEGORIES.get(rule)}; evidence_count={len(evidence)}",
                                limitations=["Periodic submission only; supervisor validation required."]).model_dump(mode="json"))
    from .rowmap import (escalation_required as _esc_req, is_escalated as _is_esc,
                       is_investigated as _is_inv, is_responded as _is_resp,
                       is_closed as _is_closed, conclusion as _concl,
                       inv_end as _inv_end, closure_time as _clo_time)
    for row in submission["records"]:
        evidence = [f"record:{submission['id']}#row-{row['_row']}"]
        severity = str(row.get("severity", "")).lower()
        _req = _esc_req(row)
        _esc = _is_esc(row)
        _inv = _is_inv(row)
        _resp = _is_resp(row)
        if row.get("alert_id") and severity == "critical" and _req and not _esc:
            add("critical_alert_no_escalation", Severity.critical, "Critical alert was not escalated",
                "Critical alert lacks an escalation event.", row, evidence)
        if row.get("alert_id") and severity == "high" and _req and not _esc:
            add("critical_alert_no_escalation", Severity.high, "High alert was not escalated",
                "High-severity alert requiring escalation lacks an escalation event.", row, evidence)
        _closed = _is_closed(row) or str(row.get("status", "")).lower() == "closed"
        if row.get("case_id") and _closed and row.get("evidence") is False:
            add("closed_without_evidence", Severity.high, "Case closed without evidence",
                "The case was closed without attached evidence.", row, evidence)
        if row.get("alert_id") and _esc and not _resp:
            add("escalation_no_response", Severity.high, "Escalation received no response",
                "An escalated alert has no recorded response.", row, evidence)
        _ct, _it = _clo_time(row), _inv_end(row)
        if row.get("case_id") and _ct and _it and str(_ct) < str(_it):
            add("closure_before_investigation", Severity.high, "Closure precedes investigation",
                "Workflow timestamps indicate closure occurred before investigation.", row, evidence)
        if row.get("case_id") and _inv and not _concl(row):
            add("investigation_without_conclusion", Severity.medium, "Investigation has no conclusion",
                "Investigation activity is recorded without a documented conclusion.", row, evidence)
        if row.get("alert_id") and _esc is False and row.get("escalated") is True and row.get("responded") is False:
            pass  # legacy flags already covered by derived flags above
        if row.get("alert_id") and not row.get("severity"):
            add("missing_severity", Severity.medium, "Alert severity is missing",
                "Severity is absent, so prioritisation is insufficiently evidenced.", row, evidence)
        if row.get("asset_id") and not (row.get("asset_criticality") or row.get("criticality")):
            add("missing_asset_criticality", Severity.low, "Asset criticality is missing",
                "Asset criticality is absent, limiting risk interpretation; this is insufficient evidence, not compliance.",
                row, evidence)
        if str(row.get("status", "")).lower() not in ("", "open", "new", "investigating", "in_progress", "closed", "resolved", "escalated"):
            add("invalid_status", Severity.medium, "Invalid workflow status",
                "The record contains a status outside the supported lifecycle.", row, evidence)
        if row.get("status") in ("closed", "resolved") and row.get("investigated") is False:
            add("invalid_status_order", Severity.high, "Closed before investigation",
                "A record is marked closed without investigation.", row, evidence)
        _case_status = str(row.get("case_status") or row.get("status") or "").lower()
        if row.get("case_id") and _case_status in ("closed", "resolved") and not _inv and not row.get("investigation_id"):
            add("invalid_status_order", Severity.high, "Closed before investigation",
                "A case is marked closed without investigation evidence.", row, evidence)
        if row.get("alert_id") and not row.get("case_id"):
            add("alert_without_case", Severity.medium, "Alert has no linked case",
                "Alert activity has no linked case record in the submitted window.", row, evidence)
    seen: dict[str, dict[str, Any]] = {}
    dup_first_emitted: set[str] = set()
    for row in submission["records"]:
        key = row.get("alert_id") or row.get("case_id")
        if key and key in seen:
            first = seen[key]
            pair = [f"record:{submission['id']}#row-{first['_row']}",
                    f"record:{submission['id']}#row-{row['_row']}"]
            # The first occurrence gets its own finding so the group exposes
            # one finding per affected record (drill-down), while other rules
            # stay merged per (rule, entity) with full evidence arrays.
            if key not in dup_first_emitted:
                dup_first_emitted.add(key)
                add("duplicate_record", Severity.medium, "Duplicate support record",
                    f"Identifier {key} appears more than once.", first, pair)
            add("duplicate_record", Severity.medium, "Duplicate support record",
                f"Identifier {key} appears more than once.", row, pair)
        elif key:
            seen[str(key)] = row
    # Deterministic text similarity catches copied/template investigations.
    text_rows = []
    for row in submission["records"]:
        text = row.get("conclusion") or row.get("notes") or row.get("investigation_notes")
        if row.get("case_id") and isinstance(text, str) and len(_normal_text(text)) >= 20:
            text_rows.append((row, _normal_text(text)))
    for index, (row, text) in enumerate(text_rows):
        for other, other_text in text_rows[index + 1:]:
            if _text_similarity(text, other_text) >= 0.92:
                add("repeated_investigation_template", Severity.medium, "Repeated investigation narrative",
                    "Investigation conclusion/notes closely match another record after normalization.",
                    row, [f"record:{submission['id']}#row-{row['_row']}",
                          f"record:{submission['id']}#row-{other['_row']}"])
                break
    # Response latency outliers are measured against the entity median.
    response_values: dict[str, list[tuple[dict[str, Any], float]]] = {}
    for row in submission["records"]:
        value = _response_minutes(row)
        if value is not None:
            response_values.setdefault(_entity(row), []).append((row, value))
    for entity_rows in response_values.values():
        if len(entity_rows) < 2:
            continue
        median = statistics.median(value for _, value in entity_rows)
        threshold = max(median * 1.5, median + 30)
        for row, value in entity_rows:
            if value > threshold:
                add("response_time_anomaly", Severity.medium, "Response time is anomalous",
                    f"Response took {value:g} minutes versus entity median {median:g} minutes.",
                    row, [f"record:{submission['id']}#row-{row['_row']}"])
    # Negative-space indicator: entities with alerts but no case or response.
    for entity_id, entity in Store.entities.items():
        rows = [r for r in submission["records"] if str(r.get("entity_id") or r.get("entity") or r.get("user") or r.get("host") or "unknown") == entity_id]
        if any(r.get("alert_id") for r in rows) and not any(r.get("case_id") for r in rows):
            add("alert_without_case", Severity.medium, "Alert has no linked case",
                "The entity has alert activity but no case record in the submitted window.", rows[0],
                [f"record:{submission['id']}#row-{r['_row']}" for r in rows])
        assets = {r.get("asset_id") for r in rows if r.get("asset_id")}
        if not assets and rows:
            add("asset_without_coverage", Severity.low, "Entity has no asset coverage",
                "Entity activity has no associated asset identifier in the submitted window.", rows[0],
                [f"record:{submission['id']}#row-{r['_row']}" for r in rows])
    # Report missing weekly periods only when timestamps span multiple weeks.
    dated = [(r, _parse_timestamp(r.get("timestamp") or r.get("time"))) for r in submission["records"]]
    weeks = {value.date() - timedelta(days=value.weekday()) for _, value in dated if value}
    if len(weeks) >= 3:
        start, end = min(weeks), max(weeks)
        expected = {start + timedelta(days=7 * i) for i in range(((end - start).days // 7) + 1)}
        for missing in sorted(expected - weeks):
            row = next((r for r, value in dated if value), submission["records"][0])
            add("negative_space_period_gap", Severity.low, "Submission has a reporting gap",
                f"No records were submitted for week starting {missing.isoformat()}.",
                row, [f"record:{submission['id']}#row-{r['_row']}" for r, value in dated if value])
    # A repeated source row can satisfy several checks, but supervisors need
    # one finding per rule/entity rather than a noisy duplicate list. Preserve
    # every supporting record in the merged evidence and lineage so the
    # finding remains auditable.
    deduplicated: dict[tuple[str, ...], dict[str, Any]] = {}
    for finding in findings:
        # Duplicate-record findings stay per affected row (one finding per
        # record) so groups expose every affected record for drill-down.
        # All other rules merge per (rule, entity) with full evidence arrays.
        if finding["rule"] == "duplicate_record":
            key: tuple[str, ...] = (finding["rule"], finding.get("entity_id") or "",
                                    finding.get("lineage", [""])[-1])
        else:
            key = (finding["rule"], finding.get("entity_id") or "")
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = finding
            continue
        existing["evidence"] = list(dict.fromkeys(
            existing.get("evidence", []) + finding.get("evidence", [])
        ))
        existing["lineage"] = list(dict.fromkeys(
            existing.get("lineage", []) + finding.get("lineage", [])
        ))
        existing["calculation"] = (
            f"{existing['calculation'].split('; evidence_count=')[0]}; "
            f"evidence_count={len(existing['evidence'])}"
        )
    return list(deduplicated.values())


def _entity(row: dict[str, Any]) -> str:
    return str(row.get("entity_id") or row.get("entity") or row.get("user") or row.get("host") or "unknown")


def _normal_text(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", " ", value.lower())).strip()


def _text_similarity(left: str, right: str) -> float:
    a, b = set(left.split()), set(right.split())
    return len(a & b) / max(len(a | b), 1)


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def _response_minutes(row: dict[str, Any]) -> Optional[float]:
    value = row.get("response_minutes")
    if value is not None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    starts = ("alert_timestamp", "opened_at", "created_at", "timestamp")
    ends = ("response_timestamp", "responded_at", "response_at")
    start = next((_parse_timestamp(row.get(k)) for k in starts if _parse_timestamp(row.get(k))), None)
    end = next((_parse_timestamp(row.get(k)) for k in ends if _parse_timestamp(row.get(k))), None)
    return (end - start).total_seconds() / 60 if start and end and end >= start else None


def assessment_summary(findings: list[dict[str, Any]], submission: dict[str, Any]) -> dict[str, Any]:
    domains = {
        "detection": not any(f["rule"] == "alert_without_case" for f in findings),
        "triage": not any(f["rule"] in ("critical_alert_no_escalation", "duplicate_record") for f in findings),
        "investigation": not any(f["rule"] == "investigation_without_conclusion" for f in findings),
        "escalation": not any(f["rule"] == "escalation_no_response" for f in findings),
        "evidence": not any(f["rule"] == "closed_without_evidence" for f in findings),
        "workflow": not any(f["rule"] in ("closure_before_investigation", "invalid_status_order", "invalid_status") for f in findings),
        "coverage": not any(f["rule"] == "asset_without_coverage" for f in findings),
        "governance": True,
    }
    entity_metrics = []
    for entity_id in sorted({_entity(row) for row in submission["records"]}):
        rows = [row for row in submission["records"] if _entity(row) == entity_id]
        entity_findings = [f for f in findings if f.get("entity_id") == entity_id]
        entity_metrics.append({"entity_id": entity_id, "record_count": len(rows),
                               "finding_count": len(entity_findings),
                               "finding_rate": round(len(entity_findings) / max(len(rows), 1), 3)})
    rates = [item["finding_rate"] for item in entity_metrics]
    peer_median = statistics.median(rates) if rates else 0
    for item in entity_metrics:
        item["peer_median"] = round(peer_median, 3)
        item["deviation"] = round(item["finding_rate"] - peer_median, 3)
    record_counts = {_entity(row): sum(1 for item in submission["records"] if _entity(item) == _entity(row))
                     for row in submission["records"]}
    entity_risk = calculate_entity_risk(findings, record_counts, Store.entities)
    return {"finding_count": len(findings), "by_severity": {s: sum(f["severity"] == s for f in findings) for s in ("low", "medium", "high", "critical")},
            "entity_risk": entity_risk,
            "capability_indicators": {**domains, "alert_to_case_linkage": any(f["rule"] == "alert_without_case" for f in findings) is False,
                                      "evidence_discipline": any(f["rule"] == "closed_without_evidence" for f in findings) is False,
                                      "workflow_ordering": any(f["rule"] == "closure_before_investigation" for f in findings) is False},
            "data_quality_issues": submission["quality_issues"],
            "peer_benchmark": {"finding_rate": round(len(findings) / max(len(submission["records"]), 1), 3),
                               "peer_group": "entity",
                               "peer_median": round(peer_median, 3),
                               "entities": entity_metrics}}


@app.on_event("startup")
def startup() -> None:
    init_db()
    load_state(Store)
    for submission in Store.submissions.values():
        index_records(submission)
    # Serverless instances start with an empty /tmp database: seed the demo
    # dataset on cold start (Docker seeds once via its entrypoint instead).
    # database.py restores the bundled snapshot first (~1 s); this is the
    # fallback when the snapshot is missing (~25 s).
    if (os.getenv("VERCEL") and os.getenv("SEED_DEMO", "true") == "true"
            and not any(s.get("source") != "demo" for s in Store.submissions.values())):
        from .seed.generate_evidence import seed
        seed()
    build_demo()


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics() -> Response:
    return Response(content=metrics.render(), media_type="text/plain; version=0.0.4")


@app.get("/api/v1/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "soc-inspect", "time": now().isoformat()}


@app.get("/api/v1/readiness")
def readiness() -> dict[str, Any]:
    from .database import readiness_check
    ready, database = readiness_check()
    return {"status": "ready" if ready else "not_ready", "database": database,
            "artifact_storage": artifact_store.backend}


@app.post("/api/v1/submissions", status_code=201)
async def create_submission(request: Request, _user: dict[str, Any] = require_roles("data_provider", "admin")) -> dict[str, Any]:
    payload: Optional[Submission] = None
    file: Optional[UploadFile] = None
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        version = form.get("schema_version")
        if version is not None and str(version) not in SUPPORTED_SCHEMA_VERSIONS:
            raise error(422, f"Unsupported schema_version '{version}'; supported versions: 1.0")
        candidate = form.get("file")
        if candidate is not None and hasattr(candidate, "read") and hasattr(candidate, "filename"):
            file = candidate
    else:
        try:
            raw_payload = await request.json()
            if isinstance(raw_payload, dict):
                metadata = raw_payload.get("metadata") or {}
                version = raw_payload.get("schema_version", metadata.get("schema_version", "1.0"))
                if str(version) not in SUPPORTED_SCHEMA_VERSIONS:
                    raise error(422, f"Unsupported schema_version '{version}'; supported versions: 1.0")
                if "schema_version" not in metadata:
                    raw_payload["metadata"] = {**metadata, "schema_version": str(version)}
            payload = Submission.model_validate(raw_payload)
        except Exception as exc:
            if isinstance(exc, HTTPException):
                raise
            raise error(422, "Provide a valid JSON submission payload") from exc
    if payload is None and file is None:
        raise error(422, "Provide JSON payload or JSON, CSV, or XLSX file")
    original_bytes: bytes | None = None
    if file:
        try:
            original_bytes = await file.read()
            records, source = ingest_bytes(file.filename or "", original_bytes)
        except IngestionError as exc:
            raise error(400, str(exc)) from exc
        payload = Submission(name=file.filename or "upload", source=source, records=records)
    assert payload is not None
    records, issues = normalize_records(payload.records)
    sid = str(uuid.uuid4())
    if original_bytes is None:
        original_bytes = json.dumps(payload.model_dump(), sort_keys=True, default=str).encode()
    artifact = artifact_store.put("submissions", sid, original_bytes,
                                  (file.filename.rsplit(".", 1)[-1] if file and file.filename and "." in file.filename else "json"))
    item = {"id": sid, **payload.model_dump(), "records": records, "content_sha256": content_hash(records),
            "original_artifact": artifact.__dict__,
            "quality_issues": issues, "quality": {"issue_count": len(issues), "rows": len(records)},
            "created_at": now().isoformat()}
    Store.submissions[sid] = item
    index_records(item)
    persist_submission(item)
    invalidate_caches()
    _audit("dataset_uploaded", "data_provider", "data_provider", "submission", sid,
           "upload submission", None, {"records": len(records)}, None, "api")
    return item


@app.post("/api/v1/submissions/paste", status_code=201)
def create_paste_submission(payload: PasteSubmission, _user: dict[str, Any] = require_roles("data_provider", "admin")) -> dict[str, Any]:
    try:
        records = parse_pasted_logs(payload.text)
    except IngestionError as exc:
        raise error(422, str(exc)) from exc
    normalized, issues = normalize_records(records)
    sid = str(uuid.uuid4())
    original_bytes = payload.text.encode("utf-8")
    artifact = artifact_store.put("submissions", sid, original_bytes, "log")
    item = {"id": sid, "name": payload.name, "source": payload.source, "records": normalized,
            "metadata": {"schema_version": "1.0", "ingestion": "paste"},
            "content_sha256": content_hash(normalized), "original_artifact": artifact.__dict__,
            "quality_issues": issues, "quality": {"issue_count": len(issues), "rows": len(normalized)},
            "created_at": now().isoformat()}
    Store.submissions[sid] = item
    index_records(item)
    persist_submission(item)
    invalidate_caches()
    _audit("dataset_uploaded", "data_provider", "data_provider", "submission", sid,
           "upload pasted submission", None, {"records": len(normalized)}, None, "api")
    return item


@app.get("/api/v1/submissions/{submission_id}")
def get_submission(submission_id: str, _user: dict[str, Any] = require_roles("data_provider", "supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    if submission_id not in Store.submissions:
        raise error(404, "Submission not found")
    return Store.submissions[submission_id]


@app.get("/api/v1/submissions/{submission_id}/quality")
def get_submission_quality(submission_id: str, _user: dict[str, Any] = require_roles("data_provider", "supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    submission = Store.submissions.get(submission_id)
    if not submission:
        raise error(404, "Submission not found")
    return {"submission_id": submission_id, **submission["quality"], "issues": submission["quality_issues"]}


@app.post("/api/v1/assessments", status_code=201)
def create_assessment(request: AssessmentRequest, _user: dict[str, Any] = require_roles("supervisor", "admin", "data_provider")) -> dict[str, Any]:
    submission = Store.submissions.get(request.submission_id)
    if not submission:
        raise error(404, "Submission not found")
    aid = str(uuid.uuid4())
    metrics.assessment_stage("started")
    def run() -> dict[str, Any]:
        metrics.assessment_stage("rules")
        findings = execute_rules(submission, aid)
        Store.findings[aid] = findings
        assessment["status"] = "completed"
        assessment["summary"] = assessment_summary(findings, submission)
        metrics.assessment_stage("completed")
        persist_assessment(assessment, findings)
        return assessment
    assessment = {"id": aid, "submission_id": request.submission_id, "requested_by": request.requested_by,
                  "status": "running", "created_at": now().isoformat(), "summary": {}}
    try:
        status, result = submit_assessment(run)
    except Exception as exc:
        metrics.assessment_stage("failed")
        assessment["status"] = "failed"
        assessment["error"] = str(exc)
        Store.assessments[aid] = assessment
        persist_assessment(assessment, [])
        return assessment
    if status == "queued":
        metrics.assessment_stage("queued")
        assessment["status"] = "queued"
        assessment["task_id"] = result
        Store.assessments[aid] = assessment
        return assessment
    findings = Store.findings[aid]
    Store.assessments[aid] = assessment
    _audit("assessment_executed", request.requested_by, "supervisor", "assessment", aid,
           "execute assessment", "running", "completed", aid, "api")
    return assessment


@app.get("/api/v1/assessments/{assessment_id}")
def get_assessment(assessment_id: str, _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin", "data_provider")) -> dict[str, Any]:
    if assessment_id not in Store.assessments:
        raise error(404, "Assessment not found")
    return Store.assessments[assessment_id]


@app.get("/api/v1/assessments/{assessment_id}/status")
def get_assessment_status(assessment_id: str, _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin", "data_provider")) -> dict[str, Any]:
    assessment = Store.assessments.get(assessment_id)
    if not assessment:
        raise error(404, "Assessment not found")
    return {"assessment_id": assessment_id, "status": assessment["status"],
            "finding_count": len(Store.findings.get(assessment_id, []))}


@app.get("/api/v1/assessments/{assessment_id}/entities")
def get_assessment_entities(assessment_id: str, _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> list[dict[str, Any]]:
    if assessment_id not in Store.assessments:
        raise error(404, "Assessment not found")
    if assessment_id not in Store.findings:
        raise error(409, "Assessment is not completed")
    summary = Store.assessments[assessment_id]["summary"]
    return summary["entity_risk"]


@app.get("/api/v1/assessments/{assessment_id}/findings")
def get_findings(assessment_id: str, _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> list[dict[str, Any]]:
    if assessment_id not in Store.assessments:
        raise error(404, "Assessment not found")
    if assessment_id not in Store.findings:
        raise error(409, "Assessment is not completed")
    return Store.findings[assessment_id]


def _evidence_index() -> dict[str, dict[str, Any]]:
    """Lazily built map of row evidence ID (record:<id>#row-N) -> source record.

    Built once and cached on Store; invalidated whenever a submission is
    added/removed so uploaded rows are always indexed.
    """
    index = Store._evidence_index
    if index is None:
        index = {
            f"record:{submission.get('id')}#row-{row.get('_row')}": row
            for submission in Store.submissions.values()
            for row in submission.get("records", [])
        }
        Store._evidence_index = index
    return index


def invalidate_caches() -> None:
    Store._evidence_index = None


def _evidence_context(assessment_id: str, finding: dict[str, Any]) -> dict[str, Any]:
    assessment = Store.assessments.get(assessment_id)
    if not assessment:
        return {}
    row_index = _evidence_index()
    rows = [row_index[item] for item in finding.get("evidence", []) if item in row_index]
    return {
        "alert_ids": sorted({str(row["alert_id"]) for row in rows if row.get("alert_id")}),
        "asset_ids": sorted({str(row["asset_id"]) for row in rows if row.get("asset_id")}),
        "timestamps": sorted({str(row["timestamp"]) for row in rows if row.get("timestamp")}),
    }


@app.post("/api/v1/assessments/{assessment_id}/ask")
def ask_assessment(assessment_id: str, request: dict[str, str],
                   _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    if assessment_id not in Store.assessments:
        raise error(404, "Assessment not found")
    question = request.get("question", "").strip()
    submission = Store.submissions[Store.assessments[assessment_id]["submission_id"]]
    records_by_evidence = {
        f"record:{submission['id']}#row-{row['_row']}": row
        for row in submission["records"]
    }
    return answer_question(question, Store.findings.get(assessment_id, []), Store.entities, records_by_evidence)


@app.get("/api/v1/findings/{finding_id}/evidence")
def get_finding_evidence(finding_id: str, _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    for findings in Store.findings.values():
        for finding in findings:
            if finding["id"] == finding_id:
                return {"finding_id": finding_id, "evidence": finding["evidence"], "lineage": finding["lineage"],
                        "calculation": finding["calculation"], "limitations": finding["limitations"]}
    raise error(404, "Finding not found")


@app.post("/api/v1/assessments/{assessment_id}/review", status_code=201)
def review_assessment(assessment_id: str, request: ReviewRequest, _user: dict[str, Any] = require_roles("reviewer", "supervisor", "admin")) -> dict[str, Any]:
    if assessment_id not in Store.assessments:
        raise error(404, "Assessment not found")
    if request.finding_id and request.finding_id not in {f["id"] for f in Store.findings[assessment_id]}:
        raise error(404, "Finding not found")
    review = {"id": str(uuid.uuid4()), "assessment_id": assessment_id, **request.model_dump(),
              "created_at": now().isoformat()}
    Store.reviews.append(review)
    persist_review(review)
    record_audit_event("assessment_reviewed", request.reviewer, "assessment", assessment_id,
                       f"decision={request.decision}", assessment_id=assessment_id,
                       previous_state=None, new_state=request.decision,
                       role="supervisor", details={"finding_id": request.finding_id,
                                                   "annotation": request.annotation})
    return review


@app.get("/api/v1/assessments/{assessment_id}/report")
def assessment_report(assessment_id: str, verify: bool = True, format: str = "json", _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> Any:
    assessment = Store.assessments.get(assessment_id)
    if not assessment:
        raise error(404, "Assessment not found")
    submission = Store.submissions[assessment["submission_id"]]
    report = {"assessment": assessment, "submission": {"id": submission["id"], "content_sha256": submission["content_sha256"]},
              "findings": Store.findings[assessment_id], "reviews": [r for r in Store.reviews if r["assessment_id"] == assessment_id]}
    serialized = json.dumps(report, sort_keys=True, separators=(",", ":"), default=str).encode()
    report_hash = hashlib.sha256(serialized).hexdigest()
    report_artifact = artifact_store.put("reports", assessment_id, serialized, "json")
    report["report_sha256"] = report_hash
    report["report_artifact"] = report_artifact.__dict__
    report["hash_verified"] = (content_hash(submission["records"]) == submission["content_sha256"]) if verify else None
    from .reporting import render_soc_inspect_html, render_soc_inspect_pdf
    if format == "html":
        return HTMLResponse(render_soc_inspect_html(report, report_hash))
    if format == "pdf":
        pdf = render_soc_inspect_pdf(report, report_hash)
        return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=assessment-{assessment_id}.pdf"})
    if format != "json":
        raise error(400, "format must be json, html, or pdf")
    return report


@app.get("/api/v1/audit-events")
def audit_events(event_type: str | None = None, actor: str | None = None,
                 target_id: str | None = None,
                 _user: dict[str, Any] = require_roles("auditor", "admin", "supervisor", "reviewer")) -> list[dict[str, Any]]:
    items = Store.audit_events
    if event_type:
        items = [e for e in items if (e.get("event_type") or e.get("type")) == event_type]
    if actor:
        items = [e for e in items if e.get("actor") == actor]
    if target_id:
        items = [e for e in items if e.get("target_id") == target_id]
    return sorted(items, key=lambda e: e.get("timestamp", ""), reverse=True)


@app.get("/api/v1/audit-events/verify")
def audit_events_verify(_user: dict[str, Any] = require_roles("auditor", "admin", "supervisor", "reviewer")) -> dict[str, Any]:
    """Recompute the audit hash chain and report the first break, if any."""
    return verify_audit_chain(Store.audit_events)


@app.get("/api/v1/review-queue")
def review_queue(_user: dict[str, Any] = require_roles("reviewer", "supervisor", "admin")) -> list[dict[str, Any]]:
    queue = []
    demo_ids = _demo_assessment_ids()
    for aid, findings in Store.findings.items():
        if aid in demo_ids:
            continue
        for finding in findings:
            priority = {"critical": 100, "high": 70, "medium": 40, "low": 10}[finding["severity"]]
            queue.append({"assessment_id": aid, "finding_id": finding["id"], "priority": priority,
                          "severity": finding["severity"], "title": finding["title"], "entity_id": finding["entity_id"],
                          "rule": finding["rule"], "control": finding["rule"].split("_", 1)[0],
                          "evidence": _evidence_context(aid, finding)})
    # Priority remains primary, but round-robin entity/rule groups prevent a
    # single noisy entity or control from monopolising the queue.
    queue.sort(key=lambda x: (-x["priority"], x["entity_id"] or "", x["rule"]))
    grouped: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
    for item in queue:
        grouped.setdefault((item["entity_id"], item["rule"]), []).append(item)
    result = []
    while grouped:
        for key in list(grouped):
            result.append(grouped[key].pop(0))
            if not grouped[key]:
                del grouped[key]
    return result


def _sat_engine(entity_id: str | None = None, sector: str | None = None,
                start_date: str | None = None, end_date: str | None = None) -> SupervisoryAnalytics:
    """Build the analytics view from current persisted state (never duplicate metrics)."""
    submissions = []
    for submission in Store.submissions.values():
        # The built-in toy demo (alice/bob/...) is only for /demo/overview;
        # it must never mix with real supervisory entities.
        if submission.get("source") == "demo":
            continue
        rows = []
        for row in submission.get("records", []):
            eid = str(row.get("entity_id") or row.get("entity") or row.get("user")
                      or row.get("host") or "")
            row_sector = row.get("sector") or row.get("entity_sector") or row.get("sector_name")
            if entity_id and eid != entity_id:
                continue
            if sector and str(row_sector or "").lower() != sector.lower():
                continue
            ts = row.get("timestamp") or row.get("time")
            if start_date and (not ts or str(ts)[:10] < start_date):
                continue
            if end_date and (not ts or str(ts)[:10] > end_date):
                continue
            rows.append(row)
        if rows:
            submissions.append({**submission, "records": rows})
    declarations = [d for d in Store.declarations.values() if not entity_id or d.get("entity_id") == entity_id]
    return SupervisoryAnalytics({"submissions": submissions, "declarations": declarations})


def _sat_entities(engine: SupervisoryAnalytics, sector: str | None = None) -> list[dict[str, Any]]:
    result = []
    risk = {item["entity_id"]: item for item in engine.all_entity_risk_scores()}
    for eid, entity in sorted(engine.entities.items()):
        if sector and str(entity.get("sector") or "").lower() != sector.lower():
            continue
        item = {"entity_id": eid, "name": entity.get("entity_name", eid),
                "sector": entity.get("sector"), "criticality": entity.get("criticality")}
        item.update(risk.get(eid, {}))
        item["alerts"] = len(engine._alerts_by_entity.get(eid, []))
        item["cases"] = len(engine._cases_by_entity.get(eid, []))
        result.append(item)
    return result


def _sat_findings(entity_id: str | None = None, sector: str | None = None,
                  severity: str | None = None, status: str | None = None,
                  rule: str | None = None, category: str | None = None,
                  start_date: str | None = None, end_date: str | None = None) -> list[dict[str, Any]]:
    statuses = {}
    for review in Store.reviews:
        if review.get("finding_id"):
            statuses[review["finding_id"]] = _norm_status(review.get("status", "NEW"))
    allowed_entities = set(_sat_engine(sector=sector).entities) if sector else None
    demo_ids = _demo_assessment_ids()
    row_index = _evidence_index()
    result = []
    for aid, findings in Store.findings.items():
        if aid in demo_ids:
            continue
        for finding in findings:
            fid = finding.get("id")
            current = statuses.get(fid, "NEW")
            if entity_id and finding.get("entity_id") != entity_id:
                continue
            if allowed_entities is not None and finding.get("entity_id") not in allowed_entities:
                continue
            if severity and str(finding.get("severity", "")).lower() != severity.lower():
                continue
            if status and current != _norm_status(status):
                continue
            if rule and finding.get("rule") != rule:
                continue
            finding_category = finding.get("category") or RULE_CATEGORIES.get(finding.get("rule"), "")
            if category and finding_category != category:
                continue
            evidence_dates = []
            for ev in finding.get("evidence", []):
                row = row_index.get(str(ev))
                if row is not None and row.get("timestamp"):
                    evidence_dates.append(str(row["timestamp"])[:10])
            if start_date and (not evidence_dates or max(evidence_dates) < start_date):
                continue
            if end_date and (not evidence_dates or min(evidence_dates) > end_date):
                continue
            result.append({**finding, "category": finding_category, "review_status": current})
    return result


def _audit(event_type: str, actor: str, role: str, target_type: str, target_id: str,
             action: str, prev: Any = None, new: Any = None, assessment_id: str | None = None,
             source: str = "api") -> dict[str, Any]:
    event = {"id": str(uuid.uuid4()), "timestamp": now().isoformat(), "event_type": event_type,
             "actor": actor, "role": role, "target_type": target_type, "target_id": target_id,
             "action": action, "previous_state": prev, "new_state": new,
             "assessment_id": assessment_id, "source": source}
    _seal_audit_event(event)
    # keep legacy keys for backwards-compat views
    event["type"] = event_type
    event["details"] = {"action": action, "previous_state": prev, "new_state": new}
    Store.audit_events.append(event)
    try:
        persist_audit_event(event)
    except Exception:
        pass
    return event


def _demo_assessment_ids() -> set[str]:
    """Assessment IDs backed by the built-in toy demo (excluded from supervision)."""
    demo_subs = {sid for sid, s in Store.submissions.items() if s.get("source") == "demo"}
    return {aid for aid, a in Store.assessments.items()
            if a.get("submission_id") in demo_subs or a.get("requested_by") == "demo"}


def _all_supervisory_findings() -> list[dict[str, Any]]:
    demo = _demo_assessment_ids()
    return [f for aid, fs in Store.findings.items() if aid not in demo for f in fs]


def _entity_compliance_view(engine: Any, findings: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    from .compliance import (classify, compliance_summary, evaluate_entity_controls,
                             recommended_action, risk_with_drivers)
    findings = findings if findings is not None else _all_supervisory_findings()
    by_entity: dict[str, list[dict]] = {}
    for f in findings:
        by_entity.setdefault(str(f.get("entity_id") or ""), []).append(f)
    peer = engine.peer_benchmark()
    views = []
    for eid, entity in sorted(engine.entities.items()):
        alerts = engine._alerts_by_entity.get(eid, [])
        cases = engine._cases_by_entity.get(eid, [])
        inv_by_case = {cid: inv for cid, inv in engine._inv_by_case.items()
                       if engine._cases_by_id.get(cid, {}).get("entity_id") == eid}
        esc_by_case = {cid: e for cid, e in engine._esc_by_case.items()
                       if engine._cases_by_id.get(cid, {}).get("entity_id") == eid}
        resp_by_case = {cid: r for cid, r in engine._resp_by_case.items()
                        if engine._cases_by_id.get(cid, {}).get("entity_id") == eid}
        rem_by_case = {cid: r for cid, r in engine._rem_by_case.items()
                       if engine._cases_by_id.get(cid, {}).get("entity_id") == eid}
        subs = engine._subs_by_entity.get(eid, [])
        pc = (peer.get("entities", {}).get(eid, {}).get("peer_comparison", {}))
        esc_dev = pc.get("escalation_rate", {}).get("deviation", 0) if isinstance(pc, dict) else 0
        ctx = {"entity_id": eid, "alerts": alerts, "cases": cases, "inv_by_case": inv_by_case,
               "esc_by_case": esc_by_case, "resp_by_case": resp_by_case, "rem_by_case": rem_by_case,
               "assets": engine._assets_by_entity.get(eid, []), "submissions": subs,
               "peer_deviation": esc_dev}
        controls = evaluate_entity_controls(ctx)
        summ = compliance_summary(controls)
        ef = by_entity.get(eid, [])
        sev = Counter(str(f.get("severity", "")).lower() for f in ef)
        # Critical *control* failure (spec §30): a critical-domain control
        # (escalation/response/closure/investigation coverage) has SEVERELY
        # broken down (NON_COMPLIANT with coverage < 50%), or critical
        # findings are systemic (>=5). A merely weak control (50-59%) leaves
        # the entity PARTIALLY_COMPLIANT rather than failing it outright.
        crit_ctrl_fail = any(c["control_id"] in ("ES-01", "IR-01", "CL-01", "IN-01")
                             and c["status"] == "NON_COMPLIANT" and (c["coverage"] or 100) < 50
                             for c in controls)
        has_crit = crit_ctrl_fail or sev.get("critical", 0) >= 5
        status = classify(summ, has_crit)
        if status == "COMPLIANT" and sev.get("critical", 0) > 0:
            # Spec §30: COMPLIANT requires no critical unresolved finding.
            # A high-scoring entity with isolated critical gaps caps at PARTIAL.
            status = "PARTIALLY_COMPLIANT"
        # Spec §30: COMPLIANT requires no critical unresolved finding.
        # An entity with critical findings caps at PARTIALLY_COMPLIANT.
        if status == "COMPLIANT" and sev.get("critical", 0) > 0:
            status = "PARTIALLY_COMPLIANT"
        risk = risk_with_drivers(ctx, controls, ef)
        peer_vals = sorted([(k, v.get("value"), v.get("peer_median"), v.get("deviation"), v.get("percentile"))
                            for k, v in (pc.items() if isinstance(pc, dict) else [])])
        views.append({"entity_id": eid, "entity_name": entity.get("entity_name", eid),
                      "sector": entity.get("sector"), "status": status,
                      "compliance_score": summ["compliance_score"],
                      "evidence_coverage": summ["evidence_coverage"],
                      "risk_score": risk["risk_score"], "risk_drivers": risk["risk_drivers"],
                      "controls_assessed": summ["controls_assessed"], "compliant": summ["compliant"],
                      "partially_compliant": summ["partially_compliant"], "non_compliant": summ["non_compliant"],
                      "insufficient_evidence": summ["insufficient_evidence"],
                      "critical": sev.get("critical", 0), "high": sev.get("high", 0),
                      "medium": sev.get("medium", 0), "low": sev.get("low", 0),
                      "controls": controls, "peer": peer_vals,
                      "recommended_action": recommended_action(status, risk["risk_score"], sev.get("critical", 0), summ["evidence_coverage"]),
                      "alerts": len(alerts), "cases": len(cases)})
    # rank: non-compliant/critical first, then risk desc, compliance asc
    order = {"NON_COMPLIANT": 0, "INSUFFICIENT_EVIDENCE": 1, "PARTIALLY_COMPLIANT": 2, "COMPLIANT": 3, "NOT_ASSESSED": 4}
    views.sort(key=lambda v: (order.get(v["status"], 5), -v["risk_score"], v["compliance_score"]))
    for i, v in enumerate(views, 1):
        v["rank"] = i
    return views


@app.get("/api/v1/analytics/overview")
def analytics_overview(entity_id: str | None = None, sector: str | None = None,
                       severity: str | None = None, start_date: str | None = None,
                       end_date: str | None = None,
                       _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    from .compliance import RULE_VERSION, data_quality_score, reporting_coverage, workflow_funnel
    engine = _sat_engine(entity_id, sector, start_date, end_date)
    comp = _entity_compliance_view(engine)
    dist = Counter(v["status"] for v in comp)
    sev = Counter(str(a.get("severity", "")).lower() for a in engine.alerts if str(a.get("severity", "")).lower() in ("low", "medium", "high", "critical"))
    crit = [f for f in _all_supervisory_findings() if str(f.get("severity", "")).lower() == "critical"]
    high = [f for f in _all_supervisory_findings() if str(f.get("severity", "")).lower() == "high"]
    avg_comp = round(statistics.fmean([v["compliance_score"] for v in comp]), 1) if comp else 0.0
    avg_ev = round(statistics.fmean([v["evidence_coverage"] for v in comp]), 1) if comp else 0.0
    dq = data_quality_score(engine.alerts, engine.cases, engine.assets, engine.submissions)
    # alerts over time (month granularity)
    by_month: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for a in engine.alerts:
        ts = str(a.get("timestamp") or "")[:7]
        if len(ts) == 7:
            by_month[ts]["total"] += 1
            by_month[ts][str(a.get("severity", "")).lower()] += 1
    trend = [{"month": m, **vals} for m, vals in sorted(by_month.items())]
    # sector compliance
    sectors: dict[str, list[dict]] = defaultdict(list)
    for v in comp:
        sectors[v.get("sector") or "Unspecified"].append(v)
    sector_rows = []
    for s, items in sorted(sectors.items()):
        c = Counter(x["status"] for x in items)
        n = len(items)
        sector_rows.append({"sector": s, "entities": n,
                            "compliance_pct": round(sum(x["compliance_score"] for x in items) / n, 1) if n else 0,
                            "non_compliant_pct": round(c.get("NON_COMPLIANT", 0) / n * 100, 1) if n else 0,
                            "insufficient_pct": round(c.get("INSUFFICIENT_EVIDENCE", 0) / n * 100, 1) if n else 0,
                            **{k.lower(): c.get(k, 0) for k in ("COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE")}})
    # control performance (avg coverage per domain)
    dom_cov: dict[str, list[float]] = defaultdict(list)
    for v in comp:
        for c in v["controls"]:
            if c["coverage"] is not None:
                dom_cov[c["domain"]].append(c["coverage"])
    control_perf = [{"domain": d, "score": round(statistics.fmean(v), 1)} for d, v in sorted(dom_cov.items())]
    gaps = engine.all_execution_gaps()
    gap_by_rule = [{"rule": k, "count": v} for k, v in sorted(Counter(g.get("rule") for g in gaps).items(), key=lambda x: -x[1])]
    dq_issues = [{"issue": i.get("type"), "count": i.get("count")} for i in dq_overview(engine)]
    funnel = workflow_funnel(engine.alerts, engine._inv_by_case, engine._esc_by_case, engine._resp_by_case, engine.cases)
    needs_attention = sum(1 for v in comp if v["status"] in ("NON_COMPLIANT", "INSUFFICIENT_EVIDENCE") or v["recommended_action"] == "IMMEDIATE REVIEW")
    weakest = sorted(control_perf, key=lambda x: x["score"])[:2]
    esc_missing = sum(1 for a in engine.alerts if a.get("escalation_required") and not (a.get("escalation_id") or (a.get("case_id") and a["case_id"] in engine._esc_by_case)))
    summary = (f"{len(comp)} entities were assessed across {len(sectors)} sectors. "
               f"{needs_attention} entities require supervisory attention. "
               f"{dist.get('NON_COMPLIANT', 0)} entities are non-compliant. "
               f"{dist.get('INSUFFICIENT_EVIDENCE', 0)} entities have insufficient evidence. "
               f"{', '.join(w['domain'] for w in weakest) if weakest else 'No control data'} "
               f"{'are' if len(weakest) != 1 else 'is'} the weakest control domain(s). "
               f"{esc_missing} critical/high alerts lacked required escalation evidence.")
    sub = next(iter(Store.submissions.values()), {})
    return {"kpis": {"entities_assessed": len(comp), "compliant": dist.get("COMPLIANT", 0),
                     "partially_compliant": dist.get("PARTIALLY_COMPLIANT", 0),
                     "non_compliant": dist.get("NON_COMPLIANT", 0),
                     "insufficient_evidence": dist.get("INSUFFICIENT_EVIDENCE", 0),
                     "critical_findings": len(crit), "high_findings": len(high),
                     "overall_compliance_pct": avg_comp, "evidence_completeness_pct": avg_ev,
                     "data_quality_pct": dq["overall"]},
            "executive_summary": summary,
            "compliance_distribution": [{"status": k, "count": v,
                                         "pct": round(v / max(len(comp), 1) * 100, 1)} for k, v in dist.items()],
            "severity": [{"severity": k, "count": v} for k, v in sev.items()],
            "alert_trend": trend, "sector_compliance": sector_rows,
            "risk_vs_compliance": [{"entity_id": v["entity_id"], "entity_name": v["entity_name"],
                                    "compliance": v["compliance_score"], "risk": v["risk_score"],
                                    "status": v["status"]} for v in comp],
            "control_performance": control_perf, "execution_gaps": gap_by_rule,
            "data_quality_issues": dq_issues, "workflow_funnel": funnel,
            "attention_matrix": comp, "reporting": reporting_coverage(engine.submissions),
            "rule_version": RULE_VERSION, "dataset_sha256": sub.get("content_sha256"),
            "disclaimer": "SYNTHETIC DEMONSTRATION DATA. Simulated SOC records for demonstration and testing only; not an assessment of the named organizations."}


def dq_overview(engine: Any) -> list[dict[str, Any]]:
    dq = engine.data_quality()
    return dq.get("issues", [])


@app.get("/api/v1/analytics/compliance")
def analytics_compliance(sector: str | None = None,
                         _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine(None, sector)
    items = _entity_compliance_view(engine)
    return {"items": items, "total": len(items),
            "method": "COMPLIANT=100, PARTIAL=50, NON_COMPLIANT=0, INSUFFICIENT excluded; score=weighted avg of evidenced controls; coverage=evidenced/expected"}


@app.get("/api/v1/analytics/entities/{entity_id}")
def analytics_entity(entity_id: str,
                     _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    from .compliance import data_quality_score, workflow_funnel
    engine = _sat_engine(entity_id)
    if entity_id not in engine.entities:
        raise error(404, "Entity not found")
    comp = next((v for v in _entity_compliance_view(engine) if v["entity_id"] == entity_id), None)
    detail = engine.entity_detail(entity_id)
    alerts = engine._alerts_by_entity.get(entity_id, [])
    cases = engine._cases_by_entity.get(entity_id, [])
    funnel = workflow_funnel(alerts, engine._inv_by_case, engine._esc_by_case, engine._resp_by_case, cases)
    dq = data_quality_score(alerts, cases, engine._assets_by_entity.get(entity_id, []), engine._subs_by_entity.get(entity_id, []))
    peer = engine.peer_benchmark()
    ent_peer = peer.get("entities", {}).get(entity_id, {})
    findings = [f for fs in Store.findings.values() for f in fs if f.get("entity_id") == entity_id]
    # evidence-enriched findings (cap evidence preview, keep full lineage)
    enriched = []
    for f in findings:
        rows = _finding_rows(f)
        enriched.append({**f, "affected_record_count": len(rows),
                         "source_rows": rows[:25], "evidence_ids": f.get("evidence", [])[:25]})
    return {"compliance": comp, "detail": detail, "funnel": funnel, "data_quality": dq,
            "peer": ent_peer, "sector_benchmarks": peer.get("sector_benchmarks", {}),
            "findings": enriched}


def _finding_rows(finding: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    row_index = _evidence_index()
    for key in finding.get("evidence", []):
        r = row_index.get(str(key))
        if r is not None:
            rows.append({"record_id": key, "alert_id": r.get("alert_id"), "case_id": r.get("case_id"),
                         "timestamp": r.get("timestamp"), "entity_id": r.get("entity_id"),
                         "severity": r.get("severity"), "asset_id": r.get("asset_id"),
                         "status": r.get("status")})
    return rows


@app.get("/api/v1/analytics/workflow")
def analytics_workflow(entity_id: str | None = None, sector: str | None = None,
                       _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    from .compliance import workflow_funnel
    engine = _sat_engine(entity_id, sector)
    return {"funnel": workflow_funnel(engine.alerts, engine._inv_by_case, engine._esc_by_case, engine._resp_by_case, engine.cases)}


@app.get("/api/v1/analytics/data-quality")
def analytics_dq(entity_id: str | None = None, sector: str | None = None,
                 _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    from .compliance import data_quality_score
    engine = _sat_engine(entity_id, sector)
    overall = data_quality_score(engine.alerts, engine.cases, engine.assets, engine.submissions)
    by_entity = {}
    for eid in engine.entities:
        by_entity[eid] = data_quality_score(engine._alerts_by_entity.get(eid, []),
                                            engine._cases_by_entity.get(eid, []),
                                            engine._assets_by_entity.get(eid, []),
                                            engine._subs_by_entity.get(eid, []))
    return {"overall": overall, "by_entity": by_entity}


@app.get("/api/v1/analytics/peer-benchmark")
def analytics_peer(entity_id: str | None = None, sector: str | None = None,
                   _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine(None, sector)
    peer = engine.peer_benchmark()
    comp = {v["entity_id"]: v for v in _entity_compliance_view(engine)}
    return {"peer": peer, "compliance": comp, "focus_entity": entity_id}


@app.get("/api/v1/analytics/findings-grouped")
def analytics_findings_grouped(entity_id: str | None = None, sector: str | None = None,
                               severity: str | None = None,
                               _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    items = _sat_findings(entity_id, sector, severity)
    grouped: dict[tuple, dict[str, Any]] = {}
    for f in items:
        key = (f.get("rule"), f.get("entity_id"))
        g = grouped.setdefault(key, {"rule": f.get("rule"), "title": f.get("title"),
                                     "entity_id": f.get("entity_id"), "severity": f.get("severity"),
                                     "domain": f.get("category") or RULE_CATEGORIES.get(f.get("rule"), ""),
                                     "finding_ids": [], "affected_alerts": set(), "affected_assets": set(),
                                     "evidence_ids": [], "sample": None})
        g["finding_ids"].append(f.get("id"))
        ctx = _evidence_context(next(iter(Store.assessments), ""), f) if Store.assessments else {}
        for a in (ctx.get("alert_ids") or []):
            g["affected_alerts"].add(a)
        for a in (ctx.get("asset_ids") or []):
            g["affected_assets"].add(a)
        g["evidence_ids"].extend(f.get("evidence", []))
        if g["sample"] is None:
            g["sample"] = f
    rows = []
    for g in grouped.values():
        n = max(len(g["affected_alerts"]), len(set(g["evidence_ids"])), len(g["finding_ids"]))
        rows.append({"rule": g["rule"], "title": g["title"], "entity_id": g["entity_id"],
                     "severity": g["severity"], "domain": g["domain"],
                     "affected_records": n, "affected_alerts": sorted(g["affected_alerts"])[:50],
                     "affected_assets": len(g["affected_assets"]), "finding_ids": g["finding_ids"],
                     "primary_finding_id": (g["sample"] or {}).get("id"),
                     "calculation": (g["sample"] or {}).get("calculation", "")})
    rows.sort(key=lambda r: (-{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(r["severity"]).lower(), 0), -(r["affected_records"])))
    return {"items": rows, "total": len(rows)}


@app.get("/api/v1/analytics/severity")
def analytics_severity(entity_id: str | None = None, sector: str | None = None,
                       start_date: str | None = None, end_date: str | None = None,
                       _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine(entity_id, sector, start_date, end_date)
    sev = Counter(str(a.get("severity", "") or "unknown").lower() for a in engine.alerts)
    total = max(len(engine.alerts), 1)
    return {"items": [{"severity": k, "count": v, "pct": round(v / total * 100, 1)}
                      for k, v in sorted(sev.items())],
            "total": len(engine.alerts),
            "method": "Share of alerts per severity class; missing severity counted as unknown (insufficient evidence)."}


@app.get("/api/v1/analytics/sectors")
def analytics_sectors(_user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine()
    comp = _entity_compliance_view(engine)
    sectors: dict[str, list[dict]] = defaultdict(list)
    for v in comp:
        sectors[v.get("sector") or "Unspecified"].append(v)
    rows = []
    for s, items in sorted(sectors.items()):
        c = Counter(x["status"] for x in items)
        n = len(items)
        alerts = sum(x["alerts"] for x in items)
        rows.append({"sector": s, "entities": n, "alerts": alerts,
                     "compliance_pct": round(sum(x["compliance_score"] for x in items) / n, 1) if n else 0,
                     "non_compliant_pct": round(c.get("NON_COMPLIANT", 0) / n * 100, 1) if n else 0,
                     "insufficient_pct": round(c.get("INSUFFICIENT_EVIDENCE", 0) / n * 100, 1) if n else 0,
                     "compliant": c.get("COMPLIANT", 0),
                     "partially_compliant": c.get("PARTIALLY_COMPLIANT", 0),
                     "non_compliant": c.get("NON_COMPLIANT", 0),
                     "insufficient_evidence": c.get("INSUFFICIENT_EVIDENCE", 0)})
    return {"items": rows, "total": len(rows)}


@app.get("/api/v1/analytics/entities")
def analytics_entities(sector: str | None = None,
                       _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine(None, sector)
    items = _entity_compliance_view(engine)
    return {"items": items, "total": len(items),
            "method": "Per-entity compliance, risk with drivers, evidence coverage and recommended action."}


@app.get("/api/v1/analytics/execution-gaps")
def analytics_execution_gaps(entity_id: str | None = None, sector: str | None = None,
                             severity: str | None = None,
                             _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine(entity_id, sector)
    items = [{**g, "domain": g.get("capability"), "affected_records": g.get("affected_count")}
             for g in engine.all_execution_gaps()]
    if severity:
        items = [x for x in items if str(x.get("severity", "")).lower() == severity.lower()]
    by_rule = Counter(str(g.get("rule")) for g in items)
    by_sev = Counter(str(g.get("severity", "")).lower() for g in items)
    by_entity = Counter(str(g.get("entity_id")) for g in items)
    return {"items": items, "total": len(items),
            "by_rule": [{"rule": k, "count": v} for k, v in by_rule.most_common()],
            "by_severity": [{"severity": k, "count": v} for k, v in by_sev.most_common()],
            "by_entity": [{"entity_id": k, "count": v} for k, v in by_entity.most_common()],
            "affected_entities": len(by_entity)}


def _alert_compliance_state(a: dict[str, Any], inv_by_case: dict, esc_by_case: dict) -> str:
    if not a.get("timestamp") or not str(a.get("severity", "")).lower() in ("low", "medium", "high", "critical"):
        return "INSUFFICIENT_EVIDENCE"
    if a.get("escalation_required") and not a.get("escalation_id"):
        return "NON_COMPLIANT"
    cid = a.get("case_id")
    if not cid:
        return "PARTIALLY_COMPLIANT"
    if cid not in inv_by_case:
        return "PARTIALLY_COMPLIANT"
    return "COMPLIANT"


def _alert_rows(entity_id: str | None = None, sector: str | None = None,
                severity: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
    engine = _sat_engine(entity_id, sector)
    rows = []
    for a in engine.alerts:
        if severity and str(a.get("severity", "")).lower() != severity.lower():
            continue
        cid = a.get("case_id")
        rows.append({"alert_id": a.get("alert_id"), "timestamp": a.get("timestamp"),
                     "entity_id": a.get("entity_id"), "asset_id": a.get("asset_id"),
                     "severity": str(a.get("severity", "") or "unknown"),
                     "status": a.get("status", ""), "case_id": cid or "",
                     "investigation": "present" if cid and cid in engine._inv_by_case else "missing",
                     "escalation": "escalated" if a.get("escalation_id") else
                                   ("required_missing" if a.get("escalation_required") else "not_required"),
                     "response": "present" if cid and cid in engine._resp_by_case else "missing",
                     "closure": engine._cases_by_id.get(cid, {}).get("status", "") if cid else "",
                     "compliance_state": _alert_compliance_state(a, engine._inv_by_case, engine._esc_by_case)})
    rows.sort(key=lambda r: str(r["timestamp"] or ""), reverse=True)
    return rows[:max(1, min(limit, 5000))]


@app.get("/api/v1/analytics/alerts")
def analytics_alerts(entity_id: str | None = None, sector: str | None = None,
                     severity: str | None = None, limit: int = 500,
                     start_date: str | None = None, end_date: str | None = None,
                     _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine(entity_id, sector, start_date, end_date)
    agg = engine.alert_analytics(entity_id if not sector else None, severity)
    items = _alert_rows(entity_id, sector, severity, limit)
    req = sum(1 for a in engine.alerts if a.get("escalation_required"))
    no_case = sum(1 for a in engine.alerts if not a.get("case_id"))
    no_inv = sum(1 for a in engine.alerts if a.get("case_id") and a["case_id"] not in engine._inv_by_case)
    no_resp = sum(1 for a in engine.alerts if a.get("case_id") and a["case_id"] not in engine._resp_by_case)
    return {**agg, "items": items, "returned": len(items),
            "alerts_requiring_escalation": req,
            "alerts_without_case": no_case,
            "alerts_without_investigation": no_inv,
            "alerts_without_response": no_resp}


@app.get("/api/v1/analytics/investigations")
def analytics_investigations(entity_id: str | None = None, sector: str | None = None,
                             limit: int = 500,
                             _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine(entity_id, sector)
    agg = engine.investigation_analytics(entity_id if not sector else None)
    items = []
    for c in engine.cases:
        inv = engine._inv_by_case.get(c["case_id"])
        if inv:
            dur = inv.get("duration_minutes")
            items.append({"investigation_id": inv.get("investigation_id", c["case_id"]),
                          "case_id": c["case_id"], "alert_id": c.get("alert_id", ""),
                          "entity_id": c.get("entity_id", ""),
                          "analyst_id": inv.get("analyst_id", ""),
                          "started": inv.get("start_time", ""), "completed": inv.get("end_time", ""),
                          "duration_minutes": dur,
                          "conclusion": inv.get("conclusion") or "MISSING CONCLUSION",
                          "status": "completed" if inv.get("conclusion") else "missing_conclusion",
                          "sla_breach": bool(dur is not None and dur > 240)})
        else:
            items.append({"investigation_id": "", "case_id": c["case_id"],
                          "alert_id": c.get("alert_id", ""), "entity_id": c.get("entity_id", ""),
                          "analyst_id": "", "started": "", "completed": "",
                          "duration_minutes": None, "conclusion": "NO INVESTIGATION",
                          "status": "missing", "sla_breach": False})
    missing_conclusion = sum(1 for i in items if i["status"] == "missing_conclusion")
    missing = sum(1 for i in items if i["status"] == "missing")
    sla = sum(1 for i in items if i["sla_breach"])
    measured = [i["duration_minutes"] for i in items if i["duration_minutes"] is not None]
    import statistics as _st
    return {**agg, "items": items[:max(1, min(limit, 5000))], "returned": min(len(items), limit),
            "missing_investigation": missing, "missing_conclusion": missing_conclusion,
            "sla_breach_count": sla,
            "avg_investigation_minutes": round(_st.fmean(measured), 1) if measured else None}


@app.get("/api/v1/analytics/escalations")
def analytics_escalations(entity_id: str | None = None, sector: str | None = None,
                          limit: int = 500,
                          _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine(entity_id, sector)
    agg = engine.escalation_analytics(entity_id if not sector else None)
    req = [a for a in engine.alerts if a.get("escalation_required")]
    items = []
    for a in sorted(req, key=lambda x: str(x.get("timestamp") or ""), reverse=True)[:max(1, min(limit, 5000))]:
        esc = engine._esc_by_case.get(a.get("case_id") or "", {})
        items.append({"alert_id": a.get("alert_id"), "timestamp": a.get("timestamp"),
                      "entity_id": a.get("entity_id"), "severity": a.get("severity"),
                      "case_id": a.get("case_id") or "",
                      "escalation_id": a.get("escalation_id") or esc.get("escalation_id", "") or "",
                      "escalation_status": "escalated" if (a.get("escalation_id") or esc) else "required_missing",
                      "escalation_timestamp": esc.get("escalation_time", ""),
                      "response": "present" if (a.get("case_id") or "") in engine._resp_by_case else "missing"})
    return {**agg, "items": items, "returned": len(items),
            "not_escalated": sum(1 for i in items if i["escalation_status"] == "required_missing")}


@app.get("/api/v1/analytics/monitoring")
def analytics_monitoring(entity_id: str | None = None, sector: str | None = None,
                         _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    engine = _sat_engine(entity_id, sector)
    agg = engine.monitoring_analytics(entity_id if not sector else None)
    alerted = {a.get("asset_id") for a in engine.alerts if a.get("asset_id")}
    items = [{"asset_id": a.get("asset_id"), "entity_id": a.get("entity_id"),
              "asset_type": a.get("asset_type", ""), "criticality": a.get("criticality", ""),
              "monitoring_status": "monitored" if a.get("asset_id") in alerted else "gap",
              "expected_monitoring": bool(a.get("expected_monitoring", True))}
             for a in engine.assets]
    return {**agg, "items": items, "returned": len(items),
            "unmonitored_assets": sum(1 for i in items if i["monitoring_status"] == "gap")}


@app.get("/api/v1/analytics/finding-evidence/{finding_id}")
def analytics_finding_evidence(finding_id: str,
                               _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    finding = next((f for fs in Store.findings.values() for f in fs if f.get("id") == finding_id), None)
    if finding is None:
        raise error(404, "Finding not found")
    rows = _finding_rows(finding)
    statuses = {r.get("finding_id"): r.get("status") for r in Store.reviews if r.get("finding_id")}
    return {"finding_id": finding_id, "rule": finding.get("rule"), "rule_version": finding.get("rule_version", "rules-1.0"),
            "entity_id": finding.get("entity_id"), "severity": finding.get("severity"),
            "domain": finding.get("category") or RULE_CATEGORIES.get(finding.get("rule"), ""),
            "title": finding.get("title"), "description": finding.get("description"),
            "calculation": finding.get("calculation", ""),
            "affected_record_count": len(rows), "evidence_ids": finding.get("evidence", []),
            "source_rows": rows[:50], "review_status": statuses.get(finding_id, "NEW")}


@app.get("/api/v1/sat/overview")
def sat_overview(entity_id: str | None = None, sector: str | None = None,
                 start_date: str | None = None, end_date: str | None = None,
                 _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    return _sat_engine(entity_id, sector, start_date, end_date).overview()


@app.get("/api/v1/sat/entities")
def sat_entities(sector: str | None = None, _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    items = _sat_entities(_sat_engine(sector=sector), sector)
    return {"items": items, "entities": items, "total": len(items)}


@app.get("/api/v1/sat/entities/{entity_id}")
def sat_entity(entity_id: str, _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    detail = _sat_engine(entity_id).entity_detail(entity_id)
    if not detail:
        raise error(404, "Entity not found")
    return detail


def _sat_analytics(kind: str, entity_id: str | None, sector: str | None,
                   start_date: str | None, end_date: str | None,
                   severity: str | None = None) -> Any:
    engine = _sat_engine(entity_id, sector, start_date, end_date)
    if kind == "alert_analytics":
        return engine.alert_analytics(entity_id, severity)
    return getattr(engine, kind)(entity_id if kind in {"investigation_analytics",
                                                       "escalation_analytics", "monitoring_analytics"} else None)


@app.get("/api/v1/sat/alerts")
def sat_alerts(entity_id: str | None = None, sector: str | None = None,
               severity: str | None = None, start_date: str | None = None, end_date: str | None = None,
               _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
               data = _sat_analytics("alert_analytics", entity_id, sector, start_date, end_date, severity)
               return data


@app.get("/api/v1/sat/investigations")
def sat_investigations(entity_id: str | None = None, sector: str | None = None,
                       start_date: str | None = None, end_date: str | None = None,
                       _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    return _sat_analytics("investigation_analytics", entity_id, sector, start_date, end_date)


@app.get("/api/v1/sat/escalations")
def sat_escalations(entity_id: str | None = None, sector: str | None = None,
                    start_date: str | None = None, end_date: str | None = None,
                    _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    return _sat_analytics("escalation_analytics", entity_id, sector, start_date, end_date)


@app.get("/api/v1/sat/monitoring")
def sat_monitoring(entity_id: str | None = None, sector: str | None = None,
                   start_date: str | None = None, end_date: str | None = None,
                   _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    return _sat_analytics("monitoring_analytics", entity_id, sector, start_date, end_date)


@app.get("/api/v1/sat/execution-gaps")
def sat_execution_gaps(entity_id: str | None = None, sector: str | None = None,
                       severity: str | None = None,
                       _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    items = _sat_engine(entity_id, sector).all_execution_gaps()
    if severity:
        items = [x for x in items if x.get("severity") == severity.lower()]
    return {"items": items, "signals": items, "total": len(items)}


@app.get("/api/v1/sat/negative-space")
def sat_negative_space(entity_id: str | None = None, sector: str | None = None,
                       severity: str | None = None,
                       _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    items = _sat_engine(entity_id, sector).all_negative_space()
    if severity:
        items = [x for x in items if x.get("severity") == severity.lower()]
    return {"items": items, "signals": items, "total": len(items)}


@app.get("/api/v1/sat/entities/{entity_id}/examination-plan")
def sat_examination_plan(entity_id: str) -> dict[str, Any]:
    plan = _sat_engine().examination_plan(entity_id)
    if not plan:
        raise error(404, "Entity not found")
    return plan


def store_declarations(records: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
    """Validate and store declared KPI values (entity_id, metric, declared_value)."""
    from .analytics import SupervisoryAnalytics as _SA
    rows = []
    for index, record in enumerate(records, 1):
        eid, metric = str(record.get("entity_id") or "").strip(), str(record.get("metric") or "").strip()
        try:
            value = float(record.get("declared_value"))
        except (TypeError, ValueError):
            raise error(422, f"row {index}: declared_value must be a number")
        if not eid or metric not in _SA.DECLARABLE_METRICS or not 0 <= value <= 100:
            raise error(422, f"row {index}: need entity_id, metric in {sorted(_SA.DECLARABLE_METRICS)}, value 0-100")
        rows.append({"entity_id": eid, "metric": metric, "declared_value": value,
                     "source": str(record.get("source") or source), "created_at": now().isoformat()})
    for row in rows:
        Store.declarations[f"{row['entity_id']}|{row['metric']}"] = row
    persist_declarations(rows)
    return rows


@app.post("/api/v1/declarations", status_code=201)
async def upload_declarations(request: Request,
                              _user: dict[str, Any] = require_roles("data_provider", "admin", "supervisor")) -> dict[str, Any]:
    """Upload a CSE self-assessment (CSV/JSON/XLSX file field `file`, or a JSON list body)."""
    if request.headers.get("content-type", "").startswith("multipart/"):
        form = await request.form()
        upload = form.get("file")
        if upload is None or not hasattr(upload, "read"):
            raise error(422, "multipart field 'file' is required")
        try:
            records, _ = ingest_bytes(upload.filename or "upload.csv", await upload.read())
        except IngestionError as exc:
            raise error(422, str(exc))
        source = f"self-assessment:{upload.filename}"
    else:
        records = await request.json()
        source = "self-assessment:api"
    if not isinstance(records, list) or not records:
        raise error(422, "expected a non-empty list of declarations")
    rows = store_declarations(records, source)
    _audit("declarations_uploaded", "data_provider", "data_provider", "declarations", source,
           "upload self-assessment", None, {"rows": len(rows)}, None, "api")
    return {"stored": len(rows), "entities": sorted({r["entity_id"] for r in rows})}


@app.get("/api/v1/validation/summary")
def validation_summary_endpoint() -> dict[str, Any]:
    """Tool effectiveness vs ground truth, random manual sampling and examiner decisions."""
    from .validation import validation_summary
    return validation_summary(_sat_engine(), _sat_findings())


@app.get("/api/v1/sat/declared-vs-observed")
def sat_declared_vs_observed(entity_id: str | None = None) -> dict[str, Any]:
    items = _sat_engine().declared_vs_observed(entity_id)
    return {"items": items, "count": len(items)}


@app.get("/api/v1/sat/peer-benchmark")
def sat_peer_benchmark(sector: str | None = None, _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    data = _sat_engine(sector=sector).peer_benchmark()
    if sector:
        data["sector_benchmarks"] = {sector: data["sector_benchmarks"].get(sector, {})}
    return data


@app.get("/api/v1/sat/findings")
def sat_findings(entity_id: str | None = None, sector: str | None = None, severity: str | None = None,
                 status: str | None = None, rule: str | None = None, category: str | None = None,
                 start_date: str | None = None, end_date: str | None = None,
                 _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    items = _sat_findings(entity_id, sector, severity, status, rule, category, start_date, end_date)
    return {"items": items, "findings": items, "total": len(items)}


@app.get("/api/v1/sat/data-quality")
def sat_data_quality(entity_id: str | None = None, sector: str | None = None,
                     _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    data = _sat_engine(entity_id, sector).data_quality()
    return data


@app.get("/api/v1/sat/review-queue")
def sat_review_queue(entity_id: str | None = None, sector: str | None = None,
                     severity: str | None = None, status: str | None = None, rule: str | None = None,
                     category: str | None = None,
                     _user: dict[str, Any] = require_roles("reviewer", "supervisor", "auditor", "admin")) -> dict[str, Any]:
    items = _sat_findings(entity_id, sector, severity, status, rule, category)
    items.sort(key=lambda x: (-{"critical": 100, "high": 70, "medium": 40, "low": 10}.get(x.get("severity"), 0), x.get("id", "")))
    return {"items": items, "queue": items, "total": len(items)}


@app.patch("/api/v1/sat/review-queue/{finding_id}")
@app.post("/api/v1/sat/review-queue/{finding_id}/status")
def sat_review_status(finding_id: str, request: SATReviewRequest,
                      _user: dict[str, Any] = require_roles("reviewer", "supervisor", "admin")) -> dict[str, Any]:
    status = _norm_status(request.status)
    if status not in REVIEW_STATUSES:
        raise error(422, f"status must be one of {', '.join(sorted(REVIEW_STATUSES))}")
    finding = next((f for fs in Store.findings.values() for f in fs if f.get("id") == finding_id), None)
    if finding is None:
        raise error(404, "Finding not found")
    prev = next((r.get("status") for r in reversed(Store.reviews) if r.get("finding_id") == finding_id), "NEW")
    aid = next(aid for aid, fs in Store.findings.items() if finding in fs)
    review = {"id": str(uuid.uuid4()), "assessment_id": aid,
              "finding_id": finding_id, "reviewer": request.reviewer, "status": status,
              "annotation": request.annotation, "created_at": now().isoformat()}
    Store.reviews.append(review)
    persist_review(review)
    event_type = {"VALIDATED": "finding_validated", "REJECTED": "finding_rejected",
                  "DISMISSED": "finding_rejected", "REQUIRES_EVIDENCE": "evidence_requested",
                  "CLOSED": "finding_closed"}.get(status, "finding_opened")
    _audit(event_type, request.reviewer, "reviewer", "finding", finding_id,
           f"{prev} -> {status}", prev, status, aid, "api")
    return review


@app.get("/api/v1/sat/sample")
def sat_sample(entity_id: str | None = None, target_size: int = 80, control_size: int = 20,
                _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> dict[str, Any]:
    if target_size < 1 or control_size < 0 or target_size > 10000:
        raise error(422, "target_size must be between 1 and 10000 and control_size cannot be negative")
    return _sat_engine(entity_id).recommended_sample(entity_id, target_size, control_size)


@app.get("/api/v1/sat/report")
def sat_report(entity_id: str | None = None, sector: str | None = None,
               format: str = "json",
               _user: dict[str, Any] = require_roles("supervisor", "reviewer", "auditor", "admin")) -> Any:
    from .compliance import RULE_VERSION, data_quality_score, workflow_funnel
    engine = _sat_engine(entity_id, sector)
    comp = _entity_compliance_view(engine)
    dist = {k: sum(1 for v in comp if v["status"] == k) for k in ("COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE")}
    sev = Counter(str(f.get("severity", "")).lower() for fs in Store.findings.values() for f in fs)
    dq = data_quality_score(engine.alerts, engine.cases, engine.assets, engine.submissions)
    sub = next(iter(Store.submissions.values()), {})
    actions = [{"entity_id": v["entity_id"], "entity_name": v["entity_name"], "status": v["status"],
                "action": v["recommended_action"], "risk": v["risk_score"]} for v in comp]
    report = {"title": "SAT-SA Supervisory Assessment Report",
              "disclaimer": "SYNTHETIC DEMONSTRATION DATA. Simulated SOC records for demonstration/testing only; does not represent actual posture of named organizations.",
              "executive_summary": f"{len(comp)} entities assessed; {dist.get('NON_COMPLIANT',0)} non-compliant; {dist.get('INSUFFICIENT_EVIDENCE',0)} insufficient evidence; critical findings {sev.get('critical',0)}; high {sev.get('high',0)}.",
              "assessment_scope": {"entity_filter": entity_id, "sector_filter": sector, "period": "2026-01 to 2026-09"},
              "dataset": {"records": len(engine.alerts), "sha256": sub.get("content_sha256"), "rule_version": RULE_VERSION, "generated_at": now().isoformat()},
              "compliance_distribution": dist, "entities": comp,
              "sector_benchmark": engine.peer_benchmark().get("sector_benchmarks", {}),
              "critical_findings": [f for f in _all_supervisory_findings() if str(f.get("severity","")).lower()=="critical"][:100],
              "high_findings": [f for f in _all_supervisory_findings() if str(f.get("severity","")).lower()=="high"][:100],
              "execution_gaps": engine.all_execution_gaps(), "negative_space": engine.all_negative_space(),
              "peer_benchmark": engine.peer_benchmark(), "data_quality": dq,
              "workflow": workflow_funnel(engine.alerts, engine._inv_by_case, engine._esc_by_case, engine._resp_by_case, engine.cases),
              "recommended_actions": actions,
              "methodology": "Compliance: COMPLIANT=100/PARTIAL=50/NON=0, INSUFFICIENT excluded; weighted avg. Risk: escalation failures + monitoring + SLA + data quality + peer deviation + severity findings, capped 100. Evidence coverage = evidenced controls / expected.",
              "rule_version": RULE_VERSION, "dataset_hash": sub.get("content_sha256"),
              "assessment_timestamp": now().isoformat(),
              "limitations": ["Periodic submission only; supervisor validation required.", "Missing evidence reported as insufficient evidence, never compliant.", "Synthetic demonstration data."],
              "findings": _sat_findings(entity_id, sector)}
    _audit("report_generated", "supervisor", "supervisor", "report", "sat-report", f"generate {format} report", None, {"entities": len(comp)}, None, "api")
    from .reporting import render_html, render_pdf
    if format == "json":
        return report
    if format == "html":
        return HTMLResponse(render_html(report))
    if format == "pdf":
        pdf = render_pdf(report)
        return Response(content=pdf, media_type="application/pdf",
                        headers={"Content-Disposition": "attachment; filename=sat-supervisory-report.pdf"})
    raise error(422, "format must be json, html, or pdf")


@app.get("/api/v1/demo/overview")
def demo_overview() -> dict[str, Any]:
    """Return a dashboard-shaped view over the built-in synthetic assessment."""
    build_demo()
    submission = next(iter(Store.submissions.values()))
    assessment = next(
        (item for item in Store.assessments.values() if item["submission_id"] == submission["id"]),
        None,
    )
    if assessment is None:
        aid = str(uuid.uuid4())
        findings = execute_rules(submission, aid)
        Store.findings[aid] = findings
        assessment = {
            "id": aid,
            "submission_id": submission["id"],
            "requested_by": "demo",
            "status": "completed",
            "created_at": now().isoformat(),
            "summary": assessment_summary(findings, submission),
        }
        Store.assessments[aid] = assessment
    elif not all("risk_score" in item for item in assessment.get("summary", {}).get("entity_risk", [])):
        findings = execute_rules(submission, assessment["id"])
        Store.findings[assessment["id"]] = findings
        assessment["summary"] = assessment_summary(findings, submission)
        persist_assessment(assessment, findings)

    findings = Store.findings[assessment["id"]]
    risk_by_entity = {
        item["entity_id"]: item for item in assessment["summary"]["entity_risk"]
    }
    entity_names = {
        entity_id: Store.entities.get(entity_id, {}).get("name", entity_id)
        for entity_id in risk_by_entity
    }
    entities = [
        {
            "entity_id": entity_id,
            "name": entity_names[entity_id],
            "sector": risk_by_entity[entity_id].get("sector"),
            "risk_score": risk_by_entity[entity_id]["risk_score"],
            "risk_level": risk_by_entity[entity_id]["tier"],
            "scoring": risk_by_entity[entity_id],
        }
        for entity_id, score_data in sorted(risk_by_entity.items(), key=lambda pair: -pair[1]["risk_score"])
    ]
    top_finding = max(
        findings,
        key=lambda finding: ({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
            str(finding.get("severity", "")), 0), len(finding.get("evidence", []))),
        default=None,
    )
    # Capabilities are computed from the analytics engine, never hard-coded.
    try:
        _engine = _sat_engine()
        _caps = _engine.capability_scores()
        capabilities = [
            {"name": name, "score": round(statistics.fmean([d[name]["score"] for d in _caps.values() if name in d]), 1)}
            for name in ("Threat Detection", "Investigation", "Escalation", "Incident Response",
                         "Security Operations", "Governance & Oversight",
                         "Operational Discipline", "Cyber Resilience")
            if any(name in d for d in _caps.values())
        ]
    except Exception:
        capabilities = []
    return {
        "assessment_id": assessment["id"],
        "summary": {
            "entities": len(entities),
            "alerts": len(submission["records"]),
            "review_candidates": len(findings),
            "critical_findings": assessment["summary"]["by_severity"]["critical"],
        },
        "entities": entities,
        "headline_finding": (
            {
                "title": top_finding["title"],
                "description": top_finding["description"],
                "entity_id": top_finding["entity_id"],
                "severity": top_finding["severity"].value if isinstance(top_finding["severity"], Severity) else top_finding["severity"],
                "finding_id": top_finding["id"],
                "evidence_count": len(top_finding["evidence"]),
            } if top_finding else None
        ),
        "capabilities": capabilities,
        "findings": [
            {
                "finding_id": finding["id"],
                "severity": finding["severity"].value if isinstance(finding["severity"], Severity) else finding["severity"],
                "title": finding["title"],
                "rationale": finding["description"],
                "entity_id": finding["entity_id"],
                "evidence_count": len(finding["evidence"]),
            }
            for finding in findings
        ],
    }
