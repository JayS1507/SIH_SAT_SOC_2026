"""Canonical field mapping for flat SOC records (legacy + relational CSV schema).

The relational demo CSV uses explicit *_id / *_status / *_timestamp columns.
Legacy uploads use boolean flags (escalated/responded/investigated).
This module derives uniform boolean evidence flags without inventing evidence.
"""
from __future__ import annotations

from typing import Any

TRUE_TOKENS = {"true", "1", "yes", "y", "required", "yes-required", "mandatory"}
ESC_DONE = {"completed", "done", "escalated", "acknowledged", "acked", "closed", "open-escalated", "in_progress", "in-progress"}
RESP_DONE = {"completed", "done", "contained", "mitigated", "resolved", "in_progress", "in-progress", "responded"}
INV_DONE = {"completed", "done", "closed", "in_progress", "in-progress", "investigated", "investigating"}


def _s(v: Any) -> str:
    return str(v or "").strip().lower()


def truthy(v: Any) -> bool:
    if v is True:
        return True
    if v is False or v is None:
        return False
    return _s(v) in TRUE_TOKENS


def falsy_explicit(v: Any) -> bool:
    return _s(v) in {"false", "0", "no", "n", "not_required", "not-required", "not required", "na", "n/a", "none"}


def escalation_required(row: dict[str, Any]) -> bool:
    """Explicit flag wins; otherwise critical/high severity implies required."""
    if "escalation_required" in row and row.get("escalation_required") not in (None, ""):
        v = row.get("escalation_required")
        if truthy(v):
            return True
        if falsy_explicit(v):
            return False
        return False
    return _s(row.get("severity")) in {"critical", "high"}


def is_escalated(row: dict[str, Any]) -> bool:
    if row.get("escalated") is True:
        return True
    if row.get("escalation_id"):
        return True
    st = _s(row.get("escalation_status"))
    if st in ESC_DONE:
        return True
    if row.get("escalation_timestamp"):
        return True
    return False


def is_investigated(row: dict[str, Any]) -> bool:
    if row.get("investigated") is True:
        return True
    if row.get("investigation_id"):
        return True
    if _s(row.get("investigation_status")) in INV_DONE:
        return True
    if row.get("investigation_started") or row.get("investigation_completed"):
        return True
    if row.get("conclusion") or row.get("investigation_conclusion"):
        return True
    return False


def is_responded(row: dict[str, Any]) -> bool:
    if row.get("responded") is True:
        return True
    if row.get("response_id"):
        return True
    if _s(row.get("response_status")) in RESP_DONE:
        return True
    if row.get("response_timestamp") or row.get("responded_at") or row.get("response_at"):
        return True
    return False


def is_closed(row: dict[str, Any]) -> bool:
    if _s(row.get("closure_status")) in {"closed", "completed", "resolved", "done"}:
        return True
    if row.get("closure_id") or row.get("closure_timestamp"):
        return True
    return _s(row.get("status") or row.get("case_status")) in {"closed", "resolved"}


def conclusion(row: dict[str, Any]) -> str:
    return str(row.get("investigation_conclusion") or row.get("conclusion") or "").strip()


def inv_end(row: dict[str, Any]) -> Any:
    return row.get("investigation_completed") or row.get("investigation_time") or row.get("end_time")


def closure_time(row: dict[str, Any]) -> Any:
    return row.get("closure_timestamp") or row.get("closure_time") or row.get("closed_at")
