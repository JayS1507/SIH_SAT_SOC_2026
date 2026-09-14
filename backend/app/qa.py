from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from typing import Any

from .taxonomy import RULE_ALIASES, RULE_CATEGORIES


RULE_IDS = set(RULE_CATEGORIES)
SEVERITIES = ("critical", "high", "medium", "low")


def _date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def parse_question(question: str, entities: dict[str, dict[str, Any]]) -> tuple[dict[str, Any] | None, str | None]:
    text = question.strip().lower()
    if not text:
        return None, "The question is empty."
    entity_matches = [entity_id for entity_id in entities if re.search(rf"\b{re.escape(entity_id.lower())}\b", text)]
    entity_id = None
    if len(entity_matches) > 1:
        return None, "The question matches multiple entities."
    if entity_matches:
        entity_id = entity_matches[0]

    sectors = {str(item.get("sector")).lower() for item in entities.values() if item.get("sector")}
    known_sector_terms = sectors | {"banking", "finance", "power", "energy", "healthcare", "telecom", "government"}
    sector_matches = [sector for sector in known_sector_terms if re.search(rf"\b{re.escape(sector)}\b", text)]
    if len(sector_matches) > 1:
        return None, "The question matches multiple sectors."
    sector = sector_matches[0] if sector_matches else None

    rule_id = next((rule for rule in RULE_IDS if rule in text), None)
    if rule_id is None:
        for alias, canonical in sorted(RULE_ALIASES.items(), key=lambda item: -len(item[0])):
            if alias in text:
                rule_id = canonical
                break
    category = next((category for category in ("execution_gap", "negative_space") if category.replace("_", " ") in text or category in text), None)
    severity = next((level for level in SEVERITIES if re.search(rf"\b{level}\b", text)), None)

    time_range: dict[str, str] | None = None
    range_match = re.search(r"(20\d{2}-\d{2}-\d{2})\s+(?:to|-)\s+(20\d{2}-\d{2}-\d{2})", text)
    since_match = re.search(r"(?:since|after)\s+(20\d{2}-\d{2}-\d{2})", text)
    before_match = re.search(r"before\s+(20\d{2}-\d{2}-\d{2})", text)
    if range_match:
        time_range = {"since": range_match.group(1), "until": range_match.group(2)}
    elif since_match:
        time_range = {"since": since_match.group(1)}
    elif before_match:
        time_range = {"until": before_match.group(1)}
    elif "this month" in text:
        today = datetime.now(timezone.utc).date()
        time_range = {"since": today.replace(day=1).isoformat(), "until": today.isoformat()}
    elif "this quarter" in text:
        today = datetime.now(timezone.utc).date()
        start_month = ((today.month - 1) // 3) * 3 + 1
        time_range = {"since": today.replace(month=start_month, day=1).isoformat(), "until": today.isoformat()}

    if any(word in text for word in ("rate", "percentage", "proportion")):
        metric = "rate"
    elif any(word in text for word in ("trend", "over time", "weekly", "monthly", "increasing", "decreasing")):
        metric = "trend"
    elif any(word in text for word in ("which", "what", "how many", "number of", "count")):
        metric = "count"
    else:
        return None, "The question does not specify a supported metric."
    if sector and sector not in sectors:
        return None, "Sector metadata is not available in this assessment."
    if entity_id is None and len(entities) > 1 and re.search(r"\bentity\b", text):
        return None, "The question does not identify a unique entity."
    return {
        "entity_id": entity_id,
        "sector": sector,
        "rule_id": rule_id,
        "rule_category": category or (RULE_CATEGORIES.get(rule_id) if rule_id else None),
        "severity": severity,
        "time_range": time_range,
        "metric": metric,
    }, None


def _in_time_range(finding: dict[str, Any], records_by_evidence: dict[str, dict[str, Any]], time_range: dict[str, str] | None) -> bool:
    if not time_range:
        return True
    timestamps = []
    for evidence_id in finding.get("evidence", []):
        row = records_by_evidence.get(evidence_id)
        if row and row.get("timestamp"):
            try:
                timestamps.append(datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00")).date())
            except ValueError:
                pass
    if not timestamps:
        return False
    return all((not time_range.get("since") or value >= date.fromisoformat(time_range["since"])) and
               (not time_range.get("until") or value <= date.fromisoformat(time_range["until"]))
               for value in timestamps)


def answer_question(question: str, findings: list[dict[str, Any]], entities: dict[str, dict[str, Any]],
                    records_by_evidence: dict[str, dict[str, Any]]) -> dict[str, Any]:
    intent, error = parse_question(question, entities)
    if error:
        return {"answer": error, "intent": None, "finding_ids": [], "evidence_ids": [], "confidence": "unresolved"}
    selected = findings
    if intent["entity_id"]:
        selected = [item for item in selected if item.get("entity_id") == intent["entity_id"]]
    if intent["sector"]:
        selected = [item for item in selected if entities.get(item.get("entity_id"), {}).get("sector", "").lower() == intent["sector"]]
    if intent["rule_id"]:
        selected = [item for item in selected if item.get("rule") == intent["rule_id"]]
    if intent["rule_category"]:
        selected = [item for item in selected if RULE_CATEGORIES.get(item.get("rule")) == intent["rule_category"]]
    if intent["severity"]:
        selected = [item for item in selected if str(getattr(item.get("severity"), "value", item.get("severity", ""))).lower() == intent["severity"]]
    selected = [item for item in selected if _in_time_range(item, records_by_evidence, intent["time_range"])]
    finding_ids = [item["id"] for item in selected]
    evidence_ids = sorted({evidence for item in selected for evidence in item.get("evidence", []) + item.get("lineage", [])})
    if intent["metric"] == "count":
        answer = f"{len(selected)} matching finding(s) grounded in {len(evidence_ids)} evidence reference(s)."
    elif intent["metric"] == "rate":
        answer = f"{len(selected)} matching finding(s) grounded in {len(evidence_ids)} evidence reference(s); rate requires a submitted record denominator."
    else:
        answer = f"{len(selected)} matching finding(s) grounded in {len(evidence_ids)} evidence reference(s); trend is limited to available evidence timestamps."
    return {"answer": answer, "intent": intent, "finding_ids": finding_ids, "evidence_ids": evidence_ids, "confidence": "resolved"}
