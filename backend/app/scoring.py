from __future__ import annotations

import math
import statistics
from typing import Any

from .taxonomy import RULE_CATEGORIES


SEVERITY_WEIGHTS = {"low": 1.0, "medium": 3.0, "high": 7.0, "critical": 12.0}
MAX_EVIDENCE_STRENGTH = 1.0
MAX_Z = 3.0
PEER_DEVIATION_FACTOR = 0.10


def _severity_value(value: Any) -> str:
    return str(getattr(value, "value", value)).lower()


def evidence_strength(finding: dict[str, Any]) -> float:
    signals = (
        min(len(finding.get("evidence", [])), 3) / 3,
        min(len(finding.get("lineage", [])), 2) / 2,
        1.0 if any(str(item).startswith("submission:") for item in finding.get("lineage", [])) else 0.0,
        1.0 if finding.get("calculation") else 0.0,
    )
    return max(0.0, min(statistics.fmean(signals), MAX_EVIDENCE_STRENGTH))


def _z_score(rate: float, peer_rates: list[float]) -> float:
    if len(peer_rates) < 2:
        return 0.0
    mean = statistics.fmean(peer_rates)
    deviation = statistics.pstdev(peer_rates)
    return 0.0 if deviation == 0 else (rate - mean) / deviation


def calculate_entity_risk(
    findings: list[dict[str, Any]],
    entity_records: dict[str, int],
    entities: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        grouped.setdefault(str(finding.get("entity_id") or "unknown"), []).append(finding)

    rates = {
        entity_id: len(entity_findings) / max(entity_records.get(entity_id, 1), 1)
        for entity_id, entity_findings in grouped.items()
    }
    all_entity_ids = sorted(set(entity_records) | set(grouped))
    sector_rates: dict[str, list[float]] = {}
    for entity_id in all_entity_ids:
        sector = entities.get(entity_id, {}).get("sector")
        if sector is not None:
            sector_rates.setdefault(str(sector), []).append(rates.get(entity_id, 0.0))

    results: list[dict[str, Any]] = []
    for entity_id in all_entity_ids:
        entity_findings = grouped.get(entity_id, [])
        volume = len(entity_findings)
        sector = entities.get(entity_id, {}).get("sector")
        peers = sector_rates.get(str(sector), []) if sector is not None else []
        raw_z = _z_score(rates.get(entity_id, 0.0), peers)
        bounded_z = max(-MAX_Z, min(raw_z, MAX_Z))
        peer_multiplier = 1.0 + PEER_DEVIATION_FACTOR * bounded_z
        category_burdens = {
            "execution_gap": sum(
                SEVERITY_WEIGHTS.get(_severity_value(finding.get("severity", "")), 0.0)
                * evidence_strength(finding)
                for finding in entity_findings
                if RULE_CATEGORIES.get(finding.get("rule")) == "execution_gap"
            ),
            "negative_space": sum(
                SEVERITY_WEIGHTS.get(_severity_value(finding.get("severity", "")), 0.0)
                * evidence_strength(finding)
                for finding in entity_findings
                if RULE_CATEGORIES.get(finding.get("rule")) == "negative_space"
            ),
        }
        base_burden = sum(
            SEVERITY_WEIGHTS.get(_severity_value(finding.get("severity", "")), 0.0)
            * evidence_strength(finding)
            for finding in entity_findings
        )
        worst_case = volume * max(SEVERITY_WEIGHTS.values()) * MAX_EVIDENCE_STRENGTH * (1 + PEER_DEVIATION_FACTOR * MAX_Z)
        score = 0.0 if worst_case == 0 else 100.0 * base_burden * peer_multiplier / worst_case
        if score > 100.0 + 1e-9:
            raise AssertionError("risk score exceeded its theoretical maximum")
        results.append({
            "entity_id": entity_id,
            "sector": sector,
            "score": score,
            "risk_score": score,
            "tier": "critical" if score >= 70 else "high" if score >= 40 else "medium",
            "base_burden": base_burden,
            "peer_adjusted_burden": base_burden * peer_multiplier,
            "genuine_worst_case_burden": worst_case,
            "raw_z": raw_z,
            "bounded_z": bounded_z,
            "peer_multiplier": peer_multiplier,
            "finding_volume": volume,
            "finding_rate": rates.get(entity_id, 0.0),
            "evidence_strengths": [evidence_strength(finding) for finding in entity_findings],
            "category_burdens": category_burdens,
            "category_scores": {
                category: (100.0 * burden * peer_multiplier / worst_case if worst_case else 0.0)
                for category, burden in category_burdens.items()
            },
            "contributing_factors": [
                {
                    "finding_id": finding.get("id"),
                    "rule": finding.get("rule"),
                    "severity": _severity_value(finding.get("severity", "")),
                    "evidence_strength": evidence_strength(finding),
                    "weighted_contribution": round(
                        SEVERITY_WEIGHTS.get(_severity_value(finding.get("severity", "")), 0.0)
                        * evidence_strength(finding), 6
                    ),
                }
                for finding in sorted(entity_findings, key=lambda item: str(item.get("id", "")))
            ],
        })
    return sorted(results, key=lambda item: (-item["risk_score"], item["entity_id"]))
