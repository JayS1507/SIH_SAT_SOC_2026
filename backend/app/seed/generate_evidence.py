"""Deterministic synthetic SOC evidence generator for SAT-SA demonstration.

ALL DATA IS SYNTHETIC. Entity names are used for demonstration purposes only.
No real cybersecurity weaknesses are implied for any real organization.

Uses fixed seed 26157 for full reproducibility.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class EntityProfile(dict):
    """Mapping used by the generator with legacy tuple-unpacking support."""
    def __iter__(self):
        yield self["id"]
        yield self["name"]
        yield self["sector"]
        yield self["archetype"]

# ---------------------------------------------------------------------------
# Entity definitions (20 CSEs across 10 sectors — SYNTHETIC DEMONSTRATION ONLY)
# ---------------------------------------------------------------------------

SEED = 26157

# Global volume scale keeps the demo fast (<20k alerts) while preserving
# archetype behaviour and relational structure.
VOLUME_SCALE = 0.12

ENTITIES: list[dict[str, Any]] = [
    # Real PSU names used as SYNTHETIC DEMONSTRATION PROFILES ONLY.
    # Weaknesses below are simulated archetypes, not real assessments.
    {"id": "ongc",   "name": "Oil and Natural Gas Corporation (ONGC)",   "sector": "Oil & Gas",                "criticality": "critical", "archetype": "good_minor_gap"},
    {"id": "ntpc",   "name": "NTPC Limited",                            "sector": "Power & Energy",            "criticality": "critical", "archetype": "escalation_gap"},
    {"id": "coal",   "name": "Coal India Limited",                      "sector": "Mining",                    "criticality": "high",     "archetype": "under_reporting"},
    {"id": "iocl",   "name": "Indian Oil Corporation Limited (IOCL)",   "sector": "Petroleum & Refining",      "criticality": "critical", "archetype": "response_failure"},
    {"id": "hal",    "name": "Hindustan Aeronautics Limited (HAL)",     "sector": "Defence & Aerospace",       "criticality": "critical", "archetype": "strong_mature"},
    {"id": "gail",   "name": "GAIL (India) Limited",                    "sector": "Natural Gas",               "criticality": "high",     "archetype": "investigation_failure"},
    {"id": "bel",    "name": "Bharat Electronics Limited (BEL)",        "sector": "Electronics & Defence",     "criticality": "critical", "archetype": "strong_mature"},
    {"id": "bhel",   "name": "Bharat Heavy Electricals Limited (BHEL)", "sector": "Heavy Engineering",         "criticality": "high",     "archetype": "mixed_moderate"},
    {"id": "mazagon","name": "Mazagon Dock Shipbuilders Limited",       "sector": "Shipbuilding",              "criticality": "high",     "archetype": "data_quality_problem"},
    {"id": "pgcil",  "name": "Power Grid Corporation of India",         "sector": "Power & Energy",            "criticality": "critical", "archetype": "strong_high_volume"},
    {"id": "bpcl",   "name": "Bharat Petroleum Corporation Limited",    "sector": "Petroleum & Refining",      "criticality": "high",     "archetype": "good_minor_gap"},
    {"id": "hpcl",   "name": "Hindustan Petroleum Corporation Limited", "sector": "Petroleum & Refining",      "criticality": "high",     "archetype": "fast_closure"},
    {"id": "rail",   "name": "Indian Railway Critical Infrastructure",  "sector": "Transport",                 "criticality": "critical", "archetype": "mixed_moderate"},
    # Fictional CSEs
    {"id": "nts",    "name": "National Telecom Systems",                "sector": "Telecom",                   "criticality": "critical", "archetype": "data_quality_problem"},
    {"id": "mbc",    "name": "Meridian Banking Corporation",            "sector": "Banking & Finance",         "criticality": "critical", "archetype": "strong_mature"},
    {"id": "epl",    "name": "Eastern Port Logistics",                  "sector": "Transport",                 "criticality": "high",     "archetype": "under_reporting"},
    {"id": "npg",    "name": "National Payments Grid",                  "sector": "Banking & Finance",         "criticality": "critical", "archetype": "good_minor_gap"},
    {"id": "cpa",    "name": "Chennai Port Authority Systems",          "sector": "Transport",                 "criticality": "high",     "archetype": "monitoring_gap"},
    {"id": "das",    "name": "Deccan Airspace Systems",                 "sector": "Defence & Aerospace",       "criticality": "critical", "archetype": "premature_closure"},
    {"id": "sgc",    "name": "Solar Grid Corporation of India",         "sector": "Power & Energy",            "criticality": "high",     "archetype": "under_reporting"},
]

# Remove the duplicate MDL entry - keep mazagon only
ENTITIES = [e for e in ENTITIES if e["id"] != "mdl"]
ENTITIES = [EntityProfile(e) for e in ENTITIES]

# Supervisory archetype aliases (spec §21) -> generator parameter sets
ARCHETYPE_ALIASES = {
    "STRONG_COMPLIANCE": "strong_mature",
    "GOOD_WITH_MINOR_GAPS": "strong_high_volume",
    "ESCALATION_FAILURE": "escalation_gap",
    "INVESTIGATION_FAILURE": "template_investigation",
    "RESPONSE_FAILURE": "escalation_gap",
    "MONITORING_GAP": "under_reporting",
    "DATA_QUALITY_FAILURE": "data_quality_problem",
    "UNDER_REPORTING": "under_reporting",
    "PREMATURE_CLOSURE": "fast_closure",
    "MIXED_RISK": "mixed_moderate",
}

# ---------------------------------------------------------------------------
# Archetype parameters
# ---------------------------------------------------------------------------

ARCHETYPE_PARAMS: dict[str, dict[str, Any]] = {
    "strong_mature": {
        "alert_volume_factor": 1.0,
        "investigation_coverage": 0.96,
        "escalation_coverage": 0.92,
        "response_coverage": 0.90,
        "fast_closure_rate": 0.03,
        "template_rate": 0.05,
        "missing_evidence_rate": 0.02,
        "remediation_rate": 0.85,
        "monitoring_coverage": 0.95,
        "investigation_duration_mean": 120,
        "investigation_duration_std": 45,
        "escalation_latency_mean": 25,
        "data_quality_issue_rate": 0.01,
    },
    "fast_closure": {
        "alert_volume_factor": 0.9,
        "investigation_coverage": 0.94,
        "escalation_coverage": 0.85,
        "response_coverage": 0.82,
        "fast_closure_rate": 0.45,
        "template_rate": 0.12,
        "missing_evidence_rate": 0.08,
        "remediation_rate": 0.60,
        "monitoring_coverage": 0.88,
        "investigation_duration_mean": 12,
        "investigation_duration_std": 8,
        "escalation_latency_mean": 15,
        "data_quality_issue_rate": 0.02,
    },
    "escalation_gap": {
        "alert_volume_factor": 1.1,
        "investigation_coverage": 0.88,
        "escalation_coverage": 0.52,
        "response_coverage": 0.65,
        "fast_closure_rate": 0.08,
        "template_rate": 0.07,
        "missing_evidence_rate": 0.12,
        "remediation_rate": 0.70,
        "monitoring_coverage": 0.85,
        "investigation_duration_mean": 90,
        "investigation_duration_std": 50,
        "escalation_latency_mean": 65,
        "data_quality_issue_rate": 0.03,
    },
    "under_reporting": {
        "alert_volume_factor": 0.35,
        "investigation_coverage": 0.80,
        "escalation_coverage": 0.70,
        "response_coverage": 0.65,
        "fast_closure_rate": 0.06,
        "template_rate": 0.10,
        "missing_evidence_rate": 0.15,
        "remediation_rate": 0.55,
        "monitoring_coverage": 0.58,
        "investigation_duration_mean": 95,
        "investigation_duration_std": 40,
        "escalation_latency_mean": 45,
        "data_quality_issue_rate": 0.05,
    },
    "repeated_alert": {
        "alert_volume_factor": 1.2,
        "investigation_coverage": 0.85,
        "escalation_coverage": 0.78,
        "response_coverage": 0.75,
        "fast_closure_rate": 0.10,
        "template_rate": 0.15,
        "missing_evidence_rate": 0.10,
        "remediation_rate": 0.40,
        "monitoring_coverage": 0.82,
        "investigation_duration_mean": 75,
        "investigation_duration_std": 35,
        "escalation_latency_mean": 35,
        "repeated_asset_rate": 0.40,
        "data_quality_issue_rate": 0.02,
    },
    "template_investigation": {
        "alert_volume_factor": 0.95,
        "investigation_coverage": 0.92,
        "escalation_coverage": 0.80,
        "response_coverage": 0.78,
        "fast_closure_rate": 0.06,
        "template_rate": 0.55,
        "missing_evidence_rate": 0.05,
        "remediation_rate": 0.65,
        "monitoring_coverage": 0.87,
        "investigation_duration_mean": 60,
        "investigation_duration_std": 20,
        "escalation_latency_mean": 30,
        "data_quality_issue_rate": 0.02,
    },
    "kpi_optimization": {
        "alert_volume_factor": 1.0,
        "investigation_coverage": 0.97,
        "escalation_coverage": 0.94,
        "response_coverage": 0.92,
        "fast_closure_rate": 0.30,
        "template_rate": 0.20,
        "missing_evidence_rate": 0.04,
        "remediation_rate": 0.90,
        "monitoring_coverage": 0.93,
        "investigation_duration_mean": 18,
        "investigation_duration_std": 10,
        "escalation_latency_mean": 10,
        "data_quality_issue_rate": 0.01,
    },
    "mixed_moderate": {
        "alert_volume_factor": 1.0,
        "investigation_coverage": 0.87,
        "escalation_coverage": 0.75,
        "response_coverage": 0.72,
        "fast_closure_rate": 0.08,
        "template_rate": 0.10,
        "missing_evidence_rate": 0.08,
        "remediation_rate": 0.65,
        "monitoring_coverage": 0.82,
        "investigation_duration_mean": 85,
        "investigation_duration_std": 40,
        "escalation_latency_mean": 40,
        "data_quality_issue_rate": 0.03,
    },
    "strong_high_volume": {
        "alert_volume_factor": 1.8,
        "investigation_coverage": 0.93,
        "escalation_coverage": 0.90,
        "response_coverage": 0.88,
        "fast_closure_rate": 0.04,
        "template_rate": 0.06,
        "missing_evidence_rate": 0.03,
        "remediation_rate": 0.82,
        "monitoring_coverage": 0.94,
        "investigation_duration_mean": 105,
        "investigation_duration_std": 40,
        "escalation_latency_mean": 20,
        "data_quality_issue_rate": 0.01,
    },
    "data_quality_problem": {
        "alert_volume_factor": 0.85,
        "investigation_coverage": 0.78,
        "escalation_coverage": 0.68,
        "response_coverage": 0.60,
        "fast_closure_rate": 0.07,
        "template_rate": 0.08,
        "missing_evidence_rate": 0.18,
        "remediation_rate": 0.55,
        "monitoring_coverage": 0.72,
        "investigation_duration_mean": 80,
        "investigation_duration_std": 45,
        "escalation_latency_mean": 50,
        "data_quality_issue_rate": 0.20,
    },
    # --- Spec §21 archetypes (10 required profiles) ---
    "good_minor_gap": {  # GOOD_WITH_MINOR_GAPS: mostly compliant, small gaps
        "alert_volume_factor": 1.0,
        "investigation_coverage": 0.90,
        "escalation_coverage": 0.88,
        "response_coverage": 0.86,
        "fast_closure_rate": 0.04,
        "template_rate": 0.06,
        "missing_evidence_rate": 0.05,
        "remediation_rate": 0.80,
        "monitoring_coverage": 0.92,
        "investigation_duration_mean": 100,
        "investigation_duration_std": 40,
        "escalation_latency_mean": 28,
        "data_quality_issue_rate": 0.015,
    },
    "investigation_failure": {  # INVESTIGATION_FAILURE: cases lack investigations, boilerplate notes
        "alert_volume_factor": 1.0,
        "investigation_coverage": 0.55,
        "escalation_coverage": 0.80,
        "response_coverage": 0.75,
        "fast_closure_rate": 0.06,
        "template_rate": 0.30,
        "missing_evidence_rate": 0.12,
        "remediation_rate": 0.60,
        "monitoring_coverage": 0.85,
        "investigation_duration_mean": 90,
        "investigation_duration_std": 45,
        "escalation_latency_mean": 40,
        "data_quality_issue_rate": 0.03,
    },
    "response_failure": {  # RESPONSE_FAILURE: escalations stall, slow response
        "alert_volume_factor": 1.0,
        "investigation_coverage": 0.90,
        "escalation_coverage": 0.85,
        "response_coverage": 0.45,
        "fast_closure_rate": 0.05,
        "template_rate": 0.07,
        "missing_evidence_rate": 0.06,
        "remediation_rate": 0.50,
        "monitoring_coverage": 0.85,
        "investigation_duration_mean": 90,
        "investigation_duration_std": 40,
        "escalation_latency_mean": 150,
        "data_quality_issue_rate": 0.02,
    },
    "monitoring_gap": {  # MONITORING_GAP: assets expected but not observed
        "alert_volume_factor": 0.9,
        "investigation_coverage": 0.88,
        "escalation_coverage": 0.80,
        "response_coverage": 0.78,
        "fast_closure_rate": 0.05,
        "template_rate": 0.07,
        "missing_evidence_rate": 0.06,
        "remediation_rate": 0.60,
        "monitoring_coverage": 0.50,
        "investigation_duration_mean": 85,
        "investigation_duration_std": 40,
        "escalation_latency_mean": 40,
        "data_quality_issue_rate": 0.02,
    },
    "premature_closure": {  # PREMATURE_CLOSURE: investigations closed too fast
        "alert_volume_factor": 0.9,
        "investigation_coverage": 0.94,
        "escalation_coverage": 0.85,
        "response_coverage": 0.82,
        "fast_closure_rate": 0.50,
        "template_rate": 0.14,
        "missing_evidence_rate": 0.09,
        "remediation_rate": 0.58,
        "monitoring_coverage": 0.88,
        "investigation_duration_mean": 11,
        "investigation_duration_std": 7,
        "escalation_latency_mean": 15,
        "data_quality_issue_rate": 0.02,
    },
}

# ---------------------------------------------------------------------------
# Sector baselines
# ---------------------------------------------------------------------------

SECTOR_BASELINES: dict[str, dict[str, Any]] = {
    "Oil & Gas": {"base_alerts_per_month": 650, "asset_count": 45, "asset_types": ["SCADA", "DCS", "HMI", "PLC", "Historian", "Engineering Workstation", "Server", "Network Switch", "Firewall", "Endpoint"], "categories": ["malware", "unauthorized_access", "policy_violation", "anomalous_traffic", "phishing", "lateral_movement", "data_exfiltration", "scada_anomaly"]},
    "Mining": {"base_alerts_per_month": 400, "asset_count": 30, "asset_types": ["SCADA", "PLC", "HMI", "Server", "Endpoint", "Firewall", "Network Switch"], "categories": ["malware", "unauthorized_access", "policy_violation", "phishing", "anomalous_traffic", "credential_misuse"]},
    "Petroleum & Refining": {"base_alerts_per_month": 620, "asset_count": 42, "asset_types": ["DCS", "SCADA", "PLC", "HMI", "Historian", "Server", "Firewall", "Endpoint"], "categories": ["malware", "unauthorized_access", "anomalous_traffic", "phishing", "policy_violation", "lateral_movement"]},
    "Defence & Aerospace": {"base_alerts_per_month": 550, "asset_count": 35, "asset_types": ["Server", "Endpoint", "Workstation", "Network Switch", "Firewall", "Classified Terminal", "Test System", "Data Diode"], "categories": ["unauthorized_access", "data_exfiltration", "malware", "phishing", "insider_threat", "policy_violation", "lateral_movement", "credential_misuse"]},
    "Natural Gas": {"base_alerts_per_month": 480, "asset_count": 34, "asset_types": ["SCADA", "DCS", "PLC", "HMI", "Server", "Firewall", "Endpoint"], "categories": ["malware", "unauthorized_access", "scada_anomaly", "phishing", "policy_violation", "anomalous_traffic"]},
    "Electronics & Defence": {"base_alerts_per_month": 500, "asset_count": 30, "asset_types": ["Server", "Endpoint", "Workstation", "Network Switch", "Firewall", "Classified Terminal", "Lab System"], "categories": ["unauthorized_access", "data_exfiltration", "malware", "phishing", "insider_threat", "policy_violation", "credential_misuse"]},
    "Power & Energy": {"base_alerts_per_month": 700, "asset_count": 50, "asset_types": ["SCADA", "RTU", "IED", "HMI", "DCS", "Server", "Endpoint", "Firewall", "Network Switch", "Historian"], "categories": ["malware", "unauthorized_access", "anomalous_traffic", "phishing", "policy_violation", "lateral_movement", "ics_anomaly", "credential_misuse"]},
    "Mining & Energy": {"base_alerts_per_month": 400, "asset_count": 30, "asset_types": ["SCADA", "PLC", "HMI", "Server", "Endpoint", "Firewall", "Network Switch"], "categories": ["malware", "unauthorized_access", "policy_violation", "phishing", "anomalous_traffic", "credential_misuse"]},
    "Aerospace & Defence": {"base_alerts_per_month": 550, "asset_count": 35, "asset_types": ["Server", "Endpoint", "Workstation", "Network Switch", "Firewall", "Classified Terminal", "Test System", "Data Diode"], "categories": ["unauthorized_access", "data_exfiltration", "malware", "phishing", "insider_threat", "policy_violation", "lateral_movement", "credential_misuse"]},
    "Defence Electronics": {"base_alerts_per_month": 500, "asset_count": 30, "asset_types": ["Server", "Endpoint", "Workstation", "Network Switch", "Firewall", "Classified Terminal", "Lab System"], "categories": ["unauthorized_access", "data_exfiltration", "malware", "phishing", "insider_threat", "policy_violation", "credential_misuse"]},
    "Heavy Engineering": {"base_alerts_per_month": 450, "asset_count": 35, "asset_types": ["SCADA", "PLC", "HMI", "Server", "Endpoint", "Firewall", "Network Switch", "DCS"], "categories": ["malware", "unauthorized_access", "policy_violation", "phishing", "anomalous_traffic", "credential_misuse"]},
    "Shipbuilding": {"base_alerts_per_month": 420, "asset_count": 28, "asset_types": ["Server", "Endpoint", "Workstation", "Network Switch", "Firewall", "Design Workstation", "CNC Controller"], "categories": ["unauthorized_access", "malware", "phishing", "policy_violation", "data_exfiltration", "credential_misuse"]},
    "Transport": {"base_alerts_per_month": 380, "asset_count": 25, "asset_types": ["Server", "Endpoint", "Firewall", "Network Switch", "Port Management System", "Container Tracking", "CCTV Controller"], "categories": ["malware", "unauthorized_access", "phishing", "policy_violation", "anomalous_traffic", "credential_misuse"]},
    "Telecom": {"base_alerts_per_month": 800, "asset_count": 55, "asset_types": ["Core Router", "Edge Router", "Server", "Endpoint", "Firewall", "Load Balancer", "DNS Server", "MPLS Switch", "CDN Node"], "categories": ["ddos", "malware", "unauthorized_access", "phishing", "anomalous_traffic", "policy_violation", "credential_misuse", "data_exfiltration"]},
    "Banking & Finance": {"base_alerts_per_month": 900, "asset_count": 60, "asset_types": ["Core Banking Server", "ATM Controller", "Web Server", "Database Server", "Endpoint", "Firewall", "Payment Gateway", "API Gateway", "Mobile Backend"], "categories": ["fraud_attempt", "malware", "phishing", "unauthorized_access", "credential_misuse", "data_exfiltration", "policy_violation", "web_attack"]},
    "Transport & Logistics": {"base_alerts_per_month": 380, "asset_count": 25, "asset_types": ["Server", "Endpoint", "Firewall", "Network Switch", "Port Management System", "Container Tracking", "CCTV Controller"], "categories": ["malware", "unauthorized_access", "phishing", "policy_violation", "anomalous_traffic", "credential_misuse"]},
}

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_WEIGHTS_BY_SECTOR: dict[str, tuple[float, ...]] = {
    "Oil & Gas": (35, 38, 20, 7),
    "Power & Energy": (33, 36, 22, 9),
    "Mining": (40, 35, 18, 7),
    "Mining & Energy": (40, 35, 18, 7),
    "Petroleum & Refining": (34, 37, 21, 8),
    "Natural Gas": (36, 37, 20, 7),
    "Aerospace & Defence": (30, 35, 25, 10),
    "Defence & Aerospace": (30, 35, 25, 10),
    "Defence Electronics": (32, 34, 24, 10),
    "Electronics & Defence": (32, 34, 24, 10),
    "Heavy Engineering": (38, 36, 19, 7),
    "Shipbuilding": (35, 37, 20, 8),
    "Shipbuilding & Defence": (35, 37, 20, 8),
    "Transport": (40, 35, 18, 7),
    "Telecom": (38, 35, 20, 7),
    "Banking & Finance": (30, 38, 23, 9),
    "Transport & Logistics": (40, 35, 18, 7),
}

ALERT_SOURCES = ["SIEM", "IDS", "EDR", "Firewall", "WAF", "Email Gateway", "DLP", "User Report", "Threat Intel Feed"]

INVESTIGATION_NOTE_TEMPLATES = [
    "Analyst reviewed alert for {asset} ({category}). Correlated with threat intelligence feeds and baseline behavior. {conclusion}",
    "Investigation of {category} activity on {asset}. Log analysis performed across {duration} minutes. {conclusion}",
    "Multi-source correlation performed for {category} on {asset}. Network and endpoint telemetry reviewed. {conclusion}",
    "Incident handler examined {category} indicators on {asset}. Compared against known attack patterns. {conclusion}",
    "Security analyst conducted deep-dive on {asset} for {category}. Timeline reconstructed from available logs. {conclusion}",
    "Forensic review of {category} alert on {asset}. Memory and disk artifacts examined where available. {conclusion}",
    "Tier-2 analyst reviewed escalated {category} event for {asset}. Cross-referenced with previous incidents. {conclusion}",
    "Automated enrichment plus manual review for {category} on {asset}. IOC validation completed. {conclusion}",
]

INVESTIGATION_CONCLUSIONS = [
    "True positive confirmed; containment applied and verified.",
    "False positive determined after correlation; no malicious activity detected.",
    "Benign activity confirmed; alert tuning recommended.",
    "Suspicious activity confirmed; escalated for response.",
    "Policy violation confirmed; referred to governance team.",
    "Inconclusive; additional monitoring recommended.",
    "True positive; root cause identified and remediation initiated.",
    "No further indicators found; case closed with monitoring.",
]

# Archetypes whose analysts reuse boilerplate investigation narratives.
TEMPLATE_ARCHETYPES = {"template_investigation", "investigation_failure"}
TEMPLATE_NOTE = "Standard investigation template: reviewed alert, checked telemetry, and closed with no further action required."

REMEDIATION_ACTIONS = [
    "Patched affected system",
    "Blocked malicious IP at firewall",
    "Reset compromised credentials",
    "Isolated affected endpoint",
    "Updated detection signatures",
    "Applied configuration hardening",
    "Removed malicious software",
    "Restored from clean backup",
    "Updated access controls",
    "Implemented network segmentation",
]

ROOT_CAUSES = [
    "Unpatched vulnerability",
    "Credential compromise",
    "Misconfigured access control",
    "Phishing email",
    "Malware infection",
    "Insider policy violation",
    "Supply chain compromise",
    "Zero-day exploit",
    "Social engineering",
    "Configuration drift",
]

CLOSURE_REASONS = [
    "Resolved - threat contained",
    "False positive - no threat",
    "Duplicate - already tracked",
    "Accepted risk - documented",
    "Resolved - patch applied",
    "Resolved - credentials rotated",
    "No action required - informational",
]

# Months for generation: Jan 2026 - Sep 2026
MONTHS = [
    datetime(2026, m, 1, tzinfo=timezone.utc) for m in range(1, 10)
]


def _ts(rng: random.Random, month_start: datetime, day_range: int = 28) -> datetime:
    """Generate a random timestamp within a month."""
    offset = timedelta(
        days=rng.randint(0, min(day_range - 1, 27)),
        hours=rng.randint(0, 23),
        minutes=rng.randint(0, 59),
        seconds=rng.randint(0, 59),
    )
    return month_start + offset


def _ts_str(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def generate_all(rng: random.Random) -> dict[str, list[dict[str, Any]]]:
    """Generate the complete synthetic dataset across all tables."""
    entities_out: list[dict[str, Any]] = []
    assets_out: list[dict[str, Any]] = []
    alerts_out: list[dict[str, Any]] = []
    cases_out: list[dict[str, Any]] = []
    investigations_out: list[dict[str, Any]] = []
    escalations_out: list[dict[str, Any]] = []
    responses_out: list[dict[str, Any]] = []
    remediations_out: list[dict[str, Any]] = []
    submissions_out: list[dict[str, Any]] = []

    alert_counter = 0
    case_counter = 0
    inv_counter = 0
    esc_counter = 0
    resp_counter = 0
    rem_counter = 0

    for entity_def in ENTITIES:
        entity_id = entity_def["id"]
        sector = entity_def["sector"]
        archetype = entity_def["archetype"]
        params = ARCHETYPE_PARAMS[archetype]
        template_rng = random.Random(f"template-{entity_id}")
        sector_base = SECTOR_BASELINES.get(sector, SECTOR_BASELINES["Transport & Logistics"])

        entities_out.append({
            "entity_id": entity_id,
            "entity_name": entity_def["name"],
            "sector": sector,
            "criticality": entity_def["criticality"],
            "synthetic_label": "SYNTHETIC DEMONSTRATION DATA",
        })

        # Generate assets
        asset_count = sector_base["asset_count"]
        asset_types = sector_base["asset_types"]
        entity_assets = []
        for ai in range(asset_count):
            asset_type = asset_types[ai % len(asset_types)]
            criticality = "critical" if ai < asset_count * 0.15 else "high" if ai < asset_count * 0.35 else "medium" if ai < asset_count * 0.7 else "low"
            expected_monitoring = True
            # Under-reporting / monitoring-gap archetypes: some assets lack expected monitoring
            if archetype == "under_reporting" and rng.random() < 0.25:
                expected_monitoring = False
            elif archetype == "monitoring_gap" and rng.random() < 0.45:
                expected_monitoring = False
            asset = {
                "asset_id": f"{entity_id}-asset-{ai+1:03d}",
                "entity_id": entity_id,
                "asset_name": f"{entity_id.upper()}-{asset_type.replace(' ', '')}-{ai+1:03d}",
                "asset_type": asset_type,
                "criticality": criticality,
                "environment": rng.choice(["production", "staging", "development", "dmz"]) if rng.random() > 0.2 else "production",
                "expected_monitoring": expected_monitoring,
                "active": True,
            }
            entity_assets.append(asset)
            assets_out.append(asset)

        # Track which assets have alerts (for monitoring coverage)
        assets_with_alerts: set[str] = set()
        # Track repeated-alert assets
        repeated_asset_pool = [a["asset_id"] for a in entity_assets[:8]] if archetype == "repeated_alert" else []

        sev_weights = SEVERITY_WEIGHTS_BY_SECTOR.get(sector, (35, 38, 20, 7))
        categories = sector_base["categories"]
        base_monthly = max(8, int(sector_base["base_alerts_per_month"] * params["alert_volume_factor"] * VOLUME_SCALE))

        for month_idx, month_start in enumerate(MONTHS):
            # Seasonal variation: slightly higher in Q1 and Q3
            seasonal = 1.0 + 0.08 * math.sin(2 * math.pi * month_idx / 9)
            # Under-reporting: missing some months
            if archetype == "under_reporting" and month_idx in (2, 5):
                # Skip these months entirely (negative space)
                submissions_out.append({
                    "submission_id": f"{entity_id}-sub-{month_idx+1:02d}",
                    "entity_id": entity_id,
                    "reporting_period": month_start.strftime("%Y-%m"),
                    "submitted_at": None,  # Not submitted
                    "record_count": 0,
                    "completeness_score": 0.0,
                    "hash": None,
                    "status": "missing",
                })
                continue

            monthly_alerts = int(base_monthly * seasonal * rng.uniform(0.85, 1.15))
            month_alerts = []
            month_cases = []

            for _ in range(monthly_alerts):
                alert_counter += 1
                severity = rng.choices(SEVERITIES, weights=sev_weights, k=1)[0]
                category = rng.choice(categories)
                source = rng.choice(ALERT_SOURCES)
                timestamp = _ts(rng, month_start)

                # Pick asset
                if archetype == "repeated_alert" and repeated_asset_pool and rng.random() < params.get("repeated_asset_rate", 0.3):
                    asset_id = rng.choice(repeated_asset_pool)
                else:
                    # Under-reporting: some alerts lack asset mapping
                    if archetype == "under_reporting" and rng.random() < 0.12:
                        asset_id = None
                    elif archetype == "data_quality_problem" and rng.random() < params["data_quality_issue_rate"]:
                        asset_id = None  # Missing asset mapping
                    else:
                        asset_id = rng.choice(entity_assets)["asset_id"]

                if asset_id:
                    assets_with_alerts.add(asset_id)

                ack_delay = max(1, int(rng.gauss(15, 8)))
                ack_at = timestamp + timedelta(minutes=ack_delay)

                escalation_required = severity in ("critical", "high") and rng.random() < 0.7
                alert_id = f"{entity_id}-ALR-{alert_counter:06d}"

                alert = {
                    "alert_id": alert_id,
                    "entity_id": entity_id,
                    "asset_id": asset_id,
                    "timestamp": _ts_str(timestamp),
                    "severity": severity,
                    "category": category,
                    "source": source,
                    "status": "closed",
                    "acknowledged_at": _ts_str(ack_at),
                    "case_id": None,
                    "escalation_required": escalation_required,
                    "escalation_id": None,
                    "closure_id": None,
                }

                # Data quality problems: duplicates, bad timestamps
                if archetype == "data_quality_problem" and rng.random() < 0.03:
                    # Create duplicate with slightly different data
                    dup = dict(alert)
                    dup["alert_id"] = f"{entity_id}-ALR-{alert_counter:06d}-DUP"
                    alerts_out.append(dup)

                if archetype == "data_quality_problem" and rng.random() < 0.04:
                    alert["timestamp"] = ""  # Invalid timestamp
                    alert["acknowledged_at"] = ""

                # Create case for most alerts (coverage depends on archetype)
                create_case = rng.random() < params["investigation_coverage"]
                if create_case:
                    case_counter += 1
                    case_id = f"{entity_id}-CASE-{case_counter:06d}"
                    alert["case_id"] = case_id

                    case_created = timestamp + timedelta(minutes=rng.randint(1, 10))
                    case_assigned = case_created + timedelta(minutes=rng.randint(2, 30))

                    # Investigation
                    has_investigation = rng.random() < params["investigation_coverage"]
                    inv_started = case_assigned + timedelta(minutes=rng.randint(5, 60))

                    if params["fast_closure_rate"] > 0 and rng.random() < params["fast_closure_rate"]:
                        inv_duration = max(1, int(rng.gauss(5, 3)))
                    else:
                        inv_duration = max(10, int(rng.gauss(
                            params["investigation_duration_mean"],
                            params["investigation_duration_std"]
                        )))

                    inv_ended = inv_started + timedelta(minutes=inv_duration)
                    case_closed = inv_ended + timedelta(minutes=rng.randint(5, 120))

                    # KPI optimization: trend of decreasing investigation time
                    if archetype == "kpi_optimization" and month_idx > 3:
                        inv_duration = max(3, inv_duration - (month_idx - 3) * 2)
                        inv_ended = inv_started + timedelta(minutes=inv_duration)
                        case_closed = inv_ended + timedelta(minutes=rng.randint(2, 30))

                    closure_reason = rng.choice(CLOSURE_REASONS)
                    root_cause = rng.choice(ROOT_CAUSES) if severity in ("critical", "high") else None

                    case = {
                        "case_id": case_id,
                        "alert_id": alert_id,
                        "entity_id": entity_id,
                        "created_at": _ts_str(case_created),
                        "assigned_at": _ts_str(case_assigned),
                        "investigation_started_at": _ts_str(inv_started) if has_investigation else None,
                        "closed_at": _ts_str(case_closed),
                        "status": "closed",
                        "priority": severity,
                        "closure_reason": closure_reason,
                        "root_cause": root_cause,
                        "remediation_id": None,
                    }
                    month_cases.append(case)
                    cases_out.append(case)

                    # Investigation record
                    if has_investigation:
                        inv_counter += 1
                        # Notes
                        asset_label = asset_id or "unmonitored asset"
                        template = rng.choice(INVESTIGATION_NOTE_TEMPLATES)
                        conclusion = rng.choice(INVESTIGATION_CONCLUSIONS)
                        notes = template.format(
                            asset=asset_label,
                            category=category,
                            duration=inv_duration,
                            conclusion=conclusion,
                        )
                        # Separate RNG so templating never shifts the main random stream.
                        if archetype in TEMPLATE_ARCHETYPES and template_rng.random() < params["template_rate"]:
                            notes = TEMPLATE_NOTE

                        # Missing evidence
                        has_evidence = rng.random() > params["missing_evidence_rate"]
                        actions_count = rng.randint(3, 15) if has_evidence else rng.randint(0, 2)
                        evidence_count = rng.randint(2, 10) if has_evidence else 0

                        inv = {
                            "investigation_id": f"{entity_id}-INV-{inv_counter:06d}",
                            "case_id": case_id,
                            "analyst_id": f"{entity_id}-analyst-{rng.randint(1, 8):02d}",
                            "start_time": _ts_str(inv_started),
                            "end_time": _ts_str(inv_ended),
                            "duration_minutes": inv_duration,
                            "actions_count": actions_count,
                            "evidence_count": evidence_count,
                            "conclusion": rng.choice(INVESTIGATION_CONCLUSIONS) if rng.random() > 0.05 else None,
                            "investigation_notes": notes,
                            "template_match": notes == TEMPLATE_NOTE,
                        }
                        investigations_out.append(inv)

                    # Escalation
                    if escalation_required:
                        should_escalate = rng.random() < params["escalation_coverage"]
                        if should_escalate:
                            esc_counter += 1
                            esc_time = inv_started + timedelta(minutes=max(5, int(rng.gauss(
                                params["escalation_latency_mean"],
                                params["escalation_latency_mean"] * 0.4
                            ))))
                            esc_id = f"{entity_id}-ESC-{esc_counter:06d}"
                            alert["escalation_id"] = esc_id

                            esc = {
                                "escalation_id": esc_id,
                                "case_id": case_id,
                                "escalation_time": _ts_str(esc_time),
                                "escalation_level": rng.choice(["L2", "L3", "Management", "CISO"]),
                                "reason": f"{severity.upper()} severity {category} requiring escalation",
                                "acknowledged": rng.random() < 0.85,
                                "recipient": f"{entity_id}-manager-{rng.randint(1, 4):02d}",
                            }
                            escalations_out.append(esc)

                            # Response
                            should_respond = rng.random() < params["response_coverage"]
                            if should_respond:
                                resp_counter += 1
                                resp_time = esc_time + timedelta(minutes=max(10, int(rng.gauss(60, 30))))
                                resp = {
                                    "response_id": f"{entity_id}-RESP-{resp_counter:06d}",
                                    "case_id": case_id,
                                    "response_type": rng.choice(["containment", "eradication", "recovery", "mitigation"]),
                                    "response_time": _ts_str(resp_time),
                                    "action": rng.choice(REMEDIATION_ACTIONS[:5]),
                                    "status": rng.choice(["completed", "completed", "completed", "in_progress"]),
                                }
                                responses_out.append(resp)

                    # Remediation
                    if root_cause and rng.random() < params["remediation_rate"]:
                        rem_counter += 1
                        rem_id = f"{entity_id}-REM-{rem_counter:06d}"
                        case["remediation_id"] = rem_id
                        rem = {
                            "remediation_id": rem_id,
                            "case_id": case_id,
                            "asset_id": asset_id,
                            "root_cause": root_cause,
                            "action": rng.choice(REMEDIATION_ACTIONS),
                            "completed_at": _ts_str(case_closed + timedelta(hours=rng.randint(1, 72))),
                            "status": rng.choice(["completed", "completed", "in_progress", "pending"]),
                        }
                        remediations_out.append(rem)

                month_alerts.append(alert)
                alerts_out.append(alert)

            # Submission record
            completeness = 0.95
            if archetype == "data_quality_problem":
                completeness = rng.uniform(0.60, 0.80)
            elif archetype == "under_reporting":
                completeness = rng.uniform(0.70, 0.85)

            sub_data = json.dumps({"month": month_start.strftime("%Y-%m"), "alerts": len(month_alerts)}).encode()
            submissions_out.append({
                "submission_id": f"{entity_id}-sub-{month_idx+1:02d}",
                "entity_id": entity_id,
                "reporting_period": month_start.strftime("%Y-%m"),
                "submitted_at": _ts_str(month_start + timedelta(days=rng.randint(28, 35))),
                "record_count": len(month_alerts),
                "completeness_score": round(completeness, 2),
                "hash": hashlib.sha256(sub_data).hexdigest(),
                "status": "submitted",
            })

    tables = {
        "entities": entities_out,
        "assets": assets_out,
        "alerts": alerts_out,
        "cases": cases_out,
        "investigations": investigations_out,
        "escalations": escalations_out,
        "responses": responses_out,
        "remediations": remediations_out,
        "submissions": submissions_out,
    }
    inject_supervisory_behaviours(tables)
    return tables


# ---------------------------------------------------------------------------
# Planted supervisory behaviours (ground truth for validation)
# ---------------------------------------------------------------------------
# Applied after generation with per-entity RNGs, so every other entity's data
# is byte-identical with or without them.
PLANTED_BEHAVIOURS = {
    "bpcl": "sla_gaming",            # looks fine on KPIs; closes cases just inside the SLA
    "cpa": "offhours_blind",         # monitoring gap: no detections at night
    "rail": "analyst_concentration",  # one login records most investigations
}
STRONG_ARCHETYPES = {"strong_mature", "strong_high_volume", "good_minor_gap"}
# Expected supervisory signal per behaviour (used by the validation module).
BEHAVIOUR_SIGNALS = {
    "escalation_gap": "EG-MISSING-ESC",
    "under_reporting": "NS-MISSING-SUB",
    "response_failure": "EG-ESC-NO-RESP",
    "investigation_failure": "EG-TEMPLATE",
    "fast_closure": "EG-FAST-CRITICAL",
    "premature_closure": "EG-FAST-CRITICAL",
    "sla_gaming": "EG-SLA-GAMING",
    "offhours_blind": "NS-OFFHOURS-BLIND",
    "analyst_concentration": "EG-ANALYST-CONCENTRATION",
}
SLA_MINUTES = 240
IST = timedelta(hours=5, minutes=30)


def ground_truth() -> dict[str, dict[str, Any]]:
    """Synthetic ground truth: which entities were built weak, and why."""
    truth = {}
    for e in ENTITIES:
        behaviours = [e["archetype"]] if e["archetype"] in BEHAVIOUR_SIGNALS else []
        if e["id"] in PLANTED_BEHAVIOURS:
            behaviours.append(PLANTED_BEHAVIOURS[e["id"]])
        if e["archetype"] in STRONG_ARCHETYPES and not behaviours:
            label = "strong"
        elif e["archetype"] == "mixed_moderate" and not behaviours:
            label = "mixed"
        else:
            label = "weak"
        truth[e["id"]] = {"archetype": e["archetype"], "label": label, "behaviours": behaviours,
                          "expected_signals": [BEHAVIOUR_SIGNALS[b] for b in behaviours]}
    return truth


def _parse(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _shift_times(record: dict[str, Any], delta: timedelta) -> None:
    for key, value in list(record.items()):
        if key.endswith(("_at", "_time", "timestamp")):
            ts = _parse(value)
            if ts:
                record[key] = _ts_str(ts + delta)


def inject_supervisory_behaviours(tables: dict[str, list[dict[str, Any]]]) -> None:
    by_case = {name: {r["case_id"]: r for r in tables[name] if r.get("case_id")}
               for name in ("cases", "investigations", "escalations", "responses", "remediations")}
    for entity_id, behaviour in PLANTED_BEHAVIOURS.items():
        rng = random.Random(f"planted-{entity_id}")
        alerts = [a for a in tables["alerts"] if a["entity_id"] == entity_id]
        if behaviour == "offhours_blind":
            # Detections only appear during the day shift: night alerts surface hours later.
            for alert in alerts:
                ts = _parse(alert.get("timestamp"))
                if not ts or (ts + IST).hour >= 7 or rng.random() > 0.97:
                    continue
                delta = timedelta(hours=9)
                _shift_times(alert, delta)
                for table in by_case.values():
                    if alert.get("case_id") in table:
                        _shift_times(table[alert["case_id"]], delta)
        elif behaviour == "sla_gaming":
            for alert in alerts:
                case = by_case["cases"].get(alert.get("case_id"))
                inv = by_case["investigations"].get(alert.get("case_id"))
                start = _parse(alert.get("timestamp"))
                if (not case or not inv or not start or alert["severity"] not in ("critical", "high")
                        or rng.random() > 0.6):
                    continue
                closed = start + timedelta(minutes=rng.uniform(SLA_MINUTES * 0.86, SLA_MINUTES - 1))
                inv_start = _parse(inv.get("start_time"))
                inv_end = closed - timedelta(minutes=rng.randint(2, 8))
                if not inv_start or inv_end <= inv_start:
                    continue
                case["closed_at"] = _ts_str(closed)
                inv["end_time"] = _ts_str(inv_end)
                inv["duration_minutes"] = max(1, int((inv_end - inv_start).total_seconds() // 60))
        elif behaviour == "analyst_concentration":
            for inv in tables["investigations"]:
                if inv["case_id"].startswith(f"{entity_id}-") and rng.random() < 0.7:
                    inv["analyst_id"] = f"{entity_id}-analyst-01"


def build_declarations(observed: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Synthetic CSE self-assessments: strong SOCs report honestly, weak ones overclaim."""
    truth = ground_truth()
    rows = []
    for eid in sorted(observed):
        rng = random.Random(f"declare-{eid}")
        honest = truth.get(eid, {}).get("label") == "strong"
        for metric in ("investigation_coverage", "escalation_rate", "response_coverage",
                       "monitoring_coverage", "evidence_completeness"):
            obs = observed[eid].get(metric)
            if obs is None:
                continue
            declared = obs + rng.uniform(0, 2.5) if honest else max(obs + rng.uniform(0, 3), rng.uniform(93, 99))
            rows.append({"entity_id": eid, "metric": metric, "declared_value": round(min(100.0, declared), 1),
                         "source": "self-assessment (synthetic)"})
    return rows


def generate_flat_records(tables: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Flatten the relational tables into the legacy flat record format for backward compatibility."""
    records: list[dict[str, Any]] = []
    case_map = {c["case_id"]: c for c in tables["cases"]}
    inv_map: dict[str, dict[str, Any]] = {}
    for inv in tables["investigations"]:
        inv_map[inv["case_id"]] = inv
    esc_map: dict[str, dict[str, Any]] = {}
    for esc in tables["escalations"]:
        esc_map[esc["case_id"]] = esc
    resp_map: dict[str, dict[str, Any]] = {}
    for resp in tables["responses"]:
        resp_map[resp["case_id"]] = resp
    rem_map: dict[str, dict[str, Any]] = {}
    for rem in tables.get("remediations", []):
        rem_map[rem["case_id"]] = rem

    entity_map = {e["entity_id"]: e for e in tables["entities"]}
    asset_map = {a["asset_id"]: a for a in tables["assets"]}

    for alert in tables["alerts"]:
        entity = entity_map.get(alert["entity_id"], {})
        asset = asset_map.get(alert.get("asset_id") or "", {})
        record: dict[str, Any] = {
            "entity_id": alert["entity_id"],
            "entity_name": entity.get("entity_name", alert["entity_id"]),
            "sector": entity.get("sector"),
            "asset_id": alert["asset_id"],
            "asset_criticality": asset.get("criticality"),
            "alert_id": alert["alert_id"],
            "type": "alert",
            "severity": alert["severity"],
            "category": alert["category"],
            "source": alert["source"],
            "status": "closed",
            "timestamp": alert["timestamp"],
            "reporting_period": str(alert.get("timestamp", ""))[:7],
            "acknowledged_at": alert.get("acknowledged_at"),
            "escalated": alert.get("escalation_id") is not None,
            "escalation_required": alert.get("escalation_required", False),
        }

        case_id = alert.get("case_id")
        if case_id and case_id in case_map:
            case = case_map[case_id]
            record["case_id"] = case_id
            record["case_status"] = case.get("status")
            record["priority"] = case.get("priority")
            record["investigated"] = case.get("investigation_started_at") is not None
            record["closure_time"] = case.get("closed_at")
            record["closed_at"] = case.get("closed_at")
            record["investigation_time"] = case.get("investigation_started_at")
            record["investigation_started_at"] = case.get("investigation_started_at")
            record["evidence"] = True

            inv = inv_map.get(case_id)
            if inv:
                record["investigation_id"] = inv.get("investigation_id")
                record["conclusion"] = inv.get("conclusion")
                record["notes"] = inv.get("investigation_notes")
                record["investigation_notes"] = inv.get("investigation_notes")
                record["investigation_duration_minutes"] = inv.get("duration_minutes")
                record["duration_minutes"] = inv.get("duration_minutes")
                record["start_time"] = inv.get("start_time")
                record["end_time"] = inv.get("end_time")
                record["analyst_id"] = inv.get("analyst_id")
                record["template_match"] = inv.get("template_match", False)
                record["evidence_count"] = inv.get("evidence_count", 0)
                record["responded"] = case_id in resp_map
            else:
                record["evidence"] = False
                record["responded"] = False

            esc = esc_map.get(case_id)
            if esc:
                record["escalation_id"] = esc.get("escalation_id")
                record["escalated"] = True
                record["escalation_time"] = esc.get("escalation_time")
                record["escalation_level"] = esc.get("escalation_level")
                record["recipient"] = esc.get("recipient")
                record["acknowledged"] = esc.get("acknowledged", False)

            resp = resp_map.get(case_id)
            if resp:
                record["response_id"] = resp.get("response_id")
                record["response_time"] = resp.get("response_time")
                record["response_timestamp"] = resp.get("response_time")
                record["response_type"] = resp.get("response_type")
                record["response_action"] = resp.get("action")

            rem = rem_map.get(case_id)
            if rem or case.get("remediation_id"):
                record["remediation_id"] = (rem or {}).get("remediation_id") or case.get("remediation_id")
                record["root_cause"] = (rem or {}).get("root_cause") or case.get("root_cause")
                record["remediation_action"] = (rem or {}).get("action")
                record["responded"] = case_id in resp_map
            else:
                record["evidence"] = False
                record["responded"] = False
        else:
            record["investigated"] = False
            record["evidence"] = False
            record["responded"] = False

        records.append(record)

    return records


def generate_records(rng: random.Random) -> list[dict[str, Any]]:
    """Backward-compatible flat record generator used by rule-recall tests."""
    records = generate_flat_records(generate_all(rng))
    return records


# ---------------------------------------------------------------------------
# Legacy-compatible seed() entry point
# ---------------------------------------------------------------------------

def seed(reset: bool = False) -> dict[str, Any]:
    """Generate and persist the synthetic dataset."""
    from ..artifacts import artifact_store
    from ..database import (
        AssessmentRow,
        EntityRow,
        FindingRow,
        ReviewRow,
        SessionLocal,
        SubmissionRow,
    )
    from ..main import (
        Store,
        assessment_summary,
        content_hash,
        execute_rules,
        index_records,
        normalize_records,
        now,
        persist_assessment,
        persist_submission,
    )

    if reset:
        Store.submissions.clear()
        Store.assessments.clear()
        Store.findings.clear()
        Store.entities.clear()
        Store.assets.clear()
        Store.alerts.clear()
        Store.cases.clear()
        Store.workflow_events.clear()
        Store.audit_events.clear()
        Store.reviews.clear()
        Store._evidence_index = None
        with SessionLocal.begin() as session:
            for model in (FindingRow, ReviewRow, AssessmentRow, SubmissionRow, EntityRow):
                session.query(model).delete()

    rng = random.Random(SEED)
    tables = generate_all(rng)
    flat_records = generate_flat_records(tables)

    records, quality_issues = normalize_records(flat_records)

    submission_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "sat-sa-synthetic-26157"))
    payload = {
        "name": "SAT-SA Synthetic Multi-Sector SOC Evidence (Jan-Sep 2026)",
        "source": "offline-seed",
        "metadata": {
            "schema_version": "1.0",
            "generator_seed": SEED,
            "synthetic": True,
            "label": "SYNTHETIC DEMONSTRATION DATA — NOT REAL",
            "assessment_period": "January 2026 – September 2026",
            "entities": len(tables["entities"]),
            "total_alerts": len(tables["alerts"]),
            "total_cases": len(tables["cases"]),
            "total_investigations": len(tables["investigations"]),
            "total_escalations": len(tables["escalations"]),
            "total_responses": len(tables["responses"]),
            "total_remediations": len(tables["remediations"]),
            "total_assets": len(tables["assets"]),
        },
        "records": records,
    }
    raw_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    artifact = artifact_store.put("submissions", submission_id, raw_bytes, "json")

    # Also persist the relational tables as a separate artifact
    tables_bytes = json.dumps(tables, sort_keys=True, separators=(",", ":"), default=str).encode()
    artifact_store.put("datasets", submission_id, tables_bytes, "json")

    submission = {
        "id": submission_id,
        **payload,
        "records": records,
        "content_sha256": content_hash(records),
        "original_artifact": artifact.__dict__,
        "quality_issues": quality_issues,
        "quality": {"issue_count": len(quality_issues), "rows": len(records)},
        "created_at": now().isoformat(),
        "_tables": tables,  # Keep in memory for analytics
    }

    Store.submissions[submission_id] = submission
    index_records(submission)
    persist_submission(submission)

    assessment_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "sat-sa-synthetic-assessment-26157"))
    findings = execute_rules(submission, assessment_id)
    Store.findings[assessment_id] = findings
    assessment = {
        "id": assessment_id,
        "submission_id": submission_id,
        "requested_by": "offline-seed",
        "status": "completed",
        "created_at": now().isoformat(),
        "summary": assessment_summary(findings, submission),
    }
    Store.assessments[assessment_id] = assessment
    persist_assessment(assessment, findings)

    # Self-assessment declarations derived from what the evidence actually shows.
    from ..main import _sat_engine, store_declarations
    from ..database import DeclarationRow
    with SessionLocal.begin() as session:
        session.query(DeclarationRow).delete()
    Store.declarations.clear()
    store_declarations(build_declarations(_sat_engine().peer_benchmark()["entities"]),
                       "self-assessment (synthetic)")

    digest = hashlib.sha256(raw_bytes).hexdigest()
    return {
        "submission_id": submission_id,
        "assessment_id": assessment_id,
        "entities": len(tables["entities"]),
        "records": len(records),
        "findings": len(findings),
        "alerts": len(tables["alerts"]),
        "cases": len(tables["cases"]),
        "investigations": len(tables["investigations"]),
        "escalations": len(tables["escalations"]),
        "responses": len(tables["responses"]),
        "remediations": len(tables["remediations"]),
        "assets": len(tables["assets"]),
        "dataset_sha256": digest,
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Generate deterministic offline SAT-SA synthetic evidence.")
    parser.add_argument("--reset", action="store_true", help="Reset persisted demo data before seeding.")
    parser.add_argument("--csv", default=None, help="Write relational demo CSV to this path.")
    args = parser.parse_args()
    if args.csv:
        print(json.dumps({"csv": export_demo_csv(args.csv)}, indent=2))
        return
    print(json.dumps(seed(reset=args.reset), indent=2, sort_keys=True))


def export_demo_csv(path: str, max_rows: int = 6000) -> dict[str, Any]:
    """Write examples/sat_sa_demo_soc.csv with the spec §22 schema (relational, consistent).

    Rows are round-robin sampled across entities so every entity is
    represented even when max_rows caps the output.
    """
    import csv
    rng = random.Random(SEED)
    tables = generate_all(rng)
    case_map = {c["case_id"]: c for c in tables["cases"]}
    inv_map = {i["case_id"]: i for i in tables["investigations"]}
    esc_map = {e["case_id"]: e for e in tables["escalations"]}
    resp_map = {r["case_id"]: r for r in tables["responses"]}
    rem_map: dict[str, list[dict[str, Any]]] = {}
    for r in tables["remediations"]:
        rem_map.setdefault(r["case_id"], []).append(r)
    ent_map = {e["entity_id"]: e for e in tables["entities"]}
    asset_map = {a["asset_id"]: a for a in tables["assets"]}
    by_entity: dict[str, list[dict[str, Any]]] = {}
    for alert in tables["alerts"]:
        by_entity.setdefault(alert["entity_id"], []).append(alert)

    def build_row(n: int, alert: dict[str, Any]) -> dict[str, Any]:
        ent = ent_map.get(alert["entity_id"], {})
        asset = asset_map.get(alert.get("asset_id") or "", {})
        case = case_map.get(alert.get("case_id") or "", {})
        inv = inv_map.get(alert.get("case_id") or "", {})
        esc = esc_map.get(alert.get("case_id") or "", {})
        resp = resp_map.get(alert.get("case_id") or "", {})
        rems = rem_map.get(alert.get("case_id") or "", [])
        rem = rems[0] if rems else {}
        period = str(alert.get("timestamp", ""))[:7] or "2026-01"
        return {
            "record_id": f"rec-{n:05d}", "timestamp": alert.get("timestamp", ""),
            "entity_id": alert.get("entity_id", ""), "entity_name": ent.get("entity_name", ""),
            "sector": ent.get("sector", ""), "asset_id": alert.get("asset_id") or "",
            "asset_name": asset.get("asset_name", ""), "asset_criticality": asset.get("criticality", ""),
            "alert_id": alert.get("alert_id", ""), "alert_category": alert.get("category", ""),
            "severity": alert.get("severity", ""),
            "alert_status": alert.get("status", ""), "case_id": alert.get("case_id") or "",
            "case_status": case.get("status", ""), "investigation_id": inv.get("investigation_id", ""),
            "investigation_status": "completed" if inv else ("missing" if case else ""),
            "investigation_started": inv.get("start_time", ""), "investigation_completed": inv.get("end_time", ""),
            "investigation_conclusion": inv.get("conclusion", ""),
            "investigation_notes": inv.get("investigation_notes", ""),
            "investigation_duration_minutes": inv.get("duration_minutes", ""),
            "evidence_count": inv.get("evidence_count", ""),
            "escalation_id": esc.get("escalation_id", "") or alert.get("escalation_id") or "",
            "escalation_required": str(bool(alert.get("escalation_required"))).lower(),
            "escalation_status": "escalated" if esc or alert.get("escalation_id") else ("required_missing" if alert.get("escalation_required") else "not_required"),
            "escalation_timestamp": esc.get("escalation_time", ""),
            "escalation_owner": esc.get("recipient", ""),
            "response_id": resp.get("response_id", ""), "response_status": resp.get("status", ""),
            "response_timestamp": resp.get("response_time", ""),
            "remediation_id": rem.get("remediation_id", ""), "remediation_action": rem.get("action", ""),
            "remediation_timestamp": rem.get("completed_at", ""),
            "closure_id": case.get("case_id", "") or "", "closure_status": case.get("status", ""),
            "closure_timestamp": case.get("closed_at", ""),
            "evidence_type": "investigation" if inv else "none",
            "evidence_present": str(bool(inv and (inv.get("evidence_count") or 0) >= 2)).lower(),
            "analyst_id": inv.get("analyst_id", ""), "reporting_period": period,
        }

    rows: list[dict[str, Any]] = []
    n = 0
    # Round-robin across entities for balanced coverage. Each entity's queue is
    # an even random sample over the whole period (chronological), so capping
    # max_rows never truncates later reporting months.
    per_entity = max_rows // max(len(by_entity), 1) + 1
    queues = {}
    for eid, alerts in by_entity.items():
        picked = alerts if len(alerts) <= per_entity else random.Random(f"csv-{eid}").sample(alerts, per_entity)
        queues[eid] = sorted(picked, key=lambda a: str(a.get("timestamp", "")))
    while any(queues.values()) and len(rows) < max_rows:
        for eid in sorted(queues):
            if queues[eid] and len(rows) < max_rows:
                n += 1
                rows.append(build_row(n, queues[eid].pop(0)))
    # Inject deliberate edge cases (spec §22) deterministically
    if rows:
        rows[0].update({"severity": "critical", "escalation_required": "true", "escalation_status": "required_missing", "escalation_id": "", "escalation_timestamp": ""})
        if len(rows) > 1:
            rows[1].update({"severity": "high", "case_id": "", "case_status": "", "investigation_status": "missing"})
        if len(rows) > 2:
            rows[2].update({"investigation_conclusion": ""})
        if len(rows) > 3:
            rows[3].update({"response_status": "", "response_id": "", "response_timestamp": ""})
        if len(rows) > 5:
            rows[5].update({"asset_id": "", "asset_name": "", "asset_criticality": ""})
        if len(rows) > 6:
            rows.append(dict(rows[6]))
        if len(rows) > 7:
            rows[7].update({"timestamp": ""})
    # Sparse-reporting entity: 3 fragmentary rows (missing severity,
    # timestamps, assets, cases). Deterministically yields
    # INSUFFICIENT_EVIDENCE — missing evidence is never compliance.
    if rows:
        sparse_keys = list(rows[0].keys())
        for i in range(3):
            sparse = {k: "" for k in sparse_keys}
            sparse.update({
                "record_id": f"rec-sparse-{i+1:02d}",
                "entity_id": "neg",
                "entity_name": "North Eastern Grid Monitor (fictional)",
                "sector": "Power & Energy",
                "alert_id": f"neg-ALR-{i+1:03d}",
                "alert_status": "open",
                "reporting_period": "2026-09",
            })
            rows.append(sparse)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    # Companion self-assessment file for the paper-vs-practice demo.
    from ..analytics import SupervisoryAnalytics
    from ..ingestion import ingest_bytes
    records, _ = ingest_bytes(p.name, p.read_bytes())
    observed = SupervisoryAnalytics({"submissions": [{"id": "csv", "records": records}]}).peer_benchmark()["entities"]
    decl_path = p.with_name("sat_sa_self_assessment.csv")
    with decl_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["entity_id", "metric", "declared_value", "source"])
        w.writeheader()
        w.writerows(build_declarations(observed))
    return {"path": str(p), "rows": len(rows), "sha256": digest, "self_assessment": str(decl_path)}


if __name__ == "__main__":
    main()
