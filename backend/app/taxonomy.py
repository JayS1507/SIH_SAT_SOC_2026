RULE_CATEGORIES = {
    "critical_alert_no_escalation": "execution_gap",
    "closed_without_evidence": "execution_gap",
    "investigation_without_conclusion": "execution_gap",
    "escalation_no_response": "execution_gap",
    "closure_before_investigation": "execution_gap",
    "invalid_status_order": "execution_gap",
    "invalid_status": "execution_gap",
    "alert_without_case": "execution_gap",
    "asset_without_coverage": "negative_space",
    "negative_space_period_gap": "negative_space",
    "repeated_investigation_template": "execution_gap",
    "response_time_anomaly": "execution_gap",
    "duplicate_record": "execution_gap",
}

RULE_ALIASES = {
    "critical no escalation": "critical_alert_no_escalation",
    "critical alerts closed without escalation": "critical_alert_no_escalation",
    "critical alert without escalation": "critical_alert_no_escalation",
    "closed without evidence": "closed_without_evidence",
    "investigation without conclusion": "investigation_without_conclusion",
    "escalation without response": "escalation_no_response",
    "closure before investigation": "closure_before_investigation",
    "alert without case": "alert_without_case",
    "asset without coverage": "asset_without_coverage",
    "reporting gap": "negative_space_period_gap",
    "repeated investigation": "repeated_investigation_template",
    "response time anomaly": "response_time_anomaly",
    "duplicate record": "duplicate_record",
}

# Supervisory controls are intentionally separate from rule taxonomy: a
# control can be insufficiently evidenced without a rule firing.
SUPERVISORY_CONTROLS = {
    "TD-01": "Threat Detection Coverage",
    "INV-01": "Investigation Quality",
    "ES-01": "Escalation Coverage",
    "IR-01": "Incident Response",
    "OP-01": "Operational Discipline",
    "GOV-01": "Governance Oversight",
    "RES-01": "Cyber Resilience",
    "MON-01": "Monitoring Coverage",
}

SUPERVISORY_STATUSES = (
    "EVIDENCED",
    "PARTIALLY_EVIDENCED",
    "NOT_EVIDENCED",
    "POTENTIAL_GAP",
    "REQUIRES_REVIEW",
    "INSUFFICIENT_DATA",
)

SUPERVISORY_CONTROL_IDS = tuple(SUPERVISORY_CONTROLS)
