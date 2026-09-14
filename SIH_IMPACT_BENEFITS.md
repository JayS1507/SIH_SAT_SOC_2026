# SIH Slide: Impact & Benefits

## From Evidence to Action

> **SOC-Inspect does not replace supervisory judgement — it makes that judgement faster, more consistent, and evidence-based.**

## Three Measurable Impact Pillars

### 1. Faster supervisory review

- Screens periodic SOC evidence automatically.
- Prioritizes high-risk entities, controls, alerts, and cases.
- Targets reduction in manual search effort; measure this during the pilot.
- **Pilot metric:** time from submission receipt to the first prioritized review queue.

### 2. More defensible decisions

- Links every finding to source rows and evidence.
- Records rules, calculations, confidence, limitations, and reviewer decisions.
- Produces hash-verifiable, audit-ready reports.
- **Pilot metric:** percentage of findings with complete evidence lineage.

### 3. Stronger operational resilience

- Detects missing escalation, incomplete investigations, response anomalies, reporting gaps, and asset coverage gaps.
- Reveals weaknesses that ordinary KPI dashboards may miss.
- Helps entities identify and correct process and evidence weaknesses before they become systemic.
- **Pilot metric:** validated execution gaps identified and resolved by capability domain.

## Before vs After

| Conventional review | With SOC-Inspect |
|---|---|
| Manual sample selection | Evidence-prioritized review queue |
| Static KPI-focused reports | Operational evidence analysis |
| Difficult to reproduce | Versioned and repeatable rules |
| Weak source traceability | Source-row evidence lineage |
| Subjective entity comparison | Context-aware peer benchmarking |
| Manual report preparation | Hash-linked report generation |

## Stakeholder Value

| Stakeholder | Measurable value |
|---|---|
| **Supervisors** | Faster review prioritization and clearer evidence drill-down. |
| **Regulators** | More consistent, comparable, and defensible assessments. |
| **SOC entities** | Clear process and evidence improvement priorities. |
| **Auditors** | Traceable records, reviewer decisions, and hash-verifiable reports. |
| **Leadership** | Capability-level risk visibility across the SOC lifecycle. |
| **Critical-sector ecosystem** | Earlier identification of repeated or systemic operational weaknesses. |

## Pilot Measurement Framework

The pilot will measure outcomes rather than claim unverified savings:

- Median time from submission receipt to first prioritized review.
- Number of records screened versus records selected for manual review.
- Percentage of findings containing complete source-row lineage.
- Number of validated execution gaps by capability domain.
- Supervisor acceptance, rejection, and annotation rates.
- Submission data-quality issue rate.
- Assessment processing time per submission.
- Report generation and hash-verification success rate.

## Value Chain

```text
Periodic SOC submission
        ↓
Validated and normalized evidence
        ↓
Execution gaps + negative space + anomalies
        ↓
Entity risk and peer comparison
        ↓
Prioritized manual review
        ↓
Evidence-linked supervisory decision
        ↓
Actionable improvement and stronger cyber resilience
```

## Strategic Differentiation

- **Not another SIEM:** It does not monitor networks or replace SOC operations.
- **Not another dashboard:** It tests whether operational evidence supports reported capability.
- **Not an autonomous judge:** It creates review candidates; supervisors make the final decision.
- **Not dependent on live telemetry:** It works with periodic, privacy-preserving submissions.
- **Not a black box:** Findings are explainable, traceable, versioned, and auditable.

## Pilot-to-Scale Impact

### Phase 1 — Controlled pilot

- One or two critical-sector entities.
- Synthetic and approved periodic SOC submissions.
- Supervisor validation of rules and findings.
- Baseline measurement of review effort and evidence quality.

### Phase 2 — Sector expansion

- Configurable peer groups.
- Additional vendor schema adapters.
- Sector-specific control expectations.
- Longitudinal assessment and trend analysis.

### Phase 3 — Supervisory platform

- Multi-entity secure deployment.
- PostgreSQL, MinIO, Redis/Celery, and Keycloak.
- Standardized reporting and audit workflows.
- Cross-sector cyber-resilience improvement indicators.

## Bottom Impact Strip

> **Less searching • Better evidence • Faster prioritization • More consistent supervision • Stronger cyber resilience**

## 30-Second Judge Explanation

> “Today, supervisors spend significant effort searching through large periodic SOC submissions before they know where attention is needed. SOC-Inspect changes that workflow by screening evidence, detecting execution gaps and missing evidence, and prioritizing the entities and cases that require human review. Every finding is traceable to source records and reproducible calculations. The pilot will measure review time, evidence completeness, prioritized findings, and validated process gaps. This creates faster, more defensible supervision without requiring access to live SOC telemetry.”

## Recommended Visual Layout

```text
┌────────────────────────────────────────────────────────────┐
│              IMPACT & BENEFITS: EVIDENCE → ACTION          │
│  Faster review | Defensible decisions | Stronger resilience │
├────────────────────────────────────────────────────────────┤
│  ⚡ FASTER REVIEW       🔗 DEFENSIBLE        🛡 RESILIENCE  │
│  Prioritized queue      Source lineage       Gap detection  │
│  Pilot: review time     Pilot: traceability  Pilot: gaps    │
├──────────────────────┬─────────────────────────────────────┤
│ BEFORE               │ WITH SOC-INSPECT                    │
│ Manual sampling      │ Evidence-prioritized review         │
│ Static KPIs          │ Operational evidence analysis       │
│ Hard to reproduce    │ Versioned rules and calculations    │
│ Weak traceability    │ Source-row lineage and hash reports │
├──────────────────────┴─────────────────────────────────────┤
│ Less searching • Better evidence • Stronger cyber resilience│
└────────────────────────────────────────────────────────────┘
```

## Presentation Guidance

- Use three visual pillars: blue for review speed, purple for evidence, and green for resilience.
- Put one measurable pilot metric under each pillar.
- Use the before/after table as the central proof of value.
- Keep stakeholder benefits in a compact side panel or speaker notes.
- Present pilot metrics as measurement targets, not achieved results.
- Do not claim a fixed percentage reduction without pilot evidence.
- Keep the closing statement visible:

> **Find the right issue, prove why it matters, and act consistently.**
