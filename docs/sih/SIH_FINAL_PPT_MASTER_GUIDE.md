# SOC-Inspect — Final SIH PPT Master Guide

## SIH 2026 | Problem Statement SIH26157

**Project:** SOC-Inspect  
**Official problem:** Supervisory Analytics Tool for SOC Assessment (SAT-SA)  
**Recommended presentation:** 12 slides, 8 minutes, followed by 2–3 minutes of questions  
**Audience:** SIH judges, cybersecurity experts, industry reviewers, and mentors

> This is the single master source for creating the final PowerPoint. Use the **On-slide content** for the PPT and the **Speaker script** as presenter notes. Do not paste the complete project documentation onto slides.

---

# 1. Final pitch positioning

## One-line description

> **SOC-Inspect is an offline-first, evidence-based supervisory analytics platform for periodic SOC assessment.**

## Core judge message

> **SOC-Inspect helps a cyber supervisor find the right entity, the right weakness, and the right cases to review—using periodic evidence rather than assumptions.**

## Central story

```text
Reported SOC capability
        ↓
Operational evidence chain
        ↓
Missing or inconsistent evidence
        ↓
Explainable review signal
        ↓
Human supervisory decision
        ↓
Verifiable report
```

## The problem in one example

> A critical alert is marked closed. The dashboard looks healthy. But the evidence chain has no investigation conclusion, escalation record, or response action. The closure number is real—the operational story is incomplete.

## Five points judges must remember

1. Healthy SOC KPIs can hide broken operational evidence.
2. SOC-Inspect converts periodic evidence into prioritized supervisory review.
3. Its strongest innovation is lifecycle analysis plus negative-space detection.
4. Findings are explainable, and a human supervisor makes the final decision.
5. One submission becomes a finding, a review decision, and a verifiable report.

---

# 2. Final presentation structure

| Slide | Title | Target time |
|---:|---|---:|
| 1 | Title and hook | 25 sec |
| 2 | Supervisory problem | 40 sec |
| 3 | Proposed solution | 45 sec |
| 4 | SIH requirement mapping | 35 sec |
| 5 | Innovation and differentiation | 40 sec |
| 6 | Technical approach | 35 sec |
| 7 | Live prototype demo | 2 min |
| 8 | Impact and benefits | 40 sec |
| 9 | Feasibility, risks, mitigation | 35 sec |
| 10 | Prototype proof | 25 sec |
| 11 | Roadmap and scale path | 25 sec |
| 12 | Closing | 25 sec |
|  | **Total planned time** | **Approximately 8 min** |

Keep detailed technology explanations and extended answers for Q&A.

---

# 3. Slide-by-slide PPT specification

## Slide 1 — Title and hook

### On-slide content

**SOC-Inspect**  
**Evidence-Based Supervisory Analytics for SOC Assessment**

`Periodic SOC evidence → Explainable findings → Human supervisory action`

Footer:

`SIH 2026 | Problem Statement SIH26157 | Team name | Institution`

### Visual

Use a clean title layout with one simple evidence-to-action pipeline. Make **SOC-Inspect** the largest text.

### Speaker script

> “Good morning respected judges, mentors, and fellow participants.
>
> A SOC can report a very high alert-closure rate and still fail to investigate its most important alerts. The problem is not always the number of alerts. It is the evidence missing between alert, investigation, escalation, response, and closure.
>
> SOC-Inspect helps a supervisor verify whether reported SOC capability is actually supported by operational evidence.”

### Design rating

**10/10 when visually clean and free of technical clutter.**

---

## Slide 2 — Supervisory problem

### On-slide content

**The gap: healthy KPIs do not always prove healthy execution**

- Manual review does not scale.
- Aggregate KPIs can hide broken workflows.
- Missing evidence is difficult to distinguish from poor performance.

Lifecycle visual:

```text
Alert → Investigation → Escalation → Response → Closure
```

Callout:

```text
Closed alert
      ↓
Missing investigation / escalation / response evidence
```

### Speaker script

> “The challenge is not simply that SOCs generate a lot of data. The challenge is proving whether reported capability is reflected in operational evidence.
>
> A critical alert may be marked closed while investigation, escalation, and response evidence are missing. Manual review can discover this, but it is slow, inconsistent, and difficult to reproduce across entities.
>
> Without prioritization, a supervisor may spend time searching routine records while a repeated process weakness remains hidden.”

### Design rating

**9.5/10.** Use one concrete example, not a long list of defects.

---

## Slide 3 — Proposed solution

### On-slide content

```text
Periodic Submission
        ↓
Validate and Hash
        ↓
Canonical Evidence Model
        ↓
Detect Gaps and Anomalies
        ↓
Prioritize Review
        ↓
Human Decision
        ↓
Verifiable Report
```

Highlight:

- Offline-first
- Evidence-based
- Human-supervised
- Periodic assessment

### Speaker script

> “SOC-Inspect accepts periodic SOC evidence, validates it, calculates a content hash, and maps heterogeneous records into a canonical evidence model.
>
> It checks the alert-to-case lifecycle, detects execution gaps, missing expected evidence, anomalies, reporting gaps, and contextual peer deviations.
>
> The output is not an unexplained score. It is a prioritized review queue with source evidence, source row, calculation, rule version, confidence, and limitations.
>
> In one sentence: we turn a large submission into a defensible list of the evidence gaps a supervisor should inspect first.”

### Design rating

**10/10.**

---

## Slide 4 — SIH requirement mapping

### On-slide content

| SIH requirement | SOC-Inspect response |
|---|---|
| Periodic SOC submissions | JSON, CSV, XLSX, restricted SQL exports |
| Execution-gap detection | Lifecycle and control checks |
| Negative-space analysis | Missing expected evidence |
| Peer benchmarking | Contextual normalized indicators |
| Review prioritization | Entity and case review queue |
| Explainability | Source lineage, calculations, rule version |
| Human supervision | Accept, reject, annotate workflow |
| Offline deployment | SQLite and private deployment model |

### Speaker script

> “The solution is designed directly around the required supervisory outcomes: evidence ingestion, execution-gap detection, negative-space analysis, peer comparison, explainable review prioritization, human judgement, and privacy-preserving deployment.”

### Design rating

**9.5/10.** Keep the table short and readable.

---

## Slide 5 — Innovation and differentiation

### On-slide content

Five pillars:

1. **External supervisory layer**
2. **Evidence before inference**
3. **Negative-space detection**
4. **Alert-to-case lifecycle analysis**
5. **Human-in-the-loop and offline-ready**

Comparison:

| Tool | Primary purpose |
|---|---|
| SIEM | Real-time monitoring and correlation |
| SOAR | Response workflow automation |
| Dashboard | KPI visualization |
| Questionnaire | Self-reported assessment |
| **SOC-Inspect** | **Evidence-based supervisory assessment** |

### Speaker script

> “We are not building another SIEM, SOAR, or dashboard.
>
> SOC-Inspect is the external supervisory evidence-analysis layer. It tests whether expected operational evidence exists, identifies what is missing, links the result back to the source, and keeps the final decision with the supervisor.”

### Design rating

**10/10** if the five pillars are visual rather than paragraph-heavy.

---

## Slide 6 — Technical approach

### On-slide content

```text
Ingestion
   ↓
Validation and Data Quality
   ↓
Canonical Evidence Mapping
   ↓
Deterministic Analytics
   ↓
Risk and Review Prioritization
   ↓
Human Review
   ↓
Report and Audit
```

Technology strip:

```text
React + TypeScript | FastAPI | SQLite/PostgreSQL | Docker
JWT/OIDC | SHA-256 artifacts | Optional MinIO/Redis
```

### Speaker script

> “The architecture has seven practical stages: ingestion, quality validation, canonical evidence mapping, deterministic rules, contextual benchmarking, human review, and reporting.
>
> Source-row lineage is preserved, unsafe SQL is rejected, rules are versioned, and missing data is not silently treated as success.
>
> The prototype runs offline with SQLite and local artifacts. It has a clear path to PostgreSQL, private object storage, background processing, and configured identity services.”

### Do not explain in the main pitch

- Correlation IDs
- Alembic internals
- Prometheus implementation details
- Nginx
- Optional GPU
- Every dependency
- Detailed SQL parser rules

### Design rating

**9/10.**

---

## Slide 7 — Live prototype demo

### On-slide content

Show the dashboard, not a dense text slide.

Demo sequence:

```text
Submission → Entity priority → Finding → Evidence → Review → Report
```

### Demonstration actions and exact narration

#### 1. Dashboard overview

> “This is the supervisor dashboard. It displays the authoritative backend assessment and keeps the evidence path visible.”

#### 2. Entity prioritization

> “The supervisor can see which entity requires attention first, the capability signals contributing to that priority, and the strength of the available evidence.”

#### 3. Open the lifecycle finding

> “This alert is marked closed, but the expected investigation conclusion, escalation, or response evidence is missing. SOC-Inspect does not call this an automatic violation. It creates a review signal.”

#### 4. Show evidence drill-down

> “We can see the entity, source submission, source row, related alert or case, rule version, calculation, confidence, and limitations. The supervisor can verify the finding instead of trusting a black-box score.”

#### 5. Record human decision

> “The supervisor can accept, reject, or annotate the finding. That decision is recorded in the audit trail. The platform recommends; the supervisor decides.”

#### 6. Generate report

> “The report can be generated in JSON, HTML, or PDF. Submission and report hashes allow later verification that the assessment refers to the same evidence.”

#### 7. Close the demo

> “This is the complete value chain: reported closure, missing evidence detected, exact record reviewed, and human decision recorded.”

### Demo recovery line

> “If the live dashboard is unavailable, the same workflow is available through the documented API and synthetic demo overview. Every prioritized item must still lead back to evidence and a human decision.”

### Design rating

**Potentially 10/10.** Demo reliability is decisive.

---

## Slide 8 — Impact and benefits

### On-slide content

Three pillars:

#### Faster review

Evidence-prioritized review queue.

#### Defensible decisions

Source lineage, calculations, confidence, limitations, and audit trail.

#### Stronger resilience

Detection of repeated execution and evidence weaknesses.

Before/after:

| Conventional review | With SOC-Inspect |
|---|---|
| Manual sampling | Evidence-prioritized queue |
| Static KPIs | Lifecycle evidence analysis |
| Weak traceability | Source-row lineage |
| Difficult reproduction | Versioned rules |
| Manual reports | Hash-verifiable reports |

### Speaker script

> “SOC-Inspect creates impact in three measurable ways: faster supervisory review, more defensible decisions, and stronger operational resilience.
>
> In the prototype demonstration, we show records screened, findings generated, and findings selected for review. In the pilot, we measure review time, evidence-lineage completeness, and validated execution gaps.
>
> These are measurable targets, not unsupported percentage claims.”

### Design rating

**9/10.**

---

## Slide 9 — Feasibility, risks, and mitigation

### On-slide content

| Feasible | Risks | Mitigation |
|---|---|---|
| Offline-first | Schema variation | Versioned adapters |
| Explainable | Missing evidence | Sufficiency classification |
| Human-supervised | False findings | Supervisor review |
| Scalable path | Sensitive data | RBAC and private deployment |
| Tested prototype | Peer comparison bias | Contextual peer groups |

### Speaker script

> “The solution is feasible because it starts with periodic evidence, a deterministic core, and proven open technologies. It does not require live telemetry, a national centralized SOC, or an external cloud service.
>
> Schema variation, missing evidence, false findings, privacy, peer bias, and adoption are real risks. We address them through versioned adapters, evidence-sufficiency states, human review, role-based access, offline deployment, audit events, and pilot-first rollout.”

### Design rating

**9/10.**

---

## Slide 10 — Prototype proof

### On-slide content

```text
15 backend tests passed
Frontend production build passed
Migration cycle passed
Docker profiles validated
```

Functional proof:

```text
Submission → Finding → Review Decision → Report
```

### Speaker script

> “The strongest proof is functional: one submission becomes one explainable finding, one review decision, and one verifiable report.
>
> The prototype also demonstrates multi-format ingestion, canonical mapping, deterministic rules, entity risk indicators, peer benchmarking, review decisions, audit events, reports, authentication, artifact hashing, SQL safety checks, migrations, metrics, and Docker deployment profiles.”

### Clearly achieved

- 15 backend tests passed
- Frontend build passed
- Migration upgrade/downgrade passed
- Authentication and RBAC tests passed
- Artifact hashing tests passed
- SQL safety tests passed
- Docker profiles validated

### Do not claim yet

- Production-scale performance
- Real-world accuracy
- Guaranteed review-time reduction
- Production tenant isolation
- Completed penetration testing
- Sector-wide deployment

### Design rating

**9/10.**

---

## Slide 11 — Roadmap and scale path

### On-slide content

#### Stage 1 — Controlled pilot

- One or two critical-sector entities
- Approved or synthetic submissions
- Supervisor validation
- Baseline measurement

#### Stage 2 — Sector expansion

- Additional schema adapters
- Contextual peer groups
- Sector-specific controls
- Longitudinal trends

#### Stage 3 — Secure supervisory platform

- PostgreSQL
- Private object storage
- Background processing
- Configured Keycloak/OIDC
- Standardized reporting

### Speaker script

> “We scale the deployment, not the level of unsupported automation. Human supervisory authority remains central at every stage.
>
> Before production, we will complete load testing, penetration testing, tenant-isolation testing, backup and restore testing, and domain-expert validation.”

### Design rating

**9/10.**

---

## Slide 12 — Closing

### On-slide content

> **Find the right issue.**  
> **Prove why it matters.**  
> **Act consistently.**

Subtitle:

> **From manual searching to evidence-prioritized cyber-resilience improvement.**

Footer:

`Team name | Institution | Contact or QR code`

### Speaker script

> “SOC-Inspect does not replace the people who supervise cybersecurity. It gives them a reliable, explainable starting point.
>
> It converts periodic SOC evidence into explainable findings, prioritizes the right entities and cases, preserves the evidence trail, and keeps the final decision with the human supervisor.
>
> Find the right issue. Prove why it matters. Act consistently.
>
> That is SOC-Inspect—an offline-first, evidence-based supervisory analytics platform for periodic SOC assessment.
>
> Thank you. We are ready for your questions.”

### Design rating

**10/10.**

---

# 4. Final claim and terminology audit

## Use these exact terms

| Preferred wording | Avoid |
|---|---|
| Periodic SOC assessment | Real-time SOC monitoring |
| Supervisory analytics | Autonomous compliance |
| Review signal | Automatic violation |
| Potential asset-coverage gap | Complete asset monitoring assessment |
| Integrity-evident | Tamper-proof |
| Hash-verifiable | Legally immutable |
| Prototype demonstrates | Production-ready |
| Pilot target | Achieved business impact |
| Configured Keycloak/OIDC deployment | Keycloak is fully deployed |
| Restricted SQL export parsing | Full SQL support |
| Human supervisor decides | AI decides |
| Scale-out path | Proven production scalability |

## Claims that are supported

- Offline-first prototype
- SQLite operation
- PostgreSQL compatibility
- JSON, CSV, XLSX, and restricted SQL export ingestion
- SHA-256 hashing
- Source-row lineage
- Deterministic rules
- Entity risk indicators
- Peer benchmarking framework
- Review queue
- Supervisor annotations
- Audit events
- JSON, HTML, and PDF reports
- JWT and RBAC
- Keycloak/OIDC-compatible validation
- Optional Redis/Celery boundary
- Prometheus-compatible metrics
- 15 backend tests passed

## Claims requiring careful wording

### Artifact integrity

Use:

> “Integrity-evident local artifacts with overwrite protection.”

Do not use “tamper-proof” or “legally immutable” for SHA-256 alone.

### Encryption

Only claim encryption as implemented if it is configured and tested. Otherwise write:

> “Encryption can be configured for production deployment.”

### Scalability

Use:

> “The architecture provides a scale-out path.”

Do not claim proven production scalability without load testing.

### Peer benchmarking

Use:

> “Prototype contextual peer benchmarking framework.”

Real production peer groups require governance based on sector, size, asset count, alert volume, and operating model.

### Asset coverage

Use:

> “Potential asset-coverage and monitoring-evidence gaps.”

Do not claim a complete critical-asset monitoring policy engine.

---

# 5. Visual design system

## Color meaning

- **Blue:** evidence, trust, ingestion, validation
- **Orange:** gaps, anomalies, risk, review priority
- **Green:** decision, mitigation, resilience, improvement
- Dark navy or charcoal background
- White text with high contrast

## Slide density

Every slide should contain:

- One main message
- Three to five supporting points
- One diagram, table, screenshot, or metric
- No paragraph longer than two lines

Move detailed explanations into speaker notes or backup slides.

## Typography

- Slide title: 30–38 pt
- Main statement: 24–30 pt
- Body text: 18–22 pt
- Footnotes/references: minimum 14–16 pt

Never reduce text below readable size to fit the entire Markdown document.

## Visual consistency

- Use the same pipeline language on Slides 1, 3, 6, and 7.
- Use the same lifecycle language everywhere:

```text
Alert → Triage → Investigation → Escalation → Response → Closure
```

- Use one icon style.
- Avoid decorative cyber imagery that does not explain the workflow.
- Use a real dashboard screenshot or controlled live demo.

---

# 6. Demo-readiness checklist

## Before the presentation

- [ ] Backend starts without errors.
- [ ] Frontend loads without internet access.
- [ ] Synthetic evidence is preloaded.
- [ ] One clear lifecycle finding is available.
- [ ] Source-row lineage is visible.
- [ ] Rule version and calculation are visible.
- [ ] Review action works.
- [ ] Report generation works.
- [ ] Hash verification can be explained.
- [ ] Screenshots or a screen recording are ready as backup.

## Demo flow

```text
Dashboard
  → Entity priority
  → Lifecycle finding
  → Evidence drill-down
  → Human review
  → Hash-verifiable report
```

## Demo failure rule

Do not spend more than 15 seconds troubleshooting live infrastructure. Switch to the screenshot or recorded workflow and continue the explanation.

---

# 7. Judge Q&A preparation

## Is this a SIEM or SOAR replacement?

> “No. SIEM and SOAR tools support live SOC operations. SOC-Inspect is an external supervisory assessment layer that analyses periodic evidence and prioritizes human review. It does not collect continuous telemetry, correlate live events, or execute response actions.”

## How do you prevent unfair judgement?

> “The system does not make the final judgement. It produces evidence-linked review candidates. Each finding includes confidence and limitations, and an authorized supervisor accepts, rejects, or annotates it. Missing evidence is separated from confirmed poor performance.”

## What happens when entities submit different formats?

> “Versioned ingestion adapters map records into a canonical evidence model. Original submissions and source-row references are retained. Unsupported or unsafe formats are rejected explicitly rather than silently misinterpreted.”

## How do you detect missing evidence?

> “We reconstruct expected relationships in the alert-to-case lifecycle. If a critical alert should have an escalation or a closed case should have investigation evidence, the absence becomes a review signal. It is labelled as missing or insufficient evidence, not automatically as misconduct.”

## How is the risk score calculated?

> “The prototype uses deterministic, versioned rules and normalized indicators. Severity, confidence, evidence strength, capability signals, and contextual peer deviation contribute to prioritization. The calculation is returned with every finding.”

## How do you protect sensitive SOC data?

> “The platform supports offline and air-gapped deployment, role-based access control, restricted ingestion, local artifact storage, audit events, and hash verification. Production deployments can use private PostgreSQL, MinIO, Redis, and configured Keycloak or OIDC services.”

## Why not use machine learning?

> “For supervisory decisions, explainability and reproducibility come first. The current core is deterministic so a supervisor can understand and challenge each result. Machine learning may assist later, but it must remain evidence-linked, validated, and subordinate to human review.”

## How will you prove impact?

> “The pilot will measure time from submission to first prioritized review, records screened versus manually reviewed, evidence-lineage completeness, validated execution gaps by domain, supervisor decision rates, data-quality issue rate, processing time, and report verification success.”

## Can this scale beyond one machine?

> “Yes, progressively. The prototype uses SQLite and local artifacts for offline operation. The architecture supports PostgreSQL, private object storage, background processing, and configured identity services. Production scaling will be validated through load and tenant-isolation testing.”

## What is the strongest innovation?

> “The strongest innovation is the combination of lifecycle-based supervisory analysis and negative-space detection. We do not only count alerts or inspect declared KPIs; we test whether expected operational evidence exists, connect findings to source records, and prioritize human review without replacing the supervisor.”

## How will real SOC practitioners validate the rules?

> “The controlled pilot will use approved or synthetic submissions and supervisor/domain-expert review. Rule acceptance, rejection, annotation, false-positive patterns, and evidence sufficiency will be measured before wider deployment.”

## What is the integration path?

> “The first integration boundary is periodic export ingestion. Additional vendor adapters can map approved JSON, CSV, XLSX, and export schemas into the canonical evidence model while preserving source lineage. Live telemetry integration is intentionally outside the current problem scope.”

---

# 8. Presenter delivery checklist

## Delivery

- [ ] Full pitch is under 8 minutes.
- [ ] Demo is under 2 minutes.
- [ ] Opening is memorized.
- [ ] Closing is memorized.
- [ ] Every speaker knows the transition.
- [ ] Technology details are not overexplained.
- [ ] Pilot targets are not presented as achieved outcomes.
- [ ] The five core judge messages are clear.

## Team handoff

Recommended allocation:

- Speaker 1: Slides 1–3
- Speaker 2: Slides 4–6
- Speaker 3: Slides 7–9
- Speaker 1: Slides 10–12 and closing

Do not switch speakers during the live demo unless rehearsed.

## Final delivery advice

- Start with the supervisory problem, not the technology stack.
- Pause after the opening example.
- Say “periodic evidence” clearly.
- Say “review signal” instead of “violation.”
- Point from every finding to its source evidence.
- Keep the demo under two minutes.
- End with the three-line closing statement.

---

# 9. Final evaluation

| Evaluation area | Expected score |
|---|---:|
| SIH problem alignment | 9.5/10 |
| Problem clarity | 9.5/10 |
| Innovation | 9.0/10 |
| Technical feasibility | 9.1/10 |
| Prototype proof | 9.0/10 |
| Industry credibility | 9.0/10 |
| Impact clarity | 9.0/10 |
| Presentation quality | 9.5/10 |
| **Overall PPT readiness** | **9.2–9.7/10** |

The presentation reaches a practical 10/10 standard when:

1. The slides remain visual and concise.
2. The live demo successfully completes the evidence-to-decision flow.
3. No unsupported production or impact claims are added.
4. The team stays within eight minutes.
5. Every speaker can answer the prepared industry questions.

## Final instruction

> **Do not copy the Markdown documents directly onto slides. Convert them into visual slides and keep the detailed explanation in the speaker notes.**

The decisive visual story is:

```text
Periodic evidence
→ Missing lifecycle evidence
→ Explainable finding
→ Human decision
→ Verifiable report
```

