# SOC-Inspect — Complete SIH Pitch Script

## SIH 2026 | Problem Statement SIH26157

**Project:** SOC-Inspect  
**Official problem:** Supervisory Analytics Tool for SOC Assessment (SAT-SA)  
**Recommended pitch length:** 8 minutes, followed by 2–3 minutes of questions  
**Presentation style:** Calm, evidence-led, confident, and demo-oriented

> **Template note:** The provided Canva URL redirects to an editable Canva design, but its slide content is not readable outside Canva in this environment. This script follows the SIH judging sequence and is written so each scene can be placed into the corresponding template page without changing the claims.

---

## Core message to repeat

> **SOC-Inspect helps a cyber supervisor find the right entity, the right weakness, and the right cases to review—using periodic evidence rather than assumptions.**

## 8-minute delivery map

| Section | Time |
|---|---:|
| Hook and problem | 1:15 |
| Solution and differentiation | 1:35 |
| Architecture | 0:45 |
| Live evidence-to-decision demo | 2:00 |
| Impact and feasibility | 1:25 |
| Proof, roadmap, and closing | 1:00 |

Keep the detailed technology stack and extended Q&A in reserve. The main pitch should tell one story: **a reported SOC capability is checked against the evidence chain that should prove it.**

## Speaking rules

- Do not call the system a SIEM, SOAR, real-time monitor, or autonomous compliance judge.
- Say **prototype** for current implementation and **pilot target** for future measurements.
- Pause after each problem statement and before each measurable claim.
- Point to the evidence trail whenever showing a finding.
- Keep the technology explanation subordinate to the supervisory value.

---

# Scene 1 — Opening hook

**Suggested time:** 25 seconds  
**Slide visual:** Project name, one-line promise, and a simple “evidence to action” pipeline.

### On-slide text

**SOC-Inspect**  
**Evidence-Based Supervisory Analytics for SOC Assessment**

`Periodic SOC evidence → Explainable findings → Human supervisory action`

### Speaker script

“Good morning respected judges, mentors, and fellow participants.

A SOC can report a very high alert-closure rate and still fail to investigate its most important alerts. The problem is not always the number of alerts. It is the evidence missing between **alert, investigation, escalation, response, and closure**.

So here is the question:

**When a SOC report says that everything is under control, how does a supervisor verify that the operational evidence supports that claim?**

Today, that verification often means searching large periodic submissions, manually selecting samples, and trying to connect records across different formats.

Our solution is **SOC-Inspect**—an offline-first, evidence-based supervisory analytics platform for periodic SOC assessment.

SOC-Inspect does not operate the SOC. It helps the supervisor decide **where attention is needed first, why it is needed, and which evidence supports that decision**.”

### Transition

“To understand why this matters, let us look at the supervisory gap.”

---

# Scene 2 — The problem

**Suggested time:** 40 seconds  
**Slide visual:** Large problem statement with three pain points.

### On-slide text

- Manual review does not scale.
- Healthy KPIs can hide weak execution.
- Missing evidence is difficult to distinguish from poor performance.

### Speaker script

“The challenge is not simply that SOCs generate a lot of data. The challenge is proving whether reported capability is reflected in operational evidence.

Consider one example: a critical alert is marked closed. The dashboard looks healthy. But when a supervisor follows the evidence chain, there is no investigation conclusion, no escalation record, and no response action. The closure number is real—but the operational story is incomplete.

The same pattern can appear as a case without evidence, an implausible response time, an important asset without monitoring evidence, or a missing reporting period.

A dashboard can show alert counts and closure percentages, but those numbers do not automatically prove that the process was executed correctly.

Manual review can discover these weaknesses, but it is slow, inconsistent, and difficult to reproduce across multiple entities.

The SIH problem asks for a supervisory layer that can identify execution gaps, negative space, anomalies, peer differences, and review priorities—while keeping the human supervisor in control.

The consequence is important: without prioritization, a supervisor may spend time searching routine records while a repeated process weakness remains hidden.”

### Transition

“Our answer is to treat a periodic submission as evidence that can be validated, connected, tested, and reviewed.”

---

# Scene 3 — The solution

**Suggested time:** 45 seconds  
**Slide visual:** Central pipeline from submission to report.

### On-slide text

`Submit → Validate → Normalize → Analyse → Prioritize → Review → Report`

### Speaker script

“SOC-Inspect accepts periodic SOC evidence in JSON, CSV, XLSX, and restricted plain-text PostgreSQL export formats.

First, it validates the submission and calculates a SHA-256 content hash. Then it maps heterogeneous records into a canonical evidence model containing entities, assets, alerts, cases, investigations, escalations, responses, and closures.

The analytics engine checks the lifecycle:

**Alert, triage, investigation, escalation, response, and closure.**

It identifies execution gaps, missing expected evidence, workflow anomalies, reporting gaps, and contextual peer deviations.

The result is not an unexplained score. It is a prioritized review queue. Each finding includes the source evidence, source row, calculation, rule version, confidence, and limitations.

Finally, the supervisor accepts, rejects, or annotates the finding, and the platform produces a hash-verifiable JSON, HTML, or PDF report.

In one sentence: **we turn a large submission into a defensible list of the evidence gaps a supervisor should inspect first.**”

### Transition

“The most important design decision is that SOC-Inspect is not another operational SOC tool.”

---

# Scene 4 — What makes it different

**Suggested time:** 40 seconds  
**Slide visual:** Comparison: SIEM/SOAR/dashboard/questionnaire versus SOC-Inspect.

### On-slide text

1. External supervisory layer.
2. Evidence before inference.
3. Negative-space detection.
4. Human-in-the-loop.
5. Offline and air-gapped ready.

### Speaker script

“SOC-Inspect is different in five ways.

**First, it is a supervisory layer.** A SIEM monitors and correlates operational events. A SOAR automates response workflows. SOC-Inspect evaluates periodic evidence for an external reviewer.

**Second, it is evidence-first.** Every finding must be traceable to submitted records. If the evidence is insufficient, the system reports insufficient evidence rather than silently treating the entity as compliant.

**Third, it performs negative-space analysis.** It looks not only at what happened, but also at what should reasonably exist but is missing—such as an expected escalation, response action, investigation conclusion, or asset-monitoring evidence.

**Fourth, it is human-in-the-loop.** The engine creates review candidates. The authorized supervisor makes the final decision.

**Fifth, it is offline-first.** Sensitive SOC submissions can remain inside a private or air-gapped environment without continuous telemetry or public-cloud processing.”

### Transition

“Let us now see how a submission moves through the technical architecture.”

---

# Scene 5 — Technical architecture

**Suggested time:** 35 seconds  
**Slide visual:** Seven-stage architecture flow.

### On-slide text

`Ingestion → Quality → Canonical model → Rules → Benchmarking → Review → Report`

### Speaker script

“The architecture has seven practical stages: ingestion, quality validation, canonical evidence mapping, deterministic rules, contextual benchmarking, human review, and reporting.

The important engineering choices are simple. Source-row lineage is preserved, unsupported or unsafe SQL is rejected, rules are versioned, and missing data is not silently treated as success.

The prototype runs offline with SQLite and local artifacts. It can progress to PostgreSQL, private object storage, background processing, and configured identity services without changing the supervisory workflow.

The technology supports the product; the product remains the evidence-to-decision path.”

### Transition

“Architecture is useful only when it produces a decision a supervisor can defend. So let us walk through one finding.”

---

# Scene 6 — Live demo: submission to finding

**Suggested time:** 2 minutes  
**Slide visual:** Use the dashboard and switch to the live prototype.

### Demo preparation

Use the synthetic demo environment:

- Start the backend and frontend from `RUN_PROJECT.md`.
- Open the dashboard.
- Keep one finding with clear source evidence visible.
- Keep the report endpoint or report download ready.

### Speaker script and actions

**Action 1 — Show the dashboard overview**

“This is the supervisor dashboard. It is not calculating an independent frontend score. It displays the authoritative backend assessment and keeps the evidence path visible.”

**Action 2 — Show entity prioritization**

“At the entity level, the supervisor can see which entity requires attention first, the capability signals contributing to that priority, and the strength of the available evidence.”

**Action 3 — Open the concrete lifecycle finding**

“Here is the central example. The alert is marked closed, but the evidence chain is incomplete: the expected investigation conclusion, escalation, or response record is missing. SOC-Inspect does not call this an automatic violation. It creates a review signal.”

**Action 4 — Point to evidence**

“The important part is the drill-down. We can see the entity, source submission, source row, related alert or case, rule version, calculation, confidence, and limitations. The supervisor can verify the finding instead of trusting a black-box score.”

**Action 5 — Show review decision**

“The supervisor can accept, reject, or annotate the finding. That decision is recorded in the audit trail. The platform recommends; the supervisor decides.”

**Action 6 — Show report**

“The final report can be generated in JSON, HTML, or PDF. The submission and report hashes allow later verification that the assessment refers to the same evidence.”

“This is the complete value chain: **reported closure → missing evidence detected → exact record reviewed → human decision recorded.**”

### Demo recovery line

“If the live dashboard is unavailable, the same workflow is available through the documented API and synthetic demo overview. The architectural point remains the same: every prioritized item must lead back to evidence and a human decision.”

### Transition

“This workflow creates value for both the supervisor and the assessed entity.”

---

# Scene 7 — Impact and measurable benefits

**Suggested time:** 40 seconds  
**Slide visual:** Three pillars: faster review, defensible decisions, stronger resilience.

### On-slide text

- Faster supervisory review.
- More defensible decisions.
- Stronger operational resilience.

### Speaker script

“SOC-Inspect creates impact in three measurable ways.

**First, faster review.** Instead of searching every record equally, supervisors receive an evidence-prioritized queue. The pilot metric is the time from submission receipt to the first useful review queue.

**Second, more defensible decisions.** Findings contain source-row lineage, rules, calculations, confidence, limitations, and reviewer decisions. The pilot metric is the percentage of findings with complete evidence lineage.

**Third, stronger operational resilience.** The platform exposes incomplete investigations, missing escalation, response anomalies, reporting gaps, and potential asset-coverage gaps before they become repeated systemic weaknesses. The pilot metric is the number of validated execution gaps identified and resolved by capability domain.

In the prototype demonstration, we will show the number of records screened, findings generated, and findings selected for review. In the pilot, we will measure review time, lineage completeness, and validated gaps. We are deliberately presenting these as measurable targets, not unsupported percentage claims.”

### Transition

“A strong prototype must also be honest about feasibility and risk.”

---

# Scene 8 — Feasibility, risks, and mitigation

**Suggested time:** 35 seconds  
**Slide visual:** Three columns: feasible, risks, mitigations.

### Speaker script

“The solution is feasible because it starts with periodic evidence, proven open technologies, and a deterministic core. It does not require live telemetry, a national centralized SOC, or an external cloud service.

The major risks are real:

- SOC submissions may use different schemas.
- Evidence may be incomplete or inaccurate.
- Rules may create false positives or false negatives.
- Cyber records are sensitive.
- Peer comparisons can be unfair if context is ignored.
- Users may distrust an automated compliance judgement.

Our mitigations are built into the design.

Versioned adapters and a canonical model address schema variation. Evidence-sufficiency states separate missing evidence from poor performance. Human review controls false findings. Role-based access, offline deployment, audit events, and integrity-evident artifacts protect sensitive data. Contextual peer groups avoid simplistic rankings. Finally, we propose a pilot-first rollout with synthetic and approved submissions before sector-wide deployment.”

### Transition

“This is not only a concept. We have implemented and tested the core vertical slice.”

---

# Scene 9 — Prototype proof

**Suggested time:** 25 seconds  
**Slide visual:** Proof badges and small architecture screenshot.

### On-slide text

`15 backend tests passed | Frontend build passed | Migrations passed | Docker profiles validated`

### Speaker script

“The working prototype demonstrates the complete evidence-to-review path.

It includes the FastAPI backend, React and TypeScript dashboard, multi-format ingestion, canonical mapping, deterministic rules, entity risk indicators, peer benchmarking, review decisions, audit events, and JSON, HTML, and PDF reports.

The prototype also demonstrates JWT and role-based access control, Keycloak or OIDC-compatible validation, restricted SQL parsing, local artifact hashing, readiness and metrics endpoints, database migrations, and Docker deployment profiles.

Our current validation includes **15 passing backend tests**, a successful frontend production build, migration upgrade and downgrade verification, authentication and RBAC tests, artifact hashing tests, SQL safety tests, and Docker profile validation. During the demo, the stronger proof is functional: one submission becomes one explainable finding, one review decision, and one verifiable report.

These results prove prototype feasibility. They are not a claim that production deployment is complete.”

### Transition

“The next step is a controlled pilot with domain validation.”

---

# Scene 10 — Roadmap and deployment

**Suggested time:** 25 seconds  
**Slide visual:** Three-stage roadmap.

### Speaker script

“Our roadmap has three stages.

**Stage one is a controlled pilot** with one or two critical-sector entities, approved or synthetic periodic submissions, and supervisor validation of every rule and finding.

**Stage two expands by sector** with configurable peer groups, additional vendor schema adapters, sector-specific control expectations, and longitudinal trend analysis.

**Stage three is a secure supervisory platform** using PostgreSQL, MinIO, Redis or Celery, and a configured Keycloak deployment, with standardized reports and stronger operational governance.

Before production, we will complete load testing, penetration testing, tenant-isolation testing, backup and restore testing, and domain-expert validation.”

### Transition

“Let me close with the value in one sentence.”

---

# Scene 11 — Closing

**Suggested time:** 25 seconds  
**Slide visual:** One-line value proposition and team/project name.

### Speaker script

“SOC-Inspect is not trying to replace the people who supervise cybersecurity.

It gives them a reliable starting point.

It converts periodic SOC evidence into explainable findings, prioritizes the right entities and cases, preserves the evidence trail, and keeps the final decision with the human supervisor.

So our closing message is:

> **Find the right issue. Prove why it matters. Act consistently.**

That is SOC-Inspect—an offline-first, evidence-based supervisory analytics platform for periodic SOC assessment.

With SOC-Inspect, supervisory assessment moves from manual searching to evidence-prioritized cyber-resilience improvement.

Thank you. We are ready for your questions.”

---

# Optional 30-second elevator pitch

“SOC-Inspect is an offline-first supervisory analytics platform for periodic SOC assessment. It ingests alert, case, investigation, escalation, response, closure, and asset evidence; validates and normalizes it; detects execution gaps, missing evidence, anomalies, and peer deviations; and prioritizes the exact entities and cases a supervisor should review. Every finding is traceable to source records, calculations, rule versions, confidence, and limitations. Unlike a SIEM or SOAR, it does not monitor or operate the SOC. It helps an external supervisor determine whether reported capability is supported by operational evidence.”

---

# Judge Q&A preparation

## 1. Is this a SIEM or SOAR replacement?

**Answer:**  
“No. SIEM and SOAR tools support live SOC operations. SOC-Inspect is an external supervisory assessment layer that analyses periodic evidence and prioritizes human review. It does not collect continuous telemetry, correlate live events, or execute response actions.”

## 2. How do you prevent the system from making an unfair judgement?

**Answer:**  
“The system does not make the final judgement. It produces evidence-linked review candidates. Each finding includes confidence and limitations, and an authorized supervisor accepts, rejects, or annotates it. Missing evidence is also separated from confirmed poor performance.”

## 3. What happens when entities submit different formats?

**Answer:**  
“We use versioned ingestion adapters and map records into a canonical evidence model. The original submission and source-row references are retained. Unsupported or unsafe formats are rejected explicitly rather than silently misinterpreted.”

## 4. How do you detect missing evidence?

**Answer:**  
“We reconstruct expected relationships in the alert-to-case lifecycle. For example, if a critical alert should have an escalation or a closed case should have investigation evidence, the absence becomes a review signal. It is labelled as missing or insufficient evidence, not automatically as misconduct.”

## 5. How is the risk score calculated?

**Answer:**  
“The prototype uses deterministic, versioned supervisory rules and normalized indicators. Severity, confidence, evidence strength, capability signals, and contextual peer deviation contribute to prioritization. The calculation is returned with every finding so it can be reviewed.”

## 6. How do you protect sensitive SOC data?

**Answer:**  
“The platform supports offline and air-gapped deployment, role-based access control, restricted ingestion, local artifact storage, audit events, and hash verification. Production deployments can use private PostgreSQL, MinIO, Redis, and configured Keycloak or OIDC services.”

## 7. Why not use machine learning?

**Answer:**  
“For supervisory decisions, explainability and reproducibility come first. The current core is deterministic so a supervisor can understand and challenge each result. Machine learning can be added later for assistance, but it must remain evidence-linked, validated, and subordinate to human review.”

## 8. How will you prove impact?

**Answer:**  
“We will measure it during the pilot: time from submission to first prioritized review, records screened versus manually reviewed, evidence-lineage completeness, validated execution gaps by domain, supervisor decision rates, data-quality issue rate, processing time, and report verification success.”

## 9. Can this scale beyond one machine?

**Answer:**  
“Yes, progressively. The prototype uses SQLite and local artifacts for offline operation. The architecture supports PostgreSQL, MinIO or S3-compatible storage, Redis and Celery for background work, and configured Keycloak or OIDC for multi-user deployment. Scaling will be validated through load and tenant-isolation testing.”

## 10. What is the strongest innovation?

**Answer:**  
“The strongest innovation is the combination of lifecycle-based supervisory analysis and negative-space detection. We do not only count alerts or inspect declared KPIs; we test whether expected operational evidence exists, connect findings to source records, and prioritize human review without replacing the supervisor.”

---

# Presenter checklist

## Before the presentation

- Open the Canva deck and map each scene to the corresponding template page.
- Replace placeholder visuals with the dashboard screenshot or live demo.
- Confirm the project name and team details on the title slide.
- Start the backend and frontend.
- Open the dashboard and verify the demo overview.
- Keep one finding, one review action, and one report ready.
- Confirm that no slide claims achieved pilot percentages.

## During the presentation

- Start with the supervisory problem, not the technology stack.
- Say “periodic evidence” clearly and repeatedly.
- Use “potential gap” or “review signal” when evidence is not conclusive.
- Point from every finding to its source evidence.
- Pause after the five differentiators.
- Keep the demo under two minutes.
- End with the one-line value proposition.

## If time is reduced to five minutes

Use Scenes 1, 2, 3, 4, 6, 7, and 11.  
Skip the detailed architecture and move the feasibility and test proof into one sentence:

> “The prototype is validated with 15 backend tests, a production frontend build, migration checks, authentication tests, artifact hashing, SQL safety checks, and Docker deployment profiles.”
