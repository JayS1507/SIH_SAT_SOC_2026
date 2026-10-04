# SOC-Inspect — Technical Architecture Pitching Script

> Use: **Technical Round / Demonstration portion of the SIH 2026 presentation.**
> Timing: ~4 minutes script + live demo + Q&A hints.

---

## THE SCRIPT

### 0. OPENING LINE (15 seconds)

> "Supervising a nation's critical-sector SOCs from periodic submissions is a data problem. Our answer is SOC-Inspect — a deterministic, evidence-first, human-supervised analytics platform."

---

### 1. THE HARD PROBLEM (30 seconds)

> "Every month, each critical-sector entity sends its SOC records — alerts, cases, investigations, escalations, responses, closures. But they arrive in different formats, with different column names, different quality levels, and different definitions of 'done'.
>
> If you're the supervisor, you have three problems: **How do I know who is actually compliant? How do I know how risky they are? And can I prove every conclusion I make?**
>
> A black-box ML model can't give you proof. An LLM hallucinates. So we built the opposite: a system where **same data set in → identical numbers out, every single time**, and every number points back to its source row."

---

### 2. THE ARCHITECTURE IN ONE BREATH (30 seconds)

> "The architecture is a pipeline of seven layers: **a FastAPI backend**, a **deterministic Python rule engine**, a **12-control compliance calculator**, a **peer-aware risk scorer**, an **analytics star schema**, a **human review layer**, and a **React supervisor dashboard** — all persisting through SQLAlchemy into SQLite for the air-gapped demo and PostgreSQL at scale. Every upload is stored as a **SHA-256 content-addressed artifact**, so nothing can be tampered with after the fact."

*(Optional: flash the architecture diagram here.)*

---

### 3. START-TO-END FLOW — "WHAT HAPPENS TO YOUR DATA" (2 minutes)

> **Step one — Secure intake.** An authenticated data provider uploads JSON, CSV, XLSX, or even a PostgreSQL dump.
>
> *(Click upload.)* "For SQL, we wrote a **restricted parser** — it accepts only `INSERT` and `COPY` blocks and **never executes anything**. DDL, functions, unsafe expressions — rejected on arrival."
>
> **Step two — Immutability.** The original bytes are immediately hashed with SHA-256 and stored as an artifact — in local storage offline, or MinIO/S3 in production. From this moment, the source of truth is tamper-evident.
>
> **Step three — Fail-closed quality gate.** Every row is validated through Pydantic: has an entity ID? a timestamp? a severity? Missing data is not silently accepted — it surfaces as a quality issue, and later becomes *insufficient evidence*, never compliance.
>
> **Step four — Canonical mapping.** Field aliases like `user`, `host`, `entity` are normalized. We reconstruct the alert-to-case-to-closure lifecycle and index everything in memory.
>
> **Step five — The rule engine.** Thirteen versioned, deterministic rules scan every row: a critical alert that wasn't escalated, a case closed without evidence, an escalation with no response, closure before investigation, duplicates, copy-paste investigations, response-time outliers.
>
> *(Show a finding.)* "Every finding is a structured object — rule, severity, confidence, rule version, and a calculation string — plus **evidence walk pointers to the exact source rows**. Nothing is opaque."
>
> **Step six — Compliance, but explicit.** We evaluate twelve supervisory controls per entity — threat detection, triage, escalation, incident response, closure discipline, data quality. Each control is a fraction: evidence observed over evidence expected. Coverage below 50% is `INSUFFICIENT_EVIDENCE`; there is no silent pass.
>
> **Step seven — Risk you can audit.** Our risk score is a transparent formula, not a magic number: severity weights, evidence strength, and a peer-deviation multiplier computed with a standard z-score against the sector median. Above it, you can read the **named contributing factors**.
>
> **Step eight — Analytics.** A star-schema engine computes ten KPIs: compliance distribution, the alert-to-closure funnel, sector comparison, execution gaps, a data-quality composite score, and a ranked attention matrix.
>
> **Step nine — Human decides.** Analytics only *create candidates*. The queue is severity-sorted but **round-robin across entities and rules**, so no single noisy entity can drown the review. The supervisor validates, rejects, or requests evidence — and **every click is written to a hash-chained audit trail**.
>
> **Step ten — Proof on paper.** Finally we generate JSON, HTML, or PDF report that embeds the dataset hash and re-verifies it. The report is hash-signed. Supervisor decisions, evidence, and provenance all in one artifact."

*(This is your demonstration. Pause. Point at the dashboard.)*

---

### 4. THE TECHNOLOGY CHOICES — AND WHY (45 seconds)

> "Three deliberate decisions make this trustworthy at scale:
>
> **First, deterministic core.** Using pure Python with `statistics` for medians and z-scores — no ML, no hidden weights, no drift between runs. Regulators can reproduce every score by hand.
>
> **Second, fail closed.** Missing data becomes insufficient evidence, not a pass. This single design choice prevents 'garbage in, compliant out'.
>
> **Third, offline-first.** The demo runs on SQLite with local artifacts and zero external services. In production the exact same code swaps to PostgreSQL 16, Redis with Celery, and MinIO — proven by our Docker Compose **production profile**."

---

### 5. PROOF & CLOSING (20 seconds)

> "And the proof: **fifty-six backend tests passing** — compliance maths, risk, ingestion, audit chaining, the SQL safety parser. A strict TypeScript build. Alembic migrations verified up and down. A deterministic, twenty-entity dataset of eleven-thousand-plus rows that replays the exact same numbers every single time.
>
> SOC-Inspect doesn't replace the supervisor — it gives the supervisor **evidence, priority, and auditability**. Thank you."

---

## LIVE DEMO SCRIPT (90 seconds, optional)

> "Let me show you the whole pipeline in under ninety seconds.
> *(1) Here's the dashboard overview* — ten KPIs computed from the demo submission.
> *(2) Now I upload the CSV* — watch the pipeline: hash stored, quality issues listed, assessment queued.
> *(3) Assessment completes* — the rule engine fired. Here's a critical finding: *alert not escalated*, and if I click it, the evidence row and the calculation behind it.
> *(4) Compliance page* — twelve controls per entity, and the classification state.
> *(5) I validate this finding* — and there it is in the audit trail with its hash.
> *(6) One click to the PDF report* — dataset hash inside, verified."

---

## EXPECTED JUDGE QUESTIONS & ANSWERS

**Q: Why not machine learning?**
> "For a supervisory authority, explainability and reproducibility are legal requirements. ML gives probability, not proof. We deliberately chose deterministic rules that a regulator can re-run by hand."

**Q: How do you prevent gaming / fake data?**
> "Three ways: the hash-chained audit trail, fail-closed insufficient-evidence state for missing fields, and peer-deviation signals that surface outliers across entities."

**Q: How does it scale beyond 20 entities?**
> "The rule engine and analytics are per-entity and O(records). The queue is diversifiable across thousands of entities. And the async boundary — Celery plus Redis — dequeues assessments, while PostgreSQL, MinIO, and Keycloak compose into the production profile we've already validated."

**Q: What about false positives from the rules?**
> "Rules create candidates only; the supervisor holds decision authority. Everything carries evidence, confidence, and limitations, so dismissal is itself an audited, justifiable event."

**Q: Is it truly offline?**
> "Yes. The demo container has no outbound calls. Ingestion, analysis, review, and PDF generation all run locally. Optional services are only pulled in by the production profile."