# SIH Slide: Technical Approach

## TECHNICAL APPROACH

### Evidence First • Deterministic Core • Human-in-the-Loop • Offline Ready

SOC-Inspect uses a modular, layered architecture that converts periodic SOC submissions into reproducible supervisory findings without requiring live telemetry or external cloud services.

---

## Technologies to Be Used

### Frontend and presentation

- **React + TypeScript** for the supervisor web application.
- **Vite** for fast development and production bundling.
- Responsive dashboard for entity risk, capability signals, findings, evidence, and review actions.
- Nginx static container for offline deployment.

### Backend and APIs

- **Python + FastAPI** for typed REST APIs and OpenAPI documentation.
- **Pydantic** for request, response, and canonical data validation.
- Correlation IDs, structured errors, health checks, readiness checks, and Prometheus metrics.

### Ingestion and processing

- JSON, CSV, XLSX, and restricted plain-text PostgreSQL export adapters.
- Python deterministic rule engine.
- Statistical calculations for response-time outliers and peer deviation.
- Optional Celery + Redis task boundary for larger assessments.
- Synchronous fallback for offline demonstration.

### Data and evidence storage

- **SQLAlchemy** for database persistence.
- **SQLite** for local air-gapped prototype operation.
- **PostgreSQL** for production-scale relational storage.
- **Alembic** for schema migrations.
- Local integrity-evident SHA-256 artifact storage.
- Optional **MinIO/S3** for private evidence and report artifacts.

### Identity and security

- JWT authentication.
- Role-based access control for supervisor, reviewer, auditor, admin, and data provider.
- Optional Keycloak/OIDC-compatible RS256 JWKS validation; the Keycloak realm is configured separately.
- Upload limits, restricted SQL parsing, source lineage, audit events, and hash verification.

### Deployment and infrastructure

- Docker and Docker Compose.
- Optional PostgreSQL, Redis, MinIO, and Keycloak-compatible deployment.
- Air-gapped/on-premise hardware:
  - 8–16 CPU cores for prototype.
  - 32–64 GB RAM.
  - 1–2 TB SSD.
  - Optional GPU only for future offline ML models.

---

## Methodology and Implementation Process

### Phase 1 — Define the evidence contract

1. Identify required fields for entities, assets, alerts, cases, investigations, escalations, responses, and closures.
2. Define supported schema version `1.0`.
3. Define source-row lineage and data-quality states.
4. Define expected workflow relationships and control expectations.

### Phase 2 — Secure submission and validation

1. Authenticate the data provider.
2. Validate file type, size, row count, and schema version.
3. Parse JSON, CSV, XLSX, or restricted SQL exports.
4. Calculate SHA-256 content hash.
5. Store the original submission as an immutable artifact.
6. Return row-level quality issues instead of silently accepting invalid data.

### Phase 3 — Canonical mapping

1. Normalize source field names.
2. Create canonical entity, asset, alert, case, and workflow records.
3. Preserve source file, source row, timestamp, entity, and transformation version.
4. Reconstruct alert-to-case lifecycle relationships.

### Phase 4 — Deterministic supervisory analysis

1. Execute versioned rules.
2. Detect execution gaps.
3. Detect missing expected evidence and reporting gaps.
4. Calculate response-time and repeated-template indicators.
5. Classify findings by severity, confidence, evidence count, and limitation.

### Phase 5 — Benchmarking and prioritization

1. Calculate entity-level capability indicators.
2. Build contextual peer metrics.
3. Calculate peer medians and deviations.
4. Generate entity risk indicators.
5. Diversify the review queue across entities and controls.

### Phase 6 — Human review and reporting

1. Supervisor opens a finding.
2. Evidence and calculations are displayed.
3. Supervisor accepts, rejects, or annotates the finding.
4. Decision is written to the audit trail.
5. JSON, HTML, or PDF report is generated.
6. Dataset and report hashes are verified.

### Phase 7 — Validation and deployment

1. Run unit, ingestion, API, security, and integration tests.
2. Run frontend production build.
3. Run Alembic upgrade/downgrade verification.
4. Validate Docker Compose demo and production profiles.
5. Pilot with approved synthetic or real periodic submissions.
6. Measure review time, evidence completeness, and validated findings.

---

## End-to-End Technical Flow

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. PERIODIC SOC SUBMISSION                                  │
│    JSON / CSV / XLSX / PostgreSQL INSERT or COPY export     │
└─────────────────────────────┬───────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. SECURE INGESTION                                          │
│    Auth → limits → schema version → file/schema safety      │
│    SHA-256 hash → integrity-evident original artifact        │
└─────────────────────────────┬───────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. VALIDATION AND CANONICAL MAPPING                         │
│    Quality checks → source-row lineage → alert/case linkage  │
│    Entity / asset / alert / case / workflow evidence         │
└─────────────────────────────┬───────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. SUPERVISORY ANALYTICS                                    │
│    Execution gaps • negative space • anomalies               │
│    lifecycle checks • peer deviation • capability signals    │
└─────────────────────────────┬───────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. RISK AND REVIEW PRIORITIZATION                            │
│    Severity + confidence + evidence strength + peer signal    │
│    Diversified entity/control review queue                    │
└─────────────────────────────┬───────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. HUMAN SUPERVISORY REVIEW                                  │
│    Evidence drill-down → accept/reject/annotate → audit log   │
└─────────────────────────────┬───────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 7. REPORT AND VERIFICATION                                   │
│    JSON / HTML / PDF → report hash → archive/export           │
└─────────────────────────────────────────────────────────────┘
```

---

## Prototype Implementation Proof

The working prototype currently demonstrates:

- FastAPI REST API with OpenAPI documentation.
- React + TypeScript supervisor dashboard.
- JSON, CSV, XLSX, and restricted SQL export ingestion.
- SQLAlchemy persistence with SQLite and PostgreSQL compatibility.
- Canonical evidence mapping and source-row lineage.
- Execution-gap, negative-space, anomaly, and peer rules.
- Eight capability indicators and entity risk scoring.
- Review queue, supervisor annotation, and audit events.
- JSON, HTML, and PDF reports with hash verification.
- JWT/RBAC and Keycloak/OIDC-compatible validation.
- Integrity-evident local artifacts and optional MinIO/S3 storage.
- Optional Redis/Celery processing boundary.
- Prometheus-compatible metrics and readiness checks.
- Docker Compose offline and production profiles.

### Validation evidence

```text
Backend tests:                 15 passed
Frontend TypeScript build:     passed
Alembic upgrade/downgrade:     passed
Docker Compose profiles:       validated
Health/readiness/metrics:      passed
Authentication and RBAC:      passed
Artifact hashing:             passed
SQL safety parser:            passed
```

---

## Architectural Principles

1. **Evidence before inference:** Every finding must reference evidence.
2. **Deterministic core:** Mandatory rules are versioned and reproducible.
3. **Fail closed:** Missing data becomes insufficient evidence, not a silent pass.
4. **Human decision authority:** Analytics create candidates; supervisors decide.
5. **Offline-first:** Sensitive submissions can be processed without external services.
6. **Lineage by default:** Transformations retain source references.
7. **Tenant and role isolation:** Evidence access follows identity and role policy.
8. **Progressive scalability:** SQLite/local artifacts first; PostgreSQL/MinIO/Redis at scale.

---

## Recommended Slide Layout

```text
┌────────────────────────────────────────────────────────────┐
│                 TECHNICAL APPROACH                         │
│ Evidence first • Deterministic • Human-supervised • Offline│
├──────────────────────┬─────────────────────────────────────┤
│ TECHNOLOGY STACK     │ IMPLEMENTATION FLOW                  │
│ React + TypeScript   │ Submit → Validate → Normalize       │
│ FastAPI + Pydantic   │ → Analyse → Prioritize → Review      │
│ SQLAlchemy + PG      │ → Report + Hash                      │
│ MinIO + Redis        │                                     │
│ Keycloak/OIDC        │ [central pipeline diagram]          │
├──────────────────────┴─────────────────────────────────────┤
│ PROOF: 15 backend tests • build passed • migrations passed │
│        Docker + offline deployment validated                │
└────────────────────────────────────────────────────────────┘
```

## 30-Second Technical Explanation

> “Our architecture is layered and evidence-first. A periodic SOC submission is authenticated, validated, hashed, and mapped to a canonical alert-to-case lifecycle. A deterministic analytics engine identifies execution gaps, missing evidence, anomalies, and peer deviations. Results are prioritized for human review, not autonomous judgement. The supervisor can inspect source-row evidence, record a decision, and generate a hash-verifiable report. The prototype runs offline with SQLite and local storage, while the same boundaries scale to PostgreSQL, MinIO, Redis/Celery, and a configured Keycloak deployment.”
