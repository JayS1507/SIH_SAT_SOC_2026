# SOC-Inspect / SAT-SA
## Complete SIH26157 Project Report

**Problem statement:** SIH26157 — Supervisory Analytics Tool for SOC Assessment (SAT-SA)  
**Project name:** SOC-Inspect  
**Category:** Software — Blockchain & Cybersecurity  
**Primary users:** External cyber supervisors, regulators, auditors, and critical-sector examiners  
**Deployment target:** Privacy-preserving, offline-first, air-gapped environment

---

## 1. Executive summary

SOC-Inspect is an evidence-based supervisory analytics platform for analysing periodic Security Operations Centre submissions. It does not replace a SOC, SIEM, SOAR platform, real-time monitoring system, or human supervisor. It converts periodic alert, case, investigation, escalation, response, closure, and asset records into a canonical evidence model and identifies where operational evidence does not support the declared process.

The platform helps a supervisor answer:

- Which entity requires attention first?
- Which capability or process has the largest execution gap?
- Which alerts or cases should be manually reviewed?
- What evidence supports each finding?
- Is the result reproducible, auditable, and hash-linked to the submitted data?

The implemented prototype covers the complete evidence-to-review workflow:

```text
Submission
  -> ingestion and schema validation
  -> canonical evidence mapping
  -> data-quality analysis
  -> deterministic supervisory rules
  -> anomaly and negative-space analysis
  -> peer benchmarking and risk scoring
  -> review prioritisation
  -> supervisor decision and annotation
  -> audit trail and JSON/HTML/PDF report
```

---

## 2. SIH26157 problem addressed

SOC reports and KPI dashboards can appear healthy while operational evidence reveals:

- Critical alerts closed without escalation.
- Cases closed without investigation evidence.
- Investigations without conclusions.
- Escalations without response actions.
- Suspiciously fast or slow response times.
- Repeated template-based investigation notes.
- Alerts without linked cases.
- Important assets without monitoring evidence.
- Missing reporting periods.
- Invalid or inconsistent workflow records.

Manual supervisory review can find these issues, but it does not scale across entities and large periodic submissions. SOC-Inspect provides an explainable decision-support layer that identifies where supervisors should focus their limited review time.

---

## 3. Scope and boundaries

### Included

- Periodic SOC evidence submissions.
- CSV, JSON, XLSX, and restricted plain-text PostgreSQL exports.
- Canonical entity, asset, alert, case, and workflow records.
- Data-quality and evidence-sufficiency checks.
- Deterministic supervisory rules.
- Negative-space and reporting-gap detection.
- Response-time and repeated-template analysis.
- Entity risk scoring and peer benchmarking.
- Human review, annotations, and audit events.
- Hash-linked reports and immutable artifacts.
- Offline SQLite operation and PostgreSQL compatibility.
- Optional MinIO/S3, Redis/Celery, and Keycloak/OIDC integration.

### Explicitly not included as an operational function

- Real-time network monitoring.
- SIEM replacement.
- SOAR replacement.
- Continuous telemetry collection.
- Autonomous enforcement or blocking.
- National centralized SOC operation.
- Final supervisory judgement without human confirmation.

---

## 4. Architecture

### 4.1 Presentation layer

- React 19
- TypeScript
- Vite
- Responsive CSS dashboard
- Entity risk prioritisation
- Capability signal view
- Review queue
- Supervisor review action

The frontend displays authoritative scores and evidence returned by the backend. It does not calculate supervisory findings independently.

### 4.2 Edge and API layer

- FastAPI
- Pydantic models
- OpenAPI documentation
- CORS configuration
- Correlation IDs using `X-Request-ID`
- Structured HTTP errors
- Health and readiness endpoints
- JWT and OIDC authentication
- Role-based access control

### 4.3 Ingestion layer

Supported formats:

- JSON arrays and versioned JSON payloads.
- CSV files.
- XLSX/XLSM files.
- Restricted SQL exports containing PostgreSQL `INSERT INTO ... VALUES`.
- Restricted PostgreSQL `COPY ... FROM STDIN` CSV blocks.

Safety controls:

- Maximum upload size: 10 MB.
- Maximum records: 10,000.
- Maximum columns: 200.
- No arbitrary SQL execution.
- DDL, binary/custom dumps, functions, and unsupported expressions are rejected.
- Every normalized row receives a source `_row` value.

### 4.4 Canonical evidence layer

The prototype maps submitted records into:

- Entities.
- Assets.
- Alerts.
- Cases.
- Workflow events.
- Submission versions.
- Findings.
- Review records.
- Audit events.

Every finding retains:

- Submission identifier.
- Source row references.
- Evidence record identifiers.
- Rule version.
- Confidence.
- Calculation.
- Limitations.

### 4.5 Supervisory analytics layer

Implemented analytics include:

- Critical alert without escalation.
- Closed case without evidence.
- Investigation without conclusion.
- Escalation without response.
- Closure before investigation.
- Invalid workflow status.
- Duplicate support records.
- Alert without linked case.
- Asset coverage gaps.
- Missing severity.
- Missing asset criticality.
- Repeated investigation narratives.
- Response-time anomalies.
- Weekly reporting gaps.
- Entity risk scoring.
- Peer median and deviation.
- Diversified review queue ordering.

### 4.6 Storage layer

- SQLAlchemy ORM.
- SQLite default for offline demonstration.
- PostgreSQL-compatible `DATABASE_URL`.
- Alembic migration configuration.
- Local immutable artifact storage.
- Optional S3-compatible MinIO artifact storage.
- SHA-256 content hashes.

### 4.7 Background processing layer

- Optional Celery task boundary.
- Optional Redis broker/result backend.
- Synchronous fallback when Redis/Celery is unavailable.
- Assessment statuses support queued, running, completed, and failed states.

### 4.8 Identity and access layer

Supported modes:

1. Offline demo mode using `DEMO_AUTH_DISABLED=true`.
2. HS256 JWT mode using `JWT_SECRET`.
3. Keycloak/OIDC mode using issuer and JWKS configuration.

Supported roles:

- `admin`
- `supervisor`
- `reviewer`
- `auditor`
- `data_provider`

### 4.9 Observability layer

- `/api/v1/health`.
- `/api/v1/readiness`.
- `/metrics`.
- Prometheus text metrics.
- Request counters.
- Error counters.
- Latency summaries.
- Assessment-stage counters.
- Request correlation IDs.

---

## 5. End-to-end data flow

### Step 1: Submission

An entity or data provider uploads a periodic package or sends a JSON submission.

### Step 2: Protection and hashing

The original content is bounded, hashed using SHA-256, and stored as an immutable artifact.

### Step 3: Schema and format detection

The adapter identifies JSON, CSV, XLSX, or restricted SQL export input.

### Step 4: Validation

The system checks:

- Required identifiers.
- Timestamp presence.
- Severity.
- Asset criticality.
- Status values.
- Duplicate identifiers.
- Row and column limits.
- Supported schema version.

### Step 5: Canonical mapping

Records are indexed into entities, assets, alerts, cases, and workflow evidence. Source-row lineage is preserved.

### Step 6: Assessment

The assessment executes deterministic rules and supporting analytics.

### Step 7: Risk and peer analysis

Findings are weighted by severity. Entity-level risk and peer deviations are calculated.

### Step 8: Review queue

The system prioritizes findings and diversifies results so one entity or control does not monopolize the queue.

### Step 9: Human review

A permitted supervisor or reviewer accepts, rejects, or annotates a finding.

### Step 10: Reporting

The system creates JSON, HTML, or PDF output containing:

- Assessment metadata.
- Submission hash.
- Findings.
- Evidence references.
- Review decisions.
- Report hash.
- Verification status.

---

## 6. SIH26157 requirement mapping

| Requirement | Implementation status |
|---|---|
| Periodic CSV ingestion | Complete |
| Periodic JSON ingestion | Complete |
| Excel ingestion | Complete |
| Restricted database export ingestion | Complete |
| Versioned payloads | Complete |
| Canonical evidence model | Complete for prototype |
| Source lineage | Complete |
| Data-quality validation | Complete |
| Evidence-sufficiency reporting | Complete |
| Execution-gap detection | Complete |
| Negative-space detection | Complete |
| Response-time anomaly detection | Complete |
| Repeated-template detection | Complete |
| Capability indicators | Complete |
| Peer benchmarking | Complete for prototype metrics |
| Entity risk scoring | Complete |
| Review prioritisation | Complete |
| Human-in-the-loop review | Complete |
| Audit trail | Complete |
| JSON report | Complete |
| HTML report | Complete |
| PDF report | Complete |
| Hash verification | Complete |
| JWT authentication | Complete |
| RBAC | Complete |
| Keycloak/OIDC-compatible validation | Complete |
| SQLAlchemy persistence | Complete |
| PostgreSQL compatibility | Complete |
| Alembic migrations | Complete |
| Local immutable artifacts | Complete |
| MinIO/S3 compatibility | Complete |
| Redis/Celery boundary | Complete |
| Prometheus-compatible metrics | Complete |
| Air-gapped demo deployment | Complete |

Production environment configuration is still required for a real Keycloak realm, PostgreSQL server, MinIO instance, Redis broker, and Prometheus/Grafana deployment.

---

## 7. API surface

### System

```text
GET /api/v1/health
GET /api/v1/readiness
GET /metrics
```

### Submissions

```text
POST /api/v1/submissions
GET  /api/v1/submissions/{submission_id}
GET  /api/v1/submissions/{submission_id}/quality
```

### Assessments

```text
POST /api/v1/assessments
GET  /api/v1/assessments/{assessment_id}
GET  /api/v1/assessments/{assessment_id}/status
GET  /api/v1/assessments/{assessment_id}/entities
GET  /api/v1/assessments/{assessment_id}/findings
```

### Evidence and review

```text
GET  /api/v1/findings/{finding_id}/evidence
GET  /api/v1/review-queue
POST /api/v1/assessments/{assessment_id}/review
GET  /api/v1/audit-events
```

### Reports

```text
GET /api/v1/assessments/{assessment_id}/report?format=json
GET /api/v1/assessments/{assessment_id}/report?format=html
GET /api/v1/assessments/{assessment_id}/report?format=pdf
```

---

## 8. Security and privacy controls

- Offline-first processing.
- No external API is required for the default demo.
- Role-protected routes.
- Configurable JWT secret.
- OIDC issuer/audience validation.
- Restricted SQL parser without execution.
- Upload size and row limits.
- Immutable artifact keys based on SHA-256.
- No raw case narrative in operational logs by design.
- Supervisor confirmation required before conclusions are treated as reviewed.
- Sensitive production deployments should use encrypted PostgreSQL, MinIO, TLS, secret management, and a real Keycloak realm.

---

## 9. Testing and validation

The backend suite contains 15 tests covering:

- Health and vertical workflow.
- CSV ingestion.
- JSON ingestion.
- XLSX ingestion.
- Restricted SQL `INSERT` parsing.
- Restricted SQL `COPY` parsing.
- Unsafe SQL rejection.
- Quality hashing and rule execution.
- Schema version rejection.
- Advanced supervisory analytics.
- Review and report generation.
- JWT role guards.
- Keycloak claim-role extraction.
- Immutable artifact hashing.
- Prometheus metrics.
- Request correlation.

Additional validation:

```text
Frontend TypeScript production build: passed
Docker Compose default configuration: passed
Docker Compose production configuration: passed
Alembic upgrade head: passed
Alembic downgrade base: passed
Live health endpoint: passed
Live readiness endpoint: passed
Live metrics endpoint: passed
Live demo overview endpoint: passed
```

---

## 10. Repository structure

```text
SIH_SAT_SOC/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── database.py
│   │   ├── ingestion.py
│   │   ├── auth.py
│   │   ├── artifacts.py
│   │   ├── metrics.py
│   │   └── tasks.py
│   ├── migrations/
│   ├── tests/
│   ├── requirements.txt
│   ├── Dockerfile
│   └── alembic.ini
├── frontend/
│   ├── src/main.tsx
│   ├── src/styles.css
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
├── PROJECT_REPORT.md
├── RUN_PROJECT.md
└── README.md
```

---

## 11. Demonstration flow

1. Start the project.
2. Open the supervisor dashboard.
3. Show the synthetic assessment.
4. Explain the entity risk ranking.
5. Open prioritized findings.
6. Drill into evidence and source-row lineage.
7. Submit a review decision.
8. Show the audit event.
9. Download JSON, HTML, or PDF report.
10. Verify the dataset and report hashes.
11. Show `/metrics` and `/api/v1/readiness`.
12. Explain that final judgement remains with the supervisor.

---

## 12. Known operational limitations

- Raw binary/custom PostgreSQL dumps are rejected; plain-text restricted exports are supported.
- A real Keycloak realm must be provisioned for production OIDC.
- PostgreSQL, MinIO, Redis, and Prometheus require environment-specific credentials/configuration.
- The default offline demo uses SQLite and local artifact storage.
- The current analytics are deterministic prototype rules; advanced ML can be added as a complementary, versioned model without replacing the evidence model.

---

## 13. Conclusion

SOC-Inspect implements the SIH26157 evidence-based supervisory assessment concept as a runnable offline-first prototype. The system moves from heterogeneous periodic evidence to explainable, auditable, human-reviewed supervisory insight without claiming to be a real-time SOC or autonomous security decision-maker.
