# SOC-Inspect (SAT-SA) — Complete Technical Architecture Walkthrough

> For the SIH 2026 Technical Round presentation. This document explains the **end‑to‑end background process** of the system: from raw SOC submission to supervisory report, with every module, data flow, formula, and proof point.

---

## 1. What the system is (30 seconds)

**SOC-Inspect** is a supervisory analytics tool for India's **Critical Sector Entities (CSEs)**. Periodic SOC submissions (alerts, cases, investigations, escalations, responses, closures) from each entity are uploaded, validated, mapped into a canonical evidence store, and run through a **deterministic rule engine**. The output is:

- an **explicit compliance classification** per entity,
- an **explainable risk score** with named drivers,
- a **ranked, evidence-linked review queue** for the supervisor,
- **JSON / HTML / PDF reports** with hash verification.

**Key design stance (why judges should trust it):**

> It is NOT a SIEM, NOT real-time monitoring, NOT autonomous response, and NOT an LLM chatbot. It is a **human-supervised, evidence-first, deterministic analytics platform**. Missing evidence is never treated as compliance. Every number is reproducible from source rows.

---

## 2. Problem statement context (SIH26157)

Supervisory authorities receive **periodic SOC submissions** from many entities in multiple formats. Today:

- Compliance is judged inconsistently.
- Findings are hard to trace to evidence.
- Risk is an opaque single number.
- The review queue is not prioritized.
- There is no tamper-evident audit trail.

SOC-Inspect converts these submissions into **reproducible, evidence-linked supervisory findings** without needing live telemetry or cloud dependencies.

---

## 3. Technology stack (as implemented)

| Layer | Technology | Role |
|---|---|---|
| Frontend | **React 19 + TypeScript + Vite** + Recharts | Supervisor dashboard (Overview, Entities, Ops, Gov pages) |
| Backend API | **Python 3.12 + FastAPI + Pydantic v2** | Typed REST API, OpenAPI docs, validation |
| Processing | **Deterministic Python rule engine**, optional **Celery + Redis** boundary | Assessment execution |
| Persistence | **SQLAlchemy ORM + SQLite** (demo) / **PostgreSQL 16** (prod), **Alembic** migrations | Relational + JSON-payload persistence |
| Artifacts | Local **SHA-256 integrity-evident store** / optional **MinIO / S3** | Immutable original uploads + reports |
| Identity | **JWT / RBAC**; optional **Keycloak-compatible RS256 JWKS** | Roles: data_provider, supervisor, reviewer, auditor, admin |
| Ops | **Docker + Docker Compose**, Prometheus `/metrics`, health/readiness, correlation IDs | Deployment and observability |

---

## 4. Layered architecture

```
┌──────────────────────────────────────────────────────────────┐
│  PRESENTATION LAYER                                           │
│  React + TS (Vite) supervisor dashboard                      │
│  Overview · Entities · Ops · Gov  →  /api/v1                │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTPS / JSON (Bearer JWT)
┌───────────────────────────▼──────────────────────────────────┐
│  API LAYER  (FastAPI app/main.py)                            │
│  Auth/RBAC · validation · correlation-ID middleware          │
│  /submissions · /assessments · /findings · /review-queue     │
│  /analytics/* · /sat/* · /reports · /audit-events            │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  PIPELINE CORE (deterministic)                               │
│                                                        │     │
│  ingestion.py ──→ normalize_records ──→ index_records ─┐     │
│  execute_rules (rule engine, main.py)                 │     │
│  compliance.py (12 control evaluation)                │     │
│  scoring.py   (risk = severity × evidence × peer)     │     │
│  analytics.py + supervisory.py (metrics, star schema) │     │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  STORAGE / PERSISTENCE                                       │
│  SQLAlchemy + SQLite/PG: submissions·assessments·findings    │
│  reviews·audit_events·entities (database.py)                 │
│  ArtifactStore: original files + reports (SHA-256)           │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│  REVIEW & AUDIT                                             │
│  Review queue → supervisor action → hash-chained audit event │
│  Report renderer → JSON / HTML / PDF + hash verification     │
└──────────────────────────────────────────────────────────────┘
```

---

## 5. The complete background process — start to end (12 steps)

### Step 1 — Start with a context (`Store`)
On startup (`main.py:536`) the app:
1. Calls `init_db()` → creates schema (Alembic-compatible, `database.py:80`).
2. Calls `load_state(Store)` → reloads all persisted submissions, assessments, findings, reviews, audit events from the database into an in‑memory `Store`.
3. Re-indexes all records (`index_records`) so entity/asset/alert/case maps are rebuilt.
4. Seeds the 20-entity demo dataset if no submission exists (`build_demo()`).

The `Store` (`main.py:137`) is the working set: submissions, assessments, findings, entities, assets, alerts, cases, workflow events, audit events, reviews.

### Step 2 — Secure submission
`POST /api/v1/submissions` (`main.py:563`) — role `data_provider`/`admin`:
- Rejects unsupported `schema_version` (only `1.0`).
- Accepts **JSON payload, multipart file (CSV / XLSX / JSON / restricted SQL dump), or pasted logs**.
- Parses via `ingestion.ingest_bytes()` (`ingestion.py:23`):
  - **CSV** → `csv.DictReader`, header validated, ≤ 200 columns.
  - **XLSX** → `openpyxl` read-only workbook.
  - **JSON** → array of objects, or common DB exports `{records|rows|data|tables}`.
  - **SQL/PostgreSQL dump** → a **restricted parser** that accepts ONLY `INSERT ... VALUES` and `COPY ... FROM STDIN`; no DDL, no functions, no arbitrary expressions, never connects to a DB (`parse_sql_export`). Malformed/unsafe SQL → `IngestionError`.
- **Every raw byte is stored as an immutable artifact** via `ArtifactStore.put()` (`artifacts.py:29`) — key is `submissions/<id>/<sha256>.<ext>`. SHA-256 is the content address, so tampering is detectable.
- A `content_sha256` is computed over the normalized record set (`content_hash`, `main.py:241`).

### Step 3 — Row-level quality gate (fail closed)
`normalize_records` (`main.py:223`) checks each row and **reports issues instead of silently accepting**:
- row has an entity identifier,
- row has a timestamp,
- alert rows carry a severity,
- asset rows carry criticality.

Missing fields = quality issues = **insufficient evidence**, never a silent pass.

### Step 4 — Canonical mapping
`index_records` (`main.py:269`) normalizes source field aliases (e.g. `entity`/`user`/`host` → entity) and builds the relational picture:
- `Store.entities` (name, sector, alert/case counts),
- `Store.assets`, `Store.alerts`, `Store.cases`,
- `Store.workflow_events` (canonical `CanonicalEvidence` records, alert→case lifecycle).

`rowmap.py` provides **derived boolean evidence flags** (`is_escalated`, `is_investigated`, `is_responded`, `is_closed`, `conclusion`, timestamps) by mapping both modern `*_id/*_status/*_timestamp` columns and legacy boolean flags — without inventing evidence.

### Step 5 — Run the rule engine (deterministic)
`POST /api/v1/assessments` (`main.py:660`) — `execute_rules(submission, aid)` (`main.py:295`) runs versioned rules over every row and emits `Finding` objects. Each finding carries:

```
rule · severity · title · description · entity_id
evidence[]          → record:<submission_id>#row-<n>
lineage[]           → submission:<id>, row:<n>
rule_version        → "rules-1.0"
confidence          → 0.85
calculation         → "rule=...; category=...; evidence_count=..."
limitations         → ["Periodic submission only; supervisor validation required."]
```

Rule set (all deterministic, all with evidence lineage):

| Rule | Category (`taxonomy.py`) | Fires when |
|---|---|---|
| `critical_alert_no_escalation` | execution_gap | critical/high alert requires escalation but none recorded |
| `closed_without_evidence` | execution_gap | case closed with `evidence=False` |
| `escalation_no_response` | execution_gap | escalated but no response |
| `closure_before_investigation` | execution_gap | closure timestamp < investigation timestamp |
| `investigation_without_conclusion` | execution_gap | investigated, no conclusion text |
| `invalid_status` / `invalid_status_order` | execution_gap | status outside lifecycle; closed before investigated |
| `alert_without_case` | execution_gap | alert activity with no linked case |
| `missing_severity` / `missing_asset_criticality` | execution_gap | evidence is incomplete (insufficient evidence, not compliance) |
| `duplicate_record` | execution_gap | repeated `alert_id`/`case_id` (one finding per affected row) |
| `repeated_investigation_template` | execution_gap | normalized text similarity ≥ 0.92 across investigation narratives |
| `response_time_anomaly` | execution_gap | response minutes > `max(median×1.5, median+30)` per entity |
| `asset_without_coverage` | negative_space | entity has alerts but no asset coverage |
| `negative_space_period_gap` | negative_space | missing weekly reporting period when timeline spans ≥ 3 weeks |

**Findings are merged per (rule, entity)** with full evidence arrays preserved — so the dashboard groups by `rule × entity`, shows affected‑record counts, and every finding stays auditable down to the source row. Duplicate findings stay per-row for drill-down.

### Step 6 — Compliance classification (12 controls)
`compliance.py` evaluates **12 supervisory controls** per entity (`TD-01…DQ-01`):

`evaluate_controls(rows, findings)` (`compliance.py:177`) computes for each control:
`coverage = numerator / denominator × 100`, then maps to a status via `_status_for` (`compliance.py:162`):

```
denominator == 0 → INSUFFICIENT_EVIDENCE
coverage ≥ 85    → COMPLIANT            (score 100)
coverage ≥ 60    → PARTIALLY_COMPLIANT  (score 50)
otherwise        → NON_COMPLIANT        (score 0)
```

Entity compliance (`entity_compliance`, `compliance.py:291`):
- `compliance_score = mean(score of sufficiently evidenced controls)`.
- `evidence_coverage` = fraction of controls with evidence.
- **Classification rule** (`classify`): evidence coverage < 50% → `INSUFFICIENT_EVIDENCE`; any unresolved **critical** finding → `NON_COMPLIANT`; score ≥ 85 → `COMPLIANT`; ≥ 60 → `PARTIALLY_COMPLIANT`; else `NON_COMPLIANT`.

Design: `INSUFFICIENT_EVIDENCE` is never a pass — it belongs in the non-watchlist with a "needs data" action.

### Step 7 — Explainable risk scoring
`scoring.calculate_entity_risk` (`scoring.py:38`) — **not an opaque number**:

```
evidence_strength = mean of:
    min(evidence count, 3)/3
    min(lineage count, 2)/2
    1 if lineage starts with "submission:" else 0
    1 if a calculation string exists else 0

base_burden = Σ [ severity_weight(low1/med3/high7/crit12)
                  × evidence_strength ]  per entity

peer z-score = (entity_rate − sector_mean) / sector_pop_stdev
peer_multiplier = 1 + 0.10 × clamp(z, −3, +3)

risk_score = 100 × base_burden × peer_multiplier / worst_case_burden
worst_case  = finding_volume × 12 × evidence_effort(1.0) × (1 + 0.10×3)
```

Output includes `tier` (critical ≥ 70 / high ≥ 40 / medium), raw & bounded z, peer multiplier, category burdens, and a `contributing_factors` list so the supervisor sees **which findings and rules drove the score**.

### Step 8 — Supervisory analytics & overview
Two engines present the picture:

- **`SupervisoryAnalytics`** (`analytics.py:72`) — builds an in‑memory **star schema** from the relational tables (entities, assets, alerts, cases, investigations, escalations, responses, remediations, submissions) with cross‑indexes (`_alerts_by_entity`, `_cases_by_id`, `_inv_by_case`, …) and computes: severity mix, alert/investigation/escalation/monitoring trends, execution gaps, peer benchmarks, workflow funnel.
- **`supervisory.py`** — 10 KPIs, compliance distribution, attention matrix, executive summary, sector breakdown, control performance, grouped findings with affected counts and calculation strings, data quality, reporting coverage.

**Data quality** (`compliance.py:417`, `supervisory.py:263`) is a weighted composite:
`0.30·completeness + 0.25·validity + 0.20·consistency + 0.15·uniqueness + 0.10·timeliness`.

**Audit hash chain** (`supervisory.py:361`): `audit_hash(prev_hash, event)` — each audit event is chained to the previous hash, so the trail is tamper‑evident.

### Step 9 — Human-in-the-loop review queue
`GET /api/v1/review-queue` (`main.py:850`):
- Priority = `{critical:100, high:70, medium:40, low:10}`,
- sorted primarily by priority then **round-robin across entity/rule groups** so one noisy entity or control cannot monopolize the queue,
- each queue item exposes `evidence` context (alert IDs, asset IDs, timestamps) for that finding.

Supervisor actions via `POST /api/v1/assessments/{id}/review` and `PATCH/status` endpoints: `VALIDATE / REJECT (DISMISS) / REQUIRES_EVIDENCE / CLOSE / FOLLOW_UP`. Every action is written to `record_audit_event` → immutable, hashed audit trail. `/api/v1/audit-events` supports filtering by event type, actor, and target.

### Step 10 — Evidence drill-down & QA
- `GET /api/v1/findings/{id}/evidence` returns evidence walk IDs, lineage, calculation, limitations.
- `GET /api/v1/assessments/{id}/ask?question=` (`qa.py`) — a **deterministic, no-LLM question answerer** that parses intent (blame/history/risk/trend/range questions) from findings + entities + evidence and returns factual answers with supporting rows.

### Step 11 — Reporting with hash verification
`GET /api/v1/assessments/{id}/report?format=json|html|pdf` (`main.py:811`):
1. Assembles `{assessment, submission(+content_sha256), findings, reviews}`.
2. Canonical serialization (sorted keys) → `report_sha256`.
3. Original bytes stored as artifact (SHA-256 content address).
4. `hash_verified` true if current records re-hash to the stored submission hash.
5. `reporting.py` renders a professional **HTML** report and a **PDF** (client-side rendering, no cloud).

### Step 12 — Audit & accountability
Every lifecycle event (`dataset_uploaded`, `assessment_executed`, `finding_validated/rejected`, `evidence_requested`, `recommendation_closed`, `report_generated`, …) is a `record_audit_event` with actor, role, previous/new state, and a content hash — persisted in the `audit_events` table. A supervisor can reconstruct *who did what, when, on which finding, with which evidence*.

---

## 6. Data model / persistence

`database.py` — SQLAlchemy tables:

| Table | Purpose |
|---|---|
| `submissions` | id, name, source, JSON payload, schema_version, created_at |
| `assessments` | id, submission FK, JSON payload, schema_version, created_at |
| `findings` | id, assessment FK, JSON payload |
| `reviews` | id, assessment FK, JSON payload, created_at |
| `audit_events` | id, JSON payload, created_at |
| `schema_metadata` | key/value (schema_version, migration_revision) |
| `entities` | id, name, sector (deduplicated across submissions) |

Payloads are JSON blobs (prototype simplicity) keyed by UUID; the same code path runs against PostgreSQL 16 in production via `DATABASE_URL` (`connect_args` switch only for SQLite threading). Alembic migrations live in `backend/migrations/versions`.

---

## 7. Security & integrity model

- **JWT authentication** — HS256 with `JWT_SECRET`, or **RS256 JWKS via Keycloak/OIDC** (`auth.py`) when `OIDC_ISSUER` is set; `realm_access`/`resource_access` roles mapped to 5 internal roles.
- **RBAC** on every route via `require_roles(...)` dependency.
- **Upload hardening**: schema-version check, size/format limits, ≤ 200 columns, restricted SQL parser (never executes SQL), row-level quality reporting.
- **Integrity-evident artifacts**: every original upload and report is stored *content-addressed by SHA-256*; `hash_verified` recomputation in reports.
- **Audit chain**: hash-chained audit events (`audit_hash(prev, event)`).
- **Fail closed**: missing evidence → `INSUFFICIENT_EVIDENCE` / quality issue, never compliant.
- Demo runs with `DEMO_AUTH_DISABLED=true`; production must disable it.

---

## 8. Deployment

`docker-compose.yml`:

| Service | Image | Profile |
|---|---|---|
| `api` | backend Dockerfile (uvicorn) | demo + prod |
| `web` | frontend Dockerfile (Nginx static) | demo + prod |
| `postgres` | postgres:16-alpine | production only |
| `redis` | redis:7-alpine (Celery queue) | production only |
| `minio` | minio/minio (artifact storage) | production only |

Offline/air-gapped prototype: SQLite + local artifact dir + no external calls (that is how the demo runs). Same boundaries scale to PG/Redis/MinIO/Keycloak.

---

## 9. Validation evidence (present these)

| Check | Result |
|---|---|
| Backend test suite (`pytest -q backend/tests`, 15 files) | **56 tests passing** — compliance maths, risk, funnel, data quality, duplicates, audit, CSV ingestion, grouping, reports, hardening, SAT API, rules recall, scoring, QA |
| Frontend production build (`vite build`, TypeScript strict) | passes |
| Alembic upgrade/downgrade | passes |
| Docker Compose demo + production profiles | validated |
| Health / readiness / Prometheus `/metrics` | passes |
| Auth + RBAC | passes |
| Artifact hashing + report hash verification | passes |
| SQL safety parser (rejects DDL/functions) | passes |
| Deterministic seed: 20 entities, 11,607 rows, 10 behavioural archetypes | reproducible |

---

## 10. Your presentation flow (technical part)

1. **Hook — 15s:** "Periodic SOC submissions from 20+ critical entities arrive in JSON, CSV, XLSX, SQL. We turn them into evidence-linked, government-auditable compliance and risk."
2. **One sentence architecture:** "FastAPI backend with a deterministic rule engine, React supervisor dashboard, SQLAlchemy persistence, SHA-256-verified artifacts, and a human review + audit layer."
3. **Walk the pipeline (read the arrows):** Submit → Validate (quality, fail-closed) → Normalize to canonical alert→case lifecycle → Run 13 versioned rules → 12-control compliance + explainable risk scoring → analytics/star-schema KPIs → prioritized review queue → supervisor decision → hash-chained audit event → JSON/HTML/PDF report with hash verification.
4. **The three words that matter:** *Evidence before inference. Deterministic core. Fail closed.*
5. **Proof:** 56 backend tests, TypeScript build clean, restricted SQL parser, hash-verified reports, 20-entity deterministic demo, offline deployment validated.

---

## 11. Key file reference map

| File | Responsibility |
|---|---|
| `backend/app/main.py` | API routes, Store, normalisation, indexing, rule engine, review, reporting orchestration |
| `backend/app/ingestion.py` | Multi-format parsing incl. restricted SQL adapter |
| `backend/app/rowmap.py` | Canonical field mapping + derived evidence flags |
| `backend/app/taxonomy.py` | Rule → category map, controls, statuses |
| `backend/app/compliance.py` | 12-control evaluation, entity classification, risk-with-drivers, data quality |
| `backend/app/scoring.py` | Evidence strength + peer-adjusted risk math |
| `backend/app/analytics.py` | SupervisoryAnalytics star-schema metrics |
| `backend/app/supervisory.py` | KPIs, attention matrix, audit hash chain, grouping |
| `backend/app/reporting.py` | JSON/HTML/PDF report rendering |
| `backend/app/artifacts.py` | SHA-256 content-addressed artifact store (local / S3 / MinIO) |
| `backend/app/auth.py` | JWT / OIDC / RBAC |
| `backend/app/database.py` | SQLAlchemy schema + persistence |
| `backend/app/tasks.py` | Sync fallback ↔ Celery/Redis boundary |
| `backend/app/qa.py` | Deterministic no-LLM question answerer |
| `backend/app/seed/generate_evidence.py` | 20-entity / 11,607-row deterministic demo |
| `frontend/src/pages/*` | React dashboard pages (Overview, Entities, Ops, Gov) |