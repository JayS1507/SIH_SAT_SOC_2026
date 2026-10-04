# SOC-Inspect — Complete Technical Architecture, Step by Step

> The definitive technical reference for the SIH 2026 technical round.
> Every step, every rule, every control, every formula, every endpoint — with the exact technology used.

---

## TABLE OF CONTENTS
1. System overview & design principles
2. Technology stack (exact versions & roles)
3. Complete pipeline map
4. Step 0 — Startup & boot sequence
5. Step 1 — Secure submission intake
6. Step 2 — Multi-format parsing
7. Step 3 — Immutability (artifact + hashing)
8. Step 4 — Row-level quality gate (fail closed)
9. Step 5 — Canonical mapping & indexing
10. Step 6 — Rule engine (all 13 rules, full logic)
11. Step 7 — Compliance model (12 controls + classification)
12. Step 8 — Risk scoring (full formulas)
13. Step 9 — Supervisory analytics (star schema)
14. Step 10 — Persistence & data model
15. Step 11 — Review queue & human decision
16. Step 12 — Hash-chained audit trail
17. Step 13 — Q&A (deterministic, no LLM)
18. Step 14 — Reporting (JSON/HTML/PDF)
19. Step 15 — Frontend dashboard
20. Security, deployment, observability
21. Every API endpoint
22. Validation evidence
23. File reference map

---

## 1. SYSTEM OVERVIEW & DESIGN PRINCIPLES

**SOC-Inspect (SAT-SA)** is a supervisory analytics platform for reviewing periodic SOC submissions from Critical Sector Entities. It converts raw SOC records into reproducible, evidence-linked compliance and risk findings.

**The 8 non-negotiable principles (state these in the presentation):**

1. **Evidence before inference** — every finding references evidence.
2. **Deterministic core** — rules are versioned (`sat-sa-rules-1.2`, `rules-1.0`); same input → same output, every run.
3. **Fail closed** — missing data becomes `INSUFFICIENT_EVIDENCE`, never a silent pass.
4. **Human decision authority** — analytics create candidates; supervisors decide.
5. **Offline first** — sensitive submissions process without any external service.
6. **Lineage by default** — every transform keeps `submission:<id>`, `row:<n>` references.
7. **Tenant & role isolation** — evidence access follows identity and role.
8. **Progressive scalability** — SQLite/local artifacts today; PostgreSQL/MinIO/Redis at scale.

---

## 2. TECHNOLOGY STACK (EXACT)

| Layer | Technology | Version / Use |
|---|---|---|
| Frontend | React + TypeScript | React 19.1, TS 5.7, react-router 7.18, Recharts 3.10 |
| Bundler | Vite | v6.1, dev server 127.0.0.1:5173 |
| Frontend serve | Nginx | static container in Docker |
| Backend | Python + FastAPI | Python 3.12+, FastAPI 0.1.0 API (`app/main.py`) |
| Validation | Pydantic v2 | models: Submission, AssessmentRequest, Finding, ReviewRequest… |
| Async HTTP | Uvicorn | serves on 127.0.0.1:8000, docs at /docs |
| Ingestion | stdlib csv/json + openpyxl | CSV, Excel, JSON, restricted SQL dump parsing |
| Rule engine | Pure Python | deterministic, no ML libraries |
| Stats | stdlib statistics | fmean, median, pstdev for outliers & z-scores |
| Persistence | SQLAlchemy 2.0 | SQLite (demo) / PostgreSQL 16 (prod), `DATABASE_URL` switch |
| Migrations | Alembic | `backend/migrations/versions` |
| Artifacts | hashlib + boto3 (optional) | SHA-256 local store / MinIO / S3 |
| Auth | PyJWT | HS256 `JWT_SECRET` or OIDC RS256 JWKS (Keycloak) |
| Async tasks | Celery + Redis | `tasks.py`; redis 7-alpine; sync fallback offline |
| Reports | reporting.py (stdlib) | JSON / HTML / PDF, pure local rendering |
| Observability | Prometheus format | `/metrics`, health, readiness, correlation IDs |
| Deploy | Docker + Compose | demo + production profiles (postgres, redis, minio) |

---

## 3. COMPLETE PIPELINE MAP

```
RAW SOC DATA
  (CSV / XLSX / JSON / SQL dump / pasted logs)
      │
      ▼
[1] AUTH + INTAKE  ── FastAPI + JWT/RBAC
      │
      ▼
[2] PARSE  ── csv | openpyxl | json | restricted SQL parser
      │
      ▼
[3] ARTIFACT  ── SHA-256 content-addressed store (local/MinIO/S3)
      │
      ▼
[4] QUALITY GATE  ── normalize_records() → quality issues (fail closed)
      │
      ▼
[5] CANONICAL MAP  ── rowmap + index_records() → entities/assets/alerts/cases
      │
      ▼
[6] RULE ENGINE  ── execute_rules() → 13 rules → findings[]
      │
      ▼
[7] COMPLIANCE  ── evaluate_controls() → 12 controls → 4-state label
      │
      ▼
[8] RISK  ── risk drivers (additive) + scoring.py peer model
      │
      ▼
[9] ANALYTICS  ── SupervisoryAnalytics star schema → 10 KPIs
      │
      ▼
[10] PERSIST  ── SQLAlchemy → submissions/assessments/findings/reviews/audit
      │
      ▼
[11] REVIEW QUEUE  ── priority sort + round-robin diversification
      │
      ▼
[12] HUMAN DECISION  ── validate/reject/evidence-request → audit event
      │
      ▼
[13] REPORT  ── JSON / HTML / PDF + hash verification
      │
      ▼
[14] DASHBOARD  ── React pages: Overview / Entities / Ops / Gov
```

---

## 4. STEP 0 — STARTUP & BOOT SEQUENCE

**Technology:** FastAPI lifespan, SQLAlchemy engine, sqlite3/PG driver.

Code: `main.py:536`, `database.py:80`

| # | Action | Code |
|---|---|---|
| 1 | Create schema (idempotent) | `init_db()` — `Base.metadata.create_all(engine)` |
| 2 | Compatibility column migration | add `schema_version` if missing on submissions/assessments |
| 3 | Write metadata rows | `schema_metadata`: `schema_version=1.0`, `migration_revision=prototype-001` |
| 4 | Load persisted state into memory | `load_state(Store)` — submissions, assessments, findings, reviews, audit events |
| 5 | Rebuild in-memory indexes | `index_records(submission)` per loaded submission |
| 6 | Seed demo if empty | `build_demo()` — 4-row synthetic demo |

**In-memory `Store` (main.py:137):** `submissions{}`, `assessments{}`, `findings{}`, `entities{}`, `assets{}`, `alerts{}`, `cases{}`, `workflow_events[]`, `audit_events[]`, `reviews[]`, lazy `_evidence_index`.

---

## 5. STEP 1 — SECURE SUBMISSION INTAKE

**Technology:** FastAPI route, Pydantic v2 `Submission` model, JWT/RBAC dependency.

Endpoint: `POST /api/v1/submissions` (main.py:563) — role `data_provider` / `admin`.
Endpoint: `POST /api/v1/submissions/paste` (main.py:621) — pasted logs.

Checks performed:
1. Schema version must be `1.0` (SUPPORTED_SCHEMA_VERSIONS = {"1", "1.0"}) → else **422**.
2. Content-type routing: multipart/form-data (file) OR JSON body.
3. If file → `ingest_bytes(filename, content)`; errors → **400** with the exact reason.
4. If JSON body → `Submission.model_validate()`; invalid → **422**.
5. Returns **201** with the stored submission object.

---

## 6. STEP 2 — MULTI-FORMAT PARSING

**Technology:** stdlib `csv`, `json`, `openpyxl`, custom regex/state-machine SQL parser.
Code: `ingestion.py` (215 lines).

Format rules (ingestion.py:23 `ingest_bytes`):

| Format | Parser | Limits |
|---|---|---|
| CSV | `csv.DictReader` (utf-8-sig) | header required, ≤ 200 columns |
| XLSX/XLSM | `openpyxl` read_only + data_only, active sheet | header row required, ≤ 200 columns |
| JSON | `json.loads` | array of objects OR `{records\|rows\|data}` OR `{tables:{}}` DB export |
| SQL/DUMP | `parse_sql_export` | only `INSERT … VALUES` + `COPY … FROM STDIN`, ≤ 10,000 statements |
| pasted logs | `parse_pasted_logs` | JSON-lines OR `key=value` lines |

**SQL safety parser (the pitch point)** — `parse_sql_export()` (ingestion.py:152):
- Regex whitelist: `INSERT INTO <table> (<cols>) VALUES (...)` and `COPY <table> (<cols>) FROM STDIN`.
- Values tokenizer `_split_sql_values` handles quotes/depth; `_sql_value` converts NULL/booleans/ints/floats/strings.
- **Rejects**: DDL, functions, `bytea`, subqueries, arbitrary expressions, custom pg_dump binary formats.
- **Never connects to or executes against a database.** It is a pure file adapter.

Every parsed record gets a lineage pointer `_row` (1-based index): `_lineage()` (ingestion.py:19).

---

## 7. STEP 3 — IMMUTABILITY (ARTIFACT + HASHING)

**Technology:** stdlib `hashlib.sha256`; `ArtifactStore` (artifacts.py) with local FS or boto3 (MinIO/S3).

Code: `artifacts.py:29` `put(category, id, content, suffix)`:
```
digest = SHA-256(content)
key    = "<category>/<id>/<digest>.<ext>"
if S3/MinIO: head_object → put_object if missing
else: local write if not exists (artifacts/<key>)
returns Artifact(key, sha256, size)
```

Two hashing layers for a submission (`main.py:608`):
- **Original bytes artifact** → the submitted file itself, content-addressed.
- **content_sha256** = SHA-256 of the *normalized records* JSON (sorted keys) — `content_hash()` (main.py:241) → verified later during reporting.

---

## 8. STEP 4 — ROW-LEVEL QUALITY GATE (FAIL CLOSED)

**Technology:** Pydantic + pure Python validation. Code: `normalize_records()` (main.py:223).

Per-row issues raised (each becomes an element of `quality_issues[]`):
1. `row N: missing entity identifier` — none of entity_id/entity/user/host/asset_id present.
2. `row N: missing timestamp` — no `timestamp` or `time`.
3. `row N: missing severity (insufficient evidence)` — has alert_id but no severity.
4. `row N: missing asset criticality (insufficient evidence)` — has asset_id but no criticality.

Behavior: issues are **reported and stored** (`quality.issue_count`, `quality.rows`), never silently dropped. These feed data-quality scoring and the `INSUFFICIENT_EVIDENCE` classification downstream.

---

## 9. STEP 5 — CANONICAL MAPPING & INDEXING

**Technology:** pure Python dicts/defaultdict. Code: `rowmap.py`, `index_records()` (main.py:269).

**Canonical entity resolution** (entity_id priority): `entity_id` → `entity` → `user` → `host` → `unknown`.

**rowmap.py — derived evidence flags (no invention of evidence):**

| Function | Returns true when |
|---|---|
| `truthy(v)` | v is True, or in TRUE_TOKENS {true,1,yes,y,required,mandatory,…} |
| `falsy_explicit(v)` | in {false,0,no,n,not_required,na,none,…} |
| `escalation_required(row)` | explicit `escalation_required` truthy, else severity is critical/high |
| `is_escalated(row)` | `escalated=True` or `escalation_id` or escalation_status in ESC_DONE or escalation_timestamp |
| `is_investigated(row)` | `investigated=True` or investigation_id or investigation_status in INV_DONE or start/completed timestamp or conclusion text |
| `is_responded(row)` | `responded=True` or response_id or response_status in RESP_DONE or response timestamp |
| `is_closed(row)` | closure_status in {closed,completed,resolved,done} or closure_id/closure_timestamp or status/case_status in {closed,resolved} |
| `conclusion(row)` | investigation_conclusion / conclusion text |
| `inv_end(row)` | investigation_completed / investigation_time / end_time |
| `closure_time(row)` | closure_timestamp / closure_time / closed_at |

**index_records builds:**
- `Store.entities`: `{id, name, sector, alerts, cases}` (dedup, name/sector enriched).
- `Store.assets`: `{id → {id, entity_id}}`.
- `Store.alerts`: `{alert_id → full row + id + entity_id}`, increments entity.alerts.
- `Store.cases`: `{case_id → full row + id + entity_id}`, increments entity.cases.
- `Store.workflow_events`: one `CanonicalEvidence` per row (`id, kind=workflow_event, entity_id, asset_id, timestamp, attributes={type,…}`).
- `Store._evidence_index`: map `record:<submission_id>#row-<n>` → source row (lazy, invalidated on new submissions).

**Evidence walk ID format used everywhere:** `record:<submission_id>#row-<N>`.
**Lineage format:** `submission:<submission_id>`, `row:<N>`.

---

## 10. STEP 6 — RULE ENGINE (ALL 13 RULES, FULL LOGIC)

**Technology:** pure deterministic Python. Code: `execute_rules()` (main.py:295), taxonomy in `taxonomy.py`.

Assessment trigger: `POST /api/v1/assessments` (main.py:660) → `submit_assessment(run)` (tasks.py) → sync (offline) or Celery queue.

**Finding object shape** (main.py:122, `Finding` model):
```
id, rule, severity(low|medium|high|critical), title, description,
entity_id, evidence[], lineage[], rule_version="rules-1.0",
confidence=0.85, calculation, limitations[]
```

**Finding creation helper `add()` (main.py:297):**
```
evidence = [record:<submission>#row-<n>]
lineage  = [submission:<id>, row:<n>]
calculation = "rule=<rule>; category=<category>; evidence_count=<n>"
limitations = ["Periodic submission only; supervisor validation required."]
```

### THE 13 RULES — trigger logic (each = 1 finding, merged per rule × entity after):

| # | Rule | Category | Severity | Exact trigger |
|---|---|---|---|---|
| 1 | `critical_alert_no_escalation` | execution_gap | critical / high | row has `alert_id`, severity is **critical** (or **high** — second branch) AND `escalation_required(row)` AND NOT `is_escalated(row)` |
| 2 | `closed_without_evidence` | execution_gap | high | row has `case_id`, is closed (`is_closed` or status=="closed") AND `evidence is False` |
| 3 | `escalation_no_response` | execution_gap | high | row has `alert_id` AND `is_escalated(row)` AND NOT `is_responded(row)` |
| 4 | `closure_before_investigation` | execution_gap | high | row has `case_id`, both `closure_time` and `investigation_end` present AND closure < investigation (string compare—ISO timestamps) |
| 5 | `investigation_without_conclusion` | execution_gap | medium | row has `case_id` AND `is_investigated(row)` AND `conclusion(row)` empty |
| 6 | `missing_severity` | execution_gap | medium | row has `alert_id` AND severity blank (insufficient evidence) |
| 7 | `missing_asset_criticality` | execution_gap | low | row has `asset_id` AND no asset_criticality/criticality |
| 8 | `invalid_status` | execution_gap | medium | status not in {open,new,investigating,in_progress,closed,resolved,escalated,""} |
| 9 | `invalid_status_order` | execution_gap | high | status in {closed,resolved} AND investigated is False; OR case closed/resolved without investigation + no investigation_id |
| 10 | `alert_without_case` | execution_gap | medium | row has `alert_id` AND no `case_id`; PLUS entity-level rule: entity has alert activity but zero case records |
| 11 | `duplicate_record` | execution_gap | medium | same `alert_id`/`case_id` seen twice — one finding per affected row with evidence pair `[first_row, this_row]` |
| 12 | `repeated_investigation_template` | execution_gap | medium | Jaccard similarity ≥ **0.92** between normalized conclusion/notes texts of ≥20 chars (both rows) |
| 13 | `response_time_anomaly` | execution_gap | medium | response minutes > `max(median × 1.5, median + 30)` computed against the entity's own response-time sample (needs ≥ 2 values) |

**Negative-space rules (absence-based):**

| Rule | Trigger |
|---|---|
| `asset_without_coverage` | entity has rows but zero asset_id values |
| `negative_space_period_gap` | timeline spans ≥ 3 weekly periods; a week in between has no records (only for `alert_id`/`case_id` rows with timestamps) |

**Text similarity math (main.py:468):**
```
_normal_text: lowercase → strip non-alphanumeric → collapse whitespace
_text_similarity(a,b) = |A ∩ B| / |A ∪ B|   (A,B = token sets)
```

**Response anomaly math (main.py:390):**
```
median = statistics.median(all response minutes for that entity)
threshold = max(median * 1.5, median + 30)
finding fires when  value > threshold
```

**Finding deduplication (main.py:433):** findings merged per `(rule, entity)` EXCEPT `duplicate_record`, which stays per affected row. Evidence and lineage arrays are merged with `dict.fromkeys` (unique, order-preserving); `calculation` evidence_count is recomputed.

---

## 11. STEP 7 — COMPLIANCE MODEL (12 CONTROLS + CLASSIFICATION)

**Technology:** pure Python. Code: `compliance.py` (rule version `sat-sa-rules-1.2`).

### 12 controls actually evaluated by `evaluate_controls()` (compliance.py:177):

| Control | Domain | Numerator / Denominator |
|---|---|---|
| **TD-01** Alert generation coverage | Threat Detection | rows with valid timestamp / all scoped rows |
| **TD-02** Severity classification completeness | Threat Detection | rows with valid severity / all scoped rows |
| **TR-01** Alert-to-case linkage | Alert Triage | rows linked via case_id / scoped rows |
| **IN-01** Investigation existence | Investigation | cases with investigation / all cases |
| **IN-02** Investigation conclusion quality | Investigation | cases with investigation AND conclusion / investigated cases |
| **ES-01** Escalation completion | Escalation | escalated / cases requiring escalation (special case: `sufficient_negative=True` → 100% when no escalation required is provable) |
| **IR-01** Response evidence | Incident Response | responded / cases that required escalation or were escalated or critical |
| **MO-01** Monitoring coverage | Monitoring Coverage | critical-assets-with-evidence / critical assets (or mapped assets fallback) |
| **CM-01** Case status validity | Case Management | cases with valid status / all cases |
| **CL-01** Closure discipline | Closure & Evidence | closures with valid order / assessable closures |
| **GV-01** Reporting completeness | Governance | rows with timestamp + known entity / all rows |
| **DQ-01** Record validity & uniqueness | Data Quality | rows minus (dups + invalid timestamps + missing mandatory) / all rows |

**Per-control output** (`ctrl()` compliance.py:188):
```
coverage = round(num / den * 100, 1)      # None if den==0
status   = _status_for(coverage, den)      # thresholds below
score    = {COMPLIANT:100, PARTIAL:50, NON:0, INSUFFICIENT:None}
calculation = "<num>/<den> = <coverage>%"
supporting_finding_ids, evidence_ids
```

### Classification thresholds (compliance.py:26, `_status_for` :162):

```
den == 0           → INSUFFICIENT_EVIDENCE
coverage ≥ 85      → COMPLIANT          (score 100)
coverage ≥ 60      → PARTIALLY_COMPLIANT (score 50)
else               → NON_COMPLIANT       (score 0)
```

### Entity compliance computation — `entity_compliance()` (compliance.py:291):

```
compliance_score = mean of scores of sufficiently evidenced controls (fmean)
evidence_coverage = scored_controls / total_controls × 100

STATE DECISION (priority order):
  no rows                          → NOT_ASSESSED
  evidence_coverage < 50%          → INSUFFICIENT_EVIDENCE
  score < 60  OR  critical findings:
      score ≥ 60 and critical ≤ 2  → PARTIALLY_COMPLIANT
      else                         → NON_COMPLIANT
  score ≥ 85 and critical == 0     → COMPLIANT
  else                             → PARTIALLY_COMPLIANT
```

Output includes: status, compliance_score, evidence_coverage, control counts (compliant/partial/non/insufficient), severity mix (critical/high/medium/low counts), full controls, risk_score, risk_drivers.

**Recommended action** — `recommend_action()` (compliance.py:381):
```
NON_COMPLIANT or critical>0 or risk≥70 → IMMEDIATE REVIEW
INSUFFICIENT_EVIDENCE                  → EVIDENCE REQUEST
PARTIAL or risk ≥ 40                   → SUPERVISORY REVIEW
compliance ≥ 85                        → NO ACTION
else                                   → ROUTINE REVIEW
```

---

## 12. STEP 8 — RISK SCORING (FULL FORMULAS)

Two complementary risk models exist; both deterministic and explainable.

### Model A — Explainable additive risk drivers (used per entity in compliance.py:333)

```
score = 0
critical findings → + min(30, critical_count × 6)
high findings     → + min(20, high_count × 3)
medium findings   → + min(8,  medium_count × 1.0)
low findings      → + min(4,  low_count × 0.5)
escalation gap    → + min(25, missing_rate% × 0.25)
investigation gap → + min(12, no_inv% × 0.12)
monitoring gap    → + min(10, critical_no_case × 1.5)
evidence limit    → + min(10, (100 − evidence_coverage) × 0.1)
score = clamp(score, 0, 100)
drivers returned sorted descending by points (named factors!)
```

### Model B — Peer-adjusted risk score (scoring.py:38 `calculate_entity_risk`)

```
evidence_strength(finding) = mean of:
    [ min(evidence_count, 3) / 3
    , min(lineage_count, 2) / 2
    , 1 if any lineage starts with "submission:" else 0
    , 1 if calculation string exists else 0 ]

rates[entity] = entity_findings / max(entity_records, 1)
z = (rate − sector_mean) / sector_pop_stdev        # 0 when <2 peers
bounded_z = clamp(z, −3, +3)
peer_multiplier = 1 + 0.10 × bounded_z

base_burden = Σ severity_weight × evidence_strength
severity_weights = {low:1.0, medium:3.0, high:7.0, critical:12.0}
worst_case = volume × 12 × 1.0 × (1 + 0.10 × 3)

risk_score = 100 × base_burden × peer_multiplier / worst_case   (0–100)
tier        = critical ≥ 70 | high ≥ 40 | medium else
```

This is the model behind the risk-vs-compliance scatter and attention matrix on the dashboard.

---

## 13. STEP 9 — SUPERVISORY ANALYTICS (STAR SCHEMA)

**Technology:** pure Python with `collections.defaultdict`. Code: `analytics.py` (1,752 lines), `supervisory.py`.

`SupervisoryAnalytics.__init__(tables)` (analytics.py:72):
- Adapts the in-memory Store into relational tables: entities, assets, alerts, cases, investigations, escalations, responses, remediations, submissions.
- Builds cross-indexes: `_alerts_by_entity`, `_cases_by_entity`, `_cases_by_id`, `_inv_by_case`, `_esc_by_case`, `_resp_by_case`, `_rem_by_case`, `_assets_by_entity`, `_subs_by_entity`.

**8 capability dimensions:** Threat Detection, Investigation, Escalation, Incident Response, Security Operations, Governance & Oversight, Operational Discipline, Cyber Resilience.

**What it computes (the 10 KPIs on the Overview page):**
1. Compliance distribution (Compliant / Partial / Non / Insufficient / Not assessed)
2. Deterministic executive summary (supervisory.py:84)
3. Severity mix (critical/high/medium/low)
4. Alert trends by month
5. Sector comparison (compliance + non-compliance %)
6. Risk-vs-compliance scatter + attention matrix (supervisory.py:61)
7. Control performance across entities (supervisory.py:146)
8. Execution gaps (per-rule × entity burden)
9. Data-quality composite (formula below)
10. Workflow funnel (supervisory.py:103) + reporting coverage

**Workflow funnel stages:** Alerts → Cases → Investigations → Escalations → Responses → Closures, each with `coverage_pct` (vs alerts) and `conversion_pct` (vs previous stage).

**Data quality composite** (compliance.py:417, METHODOLOGY):
```
overall = 0.30·completeness + 0.25·validity + 0.20·consistency
        + 0.15·uniqueness    + 0.10·timeliness
```
Dimensions measured over mandatory fields `(entity_id, timestamp, severity, asset_id)`.

**Grouped findings** (supervisory.py:156): grouped by `rule × entity` with `affected_records`, denominator logic per rule, and a human-readable `calculation` string for each group.

---

## 14. STEP 10 — PERSISTENCE & DATA MODEL

**Technology:** SQLAlchemy 2.0 ORM; SQLite default → PostgreSQL via `DATABASE_URL`. Code: `database.py`.

Tables:

| Table | Columns | Meaning |
|---|---|---|
| `submissions` | id PK, name, source, payload(Text JSON), created_at, schema_version | submitted dataset + quality issues |
| `assessments` | id PK, submission_id FK, payload(JSON), created_at, schema_version | assessment + summary |
| `findings` | id PK, assessment_id FK, payload(JSON) | each finding |
| `reviews` | id PK, assessment_id FK, payload(JSON), created_at | supervisor decisions |
| `audit_events` | id PK, payload(JSON), created_at | immutable trail |
| `schema_metadata` | key PK, value | schema_version, migration_revision |
| `entities` | id PK, name, sector, created_at | deduplicated entity registry |

Write functions: `persist_submission`, `persist_assessment`, `persist_review`, `persist_audit_event` (all use `session.merge` inside a transaction).
Load: `load_state(store)` rebuilds the entire in-memory Store on boot.
`readiness_check()` runs `SELECT 1` for the readiness endpoint.

---

## 15. STEP 11 — REVIEW QUEUE & HUMAN DECISION

**Technology:** FastAPI + pure Python sorting. Code: `main.py:850` (`review_queue`), `main.py:793` (`review_assessment`).

Queue construction:
```
priority = {critical:100, high:70, medium:40, low:10}
queue.sort(key = (−priority, entity_id, rule))     # deterministic
Round-robin across entities/rules prevents a single noisy entity/control
from monopolizing the queue.
Each item exposes evidence context: alert_ids, asset_ids, timestamps.
```

Review decision route: `POST /api/v1/assessments/{id}/review`.
Statuses (REVIEW_STATUSES): NEW, UNDER_REVIEW, IN_REVIEW, VALIDATED, DISMISSED, REJECTED, REQUIRES_EVIDENCE, FOLLOW_UP, CLOSED with aliases (`IN_REVIEW→UNDER_REVIEW`, `REJECTED→DISMISSED`).

SAT review routes: `PATCH /api/v1/sat/review-queue/{finding_id}` and `POST …/status`.

Every decision → `record_audit_event(...)` with actor, role, previous/new state, annotation, details.

---

## 16. STEP 12 — HASH-CHAINED AUDIT TRAIL

**Technology:** stdlib `hashlib.sha256`. Code: `record_audit_event` (main.py:198), `audit_hash` (supervisory.py:361, compliance.py:505).

Event payload:
```
{id, timestamp, event_type, actor, target_type, target_id, action,
 assessment_id, previous_state, new_state, source, role, event_hash, details}
event_hash = SHA-256(JSON(core, sort_keys))
```

Chaining: `audit_hash(prev_hash, event)` = SHA-256 over previous hash + event. Combined with `event_hash`, the full chain is tamper-evident.

Event types: assessment_created, dataset_uploaded, assessment_executed, finding_generated, finding_opened, finding_validated, finding_rejected, evidence_requested, reviewer_assigned, finding_closed, report_generated.

Query endpoint: `GET /api/v1/audit-events?event_type=&actor=&target_id=` — role `auditor`/`admin`/`supervisor`/`reviewer`.

---

## 17. STEP 13 — DETERMINISTIC Q&A (NO LLM)

**Technology:** pure keyword/pattern parsing. Code: `qa.py`.

`answer_question(question, findings, entities, records_by_evidence)`:
- `parse_question` extracts intent (blame / history / risk / trend / time-range) and filters.
- `_in_time_range(finding, records, time_range)` supports date-window questions.
- `_date(value)` parses timestamps.

Purpose: the supervisor asks "which entity is driving the criticals this month?" and gets a factual, evidence-anchored answer — no LLM, no hallucination. Endpoint: `POST /api/v1/assessments/{id}/ask`.

---

## 18. STEP 14 — REPORTING (JSON / HTML / PDF)

**Technology:** pure Python; `reporting.py` (render_html, render_pdf). Code: `main.py:811`.

`GET /api/v1/assessments/{id}/report?format=json|html|pdf`:
```
report = {assessment, submission(id, content_sha256), findings, reviews}
serialized = JSON(sorted_keys, no spaces)
report_sha256 = SHA-256(serialized)
artifact  = artifact_store.put("reports", assessment_id, bytes, "json")
hash_verified = (SHA-256(current records) == submission.content_sha256) ?
report["report_sha256"], report["report_artifact"], report["hash_verified"]
```
Response: JSON (structured), `text/html` (professional HTML layout), `application/pdf` (download), all generated locally, offline.

---

## 19. STEP 15 — FRONTEND DASHBOARD

**Technology:** React 19 + TypeScript 5.7 + Vite 6 + Recharts 3 + react-router 7 + Nginx.

Pages (`frontend/src/pages/`):
- **Overview.tsx** — 10 KPIs, compliance distribution, severity mix, alert trends, risk-vs-compliance scatter, attention matrix.
- **Entities.tsx** — per-entity drill-down: compliance, risk, funnel, execution gaps, peer radar, evidence lineage.
- **Ops.tsx** — operational KPIs: funnel, execution gaps, reporting coverage, data quality.
- **Gov.tsx** — governance: audit trail, review queue, validated findings.

Shared: `api.ts` (typed fetch client), `ui.tsx` (chart + UI primitives), `styles.css`.

Build: `vite build` → static bundle → Nginx container (serves on port 80, exposed 5173).

---

## 20. SECURITY, DEPLOYMENT, OBSERVABILITY

### Security (auth.py)
- `DEMO_AUTH_DISABLED=true` → demo claims `{sub:demo, roles:[admin]}`.
- Production: Bearer JWT → HS256 (`JWT_SECRET`) or RS256 via Keycloak JWKS (`OIDC_ISSUER`/`OIDC_JWKS_URL`); roles from `roles`, `realm_access`, `resource_access`; only internal ROLES accepted; unknown → 403.
- `require_roles(*allowed)` FastAPI dependency applied to every protected route.
- RBAC roles: `supervisor`, `reviewer`, `auditor`, `admin`, `data_provider`.

### Upload hardening
schema version, ≤200 columns, ≤10,000 SQL statements, restricted SQL parser, row-level quality.

### Deployment (docker-compose.yml)
| Service | Image | Profile |
|---|---|---|
| api (uvicorn :8000) | backend/Dockerfile | demo + prod |
| web (Nginx :80→5173) | frontend/Dockerfile | demo + prod |
| postgres 16-alpine | postgres | production |
| redis 7-alpine | redis (Celery broker) | production |
| minio | minio/minio :9000 | production |

### Observability
- `GET /api/v1/health` → `{status:ok, service:soc-inspect, time}`.
- `GET /api/v1/readiness` → DB `SELECT 1` + artifact backend.
- `GET /metrics` → Prometheus text format (request counts, latencies, assessment stages).
- Correlation middleware: assigns `X-Request-ID`, records metrics, adds ID to structured errors.

---

## 21. EVERY API ENDPOINT

**Base:** `/api/v1` — OpenAPI docs at `/docs`.

| Area | Endpoints |
|---|---|
| Health | `GET /health`, `GET /readiness`, `GET /metrics` |
| Submissions | `POST /submissions`, `POST /submissions/paste`, `GET /submissions/{id}`, `GET /submissions/{id}/quality` |
| Assessments | `POST /assessments`, `GET /assessments/{id}`, `GET /assessments/{id}/status`, `GET /assessments/{id}/entities`, `GET /assessments/{id}/findings`, `POST /assessments/{id}/ask`, `POST /assessments/{id}/review`, `GET /assessments/{id}/report` |
| Findings | `GET /findings/{id}/evidence` |
| Reviews | `GET /review-queue`, `GET /audit-events` |
| Analytics | `analytic/overview`, `compliance`, `entities`, `entities/{id}`, `severity`, `sectors`, `workflow`, `execution-gaps`, `alerts`, `investigations`, `escalations`, `monitoring`, `data-quality`, `peer-benchmark`, `findings-grouped`, `finding-evidence/{id}` |
| SAT view | `sat/overview`, `sat/entities`, `sat/entities/{id}`, `sat/alerts`, `sat/investigations`, `sat/escalations`, `sat/monitoring`, `sat/execution-gaps`, `sat/negative-space`, `sat/peer-benchmark`, `sat/findings`, `sat/data-quality`, `sat/review-queue`, `PATCH sat/review-queue/{id}`, `POST sat/review-queue/{id}/status`, `sat/sample`, `sat/report` |
| Demo | `demo/overview` |

---

## 22. VALIDATION EVIDENCE

| Check | Command / Result |
|---|---|
| Backend tests | `pytest -q backend/tests` — **56 passing** across 15 files |
| Test files | test_analytics, test_api, test_compliance, test_data_quality, test_hardening, test_ingestion, test_phase5, test_production_areas, test_qa, test_rule_recall, test_sample, test_sat_api, test_scoring, test_supervisory, conftest |
| Frontend | `vite build` — strict TypeScript, passes |
| Migrations | Alembic upgrade/downgrade verified |
| Docker | demo + production profiles validated |
| Ops | health/readiness/metrics passes |
| Security | auth + RBAC passes; SQL safety parser rejects DDL/functions |
| Demo data | `examples/sat_sa_demo_soc.csv` — 20 entities, 11,607 rows, 32 columns, 10 behavioural archetypes, deterministic seed (`seed(reset=True)` → `soc_inspect.db` 32 MB) |

---

## 23. FILE REFERENCE MAP

| File | Role |
|---|---|
| `backend/app/main.py` | FastAPI routes, Store, normalize, index, rule engine, review, reporting orchestration (1768 lines) |
| `backend/app/ingestion.py` | CSV/XLSX/JSON/SQL/paste parsing + restricted SQL parser |
| `backend/app/rowmap.py` | canonical field mapping + derived evidence flags |
| `backend/app/taxonomy.py` | rule→category map, controls, statuses |
| `backend/app/compliance.py` | 12 controls, classification, additive risk, funnel, data quality |
| `backend/app/scoring.py` | evidence strength + peer-adjusted risk |
| `backend/app/analytics.py` | SupervisoryAnalytics star schema (1752 lines) |
| `backend/app/supervisory.py` | KPIs, attention matrix, audit hash chain, grouping |
| `backend/app/reporting.py` | JSON/HTML/PDF rendering |
| `backend/app/artifacts.py` | SHA-256 content-addressed artifact store (local/S3/MinIO) |
| `backend/app/auth.py` | JWT / OIDC / RBAC |
| `backend/app/database.py` | SQLAlchemy schema + persistence + load_state |
| `backend/app/tasks.py` | sync ↔ Celery/Redis boundary |
| `backend/app/qa.py` | deterministic no-LLM Q&A |
| `backend/app/metrics.py` | Prometheus metrics |
| `backend/app/seed/generate_evidence.py` | 20-entity / 11,607-row deterministic demo |
| `frontend/src/pages/` | Overview, Entities, Ops, Gov dashboard pages |
| `frontend/src/api.ts` | typed API client |
| `docker-compose.yml` | demo + production profiles |
| `examples/sat_sa_demo_soc.csv` | replays the full demo |

---

## Presentation cheat sheet

1. **"Deterministic core"** = rules versioned `rules-1.0` / `sat-sa-rules-1.2`, pure Python, no randomness.
2. **"Fail closed"** = missing evidence → INSUFFICIENT_EVIDENCE, never compliance.
3. **13 rules** = execution gaps (workflow broken) + negative space (evidence missing).
4. **12 controls** = TD-01/02, TR-01, IN-01/02, ES-01, IR-01, MO-01, CM-01, CL-01, GV-01, DQ-01.
5. **Risk** = additive named drivers (compliance.py) + peer z-score model (scoring.py).
6. **Evidence walk** = `record:<submission>#row-<N>` → click to source row.
7. **Proof** = 56 tests, TypeScript build clean, SQL parser safe, hash-verified reports, offline-first Docker.
8. **Human in the loop** = queue sorts candidates only; every decision is a hash-chained audit event.