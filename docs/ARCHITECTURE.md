# SAT-SA Architecture (SIH26157)

Supervisory Analytics Tool for SOC Assessment. It analyses periodic SOC alert and case-management submissions from many CSEs and tells NCIIPC supervisors which entities, controls and alert samples to review manually. It is not a SIEM, does not monitor in real time, and does not collect telemetry.

## 1. Solution architecture

```
 CSE periodic exports            NCIIPC air-gapped host (Docker Compose, 2 containers)
 (CSV / JSON / XLSX /    ┌──────────────────────────────────────────────────────────────┐
  SQL dump / API POST)   │  web  (nginx)  React UI ── /api/* reverse proxy ──┐          │
        │  upload        │                                                   ▼          │
        └───────────────►│  api  (FastAPI, Python 3.12)                                 │
                         │   ingestion ─► normalisation & lineage (_row) ─► data-quality│
                         │   analytics engine: execution gaps · negative space ·       │
                         │     peer outliers · capability scores · risk · sampling     │
                         │   compliance model (12 domains) · review queue · reports    │
                         │   hash-chained audit trail                                  │
                         │  storage: SQLite volume (default) or PostgreSQL; local      │
                         │           artifact store for raw submissions & reports       │
                         └──────────────────────────────────────────────────────────────┘
```

All processing is local. No external URLs, CDNs, fonts, SaaS, or hosted models are referenced anywhere in the code.

## 2. Functional design

| Requirement | Implementation |
|---|---|
| Paper vs practice (the PS definition of an execution gap) | CSE self-assessments (`POST /api/v1/declarations`, CSV/JSON/XLSX) are compared with the same metric measured from the evidence. A gap of at least 15 points is flagged as `EG-DECLARED-GAP` and scored as "Reporting integrity". |
| Behaviour checks (use cases viii, ix) | SLA gaming: closures bunch just inside the SLA deadline. Analyst concentration: one login records most investigations. Night-time blind spot: no detections between 00:00 and 07:00 IST while peers detect around the clock. |
| Ingest multi-CSE structured data (FR1-3) | `POST /api/v1/submissions` accepts CSV, JSON, XLSX, restricted SQL/`pg_dump` text; pasted JSON-lines/key=value. Every record keeps its source row number for lineage. |
| Detection / investigation / escalation weaknesses, execution gaps (FR4-5) | 8 execution-gap rules: fast critical closure, cases without investigation, no conclusion, required escalation missing, escalation without response, repeated alerts on an asset without remediation, templated investigation narratives, fast closure with thin evidence. |
| Negative space (FR6) | Missing monthly reporting periods, critical assets with no telemetry, alert volume below sector peers, low investigation coverage, alert categories most sector peers report but the entity never does, statistical under-performance versus peers. |
| Anomalies / outliers (FR7) | Robust z-score (median/MAD, Iglewicz-Hoaglin cut-off 3.5) on investigation, escalation, response, monitoring and evidence metrics across all entities. |
| Peer comparison (FR8) | Sector medians, percentiles and deviations for each control metric. |
| Entity risk indicators (FR9) | 0-100 score with named contributors (execution gaps, negative space, peer deviation, capability weakness) → LOW / MODERATE / HIGH / CRITICAL. |
| Prioritise review (FR10) | Ranked attention matrix; `GET /sat/sample` returns a prioritised case sample with reasons, plus a random control sample. Each entity gets an **examination plan** (`/sat/entities/{id}/examination-plan`): questions to ask, documents to request, and the case IDs to pull first. |
| Explainability and audit (FR11-14) | Each finding carries the rule ID and version, observed versus expected value, the calculation, and source-row evidence IDs. Reviewer actions are written to a SHA-256 hash-chained audit log. |
| Reporting, trends, drill-down (FR15-17) | Dashboards, monthly trend series, entity drill-down to source rows, and JSON/HTML/PDF reports stamped with the dataset hash and methodology. |

## 3. Analytics methodology

The analytics are deterministic and rule-based, and each rule can be explained on its own terms. A signal's **intensity** for an execution gap is the share of the entity's cases affected, reaching full intensity at 15%. Signals combine with a saturating noisy-OR:
`component = 100 × (1 − Π(1 − severity_weight × intensity))`, with severity weights critical 1.0, high 0.6, medium 0.3, low 0.1.
`risk = 0.45·execution + 0.20·negative-space + 0.20·peer-deviation + 0.15·capability-weakness + 0.10·reporting-integrity` (capped at 100). Risk tiers are CRITICAL ≥ 60, HIGH ≥ 40, MODERATE ≥ 25.
Compliance is the weighted average of controls that have enough evidence. If evidence coverage is below 50%, the entity is classed `INSUFFICIENT_EVIDENCE`, so missing evidence is never counted as compliance. Templated investigations are found by comparing normalised free-text notes within each entity: the same note must appear at least 5 times and make up at least 10% of that entity's notes. Duration is taken from the reported field, or worked out from the start and end timestamps.

**AI/ML statement.** The prototype uses no machine-learning model, so there is no model architecture, training pipeline or model-update process, and no GPU is needed. Statistical outlier detection (median/MAD) is closed-form and fully reproducible. Explainability: every score breaks down into named contributors and rule evidence. Auditability: the rule version, dataset SHA-256 and hash-chained reviewer actions are recorded. Any future ML model must run offline, be loaded from a signed local file, and be shown alongside these rules, never instead of them.

## 4. Data requirements

The minimum fields are `entity_id`, `timestamp`, `alert_id`, and `severity`. Recommended fields are `sector`, `asset_id`, `asset_criticality`, `alert_category`, `case_id`, investigation start, end, duration, conclusion and notes, `evidence_count`, `escalation_required`/`escalation_id`, `response_id`, `remediation_id`, closure timestamp, `analyst_id` and `reporting_period`. The full 40-column schema is in `examples/sat_sa_demo_soc.csv`. No raw logs, packet captures or personal data are needed.

## 5. Infrastructure and deployment

- **Hardware (prototype):** 2 vCPU, 4 GB RAM and 10 GB disk handle about 100k records. For national scale, use 8 vCPU, 16 GB RAM and PostgreSQL.
- **Software:** Docker Engine 24+ with Compose v2 on Linux. No internet access is needed at runtime.
- **Air-gapped install:** on a connected build host, `scripts/build-offline-bundle.sh` produces one tarball containing the images, the compose file and a checksum file. On the target host, `install-offline.sh` checks the checksums, runs `docker load` and starts the stack with `--pull never`.
- **Operations:** health and readiness probes run at `/api/v1/health` and `/api/v1/readiness`, and Prometheus metrics are at `/metrics`. Data lives on the `satsa-data` volume. To upgrade, load the new images and restart the stack; the data volume is kept.

## 6. Validation methodology (live on the **Validation** page, `GET /api/v1/validation/summary`)

1. **Ground truth.** The generator plants 10 archetypes and 3 extra behaviours: SLA gaming in BPCL, a night-time blind spot in CPA, and analyst concentration in RAIL. **Measured result: risk-score AUC 1.0, tier accuracy 100%, 11/11 planted behaviours detected, with no false positives on the three behaviour checks.** A broadly-firing rule only counts as a detection when the entity's rate is at least 1.5× the median across entities.
2. **Comparison with manual random sampling.** A simulated examiner checklist (7 deficiency tests) is applied to all 10,177 cases. **Measured result: a 5% sample from SAT-SA is 100% deficient cases, against 22% for random sampling (4.5× lift). Finding half of all deficient cases takes 12% of review effort with SAT-SA versus 48% with random sampling.** The checklist uses some of the same evidence fields as the prioritiser, so this test measures how well the tool orders cases. The independent tests are (1) and (3).
3. **Examiner agreement.** Live precision for each rule is calculated from validate/reject decisions in the review queue. Rule thresholds are versioned and are only changed after precision is re-measured on stored decisions.
4. **Determinism.** The same input and rule version always produce the same output. Reports carry the dataset hash.
