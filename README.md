# SOC-Inspect (SAT-SA)

Evidence-based supervisory analytics for reviewing SOC submissions from Critical Sector Entities. Built for SIH 2026 problem statement SIH26157.

SOC-Inspect is a **supervisory analytics tool**. It is not a SIEM, not real-time SOC monitoring, not autonomous incident response, and not a chatbot. It answers: which entities are compliant, which need attention, what evidence supports every finding, and what action the supervisor took.

> **Synthetic demonstration data.** The bundled dataset simulates SOC records for named organisations (ONGC, NTPC, IOCL, HAL, GAIL, BEL, BHEL, Mazagon Dock, …). It does **not** represent their actual cybersecurity posture, compliance status, or incidents.

## What it does

- **Explicit compliance model** — every entity gets `COMPLIANT / PARTIALLY_COMPLIANT / NON_COMPLIANT / INSUFFICIENT_EVIDENCE`, a compliance score, evidence coverage, and control-by-control calculations across 12 domains (Threat Detection → Cyber Resilience). Missing evidence is never treated as compliance.
- **Explainable risk scoring** — a magnitude-aware risk score (the share of cases affected by each signal) with named drivers, rather than an opaque number.
- **Execution gaps and negative space** — fast critical closures, missing escalations, templated investigation notes (detected from free text), repeated alerts without remediation, missing reporting periods, unmonitored critical assets, absent alert categories versus sector peers, and robust (median/MAD) statistical outliers versus peers.
- **Paper vs practice** — CSE self-assessments are compared with what the evidence shows; overstated KPIs are execution gaps (`examples/sat_sa_self_assessment.csv`).
- **Behaviour checks** — SLA gaming (closures bunched just inside the deadline), analyst concentration, and night-time blind spots.
- **Examination plan** — for each entity: the questions to ask, the documents to request, and the case IDs to pull first (printable).
- **Validation, measured** — risk-score AUC 1.0 against planted ground truth; a 5% prioritised sample is 4.5× richer in deficient cases than random sampling.
- **Supervisory command overview** — 10 KPIs, deterministic executive summary, compliance distribution, severity mix, alert trends, sector comparison, risk-vs-compliance scatter, control performance, execution gaps, data-quality issues, workflow funnel, reporting coverage, and a ranked attention matrix with deterministic recommended actions.
- **Entity drill-down** — compliance, risk, funnel (Alert → Case → Investigation → Escalation → Response → Closure), execution gaps, peer radar, and evidence lineage down to source rows.
- **Evidence-first findings** — grouped by rule × entity with affected-record counts; every finding carries rule version, calculation, and source rows.
- **Actionable review queue + hash-chained audit trail** — every validate, reject, evidence-request or close action is an audited event linked to the previous event's hash. `GET /api/v1/audit-events/verify` detects any edit, deletion or reordering.
- **Professional reports** — JSON / HTML / PDF with scope, dataset hash, methodology, rule version, and limitations.

## Deployment (Docker, offline)

Prerequisites: Docker Engine 24+ with Compose v2. Nothing is fetched from the internet at runtime.

```bash
cp .env.example .env          # optional: port, auth, seeding
docker compose up -d --build  # UI + API on http://<host>:8080
```

The first start seeds the deterministic 20-entity demo dataset into the `satsa-data` volume. This takes about a minute and happens only once. nginx serves the UI and proxies `/api/*`, so clients only need port 8080. The data persists across restarts and upgrades.

**Air-gapped host.** On a connected build machine, run `scripts/build-offline-bundle.sh`. It writes `dist/sat-sa-offline-<ver>.tar.gz` (~135 MB, containing the images, compose file, checksums and installer). Copy the tarball to the target host, extract it, and run `./install-offline.sh`. The installer verifies the checksums, runs `docker load`, and starts the stack with `--pull never`.

Auth is disabled for the demo (`DEMO_AUTH_DISABLED=true`). Production must set it to `false` and provide a strong `JWT_SECRET`. The API runs as one worker by design, because assessment state is held in-process and backed by the database.

## Hosted demo (Vercel)

`vercel.json` deploys the project as two services on one domain: `frontend` (Vite static build) serves `/`, and `backend` (FastAPI, `backend/index.py`) serves `/api/*`. This is for a public demo link only. The NCIIPC deployment target is the offline Docker stack above.

Interactive API docs are at `/docs`. Serverless limits apply. Each instance unpacks the bundled demo snapshot (`backend/app/seed/demo_snapshot.db.gz`) into its own `/tmp` SQLite on cold start (~1 s), and reviews and uploads are not shared between instances or kept across restarts. After changing the generator, regenerate the snapshot: `DATABASE_URL=sqlite:////tmp/s.db python -m app.seed.generate_evidence --reset && gzip -9 -n -c /tmp/s.db > app/seed/demo_snapshot.db.gz` (run inside `backend/`). For persistence, set `DATABASE_URL` to PostgreSQL. Uploads are limited to 4.5 MB per request.

## Local development

Prerequisites: Python 3.12+, Node 20+.

```bash
# Backend (http://127.0.0.1:8000, docs at /docs)
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn app.main:app --app-dir backend

# Frontend (http://127.0.0.1:5173)
cd frontend && npm install && npm run dev   # proxies /api to :8000

# (Re)seed the 20-entity synthetic demo dataset (11.6k alerts, deterministic)
cd backend && python -m app.seed.generate_evidence --reset
```

## Demo data

`examples/sat_sa_demo_soc.csv` — 5,528 relational rows × 40 columns across 21 entities and 10 behavioural archetypes, sampled evenly over January–September 2026 (strong compliance, escalation/investigation/response failures, monitoring gaps, data-quality issues, under-reporting, premature closure, mixed risk). Upload it via **Submissions** to replay the full demo, including deliberate edge cases (missing escalation, alert without case, conclusion-less investigation, duplicates, reporting gaps).

## API (base `/api/v1`)

| Area | Endpoints |
|---|---|
| Analytics | `analytics/overview`, `analytics/compliance`, `analytics/entities`, `analytics/entities/{id}`, `analytics/severity`, `analytics/sectors`, `analytics/workflow`, `analytics/execution-gaps`, `analytics/alerts`, `analytics/investigations`, `analytics/escalations`, `analytics/monitoring`, `analytics/data-quality`, `analytics/peer-benchmark`, `analytics/findings-grouped`, `analytics/finding-evidence/{id}` |
| Pipeline | `submissions` (JSON/CSV/XLSX/SQL/paste), `assessments`, `findings`, `findings/{id}/evidence`, `review-queue`, `audit-events` |
| Reports | `assessments/{id}/report`, `sat/report` (`?format=json\|html\|pdf`) |

## Tests

```bash
pytest -q backend/tests   # 68 tests: compliance maths, risk separation vs ground truth,
                          # signals on uploaded CSVs, audit chain, ingestion, reports
cd frontend && npm run build   # type-checks then builds
```

## Layout

```
backend/app/        FastAPI app: main.py (routes), analytics.py, compliance.py,
                    ingestion.py, scoring.py, taxonomy.py, seed/generate_evidence.py
frontend/src/       React + TypeScript: ui.tsx (charts/primitives), pages/
examples/           sat_sa_demo_soc.csv demo dataset
docs/ARCHITECTURE.md 2-page architecture, methodology, AI/ML statement, validation
docs/sih/           SIH presentation and reference material
scripts/            offline (air-gapped) bundle build + install
```

## Methodology (short)

See `docs/ARCHITECTURE.md` for the full methodology. 
Compliance score = weighted average of sufficiently evidenced controls (`COMPLIANT=100, PARTIAL=50, NON=0`; `INSUFFICIENT_EVIDENCE` excluded from the numerator but counted in coverage). Classification: evidence coverage < 50% → `INSUFFICIENT_EVIDENCE`; any unresolved critical finding → `NON_COMPLIANT`; score ≥ 85 → `COMPLIANT`; ≥ 60 → `PARTIALLY_COMPLIANT`. Data quality = `0.30·completeness + 0.25·validity + 0.20·consistency + 0.15·uniqueness + 0.10·timeliness`.
