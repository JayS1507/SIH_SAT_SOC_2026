# SOC-Inspect (SAT-SA)

Evidence-based supervisory analytics for reviewing SOC submissions from Critical Sector Entities. Built for SIH 2026 problem statement SIH26157.

SOC-Inspect is a **supervisory analytics tool**. It is not a SIEM, not real-time SOC monitoring, not autonomous incident response, and not a chatbot. It answers: which entities are compliant, which need attention, what evidence supports every finding, and what action the supervisor took.

> **Synthetic demonstration data.** The bundled dataset simulates SOC records for named organisations (ONGC, NTPC, IOCL, HAL, GAIL, BEL, BHEL, Mazagon Dock, …). It does **not** represent their actual cybersecurity posture, compliance status, or incidents.

## What it does

- **Explicit compliance model** — every entity gets `COMPLIANT / PARTIALLY_COMPLIANT / NON_COMPLIANT / INSUFFICIENT_EVIDENCE`, a compliance score, evidence coverage, and control-by-control calculations across 12 domains (Threat Detection → Cyber Resilience). Missing evidence is never treated as compliance.
- **Explainable risk scoring** — risk with named drivers (escalation failures, monitoring gaps, SLA breaches, data quality, peer deviation), not an opaque number.
- **Supervisory command overview** — 10 KPIs, deterministic executive summary, compliance distribution, severity mix, alert trends, sector comparison, risk-vs-compliance scatter, control performance, execution gaps, data-quality issues, workflow funnel, reporting coverage, and a ranked attention matrix with deterministic recommended actions.
- **Entity drill-down** — compliance, risk, funnel (Alert → Case → Investigation → Escalation → Response → Closure), execution gaps, peer radar, and evidence lineage down to source rows.
- **Evidence-first findings** — grouped by rule × entity with affected-record counts; every finding carries rule version, calculation, and source rows.
- **Actionable review queue + hash-chained audit trail** — every validate/reject/evidence-request/close action is an immutable audited event.
- **Professional reports** — JSON / HTML / PDF with scope, dataset hash, methodology, rule version, and limitations.

## Quickstart

Prerequisites: Python 3.12+, Node 20+.

```bash
# Backend (http://127.0.0.1:8000, docs at /docs)
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn app.main:app --app-dir backend

# Frontend (http://127.0.0.1:5173)
cd frontend && npm install && npm run dev

# Seed the 20-entity synthetic demo dataset (11.6k alerts, deterministic)
python -c "from backend.app.seed.generate_evidence import seed; seed(reset=True)"
```

Or `docker compose up --build`. Auth is disabled for the offline demo (`DEMO_AUTH_DISABLED=true`); production must set it to `false` with a strong `JWT_SECRET`.

## Demo data

`examples/sat_sa_demo_soc.csv` — 11,607 relational rows × 32 columns across 20 entities and 10 behavioural archetypes (strong compliance, escalation/investigation/response failures, monitoring gaps, data-quality issues, under-reporting, premature closure, mixed risk). Upload it via **Submissions** to replay the full demo, including deliberate edge cases (missing escalation, alert without case, conclusion-less investigation, duplicates, reporting gaps).

## API (base `/api/v1`)

| Area | Endpoints |
|---|---|
| Analytics | `analytics/overview`, `analytics/compliance`, `analytics/entities`, `analytics/entities/{id}`, `analytics/severity`, `analytics/sectors`, `analytics/workflow`, `analytics/execution-gaps`, `analytics/alerts`, `analytics/investigations`, `analytics/escalations`, `analytics/monitoring`, `analytics/data-quality`, `analytics/peer-benchmark`, `analytics/findings-grouped`, `analytics/finding-evidence/{id}` |
| Pipeline | `submissions` (JSON/CSV/XLSX/SQL/paste), `assessments`, `findings`, `findings/{id}/evidence`, `review-queue`, `audit-events` |
| Reports | `assessments/{id}/report`, `sat/report` (`?format=json\|html\|pdf`) |

## Tests

```bash
pytest -q backend/tests   # 56 tests: compliance maths, risk, funnel, data quality,
                          # duplicates, audit, CSV ingestion, grouping, reports
```

## Layout

```
backend/app/        FastAPI app: main.py (routes), analytics.py, compliance.py,
                    ingestion.py, scoring.py, taxonomy.py, seed/generate_evidence.py
frontend/src/       React + TypeScript: ui.tsx (charts/primitives), pages/
examples/           sat_sa_demo_soc.csv demo dataset
docs/sih/           SIH presentation and reference material
```

## Methodology (short)

Compliance score = weighted average of sufficiently evidenced controls (`COMPLIANT=100, PARTIAL=50, NON=0`; `INSUFFICIENT_EVIDENCE` excluded from the numerator but counted in coverage). Classification: evidence coverage < 50% → `INSUFFICIENT_EVIDENCE`; any unresolved critical finding → `NON_COMPLIANT`; score ≥ 85 → `COMPLIANT`; ≥ 60 → `PARTIALLY_COMPLIANT`. Data quality = `0.30·completeness + 0.25·validity + 0.20·consistency + 0.15·uniqueness + 0.10·timeliness`.
