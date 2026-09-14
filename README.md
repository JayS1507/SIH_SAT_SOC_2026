# SOC-Inspect (SIH26157)

SOC-Inspect is an offline-first supervisory analytics prototype for assessing periodic SOC evidence. It helps supervisors identify execution gaps, missing evidence, abnormal operational patterns, and cases that deserve manual review. It is deliberately **not** a SIEM, real-time monitoring system, SOAR replacement, or autonomous decision-maker.

## Prototype vertical slice

The current slice provides:

- A typed FastAPI API for submissions, assessments, findings, review queue, and demo data.
- JSON database exports are accepted as arrays or common `records`/`rows`/`data`/`tables` shapes; CSV and XLSX remain supported. The offline adapter does not connect to PostgreSQL or ingest SQL dumps—export rows to JSON/CSV/XLSX first.
- Canonical alert/case/workflow records with source-row lineage.
- Deterministic, explainable rules for missing escalation, missing investigation evidence, escalation without response, invalid lifecycle order, and negative-space signals.
- Entity risk scoring and evidence-backed review prioritisation.
- A React/Vite supervisor dashboard that consumes the API.
- SQLAlchemy persistence with SQLite for the offline demo and PostgreSQL-compatible `DATABASE_URL` deployment.
- Core conformance analytics for repeated investigation templates, response-time outliers, weekly reporting gaps, asset/severity sufficiency, normalized peer deviation, and diversified review queues.

## Run locally

### Backend

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn app.main:app --reload --app-dir backend
```

The API is available at `http://localhost:8000`, interactive OpenAPI documentation at `/docs`, and demo overview at `/api/v1/demo/overview`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The frontend expects the backend at `http://localhost:8000`; set `VITE_API_URL` to override it.

### Tests

```bash
pytest -q backend/tests
```

### Offline Docker demo

```bash
docker compose up --build
```

Open `http://localhost:5173` for the supervisor dashboard and `http://localhost:8000/docs` for the API. The default compose setup remains self-contained and offline. Optional production dependencies are available with `docker compose --profile production up`.

Authentication is intentionally disabled for the demo (`DEMO_AUTH_DISABLED=true`).
Production deployments must set it to `false`, configure a strong `JWT_SECRET`,
and provide role-bearing HS256 Bearer tokens. Submissions and reports are
stored as immutable SHA-256 keyed artifacts on the local filesystem by default;
set the S3/MinIO variables documented in `backend/README.md` to use object
storage. Redis/Celery is optional; without it assessment execution falls back
to synchronous processing.

## Assessment invariants

1. Every finding must link to source evidence and a rule version.
2. Missing data is reported as insufficient evidence, never silently treated as compliant.
3. Analytics create review candidates; a supervisor makes the final decision.
4. The same submission can be reprocessed without duplicating records.
5. No raw sensitive case narrative is required by the prototype API.

## SIH26157 implementation boundary

The offline adapter accepts JSON/CSV/XLSX and restricted plain-text PostgreSQL
`INSERT`/`COPY` exports, while rejecting binary/custom dumps and arbitrary SQL.
Prometheus text metrics and Alembic migrations are included. Production
deployments still need external alert routing, dashboarding, and a managed
Keycloak realm configuration.
