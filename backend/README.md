# SIH26157 SOC-Inspect backend

Runnable FastAPI prototype with SQLAlchemy-backed canonical records, deterministic SOC execution-gap rules, data-quality checks, risk scoring, evidence lineage, and a review queue.

SQLite is used by default for an offline demo (`sqlite:///./soc_inspect.db`). Set
`DATABASE_URL` to a PostgreSQL SQLAlchemy URL for deployment; the table layout is
kept migration-ready.

The demo defaults to `DEMO_AUTH_DISABLED=true`. For production set it to
`false`, provide a strong `JWT_SECRET`, and send an HS256 Bearer JWT with one of
the roles `supervisor`, `reviewer`, `auditor`, `admin`, or `data_provider`.
Alternatively configure `OIDC_ISSUER` (a Keycloak issuer URL) and optionally
`OIDC_JWKS_URL`/`OIDC_AUDIENCE` to validate RS256 OIDC tokens. Keycloak
`realm_access.roles` and `resource_access.*.roles` are supported.
Artifacts use immutable SHA-256 keys under `ARTIFACT_LOCAL_DIR` by default.
Set `ARTIFACT_STORAGE=s3` (or `minio`), `S3_BUCKET`, and normal boto3
credentials; `S3_ENDPOINT_URL` enables MinIO. `CELERY_BROKER_URL` enables the
optional task boundary; without a reachable broker assessments run
synchronously for the offline demo.

`/api/v1/readiness` verifies database connectivity. Every response includes an
`X-Request-ID` correlation ID (or echoes the supplied one).

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Interactive API docs are available at `/docs`. A synthetic submission is loaded at startup; use its ID from the application state or create a submission with `POST /api/v1/submissions`.

JSON submission:
```json
{"name":"April export","source":"siem","records":[{"entity_id":"alice","alert_id":"a1","severity":"critical","escalated":false,"timestamp":"2026-01-01T00:00:00Z"}]}
```

JSON, CSV, XLSX, and restricted plain-text PostgreSQL `.sql`/`.dump` exports
are accepted as multipart field `file`. SQL files may contain only `INSERT INTO
... VALUES` rows or `COPY ... FROM STDIN` CSV blocks. DDL, binary/custom
`pg_dump` formats, functions, expressions, and arbitrary SQL execution are
rejected. Uploads accept files of any size, and each normalized record includes its
source row number as `_row`. Run tests from the repository root with `pytest`.

`/metrics` exposes dependency-free Prometheus text metrics for request totals,
5xx errors, request latency summaries, and assessment pipeline stages.

Alembic commands (`cd backend && alembic upgrade head` or `alembic downgrade
base`) are provided for PostgreSQL and SQLite deployments. The application
continues to use SQLite and `create_all` by default for the offline demo.
