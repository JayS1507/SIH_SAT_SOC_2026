# SOC-Inspect Run Guide

This file contains the exact commands to run the SIH26157 prototype.

## 1. Prerequisites

Required:

- Python 3.12 or newer.
- Node.js 20 or newer.
- npm.

Optional:

- Docker and Docker Compose.
- PostgreSQL.
- Redis.
- MinIO.

## 2. Run offline with local development servers

From the repository root:

### Backend

```bash
cd /home/master/SIH_SAT_SOC
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements.txt
backend/.venv/bin/uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

The backend will be available at:

```text
API:     http://localhost:8000
Docs:    http://localhost:8000/docs
Health:  http://localhost:8000/api/v1/health
Ready:   http://localhost:8000/api/v1/readiness
Metrics: http://localhost:8000/metrics
```

### Frontend

Open another terminal:

```bash
cd /home/master/SIH_SAT_SOC/frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The frontend uses `http://localhost:8000/api/v1` by default. To change it:

```bash
VITE_API_URL=http://localhost:8000/api/v1 npm run dev
```

## 3. Run with Docker Compose

From the repository root:

```bash
docker compose up --build
```

Open:

```text
Dashboard: http://localhost:5173
API docs:  http://localhost:8000/docs
Metrics:   http://localhost:8000/metrics
```

Stop the services:

```bash
docker compose down
```

Remove local Docker volumes as well:

```bash
docker compose down -v
```

## 4. Run the optional production service profile

This starts PostgreSQL, Redis, and MinIO in addition to the API and frontend:

```bash
docker compose --profile production up --build
```

The optional services use the development credentials declared in `docker-compose.yml`. Replace them before any real deployment.

Services:

```text
PostgreSQL: localhost:5432
Redis:      localhost:6379
MinIO API:  localhost:9000
MinIO UI:   localhost:9001
```

## 5. Run tests

Backend tests:

```bash
backend/.venv/bin/pytest -q backend/tests
```

Frontend production build:

```bash
cd frontend
npm run build
```

Validate Docker configuration:

```bash
docker compose config --quiet
docker compose --profile production config --quiet
```

## 6. Run Alembic migrations

The default offline database is SQLite:

```bash
cd backend
DATABASE_URL=sqlite:///./soc_inspect.db .venv/bin/alembic upgrade head
```

Rollback:

```bash
DATABASE_URL=sqlite:///./soc_inspect.db .venv/bin/alembic downgrade base
```

For PostgreSQL:

```bash
cd backend
DATABASE_URL=postgresql+psycopg://soc:password@localhost:5432/soc_inspect \
  .venv/bin/alembic upgrade head
```

## 7. Production authentication

### Demo mode

The default Docker demo disables authentication:

```env
DEMO_AUTH_DISABLED=true
```

### HS256 JWT mode

Set:

```env
DEMO_AUTH_DISABLED=false
JWT_SECRET=replace-with-a-long-random-secret
```

The JWT must contain one of:

```text
admin
supervisor
reviewer
auditor
data_provider
```

Example token generation in Python:

```python
import jwt
token = jwt.encode(
    {"sub": "supervisor-1", "roles": ["supervisor"]},
    "replace-with-a-long-random-secret",
    algorithm="HS256",
)
print(token)
```

Use the token:

```bash
curl -H "Authorization: Bearer <TOKEN>" \
  http://localhost:8000/api/v1/review-queue
```

### Keycloak/OIDC mode

Set:

```env
DEMO_AUTH_DISABLED=false
OIDC_ISSUER=https://keycloak.example/realms/soc
OIDC_AUDIENCE=soc-inspect
OIDC_JWKS_URL=https://keycloak.example/realms/soc/protocol/openid-connect/certs
```

The backend accepts roles from:

- `realm_access.roles`
- `resource_access.<client>.roles`

## 8. PostgreSQL, Redis, and MinIO configuration

```env
DATABASE_URL=postgresql+psycopg://soc:password@postgres:5432/soc_inspect
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/1
ARTIFACT_STORAGE=s3
S3_ENDPOINT_URL=http://minio:9000
S3_BUCKET=soc-inspect
AWS_ACCESS_KEY_ID=minio
AWS_SECRET_ACCESS_KEY=replace-me
```

Without Redis, assessments use the synchronous offline fallback. Without MinIO/S3 settings, artifacts use local immutable filesystem storage.

## 9. Upload a JSON submission

```bash
curl -X POST http://localhost:8000/api/v1/submissions \
  -H "Content-Type: application/json" \
  -d '{
    "name": "April SOC export",
    "source": "demo-provider",
    "metadata": {"schema_version": "1.0"},
    "records": [
      {
        "entity_id": "E-07",
        "asset_id": "critical-firewall-01",
        "alert_id": "A-1001",
        "type": "alert",
        "severity": "critical",
        "asset_criticality": "critical",
        "escalated": false,
        "status": "open",
        "timestamp": "2026-04-01T10:00:00Z"
      }
    ]
  }'
```

Save the returned `id` as `SUBMISSION_ID`.

## 10. Start an assessment

```bash
curl -X POST http://localhost:8000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d "{\"submission_id\":\"$SUBMISSION_ID\",\"requested_by\":\"demo-supervisor\"}"
```

Save the returned `id` as `ASSESSMENT_ID`.

## 11. Inspect findings and review queue

```bash
curl http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/status
curl http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/findings
curl http://localhost:8000/api/v1/review-queue
```

Evidence drill-down:

```bash
curl http://localhost:8000/api/v1/findings/<FINDING_ID>/evidence
```

## 12. Record a supervisor review

```bash
curl -X POST http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/review \
  -H "Content-Type: application/json" \
  -d '{
    "reviewer": "supervisor-1",
    "finding_id": "<FINDING_ID>",
    "decision": "accepted",
    "annotation": "Evidence selected for manual validation."
  }'
```

Audit events:

```bash
curl http://localhost:8000/api/v1/audit-events
```

## 13. Download reports

JSON:

```bash
curl -o report.json \
  "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/report?format=json"
```

HTML:

```bash
curl -o report.html \
  "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/report?format=html"
```

PDF:

```bash
curl -o report.pdf \
  "http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/report?format=pdf"
```

## 14. Troubleshooting

### Backend dependency error

Use the project virtual environment:

```bash
backend/.venv/bin/python -m pip install -r backend/requirements.txt
```

### Frontend cannot reach API

Confirm the backend is running:

```bash
curl http://localhost:8000/api/v1/health
```

Then set:

```bash
VITE_API_URL=http://localhost:8000/api/v1 npm run dev
```

### Authentication returns 401/403

For the demo:

```env
DEMO_AUTH_DISABLED=true
```

For production, verify the JWT secret, issuer, audience, and role claims.

### Database schema error

Run:

```bash
cd backend
.venv/bin/alembic upgrade head
```

### SQL upload rejected

Only restricted plain-text `INSERT INTO ... VALUES` and `COPY ... FROM STDIN` exports are accepted. Binary/custom `pg_dump` files and arbitrary SQL are intentionally rejected.

## 15. Shutdown and cleanup

Stop local processes with `Ctrl+C`.

For Docker:

```bash
docker compose down
```

Generated local runtime data such as SQLite databases and artifacts should not be committed.
