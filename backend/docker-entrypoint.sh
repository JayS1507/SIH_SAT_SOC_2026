#!/bin/sh
# Container entrypoint: seed the deterministic demo dataset once, then serve.
set -e
mkdir -p "${ARTIFACT_LOCAL_DIR:-/data/artifacts}"
MARKER="${SEED_MARKER:-/data/.seeded}"
if [ "${SEED_DEMO:-true}" = "true" ] && [ ! -f "$MARKER" ]; then
  echo "Seeding 20-entity synthetic demo dataset (first start only, ~30s)..."
  python -m app.seed.generate_evidence --reset >/dev/null
  touch "$MARKER"
fi
# Single worker: assessment state is held in-process (backed by the database).
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'
