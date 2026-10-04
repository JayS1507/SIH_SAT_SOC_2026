#!/usr/bin/env bash
# Run on the air-gapped host inside the extracted bundle directory.
# Requires Docker Engine + Compose v2. No network access is used.
set -euo pipefail
cd "$(dirname "$0")"
sha256sum -c SHA256SUMS
gunzip -c images.tar.gz | docker load
[ -f .env ] || cp .env.example .env
# --no-build / --pull never: use only the images loaded above.
docker compose up -d --no-build --pull never
echo "SAT-SA starting (first start seeds demo data, ~1 min). Open http://<this-host>:<SATSA_PORT, default 8080>"
