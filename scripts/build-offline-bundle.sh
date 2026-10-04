#!/usr/bin/env bash
# Run on an internet-connected build host. Produces dist/sat-sa-offline-<ver>.tar.gz
# containing the container images, compose file and installer for an air-gapped host.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${SATSA_VERSION:-1.0}"
OUT="dist/sat-sa-offline-${VERSION}"
rm -rf "$OUT" && mkdir -p "$OUT"

SATSA_VERSION="$VERSION" docker compose build
IMAGES=("sat-sa/api:${VERSION}" "sat-sa/web:${VERSION}")
if [ "${WITH_POSTGRES:-false}" = "true" ]; then
  docker pull postgres:16-alpine
  IMAGES+=("postgres:16-alpine")
fi
docker save "${IMAGES[@]}" | gzip > "$OUT/images.tar.gz"

cp docker-compose.yml .env.example scripts/install-offline.sh "$OUT/"
cp -r examples "$OUT/"
(cd "$OUT" && sha256sum images.tar.gz docker-compose.yml install-offline.sh > SHA256SUMS)
tar -C dist -czf "dist/sat-sa-offline-${VERSION}.tar.gz" "sat-sa-offline-${VERSION}"
echo "Bundle: dist/sat-sa-offline-${VERSION}.tar.gz"
