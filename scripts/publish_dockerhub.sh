#!/usr/bin/env bash
# Build & push anonymous-ready public image to Docker Hub.
# Usage:
#   ./scripts/publish_dockerhub.sh
#   DOCKERHUB_USER=yangye2 VERSION=1.0.0 ./scripts/publish_dockerhub.sh
set -euo pipefail
cd "$(dirname "$0")/.."

USER_NAME="${DOCKERHUB_USER:-yangye2}"
# Public Docker Hub repo name (NOT the private git repo name).
IMAGE_NAME="${DOCKERHUB_IMAGE:-grok-register-pro}"
VERSION="${VERSION:-1.2.24}"
LATEST_TAG="${USER_NAME}/${IMAGE_NAME}:latest"
VERSION_TAG="${USER_NAME}/${IMAGE_NAME}:${VERSION}"

echo "[publish] checking docker login..."
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon not available" >&2
  exit 1
fi
if ! docker buildx version >/dev/null 2>&1; then
  echo "[publish] buildx not required; using docker build"
fi

echo "[publish] privacy preflight..."
if [[ -f .env ]]; then
  echo "[publish] NOTE: .env exists locally but should be dockerignored"
fi
if [[ -d data || -d generated ]]; then
  echo "[publish] NOTE: data/generated exist locally but should be dockerignored"
fi

# Fail if dockerignore somehow missing critical rules
for must in '.env' 'data/' 'generated/'; do
  if ! grep -qxF "$must" .dockerignore && ! grep -qF "$must" .dockerignore; then
    echo "ERROR: .dockerignore missing $must" >&2
    exit 1
  fi
done

echo "[publish] building $VERSION_TAG (includes Camoufox browser; may take a while)..."
docker build \
  --pull \
  -t "$VERSION_TAG" \
  -t "$LATEST_TAG" \
  .

echo "[publish] quick image privacy smoke..."
docker run --rm "$LATEST_TAG" sh -c '
  set -e
  test ! -f /app/.env
  test ! -d /app/data
  test ! -d /app/generated
  test ! -f /app/generated/register_pro/register_pro.sqlite3
  # browser should be baked
  ls /opt/browser-cache/camoufox >/dev/null
  echo privacy_smoke_ok
'

echo "[publish] pushing..."
docker push "$VERSION_TAG"
docker push "$LATEST_TAG"

echo
echo "[publish] done"
echo "  $VERSION_TAG"
echo "  $LATEST_TAG"
echo
echo "Server test:"
echo "  docker pull $LATEST_TAG"
echo "  mkdir -p ./data/register_pro"
echo "  docker run -d --name grok-register-pro -p 8788:8788 --shm-size=1g \\"
echo "    -v \"\$PWD/data/register_pro:/data\" \\"
echo "    -e GROK_REGISTER_ADMIN_BOOTSTRAP_PASSWORD='改成强密码' \\"
echo "    $LATEST_TAG"
