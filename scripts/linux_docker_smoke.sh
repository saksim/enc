#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DOCKER_IMAGE="${DOCKER_IMAGE:-python:3.11-slim}"
DOCKER_PULL_POLICY="${DOCKER_PULL_POLICY:-never}"
CONTAINER_SMOKE_ROOT="${CONTAINER_SMOKE_ROOT:-.tmp_linux_smoke_docker}"
SKIP_APT_INSTALL="${SKIP_APT_INSTALL:-0}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not found. Install Docker first or use scripts/linux_local_smoke.sh on a Python-capable host." >&2
  exit 1
fi

case "$CONTAINER_SMOKE_ROOT" in
  ""|"/"|"."|".."|"/workspace")
    echo "Refusing unsafe CONTAINER_SMOKE_ROOT: $CONTAINER_SMOKE_ROOT" >&2
    exit 1
    ;;
esac

case "$DOCKER_PULL_POLICY" in
  never|missing|always) ;;
  *)
    echo "Invalid DOCKER_PULL_POLICY: $DOCKER_PULL_POLICY (expected never, missing, or always)" >&2
    exit 1
    ;;
esac

echo "[1/2] Running smoke test in Docker image: $DOCKER_IMAGE (pull policy: $DOCKER_PULL_POLICY)"
docker run --rm \
  --pull "$DOCKER_PULL_POLICY" \
  -v "$ROOT_DIR":/workspace \
  -w /workspace \
  -e SMOKE_ROOT="$CONTAINER_SMOKE_ROOT" \
  -e SKIP_APT_INSTALL="$SKIP_APT_INSTALL" \
  "$DOCKER_IMAGE" \
  bash -lc '
set -euo pipefail

SMOKE_ROOT="${SMOKE_ROOT:-.tmp_linux_smoke_docker}"
SRC_DIR="$SMOKE_ROOT/demo_src"
STAGING_DIR="$SMOKE_ROOT/out/staging"
RELEASE_DIR="$SMOKE_ROOT/out/release"
OPS_DIR="$SMOKE_ROOT/ops"
SCOPE_FILE="$SMOKE_ROOT/demo_scope.json"
APPROVAL_KEY_FILE="$OPS_DIR/release_approval.key"
SKIP_APT_INSTALL="${SKIP_APT_INSTALL:-0}"

mkdir -p "$SMOKE_ROOT"
RESOLVED_SMOKE_ROOT="$(cd "$SMOKE_ROOT" && pwd)"
if [[ "$RESOLVED_SMOKE_ROOT" == "/" || "$RESOLVED_SMOKE_ROOT" == "/workspace" ]]; then
  echo "Refusing unsafe SMOKE_ROOT: $SMOKE_ROOT" >&2
  exit 1
fi

echo "[container 1/7] Installing native and Python dependencies"
if [[ "$SKIP_APT_INSTALL" != "1" ]]; then
  apt-get update
  apt-get install -y --no-install-recommends build-essential
else
  echo "Skipping apt install because SKIP_APT_INSTALL=1"
fi
if ! command -v gcc >/dev/null 2>&1; then
  echo "gcc not found in container. Use an image with build-essential installed or run without SKIP_APT_INSTALL=1." >&2
  exit 1
fi
python -m pip install -U pip wheel
python -m pip install pycryptodome setuptools Cython pytest

echo "[container 2/7] Preparing smoke fixture: $SMOKE_ROOT"
rm -rf "$SMOKE_ROOT"
mkdir -p "$SRC_DIR" "$OPS_DIR"
cat > "$SRC_DIR/__init__.py" <<'"'"'PY'"'"'
def add(a, b):
    return a + b
PY
cat > "$SCOPE_FILE" <<'"'"'JSON'"'"'
{
  "rules": [
    {
      "pattern": "**/*.py",
      "action": "protect"
    }
  ]
}
JSON
APPROVAL_KEY_FILE="$APPROVAL_KEY_FILE" python - <<'"'"'PY'"'"'
import os
from pathlib import Path
Path(os.environ["APPROVAL_KEY_FILE"]).write_bytes(
    b"demo-local-approval-key-rotate-before-prod"
)
PY

echo "[container 3/7] Checking soenc CLI"
python soenc.py --help >/dev/null

echo "[container 4/7] Running protect -> build -> verify -> package"
python soenc.py protect -t "$SRC_DIR" -o "$STAGING_DIR" --scope-config "$SCOPE_FILE"
python soenc.py build --staging-dir "$STAGING_DIR" --build-profile auto
python soenc.py verify --staging-dir "$STAGING_DIR"
python soenc.py package --staging-dir "$STAGING_DIR" --dist-dir "$RELEASE_DIR"

echo "[container 5/7] Running approval and release gate"
python soenc.py approve-release \
  --dist-dir "$RELEASE_DIR" \
  --release-approval-key-file "$APPROVAL_KEY_FILE" \
  --approver ops-a \
  --approver security-b

python soenc.py release \
  --dist-dir "$RELEASE_DIR" \
  --require-release-approval \
  --release-approval-file "$RELEASE_DIR/release_approval.json" \
  --release-approval-key-file "$APPROVAL_KEY_FILE"

echo "[container 6/7] Checking expected release artifacts"
test -f "$RELEASE_DIR/release_bundle.json"
test -f "$RELEASE_DIR/release_approval.json"
test -f "$RELEASE_DIR/release_receipt.json"

echo "[container 7/7] Smoke test passed"
'

echo "[2/2] Docker smoke test passed"
echo "Release output: $ROOT_DIR/$CONTAINER_SMOKE_ROOT/out/release"
