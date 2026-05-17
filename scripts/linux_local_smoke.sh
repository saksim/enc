#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
SMOKE_ROOT="${SMOKE_ROOT:-.tmp_linux_smoke_local}"
VENV_DIR="${VENV_DIR:-.venv-linux-smoke}"

SRC_DIR="$SMOKE_ROOT/demo_src"
STAGING_DIR="$SMOKE_ROOT/out/staging"
RELEASE_DIR="$SMOKE_ROOT/out/release"
OPS_DIR="$SMOKE_ROOT/ops"
SCOPE_FILE="$SMOKE_ROOT/demo_scope.json"
APPROVAL_KEY_FILE="$OPS_DIR/release_approval.key"

ensure_safe_smoke_root() {
  local path="$1"
  local resolved
  mkdir -p "$path"
  resolved="$(cd "$path" && pwd)"
  if [[ "$resolved" == "/" || "$resolved" == "$ROOT_DIR" ]]; then
    echo "Refusing unsafe SMOKE_ROOT: $path" >&2
    exit 1
  fi
}

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python executable not found: $PYTHON_BIN" >&2
  echo "Install Python first, for example: sudo apt install -y python3 python3-venv python3-dev build-essential" >&2
  exit 1
fi

if ! command -v gcc >/dev/null 2>&1; then
  echo "gcc not found. Install a native build toolchain first, for example: sudo apt install -y build-essential" >&2
  exit 1
fi

ensure_safe_smoke_root "$SMOKE_ROOT"

echo "[1/8] Creating virtual environment: $VENV_DIR"
"$PYTHON_BIN" -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "[2/8] Installing Python dependencies"
python -m pip install -U pip wheel
python -m pip install pycryptodome setuptools Cython pytest

echo "[3/8] Preparing smoke fixture: $SMOKE_ROOT"
rm -rf "$SMOKE_ROOT"
mkdir -p "$SRC_DIR" "$OPS_DIR"
cat > "$SRC_DIR/__init__.py" <<'PY'
def add(a, b):
    return a + b
PY
cat > "$SCOPE_FILE" <<'JSON'
{
  "rules": [
    {
      "pattern": "**/*.py",
      "action": "protect"
    }
  ]
}
JSON
APPROVAL_KEY_FILE="$APPROVAL_KEY_FILE" python - <<'PY'
import os
from pathlib import Path
Path(os.environ["APPROVAL_KEY_FILE"]).write_bytes(
    b"demo-local-approval-key-rotate-before-prod"
)
PY

echo "[4/8] Checking soenc CLI"
python soenc.py --help >/dev/null

echo "[5/8] Running protect -> build -> verify -> package"
python soenc.py protect -t "$SRC_DIR" -o "$STAGING_DIR" --scope-config "$SCOPE_FILE"
python soenc.py build --staging-dir "$STAGING_DIR" --build-profile auto
python soenc.py verify --staging-dir "$STAGING_DIR"
python soenc.py package --staging-dir "$STAGING_DIR" --dist-dir "$RELEASE_DIR"

echo "[6/8] Running approval and release gate"
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

echo "[7/8] Checking expected release artifacts"
test -f "$RELEASE_DIR/release_bundle.json"
test -f "$RELEASE_DIR/release_approval.json"
test -f "$RELEASE_DIR/release_receipt.json"

echo "[8/8] Smoke test passed"
echo "Release output: $ROOT_DIR/$RELEASE_DIR"
