#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
TARGET_DIR="${TARGET_DIR:-}"
SMOKE_ROOT="${SMOKE_ROOT:-.tmp_linux_release_acceptance}"
VENV_DIR="${VENV_DIR:-.venv-linux-acceptance}"

if [[ -z "$TARGET_DIR" ]]; then
  echo "TARGET_DIR is required. Example: TARGET_DIR=./src_pkg bash scripts/linux_release_acceptance.sh" >&2
  exit 2
fi

SRC_DIR="$TARGET_DIR"
STAGING_DIR="$SMOKE_ROOT/out/staging"
BUILD_DIR="$STAGING_DIR/build"
RELEASE_DIR="$SMOKE_ROOT/out/release"
OPS_DIR="$SMOKE_ROOT/ops"
SCOPE_FILE="$SMOKE_ROOT/scope.json"
APPROVAL_KEY_FILE="$OPS_DIR/release_approval.key"
TAMPER_DIR="$SMOKE_ROOT/tamper"

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
  exit 1
fi

if ! command -v gcc >/dev/null 2>&1; then
  echo "gcc not found. Install build-essential first." >&2
  exit 1
fi

if [[ ! -d "$SRC_DIR" ]]; then
  echo "TARGET_DIR is not a directory: $SRC_DIR" >&2
  exit 1
fi

ensure_safe_smoke_root "$SMOKE_ROOT"

echo "[1/9] Creating virtual environment: $VENV_DIR"
"$PYTHON_BIN" -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "[2/9] Installing Python dependencies"
python -m pip install -U pip wheel
python -m pip install pycryptodome setuptools Cython pytest

echo "[3/9] Preparing acceptance workspace: $SMOKE_ROOT"
rm -rf "$SMOKE_ROOT"
mkdir -p "$OPS_DIR" "$TAMPER_DIR"

cat > "$SCOPE_FILE" <<'JSON'
{}
JSON

APPROVAL_KEY_FILE="$APPROVAL_KEY_FILE" python - <<'PY'
import os
from pathlib import Path
Path(os.environ["APPROVAL_KEY_FILE"]).write_bytes(
    b"acceptance-approval-key-rotate-before-prod"
)
PY

echo "[4/9] Mainline pass: protect -> build -> verify -> package -> approve-release -> release"
python soenc.py protect -t "$SRC_DIR" -o "$STAGING_DIR" --scope-config "$SCOPE_FILE"
python soenc.py build --staging-dir "$STAGING_DIR" --build-profile auto
python soenc.py verify --staging-dir "$STAGING_DIR"
python soenc.py package --staging-dir "$STAGING_DIR" --dist-dir "$RELEASE_DIR"
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

echo "[5/9] Artifact presence checks"
test -f "$RELEASE_DIR/release_bundle.json"
test -f "$RELEASE_DIR/release_approval.json"
test -f "$RELEASE_DIR/release_receipt.json"
test -f "$STAGING_DIR/build_manifest.json"

echo "[6/9] Fail-closed test A: tampered release_approval.json must fail release gate"
cp "$RELEASE_DIR/release_approval.json" "$TAMPER_DIR/release_approval.json"
python - "$TAMPER_DIR/release_approval.json" <<'PY'
import json
import sys
from pathlib import Path
p = Path(sys.argv[1])
payload = json.loads(p.read_text(encoding="utf-8"))
approvers = list(payload.get("approvers") or [])
approvers.append("tampered-user")
payload["approvers"] = approvers
p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
PY

if python soenc.py release \
  --dist-dir "$RELEASE_DIR" \
  --require-release-approval \
  --release-approval-file "$TAMPER_DIR/release_approval.json" \
  --release-approval-key-file "$APPROVAL_KEY_FILE"
then
  echo "ERROR: tampered release_approval.json unexpectedly passed release gate" >&2
  exit 1
fi

echo "[7/9] Fail-closed test B: tampered runtime fingerprint in build_manifest.json must fail verify"
cp "$STAGING_DIR/build_manifest.json" "$TAMPER_DIR/build_manifest.json.bak"
python - "$STAGING_DIR/build_manifest.json" <<'PY'
import json
import sys
from pathlib import Path
p = Path(sys.argv[1])
payload = json.loads(p.read_text(encoding="utf-8"))
rt = payload.get("runtime_delivery")
if isinstance(rt, dict):
    fps = rt.get("compiled_runtime_fingerprints")
    if isinstance(fps, list) and fps and isinstance(fps[0], dict):
        fps[0]["digest_hex"] = "0" * 64
payload["runtime_delivery"] = rt
p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
PY

if python soenc.py verify --staging-dir "$STAGING_DIR"
then
  echo "ERROR: tampered build_manifest runtime fingerprint unexpectedly passed verify" >&2
  exit 1
fi
mv "$TAMPER_DIR/build_manifest.json.bak" "$STAGING_DIR/build_manifest.json"

echo "[8/9] Sanity: verify passes again after restoring manifest"
python soenc.py verify --staging-dir "$STAGING_DIR"

echo "[9/9] Acceptance checks passed"
echo "Release output: $ROOT_DIR/$RELEASE_DIR"
