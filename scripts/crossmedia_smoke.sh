#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd -P)"
if [[ -n "${SOENC_CM_SMOKE_WORK:-}" ]]; then
  WORK="$SOENC_CM_SMOKE_WORK"
else
  suffix="$(date -u +%Y%m%d%H%M%S)_$(python -c 'import uuid; print(uuid.uuid4().hex[:8])')"
  WORK="$ROOT/.tmp_crossmedia_smoke_${suffix}"
fi

case "$(python -c 'import os,sys; root=os.path.realpath(sys.argv[1]); work=os.path.realpath(sys.argv[2]); print("ok" if work == root or work.startswith(root + os.sep) else "bad")' "$ROOT" "$WORK")" in
  ok) ;;
  *) echo "refuse to operate outside workspace: $WORK" >&2; exit 30 ;;
esac

if [[ -n "${SOENC_CM_SMOKE_WORK:-}" && -e "$WORK" ]]; then
  rm -rf -- "$WORK"
fi
mkdir -p "$WORK"

KEY_FILE="$WORK/key.bin"
PLAIN_FILE="$WORK/plain.txt"
SEND_DIR="$WORK/send"
PHOTOS_DIR="$WORK/photos"
RECEIVE_DIR="$WORK/receive"
RESTORED_FILE="$WORK/restored.txt"

python soenc.py cm keygen --key-file "$KEY_FILE"
python -c 'from pathlib import Path; Path(__import__("sys").argv[1]).write_text("hello cross media encrypted transport", encoding="utf-8")' "$PLAIN_FILE"

python soenc.py cm send \
  --input "$PLAIN_FILE" \
  --key-file "$KEY_FILE" \
  --output-dir "$SEND_DIR" \
  --mode qr

python scripts/simulate_capture_distortions.py \
  --input "$SEND_DIR/pages" \
  --output "$PHOTOS_DIR" \
  --jpeg-quality 85 \
  --rotate-deg 1.0

python soenc.py cm receive \
  --image-input "$PHOTOS_DIR" \
  --key-file "$KEY_FILE" \
  --output "$RESTORED_FILE" \
  --work-dir "$RECEIVE_DIR"

python -c 'from pathlib import Path; import hashlib, sys; a=Path(sys.argv[1]).read_bytes(); b=Path(sys.argv[2]).read_bytes(); assert hashlib.sha256(a).digest()==hashlib.sha256(b).digest(); print("sha256=" + hashlib.sha256(a).hexdigest().upper())' "$PLAIN_FILE" "$RESTORED_FILE"
echo CROSSMEDIA_SMOKE_OK
