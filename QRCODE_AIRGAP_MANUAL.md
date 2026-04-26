# QRCode Airgap Transport Manual

## 1. Goal

`qrcode_helper.py` is an **airgap transport layer**.

It only handles:

1. Exporting an already-encrypted small artifact to OCR-friendly package.
2. Extracting OCR text from image pages.
3. Analyzing OCR text quality before recover.
4. Verifying and recovering artifact content.

It does not perform source code encryption.

## 2. Protocol

Protocol version: `AT1`.

Core features:

1. `safe_base32` payload encoding.
2. Line-level `CRC16`.
3. Optional page-level CRC.
4. Binary `sidecar` per line for OCR-free structured recovery.
5. Redundant chunk copies with optional interleaving.
6. Package-level `SHA256`.
7. Optional PNG rendering for camera transfer.
7. Per-line machine-readable sidecar blocks for manifest-guided recovery.
8. `recover-images` / `ocr-extract --manifest` prefers sidecar decode before generic OCR.

Generated package structure:

```text
<output_dir>/
  <ARTIFACT_ID>.manifest.json
  <ARTIFACT_ID>.payload.txt
  pages/
    page_0001.png
    page_0002.png
    ...
  pages_txt/
    page_0001.txt
    page_0002.txt
    ...
```

## 2.1 Dependency Install (TUNA Mirror)

`pip` install (Python 3.11):

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pillow pytesseract easyocr
```

`pip` install (Python 3.6):

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple pillow pytesseract
```

Notes:

1. `easyocr` usually requires modern PyTorch and is recommended on Python 3.11.
2. New packages embed a binary `sidecar`, so `recover-images --backend auto` can recover even when OCR libraries are unavailable.
3. For sidecar-only recovery, `Pillow` is enough. `pytesseract` / `easyocr` are only needed for old packages without sidecar or for external OCR text workflows.
4. If `pytesseract` is missing but local `tesseract.exe` is available on `PATH`, the `tesseract` backend now calls the CLI directly.
5. When a manifest exists but `render_layout` metadata is missing, `tesseract` now falls back to manifest-guided line OCR (band detection + payload/CRC crops) instead of coarse full-page OCR.
6. If `Pillow` is unavailable on an older interpreter, `export` still emits `pages_txt/`, and `analyze` / `verify` / `recover` can still run against those text pages without image OCR.
7. In `auto` mode, execution stops as soon as one backend becomes recoverable.

## 3. Commands

### 3.1 Export

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py export `
  -i .\encrypted_payload.bin `
  -o .\airgap_pkg `
  --filename-prefix page `
  --redundancy-copies 2
```

Important options:

1. `--max-compressed-kib` default `64`.
2. `--chunk-chars` default `40`.
3. `--lines-per-page` default `20`.
4. `--artifact-id` optional custom id.
5. `--redundancy-copies` chunk copy count (default `1`).
6. `--no-interleave` disables copy interleaving (default interleave enabled).

### 3.2 OCR Extract

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py ocr-extract `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -i .\airgap_pkg\pages `
  -o .\airgap_pkg\ocr_raw.txt `
  --backend tesseract `
  --lang eng `
  --psm 6
```

Backend notes:

1. `sidecar` uses render metadata + binary sidecar and does not require OCR libraries.
2. `tesseract` works with either `pytesseract` or direct `tesseract.exe` CLI when sidecar is unavailable.
3. With `--manifest` but no `render_layout`, `tesseract` switches to manifest-guided line OCR and reconstructs lines from payload/CRC crops.
4. `easyocr` requires `easyocr` only when sidecar is unavailable.
5. When backend is `easyocr`, `--lang eng` is auto-mapped to `en`.
6. Multi-language input like `eng+chi_sim` is supported and mapped for EasyOCR.

Example sidecar-first extract:

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py ocr-extract `
  -i .\airgap_pkg\pages `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -o .\airgap_pkg\ocr_raw.txt `
  --backend sidecar
```
5. When `--manifest` points to self-generated pages, structured sidecar decode is attempted before OCR text recognition.

### 3.3 Analyze

`analyze` reports missing chunks and parse quality before recover.

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py analyze `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\ocr_raw.txt `
  --max-list 300 `
  --save-report .\airgap_pkg\analyze_report.json `
  --emit-missing-file .\airgap_pkg\missing_chunks.csv
```

Key output fields:

1. `missing_chunks_count` / `missing_chunks_sample`
2. `missing_chunk_locations_sample` (`chunk_index,page,line,copy,priority`)
3. `missing_chunk_retake_plan_sample` (one best retake point per missing chunk)
4. `line_error_count` / `line_errors_sample`
5. `line_warning_count` / `line_warnings_sample`
6. `page_crc_error_count` / `page_crc_errors`
7. `duplicate_conflict_count` / `duplicate_conflicts`

Behavior note:

1. `page_crc_error_count > 0` is treated as warning.
2. Recover still succeeds when all required unique chunks are present and checksums pass.

### 3.4 Verify

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py verify `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\ocr_raw.txt
```

### 3.5 Recover

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py recover `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\ocr_raw.txt `
  -o .\recovered_payload.bin
```

### 3.6 Recover Images (One Shot)

`recover-images` performs `ocr-extract -> analyze -> recover` in one command.

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py recover-images `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -i .\airgap_pkg\pages `
  -o .\recovered_payload.bin `
  --backend auto `
  --lang eng `
  --psm 6 `
  --ocr-text-output .\airgap_pkg\ocr_raw.txt `
  --save-analyze-report .\airgap_pkg\analyze_report.json `
  --emit-missing-file .\airgap_pkg\missing_chunks.csv
```

If OCR quality is not sufficient, command exits with non-zero and returns:

1. `analyze.report_path`
2. `analyze.missing_file_path`
3. counts for `missing_chunks`, `line_error`, `page_crc_error`
4. `backends_compared` with per-backend metrics and paths
5. `missing_chunk_retake_plan_sample` for fast re-capture

Backend selection note:

1. `recover-images --backend auto` tries `sidecar` first when the manifest contains binary sidecar metadata.
2. If sidecar is absent, it falls back to available OCR backends, including direct `tesseract.exe` CLI when present.
3. If you pass explicit `--ocr-text-output`, `--save-analyze-report`, or `--emit-missing-file`, the selected backend artifacts are copied to those exact paths; backend-suffixed filenames are only used internally while comparing auto candidates.

When manifest and self-generated pages are both available, `recover-images` first uses manifest-guided sidecar extraction, then falls back to manifest-guided line OCR / generic OCR only when sidecar data is unavailable or damaged.

## 4. Workflow

1. Build encrypted artifact in main chain.
2. `export` to generate pages and manifest.
3. Transfer image pages across airgap.
4. OCR to text (`ocr-extract`) or provide external OCR text.
5. `analyze` and inspect report.
6. `verify`.
7. `recover`.

If you want fewer manual steps, use `recover-images`.

## 4.1 Anti-Loss Recommendation

For camera/OCR transfer, recommended export settings:

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py export `
  -i .\encrypted_payload.bin `
  -o .\airgap_pkg `
  --redundancy-copies 2 `
  --parity-group-size 8 `
  --chunk-chars 40 `
  --lines-per-page 20
```

When `analyze` fails:

1. Use `missing_chunk_retake_plan_sample` first.
2. Re-capture listed `page,line` of `copy=1` first, then fallback copy.
3. Merge OCR text and rerun `analyze -> verify -> recover`.

## 5. OCR Normalization

Parser tolerance:

1. Lowercase OCR output.
2. Extra spaces/tabs/newlines.
3. Full-width separators and OCR-confused delimiters around `|`.
4. Limited alias mapping (`0/O -> Q`, `1/I -> L`) in non-strict mode.

Use `--strict-payload-chars` when you need strict parsing.

## 6. Limits

1. Designed for small artifacts.
2. Default compressed size limit is `64 KiB`.
3. If Pillow is unavailable, PNG pages are not generated.

## 7. Quick Smoke Test

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py export `
  -i .\encryption_helper.py -o .\_airgap_demo `
  --redundancy-copies 2

$manifest = (Get-ChildItem .\_airgap_demo\*.manifest.json | Select-Object -First 1).FullName

& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py analyze `
  -m $manifest -t .\_airgap_demo\pages_txt `
  --save-report .\_airgap_demo\report.json `
  --emit-missing-file .\_airgap_demo\missing_chunks.csv

& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py verify `
  -m $manifest -t .\_airgap_demo\pages_txt

& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py recover `
  -m $manifest -t .\_airgap_demo\pages_txt -o .\_airgap_demo\restored.bin
```

