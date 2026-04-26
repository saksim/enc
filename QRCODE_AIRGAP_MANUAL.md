# QRCode Airgap Transport Manual

## 1. What This Tool Does

`qrcode_helper.py` is not the source-code encryptor. It is the airgap transport layer.

It handles:

1. exporting an already-encrypted small artifact into image and text pages
2. extracting OCR text from images
3. analyzing OCR quality before recovery
4. verifying and recovering the original bytes

It does not handle:

1. source encryption
2. Cython compile

Those jobs belong to `encryption_helper.py` and `py2_linux_rec_opera.py`.

## 2. Core Features

Protocol version: `AT1`

Current transport features:

1. `safe_base32` payload encoding
2. line-level `CRC16`
3. optional page-level CRC
4. line-level binary `sidecar`
5. redundant data copies
6. optional parity chunks
7. package-level `SHA256`
8. `recover-images --backend auto` backend selection

## 3. Package Layout

Typical `export` output:

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

Meaning:

1. `manifest.json` is the recovery index
2. `pages/` is the image side of the transport
3. `pages_txt/` is ideal for local smoke tests

## 4. Dependencies and Backends

### Minimum dependency set

If you only need text-page recovery or image `sidecar` recovery, install:

```text
Python 3.6+
Pillow
```

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' -m pip install pillow
```

### OCR dependency set

If you need `tesseract` or `easyocr`:

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' -m pip install pillow pytesseract easyocr
& 'D:\code_environment\anaconda_all_css\py36\python.exe' -m pip install pillow pytesseract
```

### Backend priority

1. `sidecar`
   - most reliable
   - does not depend on OCR text recognition
   - best for self-generated pages
2. `tesseract`
   - works through `pytesseract`
   - can also call local `tesseract.exe`
3. `easyocr`
   - usually best on Python 3.11
4. `auto`
   - tries `sidecar`
   - then `tesseract`
   - then `easyocr`

## 5. Fastest Newcomer Loop

### 5.1 Real Python 3.6 transport loop

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\encryption_helper.py `
  -o .\_airgap_demo `
  --filename-prefix demo `
  --chunk-chars 24 `
  --lines-per-page 8 `
  --redundancy-copies 2 `
  --parity-group-size 4

$manifest = (Get-ChildItem .\_airgap_demo\*.manifest.json | Select-Object -First 1).FullName

& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py analyze `
  -m $manifest `
  -t .\_airgap_demo\pages_txt `
  --max-list 20 `
  --save-report .\_airgap_demo\analyze.json `
  --emit-missing-file .\_airgap_demo\missing.csv

& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py verify `
  -m $manifest `
  -t .\_airgap_demo\pages_txt

& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py recover `
  -m $manifest `
  -t .\_airgap_demo\pages_txt `
  -o .\_airgap_demo\restored.bin
```

### 5.2 If you have images instead of OCR text

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py recover-images `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -i .\airgap_pkg\pages `
  -o .\recovered_payload.bin `
  --backend auto `
  --ocr-text-output .\airgap_pkg\ocr_raw.txt `
  --save-analyze-report .\airgap_pkg\analyze_report.json `
  --emit-missing-file .\airgap_pkg\missing_chunks.csv
```

## 6. Command Reference

### 6.1 `export`

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py export `
  -i .\encrypted_payload.bin `
  -o .\airgap_pkg `
  --filename-prefix page `
  --redundancy-copies 2 `
  --parity-group-size 4
```

Key options:

1. `--max-compressed-kib`
2. `--chunk-chars`
3. `--lines-per-page`
4. `--redundancy-copies`
5. `--no-interleave`
6. `--parity-group-size`

### 6.2 `ocr-extract`

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py ocr-extract `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -i .\airgap_pkg\pages `
  -o .\airgap_pkg\ocr_raw.txt `
  --backend sidecar
```

### 6.3 `analyze`

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py analyze `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\ocr_raw.txt `
  --max-list 200 `
  --save-report .\airgap_pkg\analyze_report.json `
  --emit-missing-file .\airgap_pkg\missing_chunks.csv
```

### 6.4 `verify`

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py verify `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\ocr_raw.txt
```

### 6.5 `recover`

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py recover `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -t .\airgap_pkg\ocr_raw.txt `
  -o .\recovered_payload.bin
```

### 6.6 `recover-images`

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py recover-images `
  -m .\airgap_pkg\YOUR_ID.manifest.json `
  -i .\airgap_pkg\pages `
  -o .\recovered_payload.bin `
  --backend auto `
  --lang eng `
  --psm 6
```

## 7. How to Read `analyze`

The most important fields are:

1. `expected_total_chunks`
2. `received_unique_chunks`
3. `received_parity_chunks`
4. `missing_chunks_count`
5. `missing_chunk_locations_sample`
6. `missing_chunk_retake_plan_sample`
7. `line_error_count`
8. `line_warning_count`
9. `page_crc_error_count`
10. `duplicate_conflict_count`

Current counting rule:

1. `received_unique_chunks` counts data chunks only
2. `received_parity_chunks` counts parity chunks separately

This avoids the old false-positive case where parity made the package look complete even though data chunks were still missing.

## 8. What Counts as Success

Recovery is successful when:

1. no required data chunks are missing
2. no hard line parse errors remain
3. no duplicate conflicts remain
4. package-level verification passes

Notes:

1. `page_crc_error_count > 0` is a warning, not a hard failure
2. recovery can still succeed if all required chunks are present and checksums pass

## 9. Recommended Camera Settings

For camera-based transport, start with:

```powershell
& 'D:\code_environment\anaconda_all_css\py311\python.exe' .\qrcode_helper.py export `
  -i .\encrypted_payload.bin `
  -o .\airgap_pkg `
  --redundancy-copies 2 `
  --parity-group-size 8 `
  --chunk-chars 40 `
  --lines-per-page 20
```

If `analyze` fails:

1. check `missing_chunk_retake_plan_sample`
2. re-capture the suggested `page,line` for `copy=1` first
3. use fallback copies next
4. merge the new OCR text and rerun `analyze -> verify -> recover`

## 10. Verified Status

Verified on `2026-04-26`:

1. Python 3.6
   - `export -> analyze -> verify -> recover` passed
2. Python 3.11
   - `recover-images --backend auto` passed
   - `backend_selected=sidecar`
3. Current tests
   - `pytest`: `12 passed`
   - Python 3.6 `unittest`: `12` tests, `OK (skipped=7)`

## 11. Common Newcomer Questions

### 11.1 Can I recover without `easyocr`

Yes.

If the package was generated by this tool and the `sidecar` is intact:

1. `Pillow` is usually enough
2. `recover-images --backend auto` will prefer `sidecar`

### 11.2 What if I only have `pages_txt/`

Use:

1. `analyze`
2. `verify`
3. `recover`

directly on `pages_txt/`.

### 11.3 What should I inspect first when OCR quality is poor

Start with:

1. `missing_chunks_count`
2. `missing_chunk_retake_plan_sample`
3. `line_errors_sample`

Those fields tell you what to re-capture first.
