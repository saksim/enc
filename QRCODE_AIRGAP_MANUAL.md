# enc2sop Transport Plugin Manual

## 1. Scope

Airgap QR/OCR workflows are optional plugin capabilities.

They are not required for mainline `protect -> build -> package -> verify -> release`.

Plugin entrypoint:

```powershell
python .\soenc.py transport <subcommand> [args]
```

## 2. Recovery Priority (Auto Backend)

When `--backend auto` is used, recovery/extraction order is:

1. sidecar geometric decode
2. manifest-guided structured extraction
3. external OCR provider (`--ocr-provider-cmd`)
4. generic OCR fallback (`tesseract`, then `easyocr`)

This policy is deterministic and aligned with production baseline decisions.

## 3. Subcommands

Transport subcommands are provided by the optional plugin surface:

1. `export`
2. `estimate`
3. `ocr-extract`
4. `analyze`
5. `verify`
6. `recover`
7. `recover-images`

## 4. Quick Start

### 4.1 Export

```powershell
python .\soenc.py transport export -i .\artifact.bin -o .\airgap_pkg --filename-prefix page
```

### 4.2 Analyze and Verify

```powershell
$manifest = (Get-ChildItem .\airgap_pkg\*.manifest.json | Select-Object -First 1).FullName

python .\soenc.py transport analyze -m $manifest -t .\airgap_pkg\pages_txt
python .\soenc.py transport verify -m $manifest -t .\airgap_pkg\pages_txt
```

### 4.3 Recover

```powershell
python .\soenc.py transport recover -m $manifest -t .\airgap_pkg\pages_txt -o .\airgap_pkg\restored.bin
```

### 4.4 Recover From Images

```powershell
python .\soenc.py transport recover-images -m $manifest -i .\airgap_pkg\pages -o .\airgap_pkg\restored.bin --backend auto
```

## 5. Backend Notes

1. `sidecar` is preferred for self-exported pages.
2. `tesseract` and `easyocr` are optional OCR backends.
3. `external` backend allows custom OCR integration through command templates.
4. Mainline platform commands remain operational even when OCR stacks are absent.

## 6. Manifest-Less Recovery

Manifest-less flows are supported for embedded-metadata pages, but manifest-guided flows are preferred when available for stronger validation and diagnostics.

## 7. When To Use Transport

Use transport plugin only when you need airgap transfer or OCR-based recovery workflows. For core product delivery, use mainline `soenc protect/build/verify/package`.
