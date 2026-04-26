# 6_so_enc

## What This Repo Does

This repo has two jobs:

1. Protect Python source files by turning them into encrypted staging `.py` files, then batch-compile them into `.pyd` or `.so`.
2. Transport small encrypted artifacts across an airgap with QR-style pages, OCR text, image sidecars, and recovery tools.

If you are new here, read this file first, then jump into the detailed manual you need.

## Main Files

| File | Role | Use it when |
| --- | --- | --- |
| `encryption_helper.py` | Main entry for source protection and staging output | You want to protect Python code |
| `decryption_helper.py` | Runtime decrypt template injected by the protector | Usually not called directly |
| `py2_linux_rec_opera.py` | Batch Cython compiler for staging trees | You want `.pyd` or `.so` deliverables |
| `qrcode_helper.py` | Airgap transport tool with `export / analyze / verify / recover` | You want OCR or image-based transfer |

## Fastest Newcomer Path

### Path A: Source protection and compile flow

Read [USAGE_MANUAL.md](/D:/Download/gaming/new_program/data_helper/6_so_enc/USAGE_MANUAL.md).

Remember these rules:

1. In directory mode, use `--scope-config`.
2. `--output-dir` must stay outside `--target`.
3. On Windows, pass `--python-exe` explicitly.
4. Source files and `scope.json` now accept both `UTF-8` and `UTF-8 BOM`.

### Path B: OCR and airgap transport flow

Read [QRCODE_AIRGAP_MANUAL.md](/D:/Download/gaming/new_program/data_helper/6_so_enc/QRCODE_AIRGAP_MANUAL.md).

The shortest closed loop is:

1. `export`
2. `analyze`
3. `verify`
4. `recover`

If you only have images, use `recover-images --backend auto`.

## Five-Minute Smoke Test

### Show the CLI help

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\encryption_helper.py --help
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py --help
```

### Run a minimal OCR transport smoke test

```powershell
& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py export `
  -i .\encryption_helper.py `
  -o .\_airgap_demo `
  --filename-prefix demo `
  --redundancy-copies 2 `
  --parity-group-size 4

$manifest = (Get-ChildItem .\_airgap_demo\*.manifest.json | Select-Object -First 1).FullName

& 'D:\code_environment\anaconda_all_css\py36\python.exe' .\qrcode_helper.py analyze `
  -m $manifest `
  -t .\_airgap_demo\pages_txt `
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

## Verified Status

Verified on `2026-04-26`:

1. Python 3.6
   - `qrcode_helper.py`: `export -> analyze -> verify -> recover`
   - `encryption_helper.py`: directory mode + `scope.json` + `--compile` + `--dist-dir`
   - `UTF-8 BOM` source files and `scope.json` are accepted
2. Python 3.11
   - `pytest`: `12 passed`
   - `qrcode_helper.py recover-images --backend auto` selected `sidecar`

## Documentation Map

1. [USAGE_MANUAL.md](/D:/Download/gaming/new_program/data_helper/6_so_enc/USAGE_MANUAL.md)
   - Source protection and compile flow
   - `encryption_helper.py`, `scope.json`, `py2_linux_rec_opera.py`
2. [QRCODE_AIRGAP_MANUAL.md](/D:/Download/gaming/new_program/data_helper/6_so_enc/QRCODE_AIRGAP_MANUAL.md)
   - OCR and image transport flow
   - `export / analyze / verify / recover / recover-images`

## Common Newcomer Pitfalls

1. The default `--python-exe` in `encryption_helper.py` is machine-specific. Do not trust it on a new machine.
2. `py2_linux_rec_opera.py` contains hard-coded Windows MSVC and SDK paths. Check them before your first compile.
3. `sidecar` is more reliable than plain OCR. Prefer it whenever the package supports it.
4. `received_unique_chunks` counts data chunks only. Extra parity chunks are now reported separately as `received_parity_chunks`.

## Recommended Handoff Order

1. Run `--help`.
2. Run a small smoke test.
3. Learn the protection flow from [USAGE_MANUAL.md](/D:/Download/gaming/new_program/data_helper/6_so_enc/USAGE_MANUAL.md).
4. Learn the OCR flow from [QRCODE_AIRGAP_MANUAL.md](/D:/Download/gaming/new_program/data_helper/6_so_enc/QRCODE_AIRGAP_MANUAL.md).
