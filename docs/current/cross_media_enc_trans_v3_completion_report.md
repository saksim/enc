# Cross-media encrypted transport V0.3 completion report

> Source blueprint: `docs/current/cross_media_enc_trans_imple_guide_v3.md`  
> Gap mapping: `docs/current/cross_media_enc_trans_v3_gap_mapping.md`  
> Completion date: 2026-06-11  
> Status: complete for the V0.3 items tracked by the current implementation blueprint.

## 1. Outcome

The current V0.3 tracked backlog is closed.

```text
Remaining documented feature items: 0
Remaining documented hard blockers: 0
```

The final pass closed the last large/high-risk items without expanding beyond
the blueprint:

```text
P0-B2 strict native code-protection smoke
P1-A OCR candidate interface
P1-B manifestless OCR-safe sidecar verification
P2-B assistive-only visual model boundary
P1-E release artifact tamper report
```

## 2. Implemented capabilities

### P0-B2 strict native proof

The code-protection smoke now proves the complete path:

```text
original .py
  -> protected staging
  -> .so/.pyd native package
  -> clean import
  -> behavior match
```

Key entrypoint:

```text
scripts/smoke_code_protection.py
```

Recorded native-build interpreter:

```text
D:\code_environment\anaconda_all_css\py312\python.exe
```

The previous blocker was environment-specific. With the py312 interpreter,
`setuptools`, `Cython`, and `Crypto` are available; remaining native package
shape/path issues were addressed by staging-relative sources and explicit
`Extension("package.module", ...)` names.

### P1-A / P1-B OCR candidate and sidecar path

The OCR provider path now normalizes observations as untrusted candidates and
keeps verifier acceptance authoritative.

Key files:

```text
enc2sop/transport/ocr_observations.py
enc2sop/transport/ocr_runtime.py
qrcode_helper.py
```

The manifestless OCR-safe sidecar path remains recoverable through embedded
headers and parity/redundancy metadata without embedding secret material.

### P2-B assistive-only visual model boundary

The visual model capability is intentionally report-only.

User entrypoint:

```text
python soenc.py cm visual-assist --image-input <path> --output-report <path>
python soenc.py cm visual-assist --image-input <path> --provider-report <json> --output-report <path>
```

Key file:

```text
enc2sop/crossmedia/visual_assist.py
```

Allowed roles:

```text
locate_qr_regions
assess_photo_quality
ocr_candidate_generation
retake_suggestion
```

Forbidden roles fail closed when supplied by a provider report:

```text
guess_ciphertext
complete_crc_failed_payload
bypass_verifier
natural_language_crypto_validation
payload/ciphertext/plaintext/SOX1/key/decrypt/verifier override fields
```

Boundary:

```text
visual-assist output is not fed into QR reassembly, CRC acceptance, SOX1
decrypt, or tag verification.
```

### P1-E release artifact tamper report

SO/PYD release packages now get a narrow integrity report.

User entrypoint:

```text
python soenc.py release --dist-dir <dist_dir> ...
```

Primary artifact:

```text
release_tamper_report.json
```

Schema:

```text
enc2sop-release-tamper-report/v1
```

The report covers:

```text
manifest signature
binary digest
runtime digest
import-time check
failure report on release errors when possible
```

Boundary:

```text
release_tamper_report.json is anti-tamper / integrity hardening only.
It is not a strong secrecy boundary.
```

## 3. Explicit non-expansion boundaries

The completion pass did not add or change the following out-of-scope areas:

```text
SOX1 cryptographic envelope semantics
key/passphrase/private-key material handling
QR payload format
promotion/evidence platform expansion
remote-KMS
release governance workflow beyond the narrow tamper report
using OCR/LLM/visual output as verifier acceptance
```

The authoritative recovery/decrypt chain remains:

```text
QR/sidecar/OCR candidates
  -> parser/normalizer
  -> CRC/parity/verifier checks
  -> SOX1 authenticated decrypt
```

## 4. Recorded validation

The following validation evidence is recorded in the gap mapping for this
completion state:

```text
D:\code_environment\anaconda_all_css\py312\python.exe -B -c <ast syntax check>
syntax_ok

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_encryption_helper.py tests\test_soenc_cli.py tests\test_crossmedia_cli.py tests\test_crossmedia_visual_assist.py tests\test_ocr_observations.py tests\test_code_protection_smoke.py -q
105 passed, 2 skipped, 2 warnings

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_qrcode_helper_sidecar.py::TransportCoreTests::test_external_backend_uses_provider_command_interface tests\test_qrcode_helper_sidecar.py::TransportCoreTests::test_manifestless_ocr_safe_sidecar_with_parity_roundtrip tests\test_qrcode_helper_sidecar.py::SidecarRecoveryTests::test_recover_images_auto_prefers_sidecar_before_external tests\test_qrcode_helper_sidecar.py::SidecarRecoveryTests::test_recover_images_auto_prefers_external_before_generic_ocr -q
4 passed
```

## 5. Handoff checklist

For future work, treat this document and the gap mapping as the V0.3 handoff
state. New work should start from a new blueprint or an explicit amendment to
the current implementation blueprint.

Before changing this completed V0.3 scope, re-check:

```text
1. Is the request present in cross_media_enc_trans_imple_guide_v3.md?
2. Does it preserve visual/OCR assistive-only semantics?
3. Does it preserve release tamper reporting as integrity hardening only?
4. Does it avoid putting secrets into images, manifests, scan reports, logs,
   release artifacts, or OCR/LLM/provider output?
```
