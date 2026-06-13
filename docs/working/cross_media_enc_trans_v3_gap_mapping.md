# Cross-media V0.3 gap mapping

> Source blueprint: `docs/working/cross_media_enc_trans_imple_guide_v3.md`
> Completion report: `docs/working/cross_media_enc_trans_v3_completion_report.md`
> Completion status: remaining documented feature items = 0; remaining documented hard blockers = 0.
> Mapping date: 2026-06-11
> Current pass update: P0-B2 strict native proof, P1-A OCR candidate interface, P2-B assistive-only visual model boundary, and P1-E release artifact tamper report.
> This pass touched Code Protection/native build, OCR provider candidate handling, visual-assist reporting, and release package integrity reports; SOX1 crypto, key material, QR payload format, and release/promotion/evidence platform expansion remain out of scope.

## 1. Current state summary

The repository already has a working cross-media product path under
`enc2sop/crossmedia/`:

```text
bytes
  -> SOX1 encrypted string
  -> QR pages/photos
  -> recovered SOX1
  -> decrypted bytes
```

The V0.3 blueprint is still valid, but its phase order must be interpreted
against the current codebase: most P0-A items are already implemented, and
P0-B strict native-build proof now passes on the user-specified py312
interpreter, and P1-A/P1-B transport enhancements are now verified against
the current OCR/sidecar implementation.

## 2. V0.3 phase mapping

| V0.3 item | Current evidence | Status | Next action |
|---|---|---:|---|
| P0-A0 CLI decoupling | `soenc.py cm --help` delegates lazily through `enc2sop.cli._run_cross_media`; `soenc.py transport --help` uses legacy plugin surface. | Mostly done | Keep protected/build deps out of `cm` and `transport` startup. |
| P0-A1 SOX1 envelope | `enc2sop/crossmedia/crypto_envelope.py` | Done | No change in this pass. |
| P0-A2 QR-first render/scan | `enc2sop/crossmedia/qr_transport.py`, `enc2sop/crossmedia/image_scan.py` | Done | No change in this pass. |
| P0-A3 send/receive | `enc2sop/crossmedia/cli.py` exposes `send` and `receive`. | Done | No change in this pass. |
| P0-A4 scan report / retake plan | Existing QR reassembly and receive reports include missing/bad image diagnostics. | Done enough for current pass | No change in this pass. |
| P0-A5 no-secret-leakage | Covered by existing cross-media tests and manifest/report fields. | Mostly done | Dedicated no-secret-leakage test file can be added later if desired. |
| P0-A6 crossmedia smoke | `scripts/crossmedia_smoke.ps1`, `scripts/crossmedia_smoke.sh`, simulated capture script. | Done | Linux/macOS real shell execution remains environment validation. |
| P0-B0 Code Protection Layer registration | `encryption_helper.py`, `decryption_helper.py`, `py2_linux_rec_opera.py` now have explicit V0.3 Code Protection Layer boundary comments. | Done | Keep responsibilities documented separately from QR/OCR/SOX1. |
| P0-B1 protect/build and cm/transport decoupling | `cm` and `transport` help paths stay decoupled from code-protection heavy imports; covered by CLI regression tests. | Done | Keep config/toolchain imports behind protect/build handlers. |
| P0-B2 code-protection smoke | `scripts/smoke_code_protection.py` creates `demo_module.py`, runs `soenc.py protect`, probes native deps, runs `soenc.py build`, then imports native artifacts from a clean directory. Verified with `D:\code_environment\anaconda_all_css\py312\python.exe`. | Done | Keep Cython sources staging-relative and module names explicit so package-shaped `.pyd/.so` outputs remain importable. |
| P0-B3 dist no-source-leakage | `enc2sop/protect/dist_check.py`, `scripts/check_dist_no_source_leak.py`, and `copy_release` now reject `.py` source leaks, generated `.c/.pyx`, temp build/cache dirs, and forbidden source/secret tokens. | Done | Keep default allow-list limited to `__init__.py`; add explicit `--allow-py` only for known bootstrap files. |
| P0-B4 local-embedded insecure marker | `encryption_helper.py` now requires `--dev-insecure-ok` for local-embedded, emits a warning, and marks manifests as `local-embedded-dev-insecure` while preserving runtime provider compatibility. | Done | Do not use this mode for strong secrecy; keep license/remote modes separate. |
| P0-B5 license-file externalization | `license-file` now defaults to external runtime delivery via `SOENC_LICENSE_FILE`; `copy_release` does not place license JSON in `dist_native` unless `--bundle-license` is explicit, and bundled delivery emits an insecure warning. Optional machine binding, HMAC license signing, and revocation-list checks are wired into the license runtime path. | Done | Keep default externalized; use `--bundle-license` only for explicit demo/lab bundles. |
| P0-B6 runtime integrity smoke | `scripts/smoke_runtime_integrity.py` exercises the generated native-loader preamble without requiring a native compiler; it proves happy path plus fail-closed behavior for runtime replacement, manifest path tampering, and digest mismatch. | Done | Keep described as hardening only, not strong secrecy. |
| P1-D license-file device binding | `license-file` now carries `subject`, `expires_at`, `allowed_module_hashes`, `machine_binding`, `key_envelope`, `signature`, and revocation metadata. Runtime enforces machine binding, signature when required, revocation list, and expiration. | Done for license runtime hardening | `allowed_module_hashes` is signed metadata, not a strong module anti-tamper boundary. |

## 3. P0-B0 Code Protection Layer registration

The Code Protection Layer is defined as:

```text
encryption_helper.py
  Owns source selection, snippet encryption, protected staging generation,
  build manifests, and package/release integrity helpers.

decryption_helper.py
  Owns protected-module runtime payload decryption, compile/exec injection,
  license-file lookup, and runtime integrity checks.

py2_linux_rec_opera.py
  Owns Cython/native packaging of protected staging into .so/.pyd artifacts.
```

Non-goals and boundaries:

```text
These files are not OCR/QR scanners.
These files are not SOX1 cross-media recovery.
These files do not replace SOX1 data encryption.
Cython/.so/.pyd raises reverse-engineering cost only and is not absolute secrecy.
cm/transport help and startup must not import these files.
```

## 4. P0-B1 dependency boundary

Allowed import direction:

```text
protect/build/package/verify/release -> encryption_helper/decryption_helper/py2_linux_rec_opera/toolchain_profile
cm/send/receive/help                 -> enc2sop.crossmedia only
transport/help                       -> plugin registry only
transport subcommands                -> legacy transport plugin when actually invoked
```

Forbidden for help/startup:

```text
soenc cm --help must not import encryption_helper, decryption_helper, py2_linux_rec_opera, or promotion modules.
soenc transport --help must not import encryption_helper, decryption_helper, py2_linux_rec_opera, Cython, or native build helpers.
```

## 5. P0-B2 smoke contract

`scripts/smoke_code_protection.py` is the V0.3 Code Protection Layer smoke entry:

```text
original .py -> protected staging -> .so/.pyd -> clean import -> behavior match
```

The smoke intentionally has two modes:

```text
strict mode:
  python scripts/smoke_code_protection.py
  returns non-zero if native packaging cannot be proven

evidence mode for non-build hosts:
  python scripts/smoke_code_protection.py --allow-blocked
  returns zero only to record a BLOCKED diagnostic report
```

Current host evidence on 2026-06-10:

```text
interpreter: D:\code_environment\anaconda_all_css\py312\python.exe
protect step: passed
native dependency probe: passed
setuptools: 80.9.0
Cython: 0.29.36
Crypto: 3.20.0
native build: passed
native outputs: demo_pkg/demo_module.pyd, demo_pkg/enc_rt_root_*.pyd
clean import observed: {"add": 5, "scale": 42}
```

The earlier blocker was specific to the previous/default Python environment.
With py312 available, the remaining failure was Windows path-length/package
shape in native build: absolute source paths caused long `build/temp/...`
paths and flat `.pyd` outputs. `py2_linux_rec_opera.py` now compiles
staging-relative sources through explicit `Extension("package.module", ...)`
objects, which preserves package-shaped native artifacts and short temp paths.

The script does not modify QR/OCR/SOX1 behavior and does not add release,
promotion, or evidence-platform capability.

## 6. Next recommended pass

P0-B2 is now verified with the prepared py312 native-build interpreter:

```text
D:\code_environment\anaconda_all_css\py312\python.exe scripts\smoke_code_protection.py --python-exe D:\code_environment\anaconda_all_css\py312\python.exe --keep-work
CODE_PROTECTION_SMOKE_OK
```

With P0-B2/B3/B4/B5/B6 implemented, the remaining P0-B item count is:

```text
0
```

After the P1-A/P1-B verification pass, P2-B visual-assist boundary work, and
P1-E release tamper report work, the remaining P1/P2 enhancement
items are:

```text
0
```

P2-B must remain assistive only: locate QR regions, assess blur/glare/crop,
assist candidate generation, and generate retake suggestions. It must not guess
ciphertext or bypass verifier checks. P1-E must stay a narrow anti-tamper
report and must not expand into release/promotion/evidence platform governance.

## 7. P0-B3/B4 current pass evidence

Implemented P0-B3:

```text
enc2sop/protect/dist_check.py
scripts/check_dist_no_source_leak.py
copy_release(...) fail-closed hook after release bundle metadata is written
```

Implemented P0-B4:

```text
keys.mode=local-embedded requires --dev-insecure-ok
manifest key_management.mode = local-embedded-dev-insecure
manifest key_management.provider_mode = local-embedded
stderr warning explains dev/demo/anti-casual boundary
```

This pass still does not modify QR/OCR/SOX1 behavior and does not implement
remote-kms or promotion/evidence platform expansion.

## 8. P0-B5 current pass evidence

Implemented P0-B5:

```text
enc2sop/keys/license.py
  license_path_policy defaults to env-only
  runtime_env = SOENC_LICENSE_FILE
  optional machine binding = SOENC_MACHINE_FINGERPRINT
  optional HMAC signature verification = SOENC_LICENSE_VERIFY_KEY_B64
  optional revocation list = SOENC_LICENSE_REVOCATION_FILE

decryption_helper.py
  env-only license lookup fails closed when SOENC_LICENSE_FILE is absent
  bundled-relative fallback is only allowed when key_ref records that policy
  signed, machine-bound, and revoked licenses fail closed at runtime

encryption_helper.py / enc2sop/cli.py
  package/copy_release defaults to externalized license sidecar
  --bundle-license is explicit and emits an insecure warning
  release bundle metadata distinguishes external vs bundled license delivery
```

Validation executed:

```text
python -m pytest tests/test_key_provider.py tests/test_soenc_config.py tests/test_soenc_cli.py tests/test_encryption_helper.py -q
95 passed, 6 skipped
```

Scope check:

```text
QR/OCR/SOX1 main path unchanged.
Release/promotion/evidence surfaces were not expanded; existing package/receipt
license-sidecar validation was narrowed to represent externalized license
delivery correctly.
```

## 9. P0-B6 current pass evidence

Implemented P0-B6:

```text
scripts/smoke_runtime_integrity.py
  Uses encryption_helper.render_module_preamble(..., require_native_runtime_loader=True)
  Stubs a runtime module whose __file__ points at synthetic .pyd artifacts
  Exercises the same generated import-time guard without requiring local Cython/native build

tests/test_runtime_integrity_smoke.py
  Runs the smoke as a subprocess and asserts all fail-closed checks are present
```

Covered failure branches:

```text
runtime replaced:
  runtime module __file__ points outside the expected package directory
  expected failure: runtime module path escaped expected package directory

manifest tampered:
  manifest compiled_relative_path no longer matches actual runtime artifact path
  expected failure: runtime fingerprint path mismatch

digest mismatch:
  manifest digest_hex differs from the runtime artifact SHA256
  expected failure: runtime fingerprint mismatch
```

Validation executed:

```text
python scripts/smoke_runtime_integrity.py
RUNTIME_INTEGRITY_SMOKE_PASSED

python -m pytest tests/test_runtime_integrity_smoke.py -q
1 passed
```

Boundary statement:

```text
This is runtime hardening evidence only.
It is not documented as strong secrecy.
It does not modify QR/OCR/SOX1 behavior.
```

## 10. P1-D current pass evidence

Implemented the remaining license-file device-binding fields and runtime
checks that do not touch QR/OCR/SOX1:

```text
enc2sop/keys/license.py
  subject
  expires_at
  allowed_module_hashes
  machine_binding / machine_fingerprint hash
  key_envelope metadata
  signature metadata

decryption_helper.py
  expires_at is parsed as ISO-8601
  expired license files fail closed with "license has expired"
  generated runtime_py/runtime_pyx sources carry the same expiration check

encryption_helper.py / soenc_config.py
  --license-subject
  --license-expires-at
  --license-allowed-module-hash
  [keys].license_subject
  [keys].license_expires_at
  [keys].license_allowed_module_hashes
```

Validation executed:

```text
python -m pytest tests/test_key_provider.py tests/test_soenc_config.py tests/test_encryption_helper.py -q
63 passed, 5 skipped
```

Scope note:

```text
allowed_module_hashes is recorded as signed license metadata in this pass.
It is not claimed as strong module anti-tamper enforcement.
Release/promotion/evidence and QR/OCR/SOX1 paths remain untouched.
```

## 11. P2-A current pass evidence

Implemented the project-side remote-KMS runtime client without touching
QR/OCR/SOX1 or release/promotion/evidence surfaces:

```text
decryption_helper.py
  _remote_kms_unwrap_key(key_ref)
  validates endpoint/token/request/response schema before unwrap
  sends HTTP JSON POST with bearer token from key_ref.request.token_env
  accepts response schema enc2sop-kms-response/v1 with plaintext_key_b64
  verifies returned plaintext key against wrapped_key.fingerprint_sha256
  retries retryable HTTP statuses 408/429/500/502/503/504 per retry_policy
  fails closed on HTTP/network/JSON/schema/fingerprint/token errors
  generated runtime_py/runtime_pyx sources carry the same client code

enc2sop/keys/remote_kms.py
  requires an explicit http(s) kms_endpoint for keys.mode=remote-kms
  keeps resolve_key() local path disabled
  removes kms_stub manifest marker
  records kms_runtime_client implemented=true, protocol=http-json-unwrap-v1
  records server-side requirements for identity auth, audit logging, revocation, and rate limiting
```

Validation executed:

```text
python -m pytest tests/test_key_provider.py -q
15 passed

python -m pytest tests/test_encryption_helper.py::EncryptionHelperTests::test_remote_kms_mode_emits_key_contract_and_runtime_fails_closed_without_token tests/test_encryption_helper.py::EncryptionHelperTests::test_remote_kms_cli_args_require_remote_kms_mode -q
2 passed

python -m pytest tests/test_key_provider.py tests/test_soenc_config.py tests/test_encryption_helper.py -q
70 passed, 5 skipped

python -m pytest tests/test_runtime_integrity_smoke.py tests/test_key_provider.py tests/test_soenc_config.py tests/test_encryption_helper.py -q
71 passed, 5 skipped

python soenc.py protect --help
python soenc.py cm --help
both help commands completed successfully
```

Boundary statement:

```text
P2-A here is the runtime/client-side implementation and manifest contract.
The KMS server itself must enforce identity authentication, audit logging,
revocation, and rate limiting behind the configured endpoint.
The runtime never falls back to local-embedded when remote-kms fails.
```


## 12. P2-C current pass plan/evidence

Implemented the non-QR/non-OCR Code Protection hardening baseline:

```text
enc2sop/protect/hardening.py
  hardening_profile = off | balanced
  balanced Cython directives: binding=false, embedsignature=false, emit_code_comments=false
  balanced native flags:
    linux/posix: -O2, -fvisibility=hidden, -Wl,-s, best-effort strip --strip-unneeded
    macOS: -O2, -fvisibility=hidden, -Wl,-x, best-effort strip -x
    Windows: /O2, /OPT:REF, /OPT:ICF
  hardening caveat is emitted as manifest metadata

py2_linux_rec_opera.py
  accepts --hardening-profile
  applies directives and extension flags before setup(build_ext)
  performs best-effort strip after native build when supported

encryption_helper.py / soenc_config.py
  expose --hardening-profile and [build].hardening_profile
  pass profile into the batch builder
  record build_hardening in build_manifest.json
```

Validation executed:

```text
python -m pytest tests/test_protect_hardening.py tests/test_soenc_config.py tests/test_encryption_helper.py::EncryptionHelperTests::test_main_hardening_profile_records_manifest_without_native_compile tests/test_encryption_helper.py::EncryptionHelperTests::test_compile_with_batch_builder_passes_hardening_profile -q
15 passed, 1 skipped

python -m pytest tests/test_protect_hardening.py tests/test_runtime_integrity_smoke.py tests/test_key_provider.py tests/test_soenc_config.py tests/test_encryption_helper.py -q
80 passed, 5 skipped

python soenc.py protect --help
python soenc.py cm --help
python soenc.py transport --help
all help commands completed successfully
```

Boundary statement:

```text
P2-C hardening raises reverse-engineering cost only.
It does not replace key security, license-file, remote-KMS, or runtime integrity.
P0-B2 native-build proof is now available for the strict off-profile smoke on this host; balanced strip-symbol behavior remains best-effort and host-toolchain dependent.
QR/OCR/SOX1 and release/promotion/evidence surfaces remain untouched.
```


## 13. P1-C current pass verification

Verified that P1-C public/private key mode is already implemented in the current
runtime path, without changing QR/OCR/SOX1 code:

```text
enc2sop/crossmedia/key_material.py
  RSA-OAEP-SHA256 hybrid envelope support
  generate_public_key_pair(public_path, private_path)
  wrap_data_key_rsa_oaep_sha256(public_key, data_key)
  unwrap_data_key_rsa_oaep_sha256(private_key, wrapped_data_key)

enc2sop/crossmedia/cli.py
  soenc.py cm keygen-public
  soenc.py cm encrypt --recipient-public-key
  soenc.py cm decrypt --private-key

tests/test_crossmedia_public_key.py
  public-key encrypt/decrypt roundtrip
  wrong private key fails without output
  ambiguous key modes are rejected
```

Validation executed:

```text
python -m pytest tests/test_crossmedia_public_key.py tests/test_crossmedia_cli.py -q
13 passed
```

Boundary statement:

```text
This pass records existing P1-C behavior and test evidence only.
No QR/OCR/SOX1 implementation files were modified.
Private key material stays outside the sealed-side encrypt path; SOX1/manifest leakage does not directly include the private key.
```

## 14. P0-B2 current pass evidence

Unlocked and verified the strict Code Protection native packaging smoke using
the user-specified interpreter:

```text
D:\code_environment\anaconda_all_css\py312\python.exe
Python 3.12.12 / Anaconda / MSC v.1929 64 bit
setuptools 80.9.0
Cython 0.29.36
wheel 0.45.1
Crypto 3.20.0
```

Implementation fix:

```text
py2_linux_rec_opera.py
  compiles paths relative to the staging root instead of absolute paths
  creates explicit setuptools.Extension names from package-relative paths
  preserves package-shaped output such as demo_pkg/demo_module.pyd

scripts/smoke_code_protection.py
  captures native build stdout/stderr with errors=replace to avoid host locale
  decode failures during MSVC/Cython output capture
```

Validation executed:

```text
D:\code_environment\anaconda_all_css\py312\python.exe -B -c <dependency probe>
all required native/protect deps import successfully

D:\code_environment\anaconda_all_css\py312\python.exe scripts\smoke_code_protection.py --python-exe D:\code_environment\anaconda_all_css\py312\python.exe --keep-work
CODE_PROTECTION_SMOKE_OK
report=.tmp_code_protection_smoke_20260610225045_d6e3a874/smoke_code_protection_report.json

D:\code_environment\anaconda_all_css\py312\python.exe -B -c <ast syntax check>
syntax_ok

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_code_protection_smoke.py tests\test_crossmedia_cli.py tests\test_encryption_helper.py::EncryptionHelperTests::test_compile_with_batch_builder_passes_hardening_profile -q
12 passed
```

Scope statement:

```text
This pass modifies only Code Protection/native smoke behavior.
No QR/OCR/SOX1 implementation files were modified.
No release/promotion/evidence platform capability was added.
```

## 15. P1-A/P1-B current pass evidence

Implemented and verified the OCR candidate interface and confirmed the existing
manifest-less sidecar metadata path required by the V0.3 guide.

P1-A implementation:

```text
enc2sop/transport/ocr_observations.py
  TextObservation(text, confidence, bbox, provider_name, image_id)
  observations_from_payload(...)
  observations_to_text(...)

enc2sop/transport/ocr_runtime.py
  external OCR JSON may now return observations/candidates/lines as provider
  candidate records
  provider candidate text is flattened into OCR text for the existing verifier
  legacy {"text": ...}, {"lines": [...]}, output_text_path, and raw stdout
  compatibility is retained
```

P1-A boundary:

```text
OCR providers expose candidates only.
Final acceptance still happens through the existing transport verifier:
format checks, line/chunk/page CRC, total SHA256, and decrypt/tag validation.
No provider is allowed to decide final payload validity or bypass verification.
```

P1-B verification:

```text
tests/test_qrcode_helper_sidecar.py::TransportCoreTests::test_manifestless_ocr_safe_sidecar_with_parity_roundtrip
  verifies ocr-safe-human-correctable-v1 + redundancy/parity + no manifest
  embedded @CFG metadata includes PF=O1, PM=modular-sum, and EL
  recovery uses embedded_headers and restores the original bytes
```

Validation executed:

```text
D:\code_environment\anaconda_all_css\py312\python.exe -B -c <ast syntax check>
syntax_ok

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_ocr_observations.py tests\test_qrcode_helper_sidecar.py::TransportCoreTests::test_external_backend_uses_provider_command_interface tests\test_qrcode_helper_sidecar.py::TransportCoreTests::test_manifestless_ocr_safe_sidecar_with_parity_roundtrip tests\test_qrcode_helper_sidecar.py::SidecarRecoveryTests::test_recover_images_auto_prefers_sidecar_before_external tests\test_qrcode_helper_sidecar.py::SidecarRecoveryTests::test_recover_images_auto_prefers_external_before_generic_ocr -q
7 passed, 3 warnings
```

Scope statement:

```text
This pass touches OCR provider candidate handling only.
SOX1 crypto, key material, QR payload format, and Code Protection crypto remain unchanged.
No release/promotion/evidence platform capability was added.
```

## 16. P2-B current pass evidence

Implemented the assistive-only visual model boundary as a report path rather
than a verifier/reassembly path:

```text
enc2sop/crossmedia/visual_assist.py
  schema = enc2sop-cross-media-visual-assist/v1
  allowed roles:
    locate_qr_regions
    assess_photo_quality
    ocr_candidate_generation
    retake_suggestion
  forbidden roles:
    guess_ciphertext
    complete_crc_failed_payload
    bypass_verifier
    natural_language_crypto_validation

enc2sop/crossmedia/cli.py
  soenc.py cm visual-assist
  --image-input
  --output-report
  optional --provider-report for external visual-model hints
```

Provider boundary:

```text
External visual-model JSON is reduced to allowed fields only:
qr_regions, quality, ocr_candidates, retake_suggestions.

Forbidden fields such as payload, ciphertext/plaintext guesses, SOX1 strings,
CRC bypass, verifier overrides, keys, passphrases, decrypt/decryption claims,
and verified/accepted verdicts fail closed before report generation.
```

Runtime boundary:

```text
visual-assist output is report-only.
OCR candidates are marked untrusted.
The report is not fed into QR reassembly, CRC acceptance, SOX1 decrypt, or tag
verification.
Existing scan/receive verifier paths remain authoritative.
```

Validation executed:

```text
D:\code_environment\anaconda_all_css\py312\python.exe -B -c <ast syntax check>
syntax_ok

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_crossmedia_visual_assist.py tests\test_crossmedia_cli.py -q
12 passed, 1 skipped

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_crossmedia_visual_assist.py tests\test_crossmedia_cli.py tests\test_crossmedia_qr_transport.py::test_scan_bad_image_report_includes_capture_quality_and_retake_suggestion tests\test_crossmedia_qr_transport.py::test_cli_scan_bad_image_writes_quality_guidance -q
12 passed, 3 skipped

D:\code_environment\anaconda_all_css\py312\python.exe soenc.py cm --help
D:\code_environment\anaconda_all_css\py312\python.exe soenc.py cm visual-assist --help
both help commands completed successfully
```

Remaining enhancement count after the P2-B pass and before the P1-E pass:

```text
P1-E release artifact tamper report
```

## 17. P1-E current pass evidence

Implemented a narrow SO/PYD release artifact tamper report without changing
SOX1, QR/OCR, key material, or promotion/evidence platform policy:

```text
encryption_helper.py
  RELEASE_TAMPER_REPORT_SCHEMA = enc2sop-release-tamper-report/v1
  RELEASE_TAMPER_REPORT_FILENAME = release_tamper_report.json
  release_tamper_report_path(dist_dir)
  write_release_failure_report(...)
  compile_with_batch_builder copies the post-validation build_manifest.json
  into build/ so import-time native-loader checks read validated runtime
  fingerprint metadata

enc2sop/cli.py
  soenc.py release writes release_tamper_report.json on successful release
  soenc.py release attempts a failure report before re-raising release errors
```

Report contents:

```text
manifest signature:
  required/present/algorithm/key_id/digest_hex

binary digest:
  per native .so/.pyd/.dll/.dylib artifact
  role = native_extension or runtime_native_extension
  sha256 + size

runtime digest:
  expected digest from release_bundle.runtime_integrity
  actual artifact sha256
  matches_expected boolean

import-time check:
  loader_mode
  loader_enforced
  require_runtime_fingerprint
  runtime_fingerprint_binding
  runtime_path_policy
  fail-closed import RuntimeError mode when configured

failure report:
  success=false
  failure.type
  failure.message
  current package binary digests when available
```

Boundary statement:

```text
release_tamper_report.json is anti-tamper / integrity hardening only.
It is not a strong secrecy boundary and does not replace manifest signing,
runtime fingerprint checks, license-file validation, remote-KMS, or SOX1
authenticated encryption.
```

Validation executed:

```text
D:\code_environment\anaconda_all_css\py312\python.exe -B -c <ast syntax check>
syntax_ok

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_encryption_helper.py::EncryptionHelperTests::test_write_release_receipt_validates_bundle_and_runtime_fingerprints tests\test_encryption_helper.py::EncryptionHelperTests::test_write_release_receipt_rejects_runtime_fingerprint_mismatch tests\test_encryption_helper.py::EncryptionHelperTests::test_write_release_failure_report_records_tamper_failure tests\test_soenc_cli.py::SoencCliTests::test_release_command_generates_release_receipt -q
4 passed

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_encryption_helper.py::EncryptionHelperTests::test_copy_release_writes_release_bundle_contract tests\test_encryption_helper.py::EncryptionHelperTests::test_write_release_receipt_validates_bundle_and_runtime_fingerprints tests\test_encryption_helper.py::EncryptionHelperTests::test_write_release_receipt_rejects_runtime_fingerprint_mismatch tests\test_encryption_helper.py::EncryptionHelperTests::test_write_release_failure_report_records_tamper_failure tests\test_encryption_helper.py::EncryptionHelperTests::test_write_release_receipt_requires_signed_approval_when_enabled tests\test_encryption_helper.py::EncryptionHelperTests::test_write_release_receipt_rejects_approval_digest_mismatch tests\test_soenc_cli.py::SoencCliTests::test_release_command_generates_release_receipt tests\test_soenc_cli.py::SoencCliTests::test_release_command_requires_signed_approval_when_enabled tests\test_soenc_cli.py::SoencCliTests::test_release_command_fails_when_approval_required_but_key_missing tests\test_soenc_cli.py::SoencCliTests::test_release_command_rejects_missing_release_bundle -q
10 passed

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_encryption_helper.py tests\test_soenc_cli.py tests\test_crossmedia_cli.py tests\test_crossmedia_visual_assist.py tests\test_ocr_observations.py tests\test_code_protection_smoke.py -q
105 passed, 2 skipped

D:\code_environment\anaconda_all_css\py312\python.exe -m pytest tests\test_qrcode_helper_sidecar.py::TransportCoreTests::test_external_backend_uses_provider_command_interface tests\test_qrcode_helper_sidecar.py::TransportCoreTests::test_manifestless_ocr_safe_sidecar_with_parity_roundtrip tests\test_qrcode_helper_sidecar.py::SidecarRecoveryTests::test_recover_images_auto_prefers_sidecar_before_external tests\test_qrcode_helper_sidecar.py::SidecarRecoveryTests::test_recover_images_auto_prefers_external_before_generic_ocr -q
4 passed
```

Final remaining item count after this pass:

```text
0
```
