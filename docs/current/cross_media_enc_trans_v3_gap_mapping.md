# Cross-media V0.3 gap mapping

> Source blueprint: `docs/current/cross_media_enc_trans_imple_guide_v3.md`  
> Mapping date: 2026-06-10  
> Current pass update: P2-C native hardening profile baseline.  
> Explicitly out of scope: QR/OCR/SOX1 behavior changes and release/promotion/evidence expansion.

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
against the current codebase: most P0-A items are already implemented, and the
only remaining P0-B gap is strict native-build proof, which is currently
blocked by this host's native-build Python dependencies.

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
| P0-B2 code-protection smoke | `scripts/smoke_code_protection.py` now creates `demo_module.py`, runs `soenc.py protect`, probes native deps, runs `soenc.py build` when possible, then imports native artifacts from a clean directory. | Script added; strict native proof currently blocked on this host | Fix native build environment (`setuptools`/`backports.tarfile` conflict and missing `Cython`) or run on a prepared native-build host. |
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

Current host evidence:

```text
protect step: passed
native dependency probe: blocked
missing/broken: setuptools, Cython
setuptools error: ImportError importing backports.tarfile from the current Python environment
```

The script does not modify QR/OCR/SOX1 behavior and does not add release,
promotion, or evidence-platform capability.

## 6. Next recommended pass

After the native build environment is available, rerun:

```text
python scripts/smoke_code_protection.py
```

With P0-B3/B4/B5/B6 now implemented, the remaining P0-B item is:

```text
P0-B2 strict native proof: still blocked by local native-build dependencies
```

After the P2-C native hardening profile baseline pass, the remaining P1/P2 enhancement
items are:

```text
P1-A OCR fallback and multi-model candidates
P1-B manifest-less sidecar metadata
P1-C public/private key mode
P1-E release artifact tamper report
P2-B visual model assistance
```

Under the current scope locks, P1-A/P1-B/P1-C/P2-B require explicit care before
touching QR/OCR/SOX1 paths, and P1-E must not expand release/promotion/evidence
without a separate confirmation.

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
Actual strip-symbol proof remains tied to the existing P0-B2 native-build environment blocker on this host.
QR/OCR/SOX1 and release/promotion/evidence surfaces remain untouched.
```
