# enc2sop Implementation Task Cards

This file is the executable backlog for future Codex or GPT-5.5 coding iterations.

## Delivery Rules

Every card should produce:

1. concrete code changes
2. focused tests or explicit verification hooks
3. matching doc updates when assumptions change

If one card is too large for one iteration, the agent should deliver a vertical slice and update the card status plus remaining sub-scope.

## Status Values

- `todo`
- `in_progress`
- `blocked`
- `done`

## P0 Cards

### CARD `ENC-P0-001`

- Status: `done`
- Goal: lazily load OCR dependencies and stop import-time coupling between core transport logic and heavy OCR backends
- Type: refactor + stability
- Depends on: none
- Main files:
  - `qrcode_helper.py`
  - new modules under a future `enc2sop/transport/ocr/`
- Deliverables:
  - OCR backends loaded only when selected
  - no `easyocr` or `torch` import at core module import time
  - stable provider boundary for `tesseract`, `easyocr`, `external`, `sidecar`
- Acceptance:
  - importing the transport core does not import `easyocr`
  - focused tests cover backend selection and lazy loading
 - Notes (2026-05-06):
   - `qrcode_helper.py` now uses lazy module loaders for `pytesseract`, `easyocr`, and `numpy`.
   - Core import no longer imports `easyocr` at module load time.
   - Added focused tests for import-time isolation and easyocr lazy-reader initialization.

### CARD `ENC-P0-002`

- Status: `in_progress`
- Goal: split `qrcode_helper.py` into bounded modules so protocol, render, OCR, recovery, and CLI are independently maintainable
- Type: architectural refactor
- Depends on: `ENC-P0-001`
- Main files:
  - `qrcode_helper.py`
  - new package layout under future `enc2sop/transport/`
- Deliverables:
  - transport core protocol module
  - render module
  - OCR adapter module
  - recover/analyze module
  - thin CLI entrypoint
- Acceptance:
  - legacy CLI behavior still works or compatibility shim exists
  - each module has focused tests
- Notes (2026-05-07):
  - Delivered a compatibility-safe vertical slice that extracts shared transport boundaries into `enc2sop.transport` while preserving legacy `qrcode_helper.py` CLI/runtime behavior.
  - Added `enc2sop/transport/protocol.py` for protocol constants, regex patterns, OCR normalization, and base32/CRC/hash helpers.
  - Added `enc2sop/transport/ocr_adapters.py` for lazy OCR backend discovery/loading (`pytesseract`, `easyocr`, `numpy`) and language mapping.
  - Rewired `qrcode_helper.py` to consume extracted modules via explicit aliases while keeping existing symbol names stable for backward compatibility.
  - Added focused regression coverage in `tests/test_transport_modules.py` to verify module extraction contracts and compatibility alias wiring.
  - Remaining sub-scope to complete card:
    - extract render pipeline from `qrcode_helper.py` into `enc2sop.transport.render`
    - extract recover/analyze path into `enc2sop.transport.recover`
    - introduce a thin transport CLI entrypoint module and reduce `qrcode_helper.py` to compatibility shim

### CARD `ENC-P0-003`

- Status: `done`
- Goal: fix the decrypt runtime compilation chain so the runtime used by protected modules is actually compiled or intentionally packaged
- Type: correctness + security
- Depends on: none
- Main files:
  - `encryption_helper.py`
  - `py2_linux_rec_opera.py`
  - tests for compile output inspection
- Deliverables:
  - resolve `__enc_rt_*` compile-skip conflict
  - explicit strategy for runtime module naming and packaging
  - manifest reflects the chosen runtime delivery mode
- Acceptance:
  - compiled output contains or correctly packages the required runtime path
  - regression test proves the intended behavior
- Notes (2026-05-07):
  - Runtime module names now use `enc_rt_*` (non-dunder), avoiding batch-compiler skip rules for `__*`.
  - `build_manifest.json` now records `runtime_delivery` metadata with explicit delivery mode and validation contract.
  - Build flow now validates that each staged runtime `.py` has a compiled native artifact in `build/`, and fails fast if missing.
  - Added focused tests for compile-eligible runtime naming and runtime-delivery validation failure/success paths.

### CARD `ENC-P0-004`

- Status: `done`
- Goal: add true end-to-end tests for `protect -> compile -> import compiled artifact -> execute protected code`
- Type: testing
- Depends on: `ENC-P0-003`
- Main files:
  - `tests/test_encryption_helper.py`
  - new end-to-end fixtures
- Deliverables:
  - a minimal sample package compiled in test automation or a dedicated integration harness
  - import verification for protected functions/classes
- Acceptance:
  - test fails on broken runtime chain
  - test passes on corrected implementation
- Notes (2026-05-07):
  - Added end-to-end compile/import execution harness in `tests/test_encryption_helper.py`:
    - `test_e2e_compiled_flow_imports_and_executes_protected_symbols`
    - `test_e2e_compiled_flow_detects_broken_runtime_chain`
  - Tests are dependency-gated when `Cython` is unavailable in the active interpreter.
  - Verified pass in a toolchain-provisioned interpreter:
    - `D:\code_environment\anaconda_all_css\py311\python.exe -m pytest -q -vv tests/test_encryption_helper.py -k e2e_compiled_flow` => 2 passed.
  - Default environment remains stable and transparently skips compile-path tests when `Cython` is absent.

### CARD `ENC-P0-005`

- Status: `done`
- Goal: replace machine-specific build paths with profile-driven toolchain discovery
- Type: productization
- Depends on: none
- Main files:
  - `encryption_helper.py`
  - `py2_linux_rec_opera.py`
  - new config helpers
- Deliverables:
  - build profile abstraction
  - path discovery with overrides
  - no mandatory hard-coded local paths in defaults
- Acceptance:
  - Windows path assumptions are configurable
  - missing toolchain errors are explicit and actionable
- Notes (2026-05-07):
  - Added `toolchain_profile.py` with profile abstraction (`auto`, `windows-msvc`, `native`) and discovery helpers.
  - `encryption_helper.py` now defaults compile interpreter to current `sys.executable` (or `SOENC_PYTHON_EXE`) instead of machine-locked paths.
  - Added explicit CLI controls:
    - `--build-profile`
    - `--vcvars-path`
  - Windows MSVC environment preparation now discovers `vcvars64.bat` via:
    - `SOENC_VCVARS64`
    - `VSINSTALLDIR`
    - `vswhere.exe`
    - standard Visual Studio installation paths
  - `py2_linux_rec_opera.py` now consumes the same build profile inputs and no longer embeds hard-coded INCLUDE/LIB/CL path constants.
  - Added focused tests in `tests/test_toolchain_profile.py` and extended `tests/test_encryption_helper.py` guard coverage for profile/CLI validation.

### CARD `ENC-P0-006`

- Status: `done`
- Goal: introduce a unified project configuration file for the platform
- Type: platform skeleton
- Depends on: `ENC-P0-005`
- Main files:
  - new `soenc.toml` loader
  - `encryption_helper.py`
  - future CLI entry layer
- Deliverables:
  - config schema for target, scope, build profile, output dirs, key mode, package metadata
  - CLI can load config file and merge command-line overrides
- Acceptance:
  - one project config can drive the protect/build mainline
- Notes (2026-05-07):
  - Added `soenc_config.py` with schema-validated TOML loading for `[project]`, `[build]`, `[keys]`, `[package]`.
  - `encryption_helper.py` now supports `--config/ -c`, auto-discovers `./soenc.toml`, and merges config defaults with CLI overrides.
  - Added tri-state CLI toggles (`--compile/--no-compile`, `--skip-bad-files/--no-skip-bad-files`, `--precheck-only/--no-precheck-only`, `--infer-namespace/--no-infer-namespace`) to make override precedence explicit.
  - Build manifest now records config provenance (`config.source`) plus `key_mode` and package metadata when config is used.
  - Added focused tests:
    - `tests/test_soenc_config.py`
    - new config merge/override coverage in `tests/test_encryption_helper.py`

### CARD `ENC-P0-007`

- Status: `done`
- Goal: add signed artifact manifests to detect tampering
- Type: security
- Depends on: `ENC-P0-006`
- Main files:
  - `encryption_helper.py`
  - packaging helpers
  - verification tests
- Deliverables:
  - manifest signature generation
  - manifest signature verification
  - failure path on signature mismatch
- Acceptance:
  - modified manifest is rejected
- Notes (2026-05-07):
  - Added signed `build_manifest.json` support in `encryption_helper.py` using HMAC-SHA256.
  - Added explicit signing/verification controls:
    - `--manifest-sign-key-file`
    - `--manifest-sign-key-b64`
    - `--manifest-key-id`
    - `--require-manifest-signature` / `--no-require-manifest-signature`
  - Added manifest canonicalization + signature verification path that rejects tampered manifests.
  - Runtime delivery validation now verifies manifest signatures (when key is provided or required) and re-signs manifest after validation updates.
  - Extended `soenc.toml` `[keys]` schema for:
    - `manifest_sign_key_file`
    - `manifest_key_id`
    - `require_manifest_signature`
  - Added focused tests in:
    - `tests/test_encryption_helper.py`
    - `tests/test_soenc_config.py`

### CARD `ENC-P0-008`

- Status: `done`
- Goal: introduce the `KeyProvider` abstraction and a first local provider implementation
- Type: security architecture
- Depends on: `ENC-P0-006`
- Main files:
  - `decryption_helper.py`
  - `encryption_helper.py`
  - new `enc2sop/keys/` package
- Deliverables:
  - provider interface
  - local provider implementation
  - wiring that decouples key acquisition from protection logic
- Acceptance:
  - protection flow runs through provider abstraction instead of ad hoc embedded key reconstruction only
- Notes (2026-05-07):
  - Added new key architecture package:
    - `enc2sop/keys/provider.py`: `KeyProvider` contract + provider registry
    - `enc2sop/keys/local.py`: `LocalEmbeddedKeyProvider` for local wrapped key references
    - `enc2sop/keys/__init__.py`: stable import surface
  - Updated `encryption_helper.py` to route key wrapping through the provider abstraction:
    - `encrypt_snippet` now returns payload + raw data key bytes
    - `pack_key_reference` resolves configured provider and emits a structured key reference
    - protected stubs now call runtime `_x(payload, key_ref, globals())`
  - Updated `decryption_helper.py` runtime templates (`runtime_py_source`, `runtime_pyx_source`) to resolve key bytes from provider key references:
    - supports `local-embedded` key references
    - preserves backward compatibility with historical raw key-parts payloads
  - Build manifest now records key-control metadata under `key_management`.
  - Added key-mode normalization alias so legacy config value `local-provider` maps to `local-embedded`.
  - Added focused tests:
    - `tests/test_key_provider.py`
    - extended `tests/test_encryption_helper.py`
    - updated `tests/test_soenc_config.py`

## P1 Cards

### CARD `ENC-P1-009`

- Status: `todo`
- Goal: add a license-file based key provider
- Type: security + productization
- Depends on: `ENC-P0-008`
- Main files:
  - `enc2sop/keys/`
  - packaging and runtime wiring
- Deliverables:
  - license file format
  - license validation flow
  - protected runtime path that reads license-derived key material
- Acceptance:
  - protected artifact can run with valid license and fails with invalid license

### CARD `ENC-P1-010`

- Status: `todo`
- Goal: define a remote-KMS provider contract and stub implementation
- Type: security platform
- Depends on: `ENC-P0-008`
- Main files:
  - `enc2sop/keys/`
  - config schema
  - docs
- Deliverables:
  - provider interface contract
  - request/response model
  - retry/error policy
- Acceptance:
  - platform can select the provider even if the real KMS integration is stubbed initially

### CARD `ENC-P1-011`

- Status: `todo`
- Goal: move the most sensitive runtime decrypt path toward a native loader
- Type: hardening
- Depends on: `ENC-P0-003`, `ENC-P0-008`
- Main files:
  - `decryption_helper.py`
  - native runtime generation path
  - build logic
- Deliverables:
  - native runtime path for sensitive modules
  - documented fallback strategy
- Acceptance:
  - at least one protected flow reduces pure-Python exposure of decrypt logic

### CARD `ENC-P1-012`

- Status: `todo`
- Goal: unify the platform command surface into a single CLI entrypoint
- Type: productization
- Depends on: `ENC-P0-006`
- Main files:
  - new CLI package
  - wrappers for current script entrypoints
- Deliverables:
  - `soenc protect/build/package/verify`
  - compatibility wrappers or migration notes for old commands
- Acceptance:
  - one documented CLI becomes the preferred entrypoint

### CARD `ENC-P1-013`

- Status: `todo`
- Goal: define a standard release bundle format for downstream product teams
- Type: packaging
- Depends on: `ENC-P0-007`, `ENC-P1-012`
- Main files:
  - packaging layer
  - docs
- Deliverables:
  - signed manifest
  - native artifacts
  - runtime dependencies
  - release metadata
- Acceptance:
  - bundle layout is stable and documented

### CARD `ENC-P1-014`

- Status: `todo`
- Goal: convert airgap transport into an optional plugin package
- Type: modularization
- Depends on: `ENC-P0-002`, `ENC-P1-012`
- Main files:
  - `enc2sop/transport/`
  - CLI plugin wiring
- Deliverables:
  - transport plugin registration
  - optional install or optional import path
- Acceptance:
  - mainline protect/build/package flow works without OCR dependencies installed

### CARD `ENC-P1-015`

- Status: `todo`
- Goal: rebuild airgap recovery around sidecar-first structured recovery
- Type: transport reliability
- Depends on: `ENC-P1-014`
- Main files:
  - transport render/recover modules
  - tests
- Deliverables:
  - sidecar-first recovery path
  - manifest-guided fallback
  - generic OCR as last resort only
- Acceptance:
  - docs and code reflect the new priority order

### CARD `ENC-P1-016`

- Status: `todo`
- Goal: create operator-facing manuals for protect/build/package/release and transport plugin usage
- Type: documentation
- Depends on: `ENC-P1-012`, `ENC-P1-013`, `ENC-P1-015`
- Main files:
  - `README.md`
  - `USAGE_MANUAL.md`
  - transport manual files
  - `docs/`
- Deliverables:
  - product-facing onboarding path
  - release operator path
  - transport plugin path
- Acceptance:
  - a new operator can follow the docs without repository archaeology

## Recommended Immediate Execution Order

1. `ENC-P0-001`
2. `ENC-P0-003`
3. `ENC-P0-004`
4. `ENC-P0-005`
5. `ENC-P0-006`
6. `ENC-P0-007`
7. `ENC-P0-008`
8. `ENC-P0-002`

Rationale:

- first stop stability and import coupling damage
- then repair the protection chain
- then prove the chain with tests
- then make the platform configurable
- then strengthen security and product surface
