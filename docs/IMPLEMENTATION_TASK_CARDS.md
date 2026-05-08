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

- Status: `done`
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
  - Delivered second extraction slice for rendering and CLI boundaries:
    - Added `enc2sop/transport/render.py` for page rendering/font fallback and sidecar layout generation.
    - Added `enc2sop/transport/cli.py` for parser construction, output helpers (`print_json`, `save_json`, `save_missing_chunks`), and command dispatch.
    - Rewired `qrcode_helper.py` compatibility layer:
      - `AirgapTransportLayer._load_font` delegates to `enc2sop.transport.render.load_font`.
      - `AirgapTransportLayer._render_page` delegates to `enc2sop.transport.render.render_page`.
      - `_build_parser` and `main` delegate to `enc2sop.transport.cli`.
      - analyze report/missing-chunk writers now call extracted CLI helpers.
    - Extended `tests/test_transport_modules.py` with extraction-contract assertions for CLI and render delegation paths.
  - Remaining sub-scope to complete card:
    - complete conversion of `qrcode_helper.py` into a thinner compatibility shim (legacy class methods still host recover/ocr pipeline logic)
  - Notes (2026-05-07, iteration 3):
    - Extracted recover/verify/analyze orchestration into `enc2sop/transport/recover.py`.
    - `qrcode_helper.AirgapTransportLayer` now delegates the following compatibility entrypoints to `enc2sop.transport.recover`:
      - `recover_artifact`
      - `_recover_artifact_against_manifest`
      - `_recover_artifact_without_manifest`
      - `verify_ocr_text`
      - `_verify_ocr_text_against_manifest`
      - `_verify_ocr_text_without_manifest`
      - `analyze_ocr_text`
      - `_analyze_ocr_text_against_manifest`
      - `_recover_encoded_payload`
    - Added focused delegation regression tests in `tests/test_transport_modules.py`.
    - Full test suite remains green after extraction (`75 passed, 3 skipped`).
    - Remaining sub-scope to complete card:
      - extract deeper parse/recovery internals (chunk parsing, conflict resolution, parity internals) from `qrcode_helper.py` into transport modules
      - finish reducing `qrcode_helper.py` toward a thin compatibility facade over transport package boundaries
  - Notes (2026-05-07, iteration 4):
    - Added `enc2sop/transport/parser.py` and extracted core recovery internals:
      - missing-chunk records/retake planning
      - data/parity chunk presence counting
      - parity recovery
      - parity-conflict downgrade handling
      - package-hash and structural conflict resolution
      - parse-error escalation
    - Rewired `enc2sop/transport/recover.py` to consume parser helpers directly (instead of invoking those paths through legacy class-bound methods).
    - Rewired `qrcode_helper.AirgapTransportLayer` compatibility methods to delegate to `enc2sop.transport.parser` for these internals.
    - Expanded extraction regression coverage in `tests/test_transport_modules.py` to assert delegation for parser-backed compatibility methods.
    - Verification:
      - `python -m pytest -q tests/test_transport_modules.py` => 14 passed
      - `python -m pytest -q tests/test_qrcode_helper_sidecar.py` => 34 passed
      - `python -m pytest -q` => 79 passed, 3 skipped
    - Remaining sub-scope to complete card:
      - extract `_parse_ocr_chunks` / `_parse_ocr_chunks_with_total` (and payload-only parser path) into transport parser modules
      - extract embedded metadata scanning/inference helpers into transport parser modules
      - leave `qrcode_helper.py` as a near-thin compatibility facade over `enc2sop.transport` boundaries
  - Notes (2026-05-07, iteration 5):
    - Extracted remaining OCR parse and metadata inference internals into `enc2sop/transport/parser.py`:
      - `_parse_ocr_chunks`
      - `_parse_ocr_chunks_payload_only_manifest`
      - `_parse_ocr_chunks_with_total`
      - `_choose_majority_metadata_value`
      - `_scan_transport_metadata`
      - `_build_inferred_manifest_from_ocr`
    - Rewired `qrcode_helper.AirgapTransportLayer` compatibility methods above to thin delegation wrappers against `enc2sop.transport.parser`.
    - Added focused delegation assertions in `tests/test_transport_modules.py` for parser parse/metadata entrypoints.
    - Verification:
      - `python -m pytest -q tests/test_transport_modules.py` => 16 passed
      - `python -m pytest -q tests/test_qrcode_helper_sidecar.py` => 34 passed
      - `python -m pytest -q` => 81 passed, 3 skipped
    - Remaining sub-scope to complete card:
      - reduce residual OCR/image pipeline internals in `qrcode_helper.py` into bounded transport modules so the file becomes a near-thin compatibility facade
  - Notes (2026-05-08, iteration 6):
    - Added `enc2sop/transport/layout.py` and extracted manifest/page-layout mapping helpers out of `qrcode_helper.py`:
      - `_get_render_layout_pages`
      - `_line_meta_has_sidecar`
      - `_page_layout_has_sidecar`
      - `_page_layouts_support_sidecar`
      - `_manifest_has_page_entries`
      - `_resolve_image_page_number`
      - `_manifest_page_entries`
      - `_manifest_entries_in_transport_order`
      - `_manifest_chunk_payload_length`
    - Rewired `qrcode_helper.AirgapTransportLayer` compatibility methods above into thin delegation wrappers against `enc2sop.transport.layout`.
    - Updated `enc2sop/transport/__init__.py` export surface to include `layout`.
    - Expanded extraction regression coverage in `tests/test_transport_modules.py` with delegation assertions for all extracted layout helper boundaries.
    - Verification:
      - `python -m pytest -q tests/test_transport_modules.py` => 17 passed
      - `python -m pytest -q tests/test_qrcode_helper_sidecar.py` => 34 passed
      - `python -m pytest -q` => 82 passed, 3 skipped
    - Remaining sub-scope to complete card:
      - extract residual OCR/image processing internals (band detection, manifest-guided crop routing, sidecar decode/image OCR pipeline helpers) into bounded transport modules
      - keep `qrcode_helper.py` as a near-thin compatibility facade over `enc2sop.transport` boundaries
  - Notes (2026-05-08, iteration 7):
    - Added `enc2sop/transport/ocr_pipeline.py` and extracted manifest-guided OCR/image pipeline helpers out of `qrcode_helper.py`:
      - `_detect_text_bands`
      - `_select_manifest_data_bands`
      - `_crop_primary_text_band`
      - `_ocr_payload_crop_tesseract`
      - `_ocr_crc_crop_tesseract`
      - `_ocr_tesseract_variants`
      - `_ocr_payload_crop_tesseract_variants`
      - `_ocr_crc_crop_tesseract_variants`
      - `_ocr_generic_line_tesseract_variants`
      - `_ocr_band_tesseract_variants`
      - `_parse_meta_line_candidate`
      - `_parse_cfg_line_candidate`
      - `_parse_hash_fragment_candidate`
      - `_parse_hash_compact_candidate`
      - `_crc_windows_from_hints`
      - `_score_candidate_crc_against_hints`
      - `_repair_payload_candidate_by_crc_hint`
      - `_choose_payload_candidate_with_crc_hint`
      - `_ocr_manifest_guided_page_tesseract`
      - `_ocr_image_crop_tesseract`
    - Rewired `qrcode_helper.AirgapTransportLayer` compatibility methods above into thin delegation wrappers against `enc2sop.transport.ocr_pipeline`.
    - Updated `enc2sop/transport/__init__.py` export surface to include `ocr_pipeline`.
    - Expanded extraction regression coverage in `tests/test_transport_modules.py` with delegation assertions for extracted OCR pipeline boundaries.
    - Verification:
      - `python -m pytest -q tests/test_transport_modules.py` => 18 passed
      - `python -m pytest -q tests/test_qrcode_helper_sidecar.py` => 34 passed
      - `python -m pytest -q` => 83 passed, 3 skipped
    - Remaining sub-scope to complete card:
      - extract residual sidecar decode/structured OCR page internals and external-provider image OCR orchestration internals from `qrcode_helper.py` into bounded transport modules
      - keep `qrcode_helper.py` as a near-thin compatibility facade over `enc2sop.transport` boundaries
  - Notes (2026-05-08, iteration 8):
    - Added `enc2sop/transport/ocr_runtime.py` and extracted residual sidecar/structured OCR runtime boundaries:
      - `_ocr_image_crop_easyocr`
      - `_decode_sidecar_payload`
      - `_ocr_structured_page_sidecar`
      - `_decode_manifest_guided_sidecar_payload`
      - `_ocr_manifest_guided_page_sidecar`
      - `_choose_payload_candidate`
      - `_repair_payload_candidate_by_crc`
      - `_ocr_structured_page_tesseract`
      - `_ocr_structured_page_easyocr`
      - `_parse_external_ocr_stdout`
      - `_run_external_ocr_provider`
      - `_ocr_single_image`
    - Rewired `qrcode_helper.AirgapTransportLayer` compatibility methods above into thin delegation wrappers against `enc2sop.transport.ocr_runtime`.
    - Updated `enc2sop/transport/__init__.py` export surface to include `ocr_runtime`.
    - Expanded extraction regression coverage in `tests/test_transport_modules.py` with delegation assertions for all extracted OCR runtime boundaries.
    - Verification:
      - `python -m pytest -q tests/test_transport_modules.py` => 19 passed
      - `python -m pytest -q tests/test_qrcode_helper_sidecar.py` => 34 passed
      - `python -m pytest -q` => 84 passed, 3 skipped
    - Remaining sub-scope to complete card:
      - extract remaining embedded-metadata page orchestration internals (`_ocr_embedded_metadata_page_tesseract`, `_build_inferred_manifest_from_metadata`, `_build_expected_page_entries`) from `qrcode_helper.py` into bounded transport modules
      - keep `qrcode_helper.py` as a near-thin compatibility facade over `enc2sop.transport` boundaries
  - Notes (2026-05-08, iteration 9):
    - Added `enc2sop/transport/ocr_embedded.py` and extracted remaining embedded-metadata page orchestration internals from `qrcode_helper.py`:
      - `_build_inferred_manifest_from_metadata`
      - `_build_expected_page_entries`
      - `_ocr_embedded_metadata_page_tesseract`
    - Rewired `qrcode_helper.AirgapTransportLayer` compatibility methods above into thin delegation wrappers against `enc2sop.transport.ocr_embedded`.
    - Updated `enc2sop/transport/__init__.py` export surface to include `ocr_embedded`.
    - Expanded extraction regression coverage in `tests/test_transport_modules.py` with delegation assertions for extracted embedded-metadata helper boundaries.
    - Verification:
      - `python -m pytest -q tests/test_transport_modules.py` => 21 passed
      - `python -m pytest -q tests/test_qrcode_helper_sidecar.py` => 34 passed
      - `python -m pytest -q` => 86 passed, 3 skipped
    - Remaining sub-scope:
      - none; `ENC-P0-002` is complete and `qrcode_helper.py` now serves as a compatibility facade over `enc2sop.transport` module boundaries.

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

- Status: `done`
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
- Notes (2026-05-08):
  - Added `enc2sop/keys/license.py` with `license-file` provider implementation and run lifecycle hooks:
    - `begin_run`: initializes license context (`license_file`, `license_id`)
    - `pack_key`: emits key refs (`mode`, `license_id`, `license_file`, `key_id`) and stores per-run key map
    - `finalize_run`: writes `soenc` license artifact (`enc2sop-license/v1`) with SHA256 integrity digest and updates `build_manifest.json` `key_management` metadata
  - Updated key package export surface:
    - `enc2sop/keys/__init__.py` now exports `LicenseFileKeyProvider`
  - Updated protection flow wiring in `encryption_helper.py`:
    - provider lifecycle hooks integrated (`_provider_begin_run`, `_provider_finalize_run`)
    - `protect_project` now accepts provider instance and allows provider finalization to mutate manifest
    - added CLI controls `--license-file`, `--license-id` and guardrails requiring `keys.mode=license-file` when used
    - release copy flow now includes license artifact when declared by manifest
  - Extended runtime key resolution in `decryption_helper.py`:
    - runtime now supports `license-file` key refs
    - resolves license path from `SOENC_LICENSE_FILE` override or manifest-relative fallback search
    - validates license schema/version/mode, `license_id`, and integrity digest before key resolution
  - Extended config contract in `soenc_config.py`:
    - `[keys]` now supports `license_file` and `license_id`
  - Added focused tests:
    - `tests/test_key_provider.py`: provider writes license + manifest metadata
    - `tests/test_encryption_helper.py`:
      - valid license-mode flow executes protected symbol successfully
      - tampered license fails at runtime with integrity mismatch
    - `tests/test_soenc_config.py`: parse/merge coverage for `license_file` and `license_id`
  - Verification:
    - `python -m pytest -q tests/test_key_provider.py tests/test_encryption_helper.py tests/test_soenc_config.py` => `28 passed, 3 skipped`

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
