# enc2sop Platform Launch Assessment

Date: `2026-05-06`
Project root: `D:\Download\gaming\new_program\data_helper\6_so_enc`
Assessment objective: convert the current repository from a developer-oriented toolset into a production-ready protection platform.

## 1. Executive Summary

The repository already contains a viable protection-oriented core:

- `encryption_helper.py` implements the source protection pipeline
- `decryption_helper.py` provides the runtime decrypt-and-exec template
- `py2_linux_rec_opera.py` performs batch Cython compilation

The repository does not yet qualify as a production platform because the delivery path is still dominated by:

- a monolithic `qrcode_helper.py`
- machine-specific toolchain configuration
- weak key-control architecture
- incomplete end-to-end validation for `protect -> compile -> import compiled artifact`

## 2. Current-State Facts

### 2.1 Core Files

| Area | File | Observed role | Assessment |
| --- | --- | --- | --- |
| Protection pipeline | `encryption_helper.py` | Protects source into encrypted staging `.py` files and can invoke batch compile | usable foundation |
| Runtime decrypt core | `decryption_helper.py` | Rebuilds key, decrypts payload, `exec`s source into module namespace | functional but weak against strong reverse engineering |
| Native build pipeline | `py2_linux_rec_opera.py` | Batch Cython build for `.pyd/.so` | useful, but too environment-specific |
| Airgap transport | `qrcode_helper.py` | Export, OCR, verify, analyze, recover, image workflows | oversized monolith and no longer suitable as mainline architecture |

### 2.2 Verified Local Findings

- `42` tests pass under local default `pytest`, with `2` compile-path tests skipped when `Cython` is unavailable in that interpreter.
- Compile-path end-to-end tests pass in a toolchain-provisioned interpreter (`D:\code_environment\anaconda_all_css\py311\python.exe`): `2` passed.
- After test completion, the process still hits a Windows access violation via `easyocr -> torch`.
- `qrcode_helper.py` is roughly `5442` lines and centralizes protocol, rendering, OCR, recovery, CLI, and provider logic.
- `encryption_helper.py` uses AES-GCM with XOR-sharded key parts, but the key material is still reconstructable inside the delivered artifact.
- The runtime delivery contract now requires compile-eligible module names (`enc_rt_*`) plus post-build validation that runtime native artifacts are present.
- `py2_linux_rec_opera.py` skips `__*` modules except `__init__.py`, creating a direct risk that the decrypt runtime is not actually compiled into the protected native delivery path.

## 3. Accepted Baseline Decisions

### [DECISION][P0] D-001 Mainline Product Definition

The platform mainline is:

`protect -> build -> package -> verify -> release`

`qrcode` and OCR flows are optional plugins for special transport scenarios, not the platform core.

### [DECISION][P0] D-002 Product Positioning

The product goal is not merely "hide Python code".

The product goal is:

1. raise reverse-engineering cost
2. retain key-control power in the platform
3. make delivery repeatable and productized
4. support `py -> protected py -> cython -> so/pyd`
5. preserve an optional airgap transfer path without letting it dominate architecture

### [DECISION][P0] D-003 qrcode Scope Reduction

`qrcode_helper.py` must be decomposed and repositioned as:

- `transport/core`
- `transport/render`
- `transport/ocr`
- `transport/recover`
- `transport/cli`

The default platform path must not depend on OCR.

### [DECISION][P0] D-004 Recovery Priority

If airgap transport is used, the preferred recovery order is:

1. sidecar geometric decode
2. manifest-guided structured extraction
3. external OCR provider
4. generic OCR fallback

### [DECISION][P0] D-005 Key Architecture Direction

Future protection strength must come from key-control architecture rather than repeated local obfuscation tricks.

The target direction is:

- per-module or per-artifact data keys
- platform-managed `KeyProvider`
- manifest signing
- optional license-file and remote-KMS modes
- eventual native runtime loader for the most sensitive decrypt path

## 4. Production Blockers

### [BLOCKER][P0] B-001 qrcode Monolith and Import-Time Heavy Dependencies

`qrcode_helper.py` imports OCR-related dependencies at module import time and can crash the process after tests through native library behavior. This is incompatible with production stability and with a clean core-platform boundary.

Impact:

- weak isolation
- test instability
- poor deployability
- high refactor cost

Progress status (2026-05-07):

- Landed first extraction slice into `enc2sop.transport`:
  - `enc2sop/transport/protocol.py` (protocol constants + parsing/normalization helpers)
  - `enc2sop/transport/ocr_adapters.py` (lazy OCR adapter boundary + backend loading)
- Landed second extraction slice into `enc2sop.transport`:
  - `enc2sop/transport/render.py` (page rendering, sidecar layout drawing, and font fallback logic)
  - `enc2sop/transport/cli.py` (transport parser/dispatch and report output helper boundaries)
- `qrcode_helper.py` now consumes these extracted modules through compatibility aliases.
- Existing transport tests remain green, including import-time easyocr isolation.
- Landed third/fourth extraction slices into `enc2sop.transport`:
  - `enc2sop/transport/recover.py` (recover/verify/analyze orchestration)
  - `enc2sop/transport/parser.py` (parity/conflict/missing-chunk parse helpers)
- `qrcode_helper.py` compatibility methods now delegate recover/parity/conflict internals into extracted transport modules.
- Landed fifth extraction slice into `enc2sop.transport`:
  - extracted OCR chunk parse and metadata inference internals into `enc2sop/transport/parser.py`.
  - `qrcode_helper.py` now delegates `_parse_ocr_chunks*` and metadata inference helpers into transport parser boundaries.
- Landed sixth extraction slice into `enc2sop.transport`:
  - added `enc2sop/transport/layout.py` for manifest/page-layout mapping boundaries and sidecar-layout eligibility checks.
  - `qrcode_helper.py` now delegates `_get_render_layout_pages`, `_line_meta_has_sidecar`, `_page_layout_has_sidecar`, `_page_layouts_support_sidecar`, `_manifest_has_page_entries`, `_resolve_image_page_number`, `_manifest_page_entries`, `_manifest_entries_in_transport_order`, and `_manifest_chunk_payload_length` into the extracted layout module.
- Landed seventh extraction slice into `enc2sop.transport`:
  - added `enc2sop/transport/ocr_pipeline.py` for manifest-guided OCR/image processing internals and OCR candidate parsing/repair helpers.
  - `qrcode_helper.py` now delegates `_detect_text_bands`, `_select_manifest_data_bands`, `_crop_primary_text_band`, `_ocr_payload_crop_tesseract*`, `_ocr_crc_crop_tesseract*`, `_ocr_tesseract_variants`, `_ocr_generic_line_tesseract_variants`, `_ocr_band_tesseract_variants`, metadata/header parse candidates, CRC-hint candidate scoring/repair helpers, `_choose_payload_candidate_with_crc_hint`, `_ocr_manifest_guided_page_tesseract`, and `_ocr_image_crop_tesseract` into the extracted OCR pipeline module.
- Landed eighth extraction slice into `enc2sop.transport`:
  - added `enc2sop/transport/ocr_runtime.py` for sidecar decode, structured-page OCR, payload candidate selection/repair, external-provider stdout/command orchestration, and single-image backend routing internals.
  - `qrcode_helper.py` now delegates `_ocr_image_crop_easyocr`, `_decode_sidecar_payload`, `_ocr_structured_page_sidecar`, `_decode_manifest_guided_sidecar_payload`, `_ocr_manifest_guided_page_sidecar`, `_choose_payload_candidate`, `_repair_payload_candidate_by_crc`, `_ocr_structured_page_tesseract`, `_ocr_structured_page_easyocr`, `_parse_external_ocr_stdout`, `_run_external_ocr_provider`, and `_ocr_single_image` into the extracted runtime module.
- Landed ninth extraction slice into `enc2sop.transport`:
  - added `enc2sop/transport/ocr_embedded.py` for embedded-metadata page orchestration and inferred-manifest/page-entry reconstruction internals.
  - `qrcode_helper.py` now delegates `_build_inferred_manifest_from_metadata`, `_build_expected_page_entries`, and `_ocr_embedded_metadata_page_tesseract` into the extracted embedded OCR module.
- `ENC-P0-002` extraction target is complete; `qrcode_helper.py` now functions as a compatibility facade over bounded `enc2sop.transport` modules.

### [BLOCKER][P0] B-002 Compile Path Risk for Decrypt Runtime

The current generated runtime module naming convention collides with the batch compiler's rule that skips `__*` files. This can invalidate the intended `protected py -> compiled native artifact` path.

Impact:

- protection chain may be incomplete
- shipped artifact may rely on plain Python runtime pieces
- current tests do not prove compiled delivery integrity

### [DONE][P0] B-003 Machine-Specific Toolchain Configuration

The repository contains hard-coded Python, MSVC, SDK, INCLUDE, and LIB paths.

Impact:

- non-portable builds
- onboarding friction
- no production-grade build profile system

Resolution status (2026-05-07):

- Added profile-driven toolchain contract with `auto`, `windows-msvc`, and `native` modes.
- Added discovery/override model for compiler preparation (`--vcvars-path`, `SOENC_VCVARS64`, `vswhere`, standard VS locations).
- Removed hard-coded default Python interpreter and hard-coded MSVC INCLUDE/LIB path injection from build scripts.
- Missing toolchain now returns explicit actionable errors instead of relying on machine-specific path assumptions.

### [DONE][P0] B-004 End-to-End Compile Validation Covered By Explicit Tests

The repository now includes explicit end-to-end tests for:

`protect -> compile -> import compiled result -> execute protected symbol`

and for broken-runtime-chain detection. These tests pass in a toolchain-provisioned interpreter and are dependency-gated in environments without `Cython`.

Residual note:

- standardize this compile-path execution in CI once build profiles/toolchain discovery (`ENC-P0-005`) is completed

### [DONE][P0] B-005 KeyProvider Baseline Implemented

The platform now has an explicit `KeyProvider` abstraction and mainline wiring for local key resolution.

Resolution status (2026-05-07):

- Added `enc2sop.keys` provider contract and registry (`KeyProvider`, `register/get_key_provider`).
- Added first provider implementation: `local-embedded`.
- Protection flow now emits provider-based key references instead of ad hoc raw local key-part tuples.
- Runtime decryption templates now resolve key material via provider key references and retain backward compatibility for historical payload shape.
- `build_manifest.json` now includes `key_management` metadata for runtime delivery audits.

Residual risk:

- remote-KMS provider contract stub is implemented (`ENC-P1-010`), but live unwrap/network integration is intentionally fail-closed until a real KMS client is added.
- `license-file` mode is now available.
- Native-loader hardening has started (`ENC-P1-011` iteration slice):
  - protected stubs can now enforce native runtime module loading (`runtime_delivery.loader_mode = native-extension-required`) and fail closed when runtime resolves to pure Python.
  - compiled-flow integration coverage now includes both native-loader success and Python-runtime substitution fail-closed behavior.
  - decrypt runtime execution now zeroizes key buffers after decrypt/exec in runtime implementations and generated templates.
  - runtime trust-boundary checks now enforce runtime module identity/origin/path constraints under native-loader mode:
    - runtime module name must match expected import target
    - runtime `__spec__.origin` must match runtime `__file__`
    - runtime path must remain in the same package directory as the protected module
    - runtime API marker/version contract is validated before decrypt execution
  - `build_manifest.json` runtime delivery metadata now records trust policy (`trust_policy`) and validation defaults are backfilled for older manifests.
  - runtime authenticity is now bound to per-build compiled-runtime identity metadata:
    - `validate_runtime_delivery` records `runtime_delivery.compiled_runtime_fingerprints[]` with per-runtime `sha256` digests and relative paths
    - native-loader stubs verify loaded runtime artifact digest/path against manifest metadata and fail closed on mismatch
  - compile/runtime packaging-policy guardrails are now implemented:
    - runtime trust policy supports explicit suffix controls (`runtime_suffix_policy`, `runtime_native_suffixes`) and rejects mixed-platform ambiguity in strict mode.
    - runtime trust policy supports explicit trusted relocation (`runtime_path_policy=trusted-relocation`, `runtime_relocation_allowed`, `trusted_runtime_roots`) with fail-closed root validation.
  - `ENC-P1-011` hardening scope is complete; remaining launch-risk focus shifts to productization (`ENC-P1-012`, `ENC-P1-013`).

## 5. Non-Blocking But Important Gaps

### [DONE][P0] G-004 Signed Manifest Integrity

Build manifest signing and verification is now active for the mainline protection flow.

Resolution status (2026-05-07):

- `build_manifest.json` now supports HMAC-SHA256 signatures with deterministic canonical payload hashing.
- `encryption_helper.py` supports signature generation and verification via:
  - `--manifest-sign-key-file`
  - `--manifest-sign-key-b64`
  - `--manifest-key-id`
  - `--require-manifest-signature`
- Compile/runtime verification path now validates manifest signatures (when configured) and fails on mismatch.
- Tamper detection tests now explicitly prove modified manifests are rejected.
- `soenc.toml` `[keys]` contract now supports:
  - `manifest_sign_key_file`
  - `manifest_key_id`
  - `require_manifest_signature`

### [DONE][P0] G-001 Unified Platform Configuration Contract

`soenc.toml` contract now exists and can drive the core protect/build flow with explicit schema validation and CLI merge precedence.

Resolution status (2026-05-07):

- Added `soenc_config.py` loader with validated sections:
  - `[project]`: target, scope config, namespace behavior, symbol scope
  - `[build]`: output/dist dirs, compile/precheck toggles, python exe, build profile, vcvars path
  - `[keys]`: key mode selection placeholder contract
  - `[package]`: package metadata placeholders
- `encryption_helper.py` now:
  - auto-discovers `./soenc.toml` or accepts `--config`
  - merges config defaults with explicit CLI overrides
  - records config source + key/package metadata in `build_manifest.json`

### [P1] G-002 Weak Product Surface

The current repo still behaves like a set of engineer-facing scripts rather than a single coherent platform product.

Progress status (2026-05-09):

- Operator-facing product documentation baseline is now complete (`ENC-P1-016`):
  - `README.md` now presents `soenc` as the preferred platform entrypoint and centers the mainline release flow.
  - `USAGE_MANUAL.md` now documents the end-to-end operator runbook for `protect/build/verify/package/release`.
  - `QRCODE_AIRGAP_MANUAL.md` now positions airgap/OCR workflows under optional `soenc transport` plugin commands and preserves sidecar-first auto recovery policy.

### [P1] G-003 Incomplete Release Packaging Story

There is no normalized signed release bundle structure for customers or downstream product teams.

Progress status (2026-05-09):

- Release-bundle contract is now implemented for mainline packaging (`ENC-P1-013`):
  - `soenc package` emits versioned `release_bundle.json` (`enc2sop-release-bundle/v1`) alongside copied release artifacts.
  - bundle metadata captures signed-manifest state, runtime fingerprint records, native/runtime/init artifact lists, and key/config/package metadata context.
  - packaging now fails closed if runtime-delivery validation metadata is incomplete when runtime files are present.
  - packaging can enforce signed manifests (`--require-manifest-signature` / `keys.require_manifest_signature`) for release output.
  - license sidecars declared by manifest are treated as required release artifacts and copied with path-safety checks.

## 6. Target Platform Architecture

## 6.1 Target Components

| Component | Responsibility |
| --- | --- |
| `enc2sop.config` | load and validate platform config |
| `enc2sop.protect` | source analysis, protection policy, staging output |
| `enc2sop.runtime` | decrypt runtime and future native loader |
| `enc2sop.build` | build profile selection and native compile orchestration |
| `enc2sop.package` | release bundle creation, manifest signing, verification |
| `enc2sop.keys` | `KeyProvider` abstraction and provider implementations |
| `enc2sop.transport` | optional airgap transport plugin family |
| `enc2sop.cli` | unified command surface |

## 6.2 Target Command Surface

The long-term CLI should converge on commands like:

- `soenc protect`
- `soenc build`
- `soenc package`
- `soenc verify`
- `soenc license issue`
- `soenc transport export`
- `soenc transport recover`

## 6.3 Architectural Principle

Keep the platform as a modular single repository with explicit boundaries, not a new monolith with renamed files.

## 7. Recommended Implementation Order

### Phase A: Structural Stabilization

1. isolate OCR imports and providers
2. split qrcode responsibilities
3. repair runtime compilation chain
4. add end-to-end compiled artifact tests
5. externalize toolchain configuration

### Phase B: Platform Skeleton

1. add unified config contract
2. add unified CLI skeleton
3. normalize build/package/report structure

### Phase C: Security Upgrade

1. signed manifests
2. `KeyProvider` abstraction
3. license-file mode
4. remote-KMS contract
5. native runtime hardening

### Phase D: Optional Transport Upgrade

1. pluginized airgap transport
2. sidecar-first recovery
3. OCR fallback adapters

## 8. Go-Live Gate

Production go-live should not be claimed until the following are true:

- all P0 cards are complete
- end-to-end protected compile/import tests pass
- build profiles work without machine-specific hard-coded paths
- manifest signing is active
- at least one non-local key-control path exists
- qrcode/OCR is no longer part of the mandatory mainline

Current go-live gate note (2026-05-07):

- As of 2026-05-08, the non-local key-control gate item is satisfied via `ENC-P1-009` (`license-file` provider path).
- As of 2026-05-08, `ENC-P1-010` is completed as a selectable `remote-kms` contract stub with explicit request/response/retry/error policy metadata and fail-closed runtime behavior.
- As of 2026-05-08, `ENC-P1-011` has an initial native-loader enforcement slice in place (config/CLI + manifest loader policy + fail-closed loader guard in protected stubs) but still requires deeper runtime-native hardening before completion.
- As of 2026-05-08 (iteration 2), native-loader compiled-flow integration tests are in place (compiled success + Python runtime substitution fail path), and runtime key buffer zeroization is applied in decrypt execution paths.
- As of 2026-05-08 (iteration 3), runtime native-loader trust boundaries are tightened with fail-closed module-name/origin/path checks and runtime API marker/version contract validation.
- As of 2026-05-09 (iteration 4), runtime authenticity is bound to manifest-linked compiled runtime fingerprints, and native-loader stubs fail closed on runtime digest/path mismatch.
- As of 2026-05-09 (iteration 5), `ENC-P1-011` is completed with explicit mixed-platform suffix policy and trusted-relocation guardrails enforced in both runtime-delivery validation and native-loader stubs.
- With `ENC-P1-012` through `ENC-P1-015` complete, no open P0 technical gate items remain; remaining launch-readiness focus is operator documentation/runbook completion (`ENC-P1-016`).
- As of 2026-05-09 (iteration 8), `ENC-P1-014` is completed with optional transport plugin wiring:
  - unified CLI now exposes `soenc transport ...` through an explicit plugin registry and transport plugin entrypoint.
  - transport command loading is fail-closed and isolated from mainline protect/build/package/verify command paths.
  - mainline platform command surface remains independent from OCR transport plugin availability.
- As of 2026-05-09 (iteration 9), `ENC-P1-015` is completed with sidecar-first recovery ordering hardening:
  - auto recovery/extraction now deterministically prioritizes sidecar decode before OCR providers.
  - manifest-guided structured extraction is preferred ahead of external/generic OCR when manifest structure is available.
  - external OCR provider path remains optional and now sits behind sidecar/structured candidates but ahead of generic OCR fallback when sidecar is unavailable.
- As of 2026-05-09 (iteration 10), `ENC-P1-016` is completed:
  - operator-facing mainline runbooks are aligned to unified `soenc protect/build/package/verify` command paths.
  - transport workflows are documented as optional plugin scope (`soenc transport ...`) and no longer presented as mandatory product flow.
  - remaining launch risk is shifted from baseline documentation gaps to final operational rollout execution and release governance.
- As of 2026-05-09 (iteration 11), `ENC-P0-009` release-governance slice is completed:
  - unified CLI now includes first-class `soenc release` command for mainline handoff gate execution.
  - release command fail-closes on release bundle/manifest/runtime-integrity mismatch and writes `release_receipt.json`.
  - release runtime artifacts are re-verified via fingerprint hash checks at handoff time.
  - `soenc.toml` now supports `[build].release_dir` alias for release output routing (mutually exclusive with `dist_dir`).
- As of 2026-05-09 (iteration 12), `ENC-P0-010` release approval gate slice is completed:
  - `soenc release` now supports an optional fail-closed signed approval policy for CI promotion/signoff workflows.
  - release approval metadata is bound to the exact `release_bundle.json` digest and verified by HMAC signature before receipt generation.
  - `soenc.toml` now supports `[release]` policy defaults (`require_approval`, `approval_file`, `approval_key_file`, `approval_key_id`).
  - `release_receipt.json` now records approval verification state for downstream audit.
- As of 2026-05-10 (iteration 13), `ENC-P0-011` CI-promotion artifact generation slice is completed:
  - unified CLI now includes `soenc approve-release` for deterministic generation of signed `release_approval.json`.
  - approval artifact generation is fail-closed on missing approval signing key or empty approver set.
  - generated approval metadata is explicitly bound to current `release_bundle.json` digest before release gate execution.
  - operator runbook now defines `package -> approve-release -> release` as the promotion-signoff sequence.
- As of 2026-05-10 (iteration 14), `ENC-P0-012` CI promotion enforcement slice is completed:
  - added `.github/workflows/release_promotion.yml` as a fail-closed promotion workflow on `main` and `release/**`.
  - workflow now executes `soenc approve-release` using CI-managed approval key secret and then enforces `soenc release --require-release-approval`.
  - promotion artifacts (`release_bundle.json`, `release_approval.json`, `release_receipt.json`) are always uploaded with `if-no-files-found: error`.
  - operator runbook now includes rollout/rollback checklist for protected-environment reviewers and approval-key rotation custody.
- As of 2026-05-10 (iteration 15), `ENC-P0-013` promotion rollout audit slice is completed:
  - unified CLI now includes `soenc audit-promotion` for fail-closed validation of branch protection/environment-reviewer/approval-secret rollout evidence.
  - repository now includes baseline promotion policy contract `docs/PROMOTION_ROLLOUT_POLICY.json` with required checks for `main`, `release/**`, `production-promotion`, and `SOENC_RELEASE_APPROVAL_KEY_B64`.
  - audit output now writes machine-readable `promotion_audit_report.json` with categorized failure reasons for operational readiness gating.
  - remaining launch risk is reduced to external platform-state execution (actual branch/environment settings and secret custody), with repository enforcement and policy verification now codified.
- As of 2026-05-10 (iteration 16), `ENC-P0-014` promotion evidence collection automation is completed:
  - unified CLI now includes `soenc collect-promotion-evidence` to gather policy-targeted rollout evidence from GitHub APIs without manual JSON assembly.
  - evidence collector writes `enc2sop-promotion-evidence/v1` payloads directly consumable by `soenc audit-promotion`.
  - collector is fail-closed on missing branch-rule/status-check rollout objects, missing required secret visibility evidence, and GitHub API permission/access failures.
  - operational launch risk is now primarily external rollout execution discipline (actual branch protection, environment reviewers, and secret custody), with automated evidence generation/audit enforcement codified in-repo.
- As of 2026-05-10 (iteration 17), `ENC-P0-015` promotion dry-run gate orchestration is completed:
  - unified CLI now includes `soenc promotion-dry-run` to execute promotion evidence collection and policy audit as one fail-closed command.
  - dry-run command supports:
    - online mode (`collect-promotion-evidence` + `audit-promotion` in one call),
    - offline mode (`--skip-collect`) for auditing pre-collected evidence artifacts.
  - command returns non-zero when collection requirements fail, policy audit fails, or required evidence file is missing in offline mode.
  - operator docs now define `promotion-dry-run` as the preferred rollout-validation gate before protected branch promotion activation.
- As of 2026-05-10 (iteration 18), `ENC-P0-016` has an execution-ready CI vertical slice landed:
  - `.github/workflows/release_promotion.yml` now runs `soenc promotion-dry-run` after signed release gate enforcement and uploads `promotion_evidence.json` + `promotion_audit_report.json` artifacts.
  - workflow now supports rehearsal controls through `workflow_dispatch` inputs:
    - `skip_promotion_collect` for offline audit mode on pre-collected evidence,
    - `rotation_rehearsal` for stale-key rejection verification.
  - optional stale-key rehearsal now fail-closes when enabled:
    - requires `SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64`,
    - fails the workflow if old-key validation unexpectedly passes.
  - remaining launch risk is external operational execution:
    - real protected-branch/environment run evidence,
    - real key-rotation rehearsal artifacts and rollback-proof records.
- As of 2026-05-10 (iteration 19), `ENC-P0-016` adds structured rotation rehearsal evidence capture in CI:
  - promotion workflow now emits `rotation_rehearsal_report.json` (`enc2sop-rotation-rehearsal/v1`) with explicit requested/executed/outcome/status fields.
  - stale-key rehearsal fail states (`blocked`/`failed`) and pass state (`passed`) are persisted as artifacts.
  - artifact upload now runs under `always()` so rehearsal evidence is retained even on fail-closed execution.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-10 (iteration 20), `ENC-P0-016` adds fail-closed promotion artifact integrity verification in CI:
  - unified CLI now includes `soenc verify-promotion-artifacts` for schema/integrity validation of:
    - `release_bundle.json`, `release_approval.json`, `release_receipt.json`,
    - `promotion_evidence.json`, `promotion_audit_report.json`,
    - `rotation_rehearsal_report.json`.
  - promotion workflow now executes `verify-promotion-artifacts` after `promotion-dry-run` and optional rotation rehearsal, and enforces `--require-rotation-pass` during rotation rehearsal runs.
  - promotion policy workflow-fragment contract now requires `verify-promotion-artifacts` command presence.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-10 (iteration 21), `ENC-P0-016` adds deterministic promotion run receipt evidence capture:
  - `soenc verify-promotion-artifacts` now emits `promotion_run_receipt.json` (`enc2sop-promotion-run-receipt/v1`) by default.
  - run receipt includes SHA256 digests for release/promotion/rotation/audit artifacts plus GitHub run context (`GITHUB_RUN_ID`, `GITHUB_SHA`, `GITHUB_REF`, when present).
  - promotion workflow now exposes `promotion_artifact_audit_report_file` and `promotion_run_receipt_file` inputs, passes them into `verify-promotion-artifacts`, and uploads both artifacts under `always()`.
  - promotion policy workflow-fragment contract now requires promotion run receipt wiring fragments.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-10 (iteration 22), `ENC-P0-016` adds fail-closed CI-context binding for archived promotion evidence:
  - `collect-promotion-evidence` now records `github_context` in `promotion_evidence.json`.
  - `soenc verify-promotion-artifacts` now supports `--require-ci-context-match` to enforce evidence/run identity consistency:
    - requires `promotion_evidence.github_context` values for `GITHUB_REPOSITORY`, `GITHUB_REF`, and `GITHUB_RUN_ID` to match the current workflow run,
    - enforces `GITHUB_SHA` match when both evidence and runtime SHA values are present.
  - promotion workflow now enables `--require-ci-context-match` for the CI artifact integrity gate.
  - promotion policy contract now requires `--require-ci-context-match` workflow fragment presence.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-10 (iteration 23), `ENC-P0-016` adds fail-closed promotion-report input digest binding:
  - `soenc audit-promotion` now writes `inputs` metadata into `promotion_audit_report.json`, including absolute input file paths and SHA256 digests for:
    - policy file,
    - evidence file,
    - workflow file.
  - `soenc verify-promotion-artifacts` now validates that `promotion_audit_report.inputs` binds to the exact `promotion_evidence.json` artifact under verification:
    - `inputs.evidence_file` must match the audited evidence path,
    - `inputs.evidence_sha256` must match the current evidence file digest.
  - this closes the tamper window where an audit pass report could previously be reused against a different evidence payload.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-11 (iteration 24), `ENC-P0-016` adds fail-closed policy/workflow digest binding at the promotion artifact gate:
  - `soenc verify-promotion-artifacts` now validates `promotion_audit_report.inputs` against all three audited inputs under verification:
    - `inputs.policy_file` + `inputs.policy_sha256`,
    - `inputs.workflow_file` + `inputs.workflow_sha256`,
    - `inputs.evidence_file` + `inputs.evidence_sha256`.
  - CI workflow now wires shared policy/workflow inputs across both `promotion-dry-run` and `verify-promotion-artifacts`:
    - `promotion_policy_file` -> `PROMOTION_POLICY_FILE`,
    - `promotion_workflow_file` -> `PROMOTION_WORKFLOW_FILE`.
  - promotion policy contract now requires these workflow fragments.
  - this closes the remaining audit-input substitution window where policy/workflow files could diverge between audit and artifact verification.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-11 (iteration 25), `ENC-P0-016` tightens strict CI-context replay resistance for archived promotion evidence:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now additionally enforces `GITHUB_RUN_ATTEMPT` match when both runtime and evidence context values are present.
  - promotion policy workflow-fragment contract now requires `GITHUB_RUN_ATTEMPT` wiring visibility.
  - this reduces replay ambiguity across repeated workflow attempts of the same run while preserving compatibility for evidence payloads that omit run-attempt context.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-11 (iteration 26), `ENC-P0-016` adds rotation-report CI-context binding under strict artifact verification:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now validates rotation rehearsal report run metadata against current workflow context:
    - `workflow_run_id` vs `GITHUB_RUN_ID`,
    - `workflow_ref` vs `GITHUB_REF`,
    - `workflow_sha` vs `GITHUB_SHA`,
    - `workflow_run_attempt` vs `GITHUB_RUN_ATTEMPT`.
  - verification now fail-closes on missing/mismatched rotation metadata for available runtime context keys, reducing stale rotation-report replay risk.
  - promotion policy workflow-fragment contract now requires these rotation metadata fragments in `.github/workflows/release_promotion.yml`.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-11 (iteration 28), `ENC-P0-016` adds pre-existing run-receipt CI-context binding under strict artifact verification:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now also validates `promotion_run_receipt.github_context` when a prior `promotion_run_receipt.json` exists before rewrite.
  - verification fail-closes when required identity keys mismatch (`GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_RUN_ID`) and when optional run keys mismatch where both sides are present (`GITHUB_SHA`, `GITHUB_RUN_ATTEMPT`).
  - this tightens replay resistance for archived/tampered run-receipt reuse across protected-branch reruns.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-11 (iteration 29), `ENC-P0-016` tightens strict CI-context governance binding for archived promotion evidence:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now requires workflow/event binding (`GITHUB_WORKFLOW`, `GITHUB_EVENT_NAME`) for:
    - `promotion_evidence.github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal evidence binding now includes:
    - `rotation_rehearsal_report.workflow_name` vs `GITHUB_WORKFLOW`,
    - `rotation_rehearsal_report.workflow_event` vs `GITHUB_EVENT_NAME`.
  - `.github/workflows/release_promotion.yml` now writes `workflow_name` and `workflow_event` into `rotation_rehearsal_report.json` for both initialization and executed rehearsal states.
  - this reduces acceptance risk for artifacts produced from non-governed workflow/event contexts while preserving compatibility for optional SHA/run-attempt checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-11 (iteration 30), `ENC-P0-016` adds cryptographic release-approval signature verification to the promotion artifact gate:
  - `soenc verify-promotion-artifacts` now supports release-approval signature verification inputs:
    - `--release-approval-key-file`,
    - `--release-approval-key-b64`,
    - `--release-approval-key-id`,
    - `--require-release-approval-signature`.
  - promotion artifact validation now verifies `release_approval.signature.digest_hex` against canonical payload bytes when a verification key is provided, and fail-closes when signature verification is required but key material is missing.
  - CI promotion workflow now enforces release-approval signature verification in the artifact gate using CI approval-key inputs.
  - promotion workflow policy contract now requires release-approval signature verification fragments.
  - this closes the residual gap where artifact verification previously checked approval schema/digest binding but did not enforce cryptographic signature verification at that final CI artifact gate.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-11 (iteration 31), `ENC-P0-016` adds release-receipt provenance binding to the promotion artifact gate:
  - `release_receipt.json` now records:
    - `release_bundle_sha256`,
    - `release_approval_sha256`,
    - `release_approval_signature_digest`.
  - `soenc verify-promotion-artifacts` now fail-closes when the release receipt does not bind to the current archived `release_bundle.json` and `release_approval.json`, or when receipt approval key/signature metadata diverges from `release_approval.json`.
  - this closes a remaining artifact-substitution window where an old receipt with `release_approval_verified=true` could be reused against a different approval artifact.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-11 (iteration 32), `ENC-P0-016` adds signed release-approval CI-context provenance binding:
  - `release_approval.json` now includes available GitHub workflow context in the signed approval payload.
  - `release_receipt.json` now records `release_approval_github_context` after signed approval validation.
  - `soenc verify-promotion-artifacts --require-ci-context-match` now fail-closes when release approval provenance or receipt-mirrored approval provenance does not match the current governed workflow run.
  - this reduces replay risk for otherwise valid approvals generated by a different workflow, event, branch, run, or run attempt.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

## 9. Assessment Status

Status: `[APPROVED BASELINE]`

This file is the current architectural truth for future iterations until a later iteration updates it explicitly.


