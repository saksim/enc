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
  - verification fail-closes when required identity keys mismatch (`GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_RUN_ID`) and when run keys mismatch where both sides are present (`GITHUB_SHA`, `GITHUB_RUN_ATTEMPT`).
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
  - this reduces acceptance risk for artifacts produced from non-governed workflow/event contexts while preserving compatibility for optional run-hash/attempt checks.
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
- As of 2026-05-12 (iteration 34), `ENC-P0-016` adds workflow-definition provenance binding under strict CI-context verification:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now treats `GITHUB_WORKFLOW_REF` and `GITHUB_WORKFLOW_SHA` as required workflow-definition context keys (in addition to `GITHUB_WORKFLOW` and `GITHUB_EVENT_NAME`) for:
    - `promotion_evidence.github_context`,
    - signed release approval/receipt provenance context,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal verification now also fail-closes on workflow-definition metadata mismatch:
    - `rotation_rehearsal_report.workflow_name_ref` vs `GITHUB_WORKFLOW_REF`,
    - `rotation_rehearsal_report.workflow_name_sha` vs `GITHUB_WORKFLOW_SHA`.
  - CI workflow/policy contracts now require these workflow-definition fragments in emitted rotation evidence and rollout policy enforcement checks.
  - this reduces acceptance risk for artifacts produced from a divergent workflow file revision/reference despite matching workflow name/event.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-12 (iteration 35), `ENC-P0-016` adds strict CI-runtime context completeness enforcement:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now fail-closes when required runtime binding keys are missing from the current workflow environment.
  - required strict runtime keys now include:
    - identity keys: `GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_RUN_ID`
    - workflow-definition/event keys: `GITHUB_WORKFLOW`, `GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`, `GITHUB_EVENT_NAME`
  - this removes a permissive gap where absent runtime workflow binding values could avoid strict mismatch checks and still permit partial-context verification.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-12 (iteration 36), `ENC-P0-016` adds strict protected-ref governance provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now enforces `GITHUB_REF_PROTECTED` runtime binding completeness and fail-closes when missing.
  - strict CI-context artifact checks now validate protected-ref parity for:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind `rotation_rehearsal_report.workflow_ref_protected` against `GITHUB_REF_PROTECTED`.
  - evidence/approval context capture now includes `GITHUB_REF_PROTECTED`, and CI workflow/policy contracts now require rotation report protected-ref metadata emission.
  - this reduces acceptance risk for replay/substitution of artifacts generated outside protected-ref enforcement posture while preserving optional semantics when protected-ref data is not present in both compared artifacts.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-12 (iteration 37), `ENC-P0-016` adds strict CI-context job-level provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now enforces `GITHUB_JOB` runtime binding completeness and fail-closes when missing.
  - strict CI-context artifact checks now validate job parity for:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind `rotation_rehearsal_report.workflow_job` against `GITHUB_JOB`.
  - evidence/approval context capture now includes `GITHUB_JOB`, and CI workflow/policy contracts now require rotation report job metadata emission.
  - this reduces acceptance risk for replay/substitution of artifacts generated under a different workflow job identity inside the same governed run context.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-12 (iteration 38), `ENC-P0-016` adds strict CI-context actor-level provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now enforces `GITHUB_ACTOR` runtime binding completeness and fail-closes when missing.
  - strict CI-context artifact checks now validate actor parity for:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind `rotation_rehearsal_report.workflow_actor` against `GITHUB_ACTOR`.
  - evidence/approval context capture now includes `GITHUB_ACTOR`, and CI workflow/policy contracts now require rotation report actor metadata emission.
  - this reduces acceptance risk for replay/substitution of artifacts generated under a different GitHub actor identity inside the same governed run context.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-12 (iteration 39), `ENC-P0-016` adds strict CI-context numeric identity provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now enforces runtime completeness and strict parity checks for:
    - `GITHUB_ACTOR_ID`,
    - `GITHUB_REPOSITORY_ID`.
  - strict numeric identity checks now apply across:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_actor_id` vs `GITHUB_ACTOR_ID`,
    - `rotation_rehearsal_report.workflow_repository_id` vs `GITHUB_REPOSITORY_ID`.
  - CI workflow/policy contracts now require these numeric identity fragments in emitted rotation evidence and rollout policy checks.
  - this reduces acceptance risk for replay/substitution across renamed/recycled actor or repository-name contexts by binding to stable numeric GitHub identities.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-12 (iteration 40), `ENC-P0-016` adds strict CI-context triggering-actor provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now captures and validates `GITHUB_TRIGGERING_ACTOR`.
  - strict triggering-actor checks now apply across:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_triggering_actor` vs `GITHUB_TRIGGERING_ACTOR`.
  - CI workflow/policy contracts now require triggering-actor fragments in emitted rotation evidence and rollout policy checks.
  - this reduces acceptance risk for replay/substitution across rerun/manual-dispatch actor context while preserving fail-closed behavior for governed runtime context keys.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-12 (iteration 41), `ENC-P0-016` adds strict CI-context repository-owner provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now enforces runtime completeness and strict parity checks for:
    - `GITHUB_REPOSITORY_OWNER`,
    - `GITHUB_REPOSITORY_OWNER_ID`.
  - strict repository-owner checks now apply across:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_repository_owner` vs `GITHUB_REPOSITORY_OWNER`,
    - `rotation_rehearsal_report.workflow_repository_owner_id` vs `GITHUB_REPOSITORY_OWNER_ID`.
  - CI workflow/policy contracts now require these repository-owner fragments in emitted rotation evidence and rollout policy checks.
  - this reduces acceptance risk for replay/substitution across ownership-boundary changes by binding artifact provenance to both owner slug and stable owner ID.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-12 (iteration 42), `ENC-P0-016` adds strict CI-host/API provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now enforces runtime completeness and strict parity checks for:
    - `GITHUB_SERVER_URL`,
    - `GITHUB_API_URL`,
    - `GITHUB_GRAPHQL_URL`.
  - strict host/API checks now apply across:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_server_url` vs `GITHUB_SERVER_URL`,
    - `rotation_rehearsal_report.workflow_api_url` vs `GITHUB_API_URL`,
    - `rotation_rehearsal_report.workflow_graphql_url` vs `GITHUB_GRAPHQL_URL`.
  - CI workflow/policy contracts now require these host/API fragments in emitted rotation evidence and rollout policy checks.
  - this reduces acceptance risk for replay/substitution across mismatched GitHub host/API surfaces (for example GHES-to-dotcom or API endpoint drift) even when workflow/job/actor identity keys match.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 43), `ENC-P0-016` upgrades strict CI replay resistance by requiring run-hash/attempt completeness:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now treats `GITHUB_SHA` and `GITHUB_RUN_ATTEMPT` as required runtime binding keys (not optional parity-only checks).
  - strict CI-context artifact checks now require and validate `GITHUB_SHA` + `GITHUB_RUN_ATTEMPT` parity for:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - this closes a remaining permissive path where strict-mode verification could proceed when run hash/attempt runtime context was absent and only later optional mismatch checks applied.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 44), `ENC-P0-016` adds strict CI run-ordinal provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now treats `GITHUB_RUN_NUMBER` as a required runtime binding key.
  - strict CI-context artifact checks now require and validate `GITHUB_RUN_NUMBER` parity for:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_run_number` vs `GITHUB_RUN_NUMBER`.
  - CI workflow/policy contracts now require `workflow_run_number` emission and `GITHUB_RUN_NUMBER` workflow fragment presence.
  - this reduces acceptance risk for replay/substitution across different workflow run ordinals that could otherwise share adjacent context values.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 45), `ENC-P0-016` adds strict branch-ref provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now treats `GITHUB_REF_NAME` and `GITHUB_REF_TYPE` as required runtime binding keys.
  - strict CI-context artifact checks now require and validate `GITHUB_REF_NAME` + `GITHUB_REF_TYPE` parity for:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_ref_name` vs `GITHUB_REF_NAME`,
    - `rotation_rehearsal_report.workflow_ref_type` vs `GITHUB_REF_TYPE`.
  - CI workflow/policy contracts now require `workflow_ref_name`/`workflow_ref_type` emission and `GITHUB_REF_NAME`/`GITHUB_REF_TYPE` workflow fragment presence.
  - this reduces acceptance risk for replay/substitution across branch/tag-name context drift while preserving strict runtime completeness guarantees.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 46), `ENC-P0-016` adds cryptographic promotion run-receipt signing and verification:
  - `soenc verify-promotion-artifacts` now signs emitted `promotion_run_receipt.json` with HMAC-SHA256 when release-approval verification key inputs are provided, binding:
    - receipt-level metadata (`passed`, `rotation_pass_required`, report path),
    - GitHub context snapshot,
    - required artifact digest rows.
  - pre-existing run receipt verification now fail-closes under signature-required policy on:
    - missing/invalid `promotion_run_receipt.signature`,
    - key-id mismatch between receipt metadata and expected promotion approval key id,
    - signature digest mismatch against canonical receipt payload.
  - this reduces replay/tamper risk for archived run receipts between collection and re-verification, complementing existing artifact row/path digest checks and strict CI-context binding.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 47), `ENC-P0-016` adds strict CI runtime-activation provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now treats `GITHUB_ACTIONS` and `CI` as required runtime binding keys.
  - strict CI-context artifact checks now require and validate `GITHUB_ACTIONS` + `CI` parity for:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_github_actions` vs `GITHUB_ACTIONS`,
    - `rotation_rehearsal_report.workflow_ci` vs `CI`.
  - CI workflow/policy contracts now require `workflow_github_actions` / `workflow_ci` emission and `GITHUB_ACTIONS` / `CI` workflow fragment presence.
  - this reduces acceptance risk for replay/substitution of archived artifacts produced outside actual CI runtime activation context while preserving broader strict-context provenance controls.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 48), `ENC-P0-016` adds strict CI runner-execution provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now enforces runtime completeness and strict parity checks for:
    - `RUNNER_ENVIRONMENT`,
    - `RUNNER_OS`,
    - `RUNNER_ARCH`.
  - strict runner-key checks now apply across:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_runner_environment` vs `RUNNER_ENVIRONMENT`,
    - `rotation_rehearsal_report.workflow_runner_os` vs `RUNNER_OS`,
    - `rotation_rehearsal_report.workflow_runner_arch` vs `RUNNER_ARCH`.
  - CI workflow/policy contracts now require these runner provenance fragments in emitted rotation evidence and rollout policy checks.
  - this reduces acceptance risk for replay/substitution across divergent runner execution posture (for example self-hosted vs github-hosted and OS/arch drift) even when repository/workflow identity keys match.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 49), `ENC-P0-016` adds strict release-execution provenance binding:
  - `release_receipt.json` now records `github_context` captured at release-gate execution time.
  - `soenc verify-promotion-artifacts --require-ci-context-match` now requires and validates `release_receipt.github_context` against current governed workflow context, in addition to existing approval/evidence/rotation/run-receipt checks.
  - this reduces replay/substitution risk where a receipt with valid digest fields could still originate from a different CI runtime context than the current governed run.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 50), `ENC-P0-016` adds offline-capable cross-artifact context consistency enforcement:
  - `soenc verify-promotion-artifacts` now supports `--require-artifact-context-consistency` to fail-close mixed-artifact replay/substitution even when runtime CI context binding is not available.
  - consistency root is archived `promotion_evidence.github_context`; strict parity + required-key completeness is enforced against:
    - `release_approval.github_context`,
    - `release_receipt.github_context`,
    - `release_receipt.release_approval_github_context`,
    - `rotation_rehearsal_report` projected `workflow_*` context,
    - pre-existing `promotion_run_receipt.github_context`.
  - release promotion workflow now enables this flag by default and rollout policy fragment contract requires it.
  - this strengthens provenance integrity for offline evidence-package validation and archive re-verification use cases.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 51), `ENC-P0-016` adds promotion-evidence repository identity binding:
  - `soenc verify-promotion-artifacts` now validates `promotion_evidence.repository` (when present) as an `owner/repo` slug and requires it to match `promotion_evidence.github_context.GITHUB_REPOSITORY`.
  - under `--require-ci-context-match`, verification now also requires `promotion_evidence.repository` (when present) to match runtime `GITHUB_REPOSITORY`.
  - strict rotation-report metadata binding now additionally includes `workflow_repository` vs runtime `GITHUB_REPOSITORY`.
  - CI workflow/policy contracts now require `workflow_repository` emission in `rotation_rehearsal_report.json`.
  - this closes a remaining substitution window where inconsistent repository identity fields across evidence/context artifacts could pass previous checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 52), `ENC-P0-016` closes strict protected-ref completeness for non-rotation artifact contexts:
  - under `--require-ci-context-match`, `soenc verify-promotion-artifacts` now fail-closes when runtime `GITHUB_REF_PROTECTED` is present but artifact contexts omit it.
  - protected-ref key completeness now applies consistently across:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - `release_receipt.github_context`,
    - pre-existing `promotion_run_receipt.github_context`,
    - existing rotation-report check for `workflow_ref_protected`.
  - this closes a permissive path where strict mode could previously pass missing `GITHUB_REF_PROTECTED` in artifact contexts (except rotation report), reducing replay/substitution risk across protected/non-protected ref provenance boundaries.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.
- As of 2026-05-13 (iteration 53), `ENC-P0-016` closes strict protected-ref value-validation gaps:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now fail-closes when runtime `GITHUB_REF_PROTECTED` is present but not parseable as an explicit boolean-like value (`true/false`, `1/0`, `yes/no`, `on/off`).
  - `soenc verify-promotion-artifacts --require-artifact-context-consistency` now fail-closes when `promotion_evidence.github_context.GITHUB_REF_PROTECTED` is present but not parseable as an explicit boolean-like value.
  - this reduces provenance ambiguity and replay/substitution tolerance caused by malformed protected-ref encodings being treated as empty/missing values during strict verification.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-13 (iteration 54), `ENC-P0-016` adds strict runner-instance provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now enforces runtime completeness and strict parity checks for:
    - `RUNNER_NAME` (in addition to existing runner environment/os/arch keys).
  - strict runner-instance checks now apply across:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - `release_receipt.github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_runner_name` vs `RUNNER_NAME`.
  - CI workflow/policy contracts now require `workflow_runner_name` emission and `RUNNER_NAME` workflow fragment presence.
  - this reduces acceptance risk for replay/substitution across runner-instance identity drift within the same runner class (for example same OS/arch/environment but different runner host instance).
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 55), `ENC-P0-016` closes strict triggering-actor completeness under CI-context matching:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now fail-closes when runtime `GITHUB_TRIGGERING_ACTOR` is present but governed artifact contexts omit it.
  - triggering-actor key completeness/parity now applies consistently across:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - `release_receipt.github_context`,
    - `rotation_rehearsal_report.workflow_triggering_actor`,
    - pre-existing `promotion_run_receipt.github_context`.
  - this closes a permissive path where strict mode could previously accept missing triggering-actor provenance in artifact payloads even when runtime supplied rerun/dispatch actor identity.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 56), `ENC-P0-016` closes strict CI-activation boolean value-validation gaps:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now fail-closes when runtime `GITHUB_ACTIONS` or `CI` is present but not parseable as explicit boolean-like values (`true/false`, `1/0`, `yes/no`, `on/off`).
  - strict governed artifact contexts now also fail-close on invalid `GITHUB_ACTIONS`/`CI` values for:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - `release_receipt.github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - `soenc verify-promotion-artifacts --require-artifact-context-consistency` now fail-closes when `promotion_evidence.github_context` carries invalid `GITHUB_ACTIONS` or `CI` value encodings.
  - this removes a permissive path where malformed CI-activation values could previously satisfy strict context checks by string equality instead of explicit boolean semantics.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 57), `ENC-P0-016` adds strict CI retention-window provenance binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now treats `GITHUB_RETENTION_DAYS` as a required runtime binding key.
  - strict CI-context artifact checks now require and validate `GITHUB_RETENTION_DAYS` parity for:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - `release_receipt.github_context`,
    - pre-existing `promotion_run_receipt.github_context`.
  - rotation rehearsal strict checks now bind:
    - `rotation_rehearsal_report.workflow_retention_days` vs `GITHUB_RETENTION_DAYS`.
  - CI workflow/policy contracts now require retention-window provenance emission and fragment presence in rollout checks.
  - this reduces acceptance risk for replay/substitution across runs with different artifact-retention policy windows, strengthening archived-evidence provenance parity.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 58), `ENC-P0-016` adds strict CI numeric/ref-type value-validation binding:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now fail-closes invalid value encodings for:
    - `GITHUB_RUN_ID`,
    - `GITHUB_RUN_ATTEMPT`,
    - `GITHUB_RUN_NUMBER`,
    - `GITHUB_RETENTION_DAYS`,
    - `GITHUB_ACTOR_ID`,
    - `GITHUB_REPOSITORY_ID`,
    - `GITHUB_REPOSITORY_OWNER_ID`,
    - `GITHUB_REF_TYPE` (must be `branch` or `tag`).
  - strict governed artifact contexts now also fail-close on invalid encodings for the same keys across:
    - `promotion_evidence.github_context`,
    - signed `release_approval.github_context`,
    - mirrored `release_receipt.release_approval_github_context`,
    - `release_receipt.github_context`,
    - pre-existing `promotion_run_receipt.github_context`,
    - rotation-report projected context checks.
  - `soenc verify-promotion-artifacts --require-artifact-context-consistency` now fail-closes when `promotion_evidence.github_context` carries invalid numeric/ref-type value encodings before parity checks.
  - this removes a permissive path where malformed numeric/ref-type identity values could pass strict provenance checks by string parity alone without semantic validity.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 59), `ENC-P0-016` closes strict rotation-report semantic-validation parity:
  - `soenc verify-promotion-artifacts --require-ci-context-match` now applies the same key-aware semantic normalization/fail-closed behavior to `rotation_rehearsal_report.workflow_*` bindings that is used for runtime and other artifact contexts.
  - strict rotation metadata checks now normalize/validate:
    - boolean-like keys (`workflow_github_actions`, `workflow_ci`, `workflow_ref_protected`),
    - positive-integer identity keys (`workflow_run_id`, `workflow_run_attempt`, `workflow_run_number`, `workflow_retention_days`, `workflow_actor_id`, `workflow_repository_id`, `workflow_repository_owner_id`),
    - enum keys (`workflow_ref_type`),
    - and existing identity/binding string keys.
  - invalid rotation-report encodings now fail closed with explicit per-key errors instead of relying on raw-string mismatch behavior.
  - this removes a residual inconsistency where malformed rotation metadata could bypass semantic validation while other strict CI-context artifacts were already fail-closed by type-aware normalization.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 60), `ENC-P0-016` refines strict numeric normalization parity for CI-context provenance:
  - `soenc verify-promotion-artifacts` strict numeric/ref-type context checks now accept and canonically normalize zero-padded positive integer encodings (for example `03`, `011`, `090`) instead of treating them as invalid.
  - this normalization applies consistently to:
    - runtime strict CI-context keys,
    - governed artifact context keys,
    - and `rotation_rehearsal_report.workflow_*` numeric projections under `--require-ci-context-match`.
  - this aligns implementation behavior with existing normalized-equivalence strict-context policy and removes an unnecessary false-negative path for semantically equivalent numeric metadata encodings.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 61), `ENC-P0-016` adds strict GitHub ref semantic validation parity:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close when `GITHUB_REF` does not semantically match `GITHUB_REF_TYPE`.
  - enforced mapping:
    - `GITHUB_REF_TYPE=branch` requires `GITHUB_REF` prefix `refs/heads/`.
    - `GITHUB_REF_TYPE=tag` requires `GITHUB_REF` prefix `refs/tags/`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context under both strict runtime matching and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where malformed ref identity (for example pull-request-style refs paired with `branch`) could pass strict provenance checks as plain string parity.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 62), `ENC-P0-016` adds strict commit-SHA semantic validation parity:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close when `GITHUB_SHA` or `GITHUB_WORKFLOW_SHA` is not a valid 40-character hexadecimal value.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where malformed SHA identity values could pass strict provenance checks as plain string parity.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 63), `ENC-P0-016` adds strict workflow-ref semantic validation parity:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close when `GITHUB_WORKFLOW_REF` is not a valid workflow-ref value.
  - accepted strict format is:
    - `<owner>/<repo>/.github/workflows/<file>.yml@refs/heads/*`, or
    - `<owner>/<repo>/.github/workflows/<file>.yml@refs/tags/*`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where malformed workflow-definition ref identity values could pass strict provenance checks as plain string parity.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-14 (iteration 64), `ENC-P0-016` adds strict ref-name semantic validation parity:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close when `GITHUB_REF_NAME` does not semantically match `GITHUB_REF` + `GITHUB_REF_TYPE`.
  - enforced mapping:
    - `GITHUB_REF_TYPE=branch` requires `GITHUB_REF_NAME` to equal the `refs/heads/` suffix of `GITHUB_REF`.
    - `GITHUB_REF_TYPE=tag` requires `GITHUB_REF_NAME` to equal the `refs/tags/` suffix of `GITHUB_REF`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where malformed/misbound ref-name identity values could pass strict provenance checks through raw key parity.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-15 (iteration 66), `ENC-P0-016` adds strict workflow-definition repository semantic validation parity:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close when `GITHUB_WORKFLOW_REF` references a repository slug that does not match `GITHUB_REPOSITORY`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where workflow-definition repository identity could diverge from repository provenance while still passing raw key parity checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-15 (iteration 67), `ENC-P0-016` adds strict workflow-definition ref semantic validation parity:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close when the `@ref` segment of `GITHUB_WORKFLOW_REF` does not equal `GITHUB_REF`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where workflow-definition ref identity could diverge from run ref provenance while still passing raw key parity checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-15 (iteration 68), `ENC-P0-016` adds strict CI host/API URL semantic validation parity:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close malformed/non-HTTP(S) values for:
    - `GITHUB_SERVER_URL`,
    - `GITHUB_API_URL`,
    - `GITHUB_GRAPHQL_URL`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where host/API provenance fields could be non-empty but malformed while still passing strict parity checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-15 (iteration 69), `ENC-P0-016` adds strict repository-slug semantic validation parity:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close malformed `GITHUB_REPOSITORY` values that are not valid `owner/repo` slugs.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where repository identity could be non-empty but malformed while still passing strict parity checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-15 (iteration 70), `ENC-P0-016` adds strict CI activation and endpoint URL semantic validation parity:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close semantically invalid CI-activation values when parseable but non-activating:
    - `GITHUB_ACTIONS` must normalize to `true`,
    - `CI` must normalize to `true`.
  - strict CI-context checks now enforce endpoint URL relationships between:
    - `GITHUB_SERVER_URL`,
    - `GITHUB_API_URL`,
    - `GITHUB_GRAPHQL_URL`.
  - enforced URL semantics:
    - for `github.com`, API and GraphQL endpoints must map to `api.github.com` with canonical paths (`/` and `/graphql`);
    - for enterprise hosts, API and GraphQL endpoints must stay same-origin with `GITHUB_SERVER_URL` and use expected paths (`/api/v3` and `/api/graphql`);
    - API and GraphQL origins must match each other.
  - this validation now applies consistently across:
    - runtime strict CI-context checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where CI activation fields and host/API provenance fields could be parseable/non-empty but semantically inconsistent with real GitHub Actions runtime endpoints.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-15 (iteration 71), `ENC-P0-016` adds strict CI URL query/fragment fail-closed normalization:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` when URL values include query strings, params, or fragments.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where decorated URL values could pass strict parity checks despite non-canonical provenance encoding.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-15 (iteration 72), `ENC-P0-016` adds strict HTTPS-only CI URL provenance semantics:
  - `soenc verify-promotion-artifacts` strict CI-context URL semantic checks now fail-close `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` when values use non-HTTPS schemes.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where `http://` endpoint values could still satisfy host/path mapping parity checks despite weaker transport provenance.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-15 (iteration 73), `ENC-P0-016` tightens strict repository-slug semantics for CI provenance:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close malformed `GITHUB_REPOSITORY` values unless they are exact two-segment slugs.
  - enforced slug shape now requires:
    - exactly one `/` separator (`owner/repo`),
    - owner and repo segments constrained to `[a-z0-9._-]`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where malformed multi-segment repository identity (for example `owner/repo/extra`) could previously pass strict provenance checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-15 (iteration 74), `ENC-P0-016` tightens strict `GITHUB_WORKFLOW_REF` repository-prefix semantics:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close malformed `GITHUB_WORKFLOW_REF` repository prefixes unless the segment before `/.github/workflows/` is a valid `owner/repo` slug.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where malformed multi-segment workflow-definition repository prefixes (for example `owner/repo/extra/.github/workflows/...`) could previously pass strict provenance key-value validation.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-16 (iteration 75), `ENC-P0-016` tightens strict `GITHUB_WORKFLOW_REF` canonical workflow-path semantics:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close non-canonical workflow-definition paths inside `/.github/workflows/`.
  - strict `GITHUB_WORKFLOW_REF` normalization now rejects:
    - empty workflow path segments,
    - traversal-like segments (`.` / `..`),
    - backslash-separated path segments.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where malformed workflow-definition path encodings could still pass strict provenance key-value checks without canonical path-shape guarantees.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-16 (iteration 76), `ENC-P0-016` tightens strict git-refname provenance semantics:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close invalid git refname values for `GITHUB_REF` (not only ref-type prefix mismatches).
  - strict `GITHUB_WORKFLOW_REF` normalization now also rejects workflow `@ref` segments that are not valid git refnames, even when they satisfy `refs/heads/*` or `refs/tags/*` prefix checks.
  - fail-closed invalid-refname coverage includes:
    - `..` or `@{` fragments,
    - control characters and disallowed git metacharacters,
    - leading-dot or `.lock` path segments,
    - trailing dot or slash.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where malformed refname encodings could pass strict provenance checks through branch/tag prefix shape alone.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-16 (iteration 77), `ENC-P0-016` tightens strict CI URL provenance normalization for credential-bearing endpoints:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` values when URL userinfo is present (for example `https://token@github.com`).
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where credential-bearing endpoint encodings could pass strict provenance key-value checks despite non-canonical CI endpoint identity.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-16 (iteration 80), `ENC-P0-016` tightens strict CI URL path canonicalization:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close non-canonical double-slash path encodings for:
    - `GITHUB_SERVER_URL`,
    - `GITHUB_API_URL`,
    - `GITHUB_GRAPHQL_URL`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where non-canonical endpoint path encodings (for example `https://api.github.com//graphql`) could still satisfy strict provenance key-value checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-16 (iteration 81), `ENC-P0-016` tightens strict CI URL whitespace canonicalization:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` values when they contain leading/trailing whitespace.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where whitespace-decorated endpoint values could normalize into canonical URLs and pass strict provenance key-value checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-16 (iteration 82), `ENC-P0-016` tightens strict `GITHUB_WORKFLOW_REF` canonical workflow-path normalization against encoded traversal bypasses:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close workflow-ref path segments that decode to traversal/separator forms, including:
    - `%2e` / `%2E` (`.`),
    - `%2e%2e` / `%2E%2E` (`..`),
    - decoded segments containing `/` or `\`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where encoded workflow-path traversal-like segments could bypass raw path-segment checks and still satisfy strict provenance key-value validation.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-16 (iteration 83), `ENC-P0-016` tightens strict `GITHUB_WORKFLOW_REF` canonical workflow-path normalization against encoded filename variants:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close workflow-ref path segments containing percent-encoding markers (`%`) even when decoded values are non-traversal.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where encoded workflow filename variants (for example `release%5Fpromotion.yml` and `release%2epromotion.yml`) could normalize into canonical workflow names and still satisfy strict provenance key-value validation.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-17 (iteration 84), `ENC-P0-016` tightens strict CI URL authority canonicalization for empty-port encodings:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` values when the authority contains a trailing colon with no numeric port (for example `https://github.com:`).
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where malformed URL authorities with empty-port syntax could remain parseable and pass strict provenance normalization.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-17 (iteration 85), `ENC-P0-016` tightens strict CI URL path canonicalization for trailing-slash endpoints:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` values when non-root paths end with a trailing slash (for example `https://api.github.com/graphql/`).
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where decorated non-root endpoint values could remain semantically equivalent yet bypass strict canonical provenance binding.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-17 (iteration 86), `ENC-P0-016` tightens strict CI SHA canonicalization:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` values when they contain leading or trailing whitespace.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where whitespace-decorated SHA values could normalize into canonical digests and still satisfy strict provenance key-value checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-17 (iteration 87), `ENC-P0-016` tightens strict CI repository/ref canonicalization:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close `GITHUB_REPOSITORY`, `GITHUB_REF`, and `GITHUB_WORKFLOW_REF` values when they contain leading or trailing whitespace.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where whitespace-decorated repository/ref provenance values could normalize into canonical identity strings and still satisfy strict provenance key-value checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-17 (iteration 88), `ENC-P0-016` tightens strict CI plain-text provenance canonicalization:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close whitespace-decorated plain-text context values (instead of trimming/accepting), including:
    - `GITHUB_EVENT_NAME`,
    - `GITHUB_WORKFLOW`,
    - `GITHUB_JOB`,
    - `GITHUB_ACTOR`.
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where whitespace-decorated textual provenance values could normalize into canonical strings and still satisfy strict provenance key-value checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-17 (iteration 89), `ENC-P0-016` tightens strict CI boolean provenance canonicalization:
  - `soenc verify-promotion-artifacts` strict CI-context checks now fail-close non-canonical boolean aliases for:
    - `GITHUB_ACTIONS`,
    - `CI`,
    - `GITHUB_REF_PROTECTED`.
  - accepted values are now canonical lowercase `true`/`false` only (no `1/0`, `yes/no`, or `on/off` aliases).
  - this validation now applies consistently across:
    - runtime strict CI-context completeness checks,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - this closes a residual permissive path where semantically equivalent truthy/falsy aliases could still satisfy strict provenance checks without deterministic string-level canonical binding.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-18 (iteration 93), Linux pre-production acceptance has completed against a real target project:
  - `scripts/linux_release_acceptance.sh` completed through `[9/9] Acceptance checks passed` for `omniprompt-gateway`.
  - The run exercised the full mainline:
    - `protect -> build -> verify -> package -> approve-release -> release`.
  - The run verified fail-closed behavior for:
    - tampered `release_approval.json`,
    - tampered runtime fingerprint metadata in `build_manifest.json`,
    - post-restore runtime verification.
  - Current launch posture:
    - mainline Linux project packaging is now pre-production-candidate,
    - `ENC-P0-016` remains blocked only by live protected-branch/environment promotion execution and archived CI evidence.
  - next required launch evidence:
    - real `.github/workflows/release_promotion.yml` execution from protected branch/environment,
    - archived promotion evidence, audit report, rotation report, artifact audit report, and run receipt,
    - live old-key rejection rehearsal using real previous approval-key material.

- As of 2026-05-19 (iteration 95), `ENC-P0-016` tightens protected-branch provenance semantics for promotion evidence:
  - `soenc verify-promotion-artifacts` strict CI-context checks now require `GITHUB_REF_PROTECTED=true` (not only parseable presence) across:
    - runtime strict CI-context binding,
    - governed artifact contexts (`promotion_evidence`, release approval/receipt contexts, pre-existing run receipt),
    - rotation-report projected context checks under both strict runtime binding and offline `--require-artifact-context-consistency`.
  - `.github/workflows/release_promotion.yml` now fails early unless `${GITHUB_REF_PROTECTED}` is exactly `true`, preventing unprotected-ref runs from emitting misleading promotion artifacts.
  - this closes a remaining permissive path where strict CI-context parity could still succeed on explicitly unprotected refs (`GITHUB_REF_PROTECTED=false`).
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-19 (iteration 97), `ENC-P0-016` extends operational evidence capture for constrained execution environments:
  - `scripts/github_release_promotion_evidence.sh` now supports `--run-id` (plus optional `--run-attempt`) to archive deterministic promotion evidence from an already-triggered protected-branch workflow run without requiring local dispatch capability.
  - capture receipts now record explicit `capture_mode` (`dispatch` or `existing-run`) and preserve deterministic required-artifact digest verification for both modes.
  - this reduces one practical operational blocker when local environments cannot call `gh workflow run`, while keeping artifact selection and audit replay semantics fail-closed.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-19 (iteration 98), `ENC-P0-016` tightens live promotion evidence-capture run identity validation:
  - `scripts/github_release_promotion_evidence.sh` now resolves run details from `repos/<repo>/actions/runs/<run_id>` and fail-closes on workflow identity mismatches before artifact download.
  - fail-closed checks now cover:
    - valid workflow `path@ref` run identity,
    - expected promotion workflow path parity (when inferable from `--workflow-file`),
    - dispatch event parity (`workflow_dispatch` for newly dispatched runs),
    - allowed event envelope for replay capture (`workflow_dispatch` or `push`),
    - branch parity against expected `--ref` for dispatch (and explicit-ref replay capture),
    - run-attempt parity across summary and run-detail APIs.
  - `promotion_capture_receipt.json` now records richer run identity metadata (`workflow_path`, resolved `workflow_ref` as `path@ref`, `workflow_dispatch_ref`, `workflow_event`, `workflow_head_branch`, `workflow_run_html_url`) for deterministic replay/audit handoff.
  - this reduces residual operator ambiguity when archiving evidence from existing run ids and strengthens provenance observability without weakening any release/promotion integrity gates.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-19 (iteration 99), `ENC-P0-016` tightens live promotion evidence-capture artifact provenance validation:
  - `scripts/github_release_promotion_evidence.sh` now resolves artifact metadata from `repos/<repo>/actions/runs/<run_id>/artifacts` before download and fails closed unless:
    - exactly one expected artifact exists for the run attempt (`soenc-promotion-<run_id>-attempt-<run_attempt>`),
    - artifact is not expired,
    - artifact `workflow_run.id` matches the targeted run id,
    - artifact metadata exposes valid digest (`sha256:<64hex>`) and numeric size.
  - helper now additionally cross-checks summary/detail run parity for `event` and `head_branch` (in addition to `run_attempt`), reducing metadata-source divergence risk before capture.
  - `promotion_capture_receipt.json` now carries expanded deterministic provenance:
    - run identity additions: `workflow_head_sha`, `workflow_run_number`,
    - `artifact_metadata` block (`id`, `digest`, `size_in_bytes`, timestamps, `archive_download_url`, and artifact-linked workflow head/run fields).
  - this reduces residual ambiguity during artifact replay/audit handoff by binding local extracted evidence to upstream GitHub artifact identity metadata, without weakening existing integrity gates.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-19 (iteration 100), `ENC-P0-016` tightens live promotion evidence-capture archive integrity validation:
  - `scripts/github_release_promotion_evidence.sh` now downloads the promotion artifact archive by artifact id and fail-closes unless:
    - downloaded archive SHA256 matches GitHub artifact metadata digest (`sha256:<64hex>`),
    - downloaded archive byte size matches GitHub artifact metadata `size_in_bytes`.
  - archive extraction now occurs only after digest/size parity is verified, reducing residual risk that local extraction state is trusted without byte-level archive identity validation.
  - `promotion_capture_receipt.json` now records `artifact_archive_verification` (`path`, `digest_verified`, `size_in_bytes_verified`) for deterministic replay/audit handoff.
  - this reduces residual ambiguity between metadata identity and extracted file state, while preserving all existing protected-branch/provenance gates.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-19 (iteration 101), `ENC-P0-016` tightens live promotion evidence-capture extraction and bundle-manifest replay integrity:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes before extraction when downloaded promotion artifact archives contain:
    - path-traversal archive member names (for example `..`, absolute-path, drive-prefixed, or null-byte forms),
    - symlink entries.
  - capture now requires `promotion_artifact_bundle.zip` in the downloaded artifact set and validates its embedded `bundle_manifest.json` (`enc2sop-promotion-artifact-bundle/v1`) against extracted artifacts:
    - required `release_*` / `promotion_*` / `rotation_*` manifest entries must exist with expected archive paths,
    - required entry SHA256 digests must match extracted artifact file digests.
  - `promotion_capture_receipt.json` now records:
    - `artifact_archive_verification.entry_count_verified`,
    - `bundle_manifest_verification` metadata (`schema`, `path`, `required_entries_verified`, `required_entry_count_verified`, `file_count_reported`, `manifest_sha256`).
  - this reduces residual risk that archive extraction semantics or downstream bundle-manifest drift could silently decouple replay evidence from the verified artifact set.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-19 (iteration 102), `ENC-P0-016` tightens live promotion evidence-capture determinism for artifact-index lag and rotation-proof binding:
  - `scripts/github_release_promotion_evidence.sh` now supports bounded artifact indexing wait (`--artifact-index-wait-seconds`, default `180`) after successful run completion:
    - retries are limited to the exact expected per-attempt artifact name,
    - timeout remains fail-closed with explicit run URL context.
  - capture now fail-closes on rotation evidence mismatch relative to requested mode:
    - with `--rotation-rehearsal true`, requires `rotation_rehearsal_report` to prove `requested=true`, `executed=true`, `old_key_rejected=true`, and `status=passed`,
    - with `--rotation-rehearsal false`, requires non-requested report state (`requested=false` or omitted, `status=not-requested` or omitted).
  - `promotion_capture_receipt.json` now records `rotation_report_verification` (`requested`, `executed`, `old_key_rejected`, `status`) for deterministic replay/audit handoff.
  - this reduces residual operational ambiguity where CI artifact indexing delay or stale/non-passing rotation report states could otherwise disrupt or weaken live evidence archival reproducibility.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-19 (iteration 103), `ENC-P0-016` tightens live promotion evidence-capture artifact metadata parity:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes when artifact metadata identity diverges from resolved run details:
    - artifact `workflow_head_branch` must match run-detail `head_branch`,
    - artifact `workflow_head_sha` must match run-detail `head_sha`.
  - this closes a residual provenance ambiguity where artifact metadata could remain internally inconsistent with the selected workflow run identity while still passing earlier artifact-id/digest/size checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-19 (iteration 104), `ENC-P0-016` tightens live promotion evidence-capture semantic binding for extracted promotion audit/receipt artifacts:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless extracted `promotion_artifact_audit_report.json` proves:
    - schema `enc2sop-promotion-artifact-audit/v1`,
    - `passed=true`,
    - `summary.total_failures=0`.
  - capture now fail-closes unless extracted `promotion_run_receipt.json` proves:
    - schema `enc2sop-promotion-run-receipt/v1`,
    - `passed=true`,
    - `rotation_pass_required` parity with requested `--rotation-rehearsal` mode,
    - required receipt artifact entries (`release_*`, `promotion_*`, `rotation_*`) with digest parity against extracted files,
    - `promotion_artifact_audit_report_file` path parity with the corresponding receipt artifact row.
  - capture now fail-closes unless run-receipt GitHub context keys match resolved run identity/strict CI expectations:
    - `GITHUB_REPOSITORY`,
    - `GITHUB_RUN_ID`,
    - `GITHUB_RUN_ATTEMPT`,
    - `GITHUB_ACTIONS=true`,
    - `CI=true`,
    - `GITHUB_REF_PROTECTED=true`,
    - and, when available from run identity, `GITHUB_EVENT_NAME` and `GITHUB_WORKFLOW_REF`.
  - `promotion_capture_receipt.json` now records `promotion_run_receipt_verification` metadata (`schema`, `passed`, `rotation_pass_required`, `artifact_entries_verified`, `artifact_entry_count_verified`) for deterministic replay/audit handoff.
  - this reduces residual ambiguity where extracted artifacts could be present but semantically inconsistent with the enforced promotion gate outcome.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-19 (iteration 105), `ENC-P0-016` tightens workflow-dispatch run-id capture determinism for live evidence archival:
  - `scripts/github_release_promotion_evidence.sh` now attempts dispatch through GitHub REST workflow-dispatch API with `return_run_details=true` and extracts `workflow_run_id` directly from structured response fields before any fallback parsing.
  - when dispatch-response run details are unavailable in a given operator environment, helper retains compatibility fallback to prior `gh workflow run` resolution paths (`dispatch output` and bounded `recent-runs` lookup), preserving operational continuity while preferring deterministic run-id provenance when available.
  - capture now records explicit run-id resolution provenance in `promotion_capture_receipt.json`:
    - `workflow_run_id_resolution_mode` with values `provided`, `dispatch-api`, `dispatch-output`, or `recent-runs`.
  - this reduces residual ambiguity in how run identity was obtained for archived promotion evidence replay, without weakening existing protected-ref / CI-context / artifact-integrity gates.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-20 (iteration 106), `ENC-P0-016` tightens attempt-level promotion execution evidence binding during live capture:
  - `scripts/github_release_promotion_evidence.sh` now verifies run-attempt job/step outcomes via GitHub jobs API (`actions/runs/<run_id>/attempts/<run_attempt>/jobs`) before artifact acceptance.
  - capture now fail-closes unless exactly one `Signed Approval Promotion Gate` job is present with:
    - `status=completed`,
    - `conclusion=success`.
  - capture now fail-closes unless required promotion-control steps report `conclusion=success`, including:
    - protected-ref enforcement,
    - promotion artifact verification,
    - promotion artifact bundling,
    - promotion artifact upload.
  - rotation-step parity is now bound to requested mode:
    - with `--rotation-rehearsal true`, rotation step must conclude `success`,
    - with `--rotation-rehearsal false`, rotation step must conclude `skipped`.
  - `promotion_capture_receipt.json` now records `promotion_job_verification` metadata (job identity/status/conclusion/timestamps, required-step count, and verified rotation-step conclusion) for deterministic replay/audit handoff.
  - this reduces residual ambiguity where run-level success could otherwise be accepted without explicit proof that critical promotion gate steps executed as expected for the exact run attempt.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-20 (iteration 107), `ENC-P0-016` tightens actor/runner provenance binding during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now captures authoritative run-level actor identity (`actor.login`, `triggering_actor.login`) from `repos/<repo>/actions/runs/<run_id>` and binds it to promotion-job metadata.
  - capture now fail-closes unless the resolved `Signed Approval Promotion Gate` job includes:
    - non-empty `runner_name` and `runner_group_name`,
    - structurally valid `labels` without mixed `self-hosted` and `github-hosted` markers,
    - actor/triggering-actor parity with run identity when run-level actor metadata is present.
  - capture now fail-closes when extracted `promotion_run_receipt.github_context` diverges from verified job/run identity for:
    - `GITHUB_ACTOR`,
    - `GITHUB_TRIGGERING_ACTOR`,
    - `RUNNER_NAME`.
  - `promotion_capture_receipt.json` now records additional verified promotion job provenance:
    - `runner_name`, `runner_group_name`, `runner_labels`, `actor_login`, `triggering_actor_login`.
  - this further reduces replay ambiguity where artifact capture could otherwise proceed despite actor/runner identity drift between run summary and job-level execution metadata.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-20 (iteration 108), `ENC-P0-016` tightens run-identity parity across promotion-job metadata and archived run-receipt context during live evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `Signed Approval Promotion Gate` job metadata matches resolved run identity for:
    - `run_id`,
    - `head_sha` (canonical 40-char lowercase hex),
    - `head_branch` (when available from resolved run identity).
  - capture now fail-closes unless `promotion_run_receipt.github_context` matches additional resolved run-identity keys when available:
    - `GITHUB_SHA`,
    - `GITHUB_RUN_NUMBER`,
    - and, when run head branch is present, `GITHUB_REF=refs/heads/<head_branch>`, `GITHUB_REF_NAME=<head_branch>`, `GITHUB_REF_TYPE=branch`.
  - this reduces residual replay ambiguity where run-receipt context could otherwise pass with a narrower key set despite run/job metadata drift on commit/run-ordinal or branch-ref identity.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-20 (iteration 109), `ENC-P0-016` tightens workflow-name provenance parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `Signed Approval Promotion Gate` job metadata matches run-summary workflow identity for:
    - `workflow_name` (when run summary exposes `workflowName`).
  - capture now fail-closes unless `promotion_run_receipt.github_context.GITHUB_WORKFLOW` matches verified promotion-job workflow identity when available.
  - `promotion_capture_receipt.json` now records verified `promotion_job_verification.workflow_name` for deterministic replay/audit handoff.
  - this reduces residual ambiguity where run-receipt workflow identity could drift from actual promotion-job execution metadata while still satisfying narrower run-id/ref checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-20 (iteration 110), `ENC-P0-016` improves live promotion evidence-capture robustness for actor provenance under API-shape variance:
  - `scripts/github_release_promotion_evidence.sh` now applies actor/triggering-actor parity checks conditionally:
    - when promotion-job payload includes `actor` / `triggering_actor`, login parity with run identity remains fail-closed,
    - when those job-level payloads are absent, capture no longer fails solely due to missing optional job fields.
  - capture receipt now records actor-parity execution state in `promotion_job_verification`:
    - `actor_parity_checked`,
    - `triggering_actor_parity_checked`.
  - this reduces residual operational fragility in environments where GitHub jobs API omits actor sub-objects, while preserving strict mismatch rejection whenever actor data is available.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-20 (iteration 111), `ENC-P0-016` tightens run-summary/detail identity parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now requests `headSha` and `number` from `gh run view` and fail-closes unless:
    - summary `headSha` is canonical lowercase 40-hex when present,
    - summary/detail commit identity matches (`headSha` == run-detail `head_sha`),
    - summary/detail run ordinals are numeric when present,
    - summary/detail run ordinals match (`number` == run-detail `run_number`).
  - this reduces residual replay ambiguity where summary metadata drift on commit/run-ordinal identity could otherwise pass while detail/API-derived artifact checks remained internally consistent.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-20 (iteration 112), `ENC-P0-016` tightens run-summary/detail URL identity parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless summary `gh run view` URL matches run-detail `html_url` for the same `run_id` when both are present.
  - this reduces residual replay ambiguity where summary/detail event/branch/sha/run-number identity could pass while run URL identity drift remained undetected.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-20 (iteration 113), `ENC-P0-016` tightens promotion-job identity/time provenance parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless the resolved `Signed Approval Promotion Gate` job metadata additionally proves:
    - numeric `job.id`,
    - numeric `job.run_attempt` parity with the resolved workflow run attempt when run-attempt metadata is present,
    - non-empty/non-whitespace `job.html_url` that structurally matches resolved run/job identity (`run_id` + `job_id`),
    - valid ISO-8601 `started_at` / `completed_at` values with monotonic timestamp ordering (`completed_at >= started_at`).
  - this reduces residual replay ambiguity where job-level metadata could pass prior step/status checks while remaining malformed or identity-incoherent on job URL/attempt/time provenance.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-21 (iteration 114), `ENC-P0-016` tightens canonical run-URL provenance binding during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless summary run URL (`gh run view`) and run-detail `html_url` both satisfy canonical identity checks:
    - HTTPS-only URLs,
    - no leading/trailing whitespace,
    - no query/fragment components,
    - canonical run path shape `/<owner>/<repo>/actions/runs/<run_id>[/attempts/<attempt>]`,
    - repository-path parity with resolved repository slug,
    - run-id path parity with resolved run id,
    - attempt-path parity when attempt suffix is present,
    - host parity between summary/detail URL views.
  - promotion capture receipts now include `workflow_run_url_verification` metadata (`host_summary`, `host_detail`, `attempt_summary`, `attempt_detail`) for replay/audit provenance handoff.
  - this reduces residual ambiguity where summary/detail URL equality could still pass with non-canonical or weakly structured URL identity forms.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-21 (iteration 115), `ENC-P0-016` tightens run/artifact timestamp provenance semantics during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless run-summary and run-detail timestamps are both semantically valid and internally consistent:
    - summary run timestamps (`createdAt`, `startedAt`, `updatedAt`) must be valid ISO-8601 with monotonic order (`createdAt <= startedAt <= updatedAt`),
    - detail run timestamps (`created_at`, `run_started_at`, `updated_at`) must be valid ISO-8601 with monotonic order (`created_at <= run_started_at <= updated_at`),
    - summary/detail timestamp parity is required for created/started/updated values.
  - capture now fail-closes unless artifact metadata timestamps (`created_at`, `updated_at`, `expires_at`) are valid ISO-8601 with monotonic order (`created_at <= updated_at <= expires_at`).
  - promotion capture receipts now include `workflow_run_timestamp_verification` metadata (summary/detail created/started/updated values) for replay/audit provenance handoff.
  - this reduces residual ambiguity where run/artifact identity checks could pass while timestamp lineage remained malformed, non-monotonic, or drifted between summary/detail metadata sources.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-21 (iteration 116), `ENC-P0-016` tightens artifact download-URL provenance binding during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless artifact metadata `archive_download_url` satisfies canonical identity checks:
    - no leading/trailing whitespace,
    - HTTPS-only URL,
    - non-empty host,
    - no query/fragment components,
    - canonical artifact-download path parity with resolved repository/artifact identity:
      - `/repos/<owner>/<repo>/actions/artifacts/<artifact_id>/zip`,
      - or `/api/v3/repos/<owner>/<repo>/actions/artifacts/<artifact_id>/zip` (GHES compatibility).
  - capture now fail-closes unless artifact download URL host matches verified run URL host identity.
  - promotion capture receipts now include `artifact_metadata.archive_download_url_host` for replay/audit provenance handoff.
  - this reduces residual ambiguity where artifact metadata could provide a syntactically present but identity-divergent download URL.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-21 (iteration 117), `ENC-P0-016` tightens promotion-job URL provenance binding during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless resolved `Signed Approval Promotion Gate` `job.html_url` satisfies canonical identity checks:
    - HTTPS-only URL,
    - no leading/trailing whitespace,
    - no query/fragment components,
    - canonical job path shape `/<owner>/<repo>/(actions/)?runs/<run_id>[/attempts/<attempt>]/(job|jobs)/<job_id>`,
    - repository-path parity with resolved repository slug,
    - run-id path parity with resolved run id,
    - job-id path parity with resolved promotion job id,
    - attempt-path parity when attempt suffix is present.
  - capture now fail-closes unless promotion job URL host matches verified run URL host identity.
  - promotion capture receipts now include `promotion_job_verification` URL provenance fields (`job_html_url_host`, `job_html_url_path`, `job_html_url_attempt`) for replay/audit handoff.
  - this reduces residual ambiguity where promotion-job URL strings could satisfy looser identity matching while still carrying non-canonical path/host semantics.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-21 (iteration 118), `ENC-P0-016` tightens run-state parity and workflow-ref semantic binding during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless run-detail state from `actions/runs/<run_id>` proves:
    - non-empty `status` with `status=completed`,
    - non-empty `conclusion` with `conclusion=success`,
    - summary/detail parity for run `status` and `conclusion`.
  - run-detail workflow `path` ref segment is now semantically normalized and validated:
    - accepts canonical `refs/*`, normalized `heads/*`/`tags/*`, and short branch aliases only when consistent with run `head_branch` under supported events.
    - capture now fail-closes when normalized workflow ref diverges from `refs/heads/<head_branch>` when `head_branch` is present.
  - run-receipt `GITHUB_WORKFLOW_REF` binding is now stricter:
    - capture validates both resolved run `workflow_path_ref` and receipt `GITHUB_WORKFLOW_REF` structure (`<path>@<ref>`),
    - fail-closes on workflow path mismatch,
    - fail-closes unless receipt ref segment matches normalized canonical workflow ref.
  - this reduces residual ambiguity where run-level success from summary polling could pass while run-detail state or workflow-ref identity semantics drifted in archived replay context.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-21 (iteration 121), `ENC-P0-016` tightens workflow-file identity and repository/server context parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `promotion_run_receipt.github_context` includes a canonical workflow-file commit identity:
    - `GITHUB_WORKFLOW_SHA` must be present and a 40-char lowercase hex digest.
  - capture now fail-closes unless numeric GitHub identity keys are present and valid in run receipt context:
    - `GITHUB_REPOSITORY_ID`,
    - `GITHUB_REPOSITORY_OWNER_ID`,
    - `GITHUB_ACTOR_ID`.
  - capture now fail-closes unless repository-owner parity is preserved:
    - `promotion_run_receipt.github_context.GITHUB_REPOSITORY_OWNER` must equal the owner segment of resolved repository slug.
  - capture now fail-closes unless GitHub URL context keys match the verified run host identity:
    - `GITHUB_SERVER_URL=https://<run-host>`,
    - for github.com host:
      - `GITHUB_API_URL=https://api.github.com`,
      - `GITHUB_GRAPHQL_URL=https://api.github.com/graphql`,
    - for enterprise hosts:
      - `GITHUB_API_URL=https://<run-host>/api/v3`,
      - `GITHUB_GRAPHQL_URL=https://<run-host>/api/graphql`.
  - promotion capture receipts now include `workflow_context_verification` metadata:
    - `repository_owner`,
    - `repository_id`,
    - `repository_owner_id`,
    - `actor_id`,
    - `workflow_sha`,
    - `server_url`,
    - `api_url`,
    - `graphql_url`.
  - this reduces residual replay ambiguity where run receipt context could otherwise pass narrower run/ref checks while omitting immutable workflow commit identity or drifting on repository/server identity metadata.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-21 (iteration 122), `ENC-P0-016` tightens run-detail numeric identity parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless run-detail payload (`actions/runs/<run_id>`) exposes numeric immutable identity keys:
    - `repository.id`,
    - `repository.owner.id`,
    - `actor.id`.
  - capture now fail-closes unless archived run-receipt context matches run-detail identity exactly:
    - `promotion_run_receipt.github_context.GITHUB_REPOSITORY_ID == repository.id`,
    - `promotion_run_receipt.github_context.GITHUB_REPOSITORY_OWNER_ID == repository.owner.id`,
    - `promotion_run_receipt.github_context.GITHUB_ACTOR_ID == actor.id`.
  - promotion capture receipts now include run-detail identity echoes under `workflow_context_verification`:
    - `run_repository_id`,
    - `run_repository_owner_id`,
    - `run_actor_id`.
  - this reduces residual ambiguity where numeric run-receipt context could be internally valid yet drift from authoritative run-detail identity metadata returned by GitHub for the resolved run id.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-21 (iteration 123), `ENC-P0-016` tightens run-detail repository-scope identity parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless run-detail payload (`actions/runs/<run_id>`) additionally proves:
    - numeric `id` matching the resolved `run_id`,
    - non-empty `repository.full_name` exactly matching resolved repository slug (`--repo`) without leading/trailing whitespace,
    - non-empty `repository.owner.login` exactly matching the owner segment of resolved repository slug without leading/trailing whitespace.
  - this reduces residual ambiguity where numeric run identity checks could pass while repository slug/owner metadata drifted from the resolved promotion scope.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-22 (iteration 124), `ENC-P0-016` tightens signed-approval provenance lineage during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `promotion_artifact_audit_report.json` proves strict gate-mode semantics:
    - `release_approval_signature_required=true`,
    - `ci_context_match_required=true`,
    - `artifact_context_consistency_required=true`,
    - `rotation_pass_required` boolean parity with requested rehearsal mode.
  - capture now fail-closes unless release-approval lineage across extracted artifacts is key-id coherent:
    - `release_approval` schema/key-id integrity,
    - `release_receipt` schema/release-approval-key-id integrity,
    - `promotion_run_receipt` required signature metadata (`algorithm`, `key_id`, `digest_hex`) and key-id parity with release artifacts.
  - this reduces residual ambiguity where replay capture could otherwise accept bundles with weaker audit-mode flags or key-id/signature-lineage drift despite passing digest/context checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-22 (iteration 125), `ENC-P0-016` tightens release-gate receipt provenance semantics during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `release_receipt.json` explicitly proves release-gate approval state:
    - `release_approval_required=true`,
    - `release_approval_verified=true`,
    - non-empty trimmed `release_approval_file`.
  - capture now fail-closes unless `release_receipt.release_approval_file` semantically targets `release_approval.json` (basename parity check), reducing replay ambiguity where key-id/signature checks could pass while receipt approval-file reference drifted.
  - this further binds captured promotion evidence to an explicitly enforced, verifiable signed-approval gate receipt state.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-22 (iteration 126), `ENC-P0-016` tightens release-receipt digest parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `release_receipt.json` additionally proves digest integrity against archived release artifacts:
    - `release_receipt.release_bundle_sha256` must be a canonical 64-char lowercase hex digest and match extracted `release_bundle.json`,
    - `release_receipt.release_approval_sha256` must be a canonical 64-char lowercase hex digest and match extracted `release_approval.json`.
  - this reduces residual replay ambiguity where release-gate approval booleans/key-id lineage could pass while release-receipt digest fields drifted from the archived release artifacts consumed in the same promotion bundle.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-22 (iteration 127), `ENC-P0-016` tightens release-approval signature and bundle-binding parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `release_approval.json` proves canonical signature and bundle-target semantics:
    - `release_approval.signature.algorithm` must be exactly `hmac-sha256`,
    - `release_approval.signature.digest_hex` must be a canonical 64-char lowercase hex digest,
    - `release_approval.release_bundle_relative_path` must be non-empty/trimmed and semantically point to `release_bundle.json`,
    - `release_approval.release_bundle_sha256` must be a canonical 64-char lowercase hex digest and match extracted `release_bundle.json`.
  - capture now fail-closes unless `release_receipt.release_approval_signature_digest` is a canonical 64-char lowercase hex digest and matches `release_approval.signature.digest_hex`.
  - this reduces residual replay ambiguity where prior release-receipt and key-id lineage checks could pass while release-approval bundle-binding and signature digest semantics drifted from archived artifacts.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-22 (iteration 129), `ENC-P0-016` tightens release-path and run-receipt artifact-path provenance parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `release_receipt.json` path semantics remain canonical and lineage-bound:
    - `release_receipt.release_bundle_relative_path` must be present, trimmed, and exactly `release_bundle.json`,
    - `release_receipt.release_bundle_relative_path` must match `release_approval.release_bundle_relative_path`.
  - capture now fail-closes unless required `promotion_run_receipt.artifacts[*].path` values preserve canonical filename semantics:
    - each required artifact entry path must end with the expected artifact filename for its key.
  - capture now fail-closes on release-path drift versus run-receipt artifact lineage:
    - `release_receipt.release_bundle_relative_path` basename must match `promotion_run_receipt.artifacts[release_bundle].path`,
    - `release_receipt.release_approval_file` must exactly match `promotion_run_receipt.artifacts[release_approval].path`.
  - this reduces residual replay ambiguity where digest/signature and key-id parity checks could pass while receipt path references diverged from archived run-receipt artifact paths.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-22 (iteration 130), `ENC-P0-016` tightens cross-artifact approval timeline provenance during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless approval/release/audit receipt timestamps are canonical ISO-8601 and monotonic across the signed-approval lineage:
    - `release_approval.approved_at_utc` is required, trimmed, and valid ISO-8601,
    - `release_receipt.generated_at_utc` is required and must be `>= release_approval.approved_at_utc`,
    - `promotion_audit_report.generated_at_utc` is required and must be `>= release_receipt.generated_at_utc`,
    - `promotion_artifact_audit_report.generated_at_utc` is required and must be `>= promotion_audit_report.generated_at_utc`,
    - `promotion_run_receipt.generated_at_utc` is required and must be `>= promotion_artifact_audit_report.generated_at_utc`.
  - capture now fail-closes unless `release_approval.approvers` remains a non-empty unique list of trimmed non-empty strings, and optional `release_approval.notes` is trimmed/non-empty when present.
  - promotion capture receipts now archive explicit `approval_lineage_timestamps` and `release_approval_metadata_verification` blocks for replay handoff.
  - this reduces residual replay ambiguity where signature/digest/path lineage could pass while artifact emission chronology remained malformed or temporally inconsistent.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-22 (iteration 131), `ENC-P0-016` tightens release-context parity binding during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless release-context artifacts are explicitly context-coherent with archived run-receipt context:
    - `release_receipt.github_context` must exist as a JSON object.
    - `release_receipt.release_approval_github_context` must exist as a JSON object.
    - `release_approval.github_context` must exist as a JSON object.
    - `release_receipt.release_approval_github_context` must exactly match `release_approval.github_context`.
  - capture now fail-closes unless each release-context object matches `promotion_run_receipt.github_context` for required canonical keys:
    - `GITHUB_REPOSITORY`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_ACTIONS`, `CI`, `GITHUB_REF_PROTECTED`,
    - `GITHUB_REPOSITORY_OWNER`, `GITHUB_REPOSITORY_ID`, `GITHUB_REPOSITORY_OWNER_ID`, `GITHUB_ACTOR_ID`,
    - `GITHUB_WORKFLOW_SHA`, `GITHUB_SERVER_URL`, `GITHUB_API_URL`, `GITHUB_GRAPHQL_URL`.
  - capture now fail-closes on optional-key drift when optional keys are present in run-receipt context:
    - `GITHUB_SHA`, `GITHUB_RUN_NUMBER`, `GITHUB_REF`, `GITHUB_REF_NAME`, `GITHUB_REF_TYPE`,
    - `GITHUB_EVENT_NAME`, `GITHUB_JOB`, `GITHUB_WORKFLOW`, `GITHUB_WORKFLOW_REF`,
    - `GITHUB_ACTOR`, `GITHUB_TRIGGERING_ACTOR`, `RUNNER_NAME`.
  - promotion capture receipts now include `release_context_verification` metadata (`contexts_verified`, `required_keys_verified`, `optional_keys_verified_when_present`) for replay/audit handoff.
  - this reduces residual replay ambiguity where strict-mode booleans in artifact-audit output could pass while release/approval context payloads drifted from the run-receipt context archived in the same evidence bundle.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-22 (iteration 132), `ENC-P0-016` tightens retention-window provenance parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless run-detail retention metadata from `actions/runs/<run_id>` proves:
    - non-empty numeric positive `retention_days`.
  - capture now fail-closes unless retention metadata stays coherent across archived artifacts:
    - `rotation_rehearsal_report.workflow_retention_days` must be present/trimmed/positive and equal run-detail `retention_days`,
    - `promotion_run_receipt.github_context.GITHUB_RETENTION_DAYS` must equal run-detail `retention_days`,
    - required release-context parity now also includes `GITHUB_RETENTION_DAYS` for:
      - `release_receipt.github_context`,
      - `release_receipt.release_approval_github_context`,
      - `release_approval.github_context`.
  - promotion capture receipts now include explicit retention lineage echoes for replay/audit handoff:
    - `workflow_context_verification.retention_days`,
    - `rotation_report_verification.workflow_retention_days`.
  - this reduces residual replay ambiguity where run/context identity checks could pass while retention-governance metadata drifted between run details and archived promotion artifacts.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 133), `ENC-P0-016` tightens promotion artifact-audit failure-list semantics during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `promotion_artifact_audit_report.json` proves coherent pass-state failure accounting:
    - `promotion_artifact_audit_report.failures` must be present as a list,
    - when `promotion_artifact_audit_report.passed=true`, `promotion_artifact_audit_report.failures` must be empty.
  - this closes a residual replay ambiguity where `passed=true` and `summary.total_failures=0` could coexist with a malformed/non-empty failure payload and still be accepted by the capture gate.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 134), `ENC-P0-016` tightens promotion report summary-count coherence during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless both promotion reports prove typed and coherent failure-count semantics:
    - `promotion_audit_report.summary.total_failures` must be integer-typed and equal `len(promotion_audit_report.failures)`.
    - `promotion_artifact_audit_report.summary.total_failures` must be integer-typed and equal `len(promotion_artifact_audit_report.failures)`.
  - this closes residual ambiguity where boolean/non-integer or inconsistent failure-count metadata could otherwise pass shallow `summary.total_failures=0` checks.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 135), `ENC-P0-016` tightens rotation-report provenance parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `rotation_rehearsal_report.json` is schema-valid and context/timeline-coherent with verified run metadata plus `promotion_run_receipt.github_context`:
    - requires `rotation_rehearsal_report.schema=enc2sop-rotation-rehearsal/v1`.
    - requires `rotation_rehearsal_report.generated_at_utc` as canonical ISO-8601 and enforces ordering:
      - `rotation_rehearsal_report.generated_at_utc <= promotion_artifact_audit_report.generated_at_utc`.
    - enforces required context-key parity:
      - `workflow_repository`, `workflow_run_id`, `workflow_run_attempt`, `workflow_github_actions`, `workflow_ci`,
      - `workflow_retention_days`, `workflow_job`, `workflow_actor_id`, `workflow_repository_id`,
      - `workflow_repository_owner`, `workflow_repository_owner_id`, `workflow_ref_protected`,
      - `workflow_name_sha`, `workflow_server_url`, `workflow_api_url`, `workflow_graphql_url`.
    - enforces optional context-key parity when present in run-receipt context:
      - `workflow_sha`, `workflow_run_number`, `workflow_ref`, `workflow_ref_name`, `workflow_ref_type`,
      - `workflow_event`, `workflow_name`, `workflow_name_ref`, `workflow_actor`,
      - `workflow_triggering_actor`, `workflow_runner_name`.
  - promotion capture receipts now include stronger rotation verification metadata:
    - `rotation_report_verification.generated_at_utc`,
    - `rotation_report_verification.context_required_keys_verified`,
    - `rotation_report_verification.context_optional_keys_verified_when_present`.
  - this reduces residual replay ambiguity where rotation pass-state booleans and retention checks could pass while rotation-report workflow identity fields drifted from archived run-receipt context.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 136), `ENC-P0-016` tightens runner-platform provenance parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless required rotation-report context parity also includes runner-platform identity keys:
    - `rotation_rehearsal_report.workflow_runner_environment` vs `promotion_run_receipt.github_context.RUNNER_ENVIRONMENT`,
    - `rotation_rehearsal_report.workflow_runner_os` vs `promotion_run_receipt.github_context.RUNNER_OS`,
    - `rotation_rehearsal_report.workflow_runner_arch` vs `promotion_run_receipt.github_context.RUNNER_ARCH`.
  - this reduces residual replay ambiguity where rotation report checks could pass while runner platform metadata drifted from archived run-receipt context.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 137), `ENC-P0-016` tightens workflow-window timeline provenance during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless workflow run timing and archived artifact timelines are window-coherent:
    - validates `workflow_run_timestamp_verification.started_at_detail` and `workflow_run_timestamp_verification.updated_at_detail` as canonical ISO-8601 and enforces `updated_at_detail >= started_at_detail`.
    - enforces workflow-window bounds for all replay-critical artifact timestamps:
      - `rotation_rehearsal_report.generated_at_utc`,
      - `release_approval.approved_at_utc`,
      - `release_receipt.generated_at_utc`,
      - `promotion_audit_report.generated_at_utc`,
      - `promotion_artifact_audit_report.generated_at_utc`,
      - `promotion_run_receipt.generated_at_utc`.
  - the capture script also corrects sequencing of the existing chronology invariant so `promotion_audit_report.generated_at_utc >= release_receipt.generated_at_utc` is evaluated only after `release_receipt.generated_at_utc` has been parsed.
  - this reduces residual replay ambiguity where timeline data could satisfy inter-artifact relative ordering while drifting outside the authoritative run execution window.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 138), `ENC-P0-016` tightens rotation-report execution-state semantics during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `rotation_rehearsal_report.json` includes canonical execution-state metadata:
    - `rotation_rehearsal_report.details` must be present, trimmed, and non-empty.
    - capture receipts now archive `rotation_report_verification.details` for replay handoff.
  - when rotation rehearsal is not required, capture now fail-closes on contradictory execution-state drift:
    - `rotation_rehearsal_report.executed` must be `false`/absent,
    - `rotation_rehearsal_report.old_key_rejected` must be `null`.
  - this reduces residual replay ambiguity where `status=not-requested` could coexist with contradictory execution-state fields and still pass capture.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 139), `ENC-P0-016` tightens explicit non-rehearsal rotation-state encoding during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `rotation_rehearsal_report.status` is always present and canonical:
    - `rotation_rehearsal_report.status` must be non-empty and trimmed in all modes.
  - when rotation rehearsal is not required, capture now enforces explicit canonical state (not implicit/omitted):
    - `rotation_rehearsal_report.requested` must be explicit `false`,
    - `rotation_rehearsal_report.executed` must be explicit `false`,
    - `rotation_rehearsal_report.old_key_rejected` must be `null`,
    - `rotation_rehearsal_report.status` must be explicit `not-requested`.
  - this reduces residual replay ambiguity where absent status/requested fields could still be interpreted as equivalent to non-rehearsal state.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 140), `ENC-P0-016` tightens artifact timestamp workflow-window provenance during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless promotion artifact metadata timelines are canonical and bounded by authoritative run-detail timing:
    - requires `artifact_metadata.created_at` and `artifact_metadata.updated_at` as canonical ISO-8601 UTC timestamps.
    - enforces artifact chronology invariant:
      - `artifact_metadata.updated_at >= artifact_metadata.created_at`.
    - enforces workflow-window bounds:
      - `artifact_metadata.created_at >= workflow_run_timestamp_verification.started_at_detail`,
      - `artifact_metadata.updated_at <= workflow_run_timestamp_verification.updated_at_detail`.
  - this reduces residual replay ambiguity where report/receipt timestamps could satisfy run-window checks while downloaded artifact metadata drifted outside the same workflow execution window.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 141), `ENC-P0-016` tightens policy/workflow bundle-entry determinism during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `bundle_manifest.json` explicitly contains canonical promotion-input provenance entries:
    - required `promotion_policy` bundle entry with `archive_path=policy/promotion_rollout_policy.json`,
    - required `promotion_workflow` bundle entry with `archive_path=workflow/release_promotion.yml`.
  - digest parity checks remain enforced between `promotion_audit_report.inputs.{policy_sha256,workflow_sha256}` and corresponding bundle-entry digests.
  - this reduces residual replay ambiguity where promotion-input digest checks could pass while policy/workflow bundle-entry presence/path determinism remained implicit.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 142), `ENC-P0-016` tightens policy/workflow run-receipt provenance determinism during live promotion evidence capture:
  - `enc2sop/promotion_artifacts.py` now emits and validates canonical policy/workflow lineage entries directly in `promotion_run_receipt.json`:
    - run-receipt artifact inventory now requires `promotion_policy` and `promotion_workflow` rows.
    - existing run-receipt binding checks now fail closed unless those rows are present and digest/path-coherent with the same `policy_path`/`workflow_path` inputs used by promotion audit and artifact audit.
  - this reduces residual replay ambiguity where bundle-manifest and audit-input provenance checks could pass while run-receipt lineage omitted policy/workflow artifacts.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 143), `ENC-P0-016` tightens cross-report policy/workflow path parity during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless policy/workflow file-path lineage is coherent across all replay-critical reports:
    - `promotion_artifact_audit_report.promotion_policy_file == promotion_audit_report.inputs.policy_file`.
    - `promotion_artifact_audit_report.promotion_workflow_file == promotion_audit_report.inputs.workflow_file`.
    - `promotion_artifact_audit_report.promotion_policy_file == promotion_run_receipt.artifacts[promotion_policy].path`.
    - `promotion_artifact_audit_report.promotion_workflow_file == promotion_run_receipt.artifacts[promotion_workflow].path`.
  - this reduces residual replay ambiguity where digest-level provenance checks could pass while artifact-audit report path fields drifted from audit-input and run-receipt canonical paths.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 144), `ENC-P0-016` tightens run-receipt required-entry determinism for policy/workflow provenance during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `promotion_run_receipt.artifacts` explicitly includes:
    - `promotion_policy` with canonical filename `promotion_rollout_policy.json`,
    - `promotion_workflow` with canonical filename `release_promotion.yml`.
  - capture now emits explicit missing-entry diagnostics before downstream path-parity checks:
    - `promotion_run_receipt.artifacts missing required entry: promotion_policy`,
    - `promotion_run_receipt.artifacts missing required entry: promotion_workflow`.
  - this reduces residual replay ambiguity where cross-report policy/workflow path checks could be side-stepped by omitting policy/workflow rows from run-receipt artifact inventory.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-23 (iteration 145), `ENC-P0-016` tightens bundle-manifest cardinality determinism during live promotion evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `bundle_manifest.json` proves coherent file-count metadata:
    - `bundle_manifest.file_count` must be present and integer-typed.
    - `bundle_manifest.file_count` must exactly match `len(bundle_manifest.files)`.
  - this reduces residual replay ambiguity where bundle-entry digest/path checks could pass while bundle-manifest cardinality metadata drifted or was malformed.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-24 (iteration 146), `ENC-P0-016` tightens promotion artifact-bundle replay determinism during live evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless `promotion_artifact_bundle.zip` contents exactly match the bundle manifest contract:
    - ZIP member paths must be safe relative forward-slash paths with no traversal, symlinks, directories, or duplicate members.
    - `bundle_manifest.files[*].archive_path` must be trimmed, relative, forward-slash-only, traversal-free, unique, and must not target `bundle_manifest.json`.
    - `bundle_manifest.files[*].name` must exactly match the required promotion evidence artifact names, including `promotion_policy` and `promotion_workflow`.
    - ZIP entries must exactly equal `bundle_manifest.files[*].archive_path` plus `bundle_manifest.json`; undeclared or missing bundle payloads are rejected.
  - promotion capture receipts now include bundle archive-entry replay metadata:
    - `bundle_manifest_verification.archive_entries_verified`,
    - `bundle_manifest_verification.archive_entry_count_verified`.
  - this reduces residual replay ambiguity where manifest digest/path checks could pass while the archive carried undeclared or missing payload entries.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

- As of 2026-05-24 (iteration 147), `ENC-P0-016` tightens nested promotion-bundle digest replay during live evidence capture:
  - `scripts/github_release_promotion_evidence.sh` now fail-closes unless every `bundle_manifest.files[*].sha256` digest matches:
    - the corresponding member bytes inside `promotion_artifact_bundle.zip`,
    - the separately uploaded/extracted artifact file for each required promotion evidence artifact.
  - promotion capture receipts now include `bundle_manifest_verification.archive_member_sha256` for replay handoff.
  - this reduces residual replay ambiguity where bundle names and archive paths matched while nested bundle member bytes drifted from separately uploaded evidence artifacts.
  - remaining launch risk remains external execution:
    - run protected-branch/environment workflow against live rollout controls,
    - archive real promotion + rotation + receipt artifacts from CI,
    - complete live old-key rejection rehearsal records.

## 9. Assessment Status

Status: `[APPROVED BASELINE]`

This file is the current architectural truth for future iterations until a later iteration updates it explicitly.
