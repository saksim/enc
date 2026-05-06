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
- `qrcode_helper.py` now consumes these extracted modules through compatibility aliases.
- Existing transport tests remain green, including import-time easyocr isolation.
- Residual blocker remains until render/recover/CLI are also split and `qrcode_helper.py` is reduced to a compatibility facade.

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

- license-file and remote-KMS providers are not yet implemented.
- current provider still resolves keys locally at runtime; this is a baseline decoupling step, not final hardening.

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

### [P1] G-003 Incomplete Release Packaging Story

There is no normalized signed release bundle structure for customers or downstream product teams.

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

- The first five gate items are now satisfied except "at least one non-local key-control path exists".
- Remaining critical work to satisfy that gate is `ENC-P1-009` (license-file provider), followed by `ENC-P1-010` (remote-KMS contract stub).

## 9. Assessment Status

Status: `[APPROVED BASELINE]`

This file is the current architectural truth for future iterations until a later iteration updates it explicitly.
