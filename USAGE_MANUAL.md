# enc2sop Usage Manual

## 1. Purpose

This manual is the operator runbook for the production mainline:

`protect -> build -> package -> verify -> release`

Mainline command surface is unified under:

```powershell
python .\soenc.py <command>
```

Airgap QR/OCR workflows are optional and documented separately in [QRCODE_AIRGAP_MANUAL.md](./QRCODE_AIRGAP_MANUAL.md).

## 2. Command Surface

```text
soenc protect
soenc build
soenc package
soenc verify
soenc approve-release
soenc release
soenc audit-promotion
soenc collect-promotion-evidence
soenc promotion-dry-run
soenc verify-promotion-artifacts
soenc transport   (optional plugin)
```

## 3. Preconditions

1. Python 3.6+.
2. Required packages for mainline:
   - `pycryptodome`
   - `setuptools`
   - `Cython` (for `build` command).
3. Native toolchain for your target platform:
   - Windows: MSVC Build Tools + Windows SDK.
   - Linux/macOS: standard C compiler toolchain.

Install example:

```powershell
python -m pip install pycryptodome setuptools Cython
```

## 3.1 Linux One-Command Smoke Scripts

Two Linux smoke-test scripts are available under `scripts/` for validating the mainline release flow.

Use this when the Linux host can install/use Python directly:

```bash
bash scripts/linux_local_smoke.sh
```

Use this when the Linux host has Docker but no Python environment:

```bash
bash scripts/linux_docker_smoke.sh
```

The Docker script defaults to `python:3.11-slim` and `DOCKER_PULL_POLICY=never`, so it uses a local image cache by default instead of blocking on Docker Hub. To allow pulling when the image is missing:

```bash
DOCKER_PULL_POLICY=missing bash scripts/linux_docker_smoke.sh
```

Both scripts create an isolated smoke fixture, run:

```text
protect -> build -> verify -> package -> approve-release -> release
```

Default output directories:

```text
.tmp_linux_smoke_local/out/release
.tmp_linux_smoke_docker/out/release
```

Optional overrides:

```bash
PYTHON_BIN=python3.11 SMOKE_ROOT=.tmp_custom bash scripts/linux_local_smoke.sh
DOCKER_IMAGE=python:3.11-slim CONTAINER_SMOKE_ROOT=.tmp_docker_custom bash scripts/linux_docker_smoke.sh
```

## 3.2 Linux Release Acceptance Script

For pre-production acceptance (mainline pass + fail-closed tamper checks), use:

```bash
TARGET_DIR=./src_pkg bash scripts/linux_release_acceptance.sh
```

What it validates:

1. Mainline flow passes:
   - `protect -> build -> verify -> package -> approve-release -> release`
2. Fail-closed behavior:
   - tampered `release_approval.json` is rejected by `soenc release`
   - tampered runtime fingerprint in `build_manifest.json` is rejected by `soenc verify`
3. Recovery sanity:
   - `soenc verify` passes again after restoring the manifest

Useful overrides:

```bash
PYTHON_BIN=python3.11 TARGET_DIR=./src_pkg SMOKE_ROOT=.tmp_acceptance_custom bash scripts/linux_release_acceptance.sh
```

Troubleshooting:

1. If build reports `ModuleNotFoundError: No module named 'Cython'`, the compile step is likely running with a different interpreter than the venv.
2. `linux_release_acceptance.sh` now pins `soenc build --python-exe` to the active venv Python automatically.

## 4. Mainline Runbook

### 4.1 Protect

Protects source files into encrypted staging `.py` outputs and writes `build_manifest.json`.

Example:

```powershell
python .\soenc.py protect -t .\src_pkg -o .\out\staging --scope-config .\src_pkg\scope.json
```

Rules:

1. `protect` is staging-only.
2. Do not pass compile/release flags here; use `build` and `package`.
3. Directory mode should use `--scope-config`.

### 4.2 Build

Compiles staged outputs and validates runtime-delivery metadata.

Example:

```powershell
python .\soenc.py build --staging-dir .\out\staging --build-profile auto
```

Useful options:

1. `--python-exe`
2. `--build-profile {auto,windows-msvc,native}`
3. `--vcvars-path` (Windows MSVC profile)
4. `--manifest-sign-key-file` or `--manifest-sign-key-b64`
5. `--require-manifest-signature`

### 4.3 Verify

Validates runtime-delivery integrity for a staging/build pair.

Example:

```powershell
python .\soenc.py verify --staging-dir .\out\staging
```

Use this after build and before packaging/release.

### 4.4 Package

Copies compiled artifacts into a release directory and emits `release_bundle.json`.

Example:

```powershell
python .\soenc.py package --staging-dir .\out\staging --dist-dir .\out\release
```

Optional:

1. `--build-dir` (defaults to `<staging-dir>/build`)
2. `--require-manifest-signature`

### 4.5 Approve-Release

Generates signed `release_approval.json` bound to the current `release_bundle.json` digest.

Example:

```powershell
python .\soenc.py approve-release --dist-dir .\out\release --release-approval-key-file .\ops\release_approval.key --approver ops-a --approver security-b
```

Behavior:

1. Reads `release_bundle.json` from release directory.
2. Computes `release_bundle_sha256`.
3. Writes signed `release_approval.json` (`enc2sop-release-approval/v1`) with approvers and signature metadata.

Optional:

1. `--release-approval-file`
2. `--release-approval-key-file` or `--release-approval-key-b64`
3. `--release-approval-key-id`
4. `--approved-at-utc`
5. `--notes`

### 4.6 Release

Release is a first-class command that validates packaged artifacts and writes an audit receipt.

Example:

```powershell
python .\soenc.py release --dist-dir .\out\release --require-manifest-signature
```

Behavior:

1. Reads `release_bundle.json` and `build_manifest.json` from release directory.
2. Verifies bundle schema/layout and manifest signature policy.
3. Re-checks packaged runtime fingerprint digests for compiled runtime artifacts.
4. Verifies packaged native/init/license artifact inventories match bundle/manifest metadata.
5. Optionally verifies signed release approval metadata (`release_approval.json`) when approval policy is enabled.
6. Writes `release_receipt.json` as handoff proof.

Optional:

1. `--require-manifest-signature`
2. `--require-release-approval`
3. `--release-approval-file`
4. `--release-approval-key-file` or `--release-approval-key-b64`
5. `--release-approval-key-id`

### 4.7 Audit-Promotion

Validates protected-branch/environment rollout evidence against the repository policy contract.

Example:

```powershell
python .\soenc.py audit-promotion --evidence-file .\ops\promotion_evidence.json
```

Behavior:

1. Loads policy from `docs/PROMOTION_ROLLOUT_POLICY.json` by default.
2. Checks required branch status checks, environment reviewer gates, secret evidence, and workflow contract fragments.
3. Writes `promotion_audit_report.json` (default output is alongside the evidence file).
4. Fails closed with non-zero exit code if evidence violates policy.

Optional:

1. `--policy-file`
2. `--workflow-file`
3. `--report-file`

### 4.8 Collect-Promotion-Evidence

Collects rollout evidence directly from GitHub APIs and writes an audit-ready evidence payload.

Example:

```powershell
python .\soenc.py collect-promotion-evidence --github-repo owner/repo --github-token $env:GITHUB_TOKEN --evidence-file .\ops\promotion_evidence.json
```

Behavior:

1. Loads required branches/environments/secrets from `docs/PROMOTION_ROLLOUT_POLICY.json`.
2. Reads branch required-status-check evidence from GitHub branch rules APIs.
3. Reads environment reviewer evidence from GitHub environment protection settings.
4. Reads secret-name presence evidence (without secret values) from repository/org/environment secret APIs.
5. Writes `enc2sop-promotion-evidence/v1` JSON directly consumable by `soenc audit-promotion`.
6. Fails closed when API permissions are missing or required rollout objects are absent.

Optional:

1. `--policy-file`
2. `--evidence-file`
3. `--github-api-url` (for GHES)

Environment fallbacks:

1. `--github-repo` falls back to `GITHUB_REPOSITORY`
2. `--github-token` falls back to `GITHUB_TOKEN`
3. `--github-api-url` falls back to `GITHUB_API_URL`, then `https://api.github.com`

### 4.9 Promotion-Dry-Run

Runs the promotion rollout gate end-to-end in one command.

Default mode: collect evidence from GitHub APIs, then audit policy.

```powershell
python .\soenc.py promotion-dry-run --github-repo owner/repo --github-token $env:GITHUB_TOKEN
```

Offline mode: skip collection and audit an existing evidence file.

```powershell
python .\soenc.py promotion-dry-run --skip-collect --evidence-file .\ops\promotion_evidence.json
```

Behavior:

1. In collection mode, gathers branch/environment/secret evidence under `enc2sop-promotion-evidence/v1`.
2. Runs policy audit against `docs/PROMOTION_ROLLOUT_POLICY.json` (or `--policy-file` override).
3. Writes `promotion_audit_report.json` (or `--report-file` override).
4. Fails closed with non-zero exit code when collection or audit policy checks fail.

Optional:

1. `--skip-collect`
2. `--github-repo`
3. `--github-token`
4. `--github-api-url`
5. `--policy-file`
6. `--workflow-file`
7. `--evidence-file`
8. `--report-file`

### 4.10 Verify-Promotion-Artifacts

Validates release/promotion/rotation artifacts as one fail-closed integrity gate.

```powershell
python .\soenc.py verify-promotion-artifacts --dist-dir .\out\release --promotion-evidence-file .\ops\promotion_evidence.json --promotion-report-file .\ops\promotion_audit_report.json --rotation-report-file .\ops\rotation_rehearsal_report.json
```

Behavior:

1. Validates `release_bundle.json`, `release_approval.json`, and `release_receipt.json` schema-critical fields.
2. Verifies `release_approval.release_bundle_sha256` matches current `release_bundle.json`.
3. Verifies `release_receipt.json` is bound to the current `release_bundle.json` and `release_approval.json` through SHA256 digest fields, and that the receipt approval key/signature/GitHub-context metadata matches the approval artifact.
4. Optional release-approval signature verification:
   - provide `--release-approval-key-file` or `--release-approval-key-b64` to validate `release_approval.signature.digest_hex` against canonical payload bytes.
   - optional `--release-approval-key-id` enforces signature key-id pinning.
   - `--require-release-approval-signature` fail-closes when no approval verification key is supplied.
5. Validates promotion evidence/report schema state and requires `promotion_audit_report.passed=true`.
6. Validates rotation report schema and status fields.
7. Optional `--require-rotation-pass` enforces `status=passed` and `old_key_rejected=true`.
8. Optional `--require-ci-context-match` enforces CI-context binding across:
   - `release_receipt.github_context` for the release gate execution context produced by the governed workflow run.
   - signed `release_approval.github_context` plus mirrored `release_receipt.release_approval_github_context` for the approval artifact produced by the governed workflow run.
   - `promotion_evidence.github_context` required identity/hash/attempt/number/retention/ref/ref-name/ref-type/workflow-definition/event/host/job/actor binding (`GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_REF_NAME`, `GITHUB_REF_TYPE`, `GITHUB_RUN_ID`, `GITHUB_SHA`, `GITHUB_RUN_ATTEMPT`, `GITHUB_RUN_NUMBER`, `GITHUB_RETENTION_DAYS`, `GITHUB_WORKFLOW`, `GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`, `GITHUB_EVENT_NAME`, `GITHUB_SERVER_URL`, `GITHUB_API_URL`, `GITHUB_GRAPHQL_URL`, `GITHUB_JOB`, `GITHUB_ACTOR`), required runner execution provenance (`RUNNER_ENVIRONMENT`, `RUNNER_OS`, `RUNNER_ARCH`, `RUNNER_NAME`), required CI-activation boolean binding (`GITHUB_ACTIONS`, `CI`, fail-closed for invalid non-boolean-like values and for semantically non-activating values such as `false`/`0`), required numeric actor/repository identity binding (`GITHUB_ACTOR_ID`, `GITHUB_REPOSITORY_ID`), required repository-owner identity binding (`GITHUB_REPOSITORY_OWNER`, `GITHUB_REPOSITORY_OWNER_ID`), required triggering-actor binding when runtime exports it (`GITHUB_TRIGGERING_ACTOR`), and protected-ref governance binding (`GITHUB_REF_PROTECTED`, fail-closed for missing or invalid non-boolean-like values). Strict mode also fail-closes invalid repository-slug encodings for `GITHUB_REPOSITORY` (must be exactly `owner/repo` with one slash and `[a-z0-9._-]` segment characters), invalid value encodings for numeric/ref-type keys (`GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_RUN_NUMBER`, `GITHUB_RETENTION_DAYS`, `GITHUB_ACTOR_ID`, `GITHUB_REPOSITORY_ID`, `GITHUB_REPOSITORY_OWNER_ID`, `GITHUB_REF_TYPE`), invalid host/API URL encodings for `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` (must be canonical HTTPS URLs with scheme and host), semantically inconsistent endpoint mappings among `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` (github.com requires `api.github.com` with canonical paths; enterprise hosts require same-origin `/api/v3` + `/api/graphql`), invalid commit-SHA encodings for `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` (must be 40-character hexadecimal values), invalid git-refname encodings for `GITHUB_REF`, invalid `GITHUB_WORKFLOW_REF` encodings (must follow `<owner>/<repo>/.github/workflows/<file>.yml@refs/heads/*` or `<owner>/<repo>/.github/workflows/<file>.yml@refs/tags/*` with a valid git refname `@ref` segment), invalid `GITHUB_WORKFLOW_REF` repository semantics (`owner/repo` segment in `GITHUB_WORKFLOW_REF` must match `GITHUB_REPOSITORY`), invalid `GITHUB_WORKFLOW_REF` ref semantics (`@ref` segment in `GITHUB_WORKFLOW_REF` must match `GITHUB_REF`), invalid `GITHUB_REF` semantics relative to `GITHUB_REF_TYPE` (`branch` -> `refs/heads/*`, `tag` -> `refs/tags/*`), and invalid `GITHUB_REF_NAME` semantics (must equal the ref suffix implied by `GITHUB_REF` + `GITHUB_REF_TYPE`).
   - optional `promotion_evidence.repository` slug binding:
     - when the field is present, it must be a valid `owner/repo` value.
     - when present, it must match `promotion_evidence.github_context.GITHUB_REPOSITORY`.
     - under strict CI mode, when present, it must also match runtime `GITHUB_REPOSITORY`.
  - `rotation_rehearsal_report.json` run metadata (`workflow_repository`, `workflow_run_id`, `workflow_ref`, `workflow_ref_name`, `workflow_ref_type`, `workflow_sha`, `workflow_run_attempt`, `workflow_run_number`, `workflow_retention_days`, `workflow_name`, `workflow_name_ref`, `workflow_name_sha`, `workflow_event`, `workflow_server_url`, `workflow_api_url`, `workflow_graphql_url`, `workflow_job`, `workflow_actor`, `workflow_triggering_actor`, `workflow_actor_id`, `workflow_repository_id`, `workflow_repository_owner`, `workflow_repository_owner_id`, `workflow_ref_protected`, `workflow_runner_environment`, `workflow_runner_os`, `workflow_runner_arch`, `workflow_runner_name`) against the current workflow run context when runtime values are present, using the same strict semantic normalization (boolean/integer/enum/protected-ref) as other CI-context artifact bindings.
   - pre-existing `promotion_run_receipt.json` `github_context` required identity/hash/attempt/number/retention/ref/ref-name/ref-type/workflow-definition/event/host/job/actor binding (`GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_REF_NAME`, `GITHUB_REF_TYPE`, `GITHUB_RUN_ID`, `GITHUB_SHA`, `GITHUB_RUN_ATTEMPT`, `GITHUB_RUN_NUMBER`, `GITHUB_RETENTION_DAYS`, `GITHUB_WORKFLOW`, `GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`, `GITHUB_EVENT_NAME`, `GITHUB_SERVER_URL`, `GITHUB_API_URL`, `GITHUB_GRAPHQL_URL`, `GITHUB_JOB`, `GITHUB_ACTOR`), required runner execution provenance (`RUNNER_ENVIRONMENT`, `RUNNER_OS`, `RUNNER_ARCH`, `RUNNER_NAME`), required CI-activation boolean binding (`GITHUB_ACTIONS`, `CI`, fail-closed for invalid non-boolean-like values and for semantically non-activating values such as `false`/`0`), required numeric actor/repository identity binding (`GITHUB_ACTOR_ID`, `GITHUB_REPOSITORY_ID`), required repository-owner identity binding (`GITHUB_REPOSITORY_OWNER`, `GITHUB_REPOSITORY_OWNER_ID`), required triggering-actor binding when runtime exports it (`GITHUB_TRIGGERING_ACTOR`), and protected-ref governance binding (`GITHUB_REF_PROTECTED`, fail-closed for missing or invalid non-boolean-like values). Strict mode also fail-closes invalid repository-slug encodings for `GITHUB_REPOSITORY` (must be exactly `owner/repo` with one slash and `[a-z0-9._-]` segment characters), invalid value encodings for numeric/ref-type keys (`GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_RUN_NUMBER`, `GITHUB_RETENTION_DAYS`, `GITHUB_ACTOR_ID`, `GITHUB_REPOSITORY_ID`, `GITHUB_REPOSITORY_OWNER_ID`, `GITHUB_REF_TYPE`), invalid host/API URL encodings for `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` (must be canonical HTTPS URLs with scheme and host), semantically inconsistent endpoint mappings among `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` (github.com requires `api.github.com` with canonical paths; enterprise hosts require same-origin `/api/v3` + `/api/graphql`), invalid commit-SHA encodings for `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` (must be 40-character hexadecimal values), invalid git-refname encodings for `GITHUB_REF`, invalid `GITHUB_WORKFLOW_REF` encodings (must follow `<owner>/<repo>/.github/workflows/<file>.yml@refs/heads/*` or `<owner>/<repo>/.github/workflows/<file>.yml@refs/tags/*` with a valid git refname `@ref` segment), invalid `GITHUB_WORKFLOW_REF` repository semantics (`owner/repo` segment in `GITHUB_WORKFLOW_REF` must match `GITHUB_REPOSITORY`), invalid `GITHUB_WORKFLOW_REF` ref semantics (`@ref` segment in `GITHUB_WORKFLOW_REF` must match `GITHUB_REF`), invalid `GITHUB_REF` semantics relative to `GITHUB_REF_TYPE` (`branch` -> `refs/heads/*`, `tag` -> `refs/tags/*`), and invalid `GITHUB_REF_NAME` semantics (must equal the ref suffix implied by `GITHUB_REF` + `GITHUB_REF_TYPE`).
9. Writes `promotion_artifact_audit_report.json` and `promotion_run_receipt.json` and exits non-zero on any mismatch.
10. Optional `--require-artifact-context-consistency` enforces cross-artifact parity rooted at `promotion_evidence.github_context`:
   - `release_approval.github_context`
   - `release_receipt.github_context`
   - `release_receipt.release_approval_github_context`
   - `rotation_rehearsal_report` projected context (`workflow_*` fields mapped to GitHub context keys)
   - pre-existing `promotion_run_receipt.github_context` (when receipt file already exists)
   - this allows offline mixed-artifact replay detection even when current CI runtime context is not available.
11. Enforces promotion audit/evidence input binding:
   - `promotion_audit_report.inputs.evidence_file` must match the evidence artifact path under verification.
   - `promotion_audit_report.inputs.evidence_sha256` must match the evidence artifact digest.
   - `promotion_audit_report.inputs.policy_file` / `policy_sha256` must match the policy file used by verification.
   - `promotion_audit_report.inputs.workflow_file` / `workflow_sha256` must match the workflow file used by verification.
12. When approval verification key inputs are provided (`--release-approval-key-file` or `--release-approval-key-b64` with `--release-approval-key-id`), emitted `promotion_run_receipt.json` includes a signed `signature` block (`hmac-sha256`) bound to canonical receipt payload bytes.
13. Under `--require-release-approval-signature`, pre-existing `promotion_run_receipt.json` must carry a valid signature bound to the provided approval verification key and expected key id before rewrite.

Optional:

1. `--report-file`
2. `--run-receipt-file`
3. `--release-approval-key-file`
4. `--release-approval-key-b64`
5. `--release-approval-key-id`
6. `--require-release-approval-signature`
7. `--require-rotation-pass`
8. `--require-ci-context-match`
9. `--require-artifact-context-consistency`
10. `--promotion-policy-file`
11. `--promotion-workflow-file`

Expected release directory includes:

1. `build_manifest.json`
2. `release_bundle.json`
3. `release_approval.json` (when approval policy is enabled)
4. `release_receipt.json`
5. compiled module artifacts (`.pyd`/`.so`)
6. compiled runtime artifacts (`enc_rt_*`)
7. package `__init__.py` files
8. license sidecar (when `keys.mode=license-file`)

## 5. soenc.toml Contract

`soenc.toml` can define defaults for the mainline.

Supported sections:

1. `[project]`
2. `[build]`
3. `[keys]`
4. `[package]`
5. `[release]`

Minimal example:

```toml
[project]
target = "./src_pkg"
scope_config = "./src_pkg/scope.json"

[build]
output_dir = "./out/staging"
release_dir = "./out/release"
build_profile = "auto"

[keys]
mode = "license-file"
license_file = "./licenses/runtime_license.json"
require_manifest_signature = true

[package]
name = "enc2sop-demo"
version = "1.0.0"
vendor = "example"
channel = "prod"

[release]
require_approval = true
approval_file = "./out/release/release_approval.json"
approval_key_file = "./ops/release_approval.key"
approval_key_id = "ops-approval-main"
```

## 6. Signature and Key Controls

1. Manifest signing is supported through key file or base64 key.
2. Signature enforcement is controlled by:
   - CLI: `--require-manifest-signature`
   - Config: `keys.require_manifest_signature = true`
3. Key mode options:
   - `local-embedded`
   - `license-file`
   - `remote-kms` (contracted fail-closed stub until live KMS integration)

## 7. Build/Runtime Guardrails

Mainline packaging and verification fail closed when:

1. staging `build_manifest.json` is missing
2. runtime delivery validation metadata is missing/incomplete
3. signature is required but missing/invalid
4. required runtime native artifacts are missing

## 8. Optional Transport Plugin

Transport is intentionally optional and isolated from mainline operation.

1. Plugin command:

```powershell
python .\soenc.py transport
```

2. Run a transport operation:

```powershell
python .\soenc.py transport export -i .\artifact.bin -o .\airgap_pkg
```

3. Generate a replayable generated-page sidecar reliability report:

```powershell
python .\soenc.py transport certify -o .\transport_cert --profile reliable-airgap-v1 --payload-size 128 --payload-size 4096 --backend sidecar --redundancy-copies 2 --parity-group-size 4
```

This writes `transport_reliability_report.json`. Add `--distortion-suite generated-page-basic-v1` to cover the basic generated-page distortion gate: PNG re-encode, JPEG recompression, mild blur, mild contrast/brightness shift, and screenshot-like high-quality recompression. Add `--distortion-suite generated-page-stress-v1` to cover generated-page resize down/up, small rotation, crop/margin loss, deterministic skew approximation, sparse noise, and print-scan-like approximation.

For OCR/text-heavy handoffs, `--payload-alphabet-profile ocr-safe-human-correctable-v1` makes generated payload lines use only `12356789OAEFHJKMNPRUVWXY`. The parser normalizes hard-safe OCR confusions, resolves ambiguous glyph candidates only through line CRC, writes `corrections_template.csv` through `analyze --emit-corrections-template` or `recover-images --emit-corrections-template` when a line cannot be resolved uniquely, and still verifies the final payload SHA256 before recovery succeeds. To produce replayable synthetic text-confusion evidence, run `soenc transport certify-ocr-confusion -o .\ocr_confusion_cert`; this writes `enc2sop-transport-ocr-safe-confusion-report/v1`, records the canonical `required_confusion_cases[]` contract, and covers `6/G/g`, `9/g/q`, `2/7/Z/z`, `O/0/o/Q/D`, `1/I/i/l/L`, `5/S/s`, `8/B/b`, whitespace insertion, dash/noise insertion, and line-break drift with per-case analyze/recovery outputs. Verify that evidence with `soenc transport verify-ocr-confusion --report-file .\ocr_confusion_cert\synthetic_ocr_confusion_report.json --output-file .\ocr_confusion_cert\synthetic_ocr_confusion_verification_report.json`; this writes `enc2sop-transport-ocr-safe-confusion-report-verification/v1` and re-checks report schema/profile/suite, payload and manifest digests, generated source-page text digests, mechanical mutation replay, case artifact digests, required confusion-family coverage, exact required-case-suite coverage, and recovered payload SHA256 parity. After an operator fills `corrected_text`, run `soenc transport replay-corrections -m .\airgap_ocr_safe\PAYLOAD.manifest.json -t .\ocr_text.txt --apply-corrections-file .\corrections_template.csv -o .\recovered.bin --report-file .\transport_ocr_correction_replay_report.json --strict-payload-chars`; this writes `enc2sop-transport-ocr-correction-replay/v1`, records applied/invalid correction rows, rejects stale generated-template rows whose `raw_text`, `normalized_text`, `status`, or `actual_crc` no longer match the current unresolved OCR line, reports unused filled rows with row number, page, line, expected CRC, and corrected-text SHA256, and writes the recovered artifact only after final SHA checks pass and the correction replay itself is accepted with no invalid, unused, malformed, or still-required rows. Malformed correction CSVs now produce a failed replay report with `correction_file_valid=false`, a structured `correction_file_error`, and suppressed output rather than only an exception. On failed replay it records `requested_output_file` plus `output_suppressed_reason`, and with unresolved current lines writes a fresh `corrections_template_retry.csv` beside the report unless `--emit-corrections-template` is provided. Verify the saved correction replay with `soenc transport verify-correction-replay --report-file .\transport_ocr_correction_replay_report.json --output-file .\transport_ocr_correction_replay_verification_report.json`; this writes `enc2sop-transport-ocr-correction-replay-verification/v1` and re-checks the report, referenced manifest/OCR/correction files, correction CSV digest, mechanical replay result, final SHA state, and output/suppression state. Package verified OCR-safe evidence with `soenc transport archive-ocr-safe-evidence --archive-file .\ocr_safe_evidence_archive.zip --manifest-file .\ocr_safe_evidence_archive_manifest.json --confusion-report-file .\ocr_confusion_cert\synthetic_ocr_confusion_report.json --correction-replay-report-file .\transport_ocr_correction_replay_report.json --require-confusion-report --require-correction-replay-report --require-source-report-verification`, then verify it with `soenc transport verify-ocr-safe-evidence-archive --archive-file .\ocr_safe_evidence_archive.zip --manifest-file .\ocr_safe_evidence_archive_manifest.json --output-file .\ocr_safe_evidence_archive_verification.json --require-confusion-report --require-correction-replay-report --require-source-report-verification`; these write `enc2sop-transport-ocr-safe-evidence-archive/v1` and `enc2sop-transport-ocr-safe-evidence-archive-verification/v1`, checking ZIP safety, external manifest envelope metadata (`archive_sha256`, `archive_size_bytes`, `archive_file`, `manifest_file`, and `embedded_manifest_sha256`), manifest parity, file digests, manifest success and typed parameter gates, manifest summary file-count/total-size, report-count/report-role, and file-role parity, required reports, archived pre-archive source-verification reports, archive-relative replay-critical paths inside embedded reports, and embedded report replay. This is a synthetic/testable human-correction profile, not a real camera, physical print-scan, or backend OCR certification claim by itself.

Backend-specific OCR-only evidence is a separate, non-default run. Use `--require-ocr-only-backend` with `--backend tesseract`, `easyocr`, or `external`, plus sidecar-disabled pages (`--no-sidecar` for generated cases). For operator capture sets, stage sidecar-free pages with `prepare-capture-corpus --ocr-only-backend tesseract` (or `easyocr`/`external`) and preflight with `validate-capture-corpus --profile ocr-only-backend-v1 --backend tesseract --require-ocr-only-backend`. The report records `ocr_only_certification`, per-case `ocr_only_evidence`, and per-backend thresholds, and fails with `ocr_only_evidence_missing` if sidecar evidence is present or the requested OCR backend was not actually selected. These reports do not certify generic OCR fallback or `reliable-airgap-v1` production readiness.

Prepare a physical/lab capture kit before the next manual scanner or camera run:

```powershell
python .\soenc.py transport prepare-capture-corpus -o .\capture_kit --classification lab --capture-medium print-scan --payload-size 64 --payload-size 257 --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4 --capture-metadata printer=example-printer --capture-metadata scanner=example-flatbed --capture-metadata dpi=300 --capture-metadata capture_session_id=example-session-001 --capture-metadata operator=example-operator --capture-metadata captured_at_utc=2026-05-28T00:00:00Z
```

This writes generated pages, empty `captures/*` drop directories, `capture_corpus.json`, `capture_kit_manifest.json`, `instructions/operator_capture_metadata_manifest_template.json`, and `instructions/operator_return_manifest_template.json`. Fill the metadata template with the actual session, operator, timestamp, and scanner/camera/printer metadata before passing it to ingestion or the one-command pipeline with `--capture-metadata-manifest-file`. If a lab returns a ZIP, rename the return template to `operator_return_manifest.json` at the ZIP root; it binds the package to the prepared corpus SHA256, can optionally bind the finalized kit-manifest SHA256, and includes a required `capture_file_inventory` block. Replace the inventory placeholders with every returned scan/photo path plus its SHA256 and byte size so extraction can reject missing, extra, or byte-drifted capture files. The kit and templates are only replay contracts. After real photos/scans are placed in the matching capture directories, bind them before certification:

```powershell
python .\soenc.py transport attach-capture-corpus --capture-corpus-file .\capture_kit\capture_corpus.json --kit-manifest-file .\capture_kit\capture_kit_manifest.json --require-captures --require-distinct-capture-images
```

If the lab or operator returns a separate folder tree, ingest it first instead of hand-editing `capture_corpus.json`. The capture root should contain one subdirectory per case label; for camera runs, provide a separate raw-photo root with matching labels:

```powershell
python .\soenc.py transport ingest-capture-corpus --capture-corpus-file .\capture_kit\capture_corpus.json --capture-root .\lab_scans --kit-manifest-file .\capture_kit\capture_kit_manifest.json --capture-medium print-scan --capture-metadata scanner=example-flatbed --capture-metadata dpi=300 --capture-metadata capture_session_id=example-session-001 --capture-metadata operator=example-operator --capture-metadata captured_at_utc=2026-05-28T00:00:00Z --require-captures
```

For multi-case lab handoffs, use the generated `instructions\operator_capture_metadata_manifest_template.json` or put operator/session/device metadata in a JSON manifest and pass `--capture-metadata-manifest-file`. The schema is `enc2sop-transport-capture-metadata-manifest/v1`; ingestion merges existing case metadata, manifest defaults, manifest per-case metadata, then CLI `--capture-metadata` overrides:

```json
{
  "schema": "enc2sop-transport-capture-metadata-manifest/v1",
  "capture_metadata_defaults": {
    "capture_session_id": "example-session-001",
    "operator": "example-operator",
    "captured_at_utc": "2026-05-28T00:00:00Z",
    "scanner": "example-flatbed",
    "dpi": "300"
  },
  "cases": [
    {
      "label": "capture-case-0001",
      "capture_metadata": {
        "scanner": "example-flatbed-unit-a"
      }
    }
  ]
}
```

This writes `enc2sop-transport-capture-corpus-ingestion-report/v1`, updates the corpus case paths, records SHA256/size bindings, and refreshes the kit manifest. It is still only ingestion evidence; attachment, validation, certification, archive verification/replay, and `certification-status` gates remain required for any medium claim.

If the lab returns a ZIP instead of an extracted folder tree, put capture files under `captures/<case-label>/...`, optional camera raw files under `raw_captures/<case-label>/...`, optionally `operator_capture_metadata_manifest.json`, and preferably `operator_return_manifest.json` at the package root. The return manifest schema is `enc2sop-transport-capture-return-manifest/v1`; when present, extraction fails closed if its `capture_corpus_sha256` does not match the prepared `capture_corpus.json`, if listed case labels are not in the prepared corpus, and it also checks `capture_kit_manifest_sha256` when that optional value is filled. When `capture_file_inventory.required=true`, every listed capture/raw image must include package path, SHA256, and byte size, and the ZIP must not contain unlisted capture images.

To avoid hand-filling those inventory values, assemble the return package from an extracted return folder:

```powershell
python .\soenc.py transport package-capture-return --capture-corpus-file .\capture_kit\capture_corpus.json --capture-root .\lab_scans -o .\operator_return_pkg --kit-manifest-file .\capture_kit\capture_kit_manifest.json --capture-metadata-manifest-file .\operator_capture_metadata_manifest.json --return-session-id example-session-001 --operator example-operator --require-capture-provenance
```

This writes `operator_return.zip`, `operator_return_manifest.json`, `operator_capture_metadata_manifest.json`, and `transport_capture_return_package_report.json` (`enc2sop-transport-capture-return-package/v1`) with exact SHA256/byte-size inventory. For lab/real claim handoffs, `--require-capture-provenance` makes package assembly fail before ZIP creation unless the metadata manifest has session, operator, timestamp, and scanner/camera/printer identity for every case. Then run the one-command pipeline with `--capture-return-package-file .\operator_return_pkg\operator_return.zip --capture-return-package-report-file .\operator_return_pkg\transport_capture_return_package_report.json`. Add `--require-capture-return-manifest --require-capture-return-file-inventory --require-capture-return-package-report` for launch/lab evidence runs so ingestion cannot start unless the ZIP carries a validated return manifest, exact capture/raw image inventory, and a matching package-assembly report. It writes `return_package\transport_capture_return_package_extraction_report.json` (`enc2sop-transport-capture-return-package-extraction/v1`), rejects unsafe ZIP members, records extracted file SHA256 values, records return-manifest and file-inventory validation state, and feeds the normal ingestion step. Packaging and extraction are handoff evidence only; the later measurement/archive/status gates still decide every transport claim.

For real camera perspective-correction kits, stage raw-photo directories with `prepare-capture-corpus --classification real --capture-medium camera-photo --include-raw-capture-dirs --perspective-correction-method "operator-supplied homography correction"`. Put raw uncorrected photos in `captures\CASE__raw`. If corrected recovery images are not already available, run `correct-capture-perspective --capture-corpus-file .\camera_capture\capture_corpus.json --mode four-point --require-raw-captures` after recording per-case `perspective_correction.source_corners`; this writes `enc2sop-transport-capture-perspective-correction-report/v1` and updates `image_path` with SHA-bound corrected images. Then run `attach-capture-corpus --require-captures --require-raw-captures --require-distinct-capture-images` before certification. Perspective correction reports are preparation evidence only; the real-camera claim still requires validate/certify/archive/status gates with `--require-real-camera-perspective-correction`.

Run a preflight validation before certification when the corpus will support a claim:

```powershell
python .\soenc.py transport validate-capture-corpus --capture-corpus-file .\capture_kit\capture_corpus.json --output-file .\capture_kit\transport_capture_validation_report.json --profile reliable-airgap-v1 --backend sidecar --require-captures --require-distinct-capture-images --capture-attachment-report-file .\capture_kit\transport_capture_attachment_report.json --require-capture-attachment-report --require-capture-provenance --capture-required-classification lab --require-physical-print-scan
```

This writes `enc2sop-transport-capture-corpus-validation/v1` with per-case missing-gate reasons. It checks readiness only; it does not run recovery or certify print-scan, camera, OCR-only, or production airgap readiness. Add `--require-capture-provenance` for real/lab claims so missing `capture_session_id`, `operator`, `captured_at_utc`, or capture device metadata fails before measurement.

This writes `transport_capture_attachment_report.json`, records attached image SHA256 values in `capture_corpus.json`, and refreshes the kit manifest summary. It is not recovery certification; use `certify --capture-corpus-file .\capture_kit\capture_corpus.json --capture-corpus-only` to measure supplied captures. Add `--require-capture-attachment-report` to the certification run when the claim depends on physical or operator-provided files; certification then fails closed with `capture_attachment_report_mismatch` unless the current capture/raw/reference image path, size, and SHA256 records match the attachment report. Add `--require-capture-provenance` when the claim depends on lab/real operator captures; certification then fails closed with `capture_provenance_missing` unless each case records session, operator, timestamp, and capture-device metadata. After a passing run, package replay evidence with `soenc transport archive-evidence --report-file .\transport_cert\transport_reliability_report.json -o .\transport_evidence_archive --require-successful-report --require-profile-certified --require-capture-attachment-report`; add `--require-physical-print-scan`, `--require-real-camera-perspective-correction`, or `--require-ocr-only-backend` to archive creation when packaging one of those claims. Archive creation fails closed unless the report required and passed the same gate. Verify the package before handoff with `soenc transport verify-evidence-archive --archive-file .\transport_evidence_archive\transport_capture_evidence_archive.zip --manifest-file .\transport_evidence_archive\transport_capture_evidence_archive_manifest.json --require-successful-report --require-profile-certified --require-capture-attachment-report` plus the same medium/backend gate, then replay it with `soenc transport replay-evidence-archive --archive-file .\transport_evidence_archive\transport_capture_evidence_archive.zip --manifest-file .\transport_evidence_archive\transport_capture_evidence_archive_manifest.json -o .\transport_evidence_replay --require-successful-report --require-profile-certified --require-capture-attachment-report` plus the same medium/backend gate. For an already populated operator corpus, `soenc transport certify-capture-evidence --capture-corpus-file .\capture_kit\capture_corpus.json -o .\capture_pipeline --profile reliable-airgap-v1 --backend sidecar --capture-required-classification lab --require-capture-provenance --require-physical-print-scan --require-certified-claim physical-print-scan` runs attach, validate, certify, archive, verify, executable archive replay, and certification status in one fail-closed chain. If the lab returns a separate folder tree, add `--capture-root .\lab_scans --capture-medium print-scan --capture-metadata-manifest-file .\operator_capture_metadata.json`; for camera evidence also add `--raw-capture-root .\raw_photos --require-raw-captures --capture-medium camera-photo`. The pipeline then writes `ingest\transport_capture_corpus_ingestion_report.json` before attachment and fails closed before certification when required external captures are missing. Then generate launch status with `soenc transport certification-status --archive-file .\transport_evidence_archive\transport_capture_evidence_archive.zip --manifest-file .\transport_evidence_archive\transport_capture_evidence_archive_manifest.json --verify-archive --require-certified-claim physical-print-scan`; repeat `--require-certified-claim` for every transport claim in the launch copy. The status command writes `claim_gate` metadata and exits non-zero if any requested claim is not certified. The archive, verifier, replay, pipeline, and status gate preserve replayability only; they do not broaden the certification claim beyond the included report gates. Reports and archives also include `certification_claims` (`enc2sop-transport-certification-claims/v1`); each claim is usable only when that claim has `certified=true`, so synthetic stress, lab print-scan, real camera perspective correction, and OCR-only backend evidence stay separate. The capture manifest schema is `enc2sop-transport-capture-corpus/v1` and records a corpus `classification` of `real`, `lab`, `synthetic`, or `stress-only`, plus per-case `capture_medium` (`unspecified`, `camera-photo`, `print-scan`, or `mixed`), `label`, `manifest_path`, `payload_path`, `image_path`, optional `reference_image_paths`, optional `raw_image_paths`, optional `perspective_correction`, and optional `capture_metadata`. Reports record source image SHA256 values, reference image SHA256 values, raw camera image SHA256 values when provided, backend, success/failure reason, capture-medium counts, and per-classification success rates. For physical/lab claims, add `--capture-required-classification lab` or `real`, `--capture-required-success-rate`, `--require-distinct-capture-images`, `--require-capture-attachment-report`, and usually `--require-capture-provenance`; the distinct gate rejects byte-identical generated-page fixture copies with `capture_reference_not_distinct`. `attach-capture-corpus --require-raw-captures` rejects missing camera raw-photo attachments with `raw_capture_images_missing`. For physical print-scan claims, also add `--require-physical-print-scan`; this requires `capture_medium=print-scan`, generated reference pages, byte-distinct scan images, and printer/scanner/dpi metadata. For a real camera perspective-correction claim, also add `--require-real-camera-perspective-correction`; this requires corpus classification `real`, raw camera photos in `raw_image_paths`, perspective-corrected recovery images in `image_path`, and `perspective_correction.applied=true` plus a method. For OCR-only claims, also add `--require-ocr-only-backend` with a non-sidecar backend and sidecar-free pages. Real camera/photo, full physical print-scan, and OCR-only claims remain uncertified unless a report explicitly measures and passes those cases for the claimed corpus and backend.

For full transport workflow and backend behavior, use [QRCODE_AIRGAP_MANUAL.md](./QRCODE_AIRGAP_MANUAL.md).

## 9. Troubleshooting

1. `staging directory not found`:
   - pass `--staging-dir` or set `[build].output_dir` in `soenc.toml`.
2. `build directory not found`:
   - run `soenc build` first or pass `--build-dir`.
3. signature-required errors:
   - provide signing key and ensure manifest contains a valid signature.
4. missing compiler/toolchain:
   - verify interpreter, Cython, and platform build tools.
5. release gate mismatch errors:
   - regenerate package (`soenc package`), regenerate approval metadata (`soenc approve-release`), and rerun release gate (`soenc release`).

## 10. Recommended Operator Sequence

1. `soenc protect`
2. `soenc build`
3. `soenc verify`
4. `soenc package`
5. `soenc approve-release`
6. `soenc release`
7. `soenc audit-promotion`
8. `soenc promotion-dry-run` (preferred rollout gate automation)
9. `soenc collect-promotion-evidence` (if manual split collect/audit steps are needed)
10. downstream release/distribution
## 11. CI Promotion Gate Rollout

Primary workflow file:

- `.github/workflows/release_promotion.yml`

The workflow enforces the signed approval gate in CI by running:

1. `soenc protect -> soenc build -> soenc verify -> soenc package`
2. `soenc approve-release` with CI-managed key material
3. `soenc release --require-release-approval`
4. artifact upload of `release_bundle.json`, `release_approval.json`, `release_receipt.json`
5. policy dry-run gate execution via `soenc promotion-dry-run` and artifact upload of:
   - `promotion_evidence.json`
   - `promotion_audit_report.json`
6. structured rotation rehearsal evidence artifact upload:
   - `rotation_rehearsal_report.json` (`enc2sop-rotation-rehearsal/v1`)
   - report is initialized for every run and finalized during `rotation_rehearsal=true` executions
7. promotion artifact integrity gate execution via `soenc verify-promotion-artifacts`
   - verifies release + promotion + rotation artifact schema/integrity before upload
8. promotion run receipt artifact upload:
   - `promotion_run_receipt.json` (`enc2sop-promotion-run-receipt/v1`)
   - includes SHA256 digests for release/promotion/rotation/audit artifacts plus GitHub run context
9. CI-context binding enforcement via `soenc verify-promotion-artifacts --require-ci-context-match`
   - ensures archived `promotion_evidence.json` context matches the current protected-branch run identity
   - ensures archived `rotation_rehearsal_report.json` run metadata (including workflow name/event) matches the current workflow run identity
   - ensures workflow-definition identity plus host/API URL/job/actor identity also matches (`GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`, `GITHUB_SERVER_URL`, `GITHUB_API_URL`, `GITHUB_GRAPHQL_URL`, `GITHUB_JOB`, `GITHUB_ACTOR`), enforces workflow-definition repository semantics (`owner/repo` segment inside `GITHUB_WORKFLOW_REF` must equal `GITHUB_REPOSITORY`), run number/retention controls also match (`GITHUB_RUN_NUMBER`, `GITHUB_RETENTION_DAYS`), ref-name/ref-type also match (`GITHUB_REF_NAME`, `GITHUB_REF_TYPE`) with semantic consistency (`GITHUB_REF_NAME` equals the suffix implied by `GITHUB_REF` + `GITHUB_REF_TYPE`), runner execution provenance also matches (`RUNNER_ENVIRONMENT`, `RUNNER_OS`, `RUNNER_ARCH`, `RUNNER_NAME`), numeric actor/repository identifiers also match (`GITHUB_ACTOR_ID`, `GITHUB_REPOSITORY_ID`), and repository-owner identity also matches (`GITHUB_REPOSITORY_OWNER`, `GITHUB_REPOSITORY_OWNER_ID`) across evidence, rotation report, and pre-existing run receipt checks
   - ensures rerun/dispatch triggering-actor context is fail-closed when runtime exports it (`GITHUB_TRIGGERING_ACTOR`) across evidence, rotation report, signed approval provenance, and pre-existing run receipt checks
   - ensures protected-ref governance context (`GITHUB_REF_PROTECTED`) remains consistent across evidence, rotation report, release approval provenance, and pre-existing run receipt checks
   - ensures any pre-existing archived `promotion_run_receipt.json` context (including workflow name/event) matches the current workflow run identity before receipt rewrite
10. promotion report input digest binding enforcement in `soenc verify-promotion-artifacts`
    - workflow now passes `--promotion-policy-file` and `--promotion-workflow-file` so audit report policy/workflow digests are validated against the exact files under verification.
11. cross-artifact context consistency enforcement in `soenc verify-promotion-artifacts --require-artifact-context-consistency`
    - ensures release approval/receipt, rotation report projection, and pre-existing run receipt are context-consistent with the archived promotion evidence context even in offline verification scenarios.

### 11.1 Required GitHub Configuration

1. Create protected environment `production-promotion` and require reviewers.
2. Add repository/environment secret `SOENC_RELEASE_APPROVAL_KEY_B64` (base64 HMAC key bytes).
3. Optional: add secret `SOENC_RELEASE_APPROVAL_KEY_ID` to pin key identity (default `ci-approval-hmac-v1`).
4. Protect `main` and `release/**` branches with required status checks including `Signed Approval Promotion Gate`.
5. Optional (rotation rehearsal): add `SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64` with previous approval HMAC key bytes.

### 11.2 Dry-Run Checklist

1. Trigger workflow manually (`workflow_dispatch`) before enabling required status checks.
2. Confirm workflow fails when `SOENC_RELEASE_APPROVAL_KEY_B64` is removed.
3. Confirm workflow fails if `release_approval.json` is tampered between `approve-release` and `release` steps.
4. Confirm workflow executes `soenc promotion-dry-run` and uploads `promotion_evidence.json` + `promotion_audit_report.json`.
5. Confirm successful run uploads all release artifacts and shows `release_approval_verified=true` in logs.
6. Trigger `workflow_dispatch` with `rotation_rehearsal=true` and confirm old key (`SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64`) is rejected.
7. Confirm `rotation_rehearsal_report.json` is uploaded:
   - `status=passed` and `old_key_rejected=true` for successful rehearsal,
   - `status=blocked` when previous-key secret is missing,
   - `status=failed` if old key unexpectedly passes.
8. Confirm `promotion_run_receipt.json` is uploaded and includes artifact digests plus run context (`GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_RUN_NUMBER`, `GITHUB_RETENTION_DAYS`, `GITHUB_SHA`, `GITHUB_REF`).
9. Confirm `promotion_artifact_audit_report.json` shows `ci_context_match_required=true` and passes under the expected protected-branch run context.
10. Confirm `rotation_rehearsal_report.json` includes workflow run metadata fields:
   - `workflow_run_id`
   - `workflow_run_attempt`
   - `workflow_run_number`
   - `workflow_retention_days`
   - `workflow_ref`
   - `workflow_ref_name`
   - `workflow_ref_type`
   - `workflow_sha`
   - `workflow_name`
   - `workflow_name_ref`
   - `workflow_name_sha`
   - `workflow_event`
   - `workflow_actor`
   - `workflow_triggering_actor`
   - `workflow_runner_environment`
   - `workflow_runner_os`
   - `workflow_runner_arch`
   - `workflow_runner_name`
   - `workflow_ref_protected`

### 11.3 Live Evidence Capture (Protected Branch/Environment)

Use this helper to execute the real workflow-dispatch run and archive deterministic evidence locally:

```bash
bash scripts/github_release_promotion_evidence.sh --repo owner/repo --ref main --rotation-rehearsal true
```

Before dispatching, validate the target repository and active workflow identity without starting a run:

```bash
bash scripts/github_release_promotion_evidence.sh --repo owner/repo --ref main --preflight-only
```

This writes `.tmp_ci/live_promotion/promotion_preflight_receipt.json` with schema `enc2sop-promotion-preflight/v1`. It proves repository API access and workflow-definition identity only; it is not a substitute for archived protected-branch promotion artifacts.

If workflow dispatch is not available from your current environment, capture from an already started run:

```bash
bash scripts/github_release_promotion_evidence.sh --repo owner/repo --run-id 123456789 --run-attempt 2
```

Optional: tune artifact-index wait behavior when GitHub artifact listing lags run completion:

```bash
bash scripts/github_release_promotion_evidence.sh --repo owner/repo --run-id 123456789 --artifact-index-wait-seconds 300
```

What it does:

1. Dispatches `.github/workflows/release_promotion.yml` via `gh workflow run`.
   - helper first tries the GitHub workflow-dispatch API with `return_run_details=true` and extracts `workflow_run_id` directly from the dispatch response when available.
   - if that API path is unavailable in the current GH CLI/runtime, helper falls back to `gh workflow run` and then resolves run id from dispatch output / recent-run fallback.
   - or, with `--run-id`, reuses an existing workflow run without dispatching.
2. Waits for completion and fails on non-success conclusions.
3. Resolves the exact per-attempt artifact metadata via GitHub API and fails closed unless:
    - exactly one matching artifact exists for the run attempt,
    - artifact is not expired,
    - artifact `workflow_run.id` matches the target run,
    - artifact digest/size metadata are present and valid,
    - artifact-linked `workflow_head_branch` and `workflow_head_sha` metadata match the resolved workflow run details.
   - helper retries boundedly (default `180s`) when artifact metadata is not yet indexed after run success; timeout remains fail-closed.
4. Verifies exact promotion gate job/step execution for the resolved run attempt before artifact acceptance:
   - `actions/runs/<run_id>/attempts/<run_attempt>/jobs` must contain exactly one `Signed Approval Promotion Gate` job.
   - that job must be `status=completed` and `conclusion=success`.
   - that job must expose non-empty `runner_name` / `runner_group_name`, and labels must not mix `self-hosted` with `github-hosted`.
   - when run-summary workflow identity is present, promotion-job `workflow_name` must match run `workflowName`.
   - when promotion-job payload includes actor metadata, `actor.login` / `triggering_actor.login` must match run details.
   - required control steps (`Require Protected Ref Context`, `Verify Promotion Artifacts`, `Bundle Promotion Artifacts`, `Upload Promotion Artifacts`, etc.) must each conclude `success`.
   - rotation-step parity is enforced:
     - with `--rotation-rehearsal true`, `Rehearse Approval Key Rotation (old key must fail)` must conclude `success`;
     - with `--rotation-rehearsal false`, that step must conclude `skipped`.
5. Downloads the artifact ZIP by artifact id and fails closed unless:
   - downloaded archive SHA256 matches `artifact_metadata.digest`,
   - downloaded archive byte size matches `artifact_metadata.size_in_bytes`.
6. Extracts the verified archive:
   - `soenc-promotion-<run_id>-attempt-<run_attempt>.zip`
7. Verifies required files are present in the extracted artifact:
   - `release_bundle.json`
   - `release_approval.json`
   - `release_receipt.json`
   - `promotion_evidence.json`
   - `promotion_audit_report.json`
   - `rotation_rehearsal_report.json`
   - `promotion_artifact_audit_report.json`
   - `promotion_run_receipt.json`
   - `promotion_artifact_bundle.zip`
8. Verifies `promotion_artifact_bundle.zip` manifest binding before accepting capture:
   - `bundle_manifest.json` exists and is valid `enc2sop-promotion-artifact-bundle/v1`.
   - required bundle entries (`release_*`, `promotion_*`, `rotation_*`) are present with expected archive paths.
   - each required bundle entry SHA256 matches the extracted required artifact file digest.
9. Verifies `promotion_artifact_audit_report.json` and `promotion_run_receipt.json` semantics before capture receipt emission:
   - `promotion_artifact_audit_report` must be `enc2sop-promotion-artifact-audit/v1` with `passed=true` and `summary.total_failures=0`.
   - `promotion_artifact_audit_report` must also prove strict gate-mode settings:
     - `release_approval_signature_required=true`,
     - `ci_context_match_required=true`,
     - `artifact_context_consistency_required=true`,
     - `rotation_pass_required` boolean parity with requested `--rotation-rehearsal` mode.
   - `promotion_run_receipt` must be `enc2sop-promotion-run-receipt/v1` with `passed=true`.
   - `promotion_run_receipt.rotation_pass_required` must match requested mode (`--rotation-rehearsal true/false`).
   - release-approval key lineage must remain coherent across extracted artifacts:
     - `release_approval.json` must be `enc2sop-release-approval/v1` with non-empty trimmed `signature.key_id`,
     - `release_receipt.json` must be `enc2sop-release-receipt/v1` with non-empty trimmed `release_approval_key_id`,
     - `promotion_run_receipt.release_approval_key_id` must match both values above.
   - `promotion_run_receipt.signature` is mandatory and must include:
     - `algorithm=hmac-sha256`,
     - non-empty trimmed `key_id` matching `promotion_run_receipt.release_approval_key_id`,
     - canonical 64-char lowercase hex `digest_hex`.
   - required run-receipt artifact entries (`release_*`, `promotion_*`, `rotation_*`) must exist and each digest must match extracted files.
   - release-context parity is independently enforced against run-receipt context:
     - `release_receipt.github_context` must exist as a JSON object.
     - `release_receipt.release_approval_github_context` must exist as a JSON object.
     - `release_approval.github_context` must exist as a JSON object.
     - `release_receipt.release_approval_github_context` must exactly match `release_approval.github_context`.
     - required keys must match run-receipt context:
       - `GITHUB_REPOSITORY`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_ACTIONS`, `CI`, `GITHUB_REF_PROTECTED`,
      - `GITHUB_REPOSITORY_OWNER`, `GITHUB_REPOSITORY_ID`, `GITHUB_REPOSITORY_OWNER_ID`, `GITHUB_ACTOR_ID`, `GITHUB_RETENTION_DAYS`,
      - `GITHUB_WORKFLOW_SHA`, `GITHUB_SERVER_URL`, `GITHUB_API_URL`, `GITHUB_GRAPHQL_URL`.
     - optional keys must match when present in run-receipt context:
       - `GITHUB_SHA`, `GITHUB_RUN_NUMBER`, `GITHUB_REF`, `GITHUB_REF_NAME`, `GITHUB_REF_TYPE`,
       - `GITHUB_EVENT_NAME`, `GITHUB_JOB`, `GITHUB_WORKFLOW`, `GITHUB_WORKFLOW_REF`,
       - `GITHUB_ACTOR`, `GITHUB_TRIGGERING_ACTOR`, `RUNNER_NAME`.
   - run-receipt GitHub context must include and match:
     - `GITHUB_REPOSITORY`,
     - `GITHUB_RUN_ID`,
     - `GITHUB_RUN_ATTEMPT`,
     - when available from run identity: `GITHUB_SHA` and `GITHUB_RUN_NUMBER`,
     - when run head branch is available from run identity: `GITHUB_REF=refs/heads/<head_branch>`, `GITHUB_REF_NAME=<head_branch>`, and `GITHUB_REF_TYPE=branch`,
     - when available from promotion-job verification: `GITHUB_WORKFLOW`,
     - `GITHUB_ACTIONS=true`,
     - `CI=true`,
     - `GITHUB_REF_PROTECTED=true`,
     - when available from promotion-job verification: `GITHUB_ACTOR`, `GITHUB_TRIGGERING_ACTOR`, and `RUNNER_NAME`,
     - and, when present from run identity, `GITHUB_EVENT_NAME` / `GITHUB_WORKFLOW_REF`.
    - promotion-gate job metadata must include and match resolved run identity for:
      - `run_id`,
      - `head_sha` (canonical 40-char lowercase hex),
      - `head_branch` (when run identity includes a branch).
    - retention-window parity must hold across capture inputs:
      - run-detail `retention_days` must be present, numeric, and positive,
      - `rotation_rehearsal_report.workflow_retention_days` must be present, trimmed, a positive integer, and match run-detail `retention_days`,
      - `promotion_run_receipt.github_context.GITHUB_RETENTION_DAYS` must match run-detail `retention_days`,
      - release-context payloads must match run-receipt `GITHUB_RETENTION_DAYS`.
10. Writes `promotion_capture_receipt.json` with artifact file paths plus SHA256 digests for replayable audit handoff.
   - receipt now records validated run identity metadata:
      - `workflow_path` and resolved `workflow_ref` (`.github/workflows/release_promotion.yml@<git-ref>`),
      - `workflow_event`, `workflow_head_branch`, `workflow_head_sha`, and `workflow_run_number`,
      - `workflow_run_html_url`,
      - `workflow_run_id_resolution_mode` (`provided`, `dispatch-api`, `dispatch-output`, or `recent-runs`).
   - receipt now records `workflow_context_verification`:
      - `repository_owner`,
      - `repository_id`,
      - `repository_owner_id`,
      - `actor_id`,
      - `run_repository_id`,
      - `run_repository_owner_id`,
      - `run_actor_id`,
      - `retention_days`,
      - `workflow_sha`,
      - `server_url`,
      - `api_url`,
      - `graphql_url`.
   - receipt now records `promotion_job_verification`:
     - promotion job identity/status/conclusion/timestamps,
     - `required_step_count_verified`,
     - rotation-step conclusion parity (`success` when requested, `skipped` when not requested),
     - runner and actor provenance binding:
       - `runner_name`,
       - `runner_group_name`,
       - `runner_labels`,
     - `actor_login`,
     - `triggering_actor_login`.
     - `actor_parity_checked`,
     - `triggering_actor_parity_checked`.
   - receipt now records `artifact_metadata` from GitHub API:
     - `id`, `digest`, `size_in_bytes`, `created_at`, `updated_at`, `expires_at`,
     - `archive_download_url`,
     - artifact-linked `workflow_run_id`, `workflow_head_branch`, and `workflow_head_sha`.
   - receipt now records `artifact_archive_verification`:
     - downloaded archive `path`,
     - `digest_verified`,
     - `size_in_bytes_verified`,
     - `entry_count_verified`.
   - receipt now records `bundle_manifest_verification`:
     - `schema`,
     - `path`,
     - `required_entries_verified`,
     - `required_entry_count_verified`,
     - `file_count_reported`,
     - `manifest_sha256`.
   - receipt now records `promotion_run_receipt_verification`:
     - `schema`,
     - `passed`,
     - `rotation_pass_required`,
     - `artifact_entries_verified`,
     - `artifact_entry_count_verified`.
    - receipt now records `rotation_report_verification`:
      - `requested`,
      - `executed`,
      - `old_key_rejected`,
      - `status`,
      - `workflow_retention_days`.
   - receipt now records `release_context_verification`:
     - `contexts_verified`,
     - `required_keys_verified`,
     - `optional_keys_verified_when_present`.
   - capture fails closed on run-identity mismatches (workflow path, event, or expected branch when dispatching / explicit `--ref` replay capture).
   - capture fails closed when rotation evidence does not match requested mode:
     - if `--rotation-rehearsal true`: requires `rotation_rehearsal_report` with `requested=true`, `executed=true`, `old_key_rejected=true`, `status=passed`.
     - if `--rotation-rehearsal false`: requires `requested=false` (or omitted) and `status=not-requested` (or omitted).

Operational prerequisites:

1. `gh` CLI installed and able to access `repos/<owner>/<repo>` via API (token-based access via `GH_TOKEN`/`GITHUB_TOKEN` is supported even when `gh auth status` is non-zero).
2. Repository allows `workflow_dispatch` for `release_promotion.yml`.
3. Workflow definition `release_promotion.yml` (or provided `--workflow-file`) must resolve via `repos/<owner>/<repo>/actions/workflows/<id-or-file>` as `state=active`.
4. Required secrets are already configured:
   - `SOENC_RELEASE_APPROVAL_KEY_B64`
   - `SOENC_RELEASE_APPROVAL_KEY_ID` (optional but recommended)
   - `SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64` (required when `--rotation-rehearsal true`)

### 11.4 Rollback Procedure

1. Disable required status check `Signed Approval Promotion Gate` in branch protection.
2. Temporarily remove environment protection gate on `production-promotion` if emergency promotion is required.
3. Keep `SOENC_RELEASE_APPROVAL_KEY_B64` secret disabled until a rotated key is provisioned.
4. Re-enable workflow gate only after rerunning the dry-run checklist.

### 11.5 Promotion Evidence Contract

`soenc audit-promotion` expects evidence JSON in this shape:

```json
{
  "schema": "enc2sop-promotion-evidence/v1",
  "branches": [
    {
      "name": "main",
      "required_status_checks": ["Signed Approval Promotion Gate"]
    },
    {
      "name": "release/**",
      "required_status_checks": ["Signed Approval Promotion Gate"]
    }
  ],
  "environments": [
    {
      "name": "production-promotion",
      "required_reviewers_count": 1
    }
  ],
  "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"]
}
```
