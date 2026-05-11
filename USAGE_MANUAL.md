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
3. Verifies `release_receipt.json` is bound to the current `release_bundle.json` and `release_approval.json` through SHA256 digest fields, and that the receipt approval key/signature metadata matches the approval artifact.
4. Optional release-approval signature verification:
   - provide `--release-approval-key-file` or `--release-approval-key-b64` to validate `release_approval.signature.digest_hex` against canonical payload bytes.
   - optional `--release-approval-key-id` enforces signature key-id pinning.
   - `--require-release-approval-signature` fail-closes when no approval verification key is supplied.
5. Validates promotion evidence/report schema state and requires `promotion_audit_report.passed=true`.
6. Validates rotation report schema and status fields.
7. Optional `--require-rotation-pass` enforces `status=passed` and `old_key_rejected=true`.
8. Optional `--require-ci-context-match` enforces CI-context binding across:
   - `promotion_evidence.github_context` identity (`GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_RUN_ID`) plus required workflow/event binding (`GITHUB_WORKFLOW`, `GITHUB_EVENT_NAME`) and optional `GITHUB_SHA`/`GITHUB_RUN_ATTEMPT` checks when both sides are present.
   - `rotation_rehearsal_report.json` run metadata (`workflow_run_id`, `workflow_ref`, `workflow_sha`, `workflow_run_attempt`, `workflow_name`, `workflow_event`) against the current workflow run context when runtime values are present.
   - pre-existing `promotion_run_receipt.json` `github_context` identity (`GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_RUN_ID`) plus required workflow/event binding (`GITHUB_WORKFLOW`, `GITHUB_EVENT_NAME`) and optional `GITHUB_SHA`/`GITHUB_RUN_ATTEMPT` checks when both sides are present.
9. Writes `promotion_artifact_audit_report.json` and `promotion_run_receipt.json` and exits non-zero on any mismatch.
10. Enforces promotion audit/evidence input binding:
   - `promotion_audit_report.inputs.evidence_file` must match the evidence artifact path under verification.
   - `promotion_audit_report.inputs.evidence_sha256` must match the evidence artifact digest.
   - `promotion_audit_report.inputs.policy_file` / `policy_sha256` must match the policy file used by verification.
   - `promotion_audit_report.inputs.workflow_file` / `workflow_sha256` must match the workflow file used by verification.

Optional:

1. `--report-file`
2. `--run-receipt-file`
3. `--release-approval-key-file`
4. `--release-approval-key-b64`
5. `--release-approval-key-id`
6. `--require-release-approval-signature`
7. `--require-rotation-pass`
8. `--require-ci-context-match`
9. `--promotion-policy-file`
10. `--promotion-workflow-file`

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
   - ensures any pre-existing archived `promotion_run_receipt.json` context (including workflow name/event) matches the current workflow run identity before receipt rewrite
10. promotion report input digest binding enforcement in `soenc verify-promotion-artifacts`
   - workflow now passes `--promotion-policy-file` and `--promotion-workflow-file` so audit report policy/workflow digests are validated against the exact files under verification.

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
8. Confirm `promotion_run_receipt.json` is uploaded and includes artifact digests plus run context (`GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_SHA`, `GITHUB_REF`).
9. Confirm `promotion_artifact_audit_report.json` shows `ci_context_match_required=true` and passes under the expected protected-branch run context.
10. Confirm `rotation_rehearsal_report.json` includes workflow run metadata fields:
   - `workflow_run_id`
   - `workflow_run_attempt`
   - `workflow_ref`
   - `workflow_sha`
   - `workflow_name`
   - `workflow_event`

### 11.3 Rollback Procedure

1. Disable required status check `Signed Approval Promotion Gate` in branch protection.
2. Temporarily remove environment protection gate on `production-promotion` if emergency promotion is required.
3. Keep `SOENC_RELEASE_APPROVAL_KEY_B64` secret disabled until a rotated key is provisioned.
4. Re-enable workflow gate only after rerunning the dry-run checklist.

### 11.4 Promotion Evidence Contract

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


