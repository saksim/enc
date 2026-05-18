# enc2sop Platform

`enc2sop` is a production-oriented Python protection platform.

Mainline product flow:

`protect -> build -> package -> verify -> release`

Airgap QR/OCR workflows remain supported, but they are optional transport plugins and are not required for mainline operation.

## Preferred CLI

Use the unified CLI entrypoint:

```powershell
python .\soenc.py --help
```

Primary commands:

1. `soenc protect`
2. `soenc build`
3. `soenc package`
4. `soenc verify`
5. `soenc release`
6. `soenc approve-release`
7. `soenc promotion-dry-run`
8. `soenc verify-promotion-artifacts` (emits `promotion_artifact_audit_report.json` and `promotion_run_receipt.json`; signs run receipts when approval verification key inputs are provided; validates promotion evidence repository identity binding when `promotion_evidence.repository` is present (`promotion_evidence.repository` must match `promotion_evidence.github_context.GITHUB_REPOSITORY`, and under strict CI mode must also match runtime `GITHUB_REPOSITORY`); supports strict `--require-ci-context-match` across release execution provenance (`release_receipt.github_context`), signed release approval provenance, promotion evidence identity, required run identity/hash/attempt/number/retention/ref/ref-name/ref-type/workflow-definition/event/host/job/actor binding (`GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_REF_NAME`, `GITHUB_REF_TYPE`, `GITHUB_RUN_ID`, `GITHUB_SHA`, `GITHUB_RUN_ATTEMPT`, `GITHUB_RUN_NUMBER`, `GITHUB_RETENTION_DAYS`, `GITHUB_WORKFLOW`, `GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`, `GITHUB_EVENT_NAME`, `GITHUB_SERVER_URL`, `GITHUB_API_URL`, `GITHUB_GRAPHQL_URL`, `GITHUB_JOB`, `GITHUB_ACTOR`), required runner-execution provenance (`RUNNER_ENVIRONMENT`, `RUNNER_OS`, `RUNNER_ARCH`, `RUNNER_NAME`), required CI-activation boolean binding (`GITHUB_ACTIONS`, `CI`, fail-closed for invalid non-boolean-like values and for semantically non-activating values such as `false`/`0`), repository-owner identity binding (`GITHUB_REPOSITORY_OWNER`, `GITHUB_REPOSITORY_OWNER_ID`), runtime-triggered mandatory triggering-actor binding (`GITHUB_TRIGGERING_ACTOR` must be present and match when runtime exports it), numeric actor/repository identity binding (`GITHUB_ACTOR_ID`, `GITHUB_REPOSITORY_ID`), protected-ref provenance (`GITHUB_REF_PROTECTED`, fail-closed for missing or invalid non-boolean-like values), rotation report run metadata (including `workflow_repository`, `workflow_run_number`, `workflow_retention_days`, and `workflow_runner_name`) with the same semantic strict-value normalization rules used for runtime/artifact contexts, and pre-existing run-receipt context; strict mode also fail-closes invalid repository-slug encodings for `GITHUB_REPOSITORY` (must be exactly `owner/repo` with one slash and `[a-z0-9._-]` segment characters), invalid non-numeric/non-semantic encodings for numeric/ref-type keys (`GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_RUN_NUMBER`, `GITHUB_RETENTION_DAYS`, `GITHUB_ACTOR_ID`, `GITHUB_REPOSITORY_ID`, `GITHUB_REPOSITORY_OWNER_ID`, `GITHUB_REF_TYPE`), invalid host/API URL encodings for `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` (must be canonical HTTPS URLs with scheme and host), semantically inconsistent endpoint mappings between `GITHUB_SERVER_URL`, `GITHUB_API_URL`, and `GITHUB_GRAPHQL_URL` (github.com => `api.github.com` with canonical paths, enterprise => same-origin `/api/v3` + `/api/graphql`), invalid commit-SHA encodings for `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` (must be 40-character hexadecimal values), invalid git-refname encodings for `GITHUB_REF` (fail-closed on malformed refname syntax), invalid `GITHUB_WORKFLOW_REF` encodings (must follow `<owner>/<repo>/.github/workflows/<file>.yml@refs/heads/*` or `<owner>/<repo>/.github/workflows/<file>.yml@refs/tags/*` with a valid git refname `@ref` segment), invalid `GITHUB_WORKFLOW_REF` repository semantics (`owner/repo` segment in `GITHUB_WORKFLOW_REF` must match `GITHUB_REPOSITORY`), invalid `GITHUB_WORKFLOW_REF` ref semantics (`@ref` segment in `GITHUB_WORKFLOW_REF` must match `GITHUB_REF`), and invalid ref semantics where `GITHUB_REF_TYPE=branch` requires `GITHUB_REF` to start with `refs/heads/`, `GITHUB_REF_TYPE=tag` requires `GITHUB_REF` to start with `refs/tags/`, and `GITHUB_REF_NAME` must match the trailing segment of `GITHUB_REF`; supports optional `--require-artifact-context-consistency` for offline cross-artifact context parity checks rooted at `promotion_evidence.github_context` across release approval/receipt, rotation report, and pre-existing run receipt; supports report input digest binding checks for policy/workflow/evidence; verifies release receipt digest binding to the archived bundle/approval; and can enforce release-approval signature verification via `--require-release-approval-signature` + approval key inputs)
9. `soenc transport` (optional plugin)

## Operator Quickstart

1. Protect source into staging:

```powershell
python .\soenc.py protect -t .\src_pkg -o .\out\staging --scope-config .\src_pkg\scope.json
```

2. Compile staged outputs:

```powershell
python .\soenc.py build --staging-dir .\out\staging --build-profile auto
```

3. Verify runtime-delivery integrity:

```powershell
python .\soenc.py verify --staging-dir .\out\staging
```

4. Package release bundle:

```powershell
python .\soenc.py package --staging-dir .\out\staging --dist-dir .\out\release
```

5. Generate signed approval metadata for CI/promotion signoff:

```powershell
python .\soenc.py approve-release --dist-dir .\out\release --release-approval-key-file .\ops\release_approval.key --approver ops-a --approver security-b
```

6. Execute release gate and emit handoff receipt:

```powershell
python .\soenc.py release --dist-dir .\out\release --require-manifest-signature --require-release-approval --release-approval-file .\out\release\release_approval.json --release-approval-key-file .\ops\release_approval.key
```

7. Release downstream artifacts from `.\out\release` (includes `release_bundle.json`, `release_approval.json`, and `release_receipt.json`).

8. Run promotion rollout dry-run gate (collects evidence and audits policy in one fail-closed step):

```powershell
python .\soenc.py promotion-dry-run --github-repo owner/repo --github-token $env:GITHUB_TOKEN
```

## Documentation Map

1. [USAGE_MANUAL.md](./USAGE_MANUAL.md)
   - End-to-end operator runbook for `protect/build/package/verify/release`
   - `soenc.toml` configuration contract
2. [QRCODE_AIRGAP_MANUAL.md](./QRCODE_AIRGAP_MANUAL.md)
   - Optional transport plugin operations (`soenc transport ...`)
   - Sidecar-first airgap recovery and OCR fallback behavior
3. [docs/PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md](./docs/PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md)
   - Architectural baseline and launch gate status
4. [docs/IMPLEMENTATION_TASK_CARDS.md](./docs/IMPLEMENTATION_TASK_CARDS.md)
   - Execution backlog and card-level status

## Linux Acceptance

After smoke passes, run the Linux pre-production acceptance script (mainline + fail-closed tamper checks):

```bash
TARGET_DIR=./src_pkg bash scripts/linux_release_acceptance.sh
```

## Compatibility Notes

Legacy script entrypoints still exist for compatibility:

1. `encryption_helper.py`
2. `qrcode_helper.py`

New platform and documentation default to `soenc.py`.
