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
8. `soenc verify-promotion-artifacts` (emits `promotion_artifact_audit_report.json` and `promotion_run_receipt.json`; supports strict `--require-ci-context-match` across promotion evidence identity, workflow/event binding, rotation report run metadata, and pre-existing run-receipt context with optional SHA/attempt checks; supports report input digest binding checks for policy/workflow/evidence; verifies release receipt digest binding to the archived bundle/approval; and can enforce release-approval signature verification via `--require-release-approval-signature` + approval key inputs)
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

## Compatibility Notes

Legacy script entrypoints still exist for compatibility:

1. `encryption_helper.py`
2. `qrcode_helper.py`

New platform and documentation default to `soenc.py`.
