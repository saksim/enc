You are continuing the `enc2sop` platform build toward production launch.

Current state as of 2026-05-18:

- The mainline product remains `protect -> build -> package -> verify -> release`.
- `qrcode` and OCR flows remain optional transport plugins, not product core.
- Linux pre-production acceptance has completed against a real target project (`omniprompt-gateway`) using `scripts/linux_release_acceptance.sh`.
- That acceptance run reached `[9/9] Acceptance checks passed`.
- The run verified:
  - `protect -> build -> verify -> package -> approve-release -> release`
  - tampered `release_approval.json` is rejected by `soenc release`
  - tampered runtime fingerprint metadata is rejected by `soenc verify`
  - restored manifest verifies successfully
- The remaining P0 blocker is `ENC-P0-016`: live protected-branch/environment CI promotion execution and archived evidence.

Work in this order:

1. Read `docs/README.md`.
2. Read `docs/PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md` and treat it as the current architectural baseline.
3. Read `docs/IMPLEMENTATION_TASK_CARDS.md` and treat it as the current execution backlog.
4. Select `ENC-P0-016` unless a newer P0 blocker was explicitly added after 2026-05-18.
5. Drive the next concrete slice toward live promotion evidence closure.

Primary goal for the next iteration:

Prepare and, where safely possible from the current environment, execute or make executable the real CI promotion evidence loop:

- `.github/workflows/release_promotion.yml` must run from a protected branch/environment.
- Promotion dry-run must collect or validate real rollout evidence.
- Promotion artifact verification must archive replayable evidence.
- Rotation rehearsal must prove old approval-key material is rejected.

Expected evidence artifacts:

- `release_bundle.json`
- `release_approval.json`
- `release_receipt.json`
- `promotion_evidence.json`
- `promotion_audit_report.json`
- `rotation_rehearsal_report.json`
- `promotion_artifact_audit_report.json`
- `promotion_run_receipt.json`

Execution rules:

- Prefer operational closure over more local hardening.
- If live GitHub execution is unavailable from the current environment, implement the smallest concrete improvement that makes the live run more deterministic, observable, or auditable.
- Do not let optional transport/OCR work delay the mainline launch gate.
- Do not weaken signed approval, manifest integrity, runtime fingerprint, or CI provenance checks.
- Preserve compatibility when the cost is low.
- Update `docs/IMPLEMENTATION_TASK_CARDS.md` during the same iteration with the new evidence state, blocker state, and remaining scope.
- If assumptions about launch readiness change, update `docs/PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md`.

Useful commands and checks:

- Local focused tests:
  - `python -m pytest -q tests/test_promotion_artifacts.py tests/test_soenc_cli.py tests/test_release_promotion_workflow.py`
  - `python -m pytest -q tests/test_encryption_helper.py tests/test_toolchain_profile.py tests/test_soenc_cli.py`
- Linux pre-production acceptance, already passed externally:
  - `TARGET_DIR=/home/saksim/program_git/omniprompt-gateway nohup bash scripts/linux_release_acceptance.sh > logs 2>&1 &`
- CI workflow target:
  - `.github/workflows/release_promotion.yml`

Required output for every iteration:

1. State the selected `card_id`.
2. State the concrete goal of the iteration.
3. Implement or execute the next concrete evidence-closure step.
4. Summarize changed files or external evidence produced.
5. Summarize verification performed.
6. Summarize what still blocks production launch.
7. Name the next recommended card.

If you encounter unexpected repository changes:

- Do not revert user work.
- Adapt if the changes are compatible.
- If the changes directly conflict with `ENC-P0-016`, document the conflict and choose the safest forward path.
