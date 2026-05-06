You are continuing the `enc2sop` platform build toward a production launch.

Work in this order:

1. Read `docs/README.md`.
2. Read `docs/PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md` and treat it as the current architectural baseline.
3. Read `docs/IMPLEMENTATION_TASK_CARDS.md` and treat it as the current execution backlog.
4. Select the highest-priority incomplete task card whose dependencies are satisfied.
5. Implement the chosen card directly in code. Do not stop at analysis unless the repository state creates a hard blocker that cannot be resolved safely in the current iteration.

Platform truth you must preserve:

- The mainline product is `protect -> build -> package -> verify -> release`.
- `qrcode` and OCR flows are optional transport plugins, not the product core.
- P0 production blockers always outrank P1 improvements.
- Prefer explicit interfaces, config-driven behavior, and modular boundaries over additional monolithic growth.
- Security improvement must focus on key-control architecture, manifest integrity, and runtime hardening, not cosmetic obfuscation.

Execution rules:

- Make concrete code changes.
- Add or update focused tests whenever the selected card changes behavior.
- If the selected card is too large, deliver a vertical slice that still lands real code and update the card status and remaining scope in `docs/IMPLEMENTATION_TASK_CARDS.md`.
- If you change assumptions, scope, priorities, or accepted architecture, update the relevant file in `docs/` during the same iteration.
- Preserve compatibility when the cost is low; remove harmful dead structure when keeping it would slow platformization.
- If you touch the compile/protection chain, prefer verification that exercises the real protected path rather than only unit-level helpers.
- Keep optional dependencies optional. The mainline platform must not require OCR stacks to import or operate.

Required output for every iteration:

1. State the selected `card_id`.
2. State the concrete goal of the iteration.
3. Implement the change.
4. Summarize changed files.
5. Summarize verification performed.
6. Summarize what still blocks production launch.
7. Name the next recommended card.

Decision rules for selecting work:

- Finish P0 before P1 unless a P1 slice is required to complete a P0 dependency.
- Prefer infrastructure that unlocks many later cards.
- Avoid cosmetic refactors unless they directly reduce launch risk.
- Do not let the transport plugin backlog delay the protect/build/package mainline.

If you encounter unexpected repository changes:

- Do not revert user work.
- Adapt if the changes are compatible.
- If the changes directly conflict with the selected card, document the conflict and choose the safest forward path.
