# enc2sop Docs

This directory is the production-go-live planning baseline for the `6_so_enc` project.

Current baseline date: `2026-05-06`
Current target: build `enc2sop` into a production-ready protection platform whose mainline flow is:

`protect -> build -> package -> verify -> release`

The airgap QR/OCR capability remains supported, but it is no longer treated as the platform mainline.

## Document Map

1. `PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md`
   Current architectural judgment, blockers, decisions, and target platform shape.
2. `IMPLEMENTATION_TASK_CARDS.md`
   Concrete implementation backlog for future Codex or GPT-5.5 coding iterations.
3. `NEXT_ITERATION_UNIVERSAL_PROMPT.md`
   Reusable next-iteration prompt. The `enc2sop` automation must use this content as its recurring prompt.

## Marker Legend

- `[DECISION]`: architecture or product decision accepted as the current baseline
- `[BLOCKER]`: issue that blocks production go-live or materially raises delivery risk
- `[P0]`: must be solved before production go-live
- `[P1]`: important but can follow after the P0 baseline is stable
- `[ASSUMPTION]`: temporary assumption that later iterations must verify or replace
- `[DONE]`: completed item

## Mandatory Read Order For Every Iteration

1. Read this file.
2. Read `PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md`.
3. Read `IMPLEMENTATION_TASK_CARDS.md`.
4. Select the highest-priority incomplete task card whose dependencies are satisfied.
5. Implement code, tests, and doc updates for that card.

## Update Rule

Any iteration that changes platform direction, scope, or implementation assumptions must update the affected file in `docs/` during the same iteration.
