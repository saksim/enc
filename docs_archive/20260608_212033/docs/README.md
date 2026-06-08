# enc2sop Docs

This directory is the production-go-live planning baseline for the `6_so_enc` project.

Current baseline date: `2026-05-06`
Current target: build `enc2sop` into a production-ready protection platform whose mainline flow is:

`protect -> build -> package -> verify -> release`

The airgap QR/OCR capability remains supported, but it is no longer treated as the platform mainline.

Current product-launch clarification date: `2026-05-25`

Broad product launch is split into separate gates:

1. mainline Beta/GA readiness for `protect -> build -> package -> verify -> release`
2. optional airgap/QR/OCR transport readiness
3. GA platform readiness that combines operational evidence plus certified transport reliability if transport is marketed as GA

The generated-page sidecar transport path now has a replayable certification loop, reliable-airgap profile, generated-page distortion report path, physical/lab capture-kit staging command, attachment-report lineage binding, capture-corpus validation preflight, evidence archive packaging with claim-specific creation gates, and strict capture gates that reject byte-identical fixture copies. Physical print-scan, real camera perspective correction, and OCR-only backend claims each have explicit non-default evidence gates. Camera/photo/full print-scan/generic-OCR transport must not be claimed as solved or GA-ready until matching reliability reports exist, pass, and are archived with the same gate.

## Document Map

1. `PRODUCT_LAUNCH_ROADMAP_2026-05-25.md`
   Active product launch track split and transport/OCR reliability construction plan.
2. `PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md`
   Current architectural baseline, decisions, blockers, and detailed launch-readiness log.
3. `IMPLEMENTATION_TASK_CARDS.md`
   Concrete implementation backlog for future Codex or GPT-5.5 coding iterations.
4. `NEXT_ITERATION_UNIVERSAL_PROMPT.md`
   Active recurring automation prompt. Future automation runs should follow this file.

## Marker Legend

- `[DECISION]`: architecture or product decision accepted as the current baseline
- `[BLOCKER]`: issue that blocks production go-live or materially raises delivery risk
- `[P0]`: must be solved before production go-live
- `[P1]`: important but can follow after the P0 baseline is stable
- `[ASSUMPTION]`: temporary assumption that later iterations must verify or replace
- `[DONE]`: completed item

## Mandatory Read Order For Every Iteration

1. Read `PRODUCT_LAUNCH_ROADMAP_2026-05-25.md`.
2. Read `PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md`.
3. Read `IMPLEMENTATION_TASK_CARDS.md`.
4. Read `NEXT_ITERATION_UNIVERSAL_PROMPT.md`.
5. Select the highest-priority incomplete task card using the card-selection policy in the roadmap/prompt.
6. Implement code, tests, and doc updates for that card.

## Update Rule

Any iteration that changes platform direction, scope, or implementation assumptions must update the affected file in `docs/` during the same iteration.
