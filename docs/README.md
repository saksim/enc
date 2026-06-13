# Documentation Map

This project uses four documentation layers. Each layer has one job.

```text
docs/latest/    Latest published user and launch guidance. Use this first.
docs/working/   Current iteration material. Useful, but not a launch promise.
docs/releases/  Versioned release notes and launch decisions.
docs/archive/   Historical snapshots and retired plans.
```

## What To Read

For the current non-OCR GA release:

1. `docs/latest/non_ocr_ga_release_manual.md`
2. `docs/latest/non_ocr_release_reverse_cost_checklist.md`
3. `docs/releases/v0.1.0-ga.md`

For the next non-OCR GA post-release mainline:

1. `docs/working/non_ocr_ga_release_landing_trust_hardening_plan.md`

For completed non-OCR GA governance history:

1. `docs/archive/non_ocr_ga_release_governance_plan_2026-06-13.md`
2. `docs/releases/v0.1.0-mainline-beta.1.md`

For ongoing OCR / cross-media work:

1. `docs/working/cross_media_enc_trans_imple_guide_v3.md`
2. `docs/working/cross_media_enc_trans_v3_gap_mapping.md`
3. `docs/working/cross_media_enc_trans_v3_completion_report.md`

`docs/PROMOTION_ROLLOUT_POLICY.json` remains at the docs root because release tooling uses that default path. Treat it as live policy, not prose documentation.

## Layer Rules

- `latest`: only material that describes the currently usable published product.
- `working`: drafts, active plans, gap mappings, iteration reports, and not-yet-launched claims.
- `releases`: immutable version facts, release notes, launch decision records, and tag-level summaries.
- `archive`: past plans and superseded documents kept for traceability.

Do not put new active work in `archive`. Do not put experiments in `latest`. If a working document becomes the public truth, promote a cleaned copy into `latest` and record the shipped delta under `releases`.
