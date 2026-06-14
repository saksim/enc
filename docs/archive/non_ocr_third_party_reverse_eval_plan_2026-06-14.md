# Non-OCR Third-Party Reverse Evaluation Plan

Date: 2026-06-13
Archived: 2026-06-14
Status: archived
Parent: `docs/working/non_ocr_post_ga_trust_hardening_checklist.md`
Scope item: third-party reverse-engineering evaluation template

## One-Line Goal

Create a repeatable, evidence-driven package for an external reviewer to assess the reverse-engineering cost of the non-OCR encryption/code-protection line without expanding the GA product promise.

## Scope

This plan covers only the non-OCR line:

```text
file encryption/decryption
Python code protection
native packaging
license-file delivery
release evidence bundle
no-source-leak / reverse-cost gate
```

## Explicit Non-Goals

This plan does not claim or implement:

```text
OCR / QR / cross-media evaluation
remote-KMS service evaluation
absolute anti-reverse guarantee
third-party evaluation completed
production incident response drill
```

## Deliverables

```text
docs/working/non_ocr_third_party_reverse_eval_template.md
docs/working/non_ocr_third_party_reverse_eval_report.template.json
scripts/non_ocr_third_party_reverse_eval_gate.py
tests/test_non_ocr_third_party_reverse_eval_gate.py
.github/workflows/non_ocr_third_party_reverse_eval.yml
```

## Required Evaluation Coverage

The report must cover:

```text
sample inventory
environment and toolchain
attack budget
allowed and prohibited techniques
findings and risk levels
retest records
claim boundary acknowledgement
release evidence references
```

## Acceptance Criteria

```text
Missing sample inventory fails the gate.
Missing environment or tools fails the gate.
Missing attack budget fails the gate.
Missing findings section fails the gate, even when empty.
Missing retest section fails the gate.
Missing claim boundary acknowledgement fails the gate.
Completed status without assessor and owner approval fails the gate.
The gate must not mark any report as a completed third-party assessment unless --require-completed is explicitly used and all completion fields are present.
Completed reports must cover the minimum sample set: encrypted file, protected Python package, native runtime, release bundle, and promotion bundle.
CI must prove the draft template passes structure validation but fails the completed-report gate.
Completed reports can be validated against local evidence files with --require-local-evidence and --evidence-root.
```

## Verification Commands

```powershell
python -B scripts\non_ocr_third_party_reverse_eval_gate.py --report docs\working\non_ocr_third_party_reverse_eval_report.template.json
python -B -m pytest -q tests\test_non_ocr_third_party_reverse_eval_gate.py -p no:cacheprovider
python -B scripts\non_ocr_third_party_reverse_eval_gate.py --report docs\working\non_ocr_third_party_reverse_eval_report.template.json --require-completed
python -B scripts\non_ocr_third_party_reverse_eval_gate.py --report <completed-report.json> --require-completed --require-local-evidence --evidence-root <evidence-dir>
```

## Release Boundary

This working plan may be used to prepare a third-party review. It must not be promoted to `docs/latest/` until an actual third-party assessment report exists and passes the completed-report gate.
## Current Implementation Status

Implemented in this round:

```text
CI workflow added: .github/workflows/non_ocr_third_party_reverse_eval.yml
Completed-report gate strengthened to require the minimum sample set.
Tests now cover completed-report sample coverage and draft-vs-completed separation.
```

CI behavior:

```text
Draft template must pass structure validation.
Draft template must fail --require-completed.
Unit tests must pass.
Optional workflow_dispatch completed_report_path can validate a real completed report with --require-completed.
Gate reports are uploaded as workflow artifacts for 90 days.
workflow_dispatch supports require_local_evidence and evidence_root for local evidence replay.
```

Remaining before any public third-party claim:

```text
A real third-party assessor must fill a completed report.
The completed report must pass --require-completed.
If local evidence files are provided, the completed report should also pass --require-local-evidence with matching sha256 values, final report sha256, and landing gate report passed=true.
The final report sha256 and storage path must be recorded.
Only then can a release document reference the third-party assessment as completed.
```
Additional implementation in this round:

```text
Completed reports can now require local evidence replay.
The gate verifies local sample files exist and match reported sha256 values.
The gate verifies the local promotion artifact bundle path, landing gate report path, landing gate passed=true, and final report sha256 when --require-local-evidence is used.
The workflow_dispatch path can opt into local evidence replay with require_local_evidence=true.
```

