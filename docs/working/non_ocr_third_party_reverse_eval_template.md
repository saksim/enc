# Non-OCR Third-Party Reverse Evaluation Template

Status: working template
Use for: external reverse-engineering cost assessment of the non-OCR GA line
Do not use for: OCR, QR, cross-media, remote-KMS, or absolute anti-reverse claims

## 1. Evaluation Identity

```text
Evaluation ID:
Reviewer organization:
Assessor name:
Assessment window:
Repository/tag under review:
Release artifact source:
Promotion artifact bundle path or URL:
Promotion artifact bundle sha256:
Landing gate report path or URL:
```

## 2. Claim Boundary

Allowed claim under review:

```text
The non-OCR encryption/code-protection line increases the cost of casual and low-budget reverse engineering, tampering, and source recovery.
```

Claims explicitly excluded:

```text
Absolute non-reversibility
Absolute non-crackability
OCR / QR / cross-media launch coverage
remote-KMS service launch coverage
Resistance against an attacker who has the full runtime environment and all keys
Completed third-party certification before this report is signed
```

The assessor must state whether this boundary was accepted before testing.

## 3. Sample Inventory

Each tested sample must include:

```text
sample_id
artifact_type: encrypted-file | protected-python-package | native-runtime | release-bundle | promotion-bundle
source_path_or_url
sha256
size_bytes
selection_reason
```

Minimum sample set:

```text
one encrypted arbitrary file sample
one protected Python package sample
one native package/runtime sample
one release_bundle.json
one promotion_artifact_bundle.zip
```

## 4. Environment And Toolchain

Record:

```text
OS and version
CPU architecture
Python version
package manager / virtualenv details
reverse tools used
hashing tools used
runtime environment variables
network policy during testing
```

## 5. Attack Budget

Record:

```text
total_hours
number_of_assessors
assessor_profile
allowed_techniques
prohibited_techniques
success criteria
stop criteria
```

Attack budget must be realistic and bounded. Do not write an unbounded or undefined budget.

## 6. Test Procedure

Required checks:

```text
Inspect release package for direct source leakage.
Verify promotion artifact bundle manifest and sha256 entries.
Attempt to recover readable business source from the protected package.
Attempt to bypass license-file fail-closed behavior.
Attempt to tamper with runtime/native artifacts and verify failure behavior.
Compare observed effort with the release reverse-cost checklist.
```

## 7. Findings

Each finding must include:

```text
finding_id
severity: Critical | High | Medium | Low | Info
title
affected_sample_ids
description
reproduction_steps
impact
recommendation
status: open | mitigated | accepted-risk | false-positive
```

Severity guidance:

```text
Critical: direct source recovery, production key exposure, or default bypass of license checks.
High: reliable low-effort bypass of a GA gate or tamper check.
Medium: meaningful information disclosure or repeatable partial bypass.
Low: hardening gap that does not invalidate the GA claim.
Info: documentation, packaging, or process observation.
```

## 8. Retest

For every mitigated Critical, High, or Medium finding, record:

```text
finding_id
retest_date
retest_artifact_sha256
retest_result: passed | failed | not-applicable
retest_notes
```

## 9. Conclusion

The conclusion must answer:

```text
Did the tested artifacts avoid direct business source disclosure?
Did the tested artifacts increase reverse-engineering cost within the stated budget?
Were any GA-blocking findings discovered?
Are all Critical and High findings mitigated, accepted, or explicitly left open?
Does the assessor agree that no excluded claim should be made?
```

## 10. Sign-Off

Required before any public statement references the assessment:

```text
Assessor signature or approval record
Project owner acknowledgement
Final report sha256
Final report storage path
```