#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Validate non-OCR third-party reverse-evaluation reports.

This gate validates assessment structure only. It does not claim that a
third-party review has completed unless --require-completed is used and the
report contains the required approvals and conclusion fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence

REPORT_SCHEMA = "enc2sop-non-ocr-third-party-reverse-eval/v1"
VALID_STATUSES = {"draft", "ready-for-review", "completed"}
VALID_ARTIFACT_TYPES = {
    "encrypted-file",
    "protected-python-package",
    "native-runtime",
    "release-bundle",
    "promotion-bundle",
}
VALID_FINDING_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
VALID_FINDING_STATUSES = {"open", "mitigated", "accepted-risk", "false-positive"}
REQUIRED_COMPLETED_SAMPLE_TYPES = {
    "encrypted-file",
    "protected-python-package",
    "native-runtime",
    "release-bundle",
    "promotion-bundle",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_EXCLUDED_CLAIM_KEYWORDS = ("absolute", "OCR", "remote-KMS")


def _load_json_object(path: Path) -> Dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("report must be a JSON object")
    return payload


def _non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _non_empty_list(value: object) -> bool:
    return isinstance(value, list) and len(value) > 0


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256_RE.match(value.strip()))


def _append_if_false(failures: List[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def _resolve_local_evidence_path(value: object, *, evidence_root: Path) -> Optional[Path]:
    if not isinstance(value, str) or not value.strip() or _is_url(value.strip()):
        return None
    candidate = Path(value.strip()).expanduser()
    if not candidate.is_absolute():
        candidate = evidence_root / candidate
    return candidate.resolve()


def _validate_local_file_sha256(
    *,
    path_value: object,
    expected_sha256: object,
    evidence_root: Path,
    label: str,
    failures: List[str],
    require_local_evidence: bool,
) -> None:
    if not require_local_evidence:
        return
    if not isinstance(path_value, str) or not path_value.strip():
        failures.append("{0} path is required when --require-local-evidence is used".format(label))
        return
    if _is_url(path_value.strip()):
        failures.append("{0} must be a local path when --require-local-evidence is used".format(label))
        return
    local_path = _resolve_local_evidence_path(path_value, evidence_root=evidence_root)
    if local_path is None or not local_path.is_file():
        failures.append("{0} local file missing: {1}".format(label, path_value))
        return
    if not _is_sha256(expected_sha256):
        failures.append("{0} expected sha256 is required when --require-local-evidence is used".format(label))
        return
    actual = _sha256_file(local_path)
    if actual != str(expected_sha256).strip():
        failures.append("{0} sha256 mismatch".format(label))


def _validate_claim_boundary(report: Mapping[str, object], failures: List[str], *, require_completed: bool) -> None:
    boundary = report.get("claim_boundary")
    if not isinstance(boundary, dict):
        failures.append("claim_boundary must be an object")
        return
    _append_if_false(failures, _non_empty_string(boundary.get("allowed_claim")), "claim_boundary.allowed_claim is required")
    excluded = boundary.get("excluded_claims")
    if not _non_empty_list(excluded):
        failures.append("claim_boundary.excluded_claims must be non-empty")
    else:
        text = "\n".join(str(item) for item in excluded)
        for keyword in REQUIRED_EXCLUDED_CLAIM_KEYWORDS:
            if keyword not in text:
                failures.append("claim_boundary.excluded_claims must mention {0}".format(keyword))
    if require_completed:
        _append_if_false(failures, boundary.get("accepted") is True, "claim_boundary.accepted must be true for completed reports")


def _validate_release_evidence(report: Mapping[str, object], failures: List[str], *, require_completed: bool, require_local_evidence: bool, evidence_root: Path) -> None:
    evidence = report.get("release_evidence")
    if not isinstance(evidence, dict):
        failures.append("release_evidence must be an object")
        return
    _append_if_false(failures, _non_empty_string(evidence.get("release_tag")), "release_evidence.release_tag is required")
    if require_completed:
        _append_if_false(
            failures,
            _is_sha256(evidence.get("promotion_artifact_bundle_sha256")),
            "release_evidence.promotion_artifact_bundle_sha256 must be a lowercase sha256 for completed reports",
        )
        _append_if_false(failures, _non_empty_string(evidence.get("landing_gate_report")), "release_evidence.landing_gate_report is required for completed reports")
        _append_if_false(failures, evidence.get("sample_hashes_verified") is True, "release_evidence.sample_hashes_verified must be true for completed reports")
    _validate_local_file_sha256(
        path_value=evidence.get("promotion_artifact_bundle_path"),
        expected_sha256=evidence.get("promotion_artifact_bundle_sha256"),
        evidence_root=evidence_root,
        label="release_evidence.promotion_artifact_bundle_path",
        failures=failures,
        require_local_evidence=require_local_evidence,
    )
    if require_local_evidence:
        landing_path = _resolve_local_evidence_path(evidence.get("landing_gate_report"), evidence_root=evidence_root)
        if landing_path is None or not landing_path.is_file():
            failures.append("release_evidence.landing_gate_report local file missing")


def _validate_samples(report: Mapping[str, object], failures: List[str], *, require_completed: bool, require_local_evidence: bool, evidence_root: Path) -> None:
    samples = report.get("samples")
    if not _non_empty_list(samples):
        failures.append("samples must be a non-empty list")
        return
    completed_sample_types = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            failures.append("samples[{0}] must be an object".format(index))
            continue
        label = "samples[{0}]".format(index)
        _append_if_false(failures, _non_empty_string(sample.get("sample_id")), "{0}.sample_id is required".format(label))
        artifact_type = sample.get("artifact_type")
        if artifact_type not in VALID_ARTIFACT_TYPES:
            failures.append("{0}.artifact_type is invalid".format(label))
        elif isinstance(artifact_type, str):
            completed_sample_types.add(artifact_type)
        _append_if_false(failures, _non_empty_string(sample.get("source_path_or_url")) or not require_completed, "{0}.source_path_or_url is required for completed reports".format(label))
        _append_if_false(failures, _is_sha256(sample.get("sha256")) or not require_completed, "{0}.sha256 must be a lowercase sha256 for completed reports".format(label))
        _validate_local_file_sha256(
            path_value=sample.get("source_path_or_url"),
            expected_sha256=sample.get("sha256"),
            evidence_root=evidence_root,
            label=label,
            failures=failures,
            require_local_evidence=require_local_evidence,
        )
        size = sample.get("size_bytes")
        _append_if_false(failures, isinstance(size, int) and not isinstance(size, bool) and size >= 0, "{0}.size_bytes must be a non-negative integer".format(label))
        _append_if_false(failures, _non_empty_string(sample.get("selection_reason")) or not require_completed, "{0}.selection_reason is required for completed reports".format(label))
    if require_completed:
        missing_types = sorted(REQUIRED_COMPLETED_SAMPLE_TYPES - completed_sample_types)
        if missing_types:
            failures.append("samples must include completed assessment artifact types: {0}".format(", ".join(missing_types)))


def _validate_environment(report: Mapping[str, object], failures: List[str], *, require_completed: bool) -> None:
    environment = report.get("environment")
    if not isinstance(environment, dict):
        failures.append("environment must be an object")
        return
    for key in ("os", "architecture", "python_version"):
        _append_if_false(failures, _non_empty_string(environment.get(key)) or not require_completed, "environment.{0} is required for completed reports".format(key))
    _append_if_false(failures, isinstance(environment.get("tools"), list), "environment.tools must be a list")
    if require_completed:
        _append_if_false(failures, _non_empty_list(environment.get("tools")), "environment.tools must be non-empty for completed reports")


def _validate_attack_budget(report: Mapping[str, object], failures: List[str], *, require_completed: bool) -> None:
    budget = report.get("attack_budget")
    if not isinstance(budget, dict):
        failures.append("attack_budget must be an object")
        return
    total_hours = budget.get("total_hours")
    _append_if_false(failures, isinstance(total_hours, int) and not isinstance(total_hours, bool) and total_hours >= 0, "attack_budget.total_hours must be a non-negative integer")
    if require_completed:
        _append_if_false(failures, total_hours > 0, "attack_budget.total_hours must be greater than zero for completed reports")
    for key in ("assessors", "allowed_techniques", "prohibited_techniques", "success_criteria", "stop_criteria"):
        _append_if_false(failures, isinstance(budget.get(key), list), "attack_budget.{0} must be a list".format(key))
        if require_completed:
            _append_if_false(failures, _non_empty_list(budget.get(key)), "attack_budget.{0} must be non-empty for completed reports".format(key))


def _validate_findings(report: Mapping[str, object], failures: List[str]) -> None:
    findings = report.get("findings")
    if not isinstance(findings, list):
        failures.append("findings must be a list, even when empty")
        return
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            failures.append("findings[{0}] must be an object".format(index))
            continue
        label = "findings[{0}]".format(index)
        for key in ("finding_id", "title", "description", "impact", "recommendation", "status"):
            _append_if_false(failures, _non_empty_string(finding.get(key)), "{0}.{1} is required".format(label, key))
        if finding.get("severity") not in VALID_FINDING_SEVERITIES:
            failures.append("{0}.severity is invalid".format(label))
        if finding.get("status") not in VALID_FINDING_STATUSES:
            failures.append("{0}.status is invalid".format(label))
        _append_if_false(failures, isinstance(finding.get("affected_sample_ids"), list), "{0}.affected_sample_ids must be a list".format(label))
        _append_if_false(failures, isinstance(finding.get("reproduction_steps"), list), "{0}.reproduction_steps must be a list".format(label))


def _validate_retest(report: Mapping[str, object], failures: List[str]) -> None:
    retest = report.get("retest")
    if not isinstance(retest, dict):
        failures.append("retest must be an object")
        return
    _append_if_false(failures, isinstance(retest.get("required"), bool), "retest.required must be a boolean")
    records = retest.get("records")
    _append_if_false(failures, isinstance(records, list), "retest.records must be a list")
    if isinstance(records, list):
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                failures.append("retest.records[{0}] must be an object".format(index))
                continue
            label = "retest.records[{0}]".format(index)
            for key in ("finding_id", "retest_date", "retest_result", "retest_notes"):
                _append_if_false(failures, _non_empty_string(record.get(key)), "{0}.{1} is required".format(label, key))
            if record.get("retest_result") not in {"passed", "failed", "not-applicable"}:
                failures.append("{0}.retest_result is invalid".format(label))
            if record.get("retest_artifact_sha256") and not _is_sha256(record.get("retest_artifact_sha256")):
                failures.append("{0}.retest_artifact_sha256 must be a lowercase sha256 when present".format(label))


def _validate_conclusion(report: Mapping[str, object], failures: List[str], *, require_completed: bool) -> None:
    conclusion = report.get("conclusion")
    if not isinstance(conclusion, dict):
        failures.append("conclusion must be an object")
        return
    for key in ("direct_source_disclosure_found", "reverse_cost_increased_within_budget", "ga_blocking_findings", "excluded_claims_respected"):
        value = conclusion.get(key)
        if value is not None and not isinstance(value, bool):
            failures.append("conclusion.{0} must be boolean or null".format(key))
        if require_completed:
            _append_if_false(failures, isinstance(value, bool), "conclusion.{0} must be boolean for completed reports".format(key))
    if require_completed:
        _append_if_false(failures, conclusion.get("excluded_claims_respected") is True, "conclusion.excluded_claims_respected must be true for completed reports")


def _validate_approval(report: Mapping[str, object], failures: List[str], *, require_completed: bool, require_local_evidence: bool, evidence_root: Path) -> None:
    approval = report.get("approval")
    if not isinstance(approval, dict):
        failures.append("approval must be an object")
        return
    if require_completed:
        for key in ("assessor", "assessor_approved_at_utc", "project_owner", "project_owner_ack_at_utc", "final_report_storage_path"):
            _append_if_false(failures, _non_empty_string(approval.get(key)), "approval.{0} is required for completed reports".format(key))
        _append_if_false(failures, _is_sha256(approval.get("final_report_sha256")), "approval.final_report_sha256 must be a lowercase sha256 for completed reports")
    if require_local_evidence:
        storage_path = _resolve_local_evidence_path(approval.get("final_report_storage_path"), evidence_root=evidence_root)
        if storage_path is None or not storage_path.is_file():
            failures.append("approval.final_report_storage_path local file missing")


def validate_report(
    report: Mapping[str, object],
    *,
    require_completed: bool = False,
    require_local_evidence: bool = False,
    evidence_root: Optional[Path] = None,
) -> Dict[str, object]:
    failures: List[str] = []
    if report.get("schema") != REPORT_SCHEMA:
        failures.append("schema mismatch: expected {0}".format(REPORT_SCHEMA))
    status = report.get("status")
    if status not in VALID_STATUSES:
        failures.append("status must be one of {0}".format(", ".join(sorted(VALID_STATUSES))))
    if require_completed and status != "completed":
        failures.append("status must be completed when --require-completed is used")
    _append_if_false(failures, _non_empty_string(report.get("evaluation_id")), "evaluation_id is required")
    root = evidence_root.resolve() if evidence_root is not None else Path.cwd().resolve()

    _validate_claim_boundary(report, failures, require_completed=require_completed)
    _validate_release_evidence(report, failures, require_completed=require_completed, require_local_evidence=require_local_evidence, evidence_root=root)
    _validate_samples(report, failures, require_completed=require_completed, require_local_evidence=require_local_evidence, evidence_root=root)
    _validate_environment(report, failures, require_completed=require_completed)
    _validate_attack_budget(report, failures, require_completed=require_completed)
    _validate_findings(report, failures)
    _validate_retest(report, failures)
    _validate_conclusion(report, failures, require_completed=require_completed)
    _validate_approval(report, failures, require_completed=require_completed, require_local_evidence=require_local_evidence, evidence_root=root)

    return {
        "schema": "enc2sop-non-ocr-third-party-reverse-eval-gate/v1",
        "passed": not failures,
        "require_completed": bool(require_completed),
        "require_local_evidence": bool(require_local_evidence),
        "evidence_root": str(root),
        "summary": {"total_failures": len(failures)},
        "failures": failures,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate a non-OCR third-party reverse-evaluation report.")
    parser.add_argument("--report", required=True, help="Evaluation report JSON to validate.")
    parser.add_argument("--require-completed", action="store_true", help="Require completed-report approvals and final conclusion fields.")
    parser.add_argument("--require-local-evidence", action="store_true", help="Require local evidence paths to exist and match reported sha256 values.")
    parser.add_argument("--evidence-root", help="Base directory for relative local evidence paths. Defaults to current working directory.")
    parser.add_argument("--gate-report", help="Optional gate report JSON output path.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report_path = Path(args.report).expanduser().resolve()
    report = _load_json_object(report_path)
    evidence_root = Path(args.evidence_root).expanduser().resolve() if args.evidence_root else Path.cwd().resolve()
    gate_report = validate_report(report, require_completed=bool(args.require_completed), require_local_evidence=bool(args.require_local_evidence), evidence_root=evidence_root)
    if args.gate_report:
        output_path = Path(args.gate_report).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(gate_report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("non_ocr_third_party_reverse_eval_gate_report={0}".format(output_path))
    if gate_report["passed"]:
        print("NON_OCR_THIRD_PARTY_REVERSE_EVAL_GATE_OK")
        return 0
    print("NON_OCR_THIRD_PARTY_REVERSE_EVAL_GATE_FAILED failures={0}".format(gate_report["summary"]["total_failures"]))
    for failure in gate_report["failures"]:
        print("failure={0}".format(failure))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())