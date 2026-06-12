#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Promotion rollout policy audit helpers for protected branch/environment gates."""

import json
import hashlib
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Tuple

PROMOTION_POLICY_SCHEMA = "enc2sop-promotion-policy/v1"
PROMOTION_EVIDENCE_SCHEMA = "enc2sop-promotion-evidence/v1"
PROMOTION_AUDIT_REPORT_SCHEMA = "enc2sop-promotion-audit-report/v1"
DEFAULT_POLICY_RELATIVE_PATH = "docs/PROMOTION_ROLLOUT_POLICY.json"
DEFAULT_REPORT_FILENAME = "promotion_audit_report.json"


class PromotionAuditError(RuntimeError):
    """Raised when promotion policy/evidence payloads are invalid."""


def _utc_now_iso8601_seconds() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_policy_path(repo_root: Path) -> Path:
    return (repo_root / DEFAULT_POLICY_RELATIVE_PATH).resolve()


def _load_json_object(path: Path, label: str) -> Dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise PromotionAuditError("{0} must be a JSON object: {1}".format(label, path))
    return payload


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PromotionAuditError("{0} must be a non-empty string".format(field_name))
    return value.strip()


def _required_string_list(value: object, field_name: str) -> Tuple[str, ...]:
    if not isinstance(value, list):
        raise PromotionAuditError("{0} must be an array of strings".format(field_name))
    normalized = []  # type: List[str]
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PromotionAuditError("{0} must contain only non-empty strings".format(field_name))
        normalized.append(item.strip())
    if not normalized:
        raise PromotionAuditError("{0} must not be empty".format(field_name))
    return tuple(sorted(set(normalized)))


def _optional_string_list(value: object, field_name: str) -> Tuple[str, ...]:
    if value is None:
        return tuple()
    if not isinstance(value, list):
        raise PromotionAuditError("{0} must be an array of strings".format(field_name))
    normalized = []  # type: List[str]
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PromotionAuditError("{0} must contain only non-empty strings".format(field_name))
        normalized.append(item.strip())
    return tuple(sorted(set(normalized)))


def _reviewer_count(environment_row: Mapping[str, object]) -> int:
    if "required_reviewers_count" in environment_row:
        value = environment_row.get("required_reviewers_count")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PromotionAuditError("evidence environments[].required_reviewers_count must be an integer >= 0")
        return value
    reviewers = environment_row.get("required_reviewers")
    if reviewers is None:
        return 0
    if not isinstance(reviewers, list):
        raise PromotionAuditError("evidence environments[].required_reviewers must be an array of reviewer strings")
    valid_reviewers = [item.strip() for item in reviewers if isinstance(item, str) and item.strip()]
    return len(set(valid_reviewers))


def _normalize_policy(policy_payload: Mapping[str, object]) -> Dict[str, object]:
    schema = _required_text(policy_payload.get("schema"), "policy.schema")
    if schema != PROMOTION_POLICY_SCHEMA:
        raise PromotionAuditError("unsupported promotion policy schema: {0}".format(schema))

    branches_value = policy_payload.get("required_branches")
    if not isinstance(branches_value, list) or not branches_value:
        raise PromotionAuditError("policy.required_branches must be a non-empty array")
    required_branches = []  # type: List[Dict[str, object]]
    for index, item in enumerate(branches_value):
        if not isinstance(item, dict):
            raise PromotionAuditError("policy.required_branches[{0}] must be an object".format(index))
        branch_name = _required_text(item.get("name"), "policy.required_branches[{0}].name".format(index))
        checks = _required_string_list(
            item.get("required_status_checks"),
            "policy.required_branches[{0}].required_status_checks".format(index),
        )
        required_branches.append({"name": branch_name, "required_status_checks": checks})

    environments_value = policy_payload.get("required_environments")
    if not isinstance(environments_value, list) or not environments_value:
        raise PromotionAuditError("policy.required_environments must be a non-empty array")
    required_environments = []  # type: List[Dict[str, object]]
    for index, item in enumerate(environments_value):
        if not isinstance(item, dict):
            raise PromotionAuditError("policy.required_environments[{0}] must be an object".format(index))
        name = _required_text(item.get("name"), "policy.required_environments[{0}].name".format(index))
        min_reviewers = item.get("min_required_reviewers")
        if isinstance(min_reviewers, bool) or not isinstance(min_reviewers, int) or min_reviewers < 0:
            raise PromotionAuditError(
                "policy.required_environments[{0}].min_required_reviewers must be an integer >= 0".format(index)
            )
        required_environments.append({"name": name, "min_required_reviewers": min_reviewers})

    required_secrets = _required_string_list(policy_payload.get("required_secrets"), "policy.required_secrets")

    workflow_value = policy_payload.get("workflow")
    if not isinstance(workflow_value, dict):
        raise PromotionAuditError("policy.workflow must be an object")
    workflow_relative_path = _required_text(workflow_value.get("relative_path"), "policy.workflow.relative_path")
    required_fragments = _required_string_list(
        workflow_value.get("required_fragments"),
        "policy.workflow.required_fragments",
    )
    return {
        "required_branches": required_branches,
        "required_environments": required_environments,
        "required_secrets": required_secrets,
        "workflow_relative_path": workflow_relative_path,
        "workflow_required_fragments": required_fragments,
    }


def _normalize_evidence(evidence_payload: Mapping[str, object]) -> Dict[str, object]:
    schema = _required_text(evidence_payload.get("schema"), "evidence.schema")
    if schema != PROMOTION_EVIDENCE_SCHEMA:
        raise PromotionAuditError("unsupported promotion evidence schema: {0}".format(schema))

    branches_value = evidence_payload.get("branches")
    if not isinstance(branches_value, list):
        raise PromotionAuditError("evidence.branches must be an array")
    branches = {}  # type: Dict[str, Tuple[str, ...]]
    for index, item in enumerate(branches_value):
        if not isinstance(item, dict):
            raise PromotionAuditError("evidence.branches[{0}] must be an object".format(index))
        branch_name = _required_text(item.get("name"), "evidence.branches[{0}].name".format(index))
        status_checks = _optional_string_list(
            item.get("required_status_checks"),
            "evidence.branches[{0}].required_status_checks".format(index),
        )
        branches[branch_name] = status_checks

    environments_value = evidence_payload.get("environments")
    if not isinstance(environments_value, list):
        raise PromotionAuditError("evidence.environments must be an array")
    environments = {}  # type: Dict[str, int]
    for index, item in enumerate(environments_value):
        if not isinstance(item, dict):
            raise PromotionAuditError("evidence.environments[{0}] must be an object".format(index))
        env_name = _required_text(item.get("name"), "evidence.environments[{0}].name".format(index))
        environments[env_name] = _reviewer_count(item)

    secrets = set(_optional_string_list(evidence_payload.get("secrets"), "evidence.secrets"))
    return {
        "branches": branches,
        "environments": environments,
        "secrets": secrets,
    }


def normalize_promotion_evidence_payload(evidence_payload: Mapping[str, object]) -> Dict[str, object]:
    """Validate and normalize evidence payload shape for reuse across modules."""
    return _normalize_evidence(evidence_payload)


_AUDIT_INPUT_FILE_KEYS = ("policy_file", "evidence_file", "workflow_file")
_AUDIT_INPUT_DIGEST_KEYS = ("policy_sha256", "evidence_sha256", "workflow_sha256")
_AUDIT_SUMMARY_COUNT_KEYS = (
    "branch_failures",
    "environment_failures",
    "secret_failures",
    "workflow_failures",
    "total_failures",
)


def _is_lower_hex_sha256(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) != 64:
        return False
    if value.lower() != value:
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def _required_report_text(value: object, field_name: str) -> str:
    text = _required_text(value, field_name)
    if text != value:
        raise PromotionAuditError("{0} must not contain leading or trailing whitespace".format(field_name))
    return text


def _optional_report_text(value: object, field_name: str) -> Optional[str]:
    if value is None:
        return None
    return _required_report_text(value, field_name)


def _required_non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PromotionAuditError("{0} must be an integer >= 0".format(field_name))
    return value


def _normalize_audit_report_summary(summary_payload: object) -> Dict[str, object]:
    if not isinstance(summary_payload, dict):
        raise PromotionAuditError("promotion_audit_report.summary must be an object")
    normalized = dict(summary_payload)
    if "total_failures" not in summary_payload:
        raise PromotionAuditError("promotion_audit_report.summary.total_failures is required")
    for key in _AUDIT_SUMMARY_COUNT_KEYS:
        if key in summary_payload:
            normalized[key] = _required_non_negative_int(
                summary_payload.get(key),
                "promotion_audit_report.summary.{0}".format(key),
            )
    return normalized


def _normalize_audit_report_failures(failures_payload: object) -> List[str]:
    if not isinstance(failures_payload, list):
        raise PromotionAuditError("promotion_audit_report.failures must be an array")
    failures = []  # type: List[str]
    for index, item in enumerate(failures_payload):
        failures.append(
            _required_report_text(
                item,
                "promotion_audit_report.failures[{0}]".format(index),
            )
        )
    return failures


def _normalize_audit_report_inputs(inputs_payload: object, *, passed: bool) -> Dict[str, object]:
    if not isinstance(inputs_payload, dict):
        raise PromotionAuditError("promotion_audit_report.inputs is required")
    normalized = {}  # type: Dict[str, object]
    for key in _AUDIT_INPUT_FILE_KEYS:
        normalized[key] = _required_report_text(
            inputs_payload.get(key),
            "promotion_audit_report.inputs.{0}".format(key),
        )
    for key in _AUDIT_INPUT_DIGEST_KEYS:
        value = inputs_payload.get(key)
        if value is None and key == "workflow_sha256" and not passed:
            normalized[key] = None
            continue
        if not _is_lower_hex_sha256(value):
            raise PromotionAuditError(
                "promotion_audit_report.inputs.{0} must be a 64-char lowercase hex digest".format(key)
            )
        normalized[key] = value
    return normalized


def normalize_promotion_audit_report_payload(report_payload: Mapping[str, object]) -> Dict[str, object]:
    """Validate and normalize promotion audit report payloads for bundle handoff.

    This intentionally validates the portable schema contract only. It does not
    read bound input files or recalculate their digests; artifact-level replay
    checks live in ``enc2sop.promotion_artifacts``.
    """
    if not isinstance(report_payload, dict):
        raise PromotionAuditError("promotion_audit_report must be a JSON object")
    schema = _required_report_text(report_payload.get("schema"), "promotion_audit_report.schema")
    if schema != PROMOTION_AUDIT_REPORT_SCHEMA:
        raise PromotionAuditError("unsupported promotion audit report schema: {0}".format(schema))
    passed_value = report_payload.get("passed")
    if not isinstance(passed_value, bool):
        raise PromotionAuditError("promotion_audit_report.passed must be a boolean")

    summary = _normalize_audit_report_summary(report_payload.get("summary"))
    failures = _normalize_audit_report_failures(report_payload.get("failures"))
    total_failures = int(summary.get("total_failures") or 0)
    if total_failures != len(failures):
        raise PromotionAuditError(
            "promotion_audit_report.summary.total_failures must match length of promotion_audit_report.failures"
        )
    if passed_value and total_failures != 0:
        raise PromotionAuditError("promotion_audit_report.summary.total_failures must be 0 when passed=true")
    if passed_value and failures:
        raise PromotionAuditError("promotion_audit_report.failures must be empty when passed=true")

    normalized = {
        "schema": schema,
        "generated_at_utc": _optional_report_text(
            report_payload.get("generated_at_utc"),
            "promotion_audit_report.generated_at_utc",
        ),
        "passed": passed_value,
        "summary": summary,
        "failures": failures,
        "inputs": _normalize_audit_report_inputs(report_payload.get("inputs"), passed=passed_value),
    }  # type: Dict[str, object]
    details = report_payload.get("details")
    if details is not None:
        if not isinstance(details, dict):
            raise PromotionAuditError("promotion_audit_report.details must be an object")
        normalized["details"] = dict(details)
    return normalized


def _resolve_path(value: Optional[str], *, repo_root: Path, fallback: Optional[Path] = None) -> Path:
    if value:
        candidate = Path(value).expanduser()
    elif fallback is not None:
        candidate = fallback
    else:
        raise PromotionAuditError("path resolution requires value or fallback")
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return candidate.resolve()


def _evaluate_audit(
    *,
    policy: Mapping[str, object],
    evidence: Mapping[str, object],
    workflow_path: Path,
) -> Dict[str, object]:
    failures = []  # type: List[str]
    branch_failures = []  # type: List[str]
    environment_failures = []  # type: List[str]
    secret_failures = []  # type: List[str]
    workflow_failures = []  # type: List[str]

    evidence_branches = evidence.get("branches") or {}
    for item in policy.get("required_branches") or ():
        branch_name = item.get("name")
        required_checks = set(item.get("required_status_checks") or ())
        actual_checks = set(evidence_branches.get(branch_name, ()))
        if branch_name not in evidence_branches:
            branch_failures.append("missing branch evidence for '{0}'".format(branch_name))
            continue
        missing_checks = sorted(required_checks - actual_checks)
        if missing_checks:
            branch_failures.append(
                "branch '{0}' missing required status checks: {1}".format(branch_name, ", ".join(missing_checks))
            )

    evidence_environments = evidence.get("environments") or {}
    for item in policy.get("required_environments") or ():
        env_name = item.get("name")
        min_reviewers = int(item.get("min_required_reviewers") or 0)
        reviewer_count = evidence_environments.get(env_name)
        if reviewer_count is None:
            environment_failures.append("missing environment evidence for '{0}'".format(env_name))
            continue
        if reviewer_count < min_reviewers:
            environment_failures.append(
                "environment '{0}' requires at least {1} reviewers (found {2})".format(
                    env_name,
                    min_reviewers,
                    reviewer_count,
                )
            )

    evidence_secrets = evidence.get("secrets") or set()
    for secret_name in policy.get("required_secrets") or ():
        if secret_name not in evidence_secrets:
            secret_failures.append("missing required secret evidence for '{0}'".format(secret_name))

    if not workflow_path.exists():
        workflow_failures.append("workflow file not found: {0}".format(workflow_path))
    else:
        workflow_text = workflow_path.read_text(encoding="utf-8")
        for fragment in policy.get("workflow_required_fragments") or ():
            if fragment not in workflow_text:
                workflow_failures.append("workflow missing required fragment: {0}".format(fragment))

    failures.extend(branch_failures)
    failures.extend(environment_failures)
    failures.extend(secret_failures)
    failures.extend(workflow_failures)
    passed = not failures

    return {
        "schema": PROMOTION_AUDIT_REPORT_SCHEMA,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "passed": passed,
        "summary": {
            "branch_failures": len(branch_failures),
            "environment_failures": len(environment_failures),
            "secret_failures": len(secret_failures),
            "workflow_failures": len(workflow_failures),
            "total_failures": len(failures),
        },
        "failures": failures,
        "details": {
            "branches": branch_failures,
            "environments": environment_failures,
            "secrets": secret_failures,
            "workflow": workflow_failures,
        },
    }


def run_promotion_audit(
    *,
    evidence_file: str,
    policy_file: Optional[str] = None,
    workflow_file: Optional[str] = None,
    report_file: Optional[str] = None,
    repo_root: Optional[Path] = None,
) -> Tuple[Path, Dict[str, object]]:
    root = repo_root.resolve() if repo_root is not None else Path.cwd().resolve()
    evidence_path = _resolve_path(evidence_file, repo_root=root)
    if not evidence_path.exists():
        raise FileNotFoundError("promotion evidence file not found: {0}".format(evidence_path))

    resolved_policy_path = _resolve_path(
        policy_file,
        repo_root=root,
        fallback=default_policy_path(root),
    )
    if not resolved_policy_path.exists():
        raise FileNotFoundError("promotion policy file not found: {0}".format(resolved_policy_path))

    policy_payload = _load_json_object(resolved_policy_path, "promotion policy")
    evidence_payload = _load_json_object(evidence_path, "promotion evidence")
    normalized_policy = _normalize_policy(policy_payload)
    normalized_evidence = normalize_promotion_evidence_payload(evidence_payload)

    workflow_rel = normalized_policy.get("workflow_relative_path")
    workflow_default = Path(workflow_rel) if isinstance(workflow_rel, str) else Path(".github/workflows/release_promotion.yml")
    resolved_workflow_path = _resolve_path(workflow_file, repo_root=root, fallback=workflow_default)
    report = _evaluate_audit(
        policy=normalized_policy,
        evidence=normalized_evidence,
        workflow_path=resolved_workflow_path,
    )
    report["inputs"] = {
        "policy_file": str(resolved_policy_path),
        "policy_sha256": _sha256_file(resolved_policy_path),
        "evidence_file": str(evidence_path),
        "evidence_sha256": _sha256_file(evidence_path),
        "workflow_file": str(resolved_workflow_path),
        "workflow_sha256": _sha256_file(resolved_workflow_path) if resolved_workflow_path.exists() else None,
    }

    report_path = _resolve_path(
        report_file,
        repo_root=root,
        fallback=evidence_path.parent / DEFAULT_REPORT_FILENAME,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report_path, report
