#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Promotion artifact integrity checks for CI rollout evidence bundles."""

import hmac
import hashlib
import json
import os
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Tuple

import encryption_helper
from enc2sop import promotion_audit

PROMOTION_ARTIFACT_AUDIT_SCHEMA = "enc2sop-promotion-artifact-audit/v1"
PROMOTION_RUN_RECEIPT_SCHEMA = "enc2sop-promotion-run-receipt/v1"
ROTATION_REHEARSAL_SCHEMA = "enc2sop-rotation-rehearsal/v1"
PROMOTION_RUN_RECEIPT_SIGNATURE_ALGORITHM = encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256
DEFAULT_REPORT_FILENAME = "promotion_artifact_audit_report.json"
DEFAULT_RUN_RECEIPT_FILENAME = "promotion_run_receipt.json"
RUN_RECEIPT_VOLATILE_ARTIFACT = "promotion_artifact_audit_report"
RUN_RECEIPT_REQUIRED_ARTIFACTS = (
    "release_bundle",
    "release_approval",
    "release_receipt",
    "promotion_evidence",
    "promotion_audit_report",
    "rotation_rehearsal_report",
    RUN_RECEIPT_VOLATILE_ARTIFACT,
)
STRICT_CONTEXT_REQUIRED_IDENTITY_KEYS = (
    "GITHUB_REPOSITORY",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_RUN_ID",
)
STRICT_CONTEXT_REQUIRED_BINDING_KEYS = (
    "GITHUB_ACTIONS",
    "CI",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
    "RUNNER_ARCH",
    "GITHUB_SHA",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_NUMBER",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_EVENT_NAME",
    "GITHUB_SERVER_URL",
    "GITHUB_API_URL",
    "GITHUB_GRAPHQL_URL",
    "GITHUB_JOB",
    "GITHUB_ACTOR",
    "GITHUB_ACTOR_ID",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_REPOSITORY_OWNER_ID",
)
STRICT_CONTEXT_OPTIONAL_BINDING_KEYS = (
    "GITHUB_TRIGGERING_ACTOR",
)
STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY = "GITHUB_REF_PROTECTED"


class PromotionArtifactAuditError(RuntimeError):
    """Raised when promotion artifact verification cannot complete."""


def _utc_now_iso8601_seconds() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _resolve_path(value: Optional[str], *, repo_root: Path, fallback: Optional[Path] = None) -> Path:
    if value:
        candidate = Path(value).expanduser()
    elif fallback is not None:
        candidate = fallback
    else:
        raise PromotionArtifactAuditError("path resolution requires value or fallback")
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return candidate.resolve()


def _load_json_object(path: Path, label: str) -> Dict[str, object]:
    if not path.exists():
        raise FileNotFoundError("{0} not found: {1}".format(label, path))
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise PromotionArtifactAuditError("{0} must be a JSON object: {1}".format(label, path))
    return payload


def _is_hex_64(value: object) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    if len(text) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in text)


def _run_receipt_payload_without_signature(payload: Mapping[str, object]) -> Dict[str, object]:
    output = dict(payload)
    output.pop("signature", None)
    return output


def _compute_run_receipt_signature(
    run_receipt_payload: Mapping[str, object],
    signature_key: bytes,
) -> str:
    return hmac.new(
        signature_key,
        encryption_helper._canonical_json_bytes(_run_receipt_payload_without_signature(run_receipt_payload)),
        hashlib.sha256,
    ).hexdigest()


def _validate_release_artifacts(
    release_dir: Path,
    failures: List[str],
    *,
    runtime_context: Optional[Mapping[str, str]],
    approval_key: Optional[bytes],
    expected_approval_key_id: Optional[str],
    require_approval_signature: bool,
    require_ci_context_match: bool,
) -> None:
    bundle_path = release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME
    approval_path = release_dir / "release_approval.json"
    receipt_path = release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME

    bundle_payload = _load_json_object(bundle_path, "release bundle")
    if bundle_payload.get("schema") != encryption_helper.RELEASE_BUNDLE_SCHEMA:
        failures.append(
            "release_bundle schema mismatch: expected {0}, got {1}".format(
                encryption_helper.RELEASE_BUNDLE_SCHEMA,
                bundle_payload.get("schema"),
            )
        )
    if bundle_payload.get("layout_version") != encryption_helper.RELEASE_LAYOUT_VERSION:
        failures.append(
            "release_bundle layout_version mismatch: expected {0}, got {1}".format(
                encryption_helper.RELEASE_LAYOUT_VERSION,
                bundle_payload.get("layout_version"),
            )
        )

    approval_payload = _load_json_object(approval_path, "release approval")
    if approval_payload.get("schema") != encryption_helper.RELEASE_APPROVAL_SCHEMA:
        failures.append(
            "release_approval schema mismatch: expected {0}, got {1}".format(
                encryption_helper.RELEASE_APPROVAL_SCHEMA,
                approval_payload.get("schema"),
            )
        )
    if approval_payload.get("release_bundle_relative_path") != encryption_helper.RELEASE_BUNDLE_FILENAME:
        failures.append("release_approval must target release_bundle.json")
    if not _is_hex_64(approval_payload.get("release_bundle_sha256")):
        failures.append("release_approval.release_bundle_sha256 must be a 64-char lowercase hex digest")
    else:
        expected_bundle_digest = encryption_helper._sha256_file(bundle_path)
        actual_bundle_digest = str(approval_payload.get("release_bundle_sha256")).strip().lower()
        if actual_bundle_digest != expected_bundle_digest:
            failures.append("release_approval bundle digest does not match release_bundle.json")
    approvers = approval_payload.get("approvers")
    if not isinstance(approvers, list) or not approvers or not all(isinstance(item, str) and item.strip() for item in approvers):
        failures.append("release_approval.approvers must be a non-empty string list")
    signature = approval_payload.get("signature")
    if not isinstance(signature, dict):
        failures.append("release_approval.signature is required")
    else:
        algorithm = str(signature.get("algorithm") or "").strip().lower()
        if algorithm != encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256:
            failures.append("release_approval.signature.algorithm must be hmac-sha256")
        digest_hex = str(signature.get("digest_hex") or "").strip().lower()
        if not _is_hex_64(digest_hex):
            failures.append("release_approval.signature.digest_hex must be a 64-char lowercase hex digest")
        actual_key_id = str(signature.get("key_id") or "").strip()
        if not actual_key_id:
            failures.append("release_approval.signature.key_id is required")
        expected_key_id = str(expected_approval_key_id or "").strip()
        if expected_key_id and actual_key_id != expected_key_id:
            failures.append(
                "release_approval.signature.key_id mismatch: expected {0}, got {1}".format(
                    expected_key_id,
                    actual_key_id or "<empty>",
                )
            )
        signed_payload = dict(approval_payload)
        signed_payload.pop("signature", None)
        if approval_key is not None:
            expected_digest = hmac.new(
                approval_key,
                encryption_helper._canonical_json_bytes(signed_payload),
                hashlib.sha256,
            ).hexdigest()
            if _is_hex_64(digest_hex) and not hmac.compare_digest(expected_digest, digest_hex):
                failures.append("release_approval.signature.digest_hex does not match provided approval verification key")
        elif require_approval_signature:
            failures.append(
                "release approval verification key is required when --require-release-approval-signature is enabled"
            )
    if require_ci_context_match:
        if runtime_context:
            _validate_ci_context_binding(
                runtime_context=runtime_context,
                artifact_context=approval_payload.get("github_context"),
                context_label="release_approval.github_context",
                failures=failures,
            )

    receipt_payload = _load_json_object(receipt_path, "release receipt")
    if receipt_payload.get("schema") != encryption_helper.RELEASE_RECEIPT_SCHEMA:
        failures.append(
            "release_receipt schema mismatch: expected {0}, got {1}".format(
                encryption_helper.RELEASE_RECEIPT_SCHEMA,
                receipt_payload.get("schema"),
            )
        )
    if receipt_payload.get("release_bundle_relative_path") != encryption_helper.RELEASE_BUNDLE_FILENAME:
        failures.append("release_receipt.release_bundle_relative_path must be release_bundle.json")
    receipt_bundle_digest = str(receipt_payload.get("release_bundle_sha256") or "").strip().lower()
    if not _is_hex_64(receipt_bundle_digest):
        failures.append("release_receipt.release_bundle_sha256 must be a 64-char lowercase hex digest")
    else:
        expected_bundle_digest = encryption_helper._sha256_file(bundle_path)
        if receipt_bundle_digest != expected_bundle_digest:
            failures.append("release_receipt.release_bundle_sha256 does not match release_bundle.json")
    if not bool(receipt_payload.get("release_approval_verified")):
        failures.append("release_receipt.release_approval_verified must be true")
    approval_sha256 = str(receipt_payload.get("release_approval_sha256") or "").strip().lower()
    if not _is_hex_64(approval_sha256):
        failures.append("release_receipt.release_approval_sha256 must be a 64-char lowercase hex digest")
    else:
        expected_approval_digest = encryption_helper._sha256_file(approval_path)
        if approval_sha256 != expected_approval_digest:
            failures.append("release_receipt.release_approval_sha256 does not match release_approval.json")
    approval_signature_digest = str(receipt_payload.get("release_approval_signature_digest") or "").strip().lower()
    if not _is_hex_64(approval_signature_digest):
        failures.append("release_receipt.release_approval_signature_digest must be a 64-char lowercase hex digest")
    elif isinstance(signature, dict):
        expected_signature_digest = str(signature.get("digest_hex") or "").strip().lower()
        if _is_hex_64(expected_signature_digest) and approval_signature_digest != expected_signature_digest:
            failures.append(
                "release_receipt.release_approval_signature_digest does not match release_approval.signature.digest_hex"
            )
    receipt_key_id = str(receipt_payload.get("release_approval_key_id") or "").strip()
    if isinstance(signature, dict):
        signature_key_id = str(signature.get("key_id") or "").strip()
        if signature_key_id and receipt_key_id != signature_key_id:
            failures.append("release_receipt.release_approval_key_id does not match release_approval.signature.key_id")
    receipt_approval_context = receipt_payload.get("release_approval_github_context")
    approval_context = approval_payload.get("github_context")
    if isinstance(approval_context, dict):
        if receipt_approval_context != approval_context:
            failures.append("release_receipt.release_approval_github_context does not match release_approval.github_context")
    elif receipt_approval_context is not None:
        failures.append("release_receipt.release_approval_github_context present but release_approval.github_context is missing")
    if require_ci_context_match:
        if runtime_context:
            _validate_ci_context_binding(
                runtime_context=runtime_context,
                artifact_context=receipt_payload.get("github_context"),
                context_label="release_receipt.github_context",
                failures=failures,
            )
            _validate_ci_context_binding(
                runtime_context=runtime_context,
                artifact_context=receipt_approval_context,
                context_label="release_receipt.release_approval_github_context",
                failures=failures,
            )
    runtime_verified = receipt_payload.get("runtime_artifacts_verified")
    if isinstance(runtime_verified, bool) or not isinstance(runtime_verified, int) or runtime_verified < 1:
        failures.append("release_receipt.runtime_artifacts_verified must be an integer >= 1")
    native_verified = receipt_payload.get("native_artifacts_verified")
    if isinstance(native_verified, bool) or not isinstance(native_verified, int) or native_verified < 1:
        failures.append("release_receipt.native_artifacts_verified must be an integer >= 1")


def _validate_promotion_evidence(evidence_path: Path, failures: List[str]) -> None:
    evidence_payload = _load_json_object(evidence_path, "promotion evidence")
    try:
        promotion_audit.normalize_promotion_evidence_payload(evidence_payload)
    except Exception as exc:
        failures.append("promotion_evidence schema validation failed: {0}".format(exc))


def _validate_promotion_report(report_path: Path, failures: List[str]) -> None:
    report_payload = _load_json_object(report_path, "promotion audit report")
    if report_payload.get("schema") != promotion_audit.PROMOTION_AUDIT_REPORT_SCHEMA:
        failures.append(
            "promotion_audit_report schema mismatch: expected {0}, got {1}".format(
                promotion_audit.PROMOTION_AUDIT_REPORT_SCHEMA,
                report_payload.get("schema"),
            )
        )
    if not bool(report_payload.get("passed")):
        failures.append("promotion_audit_report.passed must be true")
    summary = report_payload.get("summary")
    if not isinstance(summary, dict):
        failures.append("promotion_audit_report.summary must be an object")
        return
    total_failures = summary.get("total_failures")
    if isinstance(total_failures, bool) or not isinstance(total_failures, int):
        failures.append("promotion_audit_report.summary.total_failures must be an integer")
    elif total_failures != 0:
        failures.append("promotion_audit_report.summary.total_failures must be 0")


def _validate_promotion_report_input_binding(
    *,
    report_path: Path,
    evidence_path: Path,
    policy_path: Path,
    workflow_path: Path,
    failures: List[str],
) -> None:
    report_payload = _load_json_object(report_path, "promotion audit report")
    inputs = report_payload.get("inputs")
    if not isinstance(inputs, dict):
        failures.append("promotion_audit_report.inputs is required for evidence/workflow digest binding")
        return

    def _validate_binding(label: str, expected_path: Path) -> None:
        file_key = "{0}_file".format(label)
        sha_key = "{0}_sha256".format(label)

        expected_path_text = str(expected_path)
        actual_path_text = str(inputs.get(file_key) or "").strip()
        if actual_path_text != expected_path_text:
            failures.append(
                "promotion_audit_report.inputs.{0} mismatch: expected {1}, got {2}".format(
                    file_key,
                    expected_path_text,
                    actual_path_text or "<empty>",
                )
            )

        if not expected_path.exists():
            failures.append(
                "promotion_audit_report.{0} digest binding file not found: {1}".format(
                    file_key,
                    expected_path,
                )
            )
            return

        expected_sha256 = encryption_helper._sha256_file(expected_path)
        actual_sha256 = str(inputs.get(sha_key) or "").strip().lower()
        if not _is_hex_64(actual_sha256):
            failures.append(
                "promotion_audit_report.inputs.{0} must be a 64-char lowercase hex digest".format(sha_key)
            )
            return
        if actual_sha256 != expected_sha256:
            failures.append(
                "promotion_audit_report.inputs.{0} mismatch: expected {1}, got {2}".format(
                    sha_key,
                    expected_sha256,
                    actual_sha256,
                )
            )

    _validate_binding("evidence", evidence_path)
    _validate_binding("policy", policy_path)
    _validate_binding("workflow", workflow_path)


def _default_workflow_path_for_policy(policy_path: Path, *, repo_root: Path) -> Path:
    fallback = (repo_root / ".github/workflows/release_promotion.yml").resolve()
    if not policy_path.exists():
        return fallback
    try:
        policy_payload = _load_json_object(policy_path, "promotion policy")
    except Exception:
        return fallback
    workflow_payload = policy_payload.get("workflow")
    if not isinstance(workflow_payload, dict):
        return fallback
    workflow_relative = str(workflow_payload.get("relative_path") or "").strip()
    if not workflow_relative:
        return fallback
    candidate = Path(workflow_relative).expanduser()
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return candidate.resolve()


def _validate_rotation_report(
    rotation_report_path: Path,
    failures: List[str],
    require_rotation_pass: bool,
    require_ci_context_match: bool,
    runtime_context: Optional[Mapping[str, str]],
) -> None:
    payload = _load_json_object(rotation_report_path, "rotation rehearsal report")
    if payload.get("schema") != ROTATION_REHEARSAL_SCHEMA:
        failures.append(
            "rotation_rehearsal_report schema mismatch: expected {0}, got {1}".format(
                ROTATION_REHEARSAL_SCHEMA,
                payload.get("schema"),
            )
        )

    requested = payload.get("requested")
    executed = payload.get("executed")
    old_key_rejected = payload.get("old_key_rejected")
    status = str(payload.get("status") or "").strip()

    if not isinstance(requested, bool):
        failures.append("rotation_rehearsal_report.requested must be boolean")
    if not isinstance(executed, bool):
        failures.append("rotation_rehearsal_report.executed must be boolean")
    if old_key_rejected is not None and not isinstance(old_key_rejected, bool):
        failures.append("rotation_rehearsal_report.old_key_rejected must be boolean or null")
    if not status:
        failures.append("rotation_rehearsal_report.status is required")

    if require_ci_context_match:
        if runtime_context:
            context_bindings = (
                ("workflow_run_id", "GITHUB_RUN_ID"),
                ("workflow_ref", "GITHUB_REF"),
                ("workflow_sha", "GITHUB_SHA"),
                ("workflow_github_actions", "GITHUB_ACTIONS"),
                ("workflow_ci", "CI"),
                ("workflow_runner_environment", "RUNNER_ENVIRONMENT"),
                ("workflow_runner_os", "RUNNER_OS"),
                ("workflow_runner_arch", "RUNNER_ARCH"),
                ("workflow_run_attempt", "GITHUB_RUN_ATTEMPT"),
                ("workflow_run_number", "GITHUB_RUN_NUMBER"),
                ("workflow_name", "GITHUB_WORKFLOW"),
                ("workflow_ref_name", "GITHUB_REF_NAME"),
                ("workflow_ref_type", "GITHUB_REF_TYPE"),
                ("workflow_name_ref", "GITHUB_WORKFLOW_REF"),
                ("workflow_name_sha", "GITHUB_WORKFLOW_SHA"),
                ("workflow_event", "GITHUB_EVENT_NAME"),
                ("workflow_server_url", "GITHUB_SERVER_URL"),
                ("workflow_api_url", "GITHUB_API_URL"),
                ("workflow_graphql_url", "GITHUB_GRAPHQL_URL"),
                ("workflow_job", "GITHUB_JOB"),
                ("workflow_actor", "GITHUB_ACTOR"),
                ("workflow_triggering_actor", "GITHUB_TRIGGERING_ACTOR"),
                ("workflow_actor_id", "GITHUB_ACTOR_ID"),
                ("workflow_repository_id", "GITHUB_REPOSITORY_ID"),
                ("workflow_repository_owner", "GITHUB_REPOSITORY_OWNER"),
                ("workflow_repository_owner_id", "GITHUB_REPOSITORY_OWNER_ID"),
                ("workflow_ref_protected", STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY),
            )
            for report_key, runtime_key in context_bindings:
                if runtime_key == STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY:
                    expected = _normalize_ref_protected(runtime_context.get(runtime_key))
                else:
                    expected = _normalize_text(runtime_context.get(runtime_key))
                if not expected:
                    continue
                if runtime_key == STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY:
                    actual = _normalize_ref_protected(payload.get(report_key))
                else:
                    actual = _normalize_text(payload.get(report_key))
                if not actual:
                    failures.append(
                        "rotation_rehearsal_report.{0} missing for CI context key {1}".format(
                            report_key,
                            runtime_key,
                        )
                    )
                    continue
                if actual != expected:
                    failures.append(
                        "rotation_rehearsal_report.{0} mismatch: expected {1}, got {2}".format(
                            report_key,
                            expected,
                            actual,
                        )
                    )

    if require_rotation_pass:
        if requested is not True:
            failures.append("rotation rehearsal pass required but report.requested is not true")
        if executed is not True:
            failures.append("rotation rehearsal pass required but report.executed is not true")
        if old_key_rejected is not True:
            failures.append("rotation rehearsal pass required but report.old_key_rejected is not true")
        if status != "passed":
            failures.append("rotation rehearsal pass required but report.status is not 'passed'")


def _github_context_snapshot() -> Dict[str, str]:
    keys = (
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_REF_PROTECTED",
        "GITHUB_ACTIONS",
        "CI",
        "RUNNER_ENVIRONMENT",
        "RUNNER_OS",
        "RUNNER_ARCH",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_RUN_NUMBER",
        "GITHUB_WORKFLOW",
        "GITHUB_REF_NAME",
        "GITHUB_REF_TYPE",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_WORKFLOW_SHA",
        "GITHUB_EVENT_NAME",
        "GITHUB_SERVER_URL",
        "GITHUB_API_URL",
        "GITHUB_GRAPHQL_URL",
        "GITHUB_JOB",
        "GITHUB_ACTOR",
        "GITHUB_TRIGGERING_ACTOR",
        "GITHUB_ACTOR_ID",
        "GITHUB_REPOSITORY_ID",
        "GITHUB_REPOSITORY_OWNER",
        "GITHUB_REPOSITORY_OWNER_ID",
    )
    context = {}
    for key in keys:
        value = os.environ.get(key)
        if value:
            context[key] = value
    return context


def _normalize_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _normalize_ref_protected(value: object) -> str:
    text = _normalize_text(value).lower()
    if text in {"true", "1", "yes", "y", "on"}:
        return "true"
    if text in {"false", "0", "no", "n", "off"}:
        return "false"
    return ""


def _validate_ci_context_binding(
    *,
    runtime_context: Mapping[str, str],
    artifact_context: object,
    context_label: str,
    failures: List[str],
) -> None:
    if not isinstance(artifact_context, dict):
        failures.append(
            "{0} must be present when --require-ci-context-match is enabled".format(context_label)
        )
        return
    for key in STRICT_CONTEXT_REQUIRED_IDENTITY_KEYS:
        expected = _normalize_text(runtime_context.get(key))
        if not expected:
            continue
        actual = _normalize_text(artifact_context.get(key))
        if not actual:
            failures.append("{0} missing required key: {1}".format(context_label, key))
            continue
        if actual != expected:
            failures.append(
                "{0}.{1} mismatch: expected {2}, got {3}".format(
                    context_label,
                    key,
                    expected,
                    actual,
                )
            )
    for key in STRICT_CONTEXT_REQUIRED_BINDING_KEYS:
        expected = _normalize_text(runtime_context.get(key))
        if not expected:
            continue
        actual = _normalize_text(artifact_context.get(key))
        if not actual:
            failures.append("{0} missing required key: {1}".format(context_label, key))
            continue
        if actual != expected:
            failures.append(
                "{0}.{1} mismatch: expected {2}, got {3}".format(
                    context_label,
                    key,
                    expected,
                    actual,
                )
            )
    for key in STRICT_CONTEXT_OPTIONAL_BINDING_KEYS:
        expected = _normalize_text(runtime_context.get(key))
        actual = _normalize_text(artifact_context.get(key))
        if expected and actual and actual != expected:
            failures.append(
                "{0}.{1} mismatch: expected {2}, got {3}".format(
                    context_label,
                    key,
                    expected,
                    actual,
                )
            )
    expected_ref_protected = _normalize_ref_protected(runtime_context.get(STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY))
    actual_ref_protected = _normalize_ref_protected(artifact_context.get(STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY))
    if expected_ref_protected and actual_ref_protected and actual_ref_protected != expected_ref_protected:
        failures.append(
            "{0}.{1} mismatch: expected {2}, got {3}".format(
                context_label,
                STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY,
                expected_ref_protected,
                actual_ref_protected,
            )
        )


def _validate_evidence_github_context(
    evidence_payload: Mapping[str, object],
    failures: List[str],
    require_ci_context_match: bool,
    runtime_context: Optional[Mapping[str, str]],
) -> None:
    if not require_ci_context_match:
        return
    if not runtime_context:
        failures.append(
            "CI context match is required but no GitHub runtime environment context is available"
        )
        return
    _validate_ci_context_binding(
        runtime_context=runtime_context,
        artifact_context=evidence_payload.get("github_context"),
        context_label="promotion_evidence.github_context",
        failures=failures,
    )


def _artifact_digest_rows(paths: List[Tuple[str, Path]]) -> List[Dict[str, str]]:
    rows = []
    for name, path in paths:
        rows.append(
            {
                "name": name,
                "path": str(path),
                "sha256": encryption_helper._sha256_file(path),
            }
        )
    return rows


def _expected_run_receipt_artifact_paths(
    *,
    report_path: Path,
    release_dir: Path,
    evidence_path: Path,
    promotion_report_path: Path,
    rotation_path: Path,
) -> List[Tuple[str, Path]]:
    return [
        ("release_bundle", release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME),
        ("release_approval", release_dir / "release_approval.json"),
        ("release_receipt", release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME),
        ("promotion_evidence", evidence_path),
        ("promotion_audit_report", promotion_report_path),
        ("rotation_rehearsal_report", rotation_path),
        (RUN_RECEIPT_VOLATILE_ARTIFACT, report_path),
    ]


def _validate_existing_run_receipt_binding(
    *,
    run_receipt_path: Path,
    report_path: Path,
    release_dir: Path,
    evidence_path: Path,
    promotion_report_path: Path,
    rotation_path: Path,
    require_rotation_pass: bool,
    require_ci_context_match: bool,
    runtime_context: Optional[Mapping[str, str]],
    approval_key: Optional[bytes],
    require_signature: bool,
    expected_signature_key_id: Optional[str],
    failures: List[str],
) -> None:
    if not run_receipt_path.exists():
        return
    payload = _load_json_object(run_receipt_path, "promotion run receipt")
    if payload.get("schema") != PROMOTION_RUN_RECEIPT_SCHEMA:
        failures.append(
            "promotion_run_receipt schema mismatch: expected {0}, got {1}".format(
                PROMOTION_RUN_RECEIPT_SCHEMA,
                payload.get("schema"),
            )
        )
    if not isinstance(payload.get("passed"), bool):
        failures.append("promotion_run_receipt.passed must be boolean")

    receipt_rotation_required = payload.get("rotation_pass_required")
    if not isinstance(receipt_rotation_required, bool):
        failures.append("promotion_run_receipt.rotation_pass_required must be boolean")
    elif receipt_rotation_required != bool(require_rotation_pass):
        failures.append(
            "promotion_run_receipt.rotation_pass_required mismatch: expected {0}, got {1}".format(
                bool(require_rotation_pass),
                receipt_rotation_required,
            )
        )

    expected_report_path_text = str(report_path)
    actual_report_path_text = _normalize_text(payload.get("promotion_artifact_audit_report_file"))
    if actual_report_path_text != expected_report_path_text:
        failures.append(
            "promotion_run_receipt.promotion_artifact_audit_report_file mismatch: expected {0}, got {1}".format(
                expected_report_path_text,
                actual_report_path_text or "<empty>",
            )
        )

    if require_ci_context_match:
        if runtime_context:
            _validate_ci_context_binding(
                runtime_context=runtime_context,
                artifact_context=payload.get("github_context"),
                context_label="promotion_run_receipt.github_context",
                failures=failures,
            )

    artifact_rows = payload.get("artifacts")
    if not isinstance(artifact_rows, list):
        failures.append("promotion_run_receipt.artifacts must be a list")
        return

    rows_by_name = {}  # type: Dict[str, Dict[str, str]]
    for index, row in enumerate(artifact_rows):
        if not isinstance(row, dict):
            failures.append("promotion_run_receipt.artifacts[{0}] must be an object".format(index))
            continue
        name = _normalize_text(row.get("name"))
        row_path = _normalize_text(row.get("path"))
        digest = _normalize_text(row.get("sha256")).lower()
        if not name:
            failures.append("promotion_run_receipt.artifacts[{0}].name is required".format(index))
            continue
        if name in rows_by_name:
            failures.append("promotion_run_receipt.artifacts duplicate name: {0}".format(name))
            continue
        if not row_path:
            failures.append("promotion_run_receipt.artifacts[{0}].path is required".format(index))
            continue
        if not _is_hex_64(digest):
            failures.append(
                "promotion_run_receipt.artifacts[{0}].sha256 must be a 64-char lowercase hex digest".format(index)
            )
            continue
        rows_by_name[name] = {
            "path": row_path,
            "sha256": digest,
        }

    expected_rows = _expected_run_receipt_artifact_paths(
        report_path=report_path,
        release_dir=release_dir,
        evidence_path=evidence_path,
        promotion_report_path=promotion_report_path,
        rotation_path=rotation_path,
    )
    for required_name in RUN_RECEIPT_REQUIRED_ARTIFACTS:
        if required_name not in rows_by_name:
            failures.append("promotion_run_receipt.artifacts missing required entry: {0}".format(required_name))

    for name, expected_path in expected_rows:
        row = rows_by_name.get(name)
        if row is None:
            continue
        expected_path_text = str(expected_path)
        actual_path_text = row["path"]
        if actual_path_text != expected_path_text:
            failures.append(
                "promotion_run_receipt.artifacts[{0}].path mismatch: expected {1}, got {2}".format(
                    name,
                    expected_path_text,
                    actual_path_text,
                )
            )
        if not expected_path.exists():
            failures.append("promotion_run_receipt artifact file not found: {0}".format(expected_path))
            continue
        expected_digest = encryption_helper._sha256_file(expected_path)
        if row["sha256"] != expected_digest:
            failures.append(
                "promotion_run_receipt.artifacts[{0}].sha256 mismatch: expected {1}, got {2}".format(
                    name,
                    expected_digest,
                    row["sha256"],
                )
            )

    signature = payload.get("signature")
    if not isinstance(signature, dict):
        if require_signature:
            failures.append("promotion_run_receipt.signature is required")
        return
    algorithm = _normalize_text(signature.get("algorithm")).lower()
    if algorithm != PROMOTION_RUN_RECEIPT_SIGNATURE_ALGORITHM:
        failures.append(
            "promotion_run_receipt.signature.algorithm must be {0}".format(
                PROMOTION_RUN_RECEIPT_SIGNATURE_ALGORITHM
            )
        )
    digest_hex = _normalize_text(signature.get("digest_hex")).lower()
    if not _is_hex_64(digest_hex):
        failures.append("promotion_run_receipt.signature.digest_hex must be a 64-char lowercase hex digest")
    key_id = _normalize_text(signature.get("key_id"))
    if not key_id:
        failures.append("promotion_run_receipt.signature.key_id is required")
    expected_key_id = _normalize_text(payload.get("release_approval_key_id"))
    if not expected_key_id:
        failures.append("promotion_run_receipt.release_approval_key_id is required")
    declared_expected_key_id = _normalize_text(expected_signature_key_id)
    if declared_expected_key_id and expected_key_id and expected_key_id != declared_expected_key_id:
        failures.append(
            "promotion_run_receipt.release_approval_key_id mismatch: expected {0}, got {1}".format(
                declared_expected_key_id,
                expected_key_id,
            )
        )
    elif key_id and key_id != expected_key_id:
        failures.append(
            "promotion_run_receipt.signature.key_id mismatch: expected {0}, got {1}".format(
                expected_key_id,
                key_id,
            )
        )

    if approval_key is None:
        if require_signature:
            failures.append("release approval verification key is required for promotion_run_receipt signature verification")
        return
    if _is_hex_64(digest_hex):
        expected_digest = _compute_run_receipt_signature(payload, approval_key)
        if not hmac.compare_digest(expected_digest, digest_hex):
            failures.append(
                "promotion_run_receipt.signature.digest_hex does not match provided approval verification key"
            )


def _validate_runtime_context_completeness(
    runtime_context: Mapping[str, str],
    failures: List[str],
) -> None:
    required_keys = (
        STRICT_CONTEXT_REQUIRED_IDENTITY_KEYS
        + STRICT_CONTEXT_REQUIRED_BINDING_KEYS
        + (STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY,)
    )
    for key in required_keys:
        if not _normalize_text(runtime_context.get(key)):
            failures.append("missing runtime GitHub context key for CI match: {0}".format(key))


def _write_promotion_run_receipt(
    *,
    run_receipt_path: Path,
    report_path: Path,
    report: Dict[str, object],
    release_dir: Path,
    evidence_path: Path,
    promotion_report_path: Path,
    rotation_path: Path,
    signature_key: Optional[bytes],
    signature_key_id: Optional[str],
) -> Path:
    artifact_rows = _artifact_digest_rows(
        _expected_run_receipt_artifact_paths(
            report_path=report_path,
            release_dir=release_dir,
            evidence_path=evidence_path,
            promotion_report_path=promotion_report_path,
            rotation_path=rotation_path,
        )
    )
    receipt = {
        "schema": PROMOTION_RUN_RECEIPT_SCHEMA,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "passed": bool(report.get("passed")),
        "rotation_pass_required": bool(report.get("rotation_pass_required")),
        "promotion_artifact_audit_report_file": str(report_path),
        "release_approval_key_id": _normalize_text(signature_key_id) or None,
        "github_context": _github_context_snapshot(),
        "artifacts": artifact_rows,
    }
    if signature_key is not None and _normalize_text(signature_key_id):
        digest_hex = _compute_run_receipt_signature(receipt, signature_key)
        receipt["signature"] = {
            "algorithm": PROMOTION_RUN_RECEIPT_SIGNATURE_ALGORITHM,
            "key_id": _normalize_text(signature_key_id),
            "digest_hex": digest_hex,
        }
    run_receipt_path.parent.mkdir(parents=True, exist_ok=True)
    run_receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
    return run_receipt_path


def run_promotion_artifact_audit(
    *,
    dist_dir: str,
    promotion_evidence_file: str,
    promotion_report_file: str,
    rotation_report_file: str,
    release_approval_key_file: Optional[str] = None,
    release_approval_key_b64: Optional[str] = None,
    release_approval_key_id: Optional[str] = None,
    promotion_policy_file: Optional[str] = None,
    promotion_workflow_file: Optional[str] = None,
    report_file: Optional[str] = None,
    run_receipt_file: Optional[str] = None,
    require_release_approval_signature: bool = False,
    require_rotation_pass: bool = False,
    require_ci_context_match: bool = False,
    repo_root: Optional[Path] = None,
) -> Tuple[Path, Dict[str, object]]:
    root = repo_root.resolve() if repo_root is not None else Path.cwd().resolve()
    release_dir = _resolve_path(dist_dir, repo_root=root)
    evidence_path = _resolve_path(promotion_evidence_file, repo_root=root)
    promotion_report_path = _resolve_path(promotion_report_file, repo_root=root)
    rotation_path = _resolve_path(rotation_report_file, repo_root=root)
    policy_path = _resolve_path(
        promotion_policy_file,
        repo_root=root,
        fallback=promotion_audit.default_policy_path(root),
    )
    workflow_path = _resolve_path(
        promotion_workflow_file,
        repo_root=root,
        fallback=_default_workflow_path_for_policy(policy_path, repo_root=root),
    )
    report_path = _resolve_path(
        report_file,
        repo_root=root,
        fallback=promotion_report_path.parent / DEFAULT_REPORT_FILENAME,
    )
    run_receipt_path = _resolve_path(
        run_receipt_file,
        repo_root=root,
        fallback=promotion_report_path.parent / DEFAULT_RUN_RECEIPT_FILENAME,
    )
    release_approval_key_path = (
        _resolve_path(release_approval_key_file, repo_root=root) if release_approval_key_file else None
    )
    release_approval_key = encryption_helper.load_release_approval_key(
        key_file=release_approval_key_path,
        key_b64=release_approval_key_b64,
    )
    runtime_context = _github_context_snapshot() if require_ci_context_match else None

    failures = []  # type: List[str]
    if require_ci_context_match and runtime_context:
        _validate_runtime_context_completeness(runtime_context, failures)
    _validate_release_artifacts(
        release_dir,
        failures,
        runtime_context=runtime_context,
        approval_key=release_approval_key,
        expected_approval_key_id=release_approval_key_id,
        require_approval_signature=require_release_approval_signature,
        require_ci_context_match=require_ci_context_match,
    )
    _validate_promotion_evidence(evidence_path, failures)
    evidence_payload = _load_json_object(evidence_path, "promotion evidence")
    _validate_evidence_github_context(
        evidence_payload,
        failures,
        require_ci_context_match=require_ci_context_match,
        runtime_context=runtime_context,
    )
    _validate_promotion_report(promotion_report_path, failures)
    _validate_promotion_report_input_binding(
        report_path=promotion_report_path,
        evidence_path=evidence_path,
        policy_path=policy_path,
        workflow_path=workflow_path,
        failures=failures,
    )
    _validate_rotation_report(
        rotation_path,
        failures,
        require_rotation_pass=require_rotation_pass,
        require_ci_context_match=require_ci_context_match,
        runtime_context=runtime_context,
    )
    _validate_existing_run_receipt_binding(
        run_receipt_path=run_receipt_path,
        report_path=report_path,
        release_dir=release_dir,
        evidence_path=evidence_path,
        promotion_report_path=promotion_report_path,
        rotation_path=rotation_path,
        require_rotation_pass=require_rotation_pass,
        require_ci_context_match=require_ci_context_match,
        runtime_context=runtime_context,
        approval_key=release_approval_key,
        require_signature=require_release_approval_signature,
        expected_signature_key_id=release_approval_key_id,
        failures=failures,
    )

    report = {
        "schema": PROMOTION_ARTIFACT_AUDIT_SCHEMA,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "release_dir": str(release_dir),
        "promotion_evidence_file": str(evidence_path),
        "promotion_report_file": str(promotion_report_path),
        "rotation_report_file": str(rotation_path),
        "promotion_policy_file": str(policy_path),
        "promotion_workflow_file": str(workflow_path),
        "rotation_pass_required": bool(require_rotation_pass),
        "release_approval_signature_required": bool(require_release_approval_signature),
        "release_approval_key_id_expected": str(release_approval_key_id or "").strip() or None,
        "ci_context_match_required": bool(require_ci_context_match),
        "passed": not failures,
        "summary": {
            "total_failures": len(failures),
        },
        "failures": failures,
    }

    report["promotion_run_receipt_file"] = str(run_receipt_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_promotion_run_receipt(
        run_receipt_path=run_receipt_path,
        report_path=report_path,
        report=report,
        release_dir=release_dir,
        evidence_path=evidence_path,
        promotion_report_path=promotion_report_path,
        rotation_path=rotation_path,
        signature_key=release_approval_key,
        signature_key_id=release_approval_key_id,
    )
    return report_path, report
