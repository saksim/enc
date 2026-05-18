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
from urllib.parse import unquote, urlparse

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
    "RUNNER_NAME",
    "GITHUB_SHA",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_NUMBER",
    "GITHUB_RETENTION_DAYS",
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
STRICT_CONTEXT_BOOLEAN_BINDING_KEYS = (
    "GITHUB_ACTIONS",
    "CI",
)
STRICT_CONTEXT_CI_TRUE_BOOLEAN_KEYS = (
    "GITHUB_ACTIONS",
    "CI",
)
STRICT_CONTEXT_POSITIVE_INTEGER_KEYS = (
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_NUMBER",
    "GITHUB_RETENTION_DAYS",
    "GITHUB_ACTOR_ID",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER_ID",
)
STRICT_CONTEXT_SHA_KEYS = (
    "GITHUB_SHA",
    "GITHUB_WORKFLOW_SHA",
)
STRICT_CONTEXT_URL_KEYS = (
    "GITHUB_SERVER_URL",
    "GITHUB_API_URL",
    "GITHUB_GRAPHQL_URL",
)
STRICT_CONTEXT_ENUM_VALUES = {
    "GITHUB_REF_TYPE": ("branch", "tag"),
    "RUNNER_ENVIRONMENT": ("github-hosted", "self-hosted"),
    "RUNNER_OS": ("linux", "windows", "macos"),
    "RUNNER_ARCH": ("x86", "x64", "arm", "arm64"),
}
STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY = "GITHUB_REF_PROTECTED"
GITHUB_REF_BRANCH_PREFIX = "refs/heads/"
GITHUB_REF_TAG_PREFIX = "refs/tags/"
GITHUB_WORKFLOW_PATH_MARKER = "/.github/workflows/"
GITHUB_WORKFLOW_FILE_SUFFIXES = (".yml", ".yaml")
GITHUB_PUBLIC_SERVER_HOST = "github.com"
GITHUB_PUBLIC_API_HOST = "api.github.com"
GITHUB_PUBLIC_API_PATH = "/"
GITHUB_PUBLIC_GRAPHQL_PATH = "/graphql"
GITHUB_ENTERPRISE_API_PATH = "/api/v3"
GITHUB_ENTERPRISE_GRAPHQL_PATH = "/api/graphql"
REPOSITORY_SLUG_SEGMENT_ALLOWED_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_.")
GIT_REF_DISALLOWED_CHARS = frozenset(" ~^:?*[\\")
ROTATION_REPORT_TO_GITHUB_CONTEXT_KEYS = (
    ("workflow_repository", "GITHUB_REPOSITORY"),
    ("workflow_run_id", "GITHUB_RUN_ID"),
    ("workflow_ref", "GITHUB_REF"),
    ("workflow_ref_name", "GITHUB_REF_NAME"),
    ("workflow_ref_type", "GITHUB_REF_TYPE"),
    ("workflow_sha", "GITHUB_SHA"),
    ("workflow_github_actions", "GITHUB_ACTIONS"),
    ("workflow_ci", "CI"),
    ("workflow_runner_environment", "RUNNER_ENVIRONMENT"),
    ("workflow_runner_os", "RUNNER_OS"),
    ("workflow_runner_arch", "RUNNER_ARCH"),
    ("workflow_runner_name", "RUNNER_NAME"),
    ("workflow_run_attempt", "GITHUB_RUN_ATTEMPT"),
    ("workflow_run_number", "GITHUB_RUN_NUMBER"),
    ("workflow_retention_days", "GITHUB_RETENTION_DAYS"),
    ("workflow_name", "GITHUB_WORKFLOW"),
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
            for report_key, runtime_key in ROTATION_REPORT_TO_GITHUB_CONTEXT_KEYS:
                expected = _normalize_ci_context_key_value(runtime_key, runtime_context.get(runtime_key))
                if not expected:
                    continue
                raw_actual = _normalize_text(payload.get(report_key))
                actual = _normalize_ci_context_key_value(runtime_key, payload.get(report_key))
                if raw_actual and not actual:
                    failures.append(
                        "rotation_rehearsal_report.{0} invalid value for CI context key {1} (expected {2})".format(
                            report_key,
                            runtime_key,
                            _context_key_value_requirement(runtime_key),
                        )
                    )
                    continue
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
        "RUNNER_NAME",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_RUN_NUMBER",
        "GITHUB_RETENTION_DAYS",
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


def _normalize_strict_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    if not value:
        return ""
    if value != value.strip():
        return ""
    for char in value:
        codepoint = ord(char)
        if codepoint < 32 or codepoint == 127:
            return ""
    return value


def _normalize_ref_protected(value: object) -> str:
    text = _normalize_strict_text(value)
    if text == "true":
        return "true"
    if text == "false":
        return "false"
    return ""


def _normalize_boolean_like(value: object) -> str:
    text = _normalize_strict_text(value)
    if text == "true":
        return "true"
    if text == "false":
        return "false"
    return ""


def _normalize_positive_integer_like(value: object) -> str:
    text = _normalize_text(value)
    if not text or not text.isdigit():
        return ""
    try:
        parsed = int(text, 10)
    except ValueError:
        return ""
    if parsed <= 0:
        return ""
    return str(parsed)


def _normalize_sha_like(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if value != text:
        return ""
    text = text.lower()
    if len(text) != 40:
        return ""
    if not all(ch in "0123456789abcdef" for ch in text):
        return ""
    return text


def _normalize_enum_like(value: object, allowed_values: Tuple[str, ...]) -> str:
    text = _normalize_text(value).lower()
    if text in allowed_values:
        return text
    return ""


def _normalize_http_url_like(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if value != text:
        return ""
    if not text:
        return ""
    parsed = urlparse(text)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return ""
    if not parsed.netloc:
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    if parsed.params or parsed.query or parsed.fragment:
        return ""
    if parsed.path and not parsed.path.startswith("/"):
        return ""
    if parsed.path.endswith("/") and parsed.path != "/":
        return ""
    if "//" in parsed.path:
        return ""
    hostname = parsed.hostname
    if not hostname:
        return ""
    if hostname.endswith("."):
        return ""
    if parsed.netloc != parsed.netloc.lower():
        return ""
    if parsed.netloc.endswith(":"):
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port is not None:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            return ""
    return parsed.geturl()


def _normalize_https_url_like(value: object) -> str:
    normalized = _normalize_http_url_like(value)
    if not normalized:
        return ""
    parsed = urlparse(normalized)
    if parsed.scheme.lower() != "https":
        return ""
    return normalized


def _normalize_url_semantic_components(value: str) -> Tuple[str, str, str]:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    return scheme, netloc, path


def _format_url_origin(scheme: str, netloc: str) -> str:
    return "{0}://{1}".format(scheme, netloc)


def _is_valid_git_ref_name(ref_name: str) -> bool:
    if not ref_name:
        return False
    if ref_name == "@":
        return False
    if ref_name.startswith("/") or ref_name.endswith("/"):
        return False
    if ref_name.endswith("."):
        return False
    if "//" in ref_name or ".." in ref_name or "@{" in ref_name:
        return False
    for char in ref_name:
        codepoint = ord(char)
        if codepoint < 32 or codepoint == 127:
            return False
        if char in GIT_REF_DISALLOWED_CHARS:
            return False
    for segment in ref_name.split("/"):
        if not segment:
            return False
        if segment.startswith("."):
            return False
        if segment.endswith(".lock"):
            return False
    return True


def _normalize_git_ref_like(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if value != text:
        return ""
    if not text:
        return ""
    if not _is_valid_git_ref_name(text):
        return ""
    return text


def _normalize_workflow_ref_like(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if value != text:
        return ""
    if not text:
        return ""
    if "@" not in text:
        return ""
    workflow_path, workflow_ref = text.split("@", 1)
    workflow_path = workflow_path.strip()
    workflow_ref = workflow_ref.strip()
    if not workflow_path or not workflow_ref:
        return ""
    marker_index = workflow_path.find(GITHUB_WORKFLOW_PATH_MARKER)
    if marker_index <= 0:
        return ""
    repository_slug = workflow_path[:marker_index]
    if not _normalize_repository_slug(repository_slug):
        return ""
    workflow_relative_path = workflow_path[marker_index + len(GITHUB_WORKFLOW_PATH_MARKER):]
    if not workflow_relative_path:
        return ""
    workflow_segments = workflow_relative_path.split("/")
    for segment in workflow_segments:
        if not segment or segment in {".", ".."}:
            return ""
        if "\\" in segment:
            return ""
        if "%" in segment:
            return ""
        decoded_segment = unquote(segment)
        if not decoded_segment:
            return ""
        if decoded_segment in {".", ".."}:
            return ""
        if "/" in decoded_segment or "\\" in decoded_segment:
            return ""
    if not workflow_path.endswith(GITHUB_WORKFLOW_FILE_SUFFIXES):
        return ""
    if not workflow_ref.startswith("refs/heads/") and not workflow_ref.startswith("refs/tags/"):
        return ""
    if not _normalize_git_ref_like(workflow_ref):
        return ""
    return "{0}@{1}".format(workflow_path, workflow_ref)


def _normalize_ci_context_key_value(key: str, value: object) -> str:
    if key == "GITHUB_REPOSITORY":
        return _normalize_repository_slug(value)
    if key == "GITHUB_REF":
        return _normalize_git_ref_like(value)
    if key == STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY:
        return _normalize_ref_protected(value)
    if key == "GITHUB_WORKFLOW_REF":
        return _normalize_workflow_ref_like(value)
    if key in STRICT_CONTEXT_URL_KEYS:
        return _normalize_https_url_like(value)
    if key in STRICT_CONTEXT_BOOLEAN_BINDING_KEYS:
        return _normalize_boolean_like(value)
    if key in STRICT_CONTEXT_POSITIVE_INTEGER_KEYS:
        return _normalize_positive_integer_like(value)
    if key in STRICT_CONTEXT_SHA_KEYS:
        return _normalize_sha_like(value)
    allowed_values = STRICT_CONTEXT_ENUM_VALUES.get(key)
    if allowed_values is not None:
        return _normalize_enum_like(value, allowed_values)
    return _normalize_strict_text(value)


def _context_key_value_requirement(key: str) -> str:
    if key == "GITHUB_REPOSITORY":
        return "owner/repo slug value with exactly one slash and [a-z0-9._-] segments"
    if key == "GITHUB_REF":
        return "valid git refname value"
    if key == STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY or key in STRICT_CONTEXT_BOOLEAN_BINDING_KEYS:
        return "true/false-like value"
    if key == "GITHUB_WORKFLOW_REF":
        return (
            "workflow ref value formatted as '<owner>/<repo>/.github/workflows/<file>.yml@refs/heads/*' "
            "or '<owner>/<repo>/.github/workflows/<file>.yml@refs/tags/*'"
        )
    if key in STRICT_CONTEXT_URL_KEYS:
        return "HTTP(S) URL with scheme and host"
    if key in STRICT_CONTEXT_POSITIVE_INTEGER_KEYS:
        return "positive integer value"
    if key in STRICT_CONTEXT_SHA_KEYS:
        return "40-character hexadecimal commit SHA value"
    if key in STRICT_CONTEXT_ENUM_VALUES:
        return "one of: {0}".format(", ".join(STRICT_CONTEXT_ENUM_VALUES[key]))
    return "non-empty value"


def _validate_runtime_context_key_value(runtime_context: Mapping[str, str], key: str, failures: List[str]) -> str:
    raw_value = _normalize_text(runtime_context.get(key))
    normalized = _normalize_ci_context_key_value(key, runtime_context.get(key))
    if raw_value and not normalized:
        failures.append(
            "invalid runtime GitHub context key for CI match: {0} (expected {1})".format(
                key,
                _context_key_value_requirement(key),
            )
        )
        return ""
    return normalized


def _validate_artifact_context_key_value(
    artifact_context: Mapping[str, object],
    *,
    context_label: str,
    key: str,
    failures: List[str],
) -> str:
    raw_value = _normalize_text(artifact_context.get(key))
    normalized = _normalize_ci_context_key_value(key, artifact_context.get(key))
    if raw_value and not normalized:
        failures.append(
            "{0} invalid key value: {1} (expected {2})".format(
                context_label,
                key,
                _context_key_value_requirement(key),
            )
        )
        return ""
    return normalized


def _normalize_repository_slug(value: object) -> str:
    if not isinstance(value, str):
        return ""
    stripped = value.strip()
    if value != stripped:
        return ""
    text = stripped.lower()
    if text.count("/") != 1:
        return ""
    owner, repo_name = text.split("/", 1)
    owner = owner.strip()
    repo_name = repo_name.strip()
    if not owner or not repo_name:
        return ""
    if any(ch not in REPOSITORY_SLUG_SEGMENT_ALLOWED_CHARS for ch in owner):
        return ""
    if any(ch not in REPOSITORY_SLUG_SEGMENT_ALLOWED_CHARS for ch in repo_name):
        return ""
    return "{0}/{1}".format(owner, repo_name)


def _normalize_repository_owner(value: object) -> str:
    if not isinstance(value, str):
        return ""
    stripped = value.strip()
    if value != stripped:
        return ""
    text = stripped.lower()
    if not text or "/" in text:
        return ""
    return text


def _workflow_ref_repository_slug(value: object) -> str:
    normalized_workflow_ref = _normalize_workflow_ref_like(value)
    if not normalized_workflow_ref:
        return ""
    workflow_path, _ = normalized_workflow_ref.split("@", 1)
    marker_index = workflow_path.find(GITHUB_WORKFLOW_PATH_MARKER)
    if marker_index <= 0:
        return ""
    return _normalize_repository_slug(workflow_path[:marker_index])


def _workflow_ref_ref_value(value: object) -> str:
    normalized_workflow_ref = _normalize_workflow_ref_like(value)
    if not normalized_workflow_ref:
        return ""
    _, workflow_ref = normalized_workflow_ref.split("@", 1)
    return workflow_ref


def _validate_repository_owner_alignment(
    context: Mapping[str, object],
    *,
    context_label: str,
    failures: List[str],
) -> None:
    repository = _normalize_repository_slug(context.get("GITHUB_REPOSITORY"))
    owner = _normalize_repository_owner(context.get("GITHUB_REPOSITORY_OWNER"))
    if not repository or not owner:
        return
    expected_owner, _ = repository.split("/", 1)
    if owner != expected_owner:
        failures.append(
            "{0}.GITHUB_REPOSITORY_OWNER mismatch with GITHUB_REPOSITORY owner: expected {1}, got {2}".format(
                context_label,
                expected_owner,
                owner,
            )
        )


def _validate_workflow_ref_repository_alignment(
    context: Mapping[str, object],
    *,
    context_label: str,
    failures: List[str],
) -> None:
    repository = _normalize_repository_slug(context.get("GITHUB_REPOSITORY"))
    workflow_ref_repository = _workflow_ref_repository_slug(context.get("GITHUB_WORKFLOW_REF"))
    if not repository or not workflow_ref_repository:
        return
    if workflow_ref_repository != repository:
        failures.append(
            "{0}.GITHUB_WORKFLOW_REF repository mismatch with GITHUB_REPOSITORY: expected {1}, got {2}".format(
                context_label,
                repository,
                workflow_ref_repository,
            )
        )


def _validate_workflow_ref_ref_alignment(
    context: Mapping[str, object],
    *,
    context_label: str,
    failures: List[str],
) -> None:
    normalized_ref = _normalize_ci_context_key_value("GITHUB_REF", context.get("GITHUB_REF"))
    workflow_ref_value = _workflow_ref_ref_value(context.get("GITHUB_WORKFLOW_REF"))
    if not normalized_ref or not workflow_ref_value:
        return
    if workflow_ref_value != normalized_ref:
        failures.append(
            "{0}.GITHUB_WORKFLOW_REF ref mismatch with GITHUB_REF: expected {1}, got {2}".format(
                context_label,
                normalized_ref,
                workflow_ref_value,
            )
        )


def _validate_ref_type_ref_alignment(
    *,
    context_label: str,
    ref_value: str,
    ref_name_value: str,
    ref_type_value: str,
    failures: List[str],
) -> None:
    if not ref_value or not ref_type_value:
        return
    expected_ref_name = ""
    if ref_type_value == "branch":
        if not ref_value.startswith(GITHUB_REF_BRANCH_PREFIX):
            failures.append(
                "{0}.GITHUB_REF invalid value for GITHUB_REF_TYPE=branch (expected prefix {1})".format(
                    context_label,
                    GITHUB_REF_BRANCH_PREFIX,
                )
            )
        else:
            expected_ref_name = ref_value[len(GITHUB_REF_BRANCH_PREFIX):]
    elif ref_type_value == "tag":
        if not ref_value.startswith(GITHUB_REF_TAG_PREFIX):
            failures.append(
                "{0}.GITHUB_REF invalid value for GITHUB_REF_TYPE=tag (expected prefix {1})".format(
                    context_label,
                    GITHUB_REF_TAG_PREFIX,
                )
            )
        else:
            expected_ref_name = ref_value[len(GITHUB_REF_TAG_PREFIX):]
    if expected_ref_name and ref_name_value and ref_name_value != expected_ref_name:
        failures.append(
            "{0}.GITHUB_REF_NAME mismatch with GITHUB_REF: expected {1}, got {2}".format(
                context_label,
                expected_ref_name,
                ref_name_value,
            )
        )


def _validate_ci_activation_key_semantics(
    context: Mapping[str, object],
    *,
    context_label: str,
    failures: List[str],
) -> None:
    for key in STRICT_CONTEXT_CI_TRUE_BOOLEAN_KEYS:
        normalized = _normalize_ci_context_key_value(key, context.get(key))
        if not normalized:
            continue
        if normalized != "true":
            failures.append(
                "{0}.{1} must be true in GitHub Actions CI context".format(
                    context_label,
                    key,
                )
            )


def _validate_ci_url_semantics(
    context: Mapping[str, object],
    *,
    context_label: str,
    failures: List[str],
) -> None:
    server_url = _normalize_https_url_like(context.get("GITHUB_SERVER_URL"))
    api_url = _normalize_https_url_like(context.get("GITHUB_API_URL"))
    graphql_url = _normalize_https_url_like(context.get("GITHUB_GRAPHQL_URL"))
    if not server_url or not api_url or not graphql_url:
        return

    server_scheme, server_netloc, server_path = _normalize_url_semantic_components(server_url)
    api_scheme, api_netloc, api_path = _normalize_url_semantic_components(api_url)
    graphql_scheme, graphql_netloc, graphql_path = _normalize_url_semantic_components(graphql_url)

    if server_path != "/":
        failures.append(
            "{0}.GITHUB_SERVER_URL invalid path: expected /, got {1}".format(
                context_label,
                server_path,
            )
        )

    api_origin = _format_url_origin(api_scheme, api_netloc)
    graphql_origin = _format_url_origin(graphql_scheme, graphql_netloc)
    if api_origin != graphql_origin:
        failures.append(
            "{0}.GITHUB_GRAPHQL_URL origin mismatch with GITHUB_API_URL: expected {1}, got {2}".format(
                context_label,
                api_origin,
                graphql_origin,
            )
        )

    server_origin = _format_url_origin(server_scheme, server_netloc)
    if server_netloc == GITHUB_PUBLIC_SERVER_HOST:
        if api_netloc != GITHUB_PUBLIC_API_HOST:
            failures.append(
                "{0}.GITHUB_API_URL host mismatch for github.com server: expected {1}, got {2}".format(
                    context_label,
                    GITHUB_PUBLIC_API_HOST,
                    api_netloc,
                )
            )
        if api_path != GITHUB_PUBLIC_API_PATH:
            failures.append(
                "{0}.GITHUB_API_URL path mismatch for github.com server: expected {1}, got {2}".format(
                    context_label,
                    GITHUB_PUBLIC_API_PATH,
                    api_path,
                )
            )
        if graphql_path != GITHUB_PUBLIC_GRAPHQL_PATH:
            failures.append(
                "{0}.GITHUB_GRAPHQL_URL path mismatch for github.com server: expected {1}, got {2}".format(
                    context_label,
                    GITHUB_PUBLIC_GRAPHQL_PATH,
                    graphql_path,
                )
            )
        return

    if api_origin != server_origin:
        failures.append(
            "{0}.GITHUB_API_URL origin mismatch with GITHUB_SERVER_URL: expected {1}, got {2}".format(
                context_label,
                server_origin,
                api_origin,
            )
        )
    if graphql_origin != server_origin:
        failures.append(
            "{0}.GITHUB_GRAPHQL_URL origin mismatch with GITHUB_SERVER_URL: expected {1}, got {2}".format(
                context_label,
                server_origin,
                graphql_origin,
            )
        )
    if api_path != GITHUB_ENTERPRISE_API_PATH:
        failures.append(
            "{0}.GITHUB_API_URL path mismatch for enterprise server: expected {1}, got {2}".format(
                context_label,
                GITHUB_ENTERPRISE_API_PATH,
                api_path,
            )
        )
    if graphql_path != GITHUB_ENTERPRISE_GRAPHQL_PATH:
        failures.append(
            "{0}.GITHUB_GRAPHQL_URL path mismatch for enterprise server: expected {1}, got {2}".format(
                context_label,
                GITHUB_ENTERPRISE_GRAPHQL_PATH,
                graphql_path,
            )
        )


def _validate_runtime_ref_semantics(
    runtime_context: Mapping[str, str],
    failures: List[str],
) -> None:
    _validate_repository_owner_alignment(
        runtime_context,
        context_label="runtime GitHub context",
        failures=failures,
    )
    _validate_workflow_ref_repository_alignment(
        runtime_context,
        context_label="runtime GitHub context",
        failures=failures,
    )
    _validate_workflow_ref_ref_alignment(
        runtime_context,
        context_label="runtime GitHub context",
        failures=failures,
    )
    normalized_ref = _normalize_ci_context_key_value("GITHUB_REF", runtime_context.get("GITHUB_REF"))
    normalized_ref_name = _normalize_ci_context_key_value("GITHUB_REF_NAME", runtime_context.get("GITHUB_REF_NAME"))
    normalized_ref_type = _normalize_ci_context_key_value("GITHUB_REF_TYPE", runtime_context.get("GITHUB_REF_TYPE"))
    _validate_ref_type_ref_alignment(
        context_label="runtime GitHub context",
        ref_value=normalized_ref,
        ref_name_value=normalized_ref_name,
        ref_type_value=normalized_ref_type,
        failures=failures,
    )
    _validate_ci_activation_key_semantics(
        runtime_context,
        context_label="runtime GitHub context",
        failures=failures,
    )
    _validate_ci_url_semantics(
        runtime_context,
        context_label="runtime GitHub context",
        failures=failures,
    )


def _validate_artifact_ref_semantics(
    artifact_context: Mapping[str, object],
    *,
    context_label: str,
    failures: List[str],
) -> None:
    _validate_repository_owner_alignment(
        artifact_context,
        context_label=context_label,
        failures=failures,
    )
    _validate_workflow_ref_repository_alignment(
        artifact_context,
        context_label=context_label,
        failures=failures,
    )
    _validate_workflow_ref_ref_alignment(
        artifact_context,
        context_label=context_label,
        failures=failures,
    )
    normalized_ref = _normalize_ci_context_key_value("GITHUB_REF", artifact_context.get("GITHUB_REF"))
    normalized_ref_name = _normalize_ci_context_key_value("GITHUB_REF_NAME", artifact_context.get("GITHUB_REF_NAME"))
    normalized_ref_type = _normalize_ci_context_key_value("GITHUB_REF_TYPE", artifact_context.get("GITHUB_REF_TYPE"))
    _validate_ref_type_ref_alignment(
        context_label=context_label,
        ref_value=normalized_ref,
        ref_name_value=normalized_ref_name,
        ref_type_value=normalized_ref_type,
        failures=failures,
    )
    _validate_ci_activation_key_semantics(
        artifact_context,
        context_label=context_label,
        failures=failures,
    )
    _validate_ci_url_semantics(
        artifact_context,
        context_label=context_label,
        failures=failures,
    )


def _validate_ci_context_binding(
    *,
    runtime_context: Mapping[str, str],
    artifact_context: object,
    context_label: str,
    failures: List[str],
    required_identity_keys: Tuple[str, ...] = STRICT_CONTEXT_REQUIRED_IDENTITY_KEYS,
    required_binding_keys: Tuple[str, ...] = STRICT_CONTEXT_REQUIRED_BINDING_KEYS,
    optional_binding_keys: Tuple[str, ...] = STRICT_CONTEXT_OPTIONAL_BINDING_KEYS,
    include_protected_ref: bool = True,
) -> None:
    if not isinstance(artifact_context, dict):
        failures.append(
            "{0} must be present when --require-ci-context-match is enabled".format(context_label)
        )
        return
    _validate_runtime_ref_semantics(runtime_context, failures)
    _validate_artifact_ref_semantics(
        artifact_context,
        context_label=context_label,
        failures=failures,
    )
    for key in required_identity_keys:
        expected = _validate_runtime_context_key_value(runtime_context, key, failures)
        if not expected:
            continue
        actual = _validate_artifact_context_key_value(
            artifact_context,
            context_label=context_label,
            key=key,
            failures=failures,
        )
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
    for key in required_binding_keys:
        expected = _validate_runtime_context_key_value(runtime_context, key, failures)
        if not expected:
            continue
        actual = _validate_artifact_context_key_value(
            artifact_context,
            context_label=context_label,
            key=key,
            failures=failures,
        )
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
    for key in optional_binding_keys:
        expected = _validate_runtime_context_key_value(runtime_context, key, failures)
        if not expected:
            continue
        actual = _validate_artifact_context_key_value(
            artifact_context,
            context_label=context_label,
            key=key,
            failures=failures,
        )
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
    if include_protected_ref:
        expected_ref_protected = _validate_runtime_context_key_value(
            runtime_context,
            STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY,
            failures,
        )
        actual_ref_protected = _validate_artifact_context_key_value(
            artifact_context,
            context_label=context_label,
            key=STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY,
            failures=failures,
        )
        if expected_ref_protected and not actual_ref_protected:
            failures.append("{0} missing required key: {1}".format(context_label, STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY))
        elif expected_ref_protected and actual_ref_protected != expected_ref_protected:
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


def _validate_evidence_repository_binding(
    evidence_payload: Mapping[str, object],
    failures: List[str],
    *,
    require_ci_context_match: bool,
    runtime_context: Optional[Mapping[str, str]],
) -> None:
    raw_repository = evidence_payload.get("repository")
    repository_text = _normalize_text(raw_repository)
    if not repository_text:
        return
    evidence_repository = _normalize_repository_slug(repository_text)
    if not evidence_repository:
        failures.append("promotion_evidence.repository must be a valid owner/repo slug")
        return

    evidence_context = evidence_payload.get("github_context")
    if not isinstance(evidence_context, dict):
        failures.append("promotion_evidence.github_context must be present when promotion_evidence.repository is set")
        return

    evidence_context_repository = _normalize_repository_slug(evidence_context.get("GITHUB_REPOSITORY"))
    if not evidence_context_repository:
        failures.append("promotion_evidence.github_context missing required key: GITHUB_REPOSITORY")
    elif evidence_context_repository != evidence_repository:
        failures.append(
            "promotion_evidence.repository mismatch with promotion_evidence.github_context.GITHUB_REPOSITORY: expected {0}, got {1}".format(
                evidence_repository,
                evidence_context_repository,
            )
        )

    if require_ci_context_match and runtime_context:
        runtime_repository = _normalize_repository_slug(runtime_context.get("GITHUB_REPOSITORY"))
        if runtime_repository and runtime_repository != evidence_repository:
            failures.append(
                "promotion_evidence.repository mismatch with runtime GITHUB_REPOSITORY: expected {0}, got {1}".format(
                    evidence_repository,
                    runtime_repository,
                )
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
    _validate_runtime_ref_semantics(runtime_context, failures)
    required_keys = (
        STRICT_CONTEXT_REQUIRED_IDENTITY_KEYS
        + STRICT_CONTEXT_REQUIRED_BINDING_KEYS
        + (STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY,)
    )
    for key in required_keys:
        normalized_value = _validate_runtime_context_key_value(runtime_context, key, failures)
        if not normalized_value:
            failures.append("missing runtime GitHub context key for CI match: {0}".format(key))


def _validate_artifact_context_completeness(
    artifact_context: Mapping[str, object],
    failures: List[str],
    *,
    context_label: str,
) -> None:
    _validate_artifact_ref_semantics(
        artifact_context,
        context_label=context_label,
        failures=failures,
    )
    required_keys = (
        STRICT_CONTEXT_REQUIRED_IDENTITY_KEYS
        + STRICT_CONTEXT_REQUIRED_BINDING_KEYS
        + (STRICT_CONTEXT_OPTIONAL_PROTECTED_REF_KEY,)
    )
    for key in required_keys:
        normalized_value = _validate_artifact_context_key_value(
            artifact_context,
            context_label=context_label,
            key=key,
            failures=failures,
        )
        if not normalized_value:
            failures.append("{0} missing required key: {1}".format(context_label, key))


def _rotation_report_to_github_context(rotation_report_payload: Mapping[str, object]) -> Dict[str, object]:
    context = {}
    for report_key, github_key in ROTATION_REPORT_TO_GITHUB_CONTEXT_KEYS:
        if report_key in rotation_report_payload:
            context[github_key] = rotation_report_payload.get(report_key)
    return context


def _validate_artifact_context_consistency(
    *,
    release_dir: Path,
    evidence_path: Path,
    rotation_path: Path,
    run_receipt_path: Path,
    failures: List[str],
) -> None:
    evidence_payload = _load_json_object(evidence_path, "promotion evidence")
    evidence_context = evidence_payload.get("github_context")
    if not isinstance(evidence_context, dict):
        failures.append(
            "promotion_evidence.github_context must be present when --require-artifact-context-consistency is enabled"
        )
        return
    _validate_artifact_context_completeness(
        evidence_context,
        failures,
        context_label="promotion_evidence.github_context",
    )

    approval_payload = _load_json_object(release_dir / "release_approval.json", "release approval")
    receipt_payload = _load_json_object(release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME, "release receipt")
    rotation_payload = _load_json_object(rotation_path, "rotation rehearsal report")

    comparison_contexts = (
        ("release_approval.github_context", approval_payload.get("github_context")),
        ("release_receipt.github_context", receipt_payload.get("github_context")),
        (
            "release_receipt.release_approval_github_context",
            receipt_payload.get("release_approval_github_context"),
        ),
        (
            "rotation_rehearsal_report.github_context_projection",
            _rotation_report_to_github_context(rotation_payload),
        ),
    )

    for label, context in comparison_contexts:
        if not isinstance(context, dict):
            failures.append("{0} must be present when --require-artifact-context-consistency is enabled".format(label))
            continue
        if label == "rotation_rehearsal_report.github_context_projection":
            _validate_ci_context_binding(
                runtime_context=evidence_context,
                artifact_context=context,
                context_label=label,
                failures=failures,
                required_identity_keys=STRICT_CONTEXT_REQUIRED_IDENTITY_KEYS,
                required_binding_keys=STRICT_CONTEXT_REQUIRED_BINDING_KEYS,
                optional_binding_keys=STRICT_CONTEXT_OPTIONAL_BINDING_KEYS,
                include_protected_ref=True,
            )
        else:
            _validate_ci_context_binding(
                runtime_context=evidence_context,
                artifact_context=context,
                context_label=label,
                failures=failures,
            )

    if not run_receipt_path.exists():
        return
    run_receipt_payload = _load_json_object(run_receipt_path, "promotion run receipt")
    run_receipt_context = run_receipt_payload.get("github_context")
    if not isinstance(run_receipt_context, dict):
        failures.append(
            "promotion_run_receipt.github_context must be present when --require-artifact-context-consistency is enabled"
        )
        return
    _validate_ci_context_binding(
        runtime_context=evidence_context,
        artifact_context=run_receipt_context,
        context_label="promotion_run_receipt.github_context",
        failures=failures,
    )


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
    require_artifact_context_consistency: bool = False,
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
    _validate_evidence_repository_binding(
        evidence_payload,
        failures,
        require_ci_context_match=require_ci_context_match,
        runtime_context=runtime_context,
    )
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
    if require_artifact_context_consistency:
        _validate_artifact_context_consistency(
            release_dir=release_dir,
            evidence_path=evidence_path,
            rotation_path=rotation_path,
            run_receipt_path=run_receipt_path,
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
        "artifact_context_consistency_required": bool(require_artifact_context_consistency),
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
