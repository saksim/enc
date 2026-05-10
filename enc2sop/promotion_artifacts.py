#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Promotion artifact integrity checks for CI rollout evidence bundles."""

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
DEFAULT_REPORT_FILENAME = "promotion_artifact_audit_report.json"
DEFAULT_RUN_RECEIPT_FILENAME = "promotion_run_receipt.json"


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


def _validate_release_artifacts(release_dir: Path, failures: List[str]) -> None:
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
        if not _is_hex_64(signature.get("digest_hex")):
            failures.append("release_approval.signature.digest_hex must be a 64-char lowercase hex digest")
        key_id = str(signature.get("key_id") or "").strip()
        if not key_id:
            failures.append("release_approval.signature.key_id is required")

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
    if not bool(receipt_payload.get("release_approval_verified")):
        failures.append("release_receipt.release_approval_verified must be true")
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
    failures: List[str],
) -> None:
    report_payload = _load_json_object(report_path, "promotion audit report")
    inputs = report_payload.get("inputs")
    if not isinstance(inputs, dict):
        failures.append("promotion_audit_report.inputs is required for evidence/workflow digest binding")
        return

    expected_evidence_path = str(evidence_path)
    actual_evidence_path = str(inputs.get("evidence_file") or "").strip()
    if actual_evidence_path != expected_evidence_path:
        failures.append(
            "promotion_audit_report.inputs.evidence_file mismatch: expected {0}, got {1}".format(
                expected_evidence_path,
                actual_evidence_path or "<empty>",
            )
        )

    expected_evidence_sha256 = encryption_helper._sha256_file(evidence_path)
    actual_evidence_sha256 = str(inputs.get("evidence_sha256") or "").strip().lower()
    if not _is_hex_64(actual_evidence_sha256):
        failures.append("promotion_audit_report.inputs.evidence_sha256 must be a 64-char lowercase hex digest")
    elif actual_evidence_sha256 != expected_evidence_sha256:
        failures.append(
            "promotion_audit_report.inputs.evidence_sha256 mismatch: expected {0}, got {1}".format(
                expected_evidence_sha256,
                actual_evidence_sha256,
            )
        )


def _validate_rotation_report(
    rotation_report_path: Path,
    failures: List[str],
    require_rotation_pass: bool,
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
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_WORKFLOW",
        "GITHUB_EVENT_NAME",
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


def _validate_evidence_github_context(
    evidence_payload: Mapping[str, object],
    failures: List[str],
    require_ci_context_match: bool,
) -> None:
    if not require_ci_context_match:
        return
    report_context = _github_context_snapshot()
    if not report_context:
        failures.append(
            "CI context match is required but no GitHub runtime environment context is available"
        )
        return
    evidence_context = evidence_payload.get("github_context")
    if not isinstance(evidence_context, dict):
        failures.append(
            "promotion_evidence.github_context must be present when --require-ci-context-match is enabled"
        )
        return
    for key in ("GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_RUN_ID"):
        expected = _normalize_text(report_context.get(key))
        actual = _normalize_text(evidence_context.get(key))
        if not expected:
            failures.append("missing runtime GitHub context key for CI match: {0}".format(key))
            continue
        if not actual:
            failures.append("promotion_evidence.github_context missing required key: {0}".format(key))
            continue
        if actual != expected:
            failures.append(
                "promotion_evidence.github_context.{0} mismatch: expected {1}, got {2}".format(
                    key,
                    expected,
                    actual,
                )
            )
    expected_sha = _normalize_text(report_context.get("GITHUB_SHA"))
    actual_sha = _normalize_text(evidence_context.get("GITHUB_SHA"))
    if expected_sha and actual_sha and actual_sha != expected_sha:
        failures.append(
            "promotion_evidence.github_context.GITHUB_SHA mismatch: expected {0}, got {1}".format(
                expected_sha,
                actual_sha,
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


def _write_promotion_run_receipt(
    *,
    run_receipt_path: Path,
    report_path: Path,
    report: Dict[str, object],
    release_dir: Path,
    evidence_path: Path,
    promotion_report_path: Path,
    rotation_path: Path,
) -> Path:
    artifact_rows = _artifact_digest_rows(
        [
            ("release_bundle", release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME),
            ("release_approval", release_dir / "release_approval.json"),
            ("release_receipt", release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME),
            ("promotion_evidence", evidence_path),
            ("promotion_audit_report", promotion_report_path),
            ("rotation_rehearsal_report", rotation_path),
            ("promotion_artifact_audit_report", report_path),
        ]
    )
    receipt = {
        "schema": PROMOTION_RUN_RECEIPT_SCHEMA,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "passed": bool(report.get("passed")),
        "rotation_pass_required": bool(report.get("rotation_pass_required")),
        "promotion_artifact_audit_report_file": str(report_path),
        "github_context": _github_context_snapshot(),
        "artifacts": artifact_rows,
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
    report_file: Optional[str] = None,
    run_receipt_file: Optional[str] = None,
    require_rotation_pass: bool = False,
    require_ci_context_match: bool = False,
    repo_root: Optional[Path] = None,
) -> Tuple[Path, Dict[str, object]]:
    root = repo_root.resolve() if repo_root is not None else Path.cwd().resolve()
    release_dir = _resolve_path(dist_dir, repo_root=root)
    evidence_path = _resolve_path(promotion_evidence_file, repo_root=root)
    promotion_report_path = _resolve_path(promotion_report_file, repo_root=root)
    rotation_path = _resolve_path(rotation_report_file, repo_root=root)

    failures = []  # type: List[str]
    _validate_release_artifacts(release_dir, failures)
    _validate_promotion_evidence(evidence_path, failures)
    evidence_payload = _load_json_object(evidence_path, "promotion evidence")
    _validate_evidence_github_context(
        evidence_payload,
        failures,
        require_ci_context_match=require_ci_context_match,
    )
    _validate_promotion_report(promotion_report_path, failures)
    _validate_promotion_report_input_binding(
        report_path=promotion_report_path,
        evidence_path=evidence_path,
        failures=failures,
    )
    _validate_rotation_report(rotation_path, failures, require_rotation_pass=require_rotation_pass)

    report = {
        "schema": PROMOTION_ARTIFACT_AUDIT_SCHEMA,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "release_dir": str(release_dir),
        "promotion_evidence_file": str(evidence_path),
        "promotion_report_file": str(promotion_report_path),
        "rotation_report_file": str(rotation_path),
        "rotation_pass_required": bool(require_rotation_pass),
        "ci_context_match_required": bool(require_ci_context_match),
        "passed": not failures,
        "summary": {
            "total_failures": len(failures),
        },
        "failures": failures,
    }

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
    )
    return report_path, report
