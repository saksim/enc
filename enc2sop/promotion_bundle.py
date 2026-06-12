#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Promotion artifact bundle creation for CI handoff archives."""

import json
import stat
import zipfile
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Tuple

import encryption_helper
from enc2sop import promotion_artifacts
from enc2sop import promotion_audit

PROMOTION_ARTIFACT_BUNDLE_SCHEMA = "enc2sop-promotion-artifact-bundle/v1"
DEFAULT_BUNDLE_FILENAME = "promotion_artifact_bundle.zip"
_ZIPINFO_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class PromotionArtifactBundleError(RuntimeError):
    """Raised when promotion artifact bundle assembly fails."""


def _utc_now_iso8601_seconds() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _resolve_path(value: Optional[str], *, repo_root: Path, fallback: Optional[Path] = None) -> Path:
    if value:
        candidate = Path(value).expanduser()
    elif fallback is not None:
        candidate = fallback
    else:
        raise PromotionArtifactBundleError("path resolution requires value or fallback")
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return candidate.resolve()


def _load_json_object(path: Path, label: str) -> Dict[str, object]:
    if not path.exists():
        raise FileNotFoundError("{0} not found: {1}".format(label, path))
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise PromotionArtifactBundleError("{0} must be a JSON object: {1}".format(label, path))
    return payload


def _ensure_file_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError("{0} not found: {1}".format(label, path))
    if not path.is_file():
        raise PromotionArtifactBundleError("{0} must be a file: {1}".format(label, path))


def _zip_write_bytes(output: zipfile.ZipFile, archive_path: str, payload: bytes) -> None:
    info = zipfile.ZipInfo(filename=archive_path, date_time=_ZIPINFO_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    output.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _bundle_rows(
    *,
    release_dir: Path,
    evidence_path: Path,
    promotion_report_path: Path,
    rotation_path: Path,
    artifact_audit_path: Path,
    run_receipt_path: Path,
    policy_path: Optional[Path],
    workflow_path: Optional[Path],
) -> List[Tuple[str, str, Path]]:
    rows = [
        ("release_bundle", "release/release_bundle.json", release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME),
        ("release_approval", "release/release_approval.json", release_dir / "release_approval.json"),
        ("release_receipt", "release/release_receipt.json", release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME),
        ("promotion_evidence", "ops/promotion_evidence.json", evidence_path),
        ("promotion_audit_report", "ops/promotion_audit_report.json", promotion_report_path),
        ("rotation_rehearsal_report", "ops/rotation_rehearsal_report.json", rotation_path),
        ("promotion_artifact_audit_report", "ops/promotion_artifact_audit_report.json", artifact_audit_path),
        ("promotion_run_receipt", "ops/promotion_run_receipt.json", run_receipt_path),
    ]
    if policy_path is not None:
        rows.append(("promotion_policy", "policy/promotion_rollout_policy.json", policy_path))
    if workflow_path is not None:
        rows.append(("promotion_workflow", "workflow/release_promotion.yml", workflow_path))
    return rows


def _validate_required_artifacts(
    *,
    artifact_audit_path: Path,
    run_receipt_path: Path,
) -> None:
    audit_payload = _load_json_object(artifact_audit_path, "promotion artifact audit report")
    if audit_payload.get("schema") != promotion_artifacts.PROMOTION_ARTIFACT_AUDIT_SCHEMA:
        raise PromotionArtifactBundleError(
            "promotion artifact audit report schema mismatch: expected {0}, got {1}".format(
                promotion_artifacts.PROMOTION_ARTIFACT_AUDIT_SCHEMA,
                audit_payload.get("schema"),
            )
        )
    if not bool(audit_payload.get("passed")):
        raise PromotionArtifactBundleError(
            "promotion artifact audit report must be passed=true before bundling"
        )

    run_receipt_payload = _load_json_object(run_receipt_path, "promotion run receipt")
    if run_receipt_payload.get("schema") != promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA:
        raise PromotionArtifactBundleError(
            "promotion run receipt schema mismatch: expected {0}, got {1}".format(
                promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA,
                run_receipt_payload.get("schema"),
            )
        )
    if not bool(run_receipt_payload.get("passed")):
        raise PromotionArtifactBundleError(
            "promotion run receipt must be passed=true before bundling"
        )


def create_promotion_artifact_bundle(
    *,
    dist_dir: str,
    promotion_evidence_file: str,
    promotion_report_file: str,
    rotation_report_file: str,
    promotion_artifact_audit_report_file: Optional[str] = None,
    promotion_run_receipt_file: Optional[str] = None,
    promotion_policy_file: Optional[str] = None,
    promotion_workflow_file: Optional[str] = None,
    bundle_file: Optional[str] = None,
    repo_root: Optional[Path] = None,
) -> Tuple[Path, Dict[str, object]]:
    root = repo_root.resolve() if repo_root is not None else Path.cwd().resolve()
    release_dir = _resolve_path(dist_dir, repo_root=root)
    evidence_path = _resolve_path(promotion_evidence_file, repo_root=root)
    promotion_report_path = _resolve_path(promotion_report_file, repo_root=root)
    rotation_path = _resolve_path(rotation_report_file, repo_root=root)
    artifact_audit_path = _resolve_path(
        promotion_artifact_audit_report_file,
        repo_root=root,
        fallback=promotion_report_path.parent / promotion_artifacts.DEFAULT_REPORT_FILENAME,
    )
    run_receipt_path = _resolve_path(
        promotion_run_receipt_file,
        repo_root=root,
        fallback=promotion_report_path.parent / promotion_artifacts.DEFAULT_RUN_RECEIPT_FILENAME,
    )
    policy_path = _resolve_path(promotion_policy_file, repo_root=root) if promotion_policy_file else None
    workflow_path = _resolve_path(promotion_workflow_file, repo_root=root) if promotion_workflow_file else None
    bundle_path = _resolve_path(
        bundle_file,
        repo_root=root,
        fallback=promotion_report_path.parent / DEFAULT_BUNDLE_FILENAME,
    )

    _validate_required_artifacts(
        artifact_audit_path=artifact_audit_path,
        run_receipt_path=run_receipt_path,
    )

    # Validate core report/evidence schemas before creating immutable handoff archive.
    promotion_audit.normalize_promotion_evidence_payload(
        _load_json_object(evidence_path, "promotion evidence"),
    )
    normalized_promotion_report = promotion_audit.normalize_promotion_audit_report_payload(
        _load_json_object(promotion_report_path, "promotion audit report"),
    )
    if not bool(normalized_promotion_report.get("passed")):
        raise PromotionArtifactBundleError(
            "promotion audit report must be passed=true before bundling"
        )

    rows = _bundle_rows(
        release_dir=release_dir,
        evidence_path=evidence_path,
        promotion_report_path=promotion_report_path,
        rotation_path=rotation_path,
        artifact_audit_path=artifact_audit_path,
        run_receipt_path=run_receipt_path,
        policy_path=policy_path,
        workflow_path=workflow_path,
    )
    for name, _, file_path in rows:
        _ensure_file_exists(file_path, name)

    manifest_entries = []
    for name, archive_path, file_path in rows:
        manifest_entries.append(
            {
                "name": name,
                "archive_path": archive_path,
                "source_path": str(file_path),
                "sha256": encryption_helper._sha256_file(file_path),
            }
        )

    manifest = {
        "schema": PROMOTION_ARTIFACT_BUNDLE_SCHEMA,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "file_count": len(manifest_entries),
        "files": manifest_entries,
    }
    manifest_bytes = json.dumps(
        manifest,
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")

    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle_path, mode="w") as output:
        for _, archive_path, file_path in sorted(rows, key=lambda item: item[1]):
            _zip_write_bytes(output, archive_path, file_path.read_bytes())
        _zip_write_bytes(output, "bundle_manifest.json", manifest_bytes)

    manifest["bundle_path"] = str(bundle_path)
    manifest["bundle_sha256"] = encryption_helper._sha256_file(bundle_path)
    return bundle_path, manifest
