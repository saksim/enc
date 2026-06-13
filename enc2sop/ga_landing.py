#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""GA landing gate checks for non-OCR release evidence bundles."""

from __future__ import annotations

import hashlib
import json
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
from enc2sop import promotion_bundle


GA_LANDING_GATE_SCHEMA = "enc2sop-non-ocr-ga-landing-gate/v1"
REQUIRED_BUNDLE_ENTRIES = (
    "release/release_bundle.json",
    "release/release_approval.json",
    "release/release_receipt.json",
    "ops/promotion_evidence.json",
    "ops/promotion_audit_report.json",
    "ops/rotation_rehearsal_report.json",
    "ops/promotion_artifact_audit_report.json",
    "ops/promotion_run_receipt.json",
    "policy/promotion_rollout_policy.json",
    "workflow/release_promotion.yml",
    "bundle_manifest.json",
)


class GALandingGateError(RuntimeError):
    """Raised when GA landing evidence cannot be loaded."""


def _utc_now_iso8601_seconds() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        digest = hashlib.sha256()
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json_file(path: Path, label: str) -> Dict[str, object]:
    if not path.exists():
        raise FileNotFoundError("{0} not found: {1}".format(label, path))
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise GALandingGateError("{0} must be a JSON object: {1}".format(label, path))
    return payload


def _load_json_bytes(payload: bytes, label: str) -> Dict[str, object]:
    parsed = json.loads(payload.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise GALandingGateError("{0} must be a JSON object".format(label))
    return parsed


def _append_if_false(failures: List[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def _non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _normalize_path(value: Optional[str], *, repo_root: Path) -> Optional[Path]:
    if not value:
        return None
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return candidate.resolve()


def _bundle_path_from_smoke(smoke_report: Mapping[str, object]) -> Optional[str]:
    release_governance = smoke_report.get("release_governance")
    if not isinstance(release_governance, dict):
        return None
    value = release_governance.get("promotion_artifact_bundle")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _bundle_sha_from_smoke(smoke_report: Mapping[str, object]) -> Optional[str]:
    release_governance = smoke_report.get("release_governance")
    if not isinstance(release_governance, dict):
        return None
    value = release_governance.get("promotion_artifact_bundle_sha256")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return None


def _validate_smoke_report(smoke_report: Mapping[str, object], failures: List[str]) -> Dict[str, bool]:
    summary = smoke_report.get("summary") if isinstance(smoke_report.get("summary"), dict) else {}
    release_governance = smoke_report.get("release_governance") if isinstance(smoke_report.get("release_governance"), dict) else {}
    reverse_cost = release_governance.get("reverse_cost_check") if isinstance(release_governance.get("reverse_cost_check"), dict) else {}
    license_e2e = smoke_report.get("license_file_e2e") if isinstance(smoke_report.get("license_file_e2e"), dict) else {}

    flags = {
        "smoke_passed": bool(smoke_report.get("passed")),
        "release_governance_passed": bool(release_governance.get("passed")),
        "license_file_e2e_passed": bool(license_e2e.get("passed")) or bool(summary.get("license_file_e2e_passed")),
        "reverse_cost_check_passed": bool(release_governance.get("reverse_cost_check_passed")) or bool(summary.get("reverse_cost_check_passed")),
        "reverse_cost_report_passed": bool(reverse_cost.get("passed")),
    }
    _append_if_false(failures, flags["smoke_passed"], "smoke report passed must be true")
    _append_if_false(failures, flags["release_governance_passed"], "release_governance.passed must be true")
    _append_if_false(failures, flags["license_file_e2e_passed"], "license_file_e2e_passed must be true")
    _append_if_false(failures, flags["reverse_cost_check_passed"], "reverse_cost_check_passed must be true")
    _append_if_false(failures, flags["reverse_cost_report_passed"], "reverse_cost_check.passed must be true")
    issues = reverse_cost.get("issues")
    if issues not in ([], None):
        failures.append("reverse_cost_check.issues must be empty")
    return flags


def _zip_entries(output: zipfile.ZipFile) -> Dict[str, bytes]:
    entries: Dict[str, bytes] = {}
    for name in output.namelist():
        if name in entries:
            raise GALandingGateError("duplicate zip entry: {0}".format(name))
        entries[name] = output.read(name)
    return entries


def _validate_manifest(entries: Mapping[str, bytes], failures: List[str]) -> Tuple[Dict[str, object], Dict[str, Dict[str, object]]]:
    manifest = _load_json_bytes(entries["bundle_manifest.json"], "bundle manifest")
    if manifest.get("schema") != promotion_bundle.PROMOTION_ARTIFACT_BUNDLE_SCHEMA:
        failures.append(
            "bundle_manifest schema mismatch: expected {0}, got {1}".format(
                promotion_bundle.PROMOTION_ARTIFACT_BUNDLE_SCHEMA,
                manifest.get("schema"),
            )
        )
    if not _non_empty_string(manifest.get("generated_at_utc")):
        failures.append("bundle_manifest.generated_at_utc is required")
    files = manifest.get("files")
    if not isinstance(files, list):
        failures.append("bundle_manifest.files must be a list")
        return manifest, {}

    rows: Dict[str, Dict[str, object]] = {}
    for index, row in enumerate(files):
        if not isinstance(row, dict):
            failures.append("bundle_manifest.files[{0}] must be an object".format(index))
            continue
        archive_path = str(row.get("archive_path") or "").strip()
        name = str(row.get("name") or "").strip()
        digest = str(row.get("sha256") or "").strip().lower()
        if not archive_path:
            failures.append("bundle_manifest.files[{0}].archive_path is required".format(index))
            continue
        if archive_path in rows:
            failures.append("bundle_manifest duplicate archive_path: {0}".format(archive_path))
            continue
        rows[archive_path] = row
        if not name:
            failures.append("bundle_manifest entry name is required for {0}".format(archive_path))
        if not _non_empty_string(row.get("source_path")):
            failures.append("bundle_manifest entry source_path is required for {0}".format(archive_path))
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            failures.append("bundle_manifest entry sha256 must be 64-char lowercase hex: {0}".format(archive_path))
            continue
        if archive_path not in entries:
            failures.append("bundle_manifest entry missing from zip: {0}".format(archive_path))
            continue
        actual = _sha256_bytes(entries[archive_path])
        if actual != digest:
            failures.append("bundle_manifest sha256 mismatch for {0}".format(archive_path))

    declared_count = manifest.get("file_count")
    if not isinstance(declared_count, int) or isinstance(declared_count, bool):
        failures.append("bundle_manifest.file_count must be an integer")
    elif declared_count != len(files):
        failures.append("bundle_manifest.file_count must equal len(files)")

    declared_paths = set(rows)
    for required in REQUIRED_BUNDLE_ENTRIES:
        if required != "bundle_manifest.json" and required not in declared_paths:
            failures.append("bundle_manifest missing required archive_path: {0}".format(required))
    for archive_path in entries:
        if archive_path != "bundle_manifest.json" and archive_path not in declared_paths:
            failures.append("zip entry is not declared in bundle_manifest: {0}".format(archive_path))
    return manifest, rows


def _artifact_sha256_manifest(rows: Mapping[str, Mapping[str, object]]) -> List[Dict[str, object]]:
    sha_rows: List[Dict[str, object]] = []
    for archive_path in sorted(rows):
        row = rows[archive_path]
        sha_rows.append(
            {
                "archive_path": archive_path,
                "name": str(row.get("name") or ""),
                "source_path": str(row.get("source_path") or ""),
                "sha256": str(row.get("sha256") or "").lower(),
            }
        )
    return sha_rows


def _validate_json_artifacts(entries: Mapping[str, bytes], failures: List[str], *, require_rotation_pass: bool) -> Dict[str, bool]:
    release_bundle_payload = _load_json_bytes(entries["release/release_bundle.json"], "release bundle")
    release_approval_payload = _load_json_bytes(entries["release/release_approval.json"], "release approval")
    release_receipt_payload = _load_json_bytes(entries["release/release_receipt.json"], "release receipt")
    promotion_evidence_payload = _load_json_bytes(entries["ops/promotion_evidence.json"], "promotion evidence")
    promotion_audit_payload = _load_json_bytes(entries["ops/promotion_audit_report.json"], "promotion audit report")
    rotation_payload = _load_json_bytes(entries["ops/rotation_rehearsal_report.json"], "rotation rehearsal report")
    artifact_audit_payload = _load_json_bytes(entries["ops/promotion_artifact_audit_report.json"], "promotion artifact audit report")
    run_receipt_payload = _load_json_bytes(entries["ops/promotion_run_receipt.json"], "promotion run receipt")

    if release_bundle_payload.get("schema") != encryption_helper.RELEASE_BUNDLE_SCHEMA:
        failures.append("release_bundle schema mismatch")
    if release_approval_payload.get("schema") != encryption_helper.RELEASE_APPROVAL_SCHEMA:
        failures.append("release_approval schema mismatch")
    if release_receipt_payload.get("schema") != encryption_helper.RELEASE_RECEIPT_SCHEMA:
        failures.append("release_receipt schema mismatch")
    try:
        promotion_audit.normalize_promotion_evidence_payload(dict(promotion_evidence_payload))
    except Exception as exc:
        failures.append("promotion_evidence schema validation failed: {0}".format(exc))
    if promotion_audit_payload.get("schema") != promotion_audit.PROMOTION_AUDIT_REPORT_SCHEMA:
        failures.append("promotion_audit_report schema mismatch")
    if artifact_audit_payload.get("schema") != promotion_artifacts.PROMOTION_ARTIFACT_AUDIT_SCHEMA:
        failures.append("promotion_artifact_audit_report schema mismatch")
    if run_receipt_payload.get("schema") != promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA:
        failures.append("promotion_run_receipt schema mismatch")
    if rotation_payload.get("schema") != promotion_artifacts.ROTATION_REHEARSAL_SCHEMA:
        failures.append("rotation_rehearsal_report schema mismatch")
    if release_bundle_payload.get("layout_version") != encryption_helper.RELEASE_LAYOUT_VERSION:
        failures.append("release_bundle layout_version mismatch")

    bundle_contents = release_bundle_payload.get("bundle_contents")
    license_file = bundle_contents.get("license_file") if isinstance(bundle_contents, dict) else None
    if isinstance(license_file, dict):
        if license_file.get("externalized") is not True:
            failures.append("release_bundle license_file.externalized must be true")
        if license_file.get("bundled") is True:
            failures.append("release_bundle license_file.bundled must be false")
    else:
        failures.append("release_bundle.bundle_contents.license_file must describe external license delivery")

    flags = {
        "promotion_audit_passed": bool(promotion_audit_payload.get("passed")),
        "promotion_artifact_audit_passed": bool(artifact_audit_payload.get("passed")),
        "promotion_run_receipt_passed": bool(run_receipt_payload.get("passed")),
        "rotation_rehearsal_passed": rotation_payload.get("status") == "passed" and rotation_payload.get("old_key_rejected") is True,
    }
    _append_if_false(failures, flags["promotion_audit_passed"], "promotion_audit_report.passed must be true")
    _append_if_false(failures, flags["promotion_artifact_audit_passed"], "promotion_artifact_audit_report.passed must be true")
    _append_if_false(failures, flags["promotion_run_receipt_passed"], "promotion_run_receipt.passed must be true")
    if require_rotation_pass:
        _append_if_false(failures, flags["rotation_rehearsal_passed"], "rotation rehearsal must pass with old_key_rejected=true")
    flags["json_schema_version_audit_passed"] = not any(
        entry.get("schema") != expected_schema
        for entry, expected_schema in (
            (release_bundle_payload, encryption_helper.RELEASE_BUNDLE_SCHEMA),
            (release_approval_payload, encryption_helper.RELEASE_APPROVAL_SCHEMA),
            (release_receipt_payload, encryption_helper.RELEASE_RECEIPT_SCHEMA),
            (promotion_audit_payload, promotion_audit.PROMOTION_AUDIT_REPORT_SCHEMA),
            (artifact_audit_payload, promotion_artifacts.PROMOTION_ARTIFACT_AUDIT_SCHEMA),
            (run_receipt_payload, promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA),
            (rotation_payload, promotion_artifacts.ROTATION_REHEARSAL_SCHEMA),
        )
    ) and release_bundle_payload.get("layout_version") == encryption_helper.RELEASE_LAYOUT_VERSION
    return flags


def run_ga_landing_gate(
    *,
    smoke_report_file: Optional[str] = None,
    promotion_artifact_bundle_file: Optional[str] = None,
    expected_bundle_sha256: Optional[str] = None,
    report_file: Optional[str] = None,
    require_rotation_pass: bool = True,
    repo_root: Optional[Path] = None,
) -> Tuple[Optional[Path], Dict[str, object]]:
    root = repo_root.resolve() if repo_root is not None else Path.cwd().resolve()
    failures: List[str] = []
    smoke_report: Optional[Dict[str, object]] = None
    smoke_flags: Dict[str, bool] = {}

    smoke_path = _normalize_path(smoke_report_file, repo_root=root)
    if smoke_path is not None:
        smoke_report = _load_json_file(smoke_path, "non-OCR GA smoke report")
        smoke_flags = _validate_smoke_report(smoke_report, failures)

    bundle_value = promotion_artifact_bundle_file
    if not bundle_value and smoke_report is not None:
        bundle_value = _bundle_path_from_smoke(smoke_report)
    bundle_path = _normalize_path(bundle_value, repo_root=root)
    if bundle_path is None:
        raise GALandingGateError("promotion artifact bundle path is required")
    if not bundle_path.exists():
        raise FileNotFoundError("promotion artifact bundle not found: {0}".format(bundle_path))

    expected_sha = (expected_bundle_sha256 or "").strip().lower()
    if not expected_sha and smoke_report is not None:
        expected_sha = _bundle_sha_from_smoke(smoke_report) or ""
    bundle_sha = _sha256_file(bundle_path)
    if expected_sha and expected_sha != bundle_sha:
        failures.append("promotion_artifact_bundle sha256 mismatch")

    with zipfile.ZipFile(bundle_path, "r") as zipped:
        entries = _zip_entries(zipped)

    for required in REQUIRED_BUNDLE_ENTRIES:
        if required not in entries:
            failures.append("promotion_artifact_bundle missing required entry: {0}".format(required))

    manifest: Dict[str, object] = {}
    manifest_rows: Dict[str, Dict[str, object]] = {}
    artifact_flags: Dict[str, bool] = {}
    if "bundle_manifest.json" in entries:
        manifest, manifest_rows = _validate_manifest(entries, failures)
    if all(path in entries for path in REQUIRED_BUNDLE_ENTRIES):
        artifact_flags = _validate_json_artifacts(entries, failures, require_rotation_pass=require_rotation_pass)

    report = {
        "schema": GA_LANDING_GATE_SCHEMA,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "passed": not failures,
        "smoke_report_file": str(smoke_path) if smoke_path is not None else None,
        "promotion_artifact_bundle_file": str(bundle_path),
        "promotion_artifact_bundle_sha256": bundle_sha,
        "require_rotation_pass": bool(require_rotation_pass),
        "summary": {
            "total_failures": len(failures),
            "bundle_manifest_present": "bundle_manifest.json" in entries,
            "bundle_manifest_schema": manifest.get("schema") if manifest else None,
            "bundle_file_count": manifest.get("file_count") if manifest else None,
            "license_file_e2e_passed": bool(smoke_flags.get("license_file_e2e_passed")),
            "reverse_cost_check_passed": bool(smoke_flags.get("reverse_cost_check_passed")),
            "promotion_audit_passed": bool(artifact_flags.get("promotion_audit_passed")),
            "promotion_artifact_audit_passed": bool(artifact_flags.get("promotion_artifact_audit_passed")),
            "promotion_run_receipt_passed": bool(artifact_flags.get("promotion_run_receipt_passed")),
            "rotation_rehearsal_passed": bool(artifact_flags.get("rotation_rehearsal_passed")),
            "json_schema_version_audit_passed": bool(artifact_flags.get("json_schema_version_audit_passed")),
        },
        "required_bundle_entries": list(REQUIRED_BUNDLE_ENTRIES),
        "artifact_manifest": {
            "zip_entry_count": len(entries),
            "declared_file_count": len(manifest_rows),
            "sha256": _artifact_sha256_manifest(manifest_rows),
        },
        "failures": failures,
    }

    output_path = _normalize_path(report_file, repo_root=root)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_path, report
