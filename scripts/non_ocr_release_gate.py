#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Non-OCR Mainline Beta / GA release gate.

This gate is intentionally scoped to the published non-OCR docs:

* docs/latest/non_ocr_code_protection_launch_strategy.md
* docs/latest/non_ocr_release_reverse_cost_checklist.md
* docs/releases/v0.1.0-mainline-beta.1.md

It verifies production-default safety posture for the non-OCR code-protection
line only. It does not add OCR, QR, cross-media, or remote-KMS service checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import encryption_helper
import soenc_config
from enc2sop import promotion_bundle
from enc2sop.protect.dist_check import run_dist_no_source_leak_check


GATE_SCHEMA = "enc2sop-non-ocr-release-gate/v1"
REQUIRED_PROMOTION_ARCHIVE_ENTRIES = {
    "release/release_bundle.json",
    "release/release_approval.json",
    "release/release_receipt.json",
    "ops/promotion_evidence.json",
    "ops/promotion_audit_report.json",
    "ops/rotation_rehearsal_report.json",
    "ops/promotion_artifact_audit_report.json",
    "ops/promotion_run_receipt.json",
    "bundle_manifest.json",
}


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_lower_hex_sha256(value: object) -> bool:
    text = str(value or "").strip()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _resolve_path(value: object, *, base_dir: Path) -> Optional[Path]:
    text = str(value or "").strip()
    if not text:
        return None
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _load_json_object(path: Path, label: str, failures: List[str]) -> Dict[str, object]:
    if not path.exists():
        failures.append("{0} missing: {1}".format(label, path))
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        failures.append("{0} is not valid JSON: {1}".format(label, exc))
        return {}
    if not isinstance(payload, dict):
        failures.append("{0} must be a JSON object: {1}".format(label, path))
        return {}
    return payload


def _require_truthy(payload: Mapping[str, object], key: str, label: str, failures: List[str]) -> None:
    if not bool(payload.get(key)):
        failures.append("{0}.{1} must be true".format(label, key))


def _validate_config(
    *,
    config_path: Path,
    repo_root: Path,
    require_key_files_exist: bool,
    failures: List[str],
) -> Optional[soenc_config.SoencProjectConfig]:
    try:
        project = soenc_config.load_project_config(str(config_path), base_dir=repo_root)
    except Exception as exc:
        failures.append("config failed to load: {0}".format(exc))
        return None
    if project is None:
        failures.append("config file is required")
        return None

    defaults = project.cli_defaults
    if project.key_mode != encryption_helper.LICENSE_FILE_MODE:
        failures.append("keys.mode must be license-file for non-OCR production/Beta release")
    if defaults.get("compile") is not True:
        failures.append("build.compile must be true for production native packaging")
    if defaults.get("runtime_native_loader") is not True:
        failures.append("build.runtime_native_loader must be true for native-only runtime")
    if defaults.get("hardening_profile") != "balanced":
        failures.append("build.hardening_profile must be balanced for Mainline Beta production default")
    if defaults.get("require_manifest_signature") is not True:
        failures.append("keys.require_manifest_signature must be true")
    if defaults.get("bundle_license") is not False:
        failures.append("keys.bundle_license must be false")
    if not defaults.get("license_file"):
        failures.append("keys.license_file must be configured")
    if not defaults.get("license_sign_key_file"):
        failures.append("keys.license_sign_key_file must be configured")
    if not defaults.get("license_sign_key_id"):
        failures.append("keys.license_sign_key_id must be configured")
    if defaults.get("require_release_approval") is not True:
        failures.append("release.require_approval must be true")
    if not defaults.get("release_approval_file"):
        failures.append("release.approval_file must be configured")
    if not defaults.get("release_approval_key_file"):
        failures.append("release.approval_key_file must be configured")
    if not defaults.get("release_approval_key_id"):
        failures.append("release.approval_key_id must be configured")
    if not defaults.get("dist_dir"):
        failures.append("build.dist_dir must be configured for release gate")

    if require_key_files_exist:
        for label, value in (
            ("keys.manifest_sign_key_file", defaults.get("manifest_sign_key_file")),
            ("keys.license_sign_key_file", defaults.get("license_sign_key_file")),
            ("release.approval_key_file", defaults.get("release_approval_key_file")),
        ):
            key_path = _resolve_path(value, base_dir=project.path.parent)
            if key_path is None or not key_path.is_file():
                failures.append("{0} must point to an existing key file".format(label))

    return project


def _validate_dist(
    *,
    dist_dir: Path,
    project: soenc_config.SoencProjectConfig,
    failures: List[str],
) -> None:
    if not dist_dir.exists():
        failures.append("dist_dir missing: {0}".format(dist_dir))
        return
    if not dist_dir.is_dir():
        failures.append("dist_dir must be a directory: {0}".format(dist_dir))
        return

    leak_report = run_dist_no_source_leak_check(dist_dir)
    if not leak_report.get("passed"):
        for issue in leak_report.get("issues") or []:
            if isinstance(issue, dict):
                failures.append(
                    "dist no-source-leak failed: {code}:{relative_path}".format(**issue)
                )
        if not leak_report.get("issues"):
            failures.append("dist no-source-leak failed")

    manifest_path = dist_dir / "build_manifest.json"
    manifest = _load_json_object(manifest_path, "build manifest", failures)
    if not manifest:
        return
    if not isinstance(manifest.get("signature"), dict):
        failures.append("build_manifest.json must contain manifest signature")
    hardening = manifest.get("build_hardening") or {}
    if not isinstance(hardening, dict) or hardening.get("profile") != "balanced":
        failures.append("build_manifest.build_hardening.profile must be balanced")

    runtime_delivery = manifest.get("runtime_delivery") or {}
    if not isinstance(runtime_delivery, dict):
        failures.append("build_manifest.runtime_delivery must be an object")
        runtime_delivery = {}
    if runtime_delivery.get("loader_mode") != encryption_helper.RUNTIME_LOADER_MODE_NATIVE_ONLY:
        failures.append("runtime_delivery.loader_mode must be native-only")
    if runtime_delivery.get("loader_enforced") is not True:
        failures.append("runtime_delivery.loader_enforced must be true")
    if manifest.get("runtime_files"):
        _require_truthy(runtime_delivery, "validated", "runtime_delivery", failures)
        if not runtime_delivery.get("compiled_runtime_files"):
            failures.append("runtime_delivery.compiled_runtime_files must be non-empty")
        if not runtime_delivery.get("compiled_runtime_fingerprints"):
            failures.append("runtime_delivery.compiled_runtime_fingerprints must be non-empty")

    key_mgmt = manifest.get("key_management") or {}
    if not isinstance(key_mgmt, dict):
        failures.append("build_manifest.key_management must be an object")
        key_mgmt = {}
    if key_mgmt.get("mode") != encryption_helper.LICENSE_FILE_MODE:
        failures.append("key_management.mode must be license-file")
    if bool(key_mgmt.get("bundle_license")):
        failures.append("key_management.bundle_license must be false")
    if key_mgmt.get("license_signature_required") is not True:
        failures.append("key_management.license_signature_required must be true")
    if key_mgmt.get("license_verify_key_env") != "SOENC_LICENSE_VERIFY_KEY_B64":
        failures.append("key_management.license_verify_key_env must be SOENC_LICENSE_VERIFY_KEY_B64")

    bundle_path = dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME
    bundle = _load_json_object(bundle_path, "release bundle", failures)
    if bundle:
        if bundle.get("schema") != encryption_helper.RELEASE_BUNDLE_SCHEMA:
            failures.append("release_bundle schema mismatch")
        if bundle.get("layout_version") != encryption_helper.RELEASE_LAYOUT_VERSION:
            failures.append("release_bundle layout_version mismatch")
        build_manifest_row = bundle.get("build_manifest") or {}
        if not isinstance(build_manifest_row, dict) or build_manifest_row.get("is_signed") is not True:
            failures.append("release_bundle.build_manifest.is_signed must be true")
        contents = bundle.get("bundle_contents") or {}
        if not isinstance(contents, dict):
            failures.append("release_bundle.bundle_contents must be an object")
            contents = {}
        if not contents.get("native_extension_files"):
            failures.append("release_bundle.bundle_contents.native_extension_files must be non-empty")
        if manifest.get("runtime_files") and not contents.get("runtime_compiled_files"):
            failures.append("release_bundle.bundle_contents.runtime_compiled_files must be non-empty")
        license_row = contents.get("license_file")
        if not isinstance(license_row, dict):
            failures.append("release_bundle.bundle_contents.license_file must describe external license-file delivery")
        else:
            if license_row.get("externalized") is not True:
                failures.append("release_bundle license_file.externalized must be true")
            if bool(license_row.get("bundled")):
                failures.append("release_bundle license_file.bundled must be false")
            if license_row.get("runtime_env") != encryption_helper.LICENSE_FILE_ENV:
                failures.append("release_bundle license_file.runtime_env must be SOENC_LICENSE_FILE")
        runtime_integrity = bundle.get("runtime_integrity") or {}
        if not isinstance(runtime_integrity, dict) or runtime_integrity.get("validated") is not True:
            failures.append("release_bundle.runtime_integrity.validated must be true")

    receipt_path = dist_dir / encryption_helper.RELEASE_RECEIPT_FILENAME
    receipt = _load_json_object(receipt_path, "release receipt", failures)
    if receipt:
        if receipt.get("schema") != encryption_helper.RELEASE_RECEIPT_SCHEMA:
            failures.append("release_receipt schema mismatch")
        if receipt.get("key_mode") != encryption_helper.LICENSE_FILE_MODE:
            failures.append("release_receipt.key_mode must be license-file")
        if receipt.get("manifest_signature_required") is not True:
            failures.append("release_receipt.manifest_signature_required must be true")
        if receipt.get("manifest_signature_present") is not True:
            failures.append("release_receipt.manifest_signature_present must be true")
        if receipt.get("release_approval_required") is not True:
            failures.append("release_receipt.release_approval_required must be true")
        if receipt.get("release_approval_verified") is not True:
            failures.append("release_receipt.release_approval_verified must be true")
        bundle_digest = receipt.get("release_bundle_sha256")
        if not _is_lower_hex_sha256(bundle_digest):
            failures.append("release_receipt.release_bundle_sha256 must be a lowercase sha256")
        elif bundle_path.exists() and bundle_digest != encryption_helper._sha256_file(bundle_path):
            failures.append("release_receipt.release_bundle_sha256 must match release_bundle.json")

    tamper_path = dist_dir / encryption_helper.RELEASE_TAMPER_REPORT_FILENAME
    tamper = _load_json_object(tamper_path, "release tamper report", failures)
    if tamper:
        if tamper.get("schema") != encryption_helper.RELEASE_TAMPER_REPORT_SCHEMA:
            failures.append("release_tamper_report schema mismatch")
        if tamper.get("success") is not True:
            failures.append("release_tamper_report.success must be true")
        checks = tamper.get("checks") or {}
        manifest_check = checks.get("manifest_signature") if isinstance(checks, dict) else {}
        if not isinstance(manifest_check, dict) or manifest_check.get("required") is not True:
            failures.append("release_tamper_report checks.manifest_signature.required must be true")


def _validate_archive_paths(names: Iterable[str], failures: List[str]) -> None:
    for name in names:
        normalized = str(name).replace("\\", "/")
        if normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
            failures.append("promotion bundle contains unsafe archive path: {0}".format(name))


def _validate_promotion_bundle(bundle_path: Path, failures: List[str]) -> None:
    if not bundle_path.exists():
        failures.append("promotion artifact bundle missing: {0}".format(bundle_path))
        return
    if not zipfile.is_zipfile(bundle_path):
        failures.append("promotion artifact bundle must be a zip file: {0}".format(bundle_path))
        return

    with zipfile.ZipFile(bundle_path, "r") as zipped:
        names = set(zipped.namelist())
        _validate_archive_paths(names, failures)
        missing = sorted(REQUIRED_PROMOTION_ARCHIVE_ENTRIES - names)
        if missing:
            failures.append("promotion artifact bundle missing entries: {0}".format(", ".join(missing)))
            return
        try:
            manifest_payload = json.loads(zipped.read("bundle_manifest.json").decode("utf-8"))
        except Exception as exc:
            failures.append("promotion artifact bundle manifest is invalid: {0}".format(exc))
            return
        if not isinstance(manifest_payload, dict):
            failures.append("promotion artifact bundle manifest must be a JSON object")
            return
        if manifest_payload.get("schema") != promotion_bundle.PROMOTION_ARTIFACT_BUNDLE_SCHEMA:
            failures.append("promotion artifact bundle manifest schema mismatch")
        files = manifest_payload.get("files")
        if not isinstance(files, list) or not files:
            failures.append("promotion artifact bundle manifest files must be non-empty")
            return
        manifest_archive_paths = set()
        for index, row in enumerate(files):
            if not isinstance(row, dict):
                failures.append("promotion artifact bundle manifest files[{0}] must be an object".format(index))
                continue
            archive_path = str(row.get("archive_path") or "").strip()
            expected_sha = str(row.get("sha256") or "").strip()
            manifest_archive_paths.add(archive_path)
            if archive_path not in names:
                failures.append("promotion artifact bundle manifest references missing entry: {0}".format(archive_path))
                continue
            if not _is_lower_hex_sha256(expected_sha):
                failures.append("promotion artifact bundle manifest sha256 invalid for {0}".format(archive_path))
                continue
            actual_sha = _sha256_bytes(zipped.read(archive_path))
            if actual_sha != expected_sha:
                failures.append("promotion artifact bundle digest mismatch for {0}".format(archive_path))
        missing_from_manifest = sorted((REQUIRED_PROMOTION_ARCHIVE_ENTRIES - {"bundle_manifest.json"}) - manifest_archive_paths)
        if missing_from_manifest:
            failures.append(
                "promotion artifact bundle manifest missing required archive paths: {0}".format(
                    ", ".join(missing_from_manifest)
                )
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the non-OCR production/Beta release gate.")
    parser.add_argument(
        "--config",
        default="soenc.production.toml",
        help="Production/Beta soenc config to validate. Defaults to ./soenc.production.toml.",
    )
    parser.add_argument("--dist-dir", help="Release dist directory. Defaults to [build].dist_dir from config.")
    parser.add_argument("--promotion-bundle", help="Optional promotion_artifact_bundle.zip to validate.")
    parser.add_argument(
        "--config-only",
        action="store_true",
        help="Validate production config defaults only; do not require release dist artifacts.",
    )
    parser.add_argument(
        "--require-key-files-exist",
        action="store_true",
        help="Require configured manifest/license/release approval key files to exist.",
    )
    parser.add_argument("--report", help="Optional JSON gate report path.")
    return parser


def _write_report(path: str, report: Mapping[str, object]) -> Path:
    report_path = Path(path).expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report_path


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path.cwd().resolve()
    config_path = _resolve_path(args.config, base_dir=repo_root)
    failures: List[str] = []
    project = _validate_config(
        config_path=config_path or (repo_root / "soenc.production.toml"),
        repo_root=repo_root,
        require_key_files_exist=bool(args.require_key_files_exist),
        failures=failures,
    )

    dist_dir = None  # type: Optional[Path]
    if project is not None and not args.config_only:
        dist_value = args.dist_dir or project.cli_defaults.get("dist_dir")
        dist_dir = _resolve_path(dist_value, base_dir=project.path.parent)
        if dist_dir is None:
            failures.append("dist_dir is required unless --config-only is used")
        else:
            _validate_dist(dist_dir=dist_dir, project=project, failures=failures)

    promotion_bundle_path = None  # type: Optional[Path]
    if args.promotion_bundle:
        promotion_bundle_path = _resolve_path(args.promotion_bundle, base_dir=repo_root)
        if promotion_bundle_path is not None:
            _validate_promotion_bundle(promotion_bundle_path, failures)

    report = {
        "schema": GATE_SCHEMA,
        "config_file": str(config_path) if config_path is not None else None,
        "config_only": bool(args.config_only),
        "dist_dir": str(dist_dir) if dist_dir is not None else None,
        "promotion_bundle": str(promotion_bundle_path) if promotion_bundle_path is not None else None,
        "passed": not failures,
        "summary": {
            "total_failures": len(failures),
        },
        "failures": failures,
    }
    if args.report:
        print("non_ocr_release_gate_report={0}".format(_write_report(args.report, report)))

    if failures:
        print("NON_OCR_RELEASE_GATE_FAILED failures={0}".format(len(failures)))
        for failure in failures:
            print("failure={0}".format(failure))
        return 1
    print("NON_OCR_RELEASE_GATE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
