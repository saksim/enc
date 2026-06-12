#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the non-OCR release gate required by the launch docs."""

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import encryption_helper
from scripts import non_ocr_release_gate


REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_config(root: Path, *, dist_dir: Path) -> Path:
    keys_dir = root / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "manifest.key").write_bytes(b"0123456789abcdef0123456789abcdef")
    (keys_dir / "license.key").write_bytes(b"abcdef0123456789abcdef0123456789")
    (keys_dir / "approval.key").write_bytes(b"fedcba9876543210fedcba9876543210")
    cfg = root / "soenc.production.toml"
    cfg.write_text(
        "\n".join(
            [
                "[build]",
                'output_dir = "./protected_build"',
                'dist_dir = "{0}"'.format(dist_dir.as_posix()),
                "compile = true",
                "runtime_native_loader = true",
                'build_profile = "auto"',
                'hardening_profile = "balanced"',
                "",
                "[keys]",
                'mode = "license-file"',
                'license_file = "licenses/production.license.json"',
                'license_id = "production-mainline-beta"',
                "bundle_license = false",
                "require_manifest_signature = true",
                'manifest_sign_key_file = "keys/manifest.key"',
                'manifest_key_id = "manifest-mainline-beta"',
                'license_sign_key_file = "keys/license.key"',
                'license_sign_key_id = "license-mainline-beta"',
                "",
                "[release]",
                "require_approval = true",
                'approval_file = "{0}"'.format((dist_dir / "release_approval.json").as_posix()),
                'approval_key_file = "keys/approval.key"',
                'approval_key_id = "release-approval-mainline-beta"',
                "",
                "[package]",
                'name = "enc2sop-protected-package"',
                'version = "0.0.0-mainline-beta"',
                'channel = "mainline-beta"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    return cfg


def _release_digest_record(path: Path, root: Path, role: str) -> dict:
    return {
        "relative_path": path.relative_to(root).as_posix(),
        "role": role,
        "sha256": encryption_helper._sha256_file(path),
        "size": path.stat().st_size,
    }


def _write_release_dist(dist_dir: Path) -> None:
    pkg = dist_dir / "pkg"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    runtime_native = pkg / "enc_rt_demo.pyd"
    runtime_native.write_bytes(b"runtime-native")
    module_native = pkg / "mod.pyd"
    module_native.write_bytes(b"module-native")
    runtime_digest = encryption_helper._sha256_file(runtime_native)
    manifest_payload = {
        "runtime_files": ["pkg/enc_rt_demo.py"],
        "runtime_delivery": {
            "loader_mode": encryption_helper.RUNTIME_LOADER_MODE_NATIVE_ONLY,
            "loader_enforced": True,
            "validated": True,
            "compiled_runtime_files": ["pkg/enc_rt_demo.pyd"],
            "compiled_runtime_fingerprints": [
                {
                    "module_name": "enc_rt_demo",
                    "source_relative_path": "pkg/enc_rt_demo.py",
                    "compiled_relative_path": "pkg/enc_rt_demo.pyd",
                    "package_relative_path": "pkg",
                    "algorithm": "sha256",
                    "digest_hex": runtime_digest,
                }
            ],
        },
        "key_management": {
            "mode": "license-file",
            "license_file": "licenses/production.license.json",
            "license_path_policy": encryption_helper.LICENSE_PATH_POLICY_ENV_ONLY,
            "runtime_env": encryption_helper.LICENSE_FILE_ENV,
            "bundle_license": False,
            "license_signature_required": True,
            "license_signature_key_id": "license-mainline-beta",
            "license_verify_key_env": "SOENC_LICENSE_VERIFY_KEY_B64",
        },
        "build_hardening": {
            "profile": "balanced",
            "native_build_required": True,
        },
    }
    manifest_key = b"0123456789abcdef0123456789abcdef"
    encryption_helper.write_manifest(dist_dir, manifest_payload, signing_key=manifest_key, key_id="manifest-mainline-beta")
    signed_manifest = json.loads((dist_dir / "build_manifest.json").read_text(encoding="utf-8"))
    release_bundle = {
        "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
        "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
        "build_manifest": {
            "relative_path": "build_manifest.json",
            "is_signed": True,
            "signature": signed_manifest["signature"],
        },
        "bundle_contents": {
            "native_extension_files": ["pkg/enc_rt_demo.pyd", "pkg/mod.pyd"],
            "runtime_compiled_files": ["pkg/enc_rt_demo.pyd"],
            "package_init_files": ["pkg/__init__.py"],
            "license_file": {
                "delivery": "external",
                "externalized": True,
                "bundled": False,
                "source_relative_path": "licenses/production.license.json",
                "runtime_env": encryption_helper.LICENSE_FILE_ENV,
                "required_for_runtime": True,
            },
        },
        "runtime_integrity": {
            "validated": True,
            "compiled_runtime_fingerprints": manifest_payload["runtime_delivery"]["compiled_runtime_fingerprints"],
        },
    }
    release_bundle_path = dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME
    release_bundle_path.write_text(json.dumps(release_bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    bundle_sha = encryption_helper._sha256_file(release_bundle_path)
    approval_key = b"fedcba9876543210fedcba9876543210"
    approval_payload = {
        "schema": encryption_helper.RELEASE_APPROVAL_SCHEMA,
        "approved_at_utc": "2026-06-12T00:00:00Z",
        "release_bundle_relative_path": encryption_helper.RELEASE_BUNDLE_FILENAME,
        "release_bundle_sha256": bundle_sha,
        "approvers": ["ops-a", "security-b"],
    }
    approval_payload["signature"] = {
        "algorithm": encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256,
        "key_id": "release-approval-mainline-beta",
        "digest_hex": "0" * 64,
    }
    (dist_dir / "release_approval.json").write_text(json.dumps(approval_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    receipt = {
        "schema": encryption_helper.RELEASE_RECEIPT_SCHEMA,
        "release_root": str(dist_dir),
        "build_manifest_relative_path": "build_manifest.json",
        "release_bundle_relative_path": encryption_helper.RELEASE_BUNDLE_FILENAME,
        "release_bundle_sha256": bundle_sha,
        "bundle_schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
        "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
        "manifest_signature_required": True,
        "manifest_signature_present": True,
        "manifest_signature_key_id": "manifest-mainline-beta",
        "runtime_artifacts_verified": 1,
        "native_artifacts_verified": 2,
        "release_approval_required": True,
        "release_approval_verified": True,
        "release_approval_key_id": "release-approval-mainline-beta",
        "key_mode": "license-file",
        "package_metadata": {"name": "enc2sop-protected-package"},
    }
    (dist_dir / encryption_helper.RELEASE_RECEIPT_FILENAME).write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tamper = {
        "schema": encryption_helper.RELEASE_TAMPER_REPORT_SCHEMA,
        "success": True,
        "classification": encryption_helper.RELEASE_TAMPER_CLASSIFICATION,
        "strong_secrecy_boundary": False,
        "release_root": str(dist_dir),
        "release_bundle_relative_path": encryption_helper.RELEASE_BUNDLE_FILENAME,
        "release_bundle_sha256": bundle_sha,
        "release_approval_required": True,
        "checks": {
            "manifest_signature": {"required": True, "present": True, "passed": True},
            "binary_digest": {
                "artifact_count": 2,
                "artifacts": [
                    _release_digest_record(runtime_native, dist_dir, "runtime"),
                    _release_digest_record(module_native, dist_dir, "native"),
                ],
            },
        },
    }
    (dist_dir / encryption_helper.RELEASE_TAMPER_REPORT_FILENAME).write_text(
        json.dumps(tamper, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _add_zip_entry(zipped: zipfile.ZipFile, archive_path: str, payload: bytes) -> str:
    zipped.writestr(archive_path, payload)
    return hashlib.sha256(payload).hexdigest()


def _write_promotion_bundle(bundle_path: Path) -> None:
    payload_by_path = {
        "release/release_bundle.json": b'{"schema":"enc2sop-release-bundle/v1"}',
        "release/release_approval.json": b'{"schema":"enc2sop-release-approval/v1"}',
        "release/release_receipt.json": b'{"schema":"enc2sop-release-receipt/v1"}',
        "ops/promotion_evidence.json": b'{"schema":"enc2sop-promotion-evidence/v1"}',
        "ops/promotion_audit_report.json": b'{"schema":"enc2sop-promotion-audit-report/v1","passed":true}',
        "ops/rotation_rehearsal_report.json": b'{"schema":"enc2sop-rotation-rehearsal/v1"}',
        "ops/promotion_artifact_audit_report.json": b'{"schema":"enc2sop-promotion-artifact-audit/v1","passed":true}',
        "ops/promotion_run_receipt.json": b'{"schema":"enc2sop-promotion-run-receipt/v1","passed":true}',
    }
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    files = []
    with zipfile.ZipFile(bundle_path, "w") as zipped:
        for archive_path, payload in sorted(payload_by_path.items()):
            digest = _add_zip_entry(zipped, archive_path, payload)
            files.append({"name": Path(archive_path).stem, "archive_path": archive_path, "sha256": digest})
        manifest = {
            "schema": "enc2sop-promotion-artifact-bundle/v1",
            "file_count": len(files),
            "files": files,
        }
        zipped.writestr("bundle_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))


def test_gate_passes_repository_production_config_in_config_only_mode() -> None:
    assert non_ocr_release_gate.main(["--config", str(REPO_ROOT / "soenc.production.toml"), "--config-only"]) == 0


def test_gate_rejects_local_embedded_production_config(tmp_path: Path) -> None:
    cfg = tmp_path / "soenc.production.toml"
    cfg.write_text(
        "\n".join(
            [
                "[build]",
                'dist_dir = "./dist"',
                "compile = true",
                "runtime_native_loader = true",
                'hardening_profile = "balanced"',
                "",
                "[keys]",
                'mode = "local-embedded"',
                "bundle_license = false",
                "require_manifest_signature = true",
                "",
                "[release]",
                "require_approval = true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "scripts/non_ocr_release_gate.py", "--config", str(cfg), "--config-only"],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 1
    assert "NON_OCR_RELEASE_GATE_FAILED" in result.stdout
    assert "keys.mode must be license-file" in result.stdout


def test_gate_validates_release_dist_and_promotion_bundle(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist_native"
    dist_dir.mkdir(parents=True)
    cfg = _write_config(tmp_path, dist_dir=dist_dir)
    _write_release_dist(dist_dir)
    bundle_path = tmp_path / "promotion_artifact_bundle.zip"
    _write_promotion_bundle(bundle_path)

    result = subprocess.run(
        [
            sys.executable,
            "scripts/non_ocr_release_gate.py",
            "--config",
            str(cfg),
            "--promotion-bundle",
            str(bundle_path),
            "--require-key-files-exist",
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "NON_OCR_RELEASE_GATE_OK" in result.stdout


def test_gate_rejects_release_dist_source_leak(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist_native"
    dist_dir.mkdir(parents=True)
    cfg = _write_config(tmp_path, dist_dir=dist_dir)
    _write_release_dist(dist_dir)
    (dist_dir / "pkg" / "leaked.py").write_text("def leaked():\n    return 1\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/non_ocr_release_gate.py", "--config", str(cfg)],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 1
    assert "dist no-source-leak failed" in result.stdout
