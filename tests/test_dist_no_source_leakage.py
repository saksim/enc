#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for P0-B3 dist no-source-leakage checks."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from enc2sop.protect.dist_check import REPORT_SCHEMA
from enc2sop.protect.dist_check import run_dist_no_source_leak_check


REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_release_metadata(dist: Path, *, bundled: bool = False, externalized: bool = True, tamper_success: bool = True) -> None:
    _write_json(
        dist / "release_bundle.json",
        {
            "bundle_contents": {
                "license_file": {
                    "bundled": bundled,
                    "externalized": externalized,
                }
            }
        },
    )
    _write_json(dist / "release_tamper_report.json", {"success": tamper_success})


def test_dist_no_source_leakage_passes_native_only_dist(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    pkg = dist / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "mod.pyd").write_bytes(b"native")
    _write_json(dist / "build_manifest.json", {"key_management": {"mode": "license-file", "bundle_license": False}})
    _write_release_metadata(dist)

    report = run_dist_no_source_leak_check(dist, require_release_metadata=True)

    assert report["schema"] == REPORT_SCHEMA
    assert report["passed"] is True
    assert report["issues"] == []


def test_dist_no_source_leakage_rejects_py_and_c_artifacts(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    pkg = dist / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "mod.py").write_text("def leaked_source():\n    return 1\n", encoding="utf-8")
    (pkg / "mod.c").write_text("/* generated c */\n", encoding="utf-8")
    (pkg / "mod.pyx").write_text("cdef int leaked\n", encoding="utf-8")

    report = run_dist_no_source_leak_check(dist)
    codes = {issue["code"] for issue in report["issues"]}

    assert report["passed"] is False
    assert "python_source_file" in codes
    assert "generated_source_file" in codes


def test_dist_no_source_leakage_rejects_secret_material_and_test_residue(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    (dist / "tests").mkdir(parents=True)
    (dist / "tests" / "test_runtime.py").write_text("", encoding="utf-8")
    (dist / "approval.key").write_text("secret", encoding="utf-8")

    report = run_dist_no_source_leak_check(dist)
    codes = {issue["code"] for issue in report["issues"]}

    assert report["passed"] is False
    assert "forbidden_temp_dir" in codes
    assert "secret_material_file" in codes


def test_dist_no_source_leakage_rejects_bundled_license_file(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_json(dist / "runtime.license.json", {"schema": "enc2sop-license/v1", "license_id": "demo"})

    report = run_dist_no_source_leak_check(dist)

    assert report["passed"] is False
    assert {issue["code"] for issue in report["issues"]} == {"license_bundle_file"}


def test_dist_no_source_leakage_rejects_local_embedded_and_bundled_license_manifest(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_json(dist / "build_manifest.json", {"key_management": {"mode": "local-embedded", "bundle_license": True}})

    report = run_dist_no_source_leak_check(dist)
    codes = {issue["code"] for issue in report["issues"]}

    assert report["passed"] is False
    assert "local_embedded_key_mode" in codes
    assert "license_bundle_enabled" in codes


def test_dist_no_source_leakage_rejects_release_bundle_license_policy_violations(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_release_metadata(dist, bundled=True, externalized=False)

    report = run_dist_no_source_leak_check(dist, require_release_metadata=True)
    codes = {issue["code"] for issue in report["issues"]}

    assert report["passed"] is False
    assert "release_bundle_license_bundled" in codes
    assert "release_bundle_license_not_externalized" in codes


def test_dist_no_source_leakage_requires_release_metadata_and_tamper_success(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()

    missing_report = run_dist_no_source_leak_check(dist, require_release_metadata=True)
    assert missing_report["passed"] is False
    assert {issue["code"] for issue in missing_report["issues"]} == {"release_metadata_missing"}

    _write_release_metadata(dist, tamper_success=False)
    failed_tamper_report = run_dist_no_source_leak_check(dist, require_release_metadata=True)
    assert failed_tamper_report["passed"] is False
    assert "release_tamper_report_failed" in {issue["code"] for issue in failed_tamper_report["issues"]}


def test_check_dist_no_source_leak_cli_reports_forbidden_token(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "README.txt").write_text("contains def secret_algorithm body", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/check_dist_no_source_leak.py",
            str(dist),
            "--forbid-token",
            "def secret_algorithm",
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 1
    assert "DIST_NO_SOURCE_LEAK_FAILED" in result.stdout
    assert "forbidden_token" in result.stdout


def test_check_dist_no_source_leak_cli_accepts_required_release_metadata(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_release_metadata(dist)

    result = subprocess.run(
        [
            sys.executable,
            "scripts/check_dist_no_source_leak.py",
            str(dist),
            "--require-release-metadata",
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "DIST_NO_SOURCE_LEAK_OK" in result.stdout
