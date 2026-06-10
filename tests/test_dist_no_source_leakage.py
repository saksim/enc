#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for P0-B3 dist no-source-leakage checks."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from enc2sop.protect.dist_check import REPORT_SCHEMA
from enc2sop.protect.dist_check import run_dist_no_source_leak_check


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_dist_no_source_leakage_passes_native_only_dist(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    pkg = dist / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "mod.pyd").write_bytes(b"native")
    (dist / "build_manifest.json").write_text("{}", encoding="utf-8")
    (dist / "release_bundle.json").write_text("{}", encoding="utf-8")

    report = run_dist_no_source_leak_check(dist)

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

    report = run_dist_no_source_leak_check(dist)
    codes = {issue["code"] for issue in report["issues"]}

    assert report["passed"] is False
    assert "python_source_file" in codes
    assert "generated_source_file" in codes


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
