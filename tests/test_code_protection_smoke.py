#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Regression coverage for the V0.3 P0-B2 code-protection smoke script."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SMOKE_SCHEMA = "enc2sop-code-protection-smoke/v1"


def test_code_protection_smoke_reports_blocked_or_passed() -> None:
    work_dir = REPO_ROOT / ".tmp_code_protection_smoke_test_{0}".format(uuid.uuid4().hex[:8])
    try:
        result = subprocess.run(
            [
                sys.executable,
                "scripts/smoke_code_protection.py",
                "--work-dir",
                str(work_dir),
                "--allow-blocked",
            ],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        assert result.returncode == 0, result.stderr
        report_path = work_dir / "smoke_code_protection_report.json"
        assert report_path.exists()
        payload = json.loads(report_path.read_text(encoding="utf-8"))

        assert payload["schema"] == SMOKE_SCHEMA
        assert payload["steps"]["protect"]["returncode"] == 0
        assert payload["status"] in {"blocked", "passed"}

        if payload["status"] == "blocked":
            assert payload["success"] is False
            assert payload["reason"] == "native_dependencies_unavailable"
            assert "native_dependency_probe" in payload["steps"]
            assert payload["steps"]["native_dependency_probe"]["missing_or_broken"]
            assert "CODE_PROTECTION_SMOKE_BLOCKED" in result.stdout
        else:
            assert payload["success"] is True
            assert payload["observed"] == {"add": 5, "scale": 42}
            assert payload["native_outputs"]
            assert "CODE_PROTECTION_SMOKE_OK" in result.stdout
    finally:
        shutil.rmtree(str(work_dir), ignore_errors=True)
