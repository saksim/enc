#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Regression coverage for the non-OCR GA governance smoke."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SMOKE_SCHEMA = "enc2sop-non-ocr-ga-governance-smoke/v1"
REQUIRED_BUNDLE_ENTRIES = {
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
}
REQUIRED_LICENSE_CASES = {
    "happy_path",
    "missing_license",
    "signature_error",
    "machine_mismatch",
    "expired",
    "revoked",
}


def test_non_ocr_ga_governance_smoke_writes_release_and_license_evidence() -> None:
    work_dir = REPO_ROOT / ".tmp_non_ocr_ga_governance_smoke_test_{0}".format(uuid.uuid4().hex[:8])
    try:
        result = subprocess.run(
            [
                sys.executable,
                "scripts/non_ocr_ga_release_governance_smoke.py",
                "--work-dir",
                str(work_dir),
            ],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        assert result.returncode == 0, result.stdout + result.stderr
        assert "NON_OCR_GA_GOVERNANCE_SMOKE_OK" in result.stdout
        report_path = work_dir / "non_ocr_ga_governance_smoke_report.json"
        assert report_path.exists()
        payload = json.loads(report_path.read_text(encoding="utf-8"))

        assert payload["schema"] == SMOKE_SCHEMA
        assert payload["passed"] is True
        assert payload["summary"] == {
            "license_file_e2e_passed": True,
            "release_governance_passed": True,
            "total_failures": 0,
        }

        release_governance = payload["release_governance"]
        assert release_governance["passed"] is True
        assert release_governance["non_ocr_release_gate_passed"] is True
        assert REQUIRED_BUNDLE_ENTRIES.issubset(set(release_governance["promotion_artifact_bundle_entries"]))
        for key in (
            "release_bundle",
            "release_approval",
            "release_receipt",
            "release_tamper_report",
            "promotion_evidence",
            "promotion_audit_report",
            "rotation_rehearsal_report",
            "promotion_artifact_audit_report",
            "promotion_run_receipt",
            "promotion_artifact_bundle",
            "non_ocr_release_gate_report",
        ):
            assert Path(release_governance[key]).exists(), key

        rotation_report = json.loads(Path(release_governance["rotation_rehearsal_report"]).read_text(encoding="utf-8"))
        assert rotation_report["status"] == "passed"
        assert rotation_report["requested"] is True
        assert rotation_report["executed"] is True
        assert rotation_report["old_key_rejected"] is True

        license_e2e = payload["license_file_e2e"]
        assert license_e2e["passed"] is True
        assert REQUIRED_LICENSE_CASES == {case["case"] for case in license_e2e["cases"]}
        assert all(case["passed"] is True for case in license_e2e["cases"])
    finally:
        shutil.rmtree(str(work_dir), ignore_errors=True)
