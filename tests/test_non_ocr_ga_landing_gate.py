#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the non-OCR GA landing gate."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Dict

import encryption_helper
from enc2sop import promotion_artifacts
from enc2sop import promotion_audit
from enc2sop import promotion_bundle
from enc2sop.ga_landing import GA_LANDING_GATE_SCHEMA
from enc2sop.ga_landing import REQUIRED_BUNDLE_ENTRIES
from enc2sop.ga_landing import run_ga_landing_gate


REPO_ROOT = Path(__file__).resolve().parents[1]


def _json_bytes(payload: Dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


def _write_bundle(path: Path, *, corrupt_manifest_sha: bool = False, rotation_passed: bool = True) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payloads = {
        "release/release_bundle.json": {
            "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
            "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
            "bundle_contents": {
                "license_file": {
                    "externalized": True,
                    "bundled": False,
                }
            },
        },
        "release/release_approval.json": {
            "schema": encryption_helper.RELEASE_APPROVAL_SCHEMA,
            "release_bundle_relative_path": encryption_helper.RELEASE_BUNDLE_FILENAME,
            "release_bundle_sha256": "a" * 64,
            "approvers": ["ops"],
            "signature": {
                "algorithm": encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256,
                "key_id": "ops-key",
                "digest_hex": "b" * 64,
            },
        },
        "release/release_receipt.json": {
            "schema": encryption_helper.RELEASE_RECEIPT_SCHEMA,
            "release_bundle_relative_path": encryption_helper.RELEASE_BUNDLE_FILENAME,
            "release_bundle_sha256": "a" * 64,
            "release_approval_verified": True,
            "runtime_artifacts_verified": 1,
            "native_artifacts_verified": 1,
        },
        "ops/promotion_evidence.json": {
            "schema": promotion_audit.PROMOTION_EVIDENCE_SCHEMA,
            "repository": "local/non-ocr-ga-test",
            "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
            "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
            "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
        },
        "ops/promotion_audit_report.json": {
            "schema": promotion_audit.PROMOTION_AUDIT_REPORT_SCHEMA,
            "passed": True,
            "summary": {"total_failures": 0},
            "failures": [],
        },
        "ops/rotation_rehearsal_report.json": {
            "schema": promotion_artifacts.ROTATION_REHEARSAL_SCHEMA,
            "requested": rotation_passed,
            "executed": rotation_passed,
            "old_key_rejected": True if rotation_passed else None,
            "status": "passed" if rotation_passed else "not-requested",
        },
        "ops/promotion_artifact_audit_report.json": {
            "schema": promotion_artifacts.PROMOTION_ARTIFACT_AUDIT_SCHEMA,
            "passed": True,
            "summary": {"total_failures": 0},
            "failures": [],
        },
        "ops/promotion_run_receipt.json": {
            "schema": promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA,
            "passed": True,
            "rotation_pass_required": rotation_passed,
            "artifacts": [],
        },
        "policy/promotion_rollout_policy.json": {"schema": "enc2sop-promotion-policy/v1"},
    }
    raw_entries = {name: _json_bytes(payload) for name, payload in payloads.items()}
    raw_entries["workflow/release_promotion.yml"] = b"name: release-promotion-gate\n"
    manifest_files = []
    for index, name in enumerate(sorted(raw_entries)):
        digest = hashlib.sha256(raw_entries[name]).hexdigest()
        if corrupt_manifest_sha and index == 0:
            digest = "0" * 64
        manifest_files.append(
            {
                "name": name.replace("/", "_"),
                "archive_path": name,
                "source_path": name,
                "sha256": digest,
            }
        )
    manifest = {
        "schema": promotion_bundle.PROMOTION_ARTIFACT_BUNDLE_SCHEMA,
        "generated_at_utc": "2026-06-13T00:00:00Z",
        "file_count": len(manifest_files),
        "files": manifest_files,
    }
    raw_entries["bundle_manifest.json"] = _json_bytes(manifest)
    assert set(REQUIRED_BUNDLE_ENTRIES).issubset(set(raw_entries))
    with zipfile.ZipFile(path, "w") as zipped:
        for name, data in raw_entries.items():
            zipped.writestr(name, data)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_smoke_report(path: Path, bundle_path: Path, bundle_sha: str, *, reverse_passed: bool = True) -> None:
    payload = {
        "schema": "enc2sop-non-ocr-ga-governance-smoke/v1",
        "passed": True,
        "summary": {
            "total_failures": 0,
            "release_governance_passed": True,
            "license_file_e2e_passed": True,
            "reverse_cost_check_passed": reverse_passed,
        },
        "release_governance": {
            "passed": True,
            "promotion_artifact_bundle": str(bundle_path),
            "promotion_artifact_bundle_sha256": bundle_sha,
            "reverse_cost_check_passed": reverse_passed,
            "reverse_cost_check": {"passed": reverse_passed, "issues": [] if reverse_passed else [{"code": "leak"}]},
        },
        "license_file_e2e": {"passed": True, "cases": []},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def test_ga_landing_gate_passes_with_valid_smoke_report_and_bundle(tmp_path: Path) -> None:
    bundle_path = tmp_path / "promotion_artifact_bundle.zip"
    bundle_sha = _write_bundle(bundle_path)
    smoke_path = tmp_path / "non_ocr_ga_governance_smoke_report.json"
    _write_smoke_report(smoke_path, bundle_path, bundle_sha)
    report_path = tmp_path / "ga_landing_gate_report.json"

    output_path, report = run_ga_landing_gate(
        smoke_report_file=str(smoke_path),
        report_file=str(report_path),
        repo_root=REPO_ROOT,
    )

    assert output_path == report_path.resolve()
    assert report["schema"] == GA_LANDING_GATE_SCHEMA
    assert report["passed"] is True
    assert report["summary"]["license_file_e2e_passed"] is True
    assert report["summary"]["reverse_cost_check_passed"] is True
    assert report["summary"]["rotation_rehearsal_passed"] is True
    assert report["failures"] == []
    assert json.loads(report_path.read_text(encoding="utf-8"))["passed"] is True


def test_ga_landing_gate_fails_on_manifest_checksum_mismatch(tmp_path: Path) -> None:
    bundle_path = tmp_path / "promotion_artifact_bundle.zip"
    bundle_sha = _write_bundle(bundle_path, corrupt_manifest_sha=True)
    smoke_path = tmp_path / "non_ocr_ga_governance_smoke_report.json"
    _write_smoke_report(smoke_path, bundle_path, bundle_sha)

    _output_path, report = run_ga_landing_gate(
        smoke_report_file=str(smoke_path),
        repo_root=REPO_ROOT,
    )

    assert report["passed"] is False
    assert any("sha256 mismatch" in item for item in report["failures"])


def test_ga_landing_gate_fails_when_reverse_cost_did_not_pass(tmp_path: Path) -> None:
    bundle_path = tmp_path / "promotion_artifact_bundle.zip"
    bundle_sha = _write_bundle(bundle_path)
    smoke_path = tmp_path / "non_ocr_ga_governance_smoke_report.json"
    _write_smoke_report(smoke_path, bundle_path, bundle_sha, reverse_passed=False)

    _output_path, report = run_ga_landing_gate(
        smoke_report_file=str(smoke_path),
        repo_root=REPO_ROOT,
    )

    assert report["passed"] is False
    assert "reverse_cost_check_passed must be true" in report["failures"]
    assert "reverse_cost_check.passed must be true" in report["failures"]
    assert "reverse_cost_check.issues must be empty" in report["failures"]


def test_ga_landing_gate_cli_prints_ci_visible_flags(tmp_path: Path) -> None:
    bundle_path = tmp_path / "promotion_artifact_bundle.zip"
    bundle_sha = _write_bundle(bundle_path)
    smoke_path = tmp_path / "non_ocr_ga_governance_smoke_report.json"
    _write_smoke_report(smoke_path, bundle_path, bundle_sha)
    report_path = tmp_path / "ga_landing_gate_report.json"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/non_ocr_ga_landing_gate.py",
            "--smoke-report",
            str(smoke_path),
            "--report",
            str(report_path),
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "NON_OCR_GA_LANDING_GATE_OK" in result.stdout
    assert "license_file_e2e_passed=True" in result.stdout
    assert "reverse_cost_check_passed=True" in result.stdout
    assert json.loads(report_path.read_text(encoding="utf-8"))["passed"] is True
