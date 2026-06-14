#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the non-OCR third-party reverse evaluation gate."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict

from scripts.non_ocr_third_party_reverse_eval_gate import REPORT_SCHEMA
from scripts.non_ocr_third_party_reverse_eval_gate import validate_report


REPO_ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 64


def _draft_report() -> Dict[str, object]:
    return {
        "schema": REPORT_SCHEMA,
        "status": "draft",
        "evaluation_id": "eval-001",
        "claim_boundary": {
            "accepted": False,
            "allowed_claim": "The non-OCR line increases reverse-engineering cost.",
            "excluded_claims": [
                "absolute non-reversibility",
                "OCR / QR / cross-media launch coverage",
                "remote-KMS service launch coverage",
            ],
        },
        "release_evidence": {
            "release_tag": "v0.1.0-ga.1",
            "promotion_artifact_bundle_sha256": "",
            "landing_gate_report": "",
            "sample_hashes_verified": False,
        },
        "samples": [
            {
                "sample_id": "sample-001",
                "artifact_type": "promotion-bundle",
                "source_path_or_url": "",
                "sha256": "",
                "size_bytes": 0,
                "selection_reason": "",
            }
        ],
        "environment": {"os": "", "architecture": "", "python_version": "", "tools": []},
        "attack_budget": {
            "total_hours": 0,
            "assessors": [],
            "allowed_techniques": [],
            "prohibited_techniques": [],
            "success_criteria": [],
            "stop_criteria": [],
        },
        "findings": [],
        "retest": {"required": False, "records": []},
        "conclusion": {
            "direct_source_disclosure_found": None,
            "reverse_cost_increased_within_budget": None,
            "ga_blocking_findings": None,
            "excluded_claims_respected": False,
        },
        "approval": {
            "assessor": "",
            "assessor_approved_at_utc": "",
            "project_owner": "",
            "project_owner_ack_at_utc": "",
            "final_report_sha256": "",
            "final_report_storage_path": "",
        },
    }


def _completed_report() -> Dict[str, object]:
    report = _draft_report()
    report["status"] = "completed"
    report["claim_boundary"]["accepted"] = True  # type: ignore[index]
    report["release_evidence"] = {
        "release_tag": "v0.1.0-ga.1",
        "promotion_artifact_bundle_sha256": SHA,
        "landing_gate_report": "https://example.test/non_ocr_ga_landing_gate_report.json",
        "sample_hashes_verified": True,
    }
    report["samples"] = [
        {
            "sample_id": "sample-001",
            "artifact_type": "encrypted-file",
            "source_path_or_url": "https://example.test/sample.enc",
            "sha256": SHA,
            "size_bytes": 256,
            "selection_reason": "Arbitrary encrypted file sample",
        },
        {
            "sample_id": "sample-002",
            "artifact_type": "protected-python-package",
            "source_path_or_url": "https://example.test/protected_package.zip",
            "sha256": SHA,
            "size_bytes": 512,
            "selection_reason": "Protected Python package sample",
        },
        {
            "sample_id": "sample-003",
            "artifact_type": "native-runtime",
            "source_path_or_url": "https://example.test/native_runtime.pyd",
            "sha256": SHA,
            "size_bytes": 768,
            "selection_reason": "Native runtime sample",
        },
        {
            "sample_id": "sample-004",
            "artifact_type": "release-bundle",
            "source_path_or_url": "https://example.test/release_bundle.json",
            "sha256": SHA,
            "size_bytes": 1024,
            "selection_reason": "Release evidence bundle metadata",
        },
        {
            "sample_id": "sample-005",
            "artifact_type": "promotion-bundle",
            "source_path_or_url": "https://example.test/promotion_artifact_bundle.zip",
            "sha256": SHA,
            "size_bytes": 2048,
            "selection_reason": "GA promotion evidence bundle under review",
        },
    ]
    report["environment"] = {
        "os": "Windows 11",
        "architecture": "x86_64",
        "python_version": "3.12",
        "tools": ["python", "sha256sum", "unzip"],
    }
    report["attack_budget"] = {
        "total_hours": 16,
        "assessors": ["external-assessor-a"],
        "allowed_techniques": ["static inspection", "runtime tamper attempts"],
        "prohibited_techniques": ["credential theft", "production service attacks"],
        "success_criteria": ["recover readable business source", "bypass license fail-closed"],
        "stop_criteria": ["budget exhausted", "critical finding discovered"],
    }
    report["conclusion"] = {
        "direct_source_disclosure_found": False,
        "reverse_cost_increased_within_budget": True,
        "ga_blocking_findings": False,
        "excluded_claims_respected": True,
    }
    report["approval"] = {
        "assessor": "external-assessor-a",
        "assessor_approved_at_utc": "2026-06-13T12:00:00Z",
        "project_owner": "project-owner",
        "project_owner_ack_at_utc": "2026-06-13T12:10:00Z",
        "final_report_sha256": SHA,
        "final_report_storage_path": "docs/evidence/non_ocr_eval_final.json",
    }
    return report



def _write_evidence_file(root: Path, relative_path: str, payload: bytes) -> str:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _completed_local_report(root: Path) -> Dict[str, object]:
    report = _completed_report()
    bundle_sha = _write_evidence_file(root, "evidence/promotion_artifact_bundle.zip", b"promotion-bundle")
    _write_evidence_file(root, "evidence/non_ocr_ga_landing_gate_report.json", b"{}")
    _write_evidence_file(root, "evidence/final_report.json", b"final-report")
    sample_specs = [
        ("sample-001", "encrypted-file", "samples/sample.enc", b"encrypted-file"),
        ("sample-002", "protected-python-package", "samples/protected_package.zip", b"protected-package"),
        ("sample-003", "native-runtime", "samples/native_runtime.pyd", b"native-runtime"),
        ("sample-004", "release-bundle", "samples/release_bundle.json", b"release-bundle"),
        ("sample-005", "promotion-bundle", "evidence/promotion_artifact_bundle.zip", b"promotion-bundle"),
    ]
    samples = []
    for sample_id, artifact_type, relative_path, payload in sample_specs:
        digest = _write_evidence_file(root, relative_path, payload)
        samples.append(
            {
                "sample_id": sample_id,
                "artifact_type": artifact_type,
                "source_path_or_url": relative_path,
                "sha256": digest,
                "size_bytes": len(payload),
                "selection_reason": "local evidence sample",
            }
        )
    report["samples"] = samples
    report["release_evidence"] = {
        "release_tag": "v0.1.0-ga.1",
        "promotion_artifact_bundle_path": "evidence/promotion_artifact_bundle.zip",
        "promotion_artifact_bundle_sha256": bundle_sha,
        "landing_gate_report": "evidence/non_ocr_ga_landing_gate_report.json",
        "sample_hashes_verified": True,
    }
    report["approval"]["final_report_storage_path"] = "evidence/final_report.json"  # type: ignore[index]
    return report
def test_draft_template_passes_structure_gate_without_completed_claim() -> None:
    gate_report = validate_report(_draft_report())

    assert gate_report["passed"] is True
    assert gate_report["require_completed"] is False
    assert gate_report["failures"] == []


def test_completed_report_passes_completed_gate() -> None:
    gate_report = validate_report(_completed_report(), require_completed=True)

    assert gate_report["passed"] is True
    assert gate_report["failures"] == []


def test_completed_gate_rejects_draft_template() -> None:
    gate_report = validate_report(_draft_report(), require_completed=True)

    assert gate_report["passed"] is False
    assert "status must be completed when --require-completed is used" in gate_report["failures"]
    assert "claim_boundary.accepted must be true for completed reports" in gate_report["failures"]
    assert "attack_budget.total_hours must be greater than zero for completed reports" in gate_report["failures"]


def test_gate_rejects_missing_samples_and_findings_section() -> None:
    report = _draft_report()
    del report["samples"]
    del report["findings"]

    gate_report = validate_report(report)

    assert gate_report["passed"] is False
    assert "samples must be a non-empty list" in gate_report["failures"]
    assert "findings must be a list, even when empty" in gate_report["failures"]



def test_completed_gate_rejects_missing_minimum_sample_types() -> None:
    report = _completed_report()
    report["samples"] = [report["samples"][-1]]  # type: ignore[index]

    gate_report = validate_report(report, require_completed=True)

    assert gate_report["passed"] is False
    assert any("samples must include completed assessment artifact types" in item for item in gate_report["failures"])
    assert any("encrypted-file" in item for item in gate_report["failures"])

def test_completed_report_passes_local_evidence_gate(tmp_path: Path) -> None:
    report = _completed_local_report(tmp_path)

    gate_report = validate_report(
        report,
        require_completed=True,
        require_local_evidence=True,
        evidence_root=tmp_path,
    )

    assert gate_report["passed"] is True
    assert gate_report["require_local_evidence"] is True
    assert gate_report["failures"] == []


def test_local_evidence_gate_rejects_sample_hash_mismatch(tmp_path: Path) -> None:
    report = _completed_local_report(tmp_path)
    report["samples"][0]["sha256"] = "b" * 64  # type: ignore[index]

    gate_report = validate_report(
        report,
        require_completed=True,
        require_local_evidence=True,
        evidence_root=tmp_path,
    )

    assert gate_report["passed"] is False
    assert "samples[0] sha256 mismatch" in gate_report["failures"]
def test_gate_cli_writes_report_for_template(tmp_path: Path) -> None:
    report_path = tmp_path / "eval.json"
    report_path.write_text(json.dumps(_draft_report(), indent=2, sort_keys=True), encoding="utf-8")
    gate_path = tmp_path / "gate.json"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/non_ocr_third_party_reverse_eval_gate.py",
            "--report",
            str(report_path),
            "--gate-report",
            str(gate_path),
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "NON_OCR_THIRD_PARTY_REVERSE_EVAL_GATE_OK" in result.stdout
    assert json.loads(gate_path.read_text(encoding="utf-8"))["passed"] is True


def test_gate_cli_rejects_template_as_completed(tmp_path: Path) -> None:
    report_path = tmp_path / "eval.json"
    report_path.write_text(json.dumps(_draft_report(), indent=2, sort_keys=True), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/non_ocr_third_party_reverse_eval_gate.py",
            "--report",
            str(report_path),
            "--require-completed",
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 1
    assert "NON_OCR_THIRD_PARTY_REVERSE_EVAL_GATE_FAILED" in result.stdout
    assert "status must be completed" in result.stdout