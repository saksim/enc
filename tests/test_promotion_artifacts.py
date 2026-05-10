import json
import os
import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock

from enc2sop import promotion_artifacts
import encryption_helper


TEST_ROOT = Path(__file__).resolve().parents[1]
TEST_RUNS_ROOT = TEST_ROOT / ".tmp_test_runs"


def _make_case_root(prefix):
    TEST_RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    root = TEST_RUNS_ROOT / "{}_{}".format(prefix, uuid.uuid4().hex[:8])
    root.mkdir(parents=True, exist_ok=False)
    return root


class PromotionArtifactsTests(unittest.TestCase):
    def make_case_root(self, prefix):
        root = _make_case_root(prefix)
        self.addCleanup(lambda: shutil.rmtree(str(root), ignore_errors=True))
        return root

    def _write_release_artifacts(self, release_dir, *, approval_key_id="ops-approval-main"):
        (release_dir / "pkg").mkdir(parents=True, exist_ok=True)
        runtime_path = release_dir / "pkg" / "enc_rt_demo.pyd"
        module_path = release_dir / "pkg" / "mod.pyd"
        init_path = release_dir / "pkg" / "__init__.py"
        runtime_path.write_bytes(b"runtime-native")
        module_path.write_bytes(b"module-native")
        init_path.write_text("", encoding="utf-8")

        bundle_payload = {
            "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
            "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
            "build_manifest": {
                "relative_path": "build_manifest.json",
                "is_signed": False,
                "signature": None,
            },
            "bundle_contents": {
                "native_extension_files": ["pkg/enc_rt_demo.pyd", "pkg/mod.pyd"],
                "runtime_compiled_files": ["pkg/enc_rt_demo.pyd"],
                "package_init_files": ["pkg/__init__.py"],
                "license_file": None,
            },
            "runtime_integrity": {
                "validated": True,
                "compiled_runtime_fingerprints": [
                    {
                        "module_name": "enc_rt_demo",
                        "source_relative_path": "pkg/enc_rt_demo.py",
                        "compiled_relative_path": "pkg/enc_rt_demo.pyd",
                        "package_relative_path": "pkg",
                        "algorithm": "sha256",
                        "digest_hex": encryption_helper._sha256_file(runtime_path),
                    }
                ],
            },
        }
        (release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(bundle_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (release_dir / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_files": ["pkg/enc_rt_demo.py"],
                    "runtime_delivery": {
                        "validated": True,
                        "compiled_runtime_files": ["pkg/enc_rt_demo.pyd"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        approval_payload = {
            "schema": encryption_helper.RELEASE_APPROVAL_SCHEMA,
            "approved_at_utc": "2026-05-10T00:00:00Z",
            "release_bundle_relative_path": encryption_helper.RELEASE_BUNDLE_FILENAME,
            "release_bundle_sha256": encryption_helper._sha256_file(release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME),
            "approvers": ["ops-a"],
            "signature": {
                "algorithm": encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256,
                "key_id": approval_key_id,
                "digest_hex": "a" * 64,
            },
        }
        (release_dir / "release_approval.json").write_text(
            json.dumps(approval_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        receipt_payload = {
            "schema": encryption_helper.RELEASE_RECEIPT_SCHEMA,
            "release_bundle_relative_path": encryption_helper.RELEASE_BUNDLE_FILENAME,
            "release_approval_verified": True,
            "runtime_artifacts_verified": 1,
            "native_artifacts_verified": 2,
        }
        (release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME).write_text(
            json.dumps(receipt_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def test_run_promotion_artifact_audit_passes_with_valid_artifacts(self):
        root = self.make_case_root("promotion_artifacts_pass")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": {
                        "GITHUB_REPOSITORY": "acme/demo",
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_RUN_ID": "12345",
                        "GITHUB_SHA": "deadbeef",
                    },
                    "branches": [
                        {"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]},
                        {"name": "release/**", "required_status_checks": ["Signed Approval Promotion Gate"]},
                    ],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        promotion_report = root / "promotion_audit_report.json"
        promotion_report.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-audit-report/v1",
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                    "inputs": {
                        "policy_file": str((root / "policy.json").resolve()),
                        "policy_sha256": "b" * 64,
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str((root / "workflow.yml").resolve()),
                        "workflow_sha256": "c" * 64,
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        rotation_report = root / "rotation_rehearsal_report.json"
        rotation_report.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-rotation-rehearsal/v1",
                    "requested": False,
                    "executed": False,
                    "old_key_rejected": None,
                    "status": "not-requested",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        report_path, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            repo_root=root,
        )

        self.assertTrue(report_path.exists())
        self.assertEqual(report["schema"], "enc2sop-promotion-artifact-audit/v1")
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["total_failures"], 0)
        run_receipt_path = promotion_report.parent / promotion_artifacts.DEFAULT_RUN_RECEIPT_FILENAME
        self.assertEqual(report["promotion_run_receipt_file"], str(run_receipt_path.resolve()))
        self.assertTrue(run_receipt_path.exists())
        run_receipt = json.loads(run_receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(run_receipt["schema"], promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA)
        self.assertTrue(run_receipt["passed"])
        self.assertEqual(
            run_receipt["promotion_artifact_audit_report_file"],
            str(report_path.resolve()),
        )
        artifact_names = {item["name"] for item in run_receipt["artifacts"]}
        self.assertIn("release_bundle", artifact_names)
        self.assertIn("release_approval", artifact_names)
        self.assertIn("release_receipt", artifact_names)
        self.assertIn("promotion_evidence", artifact_names)
        self.assertIn("promotion_audit_report", artifact_names)
        self.assertIn("rotation_rehearsal_report", artifact_names)
        self.assertIn("promotion_artifact_audit_report", artifact_names)
        for item in run_receipt["artifacts"]:
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")

    def test_run_promotion_artifact_audit_fails_when_rotation_pass_required_but_not_passed(self):
        root = self.make_case_root("promotion_artifacts_rotation_fail")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": {
                        "GITHUB_REPOSITORY": "acme/demo",
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_RUN_ID": "12345",
                    },
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        promotion_report = root / "promotion_audit_report.json"
        promotion_report.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-audit-report/v1",
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                    "inputs": {
                        "policy_file": str((root / "policy.json").resolve()),
                        "policy_sha256": "b" * 64,
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str((root / "workflow.yml").resolve()),
                        "workflow_sha256": "c" * 64,
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        rotation_report = root / "rotation_rehearsal_report.json"
        rotation_report.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-rotation-rehearsal/v1",
                    "requested": True,
                    "executed": True,
                    "old_key_rejected": True,
                    "status": "failed",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            require_rotation_pass=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(any("report.status is not 'passed'" in item for item in report["failures"]))

    def test_run_promotion_artifact_audit_requires_ci_context_match(self):
        root = self.make_case_root("promotion_artifacts_ci_context")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": {
                        "GITHUB_REPOSITORY": "acme/demo",
                        "GITHUB_REF": "refs/heads/release/x",
                        "GITHUB_RUN_ID": "99999",
                        "GITHUB_SHA": "cafebabe",
                    },
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        promotion_report = root / "promotion_audit_report.json"
        promotion_report.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-audit-report/v1",
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                    "inputs": {
                        "policy_file": str((root / "policy.json").resolve()),
                        "policy_sha256": "b" * 64,
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str((root / "workflow.yml").resolve()),
                        "workflow_sha256": "c" * 64,
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        rotation_report = root / "rotation_rehearsal_report.json"
        rotation_report.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-rotation-rehearsal/v1",
                    "requested": False,
                    "executed": False,
                    "old_key_rejected": None,
                    "status": "not-requested",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_REPOSITORY": "acme/demo",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_RUN_ID": "12345",
                "GITHUB_SHA": "deadbeef",
            },
            clear=False,
        ):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                require_ci_context_match=True,
                repo_root=root,
            )
        self.assertFalse(report["passed"])
        self.assertTrue(any("GITHUB_REF mismatch" in item for item in report["failures"]))
        self.assertTrue(any("GITHUB_RUN_ID mismatch" in item for item in report["failures"]))

    def test_run_promotion_artifact_audit_fails_when_promotion_report_digest_binding_mismatch(self):
        root = self.make_case_root("promotion_artifacts_report_binding_mismatch")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": {
                        "GITHUB_REPOSITORY": "acme/demo",
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_RUN_ID": "12345",
                    },
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        promotion_report = root / "promotion_audit_report.json"
        promotion_report.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-audit-report/v1",
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                    "inputs": {
                        "policy_file": str((root / "policy.json").resolve()),
                        "policy_sha256": "b" * 64,
                        "evidence_file": str((root / "different_promotion_evidence.json").resolve()),
                        "evidence_sha256": "a" * 64,
                        "workflow_file": str((root / "workflow.yml").resolve()),
                        "workflow_sha256": "c" * 64,
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        rotation_report = root / "rotation_rehearsal_report.json"
        rotation_report.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-rotation-rehearsal/v1",
                    "requested": False,
                    "executed": False,
                    "old_key_rejected": None,
                    "status": "not-requested",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(any("inputs.evidence_file mismatch" in item for item in report["failures"]))
        self.assertTrue(any("inputs.evidence_sha256 mismatch" in item for item in report["failures"]))


if __name__ == "__main__":
    unittest.main()
