import json
import shutil
import unittest
import uuid
import zipfile
from pathlib import Path

import encryption_helper
from enc2sop import promotion_artifacts
from enc2sop import promotion_bundle


TEST_ROOT = Path(__file__).resolve().parents[1]
TEST_RUNS_ROOT = TEST_ROOT / ".tmp_test_runs"


def _make_case_root(prefix):
    TEST_RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    root = TEST_RUNS_ROOT / "{}_{}".format(prefix, uuid.uuid4().hex[:8])
    root.mkdir(parents=True, exist_ok=False)
    return root


class PromotionBundleTests(unittest.TestCase):
    def make_case_root(self, prefix):
        root = _make_case_root(prefix)
        self.addCleanup(lambda: shutil.rmtree(str(root), ignore_errors=True))
        return root

    def _write_release_artifacts(
        self,
        release_dir,
        *,
        approval_key_id="ops-approval-main",
    ):
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
        approval_path = release_dir / "release_approval.json"
        receipt_payload = {
            "schema": encryption_helper.RELEASE_RECEIPT_SCHEMA,
            "release_bundle_relative_path": encryption_helper.RELEASE_BUNDLE_FILENAME,
            "release_bundle_sha256": encryption_helper._sha256_file(release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME),
            "release_approval_verified": True,
            "release_approval_sha256": encryption_helper._sha256_file(approval_path),
            "release_approval_key_id": approval_key_id,
            "release_approval_signature_digest": approval_payload["signature"]["digest_hex"],
            "runtime_artifacts_verified": 1,
            "native_artifacts_verified": 2,
        }
        (release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME).write_text(
            json.dumps(receipt_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _write_promotion_artifacts(self, root, *, include_policy=False):
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "repository": "acme/demo",
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        promotion_report_path = root / "promotion_audit_report.json"
        promotion_report_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-audit-report/v1",
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                    "inputs": {
                        "policy_file": str((root / "policy.json").resolve()),
                        "policy_sha256": "a" * 64,
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str((root / "workflow.yml").resolve()),
                        "workflow_sha256": "b" * 64,
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        rotation_path = root / "rotation_rehearsal_report.json"
        rotation_path.write_text(
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
        artifact_audit_path = root / promotion_artifacts.DEFAULT_REPORT_FILENAME
        artifact_audit_path.write_text(
            json.dumps(
                {
                    "schema": promotion_artifacts.PROMOTION_ARTIFACT_AUDIT_SCHEMA,
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        run_receipt_path = root / promotion_artifacts.DEFAULT_RUN_RECEIPT_FILENAME
        run_receipt_path.write_text(
            json.dumps(
                {
                    "schema": promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA,
                    "passed": True,
                    "rotation_pass_required": False,
                    "promotion_artifact_audit_report_file": str(artifact_audit_path.resolve()),
                    "artifacts": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        policy_path = None
        workflow_path = None
        if include_policy:
            policy_path = root / "policy.json"
            workflow_path = root / "workflow.yml"
            policy_path.write_text('{"schema":"enc2sop-promotion-policy/v1"}', encoding="utf-8")
            workflow_path.write_text("name: release-promotion-gate\n", encoding="utf-8")
        return (
            evidence_path,
            promotion_report_path,
            rotation_path,
            artifact_audit_path,
            run_receipt_path,
            policy_path,
            workflow_path,
        )

    def test_create_promotion_artifact_bundle_writes_expected_entries(self):
        root = self.make_case_root("promotion_bundle_pass")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        (
            evidence_path,
            promotion_report_path,
            rotation_path,
            artifact_audit_path,
            run_receipt_path,
            _policy_path,
            _workflow_path,
        ) = self._write_promotion_artifacts(root)

        bundle_path, manifest = promotion_bundle.create_promotion_artifact_bundle(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report_path),
            rotation_report_file=str(rotation_path),
            promotion_artifact_audit_report_file=str(artifact_audit_path),
            promotion_run_receipt_file=str(run_receipt_path),
            repo_root=root,
        )

        self.assertTrue(bundle_path.exists())
        self.assertEqual(manifest["schema"], promotion_bundle.PROMOTION_ARTIFACT_BUNDLE_SCHEMA)
        self.assertEqual(bundle_path.name, promotion_bundle.DEFAULT_BUNDLE_FILENAME)
        self.assertRegex(manifest["bundle_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(manifest["file_count"], 8)
        with zipfile.ZipFile(bundle_path, "r") as zipped:
            entries = set(zipped.namelist())
            self.assertIn("release/release_bundle.json", entries)
            self.assertIn("release/release_approval.json", entries)
            self.assertIn("release/release_receipt.json", entries)
            self.assertIn("ops/promotion_evidence.json", entries)
            self.assertIn("ops/promotion_audit_report.json", entries)
            self.assertIn("ops/rotation_rehearsal_report.json", entries)
            self.assertIn("ops/promotion_artifact_audit_report.json", entries)
            self.assertIn("ops/promotion_run_receipt.json", entries)
            self.assertIn("bundle_manifest.json", entries)
            manifest_payload = json.loads(zipped.read("bundle_manifest.json").decode("utf-8"))
            self.assertEqual(manifest_payload["schema"], promotion_bundle.PROMOTION_ARTIFACT_BUNDLE_SCHEMA)
            manifest_names = {item["name"] for item in manifest_payload["files"]}
            self.assertIn("release_bundle", manifest_names)
            self.assertIn("promotion_run_receipt", manifest_names)

    def test_create_promotion_artifact_bundle_includes_policy_and_workflow_when_provided(self):
        root = self.make_case_root("promotion_bundle_with_policy")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        (
            evidence_path,
            promotion_report_path,
            rotation_path,
            artifact_audit_path,
            run_receipt_path,
            policy_path,
            workflow_path,
        ) = self._write_promotion_artifacts(root, include_policy=True)

        bundle_path, manifest = promotion_bundle.create_promotion_artifact_bundle(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report_path),
            rotation_report_file=str(rotation_path),
            promotion_artifact_audit_report_file=str(artifact_audit_path),
            promotion_run_receipt_file=str(run_receipt_path),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            repo_root=root,
        )

        self.assertTrue(bundle_path.exists())
        self.assertEqual(manifest["file_count"], 10)
        with zipfile.ZipFile(bundle_path, "r") as zipped:
            entries = set(zipped.namelist())
            self.assertIn("policy/promotion_rollout_policy.json", entries)
            self.assertIn("workflow/release_promotion.yml", entries)

    def test_create_promotion_artifact_bundle_fails_when_promotion_report_is_not_passed(self):
        root = self.make_case_root("promotion_bundle_promotion_report_fail")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        (
            evidence_path,
            promotion_report_path,
            rotation_path,
            artifact_audit_path,
            run_receipt_path,
            _policy_path,
            _workflow_path,
        ) = self._write_promotion_artifacts(root)
        promotion_report_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-audit-report/v1",
                    "passed": False,
                    "summary": {"total_failures": 1},
                    "failures": ["missing branch evidence for 'main'"],
                    "inputs": {
                        "policy_file": str((root / "policy.json").resolve()),
                        "policy_sha256": "a" * 64,
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str((root / "workflow.yml").resolve()),
                        "workflow_sha256": "b" * 64,
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(promotion_bundle.PromotionArtifactBundleError, "promotion audit report must be passed=true"):
            promotion_bundle.create_promotion_artifact_bundle(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report_path),
                rotation_report_file=str(rotation_path),
                promotion_artifact_audit_report_file=str(artifact_audit_path),
                promotion_run_receipt_file=str(run_receipt_path),
                repo_root=root,
            )

    def test_create_promotion_artifact_bundle_fails_when_audit_report_is_not_passed(self):
        root = self.make_case_root("promotion_bundle_audit_fail")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        (
            evidence_path,
            promotion_report_path,
            rotation_path,
            artifact_audit_path,
            run_receipt_path,
            _policy_path,
            _workflow_path,
        ) = self._write_promotion_artifacts(root)
        artifact_audit_path.write_text(
            json.dumps(
                {
                    "schema": promotion_artifacts.PROMOTION_ARTIFACT_AUDIT_SCHEMA,
                    "passed": False,
                    "summary": {"total_failures": 1},
                    "failures": ["gate failed"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(promotion_bundle.PromotionArtifactBundleError, "must be passed=true"):
            promotion_bundle.create_promotion_artifact_bundle(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report_path),
                rotation_report_file=str(rotation_path),
                promotion_artifact_audit_report_file=str(artifact_audit_path),
                promotion_run_receipt_file=str(run_receipt_path),
                repo_root=root,
            )

    def test_create_promotion_artifact_bundle_fails_when_run_receipt_is_not_passed(self):
        root = self.make_case_root("promotion_bundle_receipt_fail")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        (
            evidence_path,
            promotion_report_path,
            rotation_path,
            artifact_audit_path,
            run_receipt_path,
            _policy_path,
            _workflow_path,
        ) = self._write_promotion_artifacts(root)
        run_receipt_path.write_text(
            json.dumps(
                {
                    "schema": promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA,
                    "passed": False,
                    "rotation_pass_required": False,
                    "promotion_artifact_audit_report_file": str(artifact_audit_path.resolve()),
                    "artifacts": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(promotion_bundle.PromotionArtifactBundleError, "must be passed=true"):
            promotion_bundle.create_promotion_artifact_bundle(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report_path),
                rotation_report_file=str(rotation_path),
                promotion_artifact_audit_report_file=str(artifact_audit_path),
                promotion_run_receipt_file=str(run_receipt_path),
                repo_root=root,
            )


if __name__ == "__main__":
    unittest.main()
