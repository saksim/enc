import base64
import hashlib
import hmac
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

    def _write_release_artifacts(self, release_dir, *, approval_key_id="ops-approval-main", approval_github_context=None):
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
        if approval_github_context is not None:
            approval_payload["github_context"] = dict(approval_github_context)
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
            "release_approval_github_context": dict(approval_github_context) if approval_github_context is not None else None,
            "runtime_artifacts_verified": 1,
            "native_artifacts_verified": 2,
        }
        (release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME).write_text(
            json.dumps(receipt_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _sign_release_approval(self, release_dir, key_bytes):
        approval_path = release_dir / "release_approval.json"
        payload = json.loads(approval_path.read_text(encoding="utf-8"))
        signed_payload = dict(payload)
        signed_payload.pop("signature", None)
        digest_hex = hmac.new(
            key_bytes,
            encryption_helper._canonical_json_bytes(signed_payload),
            hashlib.sha256,
        ).hexdigest()
        payload["signature"]["digest_hex"] = digest_hex
        approval_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        receipt_path = release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["release_approval_sha256"] = encryption_helper._sha256_file(approval_path)
            receipt["release_approval_signature_digest"] = digest_hex
            receipt_path.write_text(
                json.dumps(receipt, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

    def _write_policy_and_workflow(self, root, *, policy_name="policy.json", workflow_name="workflow.yml"):
        policy_path = root / policy_name
        workflow_path = root / workflow_name
        workflow_path.write_text(
            "name: release-promotion-gate\npython ./soenc.py promotion-dry-run\n",
            encoding="utf-8",
        )
        policy_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-policy/v1",
                    "required_branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "required_environments": [{"name": "production-promotion", "min_required_reviewers": 1}],
                    "required_secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                    "workflow": {
                        "relative_path": workflow_name,
                        "required_fragments": ["python ./soenc.py promotion-dry-run"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return policy_path, workflow_path

    def _build_run_receipt_payload(
        self,
        *,
        release_dir,
        evidence_path,
        promotion_report_path,
        rotation_report_path,
        report_path,
        passed=True,
        rotation_pass_required=False,
        github_context=None,
    ):
        artifact_paths = [
            ("release_bundle", release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME),
            ("release_approval", release_dir / "release_approval.json"),
            ("release_receipt", release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME),
            ("promotion_evidence", evidence_path),
            ("promotion_audit_report", promotion_report_path),
            ("rotation_rehearsal_report", rotation_report_path),
            ("promotion_artifact_audit_report", report_path),
        ]
        artifacts = []
        for name, path in artifact_paths:
            artifacts.append(
                {
                    "name": name,
                    "path": str(path.resolve()),
                    "sha256": encryption_helper._sha256_file(path),
                }
            )
        return {
            "schema": promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA,
            "generated_at_utc": "2026-05-11T00:00:00Z",
            "passed": bool(passed),
            "rotation_pass_required": bool(rotation_pass_required),
            "promotion_artifact_audit_report_file": str(report_path.resolve()),
            "github_context": github_context if github_context is not None else {},
            "artifacts": artifacts,
        }

    def test_run_promotion_artifact_audit_passes_with_valid_artifacts(self):
        root = self.make_case_root("promotion_artifacts_pass")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            repo_root=root,
        )

        self.assertTrue(report_path.exists())
        self.assertEqual(report["schema"], "enc2sop-promotion-artifact-audit/v1")
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["total_failures"], 0)
        self.assertEqual(report["promotion_policy_file"], str(policy_path.resolve()))
        self.assertEqual(report["promotion_workflow_file"], str(workflow_path.resolve()))
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

    def test_run_promotion_artifact_audit_verifies_release_approval_signature_with_key(self):
        root = self.make_case_root("promotion_artifacts_approval_signature_key_pass")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        approval_key = b"ci-approval-key-v1"
        self._sign_release_approval(release_dir, approval_key)
        approval_key_b64 = base64.b64encode(approval_key).decode("ascii")

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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            release_approval_key_b64=approval_key_b64,
            release_approval_key_id="ops-approval-main",
            require_release_approval_signature=True,
            repo_root=root,
        )
        self.assertTrue(report["passed"])

    def test_run_promotion_artifact_audit_fails_when_release_approval_signature_key_mismatches(self):
        root = self.make_case_root("promotion_artifacts_approval_signature_key_fail")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        approval_key = b"ci-approval-key-v1"
        self._sign_release_approval(release_dir, approval_key)
        wrong_key_b64 = base64.b64encode(b"wrong-approval-key").decode("ascii")

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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            release_approval_key_b64=wrong_key_b64,
            require_release_approval_signature=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "release_approval.signature.digest_hex does not match provided approval verification key" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_release_approval_signature_required_without_key(self):
        root = self.make_case_root("promotion_artifacts_approval_signature_missing_key")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_release_approval_signature=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "release approval verification key is required when --require-release-approval-signature is enabled"
                in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_release_receipt_approval_digest_is_stale(self):
        root = self.make_case_root("promotion_artifacts_receipt_approval_digest_stale")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        receipt_path = release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME
        receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt_payload["release_approval_sha256"] = "0" * 64
        receipt_path.write_text(
            json.dumps(receipt_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            repo_root=root,
        )

        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "release_receipt.release_approval_sha256 does not match release_approval.json" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_rotation_pass_required_but_not_passed(self):
        root = self.make_case_root("promotion_artifacts_rotation_fail")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
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
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": {
                        "GITHUB_REPOSITORY": "acme/demo",
                        "GITHUB_REF": "refs/heads/release/x",
                        "GITHUB_RUN_ID": "99999",
                        "GITHUB_RUN_ATTEMPT": "2",
                        "GITHUB_SHA": "cafebabe",
                        "GITHUB_WORKFLOW": "release-promotion-gate-other",
                        "GITHUB_EVENT_NAME": "workflow_dispatch",
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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_SHA": "deadbeef",
                "GITHUB_WORKFLOW": "release-promotion-gate",
                "GITHUB_EVENT_NAME": "push",
            },
            clear=False,
        ):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                require_ci_context_match=True,
                repo_root=root,
            )
        self.assertFalse(report["passed"])
        self.assertTrue(any("GITHUB_REF mismatch" in item for item in report["failures"]))
        self.assertTrue(any("GITHUB_RUN_ID mismatch" in item for item in report["failures"]))
        self.assertTrue(any("GITHUB_RUN_ATTEMPT mismatch" in item for item in report["failures"]))
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_run_id missing" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_run_attempt missing" in item for item in report["failures"])
        )
        self.assertTrue(
            any("promotion_evidence.github_context.GITHUB_WORKFLOW mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("promotion_evidence.github_context.GITHUB_EVENT_NAME mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_name missing" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_event missing" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_ci_context_match_accepts_matching_rotation_metadata(self):
        root = self.make_case_root("promotion_artifacts_rotation_context_match_pass")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_SHA": "deadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_EVENT_NAME": "push",
        }
        self._write_release_artifacts(release_dir, approval_github_context=github_context)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": github_context,
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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_ref": "refs/heads/main",
                    "workflow_sha": "deadbeef",
                    "workflow_name": "release-promotion-gate",
                    "workflow_event": "push",
                    "requested": True,
                    "executed": True,
                    "old_key_rejected": True,
                    "status": "passed",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with mock.patch.dict(
            os.environ,
            github_context,
            clear=False,
        ):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                require_ci_context_match=True,
                require_rotation_pass=True,
                repo_root=root,
            )
        self.assertTrue(report["passed"])

    def test_run_promotion_artifact_audit_fails_when_rotation_context_metadata_mismatches(self):
        root = self.make_case_root("promotion_artifacts_rotation_context_mismatch")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "deadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_EVENT_NAME": "push",
        }
        self._write_release_artifacts(release_dir, approval_github_context=github_context)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": github_context,
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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "999",
                    "workflow_ref": "refs/heads/release/legacy",
                    "workflow_sha": "cafebabe",
                    "workflow_name": "release-promotion-gate",
                    "workflow_event": "workflow_dispatch",
                    "requested": True,
                    "executed": True,
                    "old_key_rejected": True,
                    "status": "passed",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with mock.patch.dict(
            os.environ,
            github_context,
            clear=False,
        ):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                require_ci_context_match=True,
                require_rotation_pass=True,
                repo_root=root,
            )
        self.assertFalse(report["passed"])
        self.assertTrue(any("rotation_rehearsal_report.workflow_ref mismatch" in item for item in report["failures"]))
        self.assertTrue(any("rotation_rehearsal_report.workflow_sha mismatch" in item for item in report["failures"]))
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_run_attempt mismatch" in item for item in report["failures"])
        )
        self.assertTrue(any("rotation_rehearsal_report.workflow_event mismatch" in item for item in report["failures"]))

    def test_run_promotion_artifact_audit_fails_when_release_approval_context_mismatches(self):
        root = self.make_case_root("promotion_artifacts_approval_context_mismatch")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(
            release_dir,
            approval_github_context={
                "GITHUB_REPOSITORY": "acme/demo",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_RUN_ID": "12345",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_SHA": "deadbeef",
                "GITHUB_WORKFLOW": "release-promotion-gate-other",
                "GITHUB_EVENT_NAME": "push",
            },
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": {
                        "GITHUB_REPOSITORY": "acme/demo",
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_RUN_ID": "12345",
                        "GITHUB_RUN_ATTEMPT": "3",
                        "GITHUB_SHA": "deadbeef",
                        "GITHUB_WORKFLOW": "release-promotion-gate",
                        "GITHUB_EVENT_NAME": "push",
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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_ref": "refs/heads/main",
                    "workflow_sha": "deadbeef",
                    "workflow_name": "release-promotion-gate",
                    "workflow_event": "push",
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
                "GITHUB_RUN_ATTEMPT": "3",
                "GITHUB_SHA": "deadbeef",
                "GITHUB_WORKFLOW": "release-promotion-gate",
                "GITHUB_EVENT_NAME": "push",
            },
            clear=False,
        ):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                require_ci_context_match=True,
                repo_root=root,
            )

        self.assertFalse(report["passed"])
        self.assertTrue(
            any("release_approval.github_context.GITHUB_RUN_ATTEMPT mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_approval.github_context.GITHUB_WORKFLOW mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context.GITHUB_WORKFLOW mismatch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_promotion_report_digest_binding_mismatch(self):
        root = self.make_case_root("promotion_artifacts_report_binding_mismatch")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str((root / "different_promotion_evidence.json").resolve()),
                        "evidence_sha256": "a" * 64,
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(any("inputs.evidence_file mismatch" in item for item in report["failures"]))
        self.assertTrue(any("inputs.evidence_sha256 mismatch" in item for item in report["failures"]))

    def test_run_promotion_artifact_audit_fails_when_policy_digest_binding_mismatch(self):
        root = self.make_case_root("promotion_artifacts_policy_binding_mismatch")
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
        policy_path = root / "policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-policy/v1",
                    "required_branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "required_environments": [{"name": "production-promotion", "min_required_reviewers": 1}],
                    "required_secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                    "workflow": {
                        "relative_path": ".github/workflows/release_promotion.yml",
                        "required_fragments": ["python ./soenc.py promotion-dry-run"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        workflow_path = root / "workflow.yml"
        workflow_path.write_text(
            "name: release-promotion-gate\npython ./soenc.py promotion-dry-run\n",
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
                        "policy_file": str((root / "different_policy.json").resolve()),
                        "policy_sha256": "f" * 64,
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(any("inputs.policy_file mismatch" in item for item in report["failures"]))
        self.assertTrue(any("inputs.policy_sha256 mismatch" in item for item in report["failures"]))

    def test_run_promotion_artifact_audit_fails_when_workflow_digest_binding_mismatch(self):
        root = self.make_case_root("promotion_artifacts_workflow_binding_mismatch")
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
        policy_path = root / "policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-policy/v1",
                    "required_branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "required_environments": [{"name": "production-promotion", "min_required_reviewers": 1}],
                    "required_secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                    "workflow": {
                        "relative_path": ".github/workflows/release_promotion.yml",
                        "required_fragments": ["python ./soenc.py promotion-dry-run"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        workflow_path = root / "workflow.yml"
        workflow_path.write_text(
            "name: release-promotion-gate\npython ./soenc.py promotion-dry-run\n",
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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str((root / "different_workflow.yml").resolve()),
                        "workflow_sha256": "f" * 64,
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(any("inputs.workflow_file mismatch" in item for item in report["failures"]))
        self.assertTrue(any("inputs.workflow_sha256 mismatch" in item for item in report["failures"]))

    def test_run_promotion_artifact_audit_accepts_existing_matching_run_receipt(self):
        root = self.make_case_root("promotion_artifacts_existing_run_receipt_pass")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
        report_path = root / promotion_artifacts.DEFAULT_REPORT_FILENAME
        report_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-artifact-audit/v1",
                    "generated_at_utc": "2026-05-11T00:00:00Z",
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        run_receipt = root / promotion_artifacts.DEFAULT_RUN_RECEIPT_FILENAME
        run_receipt.write_text(
            json.dumps(
                self._build_run_receipt_payload(
                    release_dir=release_dir,
                    evidence_path=evidence_path,
                    promotion_report_path=promotion_report,
                    rotation_report_path=rotation_report,
                    report_path=report_path,
                ),
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
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            report_file=str(report_path),
            run_receipt_file=str(run_receipt),
            repo_root=root,
        )
        self.assertTrue(report["passed"])
        updated_receipt = json.loads(run_receipt.read_text(encoding="utf-8"))
        self.assertEqual(updated_receipt["schema"], promotion_artifacts.PROMOTION_RUN_RECEIPT_SCHEMA)
        self.assertEqual(
            updated_receipt["promotion_artifact_audit_report_file"],
            str(report_path.resolve()),
        )

    def test_run_promotion_artifact_audit_fails_with_tampered_existing_run_receipt(self):
        root = self.make_case_root("promotion_artifacts_existing_run_receipt_fail")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
        report_path = root / promotion_artifacts.DEFAULT_REPORT_FILENAME
        report_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-artifact-audit/v1",
                    "generated_at_utc": "2026-05-11T00:00:00Z",
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        payload = self._build_run_receipt_payload(
            release_dir=release_dir,
            evidence_path=evidence_path,
            promotion_report_path=promotion_report,
            rotation_report_path=rotation_report,
            report_path=report_path,
        )
        payload["artifacts"][0]["sha256"] = "f" * 64
        run_receipt = root / promotion_artifacts.DEFAULT_RUN_RECEIPT_FILENAME
        run_receipt.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            report_file=str(report_path),
            run_receipt_file=str(run_receipt),
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any("promotion_run_receipt.artifacts[release_bundle].sha256 mismatch" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_ci_context_match_accepts_existing_matching_run_receipt(self):
        root = self.make_case_root("promotion_artifacts_existing_run_receipt_ci_context_pass")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_SHA": "deadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_EVENT_NAME": "push",
        }
        self._write_release_artifacts(release_dir, approval_github_context=github_context)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": github_context,
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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_sha": "deadbeef",
                    "workflow_ref": "refs/heads/main",
                    "workflow_name": "release-promotion-gate",
                    "workflow_event": "push",
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
        report_path = root / promotion_artifacts.DEFAULT_REPORT_FILENAME
        report_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-artifact-audit/v1",
                    "generated_at_utc": "2026-05-11T00:00:00Z",
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        run_receipt = root / promotion_artifacts.DEFAULT_RUN_RECEIPT_FILENAME
        run_receipt.write_text(
            json.dumps(
                self._build_run_receipt_payload(
                    release_dir=release_dir,
                    evidence_path=evidence_path,
                    promotion_report_path=promotion_report,
                    rotation_report_path=rotation_report,
                    report_path=report_path,
                    github_context=github_context,
                ),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with mock.patch.dict(
            os.environ,
            github_context,
            clear=False,
        ):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                report_file=str(report_path),
                run_receipt_file=str(run_receipt),
                require_ci_context_match=True,
                repo_root=root,
            )
        self.assertTrue(report["passed"])

    def test_run_promotion_artifact_audit_ci_context_match_fails_with_existing_run_receipt_attempt_mismatch(self):
        root = self.make_case_root("promotion_artifacts_existing_run_receipt_ci_context_fail")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_SHA": "deadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_EVENT_NAME": "push",
        }
        self._write_release_artifacts(release_dir, approval_github_context=github_context)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": github_context,
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
                        "policy_file": str(policy_path.resolve()),
                        "policy_sha256": encryption_helper._sha256_file(policy_path),
                        "evidence_file": str(evidence_path.resolve()),
                        "evidence_sha256": encryption_helper._sha256_file(evidence_path),
                        "workflow_file": str(workflow_path.resolve()),
                        "workflow_sha256": encryption_helper._sha256_file(workflow_path),
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
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_sha": "deadbeef",
                    "workflow_ref": "refs/heads/main",
                    "workflow_name": "release-promotion-gate",
                    "workflow_event": "push",
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
        report_path = root / promotion_artifacts.DEFAULT_REPORT_FILENAME
        report_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-artifact-audit/v1",
                    "generated_at_utc": "2026-05-11T00:00:00Z",
                    "passed": True,
                    "summary": {"total_failures": 0},
                    "failures": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        run_receipt = root / promotion_artifacts.DEFAULT_RUN_RECEIPT_FILENAME
        run_receipt.write_text(
            json.dumps(
                self._build_run_receipt_payload(
                    release_dir=release_dir,
                    evidence_path=evidence_path,
                    promotion_report_path=promotion_report,
                    rotation_report_path=rotation_report,
                    report_path=report_path,
                    github_context={
                        "GITHUB_REPOSITORY": "acme/demo",
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_RUN_ID": "12345",
                        "GITHUB_RUN_ATTEMPT": "2",
                        "GITHUB_SHA": "deadbeef",
                        "GITHUB_WORKFLOW": "release-promotion-gate-other",
                        "GITHUB_EVENT_NAME": "push",
                    },
                ),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with mock.patch.dict(
            os.environ,
            github_context,
            clear=False,
        ):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                report_file=str(report_path),
                run_receipt_file=str(run_receipt),
                require_ci_context_match=True,
                repo_root=root,
            )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context.GITHUB_RUN_ATTEMPT mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context.GITHUB_WORKFLOW mismatch" in item
                for item in report["failures"]
            )
        )


if __name__ == "__main__":
    unittest.main()
