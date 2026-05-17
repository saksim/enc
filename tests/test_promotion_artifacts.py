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

    def _write_release_artifacts(
        self,
        release_dir,
        *,
        approval_key_id="ops-approval-main",
        approval_github_context=None,
        release_github_context=None,
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
        if approval_github_context is not None:
            approval_payload["github_context"] = dict(approval_github_context)
        (release_dir / "release_approval.json").write_text(
            json.dumps(approval_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        approval_path = release_dir / "release_approval.json"
        receipt_payload = {
            "schema": encryption_helper.RELEASE_RECEIPT_SCHEMA,
            "github_context": dict(release_github_context) if release_github_context is not None else None,
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
                        "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
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
                        "GITHUB_ACTIONS": "false",
                        "CI": "false",
            "RUNNER_ENVIRONMENT": "self-hosted",
                        "RUNNER_OS": "Windows",
                        "RUNNER_ARCH": "ARM64",
            "RUNNER_NAME": "runner-arm64",
                        "GITHUB_RUN_ID": "99999",
                        "GITHUB_RUN_ATTEMPT": "2",
                        "GITHUB_SHA": "cafebabecafebabecafebabecafebabecafebabe",
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
                "GITHUB_ACTIONS": "true",
                "CI": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
                "GITHUB_RUN_ID": "12345",
                "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
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
        self.assertTrue(any("GITHUB_ACTIONS mismatch" in item for item in report["failures"]))
        self.assertTrue(any(".CI mismatch" in item for item in report["failures"]))
        self.assertTrue(any(".RUNNER_ENVIRONMENT mismatch" in item for item in report["failures"]))
        self.assertTrue(any(".RUNNER_OS mismatch" in item for item in report["failures"]))
        self.assertTrue(any(".RUNNER_ARCH mismatch" in item for item in report["failures"]))
        self.assertTrue(any(".RUNNER_NAME mismatch" in item for item in report["failures"]))
        self.assertTrue(any("GITHUB_RUN_ID mismatch" in item for item in report["failures"]))
        self.assertTrue(any("GITHUB_RUN_ATTEMPT mismatch" in item for item in report["failures"]))
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_run_id missing" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_run_attempt missing" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_runner_environment missing" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_runner_os missing" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_runner_arch missing" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_runner_name missing" in item for item in report["failures"])
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
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "12",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "12",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_EVENT_NAME": "push",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
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
                    "workflow_repository": "other/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "999",
                    "workflow_ref": "refs/heads/release/legacy",
                    "workflow_sha": "cafebabecafebabecafebabecafebabecafebabe",
                    "workflow_github_actions": "false",
                    "workflow_ci": "false",
                    "workflow_runner_environment": "self-hosted",
                    "workflow_runner_os": "Windows",
                    "workflow_runner_arch": "ARM64",
                    "workflow_runner_name": "runner-arm64",
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
        self.assertTrue(any("rotation_rehearsal_report.workflow_repository mismatch" in item for item in report["failures"]))
        self.assertTrue(any("rotation_rehearsal_report.workflow_sha mismatch" in item for item in report["failures"]))
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_github_actions mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_ci mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_runner_environment mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_runner_os mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_runner_arch mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_runner_name mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("rotation_rehearsal_report.workflow_run_attempt mismatch" in item for item in report["failures"])
        )
        self.assertTrue(any("rotation_rehearsal_report.workflow_event mismatch" in item for item in report["failures"]))

    def test_run_promotion_artifact_audit_ci_context_match_accepts_normalized_rotation_values(self):
        root = self.make_case_root("promotion_artifacts_rotation_context_normalized_pass")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "03",
                    "workflow_run_number": "011",
                    "workflow_retention_days": "090",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "BRANCH",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "TRUE",
                    "workflow_ci": "ON",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "042",
                    "workflow_repository_id": "04242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "0424242",
                    "workflow_ref_protected": "YES",
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
                repo_root=root,
            )
        self.assertTrue(report["passed"])

    def test_run_promotion_artifact_audit_fails_when_rotation_context_values_invalid(self):
        root = self.make_case_root("promotion_artifacts_rotation_context_invalid_value_fail")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "run-12345",
                    "workflow_run_attempt": "attempt-3",
                    "workflow_run_number": "1st",
                    "workflow_retention_days": "thirty",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "pull_request",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "sometimes",
                    "workflow_ci": "maybe",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "actor42",
                    "workflow_repository_id": "repo-4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "owner-424242",
                    "workflow_ref_protected": "protected",
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
                repo_root=root,
            )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_run_id invalid value for CI context key GITHUB_RUN_ID"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_run_attempt invalid value for CI context key GITHUB_RUN_ATTEMPT"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_run_number invalid value for CI context key GITHUB_RUN_NUMBER"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_retention_days invalid value for CI context key GITHUB_RETENTION_DAYS"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_ref_type invalid value for CI context key GITHUB_REF_TYPE"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_github_actions invalid value for CI context key GITHUB_ACTIONS"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_ci invalid value for CI context key CI"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_actor_id invalid value for CI context key GITHUB_ACTOR_ID"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_repository_id invalid value for CI context key GITHUB_REPOSITORY_ID"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_repository_owner_id invalid value for CI context key GITHUB_REPOSITORY_OWNER_ID"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_ref_protected invalid value for CI context key GITHUB_REF_PROTECTED"
                in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_ref_protected_missing_from_context_artifacts(self):
        root = self.make_case_root("promotion_artifacts_ref_protected_missing")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        approval_context = dict(github_context)
        approval_context.pop("GITHUB_REF_PROTECTED")
        release_context = dict(github_context)
        release_context.pop("GITHUB_REF_PROTECTED")
        self._write_release_artifacts(
            release_dir,
            approval_github_context=approval_context,
            release_github_context=release_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_context = dict(github_context)
        evidence_context.pop("GITHUB_REF_PROTECTED")
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
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
        run_receipt_context = dict(github_context)
        run_receipt_context.pop("GITHUB_REF_PROTECTED")
        run_receipt.write_text(
            json.dumps(
                self._build_run_receipt_payload(
                    release_dir=release_dir,
                    evidence_path=evidence_path,
                    promotion_report_path=promotion_report,
                    rotation_report_path=rotation_report,
                    report_path=report_path,
                    github_context=run_receipt_context,
                ),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with mock.patch.dict(os.environ, github_context, clear=False):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                run_receipt_file=str(run_receipt),
                require_ci_context_match=True,
                repo_root=root,
            )

        self.assertFalse(report["passed"])
        self.assertTrue(
            any("promotion_evidence.github_context missing required key: GITHUB_REF_PROTECTED" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_approval.github_context missing required key: GITHUB_REF_PROTECTED" in item for item in report["failures"])
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context missing required key: GITHUB_REF_PROTECTED" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any("release_receipt.github_context missing required key: GITHUB_REF_PROTECTED" in item for item in report["failures"])
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_ref_protected missing for CI context key GITHUB_REF_PROTECTED" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any("promotion_run_receipt.github_context missing required key: GITHUB_REF_PROTECTED" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_triggering_actor_missing_from_context_artifacts(self):
        root = self.make_case_root("promotion_artifacts_triggering_actor_missing")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        approval_context = dict(github_context)
        approval_context.pop("GITHUB_TRIGGERING_ACTOR")
        release_context = dict(github_context)
        release_context.pop("GITHUB_TRIGGERING_ACTOR")
        self._write_release_artifacts(
            release_dir,
            approval_github_context=approval_context,
            release_github_context=release_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_context = dict(github_context)
        evidence_context.pop("GITHUB_TRIGGERING_ACTOR")
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
        run_receipt_context = dict(github_context)
        run_receipt_context.pop("GITHUB_TRIGGERING_ACTOR")
        run_receipt.write_text(
            json.dumps(
                self._build_run_receipt_payload(
                    release_dir=release_dir,
                    evidence_path=evidence_path,
                    promotion_report_path=promotion_report,
                    rotation_report_path=rotation_report,
                    report_path=report_path,
                    github_context=run_receipt_context,
                ),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with mock.patch.dict(os.environ, github_context, clear=False):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                run_receipt_file=str(run_receipt),
                require_ci_context_match=True,
                repo_root=root,
            )

        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context missing required key: GITHUB_TRIGGERING_ACTOR" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_approval.github_context missing required key: GITHUB_TRIGGERING_ACTOR" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context missing required key: GITHUB_TRIGGERING_ACTOR" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.github_context missing required key: GITHUB_TRIGGERING_ACTOR" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_triggering_actor missing for CI context key GITHUB_TRIGGERING_ACTOR"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context missing required key: GITHUB_TRIGGERING_ACTOR" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_ref_protected_value_is_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_ref_protected_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_REF_PROTECTED"] = "maybe"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_REF_PROTECTED" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_ci_boolean_keys_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_ci_boolean_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_ACTIONS"] = "sometimes"
        invalid_runtime_context["CI"] = "maybe"
        invalid_runtime_context["GITHUB_RETENTION_DAYS"] = ""
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_ACTIONS" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: CI" in item for item in report["failures"])
        )
        self.assertTrue(
            any("missing runtime GitHub context key for CI match: GITHUB_RETENTION_DAYS" in item for item in report["failures"])
        )

        invalid_runtime_context_semantic = dict(github_context)
        invalid_runtime_context_semantic["GITHUB_ACTIONS"] = "false"
        invalid_runtime_context_semantic["CI"] = "0"
        with mock.patch.dict(os.environ, invalid_runtime_context_semantic, clear=False):
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
            any(
                "runtime GitHub context.GITHUB_ACTIONS must be true in GitHub Actions CI context" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "runtime GitHub context.CI must be true in GitHub Actions CI context" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_numeric_or_ref_type_values_are_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_numeric_ref_type_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_RUN_ID"] = "run-12345"
        invalid_runtime_context["GITHUB_RUN_ATTEMPT"] = "3rd"
        invalid_runtime_context["GITHUB_ACTOR_ID"] = "actor42"
        invalid_runtime_context["GITHUB_REF_TYPE"] = "head"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_RUN_ID" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_RUN_ATTEMPT" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_ACTOR_ID" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_REF_TYPE" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_runner_values_are_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_runner_values_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["RUNNER_ENVIRONMENT"] = "dedicated"
        invalid_runtime_context["RUNNER_OS"] = "BSD"
        invalid_runtime_context["RUNNER_ARCH"] = "riscv64"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: RUNNER_ENVIRONMENT" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: RUNNER_OS" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: RUNNER_ARCH" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_text_binding_values_have_whitespace(self):
        root = self.make_case_root("promotion_artifacts_runtime_text_whitespace_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_EVENT_NAME"] = " push"
        invalid_runtime_context["GITHUB_WORKFLOW"] = "release-promotion-gate "
        invalid_runtime_context["GITHUB_JOB"] = " promotion-gate "
        invalid_runtime_context["GITHUB_ACTOR"] = " octocat "
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_EVENT_NAME" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_WORKFLOW" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_JOB" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_ACTOR" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_sha_values_are_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_sha_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_SHA"] = "sha-deadbeef"
        invalid_runtime_context["GITHUB_WORKFLOW_SHA"] = "facefeed"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SHA" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_WORKFLOW_SHA" in item for item in report["failures"])
        )

        invalid_runtime_context_whitespace_sha = dict(github_context)
        invalid_runtime_context_whitespace_sha["GITHUB_SHA"] = " deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        invalid_runtime_context_whitespace_sha["GITHUB_WORKFLOW_SHA"] = "facefeedfacefeedfacefeedfacefeedfacefeed "
        with mock.patch.dict(os.environ, invalid_runtime_context_whitespace_sha, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SHA" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_WORKFLOW_SHA" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_workflow_ref_is_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_workflow_ref_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_workflow_ref_values = (
            "acme/demo/.github/workflows/release_promotion.yml",
            "acme/demo/.github/workflows/./release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/sub/../release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/sub\\release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/%2e/release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/sub/%2e%2e/release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/release%5Fpromotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/release%2epromotion.yml@refs/heads/main",
            " acme/demo/.github/workflows/release_promotion.yml@refs/heads/main ",
        )
        for invalid_workflow_ref in invalid_workflow_ref_values:
            invalid_runtime_context = dict(github_context)
            invalid_runtime_context["GITHUB_WORKFLOW_REF"] = invalid_workflow_ref
            with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
                any(
                    "invalid runtime GitHub context key for CI match: GITHUB_WORKFLOW_REF" in item
                    for item in report["failures"]
                )
            )

    def test_run_promotion_artifact_audit_fails_when_runtime_workflow_ref_repository_slug_is_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_workflow_ref_repository_slug_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_WORKFLOW_REF"] = (
            "acme/demo/extra/.github/workflows/release_promotion.yml@refs/heads/main"
        )
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_WORKFLOW_REF" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_url_values_are_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_urls_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_SERVER_URL"] = "github.com"
        invalid_runtime_context["GITHUB_API_URL"] = "api.github.com"
        invalid_runtime_context["GITHUB_GRAPHQL_URL"] = "ssh://api.github.com/graphql"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SERVER_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_API_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL" in item for item in report["failures"])
        )

        invalid_runtime_context_canonical = dict(github_context)
        invalid_runtime_context_canonical["GITHUB_SERVER_URL"] = "https://github.com."
        invalid_runtime_context_canonical["GITHUB_API_URL"] = "https://api.github.com:443"
        invalid_runtime_context_canonical["GITHUB_GRAPHQL_URL"] = "https://API.GitHub.com/graphql"
        with mock.patch.dict(os.environ, invalid_runtime_context_canonical, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SERVER_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_API_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL" in item for item in report["failures"])
        )

        invalid_runtime_context_semantic = dict(github_context)
        invalid_runtime_context_semantic["GITHUB_SERVER_URL"] = "https://github.com"
        invalid_runtime_context_semantic["GITHUB_API_URL"] = "https://github.com/api/v3"
        invalid_runtime_context_semantic["GITHUB_GRAPHQL_URL"] = "https://github.com/api/graphql"
        with mock.patch.dict(os.environ, invalid_runtime_context_semantic, clear=False):
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
            any(
                "runtime GitHub context.GITHUB_API_URL host mismatch for github.com server: expected api.github.com"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "runtime GitHub context.GITHUB_API_URL path mismatch for github.com server: expected /, got /api/v3"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "runtime GitHub context.GITHUB_GRAPHQL_URL path mismatch for github.com server: expected /graphql, got /api/graphql"
                in item
                for item in report["failures"]
            )
        )

        invalid_runtime_context_http_scheme = dict(github_context)
        invalid_runtime_context_http_scheme["GITHUB_SERVER_URL"] = "http://github.com"
        invalid_runtime_context_http_scheme["GITHUB_API_URL"] = "http://api.github.com"
        invalid_runtime_context_http_scheme["GITHUB_GRAPHQL_URL"] = "http://api.github.com/graphql"
        with mock.patch.dict(os.environ, invalid_runtime_context_http_scheme, clear=False):
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
            any(
                "invalid runtime GitHub context key for CI match: GITHUB_SERVER_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "invalid runtime GitHub context key for CI match: GITHUB_API_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL"
                in item
                for item in report["failures"]
            )
        )

        invalid_runtime_context_query_fragment = dict(github_context)
        invalid_runtime_context_query_fragment["GITHUB_SERVER_URL"] = "https://github.com/?x=1"
        invalid_runtime_context_query_fragment["GITHUB_API_URL"] = "https://api.github.com#anchor"
        invalid_runtime_context_query_fragment["GITHUB_GRAPHQL_URL"] = "https://api.github.com/graphql?debug=1"
        with mock.patch.dict(os.environ, invalid_runtime_context_query_fragment, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SERVER_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_API_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL" in item for item in report["failures"])
        )

        invalid_runtime_context_userinfo = dict(github_context)
        invalid_runtime_context_userinfo["GITHUB_SERVER_URL"] = "https://token@github.com"
        invalid_runtime_context_userinfo["GITHUB_API_URL"] = "https://token@api.github.com"
        invalid_runtime_context_userinfo["GITHUB_GRAPHQL_URL"] = "https://token@api.github.com/graphql"
        with mock.patch.dict(os.environ, invalid_runtime_context_userinfo, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SERVER_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_API_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL" in item for item in report["failures"])
        )

        invalid_runtime_context_invalid_port = dict(github_context)
        invalid_runtime_context_invalid_port["GITHUB_SERVER_URL"] = "https://github.com:abc"
        invalid_runtime_context_invalid_port["GITHUB_API_URL"] = "https://api.github.com:def"
        invalid_runtime_context_invalid_port["GITHUB_GRAPHQL_URL"] = "https://api.github.com:ghi/graphql"
        with mock.patch.dict(os.environ, invalid_runtime_context_invalid_port, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SERVER_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_API_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL" in item for item in report["failures"])
        )

        invalid_runtime_context_noncanonical_path = dict(github_context)
        invalid_runtime_context_noncanonical_path["GITHUB_SERVER_URL"] = "https://github.com//"
        invalid_runtime_context_noncanonical_path["GITHUB_API_URL"] = "https://api.github.com//"
        invalid_runtime_context_noncanonical_path["GITHUB_GRAPHQL_URL"] = "https://api.github.com//graphql"
        with mock.patch.dict(os.environ, invalid_runtime_context_noncanonical_path, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SERVER_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_API_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL" in item for item in report["failures"])
        )

        invalid_runtime_context_trailing_slash_path = dict(github_context)
        invalid_runtime_context_trailing_slash_path["GITHUB_SERVER_URL"] = "https://github.com"
        invalid_runtime_context_trailing_slash_path["GITHUB_API_URL"] = "https://api.github.com"
        invalid_runtime_context_trailing_slash_path["GITHUB_GRAPHQL_URL"] = "https://api.github.com/graphql/"
        with mock.patch.dict(os.environ, invalid_runtime_context_trailing_slash_path, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL" in item for item in report["failures"])
        )

        invalid_runtime_context_empty_port = dict(github_context)
        invalid_runtime_context_empty_port["GITHUB_SERVER_URL"] = "https://github.com:"
        invalid_runtime_context_empty_port["GITHUB_API_URL"] = "https://api.github.com:"
        invalid_runtime_context_empty_port["GITHUB_GRAPHQL_URL"] = "https://api.github.com:/graphql"
        with mock.patch.dict(os.environ, invalid_runtime_context_empty_port, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SERVER_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_API_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL" in item for item in report["failures"])
        )

        invalid_runtime_context_whitespace = dict(github_context)
        invalid_runtime_context_whitespace["GITHUB_SERVER_URL"] = " https://github.com"
        invalid_runtime_context_whitespace["GITHUB_API_URL"] = "https://api.github.com "
        invalid_runtime_context_whitespace["GITHUB_GRAPHQL_URL"] = " https://api.github.com/graphql "
        with mock.patch.dict(os.environ, invalid_runtime_context_whitespace, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_SERVER_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_API_URL" in item for item in report["failures"])
        )
        self.assertTrue(
            any("invalid runtime GitHub context key for CI match: GITHUB_GRAPHQL_URL" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_ref_semantics_are_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_ref_semantics_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_REF"] = "refs/pull/7/merge"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any(
                "runtime GitHub context.GITHUB_REF invalid value for GITHUB_REF_TYPE=branch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_REF mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_ref mismatch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_ref_git_refname_is_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_ref_git_refname_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_REF"] = "refs/heads/main..bak"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_REF" in item for item in report["failures"])
        )

        invalid_runtime_context_whitespace_ref = dict(github_context)
        invalid_runtime_context_whitespace_ref["GITHUB_REF"] = " refs/heads/main "
        with mock.patch.dict(os.environ, invalid_runtime_context_whitespace_ref, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_REF" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_ref_name_semantics_are_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_ref_name_semantics_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_REF_NAME"] = "release-main"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any(
                "runtime GitHub context.GITHUB_REF_NAME mismatch with GITHUB_REF" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_REF_NAME mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_ref_name mismatch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_repository_owner_semantics_are_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_repository_owner_semantics_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_REPOSITORY_OWNER"] = "other-org"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any(
                "runtime GitHub context.GITHUB_REPOSITORY_OWNER mismatch with GITHUB_REPOSITORY owner" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_REPOSITORY_OWNER mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_repository_owner mismatch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_workflow_ref_repository_semantics_are_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_workflow_ref_repository_semantics_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context[
            "GITHUB_WORKFLOW_REF"
        ] = "other-org/demo/.github/workflows/release_promotion.yml@refs/heads/main"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any(
                "runtime GitHub context.GITHUB_WORKFLOW_REF repository mismatch with GITHUB_REPOSITORY"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_WORKFLOW_REF mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_name_ref mismatch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_workflow_ref_ref_semantics_are_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_workflow_ref_ref_semantics_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context[
            "GITHUB_WORKFLOW_REF"
        ] = "acme/demo/.github/workflows/release_promotion.yml@refs/heads/release/old"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any(
                "runtime GitHub context.GITHUB_WORKFLOW_REF ref mismatch with GITHUB_REF" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_WORKFLOW_REF mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_name_ref mismatch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_runtime_repository_slug_is_invalid(self):
        root = self.make_case_root("promotion_artifacts_runtime_repository_slug_invalid")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_runtime_context = dict(github_context)
        invalid_runtime_context["GITHUB_REPOSITORY"] = "acme"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_REPOSITORY" in item for item in report["failures"])
        )

        invalid_runtime_context["GITHUB_REPOSITORY"] = "acme/demo/extra"
        with mock.patch.dict(os.environ, invalid_runtime_context, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_REPOSITORY" in item for item in report["failures"])
        )

        invalid_runtime_context_whitespace_repository = dict(github_context)
        invalid_runtime_context_whitespace_repository["GITHUB_REPOSITORY"] = " acme/demo "
        with mock.patch.dict(os.environ, invalid_runtime_context_whitespace_repository, clear=False):
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
            any("invalid runtime GitHub context key for CI match: GITHUB_REPOSITORY" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_fails_when_retention_days_missing_from_context_artifacts(self):
        root = self.make_case_root("promotion_artifacts_retention_days_missing")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        approval_context = dict(github_context)
        approval_context.pop("GITHUB_RETENTION_DAYS")
        release_context = dict(github_context)
        release_context.pop("GITHUB_RETENTION_DAYS")
        self._write_release_artifacts(
            release_dir,
            approval_github_context=approval_context,
            release_github_context=release_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_context = dict(github_context)
        evidence_context.pop("GITHUB_RETENTION_DAYS")
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
        run_receipt_context = dict(github_context)
        run_receipt_context.pop("GITHUB_RETENTION_DAYS")
        run_receipt.write_text(
            json.dumps(
                self._build_run_receipt_payload(
                    release_dir=release_dir,
                    evidence_path=evidence_path,
                    promotion_report_path=promotion_report,
                    rotation_report_path=rotation_report,
                    report_path=report_path,
                    github_context=run_receipt_context,
                ),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with mock.patch.dict(os.environ, github_context, clear=False):
            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                run_receipt_file=str(run_receipt),
                require_ci_context_match=True,
                repo_root=root,
            )

        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context missing required key: GITHUB_RETENTION_DAYS" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_approval.github_context missing required key: GITHUB_RETENTION_DAYS" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context missing required key: GITHUB_RETENTION_DAYS" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.github_context missing required key: GITHUB_RETENTION_DAYS" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "rotation_rehearsal_report.workflow_retention_days missing for CI context key GITHUB_RETENTION_DAYS"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context missing required key: GITHUB_RETENTION_DAYS" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_release_approval_context_mismatches(self):
        root = self.make_case_root("promotion_artifacts_approval_context_mismatch")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(
            release_dir,
            approval_github_context={
                "GITHUB_REPOSITORY": "acme/demo",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_ACTIONS": "false",
                "CI": "false",
                "RUNNER_ENVIRONMENT": "self-hosted",
                "RUNNER_OS": "Windows",
                "RUNNER_ARCH": "ARM64",
            "RUNNER_NAME": "runner-arm64",
                "GITHUB_RUN_ID": "12345",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_RUN_NUMBER": "11",
                "GITHUB_RETENTION_DAYS": "1",
                "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
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
                        "GITHUB_ACTIONS": "true",
                        "CI": "true",
                        "RUNNER_ENVIRONMENT": "github-hosted",
                        "RUNNER_OS": "Linux",
                        "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
                        "GITHUB_RUN_ID": "12345",
                        "GITHUB_RUN_ATTEMPT": "3",
                        "GITHUB_RUN_NUMBER": "11",
                        "GITHUB_RETENTION_DAYS": "90",
                        "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
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
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
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
                "GITHUB_ACTIONS": "true",
                "CI": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Linux",
                "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
                "GITHUB_RUN_ID": "12345",
                "GITHUB_RUN_ATTEMPT": "3",
                "GITHUB_RUN_NUMBER": "11",
                "GITHUB_RETENTION_DAYS": "90",
                "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
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
            any("release_approval.github_context.GITHUB_ACTIONS mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_approval.github_context.CI mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_approval.github_context.RUNNER_ENVIRONMENT mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_approval.github_context.RUNNER_OS mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_approval.github_context.RUNNER_ARCH mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_approval.github_context.GITHUB_RETENTION_DAYS mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_approval.github_context.GITHUB_WORKFLOW mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context.GITHUB_ACTIONS mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context.CI mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context.RUNNER_ENVIRONMENT mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context.RUNNER_OS mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context.RUNNER_ARCH mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context.GITHUB_RETENTION_DAYS mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "release_receipt.release_approval_github_context.GITHUB_WORKFLOW mismatch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_release_receipt_context_mismatches(self):
        root = self.make_case_root("promotion_artifacts_release_receipt_context_mismatch")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        approval_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "11",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        receipt_context = dict(approval_context)
        receipt_context.update(
            {
                "GITHUB_ACTIONS": "false",
                "CI": "false",
                "RUNNER_ENVIRONMENT": "self-hosted",
                "RUNNER_OS": "Windows",
                "RUNNER_ARCH": "ARM64",
            "RUNNER_NAME": "runner-arm64",
                "GITHUB_WORKFLOW": "release-promotion-gate-other",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_RETENTION_DAYS": "1",
            }
        )
        self._write_release_artifacts(
            release_dir,
            approval_github_context=approval_context,
            release_github_context=receipt_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": approval_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "11",
                    "workflow_retention_days": "90",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        with mock.patch.dict(os.environ, approval_context, clear=False):
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
            any("release_receipt.github_context.GITHUB_RUN_ATTEMPT mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_receipt.github_context.GITHUB_ACTIONS mismatch" in item for item in report["failures"])
        )
        self.assertTrue(any("release_receipt.github_context.CI mismatch" in item for item in report["failures"]))
        self.assertTrue(
            any("release_receipt.github_context.RUNNER_ENVIRONMENT mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_receipt.github_context.RUNNER_OS mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_receipt.github_context.RUNNER_ARCH mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_receipt.github_context.GITHUB_RETENTION_DAYS mismatch" in item for item in report["failures"])
        )
        self.assertTrue(
            any("release_receipt.github_context.GITHUB_WORKFLOW mismatch" in item for item in report["failures"])
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
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "15",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "15",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "16",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
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
                    "workflow_run_number": "16",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
                        "GITHUB_REF_NAME": "release/x",
                        "GITHUB_REF_TYPE": "branch",
                        "GITHUB_REF_PROTECTED": "false",
                        "GITHUB_ACTIONS": "false",
                        "CI": "false",
                        "RUNNER_ENVIRONMENT": "self-hosted",
                        "RUNNER_OS": "Windows",
                        "RUNNER_ARCH": "ARM64",
            "RUNNER_NAME": "runner-arm64",
                        "GITHUB_RUN_ID": "12345",
                        "GITHUB_RUN_ATTEMPT": "2",
                        "GITHUB_RUN_NUMBER": "2",
                        "GITHUB_RETENTION_DAYS": "1",
                        "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                        "GITHUB_WORKFLOW": "release-promotion-gate-other",
                        "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/release/x",
                        "GITHUB_WORKFLOW_SHA": "badc0de0badc0de0badc0de0badc0de0badc0de0",
                        "GITHUB_EVENT_NAME": "push",
                        "GITHUB_SERVER_URL": "https://github.com",
                        "GITHUB_API_URL": "https://api.github.com",
                        "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
                        "GITHUB_JOB": "promotion-gate-other",
                        "GITHUB_ACTOR": "other-actor",
                        "GITHUB_ACTOR_ID": "999",
                        "GITHUB_REPOSITORY_ID": "9999",
                        "GITHUB_REPOSITORY_OWNER": "other-org",
                        "GITHUB_REPOSITORY_OWNER_ID": "99999",
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
                "promotion_run_receipt.github_context.GITHUB_ACTIONS mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context.CI mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context.RUNNER_ENVIRONMENT mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context.RUNNER_OS mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context.RUNNER_ARCH mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context.RUNNER_NAME mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context.GITHUB_WORKFLOW mismatch" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_run_receipt.github_context.GITHUB_RETENTION_DAYS mismatch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_passes(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_pass")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "17",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "17",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            report_file=str(report_path),
            run_receipt_file=str(run_receipt),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertTrue(report["passed"])
        self.assertTrue(report["artifact_context_consistency_required"])

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_mismatch(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_mismatch")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        approval_context = dict(github_context)
        approval_context["GITHUB_RUN_ATTEMPT"] = "2"
        self._write_release_artifacts(
            release_dir,
            approval_github_context=approval_context,
            release_github_context=github_context,
        )
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
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "release_approval.github_context.GITHUB_RUN_ATTEMPT mismatch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_ref_protected(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_ref_protected")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_REF_PROTECTED"] = "not-sure"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_REF_PROTECTED" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_ci_booleans(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_ci_booleans")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_ACTIONS"] = "enabled"
        invalid_evidence_context["CI"] = "disabled"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_ACTIONS" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: CI" in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_semantic = dict(github_context)
        invalid_evidence_context_semantic["GITHUB_ACTIONS"] = "false"
        invalid_evidence_context_semantic["CI"] = "0"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_semantic,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_ACTIONS must be true in GitHub Actions CI context"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context.CI must be true in GitHub Actions CI context"
                in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_numeric_or_ref_type(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_numeric_ref_type")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_RUN_NUMBER"] = "run18"
        invalid_evidence_context["GITHUB_REPOSITORY_OWNER_ID"] = "owner-424242"
        invalid_evidence_context["GITHUB_REF_TYPE"] = "pull_request"
        invalid_evidence_context["GITHUB_REF"] = "refs/pull/18/merge"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_RUN_NUMBER" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_REPOSITORY_OWNER_ID" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_REF_TYPE" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_runner_values(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_runner_values")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["RUNNER_ENVIRONMENT"] = "dedicated"
        invalid_evidence_context["RUNNER_OS"] = "BSD"
        invalid_evidence_context["RUNNER_ARCH"] = "RISCV64"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: RUNNER_ENVIRONMENT" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: RUNNER_OS" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: RUNNER_ARCH" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_sha_values(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_sha")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_SHA"] = "sha-123"
        invalid_evidence_context["GITHUB_WORKFLOW_SHA"] = "facefeed"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SHA" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_WORKFLOW_SHA" in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_whitespace_sha = dict(github_context)
        invalid_evidence_context_whitespace_sha["GITHUB_SHA"] = " deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        invalid_evidence_context_whitespace_sha["GITHUB_WORKFLOW_SHA"] = "facefeedfacefeedfacefeedfacefeedfacefeed "
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_whitespace_sha,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SHA" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_WORKFLOW_SHA" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_workflow_ref(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_workflow_ref")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        promotion_report = root / "promotion_audit_report.json"
        rotation_report = root / "rotation_rehearsal_report.json"
        rotation_report.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-rotation-rehearsal/v1",
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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

        invalid_workflow_ref_values = (
            "acme/demo/release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/./release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/sub/../release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/sub\\release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/%2e/release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/sub/%2e%2e/release_promotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/release%5Fpromotion.yml@refs/heads/main",
            "acme/demo/.github/workflows/release%2epromotion.yml@refs/heads/main",
            " acme/demo/.github/workflows/release_promotion.yml@refs/heads/main ",
        )
        for invalid_workflow_ref in invalid_workflow_ref_values:
            invalid_evidence_context = dict(github_context)
            invalid_evidence_context["GITHUB_WORKFLOW_REF"] = invalid_workflow_ref
            evidence_path.write_text(
                json.dumps(
                    {
                        "schema": "enc2sop-promotion-evidence/v1",
                        "github_context": invalid_evidence_context,
                        "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                        "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                        "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
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

            _, report = promotion_artifacts.run_promotion_artifact_audit(
                dist_dir=str(release_dir),
                promotion_evidence_file=str(evidence_path),
                promotion_report_file=str(promotion_report),
                rotation_report_file=str(rotation_report),
                promotion_policy_file=str(policy_path),
                promotion_workflow_file=str(workflow_path),
                require_artifact_context_consistency=True,
                repo_root=root,
            )
            self.assertFalse(report["passed"])
            self.assertTrue(
                any(
                    "promotion_evidence.github_context invalid key value: GITHUB_WORKFLOW_REF" in item
                    for item in report["failures"]
                )
            )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_workflow_ref_repository_slug(
        self,
    ):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_workflow_ref_repository_slug")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_WORKFLOW_REF"] = (
            "acme/demo/extra/.github/workflows/release_promotion.yml@refs/heads/main"
        )
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_WORKFLOW_REF" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_url_values(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_urls")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_SERVER_URL"] = "github.com"
        invalid_evidence_context["GITHUB_API_URL"] = "api.github.com"
        invalid_evidence_context["GITHUB_GRAPHQL_URL"] = "ssh://api.github.com/graphql"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SERVER_URL" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_API_URL" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL" in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_canonical = dict(github_context)
        invalid_evidence_context_canonical["GITHUB_SERVER_URL"] = "https://github.com."
        invalid_evidence_context_canonical["GITHUB_API_URL"] = "https://api.github.com:443"
        invalid_evidence_context_canonical["GITHUB_GRAPHQL_URL"] = "https://API.GitHub.com/graphql"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_canonical,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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

        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SERVER_URL" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_API_URL" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL" in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_semantic = dict(github_context)
        invalid_evidence_context_semantic["GITHUB_SERVER_URL"] = "https://github.com"
        invalid_evidence_context_semantic["GITHUB_API_URL"] = "https://github.com/api/v3"
        invalid_evidence_context_semantic["GITHUB_GRAPHQL_URL"] = "https://github.com/api/graphql"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_semantic,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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

        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_API_URL host mismatch for github.com server: expected api.github.com"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_API_URL path mismatch for github.com server: expected /, got /api/v3"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_GRAPHQL_URL path mismatch for github.com server: expected /graphql, got /api/graphql"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_http_scheme = dict(github_context)
        invalid_evidence_context_http_scheme["GITHUB_SERVER_URL"] = "http://github.com"
        invalid_evidence_context_http_scheme["GITHUB_API_URL"] = "http://api.github.com"
        invalid_evidence_context_http_scheme["GITHUB_GRAPHQL_URL"] = "http://api.github.com/graphql"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_http_scheme,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SERVER_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_API_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_query_fragment = dict(github_context)
        invalid_evidence_context_query_fragment["GITHUB_SERVER_URL"] = "https://github.com/?x=1"
        invalid_evidence_context_query_fragment["GITHUB_API_URL"] = "https://api.github.com#anchor"
        invalid_evidence_context_query_fragment["GITHUB_GRAPHQL_URL"] = "https://api.github.com/graphql?debug=1"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_query_fragment,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SERVER_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_API_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_userinfo = dict(github_context)
        invalid_evidence_context_userinfo["GITHUB_SERVER_URL"] = "https://token@github.com"
        invalid_evidence_context_userinfo["GITHUB_API_URL"] = "https://token@api.github.com"
        invalid_evidence_context_userinfo["GITHUB_GRAPHQL_URL"] = "https://token@api.github.com/graphql"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_userinfo,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SERVER_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_API_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_invalid_port = dict(github_context)
        invalid_evidence_context_invalid_port["GITHUB_SERVER_URL"] = "https://github.com:abc"
        invalid_evidence_context_invalid_port["GITHUB_API_URL"] = "https://api.github.com:def"
        invalid_evidence_context_invalid_port["GITHUB_GRAPHQL_URL"] = "https://api.github.com:ghi/graphql"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_invalid_port,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SERVER_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_API_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_noncanonical_path = dict(github_context)
        invalid_evidence_context_noncanonical_path["GITHUB_SERVER_URL"] = "https://github.com//"
        invalid_evidence_context_noncanonical_path["GITHUB_API_URL"] = "https://api.github.com//"
        invalid_evidence_context_noncanonical_path["GITHUB_GRAPHQL_URL"] = "https://api.github.com//graphql"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_noncanonical_path,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SERVER_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_API_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_trailing_slash_path = dict(github_context)
        invalid_evidence_context_trailing_slash_path["GITHUB_SERVER_URL"] = "https://github.com"
        invalid_evidence_context_trailing_slash_path["GITHUB_API_URL"] = "https://api.github.com"
        invalid_evidence_context_trailing_slash_path["GITHUB_GRAPHQL_URL"] = "https://api.github.com/graphql/"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_trailing_slash_path,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_empty_port = dict(github_context)
        invalid_evidence_context_empty_port["GITHUB_SERVER_URL"] = "https://github.com:"
        invalid_evidence_context_empty_port["GITHUB_API_URL"] = "https://api.github.com:"
        invalid_evidence_context_empty_port["GITHUB_GRAPHQL_URL"] = "https://api.github.com:/graphql"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_empty_port,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SERVER_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_API_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context_whitespace = dict(github_context)
        invalid_evidence_context_whitespace["GITHUB_SERVER_URL"] = " https://github.com"
        invalid_evidence_context_whitespace["GITHUB_API_URL"] = "https://api.github.com "
        invalid_evidence_context_whitespace["GITHUB_GRAPHQL_URL"] = " https://api.github.com/graphql "
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context_whitespace,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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
        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_SERVER_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_API_URL"
                in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_GRAPHQL_URL"
                in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_text_whitespace_values(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_text_whitespace")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_EVENT_NAME"] = " push "
        invalid_evidence_context["GITHUB_WORKFLOW"] = " release-promotion-gate "
        invalid_evidence_context["GITHUB_JOB"] = " promotion-gate "
        invalid_evidence_context["GITHUB_ACTOR"] = " octocat "
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_EVENT_NAME" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_WORKFLOW" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_JOB" in item
                for item in report["failures"]
            )
        )
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_ACTOR" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_ref_semantics(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_ref_semantics")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_REF"] = "refs/pull/18/merge"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_REF invalid value for GITHUB_REF_TYPE=branch" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_ref_git_refname(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_ref_git_refname")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_REF"] = "refs/heads/main..bak"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any("promotion_evidence.github_context invalid key value: GITHUB_REF" in item for item in report["failures"])
        )

        invalid_evidence_context["GITHUB_REF"] = " refs/heads/main "
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
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

        _, report = promotion_artifacts.run_promotion_artifact_audit(
            dist_dir=str(release_dir),
            promotion_evidence_file=str(evidence_path),
            promotion_report_file=str(promotion_report),
            rotation_report_file=str(rotation_report),
            promotion_policy_file=str(policy_path),
            promotion_workflow_file=str(workflow_path),
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any("promotion_evidence.github_context invalid key value: GITHUB_REF" in item for item in report["failures"])
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_ref_name_semantics(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_ref_name_semantics")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_REF_NAME"] = "release-main"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_REF_NAME mismatch with GITHUB_REF" in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_repository_owner_semantics(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_repository_owner_semantics")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_REPOSITORY_OWNER"] = "other-org"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_REPOSITORY_OWNER mismatch with GITHUB_REPOSITORY owner"
                in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_workflow_ref_repository_semantics(
        self,
    ):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_workflow_ref_repository_semantics")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context[
            "GITHUB_WORKFLOW_REF"
        ] = "other-org/demo/.github/workflows/release_promotion.yml@refs/heads/main"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_WORKFLOW_REF repository mismatch with GITHUB_REPOSITORY"
                in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_workflow_ref_ref_semantics(
        self,
    ):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_workflow_ref_ref_semantics")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context[
            "GITHUB_WORKFLOW_REF"
        ] = "acme/demo/.github/workflows/release_promotion.yml@refs/heads/release/old"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context.GITHUB_WORKFLOW_REF ref mismatch with GITHUB_REF"
                in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_artifact_context_consistency_fails_on_invalid_repository_slug_value(self):
        root = self.make_case_root("promotion_artifacts_context_consistency_invalid_repository_slug")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "18",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_TRIGGERING_ACTOR": "ops-oncall",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        invalid_evidence_context = dict(github_context)
        invalid_evidence_context["GITHUB_REPOSITORY"] = "acme"
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "18",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_triggering_actor": "ops-oncall",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_REPOSITORY"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context["GITHUB_REPOSITORY"] = "acme/demo/extra"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_REPOSITORY"
                in item
                for item in report["failures"]
            )
        )

        invalid_evidence_context["GITHUB_REPOSITORY"] = " acme/demo "
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "github_context": invalid_evidence_context,
                    "branches": [{"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]}],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.github_context invalid key value: GITHUB_REPOSITORY"
                in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_fails_when_evidence_repository_conflicts_with_context(self):
        root = self.make_case_root("promotion_artifacts_evidence_repo_context_mismatch")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        self._write_release_artifacts(release_dir)
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "repository": "acme/demo",
                    "github_context": {
                        "GITHUB_REPOSITORY": "other/demo",
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
            require_artifact_context_consistency=True,
            repo_root=root,
        )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.repository mismatch with promotion_evidence.github_context.GITHUB_REPOSITORY"
                in item
                for item in report["failures"]
            )
        )

    def test_run_promotion_artifact_audit_ci_context_match_fails_when_runtime_repository_conflicts_with_evidence(self):
        root = self.make_case_root("promotion_artifacts_runtime_repo_mismatch")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        github_context = {
            "GITHUB_REPOSITORY": "acme/demo",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REF_NAME": "main",
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_PROTECTED": "true",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "runner-x64",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_RUN_NUMBER": "19",
            "GITHUB_RETENTION_DAYS": "90",
            "GITHUB_SHA": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "GITHUB_WORKFLOW": "release-promotion-gate",
            "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
            "GITHUB_WORKFLOW_SHA": "facefeedfacefeedfacefeedfacefeedfacefeed",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com",
            "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
            "GITHUB_JOB": "promotion-gate",
            "GITHUB_ACTOR": "octocat",
            "GITHUB_ACTOR_ID": "42",
            "GITHUB_REPOSITORY_ID": "4242",
            "GITHUB_REPOSITORY_OWNER": "acme",
            "GITHUB_REPOSITORY_OWNER_ID": "424242",
        }
        self._write_release_artifacts(
            release_dir,
            approval_github_context=github_context,
            release_github_context=github_context,
        )
        policy_path, workflow_path = self._write_policy_and_workflow(root)

        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "repository": "other/demo",
                    "github_context": dict(github_context),
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
                    "workflow_repository": "acme/demo",
                    "workflow_run_id": "12345",
                    "workflow_run_attempt": "3",
                    "workflow_run_number": "19",
                    "workflow_retention_days": "90",
                    "workflow_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "workflow_github_actions": "true",
                    "workflow_ci": "true",
                    "workflow_runner_environment": "github-hosted",
                    "workflow_runner_os": "Linux",
                    "workflow_runner_arch": "X64",
                    "workflow_runner_name": "runner-x64",
                    "workflow_ref": "refs/heads/main",
                    "workflow_ref_name": "main",
                    "workflow_ref_type": "branch",
                    "workflow_name": "release-promotion-gate",
                    "workflow_name_ref": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                    "workflow_name_sha": "facefeedfacefeedfacefeedfacefeedfacefeed",
                    "workflow_event": "push",
                    "workflow_server_url": "https://github.com",
                    "workflow_api_url": "https://api.github.com",
                    "workflow_graphql_url": "https://api.github.com/graphql",
                    "workflow_job": "promotion-gate",
                    "workflow_actor": "octocat",
                    "workflow_actor_id": "42",
                    "workflow_repository_id": "4242",
                    "workflow_repository_owner": "acme",
                    "workflow_repository_owner_id": "424242",
                    "workflow_ref_protected": "true",
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
                repo_root=root,
            )
        self.assertFalse(report["passed"])
        self.assertTrue(
            any(
                "promotion_evidence.repository mismatch with runtime GITHUB_REPOSITORY" in item
                for item in report["failures"]
            )
        )


if __name__ == "__main__":
    unittest.main()



