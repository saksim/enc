import json
import shutil
import unittest
import uuid
from pathlib import Path

from enc2sop import promotion_audit


TEST_ROOT = Path(__file__).resolve().parents[1]
TEST_RUNS_ROOT = TEST_ROOT / ".tmp_test_runs"


def _make_case_root(prefix):
    TEST_RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    root = TEST_RUNS_ROOT / "{}_{}".format(prefix, uuid.uuid4().hex[:8])
    root.mkdir(parents=True, exist_ok=False)
    return root


class PromotionAuditTests(unittest.TestCase):
    def make_case_root(self, prefix):
        root = _make_case_root(prefix)
        self.addCleanup(lambda: shutil.rmtree(str(root), ignore_errors=True))
        return root

    def test_run_promotion_audit_writes_input_digest_binding_metadata(self):
        root = self.make_case_root("promotion_audit_input_binding")
        policy_path = root / "policy.json"
        evidence_path = root / "promotion_evidence.json"
        workflow_path = root / "release_promotion.yml"
        report_path = root / "promotion_audit_report.json"

        workflow_text = "name: release-promotion-gate\npython ./soenc.py promotion-dry-run\n"
        workflow_path.write_text(workflow_text, encoding="utf-8")

        policy_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-policy/v1",
                    "required_branches": [
                        {
                            "name": "main",
                            "required_status_checks": ["Signed Approval Promotion Gate"],
                        }
                    ],
                    "required_environments": [
                        {
                            "name": "production-promotion",
                            "min_required_reviewers": 1,
                        }
                    ],
                    "required_secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                    "workflow": {
                        "relative_path": str(workflow_path),
                        "required_fragments": ["name: release-promotion-gate"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "branches": [
                        {
                            "name": "main",
                            "required_status_checks": ["Signed Approval Promotion Gate"],
                        }
                    ],
                    "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        written_report_path, report = promotion_audit.run_promotion_audit(
            evidence_file=str(evidence_path),
            policy_file=str(policy_path),
            workflow_file=str(workflow_path),
            report_file=str(report_path),
            repo_root=root,
        )

        self.assertEqual(written_report_path.resolve(), report_path.resolve())
        self.assertTrue(report.get("passed"))
        inputs = report.get("inputs")
        self.assertIsInstance(inputs, dict)
        self.assertEqual(inputs.get("policy_file"), str(policy_path.resolve()))
        self.assertEqual(inputs.get("evidence_file"), str(evidence_path.resolve()))
        self.assertEqual(inputs.get("workflow_file"), str(workflow_path.resolve()))
        self.assertRegex(str(inputs.get("policy_sha256")), r"^[0-9a-f]{64}$")
        self.assertRegex(str(inputs.get("evidence_sha256")), r"^[0-9a-f]{64}$")
        self.assertRegex(str(inputs.get("workflow_sha256")), r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
