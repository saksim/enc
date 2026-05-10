import pathlib
import unittest


class ReleasePromotionWorkflowTests(unittest.TestCase):
    def test_workflow_enforces_signed_approval_gate(self):
        repo_root = pathlib.Path(__file__).resolve().parents[1]
        workflow_path = repo_root / ".github" / "workflows" / "release_promotion.yml"
        self.assertTrue(workflow_path.exists(), "release promotion workflow is missing")

        payload = workflow_path.read_text(encoding="utf-8")

        self.assertIn("python ./soenc.py approve-release", payload)
        self.assertIn("python ./soenc.py release", payload)
        self.assertIn("--require-release-approval", payload)
        self.assertIn("python ./soenc.py promotion-dry-run", payload)
        self.assertIn("python ./soenc.py verify-promotion-artifacts", payload)
        self.assertIn("--require-ci-context-match", payload)
        self.assertIn("PROMOTION_REPORT_FILE", payload)
        self.assertIn("SOENC_RELEASE_APPROVAL_KEY_B64", payload)
        self.assertIn("SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64", payload)
        self.assertIn("rotation_rehearsal", payload)
        self.assertIn("rotation_report_file", payload)
        self.assertIn("promotion_artifact_audit_report_file", payload)
        self.assertIn("promotion_run_receipt_file", payload)
        self.assertIn("PROMOTION_ARTIFACT_AUDIT_REPORT_FILE", payload)
        self.assertIn("PROMOTION_RUN_RECEIPT_FILE", payload)
        self.assertIn("ROTATION_REPORT_FILE", payload)
        self.assertIn("enc2sop-rotation-rehearsal/v1", payload)
        self.assertIn("if: ${{ always() }}", payload)
        self.assertIn("promotion_evidence_file", payload)
        self.assertIn("promotion_report_file", payload)
        self.assertIn("GITHUB_TOKEN", payload)
        self.assertIn("SKIP_PROMOTION_COLLECT", payload)
        self.assertIn("actions: read", payload)
        self.assertIn("soenc-promotion-${{ github.run_id }}", payload)
        self.assertIn("release_approval.json", payload)
        self.assertIn("release_receipt.json", payload)
        self.assertIn("promotion_evidence.json", payload)
        self.assertIn("promotion_audit_report.json", payload)
        self.assertIn("promotion_artifact_audit_report.json", payload)
        self.assertIn("rotation_rehearsal_report.json", payload)
        self.assertIn("promotion_run_receipt.json", payload)
        self.assertIn("if-no-files-found: error", payload)


if __name__ == "__main__":
    unittest.main()
