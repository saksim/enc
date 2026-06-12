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
        self.assertIn("python ./soenc.py bundle-promotion-artifacts", payload)
        self.assertIn("python scripts/non_ocr_release_gate.py", payload)
        self.assertIn("--config soenc.production.toml", payload)
        self.assertIn("--promotion-bundle \"$PROMOTION_ARTIFACT_BUNDLE_FILE\"", payload)
        self.assertIn("--report \"$NON_OCR_RELEASE_GATE_REPORT_FILE\"", payload)
        self.assertIn("--require-ci-context-match", payload)
        self.assertIn("--require-artifact-context-consistency", payload)
        self.assertIn("--release-approval-key-b64", payload)
        self.assertIn("--release-approval-key-id", payload)
        self.assertIn("--require-release-approval-signature", payload)
        self.assertIn("PROMOTION_REPORT_FILE", payload)
        self.assertIn("SOENC_RELEASE_APPROVAL_KEY_B64", payload)
        self.assertIn("SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64", payload)
        self.assertIn("rotation_rehearsal", payload)
        self.assertIn("rotation_report_file", payload)
        self.assertIn("promotion_policy_file", payload)
        self.assertIn("promotion_workflow_file", payload)
        self.assertIn("promotion_artifact_audit_report_file", payload)
        self.assertIn("promotion_run_receipt_file", payload)
        self.assertIn("promotion_artifact_bundle_file", payload)
        self.assertIn("NON_OCR_RELEASE_GATE_REPORT_FILE", payload)
        self.assertIn("PROMOTION_POLICY_FILE", payload)
        self.assertIn("PROMOTION_WORKFLOW_FILE", payload)
        self.assertIn("PROMOTION_ARTIFACT_AUDIT_REPORT_FILE", payload)
        self.assertIn("PROMOTION_RUN_RECEIPT_FILE", payload)
        self.assertIn("PROMOTION_ARTIFACT_BUNDLE_FILE", payload)
        self.assertIn("ROTATION_REPORT_FILE", payload)
        self.assertIn("enc2sop-rotation-rehearsal/v1", payload)
        self.assertIn("if: ${{ always() }}", payload)
        self.assertIn("promotion_evidence_file", payload)
        self.assertIn("promotion_report_file", payload)
        self.assertIn("GITHUB_TOKEN", payload)
        self.assertIn("SKIP_PROMOTION_COLLECT", payload)
        self.assertIn("Require Protected Ref Context", payload)
        self.assertIn("if [ \"${GITHUB_REF_PROTECTED:-}\" != \"true\" ]; then", payload)
        self.assertIn("Promotion workflow requires protected ref context (GITHUB_REF_PROTECTED=true)", payload)
        self.assertIn("actions: read", payload)
        self.assertIn("soenc-promotion-${{ github.run_id }}-attempt-${{ github.run_attempt }}", payload)
        self.assertIn("release_approval.json", payload)
        self.assertIn("release_receipt.json", payload)
        self.assertIn("promotion_evidence.json", payload)
        self.assertIn("promotion_audit_report.json", payload)
        self.assertIn("promotion_artifact_audit_report.json", payload)
        self.assertIn("rotation_rehearsal_report.json", payload)
        self.assertIn("promotion_run_receipt.json", payload)
        self.assertIn("promotion_artifact_bundle.zip", payload)
        self.assertIn("non_ocr_release_gate_report.json", payload)
        self.assertIn("mode = \"license-file\"", payload)
        self.assertIn("bundle_license = false", payload)
        self.assertIn("require_manifest_signature = true", payload)
        self.assertIn("runtime_native_loader = true", payload)
        self.assertIn("hardening_profile = \"balanced\"", payload)
        self.assertIn("python encryption_helper.py", payload)
        self.assertIn("--config \"$ci_config\"", payload)
        self.assertIn("license_file = \"licenses/ci-license.json\"", payload)
        self.assertNotIn("license_file = \"${workspace_root}/licenses/ci-license.json\"", payload)
        self.assertIn("--no-compile", payload)
        self.assertIn("workspace_root=\"$(pwd)/.tmp_ci/workspace\"", payload)
        self.assertIn("\"workflow_name\": \"${GITHUB_WORKFLOW}\"", payload)
        self.assertIn("\"workflow_repository\": \"${GITHUB_REPOSITORY}\"", payload)
        self.assertIn("\"workflow_run_number\": \"${GITHUB_RUN_NUMBER}\"", payload)
        self.assertIn("\"workflow_retention_days\": \"${GITHUB_RETENTION_DAYS}\"", payload)
        self.assertIn("\"workflow_github_actions\": \"${GITHUB_ACTIONS}\"", payload)
        self.assertIn("\"workflow_ci\": \"${CI}\"", payload)
        self.assertIn("\"workflow_runner_environment\": \"${RUNNER_ENVIRONMENT}\"", payload)
        self.assertIn("\"workflow_runner_os\": \"${RUNNER_OS}\"", payload)
        self.assertIn("\"workflow_runner_arch\": \"${RUNNER_ARCH}\"", payload)
        self.assertIn("\"workflow_runner_name\": \"${RUNNER_NAME}\"", payload)
        self.assertIn("\"workflow_ref_name\": \"${GITHUB_REF_NAME}\"", payload)
        self.assertIn("\"workflow_ref_type\": \"${GITHUB_REF_TYPE}\"", payload)
        self.assertIn("\"workflow_name_ref\": \"${GITHUB_WORKFLOW_REF}\"", payload)
        self.assertIn("\"workflow_name_sha\": \"${GITHUB_WORKFLOW_SHA}\"", payload)
        self.assertIn("\"workflow_event\": \"${GITHUB_EVENT_NAME}\"", payload)
        self.assertIn("\"workflow_server_url\": \"${GITHUB_SERVER_URL}\"", payload)
        self.assertIn("\"workflow_api_url\": \"${GITHUB_API_URL}\"", payload)
        self.assertIn("\"workflow_graphql_url\": \"${GITHUB_GRAPHQL_URL}\"", payload)
        self.assertIn("\"workflow_job\": \"${GITHUB_JOB}\"", payload)
        self.assertIn("\"workflow_actor\": \"${GITHUB_ACTOR}\"", payload)
        self.assertIn("\"workflow_triggering_actor\": \"${GITHUB_TRIGGERING_ACTOR}\"", payload)
        self.assertIn("\"workflow_actor_id\": \"${GITHUB_ACTOR_ID}\"", payload)
        self.assertIn("\"workflow_repository_id\": \"${GITHUB_REPOSITORY_ID}\"", payload)
        self.assertIn("\"workflow_repository_owner\": \"${GITHUB_REPOSITORY_OWNER}\"", payload)
        self.assertIn("\"workflow_repository_owner_id\": \"${GITHUB_REPOSITORY_OWNER_ID}\"", payload)
        self.assertIn("\"workflow_ref_protected\": \"${GITHUB_REF_PROTECTED}\"", payload)
        self.assertIn("if-no-files-found: error", payload)

    def test_mainline_beta_smoke_script_contract(self):
        repo_root = pathlib.Path(__file__).resolve().parents[1]
        script_path = repo_root / "scripts" / "mainline_beta_smoke.ps1"
        self.assertTrue(script_path.exists(), "Mainline Beta smoke script is missing")
        payload = script_path.read_text(encoding="utf-8")

        self.assertIn("non_ocr_code_protection_launch_strategy_20260612.md", payload)
        self.assertIn(r"tests\test_encryption_helper.py", payload)
        self.assertIn(r"tests\test_decryption_helper.py", payload)
        self.assertIn(r"tests\test_soenc_cli.py", payload)
        self.assertIn(r"tests\test_promotion_bundle.py", payload)
        self.assertIn(r"tests\test_promotion_artifacts.py", payload)
        self.assertIn(r"tests\test_release_promotion_workflow.py", payload)
        self.assertIn(r"tests\test_non_ocr_release_gate.py", payload)
        self.assertIn(r"scripts\non_ocr_release_gate.py", payload)
        self.assertIn("--config-only", payload)
        self.assertIn(r"scripts\smoke_code_protection.py", payload)
        self.assertIn(r"scripts\smoke_runtime_integrity.py", payload)
        self.assertIn("MAINLINE_BETA_SMOKE_OK", payload)
        self.assertNotIn("test_crossmedia", payload)

    def test_release_reverse_cost_checklist_contract(self):
        repo_root = pathlib.Path(__file__).resolve().parents[1]
        checklist_path = repo_root / "docs" / "current" / "non_ocr_release_reverse_cost_checklist_20260612.md"
        self.assertTrue(checklist_path.exists(), "release reverse-cost checklist is missing")
        payload = checklist_path.read_text(encoding="utf-8")

        self.assertIn("非 OCR", payload)
        self.assertIn("逆向成本", payload)
        self.assertIn("不承诺绝对不可逆向", payload)
        self.assertIn("license-file", payload)
        self.assertIn("bundle_license = false", payload)
        self.assertIn("manifest signature", payload)
        self.assertIn("runtime integrity", payload)
        self.assertIn("dist no-source-leak", payload)
        self.assertIn("promotion_artifact_bundle.zip", payload)
        self.assertIn("local-embedded", payload)
        self.assertIn("--dev-insecure-ok", payload)
        self.assertIn("SOENC_LICENSE_VERIFY_KEY_B64", payload)
        self.assertIn("SOENC_MACHINE_FINGERPRINT", payload)
        self.assertIn("SOENC_LICENSE_REVOCATION_FILE", payload)

    def test_live_promotion_capture_script_contract(self):
        repo_root = pathlib.Path(__file__).resolve().parents[1]
        script_path = repo_root / "scripts" / "github_release_promotion_evidence.sh"
        self.assertTrue(script_path.exists(), "promotion evidence capture script is missing")
        payload = script_path.read_text(encoding="utf-8")

        self.assertIn("gh workflow run", payload)
        self.assertIn("return_run_details", payload)
        self.assertIn("repos/${repo}/actions/workflows/${workflow_encoded}/dispatches", payload)
        self.assertNotRegex(payload, r"\|\s*python\s+-[^\n]*<<'PY'")
        self.assertIn('workflow_probe_parsed="$(python - "$workflow_probe_output" <<\'PY\'', payload)
        self.assertIn('python - "$dispatch_epoch" "$runs_json" <<\'PY\'', payload)
        self.assertIn('promotion_jobs_json_path="${OUTPUT_ROOT}/run-${run_id}-attempt-${run_attempt}/promotion_jobs.json"', payload)
        self.assertIn('payload_path = Path(sys.argv[11])', payload)
        self.assertIn('artifact_metadata_json_path="${OUTPUT_ROOT}/run-${run_id}-attempt-${run_attempt}/artifact_metadata.json"', payload)
        self.assertIn('payload_path = Path(sys.argv[4])', payload)
        self.assertIn("Workflow dispatch API with run details failed; falling back to gh workflow run...", payload)
        self.assertIn("Dispatch response run id candidates are inconsistent", payload)
        self.assertIn("Dispatch response workflow_id is not numeric:", payload)
        self.assertIn("dispatch_run_url_api", payload)
        self.assertIn("dispatch_run_html_url", payload)
        self.assertIn("dispatch_workflow_id_api", payload)
        self.assertIn("Dispatch response workflow_id is not numeric for run_id=${run_id}: ${dispatch_workflow_id_api}", payload)
        self.assertIn(
            "Dispatch response workflow_id mismatch for run_id=${run_id}: expected ${resolved_workflow_definition_id}, got ${dispatch_workflow_id_api}",
            payload,
        )
        self.assertIn("Dispatch response run_url must not contain whitespace for run_id=${run_id}: ${dispatch_run_url_api}", payload)
        self.assertIn(
            "Dispatch response run_url does not contain a canonical /actions/runs/<id> segment: {0}",
            payload,
        )
        self.assertIn(
            "Dispatch response html_url does not contain a canonical /actions/runs/<id> segment: {0}",
            payload,
        )
        self.assertIn("Dispatch response run_url run_id mismatch: expected ${run_id}, got ${dispatch_run_id_from_url}", payload)
        self.assertIn("Dispatch response html_url run_id mismatch: expected ${run_id}, got ${dispatch_html_run_id}", payload)
        self.assertIn(
            "Dispatch response run_id is required and must be numeric when run_id_resolution_mode=dispatch-api.",
            payload,
        )
        self.assertIn(
            "Dispatch response run_id mismatch with resolved workflow_run_id: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "Dispatch response workflow_id is required and must be numeric when run_id_resolution_mode=dispatch-api.",
            payload,
        )
        self.assertIn(
            "Dispatch response workflow_id mismatch with workflow definition id: expected {0}, got {1}",
            payload,
        )
        self.assertIn("Dispatch response run_url must not contain leading or trailing whitespace.", payload)
        self.assertIn("Dispatch response run_url is not canonical: {0}", payload)
        self.assertIn(
            "Dispatch response run_url run_id mismatch with resolved workflow_run_id: expected {0}, got {1}",
            payload,
        )
        self.assertIn("Dispatch response html_url must not contain leading or trailing whitespace.", payload)
        self.assertIn("Dispatch response html_url is not canonical: {0}", payload)
        self.assertIn(
            "Dispatch response html_url run_id mismatch with resolved workflow_run_id: expected {0}, got {1}",
            payload,
        )
        self.assertIn("dispatch_url_identity_verification", payload)
        self.assertIn("dispatch_run_url_host_verified", payload)
        self.assertIn("dispatch_html_url_host_verified", payload)
        self.assertIn("dispatch_run_url_attempt_verified", payload)
        self.assertIn("dispatch_html_url_attempt_verified", payload)
        self.assertIn("{0} must use https scheme.", payload)
        self.assertIn("{0} must not include query or fragment components.", payload)
        self.assertIn("{0} host mismatch with resolved run url host: expected {1}, got {2}", payload)
        self.assertIn("{0} path is not canonical: {1}", payload)
        self.assertIn("{0} repository path mismatch: expected {1}, got {2}", payload)
        self.assertIn("{0} run_id path mismatch: expected {1}, got {2}", payload)
        self.assertIn("{0} attempt path mismatch: expected {1}, got {2}", payload)
        self.assertIn("dispatch response URL host mismatch between run_url and html_url: {0} vs {1}", payload)
        self.assertIn("Checking GitHub CLI authentication and repository API access...", payload)
        self.assertIn("gh auth status reported non-zero; continuing with repository API probe for ${repo}.", payload)
        self.assertIn("repo_probe_output=\"$(gh api \"repos/${repo}\" --jq '.full_name' 2>&1)\"", payload)
        self.assertIn("GitHub repository API probe failed for ${repo}.", payload)
        self.assertIn("Provide a token with repository and Actions API access via GH_TOKEN/GITHUB_TOKEN or gh auth login.", payload)
        self.assertIn("GitHub repository API probe passed for ${repo_probe_output}", payload)
        self.assertIn("GitHub repository API probe mismatch: expected ${repo}, got ${repo_probe_output}", payload)
        self.assertIn("Invalid repo slug: ${value} (expected owner/repo)", payload)
        self.assertIn("require_repo_slug \"$REPO\"", payload)
        self.assertIn("Resolving workflow definition identity for ${workflow_file} on ${repo}...", payload)
        self.assertIn("gh api \"repos/${repo}/actions/workflows/${workflow_encoded}\" 2>&1", payload)
        self.assertIn("Unable to resolve workflow definition for ${workflow_file} on ${repo}.", payload)
        self.assertIn("Resolved workflow id is not numeric for ${workflow_file} on ${repo}: ${workflow_id}", payload)
        self.assertIn("Resolved workflow path is invalid for ${workflow_file} on ${repo}: ${workflow_path}", payload)
        self.assertIn("Resolved workflow path is outside .github/workflows for ${workflow_file} on ${repo}: ${workflow_path}", payload)
        self.assertIn("Resolved workflow definition path mismatch for ${workflow_file}: expected ${expected_workflow_path}, got ${workflow_path}", payload)
        self.assertIn("Resolved workflow state is not active for ${workflow_file} on ${repo}: ${workflow_state}", payload)
        self.assertIn("Resolved workflow name is invalid for ${workflow_file} on ${repo}: ${workflow_name}", payload)
        self.assertIn("Resolved workflow definition id=${workflow_id} path=${workflow_path} state=${workflow_state} name=${workflow_name}", payload)
        self.assertIn("run workflow_id is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run workflow_id is not numeric in run details for run_id=${run_id}: ${run_workflow_id_api}", payload)
        self.assertIn("run workflow_id mismatch for run_id=${run_id}: expected ${resolved_workflow_definition_id}, got ${run_workflow_id_api}", payload)
        self.assertIn("Resolved run workflow_id is not numeric.", payload)
        self.assertIn("Resolved workflow definition id is not numeric.", payload)
        self.assertIn("Resolved run workflow_id mismatch with workflow definition id: expected {0}, got {1}", payload)
        self.assertIn("gh run view", payload)
        self.assertIn("--json attempt,status,conclusion,url,updatedAt,event,headBranch,workflowName,headSha,number,createdAt,startedAt", payload)
        self.assertIn("actions/runs/${run_id}/attempts/${run_attempt}/jobs?per_page=100", payload)
        self.assertIn("Verifying promotion gate job and step outcomes for run attempt ${run_attempt}", payload)
        self.assertIn("Workflow jobs payload is invalid for promotion-gate verification.", payload)
        self.assertIn("Expected exactly one job named {0}; found {1}.", payload)
        self.assertIn("Promotion gate job status must be completed; got {0}", payload)
        self.assertIn("Promotion gate job conclusion must be success; got {0}", payload)
        self.assertIn("Promotion gate job id must be numeric; got {0}", payload)
        self.assertIn("Promotion gate job runner_name is missing.", payload)
        self.assertIn("Promotion gate job runner_group_name is missing.", payload)
        self.assertIn("Promotion gate job run_id mismatch: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job run_attempt must be numeric when provided.", payload)
        self.assertIn("Promotion gate job run_attempt mismatch: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job html_url is missing.", payload)
        self.assertIn("Promotion gate job html_url must not contain leading or trailing whitespace.", payload)
        self.assertIn("Promotion gate job html_url must use https scheme.", payload)
        self.assertIn("Promotion gate job html_url host is missing.", payload)
        self.assertIn("Promotion gate job html_url must not include query or fragment components.", payload)
        self.assertIn("Promotion gate job html_url path is not canonical: {0}", payload)
        self.assertIn("Promotion gate job html_url repository path mismatch: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job html_url run_id path mismatch: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job html_url job_id path mismatch: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job html_url attempt path mismatch: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job html_url host mismatch with run url host: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job {0} is missing.", payload)
        self.assertIn("Promotion gate job {0} is not valid ISO-8601: {1}", payload)
        self.assertIn("Promotion gate job completed_at precedes started_at: {0} < {1}", payload)
        self.assertIn("job_started_at = str(job.get(\"started_at\", \"\"))", payload)
        self.assertIn("job_completed_at = str(job.get(\"completed_at\", \"\"))", payload)
        self.assertIn("Promotion gate job head_sha is missing while run head_sha is present.", payload)
        self.assertIn("Promotion gate job head_sha is not a canonical 40-char lowercase hex digest.", payload)
        self.assertIn("Promotion gate job head_sha mismatch with run head_sha: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job head_branch is missing while run head_branch is present.", payload)
        self.assertIn("Promotion gate job head_branch must not contain leading or trailing whitespace.", payload)
        self.assertIn("Promotion gate job head_branch mismatch with run head_branch: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job workflow_name is missing while run workflow_name is present.", payload)
        self.assertIn("Promotion gate job workflow_name must not contain leading or trailing whitespace.", payload)
        self.assertIn("Resolved run workflow_name must not contain leading or trailing whitespace.", payload)
        self.assertIn("Promotion gate job workflow_name mismatch with run workflow_name: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job labels payload is invalid.", payload)
        self.assertIn("Promotion gate job labels must not mix self-hosted and github-hosted markers.", payload)
        self.assertIn("Promotion gate job actor payload is invalid when provided.", payload)
        self.assertIn("Promotion gate job actor.login is missing when actor payload is provided.", payload)
        self.assertIn("Promotion gate job actor.login must not contain leading or trailing whitespace.", payload)
        self.assertIn("Promotion gate job actor.login mismatch with run actor: expected {0}, got {1}", payload)
        self.assertIn("Promotion gate job triggering_actor payload is invalid when provided.", payload)
        self.assertIn("Promotion gate job triggering_actor.login is missing when triggering_actor payload is provided.", payload)
        self.assertIn("Promotion gate job triggering_actor.login must not contain leading or trailing whitespace.", payload)
        self.assertIn("Promotion gate job triggering_actor.login mismatch with run triggering_actor: expected {0}, got {1}", payload)
        self.assertIn("Missing required promotion gate step: {0}", payload)
        self.assertIn("Promotion gate step {0} must conclude with success; got {1}", payload)
        self.assertIn("rotation rehearsal step must conclude with success when required; got {0}", payload)
        self.assertIn("rotation rehearsal step must conclude with skipped when rehearsal is not required; got {0}", payload)
        self.assertIn("gh api \"repos/${REPO}/actions/runs/${run_id}/artifacts?per_page=100&name=${artifact_name}\"", payload)
        self.assertIn("gh api \"repos/${REPO}/actions/artifacts/${artifact_id}/zip\" --method GET --header \"Accept: application/zip\" --output \"$artifact_zip_path\"", payload)
        self.assertIn("--artifact-index-wait-seconds <int>", payload)
        self.assertIn("--preflight-only", payload)
        self.assertIn("--preflight-only cannot be combined with --run-id.", payload)
        self.assertIn("write_promotion_preflight_receipt()", payload)
        self.assertIn("promotion_preflight_receipt.json", payload)
        self.assertIn("enc2sop-promotion-preflight/v1", payload)
        self.assertIn('"repository_api_verified": True', payload)
        self.assertIn('"dispatch_executed": False', payload)
        self.assertIn("Promotion evidence preflight passed.", payload)
        self.assertIn("preflight_receipt=${preflight_receipt_path}", payload)
        self.assertIn("rerun without --preflight-only to dispatch or capture the protected-branch promotion run", payload)
        self.assertIn("--expected-environment <name>", payload)
        self.assertIn("--no-require-environment-reviewers", payload)
        self.assertIn("--required-secret <name>", payload)
        self.assertIn("strip_crlf()", payload)
        self.assertIn("secret_name=\"$(strip_crlf \"$secret_name\")\"", payload)
        self.assertIn("required_secret_name=\"$(strip_crlf \"$required_secret_name\")\"", payload)
        self.assertIn("verify_branch_protection_preflight", payload)
        self.assertIn("branches API protected flag must be true", payload)
        self.assertIn("verify_environment_preflight", payload)
        self.assertIn("Environment preflight requires at least one reviewer", payload)
        self.assertIn("protection_rules", payload)
        self.assertIn("required_reviewers", payload)
        self.assertIn("verify_secret_metadata_name", payload)
        self.assertIn("Required secret metadata not found", payload)
        self.assertIn("branch_protection_preflight", payload)
        self.assertIn("environment_reviewer_preflight", payload)
        self.assertIn("required_secret_preflight", payload)
        self.assertIn("\"branch_protection_preflight\": branch_protection_preflight", payload)
        self.assertIn("\"environment_reviewer_preflight\": environment_preflight", payload)
        self.assertIn("\"required_secret_preflight\": {", payload)
        self.assertIn("SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64", payload)
        self.assertIn("Timed out waiting for artifact metadata indexing for ${artifact_name}.", payload)
        self.assertIn("Artifact metadata not yet indexed for ${artifact_name}; retrying in ${POLL_INTERVAL_SECONDS}s...", payload)
        self.assertIn("Artifact archive digest mismatch for {0}: expected {1}, got {2}", payload)
        self.assertIn("Artifact archive size mismatch for {0}: expected {1}, got {2}", payload)
        self.assertIn("Artifact archive member path traversal detected: {0}", payload)
        self.assertIn("Artifact archive contains symlink entry: {0}", payload)
        self.assertIn("promotion_artifact_bundle.zip is missing bundle_manifest.json", payload)
        self.assertIn("promotion_artifact_bundle.zip member path must use forward slashes: {0}", payload)
        self.assertIn("promotion_artifact_bundle.zip member path is not relative: {0}", payload)
        self.assertIn("promotion_artifact_bundle.zip member path traversal detected: {0}", payload)
        self.assertIn("promotion_artifact_bundle.zip contains symlink entry: {0}", payload)
        self.assertIn("promotion_artifact_bundle.zip contains duplicate member path: {0}", payload)
        self.assertIn(
            "promotion_artifact_bundle.zip entries must exactly match bundle_manifest.files archive_path values plus bundle_manifest.json; missing={0}; extra={1}",
            payload,
        )
        self.assertIn("bundle_manifest schema mismatch: expected enc2sop-promotion-artifact-bundle/v1, got {0}", payload)
        self.assertIn("bundle_manifest.file_count must be an integer", payload)
        self.assertIn(
            "bundle_manifest.file_count must match length of bundle_manifest.files: expected {0}, got {1}",
            payload,
        )
        self.assertIn("bundle_manifest missing required entry: {0}", payload)
        self.assertIn("bundle_manifest missing required entry: promotion_policy", payload)
        self.assertIn("bundle_manifest missing required entry: promotion_workflow", payload)
        self.assertIn(
            "bundle_manifest.files names must exactly match required promotion evidence entries; missing={0}; extra={1}",
            payload,
        )
        self.assertIn("bundle_manifest.files[{0}].archive_path must not contain leading or trailing whitespace", payload)
        self.assertIn("bundle_manifest.files[{0}].archive_path must be a relative forward-slash path", payload)
        self.assertIn("bundle_manifest.files[{0}].archive_path contains traversal or empty path segment", payload)
        self.assertIn("bundle_manifest.files[{0}].archive_path must not target bundle_manifest.json", payload)
        self.assertIn("bundle_manifest.files duplicate archive_path: {0}", payload)
        self.assertIn(
            "bundle_manifest.files[{0}].sha256 mismatch with promotion_artifact_bundle.zip member {1}: expected {2}, got {3}",
            payload,
        )
        self.assertIn("bundle_manifest sha256 mismatch for {0}: expected {1}, got {2}", payload)
        self.assertIn(
            "promotion_artifact_bundle.zip member digest mismatch for {0}: expected {1}, got {2}",
            payload,
        )
        self.assertIn(
            "bundle_manifest archive_path mismatch for promotion_policy: expected policy/promotion_rollout_policy.json, got {0}",
            payload,
        )
        self.assertIn(
            "bundle_manifest archive_path mismatch for promotion_workflow: expected workflow/release_promotion.yml, got {0}",
            payload,
        )
        self.assertIn(
            "promotion_artifact_audit_report schema mismatch: expected enc2sop-promotion-artifact-audit/v1, got {0}",
            payload,
        )
        self.assertIn("promotion_artifact_audit_report.passed must be true", payload)
        self.assertIn("promotion_artifact_audit_report.summary.total_failures must be an integer", payload)
        self.assertIn("promotion_artifact_audit_report.summary.total_failures must be 0", payload)
        self.assertIn("promotion_artifact_audit_report.failures must be a list", payload)
        self.assertIn(
            "promotion_artifact_audit_report.summary.total_failures must match length of promotion_artifact_audit_report.failures",
            payload,
        )
        self.assertIn("promotion_artifact_audit_report.failures must be empty when report passed=true", payload)
        self.assertIn("promotion_audit_report schema mismatch: expected enc2sop-promotion-audit-report/v1, got {0}", payload)
        self.assertIn("promotion_audit_report.passed must be true", payload)
        self.assertIn("promotion_audit_report.summary.total_failures must be an integer", payload)
        self.assertIn("promotion_audit_report.summary.total_failures must be 0", payload)
        self.assertIn("promotion_audit_report.failures must be a list", payload)
        self.assertIn(
            "promotion_audit_report.summary.total_failures must match length of promotion_audit_report.failures",
            payload,
        )
        self.assertIn("promotion_audit_report.failures must be empty when report passed=true", payload)
        self.assertIn("promotion_audit_report.inputs is required", payload)
        self.assertIn("promotion_audit_report.inputs.evidence_file is required", payload)
        self.assertIn("promotion_audit_report.inputs.evidence_file must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_audit_report.inputs.evidence_sha256 must be a 64-char lowercase hex digest", payload)
        self.assertIn("promotion_audit_report.inputs.evidence_sha256 mismatch with promotion_evidence.json: expected {0}, got {1}", payload)
        self.assertIn("promotion_audit_report.inputs.policy_file is required", payload)
        self.assertIn("promotion_audit_report.inputs.policy_file must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_audit_report.inputs.policy_sha256 must be a 64-char lowercase hex digest", payload)
        self.assertIn("promotion_audit_report.inputs.policy_sha256 mismatch with promotion_policy bundle entry: expected {0}, got {1}", payload)
        self.assertIn("promotion_audit_report.inputs.workflow_file is required", payload)
        self.assertIn("promotion_audit_report.inputs.workflow_file must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_audit_report.inputs.workflow_sha256 must be a 64-char lowercase hex digest", payload)
        self.assertIn("promotion_audit_report.inputs.workflow_sha256 mismatch with promotion_workflow bundle entry: expected {0}, got {1}", payload)
        self.assertIn("promotion_artifact_audit_report.release_dir is required", payload)
        self.assertIn("promotion_artifact_audit_report.release_dir must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_artifact_audit_report.promotion_evidence_file is required", payload)
        self.assertIn("promotion_artifact_audit_report.promotion_evidence_file must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_artifact_audit_report.promotion_report_file is required", payload)
        self.assertIn("promotion_artifact_audit_report.promotion_report_file must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_artifact_audit_report.rotation_report_file is required", payload)
        self.assertIn("promotion_artifact_audit_report.rotation_report_file must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_artifact_audit_report.promotion_policy_file is required", payload)
        self.assertIn("promotion_artifact_audit_report.promotion_policy_file must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_artifact_audit_report.promotion_workflow_file is required", payload)
        self.assertIn("promotion_artifact_audit_report.promotion_workflow_file must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "promotion_artifact_audit_report.promotion_policy_file does not match promotion_audit_report.inputs.policy_file: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "promotion_artifact_audit_report.promotion_workflow_file does not match promotion_audit_report.inputs.workflow_file: expected {0}, got {1}",
            payload,
        )
        self.assertIn("promotion_artifact_audit_report.promotion_run_receipt_file is required", payload)
        self.assertIn("promotion_artifact_audit_report.promotion_run_receipt_file must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_artifact_audit_report.release_approval_key_id_expected is required", payload)
        self.assertIn("promotion_artifact_audit_report.release_approval_key_id_expected must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "{0} does not match promotion_run_receipt.artifacts[{1}].path: expected {2}, got {3}",
            payload,
        )
        self.assertIn(
            "promotion_audit_report.inputs.policy_file does not match promotion_run_receipt.artifacts[promotion_policy].path: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "promotion_audit_report.inputs.workflow_file does not match promotion_run_receipt.artifacts[promotion_workflow].path: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "promotion_artifact_audit_report.promotion_policy_file does not match promotion_run_receipt.artifacts[promotion_policy].path: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "promotion_artifact_audit_report.promotion_workflow_file does not match promotion_run_receipt.artifacts[promotion_workflow].path: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "promotion_run_receipt.artifacts missing required entry: promotion_policy",
            payload,
        )
        self.assertIn(
            "promotion_run_receipt.artifacts missing required entry: promotion_workflow",
            payload,
        )
        self.assertIn(
            "promotion_artifact_audit_report.promotion_run_receipt_file does not match promotion_run_receipt.artifacts[promotion_run_receipt].path",
            payload,
        )
        self.assertIn(
            "promotion_artifact_audit_report.release_approval_key_id_expected mismatch with release_approval.signature.key_id: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "promotion_artifact_audit_report.release_approval_key_id_expected mismatch with release_receipt.release_approval_key_id: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "promotion_artifact_audit_report.release_approval_key_id_expected mismatch with promotion_run_receipt.release_approval_key_id: expected {0}, got {1}",
            payload,
        )
        self.assertIn("promotion_artifact_audit_report.release_approval_signature_required must be true", payload)
        self.assertIn("promotion_artifact_audit_report.ci_context_match_required must be true", payload)
        self.assertIn("promotion_artifact_audit_report.artifact_context_consistency_required must be true", payload)
        self.assertIn("promotion_artifact_audit_report.rotation_pass_required must be boolean", payload)
        self.assertIn("promotion_artifact_audit_report.rotation_pass_required mismatch: expected {0}, got {1}", payload)
        self.assertIn("release_approval schema mismatch: expected enc2sop-release-approval/v1, got {0}", payload)
        self.assertIn("release_approval.signature is required", payload)
        self.assertIn("release_approval.signature.algorithm must be hmac-sha256", payload)
        self.assertIn("release_approval.signature.key_id is required", payload)
        self.assertIn("release_approval.signature.key_id must not contain leading or trailing whitespace", payload)
        self.assertIn("release_approval.signature.digest_hex must be a 64-char lowercase hex digest", payload)
        self.assertIn("{0} is required", payload)
        self.assertIn("{0} must not contain leading or trailing whitespace", payload)
        self.assertIn("{0} is not valid ISO-8601: {1}", payload)
        self.assertIn("release_approval.approvers must be a non-empty list", payload)
        self.assertIn("release_approval.approvers[{0}] must be a non-empty string", payload)
        self.assertIn("release_approval.approvers[{0}] must not contain leading or trailing whitespace", payload)
        self.assertIn("release_approval.approvers contains duplicate value: {0}", payload)
        self.assertIn("release_approval.notes must be a non-empty string when present", payload)
        self.assertIn("release_approval.notes must not contain leading or trailing whitespace", payload)
        self.assertIn("release_approval.release_bundle_relative_path is required", payload)
        self.assertIn("release_approval.release_bundle_relative_path must not contain leading or trailing whitespace", payload)
        self.assertIn("release_approval.release_bundle_relative_path must point to release_bundle.json; got {0}", payload)
        self.assertIn("release_approval.release_bundle_sha256 must be a 64-char lowercase hex digest", payload)
        self.assertIn(
            "release_approval.release_bundle_sha256 mismatch with release_bundle.json: expected {0}, got {1}",
            payload,
        )
        self.assertIn("release_receipt schema mismatch: expected enc2sop-release-receipt/v1, got {0}", payload)
        self.assertIn("release_receipt.release_approval_required must be true", payload)
        self.assertIn("release_receipt.release_approval_verified must be true", payload)
        self.assertIn("release_receipt.release_bundle_relative_path is required", payload)
        self.assertIn("release_receipt.release_bundle_relative_path must not contain leading or trailing whitespace", payload)
        self.assertIn("release_receipt.release_bundle_relative_path must be release_bundle.json; got {0}", payload)
        self.assertIn(
            "release_receipt.release_bundle_relative_path mismatch with release_approval.release_bundle_relative_path: expected {0}, got {1}",
            payload,
        )
        self.assertIn("release_receipt.release_bundle_sha256 must be a 64-char lowercase hex digest", payload)
        self.assertIn(
            "release_receipt.release_bundle_sha256 mismatch with release_bundle.json: expected {0}, got {1}",
            payload,
        )
        self.assertIn("release_receipt.release_approval_sha256 must be a 64-char lowercase hex digest", payload)
        self.assertIn(
            "release_receipt.release_approval_sha256 mismatch with release_approval.json: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "release_receipt.release_approval_signature_digest must be a 64-char lowercase hex digest",
            payload,
        )
        self.assertIn(
            "release_receipt.release_approval_signature_digest mismatch with release_approval.signature.digest_hex: expected {0}, got {1}",
            payload,
        )
        self.assertIn("release_receipt.release_approval_file is required", payload)
        self.assertIn("release_receipt.release_approval_file must not contain leading or trailing whitespace", payload)
        self.assertIn("release_receipt.release_approval_file must point to release_approval.json; got {0}", payload)
        self.assertIn("release_receipt.release_approval_key_id is required", payload)
        self.assertIn("release_receipt.release_approval_key_id must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "release_receipt.generated_at_utc must be >= release_approval.approved_at_utc; got {0} < {1}",
            payload,
        )
        self.assertIn("release_receipt.github_context must be a JSON object", payload)
        self.assertIn("release_receipt.release_approval_github_context must be a JSON object", payload)
        self.assertIn("release_approval.github_context must be a JSON object", payload)
        self.assertIn(
            "release_receipt.release_approval_github_context must match release_approval.github_context",
            payload,
        )
        self.assertIn(
            "promotion_run_receipt schema mismatch: expected enc2sop-promotion-run-receipt/v1, got {0}",
            payload,
        )
        self.assertIn(
            "promotion_audit_report.generated_at_utc must be >= release_receipt.generated_at_utc; got {0} < {1}",
            payload,
        )
        self.assertIn(
            "promotion_artifact_audit_report.generated_at_utc must be >= promotion_audit_report.generated_at_utc; got {0} < {1}",
            payload,
        )
        self.assertIn(
            "promotion_run_receipt.generated_at_utc must be >= promotion_artifact_audit_report.generated_at_utc; got {0} < {1}",
            payload,
        )
        self.assertIn("promotion_run_receipt.passed must be true", payload)
        self.assertIn("promotion_run_receipt.rotation_pass_required must be boolean", payload)
        self.assertIn("promotion_run_receipt.rotation_pass_required mismatch: expected {0}, got {1}", payload)
        self.assertIn("promotion_run_receipt.release_approval_key_id is required", payload)
        self.assertIn("promotion_run_receipt.release_approval_key_id must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "promotion_run_receipt.release_approval_key_id mismatch with release_approval.signature.key_id: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "promotion_run_receipt.release_approval_key_id mismatch with release_receipt.release_approval_key_id: expected {0}, got {1}",
            payload,
        )
        self.assertIn("promotion_run_receipt.signature is required", payload)
        self.assertIn("promotion_run_receipt.signature.algorithm must be hmac-sha256", payload)
        self.assertIn("promotion_run_receipt.signature.key_id is required", payload)
        self.assertIn("promotion_run_receipt.signature.key_id must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "promotion_run_receipt.signature.key_id mismatch with promotion_run_receipt.release_approval_key_id: expected {0}, got {1}",
            payload,
        )
        self.assertIn("promotion_run_receipt.signature.digest_hex must be a 64-char lowercase hex digest", payload)
        self.assertIn("promotion_run_receipt.artifacts must be a list", payload)
        self.assertIn("promotion_run_receipt.artifacts missing required entry: {0}", payload)
        self.assertIn("promotion_run_receipt.artifacts[{0}].path must end with {1}; got {2}", payload)
        self.assertIn("promotion_run_receipt.artifacts[{0}].sha256 mismatch: expected {1}, got {2}", payload)
        self.assertIn("promotion_run_receipt.promotion_artifact_audit_report_file is required", payload)
        self.assertIn(
            "promotion_run_receipt.promotion_artifact_audit_report_file does not match artifacts[promotion_artifact_audit_report].path",
            payload,
        )
        self.assertIn(
            "release_receipt.release_bundle_relative_path does not match promotion_run_receipt.artifacts[release_bundle].path basename: expected {0}, got {1}",
            payload,
        )
        self.assertIn(
            "release_receipt.release_approval_file does not match promotion_run_receipt.artifacts[release_approval].path: expected {0}, got {1}",
            payload,
        )
        self.assertIn("promotion_run_receipt.github_context missing required key: {0}", payload)
        self.assertIn(
            "promotion_run_receipt.github_context.{0} must not contain leading or trailing whitespace",
            payload,
        )
        self.assertIn("promotion_run_receipt.github_context.{0} mismatch: expected {1}, got {2}", payload)
        self.assertIn("{0} missing required key: {1}", payload)
        self.assertIn("{0}.{1} must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "{0}.{1} mismatch with promotion_run_receipt.github_context: expected {2}, got {3}",
            payload,
        )
        self.assertIn("Resolved run head_sha is not a canonical 40-char lowercase hex digest.", payload)
        self.assertIn("Resolved run_number is not numeric.", payload)
        self.assertIn("Resolved run retention_days is not numeric.", payload)
        self.assertIn("Resolved run retention_days must be positive.", payload)
        self.assertIn("Resolved run head_branch must not contain leading or trailing whitespace.", payload)
        self.assertIn("Invalid workflow-job-id: ${WORKFLOW_JOB_ID} (expected non-empty token without whitespace)", payload)
        self.assertIn("--workflow-job-id <job-id>", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_SHA\", workflow_head_sha)", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_RUN_NUMBER\", workflow_run_number)", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_RETENTION_DAYS\", workflow_retention_days)", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_JOB\", workflow_job_id)", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_REF\", \"refs/heads/{0}\".format(workflow_head_branch))", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_REF_NAME\", workflow_head_branch)", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_REF_TYPE\", \"branch\")", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_REPOSITORY_OWNER\", expected_repo_owner)", payload)
        self.assertIn("promotion_run_receipt.github_context.GITHUB_WORKFLOW_SHA must be a 40-char lowercase hex digest", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_SERVER_URL\", expected_server_url)", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_API_URL\", expected_api_url)", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_GRAPHQL_URL\", expected_graphql_url)", payload)
        self.assertIn("promotion_run_receipt.github_context.{0} must be a positive integer", payload)
        self.assertIn("Resolved run workflow path@ref identity must not contain leading or trailing whitespace.", payload)
        self.assertIn("Resolved run workflow path@ref identity is invalid: {0}", payload)
        self.assertIn("Resolved run workflow ref segment must not contain leading or trailing whitespace.", payload)
        self.assertIn("promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF is invalid: {0}", payload)
        self.assertIn("promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF ref segment must not contain leading or trailing whitespace", payload)
        self.assertIn("promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF workflow path mismatch: expected {0}, got {1}", payload)
        self.assertIn("Resolved run workflow_ref is not canonical for semantic parity checks: {0}", payload)
        self.assertIn("promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF ref mismatch: expected {0}, got {1}", payload)
        self.assertIn("Resolved run repository.id is not numeric.", payload)
        self.assertIn("promotion_run_receipt.github_context.GITHUB_REPOSITORY_ID mismatch with run repository.id: expected {0}, got {1}", payload)
        self.assertIn("Resolved run repository.owner.id is not numeric.", payload)
        self.assertIn("promotion_run_receipt.github_context.GITHUB_REPOSITORY_OWNER_ID mismatch with run repository.owner.id: expected {0}, got {1}", payload)
        self.assertIn("Resolved run actor.id is not numeric.", payload)
        self.assertIn("promotion_run_receipt.github_context.GITHUB_ACTOR_ID mismatch with run actor.id: expected {0}, got {1}", payload)
        self.assertIn("_require_run_receipt_context_key(\"GITHUB_WORKFLOW\", promotion_workflow_name_verified)", payload)
        self.assertIn("Verifying artifact archive digest and extracting ${artifact_name}", payload)
        self.assertIn("soenc-promotion-${run_id}-attempt-${run_attempt}", payload)
        self.assertIn("--run-id <id>", payload)
        self.assertIn("--run-attempt <int>", payload)
        self.assertIn("capture_mode", payload)
        self.assertIn("Using existing workflow run run_id=${run_id} on ${REPO}", payload)
        self.assertIn("run_id_resolution_mode=${run_id_resolution_mode}", payload)
        self.assertIn("\"workflow_run_id_resolution_mode\": run_id_resolution_mode", payload)
        self.assertIn("Dispatch output did not include a run id; resolving via recent workflow runs...", payload)
        self.assertIn("--run-attempt requires --run-id.", payload)
        self.assertIn("run_attempt mismatch for run_id=${run_id}", payload)
        self.assertIn("gh api \"repos/${REPO}/actions/runs/${run_id}\"", payload)
        self.assertIn("Artifact list payload is invalid for run metadata verification.", payload)
        self.assertIn("Expected exactly one artifact named {0}; found {1}.", payload)
        self.assertIn("Artifact workflow_run.id mismatch for {0}: expected {1}, got {2}", payload)
        self.assertIn("Artifact {0} has invalid digest metadata.", payload)
        self.assertIn("Artifact {0} archive_download_url must not contain leading or trailing whitespace.", payload)
        self.assertIn("Artifact {0} archive_download_url must use https scheme.", payload)
        self.assertIn("Artifact {0} archive_download_url host is missing.", payload)
        self.assertIn("Artifact {0} archive_download_url must not include query or fragment components.", payload)
        self.assertIn("Artifact {0} archive_download_url path mismatch: expected {1}, got {2}", payload)
        self.assertIn("artifact archive_download_url host mismatch for run_id=${run_id}: expected API host ${expected_artifact_api_host}, got ${artifact_archive_download_url_host}", payload)
        self.assertIn("run event mismatch between summary and run details for run_id=${run_id}", payload)
        self.assertIn("run status is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run status is not completed in run details for run_id=${run_id}", payload)
        self.assertIn("run status mismatch between summary and run details for run_id=${run_id}", payload)
        self.assertIn("run conclusion is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run conclusion is not success in run details for run_id=${run_id}", payload)
        self.assertIn("run conclusion mismatch between summary and run details for run_id=${run_id}", payload)
        self.assertIn("run html_url mismatch between summary and run details for run_id=${run_id}", payload)
        self.assertIn("run workflow ref is missing for run_id={0}", payload)
        self.assertIn("run workflow ref must not contain leading or trailing whitespace for run_id={0}", payload)
        self.assertIn("run workflow ref short branch mismatch for run_id={0}: workflow_ref={1}, head_branch={2}", payload)
        self.assertIn("run workflow ref is not canonical or semantically normalizable for run_id={0}: {1}", payload)
        self.assertIn("run workflow ref normalization mismatch with head branch for run_id=${run_id}", payload)
        self.assertIn("{0} path is not a canonical GitHub Actions run URL: {1}", payload)
        self.assertIn("{0} repository path mismatch: expected {1}, got {2}", payload)
        self.assertIn("{0} run_id path mismatch: expected {1}, got {2}", payload)
        self.assertIn("{0} attempt path mismatch: expected {1}, got {2}", payload)
        self.assertIn("run url host mismatch between summary and run details for run_id={0}: {1} vs {2}", payload)
        self.assertIn("head_branch mismatch between summary and run details for run_id=${run_id}", payload)
        self.assertIn("run head_sha is not a canonical 40-char lowercase hex digest in summary metadata for run_id=${run_id}", payload)
        self.assertIn("head_sha mismatch between summary and run details for run_id=${run_id}", payload)
        self.assertIn("run number is not numeric in summary metadata for run_id=${run_id}", payload)
        self.assertIn("run number is not numeric in run details metadata for run_id=${run_id}", payload)
        self.assertIn("run number mismatch between summary and run details for run_id=${run_id}", payload)
        self.assertIn("run retention_days is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run retention_days is not numeric in run details for run_id=${run_id}", payload)
        self.assertIn("run retention_days must be positive in run details for run_id=${run_id}", payload)
        self.assertIn("run attempt is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run attempt is not numeric in run details for run_id=${run_id}", payload)
        self.assertIn("run attempt is not numeric in summary metadata for run_id=${run_id}", payload)
        self.assertIn("run attempt mismatch between summary and run details for run_id=${run_id}", payload)
        self.assertIn("run id is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run id is not numeric in run details for run_id=${run_id}", payload)
        self.assertIn("run id mismatch between resolved run id and run details for run_id=${run_id}", payload)
        self.assertIn("run repository.full_name is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run repository.full_name must not contain leading or trailing whitespace in run details for run_id=${run_id}", payload)
        self.assertIn("run repository.full_name mismatch for run_id=${run_id}: expected ${REPO}, got ${run_repository_full_name_api}", payload)
        self.assertIn("run repository.owner.login is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run repository.owner.login must not contain leading or trailing whitespace in run details for run_id=${run_id}", payload)
        self.assertIn("run repository.owner.login mismatch for run_id=${run_id}: expected ${expected_repo_owner_api}, got ${run_repository_owner_login_api}", payload)
        self.assertIn("run repository.id is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run repository.id is not numeric in run details for run_id=${run_id}", payload)
        self.assertIn("run repository.owner.id is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run repository.owner.id is not numeric in run details for run_id=${run_id}", payload)
        self.assertIn("run actor.id is missing in run details for run_id=${run_id}", payload)
        self.assertIn("run actor.id is not numeric in run details for run_id=${run_id}", payload)
        self.assertIn("{0} is missing for run_id={1}", payload)
        self.assertIn("run summary startedAt precedes createdAt for run_id={0}: {1} < {2}", payload)
        self.assertIn("run summary updatedAt precedes startedAt for run_id={0}: {1} < {2}", payload)
        self.assertIn("run detail run_started_at precedes created_at for run_id={0}: {1} < {2}", payload)
        self.assertIn("run detail updated_at precedes run_started_at for run_id={0}: {1} < {2}", payload)
        self.assertIn("run created timestamp mismatch between summary and run details for run_id={0}: {1} vs {2}", payload)
        self.assertIn("run started timestamp mismatch between summary and run details for run_id={0}: {1} vs {2}", payload)
        self.assertIn("run updated timestamp mismatch between summary and run details for run_id={0}: {1} vs {2}", payload)
        self.assertIn(
            "workflow_run_timestamp_verification.updated_at_detail must be >= workflow_run_timestamp_verification.started_at_detail; got {0} < {1}",
            payload,
        )
        self.assertIn(
            "{0} must be >= workflow_run_timestamp_verification.started_at_detail; got {1} < {2}",
            payload,
        )
        self.assertIn(
            "{0} must be <= workflow_run_timestamp_verification.updated_at_detail; got {1} > {2}",
            payload,
        )
        self.assertIn(
            "artifact_metadata.updated_at must be >= artifact_metadata.created_at; got {0} < {1}",
            payload,
        )
        self.assertIn("artifact_metadata.workflow_run_id", payload)
        self.assertIn("artifact_metadata.workflow_run_id mismatch with workflow_run_id: expected {0}, got {1}", payload)
        self.assertIn("artifact_metadata.size_in_bytes", payload)
        self.assertIn("artifact_archive_verification.size_in_bytes_verified", payload)
        self.assertIn(
            "artifact_archive_verification.size_in_bytes_verified mismatch with artifact_metadata.size_in_bytes: expected {0}, got {1}",
            payload,
        )
        self.assertIn("artifact_metadata.digest must be a canonical sha256:<64-char lowercase hex> value", payload)
        self.assertIn(
            "artifact_archive_verification.digest_verified must be a canonical sha256:<64-char lowercase hex> value",
            payload,
        )
        self.assertIn(
            "artifact_archive_verification.digest_verified mismatch with artifact_metadata.digest: expected {0}, got {1}",
            payload,
        )
        self.assertIn("artifact_archive_verification.entry_count_verified", payload)
        self.assertIn("artifact_metadata.archive_download_url_host is required", payload)
        self.assertIn("artifact_metadata.archive_download_url_host must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "artifact_metadata.archive_download_url_host mismatch with expected API host: expected {0}, got {1}",
            payload,
        )
        self.assertIn("artifact_metadata.workflow_head_branch must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "artifact_metadata.workflow_head_branch mismatch with workflow_head_branch: expected {0}, got {1}",
            payload,
        )
        self.assertIn("artifact_metadata.workflow_head_sha must not contain leading or trailing whitespace", payload)
        self.assertIn("artifact_metadata.workflow_head_sha must be a 40-char lowercase hex digest", payload)
        self.assertIn(
            "artifact_metadata.workflow_head_sha mismatch with workflow_head_sha: expected {0}, got {1}",
            payload,
        )
        self.assertIn("\"artifact_metadata.created_at\",", payload)
        self.assertIn("\"artifact_metadata.updated_at\",", payload)
        self.assertIn(
            "promotion_audit_report.generated_at_utc must be >= release_receipt.generated_at_utc; got {0} < {1}",
            payload,
        )
        self.assertIn("{0} is missing for artifact {1} (run_id={2})", payload)
        self.assertIn("artifact updated_at precedes created_at for {0} (run_id={1}): {2} < {3}", payload)
        self.assertIn("artifact expires_at precedes updated_at for {0} (run_id={1}): {2} < {3}", payload)
        self.assertIn("artifact workflow_head_branch mismatch for run_id=${run_id}", payload)
        self.assertIn("artifact workflow_head_sha mismatch for run_id=${run_id}", payload)
        self.assertIn("workflow path mismatch for run_id=${run_id}", payload)
        self.assertIn("run event mismatch for dispatched run_id=${run_id}", payload)
        self.assertIn("run event is not supported for promotion evidence capture", payload)
        self.assertIn("head_branch mismatch for run_id=${run_id}", payload)
        self.assertIn("workflow_path", payload)
        self.assertIn("workflow_path_ref", payload)
        self.assertIn("workflow_head_branch", payload)
        self.assertIn("workflow_head_sha", payload)
        self.assertIn("workflow_job_id", payload)
        self.assertIn("workflow_run_number", payload)
        self.assertIn("artifact_metadata", payload)
        self.assertIn("archive_download_url_host", payload)
        self.assertIn("artifact_archive_verification", payload)
        self.assertIn("digest_verified", payload)
        self.assertIn("size_in_bytes_verified", payload)
        self.assertIn("entry_count_verified", payload)
        self.assertIn("bundle_manifest_verification", payload)
        self.assertIn("required_entries_verified", payload)
        self.assertIn("archive_entries_verified", payload)
        self.assertIn("archive_entry_count_verified", payload)
        self.assertIn("archive_member_sha256", payload)
        self.assertIn("manifest_sha256", payload)
        self.assertIn("promotion_run_receipt_verification", payload)
        self.assertIn("artifact_entries_verified", payload)
        self.assertIn("artifact_entry_count_verified", payload)
        self.assertIn("approval_lineage_timestamps", payload)
        self.assertIn("release_approval_approved_at_utc", payload)
        self.assertIn("release_receipt_generated_at_utc", payload)
        self.assertIn("promotion_audit_report_generated_at_utc", payload)
        self.assertIn("promotion_artifact_audit_report_generated_at_utc", payload)
        self.assertIn("promotion_run_receipt_generated_at_utc", payload)
        self.assertIn("release_approval_metadata_verification", payload)
        self.assertIn("approver_count", payload)
        self.assertIn("approvers", payload)
        self.assertIn("notes_present", payload)
        self.assertIn("workflow_run_html_url", payload)
        self.assertIn("workflow_run_url_verification", payload)
        self.assertIn("host_summary", payload)
        self.assertIn("host_detail", payload)
        self.assertIn("attempt_summary", payload)
        self.assertIn("attempt_detail", payload)
        self.assertIn("workflow_run_timestamp_verification", payload)
        self.assertIn("created_at_summary", payload)
        self.assertIn("started_at_summary", payload)
        self.assertIn("updated_at_summary", payload)
        self.assertIn("created_at_detail", payload)
        self.assertIn("started_at_detail", payload)
        self.assertIn("updated_at_detail", payload)
        self.assertIn("workflow_context_verification", payload)
        self.assertIn("dispatch_response_verification", payload)
        self.assertIn("\"dispatch_response_verification\": {", payload)
        self.assertIn("\"run_id\": _maybe_int(dispatch_run_id)", payload)
        self.assertIn("\"workflow_id\": _maybe_int(dispatch_workflow_id)", payload)
        self.assertIn("\"run_url\": dispatch_run_url or None", payload)
        self.assertIn("\"html_url\": dispatch_run_html_url or None", payload)
        self.assertIn("\"run_url_host\": dispatch_run_url_host or None", payload)
        self.assertIn("\"html_url_host\": dispatch_html_url_host or None", payload)
        self.assertIn("\"run_url_attempt\": _maybe_int(dispatch_run_url_attempt)", payload)
        self.assertIn("\"html_url_attempt\": _maybe_int(dispatch_html_url_attempt)", payload)
        self.assertIn("workflow_definition_verification", payload)
        self.assertIn("\"workflow_definition_verification\": {", payload)
        self.assertIn("\"run_workflow_id\": _maybe_int(workflow_run_workflow_id)", payload)
        self.assertIn("repository_owner", payload)
        self.assertIn("repository_id", payload)
        self.assertIn("repository_owner_id", payload)
        self.assertIn("actor_id", payload)
        self.assertIn("run_repository_id", payload)
        self.assertIn("run_repository_owner_id", payload)
        self.assertIn("run_actor_id", payload)
        self.assertIn("retention_days", payload)
        self.assertIn("workflow_sha", payload)
        self.assertIn("server_url", payload)
        self.assertIn("api_url", payload)
        self.assertIn("graphql_url", payload)
        self.assertIn("release_context_verification", payload)
        self.assertIn("contexts_verified", payload)
        self.assertIn("required_keys_verified", payload)
        self.assertIn("optional_keys_verified_when_present", payload)
        self.assertIn("rotation_rehearsal", payload)
        self.assertIn("rotation_report_verification", payload)
        self.assertIn("generated_at_utc", payload)
        self.assertIn("details", payload)
        self.assertIn("workflow_retention_days", payload)
        self.assertIn("context_required_keys_verified", payload)
        self.assertIn("context_optional_keys_verified_when_present", payload)
        self.assertIn("promotion_job_verification", payload)
        self.assertIn("required_step_count_verified", payload)
        self.assertIn("rotation_step_conclusion", payload)
        self.assertIn("runner_name", payload)
        self.assertIn("runner_group_name", payload)
        self.assertIn("runner_labels", payload)
        self.assertIn("workflow_name", payload)
        self.assertIn("actor_login", payload)
        self.assertIn("triggering_actor_login", payload)
        self.assertIn("actor_parity_checked", payload)
        self.assertIn("triggering_actor_parity_checked", payload)
        self.assertIn("job_html_url_host", payload)
        self.assertIn("job_html_url_path", payload)
        self.assertIn("job_html_url_attempt", payload)
        self.assertIn("rotation_rehearsal_report.status must be passed when rotation rehearsal is required; got {0}", payload)
        self.assertIn("rotation_rehearsal_report.requested must be true when rotation rehearsal is required", payload)
        self.assertIn("rotation_rehearsal_report.executed must be true when rotation rehearsal is required", payload)
        self.assertIn("rotation_rehearsal_report.old_key_rejected must be true when rotation rehearsal is required", payload)
        self.assertIn("rotation_rehearsal_report.details is required", payload)
        self.assertIn("rotation_rehearsal_report.details must not contain leading or trailing whitespace", payload)
        self.assertIn("rotation_rehearsal_report.status is required", payload)
        self.assertIn("rotation_rehearsal_report.status must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "rotation_rehearsal_report schema mismatch: expected enc2sop-rotation-rehearsal/v1, got {0}",
            payload,
        )
        self.assertIn("rotation_report_generated_at_utc, rotation_report_generated_at_dt = parse_required_iso8601_utc(", payload)
        self.assertIn("\"rotation_rehearsal_report.generated_at_utc\",", payload)
        self.assertIn(
            "rotation_rehearsal_report.generated_at_utc must be <= promotion_artifact_audit_report.generated_at_utc; got {0} > {1}",
            payload,
        )
        self.assertIn("rotation_workflow_retention_days = parse_required_positive_integer(", payload)
        self.assertIn("\"rotation_rehearsal_report.workflow_retention_days\",", payload)
        self.assertIn("rotation_rehearsal_report.workflow_retention_days mismatch with run retention_days: expected {0}, got {1}", payload)
        self.assertIn("rotation_rehearsal_report.{0} must not contain leading or trailing whitespace", payload)
        self.assertIn(
            "rotation_rehearsal_report.{0} mismatch with promotion_run_receipt.github_context.{1}: expected {2}, got {3}",
            payload,
        )
        self.assertIn(
            "rotation_rehearsal_report.{0} is required when promotion_run_receipt.github_context.{1} is present",
            payload,
        )
        self.assertIn("(\"workflow_runner_environment\", \"RUNNER_ENVIRONMENT\")", payload)
        self.assertIn("(\"workflow_runner_os\", \"RUNNER_OS\")", payload)
        self.assertIn("(\"workflow_runner_arch\", \"RUNNER_ARCH\")", payload)
        self.assertIn("rotation_rehearsal_report.requested must be false when rotation rehearsal is not required", payload)
        self.assertIn("rotation_rehearsal_report.executed must be false when rotation rehearsal is not required", payload)
        self.assertIn("rotation_rehearsal_report.old_key_rejected must be null when rotation rehearsal is not required", payload)
        self.assertIn("rotation_rehearsal_report.status must be not-requested when rotation rehearsal is not required; got {0}", payload)
        self.assertIn("promotion_capture_receipt.json", payload)
        self.assertIn("\"release_bundle.json\"", payload)
        self.assertIn("\"release_approval.json\"", payload)
        self.assertIn("\"release_receipt.json\"", payload)
        self.assertIn("\"promotion_evidence.json\"", payload)
        self.assertIn("\"promotion_audit_report.json\"", payload)
        self.assertIn("\"rotation_rehearsal_report.json\"", payload)
        self.assertIn("\"promotion_artifact_audit_report.json\"", payload)
        self.assertIn("\"promotion_run_receipt.json\"", payload)
        self.assertIn("\"promotion_artifact_bundle.zip\"", payload)
        self.assertIn("\"non_ocr_release_gate_report.json\"", payload)
        self.assertIn("non_ocr_release_gate_report schema mismatch", payload)
        self.assertIn("non_ocr_release_gate_report.passed must be true", payload)
        self.assertIn("non_ocr_release_gate_report.summary.total_failures must be 0", payload)
        self.assertIn("enc2sop-promotion-evidence-capture/v1", payload)


if __name__ == "__main__":
    unittest.main()
