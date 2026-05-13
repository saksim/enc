import json
import os
import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock

from enc2sop import promotion_evidence


TEST_ROOT = Path(__file__).resolve().parents[1]
TEST_RUNS_ROOT = TEST_ROOT / ".tmp_test_runs"


def _make_case_root(prefix):
    TEST_RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    root = TEST_RUNS_ROOT / "{}_{}".format(prefix, uuid.uuid4().hex[:8])
    root.mkdir(parents=True, exist_ok=False)
    return root


class _FakeGitHubClient(object):
    def __init__(
        self,
        *,
        branch_rules=None,
        env_reviewers=None,
        repo_secrets=None,
        repo_org_secrets=None,
        env_secrets=None,
    ):
        self.branch_rules = branch_rules or {}
        self.env_reviewers = env_reviewers or {}
        self.repo_secrets = set(repo_secrets or [])
        self.repo_org_secrets = set(repo_org_secrets or [])
        self.env_secrets = env_secrets or {}

    def get_branch_rules(self, *, owner, repo, branch_name):
        _ = (owner, repo)
        return list(self.branch_rules.get(branch_name, []))

    def get_environment(self, *, owner, repo, environment_name):
        _ = (owner, repo)
        reviewer_count = int(self.env_reviewers.get(environment_name, 0))
        reviewers = []
        for idx in range(reviewer_count):
            reviewers.append({"reviewer": {"id": idx + 1, "login": "rev{0}".format(idx + 1)}})
        return {
            "name": environment_name,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "reviewers": reviewers,
                }
            ],
        }

    def list_repository_secret_names(self, *, owner, repo):
        _ = (owner, repo)
        return set(self.repo_secrets)

    def list_repository_organization_secret_names(self, *, owner, repo):
        _ = (owner, repo)
        return set(self.repo_org_secrets)

    def list_environment_secret_names(self, *, owner, repo, environment_name):
        _ = (owner, repo)
        return set(self.env_secrets.get(environment_name, set()))


class PromotionEvidenceTests(unittest.TestCase):
    def make_case_root(self, prefix):
        root = _make_case_root(prefix)
        self.addCleanup(lambda: shutil.rmtree(str(root), ignore_errors=True))
        return root

    def _write_policy(self, root):
        policy_path = root / "policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-policy/v1",
                    "required_branches": [
                        {
                            "name": "main",
                            "required_status_checks": ["Signed Approval Promotion Gate"],
                        },
                        {
                            "name": "release/**",
                            "required_status_checks": ["Signed Approval Promotion Gate"],
                        },
                    ],
                    "required_environments": [
                        {
                            "name": "production-promotion",
                            "min_required_reviewers": 1,
                        }
                    ],
                    "required_secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                    "workflow": {
                        "relative_path": ".github/workflows/release_promotion.yml",
                        "required_fragments": ["Signed Approval Promotion Gate"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return policy_path

    def test_collect_promotion_evidence_builds_audit_ready_payload(self):
        root = self.make_case_root("promotion_evidence_success")
        policy_path = self._write_policy(root)
        evidence_path = root / "ops" / "promotion_evidence.json"
        fake_client = _FakeGitHubClient(
            branch_rules={
                "main": [
                    {
                        "type": "required_status_checks",
                        "parameters": {
                            "required_status_checks": [
                                {"context": "Signed Approval Promotion Gate"},
                                {"context": "lint"},
                            ]
                        },
                    }
                ],
                "release/enc2sop/probe": [
                    {
                        "type": "required_status_checks",
                        "parameters": {
                            "required_status_checks": [
                                {"context": "Signed Approval Promotion Gate"},
                            ]
                        },
                    }
                ],
            },
            env_reviewers={"production-promotion": 2},
            repo_secrets={"SOENC_RELEASE_APPROVAL_KEY_B64"},
            repo_org_secrets=set(),
            env_secrets={"production-promotion": {"ENV_ONLY_SECRET"}},
        )

        with mock.patch.dict(
            os.environ,
            {
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
                "GITHUB_SHA": "abc123",
                "GITHUB_RUN_ID": "42",
                "GITHUB_RUN_ATTEMPT": "3",
                "GITHUB_RUN_NUMBER": "17",
                "GITHUB_WORKFLOW_REF": "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
                "GITHUB_WORKFLOW_SHA": "feedface",
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
            },
            clear=False,
        ):
            written_path, payload = promotion_evidence.collect_promotion_evidence(
                repo="acme/demo",
                token="fake-token",
                policy_file=str(policy_path),
                evidence_file=str(evidence_path),
                repo_root=root,
                github_client=fake_client,
            )

        self.assertEqual(written_path, evidence_path.resolve())
        self.assertTrue(evidence_path.exists())
        self.assertEqual(payload["schema"], "enc2sop-promotion-evidence/v1")
        self.assertEqual(payload["repository"], "acme/demo")
        self.assertEqual(payload["secrets"], ["SOENC_RELEASE_APPROVAL_KEY_B64"])
        self.assertEqual(payload["github_context"]["GITHUB_REPOSITORY"], "acme/demo")
        self.assertEqual(payload["github_context"]["GITHUB_REF"], "refs/heads/main")
        self.assertEqual(payload["github_context"]["GITHUB_REF_NAME"], "main")
        self.assertEqual(payload["github_context"]["GITHUB_REF_TYPE"], "branch")
        self.assertEqual(payload["github_context"]["GITHUB_REF_PROTECTED"], "true")
        self.assertEqual(payload["github_context"]["GITHUB_ACTIONS"], "true")
        self.assertEqual(payload["github_context"]["CI"], "true")
        self.assertEqual(payload["github_context"]["RUNNER_ENVIRONMENT"], "github-hosted")
        self.assertEqual(payload["github_context"]["RUNNER_OS"], "Linux")
        self.assertEqual(payload["github_context"]["RUNNER_ARCH"], "X64")
        self.assertEqual(payload["github_context"]["GITHUB_RUN_ID"], "42")
        self.assertEqual(payload["github_context"]["GITHUB_RUN_ATTEMPT"], "3")
        self.assertEqual(payload["github_context"]["GITHUB_RUN_NUMBER"], "17")
        self.assertEqual(payload["github_context"]["GITHUB_JOB"], "promotion-gate")
        self.assertEqual(payload["github_context"]["GITHUB_ACTOR"], "octocat")
        self.assertEqual(payload["github_context"]["GITHUB_TRIGGERING_ACTOR"], "ops-oncall")
        self.assertEqual(payload["github_context"]["GITHUB_ACTOR_ID"], "42")
        self.assertEqual(payload["github_context"]["GITHUB_REPOSITORY_ID"], "4242")
        self.assertEqual(payload["github_context"]["GITHUB_REPOSITORY_OWNER"], "acme")
        self.assertEqual(payload["github_context"]["GITHUB_REPOSITORY_OWNER_ID"], "424242")
        self.assertEqual(payload["github_context"]["GITHUB_SERVER_URL"], "https://github.com")
        self.assertEqual(payload["github_context"]["GITHUB_API_URL"], "https://api.github.com")
        self.assertEqual(payload["github_context"]["GITHUB_GRAPHQL_URL"], "https://api.github.com/graphql")
        self.assertEqual(
            payload["github_context"]["GITHUB_WORKFLOW_REF"],
            "acme/demo/.github/workflows/release_promotion.yml@refs/heads/main",
        )
        self.assertEqual(payload["github_context"]["GITHUB_WORKFLOW_SHA"], "feedface")
        branches = {row["name"]: row["required_status_checks"] for row in payload["branches"]}
        self.assertIn("Signed Approval Promotion Gate", branches["main"])
        self.assertIn("Signed Approval Promotion Gate", branches["release/**"])
        envs = {row["name"]: row["required_reviewers_count"] for row in payload["environments"]}
        self.assertEqual(envs["production-promotion"], 2)

        written_payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(written_payload["schema"], "enc2sop-promotion-evidence/v1")
        self.assertEqual(written_payload["repository"], "acme/demo")

    def test_collect_promotion_evidence_fails_closed_when_required_secret_not_visible(self):
        root = self.make_case_root("promotion_evidence_missing_secret")
        policy_path = self._write_policy(root)
        fake_client = _FakeGitHubClient(
            branch_rules={
                "main": [
                    {
                        "parameters": {"required_status_checks": [{"context": "Signed Approval Promotion Gate"}]}
                    }
                ],
                "release/enc2sop/probe": [
                    {
                        "parameters": {"required_status_checks": [{"context": "Signed Approval Promotion Gate"}]}
                    }
                ],
            },
            env_reviewers={"production-promotion": 1},
            repo_secrets=set(),
            repo_org_secrets=set(),
            env_secrets={"production-promotion": set()},
        )

        with self.assertRaisesRegex(promotion_evidence.PromotionEvidenceError, "missing required secret rollout evidence"):
            promotion_evidence.collect_promotion_evidence(
                repo="acme/demo",
                token="fake-token",
                policy_file=str(policy_path),
                repo_root=root,
                github_client=fake_client,
            )

    def test_collect_promotion_evidence_fails_closed_when_branch_checks_missing(self):
        root = self.make_case_root("promotion_evidence_missing_branch_checks")
        policy_path = self._write_policy(root)
        fake_client = _FakeGitHubClient(
            branch_rules={
                "main": [],
                "release/enc2sop/probe": [],
            },
            env_reviewers={"production-promotion": 1},
            repo_secrets={"SOENC_RELEASE_APPROVAL_KEY_B64"},
            repo_org_secrets=set(),
            env_secrets={"production-promotion": set()},
        )

        with self.assertRaisesRegex(
            promotion_evidence.PromotionEvidenceError,
            "missing active branch rules for policy branch 'main'",
        ):
            promotion_evidence.collect_promotion_evidence(
                repo="acme/demo",
                token="fake-token",
                policy_file=str(policy_path),
                repo_root=root,
                github_client=fake_client,
            )


if __name__ == "__main__":
    unittest.main()

