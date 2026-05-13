#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""GitHub-backed promotion rollout evidence collector."""

import json
import os
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.parse import quote
from urllib.parse import urlencode
from urllib.request import Request
from urllib.request import urlopen

from enc2sop import promotion_audit

PROMOTION_EVIDENCE_SCHEMA = promotion_audit.PROMOTION_EVIDENCE_SCHEMA
PROMOTION_POLICY_SCHEMA = promotion_audit.PROMOTION_POLICY_SCHEMA
DEFAULT_GITHUB_API_BASE_URL = "https://api.github.com"
DEFAULT_GITHUB_API_VERSION = "2022-11-28"
DEFAULT_EVIDENCE_RELATIVE_PATH = "ops/promotion_evidence.json"
GITHUB_CONTEXT_KEYS = (
    "GITHUB_REPOSITORY",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_REF_PROTECTED",
    "GITHUB_ACTIONS",
    "CI",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
    "RUNNER_ARCH",
    "GITHUB_SHA",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_NUMBER",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_EVENT_NAME",
    "GITHUB_SERVER_URL",
    "GITHUB_API_URL",
    "GITHUB_GRAPHQL_URL",
    "GITHUB_JOB",
    "GITHUB_ACTOR",
    "GITHUB_TRIGGERING_ACTOR",
    "GITHUB_ACTOR_ID",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_REPOSITORY_OWNER_ID",
)


class PromotionEvidenceError(RuntimeError):
    """Raised when GitHub evidence collection fails."""


def _utc_now_iso8601_seconds() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _github_context_snapshot() -> Dict[str, str]:
    context = {}
    for key in GITHUB_CONTEXT_KEYS:
        value = os.environ.get(key)
        if value:
            context[key] = value
    return context


def _required_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PromotionEvidenceError("{0} must be a non-empty string".format(field_name))
    return value.strip()


def _required_text_list(value: object, field_name: str) -> Tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise PromotionEvidenceError("{0} must be a non-empty array".format(field_name))
    normalized = []  # type: List[str]
    for item in value:
        normalized.append(_required_text(item, field_name))
    return tuple(normalized)


def _load_json_object(path: Path, label: str) -> Dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise PromotionEvidenceError("{0} must be a JSON object: {1}".format(label, path))
    return payload


def _resolve_path(value: Optional[str], *, repo_root: Path, fallback: Path) -> Path:
    candidate = Path(value).expanduser() if value else fallback
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return candidate.resolve()


def _normalize_policy_targets(policy_payload: Mapping[str, object]) -> Dict[str, object]:
    schema = _required_text(policy_payload.get("schema"), "policy.schema")
    if schema != PROMOTION_POLICY_SCHEMA:
        raise PromotionEvidenceError("unsupported promotion policy schema: {0}".format(schema))

    required_branches = []  # type: List[str]
    branches_value = policy_payload.get("required_branches")
    if not isinstance(branches_value, list) or not branches_value:
        raise PromotionEvidenceError("policy.required_branches must be a non-empty array")
    for index, item in enumerate(branches_value):
        if not isinstance(item, dict):
            raise PromotionEvidenceError("policy.required_branches[{0}] must be an object".format(index))
        required_branches.append(_required_text(item.get("name"), "policy.required_branches[{0}].name".format(index)))

    required_environments = []  # type: List[str]
    environments_value = policy_payload.get("required_environments")
    if not isinstance(environments_value, list) or not environments_value:
        raise PromotionEvidenceError("policy.required_environments must be a non-empty array")
    for index, item in enumerate(environments_value):
        if not isinstance(item, dict):
            raise PromotionEvidenceError("policy.required_environments[{0}] must be an object".format(index))
        required_environments.append(
            _required_text(item.get("name"), "policy.required_environments[{0}].name".format(index))
        )

    required_secrets = _required_text_list(policy_payload.get("required_secrets"), "policy.required_secrets")
    return {
        "required_branches": tuple(required_branches),
        "required_environments": tuple(required_environments),
        "required_secrets": required_secrets,
    }


def _parse_repo_slug(repo_slug: str) -> Tuple[str, str]:
    value = _required_text(repo_slug, "repo")
    if "/" not in value:
        raise PromotionEvidenceError("repo must be formatted as 'owner/repo'")
    owner, repo_name = value.split("/", 1)
    owner = owner.strip()
    repo_name = repo_name.strip()
    if not owner or not repo_name:
        raise PromotionEvidenceError("repo must be formatted as 'owner/repo'")
    return owner, repo_name


def _branch_probe_name(branch_name: str) -> str:
    candidate = _required_text(branch_name, "policy.required_branches[].name")
    if candidate.startswith("refs/heads/"):
        candidate = candidate[len("refs/heads/") :]
    probe = candidate
    if "*" in probe or "?" in probe:
        probe = probe.replace("**", "enc2sop/probe")
        probe = probe.replace("*", "enc2sop")
        probe = probe.replace("?", "x")
    while "//" in probe:
        probe = probe.replace("//", "/")
    probe = probe.strip("/")
    if not probe:
        raise PromotionEvidenceError("unable to derive branch probe name from policy value: {0}".format(branch_name))
    if probe.endswith("/"):
        probe = "{0}enc2sop".format(probe)
    return probe


def _extract_required_status_checks(rules: Sequence[object]) -> Tuple[str, ...]:
    checks = set()  # type: Set[str]
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        parameters = rule.get("parameters")
        if isinstance(parameters, dict):
            required_checks = parameters.get("required_status_checks")
            if isinstance(required_checks, list):
                for item in required_checks:
                    if not isinstance(item, dict):
                        continue
                    context = item.get("context")
                    if isinstance(context, str) and context.strip():
                        checks.add(context.strip())
            contexts = parameters.get("contexts")
            if isinstance(contexts, list):
                for context in contexts:
                    if isinstance(context, str) and context.strip():
                        checks.add(context.strip())
        rule_contexts = rule.get("contexts")
        if isinstance(rule_contexts, list):
            for context in rule_contexts:
                if isinstance(context, str) and context.strip():
                    checks.add(context.strip())
    return tuple(sorted(checks))


def _extract_required_reviewer_count(environment_payload: Mapping[str, object]) -> int:
    protection_rules = environment_payload.get("protection_rules")
    if not isinstance(protection_rules, list):
        return 0
    for rule in protection_rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("type") != "required_reviewers":
            continue
        reviewers = rule.get("reviewers")
        if not isinstance(reviewers, list):
            return 0
        normalized = []  # type: List[str]
        for reviewer in reviewers:
            if not isinstance(reviewer, dict):
                continue
            reviewer_info = reviewer.get("reviewer")
            if not isinstance(reviewer_info, dict):
                continue
            reviewer_id = reviewer_info.get("id")
            reviewer_login = reviewer_info.get("login")
            if reviewer_id is not None:
                normalized.append(str(reviewer_id))
            elif isinstance(reviewer_login, str) and reviewer_login.strip():
                normalized.append(reviewer_login.strip().lower())
        return len(set(normalized))
    return 0


class GitHubApiClient:
    """Small stdlib GitHub API client for promotion evidence collection."""

    def __init__(
        self,
        *,
        token: str,
        api_base_url: str = DEFAULT_GITHUB_API_BASE_URL,
        api_version: str = DEFAULT_GITHUB_API_VERSION,
        timeout_seconds: float = 20.0,
    ) -> None:
        self._token = _required_text(token, "github token")
        self._api_base_url = _required_text(api_base_url, "github api base url").rstrip("/")
        self._api_version = _required_text(api_version, "github api version")
        self._timeout_seconds = timeout_seconds

    def _api_url(self, endpoint: str, query: Optional[Mapping[str, object]] = None) -> str:
        path = endpoint if endpoint.startswith("/") else "/" + endpoint
        base_url = self._api_base_url
        url = "{0}{1}".format(base_url, path)
        if query:
            encoded = urlencode(
                {key: str(value) for key, value in query.items() if value is not None},
                doseq=True,
            )
            if encoded:
                url = "{0}?{1}".format(url, encoded)
        return url

    def _request_json(self, endpoint: str, *, query: Optional[Mapping[str, object]] = None) -> object:
        url = self._api_url(endpoint, query=query)
        request = Request(
            url=url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer {0}".format(self._token),
                "X-GitHub-Api-Version": self._api_version,
                "User-Agent": "enc2sop-promotion-evidence/1",
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                payload = response.read()
                charset = response.headers.get_content_charset() or "utf-8"
        except HTTPError as exc:
            error_text = ""
            try:
                error_text = exc.read().decode("utf-8", errors="replace")
            except Exception:  # pragma: no cover - defensive fallback
                error_text = ""
            suffix = " (HTTP {0})".format(exc.code)
            if error_text:
                suffix = "{0}: {1}".format(suffix, error_text.strip())
            raise PromotionEvidenceError(
                "GitHub API request failed for {0}{1}".format(url, suffix)
            ) from exc
        except URLError as exc:
            raise PromotionEvidenceError("GitHub API request failed for {0}: {1}".format(url, exc.reason)) from exc

        try:
            return json.loads(payload.decode(charset))
        except json.JSONDecodeError as exc:
            raise PromotionEvidenceError("GitHub API returned non-JSON response for {0}".format(url)) from exc

    def _list_paginated(self, endpoint: str, *, list_field: Optional[str] = None) -> List[object]:
        rows = []  # type: List[object]
        page = 1
        while True:
            payload = self._request_json(
                endpoint,
                query={
                    "per_page": 100,
                    "page": page,
                },
            )
            if list_field is None:
                if not isinstance(payload, list):
                    raise PromotionEvidenceError(
                        "GitHub API pagination expected array response at {0}".format(endpoint)
                    )
                page_rows = payload
            else:
                if not isinstance(payload, dict):
                    raise PromotionEvidenceError(
                        "GitHub API pagination expected object response at {0}".format(endpoint)
                    )
                page_rows = payload.get(list_field)
                if not isinstance(page_rows, list):
                    raise PromotionEvidenceError(
                        "GitHub API response missing array field '{0}' for {1}".format(list_field, endpoint)
                    )
            rows.extend(page_rows)
            if len(page_rows) < 100:
                break
            page += 1
        return rows

    def get_branch_rules(self, *, owner: str, repo: str, branch_name: str) -> List[object]:
        endpoint = "/repos/{0}/{1}/rules/branches/{2}".format(
            quote(owner, safe=""),
            quote(repo, safe=""),
            quote(branch_name, safe=""),
        )
        return self._list_paginated(endpoint)

    def get_environment(self, *, owner: str, repo: str, environment_name: str) -> Dict[str, object]:
        endpoint = "/repos/{0}/{1}/environments/{2}".format(
            quote(owner, safe=""),
            quote(repo, safe=""),
            quote(environment_name, safe=""),
        )
        payload = self._request_json(endpoint)
        if not isinstance(payload, dict):
            raise PromotionEvidenceError("GitHub environment payload must be an object: {0}".format(endpoint))
        return payload

    def list_repository_secret_names(self, *, owner: str, repo: str) -> Set[str]:
        endpoint = "/repos/{0}/{1}/actions/secrets".format(quote(owner, safe=""), quote(repo, safe=""))
        rows = self._list_paginated(endpoint, list_field="secrets")
        return _collect_secret_names(rows, "repository secrets")

    def list_repository_organization_secret_names(self, *, owner: str, repo: str) -> Set[str]:
        endpoint = "/repos/{0}/{1}/actions/organization-secrets".format(quote(owner, safe=""), quote(repo, safe=""))
        rows = self._list_paginated(endpoint, list_field="secrets")
        return _collect_secret_names(rows, "repository organization secrets")

    def list_environment_secret_names(self, *, owner: str, repo: str, environment_name: str) -> Set[str]:
        endpoint = "/repos/{0}/{1}/environments/{2}/secrets".format(
            quote(owner, safe=""),
            quote(repo, safe=""),
            quote(environment_name, safe=""),
        )
        rows = self._list_paginated(endpoint, list_field="secrets")
        return _collect_secret_names(rows, "environment secrets")


def _collect_secret_names(rows: Sequence[object], label: str) -> Set[str]:
    names = set()  # type: Set[str]
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise PromotionEvidenceError("{0} row {1} must be an object".format(label, index))
        name = _required_text(row.get("name"), "{0}[{1}].name".format(label, index))
        names.add(name)
    return names


def collect_promotion_evidence(
    *,
    repo: str,
    token: str,
    policy_file: Optional[str] = None,
    evidence_file: Optional[str] = None,
    api_base_url: Optional[str] = None,
    repo_root: Optional[Path] = None,
    fail_on_missing_rollout_objects: bool = True,
    github_client: Optional[GitHubApiClient] = None,
) -> Tuple[Path, Dict[str, object]]:
    root = repo_root.resolve() if repo_root is not None else Path.cwd().resolve()
    policy_path = _resolve_path(
        policy_file,
        repo_root=root,
        fallback=promotion_audit.default_policy_path(root),
    )
    if not policy_path.exists():
        raise FileNotFoundError("promotion policy file not found: {0}".format(policy_path))
    policy_payload = _load_json_object(policy_path, "promotion policy")
    policy_targets = _normalize_policy_targets(policy_payload)

    owner, repo_name = _parse_repo_slug(repo)
    client = github_client
    if client is None:
        resolved_api_base_url = (
            api_base_url
            or os.environ.get("GITHUB_API_URL")
            or DEFAULT_GITHUB_API_BASE_URL
        )
        client = GitHubApiClient(token=token, api_base_url=resolved_api_base_url)

    branches = []  # type: List[Dict[str, object]]
    missing_rollout = []  # type: List[str]
    for branch_name in policy_targets["required_branches"]:
        probe_name = _branch_probe_name(branch_name)
        rules = client.get_branch_rules(owner=owner, repo=repo_name, branch_name=probe_name)
        checks = _extract_required_status_checks(rules)
        if fail_on_missing_rollout_objects and not rules:
            missing_rollout.append(
                "missing active branch rules for policy branch '{0}' (probe '{1}')".format(branch_name, probe_name)
            )
        if fail_on_missing_rollout_objects and not checks:
            missing_rollout.append(
                "missing required status-check rollout for policy branch '{0}' (probe '{1}')".format(
                    branch_name,
                    probe_name,
                )
            )
        branches.append(
            {
                "name": branch_name,
                "required_status_checks": list(checks),
            }
        )

    environments = []  # type: List[Dict[str, object]]
    environment_secret_names = set()  # type: Set[str]
    for environment_name in policy_targets["required_environments"]:
        payload = client.get_environment(owner=owner, repo=repo_name, environment_name=environment_name)
        reviewer_count = _extract_required_reviewer_count(payload)
        environments.append(
            {
                "name": environment_name,
                "required_reviewers_count": reviewer_count,
            }
        )
        environment_secret_names.update(
            client.list_environment_secret_names(
                owner=owner,
                repo=repo_name,
                environment_name=environment_name,
            )
        )

    repository_secret_names = client.list_repository_secret_names(owner=owner, repo=repo_name)
    repository_org_secret_names = client.list_repository_organization_secret_names(owner=owner, repo=repo_name)
    available_secret_names = set(repository_secret_names)
    available_secret_names.update(repository_org_secret_names)
    available_secret_names.update(environment_secret_names)

    required_secret_names = policy_targets["required_secrets"]
    found_required_secrets = sorted({name for name in required_secret_names if name in available_secret_names})
    missing_required_secrets = sorted({name for name in required_secret_names if name not in available_secret_names})
    if fail_on_missing_rollout_objects and missing_required_secrets:
        missing_rollout.append(
            "missing required secret rollout evidence: {0}".format(", ".join(missing_required_secrets))
        )
    if missing_rollout:
        raise PromotionEvidenceError("; ".join(missing_rollout))

    evidence_payload = {
        "schema": PROMOTION_EVIDENCE_SCHEMA,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "repository": "{0}/{1}".format(owner, repo_name),
        "github_context": _github_context_snapshot(),
        "branches": branches,
        "environments": environments,
        "secrets": found_required_secrets,
    }
    promotion_audit.normalize_promotion_evidence_payload(evidence_payload)

    evidence_path = _resolve_path(
        evidence_file,
        repo_root=root,
        fallback=Path(DEFAULT_EVIDENCE_RELATIVE_PATH),
    )
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(evidence_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return evidence_path, evidence_payload
