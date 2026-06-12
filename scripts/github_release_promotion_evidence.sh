#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WORKFLOW_FILE="release_promotion.yml"
WORKFLOW_JOB_ID="promotion-gate"
REF="main"
REF_EXPLICIT="false"
ROTATION_REHEARSAL="true"
SKIP_PROMOTION_COLLECT="false"
APPROVER=""
RUN_ID=""
RUN_ATTEMPT=""
OUTPUT_ROOT=".tmp_ci/live_promotion"
PREFLIGHT_ONLY="false"
EXPECTED_ENVIRONMENT="production-promotion"
REQUIRE_ENVIRONMENT_REVIEWERS="true"
REQUIRED_SECRET_NAMES="SOENC_RELEASE_APPROVAL_KEY_B64"
POLL_INTERVAL_SECONDS=10
TIMEOUT_SECONDS=5400
ARTIFACT_INDEX_WAIT_SECONDS=180
REPO="${GITHUB_REPOSITORY:-}"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/github_release_promotion_evidence.sh [options]

Options:
  --repo <owner/repo>                GitHub repository slug (default: auto-detect from gh repo view).
  --ref <branch-or-tag>              Workflow ref for workflow_dispatch (default: main).
  --workflow-file <file>             Workflow file name/id (default: release_promotion.yml).
  --workflow-job-id <job-id>         Workflow job id expected in run receipt context (default: promotion-gate).
  --rotation-rehearsal <true|false>  Pass workflow_dispatch input rotation_rehearsal (default: true).
  --skip-promotion-collect <true|false>
                                     Pass workflow_dispatch input skip_promotion_collect (default: false).
  --approver <identity>              Optional approver input for workflow dispatch.
  --run-id <id>                      Capture evidence from an existing workflow run id (skip dispatch).
  --run-attempt <int>                Expected attempt number for --run-id (optional strict check).
  --output-root <dir>                Local evidence output root (default: .tmp_ci/live_promotion).
  --preflight-only                   Validate repo/workflow identity, write promotion_preflight_receipt.json, and exit before dispatch.
  --expected-environment <name>      Required GitHub environment name (default: production-promotion).
  --no-require-environment-reviewers Do not require at least one deployment branch policy/reviewer in environment preflight.
  --required-secret <name>           Required repository/environment secret metadata name. Repeatable.
  --poll-interval-seconds <int>      Run-state poll interval (default: 10).
  --timeout-seconds <int>            Max wait for run completion (default: 5400).
  --artifact-index-wait-seconds <int>
                                     Max wait for GitHub artifact indexing after run success (default: 180).
  -h, --help                         Show this help.

Example:
  bash scripts/github_release_promotion_evidence.sh \
    --repo owner/repo \
    --ref main \
    --rotation-rehearsal true
USAGE
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 1
  fi
}

require_boolean_token() {
  local value="$1"
  local label="$2"
  if [[ "$value" != "true" && "$value" != "false" ]]; then
    echo "Invalid ${label}: ${value} (expected true or false)" >&2
    exit 1
  fi
}

require_positive_integer() {
  local value="$1"
  local label="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -le 0 ]]; then
    echo "Invalid ${label}: ${value} (expected positive integer)" >&2
    exit 1
  fi
}

expected_api_host_for_run_host() {
  local run_host="$1"
  if [[ -z "$run_host" ]]; then
    printf '%s\n' ""
    return 0
  fi
  local normalized="${run_host,,}"
  if [[ "$normalized" == "github.com" ]]; then
    printf '%s\n' "api.github.com"
    return 0
  fi
  printf '%s\n' "$normalized"
}

require_repo_slug() {
  local value="$1"
  if [[ -z "$value" || "$value" != "${value//[[:space:]]/}" ]]; then
    echo "Invalid repo slug: ${value} (expected owner/repo without whitespace)" >&2
    exit 1
  fi
  if [[ "$value" != */* || "$value" == */ || "$value" == /* || "$value" == */*/* ]]; then
    echo "Invalid repo slug: ${value} (expected owner/repo)" >&2
    exit 1
  fi
}

join_by_comma() {
  local IFS=","
  printf '%s' "$*"
}

require_token_no_whitespace() {
  local value="$1"
  local label="$2"
  if [[ -z "$value" || "$value" != "${value//[[:space:]]/}" ]]; then
    echo "Invalid ${label}: ${value} (expected non-empty token without whitespace)" >&2
    exit 1
  fi
}

strip_crlf() {
  local value="$1"
  value="${value//$'\r'/}"
  value="${value//$'\n'/}"
  printf '%s' "$value"
}

verify_github_cli_repo_access() {
  local repo="$1"
  local auth_status_output=""
  local auth_status_code=0
  local repo_probe_output=""
  local repo_probe_status=0
  echo "Checking GitHub CLI authentication and repository API access..."
  set +e
  auth_status_output="$(gh auth status 2>&1)"
  auth_status_code=$?
  set -e
  if [[ "$auth_status_code" -ne 0 ]]; then
    echo "gh auth status reported non-zero; continuing with repository API probe for ${repo}."
  fi
  set +e
  repo_probe_output="$(gh api "repos/${repo}" --jq '.full_name' 2>&1)"
  repo_probe_status=$?
  set -e
  if [[ "$repo_probe_status" -ne 0 ]]; then
    echo "GitHub repository API probe failed for ${repo}." >&2
    if [[ -n "$auth_status_output" ]]; then
      printf '%s\n' "$auth_status_output" >&2
    fi
    printf '%s\n' "$repo_probe_output" >&2
    echo "Provide a token with repository and Actions API access via GH_TOKEN/GITHUB_TOKEN or gh auth login." >&2
    exit 1
  fi
  if [[ -z "$repo_probe_output" || "$repo_probe_output" != "${repo_probe_output//[[:space:]]/}" ]]; then
    echo "GitHub repository API probe returned invalid repository identity for ${repo}." >&2
    exit 1
  fi
  if [[ "${repo_probe_output,,}" != "${repo,,}" ]]; then
    echo "GitHub repository API probe mismatch: expected ${repo}, got ${repo_probe_output}" >&2
    exit 1
  fi
  echo "GitHub repository API probe passed for ${repo_probe_output}"
}

resolve_workflow_definition_identity() {
  local repo="$1"
  local workflow_file="$2"
  local expected_workflow_path="$3"
  local workflow_encoded=""
  local workflow_probe_output=""
  local workflow_probe_status=0
  local workflow_probe_parsed=""
  local workflow_id=""
  local workflow_path=""
  local workflow_state=""
  local workflow_name=""
  workflow_encoded="$(urlencode_path_segment "$workflow_file")"
  echo "Resolving workflow definition identity for ${workflow_file} on ${repo}..." >&2
  set +e
  workflow_probe_output="$(gh api "repos/${repo}/actions/workflows/${workflow_encoded}" 2>&1)"
  workflow_probe_status=$?
  set -e
  if [[ "$workflow_probe_status" -ne 0 ]]; then
    echo "Unable to resolve workflow definition for ${workflow_file} on ${repo}." >&2
    printf '%s\n' "$workflow_probe_output" >&2
    exit 1
  fi
  workflow_probe_parsed="$(python - "$workflow_probe_output" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
print(payload.get("id", ""))
print(payload.get("path", ""))
print(payload.get("state", ""))
print(payload.get("name", ""))
PY
)"
  workflow_id="$(printf '%s\n' "$workflow_probe_parsed" | sed -n '1p')"
  workflow_path="$(printf '%s\n' "$workflow_probe_parsed" | sed -n '2p')"
  workflow_state="$(printf '%s\n' "$workflow_probe_parsed" | sed -n '3p')"
  workflow_name="$(printf '%s\n' "$workflow_probe_parsed" | sed -n '4p')"

  if [[ ! "$workflow_id" =~ ^[0-9]+$ ]]; then
    echo "Resolved workflow id is not numeric for ${workflow_file} on ${repo}: ${workflow_id}" >&2
    exit 1
  fi
  if [[ -z "$workflow_path" || "$workflow_path" != "${workflow_path//[[:space:]]/}" ]]; then
    echo "Resolved workflow path is invalid for ${workflow_file} on ${repo}: ${workflow_path}" >&2
    exit 1
  fi
  if [[ "$workflow_path" != .github/workflows/* ]]; then
    echo "Resolved workflow path is outside .github/workflows for ${workflow_file} on ${repo}: ${workflow_path}" >&2
    exit 1
  fi
  if [[ -n "$expected_workflow_path" && "$workflow_path" != "$expected_workflow_path" ]]; then
    echo "Resolved workflow definition path mismatch for ${workflow_file}: expected ${expected_workflow_path}, got ${workflow_path}" >&2
    exit 1
  fi
  if [[ "$workflow_state" != "active" ]]; then
    echo "Resolved workflow state is not active for ${workflow_file} on ${repo}: ${workflow_state}" >&2
    exit 1
  fi
  if [[ -z "$workflow_name" || "$workflow_name" =~ ^[[:space:]] || "$workflow_name" =~ [[:space:]]$ ]]; then
    echo "Resolved workflow name is invalid for ${workflow_file} on ${repo}: ${workflow_name}" >&2
    exit 1
  fi

  echo "Resolved workflow definition id=${workflow_id} path=${workflow_path} state=${workflow_state} name=${workflow_name}" >&2
  printf '%s\n' "$workflow_id"
  printf '%s\n' "$workflow_path"
  printf '%s\n' "$workflow_state"
  printf '%s\n' "$workflow_name"
}

verify_branch_protection_preflight() {
  local repo="$1"
  local ref_name="$2"
  if [[ -z "$ref_name" ]]; then
    echo '{"required":false,"verified":false,"reason":"non-branch-ref"}'
    return 0
  fi
  local branch_encoded=""
  local branch_json=""
  local branch_status=0
  branch_encoded="$(urlencode_path_segment "$ref_name")"
  set +e
  branch_json="$(gh api "repos/${repo}/branches/${branch_encoded}" 2>&1)"
  branch_status=$?
  set -e
  if [[ "$branch_status" -ne 0 ]]; then
    echo "Unable to resolve branch protection metadata for ${repo}@${ref_name}." >&2
    printf '%s\n' "$branch_json" >&2
    exit 1
  fi
  python - "$ref_name" "$branch_json" <<'PY'
import json
import sys

ref_name = sys.argv[1]
payload = json.loads(sys.argv[2])
protected = payload.get("protected")
if protected is not True:
    print(
        "Branch protection preflight failed for {0}: branches API protected flag must be true".format(ref_name),
        file=sys.stderr,
    )
    sys.exit(1)
print(json.dumps({
    "required": True,
    "verified": True,
    "branch": ref_name,
    "protected": True,
}, ensure_ascii=False))
PY
}

verify_environment_preflight() {
  local repo="$1"
  local environment_name="$2"
  local require_reviewers="$3"
  if [[ -z "$environment_name" ]]; then
    echo '{"required":false,"verified":false,"reason":"not-configured"}'
    return 0
  fi
  local environment_encoded=""
  local environment_json=""
  local environment_status=0
  environment_encoded="$(urlencode_path_segment "$environment_name")"
  set +e
  environment_json="$(gh api "repos/${repo}/environments/${environment_encoded}" 2>&1)"
  environment_status=$?
  set -e
  if [[ "$environment_status" -ne 0 ]]; then
    echo "Unable to resolve environment metadata for ${repo} environment ${environment_name}." >&2
    printf '%s\n' "$environment_json" >&2
    exit 1
  fi
  python - "$environment_name" "$require_reviewers" "$environment_json" <<'PY'
import json
import sys

expected_name, require_reviewers, raw = sys.argv[1:4]
payload = json.loads(raw)
actual_name = payload.get("name")
if actual_name != expected_name:
    print(
        "Environment preflight name mismatch: expected {0}, got {1}".format(expected_name, actual_name),
        file=sys.stderr,
    )
    sys.exit(1)
protection_rules = payload.get("protection_rules")
if not isinstance(protection_rules, list):
    protection_rules = []
reviewer_count = 0
required_reviewer_rule_count = 0
for rule in protection_rules:
    if not isinstance(rule, dict) or rule.get("type") != "required_reviewers":
        continue
    required_reviewer_rule_count += 1
    reviewers = rule.get("reviewers")
    if isinstance(reviewers, list):
        reviewer_count += len(reviewers)
if require_reviewers == "true" and reviewer_count <= 0:
    print("Environment preflight requires at least one reviewer for {0}".format(expected_name), file=sys.stderr)
    sys.exit(1)
deployment_branch_policy = payload.get("deployment_branch_policy")
print(json.dumps({
    "required": True,
    "verified": True,
    "name": actual_name,
    "reviewer_count": reviewer_count,
    "required_reviewer_rule_count": required_reviewer_rule_count,
    "reviewers_required": require_reviewers == "true",
    "deployment_branch_policy_present": isinstance(deployment_branch_policy, dict),
}, ensure_ascii=False))
PY
}

verify_required_secrets_preflight() {
  local repo="$1"
  local environment_name="$2"
  local required_csv="$3"
  local rotation_rehearsal="$4"
  python - "$required_csv" "$rotation_rehearsal" <<'PY'
import sys

required_csv, rotation_rehearsal = sys.argv[1:3]
names = [item.strip() for item in required_csv.split(",") if item.strip()]
if rotation_rehearsal == "true" and "SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64" not in names:
    names.append("SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64")
for name in names:
    if any(ch.isspace() for ch in name):
        print("Required secret name must not contain whitespace: {0}".format(name), file=sys.stderr)
        sys.exit(1)
print("\n".join(names))
PY
}

verify_secret_metadata_name() {
  local repo="$1"
  local environment_name="$2"
  local secret_name="$3"
  local secret_encoded=""
  local repo_secret_json=""
  local repo_secret_status=0
  secret_name="$(strip_crlf "$secret_name")"
  environment_name="$(strip_crlf "$environment_name")"
  require_token_no_whitespace "$secret_name" "required-secret"
  secret_encoded="$(urlencode_path_segment "$secret_name")"
  set +e
  repo_secret_json="$(gh api "repos/${repo}/actions/secrets/${secret_encoded}" 2>&1)"
  repo_secret_status=$?
  set -e
  if [[ "$repo_secret_status" -eq 0 ]]; then
    python - "$secret_name" "repository" "$repo_secret_json" <<'PY'
import json
import sys
expected_name, scope, raw = sys.argv[1:4]
payload = json.loads(raw)
if payload.get("name") != expected_name:
    print("Required secret metadata name mismatch for {0}: got {1}".format(expected_name, payload.get("name")), file=sys.stderr)
    sys.exit(1)
print(json.dumps({"name": expected_name, "scope": scope, "metadata_verified": True}, ensure_ascii=False))
PY
    return 0
  fi
  if [[ -n "$environment_name" ]]; then
    local environment_encoded=""
    local env_secret_json=""
    local env_secret_status=0
    environment_encoded="$(urlencode_path_segment "$environment_name")"
    set +e
    env_secret_json="$(gh api "repos/${repo}/environments/${environment_encoded}/secrets/${secret_encoded}" 2>&1)"
    env_secret_status=$?
    set -e
    if [[ "$env_secret_status" -eq 0 ]]; then
      python - "$secret_name" "environment" "$environment_name" "$env_secret_json" <<'PY'
import json
import sys
expected_name, scope, environment_name, raw = sys.argv[1:5]
payload = json.loads(raw)
if payload.get("name") != expected_name:
    print("Required environment secret metadata name mismatch for {0}: got {1}".format(expected_name, payload.get("name")), file=sys.stderr)
    sys.exit(1)
print(json.dumps({"name": expected_name, "scope": scope, "environment": environment_name, "metadata_verified": True}, ensure_ascii=False))
PY
      return 0
    fi
  fi
  echo "Required secret metadata not found for ${secret_name} in repository or environment ${environment_name:-<none>}." >&2
  printf '%s\n' "$repo_secret_json" >&2
  exit 1
}

normalize_branch_ref_name() {
  local ref_value="$1"
  if [[ "$ref_value" == refs/heads/* ]]; then
    printf '%s\n' "${ref_value#refs/heads/}"
    return 0
  fi
  if [[ "$ref_value" == refs/tags/* || "$ref_value" == refs/* ]]; then
    printf '%s\n' ""
    return 0
  fi
  printf '%s\n' "$ref_value"
}

resolve_expected_workflow_path() {
  local workflow_value="$1"
  if [[ "$workflow_value" =~ ^[0-9]+$ ]]; then
    printf '%s\n' ""
    return 0
  fi
  if [[ "$workflow_value" == */* ]]; then
    printf '%s\n' "$workflow_value"
    return 0
  fi
  if [[ "$workflow_value" == *.yml || "$workflow_value" == *.yaml ]]; then
    printf '%s\n' ".github/workflows/${workflow_value}"
    return 0
  fi
  printf '%s\n' ""
}

extract_run_id_from_dispatch_output() {
  local text="$1"
  printf '%s\n' "$text" | python -c 'import re,sys
text=sys.stdin.read()
matches=re.findall(r"/actions/runs/([0-9]+)", text)
print(matches[-1] if matches else "")
'
}

extract_run_id_from_dispatch_response_json() {
  local text="$1"
  printf '%s\n' "$text" | python -c 'import json,re,sys
text=sys.stdin.read()
if not text.strip():
    print("")
    print("")
    print("")
    print("")
    raise SystemExit(0)
try:
    payload=json.loads(text)
except Exception:
    print("")
    print("")
    print("")
    print("")
    raise SystemExit(0)
workflow_run = payload.get("workflow_run")
if not isinstance(workflow_run, dict):
    workflow_run = {}
run_url = payload.get("run_url")
if not isinstance(run_url, str):
    run_url = ""
if not run_url:
    run_url = payload.get("url")
if not isinstance(run_url, str):
    run_url = ""
if not run_url:
    workflow_run_url = workflow_run.get("url")
    if isinstance(workflow_run_url, str):
        run_url = workflow_run_url
html_url = payload.get("html_url")
if not isinstance(html_url, str):
    html_url = ""
if not html_url:
    workflow_url = payload.get("workflow_url")
    if isinstance(workflow_url, str):
        html_url = workflow_url
if not html_url:
    workflow_run_html_url = workflow_run.get("html_url")
    if isinstance(workflow_run_html_url, str):
        html_url = workflow_run_html_url
workflow_id_value = payload.get("workflow_id")
if workflow_id_value is None:
    workflow_id_value = workflow_run.get("workflow_id")
workflow_id_text = str(workflow_id_value) if workflow_id_value is not None else ""
if workflow_id_text and not workflow_id_text.isdigit():
    print("Dispatch response workflow_id is not numeric: {0}".format(workflow_id_text), file=sys.stderr)
    raise SystemExit(1)

candidates=[]
candidate_sources={}
def add_candidate(value, source):
    value_text=str(value) if value is not None else ""
    if value_text.isdigit():
        candidates.append(value_text)
        candidate_sources.setdefault(value_text, set()).add(source)

add_candidate(payload.get("workflow_run_id"), "workflow_run_id")
add_candidate(payload.get("run_id"), "run_id")
if isinstance(workflow_run, dict):
    add_candidate(workflow_run.get("id"), "workflow_run.id")
for key in ("run_url", "html_url", "url", "workflow_url"):
    value=payload.get(key)
    if not isinstance(value,str):
        continue
    matches=re.findall(r"/actions/runs/([0-9]+)", value)
    if matches:
        add_candidate(matches[-1], key)
for key in ("url", "html_url"):
    value=workflow_run.get(key)
    if not isinstance(value,str):
        continue
    matches=re.findall(r"/actions/runs/([0-9]+)", value)
    if matches:
        add_candidate(matches[-1], "workflow_run.{0}".format(key))

candidate_unique = sorted(set(candidates))
if len(candidate_unique) > 1:
    details = []
    for candidate_id in candidate_unique:
        sources = sorted(candidate_sources.get(candidate_id, []))
        details.append("{0}<-{1}".format(candidate_id, "|".join(sources)))
    print(
        "Dispatch response run id candidates are inconsistent: {0}".format(
            ", ".join(details)
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)

run_id = candidate_unique[0] if candidate_unique else ""
print(run_id)
print(run_url if isinstance(run_url, str) else "")
print(html_url if isinstance(html_url, str) else "")
print(workflow_id_text)
'
}

urlencode_path_segment() {
  local value="$1"
  value="$(strip_crlf "$value")"
  python - "$value" <<'PY'
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe=""))
PY
}

build_dispatch_request_body() {
  local ref="$1"
  local rotation_rehearsal="$2"
  local skip_collect="$3"
  local approver="$4"
  python - "$ref" "$rotation_rehearsal" "$skip_collect" "$approver" <<'PY'
import json
import sys

ref = sys.argv[1]
rotation_rehearsal = sys.argv[2]
skip_collect = sys.argv[3]
approver = sys.argv[4]

payload = {
    "ref": ref,
    "return_run_details": True,
    "inputs": {
        "rotation_rehearsal": rotation_rehearsal,
        "skip_promotion_collect": skip_collect,
    },
}
if approver:
    payload["inputs"]["approver"] = approver
print(json.dumps(payload, ensure_ascii=False))
PY
}

dispatch_workflow_with_run_details() {
  local repo="$1"
  local workflow_file="$2"
  local ref="$3"
  local rotation_rehearsal="$4"
  local skip_collect="$5"
  local approver="$6"
  local workflow_encoded
  local request_body
  workflow_encoded="$(urlencode_path_segment "$workflow_file")"
  request_body="$(build_dispatch_request_body "$ref" "$rotation_rehearsal" "$skip_collect" "$approver")"
  printf '%s\n' "$request_body" | gh api \
    --method POST \
    --header "Accept: application/vnd.github+json" \
    --header "X-GitHub-Api-Version: 2026-03-10" \
    "repos/${repo}/actions/workflows/${workflow_encoded}/dispatches" \
    --input -
}

write_promotion_preflight_receipt() {
  local receipt_path="$1"
  local repo="$2"
  local workflow_file="$3"
  local ref="$4"
  local expected_workflow_path="$5"
  local workflow_id="$6"
  local workflow_path="$7"
  local workflow_state="$8"
  local workflow_name="$9"
  local rotation_rehearsal="${10}"
  local skip_collect="${11}"
  local branch_protection_preflight_json="${12}"
  local environment_preflight_json="${13}"
  local required_secret_preflight_jsonl="${14}"
  python - \
    "$receipt_path" \
    "$repo" \
    "$workflow_file" \
    "$ref" \
    "$expected_workflow_path" \
    "$workflow_id" \
    "$workflow_path" \
    "$workflow_state" \
    "$workflow_name" \
    "$rotation_rehearsal" \
    "$skip_collect" \
    "$branch_protection_preflight_json" \
    "$environment_preflight_json" \
    "$required_secret_preflight_jsonl" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    receipt_path,
    repo,
    workflow_file,
    workflow_dispatch_ref,
    expected_workflow_path,
    workflow_id,
    workflow_path,
    workflow_state,
    workflow_name,
    rotation_rehearsal,
    skip_collect,
    branch_protection_preflight_json,
    environment_preflight_json,
    required_secret_preflight_jsonl,
) = sys.argv[1:15]

def load_object(label: str, text: str):
    try:
        payload = json.loads(text)
    except Exception as exc:
        print("{0} preflight payload is not valid JSON: {1}".format(label, exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(payload, dict):
        print("{0} preflight payload must be a JSON object".format(label), file=sys.stderr)
        sys.exit(1)
    return payload

branch_protection_preflight = load_object("branch_protection", branch_protection_preflight_json)
environment_preflight = load_object("environment", environment_preflight_json)
required_secret_preflight = []
for line in required_secret_preflight_jsonl.splitlines():
    if not line.strip():
        continue
    required_secret_preflight.append(load_object("required_secret", line))

payload = {
    "schema": "enc2sop-promotion-preflight/v1",
    "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "github_repository": repo,
    "workflow_file": workflow_file,
    "workflow_dispatch_ref": workflow_dispatch_ref,
    "repository_api_verified": True,
    "preflight_only": True,
    "dispatch_executed": False,
    "rotation_rehearsal_requested": rotation_rehearsal == "true",
    "skip_promotion_collect_requested": skip_collect == "true",
    "workflow_definition_verification": {
        "id": int(workflow_id),
        "path": workflow_path,
        "expected_path": expected_workflow_path or workflow_path,
        "state": workflow_state,
        "name": workflow_name,
    },
    "branch_protection_preflight": branch_protection_preflight,
    "environment_reviewer_preflight": environment_preflight,
    "required_secret_preflight": {
        "required_count": len(required_secret_preflight),
        "secrets": required_secret_preflight,
    },
    "next_step": "rerun without --preflight-only to dispatch or capture the protected-branch promotion run",
}
path = Path(receipt_path)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
print(str(path))
PY
}

resolve_run_id_from_recent_runs() {
  local repo="$1"
  local workflow_file="$2"
  local ref="$3"
  local dispatch_epoch="$4"
  local ref_name="$ref"
  if [[ "$ref_name" == refs/heads/* ]]; then
    ref_name="${ref_name#refs/heads/}"
  fi
  local runs_json
  runs_json="$(gh run list \
    --repo "$repo" \
    --workflow "$workflow_file" \
    --event workflow_dispatch \
    --branch "$ref_name" \
    --limit 20 \
    --json databaseId,createdAt,event,headBranch,url)"
  python - "$dispatch_epoch" "$runs_json" <<'PY'
import datetime
import json
import sys

dispatch_epoch = float(sys.argv[1])
payload = json.loads(sys.argv[2])

def parse_epoch(value: str) -> float:
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()

candidates = []
for item in payload:
    created = item.get("createdAt")
    if not isinstance(created, str):
        continue
    try:
        created_epoch = parse_epoch(created)
    except ValueError:
        continue
    # Tolerate small clock drift for robust fallback selection.
    if created_epoch + 30 < dispatch_epoch:
        continue
    if item.get("event") != "workflow_dispatch":
        continue
    run_id = item.get("databaseId")
    if isinstance(run_id, int):
        candidates.append((created_epoch, str(run_id)))
    elif isinstance(run_id, str) and run_id.isdigit():
        candidates.append((created_epoch, run_id))

if not candidates:
    print("")
else:
    candidates.sort(key=lambda entry: entry[0], reverse=True)
    print(candidates[0][1])
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="$2"
      shift 2
      ;;
    --ref)
      REF="$2"
      REF_EXPLICIT="true"
      shift 2
      ;;
    --workflow-file)
      WORKFLOW_FILE="$2"
      shift 2
      ;;
    --workflow-job-id)
      WORKFLOW_JOB_ID="$2"
      shift 2
      ;;
    --rotation-rehearsal)
      ROTATION_REHEARSAL="$2"
      shift 2
      ;;
    --skip-promotion-collect)
      SKIP_PROMOTION_COLLECT="$2"
      shift 2
      ;;
    --approver)
      APPROVER="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --run-attempt)
      RUN_ATTEMPT="$2"
      shift 2
      ;;
    --output-root)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --preflight-only)
      PREFLIGHT_ONLY="true"
      shift
      ;;
    --expected-environment)
      EXPECTED_ENVIRONMENT="$2"
      shift 2
      ;;
    --no-require-environment-reviewers)
      REQUIRE_ENVIRONMENT_REVIEWERS="false"
      shift
      ;;
    --required-secret)
      require_token_no_whitespace "$2" "required-secret"
      if [[ -z "$REQUIRED_SECRET_NAMES" ]]; then
        REQUIRED_SECRET_NAMES="$2"
      else
        REQUIRED_SECRET_NAMES="${REQUIRED_SECRET_NAMES},$2"
      fi
      shift 2
      ;;
    --poll-interval-seconds)
      POLL_INTERVAL_SECONDS="$2"
      shift 2
      ;;
    --timeout-seconds)
      TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --artifact-index-wait-seconds)
      ARTIFACT_INDEX_WAIT_SECONDS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_command gh
require_command python
require_command sed

if [[ -z "$WORKFLOW_JOB_ID" || "$WORKFLOW_JOB_ID" != "${WORKFLOW_JOB_ID//[[:space:]]/}" ]]; then
  echo "Invalid workflow-job-id: ${WORKFLOW_JOB_ID} (expected non-empty token without whitespace)" >&2
  exit 1
fi

require_boolean_token "$ROTATION_REHEARSAL" "rotation-rehearsal"
require_boolean_token "$SKIP_PROMOTION_COLLECT" "skip-promotion-collect"
require_boolean_token "$PREFLIGHT_ONLY" "preflight-only"
require_boolean_token "$REQUIRE_ENVIRONMENT_REVIEWERS" "require-environment-reviewers"
if [[ -n "$EXPECTED_ENVIRONMENT" ]]; then
  if [[ "$EXPECTED_ENVIRONMENT" =~ ^[[:space:]] || "$EXPECTED_ENVIRONMENT" =~ [[:space:]]$ ]]; then
    echo "Invalid expected-environment: must not contain leading or trailing whitespace" >&2
    exit 1
  fi
fi
require_positive_integer "$POLL_INTERVAL_SECONDS" "poll-interval-seconds"
require_positive_integer "$TIMEOUT_SECONDS" "timeout-seconds"
require_positive_integer "$ARTIFACT_INDEX_WAIT_SECONDS" "artifact-index-wait-seconds"
if [[ -n "$RUN_ID" ]]; then
  require_positive_integer "$RUN_ID" "run-id"
fi
if [[ -n "$RUN_ATTEMPT" ]]; then
  require_positive_integer "$RUN_ATTEMPT" "run-attempt"
fi
if [[ -z "$RUN_ID" && -n "$RUN_ATTEMPT" ]]; then
  echo "--run-attempt requires --run-id." >&2
  exit 1
fi
if [[ "$PREFLIGHT_ONLY" == "true" && -n "$RUN_ID" ]]; then
  echo "--preflight-only cannot be combined with --run-id." >&2
  exit 1
fi

if [[ -z "$REPO" ]]; then
  REPO="$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null || true)"
fi
if [[ -z "$REPO" ]]; then
  echo "Unable to resolve repository slug. Provide --repo <owner/repo>." >&2
  exit 1
fi
require_repo_slug "$REPO"

expected_workflow_path="$(resolve_expected_workflow_path "$WORKFLOW_FILE")"
expected_branch_ref="$(normalize_branch_ref_name "$REF")"

verify_github_cli_repo_access "$REPO"
resolved_workflow_definition="$(resolve_workflow_definition_identity "$REPO" "$WORKFLOW_FILE" "$expected_workflow_path")"
resolved_workflow_definition_id="$(printf '%s\n' "$resolved_workflow_definition" | sed -n '1p')"
resolved_workflow_definition_path="$(printf '%s\n' "$resolved_workflow_definition" | sed -n '2p')"
resolved_workflow_definition_state="$(printf '%s\n' "$resolved_workflow_definition" | sed -n '3p')"
resolved_workflow_definition_name="$(printf '%s\n' "$resolved_workflow_definition" | sed -n '4p')"
if [[ -z "$expected_workflow_path" ]]; then
  expected_workflow_path="$resolved_workflow_definition_path"
fi

branch_protection_preflight_json="$(verify_branch_protection_preflight "$REPO" "$expected_branch_ref")"
environment_preflight_json="$(verify_environment_preflight "$REPO" "$EXPECTED_ENVIRONMENT" "$REQUIRE_ENVIRONMENT_REVIEWERS")"
required_secret_names_resolved="$(verify_required_secrets_preflight "$REPO" "$EXPECTED_ENVIRONMENT" "$REQUIRED_SECRET_NAMES" "$ROTATION_REHEARSAL")"
required_secret_preflight_jsonl=""
while IFS= read -r required_secret_name; do
  required_secret_name="$(strip_crlf "$required_secret_name")"
  if [[ -z "$required_secret_name" ]]; then
    continue
  fi
  required_secret_row="$(verify_secret_metadata_name "$REPO" "$EXPECTED_ENVIRONMENT" "$required_secret_name")"
  if [[ -z "$required_secret_preflight_jsonl" ]]; then
    required_secret_preflight_jsonl="$required_secret_row"
  else
    required_secret_preflight_jsonl="${required_secret_preflight_jsonl}"$'\n'"${required_secret_row}"
  fi
done <<< "$required_secret_names_resolved"

mkdir -p "$OUTPUT_ROOT"
if [[ "$PREFLIGHT_ONLY" == "true" ]]; then
  preflight_receipt_path="${OUTPUT_ROOT}/promotion_preflight_receipt.json"
  write_promotion_preflight_receipt \
    "$preflight_receipt_path" \
    "$REPO" \
    "$WORKFLOW_FILE" \
    "$REF" \
    "$expected_workflow_path" \
    "$resolved_workflow_definition_id" \
    "$resolved_workflow_definition_path" \
    "$resolved_workflow_definition_state" \
    "$resolved_workflow_definition_name" \
    "$ROTATION_REHEARSAL" \
    "$SKIP_PROMOTION_COLLECT" \
    "$branch_protection_preflight_json" \
    "$environment_preflight_json" \
    "$required_secret_preflight_jsonl"
  echo "Promotion evidence preflight passed."
  echo "preflight_receipt=${preflight_receipt_path}"
  exit 0
fi
dispatch_epoch="$(date -u +%s)"
dispatch_utc=""
capture_mode="dispatch"
run_id=""
run_id_resolution_mode="provided"
dispatch_run_url_api=""
dispatch_run_html_url=""
dispatch_workflow_id_api=""
if [[ -n "$RUN_ID" ]]; then
  capture_mode="existing-run"
  run_id="$RUN_ID"
  run_id_resolution_mode="provided"
  echo "Using existing workflow run run_id=${run_id} on ${REPO}"
else
  dispatch_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Dispatching workflow ${WORKFLOW_FILE} on ${REPO}@${REF}"

  dispatch_output=""
  dispatch_status=0
  set +e
  dispatch_output="$(dispatch_workflow_with_run_details "$REPO" "$WORKFLOW_FILE" "$REF" "$ROTATION_REHEARSAL" "$SKIP_PROMOTION_COLLECT" "$APPROVER" 2>&1)"
  dispatch_status=$?
  set -e
  if [[ "$dispatch_status" -ne 0 ]]; then
    printf '%s\n' "$dispatch_output"
    echo "Workflow dispatch API with run details failed; falling back to gh workflow run..." >&2
    dispatch_cmd=(
      gh workflow run "$WORKFLOW_FILE"
      --repo "$REPO"
      --ref "$REF"
      -f "rotation_rehearsal=${ROTATION_REHEARSAL}"
      -f "skip_promotion_collect=${SKIP_PROMOTION_COLLECT}"
    )
    if [[ -n "$APPROVER" ]]; then
      dispatch_cmd+=(-f "approver=${APPROVER}")
    fi
    set +e
    dispatch_output="$("${dispatch_cmd[@]}" 2>&1)"
    dispatch_status=$?
    set -e
    printf '%s\n' "$dispatch_output"
    if [[ "$dispatch_status" -ne 0 ]]; then
      echo "Workflow dispatch failed." >&2
      exit "$dispatch_status"
    fi
    run_id="$(extract_run_id_from_dispatch_output "$dispatch_output")"
    if [[ -n "$run_id" ]]; then
      run_id_resolution_mode="dispatch-output"
    fi
  else
    if [[ -n "$dispatch_output" ]]; then
      printf '%s\n' "$dispatch_output"
    fi
    dispatch_response_parsed="$(extract_run_id_from_dispatch_response_json "$dispatch_output")"
    run_id="$(printf '%s\n' "$dispatch_response_parsed" | sed -n '1p')"
    dispatch_run_url_api="$(printf '%s\n' "$dispatch_response_parsed" | sed -n '2p')"
    dispatch_run_html_url="$(printf '%s\n' "$dispatch_response_parsed" | sed -n '3p')"
    dispatch_workflow_id_api="$(printf '%s\n' "$dispatch_response_parsed" | sed -n '4p')"
    if [[ -n "$run_id" ]]; then
      run_id_resolution_mode="dispatch-api"
    fi
  fi
  if [[ -z "$run_id" ]]; then
    echo "Dispatch output did not include a run id; resolving via recent workflow runs..."
    run_id="$(resolve_run_id_from_recent_runs "$REPO" "$WORKFLOW_FILE" "$REF" "$dispatch_epoch")"
    if [[ -n "$run_id" ]]; then
      run_id_resolution_mode="recent-runs"
    fi
  fi
  if [[ -z "$run_id" ]]; then
    echo "Unable to determine workflow run id for dispatched promotion run." >&2
    exit 1
  fi
fi
echo "Resolved run_id=${run_id}"
echo "run_id_resolution_mode=${run_id_resolution_mode}"

deadline_epoch="$((dispatch_epoch + TIMEOUT_SECONDS))"
run_attempt=""
run_url=""
run_status=""
run_conclusion=""
run_metadata_json=""
run_event=""
run_head_branch=""
run_workflow_name=""
run_head_sha=""
run_number=""
run_created_at=""
run_started_at=""

while :; do
  run_metadata_json="$(gh run view "$run_id" --repo "$REPO" --json attempt,status,conclusion,url,updatedAt,event,headBranch,workflowName,headSha,number,createdAt,startedAt)"
  parsed="$(printf '%s\n' "$run_metadata_json" | python -c 'import json,sys
payload=json.load(sys.stdin)
print(payload.get("attempt",""))
print(payload.get("status",""))
print(payload.get("conclusion",""))
print(payload.get("url",""))
print(payload.get("updatedAt",""))
print(payload.get("event",""))
print(payload.get("headBranch",""))
print(payload.get("workflowName",""))
print(payload.get("headSha",""))
print(payload.get("number",""))
print(payload.get("createdAt",""))
print(payload.get("startedAt",""))
')"
  run_attempt="$(printf '%s\n' "$parsed" | sed -n '1p')"
  run_status="$(printf '%s\n' "$parsed" | sed -n '2p')"
  run_conclusion="$(printf '%s\n' "$parsed" | sed -n '3p')"
  run_url="$(printf '%s\n' "$parsed" | sed -n '4p')"
  run_updated_at="$(printf '%s\n' "$parsed" | sed -n '5p')"
  run_event="$(printf '%s\n' "$parsed" | sed -n '6p')"
  run_head_branch="$(printf '%s\n' "$parsed" | sed -n '7p')"
  run_workflow_name="$(printf '%s\n' "$parsed" | sed -n '8p')"
  run_head_sha="$(printf '%s\n' "$parsed" | sed -n '9p')"
  run_number="$(printf '%s\n' "$parsed" | sed -n '10p')"
  run_created_at="$(printf '%s\n' "$parsed" | sed -n '11p')"
  run_started_at="$(printf '%s\n' "$parsed" | sed -n '12p')"
  echo "run_id=${run_id} attempt=${run_attempt:-unknown} status=${run_status:-unknown} conclusion=${run_conclusion:-pending} run_number=${run_number:-unknown}"
  echo "event=${run_event:-unknown} head_branch=${run_head_branch:-unknown} head_sha=${run_head_sha:-unknown} workflow_name=${run_workflow_name:-unknown} created=${run_created_at:-unknown} started=${run_started_at:-unknown} updated=${run_updated_at:-unknown}"

  if [[ "$run_status" == "completed" ]]; then
    break
  fi
  now_epoch="$(date -u +%s)"
  if [[ "$now_epoch" -ge "$deadline_epoch" ]]; then
    echo "Timed out waiting for workflow run completion (run_id=${run_id})." >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
  sleep "$POLL_INTERVAL_SECONDS"
done

if [[ "$run_conclusion" != "success" ]]; then
  fail_dir="${OUTPUT_ROOT}/run-${run_id}-attempt-${run_attempt:-unknown}"
  mkdir -p "$fail_dir"
  gh run view "$run_id" --repo "$REPO" --log-failed > "${fail_dir}/run_failed.log" || true
  echo "Workflow run failed: conclusion=${run_conclusion}" >&2
  echo "run_url=${run_url}" >&2
  echo "failed_log=${fail_dir}/run_failed.log" >&2
  exit 1
fi

if [[ -z "$run_attempt" ]]; then
  echo "Unable to resolve run attempt for run_id=${run_id}" >&2
  exit 1
fi
if [[ -n "$RUN_ATTEMPT" && "$run_attempt" != "$RUN_ATTEMPT" ]]; then
  echo "run_attempt mismatch for run_id=${run_id}: expected ${RUN_ATTEMPT}, got ${run_attempt}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

run_detail_json="$(gh api "repos/${REPO}/actions/runs/${run_id}")"
run_detail_parsed="$(printf '%s\n' "$run_detail_json" | python -c 'import json,sys
payload=json.load(sys.stdin)
actor = payload.get("actor")
triggering_actor = payload.get("triggering_actor")
repository = payload.get("repository")
repository_owner = repository.get("owner") if isinstance(repository, dict) else None
print(payload.get("event",""))
print(payload.get("head_branch",""))
print(payload.get("head_sha",""))
print(payload.get("path",""))
print(payload.get("html_url",""))
print(payload.get("status",""))
print(payload.get("conclusion",""))
print(payload.get("created_at",""))
print(payload.get("run_started_at",""))
print(payload.get("updated_at",""))
print(payload.get("run_attempt",""))
print(payload.get("run_number",""))
print(payload.get("retention_days",""))
print(repository.get("id","") if isinstance(repository, dict) else "")
print(repository_owner.get("id","") if isinstance(repository_owner, dict) else "")
print(actor.get("id","") if isinstance(actor, dict) else "")
print(actor.get("login","") if isinstance(actor, dict) else "")
print(triggering_actor.get("login","") if isinstance(triggering_actor, dict) else "")
print(payload.get("id",""))
print(repository.get("full_name","") if isinstance(repository, dict) else "")
print(repository_owner.get("login","") if isinstance(repository_owner, dict) else "")
print(payload.get("workflow_id",""))
')"
run_event_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '1p')"
run_head_branch_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '2p')"
run_head_sha_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '3p')"
run_workflow_path_ref="$(printf '%s\n' "$run_detail_parsed" | sed -n '4p')"
run_html_url_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '5p')"
run_status_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '6p')"
run_conclusion_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '7p')"
run_created_at_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '8p')"
run_started_at_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '9p')"
run_updated_at_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '10p')"
run_attempt_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '11p')"
run_number_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '12p')"
run_retention_days_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '13p')"
run_repository_id_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '14p')"
run_repository_owner_id_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '15p')"
run_actor_id_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '16p')"
run_actor_login_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '17p')"
run_triggering_actor_login_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '18p')"
run_id_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '19p')"
run_repository_full_name_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '20p')"
run_repository_owner_login_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '21p')"
run_workflow_id_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '22p')"

if [[ -n "$dispatch_workflow_id_api" ]]; then
  if [[ ! "$dispatch_workflow_id_api" =~ ^[0-9]+$ ]]; then
    echo "Dispatch response workflow_id is not numeric for run_id=${run_id}: ${dispatch_workflow_id_api}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
  if [[ "$dispatch_workflow_id_api" != "$resolved_workflow_definition_id" ]]; then
    echo "Dispatch response workflow_id mismatch for run_id=${run_id}: expected ${resolved_workflow_definition_id}, got ${dispatch_workflow_id_api}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
fi

if [[ -z "$run_workflow_path_ref" ]]; then
  echo "Unable to resolve workflow path identity for run_id=${run_id}." >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ "$run_workflow_path_ref" != "${run_workflow_path_ref//[[:space:]]/}" ]]; then
  echo "Resolved workflow path identity is invalid for run_id=${run_id}: ${run_workflow_path_ref}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ "$run_workflow_path_ref" == *@* ]]; then
  run_workflow_path="${run_workflow_path_ref%@*}"
  run_workflow_ref="${run_workflow_path_ref#*@}"
else
  run_workflow_path="$run_workflow_path_ref"
  if [[ -z "$run_head_branch_api" ]]; then
    echo "Unable to derive workflow ref for run_id=${run_id}: run details path did not include @ref and head_branch is missing." >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
  run_workflow_ref="$run_head_branch_api"
  echo "Run details workflow path did not include @ref; deriving workflow ref from head_branch for run_id=${run_id}." >&2
fi

if [[ "$run_workflow_path" == "${REPO}/.github/workflows/"* ]]; then
  run_workflow_path="${run_workflow_path#${REPO}/}"
fi
if [[ -z "$run_workflow_path" || "$run_workflow_path" != "${run_workflow_path//[[:space:]]/}" ]]; then
  echo "Resolved workflow path is invalid for run_id=${run_id}: ${run_workflow_path}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -n "$expected_workflow_path" && "$run_workflow_path" != "$expected_workflow_path" ]]; then
  echo "workflow path mismatch for run_id=${run_id}: expected ${expected_workflow_path}, got ${run_workflow_path}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ -z "$run_workflow_id_api" ]]; then
  echo "run workflow_id is missing in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ ! "$run_workflow_id_api" =~ ^[0-9]+$ ]]; then
  echo "run workflow_id is not numeric in run details for run_id=${run_id}: ${run_workflow_id_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ "$run_workflow_id_api" != "$resolved_workflow_definition_id" ]]; then
  echo "run workflow_id mismatch for run_id=${run_id}: expected ${resolved_workflow_definition_id}, got ${run_workflow_id_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

workflow_ref_normalization_verified="$(python - "$run_id" "$run_url" "$run_workflow_ref" "$run_head_branch_api" "$run_event_api" <<'PY'
import sys

run_id = sys.argv[1]
run_url = sys.argv[2]
run_workflow_ref = sys.argv[3]
run_head_branch = sys.argv[4]
run_event = sys.argv[5]

if not isinstance(run_workflow_ref, str) or not run_workflow_ref:
    print("run workflow ref is missing for run_id={0}".format(run_id), file=sys.stderr)
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)
if run_workflow_ref != run_workflow_ref.strip():
    print("run workflow ref must not contain leading or trailing whitespace for run_id={0}".format(run_id), file=sys.stderr)
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)

if run_workflow_ref.startswith("refs/"):
    print(run_workflow_ref)
    sys.exit(0)

if run_workflow_ref.startswith("heads/"):
    normalized = "refs/{0}".format(run_workflow_ref)
    print(normalized)
    sys.exit(0)

if run_workflow_ref.startswith("tags/"):
    normalized = "refs/{0}".format(run_workflow_ref)
    print(normalized)
    sys.exit(0)

if run_workflow_ref in ("main", "master"):
    normalized = "refs/heads/{0}".format(run_workflow_ref)
    if run_head_branch and run_workflow_ref != run_head_branch:
        print(
            "run workflow ref short branch mismatch for run_id={0}: workflow_ref={1}, head_branch={2}".format(
                run_id, run_workflow_ref, run_head_branch
            ),
            file=sys.stderr,
        )
        print("run_url={0}".format(run_url), file=sys.stderr)
        sys.exit(1)
    print(normalized)
    sys.exit(0)

if run_head_branch and run_workflow_ref == run_head_branch and run_event in ("push", "workflow_dispatch"):
    print("refs/heads/{0}".format(run_workflow_ref))
    sys.exit(0)

print(
    "run workflow ref is not canonical or semantically normalizable for run_id={0}: {1}".format(
        run_id,
        run_workflow_ref,
    ),
    file=sys.stderr,
)
print("run_url={0}".format(run_url), file=sys.stderr)
sys.exit(1)
PY
)"

if [[ -n "$run_head_branch_api" ]]; then
  expected_workflow_ref_from_head_branch="refs/heads/${run_head_branch_api}"
  if [[ "$workflow_ref_normalization_verified" != "$expected_workflow_ref_from_head_branch" ]]; then
    echo "run workflow ref normalization mismatch with head branch for run_id=${run_id}: expected ${expected_workflow_ref_from_head_branch}, got ${workflow_ref_normalization_verified}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
fi
run_workflow_ref="$workflow_ref_normalization_verified"
run_workflow_path_ref_identity="${REPO}/${run_workflow_path}@${run_workflow_ref}"

if [[ -n "$expected_branch_ref" ]]; then
  require_branch_match="false"
  if [[ "$capture_mode" == "dispatch" ]]; then
    require_branch_match="true"
  elif [[ "$REF_EXPLICIT" == "true" ]]; then
    require_branch_match="true"
  fi
  if [[ "$require_branch_match" == "true" ]]; then
    if [[ -z "$run_head_branch_api" ]]; then
      echo "Missing run head_branch for run_id=${run_id}; expected ${expected_branch_ref}" >&2
      echo "run_url=${run_url}" >&2
      exit 1
    fi
    if [[ "$run_head_branch_api" != "$expected_branch_ref" ]]; then
      echo "head_branch mismatch for run_id=${run_id}: expected ${expected_branch_ref}, got ${run_head_branch_api}" >&2
      echo "run_url=${run_url}" >&2
      exit 1
    fi
  fi
fi

if [[ "$capture_mode" == "dispatch" ]]; then
  if [[ "$run_event_api" != "workflow_dispatch" ]]; then
    echo "run event mismatch for dispatched run_id=${run_id}: expected workflow_dispatch, got ${run_event_api}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
elif [[ "$run_event_api" != "workflow_dispatch" && "$run_event_api" != "push" ]]; then
  echo "run event is not supported for promotion evidence capture: ${run_event_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -n "$run_event" && -n "$run_event_api" && "$run_event" != "$run_event_api" ]]; then
  echo "run event mismatch between summary and run details for run_id=${run_id}: ${run_event} vs ${run_event_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -z "$run_status_api" ]]; then
  echo "run status is missing in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ "$run_status_api" != "completed" ]]; then
  echo "run status is not completed in run details for run_id=${run_id}: ${run_status_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ -n "$run_status" && "$run_status" != "$run_status_api" ]]; then
  echo "run status mismatch between summary and run details for run_id=${run_id}: ${run_status} vs ${run_status_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -z "$run_conclusion_api" ]]; then
  echo "run conclusion is missing in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ "$run_conclusion_api" != "success" ]]; then
  echo "run conclusion is not success in run details for run_id=${run_id}: ${run_conclusion_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ -n "$run_conclusion" && "$run_conclusion" != "$run_conclusion_api" ]]; then
  echo "run conclusion mismatch between summary and run details for run_id=${run_id}: ${run_conclusion} vs ${run_conclusion_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -n "$run_url" && -n "$run_html_url_api" && "$run_url" != "$run_html_url_api" ]]; then
  echo "run html_url mismatch between summary and run details for run_id=${run_id}: ${run_url} vs ${run_html_url_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -n "$dispatch_run_url_api" ]]; then
  if [[ "$dispatch_run_url_api" != "${dispatch_run_url_api//[[:space:]]/}" ]]; then
    echo "Dispatch response run_url must not contain whitespace for run_id=${run_id}: ${dispatch_run_url_api}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
  dispatch_run_id_from_url="$(python - "$run_id" "$dispatch_run_url_api" <<'PY'
import re
import sys

run_id = sys.argv[1]
run_url = sys.argv[2].strip()
if not run_url:
    print("")
    raise SystemExit(0)
match = re.search(r"/actions/runs/([0-9]+)", run_url)
if not match:
    print(
        "Dispatch response run_url does not contain a canonical /actions/runs/<id> segment: {0}".format(
            run_url
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)
print(match.group(1))
PY
)"
  if [[ -n "$dispatch_run_id_from_url" && "$dispatch_run_id_from_url" != "$run_id" ]]; then
    echo "Dispatch response run_url run_id mismatch: expected ${run_id}, got ${dispatch_run_id_from_url}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
fi

if [[ -n "$dispatch_run_html_url" ]]; then
  if [[ "$dispatch_run_html_url" != "${dispatch_run_html_url//[[:space:]]/}" ]]; then
    echo "Dispatch response html_url must not contain whitespace for run_id=${run_id}: ${dispatch_run_html_url}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
  dispatch_html_run_id="$(python - "$run_id" "$dispatch_run_html_url" <<'PY'
import re
import sys

run_id = sys.argv[1]
run_url = sys.argv[2].strip()
if not run_url:
    print("")
    raise SystemExit(0)
match = re.search(r"/actions/runs/([0-9]+)", run_url)
if not match:
    print(
        "Dispatch response html_url does not contain a canonical /actions/runs/<id> segment: {0}".format(
            run_url
        ),
        file=sys.stderr,
    )
    raise SystemExit(1)
print(match.group(1))
PY
)"
  if [[ -n "$dispatch_html_run_id" && "$dispatch_html_run_id" != "$run_id" ]]; then
    echo "Dispatch response html_url run_id mismatch: expected ${run_id}, got ${dispatch_html_run_id}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
fi

run_url_identity_verification="$(python - "$run_id" "$run_attempt" "$REPO" "$run_url" "$run_html_url_api" <<'PY'
import re
import sys
from urllib.parse import urlsplit

run_id = sys.argv[1]
run_attempt = sys.argv[2]
repo = sys.argv[3]
summary_url = sys.argv[4]
detail_url = sys.argv[5]

def _parse_and_verify_run_url(label: str, value: str):
    if not isinstance(value, str) or not value:
        print("{0} is missing.".format(label), file=sys.stderr)
        sys.exit(1)
    if value != value.strip():
        print("{0} must not contain leading or trailing whitespace.".format(label), file=sys.stderr)
        sys.exit(1)
    parts = urlsplit(value)
    if parts.scheme != "https":
        print("{0} must use https scheme.".format(label), file=sys.stderr)
        sys.exit(1)
    if not parts.netloc:
        print("{0} host is missing.".format(label), file=sys.stderr)
        sys.exit(1)
    if parts.query or parts.fragment:
        print("{0} must not include query or fragment components.".format(label), file=sys.stderr)
        sys.exit(1)
    match = re.fullmatch(
        r"/(?P<repo>[^/\s]+/[^/\s]+)/actions/runs/(?P<run_id>[0-9]+)(?:/attempts/(?P<attempt>[0-9]+))?/?",
        parts.path,
    )
    if match is None:
        print(
            "{0} path is not a canonical GitHub Actions run URL: {1}".format(label, value),
            file=sys.stderr,
        )
        sys.exit(1)
    path_repo = match.group("repo")
    if path_repo != repo:
        print(
            "{0} repository path mismatch: expected {1}, got {2}".format(
                label,
                repo,
                path_repo,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    path_run_id = match.group("run_id")
    if path_run_id != run_id:
        print(
            "{0} run_id path mismatch: expected {1}, got {2}".format(
                label,
                run_id,
                path_run_id,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    attempt = match.group("attempt") or ""
    if attempt and run_attempt and attempt != run_attempt:
        print(
            "{0} attempt path mismatch: expected {1}, got {2}".format(
                label,
                run_attempt,
                attempt,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    return parts.netloc, attempt

summary_host, summary_attempt = _parse_and_verify_run_url("run summary url", summary_url)
detail_host, detail_attempt = _parse_and_verify_run_url("run detail html_url", detail_url)
if summary_host != detail_host:
    print(
        "run url host mismatch between summary and run details for run_id={0}: {1} vs {2}".format(
            run_id,
            summary_host,
            detail_host,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

print(summary_host)
print(summary_attempt)
print(detail_host)
print(detail_attempt)
PY
)"
run_url_host_verified="$(printf '%s\n' "$run_url_identity_verification" | sed -n '1p')"
run_url_attempt_verified="$(printf '%s\n' "$run_url_identity_verification" | sed -n '2p')"
run_html_url_host_verified="$(printf '%s\n' "$run_url_identity_verification" | sed -n '3p')"
run_html_url_attempt_verified="$(printf '%s\n' "$run_url_identity_verification" | sed -n '4p')"

dispatch_url_identity_verification="$(python - "$run_id" "$run_attempt" "$REPO" "$run_url_host_verified" "$dispatch_run_url_api" "$dispatch_run_html_url" <<'PY'
import re
import sys
from urllib.parse import urlsplit

run_id = sys.argv[1]
run_attempt = sys.argv[2]
repo = sys.argv[3]
expected_host = sys.argv[4]
dispatch_run_url = sys.argv[5]
dispatch_html_url = sys.argv[6]

def _verify_optional_dispatch_url(label: str, value: str) -> tuple[str, str]:
    if not value:
        return "", ""
    if value != value.strip():
        print("{0} must not contain leading or trailing whitespace.".format(label), file=sys.stderr)
        sys.exit(1)
    parts = urlsplit(value)
    if parts.scheme != "https":
        print("{0} must use https scheme.".format(label), file=sys.stderr)
        sys.exit(1)
    if not parts.netloc:
        print("{0} host is missing.".format(label), file=sys.stderr)
        sys.exit(1)
    if parts.query or parts.fragment:
        print("{0} must not include query or fragment components.".format(label), file=sys.stderr)
        sys.exit(1)
    if expected_host and parts.netloc.lower() != expected_host.lower():
        print(
            "{0} host mismatch with resolved run url host: expected {1}, got {2}".format(
                label,
                expected_host,
                parts.netloc,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    match = re.fullmatch(
        r"/(?P<repo>[^/\s]+/[^/\s]+)/actions/runs/(?P<run_id>[0-9]+)(?:/attempts/(?P<attempt>[0-9]+))?/?",
        parts.path,
    )
    if match is None:
        print("{0} path is not canonical: {1}".format(label, value), file=sys.stderr)
        sys.exit(1)
    path_repo = match.group("repo")
    if path_repo != repo:
        print(
            "{0} repository path mismatch: expected {1}, got {2}".format(
                label,
                repo,
                path_repo,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    path_run_id = match.group("run_id")
    if path_run_id != run_id:
        print(
            "{0} run_id path mismatch: expected {1}, got {2}".format(
                label,
                run_id,
                path_run_id,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    attempt = match.group("attempt") or ""
    if attempt and run_attempt and attempt != run_attempt:
        print(
            "{0} attempt path mismatch: expected {1}, got {2}".format(
                label,
                run_attempt,
                attempt,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    return parts.netloc, attempt

run_url_host, run_url_attempt = _verify_optional_dispatch_url("dispatch response run_url", dispatch_run_url)
html_url_host, html_url_attempt = _verify_optional_dispatch_url("dispatch response html_url", dispatch_html_url)
if run_url_host and html_url_host and run_url_host.lower() != html_url_host.lower():
    print(
        "dispatch response URL host mismatch between run_url and html_url: {0} vs {1}".format(
            run_url_host,
            html_url_host,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
print(run_url_host)
print(run_url_attempt)
print(html_url_host)
print(html_url_attempt)
PY
)"
dispatch_run_url_host_verified="$(printf '%s\n' "$dispatch_url_identity_verification" | sed -n '1p')"
dispatch_run_url_attempt_verified="$(printf '%s\n' "$dispatch_url_identity_verification" | sed -n '2p')"
dispatch_html_url_host_verified="$(printf '%s\n' "$dispatch_url_identity_verification" | sed -n '3p')"
dispatch_html_url_attempt_verified="$(printf '%s\n' "$dispatch_url_identity_verification" | sed -n '4p')"

if [[ -n "$run_head_branch" && -n "$run_head_branch_api" && "$run_head_branch" != "$run_head_branch_api" ]]; then
  echo "head_branch mismatch between summary and run details for run_id=${run_id}: ${run_head_branch} vs ${run_head_branch_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -n "$run_head_sha" ]]; then
  if [[ ! "$run_head_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "run head_sha is not a canonical 40-char lowercase hex digest in summary metadata for run_id=${run_id}: ${run_head_sha}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
fi
if [[ -n "$run_head_sha" && -n "$run_head_sha_api" && "$run_head_sha" != "$run_head_sha_api" ]]; then
  echo "head_sha mismatch between summary and run details for run_id=${run_id}: ${run_head_sha} vs ${run_head_sha_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -n "$run_number" && ! "$run_number" =~ ^[0-9]+$ ]]; then
  echo "run number is not numeric in summary metadata for run_id=${run_id}: ${run_number}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ -n "$run_number_api" && ! "$run_number_api" =~ ^[0-9]+$ ]]; then
  echo "run number is not numeric in run details metadata for run_id=${run_id}: ${run_number_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ -n "$run_number" && -n "$run_number_api" && "$run_number" != "$run_number_api" ]]; then
  echo "run number mismatch between summary and run details for run_id=${run_id}: ${run_number} vs ${run_number_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -z "$run_retention_days_api" ]]; then
  echo "Run details retention_days is missing; deferring retention_days verification to workflow artifacts for run_id=${run_id}." >&2
else
  if [[ ! "$run_retention_days_api" =~ ^[0-9]+$ ]]; then
    echo "run retention_days is not numeric in run details for run_id=${run_id}: ${run_retention_days_api}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
  if [[ "$run_retention_days_api" -le 0 ]]; then
    echo "run retention_days must be positive in run details for run_id=${run_id}: ${run_retention_days_api}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
fi

run_timestamp_verification="$(python - "$run_id" "$run_url" "$run_created_at" "$run_started_at" "$run_updated_at" "$run_created_at_api" "$run_started_at_api" "$run_updated_at_api" <<'PY'
import sys
from datetime import datetime

run_id = sys.argv[1]
run_url = sys.argv[2]
run_created_at_summary = sys.argv[3]
run_started_at_summary = sys.argv[4]
run_updated_at_summary = sys.argv[5]
run_created_at_detail = sys.argv[6]
run_started_at_detail = sys.argv[7]
run_updated_at_detail = sys.argv[8]

def parse_required_iso8601_utc(label: str, value: str) -> datetime:
    if not isinstance(value, str) or not value:
        print("{0} is missing for run_id={1}".format(label, run_id), file=sys.stderr)
        print("run_url={0}".format(run_url), file=sys.stderr)
        sys.exit(1)
    if value != value.strip():
        print("{0} must not contain leading or trailing whitespace for run_id={1}".format(label, run_id), file=sys.stderr)
        print("run_url={0}".format(run_url), file=sys.stderr)
        sys.exit(1)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        print("{0} is not valid ISO-8601 for run_id={1}: {2}".format(label, run_id, value), file=sys.stderr)
        print("run_url={0}".format(run_url), file=sys.stderr)
        sys.exit(1)

created_summary_dt = parse_required_iso8601_utc("run summary createdAt", run_created_at_summary)
started_summary_dt = parse_required_iso8601_utc("run summary startedAt", run_started_at_summary)
updated_summary_dt = parse_required_iso8601_utc("run summary updatedAt", run_updated_at_summary)
if started_summary_dt < created_summary_dt:
    print(
        "run summary startedAt precedes createdAt for run_id={0}: {1} < {2}".format(
            run_id,
            run_started_at_summary,
            run_created_at_summary,
        ),
        file=sys.stderr,
    )
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)
if updated_summary_dt < started_summary_dt:
    print(
        "run summary updatedAt precedes startedAt for run_id={0}: {1} < {2}".format(
            run_id,
            run_updated_at_summary,
            run_started_at_summary,
        ),
        file=sys.stderr,
    )
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)

created_detail_dt = parse_required_iso8601_utc("run detail created_at", run_created_at_detail)
started_detail_dt = parse_required_iso8601_utc("run detail run_started_at", run_started_at_detail)
updated_detail_dt = parse_required_iso8601_utc("run detail updated_at", run_updated_at_detail)
if started_detail_dt < created_detail_dt:
    print(
        "run detail run_started_at precedes created_at for run_id={0}: {1} < {2}".format(
            run_id,
            run_started_at_detail,
            run_created_at_detail,
        ),
        file=sys.stderr,
    )
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)
if updated_detail_dt < started_detail_dt:
    print(
        "run detail updated_at precedes run_started_at for run_id={0}: {1} < {2}".format(
            run_id,
            run_updated_at_detail,
            run_started_at_detail,
        ),
        file=sys.stderr,
    )
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)

if created_summary_dt != created_detail_dt:
    print(
        "run created timestamp mismatch between summary and run details for run_id={0}: {1} vs {2}".format(
            run_id,
            run_created_at_summary,
            run_created_at_detail,
        ),
        file=sys.stderr,
    )
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)
if started_summary_dt != started_detail_dt:
    print(
        "run started timestamp mismatch between summary and run details for run_id={0}: {1} vs {2}".format(
            run_id,
            run_started_at_summary,
            run_started_at_detail,
        ),
        file=sys.stderr,
    )
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)
if updated_summary_dt != updated_detail_dt:
    print(
        "run updated timestamp mismatch between summary and run details for run_id={0}: {1} vs {2}".format(
            run_id,
            run_updated_at_summary,
            run_updated_at_detail,
        ),
        file=sys.stderr,
    )
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)

print(run_created_at_summary)
print(run_started_at_summary)
print(run_updated_at_summary)
print(run_created_at_detail)
print(run_started_at_detail)
print(run_updated_at_detail)
PY
)"
run_created_at_summary_verified="$(printf '%s\n' "$run_timestamp_verification" | sed -n '1p')"
run_started_at_summary_verified="$(printf '%s\n' "$run_timestamp_verification" | sed -n '2p')"
run_updated_at_summary_verified="$(printf '%s\n' "$run_timestamp_verification" | sed -n '3p')"
run_created_at_detail_verified="$(printf '%s\n' "$run_timestamp_verification" | sed -n '4p')"
run_started_at_detail_verified="$(printf '%s\n' "$run_timestamp_verification" | sed -n '5p')"
run_updated_at_detail_verified="$(printf '%s\n' "$run_timestamp_verification" | sed -n '6p')"

if [[ -z "$run_attempt_api" ]]; then
  echo "run attempt is missing in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ ! "$run_attempt_api" =~ ^[0-9]+$ ]]; then
  echo "run attempt is not numeric in run details for run_id=${run_id}: ${run_attempt_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ ! "$run_attempt" =~ ^[0-9]+$ ]]; then
  echo "run attempt is not numeric in summary metadata for run_id=${run_id}: ${run_attempt}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ "$run_attempt_api" != "$run_attempt" ]]; then
  echo "run attempt mismatch between summary and run details for run_id=${run_id}: ${run_attempt} vs ${run_attempt_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -z "$run_id_api" ]]; then
  echo "run id is missing in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ ! "$run_id_api" =~ ^[0-9]+$ ]]; then
  echo "run id is not numeric in run details for run_id=${run_id}: ${run_id_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ "$run_id_api" != "$run_id" ]]; then
  echo "run id mismatch between resolved run id and run details for run_id=${run_id}: ${run_id_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -z "$run_repository_full_name_api" ]]; then
  echo "run repository.full_name is missing in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
run_repository_full_name_api_trimmed="$(printf '%s\n' "$run_repository_full_name_api" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
if [[ "$run_repository_full_name_api" != "$run_repository_full_name_api_trimmed" ]]; then
  echo "run repository.full_name must not contain leading or trailing whitespace in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ "$run_repository_full_name_api" != "$REPO" ]]; then
  echo "run repository.full_name mismatch for run_id=${run_id}: expected ${REPO}, got ${run_repository_full_name_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ "$REPO" == */* ]]; then
  expected_repo_owner_api="${REPO%%/*}"
  if [[ -z "$run_repository_owner_login_api" ]]; then
    echo "run repository.owner.login is missing in run details for run_id=${run_id}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
  run_repository_owner_login_api_trimmed="$(printf '%s\n' "$run_repository_owner_login_api" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  if [[ "$run_repository_owner_login_api" != "$run_repository_owner_login_api_trimmed" ]]; then
    echo "run repository.owner.login must not contain leading or trailing whitespace in run details for run_id=${run_id}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
  if [[ "$run_repository_owner_login_api" != "$expected_repo_owner_api" ]]; then
    echo "run repository.owner.login mismatch for run_id=${run_id}: expected ${expected_repo_owner_api}, got ${run_repository_owner_login_api}" >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
fi

if [[ -z "$run_repository_id_api" ]]; then
  echo "run repository.id is missing in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ ! "$run_repository_id_api" =~ ^[0-9]+$ ]]; then
  echo "run repository.id is not numeric in run details for run_id=${run_id}: ${run_repository_id_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -z "$run_repository_owner_id_api" ]]; then
  echo "run repository.owner.id is missing in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ ! "$run_repository_owner_id_api" =~ ^[0-9]+$ ]]; then
  echo "run repository.owner.id is not numeric in run details for run_id=${run_id}: ${run_repository_owner_id_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -z "$run_actor_id_api" ]]; then
  echo "run actor.id is missing in run details for run_id=${run_id}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
if [[ ! "$run_actor_id_api" =~ ^[0-9]+$ ]]; then
  echo "run actor.id is not numeric in run details for run_id=${run_id}: ${run_actor_id_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

echo "Verifying promotion gate job and step outcomes for run attempt ${run_attempt}"
promotion_jobs_json="$(gh api "repos/${REPO}/actions/runs/${run_id}/attempts/${run_attempt}/jobs?per_page=100")"
promotion_jobs_json_path="${OUTPUT_ROOT}/run-${run_id}-attempt-${run_attempt}/promotion_jobs.json"
mkdir -p "$(dirname "$promotion_jobs_json_path")"
printf '%s\n' "$promotion_jobs_json" > "$promotion_jobs_json_path"
promotion_job_verification_parsed="$(python - "$ROTATION_REHEARSAL" "$run_actor_login_api" "$run_triggering_actor_login_api" "$run_id" "$run_attempt" "$run_head_sha_api" "$run_head_branch_api" "$REPO" "$run_url_host_verified" "$run_workflow_name" "$promotion_jobs_json_path" <<'PY'
import json
import re
import sys
from urllib.parse import urlsplit
from datetime import datetime
from pathlib import Path

rotation_rehearsal = sys.argv[1]
run_actor_login = sys.argv[2]
run_triggering_actor_login = sys.argv[3]
expected_run_id = sys.argv[4]
expected_run_attempt = sys.argv[5]
expected_head_sha = sys.argv[6]
expected_head_branch = sys.argv[7]
expected_repo = sys.argv[8]
expected_run_url_host = sys.argv[9]
expected_workflow_name = sys.argv[10]
payload_path = Path(sys.argv[11])
payload = json.loads(payload_path.read_text(encoding="utf-8"))
job_rows = payload.get("jobs")
if not isinstance(job_rows, list):
    print("Workflow jobs payload is invalid for promotion-gate verification.", file=sys.stderr)
    sys.exit(1)

promotion_job_name = "Signed Approval Promotion Gate"
matches = [row for row in job_rows if isinstance(row, dict) and row.get("name") == promotion_job_name]
if len(matches) != 1:
    print(
        "Expected exactly one job named {0}; found {1}.".format(
            promotion_job_name, len(matches)
        ),
        file=sys.stderr,
    )
    sys.exit(1)
job = matches[0]
job_status = job.get("status")
job_conclusion = job.get("conclusion")
if job_status != "completed":
    print(
        "Promotion gate job status must be completed; got {0}".format(job_status),
        file=sys.stderr,
    )
    sys.exit(1)
if job_conclusion != "success":
    print(
        "Promotion gate job conclusion must be success; got {0}".format(job_conclusion),
        file=sys.stderr,
    )
    sys.exit(1)

job_id = job.get("id")
job_id_text = str(job_id) if job_id is not None else ""
if not job_id_text.isdigit():
    print(
        "Promotion gate job id must be numeric; got {0}".format(job_id_text or "<missing>"),
        file=sys.stderr,
    )
    sys.exit(1)

job_run_id = job.get("run_id")
job_run_id_text = str(job_run_id) if job_run_id is not None else ""
if not job_run_id_text.isdigit() or job_run_id_text != expected_run_id:
    print(
        "Promotion gate job run_id mismatch: expected {0}, got {1}".format(
            expected_run_id, job_run_id_text or "<missing>"
        ),
        file=sys.stderr,
    )
    sys.exit(1)

job_run_attempt = job.get("run_attempt")
if job_run_attempt is not None:
    job_run_attempt_text = str(job_run_attempt)
    if not job_run_attempt_text.isdigit():
        print("Promotion gate job run_attempt must be numeric when provided.", file=sys.stderr)
        sys.exit(1)
    if expected_run_attempt and job_run_attempt_text != expected_run_attempt:
        print(
            "Promotion gate job run_attempt mismatch: expected {0}, got {1}".format(
                expected_run_attempt, job_run_attempt_text
            ),
            file=sys.stderr,
        )
        sys.exit(1)

job_html_url = job.get("html_url")
if not isinstance(job_html_url, str) or not job_html_url.strip():
    print("Promotion gate job html_url is missing.", file=sys.stderr)
    sys.exit(1)
if job_html_url != job_html_url.strip():
    print("Promotion gate job html_url must not contain leading or trailing whitespace.", file=sys.stderr)
    sys.exit(1)
job_html_url_parts = urlsplit(job_html_url)
if job_html_url_parts.scheme != "https":
    print("Promotion gate job html_url must use https scheme.", file=sys.stderr)
    sys.exit(1)
if not job_html_url_parts.netloc:
    print("Promotion gate job html_url host is missing.", file=sys.stderr)
    sys.exit(1)
if job_html_url_parts.query or job_html_url_parts.fragment:
    print("Promotion gate job html_url must not include query or fragment components.", file=sys.stderr)
    sys.exit(1)
job_url_match = re.fullmatch(
    r"/(?P<repo>[^/\s]+/[^/\s]+)/(?:actions/)?runs/(?P<run_id>[0-9]+)(?:/attempts/(?P<attempt>[0-9]+))?/(?:(?:job|jobs)/)(?P<job_id>[0-9]+)/?",
    job_html_url_parts.path,
)
if job_url_match is None:
    print(
        "Promotion gate job html_url path is not canonical: {0}".format(job_html_url),
        file=sys.stderr,
    )
    sys.exit(1)
job_html_url_repo = job_url_match.group("repo")
if job_html_url_repo != expected_repo:
    print(
        "Promotion gate job html_url repository path mismatch: expected {0}, got {1}".format(
            expected_repo, job_html_url_repo
        ),
        file=sys.stderr,
    )
    sys.exit(1)
job_html_url_run_id = job_url_match.group("run_id")
if job_html_url_run_id != expected_run_id:
    print(
        "Promotion gate job html_url run_id path mismatch: expected {0}, got {1}".format(
            expected_run_id, job_html_url_run_id
        ),
        file=sys.stderr,
    )
    sys.exit(1)
job_html_url_job_id = job_url_match.group("job_id")
if job_html_url_job_id != job_id_text:
    print(
        "Promotion gate job html_url job_id path mismatch: expected {0}, got {1}".format(
            job_id_text, job_html_url_job_id
        ),
        file=sys.stderr,
    )
    sys.exit(1)
job_html_url_attempt = job_url_match.group("attempt") or ""
if job_html_url_attempt and expected_run_attempt and job_html_url_attempt != expected_run_attempt:
    print(
        "Promotion gate job html_url attempt path mismatch: expected {0}, got {1}".format(
            expected_run_attempt, job_html_url_attempt
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if expected_run_url_host and job_html_url_parts.netloc != expected_run_url_host:
    print(
        "Promotion gate job html_url host mismatch with run url host: expected {0}, got {1}".format(
            expected_run_url_host,
            job_html_url_parts.netloc,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

def parse_iso8601_utc(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        print("Promotion gate job {0} is missing.".format(label), file=sys.stderr)
        sys.exit(1)
    text = value.strip()
    if text != value:
        print(
            "Promotion gate job {0} must not contain leading or trailing whitespace.".format(label),
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        print("Promotion gate job {0} is not valid ISO-8601: {1}".format(label, value), file=sys.stderr)
        sys.exit(1)

job_started_at = str(job.get("started_at", ""))
job_completed_at = str(job.get("completed_at", ""))
job_started_at_dt = parse_iso8601_utc(job_started_at, "started_at")
job_completed_at_dt = parse_iso8601_utc(job_completed_at, "completed_at")
if job_completed_at_dt < job_started_at_dt:
    print(
        "Promotion gate job completed_at precedes started_at: {0} < {1}".format(
            job_completed_at, job_started_at
        ),
        file=sys.stderr,
    )
    sys.exit(1)

job_head_sha = job.get("head_sha")
if expected_head_sha:
    if not isinstance(job_head_sha, str) or not job_head_sha:
        print("Promotion gate job head_sha is missing while run head_sha is present.", file=sys.stderr)
        sys.exit(1)
    if not re.fullmatch(r"[0-9a-f]{40}", job_head_sha):
        print("Promotion gate job head_sha is not a canonical 40-char lowercase hex digest.", file=sys.stderr)
        sys.exit(1)
    if job_head_sha != expected_head_sha:
        print(
            "Promotion gate job head_sha mismatch with run head_sha: expected {0}, got {1}".format(
                expected_head_sha, job_head_sha
            ),
            file=sys.stderr,
        )
        sys.exit(1)

job_head_branch = job.get("head_branch")
if expected_head_branch:
    if not isinstance(job_head_branch, str) or not job_head_branch.strip():
        print("Promotion gate job head_branch is missing while run head_branch is present.", file=sys.stderr)
        sys.exit(1)
    if job_head_branch != job_head_branch.strip():
        print("Promotion gate job head_branch must not contain leading or trailing whitespace.", file=sys.stderr)
        sys.exit(1)
    if job_head_branch != expected_head_branch:
        print(
            "Promotion gate job head_branch mismatch with run head_branch: expected {0}, got {1}".format(
                expected_head_branch, job_head_branch
            ),
            file=sys.stderr,
        )
        sys.exit(1)

runner_name = job.get("runner_name")
if not isinstance(runner_name, str) or not runner_name.strip():
    print("Promotion gate job runner_name is missing.", file=sys.stderr)
    sys.exit(1)
if runner_name != runner_name.strip():
    print("Promotion gate job runner_name must not contain leading or trailing whitespace.", file=sys.stderr)
    sys.exit(1)

runner_group_name = job.get("runner_group_name")
if not isinstance(runner_group_name, str) or not runner_group_name.strip():
    print("Promotion gate job runner_group_name is missing.", file=sys.stderr)
    sys.exit(1)
if runner_group_name != runner_group_name.strip():
    print("Promotion gate job runner_group_name must not contain leading or trailing whitespace.", file=sys.stderr)
    sys.exit(1)

labels = job.get("labels")
if not isinstance(labels, list):
    print("Promotion gate job labels payload is invalid.", file=sys.stderr)
    sys.exit(1)
normalized_labels = []
for index, label in enumerate(labels):
    if not isinstance(label, str) or not label.strip():
        print("Promotion gate job label row {0} is invalid.".format(index), file=sys.stderr)
        sys.exit(1)
    if label != label.strip():
        print("Promotion gate job label row {0} must not contain leading or trailing whitespace.".format(index), file=sys.stderr)
        sys.exit(1)
    normalized_labels.append(label)
if "self-hosted" in normalized_labels and "github-hosted" in normalized_labels:
    print("Promotion gate job labels must not mix self-hosted and github-hosted markers.", file=sys.stderr)
    sys.exit(1)

job_workflow_name = job.get("workflow_name")
if expected_workflow_name:
    if not isinstance(job_workflow_name, str) or not job_workflow_name:
        print("Promotion gate job workflow_name is missing while run workflow_name is present.", file=sys.stderr)
        sys.exit(1)
    if job_workflow_name != job_workflow_name.strip():
        print("Promotion gate job workflow_name must not contain leading or trailing whitespace.", file=sys.stderr)
        sys.exit(1)
    if expected_workflow_name != expected_workflow_name.strip():
        print("Resolved run workflow_name must not contain leading or trailing whitespace.", file=sys.stderr)
        sys.exit(1)
    if job_workflow_name != expected_workflow_name:
        print(
            "Promotion gate job workflow_name mismatch with run workflow_name: expected {0}, got {1}".format(
                expected_workflow_name, job_workflow_name
            ),
            file=sys.stderr,
        )
        sys.exit(1)

step_rows = job.get("steps")
if not isinstance(step_rows, list):
    print("Promotion gate job steps payload is invalid.", file=sys.stderr)
    sys.exit(1)
step_map = {}
for index, row in enumerate(step_rows):
    if not isinstance(row, dict):
        print("Promotion gate step row {0} is invalid.".format(index), file=sys.stderr)
        sys.exit(1)
    step_name = row.get("name")
    if not isinstance(step_name, str) or not step_name.strip():
        print("Promotion gate step row {0} is missing name.".format(index), file=sys.stderr)
        sys.exit(1)
    if step_name in step_map:
        print("Promotion gate contains duplicate step name: {0}".format(step_name), file=sys.stderr)
        sys.exit(1)
    step_map[step_name] = row

required_success_steps = [
    "Checkout",
    "Setup Python",
    "Install Mainline Dependencies",
    "Resolve Promotion Inputs",
    "Require Protected Ref Context",
    "Initialize Rotation Rehearsal Report",
    "Build Mainline Release Fixture",
    "Generate Signed Release Approval",
    "Enforce Mandatory Release Approval Gate",
    "Run Promotion Dry Run Gate",
    "Verify Promotion Artifacts",
    "Bundle Promotion Artifacts",
    "Upload Promotion Artifacts",
]
for step_name in required_success_steps:
    step_row = step_map.get(step_name)
    if step_row is None:
        print("Missing required promotion gate step: {0}".format(step_name), file=sys.stderr)
        sys.exit(1)
    step_conclusion = step_row.get("conclusion")
    if step_conclusion != "success":
        print(
            "Promotion gate step {0} must conclude with success; got {1}".format(
                step_name, step_conclusion
            ),
            file=sys.stderr,
        )
        sys.exit(1)

rotation_step_name = "Rehearse Approval Key Rotation (old key must fail)"
rotation_step_row = step_map.get(rotation_step_name)
rotation_step_conclusion = ""
if rotation_step_row is not None:
    raw_rotation_step_conclusion = rotation_step_row.get("conclusion")
    if isinstance(raw_rotation_step_conclusion, str):
        rotation_step_conclusion = raw_rotation_step_conclusion

if rotation_rehearsal == "true":
    if rotation_step_row is None:
        print(
            "Missing required promotion gate step when rotation rehearsal is enabled: {0}".format(
                rotation_step_name
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    if rotation_step_conclusion != "success":
        print(
            "rotation rehearsal step must conclude with success when required; got {0}".format(
                rotation_step_conclusion
            ),
            file=sys.stderr,
        )
        sys.exit(1)
else:
    if rotation_step_row is not None and rotation_step_conclusion != "skipped":
        print(
            "rotation rehearsal step must conclude with skipped when rehearsal is not required; got {0}".format(
                rotation_step_conclusion
            ),
            file=sys.stderr,
        )
        sys.exit(1)

actor_parity_checked = False
if run_actor_login:
    actor = job.get("actor")
    if actor is not None:
        if not isinstance(actor, dict):
            print("Promotion gate job actor payload is invalid when provided.", file=sys.stderr)
            sys.exit(1)
        actor_login = actor.get("login")
        if not isinstance(actor_login, str) or not actor_login:
            print("Promotion gate job actor.login is missing when actor payload is provided.", file=sys.stderr)
            sys.exit(1)
        if actor_login != actor_login.strip():
            print("Promotion gate job actor.login must not contain leading or trailing whitespace.", file=sys.stderr)
            sys.exit(1)
        if actor_login != run_actor_login:
            print(
                "Promotion gate job actor.login mismatch with run actor: expected {0}, got {1}".format(
                    run_actor_login, actor_login
                ),
                file=sys.stderr,
            )
            sys.exit(1)
        actor_parity_checked = True

triggering_actor_parity_checked = False
if run_triggering_actor_login:
    triggering_actor = job.get("triggering_actor")
    if triggering_actor is not None:
        if not isinstance(triggering_actor, dict):
            print("Promotion gate job triggering_actor payload is invalid when provided.", file=sys.stderr)
            sys.exit(1)
        triggering_actor_login = triggering_actor.get("login")
        if not isinstance(triggering_actor_login, str) or not triggering_actor_login:
            print("Promotion gate job triggering_actor.login is missing when triggering_actor payload is provided.", file=sys.stderr)
            sys.exit(1)
        if triggering_actor_login != triggering_actor_login.strip():
            print("Promotion gate job triggering_actor.login must not contain leading or trailing whitespace.", file=sys.stderr)
            sys.exit(1)
        if triggering_actor_login != run_triggering_actor_login:
            print(
                "Promotion gate job triggering_actor.login mismatch with run triggering_actor: expected {0}, got {1}".format(
                    run_triggering_actor_login, triggering_actor_login
                ),
                file=sys.stderr,
            )
            sys.exit(1)
        triggering_actor_parity_checked = True

print(str(job.get("id", "")))
print(job_html_url)
print(job_html_url_parts.netloc)
print(job_html_url_parts.path)
print(job_html_url_attempt)
print(str(job_status or ""))
print(str(job_conclusion or ""))
print(job_started_at)
print(job_completed_at)
print(str(len(required_success_steps)))
print(rotation_step_conclusion)
print(rotation_step_name)
print(runner_name)
print(runner_group_name)
print("|".join(normalized_labels))
print(job_workflow_name or "")
print(run_actor_login)
print(run_triggering_actor_login)
print("true" if actor_parity_checked else "false")
print("true" if triggering_actor_parity_checked else "false")
PY
)"
promotion_job_id="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '1p')"
promotion_job_html_url="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '2p')"
promotion_job_html_url_host_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '3p')"
promotion_job_html_url_path_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '4p')"
promotion_job_html_url_attempt_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '5p')"
promotion_job_status_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '6p')"
promotion_job_conclusion_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '7p')"
promotion_job_started_at="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '8p')"
promotion_job_completed_at="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '9p')"
promotion_required_step_count_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '10p')"
promotion_rotation_step_conclusion_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '11p')"
promotion_rotation_step_name="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '12p')"
promotion_runner_name_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '13p')"
promotion_runner_group_name_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '14p')"
promotion_runner_labels_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '15p')"
promotion_workflow_name_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '16p')"
promotion_actor_login_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '17p')"
promotion_triggering_actor_login_verified="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '18p')"
promotion_actor_parity_checked="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '19p')"
promotion_triggering_actor_parity_checked="$(printf '%s\n' "$promotion_job_verification_parsed" | sed -n '20p')"

dispatch_run_id_verified=""
if [[ "$run_id_resolution_mode" == "dispatch-api" ]]; then
  dispatch_run_id_verified="$run_id"
fi
dispatch_workflow_id_verified=""
if [[ "$run_id_resolution_mode" == "dispatch-api" ]]; then
  dispatch_workflow_id_verified="$dispatch_workflow_id_api"
fi

artifact_name="soenc-promotion-${run_id}-attempt-${run_attempt}"
artifact_metadata_deadline_epoch="$(( $(date -u +%s) + ARTIFACT_INDEX_WAIT_SECONDS ))"
artifact_metadata_parsed=""
while :; do
artifact_metadata_json="$(gh api "repos/${REPO}/actions/runs/${run_id}/artifacts?per_page=100&name=${artifact_name}")"
artifact_metadata_json_path="${OUTPUT_ROOT}/run-${run_id}-attempt-${run_attempt}/artifact_metadata.json"
mkdir -p "$(dirname "$artifact_metadata_json_path")"
printf '%s\n' "$artifact_metadata_json" > "$artifact_metadata_json_path"
set +e
  artifact_metadata_parsed="$(python - "$artifact_name" "$run_id" "$REPO" "$artifact_metadata_json_path" <<'PY' 2>&1
import json
import re
import sys
from urllib.parse import urlsplit
from pathlib import Path

artifact_name = sys.argv[1]
expected_run_id = sys.argv[2]
expected_repo = sys.argv[3]
payload_path = Path(sys.argv[4])
payload = json.loads(payload_path.read_text(encoding="utf-8"))
artifact_rows = payload.get("artifacts")
if not isinstance(artifact_rows, list):
    print("Artifact list payload is invalid for run metadata verification.", file=sys.stderr)
    sys.exit(1)
matches = [row for row in artifact_rows if isinstance(row, dict) and row.get("name") == artifact_name]
if len(matches) != 1:
    print(
        "Expected exactly one artifact named {0}; found {1}.".format(artifact_name, len(matches)),
        file=sys.stderr,
    )
    sys.exit(1)
artifact = matches[0]
if artifact.get("expired") is True:
    print("Artifact {0} is expired.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
workflow_run = artifact.get("workflow_run")
if not isinstance(workflow_run, dict):
    print("Artifact {0} missing workflow_run metadata.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
workflow_run_id = workflow_run.get("id")
workflow_run_id_text = str(workflow_run_id) if workflow_run_id is not None else ""
if not workflow_run_id_text.isdigit() or workflow_run_id_text != expected_run_id:
    print(
        "Artifact workflow_run.id mismatch for {0}: expected {1}, got {2}".format(
            artifact_name, expected_run_id, workflow_run_id_text or "<missing>"
        ),
        file=sys.stderr,
    )
    sys.exit(1)
artifact_id = artifact.get("id")
artifact_id_text = str(artifact_id) if artifact_id is not None else ""
if not artifact_id_text.isdigit():
    print("Artifact {0} missing numeric id.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
size_in_bytes = artifact.get("size_in_bytes")
size_in_bytes_text = str(size_in_bytes) if size_in_bytes is not None else ""
if not size_in_bytes_text.isdigit():
    print("Artifact {0} missing numeric size_in_bytes.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
digest = artifact.get("digest")
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    print("Artifact {0} has invalid digest metadata.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
archive_download_url = artifact.get("archive_download_url")
if not isinstance(archive_download_url, str) or not archive_download_url:
    print("Artifact {0} missing archive_download_url.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
if archive_download_url != archive_download_url.strip():
    print("Artifact {0} archive_download_url must not contain leading or trailing whitespace.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
archive_parts = urlsplit(archive_download_url)
if archive_parts.scheme != "https":
    print("Artifact {0} archive_download_url must use https scheme.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
if not archive_parts.netloc:
    print("Artifact {0} archive_download_url host is missing.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
if archive_parts.query or archive_parts.fragment:
    print("Artifact {0} archive_download_url must not include query or fragment components.".format(artifact_name), file=sys.stderr)
    sys.exit(1)
expected_archive_paths = {
    "/repos/{0}/actions/artifacts/{1}/zip".format(expected_repo, artifact_id_text),
    "/api/v3/repos/{0}/actions/artifacts/{1}/zip".format(expected_repo, artifact_id_text),
}
normalized_archive_path = archive_parts.path.rstrip("/") or "/"
if normalized_archive_path not in expected_archive_paths:
    print(
        "Artifact {0} archive_download_url path mismatch: expected {1}, got {2}".format(
            artifact_name,
            " or ".join(sorted(expected_archive_paths)),
            archive_parts.path,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
print(artifact_id_text)
print(digest)
print(size_in_bytes_text)
print(artifact.get("created_at", ""))
print(artifact.get("updated_at", ""))
print(artifact.get("expires_at", ""))
print(archive_download_url)
print(workflow_run_id_text)
print(workflow_run.get("head_branch", ""))
print(workflow_run.get("head_sha", ""))
print(archive_parts.netloc)
PY
)"
artifact_metadata_status=$?
set -e
if [[ "$artifact_metadata_status" -eq 0 ]]; then
  break
fi
if [[ "$artifact_metadata_parsed" == *"Expected exactly one artifact named ${artifact_name}; found 0."* ]]; then
  now_epoch="$(date -u +%s)"
  if [[ "$now_epoch" -ge "$artifact_metadata_deadline_epoch" ]]; then
    printf '%s\n' "$artifact_metadata_parsed" >&2
    echo "Timed out waiting for artifact metadata indexing for ${artifact_name}." >&2
    echo "run_url=${run_url}" >&2
    exit 1
  fi
  echo "Artifact metadata not yet indexed for ${artifact_name}; retrying in ${POLL_INTERVAL_SECONDS}s..."
  sleep "$POLL_INTERVAL_SECONDS"
  continue
fi
printf '%s\n' "$artifact_metadata_parsed" >&2
exit 1
done
artifact_id="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '1p')"
artifact_digest="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '2p')"
artifact_size_bytes="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '3p')"
artifact_created_at="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '4p')"
artifact_updated_at="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '5p')"
artifact_expires_at="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '6p')"
artifact_archive_download_url="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '7p')"
artifact_workflow_run_id="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '8p')"
artifact_workflow_head_branch="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '9p')"
artifact_workflow_head_sha="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '10p')"
artifact_archive_download_url_host="$(printf '%s\n' "$artifact_metadata_parsed" | sed -n '11p')"

artifact_timestamp_verification="$(python - "$artifact_name" "$run_id" "$run_url" "$artifact_created_at" "$artifact_updated_at" "$artifact_expires_at" <<'PY'
import sys
from datetime import datetime

artifact_name = sys.argv[1]
run_id = sys.argv[2]
run_url = sys.argv[3]
artifact_created_at = sys.argv[4]
artifact_updated_at = sys.argv[5]
artifact_expires_at = sys.argv[6]

def parse_required_iso8601_utc(label: str, value: str) -> datetime:
    if not isinstance(value, str) or not value:
        print("{0} is missing for artifact {1} (run_id={2})".format(label, artifact_name, run_id), file=sys.stderr)
        print("run_url={0}".format(run_url), file=sys.stderr)
        sys.exit(1)
    if value != value.strip():
        print(
            "{0} must not contain leading or trailing whitespace for artifact {1} (run_id={2})".format(
                label,
                artifact_name,
                run_id,
            ),
            file=sys.stderr,
        )
        print("run_url={0}".format(run_url), file=sys.stderr)
        sys.exit(1)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        print(
            "{0} is not valid ISO-8601 for artifact {1} (run_id={2}): {3}".format(
                label,
                artifact_name,
                run_id,
                value,
            ),
            file=sys.stderr,
        )
        print("run_url={0}".format(run_url), file=sys.stderr)
        sys.exit(1)

created_at_dt = parse_required_iso8601_utc("artifact created_at", artifact_created_at)
updated_at_dt = parse_required_iso8601_utc("artifact updated_at", artifact_updated_at)
expires_at_dt = parse_required_iso8601_utc("artifact expires_at", artifact_expires_at)
if updated_at_dt < created_at_dt:
    print(
        "artifact updated_at precedes created_at for {0} (run_id={1}): {2} < {3}".format(
            artifact_name,
            run_id,
            artifact_updated_at,
            artifact_created_at,
        ),
        file=sys.stderr,
    )
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)
if expires_at_dt < updated_at_dt:
    print(
        "artifact expires_at precedes updated_at for {0} (run_id={1}): {2} < {3}".format(
            artifact_name,
            run_id,
            artifact_expires_at,
            artifact_updated_at,
        ),
        file=sys.stderr,
    )
    print("run_url={0}".format(run_url), file=sys.stderr)
    sys.exit(1)

print(artifact_created_at)
print(artifact_updated_at)
print(artifact_expires_at)
PY
)"
artifact_created_at_verified="$(printf '%s\n' "$artifact_timestamp_verification" | sed -n '1p')"
artifact_updated_at_verified="$(printf '%s\n' "$artifact_timestamp_verification" | sed -n '2p')"
artifact_expires_at_verified="$(printf '%s\n' "$artifact_timestamp_verification" | sed -n '3p')"

if [[ -n "$run_head_branch_api" && -n "$artifact_workflow_head_branch" && "$run_head_branch_api" != "$artifact_workflow_head_branch" ]]; then
  echo "artifact workflow_head_branch mismatch for run_id=${run_id}: expected ${run_head_branch_api}, got ${artifact_workflow_head_branch}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -n "$run_head_sha_api" && -n "$artifact_workflow_head_sha" && "$run_head_sha_api" != "$artifact_workflow_head_sha" ]]; then
  echo "artifact workflow_head_sha mismatch for run_id=${run_id}: expected ${run_head_sha_api}, got ${artifact_workflow_head_sha}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi
expected_artifact_api_host="$(expected_api_host_for_run_host "$run_url_host_verified")"
if [[ -n "$expected_artifact_api_host" && -n "$artifact_archive_download_url_host" && "${expected_artifact_api_host,,}" != "${artifact_archive_download_url_host,,}" ]]; then
  echo "artifact archive_download_url host mismatch for run_id=${run_id}: expected API host ${expected_artifact_api_host}, got ${artifact_archive_download_url_host}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

run_dir="${OUTPUT_ROOT}/run-${run_id}-attempt-${run_attempt}"
download_dir="${run_dir}/download"
artifact_zip_path="${run_dir}/${artifact_name}.zip"
mkdir -p "$download_dir"

echo "Downloading artifact archive ${artifact_name}"
gh api "repos/${REPO}/actions/artifacts/${artifact_id}/zip" --method GET > "$artifact_zip_path"

echo "Verifying artifact archive digest and extracting ${artifact_name}"
artifact_archive_verification="$(python - "$artifact_zip_path" "$artifact_digest" "$artifact_size_bytes" "$download_dir" <<'PY'
import hashlib
import stat
import sys
import zipfile
from pathlib import Path

archive_path = Path(sys.argv[1]).resolve()
expected_digest = sys.argv[2]
expected_size_text = sys.argv[3]
extract_dir = Path(sys.argv[4]).resolve()

if not archive_path.exists():
    print("Downloaded artifact archive does not exist: {0}".format(archive_path), file=sys.stderr)
    sys.exit(1)
if not expected_size_text.isdigit():
    print("Artifact metadata size is non-numeric: {0}".format(expected_size_text), file=sys.stderr)
    sys.exit(1)

size_bytes = 0
digest = hashlib.sha256()
with archive_path.open("rb") as handle:
    while True:
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        size_bytes += len(chunk)
        digest.update(chunk)

actual_digest = "sha256:{0}".format(digest.hexdigest())
if actual_digest != expected_digest:
    print(
        "Artifact archive digest mismatch for {0}: expected {1}, got {2}".format(
            archive_path.name, expected_digest, actual_digest
        ),
        file=sys.stderr,
    )
    sys.exit(1)

expected_size = int(expected_size_text)
if size_bytes != expected_size:
    print(
        "Artifact archive size mismatch for {0}: expected {1}, got {2}".format(
            archive_path.name, expected_size, size_bytes
        ),
        file=sys.stderr,
    )
    sys.exit(1)

extract_dir.mkdir(parents=True, exist_ok=True)

def _is_safe_archive_member_path(root: Path, member_name: str) -> bool:
    if not member_name or "\x00" in member_name:
        return False
    normalized_name = member_name.replace("\\", "/")
    if normalized_name.startswith("/"):
        return False
    if len(normalized_name) >= 2 and normalized_name[1] == ":":
        return False
    segments = normalized_name.split("/")
    for segment in segments:
        if segment in ("", "."):
            continue
        if segment == "..":
            return False
    candidate = (root / normalized_name).resolve()
    return candidate == root or root in candidate.parents

def _is_zipinfo_symlink(entry: zipfile.ZipInfo) -> bool:
    mode = (entry.external_attr >> 16) & 0o170000
    return mode == stat.S_IFLNK

extracted_entries = 0
with zipfile.ZipFile(archive_path, "r") as archive:
    for entry in archive.infolist():
        if not _is_safe_archive_member_path(extract_dir, entry.filename):
            print(
                "Artifact archive member path traversal detected: {0}".format(entry.filename),
                file=sys.stderr,
            )
            sys.exit(1)
        if _is_zipinfo_symlink(entry):
            print(
                "Artifact archive contains symlink entry: {0}".format(entry.filename),
                file=sys.stderr,
            )
            sys.exit(1)
    archive.extractall(extract_dir)
    extracted_entries = len(archive.infolist())

print(actual_digest)
print(size_bytes)
print(extracted_entries)
PY
)"
artifact_archive_digest_verified="$(printf '%s\n' "$artifact_archive_verification" | sed -n '1p')"
artifact_archive_size_bytes="$(printf '%s\n' "$artifact_archive_verification" | sed -n '2p')"
artifact_archive_entry_count="$(printf '%s\n' "$artifact_archive_verification" | sed -n '3p')"

receipt_path="${run_dir}/promotion_capture_receipt.json"
python - \
  "$download_dir" \
  "$receipt_path" \
  "$REPO" \
  "$REF" \
  "$WORKFLOW_FILE" \
  "$run_id" \
  "$run_attempt" \
  "$run_url" \
  "$artifact_name" \
  "$ROTATION_REHEARSAL" \
  "$dispatch_utc" \
  "$dispatch_run_id_verified" \
  "$dispatch_workflow_id_verified" \
  "$dispatch_run_url_api" \
  "$dispatch_run_html_url" \
  "$dispatch_run_url_host_verified" \
  "$dispatch_html_url_host_verified" \
  "$dispatch_run_url_attempt_verified" \
  "$dispatch_html_url_attempt_verified" \
  "$capture_mode" \
  "$run_id_resolution_mode" \
  "$run_event_api" \
  "$run_head_branch_api" \
  "$run_workflow_path" \
  "$run_workflow_path_ref_identity" \
  "$run_html_url_api" \
  "$run_url_host_verified" \
  "$run_url_attempt_verified" \
  "$run_html_url_host_verified" \
  "$run_html_url_attempt_verified" \
  "$run_created_at_summary_verified" \
  "$run_started_at_summary_verified" \
  "$run_updated_at_summary_verified" \
  "$run_created_at_detail_verified" \
  "$run_started_at_detail_verified" \
  "$run_updated_at_detail_verified" \
  "$WORKFLOW_JOB_ID" \
  "$run_head_sha_api" \
  "$run_workflow_id_api" \
  "$run_number_api" \
  "$run_retention_days_api" \
  "$run_repository_id_api" \
  "$run_repository_owner_id_api" \
  "$run_actor_id_api" \
  "$artifact_id" \
  "$artifact_digest" \
  "$artifact_size_bytes" \
  "$artifact_created_at_verified" \
  "$artifact_updated_at_verified" \
  "$artifact_expires_at_verified" \
  "$artifact_archive_download_url" \
  "$artifact_archive_download_url_host" \
  "$artifact_workflow_run_id" \
  "$artifact_workflow_head_branch" \
  "$artifact_workflow_head_sha" \
  "$artifact_zip_path" \
  "$artifact_archive_digest_verified" \
  "$artifact_archive_size_bytes" \
  "$artifact_archive_entry_count" \
  "$promotion_job_id" \
  "$promotion_job_html_url" \
  "$promotion_job_html_url_host_verified" \
  "$promotion_job_html_url_path_verified" \
  "$promotion_job_html_url_attempt_verified" \
  "$promotion_job_status_verified" \
  "$promotion_job_conclusion_verified" \
  "$promotion_job_started_at" \
  "$promotion_job_completed_at" \
  "$promotion_required_step_count_verified" \
  "$promotion_rotation_step_name" \
  "$promotion_rotation_step_conclusion_verified" \
  "$promotion_runner_name_verified" \
  "$promotion_runner_group_name_verified" \
  "$promotion_runner_labels_verified" \
  "$promotion_workflow_name_verified" \
  "$promotion_actor_login_verified" \
  "$promotion_triggering_actor_login_verified" \
  "$promotion_actor_parity_checked" \
  "$promotion_triggering_actor_parity_checked" \
  "$resolved_workflow_definition_id" \
  "$resolved_workflow_definition_path" \
  "$resolved_workflow_definition_state" \
  "$resolved_workflow_definition_name" \
  "$branch_protection_preflight_json" \
  "$environment_preflight_json" \
  "$required_secret_preflight_jsonl" <<'PY'
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime
from datetime import timezone
from pathlib import Path

(
    download_root_arg,
    receipt_path_arg,
    repo,
    ref,
    workflow_file,
    run_id,
    run_attempt,
    run_url,
    artifact_name,
    rotation_rehearsal,
    dispatch_utc,
    dispatch_run_id,
    dispatch_workflow_id,
    dispatch_run_url,
    dispatch_run_html_url,
    dispatch_run_url_host,
    dispatch_run_html_url_host,
    dispatch_run_url_attempt,
    dispatch_run_html_url_attempt,
    capture_mode,
    run_id_resolution_mode,
    workflow_event,
    workflow_head_branch,
    workflow_path,
    workflow_path_ref,
    workflow_html_url,
    workflow_run_url_host,
    workflow_run_url_attempt,
    workflow_run_html_url_host,
    workflow_run_html_url_attempt,
    workflow_created_at,
    workflow_started_at,
    workflow_updated_at,
    workflow_created_at_detail,
    workflow_started_at_detail,
    workflow_updated_at_detail,
    workflow_job_id,
    workflow_head_sha,
    workflow_run_workflow_id,
    workflow_run_number,
    workflow_retention_days,
    workflow_repository_id,
    workflow_repository_owner_id,
    workflow_actor_id,
    artifact_id,
    artifact_digest,
    artifact_size_in_bytes,
    artifact_created_at,
    artifact_updated_at,
    artifact_expires_at,
    artifact_archive_download_url,
    artifact_archive_download_url_host,
    artifact_workflow_run_id,
    artifact_workflow_head_branch,
    artifact_workflow_head_sha,
    artifact_archive_path,
    artifact_archive_digest_verified,
    artifact_archive_size_bytes,
    artifact_archive_entry_count,
    promotion_job_id,
    promotion_job_html_url,
    promotion_job_html_url_host_verified,
    promotion_job_html_url_path_verified,
    promotion_job_html_url_attempt_verified,
    promotion_job_status_verified,
    promotion_job_conclusion_verified,
    promotion_job_started_at,
    promotion_job_completed_at,
    promotion_required_step_count_verified,
    promotion_rotation_step_name,
    promotion_rotation_step_conclusion_verified,
    promotion_runner_name_verified,
    promotion_runner_group_name_verified,
    promotion_runner_labels_verified,
    promotion_workflow_name_verified,
    promotion_actor_login_verified,
    promotion_triggering_actor_login_verified,
    promotion_actor_parity_checked,
    promotion_triggering_actor_parity_checked,
    workflow_definition_id,
    workflow_definition_path,
    workflow_definition_state,
    workflow_definition_name,
    branch_protection_preflight_json,
    environment_preflight_json,
    required_secret_preflight_jsonl,
) = sys.argv[1:]

download_root = Path(download_root_arg).resolve()
receipt_path = Path(receipt_path_arg).resolve()

required_files = [
    "release_bundle.json",
    "release_approval.json",
    "release_receipt.json",
    "promotion_evidence.json",
    "promotion_audit_report.json",
    "rotation_rehearsal_report.json",
    "promotion_artifact_audit_report.json",
    "promotion_run_receipt.json",
    "promotion_artifact_bundle.zip",
    "non_ocr_release_gate_report.json",
]

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

missing = []
duplicate = []
resolved = {}
for name in required_files:
    matches = sorted(download_root.rglob(name))
    if not matches:
        missing.append(name)
        continue
    if len(matches) > 1:
        duplicate.append(name)
    resolved[name] = matches[0].resolve()

if missing or duplicate:
    if missing:
        print("Missing required files: {0}".format(", ".join(missing)), file=sys.stderr)
    if duplicate:
        print("Duplicate required files detected: {0}".format(", ".join(duplicate)), file=sys.stderr)
    sys.exit(1)

generated_at_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def load_preflight_object(label: str, text: str):
    try:
        payload = json.loads(text)
    except Exception as exc:
        print("{0} preflight payload is not valid JSON: {1}".format(label, exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(payload, dict):
        print("{0} preflight payload must be a JSON object".format(label), file=sys.stderr)
        sys.exit(1)
    return payload

branch_protection_preflight = load_preflight_object(
    "branch_protection",
    branch_protection_preflight_json,
)
environment_preflight = load_preflight_object(
    "environment",
    environment_preflight_json,
)
required_secret_preflight = [
    load_preflight_object("required_secret", line)
    for line in required_secret_preflight_jsonl.splitlines()
    if line.strip()
]

def parse_required_iso8601_utc(label: str, value: object):
    if not isinstance(value, str) or not value.strip():
        print("{0} is required".format(label), file=sys.stderr)
        sys.exit(1)
    if value != value.strip():
        print("{0} must not contain leading or trailing whitespace".format(label), file=sys.stderr)
        sys.exit(1)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        print("{0} is not valid ISO-8601: {1}".format(label, value), file=sys.stderr)
        sys.exit(1)
    return value, parsed

workflow_run_started_at_detail_utc, workflow_run_started_at_detail_dt = parse_required_iso8601_utc(
    "workflow_run_timestamp_verification.started_at_detail",
    workflow_started_at_detail,
)
workflow_run_updated_at_detail_utc, workflow_run_updated_at_detail_dt = parse_required_iso8601_utc(
    "workflow_run_timestamp_verification.updated_at_detail",
    workflow_updated_at_detail,
)
if workflow_run_updated_at_detail_dt < workflow_run_started_at_detail_dt:
    print(
        "workflow_run_timestamp_verification.updated_at_detail must be >= workflow_run_timestamp_verification.started_at_detail; got {0} < {1}".format(
            workflow_run_updated_at_detail_utc,
            workflow_run_started_at_detail_utc,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

def require_timestamp_within_workflow_run_window(label: str, value_utc: str, value_dt):
    if value_dt < workflow_run_started_at_detail_dt:
        print(
            "{0} must be >= workflow_run_timestamp_verification.started_at_detail; got {1} < {2}".format(
                label,
                value_utc,
                workflow_run_started_at_detail_utc,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    if value_dt > workflow_run_updated_at_detail_dt:
        print(
            "{0} must be <= workflow_run_timestamp_verification.updated_at_detail; got {1} > {2}".format(
                label,
                value_utc,
                workflow_run_updated_at_detail_utc,
            ),
            file=sys.stderr,
        )
        sys.exit(1)

artifact_created_at_utc, artifact_created_at_dt = parse_required_iso8601_utc(
    "artifact_metadata.created_at",
    artifact_created_at,
)
artifact_updated_at_utc, artifact_updated_at_dt = parse_required_iso8601_utc(
    "artifact_metadata.updated_at",
    artifact_updated_at,
)
if artifact_updated_at_dt < artifact_created_at_dt:
    print(
        "artifact_metadata.updated_at must be >= artifact_metadata.created_at; got {0} < {1}".format(
            artifact_updated_at_utc,
            artifact_created_at_utc,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
require_timestamp_within_workflow_run_window(
    "artifact_metadata.created_at",
    artifact_created_at_utc,
    artifact_created_at_dt,
)
require_timestamp_within_workflow_run_window(
    "artifact_metadata.updated_at",
    artifact_updated_at_utc,
    artifact_updated_at_dt,
)

def parse_required_positive_integer(label: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        print("{0} is required".format(label), file=sys.stderr)
        sys.exit(1)
    if value != value.strip():
        print("{0} must not contain leading or trailing whitespace".format(label), file=sys.stderr)
        sys.exit(1)
    if not value.isdigit() or int(value) <= 0:
        print("{0} must be a positive integer".format(label), file=sys.stderr)
        sys.exit(1)
    return value

artifact_workflow_run_id_text = parse_required_positive_integer(
    "artifact_metadata.workflow_run_id",
    artifact_workflow_run_id,
)
if artifact_workflow_run_id_text != run_id:
    print(
        "artifact_metadata.workflow_run_id mismatch with workflow_run_id: expected {0}, got {1}".format(
            run_id,
            artifact_workflow_run_id_text,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

artifact_size_in_bytes_text = parse_required_positive_integer(
    "artifact_metadata.size_in_bytes",
    artifact_size_in_bytes,
)
artifact_archive_size_bytes_text = parse_required_positive_integer(
    "artifact_archive_verification.size_in_bytes_verified",
    artifact_archive_size_bytes,
)
if artifact_archive_size_bytes_text != artifact_size_in_bytes_text:
    print(
        "artifact_archive_verification.size_in_bytes_verified mismatch with artifact_metadata.size_in_bytes: expected {0}, got {1}".format(
            artifact_size_in_bytes_text,
            artifact_archive_size_bytes_text,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

if not isinstance(artifact_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_digest):
    print("artifact_metadata.digest must be a canonical sha256:<64-char lowercase hex> value", file=sys.stderr)
    sys.exit(1)
if not isinstance(artifact_archive_digest_verified, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_archive_digest_verified):
    print(
        "artifact_archive_verification.digest_verified must be a canonical sha256:<64-char lowercase hex> value",
        file=sys.stderr,
    )
    sys.exit(1)
if artifact_archive_digest_verified != artifact_digest:
    print(
        "artifact_archive_verification.digest_verified mismatch with artifact_metadata.digest: expected {0}, got {1}".format(
            artifact_digest,
            artifact_archive_digest_verified,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

parse_required_positive_integer(
    "artifact_archive_verification.entry_count_verified",
    artifact_archive_entry_count,
)

if not isinstance(artifact_archive_download_url_host, str) or not artifact_archive_download_url_host.strip():
    print("artifact_metadata.archive_download_url_host is required", file=sys.stderr)
    sys.exit(1)
if artifact_archive_download_url_host != artifact_archive_download_url_host.strip():
    print("artifact_metadata.archive_download_url_host must not contain leading or trailing whitespace", file=sys.stderr)
    sys.exit(1)

def expected_artifact_api_host_for_run_host(host: str) -> str:
    normalized = (host or "").strip().lower()
    if not normalized:
        return ""
    if normalized == "github.com":
        return "api.github.com"
    return normalized

expected_artifact_api_host = expected_artifact_api_host_for_run_host(workflow_run_url_host)
if expected_artifact_api_host and artifact_archive_download_url_host.lower() != expected_artifact_api_host:
    print(
        "artifact_metadata.archive_download_url_host mismatch with expected API host: expected {0}, got {1}".format(
            expected_artifact_api_host,
            artifact_archive_download_url_host,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

if artifact_workflow_head_branch:
    if artifact_workflow_head_branch != artifact_workflow_head_branch.strip():
        print("artifact_metadata.workflow_head_branch must not contain leading or trailing whitespace", file=sys.stderr)
        sys.exit(1)
    if workflow_head_branch and artifact_workflow_head_branch != workflow_head_branch:
        print(
            "artifact_metadata.workflow_head_branch mismatch with workflow_head_branch: expected {0}, got {1}".format(
                workflow_head_branch,
                artifact_workflow_head_branch,
            ),
            file=sys.stderr,
        )
        sys.exit(1)

if artifact_workflow_head_sha:
    if artifact_workflow_head_sha != artifact_workflow_head_sha.strip():
        print("artifact_metadata.workflow_head_sha must not contain leading or trailing whitespace", file=sys.stderr)
        sys.exit(1)
    if not re.fullmatch(r"[0-9a-f]{40}", artifact_workflow_head_sha):
        print("artifact_metadata.workflow_head_sha must be a 40-char lowercase hex digest", file=sys.stderr)
        sys.exit(1)
    if workflow_head_sha and artifact_workflow_head_sha != workflow_head_sha:
        print(
            "artifact_metadata.workflow_head_sha mismatch with workflow_head_sha: expected {0}, got {1}".format(
                workflow_head_sha,
                artifact_workflow_head_sha,
            ),
            file=sys.stderr,
        )
        sys.exit(1)

artifact_rows = []
for name in required_files:
    path = resolved[name]
    artifact_rows.append(
        {
            "name": name,
            "path": str(path),
            "sha256": sha256_file(path),
        }
    )

non_ocr_release_gate_report_path = resolved["non_ocr_release_gate_report.json"]
try:
    non_ocr_release_gate_report_payload = json.loads(
        non_ocr_release_gate_report_path.read_text(encoding="utf-8")
    )
except Exception as exc:
    print("non_ocr_release_gate_report.json is not valid JSON: {0}".format(exc), file=sys.stderr)
    sys.exit(1)

if not isinstance(non_ocr_release_gate_report_payload, dict):
    print("non_ocr_release_gate_report.json must be a JSON object", file=sys.stderr)
    sys.exit(1)
if non_ocr_release_gate_report_payload.get("schema") != "enc2sop-non-ocr-release-gate/v1":
    print(
        "non_ocr_release_gate_report schema mismatch: expected enc2sop-non-ocr-release-gate/v1, got {0}".format(
            non_ocr_release_gate_report_payload.get("schema")
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if non_ocr_release_gate_report_payload.get("passed") is not True:
    print("non_ocr_release_gate_report.passed must be true", file=sys.stderr)
    sys.exit(1)
non_ocr_release_gate_summary = non_ocr_release_gate_report_payload.get("summary")
if not isinstance(non_ocr_release_gate_summary, dict):
    print("non_ocr_release_gate_report.summary must be a JSON object", file=sys.stderr)
    sys.exit(1)
if non_ocr_release_gate_summary.get("total_failures") != 0:
    print("non_ocr_release_gate_report.summary.total_failures must be 0", file=sys.stderr)
    sys.exit(1)
if non_ocr_release_gate_report_payload.get("failures") not in ([], None):
    print("non_ocr_release_gate_report.failures must be empty", file=sys.stderr)
    sys.exit(1)

rotation_report_path = resolved["rotation_rehearsal_report.json"]
try:
    rotation_report_payload = json.loads(rotation_report_path.read_text(encoding="utf-8"))
except Exception as exc:
    print("rotation_rehearsal_report.json is not valid JSON: {0}".format(exc), file=sys.stderr)
    sys.exit(1)

if not isinstance(rotation_report_payload, dict):
    print("rotation_rehearsal_report must be a JSON object", file=sys.stderr)
    sys.exit(1)
if rotation_report_payload.get("schema") != "enc2sop-rotation-rehearsal/v1":
    print(
        "rotation_rehearsal_report schema mismatch: expected enc2sop-rotation-rehearsal/v1, got {0}".format(
            rotation_report_payload.get("schema")
        ),
        file=sys.stderr,
    )
    sys.exit(1)

rotation_requested = rotation_report_payload.get("requested")
rotation_executed = rotation_report_payload.get("executed")
rotation_old_key_rejected = rotation_report_payload.get("old_key_rejected")
rotation_status = rotation_report_payload.get("status")
if not isinstance(rotation_status, str) or not rotation_status.strip():
    print("rotation_rehearsal_report.status is required", file=sys.stderr)
    sys.exit(1)
if rotation_status != rotation_status.strip():
    print("rotation_rehearsal_report.status must not contain leading or trailing whitespace", file=sys.stderr)
    sys.exit(1)
rotation_details = rotation_report_payload.get("details")
if not isinstance(rotation_details, str) or not rotation_details.strip():
    print("rotation_rehearsal_report.details is required", file=sys.stderr)
    sys.exit(1)
if rotation_details != rotation_details.strip():
    print("rotation_rehearsal_report.details must not contain leading or trailing whitespace", file=sys.stderr)
    sys.exit(1)
rotation_report_generated_at_utc, rotation_report_generated_at_dt = parse_required_iso8601_utc(
    "rotation_rehearsal_report.generated_at_utc",
    rotation_report_payload.get("generated_at_utc"),
)
rotation_workflow_retention_days = parse_required_positive_integer(
    "rotation_rehearsal_report.workflow_retention_days",
    rotation_report_payload.get("workflow_retention_days"),
)
if not workflow_retention_days:
    workflow_retention_days = rotation_workflow_retention_days
require_timestamp_within_workflow_run_window(
    "rotation_rehearsal_report.generated_at_utc",
    rotation_report_generated_at_utc,
    rotation_report_generated_at_dt,
)
if not workflow_retention_days or not workflow_retention_days.isdigit():
    print("Resolved run retention_days is not numeric.", file=sys.stderr)
    sys.exit(1)
if int(workflow_retention_days) <= 0:
    print("Resolved run retention_days must be positive.", file=sys.stderr)
    sys.exit(1)
if rotation_workflow_retention_days != workflow_retention_days:
    print(
        "rotation_rehearsal_report.workflow_retention_days mismatch with run retention_days: expected {0}, got {1}".format(
            workflow_retention_days,
            rotation_workflow_retention_days,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

if rotation_rehearsal == "true":
    if rotation_requested is not True:
        print("rotation_rehearsal_report.requested must be true when rotation rehearsal is required", file=sys.stderr)
        sys.exit(1)
    if rotation_executed is not True:
        print("rotation_rehearsal_report.executed must be true when rotation rehearsal is required", file=sys.stderr)
        sys.exit(1)
    if rotation_old_key_rejected is not True:
        print("rotation_rehearsal_report.old_key_rejected must be true when rotation rehearsal is required", file=sys.stderr)
        sys.exit(1)
    if rotation_status != "passed":
        print(
            "rotation_rehearsal_report.status must be passed when rotation rehearsal is required; got {0}".format(
                rotation_status
            ),
            file=sys.stderr,
        )
        sys.exit(1)
else:
    if rotation_requested is not False:
        print("rotation_rehearsal_report.requested must be false when rotation rehearsal is not required", file=sys.stderr)
        sys.exit(1)
    if rotation_executed is not False:
        print("rotation_rehearsal_report.executed must be false when rotation rehearsal is not required", file=sys.stderr)
        sys.exit(1)
    if rotation_old_key_rejected is not None:
        print("rotation_rehearsal_report.old_key_rejected must be null when rotation rehearsal is not required", file=sys.stderr)
        sys.exit(1)
    if rotation_status != "not-requested":
        print(
            "rotation_rehearsal_report.status must be not-requested when rotation rehearsal is not required; got {0}".format(
                rotation_status
            ),
            file=sys.stderr,
        )
        sys.exit(1)

required_bundle_entries = {
    "release_bundle": ("release/release_bundle.json", "release_bundle.json"),
    "release_approval": ("release/release_approval.json", "release_approval.json"),
    "release_receipt": ("release/release_receipt.json", "release_receipt.json"),
    "promotion_evidence": ("ops/promotion_evidence.json", "promotion_evidence.json"),
    "promotion_audit_report": ("ops/promotion_audit_report.json", "promotion_audit_report.json"),
    "rotation_rehearsal_report": ("ops/rotation_rehearsal_report.json", "rotation_rehearsal_report.json"),
    "promotion_artifact_audit_report": ("ops/promotion_artifact_audit_report.json", "promotion_artifact_audit_report.json"),
    "promotion_run_receipt": ("ops/promotion_run_receipt.json", "promotion_run_receipt.json"),
}
required_bundle_entry_names = set(required_bundle_entries) | {"promotion_policy", "promotion_workflow"}

bundle_archive_path = resolved["promotion_artifact_bundle.zip"]
try:
    with zipfile.ZipFile(bundle_archive_path, "r") as bundle_archive:
        bundle_archive_member_paths = []
        bundle_archive_member_path_set = set()
        bundle_archive_member_sha256 = {}
        for entry in bundle_archive.infolist():
            normalized_entry_name = entry.filename.replace("\\", "/")
            if normalized_entry_name != entry.filename:
                print(
                    "promotion_artifact_bundle.zip member path must use forward slashes: {0}".format(entry.filename),
                    file=sys.stderr,
                )
                sys.exit(1)
            if not normalized_entry_name or normalized_entry_name.startswith("/"):
                print(
                    "promotion_artifact_bundle.zip member path is not relative: {0}".format(entry.filename),
                    file=sys.stderr,
                )
                sys.exit(1)
            if any(segment in ("", ".", "..") for segment in normalized_entry_name.split("/")):
                print(
                    "promotion_artifact_bundle.zip member path traversal detected: {0}".format(entry.filename),
                    file=sys.stderr,
                )
                sys.exit(1)
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                print(
                    "promotion_artifact_bundle.zip contains symlink entry: {0}".format(entry.filename),
                    file=sys.stderr,
                )
                sys.exit(1)
            if entry.is_dir():
                print(
                    "promotion_artifact_bundle.zip contains undeclared directory entry: {0}".format(entry.filename),
                    file=sys.stderr,
                )
                sys.exit(1)
            if normalized_entry_name in bundle_archive_member_path_set:
                print(
                    "promotion_artifact_bundle.zip contains duplicate member path: {0}".format(normalized_entry_name),
                    file=sys.stderr,
                )
                sys.exit(1)
            bundle_archive_member_path_set.add(normalized_entry_name)
            bundle_archive_member_paths.append(normalized_entry_name)
            bundle_archive_member_sha256[normalized_entry_name] = hashlib.sha256(
                bundle_archive.read(entry.filename)
            ).hexdigest()
        try:
            bundle_manifest_bytes = bundle_archive.read("bundle_manifest.json")
        except KeyError:
            print(
                "promotion_artifact_bundle.zip is missing bundle_manifest.json",
                file=sys.stderr,
            )
            sys.exit(1)
except zipfile.BadZipFile:
    print("promotion_artifact_bundle.zip is not a valid zip archive", file=sys.stderr)
    sys.exit(1)

try:
    bundle_manifest_payload = json.loads(bundle_manifest_bytes.decode("utf-8"))
except Exception as exc:
    print("bundle_manifest.json is not valid JSON: {0}".format(exc), file=sys.stderr)
    sys.exit(1)

if not isinstance(bundle_manifest_payload, dict):
    print("bundle_manifest.json must be a JSON object", file=sys.stderr)
    sys.exit(1)

if bundle_manifest_payload.get("schema") != "enc2sop-promotion-artifact-bundle/v1":
    print(
        "bundle_manifest schema mismatch: expected enc2sop-promotion-artifact-bundle/v1, got {0}".format(
            bundle_manifest_payload.get("schema")
        ),
        file=sys.stderr,
    )
    sys.exit(1)

bundle_manifest_rows = bundle_manifest_payload.get("files")
if not isinstance(bundle_manifest_rows, list):
    print("bundle_manifest.files must be a list", file=sys.stderr)
    sys.exit(1)
bundle_manifest_file_count = bundle_manifest_payload.get("file_count")
if not isinstance(bundle_manifest_file_count, int) or isinstance(bundle_manifest_file_count, bool):
    print("bundle_manifest.file_count must be an integer", file=sys.stderr)
    sys.exit(1)
if bundle_manifest_file_count != len(bundle_manifest_rows):
    print(
        "bundle_manifest.file_count must match length of bundle_manifest.files: expected {0}, got {1}".format(
            len(bundle_manifest_rows),
            bundle_manifest_file_count,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

bundle_rows_by_name = {}
bundle_manifest_archive_paths = []
bundle_manifest_archive_path_set = set()
for index, row in enumerate(bundle_manifest_rows):
    if not isinstance(row, dict):
        print("bundle_manifest.files[{0}] must be an object".format(index), file=sys.stderr)
        sys.exit(1)
    name = row.get("name")
    archive_path = row.get("archive_path")
    digest_hex = row.get("sha256")
    if not isinstance(name, str) or not name.strip():
        print("bundle_manifest.files[{0}].name is required".format(index), file=sys.stderr)
        sys.exit(1)
    if name in bundle_rows_by_name:
        print("bundle_manifest.files duplicate name: {0}".format(name), file=sys.stderr)
        sys.exit(1)
    if not isinstance(archive_path, str) or not archive_path.strip():
        print("bundle_manifest.files[{0}].archive_path is required".format(index), file=sys.stderr)
        sys.exit(1)
    if archive_path != archive_path.strip():
        print("bundle_manifest.files[{0}].archive_path must not contain leading or trailing whitespace".format(index), file=sys.stderr)
        sys.exit(1)
    if "\\" in archive_path or archive_path.startswith("/"):
        print("bundle_manifest.files[{0}].archive_path must be a relative forward-slash path".format(index), file=sys.stderr)
        sys.exit(1)
    if any(segment in ("", ".", "..") for segment in archive_path.split("/")):
        print("bundle_manifest.files[{0}].archive_path contains traversal or empty path segment".format(index), file=sys.stderr)
        sys.exit(1)
    if archive_path == "bundle_manifest.json":
        print("bundle_manifest.files[{0}].archive_path must not target bundle_manifest.json".format(index), file=sys.stderr)
        sys.exit(1)
    if archive_path in bundle_manifest_archive_path_set:
        print("bundle_manifest.files duplicate archive_path: {0}".format(archive_path), file=sys.stderr)
        sys.exit(1)
    if not isinstance(digest_hex, str) or len(digest_hex) != 64 or any(ch not in "0123456789abcdef" for ch in digest_hex):
        print(
            "bundle_manifest.files[{0}].sha256 must be a 64-char lowercase hex digest".format(index),
            file=sys.stderr,
        )
        sys.exit(1)
    archive_member_digest = bundle_archive_member_sha256.get(archive_path)
    if archive_member_digest is not None and digest_hex != archive_member_digest:
        print(
            "bundle_manifest.files[{0}].sha256 mismatch with promotion_artifact_bundle.zip member {1}: expected {2}, got {3}".format(
                index,
                archive_path,
                archive_member_digest,
                digest_hex,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    bundle_manifest_archive_path_set.add(archive_path)
    bundle_manifest_archive_paths.append(archive_path)
    bundle_rows_by_name[name] = {
        "archive_path": archive_path,
        "sha256": digest_hex,
    }

actual_bundle_entry_names = set(bundle_rows_by_name)
if actual_bundle_entry_names != required_bundle_entry_names:
    missing_entry_names = sorted(required_bundle_entry_names - actual_bundle_entry_names)
    extra_entry_names = sorted(actual_bundle_entry_names - required_bundle_entry_names)
    print(
        "bundle_manifest.files names must exactly match required promotion evidence entries; missing={0}; extra={1}".format(
            ", ".join(missing_entry_names) if missing_entry_names else "<none>",
            ", ".join(extra_entry_names) if extra_entry_names else "<none>",
        ),
        file=sys.stderr,
    )
    sys.exit(1)

expected_bundle_archive_paths = sorted(bundle_manifest_archive_path_set | {"bundle_manifest.json"})
actual_bundle_archive_paths = sorted(bundle_archive_member_path_set)
if actual_bundle_archive_paths != expected_bundle_archive_paths:
    missing_archive_paths = sorted(set(expected_bundle_archive_paths) - set(actual_bundle_archive_paths))
    extra_archive_paths = sorted(set(actual_bundle_archive_paths) - set(expected_bundle_archive_paths))
    print(
        "promotion_artifact_bundle.zip entries must exactly match bundle_manifest.files archive_path values plus bundle_manifest.json; missing={0}; extra={1}".format(
            ", ".join(missing_archive_paths) if missing_archive_paths else "<none>",
            ", ".join(extra_archive_paths) if extra_archive_paths else "<none>",
        ),
        file=sys.stderr,
    )
    sys.exit(1)

for bundle_name, (expected_archive_path, expected_filename) in required_bundle_entries.items():
    row = bundle_rows_by_name.get(bundle_name)
    if row is None:
        print("bundle_manifest missing required entry: {0}".format(bundle_name), file=sys.stderr)
        sys.exit(1)
    if row["archive_path"] != expected_archive_path:
        print(
            "bundle_manifest archive_path mismatch for {0}: expected {1}, got {2}".format(
                bundle_name,
                expected_archive_path,
                row["archive_path"],
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    expected_digest = sha256_file(resolved[expected_filename])
    if row["sha256"] != expected_digest:
        print(
            "bundle_manifest sha256 mismatch for {0}: expected {1}, got {2}".format(
                bundle_name,
                expected_digest,
                row["sha256"],
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    archive_member_digest = bundle_archive_member_sha256.get(row["archive_path"])
    if archive_member_digest != expected_digest:
        print(
            "promotion_artifact_bundle.zip member digest mismatch for {0}: expected {1}, got {2}".format(
                bundle_name,
                expected_digest,
                archive_member_digest or "<missing>",
            ),
            file=sys.stderr,
        )
        sys.exit(1)

promotion_audit_report_path = resolved["promotion_audit_report.json"]
try:
    promotion_audit_report_payload = json.loads(
        promotion_audit_report_path.read_text(encoding="utf-8")
    )
except Exception as exc:
    print("promotion_audit_report.json is not valid JSON: {0}".format(exc), file=sys.stderr)
    sys.exit(1)

if not isinstance(promotion_audit_report_payload, dict):
    print("promotion_audit_report.json must be a JSON object", file=sys.stderr)
    sys.exit(1)
if promotion_audit_report_payload.get("schema") != "enc2sop-promotion-audit-report/v1":
    print(
        "promotion_audit_report schema mismatch: expected enc2sop-promotion-audit-report/v1, got {0}".format(
            promotion_audit_report_payload.get("schema")
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_audit_report_payload.get("passed") is not True:
    print("promotion_audit_report.passed must be true", file=sys.stderr)
    sys.exit(1)
promotion_audit_report_summary = promotion_audit_report_payload.get("summary")
if not isinstance(promotion_audit_report_summary, dict):
    print("promotion_audit_report.summary must be an object", file=sys.stderr)
    sys.exit(1)
promotion_audit_report_total_failures = promotion_audit_report_summary.get("total_failures")
if not isinstance(promotion_audit_report_total_failures, int) or isinstance(promotion_audit_report_total_failures, bool):
    print("promotion_audit_report.summary.total_failures must be an integer", file=sys.stderr)
    sys.exit(1)
if promotion_audit_report_total_failures != 0:
    print("promotion_audit_report.summary.total_failures must be 0", file=sys.stderr)
    sys.exit(1)
promotion_audit_report_failures = promotion_audit_report_payload.get("failures")
if not isinstance(promotion_audit_report_failures, list):
    print("promotion_audit_report.failures must be a list", file=sys.stderr)
    sys.exit(1)
if promotion_audit_report_total_failures != len(promotion_audit_report_failures):
    print("promotion_audit_report.summary.total_failures must match length of promotion_audit_report.failures", file=sys.stderr)
    sys.exit(1)
if promotion_audit_report_failures:
    print("promotion_audit_report.failures must be empty when report passed=true", file=sys.stderr)
    sys.exit(1)
promotion_audit_report_inputs = promotion_audit_report_payload.get("inputs")
if not isinstance(promotion_audit_report_inputs, dict):
    print("promotion_audit_report.inputs is required", file=sys.stderr)
    sys.exit(1)
promotion_audit_report_generated_at_utc, promotion_audit_report_generated_at_dt = parse_required_iso8601_utc(
    "promotion_audit_report.generated_at_utc",
    promotion_audit_report_payload.get("generated_at_utc"),
)

promotion_audit_report_inputs_evidence_file = promotion_audit_report_inputs.get("evidence_file")
if not isinstance(promotion_audit_report_inputs_evidence_file, str) or not promotion_audit_report_inputs_evidence_file.strip():
    print("promotion_audit_report.inputs.evidence_file is required", file=sys.stderr)
    sys.exit(1)
if promotion_audit_report_inputs_evidence_file != promotion_audit_report_inputs_evidence_file.strip():
    print(
        "promotion_audit_report.inputs.evidence_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
promotion_audit_report_inputs_evidence_sha256 = promotion_audit_report_inputs.get("evidence_sha256")
if not isinstance(promotion_audit_report_inputs_evidence_sha256, str) or not re.fullmatch(
    r"[0-9a-f]{64}",
    promotion_audit_report_inputs_evidence_sha256,
):
    print(
        "promotion_audit_report.inputs.evidence_sha256 must be a 64-char lowercase hex digest",
        file=sys.stderr,
    )
    sys.exit(1)
actual_promotion_evidence_sha256 = sha256_file(resolved["promotion_evidence.json"])
if promotion_audit_report_inputs_evidence_sha256 != actual_promotion_evidence_sha256:
    print(
        "promotion_audit_report.inputs.evidence_sha256 mismatch with promotion_evidence.json: expected {0}, got {1}".format(
            actual_promotion_evidence_sha256,
            promotion_audit_report_inputs_evidence_sha256,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

promotion_audit_report_inputs_policy_file = promotion_audit_report_inputs.get("policy_file")
if not isinstance(promotion_audit_report_inputs_policy_file, str) or not promotion_audit_report_inputs_policy_file.strip():
    print("promotion_audit_report.inputs.policy_file is required", file=sys.stderr)
    sys.exit(1)
if promotion_audit_report_inputs_policy_file != promotion_audit_report_inputs_policy_file.strip():
    print(
        "promotion_audit_report.inputs.policy_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
promotion_audit_report_inputs_policy_sha256 = promotion_audit_report_inputs.get("policy_sha256")
if not isinstance(promotion_audit_report_inputs_policy_sha256, str) or not re.fullmatch(
    r"[0-9a-f]{64}",
    promotion_audit_report_inputs_policy_sha256,
):
    print(
        "promotion_audit_report.inputs.policy_sha256 must be a 64-char lowercase hex digest",
        file=sys.stderr,
    )
    sys.exit(1)
bundle_policy_row = bundle_rows_by_name.get("promotion_policy")
if bundle_policy_row is None:
    print(
        "bundle_manifest missing required entry: promotion_policy",
        file=sys.stderr,
    )
    sys.exit(1)
if bundle_policy_row["archive_path"] != "policy/promotion_rollout_policy.json":
    print(
        "bundle_manifest archive_path mismatch for promotion_policy: expected policy/promotion_rollout_policy.json, got {0}".format(
            bundle_policy_row["archive_path"]
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if bundle_policy_row is not None and promotion_audit_report_inputs_policy_sha256 != bundle_policy_row["sha256"]:
    print(
        "promotion_audit_report.inputs.policy_sha256 mismatch with promotion_policy bundle entry: expected {0}, got {1}".format(
            bundle_policy_row["sha256"],
            promotion_audit_report_inputs_policy_sha256,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

promotion_audit_report_inputs_workflow_file = promotion_audit_report_inputs.get("workflow_file")
if not isinstance(promotion_audit_report_inputs_workflow_file, str) or not promotion_audit_report_inputs_workflow_file.strip():
    print("promotion_audit_report.inputs.workflow_file is required", file=sys.stderr)
    sys.exit(1)
if promotion_audit_report_inputs_workflow_file != promotion_audit_report_inputs_workflow_file.strip():
    print(
        "promotion_audit_report.inputs.workflow_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
promotion_audit_report_inputs_workflow_sha256 = promotion_audit_report_inputs.get("workflow_sha256")
if not isinstance(promotion_audit_report_inputs_workflow_sha256, str) or not re.fullmatch(
    r"[0-9a-f]{64}",
    promotion_audit_report_inputs_workflow_sha256,
):
    print(
        "promotion_audit_report.inputs.workflow_sha256 must be a 64-char lowercase hex digest",
        file=sys.stderr,
    )
    sys.exit(1)
bundle_workflow_row = bundle_rows_by_name.get("promotion_workflow")
if bundle_workflow_row is None:
    print(
        "bundle_manifest missing required entry: promotion_workflow",
        file=sys.stderr,
    )
    sys.exit(1)
if bundle_workflow_row["archive_path"] != "workflow/release_promotion.yml":
    print(
        "bundle_manifest archive_path mismatch for promotion_workflow: expected workflow/release_promotion.yml, got {0}".format(
            bundle_workflow_row["archive_path"]
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if bundle_workflow_row is not None and promotion_audit_report_inputs_workflow_sha256 != bundle_workflow_row["sha256"]:
    print(
        "promotion_audit_report.inputs.workflow_sha256 mismatch with promotion_workflow bundle entry: expected {0}, got {1}".format(
            bundle_workflow_row["sha256"],
            promotion_audit_report_inputs_workflow_sha256,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

promotion_artifact_audit_report_path = resolved["promotion_artifact_audit_report.json"]
try:
    promotion_artifact_audit_report_payload = json.loads(
        promotion_artifact_audit_report_path.read_text(encoding="utf-8")
    )
except Exception as exc:
    print(
        "promotion_artifact_audit_report.json is not valid JSON: {0}".format(exc),
        file=sys.stderr,
    )
    sys.exit(1)

if not isinstance(promotion_artifact_audit_report_payload, dict):
    print("promotion_artifact_audit_report.json must be a JSON object", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_payload.get("schema") != "enc2sop-promotion-artifact-audit/v1":
    print(
        "promotion_artifact_audit_report schema mismatch: expected enc2sop-promotion-artifact-audit/v1, got {0}".format(
            promotion_artifact_audit_report_payload.get("schema")
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_payload.get("passed") is not True:
    print("promotion_artifact_audit_report.passed must be true", file=sys.stderr)
    sys.exit(1)
promotion_artifact_audit_report_summary = promotion_artifact_audit_report_payload.get("summary")
if not isinstance(promotion_artifact_audit_report_summary, dict):
    print("promotion_artifact_audit_report.summary must be an object", file=sys.stderr)
    sys.exit(1)
promotion_artifact_audit_report_total_failures = promotion_artifact_audit_report_summary.get("total_failures")
if not isinstance(promotion_artifact_audit_report_total_failures, int) or isinstance(promotion_artifact_audit_report_total_failures, bool):
    print("promotion_artifact_audit_report.summary.total_failures must be an integer", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_total_failures != 0:
    print("promotion_artifact_audit_report.summary.total_failures must be 0", file=sys.stderr)
    sys.exit(1)
promotion_artifact_audit_report_failures = promotion_artifact_audit_report_payload.get("failures")
if not isinstance(promotion_artifact_audit_report_failures, list):
    print("promotion_artifact_audit_report.failures must be a list", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_total_failures != len(promotion_artifact_audit_report_failures):
    print("promotion_artifact_audit_report.summary.total_failures must match length of promotion_artifact_audit_report.failures", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_failures:
    print("promotion_artifact_audit_report.failures must be empty when report passed=true", file=sys.stderr)
    sys.exit(1)
promotion_artifact_audit_report_generated_at_utc, promotion_artifact_audit_report_generated_at_dt = parse_required_iso8601_utc(
    "promotion_artifact_audit_report.generated_at_utc",
    promotion_artifact_audit_report_payload.get("generated_at_utc"),
)
if promotion_artifact_audit_report_generated_at_dt < promotion_audit_report_generated_at_dt:
    print(
        "promotion_artifact_audit_report.generated_at_utc must be >= promotion_audit_report.generated_at_utc; got {0} < {1}".format(
            promotion_artifact_audit_report_generated_at_utc,
            promotion_audit_report_generated_at_utc,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if rotation_report_generated_at_dt > promotion_artifact_audit_report_generated_at_dt:
    print(
        "rotation_rehearsal_report.generated_at_utc must be <= promotion_artifact_audit_report.generated_at_utc; got {0} > {1}".format(
            rotation_report_generated_at_utc,
            promotion_artifact_audit_report_generated_at_utc,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
require_timestamp_within_workflow_run_window(
    "promotion_artifact_audit_report.generated_at_utc",
    promotion_artifact_audit_report_generated_at_utc,
    promotion_artifact_audit_report_generated_at_dt,
)
promotion_artifact_audit_report_release_dir = promotion_artifact_audit_report_payload.get("release_dir")
if not isinstance(promotion_artifact_audit_report_release_dir, str) or not promotion_artifact_audit_report_release_dir.strip():
    print("promotion_artifact_audit_report.release_dir is required", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_release_dir != promotion_artifact_audit_report_release_dir.strip():
    print("promotion_artifact_audit_report.release_dir must not contain leading or trailing whitespace", file=sys.stderr)
    sys.exit(1)
promotion_artifact_audit_report_evidence_file = promotion_artifact_audit_report_payload.get("promotion_evidence_file")
if not isinstance(promotion_artifact_audit_report_evidence_file, str) or not promotion_artifact_audit_report_evidence_file.strip():
    print("promotion_artifact_audit_report.promotion_evidence_file is required", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_evidence_file != promotion_artifact_audit_report_evidence_file.strip():
    print(
        "promotion_artifact_audit_report.promotion_evidence_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
promotion_artifact_audit_report_promotion_report_file = promotion_artifact_audit_report_payload.get("promotion_report_file")
if (
    not isinstance(promotion_artifact_audit_report_promotion_report_file, str)
    or not promotion_artifact_audit_report_promotion_report_file.strip()
):
    print("promotion_artifact_audit_report.promotion_report_file is required", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_promotion_report_file != promotion_artifact_audit_report_promotion_report_file.strip():
    print(
        "promotion_artifact_audit_report.promotion_report_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
promotion_artifact_audit_report_rotation_report_file = promotion_artifact_audit_report_payload.get("rotation_report_file")
if (
    not isinstance(promotion_artifact_audit_report_rotation_report_file, str)
    or not promotion_artifact_audit_report_rotation_report_file.strip()
):
    print("promotion_artifact_audit_report.rotation_report_file is required", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_rotation_report_file != promotion_artifact_audit_report_rotation_report_file.strip():
    print(
        "promotion_artifact_audit_report.rotation_report_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
promotion_artifact_audit_report_policy_file = promotion_artifact_audit_report_payload.get("promotion_policy_file")
if not isinstance(promotion_artifact_audit_report_policy_file, str) or not promotion_artifact_audit_report_policy_file.strip():
    print("promotion_artifact_audit_report.promotion_policy_file is required", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_policy_file != promotion_artifact_audit_report_policy_file.strip():
    print(
        "promotion_artifact_audit_report.promotion_policy_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
promotion_artifact_audit_report_workflow_file = promotion_artifact_audit_report_payload.get("promotion_workflow_file")
if (
    not isinstance(promotion_artifact_audit_report_workflow_file, str)
    or not promotion_artifact_audit_report_workflow_file.strip()
):
    print("promotion_artifact_audit_report.promotion_workflow_file is required", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_workflow_file != promotion_artifact_audit_report_workflow_file.strip():
    print(
        "promotion_artifact_audit_report.promotion_workflow_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_policy_file != promotion_audit_report_inputs_policy_file:
    print(
        "promotion_artifact_audit_report.promotion_policy_file does not match promotion_audit_report.inputs.policy_file: expected {0}, got {1}".format(
            promotion_audit_report_inputs_policy_file,
            promotion_artifact_audit_report_policy_file,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_workflow_file != promotion_audit_report_inputs_workflow_file:
    print(
        "promotion_artifact_audit_report.promotion_workflow_file does not match promotion_audit_report.inputs.workflow_file: expected {0}, got {1}".format(
            promotion_audit_report_inputs_workflow_file,
            promotion_artifact_audit_report_workflow_file,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
promotion_artifact_audit_report_run_receipt_file = promotion_artifact_audit_report_payload.get("promotion_run_receipt_file")
if (
    not isinstance(promotion_artifact_audit_report_run_receipt_file, str)
    or not promotion_artifact_audit_report_run_receipt_file.strip()
):
    print("promotion_artifact_audit_report.promotion_run_receipt_file is required", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_run_receipt_file != promotion_artifact_audit_report_run_receipt_file.strip():
    print(
        "promotion_artifact_audit_report.promotion_run_receipt_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
promotion_artifact_audit_report_key_id_expected = promotion_artifact_audit_report_payload.get(
    "release_approval_key_id_expected"
)
if (
    not isinstance(promotion_artifact_audit_report_key_id_expected, str)
    or not promotion_artifact_audit_report_key_id_expected.strip()
):
    print("promotion_artifact_audit_report.release_approval_key_id_expected is required", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_report_key_id_expected != promotion_artifact_audit_report_key_id_expected.strip():
    print(
        "promotion_artifact_audit_report.release_approval_key_id_expected must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
expected_rotation_pass_required = rotation_rehearsal == "true"
if promotion_artifact_audit_report_payload.get("release_approval_signature_required") is not True:
    print(
        "promotion_artifact_audit_report.release_approval_signature_required must be true",
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_payload.get("ci_context_match_required") is not True:
    print(
        "promotion_artifact_audit_report.ci_context_match_required must be true",
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_payload.get("artifact_context_consistency_required") is not True:
    print(
        "promotion_artifact_audit_report.artifact_context_consistency_required must be true",
        file=sys.stderr,
    )
    sys.exit(1)
promotion_artifact_audit_rotation_required = promotion_artifact_audit_report_payload.get("rotation_pass_required")
if not isinstance(promotion_artifact_audit_rotation_required, bool):
    print("promotion_artifact_audit_report.rotation_pass_required must be boolean", file=sys.stderr)
    sys.exit(1)
if promotion_artifact_audit_rotation_required != expected_rotation_pass_required:
    print(
        "promotion_artifact_audit_report.rotation_pass_required mismatch: expected {0}, got {1}".format(
            expected_rotation_pass_required,
            promotion_artifact_audit_rotation_required,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

release_approval_path = resolved["release_approval.json"]
try:
    release_approval_payload = json.loads(release_approval_path.read_text(encoding="utf-8"))
except Exception as exc:
    print("release_approval.json is not valid JSON: {0}".format(exc), file=sys.stderr)
    sys.exit(1)
if not isinstance(release_approval_payload, dict):
    print("release_approval.json must be a JSON object", file=sys.stderr)
    sys.exit(1)
if release_approval_payload.get("schema") != "enc2sop-release-approval/v1":
    print(
        "release_approval schema mismatch: expected enc2sop-release-approval/v1, got {0}".format(
            release_approval_payload.get("schema")
        ),
        file=sys.stderr,
    )
    sys.exit(1)
release_approval_signature = release_approval_payload.get("signature")
if not isinstance(release_approval_signature, dict):
    print("release_approval.signature is required", file=sys.stderr)
    sys.exit(1)
release_approval_signature_algorithm = release_approval_signature.get("algorithm")
if release_approval_signature_algorithm != "hmac-sha256":
    print("release_approval.signature.algorithm must be hmac-sha256", file=sys.stderr)
    sys.exit(1)
release_approval_signature_key_id = release_approval_signature.get("key_id")
if not isinstance(release_approval_signature_key_id, str) or not release_approval_signature_key_id.strip():
    print("release_approval.signature.key_id is required", file=sys.stderr)
    sys.exit(1)
if release_approval_signature_key_id != release_approval_signature_key_id.strip():
    print(
        "release_approval.signature.key_id must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
release_approval_signature_digest_hex = release_approval_signature.get("digest_hex")
if not isinstance(release_approval_signature_digest_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", release_approval_signature_digest_hex):
    print("release_approval.signature.digest_hex must be a 64-char lowercase hex digest", file=sys.stderr)
    sys.exit(1)
release_approval_bundle_relative_path = release_approval_payload.get("release_bundle_relative_path")
if not isinstance(release_approval_bundle_relative_path, str) or not release_approval_bundle_relative_path.strip():
    print("release_approval.release_bundle_relative_path is required", file=sys.stderr)
    sys.exit(1)
if release_approval_bundle_relative_path != release_approval_bundle_relative_path.strip():
    print(
        "release_approval.release_bundle_relative_path must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
if Path(release_approval_bundle_relative_path).name != "release_bundle.json":
    print(
        "release_approval.release_bundle_relative_path must point to release_bundle.json; got {0}".format(
            release_approval_bundle_relative_path
        ),
        file=sys.stderr,
    )
    sys.exit(1)
release_approval_bundle_sha256 = release_approval_payload.get("release_bundle_sha256")
if not isinstance(release_approval_bundle_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", release_approval_bundle_sha256):
    print("release_approval.release_bundle_sha256 must be a 64-char lowercase hex digest", file=sys.stderr)
    sys.exit(1)
actual_release_bundle_sha256 = sha256_file(resolved["release_bundle.json"])
if release_approval_bundle_sha256 != actual_release_bundle_sha256:
    print(
        "release_approval.release_bundle_sha256 mismatch with release_bundle.json: expected {0}, got {1}".format(
            actual_release_bundle_sha256,
            release_approval_bundle_sha256,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
release_approval_approved_at_utc, release_approval_approved_at_dt = parse_required_iso8601_utc(
    "release_approval.approved_at_utc",
    release_approval_payload.get("approved_at_utc"),
)
require_timestamp_within_workflow_run_window(
    "release_approval.approved_at_utc",
    release_approval_approved_at_utc,
    release_approval_approved_at_dt,
)
release_approval_approvers = release_approval_payload.get("approvers")
if not isinstance(release_approval_approvers, list) or not release_approval_approvers:
    print("release_approval.approvers must be a non-empty list", file=sys.stderr)
    sys.exit(1)
normalized_release_approval_approvers = []
seen_release_approval_approvers = set()
for index, item in enumerate(release_approval_approvers):
    if not isinstance(item, str) or not item.strip():
        print("release_approval.approvers[{0}] must be a non-empty string".format(index), file=sys.stderr)
        sys.exit(1)
    if item != item.strip():
        print(
            "release_approval.approvers[{0}] must not contain leading or trailing whitespace".format(index),
            file=sys.stderr,
        )
        sys.exit(1)
    if item in seen_release_approval_approvers:
        print("release_approval.approvers contains duplicate value: {0}".format(item), file=sys.stderr)
        sys.exit(1)
    normalized_release_approval_approvers.append(item)
    seen_release_approval_approvers.add(item)
release_approval_notes = release_approval_payload.get("notes")
if release_approval_notes is not None:
    if not isinstance(release_approval_notes, str) or not release_approval_notes.strip():
        print("release_approval.notes must be a non-empty string when present", file=sys.stderr)
        sys.exit(1)
    if release_approval_notes != release_approval_notes.strip():
        print("release_approval.notes must not contain leading or trailing whitespace", file=sys.stderr)
        sys.exit(1)

release_receipt_path = resolved["release_receipt.json"]
try:
    release_receipt_payload = json.loads(release_receipt_path.read_text(encoding="utf-8"))
except Exception as exc:
    print("release_receipt.json is not valid JSON: {0}".format(exc), file=sys.stderr)
    sys.exit(1)
if not isinstance(release_receipt_payload, dict):
    print("release_receipt.json must be a JSON object", file=sys.stderr)
    sys.exit(1)
if release_receipt_payload.get("schema") != "enc2sop-release-receipt/v1":
    print(
        "release_receipt schema mismatch: expected enc2sop-release-receipt/v1, got {0}".format(
            release_receipt_payload.get("schema")
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if release_receipt_payload.get("release_approval_required") is not True:
    print("release_receipt.release_approval_required must be true", file=sys.stderr)
    sys.exit(1)
if release_receipt_payload.get("release_approval_verified") is not True:
    print("release_receipt.release_approval_verified must be true", file=sys.stderr)
    sys.exit(1)
release_receipt_bundle_relative_path = release_receipt_payload.get("release_bundle_relative_path")
if not isinstance(release_receipt_bundle_relative_path, str) or not release_receipt_bundle_relative_path.strip():
    print("release_receipt.release_bundle_relative_path is required", file=sys.stderr)
    sys.exit(1)
if release_receipt_bundle_relative_path != release_receipt_bundle_relative_path.strip():
    print(
        "release_receipt.release_bundle_relative_path must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
if release_receipt_bundle_relative_path != "release_bundle.json":
    print(
        "release_receipt.release_bundle_relative_path must be release_bundle.json; got {0}".format(
            release_receipt_bundle_relative_path
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if release_receipt_bundle_relative_path != release_approval_bundle_relative_path:
    print(
        "release_receipt.release_bundle_relative_path mismatch with release_approval.release_bundle_relative_path: expected {0}, got {1}".format(
            release_approval_bundle_relative_path,
            release_receipt_bundle_relative_path,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
release_receipt_bundle_sha256 = release_receipt_payload.get("release_bundle_sha256")
if not isinstance(release_receipt_bundle_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", release_receipt_bundle_sha256):
    print(
        "release_receipt.release_bundle_sha256 must be a 64-char lowercase hex digest",
        file=sys.stderr,
    )
    sys.exit(1)
if release_receipt_bundle_sha256 != actual_release_bundle_sha256:
    print(
        "release_receipt.release_bundle_sha256 mismatch with release_bundle.json: expected {0}, got {1}".format(
            actual_release_bundle_sha256,
            release_receipt_bundle_sha256,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
release_receipt_approval_sha256 = release_receipt_payload.get("release_approval_sha256")
if not isinstance(release_receipt_approval_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", release_receipt_approval_sha256):
    print(
        "release_receipt.release_approval_sha256 must be a 64-char lowercase hex digest",
        file=sys.stderr,
    )
    sys.exit(1)
actual_release_approval_sha256 = sha256_file(resolved["release_approval.json"])
if release_receipt_approval_sha256 != actual_release_approval_sha256:
    print(
        "release_receipt.release_approval_sha256 mismatch with release_approval.json: expected {0}, got {1}".format(
            actual_release_approval_sha256,
            release_receipt_approval_sha256,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
release_receipt_approval_signature_digest = release_receipt_payload.get("release_approval_signature_digest")
if not isinstance(release_receipt_approval_signature_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", release_receipt_approval_signature_digest):
    print(
        "release_receipt.release_approval_signature_digest must be a 64-char lowercase hex digest",
        file=sys.stderr,
    )
    sys.exit(1)
if release_receipt_approval_signature_digest != release_approval_signature_digest_hex:
    print(
        "release_receipt.release_approval_signature_digest mismatch with release_approval.signature.digest_hex: expected {0}, got {1}".format(
            release_approval_signature_digest_hex,
            release_receipt_approval_signature_digest,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
release_receipt_approval_file = release_receipt_payload.get("release_approval_file")
if not isinstance(release_receipt_approval_file, str) or not release_receipt_approval_file.strip():
    print("release_receipt.release_approval_file is required", file=sys.stderr)
    sys.exit(1)
if release_receipt_approval_file != release_receipt_approval_file.strip():
    print(
        "release_receipt.release_approval_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
if Path(release_receipt_approval_file).name != "release_approval.json":
    print(
        "release_receipt.release_approval_file must point to release_approval.json; got {0}".format(
            release_receipt_approval_file
        ),
        file=sys.stderr,
    )
    sys.exit(1)
release_receipt_key_id = release_receipt_payload.get("release_approval_key_id")
if not isinstance(release_receipt_key_id, str) or not release_receipt_key_id.strip():
    print("release_receipt.release_approval_key_id is required", file=sys.stderr)
    sys.exit(1)
if release_receipt_key_id != release_receipt_key_id.strip():
    print(
        "release_receipt.release_approval_key_id must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
release_receipt_generated_at_utc, release_receipt_generated_at_dt = parse_required_iso8601_utc(
    "release_receipt.generated_at_utc",
    release_receipt_payload.get("generated_at_utc"),
)
if release_receipt_generated_at_dt < release_approval_approved_at_dt:
    print(
        "release_receipt.generated_at_utc must be >= release_approval.approved_at_utc; got {0} < {1}".format(
            release_receipt_generated_at_utc,
            release_approval_approved_at_utc,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
require_timestamp_within_workflow_run_window(
    "release_receipt.generated_at_utc",
    release_receipt_generated_at_utc,
    release_receipt_generated_at_dt,
)
if promotion_audit_report_generated_at_dt < release_receipt_generated_at_dt:
    print(
        "promotion_audit_report.generated_at_utc must be >= release_receipt.generated_at_utc; got {0} < {1}".format(
            promotion_audit_report_generated_at_utc,
            release_receipt_generated_at_utc,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
require_timestamp_within_workflow_run_window(
    "promotion_audit_report.generated_at_utc",
    promotion_audit_report_generated_at_utc,
    promotion_audit_report_generated_at_dt,
)
release_receipt_context = release_receipt_payload.get("github_context")
if not isinstance(release_receipt_context, dict):
    print("release_receipt.github_context must be a JSON object", file=sys.stderr)
    sys.exit(1)
release_receipt_approval_context = release_receipt_payload.get("release_approval_github_context")
if not isinstance(release_receipt_approval_context, dict):
    print("release_receipt.release_approval_github_context must be a JSON object", file=sys.stderr)
    sys.exit(1)
release_approval_context = release_approval_payload.get("github_context")
if not isinstance(release_approval_context, dict):
    print("release_approval.github_context must be a JSON object", file=sys.stderr)
    sys.exit(1)
if release_receipt_approval_context != release_approval_context:
    print("release_receipt.release_approval_github_context must match release_approval.github_context", file=sys.stderr)
    sys.exit(1)

run_receipt_path = resolved["promotion_run_receipt.json"]
try:
    run_receipt_payload = json.loads(run_receipt_path.read_text(encoding="utf-8"))
except Exception as exc:
    print("promotion_run_receipt.json is not valid JSON: {0}".format(exc), file=sys.stderr)
    sys.exit(1)

if not isinstance(run_receipt_payload, dict):
    print("promotion_run_receipt.json must be a JSON object", file=sys.stderr)
    sys.exit(1)
if run_receipt_payload.get("schema") != "enc2sop-promotion-run-receipt/v1":
    print(
        "promotion_run_receipt schema mismatch: expected enc2sop-promotion-run-receipt/v1, got {0}".format(
            run_receipt_payload.get("schema")
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if run_receipt_payload.get("passed") is not True:
    print("promotion_run_receipt.passed must be true", file=sys.stderr)
    sys.exit(1)
rotation_pass_required = run_receipt_payload.get("rotation_pass_required")
if not isinstance(rotation_pass_required, bool):
    print("promotion_run_receipt.rotation_pass_required must be boolean", file=sys.stderr)
    sys.exit(1)
if rotation_pass_required != expected_rotation_pass_required:
    print(
        "promotion_run_receipt.rotation_pass_required mismatch: expected {0}, got {1}".format(
            expected_rotation_pass_required,
            rotation_pass_required,
        ),
        file=sys.stderr,
    )
    sys.exit(1)

required_run_receipt_entries = {
    "release_bundle": "release_bundle.json",
    "release_approval": "release_approval.json",
    "release_receipt": "release_receipt.json",
    "promotion_evidence": "promotion_evidence.json",
    "promotion_audit_report": "promotion_audit_report.json",
    "rotation_rehearsal_report": "rotation_rehearsal_report.json",
    "promotion_artifact_audit_report": "promotion_artifact_audit_report.json",
}

run_receipt_artifacts = run_receipt_payload.get("artifacts")
if not isinstance(run_receipt_artifacts, list):
    print("promotion_run_receipt.artifacts must be a list", file=sys.stderr)
    sys.exit(1)

run_receipt_rows_by_name = {}
for index, row in enumerate(run_receipt_artifacts):
    if not isinstance(row, dict):
        print("promotion_run_receipt.artifacts[{0}] must be an object".format(index), file=sys.stderr)
        sys.exit(1)
    name = row.get("name")
    path_value = row.get("path")
    digest_value = row.get("sha256")
    if not isinstance(name, str) or not name.strip():
        print("promotion_run_receipt.artifacts[{0}].name is required".format(index), file=sys.stderr)
        sys.exit(1)
    if name in run_receipt_rows_by_name:
        print("promotion_run_receipt.artifacts duplicate name: {0}".format(name), file=sys.stderr)
        sys.exit(1)
    if not isinstance(path_value, str) or not path_value.strip():
        print("promotion_run_receipt.artifacts[{0}].path is required".format(index), file=sys.stderr)
        sys.exit(1)
    if path_value != path_value.strip():
        print(
            "promotion_run_receipt.artifacts[{0}].path must not contain leading or trailing whitespace".format(index),
            file=sys.stderr,
        )
        sys.exit(1)
    if not isinstance(digest_value, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_value):
        print(
            "promotion_run_receipt.artifacts[{0}].sha256 must be a 64-char lowercase hex digest".format(index),
            file=sys.stderr,
        )
        sys.exit(1)
    run_receipt_rows_by_name[name] = {
        "path": path_value,
        "sha256": digest_value,
    }

for run_receipt_name, expected_filename in required_run_receipt_entries.items():
    row = run_receipt_rows_by_name.get(run_receipt_name)
    if row is None:
        print(
            "promotion_run_receipt.artifacts missing required entry: {0}".format(run_receipt_name),
            file=sys.stderr,
        )
        sys.exit(1)
    if Path(row["path"]).name != expected_filename:
        print(
            "promotion_run_receipt.artifacts[{0}].path must end with {1}; got {2}".format(
                run_receipt_name,
                expected_filename,
                row["path"],
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    expected_digest = sha256_file(resolved[expected_filename])
    if row["sha256"] != expected_digest:
        print(
            "promotion_run_receipt.artifacts[{0}].sha256 mismatch: expected {1}, got {2}".format(
                run_receipt_name,
                expected_digest,
                row["sha256"],
            ),
            file=sys.stderr,
        )
        sys.exit(1)

report_binding_rows = (
    ("promotion_artifact_audit_report.promotion_evidence_file", promotion_artifact_audit_report_evidence_file, "promotion_evidence"),
    (
        "promotion_artifact_audit_report.promotion_report_file",
        promotion_artifact_audit_report_promotion_report_file,
        "promotion_audit_report",
    ),
    (
        "promotion_artifact_audit_report.rotation_report_file",
        promotion_artifact_audit_report_rotation_report_file,
        "rotation_rehearsal_report",
    ),
    ("promotion_audit_report.inputs.evidence_file", promotion_audit_report_inputs_evidence_file, "promotion_evidence"),
)
for binding_label, binding_value, artifact_name in report_binding_rows:
    artifact_row = run_receipt_rows_by_name.get(artifact_name)
    if artifact_row is None:
        continue
    if binding_value != artifact_row["path"]:
        print(
            "{0} does not match promotion_run_receipt.artifacts[{1}].path: expected {2}, got {3}".format(
                binding_label,
                artifact_name,
                artifact_row["path"],
                binding_value,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
policy_row = run_receipt_rows_by_name.get("promotion_policy")
if policy_row is None:
    print(
        "promotion_run_receipt.artifacts missing required entry: promotion_policy",
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_audit_report_inputs_policy_file != policy_row["path"]:
    print(
        "promotion_audit_report.inputs.policy_file does not match promotion_run_receipt.artifacts[promotion_policy].path: expected {0}, got {1}".format(
            policy_row["path"],
            promotion_audit_report_inputs_policy_file,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_policy_file != policy_row["path"]:
    print(
        "promotion_artifact_audit_report.promotion_policy_file does not match promotion_run_receipt.artifacts[promotion_policy].path: expected {0}, got {1}".format(
            policy_row["path"],
            promotion_artifact_audit_report_policy_file,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if policy_row["sha256"] != bundle_policy_row["sha256"]:
    print(
        "promotion_run_receipt.artifacts[promotion_policy].sha256 mismatch with promotion_policy bundle entry: expected {0}, got {1}".format(
            bundle_policy_row["sha256"],
            policy_row["sha256"],
        ),
        file=sys.stderr,
    )
    sys.exit(1)
workflow_row = run_receipt_rows_by_name.get("promotion_workflow")
if workflow_row is None:
    print(
        "promotion_run_receipt.artifacts missing required entry: promotion_workflow",
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_audit_report_inputs_workflow_file != workflow_row["path"]:
    print(
        "promotion_audit_report.inputs.workflow_file does not match promotion_run_receipt.artifacts[promotion_workflow].path: expected {0}, got {1}".format(
            workflow_row["path"],
            promotion_audit_report_inputs_workflow_file,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_workflow_file != workflow_row["path"]:
    print(
        "promotion_artifact_audit_report.promotion_workflow_file does not match promotion_run_receipt.artifacts[promotion_workflow].path: expected {0}, got {1}".format(
            workflow_row["path"],
            promotion_artifact_audit_report_workflow_file,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if workflow_row["sha256"] != bundle_workflow_row["sha256"]:
    print(
        "promotion_run_receipt.artifacts[promotion_workflow].sha256 mismatch with promotion_workflow bundle entry: expected {0}, got {1}".format(
            bundle_workflow_row["sha256"],
            workflow_row["sha256"],
        ),
        file=sys.stderr,
    )
    sys.exit(1)

run_receipt_report_file = run_receipt_payload.get("promotion_artifact_audit_report_file")
report_row = run_receipt_rows_by_name.get("promotion_artifact_audit_report")
if not isinstance(run_receipt_report_file, str) or not run_receipt_report_file.strip():
    print("promotion_run_receipt.promotion_artifact_audit_report_file is required", file=sys.stderr)
    sys.exit(1)
if run_receipt_report_file != run_receipt_report_file.strip():
    print(
        "promotion_run_receipt.promotion_artifact_audit_report_file must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
if report_row is not None and run_receipt_report_file != report_row["path"]:
    print(
        "promotion_run_receipt.promotion_artifact_audit_report_file does not match artifacts[promotion_artifact_audit_report].path",
        file=sys.stderr,
    )
    sys.exit(1)
release_bundle_row = run_receipt_rows_by_name.get("release_bundle")
if release_bundle_row is not None and release_receipt_bundle_relative_path != Path(release_bundle_row["path"]).name:
    print(
        "release_receipt.release_bundle_relative_path does not match promotion_run_receipt.artifacts[release_bundle].path basename: expected {0}, got {1}".format(
            Path(release_bundle_row["path"]).name,
            release_receipt_bundle_relative_path,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
release_approval_row = run_receipt_rows_by_name.get("release_approval")
if release_approval_row is not None and release_receipt_approval_file != release_approval_row["path"]:
    print(
        "release_receipt.release_approval_file does not match promotion_run_receipt.artifacts[release_approval].path: expected {0}, got {1}".format(
            release_approval_row["path"],
            release_receipt_approval_file,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
run_receipt_row = run_receipt_rows_by_name.get("promotion_run_receipt")
if run_receipt_row is not None and promotion_artifact_audit_report_run_receipt_file != run_receipt_row["path"]:
    print(
        "promotion_artifact_audit_report.promotion_run_receipt_file does not match promotion_run_receipt.artifacts[promotion_run_receipt].path",
        file=sys.stderr,
    )
    sys.exit(1)
run_receipt_release_approval_key_id = run_receipt_payload.get("release_approval_key_id")
if not isinstance(run_receipt_release_approval_key_id, str) or not run_receipt_release_approval_key_id.strip():
    print("promotion_run_receipt.release_approval_key_id is required", file=sys.stderr)
    sys.exit(1)
if run_receipt_release_approval_key_id != run_receipt_release_approval_key_id.strip():
    print(
        "promotion_run_receipt.release_approval_key_id must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
if run_receipt_release_approval_key_id != release_approval_signature_key_id:
    print(
        "promotion_run_receipt.release_approval_key_id mismatch with release_approval.signature.key_id: expected {0}, got {1}".format(
            release_approval_signature_key_id,
            run_receipt_release_approval_key_id,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if run_receipt_release_approval_key_id != release_receipt_key_id:
    print(
        "promotion_run_receipt.release_approval_key_id mismatch with release_receipt.release_approval_key_id: expected {0}, got {1}".format(
            release_receipt_key_id,
            run_receipt_release_approval_key_id,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_key_id_expected != release_approval_signature_key_id:
    print(
        "promotion_artifact_audit_report.release_approval_key_id_expected mismatch with release_approval.signature.key_id: expected {0}, got {1}".format(
            release_approval_signature_key_id,
            promotion_artifact_audit_report_key_id_expected,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_key_id_expected != release_receipt_key_id:
    print(
        "promotion_artifact_audit_report.release_approval_key_id_expected mismatch with release_receipt.release_approval_key_id: expected {0}, got {1}".format(
            release_receipt_key_id,
            promotion_artifact_audit_report_key_id_expected,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if promotion_artifact_audit_report_key_id_expected != run_receipt_release_approval_key_id:
    print(
        "promotion_artifact_audit_report.release_approval_key_id_expected mismatch with promotion_run_receipt.release_approval_key_id: expected {0}, got {1}".format(
            run_receipt_release_approval_key_id,
            promotion_artifact_audit_report_key_id_expected,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
run_receipt_signature = run_receipt_payload.get("signature")
if not isinstance(run_receipt_signature, dict):
    print("promotion_run_receipt.signature is required", file=sys.stderr)
    sys.exit(1)
run_receipt_signature_algorithm = run_receipt_signature.get("algorithm")
if run_receipt_signature_algorithm != "hmac-sha256":
    print("promotion_run_receipt.signature.algorithm must be hmac-sha256", file=sys.stderr)
    sys.exit(1)
run_receipt_signature_key_id = run_receipt_signature.get("key_id")
if not isinstance(run_receipt_signature_key_id, str) or not run_receipt_signature_key_id.strip():
    print("promotion_run_receipt.signature.key_id is required", file=sys.stderr)
    sys.exit(1)
if run_receipt_signature_key_id != run_receipt_signature_key_id.strip():
    print(
        "promotion_run_receipt.signature.key_id must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
if run_receipt_signature_key_id != run_receipt_release_approval_key_id:
    print(
        "promotion_run_receipt.signature.key_id mismatch with promotion_run_receipt.release_approval_key_id: expected {0}, got {1}".format(
            run_receipt_release_approval_key_id,
            run_receipt_signature_key_id,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
run_receipt_signature_digest = run_receipt_signature.get("digest_hex")
if not isinstance(run_receipt_signature_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", run_receipt_signature_digest):
    print("promotion_run_receipt.signature.digest_hex must be a 64-char lowercase hex digest", file=sys.stderr)
    sys.exit(1)
promotion_run_receipt_generated_at_utc, promotion_run_receipt_generated_at_dt = parse_required_iso8601_utc(
    "promotion_run_receipt.generated_at_utc",
    run_receipt_payload.get("generated_at_utc"),
)
if promotion_run_receipt_generated_at_dt < promotion_artifact_audit_report_generated_at_dt:
    print(
        "promotion_run_receipt.generated_at_utc must be >= promotion_artifact_audit_report.generated_at_utc; got {0} < {1}".format(
            promotion_run_receipt_generated_at_utc,
            promotion_artifact_audit_report_generated_at_utc,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
require_timestamp_within_workflow_run_window(
    "promotion_run_receipt.generated_at_utc",
    promotion_run_receipt_generated_at_utc,
    promotion_run_receipt_generated_at_dt,
)

run_receipt_context = run_receipt_payload.get("github_context")
if not isinstance(run_receipt_context, dict):
    print("promotion_run_receipt.github_context must be a JSON object", file=sys.stderr)
    sys.exit(1)

def _require_run_receipt_context_key(key: str, expected: str):
    value = run_receipt_context.get(key)
    if not isinstance(value, str) or not value:
        print("promotion_run_receipt.github_context missing required key: {0}".format(key), file=sys.stderr)
        sys.exit(1)
    if value != value.strip():
        print(
            "promotion_run_receipt.github_context.{0} must not contain leading or trailing whitespace".format(key),
            file=sys.stderr,
        )
        sys.exit(1)
    if expected and value != expected:
        print(
            "promotion_run_receipt.github_context.{0} mismatch: expected {1}, got {2}".format(
                key,
                expected,
                value,
            ),
            file=sys.stderr,
        )
        sys.exit(1)

def _require_positive_integer_context_key(key: str) -> str:
    value = run_receipt_context.get(key)
    if not isinstance(value, str) or not value:
        print("promotion_run_receipt.github_context missing required key: {0}".format(key), file=sys.stderr)
        sys.exit(1)
    if value != value.strip():
        print(
            "promotion_run_receipt.github_context.{0} must not contain leading or trailing whitespace".format(key),
            file=sys.stderr,
        )
        sys.exit(1)
    if not value.isdigit():
        print(
            "promotion_run_receipt.github_context.{0} must be a positive integer".format(key),
            file=sys.stderr,
        )
        sys.exit(1)
    return value

def _require_context_key_from_run_receipt(
    context_payload: dict,
    context_label: str,
    key: str,
    *,
    required: bool,
):
    expected_value = run_receipt_context.get(key)
    if not isinstance(expected_value, str) or not expected_value:
        if required:
            print("promotion_run_receipt.github_context missing required key: {0}".format(key), file=sys.stderr)
            sys.exit(1)
        return
    if expected_value != expected_value.strip():
        print(
            "promotion_run_receipt.github_context.{0} must not contain leading or trailing whitespace".format(key),
            file=sys.stderr,
        )
        sys.exit(1)
    value = context_payload.get(key)
    if not isinstance(value, str) or not value:
        print("{0} missing required key: {1}".format(context_label, key), file=sys.stderr)
        sys.exit(1)
    if value != value.strip():
        print(
            "{0}.{1} must not contain leading or trailing whitespace".format(context_label, key),
            file=sys.stderr,
        )
        sys.exit(1)
    if value != expected_value:
        print(
            "{0}.{1} mismatch with promotion_run_receipt.github_context: expected {2}, got {3}".format(
                context_label,
                key,
                expected_value,
                value,
            ),
            file=sys.stderr,
        )
        sys.exit(1)

_require_run_receipt_context_key("GITHUB_REPOSITORY", repo)
_require_run_receipt_context_key("GITHUB_RUN_ID", run_id)
_require_run_receipt_context_key("GITHUB_RUN_ATTEMPT", run_attempt)
_require_run_receipt_context_key("GITHUB_ACTIONS", "true")
_require_run_receipt_context_key("CI", "true")
_require_run_receipt_context_key("GITHUB_REF_PROTECTED", "true")
if "/" in repo:
    expected_repo_owner = repo.split("/", 1)[0]
    _require_run_receipt_context_key("GITHUB_REPOSITORY_OWNER", expected_repo_owner)
else:
    expected_repo_owner = ""
repository_id_context = _require_positive_integer_context_key("GITHUB_REPOSITORY_ID")
repository_owner_id_context = _require_positive_integer_context_key("GITHUB_REPOSITORY_OWNER_ID")
actor_id_context = _require_positive_integer_context_key("GITHUB_ACTOR_ID")
if not workflow_repository_id or not workflow_repository_id.isdigit():
    print("Resolved run repository.id is not numeric.", file=sys.stderr)
    sys.exit(1)
if repository_id_context != workflow_repository_id:
    print(
        "promotion_run_receipt.github_context.GITHUB_REPOSITORY_ID mismatch with run repository.id: expected {0}, got {1}".format(
            workflow_repository_id,
            repository_id_context,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if not workflow_repository_owner_id or not workflow_repository_owner_id.isdigit():
    print("Resolved run repository.owner.id is not numeric.", file=sys.stderr)
    sys.exit(1)
if repository_owner_id_context != workflow_repository_owner_id:
    print(
        "promotion_run_receipt.github_context.GITHUB_REPOSITORY_OWNER_ID mismatch with run repository.owner.id: expected {0}, got {1}".format(
            workflow_repository_owner_id,
            repository_owner_id_context,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
if not workflow_actor_id or not workflow_actor_id.isdigit():
    print("Resolved run actor.id is not numeric.", file=sys.stderr)
    sys.exit(1)
if actor_id_context != workflow_actor_id:
    print(
        "promotion_run_receipt.github_context.GITHUB_ACTOR_ID mismatch with run actor.id: expected {0}, got {1}".format(
            workflow_actor_id,
            actor_id_context,
        ),
        file=sys.stderr,
    )
    sys.exit(1)
workflow_sha_context = run_receipt_context.get("GITHUB_WORKFLOW_SHA")
if not isinstance(workflow_sha_context, str) or not workflow_sha_context:
    print("promotion_run_receipt.github_context missing required key: GITHUB_WORKFLOW_SHA", file=sys.stderr)
    sys.exit(1)
if workflow_sha_context != workflow_sha_context.strip():
    print(
        "promotion_run_receipt.github_context.GITHUB_WORKFLOW_SHA must not contain leading or trailing whitespace",
        file=sys.stderr,
    )
    sys.exit(1)
if not re.fullmatch(r"[0-9a-f]{40}", workflow_sha_context):
    print(
        "promotion_run_receipt.github_context.GITHUB_WORKFLOW_SHA must be a 40-char lowercase hex digest",
        file=sys.stderr,
    )
    sys.exit(1)
run_url_host_normalized = (workflow_run_url_host or "").strip().lower()
expected_server_url = ""
expected_api_url = ""
expected_graphql_url = ""
if run_url_host_normalized:
    expected_server_url = "https://{0}".format(run_url_host_normalized)
    if run_url_host_normalized == "github.com":
        expected_api_url = "https://api.github.com"
        expected_graphql_url = "https://api.github.com/graphql"
    else:
        expected_api_url = "{0}/api/v3".format(expected_server_url)
        expected_graphql_url = "{0}/api/graphql".format(expected_server_url)
if expected_server_url:
    _require_run_receipt_context_key("GITHUB_SERVER_URL", expected_server_url)
if expected_api_url:
    _require_run_receipt_context_key("GITHUB_API_URL", expected_api_url)
if expected_graphql_url:
    _require_run_receipt_context_key("GITHUB_GRAPHQL_URL", expected_graphql_url)
if workflow_head_sha:
    if not re.fullmatch(r"[0-9a-f]{40}", workflow_head_sha):
        print("Resolved run head_sha is not a canonical 40-char lowercase hex digest.", file=sys.stderr)
        sys.exit(1)
    _require_run_receipt_context_key("GITHUB_SHA", workflow_head_sha)
if workflow_run_number:
    if not workflow_run_number.isdigit():
        print("Resolved run_number is not numeric.", file=sys.stderr)
        sys.exit(1)
    _require_run_receipt_context_key("GITHUB_RUN_NUMBER", workflow_run_number)
if workflow_retention_days:
    if not workflow_retention_days.isdigit():
        print("Resolved run retention_days is not numeric.", file=sys.stderr)
        sys.exit(1)
    if int(workflow_retention_days) <= 0:
        print("Resolved run retention_days must be positive.", file=sys.stderr)
        sys.exit(1)
    _require_run_receipt_context_key("GITHUB_RETENTION_DAYS", workflow_retention_days)
if workflow_run_workflow_id:
    if not workflow_run_workflow_id.isdigit():
        print("Resolved run workflow_id is not numeric.", file=sys.stderr)
        sys.exit(1)
    if not workflow_definition_id.isdigit():
        print("Resolved workflow definition id is not numeric.", file=sys.stderr)
        sys.exit(1)
    if workflow_run_workflow_id != workflow_definition_id:
        print(
            "Resolved run workflow_id mismatch with workflow definition id: expected {0}, got {1}".format(
                workflow_definition_id,
                workflow_run_workflow_id,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
if run_id_resolution_mode == "dispatch-api":
    if not dispatch_run_id or not dispatch_run_id.isdigit():
        print("Dispatch response run_id is required and must be numeric when run_id_resolution_mode=dispatch-api.", file=sys.stderr)
        sys.exit(1)
    if dispatch_run_id != run_id:
        print(
            "Dispatch response run_id mismatch with resolved workflow_run_id: expected {0}, got {1}".format(
                run_id,
                dispatch_run_id,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    if not dispatch_workflow_id or not dispatch_workflow_id.isdigit():
        print("Dispatch response workflow_id is required and must be numeric when run_id_resolution_mode=dispatch-api.", file=sys.stderr)
        sys.exit(1)
    if not workflow_definition_id.isdigit():
        print("Resolved workflow definition id is not numeric.", file=sys.stderr)
        sys.exit(1)
    if dispatch_workflow_id != workflow_definition_id:
        print(
            "Dispatch response workflow_id mismatch with workflow definition id: expected {0}, got {1}".format(
                workflow_definition_id,
                dispatch_workflow_id,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    if dispatch_run_url:
        if dispatch_run_url != dispatch_run_url.strip():
            print("Dispatch response run_url must not contain leading or trailing whitespace.", file=sys.stderr)
            sys.exit(1)
        match = re.search(r"/actions/runs/([0-9]+)", dispatch_run_url)
        if match is None:
            print("Dispatch response run_url is not canonical: {0}".format(dispatch_run_url), file=sys.stderr)
            sys.exit(1)
        if match.group(1) != run_id:
            print(
                "Dispatch response run_url run_id mismatch with resolved workflow_run_id: expected {0}, got {1}".format(
                    run_id,
                    match.group(1),
                ),
                file=sys.stderr,
            )
            sys.exit(1)
    if dispatch_run_html_url:
        if dispatch_run_html_url != dispatch_run_html_url.strip():
            print("Dispatch response html_url must not contain leading or trailing whitespace.", file=sys.stderr)
            sys.exit(1)
        match = re.search(r"/actions/runs/([0-9]+)", dispatch_run_html_url)
        if match is None:
            print("Dispatch response html_url is not canonical: {0}".format(dispatch_run_html_url), file=sys.stderr)
            sys.exit(1)
        if match.group(1) != run_id:
            print(
                "Dispatch response html_url run_id mismatch with resolved workflow_run_id: expected {0}, got {1}".format(
                    run_id,
                    match.group(1),
                ),
                file=sys.stderr,
            )
            sys.exit(1)
if workflow_head_branch:
    if workflow_head_branch != workflow_head_branch.strip():
        print("Resolved run head_branch must not contain leading or trailing whitespace.", file=sys.stderr)
        sys.exit(1)
    _require_run_receipt_context_key("GITHUB_REF", "refs/heads/{0}".format(workflow_head_branch))
    _require_run_receipt_context_key("GITHUB_REF_NAME", workflow_head_branch)
    _require_run_receipt_context_key("GITHUB_REF_TYPE", "branch")
if workflow_event:
    _require_run_receipt_context_key("GITHUB_EVENT_NAME", workflow_event)
if workflow_job_id:
    _require_run_receipt_context_key("GITHUB_JOB", workflow_job_id)
if workflow_path_ref:
    if workflow_path_ref != workflow_path_ref.strip():
        print("Resolved run workflow path@ref identity must not contain leading or trailing whitespace.", file=sys.stderr)
        sys.exit(1)
    if "@" not in workflow_path_ref:
        print("Resolved run workflow path@ref identity is invalid: {0}".format(workflow_path_ref), file=sys.stderr)
        sys.exit(1)
    workflow_path_ref_path, workflow_path_ref_ref = workflow_path_ref.rsplit("@", 1)
    if not workflow_path_ref_path or not workflow_path_ref_ref:
        print("Resolved run workflow path@ref identity is invalid: {0}".format(workflow_path_ref), file=sys.stderr)
        sys.exit(1)
    if workflow_path_ref_ref != workflow_path_ref_ref.strip():
        print("Resolved run workflow ref segment must not contain leading or trailing whitespace.", file=sys.stderr)
        sys.exit(1)
    workflow_ref = workflow_path_ref_ref
    context_workflow_ref_value = run_receipt_context.get("GITHUB_WORKFLOW_REF")
    if not isinstance(context_workflow_ref_value, str) or not context_workflow_ref_value:
        print("promotion_run_receipt.github_context missing required key: GITHUB_WORKFLOW_REF", file=sys.stderr)
        sys.exit(1)
    if context_workflow_ref_value != context_workflow_ref_value.strip():
        print(
            "promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF must not contain leading or trailing whitespace",
            file=sys.stderr,
        )
        sys.exit(1)
    if "@" not in context_workflow_ref_value:
        print(
            "promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF is invalid: {0}".format(
                context_workflow_ref_value
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    context_workflow_ref_path, context_workflow_ref_ref = context_workflow_ref_value.rsplit("@", 1)
    if not context_workflow_ref_path or not context_workflow_ref_ref:
        print(
            "promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF is invalid: {0}".format(
                context_workflow_ref_value
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    if context_workflow_ref_ref != context_workflow_ref_ref.strip():
        print(
            "promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF ref segment must not contain leading or trailing whitespace",
            file=sys.stderr,
        )
        sys.exit(1)
    if context_workflow_ref_path != workflow_path_ref_path:
        print(
            "promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF workflow path mismatch: expected {0}, got {1}".format(
                workflow_path_ref_path,
                context_workflow_ref_path,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    if workflow_ref:
        if not workflow_ref.startswith("refs/"):
            print(
                "Resolved run workflow_ref is not canonical for semantic parity checks: {0}".format(
                    workflow_ref
                ),
                file=sys.stderr,
            )
            sys.exit(1)
        if context_workflow_ref_ref != workflow_ref:
            print(
                "promotion_run_receipt.github_context.GITHUB_WORKFLOW_REF ref mismatch: expected {0}, got {1}".format(
                    workflow_ref,
                    context_workflow_ref_ref,
                ),
                file=sys.stderr,
            )
            sys.exit(1)
if promotion_workflow_name_verified:
    _require_run_receipt_context_key("GITHUB_WORKFLOW", promotion_workflow_name_verified)
if promotion_actor_login_verified:
    _require_run_receipt_context_key("GITHUB_ACTOR", promotion_actor_login_verified)
if promotion_triggering_actor_login_verified:
    _require_run_receipt_context_key("GITHUB_TRIGGERING_ACTOR", promotion_triggering_actor_login_verified)
if promotion_runner_name_verified:
    _require_run_receipt_context_key("RUNNER_NAME", promotion_runner_name_verified)

rotation_required_context_map = (
    ("workflow_repository", "GITHUB_REPOSITORY"),
    ("workflow_run_id", "GITHUB_RUN_ID"),
    ("workflow_run_attempt", "GITHUB_RUN_ATTEMPT"),
    ("workflow_github_actions", "GITHUB_ACTIONS"),
    ("workflow_ci", "CI"),
    ("workflow_runner_environment", "RUNNER_ENVIRONMENT"),
    ("workflow_runner_os", "RUNNER_OS"),
    ("workflow_runner_arch", "RUNNER_ARCH"),
    ("workflow_retention_days", "GITHUB_RETENTION_DAYS"),
    ("workflow_job", "GITHUB_JOB"),
    ("workflow_actor_id", "GITHUB_ACTOR_ID"),
    ("workflow_repository_id", "GITHUB_REPOSITORY_ID"),
    ("workflow_repository_owner", "GITHUB_REPOSITORY_OWNER"),
    ("workflow_repository_owner_id", "GITHUB_REPOSITORY_OWNER_ID"),
    ("workflow_ref_protected", "GITHUB_REF_PROTECTED"),
    ("workflow_name_sha", "GITHUB_WORKFLOW_SHA"),
    ("workflow_server_url", "GITHUB_SERVER_URL"),
    ("workflow_api_url", "GITHUB_API_URL"),
    ("workflow_graphql_url", "GITHUB_GRAPHQL_URL"),
)
rotation_optional_context_map = (
    ("workflow_sha", "GITHUB_SHA"),
    ("workflow_run_number", "GITHUB_RUN_NUMBER"),
    ("workflow_ref", "GITHUB_REF"),
    ("workflow_ref_name", "GITHUB_REF_NAME"),
    ("workflow_ref_type", "GITHUB_REF_TYPE"),
    ("workflow_event", "GITHUB_EVENT_NAME"),
    ("workflow_name", "GITHUB_WORKFLOW"),
    ("workflow_name_ref", "GITHUB_WORKFLOW_REF"),
    ("workflow_actor", "GITHUB_ACTOR"),
    ("workflow_triggering_actor", "GITHUB_TRIGGERING_ACTOR"),
    ("workflow_runner_name", "RUNNER_NAME"),
)

for rotation_field, context_key in rotation_required_context_map:
    expected_value = run_receipt_context.get(context_key)
    if not isinstance(expected_value, str) or not expected_value:
        print("promotion_run_receipt.github_context missing required key: {0}".format(context_key), file=sys.stderr)
        sys.exit(1)
    if expected_value != expected_value.strip():
        print(
            "promotion_run_receipt.github_context.{0} must not contain leading or trailing whitespace".format(
                context_key
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    rotation_value = rotation_report_payload.get(rotation_field)
    if not isinstance(rotation_value, str) or not rotation_value:
        print("rotation_rehearsal_report.{0} is required".format(rotation_field), file=sys.stderr)
        sys.exit(1)
    if rotation_value != rotation_value.strip():
        print(
            "rotation_rehearsal_report.{0} must not contain leading or trailing whitespace".format(
                rotation_field
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    if rotation_value != expected_value:
        print(
            "rotation_rehearsal_report.{0} mismatch with promotion_run_receipt.github_context.{1}: expected {2}, got {3}".format(
                rotation_field,
                context_key,
                expected_value,
                rotation_value,
            ),
            file=sys.stderr,
        )
        sys.exit(1)

for rotation_field, context_key in rotation_optional_context_map:
    expected_value = run_receipt_context.get(context_key)
    if not isinstance(expected_value, str) or not expected_value:
        continue
    if expected_value != expected_value.strip():
        print(
            "promotion_run_receipt.github_context.{0} must not contain leading or trailing whitespace".format(
                context_key
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    rotation_value = rotation_report_payload.get(rotation_field)
    if not isinstance(rotation_value, str) or not rotation_value:
        print(
            "rotation_rehearsal_report.{0} is required when promotion_run_receipt.github_context.{1} is present".format(
                rotation_field,
                context_key,
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    if rotation_value != rotation_value.strip():
        print(
            "rotation_rehearsal_report.{0} must not contain leading or trailing whitespace".format(
                rotation_field
            ),
            file=sys.stderr,
        )
        sys.exit(1)
    if rotation_value != expected_value:
        print(
            "rotation_rehearsal_report.{0} mismatch with promotion_run_receipt.github_context.{1}: expected {2}, got {3}".format(
                rotation_field,
                context_key,
                expected_value,
                rotation_value,
            ),
            file=sys.stderr,
        )
        sys.exit(1)

required_release_context_keys = (
    "GITHUB_REPOSITORY",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_ACTIONS",
    "CI",
    "GITHUB_REF_PROTECTED",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER_ID",
    "GITHUB_ACTOR_ID",
    "GITHUB_RETENTION_DAYS",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_SERVER_URL",
    "GITHUB_API_URL",
    "GITHUB_GRAPHQL_URL",
)
optional_release_context_keys = (
    "GITHUB_SHA",
    "GITHUB_RUN_NUMBER",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_EVENT_NAME",
    "GITHUB_JOB",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_ACTOR",
    "GITHUB_TRIGGERING_ACTOR",
    "RUNNER_NAME",
)
release_context_rows = (
    ("release_receipt.github_context", release_receipt_context),
    ("release_receipt.release_approval_github_context", release_receipt_approval_context),
    ("release_approval.github_context", release_approval_context),
)
for release_context_label, release_context_payload in release_context_rows:
    for required_key in required_release_context_keys:
        _require_context_key_from_run_receipt(
            release_context_payload,
            release_context_label,
            required_key,
            required=True,
        )
    for optional_key in optional_release_context_keys:
        _require_context_key_from_run_receipt(
            release_context_payload,
            release_context_label,
            optional_key,
            required=False,
        )

def _maybe_int(text: str):
    if text and text.isdigit():
        return int(text)
    return None

receipt = {
    "schema": "enc2sop-promotion-evidence-capture/v1",
    "generated_at_utc": generated_at_utc,
    "capture_mode": capture_mode,
    "dispatch_utc": dispatch_utc or None,
    "github_repository": repo,
    "workflow_file": workflow_file,
    "workflow_ref": workflow_path_ref,
    "workflow_dispatch_ref": ref,
    "workflow_path": workflow_path,
    "workflow_job_id": workflow_job_id,
    "workflow_event": workflow_event,
    "workflow_head_branch": workflow_head_branch or None,
    "workflow_head_sha": workflow_head_sha or None,
    "workflow_run_id": run_id,
    "workflow_run_attempt": run_attempt,
    "workflow_run_id_resolution_mode": run_id_resolution_mode,
    "dispatch_response_verification": {
        "run_id": _maybe_int(dispatch_run_id),
        "workflow_id": _maybe_int(dispatch_workflow_id),
        "run_url": dispatch_run_url or None,
        "html_url": dispatch_run_html_url or None,
        "run_url_host": dispatch_run_url_host or None,
        "html_url_host": dispatch_html_url_host or None,
        "run_url_attempt": _maybe_int(dispatch_run_url_attempt),
        "html_url_attempt": _maybe_int(dispatch_html_url_attempt),
    },
    "workflow_run_number": _maybe_int(workflow_run_number),
    "workflow_run_url": run_url,
    "workflow_run_html_url": workflow_html_url or run_url,
    "workflow_run_url_verification": {
        "host_summary": workflow_run_url_host or None,
        "host_detail": workflow_run_html_url_host or None,
        "attempt_summary": _maybe_int(workflow_run_url_attempt),
        "attempt_detail": _maybe_int(workflow_run_html_url_attempt),
    },
    "workflow_run_timestamp_verification": {
        "created_at_summary": workflow_created_at or None,
        "started_at_summary": workflow_started_at or None,
        "updated_at_summary": workflow_updated_at or None,
        "created_at_detail": workflow_created_at_detail or None,
        "started_at_detail": workflow_started_at_detail or None,
        "updated_at_detail": workflow_updated_at_detail or None,
    },
    "workflow_context_verification": {
        "repository_owner": expected_repo_owner or None,
        "repository_id": _maybe_int(repository_id_context),
        "repository_owner_id": _maybe_int(repository_owner_id_context),
        "actor_id": _maybe_int(actor_id_context),
        "run_repository_id": _maybe_int(workflow_repository_id),
        "run_repository_owner_id": _maybe_int(workflow_repository_owner_id),
        "run_actor_id": _maybe_int(workflow_actor_id),
        "retention_days": _maybe_int(workflow_retention_days),
        "workflow_sha": workflow_sha_context,
        "server_url": expected_server_url or None,
        "api_url": expected_api_url or None,
        "graphql_url": expected_graphql_url or None,
    },
    "workflow_definition_verification": {
        "id": _maybe_int(workflow_definition_id),
        "path": workflow_definition_path or None,
        "state": workflow_definition_state or None,
        "name": workflow_definition_name or None,
        "run_workflow_id": _maybe_int(workflow_run_workflow_id),
    },
    "branch_protection_preflight": branch_protection_preflight,
    "environment_reviewer_preflight": environment_preflight,
    "required_secret_preflight": {
        "required_count": len(required_secret_preflight),
        "secrets": required_secret_preflight,
    },
    "release_context_verification": {
        "contexts_verified": [label for label, _ in release_context_rows],
        "required_keys_verified": [key for key in required_release_context_keys],
        "optional_keys_verified_when_present": [key for key in optional_release_context_keys],
    },
    "promotion_job_verification": {
        "job_name": "Signed Approval Promotion Gate",
        "job_id": _maybe_int(promotion_job_id),
        "job_html_url": promotion_job_html_url or None,
        "job_html_url_host": promotion_job_html_url_host_verified or None,
        "job_html_url_path": promotion_job_html_url_path_verified or None,
        "job_html_url_attempt": _maybe_int(promotion_job_html_url_attempt_verified),
        "status": promotion_job_status_verified or None,
        "conclusion": promotion_job_conclusion_verified or None,
        "started_at": promotion_job_started_at or None,
        "completed_at": promotion_job_completed_at or None,
        "required_step_count_verified": _maybe_int(promotion_required_step_count_verified),
        "rotation_step_name": promotion_rotation_step_name or None,
        "rotation_step_conclusion": promotion_rotation_step_conclusion_verified or None,
        "runner_name": promotion_runner_name_verified or None,
        "runner_group_name": promotion_runner_group_name_verified or None,
        "runner_labels": [label for label in promotion_runner_labels_verified.split("|") if label] if promotion_runner_labels_verified else [],
        "workflow_name": promotion_workflow_name_verified or None,
        "actor_login": promotion_actor_login_verified or None,
        "triggering_actor_login": promotion_triggering_actor_login_verified or None,
        "actor_parity_checked": promotion_actor_parity_checked == "true",
        "triggering_actor_parity_checked": promotion_triggering_actor_parity_checked == "true",
    },
    "artifact_name": artifact_name,
    "artifact_metadata": {
        "id": _maybe_int(artifact_id),
        "name": artifact_name,
        "digest": artifact_digest,
        "size_in_bytes": _maybe_int(artifact_size_in_bytes),
        "created_at": artifact_created_at or None,
        "updated_at": artifact_updated_at or None,
        "expires_at": artifact_expires_at or None,
        "archive_download_url": artifact_archive_download_url,
        "archive_download_url_host": artifact_archive_download_url_host or None,
        "workflow_run_id": _maybe_int(artifact_workflow_run_id),
        "workflow_head_branch": artifact_workflow_head_branch or None,
        "workflow_head_sha": artifact_workflow_head_sha or None,
    },
    "artifact_archive_verification": {
        "path": artifact_archive_path,
        "digest_verified": artifact_archive_digest_verified,
        "size_in_bytes_verified": _maybe_int(artifact_archive_size_bytes),
        "entry_count_verified": _maybe_int(artifact_archive_entry_count),
    },
    "bundle_manifest_verification": {
        "schema": "enc2sop-promotion-artifact-bundle/v1",
        "path": "{0}::bundle_manifest.json".format(bundle_archive_path),
        "required_entries_verified": sorted(required_bundle_entries.keys()),
        "required_entry_count_verified": len(required_bundle_entries),
        "file_count_reported": _maybe_int(str(bundle_manifest_payload.get("file_count"))),
        "archive_entries_verified": actual_bundle_archive_paths,
        "archive_entry_count_verified": len(actual_bundle_archive_paths),
        "archive_member_sha256": {
            path: bundle_archive_member_sha256[path]
            for path in actual_bundle_archive_paths
        },
        "manifest_sha256": hashlib.sha256(bundle_manifest_bytes).hexdigest(),
    },
    "promotion_run_receipt_verification": {
        "schema": "enc2sop-promotion-run-receipt/v1",
        "passed": True,
        "rotation_pass_required": rotation_pass_required,
        "artifact_entries_verified": sorted(required_run_receipt_entries.keys()),
        "artifact_entry_count_verified": len(required_run_receipt_entries),
    },
    "approval_lineage_timestamps": {
        "release_approval_approved_at_utc": release_approval_approved_at_utc,
        "release_receipt_generated_at_utc": release_receipt_generated_at_utc,
        "promotion_audit_report_generated_at_utc": promotion_audit_report_generated_at_utc,
        "promotion_artifact_audit_report_generated_at_utc": promotion_artifact_audit_report_generated_at_utc,
        "promotion_run_receipt_generated_at_utc": promotion_run_receipt_generated_at_utc,
    },
    "release_approval_metadata_verification": {
        "approver_count": len(normalized_release_approval_approvers),
        "approvers": normalized_release_approval_approvers,
        "notes_present": release_approval_notes is not None,
    },
    "rotation_rehearsal": rotation_rehearsal == "true",
    "rotation_report_verification": {
        "generated_at_utc": rotation_report_generated_at_utc,
        "requested": rotation_requested,
        "executed": rotation_executed,
        "old_key_rejected": rotation_old_key_rejected,
        "status": rotation_status,
        "details": rotation_details,
        "workflow_retention_days": _maybe_int(rotation_workflow_retention_days),
        "context_required_keys_verified": [context_key for _, context_key in rotation_required_context_map],
        "context_optional_keys_verified_when_present": [context_key for _, context_key in rotation_optional_context_map],
    },
    "artifact_download_root": str(download_root),
    "artifacts": artifact_rows,
}

receipt_path.parent.mkdir(parents=True, exist_ok=True)
receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
print(str(receipt_path))
PY

echo "Promotion evidence captured successfully."
echo "run_id=${run_id}"
echo "run_attempt=${run_attempt}"
echo "run_url=${run_url}"
echo "artifact_name=${artifact_name}"
echo "download_dir=${download_dir}"
echo "capture_receipt=${receipt_path}"
