#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WORKFLOW_FILE="release_promotion.yml"
REF="main"
REF_EXPLICIT="false"
ROTATION_REHEARSAL="true"
SKIP_PROMOTION_COLLECT="false"
APPROVER=""
RUN_ID=""
RUN_ATTEMPT=""
OUTPUT_ROOT=".tmp_ci/live_promotion"
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
  --rotation-rehearsal <true|false>  Pass workflow_dispatch input rotation_rehearsal (default: true).
  --skip-promotion-collect <true|false>
                                     Pass workflow_dispatch input skip_promotion_collect (default: false).
  --approver <identity>              Optional approver input for workflow dispatch.
  --run-id <id>                      Capture evidence from an existing workflow run id (skip dispatch).
  --run-attempt <int>                Expected attempt number for --run-id (optional strict check).
  --output-root <dir>                Local evidence output root (default: .tmp_ci/live_promotion).
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
    raise SystemExit(0)
try:
    payload=json.loads(text)
except Exception:
    print("")
    raise SystemExit(0)
candidates=[]
def add_candidate(value):
    value_text=str(value) if value is not None else ""
    if value_text.isdigit():
        candidates.append(value_text)
add_candidate(payload.get("workflow_run_id"))
add_candidate(payload.get("run_id"))
workflow_run=payload.get("workflow_run")
if isinstance(workflow_run, dict):
    add_candidate(workflow_run.get("id"))
for key in ("run_url", "html_url", "url"):
    value=payload.get(key)
    if not isinstance(value,str):
        continue
    matches=re.findall(r"/actions/runs/([0-9]+)", value)
    if matches:
        candidates.append(matches[-1])
print(candidates[0] if candidates else "")
'
}

urlencode_path_segment() {
  local value="$1"
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
  printf '%s\n' "$runs_json" | python - "$dispatch_epoch" <<'PY'
import datetime
import json
import sys

dispatch_epoch = float(sys.argv[1])
payload = json.load(sys.stdin)

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

require_boolean_token "$ROTATION_REHEARSAL" "rotation-rehearsal"
require_boolean_token "$SKIP_PROMOTION_COLLECT" "skip-promotion-collect"
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

if [[ -z "$REPO" ]]; then
  REPO="$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null || true)"
fi
if [[ -z "$REPO" ]]; then
  echo "Unable to resolve repository slug. Provide --repo <owner/repo>." >&2
  exit 1
fi

expected_workflow_path="$(resolve_expected_workflow_path "$WORKFLOW_FILE")"
expected_branch_ref="$(normalize_branch_ref_name "$REF")"

echo "Checking GitHub CLI authentication..."
gh auth status >/dev/null

mkdir -p "$OUTPUT_ROOT"
dispatch_epoch="$(date -u +%s)"
dispatch_utc=""
capture_mode="dispatch"
run_id=""
run_id_resolution_mode="provided"
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
    run_id="$(extract_run_id_from_dispatch_response_json "$dispatch_output")"
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

while :; do
  run_metadata_json="$(gh run view "$run_id" --repo "$REPO" --json attempt,status,conclusion,url,updatedAt,event,headBranch,workflowName)"
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
')"
  run_attempt="$(printf '%s\n' "$parsed" | sed -n '1p')"
  run_status="$(printf '%s\n' "$parsed" | sed -n '2p')"
  run_conclusion="$(printf '%s\n' "$parsed" | sed -n '3p')"
  run_url="$(printf '%s\n' "$parsed" | sed -n '4p')"
  run_updated_at="$(printf '%s\n' "$parsed" | sed -n '5p')"
  run_event="$(printf '%s\n' "$parsed" | sed -n '6p')"
  run_head_branch="$(printf '%s\n' "$parsed" | sed -n '7p')"
  run_workflow_name="$(printf '%s\n' "$parsed" | sed -n '8p')"
  echo "run_id=${run_id} attempt=${run_attempt:-unknown} status=${run_status:-unknown} conclusion=${run_conclusion:-pending}"
  echo "event=${run_event:-unknown} head_branch=${run_head_branch:-unknown} workflow_name=${run_workflow_name:-unknown} updated=${run_updated_at:-unknown}"

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
print(payload.get("event",""))
print(payload.get("head_branch",""))
print(payload.get("head_sha",""))
print(payload.get("path",""))
print(payload.get("html_url",""))
print(payload.get("run_attempt",""))
print(payload.get("run_number",""))
')"
run_event_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '1p')"
run_head_branch_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '2p')"
run_head_sha_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '3p')"
run_workflow_path_ref="$(printf '%s\n' "$run_detail_parsed" | sed -n '4p')"
run_html_url_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '5p')"
run_attempt_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '6p')"
run_number_api="$(printf '%s\n' "$run_detail_parsed" | sed -n '7p')"

if [[ -z "$run_workflow_path_ref" || "$run_workflow_path_ref" != *@* ]]; then
  echo "Unable to resolve workflow path@ref identity for run_id=${run_id}." >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

run_workflow_path="${run_workflow_path_ref%@*}"
run_workflow_ref="${run_workflow_path_ref#*@}"

if [[ -n "$expected_workflow_path" && "$run_workflow_path" != "$expected_workflow_path" ]]; then
  echo "workflow path mismatch for run_id=${run_id}: expected ${expected_workflow_path}, got ${run_workflow_path}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

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

if [[ -n "$run_head_branch" && -n "$run_head_branch_api" && "$run_head_branch" != "$run_head_branch_api" ]]; then
  echo "head_branch mismatch between summary and run details for run_id=${run_id}: ${run_head_branch} vs ${run_head_branch_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

if [[ -n "$run_attempt_api" && "$run_attempt_api" != "$run_attempt" ]]; then
  echo "run attempt mismatch between summary and run details for run_id=${run_id}: ${run_attempt} vs ${run_attempt_api}" >&2
  echo "run_url=${run_url}" >&2
  exit 1
fi

artifact_name="soenc-promotion-${run_id}-attempt-${run_attempt}"
artifact_metadata_deadline_epoch="$(( $(date -u +%s) + ARTIFACT_INDEX_WAIT_SECONDS ))"
artifact_metadata_parsed=""
while :; do
artifact_metadata_json="$(gh api "repos/${REPO}/actions/runs/${run_id}/artifacts?per_page=100&name=${artifact_name}")"
set +e
artifact_metadata_parsed="$(printf '%s\n' "$artifact_metadata_json" | python - "$artifact_name" "$run_id" <<'PY' 2>&1
import json
import re
import sys

artifact_name = sys.argv[1]
expected_run_id = sys.argv[2]
payload = json.load(sys.stdin)
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

run_dir="${OUTPUT_ROOT}/run-${run_id}-attempt-${run_attempt}"
download_dir="${run_dir}/download"
artifact_zip_path="${run_dir}/${artifact_name}.zip"
mkdir -p "$download_dir"

echo "Downloading artifact archive ${artifact_name}"
gh api "repos/${REPO}/actions/artifacts/${artifact_id}/zip" --method GET --header "Accept: application/zip" --output "$artifact_zip_path"

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
  "$capture_mode" \
  "$run_id_resolution_mode" \
  "$run_event_api" \
  "$run_head_branch_api" \
  "$run_workflow_path" \
  "$run_workflow_ref" \
  "$run_html_url_api" \
  "$run_head_sha_api" \
  "$run_number_api" \
  "$artifact_id" \
  "$artifact_digest" \
  "$artifact_size_bytes" \
  "$artifact_created_at" \
  "$artifact_updated_at" \
  "$artifact_expires_at" \
  "$artifact_archive_download_url" \
  "$artifact_workflow_run_id" \
  "$artifact_workflow_head_branch" \
  "$artifact_workflow_head_sha" \
  "$artifact_zip_path" \
  "$artifact_archive_digest_verified" \
  "$artifact_archive_size_bytes" \
  "$artifact_archive_entry_count" <<'PY'
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime
from datetime import timezone
from pathlib import Path

download_root = Path(sys.argv[1]).resolve()
receipt_path = Path(sys.argv[2]).resolve()
repo = sys.argv[3]
ref = sys.argv[4]
workflow_file = sys.argv[5]
run_id = sys.argv[6]
run_attempt = sys.argv[7]
run_url = sys.argv[8]
artifact_name = sys.argv[9]
rotation_rehearsal = sys.argv[10]
dispatch_utc = sys.argv[11]
capture_mode = sys.argv[12]
run_id_resolution_mode = sys.argv[13]
workflow_event = sys.argv[14]
workflow_head_branch = sys.argv[15]
workflow_path = sys.argv[16]
workflow_path_ref = sys.argv[17]
workflow_html_url = sys.argv[18]
workflow_head_sha = sys.argv[19]
workflow_run_number = sys.argv[20]
artifact_id = sys.argv[21]
artifact_digest = sys.argv[22]
artifact_size_in_bytes = sys.argv[23]
artifact_created_at = sys.argv[24]
artifact_updated_at = sys.argv[25]
artifact_expires_at = sys.argv[26]
artifact_archive_download_url = sys.argv[27]
artifact_workflow_run_id = sys.argv[28]
artifact_workflow_head_branch = sys.argv[29]
artifact_workflow_head_sha = sys.argv[30]
artifact_archive_path = sys.argv[31]
artifact_archive_digest_verified = sys.argv[32]
artifact_archive_size_bytes = sys.argv[33]
artifact_archive_entry_count = sys.argv[34]

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

rotation_report_path = resolved["rotation_rehearsal_report.json"]
try:
    rotation_report_payload = json.loads(rotation_report_path.read_text(encoding="utf-8"))
except Exception as exc:
    print("rotation_rehearsal_report.json is not valid JSON: {0}".format(exc), file=sys.stderr)
    sys.exit(1)

if not isinstance(rotation_report_payload, dict):
    print("rotation_rehearsal_report must be a JSON object", file=sys.stderr)
    sys.exit(1)

rotation_requested = rotation_report_payload.get("requested")
rotation_executed = rotation_report_payload.get("executed")
rotation_old_key_rejected = rotation_report_payload.get("old_key_rejected")
rotation_status = rotation_report_payload.get("status")

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
    if rotation_requested not in (False, None):
        print("rotation_rehearsal_report.requested must be false when rotation rehearsal is not required", file=sys.stderr)
        sys.exit(1)
    if rotation_status not in ("not-requested", None):
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

bundle_archive_path = resolved["promotion_artifact_bundle.zip"]
try:
    with zipfile.ZipFile(bundle_archive_path, "r") as bundle_archive:
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

bundle_rows_by_name = {}
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
    if not isinstance(digest_hex, str) or len(digest_hex) != 64 or any(ch not in "0123456789abcdef" for ch in digest_hex):
        print(
            "bundle_manifest.files[{0}].sha256 must be a 64-char lowercase hex digest".format(index),
            file=sys.stderr,
        )
        sys.exit(1)
    bundle_rows_by_name[name] = {
        "archive_path": archive_path,
        "sha256": digest_hex,
    }

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
if promotion_artifact_audit_report_summary.get("total_failures") != 0:
    print("promotion_artifact_audit_report.summary.total_failures must be 0", file=sys.stderr)
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
expected_rotation_pass_required = rotation_rehearsal == "true"
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

_require_run_receipt_context_key("GITHUB_REPOSITORY", repo)
_require_run_receipt_context_key("GITHUB_RUN_ID", run_id)
_require_run_receipt_context_key("GITHUB_RUN_ATTEMPT", run_attempt)
_require_run_receipt_context_key("GITHUB_ACTIONS", "true")
_require_run_receipt_context_key("CI", "true")
_require_run_receipt_context_key("GITHUB_REF_PROTECTED", "true")
if workflow_event:
    _require_run_receipt_context_key("GITHUB_EVENT_NAME", workflow_event)
if workflow_path_ref:
    _require_run_receipt_context_key("GITHUB_WORKFLOW_REF", workflow_path_ref)

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
    "workflow_event": workflow_event,
    "workflow_head_branch": workflow_head_branch or None,
    "workflow_head_sha": workflow_head_sha or None,
    "workflow_run_id": run_id,
    "workflow_run_attempt": run_attempt,
    "workflow_run_id_resolution_mode": run_id_resolution_mode,
    "workflow_run_number": _maybe_int(workflow_run_number),
    "workflow_run_url": run_url,
    "workflow_run_html_url": workflow_html_url or run_url,
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
        "manifest_sha256": hashlib.sha256(bundle_manifest_bytes).hexdigest(),
    },
    "promotion_run_receipt_verification": {
        "schema": "enc2sop-promotion-run-receipt/v1",
        "passed": True,
        "rotation_pass_required": rotation_pass_required,
        "artifact_entries_verified": sorted(required_run_receipt_entries.keys()),
        "artifact_entry_count_verified": len(required_run_receipt_entries),
    },
    "rotation_rehearsal": rotation_rehearsal == "true",
    "rotation_report_verification": {
        "requested": rotation_requested,
        "executed": rotation_executed,
        "old_key_rejected": rotation_old_key_rejected,
        "status": rotation_status,
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
