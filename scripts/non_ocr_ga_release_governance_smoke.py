#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Local GA-readiness smoke for non-OCR release governance.

This script is intentionally scoped to
``docs/working/non_ocr_ga_release_governance_plan.md``. It creates a local,
replayable evidence bundle for the first GA batch:

1. release evidence archival
2. approval-key rotation rehearsal
3. production license-file E2E fail-closed checks

It does not exercise OCR, QR, cross-media transport, remote-KMS, or external
GitHub APIs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sys
import zipfile
from contextlib import contextmanager
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Dict, Iterator, List, Mapping, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import encryption_helper
from decryption_helper import _license_key_from_ref
from enc2sop import promotion_artifacts
from enc2sop import promotion_audit
from enc2sop import promotion_bundle
from enc2sop.keys import LicenseFileKeyProvider
from scripts import non_ocr_release_gate


SMOKE_SCHEMA = "enc2sop-non-ocr-ga-governance-smoke/v1"
APPROVAL_KEY = b"ga-release-approval-key-00000001"
OLD_APPROVAL_KEY = b"ga-old-approval-key-000000000000"
MANIFEST_KEY = b"ga-manifest-signing-key-000000001"
LICENSE_KEY = b"ga-license-signing-key-0000000001"
DATA_KEY = b"0123456789abcdef0123456789abcdef"
LOCAL_GITHUB_CONTEXT = {
    "GITHUB_REPOSITORY": "local/non-ocr-ga-smoke",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_REF_NAME": "main",
    "GITHUB_REF_TYPE": "branch",
    "GITHUB_RUN_ID": "1001",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_RUN_NUMBER": "42",
    "GITHUB_RETENTION_DAYS": "90",
    "GITHUB_ACTIONS": "true",
    "CI": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "linux",
    "RUNNER_ARCH": "x64",
    "RUNNER_NAME": "local-ga-runner",
    "GITHUB_SHA": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "GITHUB_WORKFLOW": "release-promotion-gate",
    "GITHUB_WORKFLOW_REF": "local/non-ocr-ga-smoke/.github/workflows/release_promotion.yml@refs/heads/main",
    "GITHUB_WORKFLOW_SHA": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_API_URL": "https://api.github.com",
    "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
    "GITHUB_JOB": "promotion-gate",
    "GITHUB_ACTOR": "local-operator",
    "GITHUB_ACTOR_ID": "10001",
    "GITHUB_REPOSITORY_ID": "20002",
    "GITHUB_REPOSITORY_OWNER": "local",
    "GITHUB_REPOSITORY_OWNER_ID": "30003",
    "GITHUB_TRIGGERING_ACTOR": "local-operator",
    "GITHUB_REF_PROTECTED": "true",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: Mapping[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


@contextmanager
def _patched_env(values: Mapping[str, Optional[str]]) -> Iterator[None]:
    old = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _require_raises(label: str, expected: str, func) -> Dict[str, object]:
    try:
        func()
    except Exception as exc:
        message = str(exc)
        if expected not in message:
            raise AssertionError("{0} raised wrong error: {1}".format(label, message)) from exc
        return {"case": label, "passed": True, "error": message}
    raise AssertionError("{0} unexpectedly passed".format(label))


def _run_license_file_e2e(work_dir: Path) -> Dict[str, object]:
    license_dir = work_dir / "license_e2e"
    provider = LicenseFileKeyProvider()
    provider.begin_run(
        {
            "license_file": "runtime.license.json",
            "license_id": "ga-license",
            "license_subject": "ga-customer",
            "license_expires_at": "2099-01-01T00:00:00Z",
            "license_machine_fingerprint": "ga-machine",
            "license_sign_key": LICENSE_KEY,
            "license_sign_key_id": "ga-license-signer",
        }
    )
    key_ref = provider.pack_key(DATA_KEY)
    provider.finalize_run(license_dir, {"key_management": {"mode": "license-file"}})
    license_path = license_dir / "runtime.license.json"
    revocation_path = license_dir / "revoked.json"
    verify_key_b64 = base64.b64encode(LICENSE_KEY).decode("ascii")
    wrong_key_b64 = base64.b64encode(b"wrong-license-signing-key-000001").decode("ascii")

    cases = []
    with _patched_env(
        {
            "SOENC_LICENSE_FILE": str(license_path),
            "SOENC_LICENSE_VERIFY_KEY_B64": verify_key_b64,
            "SOENC_MACHINE_FINGERPRINT": "ga-machine",
            "SOENC_LICENSE_REVOCATION_FILE": None,
        }
    ):
        resolved = _license_key_from_ref(key_ref)
        if resolved != DATA_KEY:
            raise AssertionError("license-file happy path returned wrong key")
        cases.append({"case": "happy_path", "passed": True})

    with _patched_env(
        {
            "SOENC_LICENSE_FILE": None,
            "SOENC_LICENSE_VERIFY_KEY_B64": verify_key_b64,
            "SOENC_MACHINE_FINGERPRINT": "ga-machine",
            "SOENC_LICENSE_REVOCATION_FILE": None,
        }
    ):
        cases.append(_require_raises("missing_license", "SOENC_LICENSE_FILE is required", lambda: _license_key_from_ref(key_ref)))

    with _patched_env(
        {
            "SOENC_LICENSE_FILE": str(license_path),
            "SOENC_LICENSE_VERIFY_KEY_B64": wrong_key_b64,
            "SOENC_MACHINE_FINGERPRINT": "ga-machine",
            "SOENC_LICENSE_REVOCATION_FILE": None,
        }
    ):
        cases.append(_require_raises("signature_error", "license signature mismatch", lambda: _license_key_from_ref(key_ref)))

    with _patched_env(
        {
            "SOENC_LICENSE_FILE": str(license_path),
            "SOENC_LICENSE_VERIFY_KEY_B64": verify_key_b64,
            "SOENC_MACHINE_FINGERPRINT": "wrong-machine",
            "SOENC_LICENSE_REVOCATION_FILE": None,
        }
    ):
        cases.append(_require_raises("machine_mismatch", "machine fingerprint mismatch", lambda: _license_key_from_ref(key_ref)))

    expired_provider = LicenseFileKeyProvider()
    expired_provider.begin_run(
        {
            "license_file": "expired.license.json",
            "license_id": "ga-expired",
            "license_expires_at": "2000-01-01T00:00:00Z",
            "license_sign_key": LICENSE_KEY,
            "license_sign_key_id": "ga-license-signer",
        }
    )
    expired_key_ref = expired_provider.pack_key(DATA_KEY)
    expired_provider.finalize_run(license_dir, {"key_management": {"mode": "license-file"}})
    with _patched_env(
        {
            "SOENC_LICENSE_FILE": str(license_dir / "expired.license.json"),
            "SOENC_LICENSE_VERIFY_KEY_B64": verify_key_b64,
            "SOENC_MACHINE_FINGERPRINT": None,
            "SOENC_LICENSE_REVOCATION_FILE": None,
        }
    ):
        cases.append(_require_raises("expired", "license has expired", lambda: _license_key_from_ref(expired_key_ref)))

    revocation_path.write_text(json.dumps({"revoked_license_ids": ["ga-license"]}, indent=2), encoding="utf-8")
    with _patched_env(
        {
            "SOENC_LICENSE_FILE": str(license_path),
            "SOENC_LICENSE_VERIFY_KEY_B64": verify_key_b64,
            "SOENC_MACHINE_FINGERPRINT": "ga-machine",
            "SOENC_LICENSE_REVOCATION_FILE": str(revocation_path),
        }
    ):
        cases.append(_require_raises("revoked", "license has been revoked", lambda: _license_key_from_ref(key_ref)))

    return {
        "passed": all(bool(item.get("passed")) for item in cases),
        "license_file": str(license_path),
        "revocation_file": str(revocation_path),
        "cases": cases,
    }


def _write_config(work_dir: Path, dist_dir: Path) -> Path:
    keys_dir = work_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "manifest.key").write_bytes(MANIFEST_KEY)
    (keys_dir / "license.key").write_bytes(LICENSE_KEY)
    (keys_dir / "approval.key").write_bytes(APPROVAL_KEY)
    config = work_dir / "soenc.production.toml"
    config.write_text(
        "\n".join(
            [
                "[build]",
                'output_dir = "./protected_build"',
                'dist_dir = "{0}"'.format(dist_dir.as_posix()),
                "compile = true",
                "runtime_native_loader = true",
                'build_profile = "auto"',
                'hardening_profile = "balanced"',
                "",
                "[keys]",
                'mode = "license-file"',
                'license_file = "licenses/production.license.json"',
                'license_id = "ga-mainline-license"',
                "bundle_license = false",
                "require_manifest_signature = true",
                'manifest_sign_key_file = "keys/manifest.key"',
                'manifest_key_id = "ga-manifest"',
                'license_sign_key_file = "keys/license.key"',
                'license_sign_key_id = "ga-license-signer"',
                "",
                "[release]",
                "require_approval = true",
                'approval_file = "{0}"'.format((dist_dir / "release_approval.json").as_posix()),
                'approval_key_file = "keys/approval.key"',
                'approval_key_id = "ga-release-approval"',
                "",
                "[package]",
                'name = "enc2sop-ga-governance-fixture"',
                'version = "0.1.0-ga-smoke"',
                'channel = "ga-smoke"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config


def _write_release_dist(dist_dir: Path) -> None:
    pkg = dist_dir / "pkg"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    runtime_native = pkg / "enc_rt_demo.pyd"
    runtime_native.write_bytes(b"runtime-native")
    module_native = pkg / "mod.pyd"
    module_native.write_bytes(b"module-native")
    runtime_digest = encryption_helper._sha256_file(runtime_native)
    manifest_payload = {
        "runtime_files": ["pkg/enc_rt_demo.py"],
        "runtime_delivery": {
            "loader_mode": encryption_helper.RUNTIME_LOADER_MODE_NATIVE_ONLY,
            "loader_enforced": True,
            "validated": True,
            "compiled_runtime_files": ["pkg/enc_rt_demo.pyd"],
            "compiled_runtime_fingerprints": [
                {
                    "module_name": "enc_rt_demo",
                    "source_relative_path": "pkg/enc_rt_demo.py",
                    "compiled_relative_path": "pkg/enc_rt_demo.pyd",
                    "package_relative_path": "pkg",
                    "algorithm": "sha256",
                    "digest_hex": runtime_digest,
                }
            ],
        },
        "key_management": {
            "mode": "license-file",
            "license_file": "licenses/production.license.json",
            "license_path_policy": encryption_helper.LICENSE_PATH_POLICY_ENV_ONLY,
            "runtime_env": encryption_helper.LICENSE_FILE_ENV,
            "bundle_license": False,
            "license_signature_required": True,
            "license_signature_key_id": "ga-license-signer",
            "license_verify_key_env": "SOENC_LICENSE_VERIFY_KEY_B64",
        },
        "build_hardening": {
            "profile": "balanced",
            "native_build_required": True,
        },
    }
    encryption_helper.write_manifest(dist_dir, manifest_payload, signing_key=MANIFEST_KEY, key_id="ga-manifest")
    signed_manifest = json.loads((dist_dir / "build_manifest.json").read_text(encoding="utf-8"))
    release_bundle = {
        "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
        "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
        "build_manifest": {
            "relative_path": "build_manifest.json",
            "is_signed": True,
            "signature": signed_manifest["signature"],
        },
        "bundle_contents": {
            "native_extension_files": ["pkg/enc_rt_demo.pyd", "pkg/mod.pyd"],
            "runtime_compiled_files": ["pkg/enc_rt_demo.pyd"],
            "package_init_files": ["pkg/__init__.py"],
            "license_file": {
                "delivery": "external",
                "externalized": True,
                "bundled": False,
                "source_relative_path": "licenses/production.license.json",
                "runtime_env": encryption_helper.LICENSE_FILE_ENV,
                "required_for_runtime": True,
            },
        },
        "runtime_integrity": {
            "validated": True,
            "compiled_runtime_fingerprints": manifest_payload["runtime_delivery"]["compiled_runtime_fingerprints"],
        },
    }
    (dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
        json.dumps(release_bundle, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    with _patched_env(LOCAL_GITHUB_CONTEXT):
        approval_path, _approval = encryption_helper.write_release_approval(
            dist_dir=str(dist_dir),
            approvers=["ga-ops", "ga-security"],
            approval_key=APPROVAL_KEY,
            approval_key_id="ga-release-approval",
            notes="local ga governance smoke",
        )
        encryption_helper.write_release_receipt(
            dist_dir=str(dist_dir),
            required_manifest_signature=True,
            key_mode="license-file",
            package_metadata={"name": "enc2sop-ga-governance-fixture", "channel": "ga-smoke"},
            require_approval=True,
            approval_file=str(approval_path),
            approval_key=APPROVAL_KEY,
            approval_key_id="ga-release-approval",
        )

def _run_rotation_rehearsal(dist_dir: Path, ops_dir: Path) -> Dict[str, object]:
    rotation_dir = ops_dir / "rotation_release_copy"
    if rotation_dir.exists():
        shutil.rmtree(str(rotation_dir))
    shutil.copytree(str(dist_dir), str(rotation_dir))
    try:
        encryption_helper.write_release_receipt(
            dist_dir=str(rotation_dir),
            required_manifest_signature=True,
            key_mode="license-file",
            package_metadata={"name": "enc2sop-ga-governance-fixture", "channel": "ga-smoke"},
            require_approval=True,
            approval_file=str(rotation_dir / "release_approval.json"),
            approval_key=OLD_APPROVAL_KEY,
            approval_key_id="ga-release-approval",
        )
    except Exception as exc:
        old_key_rejected = True
        details = str(exc)
    else:
        old_key_rejected = False
        details = "old approval key unexpectedly passed release gate"
    report = {
        "schema": promotion_artifacts.ROTATION_REHEARSAL_SCHEMA,
        "generated_at_utc": _utc_now(),
        "requested": True,
        "executed": True,
        "old_key_rejected": old_key_rejected,
        "status": "passed" if old_key_rejected else "failed",
        "details": details,
    }
    path = _write_json(ops_dir / "rotation_rehearsal_report.json", report)
    return {"path": str(path), "passed": old_key_rejected, "details": details}


def _write_promotion_evidence(ops_dir: Path) -> Path:
    payload = {
        "schema": promotion_audit.PROMOTION_EVIDENCE_SCHEMA,
        "generated_at_utc": _utc_now(),
        "repository": "local/non-ocr-ga-smoke",
        "github_context": dict(LOCAL_GITHUB_CONTEXT),
        "branches": [
            {"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]},
            {"name": "release/**", "required_status_checks": ["Signed Approval Promotion Gate"]},
        ],
        "environments": [{"name": "production-promotion", "required_reviewers_count": 1}],
        "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
    }
    promotion_audit.normalize_promotion_evidence_payload(payload)
    return _write_json(ops_dir / "promotion_evidence.json", payload)


def _run_release_governance(work_dir: Path) -> Dict[str, object]:
    dist_dir = work_dir / "release"
    ops_dir = work_dir / "ops"
    dist_dir.mkdir(parents=True, exist_ok=True)
    ops_dir.mkdir(parents=True, exist_ok=True)
    config_path = _write_config(work_dir, dist_dir)
    _write_release_dist(dist_dir)
    evidence_path = _write_promotion_evidence(ops_dir)
    promotion_report_path, promotion_report = promotion_audit.run_promotion_audit(
        evidence_file=str(evidence_path),
        policy_file=str(REPO_ROOT / "docs" / "PROMOTION_ROLLOUT_POLICY.json"),
        workflow_file=str(REPO_ROOT / ".github" / "workflows" / "release_promotion.yml"),
        report_file=str(ops_dir / "promotion_audit_report.json"),
        repo_root=REPO_ROOT,
    )
    rotation = _run_rotation_rehearsal(dist_dir, ops_dir)
    artifact_report_path, artifact_report = promotion_artifacts.run_promotion_artifact_audit(
        dist_dir=str(dist_dir),
        promotion_evidence_file=str(evidence_path),
        promotion_report_file=str(promotion_report_path),
        rotation_report_file=rotation["path"],
        release_approval_key_b64=base64.b64encode(APPROVAL_KEY).decode("ascii"),
        release_approval_key_id="ga-release-approval",
        promotion_policy_file=str(REPO_ROOT / "docs" / "PROMOTION_ROLLOUT_POLICY.json"),
        promotion_workflow_file=str(REPO_ROOT / ".github" / "workflows" / "release_promotion.yml"),
        report_file=str(ops_dir / promotion_artifacts.DEFAULT_REPORT_FILENAME),
        run_receipt_file=str(ops_dir / promotion_artifacts.DEFAULT_RUN_RECEIPT_FILENAME),
        require_release_approval_signature=True,
        require_rotation_pass=True,
        require_ci_context_match=False,
        require_artifact_context_consistency=False,
        repo_root=REPO_ROOT,
    )
    run_receipt_path = Path(str(artifact_report.get("promotion_run_receipt_file")))
    bundle_path, bundle_manifest = promotion_bundle.create_promotion_artifact_bundle(
        dist_dir=str(dist_dir),
        promotion_evidence_file=str(evidence_path),
        promotion_report_file=str(promotion_report_path),
        rotation_report_file=rotation["path"],
        promotion_artifact_audit_report_file=str(artifact_report_path),
        promotion_run_receipt_file=str(run_receipt_path),
        promotion_policy_file=str(REPO_ROOT / "docs" / "PROMOTION_ROLLOUT_POLICY.json"),
        promotion_workflow_file=str(REPO_ROOT / ".github" / "workflows" / "release_promotion.yml"),
        bundle_file=str(ops_dir / promotion_bundle.DEFAULT_BUNDLE_FILENAME),
        repo_root=REPO_ROOT,
    )
    gate_report_path = ops_dir / "non_ocr_release_gate_report.json"
    gate_code = non_ocr_release_gate.main(
        [
            "--config",
            str(config_path),
            "--dist-dir",
            str(dist_dir),
            "--promotion-bundle",
            str(bundle_path),
            "--require-key-files-exist",
            "--report",
            str(gate_report_path),
        ]
    )
    gate_report = json.loads(gate_report_path.read_text(encoding="utf-8"))
    with zipfile.ZipFile(bundle_path, "r") as zipped:
        bundle_entries = sorted(zipped.namelist())
    return {
        "passed": bool(promotion_report.get("passed"))
        and bool(rotation.get("passed"))
        and bool(artifact_report.get("passed"))
        and gate_code == 0
        and bool(gate_report.get("passed")),
        "dist_dir": str(dist_dir),
        "ops_dir": str(ops_dir),
        "config": str(config_path),
        "release_bundle": str(dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME),
        "release_approval": str(dist_dir / "release_approval.json"),
        "release_receipt": str(dist_dir / encryption_helper.RELEASE_RECEIPT_FILENAME),
        "release_tamper_report": str(dist_dir / encryption_helper.RELEASE_TAMPER_REPORT_FILENAME),
        "promotion_evidence": str(evidence_path),
        "promotion_audit_report": str(promotion_report_path),
        "rotation_rehearsal_report": rotation["path"],
        "promotion_artifact_audit_report": str(artifact_report_path),
        "promotion_run_receipt": str(run_receipt_path),
        "promotion_artifact_bundle": str(bundle_path),
        "promotion_artifact_bundle_sha256": bundle_manifest.get("bundle_sha256"),
        "promotion_artifact_bundle_entries": bundle_entries,
        "non_ocr_release_gate_report": str(gate_report_path),
        "non_ocr_release_gate_passed": bool(gate_report.get("passed")),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run local non-OCR GA governance smoke.")
    parser.add_argument("--work-dir", help="Working directory. Defaults to .tmp_non_ocr_ga_governance_smoke.")
    parser.add_argument("--report", help="Optional JSON report path. Defaults to <work-dir>/non_ocr_ga_governance_smoke_report.json.")
    parser.add_argument("--keep-work-dir", action="store_true", help="Do not delete an existing work directory before running.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    work_dir = Path(args.work_dir or (REPO_ROOT / ".tmp_non_ocr_ga_governance_smoke")).expanduser()
    if not work_dir.is_absolute():
        work_dir = (Path.cwd() / work_dir).resolve()
    if work_dir.exists() and not args.keep_work_dir:
        shutil.rmtree(str(work_dir))
    work_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(args.report).expanduser().resolve() if args.report else (work_dir / "non_ocr_ga_governance_smoke_report.json")

    failures: List[str] = []
    release_governance: Dict[str, object] = {}
    license_e2e: Dict[str, object] = {}
    try:
        release_governance = _run_release_governance(work_dir)
        if not release_governance.get("passed"):
            failures.append("release governance evidence did not pass")
    except Exception as exc:
        failures.append("release governance failed: {0}".format(exc))
    try:
        license_e2e = _run_license_file_e2e(work_dir)
        if not license_e2e.get("passed"):
            failures.append("license-file E2E did not pass")
    except Exception as exc:
        failures.append("license-file E2E failed: {0}".format(exc))

    report = {
        "schema": SMOKE_SCHEMA,
        "generated_at_utc": _utc_now(),
        "work_dir": str(work_dir),
        "passed": not failures,
        "summary": {
            "total_failures": len(failures),
            "release_governance_passed": bool(release_governance.get("passed")),
            "license_file_e2e_passed": bool(license_e2e.get("passed")),
        },
        "failures": failures,
        "release_governance": release_governance,
        "license_file_e2e": license_e2e,
    }
    _write_json(report_path, report)
    print("non_ocr_ga_governance_smoke_report={0}".format(report_path))
    if failures:
        print("NON_OCR_GA_GOVERNANCE_SMOKE_FAILED failures={0}".format(len(failures)))
        for failure in failures:
            print("failure={0}".format(failure))
        return 1
    print("NON_OCR_GA_GOVERNANCE_SMOKE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
