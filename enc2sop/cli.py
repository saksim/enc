#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unified CLI entrypoint for the enc2sop mainline flow."""

import argparse
import os
import sys
from pathlib import Path
from typing import Optional
from typing import Sequence

import encryption_helper
from enc2sop import plugin_registry
from enc2sop import promotion_artifacts
from enc2sop import promotion_audit
from enc2sop import promotion_evidence
from soenc_config import SoencProjectConfig
from soenc_config import load_project_config
from toolchain_profile import DEFAULT_BUILD_PROFILE
from toolchain_profile import SUPPORTED_BUILD_PROFILES
from toolchain_profile import resolve_python_executable


def _option_present(argv: Sequence[str], option_name: str) -> bool:
    for item in argv:
        if item == option_name or item.startswith(option_name + "="):
            return True
    return False


def _load_project_config(path: Optional[str]) -> Optional[SoencProjectConfig]:
    return load_project_config(config_path=path, base_dir=Path.cwd())


def _project_default(project_config: Optional[SoencProjectConfig], field: str):
    if project_config is None:
        return None
    return project_config.cli_defaults.get(field)


def _resolve_staging_dir(args, project_config: Optional[SoencProjectConfig]) -> Path:
    staging_value = args.staging_dir or _project_default(project_config, "output_dir")
    if not staging_value:
        raise ValueError("--staging-dir is required (or configure [build].output_dir in soenc.toml)")
    staging_dir = encryption_helper.normalize_path(staging_value)
    if not staging_dir.exists():
        raise FileNotFoundError("staging directory not found: {0}".format(staging_dir))
    return staging_dir


def _resolve_build_dir(args, staging_dir: Path) -> Path:
    build_value = args.build_dir if getattr(args, "build_dir", None) else str(staging_dir / "build")
    build_dir = encryption_helper.normalize_path(build_value)
    if not build_dir.exists():
        raise FileNotFoundError("build directory not found: {0}".format(build_dir))
    return build_dir


def _resolve_manifest_sign_key(args, project_config: Optional[SoencProjectConfig]):
    key_file_text = args.manifest_sign_key_file or _project_default(project_config, "manifest_sign_key_file")
    key_file = encryption_helper.normalize_path(key_file_text) if key_file_text else None
    key_b64 = args.manifest_sign_key_b64
    return encryption_helper._load_manifest_sign_key(key_file=key_file, key_b64=key_b64)


def _resolve_require_manifest_signature(args, project_config: Optional[SoencProjectConfig]) -> bool:
    if args.require_manifest_signature is not None:
        return bool(args.require_manifest_signature)
    config_value = _project_default(project_config, "require_manifest_signature")
    return bool(config_value) if config_value is not None else False


def _resolve_require_release_approval(args, project_config: Optional[SoencProjectConfig]) -> bool:
    if args.require_release_approval is not None:
        return bool(args.require_release_approval)
    config_value = _project_default(project_config, "require_release_approval")
    return bool(config_value) if config_value is not None else False


def _run_protect(args) -> int:
    forwarded = list(args.forwarded or [])
    if _option_present(forwarded, "--compile") or _option_present(forwarded, "--dist-dir"):
        raise ValueError("soenc protect only supports staging protection; use 'soenc build' and 'soenc package'")
    forwarded.append("--no-compile")
    try:
        return int(encryption_helper.main(forwarded))
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        return 0


def _run_build(args) -> int:
    project_config = _load_project_config(args.config)
    staging_dir = _resolve_staging_dir(args, project_config)
    build_profile = args.build_profile or _project_default(project_config, "build_profile") or DEFAULT_BUILD_PROFILE
    vcvars_text = args.vcvars_path or _project_default(project_config, "vcvars_path")
    vcvars_path = encryption_helper.normalize_path(vcvars_text) if vcvars_text else None
    python_exe_text = args.python_exe or _project_default(project_config, "python_exe")
    python_exe = resolve_python_executable(python_exe_text)
    if not python_exe.exists():
        raise FileNotFoundError("python executable not found: {0}".format(python_exe))
    manifest_sign_key = _resolve_manifest_sign_key(args, project_config)
    require_manifest_signature = _resolve_require_manifest_signature(args, project_config)
    if require_manifest_signature and manifest_sign_key is None:
        raise ValueError("--require-manifest-signature requires --manifest-sign-key-file or --manifest-sign-key-b64")

    build_dir = encryption_helper.compile_with_batch_builder(
        python_exe=python_exe,
        output_dir=staging_dir,
        build_profile=build_profile,
        vcvars_path=vcvars_path,
        manifest_sign_key=manifest_sign_key,
        require_manifest_signature=require_manifest_signature,
    )
    print("staging_dir={0}".format(staging_dir))
    print("build_dir={0}".format(build_dir))
    print("build_profile={0}".format(build_profile))
    return 0


def _run_package(args) -> int:
    project_config = _load_project_config(args.config)
    staging_dir = _resolve_staging_dir(args, project_config)
    build_dir = _resolve_build_dir(args, staging_dir)
    dist_value = args.dist_dir or _project_default(project_config, "dist_dir")
    if not dist_value:
        raise ValueError("--dist-dir is required (or configure [build].dist_dir in soenc.toml)")
    dist_dir = encryption_helper.normalize_path(dist_value)
    require_manifest_signature = _resolve_require_manifest_signature(args, project_config)
    package_metadata = project_config.package_metadata if project_config is not None else None

    actual_dist_dir, copied_files = encryption_helper.copy_release(
        build_dir=build_dir,
        dist_dir=dist_dir,
        staging_dir=staging_dir,
        package_metadata=package_metadata,
        require_manifest_signature=require_manifest_signature,
    )
    print("staging_dir={0}".format(staging_dir))
    print("build_dir={0}".format(build_dir))
    print("dist_dir={0}".format(actual_dist_dir))
    print("copied_files={0}".format(len(copied_files)))
    return 0


def _run_verify(args) -> int:
    project_config = _load_project_config(args.config)
    staging_dir = _resolve_staging_dir(args, project_config)
    build_dir = _resolve_build_dir(args, staging_dir)
    manifest_sign_key = _resolve_manifest_sign_key(args, project_config)
    require_manifest_signature = _resolve_require_manifest_signature(args, project_config)
    if require_manifest_signature and manifest_sign_key is None:
        raise ValueError("--require-manifest-signature requires --manifest-sign-key-file or --manifest-sign-key-b64")

    compiled_runtime_files = encryption_helper.validate_runtime_delivery(
        staging_dir=staging_dir,
        build_dir=build_dir,
        signing_key=manifest_sign_key,
        require_manifest_signature=require_manifest_signature,
    )
    print("staging_dir={0}".format(staging_dir))
    print("build_dir={0}".format(build_dir))
    print("verified_runtime_files={0}".format(len(compiled_runtime_files)))
    for runtime_file in compiled_runtime_files:
        print("runtime={0}".format(runtime_file))
    return 0


def _run_release(args) -> int:
    project_config = _load_project_config(args.config)
    dist_value = args.dist_dir or _project_default(project_config, "dist_dir")
    if not dist_value:
        raise ValueError("--dist-dir is required (or configure [build].dist_dir in soenc.toml)")
    dist_dir = encryption_helper.normalize_path(dist_value)
    require_manifest_signature = _resolve_require_manifest_signature(args, project_config)
    require_release_approval = _resolve_require_release_approval(args, project_config)
    approval_file_value = args.release_approval_file or _project_default(project_config, "release_approval_file")
    approval_key_file_value = args.release_approval_key_file or _project_default(project_config, "release_approval_key_file")
    approval_key_id = args.release_approval_key_id or _project_default(project_config, "release_approval_key_id")
    approval_key_file = encryption_helper.normalize_path(approval_key_file_value) if approval_key_file_value else None
    approval_key = encryption_helper.load_release_approval_key(
        key_file=approval_key_file,
        key_b64=args.release_approval_key_b64,
    )
    if require_release_approval and approval_key is None:
        raise ValueError(
            "--require-release-approval requires --release-approval-key-file or --release-approval-key-b64"
        )
    package_metadata = project_config.package_metadata if project_config is not None else None
    key_mode = project_config.key_mode if project_config is not None else None

    receipt_path, receipt = encryption_helper.write_release_receipt(
        dist_dir=dist_dir,
        required_manifest_signature=require_manifest_signature,
        key_mode=key_mode,
        package_metadata=package_metadata,
        require_approval=require_release_approval,
        approval_file=approval_file_value,
        approval_key=approval_key,
        approval_key_id=approval_key_id,
    )
    print("dist_dir={0}".format(dist_dir))
    print("release_bundle={0}".format(encryption_helper.release_bundle_path(dist_dir)))
    print("release_receipt={0}".format(receipt_path))
    print("manifest_signature_present={0}".format(receipt.get("manifest_signature_present")))
    print("runtime_artifacts_verified={0}".format(receipt.get("runtime_artifacts_verified")))
    print("release_approval_verified={0}".format(receipt.get("release_approval_verified")))
    return 0


def _run_approve_release(args) -> int:
    project_config = _load_project_config(args.config)
    dist_value = args.dist_dir or _project_default(project_config, "dist_dir")
    if not dist_value:
        raise ValueError("--dist-dir is required (or configure [build].dist_dir in soenc.toml)")
    dist_dir = encryption_helper.normalize_path(dist_value)
    approval_file_value = args.release_approval_file or _project_default(project_config, "release_approval_file")
    approval_key_file_value = args.release_approval_key_file or _project_default(project_config, "release_approval_key_file")
    approval_key_id = args.release_approval_key_id or _project_default(project_config, "release_approval_key_id")
    approval_key_file = encryption_helper.normalize_path(approval_key_file_value) if approval_key_file_value else None
    approval_key = encryption_helper.load_release_approval_key(
        key_file=approval_key_file,
        key_b64=args.release_approval_key_b64,
    )
    if approval_key is None:
        raise ValueError(
            "approve-release requires --release-approval-key-file or --release-approval-key-b64"
        )
    approval_path, payload = encryption_helper.write_release_approval(
        dist_dir=dist_dir,
        approvers=args.approver,
        approval_key=approval_key,
        approval_file=approval_file_value,
        approval_key_id=approval_key_id,
        approved_at_utc=args.approved_at_utc,
        notes=args.notes,
    )
    print("dist_dir={0}".format(dist_dir))
    print("release_bundle={0}".format(encryption_helper.release_bundle_path(dist_dir)))
    print("release_approval={0}".format(approval_path))
    print("approvers={0}".format(",".join(payload.get("approvers") or [])))
    print("release_bundle_sha256={0}".format(payload.get("release_bundle_sha256")))
    print("release_approval_key_id={0}".format(payload.get("signature", {}).get("key_id")))
    return 0


def _run_transport(args) -> int:
    forwarded = list(args.forwarded or [])
    if not forwarded:
        print("available optional plugins:")
        for row in plugin_registry.plugin_help_rows():
            print("  {0}".format(row))
        print("usage: soenc transport <plugin-subcommand> [args]")
        print("example: soenc transport export -i artifact.bin -o ./pkg")
        return 0
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]
    if not forwarded:
        raise ValueError("transport command requires plugin subcommand arguments")
    return plugin_registry.invoke_plugin_command("transport", forwarded)


def _run_audit_promotion(args) -> int:
    report_path, report = promotion_audit.run_promotion_audit(
        evidence_file=args.evidence_file,
        policy_file=args.policy_file,
        workflow_file=args.workflow_file,
        report_file=args.report_file,
        repo_root=Path.cwd(),
    )
    failures = report.get("failures") or []
    print("promotion_policy={0}".format(args.policy_file or promotion_audit.DEFAULT_POLICY_RELATIVE_PATH))
    print("promotion_evidence={0}".format(args.evidence_file))
    print("promotion_audit_report={0}".format(report_path))
    print("promotion_audit_passed={0}".format(bool(report.get("passed"))))
    print("promotion_audit_failures={0}".format(len(failures)))
    for item in failures:
        print("failure={0}".format(item))
    return 0 if report.get("passed") else 1


def _run_collect_promotion_evidence(args) -> int:
    token = args.github_token or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError(
            "collect-promotion-evidence requires --github-token or GITHUB_TOKEN environment variable"
        )
    repo = args.github_repo or os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise ValueError(
            "collect-promotion-evidence requires --github-repo or GITHUB_REPOSITORY environment variable"
        )
    evidence_path, payload = promotion_evidence.collect_promotion_evidence(
        repo=repo,
        token=token,
        policy_file=args.policy_file,
        evidence_file=args.evidence_file,
        api_base_url=args.github_api_url,
        repo_root=Path.cwd(),
    )
    print("promotion_policy={0}".format(args.policy_file or promotion_audit.DEFAULT_POLICY_RELATIVE_PATH))
    print("promotion_evidence={0}".format(evidence_path))
    print("promotion_repository={0}".format(payload.get("repository")))
    print("promotion_branches={0}".format(len(payload.get("branches") or [])))
    print("promotion_environments={0}".format(len(payload.get("environments") or [])))
    print("promotion_required_secrets_found={0}".format(len(payload.get("secrets") or [])))
    return 0


def _run_promotion_dry_run(args) -> int:
    evidence_file = args.evidence_file
    if args.skip_collect:
        if not evidence_file:
            raise ValueError("promotion-dry-run --skip-collect requires --evidence-file")
        evidence_path = encryption_helper.normalize_path(evidence_file)
        if not evidence_path.exists():
            raise FileNotFoundError("promotion evidence file not found: {0}".format(evidence_path))
    else:
        token = args.github_token or os.environ.get("GITHUB_TOKEN")
        if not token:
            raise ValueError(
                "promotion-dry-run requires --github-token or GITHUB_TOKEN environment variable"
            )
        repo = args.github_repo or os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            raise ValueError(
                "promotion-dry-run requires --github-repo or GITHUB_REPOSITORY environment variable"
            )
        evidence_path, payload = promotion_evidence.collect_promotion_evidence(
            repo=repo,
            token=token,
            policy_file=args.policy_file,
            evidence_file=evidence_file,
            api_base_url=args.github_api_url,
            repo_root=Path.cwd(),
        )
        print("promotion_repository={0}".format(payload.get("repository")))
        print("promotion_branches={0}".format(len(payload.get("branches") or [])))
        print("promotion_environments={0}".format(len(payload.get("environments") or [])))
        print("promotion_required_secrets_found={0}".format(len(payload.get("secrets") or [])))

    report_path, report = promotion_audit.run_promotion_audit(
        evidence_file=str(evidence_path),
        policy_file=args.policy_file,
        workflow_file=args.workflow_file,
        report_file=args.report_file,
        repo_root=Path.cwd(),
    )
    failures = report.get("failures") or []
    print("promotion_policy={0}".format(args.policy_file or promotion_audit.DEFAULT_POLICY_RELATIVE_PATH))
    print("promotion_evidence={0}".format(evidence_path))
    print("promotion_audit_report={0}".format(report_path))
    print("promotion_dry_run_passed={0}".format(bool(report.get("passed"))))
    print("promotion_audit_failures={0}".format(len(failures)))
    for item in failures:
        print("failure={0}".format(item))
    return 0 if report.get("passed") else 1


def _run_verify_promotion_artifacts(args) -> int:
    report_path, report = promotion_artifacts.run_promotion_artifact_audit(
        dist_dir=args.dist_dir,
        promotion_evidence_file=args.promotion_evidence_file,
        promotion_report_file=args.promotion_report_file,
        rotation_report_file=args.rotation_report_file,
        release_approval_key_file=args.release_approval_key_file,
        release_approval_key_b64=args.release_approval_key_b64,
        release_approval_key_id=args.release_approval_key_id,
        promotion_policy_file=args.promotion_policy_file,
        promotion_workflow_file=args.promotion_workflow_file,
        report_file=args.report_file,
        run_receipt_file=args.run_receipt_file,
        require_release_approval_signature=args.require_release_approval_signature,
        require_rotation_pass=args.require_rotation_pass,
        require_ci_context_match=args.require_ci_context_match,
        require_artifact_context_consistency=args.require_artifact_context_consistency,
        repo_root=Path.cwd(),
    )
    failures = report.get("failures") or []
    print("promotion_artifact_audit_report={0}".format(report_path))
    print("promotion_run_receipt={0}".format(report.get("promotion_run_receipt_file")))
    print("promotion_artifact_audit_passed={0}".format(bool(report.get("passed"))))
    print("promotion_artifact_audit_failures={0}".format(len(failures)))
    for item in failures:
        print("failure={0}".format(item))
    return 0 if report.get("passed") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soenc",
        description="Unified enc2sop platform CLI (protect -> build -> package -> verify -> release).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    protect_parser = subparsers.add_parser(
        "protect",
        help="Protect source into encrypted staging outputs (compile step disabled for this command).",
    )
    protect_parser.add_argument(
        "forwarded",
        nargs="*",
        help="Arguments forwarded to encryption_helper.py protect flow (for example: -t src -o out --scope-config scope.json).",
    )
    protect_parser.set_defaults(handler=_run_protect)

    build_parser = subparsers.add_parser(
        "build",
        help="Compile an existing staging directory into native runtime artifacts.",
    )
    build_parser.add_argument("--config", "-c", help="Optional soenc.toml path.")
    build_parser.add_argument("--staging-dir", "-s", help="Staging directory containing encrypted .py outputs.")
    build_parser.add_argument("--python-exe", help="Python interpreter used for batch compile.")
    build_parser.add_argument(
        "--build-profile",
        choices=SUPPORTED_BUILD_PROFILES,
        help="Build profile used for native compile.",
    )
    build_parser.add_argument("--vcvars-path", help="Optional explicit vcvars64.bat path for windows-msvc profile.")
    build_parser.add_argument(
        "--manifest-sign-key-file",
        help="Path to manifest signing key bytes used for verify/re-sign during runtime delivery validation.",
    )
    build_parser.add_argument(
        "--manifest-sign-key-b64",
        help="Base64-encoded manifest signing key bytes. Alternative to --manifest-sign-key-file.",
    )
    encryption_helper.add_tristate_flag(
        build_parser,
        "require-manifest-signature",
        "Require a valid build_manifest.json signature during runtime delivery validation.",
        "Do not require manifest signature validation.",
    )
    build_parser.set_defaults(handler=_run_build)

    package_parser = subparsers.add_parser(
        "package",
        help="Copy compiled native artifacts and metadata into a release directory.",
    )
    package_parser.add_argument("--config", "-c", help="Optional soenc.toml path.")
    package_parser.add_argument("--staging-dir", "-s", help="Staging directory containing build_manifest.json.")
    package_parser.add_argument("--build-dir", help="Compiled build directory. Defaults to <staging-dir>/build.")
    package_parser.add_argument("--dist-dir", "-d", help="Release output directory.")
    encryption_helper.add_tristate_flag(
        package_parser,
        "require-manifest-signature",
        "Require build_manifest.json to be signed before release packaging.",
        "Allow release packaging from unsigned manifest.",
    )
    package_parser.set_defaults(handler=_run_package)

    verify_parser = subparsers.add_parser(
        "verify",
        help="Validate runtime delivery integrity for a staging/build pair.",
    )
    verify_parser.add_argument("--config", "-c", help="Optional soenc.toml path.")
    verify_parser.add_argument("--staging-dir", "-s", help="Staging directory containing build_manifest.json.")
    verify_parser.add_argument("--build-dir", help="Compiled build directory. Defaults to <staging-dir>/build.")
    verify_parser.add_argument(
        "--manifest-sign-key-file",
        help="Path to manifest signing key bytes used for signature verification.",
    )
    verify_parser.add_argument(
        "--manifest-sign-key-b64",
        help="Base64-encoded manifest signing key bytes. Alternative to --manifest-sign-key-file.",
    )
    encryption_helper.add_tristate_flag(
        verify_parser,
        "require-manifest-signature",
        "Require a valid build_manifest.json signature before runtime validation succeeds.",
        "Do not require manifest signature validation.",
    )
    verify_parser.set_defaults(handler=_run_verify)

    release_parser = subparsers.add_parser(
        "release",
        help="Validate packaged release contents and write a release receipt.",
    )
    release_parser.add_argument("--config", "-c", help="Optional soenc.toml path.")
    release_parser.add_argument("--dist-dir", "-d", help="Release directory created by soenc package.")
    release_parser.add_argument(
        "--release-approval-file",
        help="Optional release approval JSON path. Defaults to <dist-dir>/release_approval.json or [release].approval_file.",
    )
    release_parser.add_argument(
        "--release-approval-key-file",
        help="Path to HMAC key bytes used to verify release approval signature.",
    )
    release_parser.add_argument(
        "--release-approval-key-b64",
        help="Base64-encoded HMAC key bytes used to verify release approval signature.",
    )
    release_parser.add_argument(
        "--release-approval-key-id",
        help="Expected key_id in release approval signature metadata.",
    )
    encryption_helper.add_tristate_flag(
        release_parser,
        "require-manifest-signature",
        "Require build_manifest.json to be signed before release receipt generation.",
        "Allow release receipt generation from unsigned manifest.",
    )
    encryption_helper.add_tristate_flag(
        release_parser,
        "require-release-approval",
        "Require signed release approval metadata before release receipt generation.",
        "Disable signed release approval requirement even if enabled in soenc.toml.",
    )
    release_parser.set_defaults(handler=_run_release)

    approve_release_parser = subparsers.add_parser(
        "approve-release",
        help="Generate signed release approval metadata for CI promotion/signoff.",
    )
    approve_release_parser.add_argument("--config", "-c", help="Optional soenc.toml path.")
    approve_release_parser.add_argument("--dist-dir", "-d", help="Release directory created by soenc package.")
    approve_release_parser.add_argument(
        "--release-approval-file",
        help="Output path for release approval JSON. Defaults to <dist-dir>/release_approval.json or [release].approval_file.",
    )
    approve_release_parser.add_argument(
        "--release-approval-key-file",
        help="Path to HMAC key bytes used to sign release approval metadata.",
    )
    approve_release_parser.add_argument(
        "--release-approval-key-b64",
        help="Base64-encoded HMAC key bytes used to sign release approval metadata.",
    )
    approve_release_parser.add_argument(
        "--release-approval-key-id",
        help="Key identifier to write in signed release approval metadata.",
    )
    approve_release_parser.add_argument(
        "--approver",
        action="append",
        required=True,
        help="Approver identity. Specify multiple --approver flags for multi-party signoff.",
    )
    approve_release_parser.add_argument(
        "--approved-at-utc",
        help="Optional approval timestamp override (ISO8601 UTC). Defaults to current UTC time.",
    )
    approve_release_parser.add_argument(
        "--notes",
        help="Optional short approval notes persisted in release_approval.json.",
    )
    approve_release_parser.set_defaults(handler=_run_approve_release)

    transport_parser = subparsers.add_parser(
        "transport",
        help="Optional airgap transport plugin commands (export/recover/verify/analyze/ocr).",
    )
    transport_parser.add_argument(
        "forwarded",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the transport plugin command surface.",
    )
    transport_parser.set_defaults(handler=_run_transport)

    audit_promotion_parser = subparsers.add_parser(
        "audit-promotion",
        help="Validate protected-branch and environment promotion rollout evidence against policy.",
    )
    audit_promotion_parser.add_argument(
        "--evidence-file",
        required=True,
        help="JSON evidence file describing branch protection/environment rollout state.",
    )
    audit_promotion_parser.add_argument(
        "--policy-file",
        help="Optional policy JSON path. Defaults to docs/PROMOTION_ROLLOUT_POLICY.json.",
    )
    audit_promotion_parser.add_argument(
        "--workflow-file",
        help="Optional workflow override path. Defaults to policy.workflow.relative_path.",
    )
    audit_promotion_parser.add_argument(
        "--report-file",
        help="Optional output path for promotion_audit_report.json.",
    )
    audit_promotion_parser.set_defaults(handler=_run_audit_promotion)

    collect_promotion_parser = subparsers.add_parser(
        "collect-promotion-evidence",
        help="Collect promotion rollout evidence from GitHub APIs for audit-promotion.",
    )
    collect_promotion_parser.add_argument(
        "--github-repo",
        help="GitHub repository slug (owner/repo). Defaults to GITHUB_REPOSITORY.",
    )
    collect_promotion_parser.add_argument(
        "--github-token",
        help="GitHub API token. Defaults to GITHUB_TOKEN environment variable.",
    )
    collect_promotion_parser.add_argument(
        "--github-api-url",
        help="GitHub API base URL override (for GHES). Defaults to GITHUB_API_URL or https://api.github.com.",
    )
    collect_promotion_parser.add_argument(
        "--policy-file",
        help="Optional policy JSON path. Defaults to docs/PROMOTION_ROLLOUT_POLICY.json.",
    )
    collect_promotion_parser.add_argument(
        "--evidence-file",
        help="Optional output path for promotion evidence JSON.",
    )
    collect_promotion_parser.set_defaults(handler=_run_collect_promotion_evidence)

    promotion_dry_run_parser = subparsers.add_parser(
        "promotion-dry-run",
        help="Run promotion rollout dry run (collect evidence + audit) with fail-closed policy checks.",
    )
    promotion_dry_run_parser.add_argument(
        "--skip-collect",
        action="store_true",
        help="Skip GitHub API collection and audit the existing --evidence-file directly.",
    )
    promotion_dry_run_parser.add_argument(
        "--github-repo",
        help="GitHub repository slug (owner/repo). Defaults to GITHUB_REPOSITORY.",
    )
    promotion_dry_run_parser.add_argument(
        "--github-token",
        help="GitHub API token. Defaults to GITHUB_TOKEN environment variable.",
    )
    promotion_dry_run_parser.add_argument(
        "--github-api-url",
        help="GitHub API base URL override (for GHES). Defaults to GITHUB_API_URL or https://api.github.com.",
    )
    promotion_dry_run_parser.add_argument(
        "--policy-file",
        help="Optional policy JSON path. Defaults to docs/PROMOTION_ROLLOUT_POLICY.json.",
    )
    promotion_dry_run_parser.add_argument(
        "--workflow-file",
        help="Optional workflow override path. Defaults to policy.workflow.relative_path.",
    )
    promotion_dry_run_parser.add_argument(
        "--evidence-file",
        help="Optional promotion evidence output/input path. Required when --skip-collect is used.",
    )
    promotion_dry_run_parser.add_argument(
        "--report-file",
        help="Optional output path for promotion_audit_report.json.",
    )
    promotion_dry_run_parser.set_defaults(handler=_run_promotion_dry_run)

    verify_promotion_artifacts_parser = subparsers.add_parser(
        "verify-promotion-artifacts",
        help="Fail-closed integrity checks for release/promotion/rotation evidence artifacts.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--dist-dir",
        required=True,
        help="Release directory containing release_bundle.json/release_approval.json/release_receipt.json.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--promotion-evidence-file",
        required=True,
        help="Path to promotion_evidence.json artifact.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--promotion-report-file",
        required=True,
        help="Path to promotion_audit_report.json artifact.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--rotation-report-file",
        required=True,
        help="Path to rotation_rehearsal_report.json artifact.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--release-approval-key-file",
        help="Optional path to HMAC key bytes used to verify release_approval.json signature digest.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--release-approval-key-b64",
        help="Optional base64-encoded HMAC key bytes used to verify release_approval.json signature digest.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--release-approval-key-id",
        help="Optional expected key_id for release_approval.json signature metadata.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--promotion-policy-file",
        help="Optional policy JSON path used for promotion audit input binding. Defaults to docs/PROMOTION_ROLLOUT_POLICY.json.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--promotion-workflow-file",
        help="Optional workflow path used for promotion audit input binding. Defaults to policy.workflow.relative_path.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--report-file",
        help="Optional output path for promotion_artifact_audit_report.json.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--run-receipt-file",
        help="Optional output path for promotion_run_receipt.json.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--require-rotation-pass",
        action="store_true",
        help="Require rotation report status=passed with old key rejection evidence.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--require-release-approval-signature",
        action="store_true",
        help="Require release approval signature verification key and fail closed on missing/invalid signature validation.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--require-ci-context-match",
        action="store_true",
        help="Require promotion_evidence.github_context to match current GitHub runtime context.",
    )
    verify_promotion_artifacts_parser.add_argument(
        "--require-artifact-context-consistency",
        action="store_true",
        help=(
            "Require release approval/receipt, rotation report, and pre-existing run receipt "
            "GitHub context to match promotion_evidence.github_context."
        ),
    )
    verify_promotion_artifacts_parser.set_defaults(handler=_run_verify_promotion_artifacts)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    else:
        argv = list(argv)
    if argv and argv[0] == "protect":
        protect_args = argparse.Namespace(forwarded=list(argv[1:]))
        return _run_protect(protect_args)
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args))
