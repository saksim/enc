import json
import hashlib
import hmac
import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

import encryption_helper
from enc2sop import cli as soenc_cli
from enc2sop import plugin_registry
from enc2sop import promotion_artifacts
from enc2sop import promotion_bundle
from enc2sop import promotion_evidence


TEST_ROOT = Path(__file__).resolve().parents[1]
TEST_RUNS_ROOT = TEST_ROOT / ".tmp_test_runs"


def _make_case_root(prefix):
    TEST_RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    root = TEST_RUNS_ROOT / "{}_{}".format(prefix, uuid.uuid4().hex[:8])
    root.mkdir(parents=True, exist_ok=False)
    return root


class WorkspaceTempMixin(object):
    def make_case_root(self, prefix):
        root = _make_case_root(prefix)
        self.addCleanup(lambda: shutil.rmtree(str(root), ignore_errors=True))
        return root


class SoencCliTests(WorkspaceTempMixin, unittest.TestCase):
    def test_protect_command_generates_staging_manifest(self):
        root = self.make_case_root("soenc_protect")
        source = root / "main.py"
        source.write_text(
            "\n".join(
                [
                    "def secret_add(a, b):",
                    "    return a + b + 1",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        output_dir = root / "out"

        exit_code = soenc_cli.main(
            [
                "protect",
                "-t",
                str(source),
                "-o",
                str(output_dir),
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue((output_dir / "build_manifest.json").exists())
        self.assertFalse((output_dir / "build").exists())

    def test_protect_command_rejects_compile_flags(self):
        root = self.make_case_root("soenc_protect_compile_guard")
        source = root / "main.py"
        source.write_text("def ok():\n    return 1\n", encoding="utf-8")
        output_dir = root / "out"

        with self.assertRaisesRegex(ValueError, "soenc protect only supports staging protection"):
            soenc_cli.main(
                [
                    "protect",
                    "-t",
                    str(source),
                    "-o",
                    str(output_dir),
                    "--compile",
                ]
            )

    def test_build_command_reads_config_and_invokes_batch_builder(self):
        root = self.make_case_root("soenc_build")
        staging_dir = root / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        config_path = root / "soenc.toml"
        config_path.write_text(
            "\n".join(
                [
                    "[build]",
                    "output_dir = \"./staging\"",
                    "python_exe = \"{0}\"".format(str(Path(sys.executable)).replace("\\", "/")),
                    "build_profile = \"native\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        with mock.patch.object(encryption_helper, "compile_with_batch_builder", return_value=staging_dir / "build") as mocked_compile:
            exit_code = soenc_cli.main(["build", "--config", str(config_path)])

        self.assertEqual(exit_code, 0)
        mocked_compile.assert_called_once()
        self.assertEqual(mocked_compile.call_args.kwargs["output_dir"], staging_dir.resolve())
        self.assertEqual(mocked_compile.call_args.kwargs["build_profile"], "native")

    def test_build_command_cli_python_exe_overrides_config_python_exe(self):
        root = self.make_case_root("soenc_build_python_exe_override")
        staging_dir = root / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        config_path = root / "soenc.toml"
        config_path.write_text(
            "\n".join(
                [
                    "[build]",
                    "output_dir = \"./staging\"",
                    "python_exe = \"/usr/bin/python3.12\"",
                    "build_profile = \"native\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        cli_python = str(Path(sys.executable).resolve())

        with mock.patch.object(encryption_helper, "compile_with_batch_builder", return_value=staging_dir / "build") as mocked_compile:
            exit_code = soenc_cli.main(
                [
                    "build",
                    "--config",
                    str(config_path),
                    "--python-exe",
                    cli_python,
                ]
            )

        self.assertEqual(exit_code, 0)
        mocked_compile.assert_called_once()
        self.assertEqual(str(mocked_compile.call_args.kwargs["python_exe"]), cli_python)

    def test_build_command_preserves_explicit_symlink_python_path(self):
        root = self.make_case_root("soenc_build_python_symlink")
        staging_dir = root / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        real_python = root / "python-real"
        real_python.write_text("#!/bin/sh\n", encoding="utf-8")
        link_python = root / "python-link"
        try:
            os.symlink(real_python, link_python)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not supported in this environment")

        with mock.patch.object(encryption_helper, "compile_with_batch_builder", return_value=staging_dir / "build") as mocked_compile:
            exit_code = soenc_cli.main(
                [
                    "build",
                    "--staging-dir",
                    str(staging_dir),
                    "--python-exe",
                    str(link_python),
                ]
            )

        self.assertEqual(exit_code, 0)
        mocked_compile.assert_called_once()
        self.assertEqual(
            str(mocked_compile.call_args.kwargs["python_exe"]),
            str(link_python.absolute()),
        )

    def test_package_command_copies_release_files(self):
        root = self.make_case_root("soenc_package")
        staging_dir = root / "staging"
        build_dir = staging_dir / "build"
        dist_dir = root / "dist"
        (build_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (build_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (build_dir / "pkg" / "mod.pyd").write_bytes(b"native")
        (build_dir / "pkg" / "enc_rt_demo.pyd").write_bytes(b"native-rt")

        license_rel = "licenses/demo.license.json"
        (staging_dir / "licenses").mkdir(parents=True, exist_ok=True)
        (staging_dir / license_rel).write_text("{\"schema\":\"enc2sop-license/v1\"}", encoding="utf-8")
        (staging_dir / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_files": ["pkg/enc_rt_demo.py"],
                    "runtime_delivery": {
                        "validated": True,
                        "compiled_runtime_files": ["pkg/enc_rt_demo.pyd"],
                    },
                    "key_management": {"license_file": license_rel},
                }
            ),
            encoding="utf-8",
        )

        exit_code = soenc_cli.main(
            [
                "package",
                "--staging-dir",
                str(staging_dir),
                "--build-dir",
                str(build_dir),
                "--dist-dir",
                str(dist_dir),
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue((dist_dir / "pkg" / "mod.pyd").exists())
        self.assertTrue((dist_dir / "pkg" / "__init__.py").exists())
        self.assertTrue((dist_dir / "build_manifest.json").exists())
        self.assertTrue((dist_dir / license_rel).exists())
        bundle = json.loads((dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).read_text(encoding="utf-8"))
        self.assertEqual(bundle["schema"], encryption_helper.RELEASE_BUNDLE_SCHEMA)
        self.assertEqual(bundle["layout_version"], encryption_helper.RELEASE_LAYOUT_VERSION)
        self.assertTrue(bundle["bundle_contents"]["native_extension_files"])
        self.assertTrue(bundle["bundle_contents"]["runtime_compiled_files"])
        self.assertTrue(bundle["bundle_contents"]["package_init_files"])
        self.assertEqual(bundle["bundle_contents"]["license_file"]["relative_path"], license_rel)

    def test_verify_command_validates_runtime_delivery(self):
        root = self.make_case_root("soenc_verify")
        staging_dir = root / "staging"
        build_dir = staging_dir / "build"
        (staging_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (build_dir / "pkg").mkdir(parents=True, exist_ok=True)

        runtime_source_rel = "pkg/enc_rt_demo.py"
        runtime_suffix = encryption_helper.runtime_host_native_suffixes()[0]
        runtime_compiled_rel = "pkg/enc_rt_demo{0}".format(runtime_suffix)

        (staging_dir / runtime_source_rel).write_text("# runtime\n", encoding="utf-8")
        (build_dir / runtime_compiled_rel).write_bytes(b"native-runtime")

        manifest = {
            "runtime_files": [runtime_source_rel],
            "runtime_modules": [
                {
                    "module_name": "enc_rt_demo",
                    "source_relative_path": runtime_source_rel,
                    "package_relative_path": "pkg",
                }
            ],
            "runtime_delivery": {
                "loader_mode": encryption_helper.RUNTIME_LOADER_MODE_NATIVE_ONLY,
                "loader_enforced": True,
            },
        }
        (staging_dir / "build_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        exit_code = soenc_cli.main(
            [
                "verify",
                "--staging-dir",
                str(staging_dir),
                "--build-dir",
                str(build_dir),
            ]
        )

        self.assertEqual(exit_code, 0)
        loaded = json.loads((staging_dir / "build_manifest.json").read_text(encoding="utf-8"))
        runtime_delivery = loaded.get("runtime_delivery") or {}
        self.assertTrue(runtime_delivery.get("validated"))
        self.assertTrue(runtime_delivery.get("compiled_runtime_files"))
        self.assertTrue(runtime_delivery.get("compiled_runtime_fingerprints"))

    def test_package_command_requires_signature_when_config_enforced(self):
        root = self.make_case_root("soenc_package_require_sig")
        staging_dir = root / "staging"
        build_dir = staging_dir / "build"
        dist_dir = root / "dist"
        (build_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (build_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (build_dir / "pkg" / "enc_rt_demo.pyd").write_bytes(b"native")
        (staging_dir / "build_manifest.json").write_text(
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
        config_path = root / "soenc.toml"
        config_path.write_text(
            "\n".join(
                [
                    "[build]",
                    "output_dir = \"./staging\"",
                    "dist_dir = \"./dist\"",
                    "",
                    "[keys]",
                    "require_manifest_signature = true",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RuntimeError, "build manifest signature is required"):
            soenc_cli.main(["package", "--config", str(config_path)])

    def test_release_command_generates_release_receipt(self):
        root = self.make_case_root("soenc_release")
        dist_dir = root / "dist"
        (dist_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (dist_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        runtime_native = dist_dir / "pkg" / "enc_rt_demo.pyd"
        runtime_native.write_bytes(b"runtime-native")
        module_native = dist_dir / "pkg" / "mod.pyd"
        module_native.write_bytes(b"module-native")
        runtime_digest = encryption_helper._sha256_file(runtime_native)
        manifest_key = b"0123456789abcdef0123456789abcdef"
        manifest_payload = {
            "runtime_files": ["pkg/enc_rt_demo.py"],
            "runtime_delivery": {
                "validated": True,
                "compiled_runtime_files": ["pkg/enc_rt_demo.pyd"],
            },
            "key_management": {
                "mode": "license-file",
                "license_file": "licenses/customer.license.json",
            },
        }
        (dist_dir / "licenses").mkdir(parents=True, exist_ok=True)
        (dist_dir / "licenses" / "customer.license.json").write_text(
            json.dumps({"schema": "enc2sop-license/v1"}),
            encoding="utf-8",
        )
        encryption_helper.write_manifest(dist_dir, manifest_payload, signing_key=manifest_key, key_id="ops-main")
        release_bundle_payload = {
            "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
            "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
            "build_manifest": {
                "relative_path": "build_manifest.json",
                "is_signed": True,
                "signature": json.loads((dist_dir / "build_manifest.json").read_text(encoding="utf-8"))["signature"],
            },
            "bundle_contents": {
                "native_extension_files": ["pkg/enc_rt_demo.pyd", "pkg/mod.pyd"],
                "runtime_compiled_files": ["pkg/enc_rt_demo.pyd"],
                "package_init_files": ["pkg/__init__.py"],
                "license_file": {
                    "relative_path": "licenses/customer.license.json",
                    "required_for_runtime": True,
                },
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
                        "digest_hex": runtime_digest,
                    }
                ],
            },
        }
        (dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(release_bundle_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        config_path = root / "soenc.toml"
        config_path.write_text(
            "\n".join(
                [
                    "[build]",
                    "dist_dir = \"./dist\"",
                    "",
                    "[keys]",
                    "mode = \"license-file\"",
                    "require_manifest_signature = true",
                    "",
                    "[package]",
                    "name = \"demo\"",
                    "version = \"1.2.3\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        exit_code = soenc_cli.main(["release", "--config", str(config_path)])

        self.assertEqual(exit_code, 0)
        receipt_path = dist_dir / encryption_helper.RELEASE_RECEIPT_FILENAME
        self.assertTrue(receipt_path.exists())
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(receipt["schema"], encryption_helper.RELEASE_RECEIPT_SCHEMA)
        self.assertTrue(receipt["manifest_signature_required"])
        self.assertTrue(receipt["manifest_signature_present"])
        self.assertEqual(receipt["manifest_signature_key_id"], "ops-main")
        self.assertEqual(receipt["runtime_artifacts_verified"], 1)
        self.assertEqual(receipt["native_artifacts_verified"], 2)
        self.assertEqual(receipt["key_mode"], "license-file")
        self.assertEqual(receipt["package_metadata"]["name"], "demo")

    def test_release_command_requires_signed_approval_when_enabled(self):
        root = self.make_case_root("soenc_release_approval")
        dist_dir = root / "dist"
        (dist_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (dist_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        runtime_native = dist_dir / "pkg" / "enc_rt_demo.pyd"
        runtime_native.write_bytes(b"runtime-native")
        module_native = dist_dir / "pkg" / "mod.pyd"
        module_native.write_bytes(b"module-native")
        runtime_digest = encryption_helper._sha256_file(runtime_native)
        manifest_key = b"0123456789abcdef0123456789abcdef"
        approval_key = b"fedcba9876543210fedcba9876543210"
        manifest_payload = {
            "runtime_files": ["pkg/enc_rt_demo.py"],
            "runtime_delivery": {
                "validated": True,
                "compiled_runtime_files": ["pkg/enc_rt_demo.pyd"],
            },
        }
        encryption_helper.write_manifest(dist_dir, manifest_payload, signing_key=manifest_key, key_id="ops-main")
        signed_manifest = json.loads((dist_dir / "build_manifest.json").read_text(encoding="utf-8"))
        release_bundle_payload = {
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
                        "digest_hex": runtime_digest,
                    }
                ],
            },
        }
        (dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(release_bundle_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        approval_payload = {
            "schema": encryption_helper.RELEASE_APPROVAL_SCHEMA,
            "approved_at_utc": "2026-05-09T00:00:00Z",
            "release_bundle_relative_path": encryption_helper.RELEASE_BUNDLE_FILENAME,
            "release_bundle_sha256": encryption_helper._sha256_file(dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME),
            "approvers": ["ops-a", "security-b"],
        }
        approval_digest = hmac.new(
            approval_key,
            encryption_helper._canonical_json_bytes(approval_payload),
            hashlib.sha256,
        ).hexdigest()
        approval_payload["signature"] = {
            "algorithm": encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256,
            "key_id": "ops-approval-main",
            "digest_hex": approval_digest,
        }
        approval_path = dist_dir / "release_approval.json"
        approval_path.write_text(json.dumps(approval_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        approval_key_file = root / "approval.key"
        approval_key_file.write_bytes(approval_key)
        config_path = root / "soenc.toml"
        config_path.write_text(
            "\n".join(
                [
                    "[build]",
                    "dist_dir = \"./dist\"",
                    "",
                    "[release]",
                    "require_approval = true",
                    "approval_file = \"./dist/release_approval.json\"",
                    "approval_key_file = \"./approval.key\"",
                    "approval_key_id = \"ops-approval-main\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        exit_code = soenc_cli.main(["release", "--config", str(config_path)])
        self.assertEqual(exit_code, 0)
        receipt = json.loads((dist_dir / encryption_helper.RELEASE_RECEIPT_FILENAME).read_text(encoding="utf-8"))
        self.assertTrue(receipt["release_approval_required"])
        self.assertTrue(receipt["release_approval_verified"])
        self.assertEqual(receipt["release_approval_key_id"], "ops-approval-main")

    def test_release_command_fails_when_approval_required_but_key_missing(self):
        root = self.make_case_root("soenc_release_approval_key_missing")
        dist_dir = root / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)
        (dist_dir / "build_manifest.json").write_text(json.dumps({"runtime_files": []}), encoding="utf-8")
        (dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(
                {
                    "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
                    "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
                    "build_manifest": {
                        "relative_path": "build_manifest.json",
                        "is_signed": False,
                        "signature": None,
                    },
                    "bundle_contents": {
                        "native_extension_files": [],
                        "runtime_compiled_files": [],
                        "package_init_files": [],
                        "license_file": None,
                    },
                    "runtime_integrity": {
                        "validated": False,
                        "compiled_runtime_fingerprints": [],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "--require-release-approval requires"):
            soenc_cli.main(["release", "--dist-dir", str(dist_dir), "--require-release-approval"])

    def test_approve_release_command_generates_signed_approval_file(self):
        root = self.make_case_root("soenc_approve_release")
        dist_dir = root / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)
        (dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(
                {
                    "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
                    "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        approval_key = b"fedcba9876543210fedcba9876543210"
        approval_key_file = root / "approval.key"
        approval_key_file.write_bytes(approval_key)
        config_path = root / "soenc.toml"
        config_path.write_text(
            "\n".join(
                [
                    "[build]",
                    "dist_dir = \"./dist\"",
                    "",
                    "[release]",
                    "approval_key_file = \"./approval.key\"",
                    "approval_key_id = \"ops-approval-main\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        exit_code = soenc_cli.main(
            [
                "approve-release",
                "--config",
                str(config_path),
                "--approver",
                "ops-a",
                "--approver",
                "security-b",
                "--notes",
                "approved in CI",
            ]
        )

        self.assertEqual(exit_code, 0)
        approval_path = dist_dir / "release_approval.json"
        self.assertTrue(approval_path.exists())
        approval_payload = json.loads(approval_path.read_text(encoding="utf-8"))
        self.assertEqual(approval_payload["schema"], encryption_helper.RELEASE_APPROVAL_SCHEMA)
        self.assertEqual(approval_payload["release_bundle_relative_path"], encryption_helper.RELEASE_BUNDLE_FILENAME)
        self.assertEqual(approval_payload["approvers"], ["ops-a", "security-b"])
        self.assertEqual(approval_payload["notes"], "approved in CI")
        signature = approval_payload.get("signature") or {}
        self.assertEqual(signature.get("algorithm"), encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256)
        self.assertEqual(signature.get("key_id"), "ops-approval-main")

        signed_payload = dict(approval_payload)
        digest_hex = signed_payload.pop("signature")["digest_hex"]
        expected_digest = hmac.new(
            approval_key,
            encryption_helper._canonical_json_bytes(signed_payload),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(digest_hex, expected_digest)

    def test_approve_release_command_requires_signing_key(self):
        root = self.make_case_root("soenc_approve_release_missing_key")
        dist_dir = root / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)
        (dist_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(
                {
                    "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
                    "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "approve-release requires"):
            soenc_cli.main(
                [
                    "approve-release",
                    "--dist-dir",
                    str(dist_dir),
                    "--approver",
                    "ops-a",
                ]
            )

    def test_release_command_rejects_missing_release_bundle(self):
        root = self.make_case_root("soenc_release_missing_bundle")
        dist_dir = root / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)
        (dist_dir / "build_manifest.json").write_text(json.dumps({"runtime_files": []}), encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "release bundle metadata missing"):
            soenc_cli.main(["release", "--dist-dir", str(dist_dir)])

    def test_transport_command_delegates_to_plugin_registry(self):
        with mock.patch.object(plugin_registry, "invoke_plugin_command", autospec=True, return_value=0) as mocked:
            exit_code = soenc_cli.main(["transport", "export", "-i", "in.bin", "-o", "out_dir"])

        self.assertEqual(exit_code, 0)
        mocked.assert_called_once_with("transport", ["export", "-i", "in.bin", "-o", "out_dir"])

    def test_transport_command_fails_when_optional_plugin_unavailable(self):
        with mock.patch.object(
            plugin_registry,
            "invoke_plugin_command",
            autospec=True,
            side_effect=RuntimeError("transport plugin is unavailable"),
        ):
            with self.assertRaisesRegex(RuntimeError, "transport plugin is unavailable"):
                soenc_cli.main(["transport", "export", "-i", "in.bin", "-o", "out_dir"])

    def test_transport_command_without_args_prints_plugin_status(self):
        with mock.patch.object(plugin_registry, "plugin_help_rows", autospec=True, return_value=["transport: optional (available)"]), mock.patch(
            "builtins.print"
        ) as mocked_print:
            exit_code = soenc_cli.main(["transport"])

        self.assertEqual(exit_code, 0)
        mocked_print.assert_any_call("available optional plugins:")
        mocked_print.assert_any_call("  transport: optional (available)")
        mocked_print.assert_any_call(
            "note: certify/archive/status transport evidence commands are experimental "
            "legacy tooling; use `soenc cm send` and `soenc cm receive` for the "
            "current cross-media encrypted user path."
        )

    def test_transport_help_marks_evidence_tools_experimental(self):
        parser = soenc_cli.build_parser()
        transport_parser = parser._subparsers._group_actions[0].choices["transport"]
        help_text = transport_parser.format_help()

        self.assertIn("experimental", help_text)
        self.assertIn("certify/archive/status", help_text)
        self.assertIn("soenc cm send", help_text)
        self.assertIn("soenc cm receive", help_text)

    def test_audit_promotion_command_passes_with_valid_evidence(self):
        root = self.make_case_root("soenc_audit_promotion_pass")
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "branches": [
                        {
                            "name": "main",
                            "required_status_checks": ["Signed Approval Promotion Gate"],
                        },
                        {
                            "name": "release/**",
                            "required_status_checks": ["Signed Approval Promotion Gate"],
                        },
                    ],
                    "environments": [
                        {
                            "name": "production-promotion",
                            "required_reviewers_count": 2,
                        }
                    ],
                    "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        report_path = root / "promotion_report.json"

        exit_code = soenc_cli.main(
            [
                "audit-promotion",
                "--evidence-file",
                str(evidence_path),
                "--report-file",
                str(report_path),
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertTrue(report_path.exists())
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["schema"], "enc2sop-promotion-audit-report/v1")
        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["total_failures"], 0)

    def test_audit_promotion_command_fails_when_evidence_is_missing_gates(self):
        root = self.make_case_root("soenc_audit_promotion_fail")
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "branches": [
                        {
                            "name": "main",
                            "required_status_checks": [],
                        }
                    ],
                    "environments": [
                        {
                            "name": "production-promotion",
                            "required_reviewers_count": 0,
                        }
                    ],
                    "secrets": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        report_path = root / "promotion_report.json"

        exit_code = soenc_cli.main(
            [
                "audit-promotion",
                "--evidence-file",
                str(evidence_path),
                "--report-file",
                str(report_path),
            ]
        )

        self.assertEqual(exit_code, 1)
        self.assertTrue(report_path.exists())
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertFalse(report["passed"])
        self.assertGreater(report["summary"]["total_failures"], 0)
        self.assertTrue(any("missing branch evidence" in item for item in report["failures"]))
        self.assertTrue(any("missing required secret evidence" in item for item in report["failures"]))

    def test_collect_promotion_evidence_command_writes_expected_schema_payload(self):
        root = self.make_case_root("soenc_collect_promotion_evidence")
        evidence_path = root / "promotion_evidence.json"
        fake_payload = {
            "schema": "enc2sop-promotion-evidence/v1",
            "repository": "acme/demo",
            "branches": [
                {"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]},
                {"name": "release/**", "required_status_checks": ["Signed Approval Promotion Gate"]},
            ],
            "environments": [{"name": "production-promotion", "required_reviewers_count": 2}],
            "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
        }
        with mock.patch.object(
            promotion_evidence,
            "collect_promotion_evidence",
            autospec=True,
            return_value=(evidence_path, fake_payload),
        ) as mocked_collect:
            exit_code = soenc_cli.main(
                [
                    "collect-promotion-evidence",
                    "--github-repo",
                    "acme/demo",
                    "--github-token",
                    "test-token",
                    "--evidence-file",
                    str(evidence_path),
                ]
            )

        self.assertEqual(exit_code, 0)
        mocked_collect.assert_called_once()
        self.assertEqual(mocked_collect.call_args.kwargs["repo"], "acme/demo")
        self.assertEqual(mocked_collect.call_args.kwargs["token"], "test-token")
        self.assertEqual(mocked_collect.call_args.kwargs["evidence_file"], str(evidence_path))

    def test_collect_promotion_evidence_command_fails_without_repo(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(ValueError, "requires --github-repo or GITHUB_REPOSITORY"):
                soenc_cli.main(
                    [
                        "collect-promotion-evidence",
                        "--github-token",
                        "test-token",
                    ]
                )

    def test_collect_promotion_evidence_command_fails_without_token(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(ValueError, "requires --github-token or GITHUB_TOKEN"):
                soenc_cli.main(
                    [
                        "collect-promotion-evidence",
                        "--github-repo",
                        "acme/demo",
                    ]
                )

    def test_promotion_dry_run_collects_and_audits_successfully(self):
        root = self.make_case_root("soenc_promotion_dry_run_collect")
        evidence_path = root / "promotion_evidence.json"
        report_path = root / "promotion_report.json"
        fake_payload = {
            "schema": "enc2sop-promotion-evidence/v1",
            "repository": "acme/demo",
            "branches": [
                {"name": "main", "required_status_checks": ["Signed Approval Promotion Gate"]},
                {"name": "release/**", "required_status_checks": ["Signed Approval Promotion Gate"]},
            ],
            "environments": [{"name": "production-promotion", "required_reviewers_count": 2}],
            "secrets": ["SOENC_RELEASE_APPROVAL_KEY_B64"],
        }
        fake_report = {
            "schema": "enc2sop-promotion-audit-report/v1",
            "passed": True,
            "failures": [],
            "summary": {"total_failures": 0},
            "inputs": {
                "policy_file": str(root / "policy.json"),
                "policy_sha256": "b" * 64,
                "evidence_file": str(evidence_path),
                "evidence_sha256": "a" * 64,
                "workflow_file": str(root / "release_promotion.yml"),
                "workflow_sha256": "c" * 64,
            },
        }

        with mock.patch.object(
            promotion_evidence,
            "collect_promotion_evidence",
            autospec=True,
            return_value=(evidence_path, fake_payload),
        ) as mocked_collect, mock.patch.object(
            soenc_cli.promotion_audit,
            "run_promotion_audit",
            autospec=True,
            return_value=(report_path, fake_report),
        ) as mocked_audit:
            exit_code = soenc_cli.main(
                [
                    "promotion-dry-run",
                    "--github-repo",
                    "acme/demo",
                    "--github-token",
                    "test-token",
                    "--evidence-file",
                    str(evidence_path),
                    "--report-file",
                    str(report_path),
                ]
            )

        self.assertEqual(exit_code, 0)
        mocked_collect.assert_called_once()
        mocked_audit.assert_called_once()
        self.assertEqual(mocked_collect.call_args.kwargs["repo"], "acme/demo")
        self.assertEqual(mocked_collect.call_args.kwargs["token"], "test-token")
        self.assertEqual(mocked_collect.call_args.kwargs["evidence_file"], str(evidence_path))
        self.assertEqual(mocked_audit.call_args.kwargs["evidence_file"], str(evidence_path))

    def test_promotion_dry_run_skip_collect_requires_existing_evidence_file(self):
        root = self.make_case_root("soenc_promotion_dry_run_skip_missing")
        missing_evidence = root / "missing.json"
        with self.assertRaisesRegex(FileNotFoundError, "promotion evidence file not found"):
            soenc_cli.main(
                [
                    "promotion-dry-run",
                    "--skip-collect",
                    "--evidence-file",
                    str(missing_evidence),
                ]
            )

    def test_promotion_dry_run_skip_collect_audits_and_fails_closed(self):
        root = self.make_case_root("soenc_promotion_dry_run_skip_fail")
        evidence_path = root / "promotion_evidence.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "schema": "enc2sop-promotion-evidence/v1",
                    "branches": [],
                    "environments": [],
                    "secrets": [],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        report_path = root / "promotion_report.json"
        fake_report = {
            "schema": "enc2sop-promotion-audit-report/v1",
            "passed": False,
            "failures": ["missing branch evidence for 'main'"],
            "summary": {"total_failures": 1},
            "inputs": {
                "policy_file": str(root / "policy.json"),
                "policy_sha256": "b" * 64,
                "evidence_file": str(evidence_path),
                "evidence_sha256": "a" * 64,
                "workflow_file": str(root / "release_promotion.yml"),
                "workflow_sha256": "c" * 64,
            },
        }
        with mock.patch.object(
            soenc_cli.promotion_audit,
            "run_promotion_audit",
            autospec=True,
            return_value=(report_path, fake_report),
        ) as mocked_audit:
            exit_code = soenc_cli.main(
                [
                    "promotion-dry-run",
                    "--skip-collect",
                    "--evidence-file",
                    str(evidence_path),
                    "--report-file",
                    str(report_path),
                ]
            )
        self.assertEqual(exit_code, 1)
        mocked_audit.assert_called_once()
        self.assertEqual(mocked_audit.call_args.kwargs["evidence_file"], str(evidence_path))

    def test_promotion_dry_run_collect_mode_requires_repo(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(ValueError, "requires --github-repo or GITHUB_REPOSITORY"):
                soenc_cli.main(
                    [
                        "promotion-dry-run",
                        "--github-token",
                        "test-token",
                    ]
                )

    def test_promotion_dry_run_collect_mode_requires_token(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(ValueError, "requires --github-token or GITHUB_TOKEN"):
                soenc_cli.main(
                    [
                        "promotion-dry-run",
                        "--github-repo",
                        "acme/demo",
                    ]
                )

    def test_verify_promotion_artifacts_command_success(self):
        root = self.make_case_root("soenc_verify_promotion_artifacts")
        report_path = root / "promotion_artifact_audit_report.json"
        fake_report = {
            "schema": "enc2sop-promotion-artifact-audit/v1",
            "passed": True,
            "failures": [],
            "summary": {"total_failures": 0},
        }
        with mock.patch.object(
            promotion_artifacts,
            "run_promotion_artifact_audit",
            autospec=True,
            return_value=(report_path, fake_report),
        ) as mocked_verify:
            exit_code = soenc_cli.main(
                [
                    "verify-promotion-artifacts",
                    "--dist-dir",
                    str(root / "release"),
                    "--promotion-evidence-file",
                    str(root / "promotion_evidence.json"),
                    "--promotion-report-file",
                    str(root / "promotion_audit_report.json"),
                    "--rotation-report-file",
                    str(root / "rotation_rehearsal_report.json"),
                ]
            )

        self.assertEqual(exit_code, 0)
        mocked_verify.assert_called_once()
        self.assertEqual(mocked_verify.call_args.kwargs["dist_dir"], str(root / "release"))
        self.assertEqual(mocked_verify.call_args.kwargs["promotion_evidence_file"], str(root / "promotion_evidence.json"))
        self.assertEqual(mocked_verify.call_args.kwargs["promotion_report_file"], str(root / "promotion_audit_report.json"))
        self.assertEqual(mocked_verify.call_args.kwargs["rotation_report_file"], str(root / "rotation_rehearsal_report.json"))
        self.assertIsNone(mocked_verify.call_args.kwargs["release_approval_key_file"])
        self.assertIsNone(mocked_verify.call_args.kwargs["release_approval_key_b64"])
        self.assertIsNone(mocked_verify.call_args.kwargs["release_approval_key_id"])
        self.assertIsNone(mocked_verify.call_args.kwargs["promotion_policy_file"])
        self.assertIsNone(mocked_verify.call_args.kwargs["promotion_workflow_file"])
        self.assertIsNone(mocked_verify.call_args.kwargs["run_receipt_file"])
        self.assertFalse(mocked_verify.call_args.kwargs["require_release_approval_signature"])
        self.assertFalse(mocked_verify.call_args.kwargs["require_rotation_pass"])
        self.assertFalse(mocked_verify.call_args.kwargs["require_ci_context_match"])
        self.assertFalse(mocked_verify.call_args.kwargs["require_artifact_context_consistency"])

    def test_verify_promotion_artifacts_command_fail_closed(self):
        root = self.make_case_root("soenc_verify_promotion_artifacts_fail")
        report_path = root / "promotion_artifact_audit_report.json"
        fake_report = {
            "schema": "enc2sop-promotion-artifact-audit/v1",
            "passed": False,
            "failures": ["release_receipt.release_approval_verified must be true"],
            "summary": {"total_failures": 1},
        }
        with mock.patch.object(
            promotion_artifacts,
            "run_promotion_artifact_audit",
            autospec=True,
            return_value=(report_path, fake_report),
        ) as mocked_verify:
            exit_code = soenc_cli.main(
                [
                    "verify-promotion-artifacts",
                    "--dist-dir",
                    str(root / "release"),
                    "--promotion-evidence-file",
                    str(root / "promotion_evidence.json"),
                    "--promotion-report-file",
                    str(root / "promotion_audit_report.json"),
                    "--rotation-report-file",
                    str(root / "rotation_rehearsal_report.json"),
                    "--release-approval-key-b64",
                    "Zm9v",
                    "--release-approval-key-id",
                    "ops-approval-main",
                    "--require-release-approval-signature",
                    "--require-rotation-pass",
                    "--require-ci-context-match",
                    "--require-artifact-context-consistency",
                ]
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(mocked_verify.call_args.kwargs["release_approval_key_b64"], "Zm9v")
        self.assertEqual(mocked_verify.call_args.kwargs["release_approval_key_id"], "ops-approval-main")
        self.assertTrue(mocked_verify.call_args.kwargs["require_release_approval_signature"])
        self.assertTrue(mocked_verify.call_args.kwargs["require_rotation_pass"])
        self.assertTrue(mocked_verify.call_args.kwargs["require_ci_context_match"])
        self.assertTrue(mocked_verify.call_args.kwargs["require_artifact_context_consistency"])

    def test_verify_promotion_artifacts_command_wires_policy_and_workflow_overrides(self):
        root = self.make_case_root("soenc_verify_promotion_artifacts_policy_workflow")
        report_path = root / "promotion_artifact_audit_report.json"
        fake_report = {
            "schema": "enc2sop-promotion-artifact-audit/v1",
            "passed": True,
            "failures": [],
            "summary": {"total_failures": 0},
        }
        policy_path = root / "policy_override.json"
        workflow_path = root / "workflow_override.yml"
        with mock.patch.object(
            promotion_artifacts,
            "run_promotion_artifact_audit",
            autospec=True,
            return_value=(report_path, fake_report),
        ) as mocked_verify:
            exit_code = soenc_cli.main(
                [
                    "verify-promotion-artifacts",
                    "--dist-dir",
                    str(root / "release"),
                    "--promotion-evidence-file",
                    str(root / "promotion_evidence.json"),
                    "--promotion-report-file",
                    str(root / "promotion_audit_report.json"),
                    "--rotation-report-file",
                    str(root / "rotation_rehearsal_report.json"),
                    "--promotion-policy-file",
                    str(policy_path),
                    "--promotion-workflow-file",
                    str(workflow_path),
                ]
            )

        self.assertEqual(exit_code, 0)
        mocked_verify.assert_called_once()
        self.assertEqual(mocked_verify.call_args.kwargs["promotion_policy_file"], str(policy_path))
        self.assertEqual(mocked_verify.call_args.kwargs["promotion_workflow_file"], str(workflow_path))

    def test_bundle_promotion_artifacts_command_success(self):
        root = self.make_case_root("soenc_bundle_promotion_artifacts")
        bundle_path = root / "promotion_artifact_bundle.zip"
        fake_manifest = {
            "schema": "enc2sop-promotion-artifact-bundle/v1",
            "bundle_sha256": "a" * 64,
            "file_count": 8,
        }
        with mock.patch.object(
            promotion_bundle,
            "create_promotion_artifact_bundle",
            autospec=True,
            return_value=(bundle_path, fake_manifest),
        ) as mocked_bundle:
            exit_code = soenc_cli.main(
                [
                    "bundle-promotion-artifacts",
                    "--dist-dir",
                    str(root / "release"),
                    "--promotion-evidence-file",
                    str(root / "promotion_evidence.json"),
                    "--promotion-report-file",
                    str(root / "promotion_audit_report.json"),
                    "--rotation-report-file",
                    str(root / "rotation_rehearsal_report.json"),
                ]
            )

        self.assertEqual(exit_code, 0)
        mocked_bundle.assert_called_once()
        self.assertEqual(mocked_bundle.call_args.kwargs["dist_dir"], str(root / "release"))
        self.assertEqual(mocked_bundle.call_args.kwargs["promotion_evidence_file"], str(root / "promotion_evidence.json"))
        self.assertEqual(mocked_bundle.call_args.kwargs["promotion_report_file"], str(root / "promotion_audit_report.json"))
        self.assertEqual(mocked_bundle.call_args.kwargs["rotation_report_file"], str(root / "rotation_rehearsal_report.json"))
        self.assertIsNone(mocked_bundle.call_args.kwargs["promotion_artifact_audit_report_file"])
        self.assertIsNone(mocked_bundle.call_args.kwargs["promotion_run_receipt_file"])
        self.assertIsNone(mocked_bundle.call_args.kwargs["promotion_policy_file"])
        self.assertIsNone(mocked_bundle.call_args.kwargs["promotion_workflow_file"])
        self.assertIsNone(mocked_bundle.call_args.kwargs["bundle_file"])

    def test_bundle_promotion_artifacts_command_wires_optional_overrides(self):
        root = self.make_case_root("soenc_bundle_promotion_artifacts_overrides")
        bundle_path = root / "ops" / "bundle.zip"
        fake_manifest = {
            "schema": "enc2sop-promotion-artifact-bundle/v1",
            "bundle_sha256": "b" * 64,
            "file_count": 10,
        }
        with mock.patch.object(
            promotion_bundle,
            "create_promotion_artifact_bundle",
            autospec=True,
            return_value=(bundle_path, fake_manifest),
        ) as mocked_bundle:
            exit_code = soenc_cli.main(
                [
                    "bundle-promotion-artifacts",
                    "--dist-dir",
                    str(root / "release"),
                    "--promotion-evidence-file",
                    str(root / "promotion_evidence.json"),
                    "--promotion-report-file",
                    str(root / "promotion_audit_report.json"),
                    "--rotation-report-file",
                    str(root / "rotation_rehearsal_report.json"),
                    "--promotion-artifact-audit-report-file",
                    str(root / "promotion_artifact_audit_report.json"),
                    "--promotion-run-receipt-file",
                    str(root / "promotion_run_receipt.json"),
                    "--promotion-policy-file",
                    str(root / "policy.json"),
                    "--promotion-workflow-file",
                    str(root / "workflow.yml"),
                    "--bundle-file",
                    str(bundle_path),
                ]
            )

        self.assertEqual(exit_code, 0)
        mocked_bundle.assert_called_once()
        self.assertEqual(
            mocked_bundle.call_args.kwargs["promotion_artifact_audit_report_file"],
            str(root / "promotion_artifact_audit_report.json"),
        )
        self.assertEqual(
            mocked_bundle.call_args.kwargs["promotion_run_receipt_file"],
            str(root / "promotion_run_receipt.json"),
        )
        self.assertEqual(mocked_bundle.call_args.kwargs["promotion_policy_file"], str(root / "policy.json"))
        self.assertEqual(mocked_bundle.call_args.kwargs["promotion_workflow_file"], str(root / "workflow.yml"))
        self.assertEqual(mocked_bundle.call_args.kwargs["bundle_file"], str(bundle_path))


if __name__ == "__main__":
    unittest.main()
