import json
import importlib
import hashlib
import hmac
import os
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import encryption_helper
import soenc_config


TEST_ROOT = Path(__file__).resolve().parents[1]
TEST_RUNS_ROOT = TEST_ROOT / ".tmp_test_runs"
RELEASE_APPROVAL_KEY = b"0123456789abcdef0123456789abcdef"


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


class EncryptionHelperTests(WorkspaceTempMixin, unittest.TestCase):
    def _write_signed_release_approval(self, *, release_dir, release_bundle_rel="release_bundle.json", key=RELEASE_APPROVAL_KEY):
        bundle_path = release_dir / release_bundle_rel
        approval_payload = {
            "schema": encryption_helper.RELEASE_APPROVAL_SCHEMA,
            "approved_at_utc": "2026-05-09T00:00:00Z",
            "release_bundle_relative_path": release_bundle_rel,
            "release_bundle_sha256": encryption_helper._sha256_file(bundle_path),
            "approvers": ["ops-a", "security-b"],
            "notes": "approved for launch",
        }
        approval_digest = hmac.new(
            key,
            encryption_helper._canonical_json_bytes(approval_payload),
            hashlib.sha256,
        ).hexdigest()
        approval_payload["signature"] = {
            "algorithm": encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256,
            "key_id": "ops-approval-main",
            "digest_hex": approval_digest,
        }
        approval_path = release_dir / "release_approval.json"
        approval_path.write_text(json.dumps(approval_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return approval_path

    def _ensure_compile_integration_ready(self):
        if importlib.util.find_spec("Cython") is None:
            self.skipTest("Cython is not installed; skipping compile integration test")
        if os.name == "nt" and encryption_helper.find_vcvars64() is None:
            self.skipTest("MSVC vcvars64.bat not found; skipping compile integration test")

    def _build_compiled_fixture(self, root, require_native_runtime_loader=False):
        package_name = "p" + uuid.uuid4().hex[:4]
        project_root = root / package_name
        project_root.mkdir(parents=True, exist_ok=True)
        (project_root / "__init__.py").write_text("", encoding="utf-8")
        module_name = "m"
        (project_root / f"{module_name}.py").write_text(
            "\n".join(
                [
                    "BASE = 7",
                    "",
                    "def protected_sum(a, b):",
                    "    return a + b + BASE",
                    "",
                    "class ProtectedBox(object):",
                    "    def __init__(self, value):",
                    "        self.value = value",
                    "",
                    "    def total(self):",
                    "        return self.value + BASE",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        output_dir = root / "o"
        argv = [
            "-t",
            str(project_root),
            "-o",
            str(output_dir),
            "--compile",
            "--python-exe",
            sys.executable,
        ]
        if require_native_runtime_loader:
            argv.append("--runtime-native-loader")
        exit_code = encryption_helper.main(argv)
        self.assertEqual(exit_code, 0)
        build_dir = output_dir / "build"
        manifest = json.loads((output_dir / "build_manifest.json").read_text(encoding="utf-8"))
        return package_name, module_name, output_dir, build_dir, manifest

    def _import_compiled_module(self, build_dir, package_name, module_name):
        build_dir_text = str(build_dir)
        sys.path.insert(0, build_dir_text)
        self.addCleanup(lambda: sys.path.remove(build_dir_text) if build_dir_text in sys.path else None)

        importlib.invalidate_caches()
        full_module = f"{package_name}.{module_name}"
        sys.modules.pop(full_module, None)
        sys.modules.pop(package_name, None)
        self.addCleanup(lambda: sys.modules.pop(full_module, None))
        self.addCleanup(lambda: sys.modules.pop(package_name, None))
        return importlib.import_module(full_module)

    def _import_module_from_root(self, root_dir, package_name, module_name):
        root_text = str(root_dir)
        sys.path.insert(0, root_text)
        self.addCleanup(lambda: sys.path.remove(root_text) if root_text in sys.path else None)

        importlib.invalidate_caches()
        full_module = f"{package_name}.{module_name}"
        sys.modules.pop(full_module, None)
        sys.modules.pop(package_name, None)
        self.addCleanup(lambda: sys.modules.pop(full_module, None))
        self.addCleanup(lambda: sys.modules.pop(package_name, None))
        return importlib.import_module(full_module)

    def test_runtime_module_names_avoid_dunder_prefix(self):
        root = self.make_case_root("runtime_name")
        src_dir = root / "src"
        pkg = src_dir / "pkg"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "a.py").write_text("def one():\n    return 1\n", encoding="utf-8")
        (pkg / "b.py").write_text("def two():\n    return 2\n", encoding="utf-8")

        mapping = encryption_helper.runtime_module_map(
            [pkg / "a.py", pkg / "b.py"],
            src_dir,
        )

        self.assertTrue(mapping)
        for name in mapping.values():
            self.assertTrue(name.startswith(encryption_helper.RUNTIME_MODULE_PREFIX + "_"))
            self.assertFalse(name.startswith("__"))
            self.assertTrue(encryption_helper.is_compile_eligible_module_name(name))

    def test_validate_runtime_delivery_rejects_missing_compiled_runtime(self):
        root = self.make_case_root("runtime_validate_missing")
        staging_dir = root / "staging"
        build_dir = root / "build"
        staging_dir.mkdir(parents=True, exist_ok=True)
        build_dir.mkdir(parents=True, exist_ok=True)

        manifest = {
            "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
            "runtime_delivery": {"mode": encryption_helper.RUNTIME_DELIVERY_MODE},
        }
        (staging_dir / "build_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RuntimeError, "compiled runtime modules missing"):
            encryption_helper.validate_runtime_delivery(staging_dir, build_dir)

    def test_manifest_signature_sign_and_verify_roundtrip(self):
        root = self.make_case_root("manifest_sign_verify")
        staging_dir = root / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
            "runtime_delivery": {"mode": encryption_helper.RUNTIME_DELIVERY_MODE},
        }
        key = b"0123456789abcdef0123456789abcdef"
        manifest_path = encryption_helper.write_manifest(
            staging_dir,
            manifest,
            signing_key=key,
            key_id="team-main",
        )

        loaded, signature = encryption_helper.verify_manifest_signature_file(manifest_path, key)
        self.assertEqual(signature["algorithm"], encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256)
        self.assertEqual(signature["key_id"], "team-main")
        self.assertIn("digest_hex", signature)
        self.assertEqual(loaded["runtime_files"], manifest["runtime_files"])

    def test_manifest_signature_rejects_tampered_manifest(self):
        root = self.make_case_root("manifest_tamper")
        staging_dir = root / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
            "runtime_delivery": {"mode": encryption_helper.RUNTIME_DELIVERY_MODE},
        }
        key = b"0123456789abcdef0123456789abcdef"
        manifest_path = encryption_helper.write_manifest(staging_dir, manifest, signing_key=key, key_id="team-main")
        tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
        tampered["runtime_files"] = ["pkg/enc_rt_pkg_9999.py"]
        manifest_path.write_text(json.dumps(tampered, ensure_ascii=False, indent=2), encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "manifest signature mismatch"):
            encryption_helper.verify_manifest_signature_file(manifest_path, key)

    def test_validate_runtime_delivery_requires_signature_when_enabled(self):
        root = self.make_case_root("manifest_require_sig")
        staging_dir = root / "staging"
        build_dir = root / "build"
        staging_dir.mkdir(parents=True, exist_ok=True)
        build_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "runtime_files": [],
            "runtime_delivery": {"mode": encryption_helper.RUNTIME_DELIVERY_MODE},
        }
        (staging_dir / "build_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RuntimeError, "manifest signature is required"):
            encryption_helper.validate_runtime_delivery(
                staging_dir,
                build_dir,
                signing_key=None,
                require_manifest_signature=True,
            )

    def test_validate_runtime_delivery_marks_manifest_validated(self):
        root = self.make_case_root("runtime_validate_ok")
        staging_dir = root / "staging"
        build_dir = root / "build"
        pkg_dir = build_dir / "pkg"
        staging_dir.mkdir(parents=True, exist_ok=True)
        pkg_dir.mkdir(parents=True, exist_ok=True)

        runtime_source = "pkg/enc_rt_pkg_1234.py"
        runtime_native = pkg_dir / "enc_rt_pkg_1234.pyd"
        runtime_native.write_bytes(b"native-binary")
        manifest = {
            "runtime_files": [runtime_source],
            "runtime_delivery": {"mode": encryption_helper.RUNTIME_DELIVERY_MODE},
        }
        manifest_path = staging_dir / "build_manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

        compiled = encryption_helper.validate_runtime_delivery(staging_dir, build_dir)

        self.assertEqual(compiled, (Path("pkg/enc_rt_pkg_1234.pyd"),))
        updated_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertTrue(updated_manifest["runtime_delivery"]["validated"])
        self.assertEqual(
            updated_manifest["runtime_delivery"]["compiled_runtime_files"],
            ["pkg/enc_rt_pkg_1234.pyd"],
        )
        self.assertFalse(updated_manifest["runtime_delivery"].get("loader_enforced", False))
        self.assertEqual(
            updated_manifest["runtime_delivery"].get("loader_mode"),
            encryption_helper.RUNTIME_LOADER_MODE_DEFAULT,
        )
        trust_policy = updated_manifest["runtime_delivery"].get("trust_policy") or {}
        self.assertEqual(trust_policy.get("runtime_api_marker"), encryption_helper.RUNTIME_API_MARKER)
        self.assertEqual(trust_policy.get("runtime_api_version"), encryption_helper.RUNTIME_API_VERSION)
        self.assertEqual(
            trust_policy.get("runtime_path_policy"),
            encryption_helper.RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR,
        )
        self.assertFalse(trust_policy.get("runtime_relocation_allowed"))
        self.assertEqual(trust_policy.get("trusted_runtime_roots"), [])
        self.assertEqual(
            trust_policy.get("runtime_suffix_policy"),
            encryption_helper.RUNTIME_SUFFIX_POLICY_STRICT_SINGLE,
        )
        self.assertTrue(trust_policy.get("runtime_native_suffixes"))
        self.assertTrue(trust_policy.get("spec_origin_match"))
        self.assertEqual(
            trust_policy.get("runtime_fingerprint_algorithm"),
            encryption_helper.RUNTIME_FINGERPRINT_ALGORITHM_SHA256,
        )
        self.assertEqual(
            trust_policy.get("runtime_fingerprint_binding"),
            encryption_helper.RUNTIME_FINGERPRINT_BINDING_MANIFEST_COMPILED,
        )
        self.assertFalse(trust_policy.get("require_runtime_fingerprint"))
        fingerprints = updated_manifest["runtime_delivery"].get("compiled_runtime_fingerprints") or []
        self.assertEqual(len(fingerprints), 1)
        fp = fingerprints[0]
        self.assertEqual(fp.get("module_name"), "enc_rt_pkg_1234")
        self.assertEqual(fp.get("source_relative_path"), "pkg/enc_rt_pkg_1234.py")
        self.assertEqual(fp.get("compiled_relative_path"), "pkg/enc_rt_pkg_1234.pyd")
        self.assertEqual(fp.get("package_relative_path"), "pkg")
        self.assertEqual(fp.get("algorithm"), encryption_helper.RUNTIME_FINGERPRINT_ALGORITHM_SHA256)
        self.assertEqual(len(str(fp.get("digest_hex") or "")), 64)

    def test_validate_runtime_delivery_keeps_manifest_signed_after_validation(self):
        root = self.make_case_root("runtime_validate_signed")
        staging_dir = root / "staging"
        build_dir = root / "build"
        pkg_dir = build_dir / "pkg"
        staging_dir.mkdir(parents=True, exist_ok=True)
        pkg_dir.mkdir(parents=True, exist_ok=True)

        key = b"0123456789abcdef0123456789abcdef"
        runtime_source = "pkg/enc_rt_pkg_1234.py"
        runtime_native = pkg_dir / "enc_rt_pkg_1234.pyd"
        runtime_native.write_bytes(b"native-binary")
        manifest = {
            "runtime_files": [runtime_source],
            "runtime_delivery": {"mode": encryption_helper.RUNTIME_DELIVERY_MODE},
        }
        manifest_path = encryption_helper.write_manifest(
            staging_dir,
            manifest,
            signing_key=key,
            key_id="team-main",
        )

        compiled = encryption_helper.validate_runtime_delivery(
            staging_dir,
            build_dir,
            signing_key=key,
            require_manifest_signature=True,
        )

        self.assertEqual(compiled, (Path("pkg/enc_rt_pkg_1234.pyd"),))
        loaded, signature = encryption_helper.verify_manifest_signature_file(manifest_path, key)
        self.assertEqual(signature["key_id"], "team-main")
        self.assertTrue(loaded["runtime_delivery"]["validated"])

    def test_copy_release_requires_validated_runtime_delivery_for_runtime_files(self):
        root = self.make_case_root("release_runtime_validation_required")
        staging_dir = root / "staging"
        build_dir = root / "build"
        dist_dir = root / "dist"
        staging_dir.mkdir(parents=True, exist_ok=True)
        (build_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (build_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (build_dir / "pkg" / "enc_rt_pkg_1234.pyd").write_bytes(b"native")
        (staging_dir / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
                    "runtime_delivery": {
                        "mode": encryption_helper.RUNTIME_DELIVERY_MODE,
                        "validated": False,
                        "compiled_runtime_files": [],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RuntimeError, "runtime delivery must be validated"):
            encryption_helper.copy_release(build_dir, dist_dir, staging_dir)

    def test_copy_release_writes_release_bundle_contract(self):
        root = self.make_case_root("release_bundle_contract")
        staging_dir = root / "staging"
        build_dir = root / "build"
        dist_dir = root / "dist"
        (build_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (build_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        runtime_native = build_dir / "pkg" / "enc_rt_pkg_1234.pyd"
        runtime_native.write_bytes(b"native-binary")
        module_native = build_dir / "pkg" / "mod.pyd"
        module_native.write_bytes(b"native-module")
        runtime_digest = hashlib.sha256(runtime_native.read_bytes()).hexdigest()
        manifest_payload = {
            "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
            "runtime_modules": [
                {
                    "module_name": "enc_rt_pkg_1234",
                    "source_relative_path": "pkg/enc_rt_pkg_1234.py",
                    "package_relative_path": "pkg",
                }
            ],
            "runtime_delivery": {
                "mode": encryption_helper.RUNTIME_DELIVERY_MODE,
                "validated": True,
                "compiled_runtime_files": ["pkg/enc_rt_pkg_1234.pyd"],
                "compiled_runtime_fingerprints": [
                    {
                        "module_name": "enc_rt_pkg_1234",
                        "source_relative_path": "pkg/enc_rt_pkg_1234.py",
                        "compiled_relative_path": "pkg/enc_rt_pkg_1234.pyd",
                        "package_relative_path": "pkg",
                        "algorithm": "sha256",
                        "digest_hex": runtime_digest,
                    }
                ],
            },
            "key_management": {
                "mode": "license-file",
                "license_file": "licenses/customer.license.json",
            },
            "config": {
                "source": str((root / "soenc.toml").resolve()),
                "package_metadata": {
                    "name": "demo",
                    "version": "1.2.3",
                    "channel": "stable",
                },
            },
        }
        (staging_dir / "licenses").mkdir(parents=True, exist_ok=True)
        (staging_dir / "licenses" / "customer.license.json").write_text(
            json.dumps({"schema": "enc2sop-license/v1"}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        encryption_helper.write_manifest(
            staging_dir,
            manifest_payload,
            signing_key=b"0123456789abcdef0123456789abcdef",
            key_id="ops-signing",
        )

        out_dir, copied = encryption_helper.copy_release(
            build_dir=build_dir,
            dist_dir=dist_dir,
            staging_dir=staging_dir,
            package_metadata={"name": "demo", "version": "1.2.3", "vendor": "acme"},
            require_manifest_signature=True,
        )

        self.assertEqual(out_dir, dist_dir.resolve())
        copied_rel = {str(path.relative_to(out_dir)).replace("\\", "/") for path in copied}
        self.assertIn("build_manifest.json", copied_rel)
        self.assertIn("licenses/customer.license.json", copied_rel)
        self.assertIn(encryption_helper.RELEASE_BUNDLE_FILENAME, copied_rel)
        self.assertIn("pkg/__init__.py", copied_rel)
        self.assertIn("pkg/mod.pyd", copied_rel)
        self.assertIn("pkg/enc_rt_pkg_1234.pyd", copied_rel)

        bundle = json.loads((out_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).read_text(encoding="utf-8"))
        self.assertEqual(bundle.get("schema"), encryption_helper.RELEASE_BUNDLE_SCHEMA)
        self.assertEqual(bundle.get("layout_version"), encryption_helper.RELEASE_LAYOUT_VERSION)
        self.assertEqual(bundle.get("build_manifest", {}).get("relative_path"), "build_manifest.json")
        self.assertTrue(bundle.get("build_manifest", {}).get("is_signed"))
        self.assertEqual(bundle.get("build_manifest", {}).get("signature", {}).get("key_id"), "ops-signing")
        self.assertIn("pkg/mod.pyd", bundle.get("bundle_contents", {}).get("native_extension_files", []))
        self.assertIn("pkg/enc_rt_pkg_1234.pyd", bundle.get("bundle_contents", {}).get("runtime_compiled_files", []))
        self.assertIn("pkg/__init__.py", bundle.get("bundle_contents", {}).get("package_init_files", []))
        self.assertEqual(
            (bundle.get("bundle_contents", {}).get("license_file") or {}).get("relative_path"),
            "licenses/customer.license.json",
        )
        self.assertEqual(
            bundle.get("runtime_integrity", {}).get("compiled_runtime_fingerprints", [{}])[0].get("digest_hex"),
            runtime_digest,
        )
        self.assertEqual(bundle.get("package_metadata", {}).get("name"), "demo")
        self.assertEqual(bundle.get("package_metadata", {}).get("vendor"), "acme")

    def test_copy_release_rejects_unsigned_manifest_when_signature_required(self):
        root = self.make_case_root("release_require_signed_manifest")
        staging_dir = root / "staging"
        build_dir = root / "build"
        dist_dir = root / "dist"
        staging_dir.mkdir(parents=True, exist_ok=True)
        (build_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (build_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (build_dir / "pkg" / "enc_rt_pkg_1234.pyd").write_bytes(b"native")
        (staging_dir / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
                    "runtime_delivery": {
                        "validated": True,
                        "compiled_runtime_files": ["pkg/enc_rt_pkg_1234.pyd"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RuntimeError, "build manifest signature is required"):
            encryption_helper.copy_release(
                build_dir=build_dir,
                dist_dir=dist_dir,
                staging_dir=staging_dir,
                require_manifest_signature=True,
            )

    def test_write_release_receipt_validates_bundle_and_runtime_fingerprints(self):
        root = self.make_case_root("release_receipt")
        release_dir = root / "release"
        (release_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (release_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        runtime_native = release_dir / "pkg" / "enc_rt_pkg_1234.pyd"
        runtime_native.write_bytes(b"runtime-binary")
        module_native = release_dir / "pkg" / "mod.pyd"
        module_native.write_bytes(b"module-binary")
        runtime_digest = hashlib.sha256(runtime_native.read_bytes()).hexdigest()

        manifest_payload = {
            "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
            "runtime_delivery": {
                "validated": True,
                "compiled_runtime_files": ["pkg/enc_rt_pkg_1234.pyd"],
            },
            "key_management": {
                "mode": "license-file",
                "license_file": "licenses/customer.license.json",
            },
        }
        (release_dir / "licenses").mkdir(parents=True, exist_ok=True)
        (release_dir / "licenses" / "customer.license.json").write_text(
            json.dumps({"schema": "enc2sop-license/v1"}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        encryption_helper.write_manifest(
            release_dir,
            manifest_payload,
            signing_key=b"0123456789abcdef0123456789abcdef",
            key_id="ops-release",
        )
        signed_manifest = encryption_helper.read_manifest(release_dir / "build_manifest.json")

        release_bundle_payload = {
            "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
            "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
            "build_manifest": {
                "relative_path": "build_manifest.json",
                "is_signed": True,
                "signature": signed_manifest["signature"],
            },
            "bundle_contents": {
                "native_extension_files": ["pkg/enc_rt_pkg_1234.pyd", "pkg/mod.pyd"],
                "runtime_compiled_files": ["pkg/enc_rt_pkg_1234.pyd"],
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
                        "module_name": "enc_rt_pkg_1234",
                        "source_relative_path": "pkg/enc_rt_pkg_1234.py",
                        "compiled_relative_path": "pkg/enc_rt_pkg_1234.pyd",
                        "package_relative_path": "pkg",
                        "algorithm": "sha256",
                        "digest_hex": runtime_digest,
                    }
                ],
            },
        }
        (release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(release_bundle_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        receipt_path, receipt = encryption_helper.write_release_receipt(
            dist_dir=release_dir,
            required_manifest_signature=True,
            key_mode="license-file",
            package_metadata={"name": "demo", "version": "2.0.0"},
        )

        self.assertEqual(receipt_path, release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME)
        self.assertEqual(receipt["schema"], encryption_helper.RELEASE_RECEIPT_SCHEMA)
        self.assertTrue(receipt["manifest_signature_required"])
        self.assertTrue(receipt["manifest_signature_present"])
        self.assertEqual(receipt["manifest_signature_key_id"], "ops-release")
        self.assertEqual(receipt["runtime_artifacts_verified"], 1)
        self.assertEqual(receipt["native_artifacts_verified"], 2)
        self.assertEqual(receipt["key_mode"], "license-file")
        self.assertEqual(receipt["package_metadata"]["version"], "2.0.0")

    def test_write_release_receipt_rejects_runtime_fingerprint_mismatch(self):
        root = self.make_case_root("release_receipt_digest_mismatch")
        release_dir = root / "release"
        (release_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (release_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        (release_dir / "pkg" / "enc_rt_pkg_1234.pyd").write_bytes(b"runtime-binary")
        (release_dir / "pkg" / "mod.pyd").write_bytes(b"module-binary")
        (release_dir / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
                    "runtime_delivery": {
                        "validated": True,
                        "compiled_runtime_files": ["pkg/enc_rt_pkg_1234.pyd"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        release_bundle_payload = {
            "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
            "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
            "build_manifest": {
                "relative_path": "build_manifest.json",
                "is_signed": False,
                "signature": None,
            },
            "bundle_contents": {
                "native_extension_files": ["pkg/enc_rt_pkg_1234.pyd", "pkg/mod.pyd"],
                "runtime_compiled_files": ["pkg/enc_rt_pkg_1234.pyd"],
                "package_init_files": ["pkg/__init__.py"],
                "license_file": None,
            },
            "runtime_integrity": {
                "validated": True,
                "compiled_runtime_fingerprints": [
                    {
                        "module_name": "enc_rt_pkg_1234",
                        "source_relative_path": "pkg/enc_rt_pkg_1234.py",
                        "compiled_relative_path": "pkg/enc_rt_pkg_1234.pyd",
                        "package_relative_path": "pkg",
                        "algorithm": "sha256",
                        "digest_hex": "0" * 64,
                    }
                ],
            },
        }
        (release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(release_bundle_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RuntimeError, "release runtime fingerprint mismatch"):
            encryption_helper.write_release_receipt(dist_dir=release_dir)

    def test_write_release_receipt_requires_signed_approval_when_enabled(self):
        root = self.make_case_root("release_receipt_with_approval")
        release_dir = root / "release"
        (release_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (release_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        runtime_native = release_dir / "pkg" / "enc_rt_pkg_1234.pyd"
        runtime_native.write_bytes(b"runtime-binary")
        (release_dir / "pkg" / "mod.pyd").write_bytes(b"module-binary")
        runtime_digest = hashlib.sha256(runtime_native.read_bytes()).hexdigest()
        manifest_payload = {
            "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
            "runtime_delivery": {
                "validated": True,
                "compiled_runtime_files": ["pkg/enc_rt_pkg_1234.pyd"],
            },
        }
        encryption_helper.write_manifest(
            release_dir,
            manifest_payload,
            signing_key=b"0123456789abcdef0123456789abcdef",
            key_id="ops-release",
        )
        signed_manifest = encryption_helper.read_manifest(release_dir / "build_manifest.json")
        release_bundle_payload = {
            "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
            "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
            "build_manifest": {
                "relative_path": "build_manifest.json",
                "is_signed": True,
                "signature": signed_manifest["signature"],
            },
            "bundle_contents": {
                "native_extension_files": ["pkg/enc_rt_pkg_1234.pyd", "pkg/mod.pyd"],
                "runtime_compiled_files": ["pkg/enc_rt_pkg_1234.pyd"],
                "package_init_files": ["pkg/__init__.py"],
                "license_file": None,
            },
            "runtime_integrity": {
                "validated": True,
                "compiled_runtime_fingerprints": [
                    {
                        "module_name": "enc_rt_pkg_1234",
                        "source_relative_path": "pkg/enc_rt_pkg_1234.py",
                        "compiled_relative_path": "pkg/enc_rt_pkg_1234.pyd",
                        "package_relative_path": "pkg",
                        "algorithm": "sha256",
                        "digest_hex": runtime_digest,
                    }
                ],
            },
        }
        (release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(release_bundle_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self._write_signed_release_approval(release_dir=release_dir)

        receipt_path, receipt = encryption_helper.write_release_receipt(
            dist_dir=release_dir,
            required_manifest_signature=True,
            require_approval=True,
            approval_file=release_dir / "release_approval.json",
            approval_key=RELEASE_APPROVAL_KEY,
        )

        self.assertEqual(receipt_path, release_dir / encryption_helper.RELEASE_RECEIPT_FILENAME)
        self.assertTrue(receipt["release_approval_required"])
        self.assertTrue(receipt["release_approval_verified"])
        self.assertEqual(receipt["release_approval_key_id"], "ops-approval-main")

    def test_write_release_receipt_rejects_approval_digest_mismatch(self):
        root = self.make_case_root("release_receipt_approval_digest_mismatch")
        release_dir = root / "release"
        (release_dir / "pkg").mkdir(parents=True, exist_ok=True)
        (release_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
        runtime_native = release_dir / "pkg" / "enc_rt_pkg_1234.pyd"
        runtime_native.write_bytes(b"runtime-binary")
        (release_dir / "pkg" / "mod.pyd").write_bytes(b"module-binary")
        runtime_digest = hashlib.sha256(runtime_native.read_bytes()).hexdigest()
        (release_dir / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_files": ["pkg/enc_rt_pkg_1234.py"],
                    "runtime_delivery": {
                        "validated": True,
                        "compiled_runtime_files": ["pkg/enc_rt_pkg_1234.pyd"],
                    },
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        release_bundle_payload = {
            "schema": encryption_helper.RELEASE_BUNDLE_SCHEMA,
            "layout_version": encryption_helper.RELEASE_LAYOUT_VERSION,
            "build_manifest": {
                "relative_path": "build_manifest.json",
                "is_signed": False,
                "signature": None,
            },
            "bundle_contents": {
                "native_extension_files": ["pkg/enc_rt_pkg_1234.pyd", "pkg/mod.pyd"],
                "runtime_compiled_files": ["pkg/enc_rt_pkg_1234.pyd"],
                "package_init_files": ["pkg/__init__.py"],
                "license_file": None,
            },
            "runtime_integrity": {
                "validated": True,
                "compiled_runtime_fingerprints": [
                    {
                        "module_name": "enc_rt_pkg_1234",
                        "source_relative_path": "pkg/enc_rt_pkg_1234.py",
                        "compiled_relative_path": "pkg/enc_rt_pkg_1234.pyd",
                        "package_relative_path": "pkg",
                        "algorithm": "sha256",
                        "digest_hex": runtime_digest,
                    }
                ],
            },
        }
        (release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
            json.dumps(release_bundle_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        approval_path = self._write_signed_release_approval(release_dir=release_dir)
        approval_payload = json.loads(approval_path.read_text(encoding="utf-8"))
        approval_payload["release_bundle_sha256"] = "0" * 64
        approval_path.write_text(json.dumps(approval_payload, ensure_ascii=False, indent=2), encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "release approval bundle digest mismatch"):
            encryption_helper.write_release_receipt(
                dist_dir=release_dir,
                require_approval=True,
                approval_file=approval_path,
                approval_key=RELEASE_APPROVAL_KEY,
            )

    def test_write_release_approval_generates_signed_payload(self):
        root = self.make_case_root("release_approval_write")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        (release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
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
        key = b"abcdef0123456789abcdef0123456789"

        approval_path, payload = encryption_helper.write_release_approval(
            dist_dir=release_dir,
            approvers=["ops-a", "security-b", "ops-a"],
            approval_key=key,
            approval_key_id="ops-approval-main",
            notes="ready for promotion",
        )

        self.assertEqual(approval_path, release_dir / "release_approval.json")
        self.assertEqual(payload["schema"], encryption_helper.RELEASE_APPROVAL_SCHEMA)
        self.assertEqual(payload["release_bundle_relative_path"], encryption_helper.RELEASE_BUNDLE_FILENAME)
        self.assertEqual(payload["approvers"], ["ops-a", "security-b"])
        self.assertEqual(payload["notes"], "ready for promotion")
        signature = payload.get("signature") or {}
        self.assertEqual(signature.get("algorithm"), encryption_helper.SIGNATURE_ALGORITHM_HMAC_SHA256)
        self.assertEqual(signature.get("key_id"), "ops-approval-main")
        signed_payload = dict(payload)
        digest_hex = signed_payload.pop("signature")["digest_hex"]
        expected_digest = hmac.new(key, encryption_helper._canonical_json_bytes(signed_payload), hashlib.sha256).hexdigest()
        self.assertEqual(digest_hex, expected_digest)

    def test_write_release_approval_requires_approver(self):
        root = self.make_case_root("release_approval_no_approver")
        release_dir = root / "release"
        release_dir.mkdir(parents=True, exist_ok=True)
        (release_dir / encryption_helper.RELEASE_BUNDLE_FILENAME).write_text(
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
        with self.assertRaisesRegex(ValueError, "requires at least one approver"):
            encryption_helper.write_release_approval(
                dist_dir=release_dir,
                approvers=[],
                approval_key=RELEASE_APPROVAL_KEY,
            )

    def test_validate_runtime_delivery_rejects_mixed_platform_artifacts_under_strict_policy(self):
        root = self.make_case_root("runtime_validate_mixed_suffix")
        staging_dir = root / "staging"
        build_dir = root / "build"
        pkg_dir = build_dir / "pkg"
        staging_dir.mkdir(parents=True, exist_ok=True)
        pkg_dir.mkdir(parents=True, exist_ok=True)

        runtime_source = "pkg/enc_rt_pkg_1234.py"
        (pkg_dir / "enc_rt_pkg_1234.pyd").write_bytes(b"native-win")
        (pkg_dir / "enc_rt_pkg_1234.so").write_bytes(b"native-linux")
        manifest = {
            "runtime_files": [runtime_source],
            "runtime_delivery": {
                "mode": encryption_helper.RUNTIME_DELIVERY_MODE,
                "trust_policy": {
                    "runtime_suffix_policy": encryption_helper.RUNTIME_SUFFIX_POLICY_STRICT_SINGLE,
                    "runtime_native_suffixes": [".pyd", ".so"],
                },
            },
        }
        (staging_dir / "build_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RuntimeError, "mixed-platform runtime artifacts detected"):
            encryption_helper.validate_runtime_delivery(staging_dir, build_dir)

    def test_validate_runtime_delivery_requires_relocation_roots_when_trusted_relocation_enabled(self):
        root = self.make_case_root("runtime_validate_trusted_roots_required")
        staging_dir = root / "staging"
        build_dir = root / "build"
        pkg_dir = build_dir / "pkg"
        staging_dir.mkdir(parents=True, exist_ok=True)
        pkg_dir.mkdir(parents=True, exist_ok=True)

        runtime_source = "pkg/enc_rt_pkg_1234.py"
        (pkg_dir / "enc_rt_pkg_1234.pyd").write_bytes(b"native-binary")
        manifest = {
            "runtime_files": [runtime_source],
            "runtime_delivery": {
                "mode": encryption_helper.RUNTIME_DELIVERY_MODE,
                "trust_policy": {
                    "runtime_path_policy": encryption_helper.RUNTIME_PATH_POLICY_TRUSTED_RELOCATION,
                    "runtime_relocation_allowed": True,
                    "trusted_runtime_roots": [],
                },
            },
        }
        (staging_dir / "build_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RuntimeError, "trusted-relocation path policy requires trusted_runtime_roots"):
            encryption_helper.validate_runtime_delivery(staging_dir, build_dir)

    def test_e2e_compiled_flow_imports_and_executes_protected_symbols(self):
        self._ensure_compile_integration_ready()
        root = self.make_case_root("e2e_ok")
        package_name, module_name, output_dir, build_dir, manifest = self._build_compiled_fixture(root)

        runtime_delivery = manifest.get("runtime_delivery") or {}
        self.assertTrue(runtime_delivery.get("validated"))
        runtime_files = runtime_delivery.get("compiled_runtime_files") or []
        self.assertTrue(runtime_files)
        for relative_path in runtime_files:
            self.assertTrue((build_dir / relative_path).exists(), relative_path)

        module = self._import_compiled_module(build_dir, package_name, module_name)
        self.assertEqual(module.protected_sum(2, 5), 14)
        self.assertEqual(module.ProtectedBox(9).total(), 16)
        self.assertTrue((output_dir / "build_manifest.json").exists())

    def test_e2e_compiled_flow_detects_broken_runtime_chain(self):
        self._ensure_compile_integration_ready()
        root = self.make_case_root("e2e_bad")
        package_name, module_name, output_dir, build_dir, manifest = self._build_compiled_fixture(root)

        runtime_delivery = manifest.get("runtime_delivery") or {}
        runtime_files = runtime_delivery.get("compiled_runtime_files") or []
        self.assertTrue(runtime_files)

        broken_build_dir = root / "b"
        runtime_artifact_rel = Path(runtime_files[0])
        for path in build_dir.rglob("*"):
            rel = path.relative_to(build_dir)
            target = broken_build_dir / rel
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if rel == runtime_artifact_rel:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)

        with self.assertRaisesRegex(RuntimeError, "compiled runtime modules missing"):
            encryption_helper.validate_runtime_delivery(output_dir, broken_build_dir)
        with self.assertRaisesRegex(ModuleNotFoundError, "enc_rt_"):
            self._import_compiled_module(broken_build_dir, package_name, module_name)

    def test_e2e_compiled_flow_native_loader_executes_with_compiled_runtime(self):
        self._ensure_compile_integration_ready()
        root = self.make_case_root("e2e_native_loader_ok")
        package_name, module_name, _output_dir, build_dir, manifest = self._build_compiled_fixture(
            root,
            require_native_runtime_loader=True,
        )

        runtime_delivery = manifest.get("runtime_delivery") or {}
        self.assertTrue(runtime_delivery.get("validated"))
        self.assertTrue(runtime_delivery.get("loader_enforced"))
        self.assertEqual(
            runtime_delivery.get("loader_mode"),
            encryption_helper.RUNTIME_LOADER_MODE_NATIVE_ONLY,
        )

        module = self._import_compiled_module(build_dir, package_name, module_name)
        self.assertEqual(module.protected_sum(2, 5), 14)
        self.assertEqual(module.ProtectedBox(9).total(), 16)

    def test_e2e_compiled_flow_native_loader_rejects_python_runtime_substitution(self):
        self._ensure_compile_integration_ready()
        root = self.make_case_root("e2e_native_loader_bad")
        package_name, module_name, output_dir, build_dir, manifest = self._build_compiled_fixture(
            root,
            require_native_runtime_loader=True,
        )

        runtime_source_files = tuple(manifest.get("runtime_files") or ())
        runtime_delivery = manifest.get("runtime_delivery") or {}
        runtime_compiled_files = tuple(runtime_delivery.get("compiled_runtime_files") or ())
        self.assertTrue(runtime_source_files)
        self.assertTrue(runtime_compiled_files)

        tampered_build_dir = root / "b_native_sub"
        runtime_artifact_rel = Path(runtime_compiled_files[0])
        for path in build_dir.rglob("*"):
            rel = path.relative_to(build_dir)
            target = tampered_build_dir / rel
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if rel == runtime_artifact_rel:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)

        runtime_source_rel = Path(runtime_source_files[0])
        runtime_source = output_dir / runtime_source_rel
        runtime_target = tampered_build_dir / runtime_source_rel
        runtime_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(runtime_source, runtime_target)

        with self.assertRaisesRegex(RuntimeError, "native runtime loader required for module"):
            self._import_compiled_module(tampered_build_dir, package_name, module_name)

    def test_load_scope_config_accepts_utf8_bom(self):
        root = self.make_case_root("scope_bom")
        scope_path = root / "scope.json"
        scope_payload = {
            "pkg/mod2.py": {
                "functions": ["use_it"],
                "all": False,
            }
        }
        scope_path.write_text(json.dumps(scope_payload, ensure_ascii=False, indent=2), encoding="utf-8-sig")

        loaded = encryption_helper.load_scope_config(scope_path)

        self.assertEqual(loaded["pkg/mod2.py"]["functions"], ["use_it"])
        self.assertFalse(loaded["pkg/mod2.py"]["all"])

    def test_main_accepts_utf8_bom_project_files(self):
        root = self.make_case_root("scope_bom_cli")
        project_root = root / "demo_proj"
        pkg_root = project_root / "pkg"
        pkg_root.mkdir(parents=True, exist_ok=True)
        (pkg_root / "__init__.py").write_text("", encoding="utf-8-sig")
        (pkg_root / "mod1.py").write_text(
            "\n".join(
                [
                    "VALUE = 10",
                    "",
                    "def add(a, b):",
                    "    return a + b + VALUE",
                    "",
                    "class Box(object):",
                    "    def __init__(self, value):",
                    "        self.value = value",
                    "",
                    "    def total(self):",
                    "        return self.value + VALUE",
                    "",
                ]
            ),
            encoding="utf-8-sig",
        )
        (pkg_root / "mod2.py").write_text(
            "\n".join(
                [
                    "from .mod1 import add",
                    "",
                    "def use_it():",
                    "    return add(1, 2)",
                    "",
                ]
            ),
            encoding="utf-8-sig",
        )
        scope_path = project_root / "scope.json"
        scope_path.write_text(
            json.dumps(
                {
                    "pkg/mod2.py": {
                        "functions": ["use_it"],
                        "all": False,
                    }
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8-sig",
        )

        output_dir = root / "enc_out"
        exit_code = encryption_helper.main(
            [
                "-t",
                str(project_root),
                "-o",
                str(output_dir),
                "--scope-config",
                str(scope_path),
            ]
        )

        self.assertEqual(exit_code, 0)
        manifest_path = output_dir / "build_manifest.json"
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertTrue(manifest["processed_files"])
        protected_by_file = {
            item["relative_path"]: item["protected_symbols"] for item in manifest["processed_files"]
        }
        self.assertEqual(protected_by_file["pkg/mod2.py"], ["function:use_it"])
        self.assertTrue((output_dir / "pkg" / "mod2.py").exists())

    def test_namespace_root_separates_output_path_from_package_namespace(self):
        root = self.make_case_root("namespace_root")
        project_root = root / "A_py"
        pkg_root = project_root / "pkg"
        pkg_root.mkdir(parents=True, exist_ok=True)
        (project_root / "__init__.py").write_text("", encoding="utf-8")
        (pkg_root / "__init__.py").write_text("", encoding="utf-8")
        (pkg_root / "mod.py").write_text(
            "\n".join(
                [
                    "def hello():",
                    "    return 'ok'",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        output_dir = root / "other_enc_middle"
        exit_code = encryption_helper.main(
            [
                "-t",
                str(project_root),
                "-o",
                str(output_dir),
                "--namespace-root",
                "A",
            ]
        )
        self.assertEqual(exit_code, 0)

        protected_module = output_dir / "A" / "pkg" / "mod.py"
        self.assertTrue(protected_module.exists())

        protected_source = protected_module.read_text(encoding="utf-8")
        self.assertIn('if __package__ else "enc_rt_', protected_source)

        manifest_path = output_dir / "build_manifest.json"
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("namespace_package"), "A")
        rels = {item["relative_path"] for item in manifest["processed_files"]}
        self.assertIn("A/pkg/mod.py", rels)

    def test_infer_namespace_maps_a_py_to_a(self):
        root = self.make_case_root("infer_namespace")
        project_root = root / "A_py"
        pkg_root = project_root / "pkg"
        pkg_root.mkdir(parents=True, exist_ok=True)
        (project_root / "__init__.py").write_text("", encoding="utf-8")
        (pkg_root / "__init__.py").write_text("", encoding="utf-8")
        (pkg_root / "mod.py").write_text(
            "\n".join(
                [
                    "def hello():",
                    "    return 'ok'",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        output_dir = root / "other_enc_middle"
        exit_code = encryption_helper.main(
            [
                "-t",
                str(project_root),
                "-o",
                str(output_dir),
                "--infer-namespace",
            ]
        )
        self.assertEqual(exit_code, 0)
        self.assertTrue((output_dir / "A" / "pkg" / "mod.py").exists())

        manifest = json.loads((output_dir / "build_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("namespace_package"), "A")

    def test_directory_target_a_keeps_namespace_a_by_default(self):
        root = self.make_case_root("direct_a")
        project_root = root / "A"
        pkg_root = project_root / "b" / "c" / "d"
        pkg_root.mkdir(parents=True, exist_ok=True)
        for rel in (
            "__init__.py",
            "b/__init__.py",
            "b/c/__init__.py",
            "b/c/d/__init__.py",
        ):
            (project_root / rel).write_text("", encoding="utf-8")
        (pkg_root / "e.py").write_text(
            "\n".join(
                [
                    "def ping():",
                    "    return 'ok'",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        output_dir = root / "other_enc_middle"
        exit_code = encryption_helper.main(
            [
                "-t",
                str(project_root),
                "-o",
                str(output_dir),
            ]
        )
        self.assertEqual(exit_code, 0)
        self.assertTrue((output_dir / "A" / "b" / "c" / "d" / "e.py").exists())

        manifest = json.loads((output_dir / "build_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest.get("namespace_package"), "A")

    def test_vcvars_path_requires_auto_or_windows_profile(self):
        root = self.make_case_root("vcvars_profile_guard")
        source = root / "main.py"
        source.write_text("def ok():\n    return 1\n", encoding="utf-8")
        output_dir = root / "out"
        fake_vcvars = root / "vcvars64.bat"
        fake_vcvars.write_text("@echo off\r\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "--vcvars-path supports only auto/windows-msvc build profiles"):
            encryption_helper.main(
                [
                    "-t",
                    str(source),
                    "-o",
                    str(output_dir),
                    "--compile",
                    "--build-profile",
                    "native",
                    "--vcvars-path",
                    str(fake_vcvars),
                ]
            )

    def test_require_manifest_signature_needs_sign_key(self):
        root = self.make_case_root("require_sig_guard")
        source = root / "main.py"
        source.write_text("def ok():\n    return 1\n", encoding="utf-8")
        output_dir = root / "out"

        with self.assertRaisesRegex(ValueError, "--require-manifest-signature requires"):
            encryption_helper.main(
                [
                    "-t",
                    str(source),
                    "-o",
                    str(output_dir),
                    "--require-manifest-signature",
                ]
            )

    def test_main_emits_signed_manifest_when_sign_key_file_configured(self):
        root = self.make_case_root("manifest_sign_cli")
        source = root / "main.py"
        source.write_text("def ok():\n    return 1\n", encoding="utf-8")
        key_file = root / "manifest.key"
        key_file.write_bytes(b"0123456789abcdef0123456789abcdef")
        output_dir = root / "out"

        exit_code = encryption_helper.main(
            [
                "-t",
                str(source),
                "-o",
                str(output_dir),
                "--manifest-sign-key-file",
                str(key_file),
                "--manifest-key-id",
                "ops-signing",
            ]
        )
        self.assertEqual(exit_code, 0)
        manifest_path = output_dir / "build_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertIn("signature", manifest)
        self.assertEqual(manifest["signature"]["key_id"], "ops-signing")
        self.assertEqual(manifest["key_management"]["mode"], "local-embedded")

    def test_main_rejects_manifest_sign_key_source_conflict(self):
        root = self.make_case_root("manifest_sign_key_conflict")
        source = root / "main.py"
        source.write_text("def ok():\n    return 1\n", encoding="utf-8")
        key_file = root / "manifest.key"
        key_file.write_bytes(b"0123456789abcdef0123456789abcdef")
        output_dir = root / "out"

        with self.assertRaisesRegex(ValueError, "either file or base64"):
            encryption_helper.main(
                [
                    "-t",
                    str(source),
                    "-o",
                    str(output_dir),
                    "--manifest-sign-key-file",
                    str(key_file),
                    "--manifest-sign-key-b64",
                    "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
                ]
            )

    def test_default_python_executable_resolver_uses_current_interpreter(self):
        with mock.patch.object(encryption_helper, "resolve_python_executable", wraps=encryption_helper.resolve_python_executable) as wrapped:
            args = encryption_helper.parse_args(["-t", __file__])
            resolved = encryption_helper.resolve_python_executable(args.python_exe)
            self.assertEqual(resolved, Path(sys.executable).resolve())
            self.assertTrue(wrapped.called)

    def test_soenc_config_drives_mainline_defaults(self):
        root = self.make_case_root("soenc_cfg_defaults")
        project_root = root / "project"
        src_dir = project_root / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "m.py").write_text(
            "\n".join(
                [
                    "def v():",
                    "    return 9",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        scope_path = project_root / "scope.json"
        scope_path.write_text(
            json.dumps(
                {
                    "m.py": {
                        "functions": ["v"],
                        "all": False,
                    }
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        cfg_path = project_root / "soenc.toml"
        cfg_path.write_text(
            "\n".join(
                [
                    "[project]",
                    "target = \"./src\"",
                    "scope_config = \"./scope.json\"",
                    "",
                    "[build]",
                    "output_dir = \"./build_out\"",
                    "compile = false",
                    "skip_bad_files = false",
                    "",
                    "[keys]",
                    "mode = \"local-provider\"",
                    "",
                    "[package]",
                    "name = \"demo-protect\"",
                    "version = \"0.1.0\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        cwd_before = Path.cwd()
        os.chdir(project_root)
        try:
            exit_code = encryption_helper.main([])
        finally:
            os.chdir(cwd_before)
        self.assertEqual(exit_code, 0)

        output_dir = project_root / "build_out"
        manifest = json.loads((output_dir / "build_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["config"]["source"], str(cfg_path.resolve()))
        self.assertEqual(manifest["config"]["key_mode"], "local-embedded")
        self.assertEqual(manifest["key_management"]["mode"], "local-embedded")
        self.assertEqual(manifest["config"]["package_metadata"]["name"], "demo-protect")
        self.assertTrue((output_dir / "m.py").exists())

    def test_protect_source_emits_provider_key_ref_structure(self):
        source = "\n".join(
            [
                "def add(a, b):",
                "    return a + b",
                "",
            ]
        )
        symbols = encryption_helper.top_level_symbols(source)
        chosen = [item for item in symbols if item.kind == "function" and item.name == "add"]
        protected = encryption_helper.protect_source(
            source,
            runtime_module="enc_rt_demo",
            symbols_to_encrypt=chosen,
            key_mode="local-embedded",
        )

        self.assertIn("'mode': 'local-embedded'", protected)
        self.assertIn("'parts': [", protected)
        self.assertIn("enc_rt_demo", protected)

    def test_protect_source_native_loader_guard_fails_without_native_runtime(self):
        source = "\n".join(
            [
                "def protected_value():",
                "    return 7",
                "",
            ]
        )
        symbols = encryption_helper.top_level_symbols(source)
        chosen = [item for item in symbols if item.kind == "function" and item.name == "protected_value"]
        protected = encryption_helper.protect_source(
            source,
            runtime_module="enc_rt_demo",
            symbols_to_encrypt=chosen,
            key_mode="local-embedded",
            require_native_runtime_loader=True,
        )

        self.assertIn("native runtime loader required for module: enc_rt_demo", protected)

        root = self.make_case_root("native_guard")
        module_globals = {
            "__name__": "pkg.mod",
            "__package__": "pkg",
            "__file__": str((root / "pkg" / "mod.py")),
            "__builtins__": __builtins__,
        }
        runtime_stub = type("RuntimeStub", (), {})()
        runtime_stub.__name__ = "pkg.enc_rt_demo"
        runtime_stub.__file__ = str((root / "pkg" / "enc_rt_demo.py"))

        with mock.patch("importlib.import_module", return_value=runtime_stub):
            with self.assertRaisesRegex(RuntimeError, "native runtime loader required for module: enc_rt_demo"):
                exec(protected, module_globals, module_globals)

    def test_protect_source_native_loader_guard_accepts_runtime_marker_and_matching_path(self):
        source = "\n".join(
            [
                "def protected_value():",
                "    return 7",
                "",
            ]
        )
        symbols = encryption_helper.top_level_symbols(source)
        chosen = [item for item in symbols if item.kind == "function" and item.name == "protected_value"]
        protected = encryption_helper.protect_source(
            source,
            runtime_module="enc_rt_demo",
            symbols_to_encrypt=chosen,
            key_mode="local-embedded",
            require_native_runtime_loader=True,
        )

        root = self.make_case_root("native_guard_ok")
        pkg_dir = root / "pkg"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        mod_file = pkg_dir / "mod.py"
        mod_file.write_text("", encoding="utf-8")
        runtime_file = pkg_dir / "enc_rt_demo.pyd"
        runtime_file.write_bytes(b"native")
        runtime_digest = hashlib.sha256(runtime_file.read_bytes()).hexdigest()
        (root / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_delivery": {
                        "compiled_runtime_fingerprints": [
                            {
                                "module_name": "enc_rt_demo",
                                "compiled_relative_path": "pkg/enc_rt_demo.pyd",
                                "algorithm": "sha256",
                                "digest_hex": runtime_digest,
                            }
                        ],
                        "trust_policy": {"require_runtime_fingerprint": True},
                    }
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        module_globals = {
            "__name__": "pkg.mod",
            "__package__": "pkg",
            "__file__": str(mod_file),
            "__builtins__": __builtins__,
        }
        runtime_stub = type("RuntimeStub", (), {})()
        runtime_stub.__name__ = "pkg.enc_rt_demo"
        runtime_stub.__file__ = str(runtime_file)
        runtime_stub.__spec__ = type("SpecStub", (), {"origin": str(runtime_file)})()
        runtime_stub.SOENC_RUNTIME_API_MARKER = encryption_helper.RUNTIME_API_MARKER
        runtime_stub.SOENC_RUNTIME_API_VERSION = encryption_helper.RUNTIME_API_VERSION
        runtime_stub._x = lambda *_args, _ns=None, **_kwargs: (_args[2].update({"VALUE": 7}) if len(_args) >= 3 else None)

        with mock.patch("importlib.import_module", return_value=runtime_stub):
            exec(protected, module_globals, module_globals)
        self.assertEqual(module_globals["VALUE"], 7)

    def test_protect_source_native_loader_guard_fails_on_runtime_fingerprint_mismatch(self):
        source = "\n".join(
            [
                "def protected_value():",
                "    return 7",
                "",
            ]
        )
        symbols = encryption_helper.top_level_symbols(source)
        chosen = [item for item in symbols if item.kind == "function" and item.name == "protected_value"]
        protected = encryption_helper.protect_source(
            source,
            runtime_module="enc_rt_demo",
            symbols_to_encrypt=chosen,
            key_mode="local-embedded",
            require_native_runtime_loader=True,
        )

        root = self.make_case_root("native_guard_fingerprint_bad")
        pkg_dir = root / "pkg"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        mod_file = pkg_dir / "mod.py"
        mod_file.write_text("", encoding="utf-8")
        runtime_file = pkg_dir / "enc_rt_demo.pyd"
        runtime_file.write_bytes(b"native-one")
        expected_digest = hashlib.sha256(b"native-two").hexdigest()
        (root / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_delivery": {
                        "compiled_runtime_fingerprints": [
                            {
                                "module_name": "enc_rt_demo",
                                "compiled_relative_path": "pkg/enc_rt_demo.pyd",
                                "algorithm": "sha256",
                                "digest_hex": expected_digest,
                            }
                        ],
                        "trust_policy": {"require_runtime_fingerprint": True},
                    }
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        module_globals = {
            "__name__": "pkg.mod",
            "__package__": "pkg",
            "__file__": str(mod_file),
            "__builtins__": __builtins__,
        }
        runtime_stub = type("RuntimeStub", (), {})()
        runtime_stub.__name__ = "pkg.enc_rt_demo"
        runtime_stub.__file__ = str(runtime_file)
        runtime_stub.__spec__ = type("SpecStub", (), {"origin": str(runtime_file)})()
        runtime_stub.SOENC_RUNTIME_API_MARKER = encryption_helper.RUNTIME_API_MARKER
        runtime_stub.SOENC_RUNTIME_API_VERSION = encryption_helper.RUNTIME_API_VERSION
        runtime_stub._x = lambda *_args, **_kwargs: None

        with mock.patch("importlib.import_module", return_value=runtime_stub):
            with self.assertRaisesRegex(RuntimeError, "runtime fingerprint mismatch for module: enc_rt_demo"):
                exec(protected, module_globals, module_globals)

    def test_protect_source_native_loader_guard_fails_on_runtime_marker_mismatch(self):
        source = "\n".join(
            [
                "def protected_value():",
                "    return 7",
                "",
            ]
        )
        symbols = encryption_helper.top_level_symbols(source)
        chosen = [item for item in symbols if item.kind == "function" and item.name == "protected_value"]
        protected = encryption_helper.protect_source(
            source,
            runtime_module="enc_rt_demo",
            symbols_to_encrypt=chosen,
            key_mode="local-embedded",
            require_native_runtime_loader=True,
        )

        root = self.make_case_root("native_guard_marker_bad")
        pkg_dir = root / "pkg"
        pkg_dir.mkdir(parents=True, exist_ok=True)
        mod_file = pkg_dir / "mod.py"
        mod_file.write_text("", encoding="utf-8")
        runtime_file = pkg_dir / "enc_rt_demo.pyd"
        runtime_file.write_bytes(b"native")

        module_globals = {
            "__name__": "pkg.mod",
            "__package__": "pkg",
            "__file__": str(mod_file),
            "__builtins__": __builtins__,
        }
        runtime_stub = type("RuntimeStub", (), {})()
        runtime_stub.__name__ = "pkg.enc_rt_demo"
        runtime_stub.__file__ = str(runtime_file)
        runtime_stub.__spec__ = type("SpecStub", (), {"origin": str(runtime_file)})()
        runtime_stub.SOENC_RUNTIME_API_MARKER = "unexpected-marker"
        runtime_stub.SOENC_RUNTIME_API_VERSION = encryption_helper.RUNTIME_API_VERSION
        runtime_stub._x = lambda *_args, **_kwargs: None

        with mock.patch("importlib.import_module", return_value=runtime_stub):
            with self.assertRaisesRegex(RuntimeError, "runtime api marker mismatch for module: enc_rt_demo"):
                exec(protected, module_globals, module_globals)

    def test_protect_source_native_loader_guard_fails_on_runtime_path_redirection(self):
        source = "\n".join(
            [
                "def protected_value():",
                "    return 7",
                "",
            ]
        )
        symbols = encryption_helper.top_level_symbols(source)
        chosen = [item for item in symbols if item.kind == "function" and item.name == "protected_value"]
        protected = encryption_helper.protect_source(
            source,
            runtime_module="enc_rt_demo",
            symbols_to_encrypt=chosen,
            key_mode="local-embedded",
            require_native_runtime_loader=True,
        )

        root = self.make_case_root("native_guard_path_bad")
        expected_pkg = root / "pkg"
        other_pkg = root / "other_pkg"
        expected_pkg.mkdir(parents=True, exist_ok=True)
        other_pkg.mkdir(parents=True, exist_ok=True)
        mod_file = expected_pkg / "mod.py"
        mod_file.write_text("", encoding="utf-8")
        runtime_file = other_pkg / "enc_rt_demo.pyd"
        runtime_file.write_bytes(b"native")
        runtime_digest = hashlib.sha256(runtime_file.read_bytes()).hexdigest()
        (root / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_delivery": {
                        "compiled_runtime_fingerprints": [
                            {
                                "module_name": "enc_rt_demo",
                                "compiled_relative_path": "other_pkg/enc_rt_demo.pyd",
                                "algorithm": "sha256",
                                "digest_hex": runtime_digest,
                            }
                        ],
                        "trust_policy": {"require_runtime_fingerprint": True},
                    }
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        module_globals = {
            "__name__": "pkg.mod",
            "__package__": "pkg",
            "__file__": str(mod_file),
            "__builtins__": __builtins__,
        }
        runtime_stub = type("RuntimeStub", (), {})()
        runtime_stub.__name__ = "pkg.enc_rt_demo"
        runtime_stub.__file__ = str(runtime_file)
        runtime_stub.__spec__ = type("SpecStub", (), {"origin": str(runtime_file)})()
        runtime_stub.SOENC_RUNTIME_API_MARKER = encryption_helper.RUNTIME_API_MARKER
        runtime_stub.SOENC_RUNTIME_API_VERSION = encryption_helper.RUNTIME_API_VERSION
        runtime_stub._x = lambda *_args, **_kwargs: None

        with mock.patch("importlib.import_module", return_value=runtime_stub):
            with self.assertRaisesRegex(
                RuntimeError,
                "runtime module path escaped expected package directory for module: enc_rt_demo",
            ):
                exec(protected, module_globals, module_globals)

    def test_protect_source_native_loader_guard_accepts_trusted_relocation(self):
        source = "\n".join(
            [
                "def protected_value():",
                "    return 7",
                "",
            ]
        )
        symbols = encryption_helper.top_level_symbols(source)
        chosen = [item for item in symbols if item.kind == "function" and item.name == "protected_value"]
        protected = encryption_helper.protect_source(
            source,
            runtime_module="enc_rt_demo",
            symbols_to_encrypt=chosen,
            key_mode="local-embedded",
            require_native_runtime_loader=True,
        )

        root = self.make_case_root("native_guard_trusted_reloc_ok")
        expected_pkg = root / "pkg"
        trusted_root = root / "trusted_rt"
        expected_pkg.mkdir(parents=True, exist_ok=True)
        trusted_root.mkdir(parents=True, exist_ok=True)
        mod_file = expected_pkg / "mod.py"
        mod_file.write_text("", encoding="utf-8")
        runtime_file = trusted_root / "enc_rt_demo.pyd"
        runtime_file.write_bytes(b"native")
        runtime_digest = hashlib.sha256(runtime_file.read_bytes()).hexdigest()
        (root / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_delivery": {
                        "compiled_runtime_fingerprints": [
                            {
                                "module_name": "enc_rt_demo",
                                "compiled_relative_path": "trusted_rt/enc_rt_demo.pyd",
                                "algorithm": "sha256",
                                "digest_hex": runtime_digest,
                            }
                        ],
                        "trust_policy": {
                            "require_runtime_fingerprint": True,
                            "runtime_path_policy": "trusted-relocation",
                            "runtime_relocation_allowed": True,
                            "trusted_runtime_roots": ["trusted_rt"],
                        },
                    }
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        module_globals = {
            "__name__": "pkg.mod",
            "__package__": "pkg",
            "__file__": str(mod_file),
            "__builtins__": __builtins__,
        }
        runtime_stub = type("RuntimeStub", (), {})()
        runtime_stub.__name__ = "pkg.enc_rt_demo"
        runtime_stub.__file__ = str(runtime_file)
        runtime_stub.__spec__ = type("SpecStub", (), {"origin": str(runtime_file)})()
        runtime_stub.SOENC_RUNTIME_API_MARKER = encryption_helper.RUNTIME_API_MARKER
        runtime_stub.SOENC_RUNTIME_API_VERSION = encryption_helper.RUNTIME_API_VERSION
        runtime_stub._x = lambda *_args, _ns=None, **_kwargs: (_args[2].update({"VALUE": 7}) if len(_args) >= 3 else None)

        with mock.patch("importlib.import_module", return_value=runtime_stub):
            exec(protected, module_globals, module_globals)
        self.assertEqual(module_globals["VALUE"], 7)

    def test_protect_source_native_loader_guard_rejects_untrusted_relocation_root(self):
        source = "\n".join(
            [
                "def protected_value():",
                "    return 7",
                "",
            ]
        )
        symbols = encryption_helper.top_level_symbols(source)
        chosen = [item for item in symbols if item.kind == "function" and item.name == "protected_value"]
        protected = encryption_helper.protect_source(
            source,
            runtime_module="enc_rt_demo",
            symbols_to_encrypt=chosen,
            key_mode="local-embedded",
            require_native_runtime_loader=True,
        )

        root = self.make_case_root("native_guard_trusted_reloc_bad")
        expected_pkg = root / "pkg"
        other_pkg = root / "other_pkg"
        expected_pkg.mkdir(parents=True, exist_ok=True)
        other_pkg.mkdir(parents=True, exist_ok=True)
        mod_file = expected_pkg / "mod.py"
        mod_file.write_text("", encoding="utf-8")
        runtime_file = other_pkg / "enc_rt_demo.pyd"
        runtime_file.write_bytes(b"native")
        runtime_digest = hashlib.sha256(runtime_file.read_bytes()).hexdigest()
        (root / "build_manifest.json").write_text(
            json.dumps(
                {
                    "runtime_delivery": {
                        "compiled_runtime_fingerprints": [
                            {
                                "module_name": "enc_rt_demo",
                                "compiled_relative_path": "other_pkg/enc_rt_demo.pyd",
                                "algorithm": "sha256",
                                "digest_hex": runtime_digest,
                            }
                        ],
                        "trust_policy": {
                            "require_runtime_fingerprint": True,
                            "runtime_path_policy": "trusted-relocation",
                            "runtime_relocation_allowed": True,
                            "trusted_runtime_roots": ["trusted_rt"],
                        },
                    }
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        module_globals = {
            "__name__": "pkg.mod",
            "__package__": "pkg",
            "__file__": str(mod_file),
            "__builtins__": __builtins__,
        }
        runtime_stub = type("RuntimeStub", (), {})()
        runtime_stub.__name__ = "pkg.enc_rt_demo"
        runtime_stub.__file__ = str(runtime_file)
        runtime_stub.__spec__ = type("SpecStub", (), {"origin": str(runtime_file)})()
        runtime_stub.SOENC_RUNTIME_API_MARKER = encryption_helper.RUNTIME_API_MARKER
        runtime_stub.SOENC_RUNTIME_API_VERSION = encryption_helper.RUNTIME_API_VERSION
        runtime_stub._x = lambda *_args, **_kwargs: None

        with mock.patch("importlib.import_module", return_value=runtime_stub):
            with self.assertRaisesRegex(
                RuntimeError,
                "runtime relocation root not trusted for module: enc_rt_demo",
            ):
                exec(protected, module_globals, module_globals)

    def test_main_runtime_native_loader_toggle_sets_manifest_loader_mode(self):
        root = self.make_case_root("runtime_loader_manifest")
        source = root / "main.py"
        source.write_text("def ok():\n    return 1\n", encoding="utf-8")
        output_dir = root / "out"

        exit_code = encryption_helper.main(
            [
                "-t",
                str(source),
                "-o",
                str(output_dir),
                "--runtime-native-loader",
            ]
        )
        self.assertEqual(exit_code, 0)
        manifest = json.loads((output_dir / "build_manifest.json").read_text(encoding="utf-8"))
        runtime_delivery = manifest.get("runtime_delivery") or {}
        self.assertTrue(runtime_delivery.get("loader_enforced"))
        self.assertEqual(
            runtime_delivery.get("loader_mode"),
            encryption_helper.RUNTIME_LOADER_MODE_NATIVE_ONLY,
        )
        trust_policy = runtime_delivery.get("trust_policy") or {}
        self.assertEqual(trust_policy.get("runtime_api_marker"), encryption_helper.RUNTIME_API_MARKER)
        self.assertEqual(trust_policy.get("runtime_api_version"), encryption_helper.RUNTIME_API_VERSION)
        self.assertEqual(
            trust_policy.get("runtime_path_policy"),
            encryption_helper.RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR,
        )
        self.assertFalse(trust_policy.get("runtime_relocation_allowed"))
        self.assertEqual(trust_policy.get("trusted_runtime_roots"), [])
        self.assertEqual(
            trust_policy.get("runtime_suffix_policy"),
            encryption_helper.RUNTIME_SUFFIX_POLICY_STRICT_SINGLE,
        )
        self.assertTrue(trust_policy.get("runtime_native_suffixes"))
        self.assertTrue(trust_policy.get("spec_origin_match"))
        self.assertEqual(
            trust_policy.get("runtime_fingerprint_algorithm"),
            encryption_helper.RUNTIME_FINGERPRINT_ALGORITHM_SHA256,
        )
        self.assertEqual(
            trust_policy.get("runtime_fingerprint_binding"),
            encryption_helper.RUNTIME_FINGERPRINT_BINDING_MANIFEST_COMPILED,
        )
        self.assertTrue(trust_policy.get("require_runtime_fingerprint"))

    def test_cli_overrides_soenc_config_values(self):
        root = self.make_case_root("soenc_cfg_override")
        project_root = root / "project"
        src_dir = project_root / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "m.py").write_text("def v():\n    return 1\n", encoding="utf-8")
        cfg_path = project_root / "soenc.toml"
        cfg_path.write_text(
            "\n".join(
                [
                    "[project]",
                    "target = \"./src\"",
                    "",
                    "[build]",
                    "output_dir = \"./out_from_cfg\"",
                    "compile = true",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        output_override = project_root / "out_from_cli"

        exit_code = encryption_helper.main(
            [
                "--config",
                str(cfg_path),
                "--output-dir",
                str(output_override),
                "--no-compile",
            ]
        )
        self.assertEqual(exit_code, 0)
        self.assertTrue((output_override / "build_manifest.json").exists())
        self.assertFalse((output_override / "build").exists())

    def test_license_file_mode_generates_license_and_runtime_executes(self):
        root = self.make_case_root("license_mode_ok")
        project_root = root / "project"
        pkg = project_root / "pkg"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "mod.py").write_text(
            "\n".join(
                [
                    "BASE = 3",
                    "",
                    "def protected_sum(a, b):",
                    "    return a + b + BASE",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        cfg_path = project_root / "soenc.toml"
        cfg_path.write_text(
            "\n".join(
                [
                    "[project]",
                    "target = \"./pkg\"",
                    "",
                    "[build]",
                    "output_dir = \"./out\"",
                    "compile = false",
                    "",
                    "[keys]",
                    "mode = \"license-file\"",
                    "license_file = \"licenses/customer.license.json\"",
                    "license_id = \"customer-a\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        exit_code = encryption_helper.main(["--config", str(cfg_path)])
        self.assertEqual(exit_code, 0)
        output_dir = project_root / "out"
        manifest = json.loads((output_dir / "build_manifest.json").read_text(encoding="utf-8"))
        key_mgmt = manifest.get("key_management") or {}
        self.assertEqual(key_mgmt.get("mode"), "license-file")
        self.assertEqual(key_mgmt.get("license_file"), "licenses/customer.license.json")
        self.assertEqual(key_mgmt.get("license_id"), "customer-a")

        license_path = output_dir / "licenses" / "customer.license.json"
        self.assertTrue(license_path.exists())
        module = self._import_module_from_root(output_dir, "pkg", "mod")
        self.assertEqual(module.protected_sum(4, 5), 12)

    def test_license_file_mode_rejects_tampered_license(self):
        root = self.make_case_root("license_mode_tamper")
        project_root = root / "project"
        pkg = project_root / "pkg"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "mod.py").write_text(
            "\n".join(
                [
                    "def secret_value():",
                    "    return 42",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        cfg_path = project_root / "soenc.toml"
        cfg_path.write_text(
            "\n".join(
                [
                    "[project]",
                    "target = \"./pkg\"",
                    "",
                    "[build]",
                    "output_dir = \"./out\"",
                    "compile = false",
                    "",
                    "[keys]",
                    "mode = \"license-file\"",
                    "license_file = \"licenses/customer.license.json\"",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        exit_code = encryption_helper.main(["--config", str(cfg_path)])
        self.assertEqual(exit_code, 0)
        output_dir = project_root / "out"
        license_path = output_dir / "licenses" / "customer.license.json"
        payload = json.loads(license_path.read_text(encoding="utf-8"))
        first_key = next(iter(payload["keys"]))
        payload["keys"][first_key] = "AAAAAAAAAAAAAAAAAAAAAA=="
        license_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "license integrity mismatch"):
            self._import_module_from_root(output_dir, "pkg", "mod")

    def test_remote_kms_mode_emits_stub_key_contract_and_runtime_fails_closed(self):
        root = self.make_case_root("remote_kms_mode")
        project_root = root / "project"
        pkg = project_root / "pkg"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        (pkg / "mod.py").write_text(
            "\n".join(
                [
                    "def protected_value():",
                    "    return 99",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        cfg_path = project_root / "soenc.toml"
        cfg_path.write_text(
            "\n".join(
                [
                    "[project]",
                    "target = \"./pkg\"",
                    "",
                    "[build]",
                    "output_dir = \"./out\"",
                    "compile = false",
                    "",
                    "[keys]",
                    "mode = \"remote-kms\"",
                    "kms_profile = \"prod\"",
                    "kms_endpoint = \"https://kms.example.local/v1\"",
                    "kms_key_id = \"main-key\"",
                    "kms_token_env = \"SOENC_KMS_TEST_TOKEN\"",
                    "kms_timeout_sec = 4.5",
                    "kms_max_retries = 3",
                    "kms_retry_backoff_ms = 700",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        exit_code = encryption_helper.main(["--config", str(cfg_path)])
        self.assertEqual(exit_code, 0)
        output_dir = project_root / "out"
        manifest = json.loads((output_dir / "build_manifest.json").read_text(encoding="utf-8"))
        key_mgmt = manifest.get("key_management") or {}
        self.assertEqual(key_mgmt.get("mode"), "remote-kms")
        self.assertEqual(key_mgmt.get("provider"), "enc2sop.keys.remote_kms")
        self.assertEqual(key_mgmt.get("kms_profile"), "prod")
        self.assertEqual(key_mgmt.get("kms_endpoint"), "https://kms.example.local/v1")
        self.assertEqual(key_mgmt.get("kms_key_id"), "main-key")
        self.assertEqual(key_mgmt.get("kms_token_env"), "SOENC_KMS_TEST_TOKEN")
        self.assertTrue((key_mgmt.get("kms_stub") or {}).get("enabled"))

        protected_source = (output_dir / "pkg" / "mod.py").read_text(encoding="utf-8")
        self.assertIn("'mode': 'remote-kms'", protected_source)
        self.assertIn("'request': {'schema': 'enc2sop-kms-request/v1'", protected_source)
        self.assertIn("'operation': 'unwrap_data_key'", protected_source)
        self.assertIn("'token_env': 'SOENC_KMS_TEST_TOKEN'", protected_source)
        self.assertIn("'retry_policy': {'max_retries': 3, 'backoff_ms': 700", protected_source)

        with self.assertRaisesRegex(RuntimeError, "token env var is missing"):
            self._import_module_from_root(output_dir, "pkg", "mod")

        with mock.patch.dict(os.environ, {"SOENC_KMS_TEST_TOKEN": "token-value"}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "runtime integration is stubbed"):
                self._import_module_from_root(output_dir, "pkg", "mod")

    def test_remote_kms_cli_args_require_remote_kms_mode(self):
        root = self.make_case_root("remote_kms_cli_guard")
        source = root / "main.py"
        source.write_text("def ok():\n    return 1\n", encoding="utf-8")
        output_dir = root / "out"
        with self.assertRaisesRegex(ValueError, "require keys.mode=remote-kms"):
            encryption_helper.main(
                [
                    "-t",
                    str(source),
                    "-o",
                    str(output_dir),
                    "--kms-profile",
                    "prod",
                ]
            )


if __name__ == "__main__":
    unittest.main()
