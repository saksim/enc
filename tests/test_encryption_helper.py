import json
import importlib
import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

import encryption_helper


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


class EncryptionHelperTests(WorkspaceTempMixin, unittest.TestCase):
    def _ensure_compile_integration_ready(self):
        if importlib.util.find_spec("Cython") is None:
            self.skipTest("Cython is not installed; skipping compile integration test")
        if os.name == "nt" and encryption_helper.find_vcvars64() is None:
            self.skipTest("MSVC vcvars64.bat not found; skipping compile integration test")

    def _build_compiled_fixture(self, root):
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
        exit_code = encryption_helper.main(
            [
                "-t",
                str(project_root),
                "-o",
                str(output_dir),
                "--compile",
                "--python-exe",
                sys.executable,
            ]
        )
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


if __name__ == "__main__":
    unittest.main()
