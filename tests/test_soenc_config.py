import sys
import tempfile
import unittest
from pathlib import Path

import soenc_config


class SoencConfigTests(unittest.TestCase):
    def test_load_project_config_parses_sections_and_resolves_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            cfg_path = root / "soenc.toml"
            (root / "src").mkdir(parents=True, exist_ok=True)
            (root / "cfg").mkdir(parents=True, exist_ok=True)
            (root / "keys").mkdir(parents=True, exist_ok=True)
            cfg_path.write_text(
                "\n".join(
                    [
                        "[project]",
                        "target = \"./src\"",
                        "scope_config = \"./cfg/scope.json\"",
                        "namespace_root = \"A\"",
                        "infer_namespace = true",
                        "",
                        "[build]",
                        "output_dir = \"./out\"",
                        "dist_dir = \"./dist\"",
                        "compile = true",
                        "runtime_native_loader = true",
                        "precheck_only = false",
                        "skip_bad_files = true",
                        "build_profile = \"auto\"",
                        "",
                        "[keys]",
                        "mode = \"local-provider\"",
                        "manifest_sign_key_file = \"./keys/manifest.key\"",
                        "manifest_key_id = \"team-a\"",
                        "require_manifest_signature = true",
                        "license_file = \"licenses/customer.license.json\"",
                        "license_id = \"customer-a\"",
                        "kms_profile = \"prod\"",
                        "kms_endpoint = \"https://kms.example.local/v1\"",
                        "kms_key_id = \"team-main\"",
                        "kms_token_env = \"SOENC_KMS_TOKEN\"",
                        "kms_timeout_sec = 4.5",
                        "kms_max_retries = 3",
                        "kms_retry_backoff_ms = 700",
                        "",
                        "[package]",
                        "name = \"demo\"",
                        "version = \"1.0.0\"",
                        "vendor = \"acme\"",
                        "channel = \"stable\"",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            project = soenc_config.load_project_config(str(cfg_path), base_dir=root)

            self.assertIsNotNone(project)
            self.assertEqual(project.path, cfg_path)
            self.assertEqual(project.key_mode, "local-embedded")
            self.assertEqual(project.package_metadata["name"], "demo")
            self.assertEqual(project.cli_defaults["manifest_key_id"], "team-a")
            self.assertEqual(
                project.cli_defaults["manifest_sign_key_file"],
                str((root / "keys" / "manifest.key").resolve()),
            )
            self.assertTrue(project.cli_defaults["require_manifest_signature"])
            self.assertEqual(project.cli_defaults["license_file"], "licenses/customer.license.json")
            self.assertEqual(project.cli_defaults["license_id"], "customer-a")
            self.assertEqual(project.cli_defaults["kms_profile"], "prod")
            self.assertEqual(project.cli_defaults["kms_endpoint"], "https://kms.example.local/v1")
            self.assertEqual(project.cli_defaults["kms_key_id"], "team-main")
            self.assertEqual(project.cli_defaults["kms_token_env"], "SOENC_KMS_TOKEN")
            self.assertEqual(project.cli_defaults["kms_timeout_sec"], 4.5)
            self.assertEqual(project.cli_defaults["kms_max_retries"], 3)
            self.assertEqual(project.cli_defaults["kms_retry_backoff_ms"], 700)
            self.assertEqual(project.cli_defaults["target"], str((root / "src").resolve()))
            self.assertEqual(project.cli_defaults["scope_config"], str((root / "cfg" / "scope.json").resolve()))
            self.assertEqual(project.cli_defaults["output_dir"], str((root / "out").resolve()))
            self.assertEqual(project.cli_defaults["dist_dir"], str((root / "dist").resolve()))
            self.assertTrue(project.cli_defaults["compile"])
            self.assertTrue(project.cli_defaults["runtime_native_loader"])
            self.assertTrue(project.cli_defaults["skip_bad_files"])

    def test_load_project_config_rejects_invalid_profile(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            cfg_path = root / "soenc.toml"
            cfg_path.write_text(
                "\n".join(
                    [
                        "[project]",
                        "target = \"./src\"",
                        "",
                        "[build]",
                        "build_profile = \"broken\"",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(soenc_config.SoencConfigError, "build.build_profile must be one of"):
                soenc_config.load_project_config(str(cfg_path), base_dir=root)

    def test_load_project_config_rejects_invalid_remote_kms_retry_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            cfg_path = root / "soenc.toml"
            cfg_path.write_text(
                "\n".join(
                    [
                        "[project]",
                        "target = \"./src\"",
                        "",
                        "[keys]",
                        "mode = \"remote-kms\"",
                        "kms_max_retries = -1",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(soenc_config.SoencConfigError, "keys.kms_max_retries must be >= 0"):
                soenc_config.load_project_config(str(cfg_path), base_dir=root)

    def test_load_project_config_requires_toml_parser_on_old_python(self):
        if sys.version_info >= (3, 11):
            self.skipTest("only relevant for Python < 3.11")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            cfg_path = root / "soenc.toml"
            cfg_path.write_text("[project]\ntarget = \"./src\"\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                soenc_config.load_project_config(str(cfg_path), base_dir=root)


if __name__ == "__main__":
    unittest.main()
