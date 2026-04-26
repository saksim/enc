import json
import shutil
import unittest
import uuid
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
