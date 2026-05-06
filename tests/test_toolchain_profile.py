import unittest
from pathlib import Path
from unittest import mock
import shutil

import toolchain_profile


class ToolchainProfileTests(unittest.TestCase):
    def test_resolve_build_profile_defaults_to_auto(self):
        self.assertEqual(toolchain_profile.resolve_build_profile(environ={}), toolchain_profile.DEFAULT_BUILD_PROFILE)

    def test_resolve_build_profile_rejects_invalid_value(self):
        with self.assertRaisesRegex(ValueError, "invalid build profile"):
            toolchain_profile.resolve_build_profile(profile="bad-profile", environ={})

    def test_resolve_python_executable_uses_env_override(self):
        fake_python = Path(".") / "fake_python.exe"
        resolved = toolchain_profile.resolve_python_executable(
            python_exe=None,
            environ={toolchain_profile.ENV_PYTHON_EXE: str(fake_python)},
        )
        self.assertEqual(resolved, fake_python.resolve())

    def test_discover_vcvars64_uses_env_override(self):
        with mock.patch.object(toolchain_profile.os, "name", "nt"):
            temp_dir = Path(__file__).resolve().parents[1] / ".tmp_test_runs" / "toolchain_profile"
            temp_dir.mkdir(parents=True, exist_ok=True)
            self.addCleanup(lambda: shutil.rmtree(str(temp_dir), ignore_errors=True))
            vcvars = temp_dir / "vcvars64.bat"
            vcvars.write_text("@echo off\r\n", encoding="utf-8")

            discovered = toolchain_profile.discover_vcvars64(
                environ={toolchain_profile.ENV_VCVARS64: str(vcvars)}
            )
            self.assertEqual(discovered, vcvars.resolve())

    def test_prepare_windows_build_env_raises_actionable_error_without_toolchain(self):
        with mock.patch.object(toolchain_profile.os, "name", "nt"):
            with mock.patch.object(toolchain_profile.shutil, "which", return_value=None):
                with mock.patch.object(toolchain_profile, "discover_vcvars64", return_value=None):
                    with self.assertRaisesRegex(RuntimeError, "MSVC toolchain not found"):
                        toolchain_profile.prepare_windows_build_env(
                            output_dir=Path(".").resolve(),
                            profile=toolchain_profile.BUILD_PROFILE_WINDOWS_MSVC,
                            environ={"PATH": ""},
                        )

    def test_prepare_windows_build_env_native_profile_returns_input_env_copy(self):
        with mock.patch.object(toolchain_profile.os, "name", "nt"):
            env = {"PATH": "C:\\bin"}
            prepared = toolchain_profile.prepare_windows_build_env(
                output_dir=Path(".").resolve(),
                profile=toolchain_profile.BUILD_PROFILE_NATIVE,
                environ=env,
            )
            self.assertEqual(prepared["PATH"], "C:\\bin")
            self.assertIsNot(prepared, env)


if __name__ == "__main__":
    unittest.main()
