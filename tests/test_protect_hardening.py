import unittest
from types import SimpleNamespace
from unittest import mock

from enc2sop.protect.hardening import HARDENING_CAVEAT
from enc2sop.protect.hardening import apply_native_extension_hardening
from enc2sop.protect.hardening import cython_compiler_directives
from enc2sop.protect.hardening import hardening_manifest
from enc2sop.protect.hardening import native_extension_hardening_options
from enc2sop.protect.hardening import normalize_hardening_profile
from enc2sop.protect.hardening import strip_native_symbols


class ProtectHardeningTests(unittest.TestCase):
    def test_profile_normalization_and_rejection(self):
        self.assertEqual(normalize_hardening_profile(None), "off")
        self.assertEqual(normalize_hardening_profile("BALANCED"), "balanced")
        with self.assertRaisesRegex(ValueError, "hardening_profile must be one of"):
            normalize_hardening_profile("unsafe")

    def test_cython_directives_for_balanced_profile(self):
        self.assertEqual(cython_compiler_directives("off"), {"always_allow_keywords": True})
        directives = cython_compiler_directives("balanced")
        self.assertTrue(directives["always_allow_keywords"])
        self.assertFalse(directives["binding"])
        self.assertFalse(directives["embedsignature"])
        self.assertFalse(directives["emit_code_comments"])

    def test_native_options_are_platform_specific(self):
        linux = native_extension_hardening_options("balanced", platform_name="linux", os_name="posix")
        self.assertIn("-fvisibility=hidden", linux["compile_args"])
        self.assertIn("-Wl,-s", linux["link_args"])
        self.assertTrue(linux["strip_symbols"])

        windows = native_extension_hardening_options("balanced", platform_name="win32", os_name="nt")
        self.assertIn("/O2", windows["compile_args"])
        self.assertIn("/OPT:REF", windows["link_args"])
        self.assertFalse(windows["strip_symbols"])

    def test_apply_native_extension_hardening_appends_flags_once(self):
        options = native_extension_hardening_options("balanced")
        first_compile_arg = (options.get("compile_args") or ())[0]
        ext = SimpleNamespace(extra_compile_args=[first_compile_arg], extra_link_args=[])
        apply_native_extension_hardening([ext], "balanced")
        apply_native_extension_hardening([ext], "balanced")
        self.assertEqual(ext.extra_compile_args.count(first_compile_arg), 1)
        for item in options.get("compile_args") or ():
            self.assertIn(item, ext.extra_compile_args)
        for item in options.get("link_args") or ():
            self.assertIn(item, ext.extra_link_args)

    def test_hardening_manifest_keeps_security_caveat(self):
        manifest = hardening_manifest("balanced")
        self.assertEqual(manifest["profile"], "balanced")
        self.assertTrue(manifest["native_build_required"])
        self.assertIn("reverse-engineering cost only", manifest["caveat"])
        self.assertEqual(manifest["caveat"], HARDENING_CAVEAT)

    def test_strip_symbols_skips_without_tool_or_when_platform_disables_strip(self):
        with mock.patch("shutil.which", return_value=None):
            result = strip_native_symbols(".", "balanced")
        self.assertFalse(result["attempted"])
        self.assertIn(
            result["skipped_reason"],
            {"strip tool not found", "profile does not enable strip_symbols"},
        )


if __name__ == "__main__":
    unittest.main()
