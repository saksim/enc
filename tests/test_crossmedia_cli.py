#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the lightweight cross-media CLI entrypoint."""

from __future__ import annotations

import builtins
import unittest
from unittest import mock

from enc2sop import cli as soenc_cli
from enc2sop.crossmedia import cli as crossmedia_cli


_HEAVY_MODULES = {
    "encryption_helper",
    "enc2sop.promotion_artifacts",
    "enc2sop.promotion_audit",
    "enc2sop.promotion_bundle",
    "enc2sop.promotion_evidence",
}


class CrossMediaCliTests(unittest.TestCase):
    def test_crossmedia_parser_help_lists_documented_commands(self) -> None:
        parser = crossmedia_cli.build_parser()
        help_text = parser.format_help()

        self.assertIn("keygen", help_text)
        self.assertIn("encrypt", help_text)
        self.assertIn("decrypt", help_text)
        self.assertIn("render", help_text)
        self.assertIn("scan", help_text)
        self.assertIn("send", help_text)
        self.assertIn("receive", help_text)

    def test_soenc_cm_help_is_lightweight(self) -> None:
        real_import = builtins.__import__
        imported = []

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in _HEAVY_MODULES:
                raise AssertionError("heavy module imported during cm help: {0}".format(name))
            imported.append(name)
            return real_import(name, globals, locals, fromlist, level)

        with mock.patch("builtins.__import__", side_effect=guarded_import):
            with self.assertRaises(SystemExit) as exc_info:
                soenc_cli.main(["cm", "--help"])

        self.assertEqual(exc_info.exception.code, 0)
        self.assertNotIn("encryption_helper", imported)

    def test_soenc_cm_without_args_prints_crossmedia_help(self) -> None:
        exit_code = soenc_cli.main(["cm"])
        self.assertEqual(exit_code, 0)

    def test_soenc_cm_delegates_forwarded_args_to_crossmedia_cli(self) -> None:
        with mock.patch.object(crossmedia_cli, "main", autospec=True, return_value=0) as mocked_main:
            exit_code = soenc_cli.main(["cm", "render", "--input-string", "x", "--output-dir", "out"])

        self.assertEqual(exit_code, 0)
        mocked_main.assert_called_once_with(["render", "--input-string", "x", "--output-dir", "out"])

    def test_crossmedia_subcommands_fail_explicitly_until_next_stage(self) -> None:
        exit_code = crossmedia_cli.main(["render", "--input-string", "SOX1.demo", "--output-dir", "pages"])
        self.assertEqual(exit_code, 40)


if __name__ == "__main__":
    unittest.main()
