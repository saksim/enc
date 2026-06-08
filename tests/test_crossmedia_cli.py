#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the lightweight cross-media CLI entrypoint."""

from __future__ import annotations

import builtins
import tempfile
import unittest
from pathlib import Path
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

    def test_crossmedia_receive_requires_key_mode_now_implemented(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exit_code = crossmedia_cli.main(
                [
                    "receive",
                    "--image-input",
                    str(root),
                    "--output",
                    str(root / "out.bin"),
                    "--work-dir",
                    str(root / "work"),
                ]
            )
            self.assertEqual(exit_code, 2)

    def test_crossmedia_send_missing_key_file_returns_key_error(self) -> None:
        exit_code = crossmedia_cli.main(["send", "--input", "missing.bin", "--output-dir", "pages", "--key-file", "missing.key"])
        self.assertEqual(exit_code, 10)

    def test_crossmedia_receive_scan_input_errors_return_file_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_file = root / "key.bin"
            key_file.write_bytes(bytes(range(32)))
            exit_code = crossmedia_cli.main(
                [
                    "receive",
                    "--image-input",
                    str(root / "missing_photos"),
                    "--output",
                    str(root / "out.bin"),
                    "--work-dir",
                    str(root / "work"),
                    "--key-file",
                    str(key_file),
                ]
            )
            self.assertEqual(exit_code, 30)

    def test_crossmedia_send_requires_exactly_one_key_mode(self) -> None:
        exit_code = crossmedia_cli.main(["send", "--input", "plain.bin", "--output-dir", "pages"])
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
