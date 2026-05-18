import subprocess
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from typing import Tuple
from unittest import mock

import qrcode_helper


TEST_ROOT = Path(__file__).resolve().parents[1]
TEST_RUNS_ROOT = TEST_ROOT / ".tmp_test_runs"


def _make_case_root(prefix: str) -> Path:
    TEST_RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    root = TEST_RUNS_ROOT / "{}_{}".format(prefix, uuid.uuid4().hex[:8])
    root.mkdir(parents=True, exist_ok=False)
    return root


class WorkspaceTempMixin(object):
    def make_case_root(self, prefix: str) -> Path:
        root = _make_case_root(prefix)
        self.addCleanup(lambda: shutil.rmtree(str(root), ignore_errors=True))
        return root


class TransportCoreTests(WorkspaceTempMixin, unittest.TestCase):
    def test_transport_import_does_not_import_easyocr(self) -> None:
        cmd = [
            sys.executable,
            "-c",
            (
                "import sys;"
                "sys.modules.pop('easyocr', None);"
                "import qrcode_helper;"
                "print('easyocr' in sys.modules)"
            ),
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        self.assertEqual(completed.stdout.strip(), "False")

    def test_easyocr_backend_loads_reader_lazily(self) -> None:
        root = self.make_case_root("easyocr_lazy")
        images = root / "images"
        images.mkdir(parents=True, exist_ok=True)
        image_path = images / "shot_0001.png"
        image_path.write_bytes(b"fake")

        class _FakeEasyOCRModule(object):
            class Reader(object):
                def __init__(self, langs, gpu=False):
                    self.langs = list(langs)
                    self.gpu = bool(gpu)

        transport = qrcode_helper.AirgapTransportLayer()
        with mock.patch.object(qrcode_helper, "EASYOCR_AVAILABLE", True), mock.patch.object(
            qrcode_helper,
            "_load_easyocr_module",
            autospec=True,
            return_value=_FakeEasyOCRModule,
        ) as mocked_loader, mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "_ocr_single_image",
            autospec=True,
            return_value="P001L001|C00000|ABCDEFGH|FF8F\n",
        ):
            result = transport.extract_text_from_images(
                image_input_path=str(images),
                output_text_path=str(root / "ocr_easyocr.txt"),
                backend="easyocr",
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["backend"], "easyocr")
        self.assertEqual(result["ocr_languages"], ["en"])
        self.assertEqual(mocked_loader.call_count, 1)

    def test_estimate_export_reports_limits_and_pages(self) -> None:
        root = self.make_case_root("estimate")
        src = root / "payload_estimate.bin"
        src.write_bytes(bytes(((index * 73) + 41) % 256 for index in range(4096)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=0,
        )
        estimate = transport.estimate_export_artifact(
            input_file=str(src),
            redundancy_copies=2,
            parity_group_size=4,
        )

        self.assertTrue(estimate["success"])
        self.assertFalse(estimate["fits_current_limit"])
        self.assertGreaterEqual(estimate["minimum_recommended_max_compressed_kib"], 1)
        self.assertGreater(estimate["data_chunk_count"], 0)
        self.assertGreater(estimate["estimated_total_pages"], 0)
        self.assertIn("warnings", estimate)

    def test_verify_without_manifest_uses_embedded_metadata(self) -> None:
        root = self.make_case_root("verify_nomani")
        src = root / "payload_verify.bin"
        src.write_bytes((b"verify-no-manifest\n" * 12) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_verify"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        verify = transport.verify_ocr_text(
            manifest_path=None,
            ocr_input_path=str(manifest_path.parent / "pages_txt"),
            strict_payload_chars=False,
        )

        self.assertTrue(verify["success"])
        self.assertEqual(verify["artifact_id"], result["artifact_id"])
        self.assertEqual(verify["verification_mode"], "embedded_metadata")
        self.assertEqual(verify["message"], "verify ok via embedded page metadata")
        self.assertNotIn("warning", verify)

    def test_export_writes_compact_hash_metadata_lines(self) -> None:
        root = self.make_case_root("compact_meta")
        src = root / "payload_compact_meta.bin"
        src.write_bytes((b"compact-metadata\n" * 12) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_compact_meta"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        first_page = sorted((manifest_path.parent / "pages_txt").glob("*.txt"))[0]
        text = first_page.read_text(encoding="ascii")
        self.assertIn("@HS1|R=", text)
        self.assertIn("@HS2|R=", text)
        self.assertNotIn("@RH1|", text)
        self.assertNotIn("@CH1|", text)

    def test_export_metadata_none_outputs_data_lines_only(self) -> None:
        root = self.make_case_root("meta_none")
        src = root / "payload_meta_none.bin"
        src.write_bytes((b"meta-none\n" * 10) + bytes(range(20)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="none",
        )
        pkg = root / "pkg_meta_none"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        first_page = sorted((Path(str(result["manifest_path"])).parent / "pages_txt").glob("*.txt"))[0]
        lines = [line.strip() for line in first_page.read_text(encoding="ascii").splitlines() if line.strip()]
        self.assertTrue(lines)
        self.assertTrue(all(line.startswith("P") for line in lines))

    def test_custom_separator_roundtrip_with_manifest(self) -> None:
        root = self.make_case_root("sep_roundtrip")
        src = root / "payload_sep_roundtrip.bin"
        src.write_bytes((b"sep-roundtrip\n" * 12) + bytes(range(32)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="none",
            line_separator="$",
        )
        pkg = root / "pkg_sep_roundtrip"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        first_page = sorted((manifest_path.parent / "pages_txt").glob("*.txt"))[0]
        text = first_page.read_text(encoding="ascii")
        self.assertIn("$C", text)

        restored = root / "restored_sep_roundtrip.bin"
        recover = transport.recover_artifact(
            manifest_path=str(manifest_path),
            ocr_input_path=str(manifest_path.parent / "pages_txt"),
            output_file=str(restored),
            strict_payload_chars=False,
        )
        self.assertTrue(recover["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_line_crc_off_roundtrip_with_manifest(self) -> None:
        root = self.make_case_root("crc_off")
        src = root / "payload_crc_off.bin"
        src.write_bytes((b"crc-off\n" * 12) + bytes(range(24)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="none",
            line_separator="$",
            line_crc_mode="off",
        )
        pkg = root / "pkg_crc_off"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        first_page = sorted((manifest_path.parent / "pages_txt").glob("*.txt"))[0]
        sample_line = first_page.read_text(encoding="ascii").splitlines()[0]
        self.assertEqual(sample_line.count("$"), 2)
        segments = sample_line.split("$")
        self.assertEqual(len(segments), 3)
        self.assertTrue(segments[2])

        restored = root / "restored_crc_off.bin"
        recover = transport.recover_artifact(
            manifest_path=str(manifest_path),
            ocr_input_path=str(manifest_path.parent / "pages_txt"),
            output_file=str(restored),
            strict_payload_chars=False,
        )
        self.assertTrue(recover["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_chunk_index_mode_roundtrip_with_manifest(self) -> None:
        root = self.make_case_root("index_chunk")
        src = root / "payload_index_chunk.bin"
        src.write_bytes((b"index-chunk\n" * 10) + bytes(range(24)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="none",
            line_separator="$",
            line_crc_mode="off",
            line_index_mode="chunk",
        )
        pkg = root / "pkg_index_chunk"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        first_page = sorted((manifest_path.parent / "pages_txt").glob("*.txt"))[0]
        sample_line = first_page.read_text(encoding="ascii").splitlines()[0]
        self.assertTrue(sample_line.startswith("C"))
        self.assertFalse(sample_line.startswith("P"))
        self.assertEqual(sample_line.count("$"), 1)

        restored = root / "restored_index_chunk.bin"
        recover = transport.recover_artifact(
            manifest_path=str(manifest_path),
            ocr_input_path=str(manifest_path.parent / "pages_txt"),
            output_file=str(restored),
            strict_payload_chars=False,
        )
        self.assertTrue(recover["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_off_index_mode_roundtrip_with_manifest(self) -> None:
        root = self.make_case_root("index_off")
        src = root / "payload_index_off.bin"
        src.write_bytes((b"index-off\n" * 10) + bytes(range(24)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="none",
            line_separator="$",
            line_crc_mode="off",
            line_index_mode="off",
            render_sidecar=False,
        )
        pkg = root / "pkg_index_off"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        first_page = sorted((manifest_path.parent / "pages_txt").glob("*.txt"))[0]
        sample_line = first_page.read_text(encoding="ascii").splitlines()[0]
        self.assertFalse(sample_line.startswith("P"))
        self.assertFalse(sample_line.startswith("C"))
        self.assertEqual(sample_line.count("$"), 0)

        restored = root / "restored_index_off.bin"
        recover = transport.recover_artifact(
            manifest_path=str(manifest_path),
            ocr_input_path=str(manifest_path.parent / "pages_txt"),
            output_file=str(restored),
            strict_payload_chars=False,
        )
        self.assertTrue(recover["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_off_index_mode_without_manifest_is_rejected(self) -> None:
        root = self.make_case_root("index_off_no_manifest")
        src = root / "payload_index_off_no_manifest.bin"
        src.write_bytes((b"index-off-no-manifest\n" * 8) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="none",
            line_separator="$",
            line_crc_mode="off",
            line_index_mode="off",
            render_sidecar=False,
        )
        pkg = root / "pkg_index_off_no_manifest"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )
        pages_txt = Path(str(result["manifest_path"])).parent / "pages_txt"
        restored = root / "restored_index_off_no_manifest.bin"

        with self.assertRaisesRegex(ValueError, "payload-only.*manifest"):
            transport.recover_artifact(
                manifest_path=None,
                ocr_input_path=str(pages_txt),
                output_file=str(restored),
                strict_payload_chars=False,
            )

    def test_verify_without_manifest_accepts_separatorless_lines(self) -> None:
        root = self.make_case_root("sep_missing_nomani")
        src = root / "payload_sep_missing_nomani.bin"
        src.write_bytes((b"sep-missing-no-manifest\n" * 12) + bytes(range(24)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="none",
            line_separator="$",
            line_crc_mode="off",
        )
        pkg = root / "pkg_sep_missing_nomani"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        ocr_like = root / "ocr_sep_missing.txt"
        lines = []
        for path in sorted((manifest_path.parent / "pages_txt").glob("*.txt")):
            for line in path.read_text(encoding="ascii").splitlines():
                stripped = line.replace("$", "")
                lines.append(stripped)
        ocr_like.write_text("\n".join(lines) + "\n", encoding="utf-8")

        verify = transport.verify_ocr_text(
            manifest_path=None,
            ocr_input_path=str(ocr_like),
            strict_payload_chars=False,
        )
        self.assertTrue(verify["success"])
        self.assertEqual(verify["verification_mode"], "structural_only")

    def test_recover_tolerates_page_line_ocr_aliases(self) -> None:
        root = self.make_case_root("page_line_aliases")
        src = root / "payload_page_line_aliases.bin"
        src.write_bytes((b"page-line-alias\n" * 20) + bytes(range(32)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="none",
            line_separator="$",
            line_crc_mode="off",
        )
        pkg = root / "pkg_page_line_aliases"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        ocr_like = root / "ocr_page_line_aliases.txt"
        mutated_lines = []
        for path in sorted((manifest_path.parent / "pages_txt").glob("*.txt")):
            for line in path.read_text(encoding="ascii").splitlines():
                if not line.startswith("P"):
                    mutated_lines.append(line)
                    continue
                if "$C" not in line:
                    mutated_lines.append(line)
                    continue
                head, tail = line.split("$C", 1)
                if len(head) < 8 or head[0] != "P" or head[4] != "L":
                    mutated_lines.append(line)
                    continue
                page_token = head[1:4].replace("0", "G")
                line_token = head[5:8].replace("0", "O").replace("4", "H")
                mutated_lines.append("P{}L{}$C{}".format(page_token, line_token, tail))
        ocr_like.write_text("\n".join(mutated_lines) + "\n", encoding="utf-8")

        restored = root / "restored_page_line_aliases.bin"
        recover = transport.recover_artifact(
            manifest_path=str(manifest_path),
            ocr_input_path=str(ocr_like),
            output_file=str(restored),
            strict_payload_chars=False,
        )
        self.assertTrue(recover["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_recover_tolerates_chunk_prefix_ocr_aliases(self) -> None:
        root = self.make_case_root("chunk_prefix_aliases")
        src = root / "payload_chunk_prefix_aliases.bin"
        src.write_bytes((b"chunk-prefix-alias\n" * 20) + bytes(range(32)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="none",
            line_separator="$",
            line_crc_mode="off",
            line_index_mode="chunk",
        )
        pkg = root / "pkg_chunk_prefix_aliases"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        ocr_like = root / "ocr_chunk_prefix_aliases.txt"
        mutated_lines = []
        for path in sorted((manifest_path.parent / "pages_txt").glob("*.txt")):
            for line in path.read_text(encoding="ascii").splitlines():
                if not line.startswith("C") or "$" not in line:
                    mutated_lines.append(line)
                    continue
                head, payload = line.split("$", 1)
                if len(head) != 6:
                    mutated_lines.append(line)
                    continue
                chunk_token = head[1:].replace("0", "O").replace("4", "H")
                mutated_lines.append("G{}${}".format(chunk_token, payload))
        ocr_like.write_text("\n".join(mutated_lines) + "\n", encoding="utf-8")

        restored = root / "restored_chunk_prefix_aliases.bin"
        recover = transport.recover_artifact(
            manifest_path=str(manifest_path),
            ocr_input_path=str(ocr_like),
            output_file=str(restored),
            strict_payload_chars=False,
        )
        self.assertTrue(recover["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for render layout assertions")
    def test_no_sidecar_removes_binary_boxes(self) -> None:
        root = self.make_case_root("no_sidecar")
        src = root / "payload_no_sidecar.bin"
        src.write_bytes((b"no-sidecar\n" * 10) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            render_sidecar=False,
        )
        pkg = root / "pkg_no_sidecar"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest = qrcode_helper.json.loads(Path(str(result["manifest_path"])).read_text(encoding="utf-8"))
        pages = manifest.get("render_layout", {}).get("pages", [])
        self.assertTrue(pages)
        for page in pages:
            for item in page.get("lines", []):
                if item.get("kind") != "data":
                    continue
                self.assertNotIn("binary_box", item)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for render layout assertions")
    def test_fixed_font_size_applies_to_render_layout(self) -> None:
        root = self.make_case_root("fixed_font")
        src = root / "payload_fixed_font.bin"
        src.write_bytes((b"font-control\n" * 10) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            font_size=58,
            fixed_font_size=True,
        )
        pkg = root / "pkg_fixed_font"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest = qrcode_helper.json.loads(Path(str(result["manifest_path"])).read_text(encoding="utf-8"))
        pages = manifest.get("render_layout", {}).get("pages", [])
        self.assertTrue(pages)
        self.assertTrue(all(int(page.get("font_size", 0)) == 58 for page in pages))

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for render layout assertions")
    def test_default_target_font_mode_keeps_requested_size(self) -> None:
        root = self.make_case_root("font_target_default")
        src = root / "payload_font_target_default.bin"
        src.write_bytes(bytes((index * 13 + 11) % 256 for index in range(6000)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=20,
            lines_per_page=30,
            max_compressed_kib=64,
            font_size=56,
            font_max_size=88,
            metadata_level="none",
            line_separator="$",
            line_crc_mode="off",
            render_sidecar=False,
        )
        pkg = root / "pkg_font_target_default"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest = qrcode_helper.json.loads(Path(str(result["manifest_path"])).read_text(encoding="utf-8"))
        pages = manifest.get("render_layout", {}).get("pages", [])
        self.assertTrue(pages)
        self.assertTrue(all(int(page.get("font_size", 0)) == 56 for page in pages))

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for render layout assertions")
    def test_fit_font_mode_can_expand_to_font_max(self) -> None:
        root = self.make_case_root("font_fit_expand")
        src = root / "payload_font_fit_expand.bin"
        src.write_bytes(bytes((index * 13 + 11) % 256 for index in range(6000)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=20,
            lines_per_page=30,
            max_compressed_kib=64,
            font_size=56,
            font_max_size=88,
            font_fit_mode="fit",
            metadata_level="none",
            line_separator="$",
            line_crc_mode="off",
            render_sidecar=False,
        )
        pkg = root / "pkg_font_fit_expand"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest = qrcode_helper.json.loads(Path(str(result["manifest_path"])).read_text(encoding="utf-8"))
        pages = manifest.get("render_layout", {}).get("pages", [])
        self.assertTrue(pages)
        self.assertTrue(all(int(page.get("font_size", 0)) == 88 for page in pages))

    def test_recover_without_manifest_uses_embedded_metadata(self) -> None:
        root = self.make_case_root("recover_nomani")
        src = root / "payload_recover.bin"
        src.write_bytes((b"recover-no-manifest\n" * 12) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_recover"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        restored = root / "restored_no_manifest.bin"
        recover = transport.recover_artifact(
            manifest_path=None,
            ocr_input_path=str(manifest_path.parent / "pages_txt"),
            output_file=str(restored),
            strict_payload_chars=False,
        )

        self.assertTrue(recover["success"])
        self.assertEqual(recover["artifact_id"], result["artifact_id"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())
        self.assertEqual(recover["verification_mode"], "embedded_metadata")
        self.assertNotIn("warning", recover)

    def test_verify_without_manifest_falls_back_for_legacy_text_pages(self) -> None:
        root = self.make_case_root("legacy_verify_nomani")
        src = root / "payload_legacy_verify.bin"
        src.write_bytes((b"legacy-verify-no-manifest\n" * 12) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_legacy_verify"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        legacy_text = root / "legacy_ocr.txt"
        lines = []
        for path in sorted((manifest_path.parent / "pages_txt").glob("*.txt")):
            for line in path.read_text(encoding="ascii").splitlines():
                if line.startswith("@CFG|") or line.startswith("@RH") or line.startswith("@CH") or line.startswith("@HS"):
                    continue
                lines.append(line)
        legacy_text.write_text("\n".join(lines) + "\n", encoding="utf-8")

        verify = transport.verify_ocr_text(
            manifest_path=None,
            ocr_input_path=str(legacy_text),
            strict_payload_chars=False,
        )

        self.assertTrue(verify["success"])
        self.assertEqual(verify["verification_mode"], "structural_only")
        self.assertIn("warning", verify)

    def test_recover_without_manifest_can_use_embedded_parity(self) -> None:
        root = self.make_case_root("recover_nomani_parity")
        src = root / "payload_recover_parity.bin"
        src.write_bytes((b"recover-parity-no-manifest\n" * 48) + bytes(range(32)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_recover_parity"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=4,
        )

        manifest_path = Path(str(result["manifest_path"]))
        damaged_text = root / "ocr_missing_one_line.txt"
        written = False
        with damaged_text.open("w", encoding="utf-8") as handle:
            for path in sorted((manifest_path.parent / "pages_txt").glob("*.txt")):
                for line in path.read_text(encoding="ascii").splitlines():
                    if (not written) and line.startswith("P") and "|C00000|" in line:
                        written = True
                        continue
                    handle.write(line + "\n")

        restored = root / "restored_no_manifest_parity.bin"
        recover = transport.recover_artifact(
            manifest_path=None,
            ocr_input_path=str(damaged_text),
            output_file=str(restored),
            strict_payload_chars=False,
        )

        self.assertTrue(recover["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_recover_images_without_manifest(self) -> None:
        root = self.make_case_root("recover_images_nomani")
        src = root / "payload_recover_images.bin"
        src.write_bytes((b"recover-images-no-manifest\n" * 12) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_recover_images"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        pages_txt_dir = manifest_path.parent / "pages_txt"
        images_dir = root / "photos"
        images_dir.mkdir(parents=True, exist_ok=True)
        (images_dir / "photo_0001.png").write_bytes(b"fake")

        def fake_extract(
            self_obj,
            image_input_path,
            output_text_path,
            backend="tesseract",
            lang="eng",
            psm=6,
            manifest_path=None,
            ocr_provider_cmd=None,
            ocr_provider_timeout_sec=120,
        ):
            merged = []
            for path in sorted(pages_txt_dir.glob("*.txt")):
                merged.append(path.read_text(encoding="ascii"))
            Path(output_text_path).write_text("".join(merged), encoding="utf-8")
            return {
                "success": True,
                "backend": backend,
                "language": lang,
                "ocr_languages": [lang],
                "psm": psm,
                "manifest_path": manifest_path,
                "image_count": 1,
                "image_files": [str(images_dir / "photo_0001.png")],
                "output_text_path": str(output_text_path),
                "structured_layout_used": False,
                "structured_page_count": 0,
                "sidecar_supported": False,
                "tesseract_mode": "mock",
                "tesseract_command": None,
                "text_length": len("".join(merged)),
            }

        restored = root / "restored_from_images_no_manifest.bin"
        with mock.patch.object(qrcode_helper.AirgapTransportLayer, "extract_text_from_images", autospec=True, side_effect=fake_extract):
            recover = transport.recover_from_images(
                manifest_path=None,
                image_input_path=str(images_dir),
                output_file=str(restored),
                backend="tesseract",
                ocr_text_output=str(root / "ocr_raw.txt"),
                save_analyze_report=str(root / "analyze.json"),
                emit_missing_file=str(root / "missing.csv"),
                max_list=20,
            )

        self.assertTrue(recover["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())
        self.assertEqual(recover["backend_selected"], "tesseract")

    def test_external_backend_uses_provider_command_interface(self) -> None:
        root = self.make_case_root("external_backend")
        images = root / "images"
        images.mkdir(parents=True, exist_ok=True)
        image_path = images / "shot_0001.png"
        image_path.write_bytes(b"fake")

        output_text = root / "ocr_external.txt"
        transport = qrcode_helper.AirgapTransportLayer()
        with mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "_run_external_ocr_provider",
            autospec=True,
            return_value="P001L001|C00000|ABCDEFGH|FF8F\n",
        ) as mocked_provider:
            result = transport.extract_text_from_images(
                image_input_path=str(images),
                output_text_path=str(output_text),
                backend="external",
                ocr_provider_cmd="dummy {image_path}",
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["backend"], "external")
        self.assertEqual(result["ocr_provider_mode"], "external_cmd")
        self.assertEqual(result["ocr_provider_cmd"], "dummy {image_path}")
        self.assertEqual(mocked_provider.call_count, 1)
        self.assertIn("P001L001|C00000|ABCDEFGH|FF8F", output_text.read_text(encoding="utf-8"))

    def test_export_reports_when_pillow_is_unavailable(self) -> None:
        root = self.make_case_root("no_pillow")
        src = root / "payload_no_pillow.bin"
        src.write_bytes((b"no-pillow\n" * 12) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_no_pillow"
        with mock.patch.object(qrcode_helper, "PIL_AVAILABLE", False):
            result = transport.export_artifact(
                input_file=str(src),
                output_dir=str(pkg),
                filename_prefix="case",
                redundancy_copies=1,
                parity_group_size=0,
            )

        self.assertTrue(result["success"])
        self.assertFalse(result["pillow_enabled"])
        self.assertEqual(result["image_count"], 0)
        self.assertGreater(result["page_text_count"], 0)
        self.assertIn("warning", result)

    def test_text_roundtrip_without_image_dependencies(self) -> None:
        root = self.make_case_root("core")
        src = root / "payload_core.bin"
        src.write_bytes((b"text-roundtrip\n" * 12) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_core"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        page_texts = sorted((manifest_path.parent / "pages_txt").glob("*.txt"))
        combined_text = root / "combined_ocr.txt"
        combined_text.write_text(
            "".join(path.read_text(encoding="ascii") for path in page_texts),
            encoding="ascii",
        )

        restored = root / "restored_core.bin"
        recover = transport.recover_artifact(
            manifest_path=str(manifest_path),
            ocr_input_path=str(combined_text),
            output_file=str(restored),
            strict_payload_chars=False,
        )

        self.assertTrue(result["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())
        self.assertEqual(recover["raw_sha256"], qrcode_helper._sha256_hex(src.read_bytes()))

    def test_manifest_with_utf8_bom_is_accepted(self) -> None:
        root = self.make_case_root("bom")
        src = root / "payload_bom.bin"
        src.write_bytes((b"bom-manifest\n" * 16) + bytes(range(32)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_bom"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text(manifest_text, encoding="utf-8-sig")

        restored = root / "restored_bom.bin"
        recover = transport.recover_artifact(
            manifest_path=str(manifest_path),
            ocr_input_path=str(manifest_path.parent / "pages_txt"),
            output_file=str(restored),
            strict_payload_chars=False,
        )

        self.assertTrue(result["success"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())
        self.assertEqual(recover["raw_sha256"], qrcode_helper._sha256_hex(src.read_bytes()))

    def test_analyze_separates_data_and_parity_chunk_counts(self) -> None:
        root = self.make_case_root("parity_counts")
        src = root / "payload_parity.bin"
        src.write_bytes((b"parity-count\n" * 48) + bytes(range(32)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_parity"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=2,
            parity_group_size=4,
        )

        manifest_path = Path(str(result["manifest_path"]))
        analyze = transport.analyze_ocr_text(
            manifest_path=str(manifest_path),
            ocr_input_path=str(manifest_path.parent / "pages_txt"),
            strict_payload_chars=False,
            max_list=20,
        )

        self.assertTrue(analyze["success"])
        self.assertEqual(analyze["received_unique_chunks"], analyze["expected_total_chunks"])
        self.assertGreater(analyze["received_parity_chunks"], 0)


@unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for image OCR tests")
class SidecarRecoveryTests(WorkspaceTempMixin, unittest.TestCase):
    def _build_fixture(self) -> Tuple[Path, qrcode_helper.AirgapTransportLayer, Path, Path]:
        root = self.make_case_root("sidecar")
        src = root / "payload.bin"
        src.write_bytes((b"sidecar-regression\n" * 24) + bytes(range(32)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        pkg = root / "pkg"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=2,
            parity_group_size=4,
        )

        manifest_path = Path(str(result["manifest_path"]))
        return root, transport, src, manifest_path

    def _build_multi_page_fixture(self) -> Tuple[Path, qrcode_helper.AirgapTransportLayer, Path]:
        root = self.make_case_root("page_map")
        src = root / "payload_multi.bin"
        src.write_bytes((b"page-map-regression\n" * 120) + bytes(range(64)) * 2)

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=16,
            lines_per_page=4,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_multi"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )
        manifest_path = Path(str(result["manifest_path"]))
        return root, transport, manifest_path

    def test_sidecar_backend_extract_and_recover(self) -> None:
        _root, transport, src, manifest_path = self._build_fixture()

        manifest = transport._load_manifest(str(manifest_path))
        page_layouts = transport._get_render_layout_pages(manifest)
        self.assertTrue(transport._page_layouts_support_sidecar(page_layouts))

        text_path = manifest_path.parent.parent / "ocr_sidecar.txt"
        images_dir = manifest_path.parent / "pages"
        extract = transport.extract_text_from_images(
            image_input_path=str(images_dir),
            output_text_path=str(text_path),
            backend="sidecar",
            manifest_path=str(manifest_path),
        )
        self.assertTrue(extract["success"])
        self.assertTrue(extract["sidecar_supported"])

        analyze = transport.analyze_ocr_text(
            manifest_path=str(manifest_path),
            ocr_input_path=str(text_path),
            strict_payload_chars=False,
            max_list=20,
        )
        self.assertTrue(analyze["success"])
        self.assertEqual(analyze["missing_chunks_count"], 0)

        restored = manifest_path.parent.parent / "restored.bin"
        recover = transport.recover_artifact(
            manifest_path=str(manifest_path),
            ocr_input_path=str(text_path),
            output_file=str(restored),
            strict_payload_chars=False,
        )
        self.assertEqual(Path(recover["output_file"]).read_bytes(), src.read_bytes())

    def test_auto_recover_works_without_ocr_dependencies(self) -> None:
        _root, transport, src, manifest_path = self._build_fixture()

        images_dir = manifest_path.parent / "pages"
        restored = manifest_path.parent.parent / "restored_auto.bin"
        with mock.patch.object(qrcode_helper, "TESSERACT_AVAILABLE", False), mock.patch.object(
            qrcode_helper, "EASYOCR_AVAILABLE", False
        ):
            result = transport.recover_from_images(
                manifest_path=str(manifest_path),
                image_input_path=str(images_dir),
                output_file=str(restored),
                backend="auto",
                ocr_text_output=str(manifest_path.parent.parent / "ocr_auto.txt"),
                save_analyze_report=str(manifest_path.parent.parent / "analyze_auto.json"),
                emit_missing_file=str(manifest_path.parent.parent / "missing_auto.csv"),
                max_list=20,
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["backend_selected"], "sidecar")
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_auto_recover_materializes_requested_output_paths(self) -> None:
        _root, transport, src, manifest_path = self._build_fixture()

        images_dir = manifest_path.parent / "pages"
        restored = manifest_path.parent.parent / "restored_named.bin"
        ocr_output = manifest_path.parent.parent / "ocr_raw.txt"
        report_output = manifest_path.parent.parent / "analyze_report.json"
        missing_output = manifest_path.parent.parent / "missing_chunks.csv"

        with mock.patch.object(qrcode_helper, "TESSERACT_PYTHON_AVAILABLE", False), mock.patch.object(
            qrcode_helper, "TESSERACT_CLI_AVAILABLE", True
        ), mock.patch.object(qrcode_helper, "TESSERACT_CMD", "tesseract"), mock.patch.object(
            qrcode_helper, "EASYOCR_AVAILABLE", False
        ):
            result = transport.recover_from_images(
                manifest_path=str(manifest_path),
                image_input_path=str(images_dir),
                output_file=str(restored),
                backend="auto",
                ocr_text_output=str(ocr_output),
                save_analyze_report=str(report_output),
                emit_missing_file=str(missing_output),
                max_list=20,
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["backend_selected"], "sidecar")
        self.assertEqual(result["ocr"]["ocr_text_output"], str(ocr_output))
        self.assertEqual(result["analyze"]["report_path"], str(report_output))
        self.assertEqual(result["analyze"]["missing_file_path"], str(missing_output))
        self.assertEqual(restored.read_bytes(), src.read_bytes())
        self.assertTrue(ocr_output.exists())
        self.assertTrue(report_output.exists())
        self.assertTrue(missing_output.exists())

    def test_manifest_guided_sidecar_recovers_without_render_layout_or_ocr_runtime(self) -> None:
        _root, transport, src, manifest_path = self._build_fixture()

        manifest = transport._load_manifest(str(manifest_path))
        manifest.pop("render_layout", None)
        legacy_manifest = manifest_path.parent.parent / "legacy_sidecar.manifest.json"
        legacy_manifest.write_text(
            qrcode_helper.json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        images_dir = manifest_path.parent / "pages"
        restored = manifest_path.parent.parent / "restored_legacy_sidecar.bin"
        with mock.patch.object(qrcode_helper, "TESSERACT_PYTHON_AVAILABLE", False), mock.patch.object(
            qrcode_helper, "TESSERACT_CLI_AVAILABLE", False
        ), mock.patch.object(qrcode_helper, "TESSERACT_CMD", None), mock.patch.object(
            qrcode_helper, "EASYOCR_AVAILABLE", False
        ):
            result = transport.recover_from_images(
                manifest_path=str(legacy_manifest),
                image_input_path=str(images_dir),
                output_file=str(restored),
                backend="auto",
                ocr_text_output=str(manifest_path.parent.parent / "legacy_sidecar_ocr.txt"),
                max_list=20,
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["backend_selected"], "sidecar")
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_tesseract_backend_accepts_cli_without_pytesseract(self) -> None:
        _root, transport, _src, manifest_path = self._build_fixture()

        images_dir = manifest_path.parent / "pages"
        output_text = manifest_path.parent.parent / "ocr_cli.txt"
        with mock.patch.object(qrcode_helper, "TESSERACT_PYTHON_AVAILABLE", False), mock.patch.object(
            qrcode_helper, "TESSERACT_CLI_AVAILABLE", True
        ), mock.patch.object(qrcode_helper, "TESSERACT_CMD", "tesseract"), mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "_tesseract_image_to_string",
            autospec=True,
            return_value="P000L001|C00000|LEGACY|ABCD\n",
        ) as mocked_ocr:
            result = transport.extract_text_from_images(
                image_input_path=str(images_dir),
                output_text_path=str(output_text),
                backend="tesseract",
                manifest_path=None,
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["backend"], "tesseract")
        self.assertEqual(result["tesseract_mode"], "cli")
        self.assertEqual(result["tesseract_command"], "tesseract")
        self.assertGreater(result["text_length"], 0)
        self.assertGreater(mocked_ocr.call_count, 0)

    def test_manifest_guided_tesseract_recovers_without_render_layout(self) -> None:
        root = self.make_case_root("manifest_guided")
        src = root / "payload_manifest_guided.bin"
        src.write_bytes((b"manifest-guided-regression\n" * 20) + bytes(range(32)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_manifest_guided"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )
        manifest_path = Path(str(result["manifest_path"]))

        manifest = transport._load_manifest(str(manifest_path))
        manifest.pop("render_layout", None)
        legacy_manifest = manifest_path.parent.parent / "legacy.manifest.json"
        legacy_manifest.write_text(
            qrcode_helper.json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        page_text_path = manifest_path.parent / "pages_txt" / "case_0001.txt"
        data_lines = [
            line.strip()
            for line in page_text_path.read_text(encoding="ascii").splitlines()
            if line.startswith("P")
        ]
        payload_ocr = []
        crc_ocr = []
        for line in data_lines:
            _prefix, _chunk, payload, crc = line.split("|")
            payload_ocr.append(payload.replace("4", "H").replace("5", "S"))
            crc_ocr.append(crc)

        output_text = manifest_path.parent.parent / "ocr_manifest_guided.txt"
        payload_variant_side_effect = []
        for item in payload_ocr:
            payload_variant_side_effect.append([item])
            payload_variant_side_effect.append([item])
        with mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "_ocr_manifest_guided_page_sidecar",
            autospec=True,
            side_effect=ValueError("force tesseract fallback"),
        ), mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "_ocr_payload_crop_tesseract_variants",
            autospec=True,
            side_effect=payload_variant_side_effect,
        ) as mocked_payload, mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "_ocr_crc_crop_tesseract_variants",
            autospec=True,
            side_effect=[[item] for item in crc_ocr],
        ) as mocked_crc:
            extract = transport.extract_text_from_images(
                image_input_path=str(manifest_path.parent / "pages" / "case_0001.png"),
                output_text_path=str(output_text),
                backend="tesseract",
                manifest_path=str(legacy_manifest),
            )

        self.assertTrue(extract["success"])
        self.assertTrue(extract["structured_layout_used"])
        self.assertGreaterEqual(mocked_payload.call_count, len(data_lines))
        self.assertEqual(mocked_crc.call_count, len(data_lines))

        analyze = transport.analyze_ocr_text(
            manifest_path=str(legacy_manifest),
            ocr_input_path=str(output_text),
            strict_payload_chars=False,
            max_list=20,
        )
        self.assertTrue(analyze["success"])

        restored = manifest_path.parent.parent / "restored_manifest_guided.bin"
        recover = transport.recover_artifact(
            manifest_path=str(legacy_manifest),
            ocr_input_path=str(output_text),
            output_file=str(restored),
            strict_payload_chars=False,
        )
        self.assertEqual(Path(recover["output_file"]).read_bytes(), src.read_bytes())

    def test_recover_images_auto_prefers_sidecar_before_external(self) -> None:
        _root, transport, src, manifest_path = self._build_fixture()
        images_dir = manifest_path.parent / "pages"
        restored = manifest_path.parent.parent / "restored_auto_sidecar_priority.bin"
        attempts = []

        def fake_extract(
            self_obj,
            image_input_path,
            output_text_path,
            backend="tesseract",
            lang="eng",
            psm=6,
            manifest_path=None,
            ocr_provider_cmd=None,
            ocr_provider_timeout_sec=120,
        ):
            attempts.append(str(backend))
            if backend != "sidecar":
                raise RuntimeError("backend should not run after sidecar success")
            merged = "".join(
                path.read_text(encoding="ascii")
                for path in sorted((Path(manifest_path).parent / "pages_txt").glob("*.txt"))
            )
            Path(output_text_path).write_text(merged, encoding="utf-8")
            return {
                "success": True,
                "backend": backend,
                "language": lang,
                "ocr_languages": [],
                "psm": psm,
                "manifest_path": manifest_path,
                "image_count": 1,
                "image_files": [str(images_dir / "case_0001.png")],
                "output_text_path": str(output_text_path),
                "structured_layout_used": True,
                "structured_page_count": 1,
                "sidecar_supported": True,
                "tesseract_mode": None,
                "tesseract_command": None,
                "text_length": len(merged),
                "ocr_provider_mode": None,
                "ocr_provider_cmd": None,
            }

        with mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "extract_text_from_images",
            autospec=True,
            side_effect=fake_extract,
        ):
            recover = transport.recover_from_images(
                manifest_path=str(manifest_path),
                image_input_path=str(images_dir),
                output_file=str(restored),
                backend="auto",
                ocr_provider_cmd="dummy {image_path}",
                ocr_text_output=str(manifest_path.parent.parent / "ocr_auto_sidecar_priority.txt"),
                max_list=20,
            )

        self.assertTrue(recover["success"])
        self.assertEqual(recover["backend_selected"], "sidecar")
        self.assertEqual(attempts, ["sidecar"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_recover_images_auto_prefers_external_before_generic_ocr(self) -> None:
        root = self.make_case_root("recover_auto_external_priority")
        src = root / "payload_auto_external_priority.bin"
        src.write_bytes((b"recover-auto-external-priority\n" * 12) + bytes(range(16)))

        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=6,
            max_compressed_kib=64,
        )
        pkg = root / "pkg_auto_external_priority"
        result = transport.export_artifact(
            input_file=str(src),
            output_dir=str(pkg),
            filename_prefix="case",
            redundancy_copies=1,
            parity_group_size=0,
        )

        manifest_path = Path(str(result["manifest_path"]))
        pages_txt_dir = manifest_path.parent / "pages_txt"
        images_dir = manifest_path.parent / "pages"
        restored = root / "restored_auto_external_priority.bin"
        attempts = []

        def fake_extract(
            self_obj,
            image_input_path,
            output_text_path,
            backend="tesseract",
            lang="eng",
            psm=6,
            manifest_path=None,
            ocr_provider_cmd=None,
            ocr_provider_timeout_sec=120,
        ):
            attempts.append(str(backend))
            merged = "".join(path.read_text(encoding="ascii") for path in sorted(pages_txt_dir.glob("*.txt")))
            Path(output_text_path).write_text(merged, encoding="utf-8")
            if backend == "external":
                return {
                    "success": True,
                    "backend": backend,
                    "language": lang,
                    "ocr_languages": [lang],
                    "psm": psm,
                    "manifest_path": manifest_path,
                    "image_count": 1,
                    "image_files": [str(images_dir / "case_0001.png")],
                    "output_text_path": str(output_text_path),
                    "structured_layout_used": False,
                    "structured_page_count": 0,
                    "sidecar_supported": False,
                    "tesseract_mode": None,
                    "tesseract_command": None,
                    "ocr_provider_mode": "external_cmd",
                    "ocr_provider_cmd": ocr_provider_cmd,
                    "text_length": len(merged),
                }
            raise RuntimeError("unexpected backend {}".format(backend))

        with mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "extract_text_from_images",
            autospec=True,
            side_effect=fake_extract,
        ), mock.patch.object(
            qrcode_helper,
            "PIL_AVAILABLE",
            False,
        ), mock.patch.object(
            qrcode_helper,
            "TESSERACT_PYTHON_AVAILABLE",
            False,
        ), mock.patch.object(
            qrcode_helper,
            "TESSERACT_CLI_AVAILABLE",
            True,
        ), mock.patch.object(
            qrcode_helper,
            "TESSERACT_CMD",
            "tesseract",
        ), mock.patch.object(
            qrcode_helper,
            "EASYOCR_AVAILABLE",
            True,
        ):
            recover = transport.recover_from_images(
                manifest_path=None,
                image_input_path=str(images_dir),
                output_file=str(restored),
                backend="auto",
                ocr_provider_cmd="dummy {image_path}",
                ocr_text_output=str(root / "ocr_auto_external_priority.txt"),
                max_list=20,
            )

        self.assertTrue(recover["success"])
        self.assertEqual(recover["backend_selected"], "external")
        self.assertEqual(attempts, ["external"])
        self.assertEqual(restored.read_bytes(), src.read_bytes())

    def test_single_page_sidecar_extract_uses_filename_page_number(self) -> None:
        _root, transport, manifest_path = self._build_multi_page_fixture()

        page_two_image = manifest_path.parent / "pages" / "case_0002.png"
        output_text = manifest_path.parent.parent / "page_two_sidecar.txt"
        extract = transport.extract_text_from_images(
            image_input_path=str(page_two_image),
            output_text_path=str(output_text),
            backend="sidecar",
            manifest_path=str(manifest_path),
        )

        self.assertTrue(extract["success"])
        expected_text_path = manifest_path.parent / "pages_txt" / "case_0002.txt"
        expected = "\n".join(
            line.strip()
            for line in expected_text_path.read_text(encoding="ascii").splitlines()
            if line.startswith("P")
        ) + "\n"
        self.assertEqual(output_text.read_text(encoding="utf-8"), expected)


if __name__ == "__main__":
    unittest.main()
