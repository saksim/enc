import shutil
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
