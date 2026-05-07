import unittest
from unittest import mock

import qrcode_helper
from enc2sop.transport import cli, ocr_adapters, parser, protocol, recover, render


class TransportModuleExtractionTests(unittest.TestCase):
    def test_protocol_base32_roundtrip(self) -> None:
        raw = b"enc2sop-transport-roundtrip"
        encoded = protocol.encode_safe_base32(raw)
        self.assertTrue(encoded)
        self.assertEqual(protocol.decode_safe_base32(encoded), raw)

    def test_protocol_signature_normalization(self) -> None:
        normalized = protocol.normalize_protocol_signature("P0011001|C00001|ABCDEFGH|FF8F")
        self.assertTrue(normalized.startswith("P001L001"))

    def test_ocr_adapter_language_mapping(self) -> None:
        langs = ocr_adapters.build_easyocr_langs("eng+chi_sim+jpn")
        self.assertEqual(langs, ["en", "ch_sim", "ja"])

    def test_qrcode_helper_protocol_aliases_use_transport_module(self) -> None:
        self.assertIs(qrcode_helper.LINE_PATTERN, protocol.LINE_PATTERN)
        self.assertIs(qrcode_helper.META_PATTERN, protocol.META_PATTERN)
        self.assertIs(qrcode_helper._normalize_ocr_line, protocol.normalize_ocr_line)
        self.assertEqual(qrcode_helper.SAFE_BASE32_ALPHABET, protocol.SAFE_BASE32_ALPHABET)

    def test_qrcode_helper_module_spec_wrapper_delegates_to_adapter(self) -> None:
        with mock.patch.object(ocr_adapters, "is_module_available", autospec=True, return_value=True) as mocked:
            self.assertTrue(qrcode_helper._module_spec_available("demo_mod"))
        mocked.assert_called_once_with("demo_mod")

    def test_qrcode_helper_cli_aliases_use_transport_cli_module(self) -> None:
        parser = qrcode_helper._build_parser()
        self.assertEqual(parser.description, "Airgap transport layer for encrypted small artifacts.")
        self.assertEqual(parser.prog, cli.build_parser().prog)
        self.assertIs(qrcode_helper._save_json, cli.save_json)
        self.assertIs(qrcode_helper._save_missing_chunks, cli.save_missing_chunks)

    def test_qrcode_helper_render_font_loader_uses_transport_render_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel_font = object()
        with mock.patch.object(qrcode_helper, "PIL_AVAILABLE", True), mock.patch.object(
            qrcode_helper,
            "ImageFont",
            object(),
        ), mock.patch.object(
            render,
            "load_font",
            autospec=True,
            return_value=sentinel_font,
        ) as mocked_loader:
            loaded = transport._load_font(28)
        self.assertIs(loaded, sentinel_font)
        mocked_loader.assert_called_once()

    def test_qrcode_helper_recover_entrypoints_delegate_to_transport_recover(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "artifact_id": "sentinel"}
        with mock.patch.object(
            recover,
            "recover_artifact",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.recover_artifact(
                manifest_path="m.json",
                ocr_input_path="ocr.txt",
                output_file="out.bin",
                strict_payload_chars=True,
            )
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            manifest_path="m.json",
            ocr_input_path="ocr.txt",
            output_file="out.bin",
            strict_payload_chars=True,
        )

    def test_qrcode_helper_verify_entrypoints_delegate_to_transport_recover(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "message": "verify ok"}
        with mock.patch.object(
            recover,
            "verify_ocr_text",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.verify_ocr_text(
                manifest_path="m.json",
                ocr_input_path="ocr.txt",
                strict_payload_chars=True,
            )
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            manifest_path="m.json",
            ocr_input_path="ocr.txt",
            strict_payload_chars=True,
        )

    def test_qrcode_helper_analyze_entrypoints_delegate_to_transport_recover(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": False, "message": "not recoverable"}
        with mock.patch.object(
            recover,
            "analyze_ocr_text",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.analyze_ocr_text(
                manifest_path=None,
                ocr_input_path="ocr.txt",
                strict_payload_chars=True,
                max_list=11,
                save_report_path="r.json",
                emit_missing_file="m.csv",
            )
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            manifest_path=None,
            ocr_input_path="ocr.txt",
            strict_payload_chars=True,
            max_list=11,
            save_report_path="r.json",
            emit_missing_file="m.csv",
        )

    def test_qrcode_helper_count_presence_delegates_to_transport_parser(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = (9, 2)
        with mock.patch.object(
            parser,
            "count_chunk_presence",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport._count_chunk_presence({"0": "AA", "100": "BB"}, 50)
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(chunks={"0": "AA", "100": "BB"}, total_chunks=50)

    def test_qrcode_helper_parity_recover_delegates_to_transport_parser(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        manifest = {"parity": {"enabled": False}}
        parsed = {"chunks": {}}
        sentinel = [3, 7]
        with mock.patch.object(
            parser,
            "apply_parity_recovery",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport._apply_parity_recovery(manifest, parsed)
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(manifest=manifest, parsed=parsed)

    def test_qrcode_helper_conflict_resolution_delegates_to_transport_parser(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        manifest = {"total_chunks": 3}
        parsed = {"duplicate_conflicts": [], "chunk_votes": {}}
        sentinel = [1]
        with mock.patch.object(
            parser,
            "resolve_conflicts_by_package_hash",
            autospec=True,
            return_value=sentinel,
        ) as mocked_hash:
            result_hash = transport._resolve_conflicts_by_package_hash(manifest, parsed)
        self.assertIs(result_hash, sentinel)
        mocked_hash.assert_called_once_with(
            transport=transport,
            manifest=manifest,
            parsed=parsed,
            max_conflicts=12,
            max_attempts=20000,
        )

        with mock.patch.object(
            parser,
            "resolve_conflicts_by_structure",
            autospec=True,
            return_value=sentinel,
        ) as mocked_struct:
            result_struct = transport._resolve_conflicts_by_structure(parsed, 3)
        self.assertIs(result_struct, sentinel)
        mocked_struct.assert_called_once_with(
            parsed=parsed,
            total_chunks=3,
            max_conflicts=10,
            max_attempts=20000,
        )

    def test_qrcode_helper_raise_parse_errors_delegates_to_transport_parser(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        parsed = {"line_errors": [], "duplicate_conflicts": [], "missing_chunks": []}
        with mock.patch.object(
            parser,
            "raise_parse_errors",
            autospec=True,
            return_value=None,
        ) as mocked:
            result = transport._raise_parse_errors(parsed, 4)
        self.assertIsNone(result)
        mocked.assert_called_once_with(parsed=parsed, total_chunks=4)

    def test_qrcode_helper_parse_entrypoints_delegate_to_transport_parser(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        manifest = {"total_chunks": 2}
        sentinel = {"chunks": {0: "AA", 1: "BB"}}
        with mock.patch.object(
            parser,
            "parse_ocr_chunks",
            autospec=True,
            return_value=sentinel,
        ) as mocked_main:
            result_main = transport._parse_ocr_chunks(manifest, "ocr.txt", True)
        self.assertIs(result_main, sentinel)
        mocked_main.assert_called_once_with(
            transport=transport,
            manifest=manifest,
            ocr_input_path="ocr.txt",
            strict_payload_chars=True,
        )

        with mock.patch.object(
            parser,
            "parse_ocr_chunks_payload_only_manifest",
            autospec=True,
            return_value=sentinel,
        ) as mocked_payload:
            result_payload = transport._parse_ocr_chunks_payload_only_manifest(manifest, "ocr.txt", False)
        self.assertIs(result_payload, sentinel)
        mocked_payload.assert_called_once_with(
            transport=transport,
            manifest=manifest,
            ocr_input_path="ocr.txt",
            strict_payload_chars=False,
        )

        with mock.patch.object(
            parser,
            "parse_ocr_chunks_with_total",
            autospec=True,
            return_value=sentinel,
        ) as mocked_total:
            result_total = transport._parse_ocr_chunks_with_total(2, "ocr.txt", True, line_index_mode="chunk")
        self.assertIs(result_total, sentinel)
        mocked_total.assert_called_once_with(
            transport=transport,
            total_chunks=2,
            ocr_input_path="ocr.txt",
            strict_payload_chars=True,
            line_index_mode="chunk",
        )

    def test_qrcode_helper_metadata_inference_entrypoints_delegate_to_transport_parser(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        votes = {"A": 2}
        metadata = {"artifact_id": "A", "total_chunks": 1}
        manifest = {"artifact_id": "A", "total_chunks": 1}

        with mock.patch.object(
            parser,
            "choose_majority_metadata_value",
            autospec=True,
            return_value="A",
        ) as mocked_choose:
            chosen = transport._choose_majority_metadata_value("artifact_id", votes)
        self.assertEqual(chosen, "A")
        mocked_choose.assert_called_once_with(label="artifact_id", votes=votes)

        with mock.patch.object(
            parser,
            "scan_transport_metadata",
            autospec=True,
            return_value=metadata,
        ) as mocked_scan:
            scanned = transport._scan_transport_metadata("ocr.txt")
        self.assertIs(scanned, metadata)
        mocked_scan.assert_called_once_with(transport=transport, ocr_input_path="ocr.txt")

        with mock.patch.object(
            parser,
            "build_inferred_manifest_from_ocr",
            autospec=True,
            return_value=manifest,
        ) as mocked_build:
            built = transport._build_inferred_manifest_from_ocr("ocr.txt")
        self.assertIs(built, manifest)
        mocked_build.assert_called_once_with(transport=transport, ocr_input_path="ocr.txt")


if __name__ == "__main__":
    unittest.main()
