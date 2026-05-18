import unittest
from unittest import mock

import qrcode_helper
from enc2sop.transport import (
    cli,
    layout,
    ocr_adapters,
    ocr_embedded,
    ocr_pipeline,
    ocr_runtime,
    parser,
    protocol,
    recover,
    render,
)


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

    def test_qrcode_helper_layout_helpers_delegate_to_transport_layout(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        manifest = {"chunk_locations": {"0": [{"page": 1, "line": 1}]}}
        page_layouts = [{"page": 1, "lines": [{"kind": "data"}]}]
        page_layout = {"page": 1, "lines": [{"kind": "data"}]}
        line_meta = {
            "binary_box": [1, 2, 3, 4],
            "binary_rows": 1,
            "binary_cols": 1,
            "bit_count": 1,
            "payload_len": 1,
        }
        image_path = qrcode_helper.Path("page_003.png")
        sentinel_entries = [{"page": 1, "line": 1, "copy": 1, "priority": 1, "chunk_index": 0}]

        with mock.patch.object(
            layout,
            "get_render_layout_pages",
            autospec=True,
            return_value=page_layouts,
        ) as mocked:
            result = transport._get_render_layout_pages(manifest)
        self.assertIs(result, page_layouts)
        mocked.assert_called_once_with(manifest=manifest)

        with mock.patch.object(
            layout,
            "line_meta_has_sidecar",
            autospec=True,
            return_value=True,
        ) as mocked:
            result = transport._line_meta_has_sidecar(line_meta)
        self.assertTrue(result)
        mocked.assert_called_once_with(line_meta=line_meta)

        with mock.patch.object(
            layout,
            "page_layout_has_sidecar",
            autospec=True,
            return_value=True,
        ) as mocked:
            result = transport._page_layout_has_sidecar(page_layout)
        self.assertTrue(result)
        mocked.assert_called_once_with(page_layout=page_layout)

        with mock.patch.object(
            layout,
            "page_layouts_support_sidecar",
            autospec=True,
            return_value=True,
        ) as mocked:
            result = transport._page_layouts_support_sidecar(page_layouts)
        self.assertTrue(result)
        mocked.assert_called_once_with(page_layouts=page_layouts)

        with mock.patch.object(
            layout,
            "manifest_has_page_entries",
            autospec=True,
            return_value=True,
        ) as mocked:
            result = transport._manifest_has_page_entries(manifest)
        self.assertTrue(result)
        mocked.assert_called_once_with(manifest=manifest)

        with mock.patch.object(
            layout,
            "resolve_image_page_number",
            autospec=True,
            return_value=3,
        ) as mocked:
            result = transport._resolve_image_page_number(image_path=image_path, image_index=2, manifest=manifest)
        self.assertEqual(result, 3)
        mocked.assert_called_once_with(image_path=image_path, image_index=2, manifest=manifest)

        with mock.patch.object(
            layout,
            "manifest_page_entries",
            autospec=True,
            return_value=sentinel_entries,
        ) as mocked:
            result = transport._manifest_page_entries(manifest=manifest, page_no=1)
        self.assertIs(result, sentinel_entries)
        mocked.assert_called_once_with(manifest=manifest, page_no=1)

        with mock.patch.object(
            layout,
            "manifest_entries_in_transport_order",
            autospec=True,
            return_value=sentinel_entries,
        ) as mocked:
            result = transport._manifest_entries_in_transport_order(manifest=manifest)
        self.assertIs(result, sentinel_entries)
        mocked.assert_called_once_with(manifest=manifest)

        with mock.patch.object(
            layout,
            "manifest_chunk_payload_length",
            autospec=True,
            return_value=40,
        ) as mocked:
            result = transport._manifest_chunk_payload_length(manifest=manifest, chunk_idx=0)
        self.assertEqual(result, 40)
        mocked.assert_called_once_with(manifest=manifest, chunk_idx=0)

    def test_qrcode_helper_ocr_pipeline_helpers_delegate_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        image = object()
        band = {"top": 1, "bottom": 9}
        raw_texts = ["@META|AT1|ID=AA|PAGE=1/1|CHUNKS=1|TOTAL=1"]
        entries = [{"page": 1, "line": 1, "chunk_index": 0}]
        manifest = {"chunk_lengths": [8]}
        variants = [(3, 4, 180)]
        crc_hints = ["ABCD"]

        with mock.patch.object(
            ocr_pipeline,
            "detect_text_bands",
            autospec=True,
            return_value=[band],
        ) as mocked:
            result = transport._detect_text_bands(image)
        self.assertEqual(result, [band])
        mocked.assert_called_once_with(image=image)

        with mock.patch.object(
            ocr_pipeline,
            "select_manifest_data_bands",
            autospec=True,
            return_value=[band],
        ) as mocked:
            result = transport._select_manifest_data_bands([band], 1)
        self.assertEqual(result, [band])
        mocked.assert_called_once_with(bands=[band], expected_count=1)

        with mock.patch.object(
            ocr_pipeline,
            "crop_primary_text_band",
            autospec=True,
            return_value=image,
        ) as mocked:
            result = transport._crop_primary_text_band(image=image, band=band)
        self.assertIs(result, image)
        mocked.assert_called_once_with(image=image, band=band)

        with mock.patch.object(
            ocr_pipeline,
            "ocr_payload_crop_tesseract",
            autospec=True,
            return_value="PAYLOAD",
        ) as mocked:
            result = transport._ocr_payload_crop_tesseract(image=image, lang="eng")
        self.assertEqual(result, "PAYLOAD")
        mocked.assert_called_once()
        self.assertIs(mocked.call_args.kwargs["transport"], transport)
        self.assertEqual(mocked.call_args.kwargs["image"], image)
        self.assertEqual(mocked.call_args.kwargs["lang"], "eng")
        self.assertIs(mocked.call_args.kwargs["image_module"], qrcode_helper.Image)
        self.assertIs(mocked.call_args.kwargs["resample_lanczos"], qrcode_helper.RESAMPLE_LANCZOS)

        with mock.patch.object(
            ocr_pipeline,
            "ocr_crc_crop_tesseract",
            autospec=True,
            return_value="ABCD",
        ) as mocked:
            result = transport._ocr_crc_crop_tesseract(image=image, lang="eng")
        self.assertEqual(result, "ABCD")
        mocked.assert_called_once()
        self.assertIs(mocked.call_args.kwargs["transport"], transport)

        with mock.patch.object(
            ocr_pipeline,
            "ocr_tesseract_variants",
            autospec=True,
            return_value=["A"],
        ) as mocked:
            result = transport._ocr_tesseract_variants(
                image=image,
                lang="eng",
                whitelist="ABC",
                variants=variants,
            )
        self.assertEqual(result, ["A"])
        mocked.assert_called_once_with(
            transport=transport,
            image=image,
            lang="eng",
            whitelist="ABC",
            variants=variants,
            image_module=qrcode_helper.Image,
            resample_lanczos=qrcode_helper.RESAMPLE_LANCZOS,
        )

        with mock.patch.object(
            ocr_pipeline,
            "ocr_payload_crop_tesseract_variants",
            autospec=True,
            return_value=["P"],
        ) as mocked:
            result = transport._ocr_payload_crop_tesseract_variants(image=image, lang="eng")
        self.assertEqual(result, ["P"])
        mocked.assert_called_once_with(
            transport=transport,
            image=image,
            lang="eng",
            image_module=qrcode_helper.Image,
            resample_lanczos=qrcode_helper.RESAMPLE_LANCZOS,
        )

        with mock.patch.object(
            ocr_pipeline,
            "ocr_crc_crop_tesseract_variants",
            autospec=True,
            return_value=["C"],
        ) as mocked:
            result = transport._ocr_crc_crop_tesseract_variants(image=image, lang="eng")
        self.assertEqual(result, ["C"])
        mocked.assert_called_once_with(
            transport=transport,
            image=image,
            lang="eng",
            image_module=qrcode_helper.Image,
            resample_lanczos=qrcode_helper.RESAMPLE_LANCZOS,
        )

        with mock.patch.object(
            ocr_pipeline,
            "ocr_generic_line_tesseract_variants",
            autospec=True,
            return_value=["L"],
        ) as mocked:
            result = transport._ocr_generic_line_tesseract_variants(
                image=image,
                lang="eng",
                whitelist="ABC",
            )
        self.assertEqual(result, ["L"])
        mocked.assert_called_once_with(
            transport=transport,
            image=image,
            lang="eng",
            whitelist="ABC",
            image_module=qrcode_helper.Image,
            resample_lanczos=qrcode_helper.RESAMPLE_LANCZOS,
        )

        with mock.patch.object(
            ocr_pipeline,
            "ocr_band_tesseract_variants",
            autospec=True,
            return_value=["B"],
        ) as mocked:
            result = transport._ocr_band_tesseract_variants(
                image=image,
                band=band,
                lang="eng",
                whitelist="ABC",
            )
        self.assertEqual(result, ["B"])
        mocked.assert_called_once_with(
            transport=transport,
            image=image,
            band=band,
            lang="eng",
            whitelist="ABC",
            image_module=qrcode_helper.Image,
            resample_lanczos=qrcode_helper.RESAMPLE_LANCZOS,
        )

        with mock.patch.object(
            ocr_pipeline,
            "parse_meta_line_candidate",
            autospec=True,
            return_value={"artifact_id": "AA"},
        ) as mocked:
            result = transport._parse_meta_line_candidate(raw_texts)
        self.assertEqual(result, {"artifact_id": "AA"})
        mocked.assert_called_once_with(raw_texts=raw_texts)

        with mock.patch.object(
            ocr_pipeline,
            "parse_cfg_line_candidate",
            autospec=True,
            return_value={"values": {"CC": 40}},
        ) as mocked:
            result = transport._parse_cfg_line_candidate(raw_texts)
        self.assertEqual(result, {"values": {"CC": 40}})
        mocked.assert_called_once_with(raw_texts=raw_texts)

        with mock.patch.object(
            ocr_pipeline,
            "parse_hash_fragment_candidate",
            autospec=True,
            return_value="@RH1|AB",
        ) as mocked:
            result = transport._parse_hash_fragment_candidate(raw_texts, "RH", 1)
        self.assertEqual(result, "@RH1|AB")
        mocked.assert_called_once_with(raw_texts=raw_texts, expected_kind="RH", expected_part=1)

        with mock.patch.object(
            ocr_pipeline,
            "parse_hash_compact_candidate",
            autospec=True,
            return_value={"RH": "AA", "CH": "BB"},
        ) as mocked:
            result = transport._parse_hash_compact_candidate(raw_texts, 1)
        self.assertEqual(result, {"RH": "AA", "CH": "BB"})
        mocked.assert_called_once_with(raw_texts=raw_texts, expected_part=1)

        with mock.patch.object(
            ocr_pipeline,
            "crc_windows_from_hints",
            autospec=True,
            return_value=["ABCD"],
        ) as mocked:
            result = transport._crc_windows_from_hints(crc_hints)
        self.assertEqual(result, ["ABCD"])
        mocked.assert_called_once_with(crc_hints=crc_hints)

        with mock.patch.object(
            ocr_pipeline,
            "score_candidate_crc_against_hints",
            autospec=True,
            return_value=(0, 0, 0, 0),
        ) as mocked:
            result = transport._score_candidate_crc_against_hints("ABCD", crc_hints)
        self.assertEqual(result, (0, 0, 0, 0))
        mocked.assert_called_once_with(candidate_crc="ABCD", crc_hints=crc_hints)

        with mock.patch.object(
            ocr_pipeline,
            "repair_payload_candidate_by_crc_hint",
            autospec=True,
            return_value=("PAY", "ABCD", (0, 0)),
        ) as mocked:
            result = transport._repair_payload_candidate_by_crc_hint("PAY", "C00001|", "ABCD", max_attempts=10)
        self.assertEqual(result, ("PAY", "ABCD", (0, 0)))
        mocked.assert_called_once_with(payload="PAY", core_prefix="C00001|", crc_hint="ABCD", max_attempts=10)

        with mock.patch.object(
            ocr_pipeline,
            "choose_payload_candidate_with_crc_hint",
            autospec=True,
            return_value="PAYLOAD",
        ) as mocked:
            result = transport._choose_payload_candidate_with_crc_hint(
                chunk_idx=1,
                expected_len=7,
                crc_hints=crc_hints,
                raw_texts=["X"],
            )
        self.assertEqual(result, "PAYLOAD")
        mocked.assert_called_once_with(
            chunk_idx=1,
            expected_len=7,
            crc_hints=crc_hints,
            raw_texts=["X"],
        )

        with mock.patch.object(
            ocr_pipeline,
            "ocr_manifest_guided_page_tesseract",
            autospec=True,
            return_value="P001L001|C00000|PAYLOAD|ABCD",
        ) as mocked:
            result = transport._ocr_manifest_guided_page_tesseract(
                image_path=qrcode_helper.Path("case_0001.png"),
                manifest=manifest,
                page_no=1,
                page_entries=entries,
                lang="eng",
            )
        self.assertEqual(result, "P001L001|C00000|PAYLOAD|ABCD")
        mocked.assert_called_once()
        self.assertIs(mocked.call_args.kwargs["transport"], transport)
        self.assertEqual(mocked.call_args.kwargs["manifest"], manifest)
        self.assertEqual(mocked.call_args.kwargs["page_no"], 1)
        self.assertEqual(mocked.call_args.kwargs["page_entries"], entries)
        self.assertEqual(mocked.call_args.kwargs["lang"], "eng")
        self.assertIs(mocked.call_args.kwargs["image_module"], qrcode_helper.Image)

        with mock.patch.object(
            ocr_pipeline,
            "ocr_image_crop_tesseract",
            autospec=True,
            return_value="PAYLOAD",
        ) as mocked:
            result = transport._ocr_image_crop_tesseract(
                image=image,
                box=[1, 2, 3, 4],
                lang="eng",
                whitelist="ABC",
                psm=11,
            )
        self.assertEqual(result, "PAYLOAD")
        mocked.assert_called_once_with(
            transport=transport,
            image=image,
            box=[1, 2, 3, 4],
            lang="eng",
            whitelist="ABC",
            image_module=qrcode_helper.Image,
            resample_lanczos=qrcode_helper.RESAMPLE_LANCZOS,
            psm=11,
        )

    def test_qrcode_helper_ocr_runtime_helpers_delegate_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        image = object()
        page_layout = {"lines": [{"kind": "data"}]}
        line_meta = {"binary_box": [1, 2, 3, 4]}
        band = {"top": 1, "bottom": 9}
        entries = [{"page": 1, "line": 1, "chunk_index": 0}]
        manifest = {"chunk_lengths": [8]}
        path = qrcode_helper.Path("case_0001.png")
        reader = object()

        with mock.patch.object(
            ocr_runtime,
            "ocr_image_crop_easyocr",
            autospec=True,
            return_value="A",
        ) as mocked:
            result = transport._ocr_image_crop_easyocr(image=image, box=[1, 2, 3, 4], reader=reader)
        self.assertEqual(result, "A")
        mocked.assert_called_once_with(
            image=image,
            box=[1, 2, 3, 4],
            reader=reader,
            image_module=qrcode_helper.Image,
            resample_lanczos=qrcode_helper.RESAMPLE_LANCZOS,
            load_numpy_module=qrcode_helper._load_numpy_module,
        )

        with mock.patch.object(
            ocr_runtime,
            "decode_sidecar_payload",
            autospec=True,
            return_value="PAYLOAD",
        ) as mocked:
            result = transport._decode_sidecar_payload(
                image=image,
                page_layout=page_layout,
                line_meta=line_meta,
            )
        self.assertEqual(result, "PAYLOAD")
        mocked.assert_called_once_with(
            transport=transport,
            image=image,
            page_layout=page_layout,
            line_meta=line_meta,
        )

        with mock.patch.object(
            ocr_runtime,
            "ocr_structured_page_sidecar",
            autospec=True,
            return_value="P001L001|C00000|PAYLOAD|ABCD",
        ) as mocked, mock.patch.object(qrcode_helper, "PIL_AVAILABLE", True):
            result = transport._ocr_structured_page_sidecar(path, page_layout)
        self.assertEqual(result, "P001L001|C00000|PAYLOAD|ABCD")
        mocked.assert_called_once_with(
            transport=transport,
            image_path=path,
            page_layout=page_layout,
            image_module=qrcode_helper.Image,
        )

        with mock.patch.object(
            ocr_runtime,
            "decode_manifest_guided_sidecar_payload",
            autospec=True,
            return_value="PAYLOAD",
        ) as mocked, mock.patch.object(qrcode_helper, "PIL_AVAILABLE", True):
            result = transport._decode_manifest_guided_sidecar_payload(
                image=image,
                band=band,
                payload_len=8,
            )
        self.assertEqual(result, "PAYLOAD")
        mocked.assert_called_once_with(
            transport=transport,
            image=image,
            band=band,
            payload_len=8,
        )

        with mock.patch.object(
            ocr_runtime,
            "ocr_manifest_guided_page_sidecar",
            autospec=True,
            return_value="P001L001|C00000|PAYLOAD|ABCD",
        ) as mocked, mock.patch.object(qrcode_helper, "PIL_AVAILABLE", True):
            result = transport._ocr_manifest_guided_page_sidecar(
                image_path=path,
                manifest=manifest,
                page_no=1,
                page_entries=entries,
            )
        self.assertEqual(result, "P001L001|C00000|PAYLOAD|ABCD")
        mocked.assert_called_once_with(
            transport=transport,
            image_path=path,
            manifest=manifest,
            page_no=1,
            page_entries=entries,
            image_module=qrcode_helper.Image,
        )

        with mock.patch.object(
            ocr_runtime,
            "choose_payload_candidate",
            autospec=True,
            return_value="PAY",
        ) as mocked:
            result = transport._choose_payload_candidate(
                chunk_idx=1,
                expected_len=3,
                expected_crc="ABCD",
                raw_texts=["PAY"],
            )
        self.assertEqual(result, "PAY")
        mocked.assert_called_once_with(
            transport=transport,
            chunk_idx=1,
            expected_len=3,
            expected_crc="ABCD",
            raw_texts=["PAY"],
        )

        with mock.patch.object(
            ocr_runtime,
            "repair_payload_candidate_by_crc",
            autospec=True,
            return_value="PAY",
        ) as mocked:
            result = transport._repair_payload_candidate_by_crc(
                payload="PAY",
                core_prefix="C00001|",
                expected_crc="ABCD",
            )
        self.assertEqual(result, "PAY")
        mocked.assert_called_once_with(
            payload="PAY",
            core_prefix="C00001|",
            expected_crc="ABCD",
        )

        with mock.patch.object(
            ocr_runtime,
            "ocr_structured_page_tesseract",
            autospec=True,
            return_value="P001L001|C00000|PAYLOAD|ABCD",
        ) as mocked, mock.patch.object(qrcode_helper, "PIL_AVAILABLE", True):
            result = transport._ocr_structured_page_tesseract(
                image_path=path,
                lang="eng",
                page_layout=page_layout,
            )
        self.assertEqual(result, "P001L001|C00000|PAYLOAD|ABCD")
        mocked.assert_called_once_with(
            transport=transport,
            image_path=path,
            lang="eng",
            page_layout=page_layout,
            image_module=qrcode_helper.Image,
        )

        with mock.patch.object(
            ocr_runtime,
            "ocr_structured_page_easyocr",
            autospec=True,
            return_value="P001L001|C00000|PAYLOAD|ABCD",
        ) as mocked, mock.patch.object(qrcode_helper, "PIL_AVAILABLE", True):
            result = transport._ocr_structured_page_easyocr(
                image_path=path,
                page_layout=page_layout,
                reader=reader,
            )
        self.assertEqual(result, "P001L001|C00000|PAYLOAD|ABCD")
        mocked.assert_called_once_with(
            transport=transport,
            image_path=path,
            page_layout=page_layout,
            reader=reader,
            image_module=qrcode_helper.Image,
            resample_lanczos=qrcode_helper.RESAMPLE_LANCZOS,
            load_numpy_module=qrcode_helper._load_numpy_module,
        )

        with mock.patch.object(
            ocr_runtime,
            "parse_external_ocr_stdout",
            autospec=True,
            return_value="TEXT",
        ) as mocked:
            result = transport._parse_external_ocr_stdout("raw")
        self.assertEqual(result, "TEXT")
        mocked.assert_called_once_with(raw_output="raw")

        with mock.patch.object(
            ocr_runtime,
            "run_external_ocr_provider",
            autospec=True,
            return_value="TEXT",
        ) as mocked:
            result = transport._run_external_ocr_provider(
                image_path=path,
                page_no=2,
                lang="eng",
                psm=6,
                manifest_path="m.json",
                provider_cmd="cmd {image_path}",
                timeout_sec=12,
            )
        self.assertEqual(result, "TEXT")
        mocked.assert_called_once_with(
            transport=transport,
            image_path=path,
            page_no=2,
            lang="eng",
            psm=6,
            manifest_path="m.json",
            provider_cmd="cmd {image_path}",
            timeout_sec=12,
            subprocess_module=qrcode_helper.subprocess,
        )

        with mock.patch.object(
            ocr_runtime,
            "ocr_single_image",
            autospec=True,
            return_value="P001L001|C00000|PAYLOAD|ABCD",
        ) as mocked:
            result = transport._ocr_single_image(
                image_path=path,
                backend="tesseract",
                lang="eng",
                psm=6,
                reader=reader,
                page_layout=page_layout,
            )
        self.assertEqual(result, "P001L001|C00000|PAYLOAD|ABCD")
        mocked.assert_called_once_with(
            transport=transport,
            image_path=path,
            backend="tesseract",
            lang="eng",
            psm=6,
            reader=reader,
            page_layout=page_layout,
            pil_available=qrcode_helper.PIL_AVAILABLE,
            image_module=qrcode_helper.Image,
            resample_lanczos=qrcode_helper.RESAMPLE_LANCZOS,
            build_easyocr_reader=qrcode_helper._build_easyocr_reader,
            load_numpy_module=qrcode_helper._load_numpy_module,
        )

    def test_qrcode_helper_embedded_metadata_helpers_delegate_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        metadata = {
            "artifact_id": "AA",
            "total_chunks": 1,
            "total_pages": 1,
            "CC": 8,
            "LP": 1,
            "RC": 1,
            "IL": 1,
            "PG": 0,
            "CS": 5,
            "RS": 3,
            "RH1": "A" * 32,
            "RH2": "B" * 32,
            "CH1": "C" * 32,
            "CH2": "D" * 32,
        }
        manifest = {"total_chunks": 1, "chunk_lengths": [8]}
        page_entries = [{"page": 1, "line": 1, "chunk_index": 0, "copy": 1}]
        image_path = qrcode_helper.Path("case_0001.png")

        with mock.patch.object(
            ocr_embedded,
            "build_inferred_manifest_from_metadata",
            autospec=True,
            return_value=manifest,
        ) as mocked_build_manifest:
            result_manifest = transport._build_inferred_manifest_from_metadata(metadata)
        self.assertIs(result_manifest, manifest)
        mocked_build_manifest.assert_called_once()
        self.assertEqual(mocked_build_manifest.call_args.kwargs["metadata"], metadata)
        self.assertTrue(callable(mocked_build_manifest.call_args.kwargs["rebuild_parity_manifest"]))

        with mock.patch.object(
            ocr_embedded,
            "build_expected_page_entries",
            autospec=True,
            return_value=page_entries,
        ) as mocked_build_entries:
            result_entries = transport._build_expected_page_entries(manifest=manifest, page_no=1, page_chunks=1)
        self.assertIs(result_entries, page_entries)
        mocked_build_entries.assert_called_once()
        self.assertEqual(mocked_build_entries.call_args.kwargs["manifest"], manifest)
        self.assertEqual(mocked_build_entries.call_args.kwargs["page_no"], 1)
        self.assertEqual(mocked_build_entries.call_args.kwargs["page_chunks"], 1)
        self.assertTrue(callable(mocked_build_entries.call_args.kwargs["build_chunk_entries"]))
        self.assertEqual(mocked_build_entries.call_args.kwargs["lines_per_page_default"], transport.lines_per_page)

        sentinel_text = "P001L001|C00000|PAYLOAD|ABCD"
        with mock.patch.object(qrcode_helper, "PIL_AVAILABLE", True), mock.patch.object(
            ocr_embedded,
            "ocr_embedded_metadata_page_tesseract",
            autospec=True,
            return_value=sentinel_text,
        ) as mocked_ocr:
            result_text = transport._ocr_embedded_metadata_page_tesseract(
                image_path=image_path,
                page_no_hint=1,
                lang="eng",
                prefer_sidecar=True,
            )
        self.assertEqual(result_text, sentinel_text)
        mocked_ocr.assert_called_once_with(
            transport=transport,
            image_path=image_path,
            page_no_hint=1,
            lang="eng",
            prefer_sidecar=True,
            image_module=qrcode_helper.Image,
            pil_available=True,
        )

    def test_qrcode_helper_embedded_metadata_ocr_requires_pillow(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        with mock.patch.object(qrcode_helper, "PIL_AVAILABLE", False), mock.patch.object(
            ocr_embedded,
            "ocr_embedded_metadata_page_tesseract",
            autospec=True,
        ) as mocked:
            with self.assertRaisesRegex(RuntimeError, "Pillow is required for embedded metadata extraction"):
                transport._ocr_embedded_metadata_page_tesseract(
                    image_path=qrcode_helper.Path("case_0001.png"),
                    page_no_hint=1,
                    lang="eng",
                    prefer_sidecar=True,
                )
        mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
