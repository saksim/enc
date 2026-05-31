import csv
import unittest
from unittest import mock
import json
import tempfile
import zipfile
import zlib
from pathlib import Path

import qrcode_helper
from enc2sop.transport import (
    certify,
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

    def test_ocr_safe_payload_profile_roundtrip_uses_restricted_alphabet(self) -> None:
        raw = b"\x00enc2sop-ocr-safe-human-correctable-profile"
        encoded = protocol.encode_payload_for_profile(
            raw,
            protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
        )

        self.assertTrue(encoded)
        self.assertTrue(
            all(ch in protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET for ch in encoded)
        )
        for excluded in "04BCDGILQSTZabcdefghijklmnopqrstuvwxyz":
            self.assertNotIn(excluded, encoded)
        self.assertEqual(
            protocol.decode_payload_for_profile(
                encoded,
                protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            ),
            raw,
        )

    def test_ocr_safe_payload_candidates_cover_confusion_families(self) -> None:
        cases = {
            "G": ["6"],
            "g": ["6", "9"],
            "q": ["O", "9"],
            "Z": ["2", "7"],
            "z": ["2", "7"],
            "0oQD": ["OOOO"],
            "Ii lL!": ["11111"],
            "S$s": ["555"],
            "Bb": ["88"],
            "4": ["A"],
            "1-2 3": ["123"],
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                result = protocol.ocr_safe_payload_candidates(raw)
                self.assertEqual(result["unexpected_chars"], "")
                self.assertEqual(result["candidates"], expected)

        unexpected = protocol.ocr_safe_payload_candidates("C")
        self.assertEqual(unexpected["unexpected_chars"], "C")
        self.assertEqual(unexpected["candidates"], [""])

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
        command_names = sorted(parser._subparsers._group_actions[0].choices.keys())
        self.assertIn("certify", command_names)
        self.assertIn("prepare-capture-corpus", command_names)
        self.assertIn("package-capture-return", command_names)
        self.assertIn("ingest-capture-corpus", command_names)
        self.assertIn("attach-capture-corpus", command_names)
        self.assertIn("validate-capture-corpus", command_names)
        self.assertIn("certify-capture-evidence", command_names)
        self.assertIn("archive-evidence", command_names)
        self.assertIn("verify-evidence-archive", command_names)
        self.assertIn("replay-evidence-archive", command_names)
        self.assertIn("certification-status", command_names)
        export_parser = parser._subparsers._group_actions[0].choices["export"]
        export_option_names = {
            option
            for action in export_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--payload-alphabet-profile", export_option_names)
        recover_parser = parser._subparsers._group_actions[0].choices["recover"]
        recover_option_names = {
            option
            for action in recover_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--apply-corrections-file", recover_option_names)
        verify_parser = parser._subparsers._group_actions[0].choices["verify"]
        verify_option_names = {
            option
            for action in verify_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--apply-corrections-file", verify_option_names)
        replay_corrections_parser = parser._subparsers._group_actions[0].choices[
            "replay-corrections"
        ]
        replay_corrections_option_names = {
            option
            for action in replay_corrections_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--apply-corrections-file", replay_corrections_option_names)
        self.assertIn("--report-file", replay_corrections_option_names)
        self.assertIn("--emit-corrections-template", replay_corrections_option_names)
        verify_correction_replay_parser = parser._subparsers._group_actions[0].choices[
            "verify-correction-replay"
        ]
        verify_correction_replay_option_names = {
            option
            for action in verify_correction_replay_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--report-file", verify_correction_replay_option_names)
        self.assertIn("--output-file", verify_correction_replay_option_names)
        self.assertIn("--allow-failed-report", verify_correction_replay_option_names)
        certify_ocr_confusion_parser = parser._subparsers._group_actions[0].choices[
            "certify-ocr-confusion"
        ]
        certify_ocr_confusion_option_names = {
            option
            for action in certify_ocr_confusion_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--report-file", certify_ocr_confusion_option_names)
        self.assertIn("--payload-size", certify_ocr_confusion_option_names)
        self.assertIn("--seed", certify_ocr_confusion_option_names)
        verify_ocr_confusion_parser = parser._subparsers._group_actions[0].choices[
            "verify-ocr-confusion"
        ]
        verify_ocr_confusion_option_names = {
            option
            for action in verify_ocr_confusion_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--report-file", verify_ocr_confusion_option_names)
        self.assertIn("--output-file", verify_ocr_confusion_option_names)
        self.assertIn("--allow-failed-report", verify_ocr_confusion_option_names)
        archive_ocr_safe_parser = parser._subparsers._group_actions[0].choices[
            "archive-ocr-safe-evidence"
        ]
        archive_ocr_safe_option_names = {
            option
            for action in archive_ocr_safe_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--archive-file", archive_ocr_safe_option_names)
        self.assertIn("--manifest-file", archive_ocr_safe_option_names)
        self.assertIn("--confusion-report-file", archive_ocr_safe_option_names)
        self.assertIn(
            "--correction-replay-report-file",
            archive_ocr_safe_option_names,
        )
        self.assertIn("--require-confusion-report", archive_ocr_safe_option_names)
        self.assertIn(
            "--require-correction-replay-report",
            archive_ocr_safe_option_names,
        )
        self.assertIn(
            "--require-source-report-verification",
            archive_ocr_safe_option_names,
        )
        verify_ocr_safe_archive_parser = parser._subparsers._group_actions[0].choices[
            "verify-ocr-safe-evidence-archive"
        ]
        verify_ocr_safe_archive_option_names = {
            option
            for action in verify_ocr_safe_archive_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--archive-file", verify_ocr_safe_archive_option_names)
        self.assertIn("--manifest-file", verify_ocr_safe_archive_option_names)
        self.assertIn("--output-file", verify_ocr_safe_archive_option_names)
        self.assertIn("--require-confusion-report", verify_ocr_safe_archive_option_names)
        self.assertIn(
            "--require-correction-replay-report",
            verify_ocr_safe_archive_option_names,
        )
        self.assertIn(
            "--require-source-report-verification",
            verify_ocr_safe_archive_option_names,
        )
        self.assertIn("--allow-failed-report", verify_ocr_safe_archive_option_names)
        analyze_parser = parser._subparsers._group_actions[0].choices["analyze"]
        analyze_option_names = {
            option
            for action in analyze_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--apply-corrections-file", analyze_option_names)
        recover_images_parser = parser._subparsers._group_actions[0].choices[
            "recover-images"
        ]
        recover_images_option_names = {
            option
            for action in recover_images_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--apply-corrections-file", recover_images_option_names)
        certify_parser = parser._subparsers._group_actions[0].choices["certify"]
        certify_option_names = {
            option
            for action in certify_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--payload-alphabet-profile", certify_option_names)
        prepare_parser = parser._subparsers._group_actions[0].choices["prepare-capture-corpus"]
        prepare_option_names = {
            option
            for action in prepare_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--include-raw-capture-dirs", prepare_option_names)
        self.assertIn("--perspective-correction-method", prepare_option_names)
        self.assertIn("--ocr-only-backend", prepare_option_names)
        self.assertIn("--payload-alphabet-profile", prepare_option_names)
        attach_parser = parser._subparsers._group_actions[0].choices["attach-capture-corpus"]
        attach_option_names = {
            option
            for action in attach_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--require-raw-captures", attach_option_names)
        package_return_parser = parser._subparsers._group_actions[0].choices[
            "package-capture-return"
        ]
        package_return_option_names = {
            option
            for action in package_return_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--capture-corpus-file", package_return_option_names)
        self.assertIn("--capture-root", package_return_option_names)
        self.assertIn("--raw-capture-root", package_return_option_names)
        self.assertIn("--capture-metadata-manifest-file", package_return_option_names)
        self.assertIn("--package-file", package_return_option_names)
        self.assertIn("--return-manifest-file", package_return_option_names)
        self.assertIn("--require-raw-captures", package_return_option_names)
        self.assertIn("--require-capture-provenance", package_return_option_names)
        ingest_parser = parser._subparsers._group_actions[0].choices["ingest-capture-corpus"]
        ingest_option_names = {
            option
            for action in ingest_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--capture-root", ingest_option_names)
        self.assertIn("--raw-capture-root", ingest_option_names)
        self.assertIn("--capture-metadata-manifest-file", ingest_option_names)
        self.assertIn("--allow-unmatched-labels", ingest_option_names)
        self.assertIn("--require-raw-captures", ingest_option_names)
        correct_parser = parser._subparsers._group_actions[0].choices[
            "correct-capture-perspective"
        ]
        correct_option_names = {
            option
            for action in correct_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--capture-corpus-file", correct_option_names)
        self.assertIn("--method", correct_option_names)
        self.assertIn("--mode", correct_option_names)
        self.assertIn("--require-raw-captures", correct_option_names)
        self.assertIn("--require-distinct-from-raw", correct_option_names)
        mode_action = [
            action
            for action in correct_parser._actions
            if "--mode" in getattr(action, "option_strings", [])
        ][0]
        self.assertIn("four-point", mode_action.choices)
        validate_parser = parser._subparsers._group_actions[0].choices["validate-capture-corpus"]
        validate_option_names = {
            option
            for action in validate_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--capture-corpus-file", validate_option_names)
        self.assertIn("--require-capture-attachment-report", validate_option_names)
        self.assertIn("--require-capture-provenance", validate_option_names)
        self.assertIn("--require-physical-print-scan", validate_option_names)
        self.assertIn(
            "--require-real-camera-perspective-correction",
            validate_option_names,
        )
        self.assertIn("--require-ocr-only-backend", validate_option_names)
        certify_parser = parser._subparsers._group_actions[0].choices["certify"]
        option_names = {
            option
            for action in certify_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--require-real-camera-perspective-correction", option_names)
        self.assertIn("--capture-attachment-report-file", option_names)
        self.assertIn("--require-capture-attachment-report", option_names)
        self.assertIn("--require-capture-provenance", option_names)
        pipeline_parser = parser._subparsers._group_actions[0].choices["certify-capture-evidence"]
        pipeline_option_names = {
            option
            for action in pipeline_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--capture-return-package-file", pipeline_option_names)
        self.assertIn("--capture-return-package-report-file", pipeline_option_names)
        self.assertIn("--require-capture-return-manifest", pipeline_option_names)
        self.assertIn("--require-capture-return-file-inventory", pipeline_option_names)
        self.assertIn("--require-capture-return-package-report", pipeline_option_names)
        self.assertIn("--capture-root", pipeline_option_names)
        self.assertIn("--raw-capture-root", pipeline_option_names)
        self.assertIn("--capture-metadata", pipeline_option_names)
        self.assertIn("--capture-metadata-manifest-file", pipeline_option_names)
        self.assertIn("--allow-unmatched-labels", pipeline_option_names)
        self.assertIn("--capture-return-extraction-report-file", pipeline_option_names)
        self.assertIn("--ingestion-report-file", pipeline_option_names)
        self.assertIn("--require-capture-provenance", pipeline_option_names)
        self.assertIn("--replay-output-dir", pipeline_option_names)
        self.assertIn("--replay-report-file", pipeline_option_names)
        self.assertIn("--replay-summary-file", pipeline_option_names)
        self.assertIn("--chunk-chars", pipeline_option_names)
        self.assertIn("--lines-per-page", pipeline_option_names)
        self.assertIn("--line-crc-mode", pipeline_option_names)
        archive_parser = parser._subparsers._group_actions[0].choices["archive-evidence"]
        archive_option_names = {
            option
            for action in archive_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--require-successful-report", archive_option_names)
        self.assertIn("--require-capture-attachment-report", archive_option_names)
        self.assertIn("--require-profile-certified", archive_option_names)
        self.assertIn("--require-physical-print-scan", archive_option_names)
        self.assertIn(
            "--require-real-camera-perspective-correction",
            archive_option_names,
        )
        self.assertIn("--require-ocr-only-backend", archive_option_names)
        verify_archive_parser = parser._subparsers._group_actions[0].choices[
            "verify-evidence-archive"
        ]
        verify_archive_option_names = {
            option
            for action in verify_archive_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--archive-file", verify_archive_option_names)
        self.assertIn("--require-successful-report", verify_archive_option_names)
        self.assertIn("--require-profile-certified", verify_archive_option_names)
        self.assertIn("--require-capture-attachment-report", verify_archive_option_names)
        self.assertIn("--require-physical-print-scan", verify_archive_option_names)
        self.assertIn(
            "--require-real-camera-perspective-correction",
            verify_archive_option_names,
        )
        self.assertIn("--require-ocr-only-backend", verify_archive_option_names)
        replay_archive_parser = parser._subparsers._group_actions[0].choices[
            "replay-evidence-archive"
        ]
        replay_archive_option_names = {
            option
            for action in replay_archive_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--archive-file", replay_archive_option_names)
        self.assertIn("--replay-report-file", replay_archive_option_names)
        self.assertIn("--require-successful-report", replay_archive_option_names)
        self.assertIn("--require-profile-certified", replay_archive_option_names)
        self.assertIn("--require-capture-attachment-report", replay_archive_option_names)
        self.assertIn("--require-physical-print-scan", replay_archive_option_names)
        self.assertIn(
            "--require-real-camera-perspective-correction",
            replay_archive_option_names,
        )
        self.assertIn("--require-ocr-only-backend", replay_archive_option_names)
        certification_status_parser = parser._subparsers._group_actions[0].choices[
            "certification-status"
        ]
        certification_status_option_names = {
            option
            for action in certification_status_parser._actions
            for option in getattr(action, "option_strings", [])
        }
        self.assertIn("--require-certified-claim", certification_status_option_names)

    def _ocr_safe_export_with_required_symbols(self, root: Path) -> tuple:
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=18,
            lines_per_page=5,
            render_sidecar=False,
            payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
        )
        required = set("6927O158A")
        payload = b""
        for attempt in range(500):
            candidate = (
                b"enc2sop-ocr-safe-confusion-"
                + str(attempt).encode("ascii")
                + bytes(range(256))
            )
            encoded = protocol.encode_payload_for_profile(
                zlib.compress(candidate, 9),
                protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            if required.issubset(set(encoded)):
                payload = candidate
                break
        self.assertTrue(payload)
        input_file = root / "payload.bin"
        input_file.write_bytes(payload)
        export = transport.export_artifact(
            input_file=str(input_file),
            output_dir=str(root / "package"),
            redundancy_copies=2,
            parity_group_size=4,
        )
        return transport, payload, export

    @staticmethod
    def _mutate_ocr_safe_payload(payload: str) -> str:
        mutated = payload
        for old, new in [
            ("6", "g"),
            ("9", "q"),
            ("2", "Z"),
            ("7", "z"),
            ("O", "0"),
            ("1", "I"),
            ("5", "S"),
            ("8", "B"),
            ("A", "4"),
        ]:
            if old in mutated:
                mutated = mutated.replace(old, new, 1)
        if len(mutated) > 4:
            mutated = mutated[:2] + " " + mutated[2:4] + "-" + mutated[4:]
        return mutated

    def test_ocr_safe_profile_recovers_synthetic_confusion_text_by_line_crc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["payload_alphabet_profile"],
                protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            self.assertEqual(manifest["alphabet"], protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET)

            ocr_lines = []
            split_done = False
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        mutated_payload = self._mutate_ocr_safe_payload(payload_text)
                        if not split_done and len(mutated_payload) > 8:
                            split_at = len(mutated_payload) // 2
                            ocr_lines.append("{}|{}".format(prefix, mutated_payload[:split_at]))
                            ocr_lines.append("{}|{}".format(mutated_payload[split_at:], crc))
                            split_done = True
                            continue
                        line = "{}|{}|{}".format(prefix, mutated_payload, crc)
                    ocr_lines.append(line)
            self.assertTrue(split_done)
            ocr_text = root / "ocr_confused.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")

            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                save_report_path=str(root / "analyze.json"),
            )
            self.assertTrue(analyze["success"])
            self.assertEqual(analyze["correction_required_count"], 0)
            warning_reasons = {
                item.get("reason") for item in analyze["line_warnings_sample"]
            }
            self.assertIn("ocr_safe_line_crc_resolved", warning_reasons)

            recovered = root / "recovered.bin"
            result = transport.recover_artifact(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                output_file=str(recovered),
                strict_payload_chars=True,
            )
            self.assertTrue(result["success"])
            self.assertEqual(recovered.read_bytes(), payload)

    def test_ocr_safe_profile_recovers_separator_like_one_confusions(self) -> None:
        for replacement in ("|", "!"):
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    transport, payload, export = self._ocr_safe_export_with_required_symbols(root)
                    manifest_path = Path(export["manifest_path"])

                    ocr_lines = []
                    mutated = False
                    for text_file in sorted(Path(path) for path in export["page_texts"]):
                        for line in text_file.read_text(encoding="ascii").splitlines():
                            if (
                                not mutated
                                and line.startswith("P")
                                and "|C" in line
                                and line.count("|") >= 3
                            ):
                                prefix, payload_text, crc = line.rsplit("|", 2)
                                if "1" in payload_text:
                                    payload_text = payload_text.replace("1", replacement, 1)
                                    line = "{}|{}|{}".format(prefix, payload_text, crc)
                                    mutated = True
                            ocr_lines.append(line)
                    self.assertTrue(mutated)
                    ocr_text = root / "ocr_one_confused.txt"
                    ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")

                    analyze = transport.analyze_ocr_text(
                        manifest_path=str(manifest_path),
                        ocr_input_path=str(ocr_text),
                        strict_payload_chars=True,
                    )
                    self.assertTrue(analyze["success"])
                    self.assertEqual(analyze["correction_required_count"], 0)

                    recovered = root / "recovered.bin"
                    result = transport.recover_artifact(
                        manifest_path=str(manifest_path),
                        ocr_input_path=str(ocr_text),
                        output_file=str(recovered),
                        strict_payload_chars=True,
                    )
                    self.assertTrue(result["success"])
                    self.assertEqual(recovered.read_bytes(), payload)

    def test_ocr_safe_profile_writes_replayable_correction_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            self.assertTrue(corrected_payload_text)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")

            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                save_report_path=str(root / "analyze.json"),
            )

            self.assertFalse(analyze["success"])
            self.assertGreaterEqual(analyze["correction_required_count"], 1)
            template_path = Path(analyze["corrections_template_path"])
            self.assertTrue(template_path.exists())
            template = template_path.read_text(encoding="utf-8")
            self.assertIn(
                "page,line,raw_text,normalized_text,candidates,status,expected_crc,actual_crc,corrected_text",
                template,
            )
            self.assertIn("unexpected-chars", template)

            with template_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            rows[0]["corrected_text"] = corrected_payload_text
            with template_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

            replay_analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                corrections_file=str(template_path),
            )
            self.assertTrue(replay_analyze["success"])
            self.assertEqual(replay_analyze["correction_required_count"], 0)
            replay = replay_analyze["correction_replay"]
            self.assertEqual(replay["filled_row_count"], 1)
            self.assertEqual(replay["applied_count"], 1)
            self.assertEqual(replay["invalid_count"], 0)

            recovered = root / "replayed.bin"
            result = transport.recover_artifact(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                output_file=str(recovered),
                strict_payload_chars=True,
                corrections_file=str(template_path),
            )
            self.assertTrue(result["success"])
            self.assertEqual(recovered.read_bytes(), payload)

    def test_ocr_safe_replay_corrections_writes_sha_verified_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")

            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["corrected_text"] = corrected_payload_text
            with template_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

            report_file = root / "correction_replay_report.json"
            output_file = root / "corrected.bin"
            result = transport.replay_ocr_corrections(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                corrections_file=str(template_path),
                output_file=str(output_file),
                report_file=str(report_file),
                strict_payload_chars=True,
            )

            self.assertTrue(result["success"])
            self.assertEqual(result["schema"], recover.CORRECTION_REPLAY_REPORT_SCHEMA)
            self.assertTrue(result["correction_file_valid"])
            self.assertIsNone(result["correction_file_error"])
            self.assertEqual(result["correction_replay"]["applied_count"], 1)
            self.assertEqual(result["correction_replay"]["invalid_count"], 0)
            correction_bytes = template_path.read_bytes()
            self.assertEqual(
                result["corrections_file_sha256"],
                protocol.sha256_hex(correction_bytes),
            )
            self.assertEqual(result["corrections_file_size"], len(correction_bytes))
            self.assertEqual(
                result["correction_replay"]["source_sha256"],
                result["corrections_file_sha256"],
            )
            self.assertEqual(
                result["correction_replay"]["source_size"],
                result["corrections_file_size"],
            )
            self.assertTrue(result["final_payload_sha256_verified"])
            self.assertEqual(result["actual_raw_sha256"], protocol.sha256_hex(payload))
            self.assertEqual(output_file.read_bytes(), payload)
            saved = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["schema"], recover.CORRECTION_REPLAY_REPORT_SCHEMA)
            self.assertEqual(saved["actual_raw_sha256"], protocol.sha256_hex(payload))
            self.assertEqual(saved["corrections_file_sha256"], result["corrections_file_sha256"])
            self.assertEqual(saved["corrections_file_size"], result["corrections_file_size"])

    def test_ocr_safe_replay_corrections_cli_writes_report_and_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")
            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["corrected_text"] = corrected_payload_text
            with template_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

            report_file = root / "cli_replay_report.json"
            output_file = root / "cli_corrected.bin"
            exit_code = cli.run_cli(
                [
                    "replay-corrections",
                    "-m",
                    str(manifest_path),
                    "-t",
                    str(ocr_text),
                    "--apply-corrections-file",
                    str(template_path),
                    "-o",
                    str(output_file),
                    "--report-file",
                    str(report_file),
                    "--strict-payload-chars",
                ],
                qrcode_helper.AirgapTransportLayer,
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(output_file.read_bytes(), payload)
            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertTrue(report["success"])
            self.assertTrue(report["final_payload_sha256_verified"])
            self.assertEqual(report["correction_replay"]["applied_count"], 1)
            correction_bytes = template_path.read_bytes()
            self.assertEqual(
                report["corrections_file_sha256"],
                protocol.sha256_hex(correction_bytes),
            )
            self.assertEqual(report["corrections_file_size"], len(correction_bytes))
            self.assertEqual(
                report["correction_replay"]["source_sha256"],
                report["corrections_file_sha256"],
            )

    def test_ocr_safe_verify_correction_replay_checks_report_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")
            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["corrected_text"] = corrected_payload_text
            with template_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

            replay_report = root / "transport_ocr_correction_replay_report.json"
            output_file = root / "corrected.bin"
            transport.replay_ocr_corrections(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                corrections_file=str(template_path),
                output_file=str(output_file),
                report_file=str(replay_report),
                strict_payload_chars=True,
            )

            verification_file = root / "correction_replay_verification.json"
            verification = transport.verify_ocr_correction_replay_report(
                report_file=str(replay_report),
                output_file=str(verification_file),
            )

            self.assertTrue(verification["success"])
            self.assertEqual(
                verification["schema"],
                recover.CORRECTION_REPLAY_VERIFICATION_SCHEMA,
            )
            self.assertTrue(verification["manifest_verified"])
            self.assertTrue(verification["ocr_input_verified"])
            self.assertTrue(verification["corrections_file_verified"])
            self.assertTrue(verification["correction_replay_reexecuted"])
            self.assertTrue(verification["final_payload_sha256_verified"])
            self.assertTrue(verification["output_file_verified"])
            self.assertEqual(verification["failure_count"], 0)
            self.assertEqual(output_file.read_bytes(), payload)
            saved = json.loads(verification_file.read_text(encoding="utf-8"))
            self.assertEqual(
                saved["schema"],
                recover.CORRECTION_REPLAY_VERIFICATION_SCHEMA,
            )
            self.assertIn(
                "does not certify real camera/photo",
                saved["certification_boundary"],
            )

    def test_ocr_safe_verify_correction_replay_cli_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, _payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")
            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["corrected_text"] = corrected_payload_text
            with template_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

            replay_report = root / "transport_ocr_correction_replay_report.json"
            transport.replay_ocr_corrections(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                corrections_file=str(template_path),
                output_file=str(root / "corrected.bin"),
                report_file=str(replay_report),
                strict_payload_chars=True,
            )
            verification_file = root / "cli_correction_replay_verification.json"

            exit_code = cli.run_cli(
                [
                    "verify-correction-replay",
                    "--report-file",
                    str(replay_report),
                    "--output-file",
                    str(verification_file),
                ],
                qrcode_helper.AirgapTransportLayer,
            )

            self.assertEqual(exit_code, 0)
            report = json.loads(verification_file.read_text(encoding="utf-8"))
            self.assertTrue(report["success"])
            self.assertEqual(
                report["schema"],
                recover.CORRECTION_REPLAY_VERIFICATION_SCHEMA,
            )

    def test_ocr_safe_verify_correction_replay_fails_on_tampered_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, _payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")
            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["corrected_text"] = corrected_payload_text
            with template_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
            replay_report = root / "transport_ocr_correction_replay_report.json"
            output_file = root / "corrected.bin"
            transport.replay_ocr_corrections(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                corrections_file=str(template_path),
                output_file=str(output_file),
                report_file=str(replay_report),
                strict_payload_chars=True,
            )
            output_file.write_bytes(b"tampered")

            verification = transport.verify_ocr_correction_replay_report(
                report_file=str(replay_report),
            )

            self.assertFalse(verification["success"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("output_file_sha256_mismatch", reasons)

    def test_ocr_safe_replay_corrections_rejects_unused_filled_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, _payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")
            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["corrected_text"] = corrected_payload_text
            extra = dict(rows[0])
            extra["line"] = "999"
            extra["corrected_text"] = corrected_payload_text
            rows.append(extra)
            with template_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

            result = transport.replay_ocr_corrections(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                corrections_file=str(template_path),
                strict_payload_chars=True,
            )

            self.assertFalse(result["success"])
            self.assertTrue(result["final_payload_sha256_verified"])
            self.assertEqual(result["correction_replay"]["filled_row_count"], 2)
            self.assertEqual(result["correction_replay"]["applied_count"], 1)
            self.assertEqual(result["unused_filled_correction_count"], 1)
            replay = result["correction_replay"]
            self.assertEqual(replay["unused_count"], 1)
            self.assertEqual(len(replay["unused_sample"]), 1)
            self.assertEqual(replay["unused_sample"][0]["line"], 999)
            self.assertEqual(
                replay["unused_sample"][0]["corrected_text_sha256"],
                protocol.sha256_hex(corrected_payload_text.encode("utf-8")),
            )
            self.assertEqual(
                result["unused_filled_correction_rows_sample"],
                replay["unused_sample"],
            )

    def test_ocr_safe_replay_corrections_suppresses_output_when_rows_unused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, _payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")
            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["corrected_text"] = corrected_payload_text
            extra = dict(rows[0])
            extra["line"] = "999"
            extra["corrected_text"] = corrected_payload_text
            rows.append(extra)
            with template_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

            output_file = root / "must_not_exist.bin"
            result = transport.replay_ocr_corrections(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                corrections_file=str(template_path),
                output_file=str(output_file),
                strict_payload_chars=True,
            )

            self.assertFalse(result["success"])
            self.assertTrue(result["final_payload_sha256_verified"])
            self.assertEqual(result["requested_output_file"], str(output_file))
            self.assertIsNone(result["output_file"])
            self.assertEqual(
                result["output_suppressed_reason"],
                "correction_replay_not_accepted",
            )
            self.assertFalse(output_file.exists())

    def test_ocr_safe_replay_corrections_reports_malformed_csv_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, _payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_text = root / "ocr_text.txt"
            ocr_text.write_text(
                "\n".join(
                    line
                    for text_file in sorted(Path(path) for path in export["page_texts"])
                    for line in text_file.read_text(encoding="ascii").splitlines()
                )
                + "\n",
                encoding="utf-8",
            )
            malformed_csv = root / "malformed_corrections.csv"
            malformed_csv.write_text(
                "page,line,raw_text\n1,1,missing-corrected-text\n",
                encoding="utf-8",
            )
            output_file = root / "must_not_exist.bin"
            report_file = root / "malformed_replay_report.json"

            result = transport.replay_ocr_corrections(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                corrections_file=str(malformed_csv),
                output_file=str(output_file),
                report_file=str(report_file),
                strict_payload_chars=True,
            )

            self.assertFalse(result["success"])
            self.assertEqual(result["schema"], recover.CORRECTION_REPLAY_REPORT_SCHEMA)
            self.assertFalse(result["correction_file_valid"])
            self.assertEqual(
                result["correction_file_error"]["reason"],
                "corrections_file_missing_required_columns",
            )
            self.assertEqual(result["output_suppressed_reason"], "correction_file_invalid")
            self.assertIsNone(result["output_file"])
            self.assertFalse(output_file.exists())
            replay = result["correction_replay"]
            self.assertEqual(replay["invalid_count"], 1)
            self.assertEqual(
                replay["invalid_sample"][0]["reason"],
                "corrections_file_missing_required_columns",
            )
            correction_bytes = malformed_csv.read_bytes()
            self.assertEqual(
                result["corrections_file_sha256"],
                protocol.sha256_hex(correction_bytes),
            )
            self.assertEqual(result["corrections_file_size"], len(correction_bytes))
            saved = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["correction_file_error"], result["correction_file_error"])
            self.assertEqual(saved["output_suppressed_reason"], "correction_file_invalid")

    def test_ocr_safe_replay_corrections_rejects_stale_template_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, _payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")
            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                template_rows = list(csv.DictReader(handle))
            self.assertEqual(len(template_rows), 1)
            base_row = dict(template_rows[0])
            base_row["corrected_text"] = corrected_payload_text

            cases = [
                ("raw_text", base_row["raw_text"] + "X", "correction_raw_text_mismatch"),
                (
                    "normalized_text",
                    base_row["normalized_text"] + "X",
                    "correction_normalized_text_mismatch",
                ),
                ("status", "unresolved", "correction_status_mismatch"),
                ("actual_crc", "DEAD", "correction_actual_crc_mismatch"),
            ]
            for field, value, reason in cases:
                with self.subTest(field=field):
                    stale_row = dict(base_row)
                    stale_row[field] = value
                    stale_template = root / "{}_stale_corrections.csv".format(field)
                    with stale_template.open("w", newline="", encoding="utf-8") as handle:
                        writer = csv.DictWriter(handle, fieldnames=list(stale_row.keys()))
                        writer.writeheader()
                        writer.writerow(stale_row)

                    result = transport.replay_ocr_corrections(
                        manifest_path=str(manifest_path),
                        ocr_input_path=str(ocr_text),
                        corrections_file=str(stale_template),
                        strict_payload_chars=True,
                    )

                    self.assertFalse(result["success"])
                    replay = result["correction_replay"]
                    self.assertEqual(replay["filled_row_count"], 1)
                    self.assertEqual(replay["applied_count"], 0)
                    self.assertEqual(replay["invalid_count"], 1)
                    self.assertEqual(replay["invalid_sample"][0]["reason"], reason)
                    self.assertEqual(result["unused_filled_correction_count"], 0)

    def test_ocr_safe_replay_corrections_emits_refreshed_template_after_invalid_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, _payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")
            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                template_rows = list(csv.DictReader(handle))
            stale_row = dict(template_rows[0])
            stale_row["corrected_text"] = corrected_payload_text
            stale_row["normalized_text"] = stale_row["normalized_text"] + "X"
            stale_template = root / "stale_corrections.csv"
            with stale_template.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(stale_row.keys()))
                writer.writeheader()
                writer.writerow(stale_row)

            report_file = root / "failed_replay_report.json"
            result = transport.replay_ocr_corrections(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                corrections_file=str(stale_template),
                report_file=str(report_file),
                strict_payload_chars=True,
            )

            self.assertFalse(result["success"])
            replay = result["correction_replay"]
            self.assertEqual(replay["invalid_count"], 1)
            self.assertEqual(
                replay["invalid_sample"][0]["reason"],
                "correction_normalized_text_mismatch",
            )
            retry_template = Path(result["refreshed_corrections_template_path"])
            self.assertEqual(retry_template.name, "corrections_template_retry.csv")
            self.assertEqual(result["refreshed_corrections_template_record_count"], 1)
            self.assertTrue(retry_template.exists())
            with retry_template.open(newline="", encoding="utf-8") as handle:
                retry_rows = list(csv.DictReader(handle))
            self.assertEqual(len(retry_rows), 1)
            self.assertEqual(retry_rows[0]["corrected_text"], "")
            self.assertEqual(
                retry_rows[0]["normalized_text"],
                template_rows[0]["normalized_text"],
            )
            saved = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(
                saved["refreshed_corrections_template_path"],
                str(retry_template),
            )

    def test_ocr_safe_confusion_certification_writes_replayable_synthetic_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            report_file = root / "synthetic_ocr_confusion_report.json"

            result = transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(report_file),
                payload_size=256,
                seed=20260530,
            )

            self.assertTrue(result["success"])
            self.assertEqual(result["schema"], recover.OCR_SAFE_CONFUSION_REPORT_SCHEMA)
            self.assertEqual(
                result["suite"],
                recover.OCR_SAFE_SYNTHETIC_CONFUSION_SUITE,
            )
            self.assertEqual(
                result["payload_alphabet_profile"],
                protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            self.assertEqual(result["alphabet"], protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET)
            self.assertEqual(result["failed_count"], 0)
            self.assertEqual(result["passed_count"], result["case_count"])
            required = {
                "6/G/g",
                "9/g/q",
                "2/7/Z/z",
                "O/0/o/Q/D",
                "1/I/i/l/L",
                "5/S/s",
                "8/B/b",
                "whitespace-insertion",
                "dash-noise-insertion",
                "line-break-drift",
            }
            self.assertTrue(required.issubset(set(result["required_confusion_families"])))
            self.assertFalse(result["missing_confusion_families"])
            for family in required:
                self.assertTrue(result["covered_confusion_families"][family])
            case_names = {case["name"] for case in result["cases"]}
            self.assertIn("line-break-drift", case_names)
            for case in result["cases"]:
                self.assertTrue(case["success"])
                self.assertTrue(case["analyze_success"])
                self.assertTrue(case["recover_success"])
                self.assertTrue(case["final_payload_sha256_verified"])
                self.assertEqual(case["correction_required_count"], 0)
                self.assertEqual(case["line_error_count"], 0)
                self.assertTrue(Path(case["ocr_input_path"]).exists())
                self.assertTrue(Path(case["analyze_report_path"]).exists())
                self.assertTrue(Path(case["recovered_output_path"]).exists())
            saved = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["schema"], recover.OCR_SAFE_CONFUSION_REPORT_SCHEMA)
            self.assertEqual(saved["payload_sha256"], result["payload_sha256"])
            self.assertEqual(len(saved["required_confusion_cases"]), saved["case_count"])
            required_case_names = {
                case["name"] for case in saved["required_confusion_cases"]
            }
            self.assertEqual(required_case_names, case_names)
            self.assertIn("does not certify real camera/photo", saved["certification_boundary"])

    def test_ocr_safe_confusion_certification_cli_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_file = root / "cli_synthetic_ocr_confusion_report.json"

            exit_code = cli.run_cli(
                [
                    "certify-ocr-confusion",
                    "-o",
                    str(root),
                    "--report-file",
                    str(report_file),
                    "--payload-alphabet-profile",
                    protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
                    "--no-sidecar",
                    "--chunk-chars",
                    "18",
                    "--lines-per-page",
                    "5",
                    "--payload-size",
                    "256",
                    "--seed",
                    "20260530",
                ],
                qrcode_helper.AirgapTransportLayer,
            )

            self.assertEqual(exit_code, 0)
            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertTrue(report["success"])
            self.assertEqual(report["schema"], recover.OCR_SAFE_CONFUSION_REPORT_SCHEMA)
            self.assertEqual(report["failed_count"], 0)

    def test_ocr_safe_confusion_report_verification_checks_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            report_file = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(report_file),
                payload_size=256,
                seed=20260530,
            )

            verification = transport.verify_ocr_safe_confusion_report(
                report_file=str(report_file),
                output_file=str(root / "synthetic_ocr_confusion_verification.json"),
            )

            self.assertTrue(verification["success"])
            self.assertEqual(
                verification["schema"],
                recover.OCR_SAFE_CONFUSION_VERIFICATION_SCHEMA,
            )
            self.assertTrue(verification["payload_verified"])
            self.assertTrue(verification["manifest_verified"])
            self.assertTrue(verification["source_page_texts_verified"])
            self.assertEqual(
                verification["mutation_replay_verified_count"],
                verification["case_count"],
            )
            self.assertEqual(
                verification["verified_case_output_count"],
                verification["case_count"],
            )
            self.assertEqual(verification["failure_count"], 0)
            saved = json.loads(
                (root / "synthetic_ocr_confusion_verification.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(saved["success"], verification["success"])
            self.assertIn(
                "does not certify real camera/photo",
                saved["certification_boundary"],
            )

    def test_ocr_safe_confusion_report_verification_fails_on_tampered_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            report_file = root / "synthetic_ocr_confusion_report.json"
            report = transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(report_file),
                payload_size=256,
                seed=20260530,
            )
            first_case = report["cases"][0]
            Path(first_case["recovered_output_path"]).write_bytes(b"tampered")

            verification = transport.verify_ocr_safe_confusion_report(
                report_file=str(report_file),
            )

            self.assertFalse(verification["success"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("case_artifact_sha256_mismatch", reasons)
            self.assertIn("case_recovered_payload_sha256_mismatch", reasons)

    def test_ocr_safe_confusion_report_verification_fails_on_tampered_mutation_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            report_file = root / "synthetic_ocr_confusion_report.json"
            report = transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(report_file),
                payload_size=256,
                seed=20260530,
            )
            report["cases"][0]["mutation"]["payload_offset"] = (
                int(report["cases"][0]["mutation"]["payload_offset"]) + 1
            )
            report_file.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

            verification = transport.verify_ocr_safe_confusion_report(
                report_file=str(report_file),
            )

            self.assertFalse(verification["success"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("case_mutation_field_mismatch", reasons)

    def test_ocr_safe_confusion_report_verification_fails_on_tampered_ocr_input_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            report_file = root / "synthetic_ocr_confusion_report.json"
            report = transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(report_file),
                payload_size=256,
                seed=20260530,
            )
            first_case = report["cases"][0]
            ocr_path = Path(first_case["ocr_input_path"])
            original_text = ocr_path.read_text(encoding="utf-8")
            mutation = first_case["mutation"]
            raw_lines = original_text.splitlines()
            line_index = int(mutation["source_line_no"]) - 1
            offset = int(mutation["payload_offset"])
            prefix, payload_text, crc = raw_lines[line_index].rsplit("|", 2)
            payload_text = (
                payload_text[:offset]
                + "6"
                + payload_text[offset + 1 :]
            )
            raw_lines[line_index] = "{}|{}|{}".format(prefix, payload_text, crc)
            ocr_path.write_bytes(("\n".join(raw_lines) + "\n").encode("utf-8"))

            verification = transport.verify_ocr_safe_confusion_report(
                report_file=str(report_file),
            )

            self.assertFalse(verification["success"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("case_artifact_sha256_mismatch", reasons)
            self.assertIn("case_mutation_ocr_input_mismatch", reasons)

    def test_ocr_safe_confusion_report_verification_requires_exact_case_suite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            report_file = root / "synthetic_ocr_confusion_report.json"
            report = transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(report_file),
                payload_size=256,
                seed=20260530,
            )
            removed_case = report["cases"].pop(0)
            report["required_confusion_cases"] = [
                case
                for case in report["required_confusion_cases"]
                if case["name"] != removed_case["name"]
            ]
            report["case_count"] = len(report["cases"])
            report["passed_count"] = len(report["cases"])
            report["failed_count"] = 0
            report_file.write_text(
                json.dumps(report, indent=2, sort_keys=True),
                encoding="utf-8",
            )

            verification = transport.verify_ocr_safe_confusion_report(
                report_file=str(report_file),
            )

            self.assertFalse(verification["success"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("required_confusion_case_missing", reasons)
            self.assertIn("case_required_missing", reasons)

    def test_ocr_safe_confusion_report_verification_cli_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_report_file = root / "synthetic_ocr_confusion_report.json"
            verify_report_file = root / "synthetic_ocr_confusion_verification.json"
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(source_report_file),
                payload_size=256,
                seed=20260530,
            )

            exit_code = cli.run_cli(
                [
                    "verify-ocr-confusion",
                    "--report-file",
                    str(source_report_file),
                    "--output-file",
                    str(verify_report_file),
                ],
                qrcode_helper.AirgapTransportLayer,
            )

            self.assertEqual(exit_code, 0)
            report = json.loads(verify_report_file.read_text(encoding="utf-8"))
            self.assertTrue(report["success"])
            self.assertEqual(
                report["schema"],
                recover.OCR_SAFE_CONFUSION_VERIFICATION_SCHEMA,
            )

    def test_qrcode_helper_ocr_confusion_verifier_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {
            "success": True,
            "schema": recover.OCR_SAFE_CONFUSION_VERIFICATION_SCHEMA,
        }
        with mock.patch.object(
            recover,
            "verify_ocr_safe_confusion_report",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.verify_ocr_safe_confusion_report(
                report_file="synthetic_ocr_confusion_report.json",
                output_file="synthetic_ocr_confusion_verification.json",
                require_success=False,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            report_file="synthetic_ocr_confusion_report.json",
            output_file="synthetic_ocr_confusion_verification.json",
            require_success=False,
        )

    def test_qrcode_helper_ocr_safe_archive_verifier_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {
            "success": True,
            "schema": recover.OCR_SAFE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA,
        }
        with mock.patch.object(
            recover,
            "verify_ocr_safe_evidence_archive",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.verify_ocr_safe_evidence_archive(
                archive_file="ocr_safe_evidence_archive.zip",
                manifest_file="ocr_safe_evidence_archive_manifest.json",
                output_file="ocr_safe_evidence_archive_verification.json",
                require_confusion_report=True,
                require_correction_replay_report=True,
                require_source_report_verification=True,
                require_success=False,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            archive_file="ocr_safe_evidence_archive.zip",
            manifest_file="ocr_safe_evidence_archive_manifest.json",
            output_file="ocr_safe_evidence_archive_verification.json",
            require_confusion_report=True,
            require_correction_replay_report=True,
            require_source_report_verification=True,
            require_success=False,
        )

    def test_qrcode_helper_ocr_safe_archiver_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {
            "success": True,
            "schema": recover.OCR_SAFE_EVIDENCE_ARCHIVE_SCHEMA,
        }
        with mock.patch.object(
            recover,
            "archive_ocr_safe_evidence",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.archive_ocr_safe_evidence(
                archive_file="ocr_safe_evidence_archive.zip",
                manifest_file="ocr_safe_evidence_archive_manifest.json",
                confusion_report_file="synthetic_ocr_confusion_report.json",
                correction_replay_report_file="transport_ocr_correction_replay_report.json",
                require_confusion_report=True,
                require_correction_replay_report=True,
                require_source_report_verification=True,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            archive_file="ocr_safe_evidence_archive.zip",
            manifest_file="ocr_safe_evidence_archive_manifest.json",
            confusion_report_file="synthetic_ocr_confusion_report.json",
            correction_replay_report_file="transport_ocr_correction_replay_report.json",
            require_confusion_report=True,
            require_correction_replay_report=True,
            require_source_report_verification=True,
        )

    def test_ocr_safe_archive_confusion_evidence_verifies_replayably(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260530,
            )

            archive_file = root / "ocr_safe_evidence_archive.zip"
            manifest_file = root / "ocr_safe_evidence_archive_manifest.json"
            archive = transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                manifest_file=str(manifest_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertTrue(archive["success"])
            self.assertEqual(archive["schema"], recover.OCR_SAFE_EVIDENCE_ARCHIVE_SCHEMA)
            self.assertTrue(archive_file.exists())
            self.assertTrue(manifest_file.exists())
            roles = {item["role"] for item in archive["files"]}
            self.assertIn("ocr_safe_confusion_report_rewritten", roles)
            self.assertIn("ocr_safe_confusion_source_verification_report", roles)
            self.assertIn("confusion_ocr_input", roles)
            self.assertIn("source_page_text", roles)
            self.assertTrue(
                archive["parameters"]["require_source_report_verification"]
            )
            self.assertTrue(
                archive["reports"][0]["source_verification"]["success"]
            )
            self.assertIn(
                "archive_path",
                archive["reports"][0]["source_verification"],
            )
            self.assertIn(
                "archive_sha256",
                archive["reports"][0]["source_verification"],
            )

            verification_file = root / "ocr_safe_evidence_archive_verification.json"
            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(archive_file),
                manifest_file=str(manifest_file),
                output_file=str(verification_file),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertTrue(verification["success"])
            self.assertEqual(
                verification["schema"],
                recover.OCR_SAFE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA,
            )
            self.assertTrue(verification["confusion_report_verified"])
            self.assertFalse(verification["correction_replay_report_verified"])
            self.assertEqual(verification["failure_count"], 0)
            self.assertEqual(
                verification["verified_file_count"],
                verification["file_count"],
            )
            self.assertEqual(
                verification["verified_total_size_bytes"],
                archive["summary"]["total_size_bytes"],
            )
            self.assertTrue(verification["summary_file_count_verified"])
            self.assertTrue(verification["summary_total_size_verified"])
            self.assertEqual(verification["verified_report_count"], 1)
            self.assertTrue(verification["summary_report_count_verified"])
            self.assertTrue(verification["summary_report_roles_verified"])
            self.assertTrue(verification["summary_roles_verified"])
            self.assertTrue(verification["archive_success_verified"])
            self.assertTrue(verification["archive_parameters_verified"])
            self.assertEqual(
                verification["archive_parameter_gates"]["require_confusion_report"],
                True,
            )
            self.assertEqual(verification["verified_roles"], archive["summary"]["roles"])
            self.assertEqual(
                verification["verified_report_roles"],
                archive["summary"]["report_roles"],
            )
            self.assertTrue(verification["require_source_report_verification"])
            self.assertTrue(
                verification["source_report_verification_required_by_manifest"]
            )
            self.assertEqual(verification["source_report_verification_count"], 1)
            saved = json.loads(verification_file.read_text(encoding="utf-8"))
            self.assertIn(
                "does not certify real camera/photo",
                saved["certification_boundary"],
            )

    def test_ocr_safe_archive_combined_evidence_cli_verifies_replayably(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport, _payload, export = self._ocr_safe_export_with_required_symbols(root)
            manifest_path = Path(export["manifest_path"])
            ocr_lines = []
            corrupted = False
            corrected_payload_text = ""
            for text_file in sorted(Path(path) for path in export["page_texts"]):
                for line in text_file.read_text(encoding="ascii").splitlines():
                    if (not corrupted) and line.startswith("P") and "|C" in line and line.count("|") >= 3:
                        prefix, payload_text, crc = line.rsplit("|", 2)
                        corrected_payload_text = payload_text
                        line = "{}|{}|{}".format(prefix, "C" + payload_text[1:], crc)
                        corrupted = True
                    ocr_lines.append(line)
            self.assertTrue(corrupted)
            ocr_text = root / "ocr_unresolved.txt"
            ocr_text.write_text("\n".join(ocr_lines) + "\n", encoding="utf-8")
            analyze = transport.analyze_ocr_text(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                strict_payload_chars=True,
                emit_corrections_file=str(root / "corrections_template.csv"),
            )
            template_path = Path(analyze["corrections_template_path"])
            with template_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            rows[0]["corrected_text"] = corrected_payload_text
            with template_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
            replay_report = root / "transport_ocr_correction_replay_report.json"
            transport.replay_ocr_corrections(
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_text),
                corrections_file=str(template_path),
                output_file=str(root / "corrected.bin"),
                report_file=str(replay_report),
                strict_payload_chars=True,
            )

            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root / "confusion"),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260530,
            )
            archive_file = root / "combined_ocr_safe_evidence.zip"
            manifest_file = root / "combined_ocr_safe_evidence_manifest.json"
            exit_code = cli.run_cli(
                [
                    "archive-ocr-safe-evidence",
                    "--archive-file",
                    str(archive_file),
                    "--manifest-file",
                    str(manifest_file),
                    "--confusion-report-file",
                    str(confusion_report),
                    "--correction-replay-report-file",
                    str(replay_report),
                    "--require-confusion-report",
                    "--require-correction-replay-report",
                    "--require-source-report-verification",
                ],
                qrcode_helper.AirgapTransportLayer,
            )
            self.assertEqual(exit_code, 0)

            verification_file = root / "combined_ocr_safe_evidence_verification.json"
            exit_code = cli.run_cli(
                [
                    "verify-ocr-safe-evidence-archive",
                    "--archive-file",
                    str(archive_file),
                    "--manifest-file",
                    str(manifest_file),
                    "--output-file",
                    str(verification_file),
                    "--require-confusion-report",
                    "--require-correction-replay-report",
                    "--require-source-report-verification",
                ],
                qrcode_helper.AirgapTransportLayer,
            )

            self.assertEqual(exit_code, 0)
            verification = json.loads(verification_file.read_text(encoding="utf-8"))
            self.assertTrue(verification["success"])
            self.assertTrue(verification["confusion_report_verified"])
            self.assertTrue(verification["correction_replay_report_verified"])
            self.assertEqual(verification["failure_count"], 0)
            self.assertEqual(verification["source_report_verification_count"], 2)
            self.assertEqual(
                {item["role"] for item in verification["report_verifications"]},
                {"ocr_safe_confusion_report", "correction_replay_report"},
            )
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            self.assertTrue(
                manifest["parameters"]["require_source_report_verification"]
            )
            for report in manifest["reports"]:
                self.assertTrue(report["source_verification_required"])
                self.assertTrue(report["source_verification"]["success"])
                self.assertIn("archive_path", report["source_verification"])
                self.assertIn("archive_sha256", report["source_verification"])

    def test_ocr_safe_archive_source_verification_report_is_archived(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260531,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            archive = transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            source_verification = archive["reports"][0]["source_verification"]
            verification_member = source_verification["archive_path"]
            with zipfile.ZipFile(str(archive_file), "r") as archive_zip:
                archived_verification = json.loads(
                    archive_zip.read(verification_member).decode("utf-8")
                )

            self.assertEqual(
                archived_verification["schema"],
                recover.OCR_SAFE_CONFUSION_VERIFICATION_SCHEMA,
            )
            self.assertTrue(archived_verification["success"])
            self.assertEqual(
                archived_verification["report_sha256"],
                archive["reports"][0]["source_sha256"],
            )
            self.assertEqual(
                protocol.sha256_hex(
                    json.dumps(
                        archived_verification,
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    ).encode("utf-8")
                ),
                source_verification["archive_sha256"],
            )

            source_report_archive = archive["reports"][0]["source_report_archive"]
            self.assertEqual(
                archived_verification["report_file"],
                source_report_archive["archive_path"],
            )
            self.assertEqual(
                source_verification["source_report_archive_path"],
                source_report_archive["archive_path"],
            )
            with zipfile.ZipFile(str(archive_file), "r") as archive_zip:
                archived_source_report = archive_zip.read(
                    source_report_archive["archive_path"]
                )
            self.assertEqual(
                protocol.sha256_hex(archived_source_report),
                archive["reports"][0]["source_sha256"],
            )

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(archive_file),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertTrue(verification["success"])
            self.assertEqual(verification["source_report_verification_count"], 1)

    def test_ocr_safe_archive_verification_fails_when_source_verification_member_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260531,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            archive = transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )
            verification_member = archive["reports"][0]["source_verification"][
                "archive_path"
            ]
            tampered_archive = root / "missing_source_verification_archive.zip"
            with zipfile.ZipFile(str(archive_file), "r") as source:
                with zipfile.ZipFile(
                    str(tampered_archive),
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                ) as target:
                    for info in source.infolist():
                        if info.filename == verification_member:
                            continue
                        target.writestr(info, source.read(info.filename))

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(tampered_archive),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertFalse(verification["success"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("archive_member_missing", reasons)
            self.assertIn("source_report_verification_archive_member_missing", reasons)

    def test_ocr_safe_archive_verification_fails_on_local_source_verifier_report_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            original = transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260531,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            archive = transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )
            verification_member = archive["reports"][0]["source_verification"][
                "archive_path"
            ]

            tampered_archive = root / "tampered_source_verifier_path_archive.zip"
            with zipfile.ZipFile(str(archive_file), "r") as source:
                verifier = json.loads(source.read(verification_member).decode("utf-8"))
                verifier["report_file"] = original["report_path"]
                tampered_verifier_payload = json.dumps(
                    verifier,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8")
                tampered_sha = protocol.sha256_hex(tampered_verifier_payload)
                tampered_size = len(tampered_verifier_payload)
                with zipfile.ZipFile(
                    str(tampered_archive),
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                ) as target:
                    for info in source.infolist():
                        payload = source.read(info.filename)
                        if info.filename == verification_member:
                            payload = tampered_verifier_payload
                        elif info.filename == recover.OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST:
                            manifest = json.loads(payload.decode("utf-8"))
                            for record in manifest["files"]:
                                if record.get("archive_path") == verification_member:
                                    manifest["summary"]["total_size_bytes"] += (
                                        tampered_size - int(record["size_bytes"])
                                    )
                                    record["sha256"] = tampered_sha
                                    record["size_bytes"] = tampered_size
                                    break
                            manifest["reports"][0]["source_verification"][
                                "archive_sha256"
                            ] = tampered_sha
                            manifest["reports"][0]["source_verification"][
                                "archive_size_bytes"
                            ] = tampered_size
                            payload = json.dumps(
                                manifest,
                                ensure_ascii=False,
                                indent=2,
                                sort_keys=True,
                            ).encode("utf-8")
                        target.writestr(info, payload)

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(tampered_archive),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertFalse(verification["success"])
            self.assertTrue(verification["confusion_report_verified"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn(
                "source_report_verification_report_path_not_archive_relative",
                reasons,
            )

    def test_ocr_safe_archive_requires_source_report_verification_before_packaging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            report = transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260530,
            )
            tamper_path = Path(report["cases"][0]["ocr_input_path"])
            tamper_path.write_text("tampered\n", encoding="utf-8")
            archive_file = root / "ocr_safe_evidence_archive.zip"

            exit_code = cli.run_cli(
                [
                    "archive-ocr-safe-evidence",
                    "--archive-file",
                    str(archive_file),
                    "--confusion-report-file",
                    str(confusion_report),
                    "--require-confusion-report",
                    "--require-source-report-verification",
                ],
                qrcode_helper.AirgapTransportLayer,
            )

            self.assertEqual(exit_code, 2)
            self.assertFalse(archive_file.exists())

    def test_ocr_safe_archive_verifier_requires_source_report_verification_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260530,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
            )

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(archive_file),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertFalse(verification["success"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("source_report_verification_not_required_by_archive", reasons)
            self.assertIn("source_report_verification_flag_missing", reasons)

    def test_ocr_safe_archive_verification_fails_on_tampered_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260530,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            manifest_file = root / "ocr_safe_evidence_archive_manifest.json"
            archive = transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                manifest_file=str(manifest_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
            )
            tamper_member = next(
                item["archive_path"]
                for item in archive["files"]
                if item["role"] == "confusion_ocr_input"
            )
            tampered_archive = root / "tampered_ocr_safe_evidence_archive.zip"
            with zipfile.ZipFile(str(archive_file), "r") as source:
                with zipfile.ZipFile(str(tampered_archive), "w", compression=zipfile.ZIP_DEFLATED) as target:
                    for info in source.infolist():
                        payload = source.read(info.filename)
                        if info.filename == tamper_member:
                            payload = b"tampered\n"
                        target.writestr(info, payload)

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(tampered_archive),
                manifest_file=str(manifest_file),
                require_confusion_report=True,
            )

            self.assertFalse(verification["success"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("external_archive_sha256_mismatch", reasons)
            self.assertIn("file_sha256_mismatch", reasons)
            self.assertIn("embedded_report_verification_failed", reasons)

    def test_ocr_safe_archive_verification_fails_on_external_manifest_envelope_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260531,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            manifest_file = root / "ocr_safe_evidence_archive_manifest.json"
            transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                manifest_file=str(manifest_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            manifest["archive_sha256"] = "0" * 64
            manifest["archive_size_bytes"] += 1
            manifest["archive_file"] = str(root / "wrong_archive.zip")
            manifest["manifest_file"] = str(root / "wrong_manifest.json")
            del manifest["embedded_manifest_sha256"]
            manifest_file.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(archive_file),
                manifest_file=str(manifest_file),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertFalse(verification["success"])
            self.assertTrue(verification["confusion_report_verified"])
            self.assertFalse(verification["external_manifest_verified"])
            self.assertEqual(verification["archive_size_bytes"], archive_file.stat().st_size)
            self.assertEqual(verification["manifest_file"], str(manifest_file.resolve()))
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("external_archive_sha256_mismatch", reasons)
            self.assertIn("external_archive_size_mismatch", reasons)
            self.assertIn("external_archive_file_name_mismatch", reasons)
            self.assertIn("external_manifest_file_name_mismatch", reasons)
            self.assertIn("embedded_manifest_sha256_missing", reasons)

    def test_ocr_safe_archive_verification_fails_on_absolute_archived_report_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            original = transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260531,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            tampered_archive = root / "tampered_absolute_report_path_archive.zip"
            with zipfile.ZipFile(str(archive_file), "r") as source:
                tampered_report_payload = None
                for info in source.infolist():
                    if info.filename != "synthetic_ocr_confusion_report.json":
                        continue
                    report = json.loads(source.read(info.filename).decode("utf-8"))
                    report["payload_file"] = original["payload_file"]
                    report["cases"][0]["ocr_input_path"] = original["cases"][0][
                        "ocr_input_path"
                    ]
                    tampered_report_payload = json.dumps(
                        report,
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    ).encode("utf-8")
                    break
                self.assertIsNotNone(tampered_report_payload)
                tampered_report_sha = protocol.sha256_hex(tampered_report_payload)
                tampered_report_size = len(tampered_report_payload)
                with zipfile.ZipFile(
                    str(tampered_archive),
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                ) as target:
                    for info in source.infolist():
                        payload = source.read(info.filename)
                        if info.filename == "synthetic_ocr_confusion_report.json":
                            payload = tampered_report_payload
                        elif info.filename == recover.OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST:
                            manifest = json.loads(payload.decode("utf-8"))
                            manifest["reports"][0][
                                "archive_report_sha256"
                            ] = tampered_report_sha
                            delta_size = 0
                            for record in manifest["files"]:
                                if record.get("archive_path") == "synthetic_ocr_confusion_report.json":
                                    delta_size = tampered_report_size - int(
                                        record["size_bytes"]
                                    )
                                    record["sha256"] = tampered_report_sha
                                    record["size_bytes"] = tampered_report_size
                                    break
                            manifest["summary"]["total_size_bytes"] += delta_size
                            payload = json.dumps(
                                manifest,
                                ensure_ascii=False,
                                indent=2,
                                sort_keys=True,
                            ).encode("utf-8")
                        target.writestr(info, payload)

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(tampered_archive),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertFalse(verification["success"])
            self.assertFalse(verification["confusion_report_verified"])
            self.assertFalse(verification["archived_report_paths_verified"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("archived_report_path_not_archive_relative", reasons)

    def test_ocr_safe_archive_verification_fails_on_report_metadata_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260530,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
            )

            tampered_archive = root / "tampered_report_metadata_archive.zip"
            with zipfile.ZipFile(str(archive_file), "r") as source:
                with zipfile.ZipFile(
                    str(tampered_archive),
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                ) as target:
                    for info in source.infolist():
                        payload = source.read(info.filename)
                        if info.filename == recover.OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST:
                            manifest = json.loads(payload.decode("utf-8"))
                            manifest["reports"][0]["archive_report_sha256"] = "0" * 64
                            payload = json.dumps(
                                manifest,
                                ensure_ascii=False,
                                indent=2,
                                sort_keys=True,
                            ).encode("utf-8")
                        target.writestr(info, payload)

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(tampered_archive),
                require_confusion_report=True,
            )

            self.assertFalse(verification["success"])
            self.assertTrue(verification["confusion_report_verified"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("archive_report_sha256_mismatch", reasons)

    def test_ocr_safe_archive_verification_fails_on_summary_role_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260531,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            tampered_archive = root / "tampered_summary_roles_archive.zip"
            with zipfile.ZipFile(str(archive_file), "r") as source:
                with zipfile.ZipFile(
                    str(tampered_archive),
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                ) as target:
                    for info in source.infolist():
                        payload = source.read(info.filename)
                        if info.filename == recover.OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST:
                            manifest = json.loads(payload.decode("utf-8"))
                            manifest["summary"]["roles"][
                                "ocr_safe_confusion_report_rewritten"
                            ] += 1
                            payload = json.dumps(
                                manifest,
                                ensure_ascii=False,
                                indent=2,
                                sort_keys=True,
                            ).encode("utf-8")
                        target.writestr(info, payload)

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(tampered_archive),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertFalse(verification["success"])
            self.assertFalse(verification["summary_roles_verified"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("summary_roles_mismatch", reasons)

    def test_ocr_safe_archive_verification_fails_on_summary_file_inventory_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260531,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            tampered_archive = root / "tampered_summary_file_inventory_archive.zip"
            with zipfile.ZipFile(str(archive_file), "r") as source:
                with zipfile.ZipFile(
                    str(tampered_archive),
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                ) as target:
                    for info in source.infolist():
                        payload = source.read(info.filename)
                        if info.filename == recover.OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST:
                            manifest = json.loads(payload.decode("utf-8"))
                            manifest["summary"]["file_count"] += 1
                            manifest["summary"]["total_size_bytes"] += 1
                            payload = json.dumps(
                                manifest,
                                ensure_ascii=False,
                                indent=2,
                                sort_keys=True,
                            ).encode("utf-8")
                        target.writestr(info, payload)

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(tampered_archive),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertFalse(verification["success"])
            self.assertTrue(verification["confusion_report_verified"])
            self.assertFalse(verification["summary_file_count_verified"])
            self.assertFalse(verification["summary_total_size_verified"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("summary_file_count_mismatch", reasons)
            self.assertIn("summary_total_size_mismatch", reasons)

    def test_ocr_safe_archive_verification_fails_on_summary_report_role_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260531,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            tampered_archive = root / "tampered_summary_report_roles_archive.zip"
            with zipfile.ZipFile(str(archive_file), "r") as source:
                with zipfile.ZipFile(
                    str(tampered_archive),
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                ) as target:
                    for info in source.infolist():
                        payload = source.read(info.filename)
                        if info.filename == recover.OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST:
                            manifest = json.loads(payload.decode("utf-8"))
                            manifest["summary"]["report_count"] += 1
                            manifest["summary"]["report_roles"][
                                "correction_replay_report"
                            ] = 1
                            payload = json.dumps(
                                manifest,
                                ensure_ascii=False,
                                indent=2,
                                sort_keys=True,
                            ).encode("utf-8")
                        target.writestr(info, payload)

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(tampered_archive),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertFalse(verification["success"])
            self.assertTrue(verification["confusion_report_verified"])
            self.assertFalse(verification["summary_report_count_verified"])
            self.assertFalse(verification["summary_report_roles_verified"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("summary_report_count_mismatch", reasons)
            self.assertIn("summary_report_roles_mismatch", reasons)

    def test_ocr_safe_archive_verification_fails_on_manifest_parameter_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            transport = qrcode_helper.AirgapTransportLayer(
                chunk_chars=18,
                lines_per_page=5,
                render_sidecar=False,
                payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            confusion_report = root / "synthetic_ocr_confusion_report.json"
            transport.certify_ocr_safe_confusions(
                output_dir=str(root),
                report_file=str(confusion_report),
                payload_size=256,
                seed=20260531,
            )
            archive_file = root / "ocr_safe_evidence_archive.zip"
            transport.archive_ocr_safe_evidence(
                archive_file=str(archive_file),
                confusion_report_file=str(confusion_report),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            tampered_archive = root / "tampered_manifest_parameters_archive.zip"
            with zipfile.ZipFile(str(archive_file), "r") as source:
                with zipfile.ZipFile(
                    str(tampered_archive),
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                ) as target:
                    for info in source.infolist():
                        payload = source.read(info.filename)
                        if info.filename == recover.OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST:
                            manifest = json.loads(payload.decode("utf-8"))
                            manifest["success"] = False
                            manifest["parameters"]["require_confusion_report"] = "yes"
                            manifest["parameters"][
                                "require_correction_replay_report"
                            ] = False
                            del manifest["parameters"][
                                "require_source_report_verification"
                            ]
                            payload = json.dumps(
                                manifest,
                                ensure_ascii=False,
                                indent=2,
                                sort_keys=True,
                            ).encode("utf-8")
                        target.writestr(info, payload)

            verification = transport.verify_ocr_safe_evidence_archive(
                archive_file=str(tampered_archive),
                require_confusion_report=True,
                require_source_report_verification=True,
            )

            self.assertFalse(verification["success"])
            self.assertTrue(verification["confusion_report_verified"])
            self.assertFalse(verification["archive_success_verified"])
            self.assertFalse(verification["archive_parameters_verified"])
            reasons = {item["reason"] for item in verification["failures"]}
            self.assertIn("archive_success_not_true", reasons)
            self.assertIn("archive_parameter_missing_or_invalid", reasons)
            self.assertIn("confusion_report_not_required_by_archive", reasons)
            self.assertIn("source_report_verification_not_required_by_archive", reasons)

    def test_qrcode_helper_certify_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "schema": certify.REPORT_SCHEMA}
        with mock.patch.object(
            certify,
            "certify_transport_reliability",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.certify_reliability(
                output_dir="out",
                payload_sizes=[32],
                iterations_per_size=1,
                seed=7,
                backend="sidecar",
                redundancy_copies=2,
                parity_group_size=4,
                profile="reliable-airgap-v1",
                allow_unsafe_profile=False,
                distortion_suite="generated-page-basic-v1",
                capture_corpus_file="captures.json",
                include_generated_corpus=False,
                require_real_camera_perspective_correction=True,
                capture_attachment_report_file="attachment.json",
                require_capture_attachment_report=True,
                require_capture_provenance=True,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertIs(mocked.call_args.kwargs["transport"], transport)
        self.assertEqual(mocked.call_args.kwargs["output_dir"], "out")
        self.assertEqual(mocked.call_args.kwargs["payload_sizes"], [32])
        self.assertEqual(mocked.call_args.kwargs["profile"], "reliable-airgap-v1")
        self.assertFalse(mocked.call_args.kwargs["allow_unsafe_profile"])
        self.assertEqual(mocked.call_args.kwargs["distortion_suite"], "generated-page-basic-v1")
        self.assertEqual(mocked.call_args.kwargs["capture_corpus_file"], "captures.json")
        self.assertFalse(mocked.call_args.kwargs["include_generated_corpus"])
        self.assertTrue(mocked.call_args.kwargs["require_real_camera_perspective_correction"])
        self.assertEqual(mocked.call_args.kwargs["capture_attachment_report_file"], "attachment.json")
        self.assertTrue(mocked.call_args.kwargs["require_capture_attachment_report"])
        self.assertTrue(mocked.call_args.kwargs["require_capture_provenance"])

    def test_qrcode_helper_prepare_capture_corpus_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "schema": certify.CAPTURE_KIT_SCHEMA}
        with mock.patch.object(
            certify,
            "prepare_capture_corpus_kit",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.prepare_capture_corpus_kit(
                output_dir="kit",
                classification="lab",
                payload_sizes=[64],
                iterations_per_size=1,
                seed=20260526,
                redundancy_copies=2,
                parity_group_size=4,
                include_raw_capture_dirs=True,
                perspective_correction_method="unit-test homography",
                capture_metadata={"scanner": "fixture"},
                ocr_only_backend="tesseract",
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertIs(mocked.call_args.kwargs["transport"], transport)
        self.assertEqual(mocked.call_args.kwargs["output_dir"], "kit")
        self.assertEqual(mocked.call_args.kwargs["classification"], "lab")
        self.assertEqual(mocked.call_args.kwargs["payload_sizes"], [64])
        self.assertEqual(mocked.call_args.kwargs["seed"], 20260526)
        self.assertTrue(mocked.call_args.kwargs["include_raw_capture_dirs"])
        self.assertEqual(
            mocked.call_args.kwargs["perspective_correction_method"],
            "unit-test homography",
        )
        self.assertEqual(mocked.call_args.kwargs["capture_metadata"], {"scanner": "fixture"})
        self.assertEqual(mocked.call_args.kwargs["ocr_only_backend"], "tesseract")

    def test_qrcode_helper_attach_capture_corpus_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "schema": certify.CAPTURE_ATTACHMENT_REPORT_SCHEMA}
        with mock.patch.object(
            certify,
            "attach_capture_corpus",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.attach_capture_corpus(
                capture_corpus_file="capture_corpus.json",
                output_dir="attach",
                report_file="report.json",
                kit_manifest_file="capture_kit_manifest.json",
                require_captures=True,
                require_distinct_capture_images=True,
                require_raw_captures=True,
                update_corpus=False,
                update_kit_manifest=False,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.kwargs["capture_corpus_file"], "capture_corpus.json")
        self.assertEqual(mocked.call_args.kwargs["output_dir"], "attach")
        self.assertEqual(mocked.call_args.kwargs["report_file"], "report.json")
        self.assertTrue(mocked.call_args.kwargs["require_captures"])
        self.assertTrue(mocked.call_args.kwargs["require_distinct_capture_images"])
        self.assertTrue(mocked.call_args.kwargs["require_raw_captures"])
        self.assertFalse(mocked.call_args.kwargs["update_corpus"])
        self.assertFalse(mocked.call_args.kwargs["update_kit_manifest"])

    def test_qrcode_helper_package_capture_return_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "schema": certify.CAPTURE_RETURN_PACKAGE_SCHEMA}
        with mock.patch.object(
            certify,
            "package_capture_return",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.package_capture_return(
                capture_corpus_file="capture_corpus.json",
                output_dir="return_pkg",
                capture_root="returned_scans",
                raw_capture_root="raw_photos",
                capture_metadata_manifest_file="operator_metadata.json",
                capture_metadata={"scanner": "delegate-flatbed"},
                kit_manifest_file="capture_kit_manifest.json",
                package_file="operator_return.zip",
                return_manifest_file="operator_return_manifest.json",
                report_file="package_report.json",
                return_session_id="session-1",
                operator="operator-a",
                returned_at_utc="2026-05-28T18:00:00Z",
                require_captures=True,
                require_raw_captures=True,
                require_capture_provenance=True,
                require_all_case_labels=False,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.kwargs["capture_corpus_file"], "capture_corpus.json")
        self.assertEqual(mocked.call_args.kwargs["output_dir"], "return_pkg")
        self.assertEqual(mocked.call_args.kwargs["capture_root"], "returned_scans")
        self.assertEqual(mocked.call_args.kwargs["raw_capture_root"], "raw_photos")
        self.assertEqual(
            mocked.call_args.kwargs["capture_metadata_manifest_file"],
            "operator_metadata.json",
        )
        self.assertEqual(
            mocked.call_args.kwargs["capture_metadata"],
            {"scanner": "delegate-flatbed"},
        )
        self.assertEqual(
            mocked.call_args.kwargs["kit_manifest_file"],
            "capture_kit_manifest.json",
        )
        self.assertEqual(mocked.call_args.kwargs["package_file"], "operator_return.zip")
        self.assertEqual(
            mocked.call_args.kwargs["return_manifest_file"],
            "operator_return_manifest.json",
        )
        self.assertEqual(mocked.call_args.kwargs["report_file"], "package_report.json")
        self.assertEqual(mocked.call_args.kwargs["return_session_id"], "session-1")
        self.assertEqual(mocked.call_args.kwargs["operator"], "operator-a")
        self.assertEqual(
            mocked.call_args.kwargs["returned_at_utc"],
            "2026-05-28T18:00:00Z",
        )
        self.assertTrue(mocked.call_args.kwargs["require_captures"])
        self.assertTrue(mocked.call_args.kwargs["require_raw_captures"])
        self.assertTrue(mocked.call_args.kwargs["require_capture_provenance"])
        self.assertFalse(mocked.call_args.kwargs["require_all_case_labels"])

    def test_qrcode_helper_ingest_capture_corpus_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {
            "success": True,
            "schema": certify.CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA,
        }
        with mock.patch.object(
            certify,
            "ingest_capture_corpus",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.ingest_capture_corpus(
                capture_corpus_file="capture_corpus.json",
                capture_root="external_scans",
                output_dir="ingest",
                report_file="ingest.json",
                kit_manifest_file="capture_kit_manifest.json",
                raw_capture_root="raw_photos",
                classification="real",
                capture_medium="camera-photo",
                capture_metadata={"device": "unit-test-camera"},
                require_captures=True,
                require_raw_captures=True,
                require_all_case_labels=False,
                update_corpus=False,
                update_kit_manifest=False,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.kwargs["capture_corpus_file"], "capture_corpus.json")
        self.assertEqual(mocked.call_args.kwargs["capture_root"], "external_scans")
        self.assertEqual(mocked.call_args.kwargs["output_dir"], "ingest")
        self.assertEqual(mocked.call_args.kwargs["raw_capture_root"], "raw_photos")
        self.assertEqual(mocked.call_args.kwargs["classification"], "real")
        self.assertEqual(mocked.call_args.kwargs["capture_medium"], "camera-photo")
        self.assertEqual(
            mocked.call_args.kwargs["capture_metadata"],
            {"device": "unit-test-camera"},
        )
        self.assertTrue(mocked.call_args.kwargs["require_captures"])
        self.assertTrue(mocked.call_args.kwargs["require_raw_captures"])
        self.assertFalse(mocked.call_args.kwargs["require_all_case_labels"])
        self.assertFalse(mocked.call_args.kwargs["update_corpus"])
        self.assertFalse(mocked.call_args.kwargs["update_kit_manifest"])

    def test_qrcode_helper_correct_capture_perspective_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {
            "success": True,
            "schema": certify.CAPTURE_PERSPECTIVE_CORRECTION_REPORT_SCHEMA,
        }
        with mock.patch.object(
            certify,
            "correct_capture_perspective",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.correct_capture_perspective(
                capture_corpus_file="capture_corpus.json",
                output_dir="corrected",
                report_file="correction.json",
                kit_manifest_file="capture_kit_manifest.json",
                method="unit-test correction",
                mode="normalize",
                require_raw_captures=True,
                require_distinct_from_raw=True,
                update_corpus=False,
                update_kit_manifest=False,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.kwargs["capture_corpus_file"], "capture_corpus.json")
        self.assertEqual(mocked.call_args.kwargs["output_dir"], "corrected")
        self.assertEqual(mocked.call_args.kwargs["report_file"], "correction.json")
        self.assertEqual(
            mocked.call_args.kwargs["kit_manifest_file"],
            "capture_kit_manifest.json",
        )
        self.assertEqual(mocked.call_args.kwargs["method"], "unit-test correction")
        self.assertEqual(mocked.call_args.kwargs["mode"], "normalize")
        self.assertTrue(mocked.call_args.kwargs["require_raw_captures"])
        self.assertTrue(mocked.call_args.kwargs["require_distinct_from_raw"])
        self.assertFalse(mocked.call_args.kwargs["update_corpus"])
        self.assertFalse(mocked.call_args.kwargs["update_kit_manifest"])

    def test_qrcode_helper_validate_capture_corpus_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "schema": certify.CAPTURE_VALIDATION_REPORT_SCHEMA}
        with mock.patch.object(
            certify,
            "validate_capture_corpus",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.validate_capture_corpus(
                capture_corpus_file="capture_corpus.json",
                output_file="validate.json",
                profile="reliable-airgap-v1",
                backend="sidecar",
                require_captures=True,
                require_distinct_capture_images=True,
                require_raw_captures=True,
                capture_attachment_report_file="attachment.json",
                require_capture_attachment_report=True,
                require_capture_provenance=True,
                capture_required_classification="real",
                require_physical_print_scan=True,
                require_real_camera_perspective_correction=True,
                require_ocr_only_backend=True,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.kwargs["capture_corpus_file"], "capture_corpus.json")
        self.assertEqual(mocked.call_args.kwargs["output_file"], "validate.json")
        self.assertEqual(mocked.call_args.kwargs["profile"], "reliable-airgap-v1")
        self.assertEqual(mocked.call_args.kwargs["backend"], "sidecar")
        self.assertTrue(mocked.call_args.kwargs["require_captures"])
        self.assertTrue(mocked.call_args.kwargs["require_distinct_capture_images"])
        self.assertTrue(mocked.call_args.kwargs["require_raw_captures"])
        self.assertEqual(
            mocked.call_args.kwargs["capture_attachment_report_file"],
            "attachment.json",
        )
        self.assertTrue(mocked.call_args.kwargs["require_capture_attachment_report"])
        self.assertTrue(mocked.call_args.kwargs["require_capture_provenance"])
        self.assertEqual(mocked.call_args.kwargs["capture_required_classification"], "real")
        self.assertTrue(mocked.call_args.kwargs["require_physical_print_scan"])
        self.assertTrue(
            mocked.call_args.kwargs["require_real_camera_perspective_correction"]
        )
        self.assertTrue(mocked.call_args.kwargs["require_ocr_only_backend"])

    def test_qrcode_helper_archive_transport_evidence_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "schema": certify.CAPTURE_EVIDENCE_ARCHIVE_SCHEMA}
        with mock.patch.object(
            certify,
            "archive_transport_evidence",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.archive_transport_evidence(
                report_file="transport_reliability_report.json",
                output_dir="archive",
                capture_corpus_file="capture_corpus.json",
                capture_attachment_report_file="attachment.json",
                archive_file="bundle.zip",
                manifest_file="bundle_manifest.json",
                require_successful_report=True,
                require_capture_attachment_report=True,
                require_physical_print_scan=True,
                require_real_camera_perspective_correction=True,
                require_ocr_only_backend=True,
                require_profile_certified=True,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertEqual(mocked.call_args.kwargs["report_file"], "transport_reliability_report.json")
        self.assertEqual(mocked.call_args.kwargs["output_dir"], "archive")
        self.assertEqual(mocked.call_args.kwargs["capture_corpus_file"], "capture_corpus.json")
        self.assertEqual(
            mocked.call_args.kwargs["capture_attachment_report_file"],
            "attachment.json",
        )
        self.assertEqual(mocked.call_args.kwargs["archive_file"], "bundle.zip")
        self.assertEqual(mocked.call_args.kwargs["manifest_file"], "bundle_manifest.json")
        self.assertTrue(mocked.call_args.kwargs["require_successful_report"])
        self.assertTrue(mocked.call_args.kwargs["require_capture_attachment_report"])
        self.assertTrue(mocked.call_args.kwargs["require_physical_print_scan"])
        self.assertTrue(
            mocked.call_args.kwargs["require_real_camera_perspective_correction"]
        )
        self.assertTrue(mocked.call_args.kwargs["require_ocr_only_backend"])
        self.assertTrue(mocked.call_args.kwargs["require_profile_certified"])

    def test_qrcode_helper_verify_transport_evidence_archive_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {
            "success": True,
            "schema": certify.CAPTURE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA,
        }
        with mock.patch.object(
            certify,
            "verify_transport_evidence_archive",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.verify_transport_evidence_archive(
                archive_file="transport_capture_evidence_archive.zip",
                manifest_file="manifest.json",
                output_file="verify.json",
                require_successful_report=True,
                require_capture_attachment_report=True,
                require_physical_print_scan=True,
                require_real_camera_perspective_correction=True,
                require_ocr_only_backend=True,
                require_profile_certified=True,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertEqual(
            mocked.call_args.kwargs["archive_file"],
            "transport_capture_evidence_archive.zip",
        )
        self.assertEqual(mocked.call_args.kwargs["manifest_file"], "manifest.json")
        self.assertEqual(mocked.call_args.kwargs["output_file"], "verify.json")
        self.assertTrue(mocked.call_args.kwargs["require_successful_report"])
        self.assertTrue(mocked.call_args.kwargs["require_capture_attachment_report"])
        self.assertTrue(mocked.call_args.kwargs["require_physical_print_scan"])
        self.assertTrue(
            mocked.call_args.kwargs["require_real_camera_perspective_correction"]
        )
        self.assertTrue(mocked.call_args.kwargs["require_ocr_only_backend"])
        self.assertTrue(mocked.call_args.kwargs["require_profile_certified"])

    def test_qrcode_helper_replay_transport_evidence_archive_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {
            "success": True,
            "schema": certify.CAPTURE_EVIDENCE_ARCHIVE_REPLAY_SCHEMA,
        }
        with mock.patch.object(
            certify,
            "replay_transport_evidence_archive",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.replay_transport_evidence_archive(
                archive_file="transport_capture_evidence_archive.zip",
                output_dir="replay",
                manifest_file="manifest.json",
                replay_report_file="replay_report.json",
                output_file="summary.json",
                require_successful_report=True,
                require_capture_attachment_report=True,
                require_physical_print_scan=True,
                require_real_camera_perspective_correction=True,
                require_ocr_only_backend=True,
                require_profile_certified=True,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertIs(mocked.call_args.kwargs["transport"], transport)
        self.assertEqual(
            mocked.call_args.kwargs["archive_file"],
            "transport_capture_evidence_archive.zip",
        )
        self.assertEqual(mocked.call_args.kwargs["output_dir"], "replay")
        self.assertEqual(mocked.call_args.kwargs["manifest_file"], "manifest.json")
        self.assertEqual(mocked.call_args.kwargs["replay_report_file"], "replay_report.json")
        self.assertEqual(mocked.call_args.kwargs["output_file"], "summary.json")
        self.assertTrue(mocked.call_args.kwargs["require_successful_report"])
        self.assertTrue(mocked.call_args.kwargs["require_capture_attachment_report"])
        self.assertTrue(mocked.call_args.kwargs["require_physical_print_scan"])
        self.assertTrue(
            mocked.call_args.kwargs["require_real_camera_perspective_correction"]
        )
        self.assertTrue(mocked.call_args.kwargs["require_ocr_only_backend"])
        self.assertTrue(mocked.call_args.kwargs["require_profile_certified"])

    def test_qrcode_helper_certification_status_entrypoint_delegates_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "schema": certify.CERTIFICATION_STATUS_SCHEMA}
        with mock.patch.object(
            certify,
            "summarize_transport_certification_status",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.summarize_transport_certification_status(
                report_file="transport_reliability_report.json",
                verification_file=None,
                archive_file=None,
                manifest_file="manifest.json",
                output_file="status.json",
                verify_archive=True,
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertEqual(
            mocked.call_args.kwargs["report_file"],
            "transport_reliability_report.json",
        )
        self.assertIsNone(mocked.call_args.kwargs["verification_file"])
        self.assertIsNone(mocked.call_args.kwargs["archive_file"])
        self.assertEqual(mocked.call_args.kwargs["manifest_file"], "manifest.json")
        self.assertEqual(mocked.call_args.kwargs["output_file"], "status.json")
        self.assertTrue(mocked.call_args.kwargs["verify_archive"])
        self.assertIsNone(mocked.call_args.kwargs["required_certified_claims"])

    def test_qrcode_helper_certification_status_entrypoint_delegates_claim_gate(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "schema": certify.CERTIFICATION_STATUS_SCHEMA}
        with mock.patch.object(
            certify,
            "summarize_transport_certification_status",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.summarize_transport_certification_status(
                report_file="transport_reliability_report.json",
                required_certified_claims=["physical-print-scan"],
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertEqual(
            mocked.call_args.kwargs["required_certified_claims"],
            ["physical-print-scan"],
        )

    def test_qrcode_helper_certify_capture_evidence_pipeline_delegates_replay_options(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {
            "success": True,
            "schema": certify.CAPTURE_CERTIFICATION_PIPELINE_SCHEMA,
        }
        with mock.patch.object(
            certify,
            "certify_capture_evidence_pipeline",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.certify_capture_evidence_pipeline(
                capture_corpus_file="capture_corpus.json",
                output_dir="pipeline",
                capture_return_package_file="operator_return.zip",
                capture_return_package_report_file="package_report.json",
                capture_root="external_scans",
                raw_capture_root="raw_photos",
                capture_medium="print-scan",
                capture_metadata={"scanner": "delegate-flatbed"},
                require_all_case_labels=False,
                require_physical_print_scan=True,
                require_capture_provenance=True,
                capture_return_extraction_report_file="return_extract.json",
                ingestion_report_file="ingest.json",
                replay_output_dir="evidence_replay",
                replay_report_file="replay_report.json",
                replay_summary_file="replay_summary.json",
                required_certified_claims=["physical-print-scan"],
            )

        self.assertIs(result, sentinel)
        mocked.assert_called_once()
        self.assertIs(mocked.call_args.kwargs["transport"], transport)
        self.assertEqual(mocked.call_args.kwargs["capture_corpus_file"], "capture_corpus.json")
        self.assertEqual(mocked.call_args.kwargs["output_dir"], "pipeline")
        self.assertEqual(
            mocked.call_args.kwargs["capture_return_package_file"],
            "operator_return.zip",
        )
        self.assertEqual(
            mocked.call_args.kwargs["capture_return_package_report_file"],
            "package_report.json",
        )
        self.assertEqual(mocked.call_args.kwargs["capture_root"], "external_scans")
        self.assertEqual(mocked.call_args.kwargs["raw_capture_root"], "raw_photos")
        self.assertEqual(mocked.call_args.kwargs["capture_medium"], "print-scan")
        self.assertEqual(
            mocked.call_args.kwargs["capture_metadata"],
            {"scanner": "delegate-flatbed"},
        )
        self.assertFalse(mocked.call_args.kwargs["require_all_case_labels"])
        self.assertTrue(mocked.call_args.kwargs["require_physical_print_scan"])
        self.assertTrue(mocked.call_args.kwargs["require_capture_provenance"])
        self.assertEqual(
            mocked.call_args.kwargs["capture_return_extraction_report_file"],
            "return_extract.json",
        )
        self.assertEqual(mocked.call_args.kwargs["ingestion_report_file"], "ingest.json")
        self.assertEqual(mocked.call_args.kwargs["replay_output_dir"], "evidence_replay")
        self.assertEqual(mocked.call_args.kwargs["replay_report_file"], "replay_report.json")
        self.assertEqual(mocked.call_args.kwargs["replay_summary_file"], "replay_summary.json")
        self.assertEqual(
            mocked.call_args.kwargs["required_certified_claims"],
            ["physical-print-scan"],
        )

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
                corrections_file="corr.csv",
            )
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            manifest_path="m.json",
            ocr_input_path="ocr.txt",
            output_file="out.bin",
            strict_payload_chars=True,
            corrections_file="corr.csv",
        )

    def test_qrcode_helper_replay_corrections_delegates_to_transport_recover(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {"success": True, "schema": recover.CORRECTION_REPLAY_REPORT_SCHEMA}
        with mock.patch.object(
            recover,
            "replay_ocr_corrections",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.replay_ocr_corrections(
                manifest_path="m.json",
                ocr_input_path="ocr.txt",
                corrections_file="filled.csv",
                output_file="out.bin",
                report_file="report.json",
                strict_payload_chars=True,
                emit_corrections_file="retry.csv",
            )
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            manifest_path="m.json",
            ocr_input_path="ocr.txt",
            corrections_file="filled.csv",
            output_file="out.bin",
            report_file="report.json",
            strict_payload_chars=True,
            emit_corrections_file="retry.csv",
        )

    def test_qrcode_helper_verify_correction_replay_delegates_to_transport_recover(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        sentinel = {
            "success": True,
            "schema": recover.CORRECTION_REPLAY_VERIFICATION_SCHEMA,
        }
        with mock.patch.object(
            recover,
            "verify_ocr_correction_replay_report",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.verify_ocr_correction_replay_report(
                report_file="correction_replay.json",
                output_file="correction_replay_verification.json",
                require_success=False,
            )
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            report_file="correction_replay.json",
            output_file="correction_replay_verification.json",
            require_success=False,
        )

    def test_qrcode_helper_ocr_confusion_entrypoint_delegates_to_transport_recover(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer(
            payload_alphabet_profile=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE
        )
        sentinel = {"success": True, "schema": recover.OCR_SAFE_CONFUSION_REPORT_SCHEMA}
        with mock.patch.object(
            recover,
            "certify_ocr_safe_confusions",
            autospec=True,
            return_value=sentinel,
        ) as mocked:
            result = transport.certify_ocr_safe_confusions(
                output_dir="out",
                report_file="report.json",
                payload_size=128,
                seed=99,
                redundancy_copies=3,
                parity_group_size=5,
                filename_prefix="confusion_page",
            )
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            output_dir="out",
            report_file="report.json",
            payload_size=128,
            seed=99,
            redundancy_copies=3,
            parity_group_size=5,
            filename_prefix="confusion_page",
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
                corrections_file="corr.csv",
            )
        self.assertIs(result, sentinel)
        mocked.assert_called_once_with(
            transport=transport,
            manifest_path="m.json",
            ocr_input_path="ocr.txt",
            strict_payload_chars=True,
            corrections_file="corr.csv",
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
                emit_corrections_file="c.csv",
                corrections_file="filled.csv",
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
            emit_corrections_file="c.csv",
            corrections_file="filled.csv",
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
            result_main = transport._parse_ocr_chunks(
                manifest,
                "ocr.txt",
                True,
                corrections_file="filled.csv",
            )
        self.assertIs(result_main, sentinel)
        mocked_main.assert_called_once_with(
            transport=transport,
            manifest=manifest,
            ocr_input_path="ocr.txt",
            strict_payload_chars=True,
            corrections_file="filled.csv",
        )

        with mock.patch.object(
            parser,
            "parse_ocr_chunks_payload_only_manifest",
            autospec=True,
            return_value=sentinel,
        ) as mocked_payload:
            result_payload = transport._parse_ocr_chunks_payload_only_manifest(
                manifest,
                "ocr.txt",
                False,
                corrections_file="filled.csv",
            )
        self.assertIs(result_payload, sentinel)
        mocked_payload.assert_called_once_with(
            transport=transport,
            manifest=manifest,
            ocr_input_path="ocr.txt",
            strict_payload_chars=False,
            corrections_file="filled.csv",
        )

        with mock.patch.object(
            parser,
            "parse_ocr_chunks_with_total",
            autospec=True,
            return_value=sentinel,
        ) as mocked_total:
            result_total = transport._parse_ocr_chunks_with_total(
                2,
                "ocr.txt",
                True,
                line_index_mode="chunk",
                corrections_file="filled.csv",
            )
        self.assertIs(result_total, sentinel)
        mocked_total.assert_called_once_with(
            transport=transport,
            total_chunks=2,
            ocr_input_path="ocr.txt",
            strict_payload_chars=True,
            line_index_mode="chunk",
            payload_alphabet_profile=None,
            chunk_lengths=None,
            corrections_file="filled.csv",
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

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for sidecar distortion decode")
    def test_sidecar_payload_decode_survives_resize_and_affine_skew(self) -> None:
        payload = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[:24]
        bits = protocol.safe_payload_to_bits(payload)
        cols = protocol.SIDECAR_BITS_PER_ROW
        rows = 3
        left = 80
        top = 120
        cell = protocol.SIDECAR_CELL_SIZE
        gap = protocol.SIDECAR_CELL_GAP
        width = 520
        height = 280
        image = qrcode_helper.Image.new("RGB", (width, height), "white")
        draw = qrcode_helper.ImageDraw.Draw(image)
        for bit_index, bit in enumerate(bits):
            if bit != "1":
                continue
            row = bit_index // cols
            col = bit_index % cols
            cell_left = left + col * (cell + gap)
            cell_top = top + row * (cell + gap)
            draw.rectangle(
                (
                    cell_left,
                    cell_top,
                    cell_left + cell - 1,
                    cell_top + cell - 1,
                ),
                fill="black",
            )

        distorted = image.resize(
            (int(round(width * 0.9)), int(round(height * 0.9))),
            qrcode_helper.RESAMPLE_LANCZOS,
        )
        distorted = distorted.transform(
            distorted.size,
            qrcode_helper.Image.AFFINE,
            (1.0, -0.015, 20.0, 0.01, 1.0, -15.0),
            resample=qrcode_helper.Image.BICUBIC,
            fillcolor="white",
        )
        page_layout = {"page_width": width, "page_height": height}
        line_meta = {
            "binary_box": [
                left,
                top,
                left + cols * cell + (cols - 1) * gap,
                top + rows * cell + (rows - 1) * gap,
            ],
            "binary_cell": cell,
            "binary_cols": cols,
            "binary_gap": gap,
            "binary_rows": rows,
            "bit_count": len(bits),
            "chunk_index": 0,
            "expected_crc": protocol.crc16_hex("C00000|{}".format(payload)),
            "payload_len": len(payload),
        }

        result = ocr_runtime.decode_sidecar_payload(
            transport=qrcode_helper.AirgapTransportLayer(),
            image=distorted,
            page_layout=page_layout,
            line_meta=line_meta,
        )

        self.assertEqual(result, payload)

    def test_qrcode_helper_ocr_runtime_page_sidecar_helpers_delegate_to_transport_module(self) -> None:
        transport = qrcode_helper.AirgapTransportLayer()
        image = object()
        page_layout = {"lines": [{"kind": "data"}]}
        band = {"top": 1, "bottom": 9}
        entries = [{"page": 1, "line": 1, "chunk_index": 0}]
        manifest = {"chunk_lengths": [8]}
        path = qrcode_helper.Path("case_0001.png")
        reader = object()

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
            payload_alphabet_profile="safe-base32-v1",
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
