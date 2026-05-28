import json
import shutil
import subprocess
import sys
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest import mock

import qrcode_helper
from enc2sop.transport import certify


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


class TransportCertificationTests(WorkspaceTempMixin, unittest.TestCase):
    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_sidecar_report_success(self) -> None:
        root = self.make_case_root("certify_sidecar")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )

        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64, 257],
            iterations_per_size=1,
            seed=123,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            max_list=20,
        )

        report_path = root / "cert" / "transport_reliability_report.json"
        self.assertTrue(result["success"])
        self.assertEqual(result["schema"], certify.REPORT_SCHEMA)
        self.assertEqual(result["profile"], "digital-sidecar-v1")
        self.assertTrue(result["profile_certified"])
        claims = {
            item["claim"]: item
            for item in result["certification_claims"]["claims"]
        }
        self.assertEqual(
            result["certification_claims"]["schema"],
            certify.CERTIFICATION_CLAIMS_SCHEMA,
        )
        self.assertTrue(claims["generated-page-sidecar"]["certified"])
        self.assertEqual(claims["generated-page-sidecar"]["status"], "local-certified")
        self.assertFalse(claims["physical-print-scan"]["certified"])
        self.assertFalse(claims["real-camera-perspective-correction"]["certified"])
        self.assertFalse(claims["backend-specific-ocr-only"]["certified"])
        self.assertTrue(result["profile_compliance"]["passed"])
        self.assertEqual(result["summary"]["total_cases"], 2)
        self.assertEqual(result["summary"]["passed_cases"], 2)
        self.assertEqual(result["summary"]["failed_cases"], 0)
        self.assertEqual(result["summary"]["success_rate"], 1.0)
        self.assertEqual(result["summary"]["outcomes_by_reason"], {"none": 2})
        self.assertEqual(result["summary"]["failures_by_reason"], {})
        self.assertTrue(report_path.exists())

        saved = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["schema"], certify.REPORT_SCHEMA)
        self.assertEqual(len(saved["cases"]), 2)
        for case in saved["cases"]:
            self.assertTrue(case["success"])
            self.assertEqual(case["failure_reason"], "none")
            self.assertEqual(case["distortion"]["name"], "control")
            self.assertEqual(case["backend_selected"], "sidecar")
            self.assertEqual(
                case["artifact_digests"]["payload_sha256"],
                case["artifact_digests"]["restored_sha256"],
            )
            self.assertTrue(case["export"]["manifest_path"])
            self.assertGreater(case["export"]["image_count"], 0)
            self.assertGreater(case["export"]["total_chunks"], 0)
            self.assertEqual(case["export"]["redundancy_copies"], 2)
            self.assertEqual(case["export"]["parity_group_size"], 4)
            self.assertEqual(case["recovery"]["metrics"]["parity_recovered_count"], 0)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_generated_page_distortion_suite(self) -> None:
        root = self.make_case_root("certify_distortion")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )

        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260525,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            distortion_suite="generated-page-basic-v1",
            max_list=20,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["distortion_suite"]["name"], "generated-page-basic-v1")
        claims = {
            item["claim"]: item
            for item in result["certification_claims"]["claims"]
        }
        self.assertTrue(claims["generated-page-sidecar"]["certified"])
        self.assertFalse(claims["generated-page-synthetic-stress"]["certified"])
        self.assertIn(
            "generated-page-stress-v1",
            claims["generated-page-synthetic-stress"]["missing_gates"],
        )
        distortion_names = [item["name"] for item in result["distortion_suite"]["distortions"]]
        self.assertIn("control", distortion_names)
        self.assertIn("png-reencode", distortion_names)
        self.assertIn("jpeg-q95", distortion_names)
        self.assertIn("screenshot-lite", distortion_names)
        self.assertGreater(result["summary"]["total_cases"], 1)
        self.assertEqual(result["summary"]["failed_cases"], 0)
        self.assertTrue(result["thresholds"]["distortion_threshold_passed"])
        for name, threshold in result["thresholds"]["distortions"].items():
            self.assertEqual(threshold["success_rate"], 1.0, name)
            self.assertTrue(threshold["threshold_passed"], name)
        for case in result["cases"]:
            self.assertTrue(case["success"])
            self.assertIn("distortion", case)
            self.assertTrue(case["artifact_digests"]["distorted_images"])
            self.assertEqual(
                case["artifact_digests"]["payload_sha256"],
                case["artifact_digests"]["restored_sha256"],
            )

        saved = json.loads((root / "cert" / "transport_reliability_report.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["parameters"]["distortion_suite"], "generated-page-basic-v1")
        self.assertIn("distortion_success_rates", saved["summary"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_generated_page_stress_claim_boundary(self) -> None:
        root = self.make_case_root("certify_stress_claims")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )

        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            distortion_suite="generated-page-stress-v1",
            max_list=20,
        )

        self.assertTrue(result["success"])
        claims = {
            item["claim"]: item
            for item in result["certification_claims"]["claims"]
        }
        self.assertTrue(claims["generated-page-sidecar"]["certified"])
        self.assertTrue(claims["generated-page-synthetic-stress"]["certified"])
        self.assertEqual(
            claims["generated-page-synthetic-stress"]["status"],
            "synthetic-stress-certified",
        )
        self.assertIn("synthetic generated-page distortions", claims["generated-page-synthetic-stress"]["boundary"].lower())
        self.assertFalse(claims["physical-print-scan"]["certified"])
        self.assertFalse(claims["real-camera-perspective-correction"]["certified"])
        self.assertFalse(claims["backend-specific-ocr-only"]["certified"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_certification_status_summarizes_report_claim_boundaries(self) -> None:
        root = self.make_case_root("certification_status_report")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            distortion_suite="generated-page-stress-v1",
            max_list=20,
        )
        self.assertTrue(result["success"])

        status_file = root / "status" / "transport_certification_status.json"
        status = certify.summarize_transport_certification_status(
            report_file=str(root / "cert" / "transport_reliability_report.json"),
            output_file=str(status_file),
        )

        self.assertTrue(status["success"])
        self.assertEqual(status["schema"], certify.CERTIFICATION_STATUS_SCHEMA)
        self.assertEqual(status["source"]["type"], "transport_reliability_report")
        self.assertTrue(status["summary"]["production_airgap_ready"])
        self.assertFalse(status["summary"]["physical_print_scan_ready"])
        self.assertFalse(status["summary"]["real_camera_ready"])
        self.assertFalse(status["summary"]["ocr_only_ready"])
        self.assertFalse(status["summary"]["generic_ocr_fallback_ready"])
        self.assertFalse(status["claim_gate"]["required"])
        self.assertTrue(status["claim_gate"]["passed"])
        claims = {item["claim"]: item for item in status["claims"]}
        self.assertTrue(claims["generated-page-sidecar"]["certified"])
        self.assertTrue(claims["generated-page-synthetic-stress"]["certified"])
        self.assertFalse(claims["physical-print-scan"]["certified"])
        self.assertIn(
            "require_physical_print_scan",
            claims["physical-print-scan"]["missing_gates"],
        )
        self.assertTrue(status["recommended_next_steps"])
        self.assertTrue(status_file.exists())
        saved = json.loads(status_file.read_text(encoding="utf-8"))
        self.assertEqual(saved["schema"], certify.CERTIFICATION_STATUS_SCHEMA)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_certification_status_claim_gate_fails_closed(self) -> None:
        root = self.make_case_root("certification_status_claim_gate")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            distortion_suite="generated-page-stress-v1",
            max_list=20,
        )
        self.assertTrue(result["success"])

        status_file = root / "status" / "transport_certification_status.json"
        status = certify.summarize_transport_certification_status(
            report_file=str(root / "cert" / "transport_reliability_report.json"),
            output_file=str(status_file),
            required_certified_claims=[
                "generated-page-sidecar",
                "physical-print-scan",
            ],
        )

        self.assertFalse(status["success"])
        self.assertTrue(status["summary"]["production_airgap_ready"])
        self.assertFalse(status["summary"]["physical_print_scan_ready"])
        self.assertTrue(status["claim_gate"]["required"])
        self.assertFalse(status["claim_gate"]["passed"])
        self.assertEqual(
            status["claim_gate"]["required_certified_claims"],
            ["generated-page-sidecar", "physical-print-scan"],
        )
        self.assertEqual(
            status["claim_gate"]["missing_required_certified_claims"],
            ["physical-print-scan"],
        )
        self.assertEqual(
            status["summary"]["missing_required_certified_claims"],
            ["physical-print-scan"],
        )
        self.assertTrue(status_file.exists())

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_operator_capture_corpus_report(self) -> None:
        root = self.make_case_root("certify_capture_corpus")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied capture corpus payload")
        export_dir = root / "exported"
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(export_dir),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        manifest_path = Path(str(export_result["manifest_path"]))
        image_path = Path(str(export_result["images"][0]))
        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "lab",
                    "metadata": {"scanner": "fixture-copy", "dpi": 300},
                    "cases": [
                        {
                            "label": "lab-flatbed-control",
                            "manifest_path": str(manifest_path),
                            "payload_path": str(payload_path),
                            "image_path": str(image_path),
                            "capture_metadata": {
                                "device": "unit-test-export",
                                "lighting": "digital fixture",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )

        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260525,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            capture_corpus_file=str(corpus_file),
            include_generated_corpus=False,
            max_list=20,
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["capture_corpus"]["provided"])
        self.assertEqual(result["capture_corpus"]["schema"], certify.CAPTURE_CORPUS_SCHEMA)
        self.assertEqual(result["capture_corpus"]["classification"], "lab")
        self.assertEqual(result["capture_corpus"]["case_count"], 1)
        self.assertEqual(result["summary"]["total_cases"], 1)
        self.assertEqual(result["summary"]["capture_case_count"], 1)
        self.assertEqual(result["summary"]["capture_classification_counts"], {"lab": 1})
        self.assertEqual(result["summary"]["capture_success_rates_by_classification"], {"lab": 1.0})
        case = result["cases"][0]
        self.assertEqual(case["capture_corpus"]["label"], "lab-flatbed-control")
        self.assertEqual(case["capture_corpus"]["classification"], "lab")
        self.assertEqual(case["capture_corpus"]["capture_metadata"]["device"], "unit-test-export")
        self.assertTrue(case["capture_corpus"]["profile_compliance"]["passed"])
        capture_checks = {item["name"]: item for item in case["capture_corpus"]["profile_compliance"]["checks"]}
        self.assertTrue(capture_checks["sidecar_layout_required"]["passed"])
        self.assertTrue(capture_checks["line_crc_required"]["passed"])
        self.assertTrue(capture_checks["payload_sha256_required"]["passed"])
        self.assertEqual(case["distortion"]["suite"], certify.OPERATOR_CAPTURE_CORPUS_SUITE)
        self.assertEqual(case["distortion"]["name"], "lab-flatbed-control")
        self.assertEqual(case["artifact_digests"]["payload_sha256"], case["artifact_digests"]["restored_sha256"])
        self.assertEqual(case["artifact_digests"]["source_images"][0]["sha256"], case["capture_corpus"]["source_images"][0]["sha256"])
        self.assertEqual(result["summary"]["capture_profile_certified_counts"], {"lab": 1})
        self.assertFalse(case["capture_corpus"]["reference_transform"]["reference_images_provided"])

        saved = json.loads((root / "cert" / "transport_reliability_report.json").read_text(encoding="utf-8"))
        self.assertFalse(saved["parameters"]["include_generated_corpus"])
        self.assertEqual(saved["parameters"]["capture_corpus_classification"], "lab")

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_capture_corpus_required_classification_and_distinct_gate(self) -> None:
        root = self.make_case_root("certify_capture_corpus_distinct")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied distinct capture corpus payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        source_page = Path(str(export_result["images"][0]))
        capture_dir = root / "captures" / "lab-distinct"
        capture_dir.mkdir(parents=True)
        capture_page = capture_dir / source_page.name
        shutil.copy2(str(source_page), str(capture_page))
        with capture_page.open("ab") as handle:
            handle.write(b"\n# lab capture fixture marker\n")
        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "lab",
                    "cases": [
                        {
                            "label": "lab-distinct",
                            "manifest_path": str(export_result["manifest_path"]),
                            "payload_path": str(payload_path),
                            "image_path": str(capture_dir),
                            "reference_image_paths": [str(source_page)],
                            "capture_metadata": {"scanner": "unit-test-distinct"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = source_transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            include_generated_corpus=False,
            require_distinct_capture_images=True,
            capture_required_classification="lab",
            capture_required_success_rate=1.0,
            max_list=20,
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["thresholds"]["capture_required_classification_passed"])
        self.assertTrue(result["thresholds"]["distinct_capture_images_passed"])
        self.assertTrue(result["thresholds"]["capture_threshold_passed"])
        self.assertEqual(result["summary"]["capture_strict_distinct_counts"], {"lab": 1})
        case = result["cases"][0]
        transform = case["capture_corpus"]["reference_transform"]
        self.assertTrue(transform["reference_images_provided"])
        self.assertTrue(transform["distinct_from_reference"])
        self.assertEqual(transform["byte_identical_match_count"], 0)
        self.assertEqual(transform["status"], "distinct-from-reference")

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_capture_corpus_distinct_gate_rejects_fixture_copy(self) -> None:
        root = self.make_case_root("certify_capture_corpus_fixture_copy")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied fixture-copy capture corpus payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        source_page = Path(str(export_result["images"][0]))
        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "lab",
                    "cases": [
                        {
                            "label": "lab-fixture-copy",
                            "manifest_path": str(export_result["manifest_path"]),
                            "payload_path": str(payload_path),
                            "image_path": str(source_page.parent),
                            "reference_image_paths": [str(source_page)],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = source_transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            include_generated_corpus=False,
            require_distinct_capture_images=True,
            capture_required_classification="lab",
            max_list=20,
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["summary"]["failures_by_reason"], {"capture_reference_not_distinct": 1})
        self.assertFalse(result["thresholds"]["distinct_capture_images_passed"])
        case = result["cases"][0]
        self.assertEqual(case["failure_reason"], "capture_reference_not_distinct")
        transform = case["capture_corpus"]["reference_transform"]
        self.assertTrue(transform["reference_images_provided"])
        self.assertFalse(transform["strict_gate_passed"])
        self.assertEqual(transform["byte_identical_match_count"], 1)
        self.assertEqual(transform["status"], "byte-identical-to-reference")

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_physical_print_scan_gate_success(self) -> None:
        root = self.make_case_root("certify_print_scan_success")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied physical print scan payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        source_pages = [Path(str(path)) for path in export_result["images"]]
        scan_dir = root / "captures" / "flatbed-scan"
        scan_dir.mkdir(parents=True)
        for source_page in source_pages:
            scan_page = scan_dir / source_page.name
            shutil.copy2(str(source_page), str(scan_page))
            with scan_page.open("ab") as handle:
                handle.write(b"\n# simulated physical print-scan fixture marker\n")

        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "lab",
                    "cases": [
                        {
                            "label": "lab-flatbed-print-scan",
                            "classification": "lab",
                            "capture_medium": "print-scan",
                            "manifest_path": str(export_result["manifest_path"]),
                            "payload_path": str(payload_path),
                            "image_path": str(scan_dir),
                            "reference_image_paths": [str(path) for path in source_pages],
                            "capture_metadata": {
                                "printer": "unit-test-printer",
                                "scanner": "unit-test-flatbed",
                                "dpi": 300,
                                "capture_session_id": "unit-test-print-session",
                                "operator": "unit-test-operator",
                                "captured_at_utc": "2026-05-28T12:00:00Z",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        attachment = source_transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])

        result = source_transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            capture_attachment_report_file=str(attachment["report_file"]),
            include_generated_corpus=False,
            require_distinct_capture_images=True,
            require_physical_print_scan=True,
            require_capture_attachment_report=True,
            require_capture_provenance=True,
            capture_required_classification="lab",
            capture_required_success_rate=1.0,
            max_list=20,
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["thresholds"]["physical_print_scan_required"])
        self.assertTrue(result["thresholds"]["physical_print_scan_passed"])
        self.assertEqual(result["summary"]["capture_medium_counts"], {"print-scan": 1})
        self.assertEqual(
            result["summary"]["capture_physical_print_scan_evidence_counts"],
            {"lab": 1},
        )
        case = result["cases"][0]
        evidence = case["capture_corpus"]["physical_print_scan_evidence"]
        self.assertTrue(evidence["evidence_passed"])
        self.assertEqual(evidence["status"], "physical-print-scan")
        self.assertEqual(evidence["capture_medium"], "print-scan")
        checks = {item["name"]: item for item in evidence["checks"]}
        self.assertTrue(checks["printer_metadata_present"]["passed"])
        self.assertTrue(checks["scanner_metadata_present"]["passed"])
        self.assertTrue(checks["scan_dpi_metadata_present"]["passed"])
        provenance = case["capture_corpus"]["capture_provenance_evidence"]
        self.assertTrue(provenance["evidence_passed"])
        self.assertEqual(provenance["session_id"], "unit-test-print-session")
        self.assertEqual(provenance["operator"], "unit-test-operator")
        self.assertEqual(provenance["device"], "unit-test-flatbed")
        self.assertTrue(result["thresholds"]["capture_provenance_required"])
        self.assertTrue(result["thresholds"]["capture_provenance_passed"])
        claims = {
            item["claim"]: item
            for item in result["certification_claims"]["claims"]
        }
        self.assertTrue(claims["physical-print-scan"]["certified"])
        self.assertEqual(claims["physical-print-scan"]["status"], "lab-certified")
        self.assertEqual(claims["physical-print-scan"]["evidence_level"], "lab")
        self.assertIn(
            "other scanner/printer combinations",
            claims["physical-print-scan"]["boundary"],
        )
        self.assertIn("capture_provenance_passed", claims["physical-print-scan"]["passed_gates"])
        self.assertFalse(claims["real-camera-perspective-correction"]["certified"])
        self.assertFalse(claims["backend-specific-ocr-only"]["certified"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_physical_print_scan_gate_fails_without_scan_contract(self) -> None:
        root = self.make_case_root("certify_print_scan_missing")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied missing print scan payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        source_page = Path(str(export_result["images"][0]))
        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "lab",
                    "cases": [
                        {
                            "label": "lab-fixture-copy-no-print-scan-metadata",
                            "classification": "lab",
                            "manifest_path": str(export_result["manifest_path"]),
                            "payload_path": str(payload_path),
                            "image_path": str(source_page.parent),
                            "reference_image_paths": [str(source_page)],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = source_transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            include_generated_corpus=False,
            require_physical_print_scan=True,
            capture_required_classification="lab",
            max_list=20,
        )

        self.assertFalse(result["success"])
        self.assertFalse(result["thresholds"]["physical_print_scan_passed"])
        self.assertEqual(
            result["summary"]["failures_by_reason"],
            {"capture_print_scan_evidence_missing": 1},
        )
        case = result["cases"][0]
        self.assertEqual(case["failure_reason"], "capture_print_scan_evidence_missing")
        evidence = case["capture_corpus"]["physical_print_scan_evidence"]
        self.assertFalse(evidence["evidence_passed"])
        checks = {item["name"]: item for item in evidence["checks"]}
        self.assertFalse(checks["capture_medium_print_scan"]["passed"])
        self.assertFalse(checks["scan_distinct_from_reference"]["passed"])
        self.assertFalse(checks["printer_metadata_present"]["passed"])
        self.assertFalse(checks["scanner_metadata_present"]["passed"])
        self.assertFalse(checks["scan_dpi_metadata_present"]["passed"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_capture_provenance_gate_fails_closed(self) -> None:
        root = self.make_case_root("certify_capture_provenance_missing")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied provenance gated payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        source_page = Path(str(export_result["images"][0]))
        scan_dir = root / "captures" / "flatbed-scan"
        scan_dir.mkdir(parents=True)
        scan_page = scan_dir / source_page.name
        shutil.copy2(str(source_page), str(scan_page))
        with scan_page.open("ab") as handle:
            handle.write(b"\n# simulated provenance missing fixture marker\n")

        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "lab",
                    "cases": [
                        {
                            "label": "lab-print-scan-without-provenance",
                            "classification": "lab",
                            "capture_medium": "print-scan",
                            "manifest_path": str(export_result["manifest_path"]),
                            "payload_path": str(payload_path),
                            "image_path": str(scan_dir),
                            "reference_image_paths": [str(source_page)],
                            "capture_metadata": {
                                "printer": "unit-test-printer",
                                "scanner": "unit-test-flatbed",
                                "dpi": 300,
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        attachment = source_transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])

        result = source_transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            capture_attachment_report_file=str(attachment["report_file"]),
            include_generated_corpus=False,
            require_distinct_capture_images=True,
            require_physical_print_scan=True,
            require_capture_attachment_report=True,
            require_capture_provenance=True,
            capture_required_classification="lab",
            capture_required_success_rate=1.0,
            max_list=20,
        )

        self.assertFalse(result["success"])
        self.assertFalse(result["thresholds"]["capture_provenance_passed"])
        self.assertEqual(
            result["summary"]["failures_by_reason"],
            {"capture_provenance_missing": 1},
        )
        case = result["cases"][0]
        self.assertEqual(case["failure_reason"], "capture_provenance_missing")
        provenance = case["capture_corpus"]["capture_provenance_evidence"]
        self.assertFalse(provenance["evidence_passed"])
        checks = {item["name"]: item for item in provenance["checks"]}
        self.assertFalse(checks["capture_session_id_present"]["passed"])
        self.assertFalse(checks["operator_present"]["passed"])
        self.assertFalse(checks["captured_at_present"]["passed"])
        self.assertTrue(checks["capture_device_present"]["passed"])
        claims = {item["claim"]: item for item in result["certification_claims"]["claims"]}
        self.assertFalse(claims["physical-print-scan"]["certified"])
        self.assertIn("capture_provenance_passed", claims["physical-print-scan"]["missing_gates"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_real_camera_perspective_evidence_gate(self) -> None:
        root = self.make_case_root("certify_capture_perspective")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied real camera perspective corpus payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        source_pages = [Path(str(path)) for path in export_result["images"]]
        raw_dir = root / "camera_raw"
        corrected_dir = root / "captures" / "real-corrected"
        raw_dir.mkdir(parents=True)
        corrected_dir.mkdir(parents=True)
        for page in source_pages:
            raw_page = raw_dir / page.name
            corrected_page = corrected_dir / page.name
            shutil.copy2(str(page), str(raw_page))
            shutil.copy2(str(page), str(corrected_page))
            with raw_page.open("ab") as handle:
                handle.write(b"\n# simulated raw camera fixture marker\n")
            with corrected_page.open("ab") as handle:
                handle.write(b"\n# simulated perspective corrected fixture marker\n")

        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "real",
                    "cases": [
                        {
                            "label": "real-camera-perspective-fixture",
                            "classification": "real",
                            "capture_medium": "camera-photo",
                            "manifest_path": str(export_result["manifest_path"]),
                            "payload_path": str(payload_path),
                            "image_path": str(corrected_dir),
                            "raw_image_paths": str(raw_dir),
                            "reference_image_paths": [str(path) for path in source_pages],
                            "capture_metadata": {
                                "device": "unit-test-camera",
                                "environment": "synthetic contract fixture",
                                "capture_session_id": "unit-test-camera-session",
                                "operator": "unit-test-operator",
                                "captured_at_utc": "2026-05-28T12:30:00Z",
                            },
                            "perspective_correction": {
                                "applied": True,
                                "method": "unit-test-fixture-copy-with-distinct-bytes",
                                "tool": "test harness",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        attachment = source_transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_raw_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])

        result = source_transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            capture_attachment_report_file=str(attachment["report_file"]),
            include_generated_corpus=False,
            require_distinct_capture_images=True,
            require_real_camera_perspective_correction=True,
            require_capture_attachment_report=True,
            require_capture_provenance=True,
            capture_required_classification="real",
            capture_required_success_rate=1.0,
            max_list=20,
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["thresholds"]["real_camera_perspective_correction_required"])
        self.assertTrue(result["thresholds"]["real_camera_perspective_correction_passed"])
        self.assertEqual(
            result["summary"]["capture_real_camera_perspective_evidence_counts"],
            {"real": 1},
        )
        case = result["cases"][0]
        evidence = case["capture_corpus"]["perspective_correction_evidence"]
        self.assertTrue(evidence["evidence_passed"])
        self.assertEqual(evidence["status"], "real-camera-perspective-correction")
        self.assertEqual(evidence["raw_image_count"], len(source_pages))
        self.assertEqual(evidence["corrected_image_count"], len(source_pages))
        self.assertTrue(evidence["raw_distinct_from_corrected"])
        self.assertEqual(evidence["raw_corrected_byte_identical_match_count"], 0)
        provenance = case["capture_corpus"]["capture_provenance_evidence"]
        self.assertTrue(provenance["evidence_passed"])
        self.assertEqual(provenance["session_id"], "unit-test-camera-session")
        self.assertEqual(provenance["device"], "unit-test-camera")
        claims = {
            item["claim"]: item
            for item in result["certification_claims"]["claims"]
        }
        self.assertTrue(claims["real-camera-perspective-correction"]["certified"])
        self.assertEqual(claims["real-camera-perspective-correction"]["status"], "real-certified")
        self.assertIn(
            "synthetic perspective-skew distortion",
            claims["real-camera-perspective-correction"]["boundary"].lower(),
        )
        self.assertIn(
            "capture_provenance_passed",
            claims["real-camera-perspective-correction"]["passed_gates"],
        )
        self.assertFalse(claims["physical-print-scan"]["certified"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_real_camera_perspective_gate_fails_without_raw_evidence(self) -> None:
        root = self.make_case_root("certify_capture_perspective_missing")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied missing perspective corpus payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        source_page = Path(str(export_result["images"][0]))
        capture_dir = root / "captures" / "real-missing"
        capture_dir.mkdir(parents=True)
        capture_page = capture_dir / source_page.name
        shutil.copy2(str(source_page), str(capture_page))
        with capture_page.open("ab") as handle:
            handle.write(b"\n# corrected-only fixture marker\n")
        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "real",
                    "cases": [
                        {
                            "label": "real-camera-missing-raw",
                            "classification": "real",
                            "manifest_path": str(export_result["manifest_path"]),
                            "payload_path": str(payload_path),
                            "image_path": str(capture_dir),
                            "reference_image_paths": [str(source_page)],
                            "perspective_correction": {
                                "applied": True,
                                "method": "unit-test-corrected-only",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        result = source_transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            include_generated_corpus=False,
            require_real_camera_perspective_correction=True,
            capture_required_classification="real",
            max_list=20,
        )

        self.assertFalse(result["success"])
        self.assertFalse(result["thresholds"]["real_camera_perspective_correction_passed"])
        self.assertEqual(result["summary"]["failures_by_reason"], {"capture_perspective_evidence_missing": 1})
        case = result["cases"][0]
        self.assertEqual(case["failure_reason"], "capture_perspective_evidence_missing")
        checks = {
            item["name"]: item
            for item in case["capture_corpus"]["perspective_correction_evidence"]["checks"]
        }
        self.assertFalse(checks["raw_camera_images_present"]["passed"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_ocr_only_backend_gate_success(self) -> None:
        root = self.make_case_root("certify_ocr_only_success")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=False,
        )

        def fake_recover(_self, manifest_path, image_input_path, output_file, backend="tesseract", **_kwargs):
            output_path = Path(output_file)
            payload_path = next(path for path in output_path.parents if (path / "payload.bin").exists()) / "payload.bin"
            payload = payload_path.read_bytes()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(payload)
            return {
                "success": True,
                "artifact_id": "OCR_ONLY_TEST",
                "output_file": str(output_path),
                "raw_size": len(payload),
                "raw_sha256": qrcode_helper._sha256_hex(payload),
                "backend_selected": backend,
                "backend_mode": backend,
                "ocr": {
                    "backend": backend,
                    "image_count": len(list(Path(image_input_path).glob("*.png"))),
                    "ocr_text_output": str(output_path.with_suffix(".txt")),
                    "structured_layout_used": True,
                },
                "analyze": {
                    "missing_chunks_count": 0,
                    "line_error_count": 0,
                    "line_warning_count": 0,
                    "page_crc_error_count": 0,
                    "duplicate_conflict_count": 0,
                    "parity_recovered_count": 0,
                    "package_hash_resolved_count": 0,
                    "report_path": None,
                    "missing_file_path": None,
                },
            }

        with mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "recover_from_images",
            autospec=True,
            side_effect=fake_recover,
        ):
            result = transport.certify_reliability(
                output_dir=str(root / "cert"),
                payload_sizes=[64],
                iterations_per_size=1,
                seed=20260526,
                backend="tesseract",
                redundancy_copies=2,
                parity_group_size=4,
                require_ocr_only_backend=True,
                ocr_only_required_success_rate=1.0,
                max_list=20,
            )

        self.assertTrue(result["success"])
        self.assertFalse(result["profile_certified"])
        self.assertTrue(result["ocr_only_certification"]["required"])
        self.assertFalse(result["ocr_only_certification"]["production_certified"])
        self.assertEqual(result["summary"]["ocr_only_backend_counts"], {"tesseract": 1})
        self.assertEqual(result["summary"]["ocr_only_success_rates_by_backend"], {"tesseract": 1.0})
        self.assertTrue(result["thresholds"]["ocr_only_threshold_passed"])
        self.assertTrue(result["thresholds"]["ocr_only_backends"]["tesseract"]["threshold_passed"])
        claims = {
            item["claim"]: item
            for item in result["certification_claims"]["claims"]
        }
        self.assertTrue(claims["backend-specific-ocr-only"]["certified"])
        self.assertEqual(claims["backend-specific-ocr-only"]["status"], "backend-measured")
        self.assertEqual(
            claims["backend-specific-ocr-only"]["evidence_level"],
            "backend-specific",
        )
        self.assertFalse(claims["generated-page-sidecar"]["certified"])
        case = result["cases"][0]
        evidence = case["ocr_only_evidence"]
        self.assertTrue(evidence["evidence_passed"])
        self.assertFalse(evidence["binary_sidecar_present"])
        self.assertFalse(evidence["export_sidecar_enabled"])
        checks = {item["name"]: item for item in evidence["checks"]}
        self.assertTrue(checks["backend_is_ocr_only"]["passed"])
        self.assertTrue(checks["binary_sidecar_absent"]["passed"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_ocr_only_gate_rejects_sidecar_layout(self) -> None:
        root = self.make_case_root("certify_ocr_only_sidecar_reject")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )

        def fake_recover(_self, manifest_path, image_input_path, output_file, backend="tesseract", **_kwargs):
            output_path = Path(output_file)
            payload_path = next(path for path in output_path.parents if (path / "payload.bin").exists()) / "payload.bin"
            payload = payload_path.read_bytes()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(payload)
            return {
                "success": True,
                "artifact_id": "OCR_ONLY_SIDECAR_TEST",
                "output_file": str(output_path),
                "raw_size": len(payload),
                "raw_sha256": qrcode_helper._sha256_hex(payload),
                "backend_selected": backend,
                "backend_mode": backend,
                "ocr": {
                    "backend": backend,
                    "image_count": len(list(Path(image_input_path).glob("*.png"))),
                    "structured_layout_used": True,
                },
                "analyze": {
                    "missing_chunks_count": 0,
                    "line_error_count": 0,
                    "line_warning_count": 0,
                    "page_crc_error_count": 0,
                    "duplicate_conflict_count": 0,
                    "parity_recovered_count": 0,
                    "package_hash_resolved_count": 0,
                },
            }

        with mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "recover_from_images",
            autospec=True,
            side_effect=fake_recover,
        ):
            result = transport.certify_reliability(
                output_dir=str(root / "cert"),
                payload_sizes=[64],
                iterations_per_size=1,
                seed=20260526,
                backend="tesseract",
                redundancy_copies=2,
                parity_group_size=4,
                require_ocr_only_backend=True,
                max_list=20,
            )

        self.assertFalse(result["success"])
        self.assertEqual(result["summary"]["failures_by_reason"], {"ocr_only_evidence_missing": 1})
        self.assertFalse(result["thresholds"]["ocr_only_threshold_passed"])
        case = result["cases"][0]
        evidence = case["ocr_only_evidence"]
        self.assertFalse(evidence["evidence_passed"])
        self.assertTrue(evidence["binary_sidecar_present"])
        checks = {item["name"]: item for item in evidence["checks"]}
        self.assertFalse(checks["binary_sidecar_absent"]["passed"])
        self.assertFalse(checks["export_sidecar_disabled"]["passed"])

    def test_certify_reliability_ocr_only_gate_requires_ocr_backend(self) -> None:
        root = self.make_case_root("certify_ocr_only_requires_backend")
        transport = qrcode_helper.AirgapTransportLayer()

        with self.assertRaisesRegex(ValueError, "require_ocr_only_backend requires backend"):
            transport.certify_reliability(
                output_dir=str(root / "cert"),
                payload_sizes=[64],
                backend="sidecar",
                require_ocr_only_backend=True,
            )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_prepare_capture_corpus_kit_stages_ocr_only_backend_contract(self) -> None:
        root = self.make_case_root("prepare_ocr_only_capture_corpus")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )

        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={"scanner": "unit-test-flatbed", "dpi": 300},
            case_label_prefix="ocr-only-flatbed",
            ocr_only_backend="tesseract",
        )

        self.assertTrue(kit["success"])
        self.assertEqual(kit["profile"], "ocr-only-backend-v1")
        self.assertEqual(kit["parameters"]["ocr_only_backend"], "tesseract")
        self.assertTrue(transport.render_sidecar)
        kit_dir = root / "kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        self.assertEqual(corpus["metadata"]["ocr_only_backend"], "tesseract")
        corpus_case = corpus["cases"][0]
        self.assertEqual(corpus_case["ocr_only_backend"], "tesseract")
        manifest = json.loads((kit_dir / corpus_case["manifest_path"]).read_text(encoding="utf-8"))
        self.assertFalse(manifest["sidecar_enabled"])
        self.assertFalse(certify._manifest_has_binary_sidecar(manifest))
        self.assertIn(
            "--require-ocr-only-backend",
            (kit_dir / "instructions" / "NEXT_STEPS.md").read_text(encoding="utf-8"),
        )

        capture_dir = kit_dir / corpus_case["image_path"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        capture_page = capture_dir / "operator-ocr-only.png"
        shutil.copy2(str(source_page), str(capture_page))
        with capture_page.open("ab") as handle:
            handle.write(b"\n# ocr-only fixture marker\n")
        attachment = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])

        validation = transport.validate_capture_corpus(
            capture_corpus_file=str(corpus_file),
            profile="ocr-only-backend-v1",
            backend="tesseract",
            require_captures=True,
            require_distinct_capture_images=True,
            capture_attachment_report_file=str(attachment["report_file"]),
            require_capture_attachment_report=True,
            capture_required_classification="lab",
            require_ocr_only_backend=True,
        )

        self.assertTrue(validation["success"])
        self.assertEqual(validation["summary"]["ocr_only_ready_case_count"], 1)
        case = validation["cases"][0]
        self.assertTrue(case["ocr_only_evidence"]["evidence_passed"])
        self.assertFalse(case["ocr_only_evidence"]["binary_sidecar_present"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_validate_capture_corpus_ocr_only_gate_rejects_sidecar_manifest(self) -> None:
        root = self.make_case_root("validate_ocr_only_rejects_sidecar")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
        )
        kit_dir = root / "kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        corpus_case = corpus["cases"][0]
        capture_dir = kit_dir / corpus_case["image_path"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        capture_page = capture_dir / "operator-sidecar.png"
        shutil.copy2(str(source_page), str(capture_page))
        with capture_page.open("ab") as handle:
            handle.write(b"\n# sidecar fixture marker\n")

        report = transport.validate_capture_corpus(
            capture_corpus_file=str(corpus_file),
            profile="ocr-only-backend-v1",
            backend="tesseract",
            require_captures=True,
            require_ocr_only_backend=True,
        )

        self.assertFalse(report["success"])
        self.assertEqual(report["summary"]["failures_by_reason"], {"ocr_only_evidence_missing": 1})
        case = report["cases"][0]
        self.assertFalse(case["ocr_only_evidence"]["strict_gate_passed"])
        self.assertTrue(case["ocr_only_evidence"]["binary_sidecar_present"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_prepare_capture_corpus_kit_can_be_filled_and_certified(self) -> None:
        root = self.make_case_root("prepare_capture_corpus")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )

        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260526,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={"scanner": "unit-test-flatbed", "dpi": 300},
            case_label_prefix="flatbed-300dpi",
        )

        kit_dir = root / "kit"
        self.assertTrue(kit["success"])
        self.assertEqual(kit["schema"], certify.CAPTURE_KIT_SCHEMA)
        self.assertEqual(kit["classification"], "lab")
        self.assertEqual(kit["capture_medium"], "print-scan")
        self.assertEqual(kit["summary"]["case_count"], 1)
        self.assertEqual(kit["summary"]["operator_captures_present"], 0)
        corpus_file = Path(str(kit["corpus_file"]))
        instructions_file = Path(str(kit["instructions_file"]))
        self.assertTrue(corpus_file.exists())
        self.assertTrue(instructions_file.exists())

        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        self.assertEqual(corpus["schema"], certify.CAPTURE_CORPUS_SCHEMA)
        self.assertEqual(corpus["classification"], "lab")
        self.assertEqual(corpus["capture_medium"], "print-scan")
        self.assertEqual(corpus["metadata"]["payload_sizes"], [64])
        self.assertEqual(corpus["metadata"]["capture_medium"], "print-scan")
        self.assertEqual(corpus["metadata"]["capture_metadata_defaults"]["scanner"], "unit-test-flatbed")
        corpus_case = corpus["cases"][0]
        self.assertEqual(corpus_case["capture_medium"], "print-scan")
        self.assertEqual(corpus_case["capture_metadata"]["scanner"], "unit-test-flatbed")
        capture_dir = kit_dir / corpus_case["image_path"]
        self.assertTrue(capture_dir.is_dir())
        self.assertEqual(
            [path.name for path in capture_dir.iterdir() if path.suffix.lower() in certify.CAPTURE_IMAGE_SUFFIXES],
            [],
        )

        kit_case = kit["cases"][0]
        for source in kit_case["kit_source"]["generated_page_images"]:
            source_path = kit_dir / source["path"]
            shutil.copy2(str(source_path), str(capture_dir / source_path.name))

        certified = transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            include_generated_corpus=False,
            max_list=20,
        )

        self.assertTrue(certified["success"])
        self.assertEqual(certified["summary"]["capture_case_count"], 1)
        self.assertEqual(certified["summary"]["capture_success_rates_by_classification"], {"lab": 1.0})
        certified_case = certified["cases"][0]
        self.assertEqual(certified_case["capture_corpus"]["label"], corpus_case["label"])
        self.assertEqual(certified_case["capture_corpus"]["capture_metadata"]["scanner"], "unit-test-flatbed")
        self.assertEqual(
            certified_case["artifact_digests"]["payload_sha256"],
            certified_case["artifact_digests"]["restored_sha256"],
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_attach_capture_corpus_binds_operator_files_and_updates_kit(self) -> None:
        root = self.make_case_root("attach_capture_corpus")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260526,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={"scanner": "unit-test-flatbed", "dpi": 300},
            case_label_prefix="attach-flatbed",
        )
        kit_dir = root / "kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        corpus_case = corpus["cases"][0]
        capture_dir = kit_dir / corpus_case["image_path"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        capture_page = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_page), str(capture_page))
        with capture_page.open("ab") as handle:
            handle.write(b"\n# attached capture marker\n")

        report = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            kit_manifest_file=str(kit_dir / "capture_kit_manifest.json"),
            require_captures=True,
            require_distinct_capture_images=True,
        )

        self.assertTrue(report["success"])
        self.assertEqual(report["schema"], certify.CAPTURE_ATTACHMENT_REPORT_SCHEMA)
        self.assertEqual(report["summary"]["case_count"], 1)
        self.assertEqual(report["summary"]["cases_with_attached_captures"], 1)
        self.assertEqual(report["summary"]["attached_capture_image_count"], 1)
        self.assertEqual(report["summary"]["distinct_capture_case_count"], 1)
        self.assertEqual(report["summary"]["failures_by_reason"], {})
        attached_case = report["cases"][0]
        self.assertTrue(attached_case["ready_for_certification"])
        self.assertEqual(
            Path(attached_case["attached_images"][0]["path"]),
            Path("captures") / corpus_case["label"] / "operator-scan.png",
        )
        self.assertTrue(Path(str(report["report_file"])).exists())

        refreshed_corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        refreshed_case = refreshed_corpus["cases"][0]
        self.assertEqual(refreshed_case["attached_capture_image_count"], 1)
        self.assertTrue(refreshed_case["capture_attachment"]["ready_for_certification"])
        self.assertEqual(
            refreshed_corpus["metadata"]["last_capture_attachment"]["attached_capture_image_count"],
            1,
        )
        refreshed_kit = json.loads((kit_dir / "capture_kit_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(refreshed_kit["summary"]["operator_captures_present"], 1)
        self.assertEqual(refreshed_kit["summary"]["operator_capture_image_count"], 1)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_capture_corpus_binds_attachment_report_lineage(self) -> None:
        root = self.make_case_root("certify_capture_attachment_lineage")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={"printer": "unit-test-printer", "scanner": "unit-test-flatbed", "dpi": 300},
            case_label_prefix="attach-lineage",
        )
        kit_dir = root / "kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        corpus_case = corpus["cases"][0]
        capture_dir = kit_dir / corpus_case["image_path"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        capture_page = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_page), str(capture_page))
        with capture_page.open("ab") as handle:
            handle.write(b"\n# attachment lineage marker\n")

        attachment = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            kit_manifest_file=str(kit_dir / "capture_kit_manifest.json"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])

        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            capture_attachment_report_file=str(attachment["report_file"]),
            include_generated_corpus=False,
            require_capture_attachment_report=True,
            require_distinct_capture_images=True,
            capture_required_classification="lab",
            capture_required_success_rate=1.0,
            max_list=20,
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["thresholds"]["capture_attachment_report_required"])
        self.assertTrue(result["thresholds"]["capture_attachment_report_passed"])
        self.assertEqual(result["summary"]["capture_attachment_report_evidence_counts"], {"lab": 1})
        case = result["cases"][0]
        evidence = case["capture_corpus"]["attachment_report_evidence"]
        self.assertTrue(evidence["strict_gate_passed"])
        self.assertEqual(evidence["status"], "capture-attachment-bound")
        self.assertEqual(evidence["attached_image_comparison"]["matching_count"], 1)
        self.assertEqual(
            evidence["report_sha256"],
            certify._sha256_file(Path(str(attachment["report_file"]))),
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_capture_corpus_attachment_report_gate_fails_on_drift(self) -> None:
        root = self.make_case_root("certify_capture_attachment_drift")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={"printer": "unit-test-printer", "scanner": "unit-test-flatbed", "dpi": 300},
        )
        kit_dir = root / "kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        corpus_case = corpus["cases"][0]
        capture_dir = kit_dir / corpus_case["image_path"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        capture_page = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_page), str(capture_page))
        with capture_page.open("ab") as handle:
            handle.write(b"\n# original attachment marker\n")
        attachment = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])
        with capture_page.open("ab") as handle:
            handle.write(b"\n# drift after attachment report\n")

        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            capture_attachment_report_file=str(attachment["report_file"]),
            include_generated_corpus=False,
            require_capture_attachment_report=True,
            require_distinct_capture_images=True,
            capture_required_classification="lab",
            max_list=20,
        )

        self.assertFalse(result["success"])
        self.assertFalse(result["thresholds"]["capture_attachment_report_passed"])
        self.assertEqual(
            result["summary"]["failures_by_reason"],
            {"capture_attachment_report_mismatch": 1},
        )
        evidence = result["cases"][0]["capture_corpus"]["attachment_report_evidence"]
        self.assertFalse(evidence["strict_gate_passed"])
        self.assertFalse(evidence["attached_image_comparison"]["exact_match"])
        self.assertEqual(evidence["attached_image_comparison"]["matching_count"], 0)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_prepare_and_attach_camera_capture_corpus_stages_raw_dirs(self) -> None:
        root = self.make_case_root("attach_camera_capture_corpus")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "camera_kit"),
            classification="real",
            capture_medium="camera-photo",
            include_raw_capture_dirs=True,
            perspective_correction_method="unit-test homography correction",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            case_label_prefix="camera-perspective",
        )
        kit_dir = root / "camera_kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        corpus_case = corpus["cases"][0]
        capture_dir = kit_dir / corpus_case["image_path"]
        raw_capture_dir = kit_dir / corpus_case["raw_image_paths"]
        self.assertTrue(raw_capture_dir.is_dir())
        self.assertEqual(corpus_case["capture_medium"], "camera-photo")
        self.assertTrue(corpus_case["perspective_correction"]["applied"])
        self.assertEqual(
            corpus_case["perspective_correction"]["method"],
            "unit-test homography correction",
        )

        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        corrected_page = capture_dir / "corrected-camera.png"
        raw_page = raw_capture_dir / "raw-camera.png"
        shutil.copy2(str(source_page), str(corrected_page))
        shutil.copy2(str(source_page), str(raw_page))
        with corrected_page.open("ab") as handle:
            handle.write(b"\n# corrected perspective fixture marker\n")
        with raw_page.open("ab") as handle:
            handle.write(b"\n# raw perspective fixture marker\n")

        report = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            kit_manifest_file=str(kit_dir / "capture_kit_manifest.json"),
            require_captures=True,
            require_raw_captures=True,
            require_distinct_capture_images=True,
        )

        self.assertTrue(report["success"])
        self.assertEqual(report["summary"]["cases_with_attached_captures"], 1)
        self.assertEqual(report["summary"]["cases_with_raw_captures"], 1)
        self.assertEqual(report["summary"]["raw_capture_image_count"], 1)
        self.assertEqual(report["summary"]["failures_by_reason"], {})
        self.assertEqual(report["cases"][0]["raw_image_count"], 1)
        refreshed_corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        refreshed_case = refreshed_corpus["cases"][0]
        self.assertEqual(refreshed_case["capture_attachment"]["raw_image_count"], 1)
        refreshed_kit = json.loads((kit_dir / "capture_kit_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(refreshed_kit["summary"]["raw_capture_directories_ready"], 1)
        self.assertEqual(refreshed_kit["summary"]["operator_raw_captures_present"], 1)
        self.assertEqual(refreshed_kit["summary"]["operator_raw_capture_image_count"], 1)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_attach_capture_corpus_fails_closed_when_required_raw_captures_missing(self) -> None:
        root = self.make_case_root("attach_camera_raw_missing")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "camera_kit"),
            classification="real",
            capture_medium="camera-photo",
            include_raw_capture_dirs=True,
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
        )
        kit_dir = root / "camera_kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        capture_dir = kit_dir / corpus["cases"][0]["image_path"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        capture_page = capture_dir / "corrected-camera.png"
        shutil.copy2(str(source_page), str(capture_page))
        with capture_page.open("ab") as handle:
            handle.write(b"\n# corrected perspective fixture marker\n")

        report = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_raw_captures=True,
            require_distinct_capture_images=True,
        )

        self.assertFalse(report["success"])
        self.assertEqual(report["summary"]["cases_missing_raw_captures"], 1)
        self.assertEqual(report["summary"]["failures_by_reason"], {"raw_capture_images_missing": 1})
        self.assertEqual(report["cases"][0]["failure_reasons"], ["raw_capture_images_missing"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_correct_capture_perspective_materializes_corrected_images_for_camera_kit(self) -> None:
        root = self.make_case_root("correct_camera_perspective")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "camera_kit"),
            classification="real",
            capture_medium="camera-photo",
            include_raw_capture_dirs=True,
            perspective_correction_method="operator correction pending",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            case_label_prefix="camera-correct",
        )
        kit_dir = root / "camera_kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        raw_dir = kit_dir / corpus["cases"][0]["raw_image_paths"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        raw_page = raw_dir / "raw-camera.png"
        shutil.copy2(str(source_page), str(raw_page))
        with raw_page.open("ab") as handle:
            handle.write(b"\n# raw camera fixture marker\n")

        report = transport.correct_capture_perspective(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "corrected"),
            kit_manifest_file=str(kit_dir / "capture_kit_manifest.json"),
            method="unit-test homography correction",
            mode="copy",
            require_raw_captures=True,
        )

        self.assertTrue(report["success"])
        self.assertEqual(
            report["schema"],
            certify.CAPTURE_PERSPECTIVE_CORRECTION_REPORT_SCHEMA,
        )
        self.assertEqual(report["summary"]["raw_capture_case_count"], 1)
        self.assertEqual(report["summary"]["corrected_case_count"], 1)
        self.assertEqual(report["summary"]["corrected_image_count"], 1)
        self.assertEqual(report["summary"]["failures_by_reason"], {})
        case = report["cases"][0]
        self.assertTrue(case["raw_images"])
        self.assertTrue(case["corrected_images"])
        self.assertEqual(
            case["raw_images"][0]["sha256"],
            case["corrected_images"][0]["sha256"],
        )
        self.assertIn(
            "not recovery certification",
            report["certification_boundary"],
        )

        refreshed_corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        refreshed_case = refreshed_corpus["cases"][0]
        corrected_dir = kit_dir / refreshed_case["image_path"]
        self.assertTrue(corrected_dir.is_dir())
        self.assertEqual(
            refreshed_case["perspective_correction"]["method"],
            "unit-test homography correction",
        )
        self.assertEqual(
            refreshed_case["perspective_correction"]["correction_report_file"],
            str(Path(str(report["output_dir"])) / "transport_capture_perspective_correction_report.json"),
        )
        refreshed_kit = json.loads((kit_dir / "capture_kit_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(
            refreshed_kit["last_perspective_correction"]["schema"],
            certify.CAPTURE_PERSPECTIVE_CORRECTION_REPORT_SCHEMA,
        )
        self.assertEqual(
            refreshed_kit["summary"]["operator_corrected_capture_image_count"],
            1,
        )

        attachment = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_raw_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])
        self.assertEqual(attachment["summary"]["cases_with_raw_captures"], 1)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_correct_capture_perspective_fails_closed_when_raw_images_missing(self) -> None:
        root = self.make_case_root("correct_camera_missing_raw")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "camera_kit"),
            classification="real",
            capture_medium="camera-photo",
            include_raw_capture_dirs=True,
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
        )

        report = transport.correct_capture_perspective(
            capture_corpus_file=str(kit["corpus_file"]),
            output_dir=str(root / "corrected"),
            require_raw_captures=True,
        )

        self.assertFalse(report["success"])
        self.assertEqual(report["summary"]["corrected_case_count"], 0)
        self.assertEqual(
            report["summary"]["failures_by_reason"],
            {"raw_capture_images_missing": 1},
        )
        self.assertEqual(report["cases"][0]["failure_reasons"], ["raw_capture_images_missing"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_correct_capture_perspective_four_point_requires_source_corners(self) -> None:
        root = self.make_case_root("correct_camera_four_point_missing_corners")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "camera_kit"),
            classification="real",
            capture_medium="camera-photo",
            include_raw_capture_dirs=True,
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
        )
        kit_dir = root / "camera_kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        raw_dir = kit_dir / corpus["cases"][0]["raw_image_paths"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        raw_page = raw_dir / "raw-camera.png"
        shutil.copy2(str(source_page), str(raw_page))

        report = transport.correct_capture_perspective(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "corrected"),
            mode="four-point",
            require_raw_captures=True,
        )

        self.assertFalse(report["success"])
        self.assertEqual(report["summary"]["raw_capture_case_count"], 1)
        self.assertEqual(report["summary"]["corrected_case_count"], 0)
        self.assertEqual(
            report["summary"]["failures_by_reason"],
            {"perspective_correction_corners_missing": 1},
        )
        self.assertEqual(
            report["cases"][0]["failure_reasons"],
            ["perspective_correction_corners_missing"],
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_archive_transport_evidence_includes_perspective_correction_report(self) -> None:
        root = self.make_case_root("archive_camera_correction_report")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "camera_kit"),
            classification="real",
            capture_medium="camera-photo",
            include_raw_capture_dirs=True,
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            case_label_prefix="camera-archive",
        )
        kit_dir = root / "camera_kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        raw_dir = kit_dir / corpus["cases"][0]["raw_image_paths"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        raw_page = raw_dir / "raw-camera.png"
        shutil.copy2(str(source_page), str(raw_page))
        with raw_page.open("ab") as handle:
            handle.write(b"\n# raw camera fixture marker\n")
        correction = transport.correct_capture_perspective(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "corrected"),
            kit_manifest_file=str(kit_dir / "capture_kit_manifest.json"),
            mode="copy",
            require_raw_captures=True,
        )
        self.assertTrue(correction["success"])
        attachment = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_raw_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])
        report = transport.certify_reliability(
            output_dir=str(root / "cert"),
            profile="reliable-airgap-v1",
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            capture_corpus_file=str(corpus_file),
            include_generated_corpus=False,
            capture_required_classification="real",
            require_distinct_capture_images=True,
            capture_attachment_report_file=str(attachment["report_file"]),
            require_capture_attachment_report=True,
            max_list=20,
        )
        self.assertTrue(report["success"])

        archive = certify.archive_transport_evidence(
            report_file=str(root / "cert" / "transport_reliability_report.json"),
            output_dir=str(root / "archive"),
            require_successful_report=True,
            require_profile_certified=True,
            require_capture_attachment_report=True,
        )

        roles = archive["summary"]["roles"]
        self.assertEqual(roles["capture_perspective_correction_report"], 1)
        verification = certify.verify_transport_evidence_archive(
            archive_file=str(archive["archive_file"]),
            manifest_file=str(archive["manifest_file"]),
            require_successful_report=True,
            require_profile_certified=True,
            require_capture_attachment_report=True,
        )
        self.assertTrue(verification["success"])
        self.assertEqual(
            verification["summary"]["roles_verified"]["capture_perspective_correction_report"],
            1,
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_attach_capture_corpus_accepts_workspace_relative_kit_manifest_path(self) -> None:
        root = self.make_case_root("attach_capture_corpus_relative_manifest")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260526,
            redundancy_copies=2,
            parity_group_size=4,
        )
        corpus_file = Path(str(kit["corpus_file"]))
        kit_manifest_path = Path(str(kit["output_dir"])) / "capture_kit_manifest.json"
        kit_manifest_relative = kit_manifest_path.relative_to(TEST_ROOT)

        report = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            kit_manifest_file=str(kit_manifest_relative),
            require_captures=False,
        )

        self.assertTrue(Path(str(report["report_file"])).exists())
        refreshed_kit = json.loads(kit_manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(refreshed_kit["summary"]["operator_captures_present"], 0)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_attach_capture_corpus_fails_closed_when_required_captures_missing(self) -> None:
        root = self.make_case_root("attach_capture_corpus_missing")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260526,
            redundancy_copies=2,
            parity_group_size=4,
        )

        report = transport.attach_capture_corpus(
            capture_corpus_file=str(kit["corpus_file"]),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )

        self.assertFalse(report["success"])
        self.assertEqual(report["summary"]["cases_missing_attached_captures"], 1)
        self.assertEqual(
            report["summary"]["failures_by_reason"],
            {"capture_images_missing": 1, "capture_reference_not_distinct": 1},
        )
        self.assertEqual(
            report["cases"][0]["failure_reasons"],
            ["capture_images_missing", "capture_reference_not_distinct"],
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_validate_capture_corpus_preflights_bound_print_scan_corpus(self) -> None:
        root = self.make_case_root("validate_capture_corpus_ready")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-flatbed",
                "dpi": 300,
            },
            case_label_prefix="validate-flatbed",
        )
        kit_dir = root / "kit"
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        corpus_case = corpus["cases"][0]
        capture_dir = kit_dir / corpus_case["image_path"]
        source_page = kit_dir / kit["cases"][0]["kit_source"]["generated_page_images"][0]["path"]
        capture_page = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_page), str(capture_page))
        with capture_page.open("ab") as handle:
            handle.write(b"\n# validation fixture marker\n")
        attachment = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])
        output_file = root / "validate" / "transport_capture_validation_report.json"

        report = transport.validate_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_file=str(output_file),
            profile="reliable-airgap-v1",
            backend="sidecar",
            require_captures=True,
            require_distinct_capture_images=True,
            capture_attachment_report_file=str(attachment["report_file"]),
            require_capture_attachment_report=True,
            capture_required_classification="lab",
            require_physical_print_scan=True,
        )

        self.assertTrue(report["success"])
        self.assertEqual(report["schema"], certify.CAPTURE_VALIDATION_REPORT_SCHEMA)
        self.assertTrue(output_file.exists())
        self.assertEqual(report["summary"]["ready_case_count"], 1)
        self.assertEqual(report["summary"]["failures_by_reason"], {})
        case = report["cases"][0]
        self.assertTrue(case["ready_for_certification"])
        self.assertTrue(case["profile_compliance"]["passed"])
        self.assertTrue(case["reference_transform"]["distinct_from_reference"])
        self.assertEqual(
            case["attachment_report_evidence"]["status"],
            "capture-attachment-bound",
        )
        self.assertEqual(
            case["physical_print_scan_evidence"]["status"],
            "physical-print-scan",
        )
        self.assertIn("preflight validation", report["certification_boundary"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_validate_capture_corpus_fails_closed_on_missing_required_captures(self) -> None:
        root = self.make_case_root("validate_capture_corpus_missing")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="real",
            capture_medium="camera-photo",
            include_raw_capture_dirs=True,
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
        )

        report = transport.validate_capture_corpus(
            capture_corpus_file=str(kit["corpus_file"]),
            profile="reliable-airgap-v1",
            backend="sidecar",
            require_captures=True,
            require_raw_captures=True,
            require_distinct_capture_images=True,
            require_capture_attachment_report=True,
            capture_required_classification="real",
            require_real_camera_perspective_correction=True,
        )

        self.assertFalse(report["success"])
        self.assertEqual(report["summary"]["ready_case_count"], 0)
        self.assertEqual(report["summary"]["cases_missing_attached_captures"], 1)
        self.assertEqual(report["summary"]["cases_missing_raw_captures"], 1)
        self.assertEqual(
            report["summary"]["failures_by_reason"],
            {
                "capture_images_missing": 1,
                "raw_capture_images_missing": 1,
                "capture_reference_not_distinct": 1,
                "capture_attachment_report_mismatch": 1,
                "capture_perspective_evidence_missing": 1,
            },
        )
        case = report["cases"][0]
        self.assertFalse(case["ready_for_certification"])
        self.assertEqual(
            case["attachment_report_evidence"]["status"],
            "missing-attachment-report",
        )
        self.assertEqual(
            case["perspective_correction_evidence"]["status"],
            "missing-raw_camera_images_present",
        )

    def test_certify_reliability_capture_corpus_requires_classification(self) -> None:
        root = self.make_case_root("certify_capture_corpus_invalid")
        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps({"schema": certify.CAPTURE_CORPUS_SCHEMA, "cases": []}),
            encoding="utf-8",
        )
        transport = qrcode_helper.AirgapTransportLayer()

        with self.assertRaisesRegex(ValueError, "capture corpus classification"):
            transport.certify_reliability(
                output_dir=str(root / "cert"),
                payload_sizes=[64],
                capture_corpus_file=str(corpus_file),
                include_generated_corpus=False,
            )

    def test_certify_reliability_real_camera_perspective_gate_requires_capture_corpus(self) -> None:
        root = self.make_case_root("certify_perspective_no_corpus")
        transport = qrcode_helper.AirgapTransportLayer()

        with self.assertRaisesRegex(
            ValueError,
            "require_real_camera_perspective_correction requires a capture_corpus_file",
        ):
            transport.certify_reliability(
                output_dir=str(root / "cert"),
                require_real_camera_perspective_correction=True,
            )

    def test_certify_reliability_physical_print_scan_gate_requires_capture_corpus(self) -> None:
        root = self.make_case_root("certify_print_scan_no_corpus")
        transport = qrcode_helper.AirgapTransportLayer()

        with self.assertRaisesRegex(
            ValueError,
            "require_physical_print_scan requires a capture_corpus_file",
        ):
            transport.certify_reliability(
                output_dir=str(root / "cert"),
                require_physical_print_scan=True,
            )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_capture_corpus_accepts_utf8_bom_manifest(self) -> None:
        root = self.make_case_root("certify_capture_corpus_bom")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied bom capture corpus payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        corpus_file = root / "capture_corpus.json"
        corpus_payload = json.dumps(
            {
                "schema": certify.CAPTURE_CORPUS_SCHEMA,
                "classification": "lab",
                "cases": [
                    {
                        "label": "bom-corpus",
                        "manifest_path": str(export_result["manifest_path"]),
                        "payload_path": str(payload_path),
                        "image_path": str(Path(str(export_result["images"][0])).parent),
                    }
                ],
            }
        )
        corpus_file.write_text("\ufeff" + corpus_payload, encoding="utf-8")

        result = source_transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            capture_corpus_file=str(corpus_file),
            include_generated_corpus=False,
            max_list=20,
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["capture_corpus"]["classification"], "lab")

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_capture_corpus_fails_closed_on_weak_manifest(self) -> None:
        root = self.make_case_root("certify_capture_corpus_weak_manifest")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"operator supplied weak capture corpus payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        weak_manifest_path = root / "weak.manifest.json"
        manifest = json.loads(Path(str(export_result["manifest_path"])).read_text(encoding="utf-8"))
        manifest.pop("raw_sha256", None)
        manifest["transport_line_crc"] = "off"
        weak_manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "lab",
                    "cases": [
                        {
                            "label": "weak-manifest",
                            "manifest_path": str(weak_manifest_path),
                            "payload_path": str(payload_path),
                            "image_path": str(Path(str(export_result["images"][0])).parent),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        result = source_transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            capture_corpus_file=str(corpus_file),
            include_generated_corpus=False,
            max_list=20,
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["summary"]["failures_by_reason"], {"capture_profile_not_certified": 1})
        case = result["cases"][0]
        self.assertEqual(case["failure_reason"], "capture_profile_not_certified")
        checks = {item["name"]: item for item in case["capture_corpus"]["profile_compliance"]["checks"]}
        self.assertFalse(checks["payload_sha256_required"]["passed"])
        self.assertFalse(checks["line_crc_required"]["passed"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_categorizes_unrecoverable_case(self) -> None:
        root = self.make_case_root("certify_fail")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )

        with mock.patch.object(
            qrcode_helper.AirgapTransportLayer,
            "recover_from_images",
            autospec=True,
            return_value={"success": False, "message": "forced failure"},
        ):
            result = transport.certify_reliability(
                output_dir=str(root / "cert"),
                payload_sizes=[64],
                iterations_per_size=1,
                seed=321,
                backend="sidecar",
                redundancy_copies=2,
                parity_group_size=4,
            )

        self.assertFalse(result["success"])
        self.assertEqual(result["summary"]["total_cases"], 1)
        self.assertEqual(result["summary"]["failed_cases"], 1)
        self.assertEqual(result["summary"]["failures_by_reason"], {"recover_failed": 1})
        self.assertEqual(result["cases"][0]["failure_reason"], "recover_failed")

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_reliable_airgap_profile_success(self) -> None:
        root = self.make_case_root("certify_reliable_airgap")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )

        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64, 257],
            iterations_per_size=1,
            seed=20260525,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            max_list=20,
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["profile_certified"])
        self.assertEqual(result["profile"], "reliable-airgap-v1")
        self.assertTrue(result["profile_compliance"]["passed"])
        self.assertTrue(result["profile_compliance"]["strict_profile"])
        checks = {item["name"]: item for item in result["profile_compliance"]["checks"]}
        self.assertTrue(checks["sidecar_backend_required"]["passed"])
        self.assertTrue(checks["render_sidecar_required"]["passed"])
        self.assertTrue(checks["line_crc_required"]["passed"])
        self.assertTrue(checks["loss_recovery_required"]["passed"])

    def test_certify_reliability_reliable_airgap_rejects_unsafe_profile(self) -> None:
        root = self.make_case_root("certify_reliable_airgap_reject")
        transport = qrcode_helper.AirgapTransportLayer(
            render_sidecar=False,
            line_crc_mode="off",
            metadata_level="none",
            line_index_mode="off",
        )

        with self.assertRaisesRegex(ValueError, "reliable-airgap-v1 profile rejected unsafe settings"):
            transport.certify_reliability(
                output_dir=str(root / "cert"),
                payload_sizes=[64],
                iterations_per_size=1,
                backend="tesseract",
                redundancy_copies=1,
                parity_group_size=0,
                profile="reliable-airgap-v1",
            )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_reliability_unsafe_override_runs_but_is_not_certified(self) -> None:
        root = self.make_case_root("certify_reliable_airgap_override")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )

        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260525,
            backend="sidecar",
            redundancy_copies=1,
            parity_group_size=0,
            profile="reliable-airgap-v1",
            allow_unsafe_profile=True,
            max_list=20,
        )

        self.assertTrue(result["success"])
        self.assertFalse(result["profile_certified"])
        self.assertFalse(result["profile_compliance"]["passed"])
        self.assertTrue(result["profile_compliance"]["unsafe_override_accepted"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_certify_command_writes_report(self) -> None:
        root = self.make_case_root("certify_cli")
        output_dir = root / "cert"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "certify",
            "-o",
            str(output_dir),
            "--payload-size",
            "64",
            "--iterations-per-size",
            "1",
            "--seed",
            "77",
            "--backend",
            "sidecar",
            "--chunk-chars",
            "24",
            "--lines-per-page",
            "8",
            "--redundancy-copies",
            "2",
            "--parity-group-size",
            "4",
            "--distortion-suite",
            "generated-page-basic-v1",
            "--max-list",
            "20",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        report_path = output_dir / "transport_reliability_report.json"
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["schema"], certify.REPORT_SCHEMA)
        self.assertEqual(stdout["distortion_suite"]["name"], "generated-page-basic-v1")
        self.assertTrue(report_path.exists())
        saved = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertGreater(saved["summary"]["total_cases"], 1)
        self.assertEqual(saved["summary"]["failed_cases"], 0)
        self.assertEqual(saved["parameters"]["distortion_suite"], "generated-page-basic-v1")

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_certify_capture_corpus_only(self) -> None:
        root = self.make_case_root("certify_cli_capture_corpus")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"cli capture corpus payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "lab",
                    "cases": [
                        {
                            "label": "cli-lab-control",
                            "manifest_path": str(export_result["manifest_path"]),
                            "payload_path": str(payload_path),
                            "image_path": str(Path(str(export_result["images"][0])).parent),
                            "capture_metadata": {"device": "unit-test-cli"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        output_dir = root / "cert"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "certify",
            "-o",
            str(output_dir),
            "--profile",
            "reliable-airgap-v1",
            "--payload-size",
            "64",
            "--backend",
            "sidecar",
            "--chunk-chars",
            "24",
            "--lines-per-page",
            "8",
            "--redundancy-copies",
            "2",
            "--parity-group-size",
            "4",
            "--capture-corpus-file",
            str(corpus_file),
            "--capture-corpus-only",
            "--capture-required-classification",
            "lab",
            "--capture-required-success-rate",
            "1.0",
            "--max-list",
            "20",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["capture_corpus"]["classification"], "lab")
        self.assertEqual(stdout["summary"]["capture_case_count"], 1)
        self.assertFalse(stdout["parameters"]["include_generated_corpus"])
        self.assertEqual(stdout["thresholds"]["capture_required_classification"], "lab")
        self.assertTrue(stdout["thresholds"]["capture_required_classification_passed"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_certify_requires_capture_provenance(self) -> None:
        root = self.make_case_root("certify_cli_capture_provenance")
        source_transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        payload_path = root / "payload.bin"
        payload_path.write_bytes(b"cli capture provenance payload")
        export_result = source_transport.export_artifact(
            input_file=str(payload_path),
            output_dir=str(root / "exported"),
            filename_prefix="capture",
            redundancy_copies=2,
            parity_group_size=4,
        )
        source_page = Path(str(export_result["images"][0]))
        capture_dir = root / "captures"
        capture_dir.mkdir(parents=True)
        capture_file = capture_dir / source_page.name
        shutil.copy2(str(source_page), str(capture_file))
        with capture_file.open("ab") as handle:
            handle.write(b"\n# cli provenance marker\n")
        corpus_file = root / "capture_corpus.json"
        corpus_file.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_CORPUS_SCHEMA,
                    "classification": "lab",
                    "cases": [
                        {
                            "label": "cli-lab-provenance",
                            "classification": "lab",
                            "capture_medium": "print-scan",
                            "manifest_path": str(export_result["manifest_path"]),
                            "payload_path": str(payload_path),
                            "image_path": str(capture_dir),
                            "reference_image_paths": [str(source_page)],
                            "capture_metadata": {
                                "printer": "cli-printer",
                                "scanner": "cli-flatbed",
                                "dpi": 300,
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        attachment = source_transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_file),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])
        output_dir = root / "cert"
        completed = subprocess.run(
            [
                sys.executable,
                "qrcode_helper.py",
                "certify",
                "-o",
                str(output_dir),
                "--profile",
                "reliable-airgap-v1",
                "--backend",
                "sidecar",
                "--chunk-chars",
                "24",
                "--lines-per-page",
                "8",
                "--redundancy-copies",
                "2",
                "--parity-group-size",
                "4",
                "--capture-corpus-file",
                str(corpus_file),
                "--capture-corpus-only",
                "--capture-attachment-report-file",
                str(attachment["report_file"]),
                "--require-capture-attachment-report",
                "--require-distinct-capture-images",
                "--require-physical-print-scan",
                "--require-capture-provenance",
                "--capture-required-classification",
                "lab",
                "--max-list",
                "20",
            ],
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)
        stdout = json.loads(completed.stdout)
        self.assertFalse(stdout["success"])
        self.assertEqual(stdout["summary"]["failures_by_reason"], {"capture_provenance_missing": 1})
        self.assertTrue(stdout["thresholds"]["capture_provenance_required"])
        self.assertFalse(stdout["thresholds"]["capture_provenance_passed"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_validate_capture_corpus_command_writes_report(self) -> None:
        root = self.make_case_root("validate_capture_cli")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-scanner",
                "dpi": "300",
                "capture_session_id": "pipeline-print-session",
                "operator": "pipeline-operator",
                "captured_at_utc": "2026-05-28T13:00:00Z",
            },
        )
        corpus_path = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        capture_dir = corpus_path.parent / case["image_path"]
        source_image = corpus_path.parent / case["reference_image_paths"][0]
        capture_image = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_image), str(capture_image))
        with capture_image.open("ab") as handle:
            handle.write(b"\n# cli validation marker\n")
        attachment = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_path),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        output_file = root / "validation" / "transport_capture_validation_report.json"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "validate-capture-corpus",
            "--capture-corpus-file",
            str(corpus_path),
            "--output-file",
            str(output_file),
            "--profile",
            "reliable-airgap-v1",
            "--backend",
            "sidecar",
            "--require-captures",
            "--require-distinct-capture-images",
            "--capture-attachment-report-file",
            str(attachment["report_file"]),
            "--require-capture-attachment-report",
            "--capture-required-classification",
            "lab",
            "--require-physical-print-scan",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["schema"], certify.CAPTURE_VALIDATION_REPORT_SCHEMA)
        self.assertEqual(stdout["summary"]["ready_case_count"], 1)
        self.assertEqual(stdout["summary"]["failures_by_reason"], {})
        self.assertTrue(output_file.exists())

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_archive_transport_evidence_packages_report_corpus_attachment_and_artifacts(self) -> None:
        root = self.make_case_root("archive_transport_evidence")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-scanner",
                "dpi": "300",
                "capture_session_id": "pipeline-print-session",
                "operator": "pipeline-operator",
                "captured_at_utc": "2026-05-28T13:00:00Z",
            },
        )
        corpus_path = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        capture_dir = corpus_path.parent / case["image_path"]
        capture_dir.mkdir(parents=True, exist_ok=True)
        source_image = corpus_path.parent / case["reference_image_paths"][0]
        capture_image = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_image), str(capture_image))
        with capture_image.open("ab") as handle:
            handle.write(b"\n# archive evidence distinct capture marker\n")

        attachment_report = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_path),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment_report["success"])

        cert_report = transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            capture_corpus_file=str(corpus_path),
            include_generated_corpus=False,
            require_distinct_capture_images=True,
            require_physical_print_scan=True,
            require_capture_attachment_report=True,
            redundancy_copies=2,
            parity_group_size=4,
            max_list=20,
        )
        self.assertTrue(cert_report["success"])

        archive_manifest = certify.archive_transport_evidence(
            report_file=str(root / "cert" / "transport_reliability_report.json"),
            output_dir=str(root / "archive"),
            require_successful_report=True,
            require_capture_attachment_report=True,
            require_physical_print_scan=True,
            require_profile_certified=True,
        )

        self.assertTrue(archive_manifest["success"])
        self.assertEqual(archive_manifest["schema"], certify.CAPTURE_EVIDENCE_ARCHIVE_SCHEMA)
        self.assertTrue(archive_manifest["certification_gates"]["physical_print_scan_passed"])
        self.assertTrue(archive_manifest["certification_gates"]["capture_attachment_report_passed"])
        archived_claims = archive_manifest["certification_gates"]["certification_claims"]
        self.assertEqual(archived_claims["schema"], certify.CERTIFICATION_CLAIMS_SCHEMA)
        archived_claim_map = {
            item["claim"]: item
            for item in archived_claims["claims"]
        }
        self.assertTrue(archived_claim_map["physical-print-scan"]["certified"])
        self.assertEqual(archived_claim_map["physical-print-scan"]["status"], "lab-certified")
        self.assertGreaterEqual(archive_manifest["summary"]["file_count"], 6)
        roles = archive_manifest["summary"]["roles"]
        self.assertEqual(roles["transport_reliability_report"], 1)
        self.assertEqual(roles["capture_corpus"], 1)
        self.assertEqual(roles["capture_attachment_report"], 1)
        self.assertGreaterEqual(roles["capture_image"], 1)
        archive_path = Path(str(archive_manifest["archive_file"]))
        manifest_path = Path(str(archive_manifest["manifest_file"]))
        self.assertTrue(archive_path.exists())
        self.assertTrue(manifest_path.exists())
        embedded_manifest_payload = None
        with zipfile.ZipFile(str(archive_path), "r") as archive:
            names = set(archive.namelist())
            embedded_manifest_payload = archive.read(
                "transport_capture_evidence_archive_manifest.json"
            ).decode("utf-8")
        self.assertIn("transport_capture_evidence_archive_manifest.json", names)
        self.assertEqual(
            qrcode_helper._sha256_hex(embedded_manifest_payload.encode("utf-8")),
            archive_manifest["embedded_manifest_sha256"],
        )
        for file_record in archive_manifest["files"]:
            self.assertIn(file_record["archive_path"], names)

        verification = certify.verify_transport_evidence_archive(
            archive_file=str(archive_path),
            manifest_file=str(manifest_path),
            require_successful_report=True,
            require_capture_attachment_report=True,
            require_physical_print_scan=True,
            require_profile_certified=True,
        )
        self.assertTrue(verification["success"])
        self.assertEqual(
            verification["schema"],
            certify.CAPTURE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA,
        )
        self.assertEqual(verification["summary"]["failure_count"], 0)
        self.assertEqual(
            verification["certification_claims"],
            archive_manifest["certification_gates"]["certification_claims"],
        )
        self.assertEqual(
            verification["summary"]["file_count_verified"],
            archive_manifest["summary"]["file_count"],
        )
        self.assertTrue(verification["checks"]["archive_entries_exact_match"])
        self.assertTrue(verification["checks"]["file_digests_verified"])
        self.assertTrue(verification["checks"]["certification_gates_verified"])

        verification_file = root / "archive" / "transport_archive_verification.json"
        verification_with_file = certify.verify_transport_evidence_archive(
            archive_file=str(archive_path),
            manifest_file=str(manifest_path),
            output_file=str(verification_file),
            require_successful_report=True,
            require_capture_attachment_report=True,
            require_physical_print_scan=True,
            require_profile_certified=True,
        )
        self.assertTrue(verification_with_file["success"])

        status = certify.summarize_transport_certification_status(
            verification_file=str(verification_file),
        )
        self.assertTrue(status["success"])
        self.assertEqual(status["source"]["type"], "transport_evidence_archive_verification")
        self.assertTrue(status["source"]["archive_verified"])
        self.assertTrue(status["summary"]["production_airgap_ready"])
        self.assertTrue(status["summary"]["physical_print_scan_ready"])
        self.assertFalse(status["summary"]["real_camera_ready"])
        claims = {item["claim"]: item for item in status["claims"]}
        self.assertTrue(claims["physical-print-scan"]["certified"])
        self.assertEqual(claims["physical-print-scan"]["evidence_level"], "lab")

        replay = transport.replay_transport_evidence_archive(
            archive_file=str(archive_path),
            manifest_file=str(manifest_path),
            output_dir=str(root / "replay_archive"),
            require_successful_report=True,
            require_capture_attachment_report=True,
            require_physical_print_scan=True,
            require_profile_certified=True,
        )
        self.assertTrue(replay["success"])
        self.assertEqual(
            replay["schema"],
            certify.CAPTURE_EVIDENCE_ARCHIVE_REPLAY_SCHEMA,
        )
        self.assertTrue(replay["summary"]["archive_verified"])
        self.assertTrue(replay["summary"]["replay_executed"])
        self.assertTrue(replay["summary"]["replay_success"])
        self.assertEqual(replay["comparison"]["mismatch_count"], 0)
        self.assertTrue(replay["comparison"]["exact_match"])
        self.assertTrue(Path(str(replay["replay_report_file"])).exists())

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_verify_transport_evidence_archive_fails_on_tampered_member(self) -> None:
        root = self.make_case_root("verify_archive_tamper")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            max_list=20,
        )
        self.assertTrue(result["success"])
        archive_manifest = certify.archive_transport_evidence(
            report_file=str(root / "cert" / "transport_reliability_report.json"),
            output_dir=str(root / "archive"),
            require_successful_report=True,
        )
        archive_path = Path(str(archive_manifest["archive_file"]))
        tampered_archive = root / "archive" / "tampered_transport_capture_evidence_archive.zip"
        shutil.copy2(str(archive_path), str(tampered_archive))

        with zipfile.ZipFile(str(tampered_archive), "a", compression=zipfile.ZIP_DEFLATED) as archive:
            report_member = next(
                item["archive_path"]
                for item in archive_manifest["files"]
                if item["role"] == "transport_reliability_report"
            )
            archive.writestr(report_member, b'{"schema":"tampered"}')

        verification = certify.verify_transport_evidence_archive(
            archive_file=str(tampered_archive),
            require_successful_report=True,
        )

        self.assertFalse(verification["success"])
        codes = {failure["code"] for failure in verification["failures"]}
        self.assertIn("duplicate_archive_member", codes)
        self.assertIn("external_archive_sha256_mismatch", codes)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_verify_transport_evidence_archive_fails_on_claim_snapshot_drift(self) -> None:
        root = self.make_case_root("verify_archive_claim_drift")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            max_list=20,
        )
        self.assertTrue(result["success"])
        archive_manifest = certify.archive_transport_evidence(
            report_file=str(root / "cert" / "transport_reliability_report.json"),
            output_dir=str(root / "archive"),
            require_successful_report=True,
        )
        archive_path = Path(str(archive_manifest["archive_file"]))
        tampered_archive = root / "archive" / "tampered_claims_archive.zip"
        shutil.copy2(str(archive_path), str(tampered_archive))

        with zipfile.ZipFile(str(archive_path), "r") as source:
            entries = {name: source.read(name) for name in source.namelist()}
        embedded_name = "transport_capture_evidence_archive_manifest.json"
        manifest = json.loads(entries[embedded_name].decode("utf-8"))
        manifest["certification_gates"]["certification_claims"]["claims"][0]["certified"] = False
        entries[embedded_name] = json.dumps(
            manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        with zipfile.ZipFile(str(tampered_archive), "w", compression=zipfile.ZIP_DEFLATED) as target:
            for name, payload in entries.items():
                target.writestr(name, payload)

        verification = certify.verify_transport_evidence_archive(
            archive_file=str(tampered_archive),
            require_successful_report=True,
        )

        self.assertFalse(verification["success"])
        codes = {failure["code"] for failure in verification["failures"]}
        self.assertIn("transport_claims_gate_mismatch", codes)

    def test_archive_transport_evidence_fails_when_success_required_for_failed_report(self) -> None:
        root = self.make_case_root("archive_failed_report")
        report_path = root / "transport_reliability_report.json"
        report_path.write_text(
            json.dumps(
                {
                    "schema": certify.REPORT_SCHEMA,
                    "success": False,
                    "thresholds": {},
                    "summary": {},
                    "cases": [],
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "transport reliability report did not pass"):
            certify.archive_transport_evidence(
                report_file=str(report_path),
                output_dir=str(root / "archive"),
                require_successful_report=True,
            )

    def test_archive_transport_evidence_fails_when_required_gate_missing(self) -> None:
        root = self.make_case_root("archive_missing_gate")
        report_path = root / "transport_reliability_report.json"
        report_path.write_text(
            json.dumps(
                {
                    "schema": certify.REPORT_SCHEMA,
                    "success": True,
                    "profile": "reliable-airgap-v1",
                    "profile_certified": True,
                    "thresholds": {
                        "capture_attachment_report_required": True,
                        "capture_attachment_report_passed": True,
                        "physical_print_scan_required": False,
                        "physical_print_scan_passed": False,
                    },
                    "summary": {},
                    "capture_corpus": {},
                    "cases": [],
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "physical print-scan gate"):
            certify.archive_transport_evidence(
                report_file=str(report_path),
                output_dir=str(root / "archive"),
                require_successful_report=True,
                require_physical_print_scan=True,
            )

    def test_archive_transport_evidence_fails_when_required_claim_not_certified(self) -> None:
        root = self.make_case_root("archive_missing_claim")
        report_path = root / "transport_reliability_report.json"
        report_path.write_text(
            json.dumps(
                {
                    "schema": certify.REPORT_SCHEMA,
                    "success": True,
                    "profile": "reliable-airgap-v1",
                    "profile_certified": True,
                    "thresholds": {
                        "capture_attachment_report_required": True,
                        "capture_attachment_report_passed": True,
                        "physical_print_scan_required": True,
                        "physical_print_scan_passed": True,
                    },
                    "certification_claims": {
                        "schema": certify.CERTIFICATION_CLAIMS_SCHEMA,
                        "claims": [
                            {
                                "claim": "physical-print-scan",
                                "certified": False,
                                "status": "not-certified",
                            }
                        ],
                    },
                    "summary": {},
                    "capture_corpus": {},
                    "cases": [],
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "physical-print-scan is not certified"):
            certify.archive_transport_evidence(
                report_file=str(report_path),
                output_dir=str(root / "archive"),
                require_successful_report=True,
                require_physical_print_scan=True,
            )

    def test_archive_transport_evidence_fails_when_profile_certified_required(self) -> None:
        root = self.make_case_root("archive_missing_profile_cert")
        report_path = root / "transport_reliability_report.json"
        report_path.write_text(
            json.dumps(
                {
                    "schema": certify.REPORT_SCHEMA,
                    "success": True,
                    "profile": "reliable-airgap-v1",
                    "profile_certified": False,
                    "thresholds": {},
                    "summary": {},
                    "capture_corpus": {},
                    "cases": [],
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "not profile-certified"):
            certify.archive_transport_evidence(
                report_file=str(report_path),
                output_dir=str(root / "archive"),
                require_successful_report=True,
                require_profile_certified=True,
            )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_capture_evidence_pipeline_runs_gated_print_scan_chain(self) -> None:
        root = self.make_case_root("capture_evidence_pipeline_print_scan")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-scanner",
                "dpi": "300",
                "capture_session_id": "pipeline-ingest-print-session",
                "operator": "pipeline-ingest-operator",
                "captured_at_utc": "2026-05-28T13:30:00Z",
            },
        )
        corpus_path = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        capture_dir = corpus_path.parent / case["image_path"]
        capture_dir.mkdir(parents=True, exist_ok=True)
        source_image = corpus_path.parent / case["reference_image_paths"][0]
        capture_image = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_image), str(capture_image))
        with capture_image.open("ab") as handle:
            handle.write(b"\n# capture evidence pipeline marker\n")

        pipeline = transport.certify_capture_evidence_pipeline(
            capture_corpus_file=str(corpus_path),
            output_dir=str(root / "pipeline"),
            profile="reliable-airgap-v1",
            backend="sidecar",
            require_physical_print_scan=True,
            require_capture_provenance=True,
            capture_required_classification="lab",
            required_certified_claims=["physical-print-scan"],
            max_list=20,
        )

        self.assertTrue(pipeline["success"])
        self.assertEqual(
            pipeline["schema"],
            certify.CAPTURE_CERTIFICATION_PIPELINE_SCHEMA,
        )
        self.assertEqual(pipeline["summary"]["failure_count"], 0)
        self.assertEqual(pipeline["summary"]["completed_step_count"], 7)
        self.assertTrue(pipeline["summary"]["archive_verified"])
        self.assertTrue(pipeline["summary"]["archive_replayed"])
        self.assertEqual(pipeline["summary"]["archive_replay_mismatch_count"], 0)
        self.assertTrue(pipeline["summary"]["status_claim_gate_passed"])
        self.assertIn("physical-print-scan", pipeline["summary"]["certified_claims"])
        self.assertTrue(pipeline["parameters"]["require_capture_provenance"])
        self.assertTrue(Path(str(pipeline["artifacts"]["pipeline_report_file"])).exists())
        self.assertTrue(
            Path(str(pipeline["artifacts"]["transport_evidence_archive_file"])).exists()
        )
        self.assertTrue(
            Path(str(pipeline["artifacts"]["transport_evidence_archive_replay_file"])).exists()
        )
        self.assertTrue(
            Path(str(pipeline["artifacts"]["transport_reliability_replay_report_file"])).exists()
        )
        self.assertTrue(
            Path(str(pipeline["artifacts"]["transport_certification_status_file"])).exists()
        )
        step_names = [step["name"] for step in pipeline["steps"]]
        self.assertEqual(
            step_names,
            [
                "attach-capture-corpus",
                "validate-capture-corpus",
                "certify",
                "archive-evidence",
                "verify-evidence-archive",
                "replay-evidence-archive",
                "certification-status",
            ],
        )

        status = json.loads(
            Path(str(pipeline["artifacts"]["transport_certification_status_file"])).read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(status["summary"]["physical_print_scan_ready"])
        self.assertEqual(
            status["claim_gate"]["required_certified_claims"],
            ["physical-print-scan"],
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_capture_evidence_pipeline_ingests_external_scans_before_attach(self) -> None:
        root = self.make_case_root("capture_evidence_pipeline_ingest_print_scan")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260528,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-scanner",
                "dpi": "300",
                "capture_session_id": "pipeline-ingest-print-session",
                "operator": "pipeline-ingest-operator",
                "captured_at_utc": "2026-05-28T13:30:00Z",
            },
        )
        corpus_path = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        source_image = corpus_path.parent / case["reference_image_paths"][0]
        external_root = root / "returned_scans"
        capture_dir = external_root / case["label"]
        capture_dir.mkdir(parents=True)
        scan_file = capture_dir / "scan-from-lab.png"
        shutil.copy2(str(source_image), str(scan_file))
        with scan_file.open("ab") as handle:
            handle.write(b"\n# capture evidence pipeline ingestion marker\n")

        pipeline = transport.certify_capture_evidence_pipeline(
            capture_corpus_file=str(corpus_path),
            output_dir=str(root / "pipeline"),
            capture_root=str(external_root),
            capture_medium="print-scan",
            capture_metadata={
                "scanner": "lab-flatbed-b",
                "dpi": "300",
                "capture_session_id": "pipeline-ingest-override-session",
                "operator": "pipeline-ingest-operator",
                "captured_at_utc": "2026-05-28T13:45:00Z",
            },
            kit_manifest_file=str(root / "kit" / "capture_kit_manifest.json"),
            profile="reliable-airgap-v1",
            backend="sidecar",
            require_physical_print_scan=True,
            require_capture_provenance=True,
            capture_required_classification="lab",
            required_certified_claims=["physical-print-scan"],
            max_list=20,
        )

        self.assertTrue(pipeline["success"])
        self.assertTrue(pipeline["summary"]["capture_ingested"])
        self.assertEqual(pipeline["summary"]["completed_step_count"], 8)
        self.assertEqual(pipeline["summary"]["failure_count"], 0)
        self.assertTrue(
            Path(str(pipeline["artifacts"]["capture_ingestion_report_file"])).exists()
        )
        step_names = [step["name"] for step in pipeline["steps"]]
        self.assertEqual(
            step_names,
            [
                "ingest-capture-corpus",
                "attach-capture-corpus",
                "validate-capture-corpus",
                "certify",
                "archive-evidence",
                "verify-evidence-archive",
                "replay-evidence-archive",
                "certification-status",
            ],
        )
        ingestion_report = json.loads(
            Path(str(pipeline["artifacts"]["capture_ingestion_report_file"])).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            ingestion_report["schema"],
            certify.CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA,
        )
        self.assertEqual(ingestion_report["summary"]["capture_image_count"], 1)
        updated_corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        self.assertEqual(
            Path(updated_corpus["cases"][0]["image_path"]).resolve(),
            capture_dir.resolve(),
        )
        self.assertEqual(updated_corpus["cases"][0]["capture_metadata"]["scanner"], "lab-flatbed-b")
        status = json.loads(
            Path(str(pipeline["artifacts"]["transport_certification_status_file"])).read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(status["summary"]["physical_print_scan_ready"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_capture_evidence_pipeline_fails_closed_on_ingestion_miss(self) -> None:
        root = self.make_case_root("capture_evidence_pipeline_ingest_missing")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260528,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-scanner",
                "dpi": "300",
            },
        )
        external_root = root / "empty_scans"
        external_root.mkdir(parents=True)

        pipeline = transport.certify_capture_evidence_pipeline(
            capture_corpus_file=str(kit["corpus_file"]),
            output_dir=str(root / "pipeline"),
            capture_root=str(external_root),
            profile="reliable-airgap-v1",
            backend="sidecar",
            require_physical_print_scan=True,
            capture_required_classification="lab",
            max_list=20,
        )

        self.assertFalse(pipeline["success"])
        self.assertEqual(pipeline["summary"]["failed_steps"], ["ingest-capture-corpus"])
        self.assertFalse(pipeline["summary"]["capture_ingested"])
        self.assertFalse(pipeline["steps"][0]["success"])
        self.assertEqual(pipeline["steps"][1]["skip_reason"], "ingest-capture-corpus failed")
        self.assertFalse((root / "pipeline" / "attach" / "transport_capture_attachment_report.json").exists())
        self.assertFalse((root / "pipeline" / "cert" / "transport_reliability_report.json").exists())

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_certify_capture_evidence_pipeline_fails_closed_before_certifying_empty_kit(self) -> None:
        root = self.make_case_root("capture_evidence_pipeline_missing")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-scanner",
                "dpi": "300",
            },
        )

        pipeline = transport.certify_capture_evidence_pipeline(
            capture_corpus_file=str(kit["corpus_file"]),
            output_dir=str(root / "pipeline"),
            profile="reliable-airgap-v1",
            backend="sidecar",
            require_physical_print_scan=True,
            capture_required_classification="lab",
            max_list=20,
        )

        self.assertFalse(pipeline["success"])
        self.assertEqual(pipeline["summary"]["failed_steps"], ["attach-capture-corpus"])
        self.assertFalse(pipeline["steps"][0]["success"])
        skipped = [step for step in pipeline["steps"] if step["skipped"]]
        self.assertEqual(len(skipped), 6)
        self.assertFalse((root / "pipeline" / "cert" / "transport_reliability_report.json").exists())
        self.assertFalse(
            (
                root
                / "pipeline"
                / "evidence_archive"
                / "transport_capture_evidence_archive.zip"
            ).exists()
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_certify_capture_evidence_command_writes_pipeline_report(self) -> None:
        root = self.make_case_root("capture_evidence_pipeline_cli")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-scanner",
                "dpi": "300",
            },
        )
        corpus_path = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        capture_dir = corpus_path.parent / case["image_path"]
        source_image = corpus_path.parent / case["reference_image_paths"][0]
        capture_image = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_image), str(capture_image))
        with capture_image.open("ab") as handle:
            handle.write(b"\n# capture evidence pipeline cli marker\n")

        output_dir = root / "pipeline"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "certify-capture-evidence",
            "--capture-corpus-file",
            str(corpus_path),
            "-o",
            str(output_dir),
            "--profile",
            "reliable-airgap-v1",
            "--backend",
            "sidecar",
            "--require-physical-print-scan",
            "--capture-required-classification",
            "lab",
            "--require-certified-claim",
            "physical-print-scan",
            "--chunk-chars",
            "24",
            "--lines-per-page",
            "8",
            "--max-list",
            "20",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(
            stdout["schema"],
            certify.CAPTURE_CERTIFICATION_PIPELINE_SCHEMA,
        )
        self.assertTrue(
            (output_dir / "transport_capture_certification_pipeline_report.json").exists()
        )
        self.assertTrue(
            (
                output_dir
                / "evidence_archive"
                / "transport_certification_status.json"
            ).exists()
        )
        self.assertTrue(
            (
                output_dir
                / "evidence_replay"
                / "transport_evidence_archive_replay_report.json"
            ).exists()
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_certify_capture_evidence_ingests_external_scans(self) -> None:
        root = self.make_case_root("capture_evidence_pipeline_cli_ingest")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        relative_kit_dir = Path(".tmp_test_runs") / root.name / "kit"
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(TEST_ROOT / relative_kit_dir),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260528,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-scanner",
                "dpi": "300",
            },
        )
        corpus = json.loads(Path(str(kit["corpus_file"])).read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        source_page = TEST_ROOT / relative_kit_dir / case["reference_image_paths"][0]
        relative_capture_root = Path(".tmp_test_runs") / root.name / "returned_scans"
        capture_dir = TEST_ROOT / relative_capture_root / case["label"]
        capture_dir.mkdir(parents=True)
        scan_file = capture_dir / "scan.png"
        shutil.copy2(str(source_page), str(scan_file))
        with scan_file.open("ab") as handle:
            handle.write(b"\n# capture evidence pipeline cli ingestion marker\n")
        relative_output_dir = Path(".tmp_test_runs") / root.name / "pipeline"

        completed = subprocess.run(
            [
                sys.executable,
                "qrcode_helper.py",
                "certify-capture-evidence",
                "--capture-corpus-file",
                str(relative_kit_dir / "capture_corpus.json"),
                "--capture-root",
                str(relative_capture_root),
                "-o",
                str(relative_output_dir),
                "--kit-manifest-file",
                str(relative_kit_dir / "capture_kit_manifest.json"),
                "--profile",
                "reliable-airgap-v1",
                "--backend",
                "sidecar",
                "--capture-medium",
                "print-scan",
                "--capture-metadata",
                "scanner=cli-pipeline-flatbed",
                "--capture-metadata",
                "capture_session_id=cli-pipeline-session",
                "--capture-metadata",
                "operator=cli-pipeline-operator",
                "--capture-metadata",
                "captured_at_utc=2026-05-28T14:00:00Z",
                "--require-physical-print-scan",
                "--require-capture-provenance",
                "--capture-required-classification",
                "lab",
                "--require-certified-claim",
                "physical-print-scan",
                "--chunk-chars",
                "24",
                "--lines-per-page",
                "8",
                "--max-list",
                "20",
            ],
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertTrue(stdout["summary"]["capture_ingested"])
        self.assertTrue(
            (
                TEST_ROOT
                / relative_output_dir
                / "ingest"
                / "transport_capture_corpus_ingestion_report.json"
            ).exists()
        )
        self.assertTrue(
            (
                TEST_ROOT
                / relative_output_dir
                / "evidence_archive"
                / "transport_certification_status.json"
            ).exists()
        )

    def test_transport_certification_status_requires_exactly_one_source(self) -> None:
        root = self.make_case_root("certification_status_source_validation")
        report_path = root / "transport_reliability_report.json"
        report_path.write_text(
            json.dumps(
                {
                    "schema": certify.REPORT_SCHEMA,
                    "success": True,
                    "profile": "reliable-airgap-v1",
                    "profile_certified": True,
                    "certification_claims": {
                        "schema": certify.CERTIFICATION_CLAIMS_SCHEMA,
                        "claims": [],
                    },
                    "summary": {},
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "exactly one"):
            certify.summarize_transport_certification_status(
                report_file=str(report_path),
                verification_file=str(report_path),
            )

    def test_transport_certification_status_rejects_archive_without_verification(self) -> None:
        root = self.make_case_root("certification_status_archive_no_verify")
        archive_path = root / "transport_capture_evidence_archive.zip"
        archive_path.write_bytes(b"not a zip")

        with self.assertRaisesRegex(ValueError, "requires verify_archive=true"):
            certify.summarize_transport_certification_status(
                archive_file=str(archive_path),
            )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_archive_evidence_command_writes_zip_and_manifest(self) -> None:
        root = self.make_case_root("archive_evidence_cli")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            max_list=20,
        )
        self.assertTrue(result["success"])
        output_dir = root / "archive"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "archive-evidence",
            "--report-file",
            str(root / "cert" / "transport_reliability_report.json"),
            "-o",
            str(output_dir),
            "--require-successful-report",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["schema"], certify.CAPTURE_EVIDENCE_ARCHIVE_SCHEMA)
        self.assertTrue((output_dir / "transport_capture_evidence_archive.zip").exists())
        self.assertTrue(
            (output_dir / "transport_capture_evidence_archive_manifest.json").exists()
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_verify_evidence_archive_command_writes_report(self) -> None:
        root = self.make_case_root("verify_archive_cli")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            max_list=20,
        )
        self.assertTrue(result["success"])
        archive_manifest = certify.archive_transport_evidence(
            report_file=str(root / "cert" / "transport_reliability_report.json"),
            output_dir=str(root / "archive"),
            require_successful_report=True,
        )
        verify_output = root / "verify" / "transport_archive_verification.json"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "verify-evidence-archive",
            "--archive-file",
            str(archive_manifest["archive_file"]),
            "--manifest-file",
            str(archive_manifest["manifest_file"]),
            "--output-file",
            str(verify_output),
            "--require-successful-report",
            "--require-profile-certified",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(
            stdout["schema"],
            certify.CAPTURE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA,
        )
        self.assertTrue(verify_output.exists())
        saved = json.loads(verify_output.read_text(encoding="utf-8"))
        self.assertEqual(saved["archive_sha256"], stdout["archive_sha256"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_replay_evidence_archive_command_writes_report(self) -> None:
        root = self.make_case_root("replay_archive_cli")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "unit-test-printer",
                "scanner": "unit-test-scanner",
                "dpi": "300",
            },
        )
        corpus_path = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        capture_dir = corpus_path.parent / case["image_path"]
        source_image = corpus_path.parent / case["reference_image_paths"][0]
        capture_image = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_image), str(capture_image))
        with capture_image.open("ab") as handle:
            handle.write(b"\n# replay archive CLI distinct marker\n")
        attachment = transport.attach_capture_corpus(
            capture_corpus_file=str(corpus_path),
            output_dir=str(root / "attach"),
            require_captures=True,
            require_distinct_capture_images=True,
        )
        self.assertTrue(attachment["success"])
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            backend="sidecar",
            profile="reliable-airgap-v1",
            capture_corpus_file=str(corpus_path),
            include_generated_corpus=False,
            require_distinct_capture_images=True,
            require_physical_print_scan=True,
            require_capture_attachment_report=True,
            redundancy_copies=2,
            parity_group_size=4,
            max_list=20,
        )
        self.assertTrue(result["success"])
        archive_manifest = certify.archive_transport_evidence(
            report_file=str(root / "cert" / "transport_reliability_report.json"),
            output_dir=str(root / "archive"),
            require_successful_report=True,
            require_capture_attachment_report=True,
            require_physical_print_scan=True,
            require_profile_certified=True,
        )
        output_dir = root / "replay"
        output_file = output_dir / "transport_evidence_archive_replay_report.json"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "replay-evidence-archive",
            "--archive-file",
            str(archive_manifest["archive_file"]),
            "--manifest-file",
            str(archive_manifest["manifest_file"]),
            "-o",
            str(output_dir),
            "--output-file",
            str(output_file),
            "--require-successful-report",
            "--require-capture-attachment-report",
            "--require-physical-print-scan",
            "--require-profile-certified",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["schema"], certify.CAPTURE_EVIDENCE_ARCHIVE_REPLAY_SCHEMA)
        self.assertTrue(stdout["summary"]["replay_success"])
        self.assertEqual(stdout["comparison"]["mismatch_count"], 0)
        self.assertTrue(output_file.exists())

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_verify_evidence_archive_accepts_workspace_relative_manifest(self) -> None:
        root = self.make_case_root("verify_archive_relative_manifest_cli")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            max_list=20,
        )
        self.assertTrue(result["success"])
        relative_archive_dir = Path(".tmp_test_runs") / root.name / "archive"
        archive_manifest = certify.archive_transport_evidence(
            report_file=str(root / "cert" / "transport_reliability_report.json"),
            output_dir=str(TEST_ROOT / relative_archive_dir),
            require_successful_report=True,
        )
        relative_archive = relative_archive_dir / "transport_capture_evidence_archive.zip"
        relative_manifest = relative_archive_dir / "transport_capture_evidence_archive_manifest.json"
        self.assertEqual(Path(archive_manifest["archive_file"]), TEST_ROOT / relative_archive)
        self.assertEqual(Path(archive_manifest["manifest_file"]), TEST_ROOT / relative_manifest)
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "verify-evidence-archive",
            "--archive-file",
            str(relative_archive),
            "--manifest-file",
            str(relative_manifest),
            "--require-successful-report",
            "--require-profile-certified",
        ]

        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["manifest_file"], str(TEST_ROOT / relative_manifest))

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_certification_status_command_writes_status(self) -> None:
        root = self.make_case_root("certification_status_cli")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            max_list=20,
        )
        self.assertTrue(result["success"])
        status_output = root / "status" / "transport_certification_status.json"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "certification-status",
            "--report-file",
            str(root / "cert" / "transport_reliability_report.json"),
            "--output-file",
            str(status_output),
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["schema"], certify.CERTIFICATION_STATUS_SCHEMA)
        self.assertTrue(stdout["summary"]["production_airgap_ready"])
        self.assertIn("generated-page-sidecar", stdout["summary"]["certified_claims"])
        self.assertTrue(status_output.exists())
        saved = json.loads(status_output.read_text(encoding="utf-8"))
        self.assertEqual(saved["source"]["type"], "transport_reliability_report")

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_certification_status_command_fails_on_missing_required_claim(self) -> None:
        root = self.make_case_root("certification_status_cli_claim_gate")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
            metadata_level="compact",
            line_index_mode="full",
            line_crc_mode="on",
            render_sidecar=True,
        )
        result = transport.certify_reliability(
            output_dir=str(root / "cert"),
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260527,
            backend="sidecar",
            redundancy_copies=2,
            parity_group_size=4,
            profile="reliable-airgap-v1",
            max_list=20,
        )
        self.assertTrue(result["success"])
        status_output = root / "status" / "transport_certification_status.json"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "certification-status",
            "--report-file",
            str(root / "cert" / "transport_reliability_report.json"),
            "--output-file",
            str(status_output),
            "--require-certified-claim",
            "physical-print-scan",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)
        stdout = json.loads(completed.stdout)
        self.assertFalse(stdout["success"])
        self.assertFalse(stdout["claim_gate"]["passed"])
        self.assertEqual(
            stdout["claim_gate"]["missing_required_certified_claims"],
            ["physical-print-scan"],
        )
        self.assertTrue(status_output.exists())
        saved = json.loads(status_output.read_text(encoding="utf-8"))
        self.assertFalse(saved["summary"]["physical_print_scan_ready"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_prepare_capture_corpus_command_writes_kit(self) -> None:
        root = self.make_case_root("prepare_capture_cli")
        relative_output_dir = Path(".tmp_test_runs") / root.name / "kit"
        output_dir = TEST_ROOT / relative_output_dir
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "prepare-capture-corpus",
            "-o",
            str(relative_output_dir),
            "--classification",
            "lab",
            "--capture-medium",
            "print-scan",
            "--payload-size",
            "64",
            "--iterations-per-size",
            "1",
            "--seed",
            "20260526",
            "--chunk-chars",
            "24",
            "--lines-per-page",
            "8",
            "--redundancy-copies",
            "2",
            "--parity-group-size",
            "4",
            "--include-raw-capture-dirs",
            "--perspective-correction-method",
            "unit-test CLI homography",
            "--capture-metadata",
            "scanner=unit-test-cli",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["schema"], certify.CAPTURE_KIT_SCHEMA)
        self.assertEqual(stdout["capture_medium"], "print-scan")
        self.assertEqual(stdout["summary"]["case_count"], 1)
        self.assertEqual(Path(stdout["corpus_file"]), relative_output_dir / "capture_corpus.json")
        self.assertTrue((output_dir / "capture_corpus.json").exists())
        self.assertTrue((output_dir / "capture_kit_manifest.json").exists())
        self.assertTrue((output_dir / "instructions" / "NEXT_STEPS.md").exists())
        corpus = json.loads((output_dir / "capture_corpus.json").read_text(encoding="utf-8"))
        self.assertEqual(corpus["capture_medium"], "print-scan")
        self.assertEqual(corpus["cases"][0]["capture_medium"], "print-scan")
        self.assertTrue(corpus["cases"][0]["reference_image_paths"])
        self.assertTrue(corpus["cases"][0]["raw_image_paths"])
        self.assertEqual(
            corpus["cases"][0]["perspective_correction"]["method"],
            "unit-test CLI homography",
        )
        self.assertEqual(stdout["summary"]["raw_capture_directories_ready"], 1)
        instructions = (output_dir / "instructions" / "NEXT_STEPS.md").read_text(encoding="utf-8")
        self.assertIn("--require-distinct-capture-images", instructions)
        self.assertIn("--capture-required-classification lab", instructions)
        self.assertIn("--require-real-camera-perspective-correction", instructions)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_prepare_capture_corpus_can_stage_ocr_only_kit(self) -> None:
        root = self.make_case_root("prepare_ocr_only_capture_cli")
        relative_output_dir = Path(".tmp_test_runs") / root.name / "kit"
        output_dir = TEST_ROOT / relative_output_dir
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "prepare-capture-corpus",
            "-o",
            str(relative_output_dir),
            "--classification",
            "lab",
            "--capture-medium",
            "print-scan",
            "--payload-size",
            "64",
            "--iterations-per-size",
            "1",
            "--seed",
            "20260527",
            "--chunk-chars",
            "24",
            "--lines-per-page",
            "8",
            "--redundancy-copies",
            "2",
            "--parity-group-size",
            "4",
            "--ocr-only-backend",
            "tesseract",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["profile"], "ocr-only-backend-v1")
        self.assertEqual(stdout["summary"]["ocr_only_backend"], "tesseract")
        corpus = json.loads((output_dir / "capture_corpus.json").read_text(encoding="utf-8"))
        self.assertEqual(corpus["metadata"]["ocr_only_backend"], "tesseract")
        manifest = json.loads((output_dir / corpus["cases"][0]["manifest_path"]).read_text(encoding="utf-8"))
        self.assertFalse(manifest["sidecar_enabled"])
        self.assertFalse(certify._manifest_has_binary_sidecar(manifest))
        instructions = (output_dir / "instructions" / "NEXT_STEPS.md").read_text(encoding="utf-8")
        self.assertIn("--backend tesseract", instructions)
        self.assertIn("--require-ocr-only-backend", instructions)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_ingest_capture_corpus_maps_external_lab_captures(self) -> None:
        root = self.make_case_root("ingest_capture_corpus")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260528,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={"scanner": "staged-fixture"},
        )
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        label = case["label"]
        source_page = root / "kit" / case["reference_image_paths"][0]
        external_root = root / "external_scans"
        capture_dir = external_root / label
        capture_dir.mkdir(parents=True)
        scan_file = capture_dir / "scan_0001.png"
        shutil.copy2(str(source_page), str(scan_file))
        scan_file.write_bytes(scan_file.read_bytes() + b"\n# simulated lab scan marker\n")

        report = transport.ingest_capture_corpus(
            capture_corpus_file=str(corpus_file),
            capture_root=str(external_root),
            output_dir=str(root / "ingest"),
            kit_manifest_file=str(root / "kit" / "capture_kit_manifest.json"),
            capture_medium="print-scan",
            capture_metadata={"dpi": "300", "scanner": "lab-flatbed-a"},
            require_captures=True,
        )

        self.assertTrue(report["success"])
        self.assertEqual(report["schema"], certify.CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA)
        self.assertEqual(report["summary"]["cases_with_captures"], 1)
        self.assertEqual(report["summary"]["capture_image_count"], 1)
        self.assertEqual(report["summary"]["failures_by_reason"], {})
        self.assertEqual(report["cases"][0]["capture_images"][0]["sha256"], certify._sha256_file(scan_file))
        updated_corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        updated_case = updated_corpus["cases"][0]
        self.assertEqual(Path(updated_case["image_path"]).resolve(), capture_dir.resolve())
        self.assertEqual(updated_case["capture_metadata"]["dpi"], "300")
        self.assertEqual(updated_case["capture_metadata"]["scanner"], "lab-flatbed-a")
        self.assertEqual(
            updated_case["capture_ingestion"]["schema"],
            certify.CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA,
        )
        kit_manifest = json.loads(
            (root / "kit" / "capture_kit_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(kit_manifest["summary"]["operator_ingested_capture_cases"], 1)
        self.assertTrue((root / "ingest" / "transport_capture_corpus_ingestion_report.json").exists())

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_ingest_capture_corpus_merges_metadata_manifest_by_case_label(self) -> None:
        root = self.make_case_root("ingest_capture_metadata_manifest")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260528,
            redundancy_copies=2,
            parity_group_size=4,
            capture_metadata={
                "printer": "prepared-printer",
                "scanner": "prepared-scanner",
                "dpi": "200",
            },
        )
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        label = case["label"]
        source_page = root / "kit" / case["reference_image_paths"][0]
        external_root = root / "external_scans"
        capture_dir = external_root / label
        capture_dir.mkdir(parents=True)
        scan_file = capture_dir / "operator-scan.png"
        shutil.copy2(str(source_page), str(scan_file))
        with scan_file.open("ab") as handle:
            handle.write(b"\n# metadata manifest ingestion marker\n")
        metadata_manifest = root / "operator_capture_metadata.json"
        metadata_manifest.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_METADATA_MANIFEST_SCHEMA,
                    "capture_metadata_defaults": {
                        "capture_session_id": "lab-session-20260528",
                        "operator": "lab-operator-a",
                        "captured_at_utc": "2026-05-28T15:00:00Z",
                        "scanner": "manifest-flatbed",
                        "dpi": "300",
                    },
                    "cases": [
                        {
                            "label": label,
                            "capture_metadata": {
                                "scanner": "manifest-case-flatbed",
                                "case_station": "station-7",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        report = transport.ingest_capture_corpus(
            capture_corpus_file=str(corpus_file),
            capture_root=str(external_root),
            output_dir=str(root / "ingest"),
            kit_manifest_file=str(root / "kit" / "capture_kit_manifest.json"),
            capture_metadata_manifest_file=str(metadata_manifest),
            capture_metadata={"scanner": "cli-override-flatbed"},
            require_captures=True,
        )

        self.assertTrue(report["success"])
        self.assertEqual(
            report["capture_metadata_manifest_sha256"],
            certify._sha256_file(metadata_manifest),
        )
        self.assertEqual(report["summary"]["capture_metadata_manifest_case_count"], 1)
        self.assertEqual(
            report["summary"]["capture_metadata_manifest_matched_case_count"],
            1,
        )
        self.assertEqual(report["summary"]["unmatched_metadata_manifest_label_count"], 0)
        self.assertTrue(report["cases"][0]["capture_metadata_manifest_case_matched"])
        updated_corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        metadata = updated_corpus["cases"][0]["capture_metadata"]
        self.assertEqual(metadata["capture_session_id"], "lab-session-20260528")
        self.assertEqual(metadata["operator"], "lab-operator-a")
        self.assertEqual(metadata["captured_at_utc"], "2026-05-28T15:00:00Z")
        self.assertEqual(metadata["scanner"], "cli-override-flatbed")
        self.assertEqual(metadata["case_station"], "station-7")
        self.assertEqual(metadata["printer"], "prepared-printer")
        self.assertEqual(updated_corpus["cases"][0]["capture_medium"], "print-scan")
        kit_manifest = json.loads(
            (root / "kit" / "capture_kit_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            kit_manifest["last_capture_ingestion"]["capture_metadata_manifest_sha256"],
            certify._sha256_file(metadata_manifest),
        )

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_ingest_capture_corpus_fails_closed_on_unmatched_metadata_manifest_label(self) -> None:
        root = self.make_case_root("ingest_metadata_manifest_unmatched")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260528,
            redundancy_copies=2,
            parity_group_size=4,
        )
        corpus_file = Path(str(kit["corpus_file"]))
        corpus = json.loads(corpus_file.read_text(encoding="utf-8"))
        case = corpus["cases"][0]
        source_page = root / "kit" / case["reference_image_paths"][0]
        external_root = root / "external_scans"
        capture_dir = external_root / case["label"]
        capture_dir.mkdir(parents=True)
        scan_file = capture_dir / "scan.png"
        shutil.copy2(str(source_page), str(scan_file))
        with scan_file.open("ab") as handle:
            handle.write(b"\n# unmatched metadata label marker\n")
        metadata_manifest = root / "operator_capture_metadata.json"
        metadata_manifest.write_text(
            json.dumps(
                {
                    "schema": certify.CAPTURE_METADATA_MANIFEST_SCHEMA,
                    "cases": [
                        {
                            "label": "not-a-prepared-case",
                            "capture_metadata": {"operator": "unexpected"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        report = transport.ingest_capture_corpus(
            capture_corpus_file=str(corpus_file),
            capture_root=str(external_root),
            output_dir=str(root / "ingest"),
            capture_metadata_manifest_file=str(metadata_manifest),
            require_captures=True,
        )

        self.assertFalse(report["success"])
        self.assertEqual(
            report["summary"]["failures_by_reason"],
            {"unexpected_capture_metadata_manifest_labels": 1},
        )
        self.assertEqual(report["unmatched_metadata_manifest_labels"], ["not-a-prepared-case"])

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_ingest_capture_corpus_fails_closed_on_missing_required_capture(self) -> None:
        root = self.make_case_root("ingest_capture_corpus_missing")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(root / "kit"),
            classification="real",
            capture_medium="camera-photo",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260528,
            redundancy_copies=2,
            parity_group_size=4,
        )
        external_root = root / "external_photos"
        external_root.mkdir(parents=True)

        report = transport.ingest_capture_corpus(
            capture_corpus_file=str(kit["corpus_file"]),
            capture_root=str(external_root),
            output_dir=str(root / "ingest"),
            require_captures=True,
        )

        self.assertFalse(report["success"])
        self.assertEqual(
            report["summary"]["failures_by_reason"],
            {"capture_label_directory_missing": 1, "capture_images_missing": 1},
        )
        self.assertEqual(report["summary"]["cases_missing_captures"], 1)

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_ingest_capture_corpus_command_writes_report(self) -> None:
        root = self.make_case_root("ingest_capture_cli")
        transport = qrcode_helper.AirgapTransportLayer(
            chunk_chars=24,
            lines_per_page=8,
            max_compressed_kib=64,
        )
        relative_kit_dir = Path(".tmp_test_runs") / root.name / "kit"
        kit = transport.prepare_capture_corpus_kit(
            output_dir=str(TEST_ROOT / relative_kit_dir),
            classification="lab",
            capture_medium="print-scan",
            payload_sizes=[64],
            iterations_per_size=1,
            seed=20260528,
            redundancy_copies=2,
            parity_group_size=4,
        )
        corpus = json.loads(Path(str(kit["corpus_file"])).read_text(encoding="utf-8"))
        label = corpus["cases"][0]["label"]
        source_page = TEST_ROOT / relative_kit_dir / corpus["cases"][0]["reference_image_paths"][0]
        relative_capture_root = Path(".tmp_test_runs") / root.name / "external_scans"
        capture_dir = TEST_ROOT / relative_capture_root / label
        capture_dir.mkdir(parents=True)
        scan_file = capture_dir / "scan.png"
        shutil.copy2(str(source_page), str(scan_file))
        scan_file.write_bytes(scan_file.read_bytes() + b"\n# cli ingestion fixture marker\n")
        relative_output_dir = Path(".tmp_test_runs") / root.name / "ingest"

        completed = subprocess.run(
            [
                sys.executable,
                "qrcode_helper.py",
                "ingest-capture-corpus",
                "--capture-corpus-file",
                str(relative_kit_dir / "capture_corpus.json"),
                "--capture-root",
                str(relative_capture_root),
                "-o",
                str(relative_output_dir),
                "--kit-manifest-file",
                str(relative_kit_dir / "capture_kit_manifest.json"),
                "--capture-medium",
                "print-scan",
                "--capture-metadata",
                "scanner=cli-flatbed",
                "--require-captures",
            ],
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertEqual(stdout["schema"], certify.CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA)
        self.assertEqual(stdout["summary"]["capture_image_count"], 1)
        self.assertTrue(
            (TEST_ROOT / relative_output_dir / "transport_capture_corpus_ingestion_report.json").exists()
        )
        updated_corpus = json.loads(
            (TEST_ROOT / relative_kit_dir / "capture_corpus.json").read_text(encoding="utf-8")
        )
        self.assertEqual(updated_corpus["cases"][0]["capture_metadata"]["scanner"], "cli-flatbed")

    @unittest.skipUnless(qrcode_helper.PIL_AVAILABLE, "requires Pillow for generated digital pages")
    def test_transport_cli_certify_reliable_airgap_profile(self) -> None:
        root = self.make_case_root("certify_cli_reliable_airgap")
        output_dir = root / "cert"
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "certify",
            "-o",
            str(output_dir),
            "--profile",
            "reliable-airgap-v1",
            "--payload-size",
            "64",
            "--iterations-per-size",
            "1",
            "--seed",
            "20260525",
            "--backend",
            "sidecar",
            "--chunk-chars",
            "24",
            "--lines-per-page",
            "8",
            "--redundancy-copies",
            "2",
            "--parity-group-size",
            "4",
            "--max-list",
            "20",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        stdout = json.loads(completed.stdout)
        self.assertTrue(stdout["success"])
        self.assertTrue(stdout["profile_certified"])
        self.assertEqual(stdout["profile"], "reliable-airgap-v1")
        self.assertTrue((output_dir / "transport_reliability_report.json").exists())

    def test_transport_cli_certify_reliable_airgap_rejects_no_sidecar(self) -> None:
        root = self.make_case_root("certify_cli_reliable_airgap_reject")
        cmd = [
            sys.executable,
            "qrcode_helper.py",
            "certify",
            "-o",
            str(root / "cert"),
            "--profile",
            "reliable-airgap-v1",
            "--payload-size",
            "64",
            "--backend",
            "sidecar",
            "--no-sidecar",
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(TEST_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)
        stdout = json.loads(completed.stdout)
        self.assertFalse(stdout["success"])
        self.assertIn("reliable-airgap-v1 profile rejected unsafe settings", stdout["error"])


if __name__ == "__main__":
    unittest.main()
