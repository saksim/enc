#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for SOX1 QR visual transport."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from enc2sop.crossmedia import crypto_envelope
from enc2sop.crossmedia import image_scan
from enc2sop.crossmedia import qr_transport
from enc2sop.transport import protocol as transport_protocol


KEY = bytes(range(32))


def _sample_sox1(payload: bytes = b"hello qr transport") -> str:
    return crypto_envelope.encrypt_bytes_to_sox1(
        payload,
        key=KEY,
        name="payload.bin",
        created_at_utc="2026-06-08T00:00:00Z",
    )


def _payloads_for(sox1: str, *, chunk_chars: int = 200) -> list[str]:
    return [qr_transport.encode_qr_payload(chunk) for chunk in qr_transport.split_sox1_string(sox1, chunk_chars=chunk_chars)]


def _error_report(exc: qr_transport.QrReassemblyError) -> dict:
    return json.loads(str(exc))


def test_split_join_roundtrip() -> None:
    sox1 = "SOX1." + ("A" * 1300)
    payloads = _payloads_for(sox1, chunk_chars=200)

    restored, report = qr_transport.reassemble_chunks(payloads)

    assert restored == sox1
    assert report["success"] is True
    assert report["chunks_total"] == 7
    assert report["missing_chunks"] == []


def test_qr_payload_parse_rejects_bad_magic() -> None:
    with pytest.raises(qr_transport.QrPayloadError, match="magic"):
        qr_transport.parse_qr_payload("BAD|v=1|data=x")


def test_qr_payload_crc_tamper_fails() -> None:
    payload = _payloads_for("SOX1." + ("A" * 250), chunk_chars=200)[0]
    tampered = payload.replace("data=SOX1.", "data=SOX2.", 1)

    with pytest.raises(qr_transport.QrPayloadError, match="CRC"):
        qr_transport.parse_qr_payload(tampered)


def test_scan_accepts_duplicate_images() -> None:
    sox1 = "SOX1." + ("B" * 500)
    payloads = _payloads_for(sox1, chunk_chars=200)

    restored, report = qr_transport.reassemble_chunks(payloads + payloads)

    assert restored == sox1
    assert report["duplicates"] == len(payloads)


def test_scan_reports_missing_chunks_with_retake_pages() -> None:
    sox1 = "SOX1." + ("C" * 750)
    payloads = _payloads_for(sox1, chunk_chars=200)

    with pytest.raises(qr_transport.QrReassemblyError) as exc_info:
        qr_transport.reassemble_chunks(payloads[:1] + payloads[2:])

    report = _error_report(exc_info.value)
    assert report["success"] is False
    assert report["missing_chunks"] == [1]
    assert report["retake_pages"] == [2]
    assert report["reason"] == "missing_or_crc_failed_chunks"


def test_scan_rejects_conflicting_duplicate_chunk() -> None:
    chunks = qr_transport.split_sox1_string("SOX1." + ("D" * 500), chunk_chars=200)
    original = chunks[0]
    conflict = replace(
        original,
        data=original.data[:-1] + ("E" if original.data[-1] != "E" else "F"),
    )
    conflict = replace(conflict, crc16=transport_protocol.crc16_hex(conflict.data))

    with pytest.raises(qr_transport.QrReassemblyError) as exc_info:
        qr_transport.reassemble_chunks(
            [
                qr_transport.encode_qr_payload(original),
                qr_transport.encode_qr_payload(conflict),
            ]
            + [qr_transport.encode_qr_payload(chunk) for chunk in chunks[1:]]
        )

    report = _error_report(exc_info.value)
    assert report["reason"] == "conflicting_duplicate_chunks"
    assert report["conflicts"]


def test_scan_rejects_mixed_artifact_ids_when_ambiguous() -> None:
    payloads = _payloads_for("SOX1." + ("E" * 250), chunk_chars=200)
    payloads += _payloads_for("SOX1." + ("F" * 250), chunk_chars=200)

    with pytest.raises(qr_transport.QrReassemblyError) as exc_info:
        qr_transport.reassemble_chunks(payloads)

    report = _error_report(exc_info.value)
    assert report["reason"] == "multiple_complete_artifacts"
    assert len(report["complete_artifact_ids"]) == 2


def _require_qr_backend() -> None:
    cv2 = pytest.importorskip("cv2")
    pytest.importorskip("PIL")
    if not hasattr(cv2, "QRCodeDetector") or not hasattr(cv2, "QRCodeEncoder_create"):
        pytest.skip("OpenCV QR encoder/detector is not available")


def test_render_scan_roundtrip_png(tmp_path: Path) -> None:
    _require_qr_backend()
    sox1 = _sample_sox1(b"png qr image roundtrip")
    output_dir = tmp_path / "pages_pkg"

    manifest = qr_transport.render_qr_pages(sox1, output_dir, chunk_chars=700)
    payloads, meta = image_scan.scan_image_input(output_dir / "pages")
    restored, report = qr_transport.reassemble_chunks(
        payloads,
        image_count=int(meta["image_count"]),
        bad_images=meta["bad_images"],
    )

    assert restored == sox1
    assert report["success"] is True
    assert manifest["recovery_requires_manifest"] is False
    assert len(payloads) == manifest["chunks_total"]


def test_render_writes_capture_guide_image_and_manifest_metadata(tmp_path: Path) -> None:
    _require_qr_backend()
    sox1 = _sample_sox1(b"capture guide image metadata")
    output_dir = tmp_path / "pages_pkg"

    manifest = qr_transport.render_qr_pages(sox1, output_dir, chunk_chars=700)

    guide_path = output_dir / "capture_guide.png"
    instructions = (output_dir / "instructions.md").read_text(encoding="utf-8")
    assert guide_path.exists()
    assert guide_path.stat().st_size > 1000
    assert manifest["capture_guide_image"] == "capture_guide.png"
    assert manifest["capture_guide"]["schema"] == qr_transport.CAPTURE_GUIDE_IMAGE_SCHEMA
    assert manifest["capture_guide"]["contains_key_material"] is False
    assert manifest["capture_guide"]["contains_sox1_payload"] is False
    assert "capture_guide.png" in instructions



def test_scan_jpeg_roundtrip(tmp_path: Path) -> None:
    _require_qr_backend()
    image_module = pytest.importorskip("PIL.Image")
    sox1 = _sample_sox1(b"jpeg qr image roundtrip")
    output_dir = tmp_path / "pages_pkg"
    photos_dir = tmp_path / "photos"
    photos_dir.mkdir()
    qr_transport.render_qr_pages(sox1, output_dir, chunk_chars=700)
    for page in sorted((output_dir / "pages").glob("*.png")):
        image_module.open(page).convert("RGB").save(photos_dir / (page.stem + ".jpg"), quality=85)

    payloads, meta = image_scan.scan_image_input(photos_dir)
    restored, _report = qr_transport.reassemble_chunks(payloads, image_count=int(meta["image_count"]), bad_images=meta["bad_images"])

    assert restored == sox1


def test_scan_rotated_image_roundtrip(tmp_path: Path) -> None:
    _require_qr_backend()
    image_module = pytest.importorskip("PIL.Image")
    sox1 = _sample_sox1(b"lightly rotated qr image roundtrip")
    output_dir = tmp_path / "pages_pkg"
    photos_dir = tmp_path / "rotated"
    photos_dir.mkdir()
    qr_transport.render_qr_pages(sox1, output_dir, chunk_chars=700)
    for page in sorted((output_dir / "pages").glob("*.png")):
        image_module.open(page).convert("RGB").rotate(1, expand=True, fillcolor="white").save(photos_dir / page.name)

    payloads, meta = image_scan.scan_image_input(photos_dir)
    restored, _report = qr_transport.reassemble_chunks(payloads, image_count=int(meta["image_count"]), bad_images=meta["bad_images"])

    assert restored == sox1


def test_scan_perspective_distorted_image_roundtrip(tmp_path: Path) -> None:
    _require_qr_backend()
    cv2 = pytest.importorskip("cv2")
    np = pytest.importorskip("numpy")
    sox1 = _sample_sox1(b"perspective corrected qr image roundtrip")
    output_dir = tmp_path / "pages_pkg"
    photos_dir = tmp_path / "perspective"
    photos_dir.mkdir()
    qr_transport.render_qr_pages(sox1, output_dir, chunk_chars=700)
    for page in sorted((output_dir / "pages").glob("*.png")):
        image = cv2.imread(str(page), cv2.IMREAD_COLOR)
        height, width = image.shape[:2]
        canvas_width = int(round(width * 1.25))
        canvas_height = int(round(height * 1.20))
        source = np.float32(
            [
                [0, 0],
                [width - 1, 0],
                [width - 1, height - 1],
                [0, height - 1],
            ]
        )
        target = np.float32(
            [
                [canvas_width * 0.09, canvas_height * 0.04],
                [canvas_width * 0.92, canvas_height * 0.10],
                [canvas_width * 0.85, canvas_height * 0.96],
                [canvas_width * 0.14, canvas_height * 0.90],
            ]
        )
        matrix = cv2.getPerspectiveTransform(source, target)
        distorted = cv2.warpPerspective(
            image,
            matrix,
            (canvas_width, canvas_height),
            flags=cv2.INTER_CUBIC,
            borderMode=cv2.BORDER_CONSTANT,
            borderValue=(96, 96, 96),
        )
        cv2.imwrite(str(photos_dir / page.name), distorted)

    payloads, meta = image_scan.scan_image_input(photos_dir)
    restored, _report = qr_transport.reassemble_chunks(
        payloads,
        image_count=int(meta["image_count"]),
        bad_images=meta["bad_images"],
    )

    assert restored == sox1


def test_scan_bad_image_report_includes_capture_quality_and_retake_suggestion(tmp_path: Path) -> None:
    _require_qr_backend()
    image_module = pytest.importorskip("PIL.Image")
    photos_dir = tmp_path / "bad_photos"
    photos_dir.mkdir()
    image_module.new("RGB", (640, 640), "white").save(photos_dir / "blank_overexposed.jpg", quality=90)

    payloads, meta = image_scan.scan_image_input(photos_dir)

    assert payloads == []
    assert meta["image_count"] == 1
    assert meta["payload_count"] == 0
    bad_image = meta["bad_images"][0]
    quality = bad_image["quality"]
    assert bad_image["path"] == "blank_overexposed.jpg"
    assert bad_image["reason"] == "qr_not_found_or_not_sox1qr"
    assert quality["schema"] == image_scan.IMAGE_QUALITY_SCHEMA
    assert quality["blur"]["status"] == "critical"
    assert quality["exposure"]["status"] == "overexposed"
    assert quality["score"] < 50
    assert "QR border" in bad_image["suggestion"]
    assert "glare/overexposure" in bad_image["suggestion"]


def test_cli_scan_bad_image_writes_quality_guidance(tmp_path: Path) -> None:
    _require_qr_backend()
    image_module = pytest.importorskip("PIL.Image")
    photos_dir = tmp_path / "bad_cli_photos"
    recovered_path = tmp_path / "recovered.sox1"
    work_dir = tmp_path / "scan_work"
    photos_dir.mkdir()
    image_module.new("RGB", (640, 640), "white").save(photos_dir / "blank.jpg", quality=90)

    result = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "scan",
            "--image-input",
            str(photos_dir),
            "--out-string",
            str(recovered_path),
            "--work-dir",
            str(work_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 20
    assert not recovered_path.exists()
    report = json.loads((work_dir / "scan_report.json").read_text(encoding="utf-8"))
    assert report["success"] is False
    assert report["reason"] == "no_valid_qr_chunks"
    assert report["bad_images"][0]["quality"]["schema"] == image_scan.IMAGE_QUALITY_SCHEMA
    assert report["bad_images"][0]["quality"]["exposure"]["status"] == "overexposed"
    assert "glare/overexposure" in report["bad_images"][0]["suggestion"]



def test_render_multi_qr_repeated_layout_manifest_and_scan(tmp_path: Path) -> None:
    _require_qr_backend()
    sox1 = _sample_sox1((b"multi qr repeated layout" * 12) + bytes(range(128)))
    output_dir = tmp_path / "multi_pages_pkg"

    manifest = qr_transport.render_qr_pages(
        sox1,
        output_dir,
        chunk_chars=200,
        qrs_per_page=6,
        repeat_copies=3,
    )
    payloads, meta = image_scan.scan_image_input(output_dir / "pages")
    restored, report = qr_transport.reassemble_chunks(
        payloads,
        image_count=int(meta["image_count"]),
        bad_images=meta["bad_images"],
    )

    assert restored == sox1
    assert report["success"] is True
    assert report["duplicates"] >= manifest["chunks_total"]
    assert manifest["qrs_per_page"] == 6
    assert manifest["repeat_copies"] == 3
    assert manifest["transmissions_total"] == manifest["chunks_total"] * 3
    assert manifest["page_count"] < manifest["transmissions_total"]
    assert len(list((output_dir / "pages").glob("page_*.png"))) == manifest["page_count"]
    assert all("items" in page for page in manifest["pages"])


def test_cli_render_multi_qr_repeated_layout_roundtrip(tmp_path: Path) -> None:
    _require_qr_backend()
    sox1_path = tmp_path / "payload.sox1"
    pages_dir = tmp_path / "rendered_multi"
    recovered_path = tmp_path / "recovered.sox1"
    work_dir = tmp_path / "scan_work"
    sox1 = _sample_sox1((b"cli multi qr" * 12) + bytes(range(64)))
    sox1_path.write_text(sox1 + "\n", encoding="utf-8")

    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "render",
            "--input-string-file",
            str(sox1_path),
            "--output-dir",
            str(pages_dir),
            "--chunk-chars",
            "200",
            "--qrs-per-page",
            "6",
            "--repeat-copies",
            "3",
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "scan",
            "--image-input",
            str(pages_dir / "pages"),
            "--out-string",
            str(recovered_path),
            "--work-dir",
            str(work_dir),
        ],
        check=True,
    )

    manifest = json.loads((pages_dir / "manifest.json").read_text(encoding="utf-8"))
    report = json.loads((work_dir / "scan_report.json").read_text(encoding="utf-8"))
    assert recovered_path.read_text(encoding="utf-8").strip() == sox1
    assert manifest["page_count"] < manifest["transmissions_total"]
    assert report["success"] is True
    assert report["duplicates"] >= manifest["chunks_total"]

def test_cli_render_scan_roundtrip(tmp_path: Path) -> None:
    _require_qr_backend()
    sox1_path = tmp_path / "payload.sox1"
    pages_dir = tmp_path / "rendered"
    recovered_path = tmp_path / "recovered.sox1"
    work_dir = tmp_path / "scan_work"
    sox1 = _sample_sox1(b"cli render scan roundtrip")
    sox1_path.write_text(sox1 + "\n", encoding="utf-8")

    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "render",
            "--input-string-file",
            str(sox1_path),
            "--output-dir",
            str(pages_dir),
            "--chunk-chars",
            "700",
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "scan",
            "--image-input",
            str(pages_dir / "pages"),
            "--out-string",
            str(recovered_path),
            "--work-dir",
            str(work_dir),
        ],
        check=True,
    )

    assert recovered_path.read_text(encoding="utf-8").strip() == sox1
    report = json.loads((work_dir / "scan_report.json").read_text(encoding="utf-8"))
    assert report["success"] is True
    assert report["missing_chunks"] == []


def test_cli_scan_missing_page_writes_retake_report(tmp_path: Path) -> None:
    _require_qr_backend()
    sox1_path = tmp_path / "payload.sox1"
    pages_dir = tmp_path / "rendered"
    photos_dir = tmp_path / "photos"
    recovered_path = tmp_path / "recovered.sox1"
    work_dir = tmp_path / "scan_work"
    sox1 = _sample_sox1(b"missing page report" * 20)
    sox1_path.write_text(sox1 + "\n", encoding="utf-8")

    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "render",
            "--input-string-file",
            str(sox1_path),
            "--output-dir",
            str(pages_dir),
            "--chunk-chars",
            "700",
        ],
        check=True,
    )
    photos_dir.mkdir()
    pages = sorted((pages_dir / "pages").glob("*.png"))
    assert len(pages) > 1
    for page in pages[1:]:
        shutil.copy2(page, photos_dir / page.name)

    result = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "scan",
            "--image-input",
            str(photos_dir),
            "--out-string",
            str(recovered_path),
            "--work-dir",
            str(work_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 20
    assert not recovered_path.exists()
    report = json.loads((work_dir / "scan_report.json").read_text(encoding="utf-8"))
    assert report["success"] is False
    assert report["reason"] == "missing_or_crc_failed_chunks"
    assert report["retake_pages"] == [1]
