#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""End-to-end tests for cross-media send/receive commands."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest


KEY = bytes(range(32))
WRONG_KEY = bytes(reversed(range(32)))


def _require_qr_backend() -> None:
    cv2 = pytest.importorskip("cv2")
    pytest.importorskip("PIL")
    if not hasattr(cv2, "QRCodeDetector") or not hasattr(cv2, "QRCodeEncoder_create"):
        pytest.skip("OpenCV QR encoder/detector is not available")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cm_send_receive_restores_original_file_and_reports(tmp_path: Path) -> None:
    _require_qr_backend()
    key_path = tmp_path / "key.bin"
    plain_path = tmp_path / "secret.bin"
    send_dir = tmp_path / "send"
    receive_dir = tmp_path / "receive"
    restored_path = tmp_path / "restored.bin"
    key_path.write_bytes(KEY)
    plain = b"cross media e2e\n" + bytes(range(256)) * 2
    plain_path.write_bytes(plain)

    send = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "send",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--output-dir",
            str(send_dir),
            "--mode",
            "qr",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    receive = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "receive",
            "--image-input",
            str(send_dir / "pages"),
            "--key-file",
            str(key_path),
            "--output",
            str(restored_path),
            "--work-dir",
            str(receive_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert restored_path.read_bytes() == plain
    assert _sha256(restored_path) == _sha256(plain_path)
    assert "input_sha256=" in send.stdout
    assert "output_sha256=" in receive.stdout

    send_report = json.loads((send_dir / "send_report.json").read_text(encoding="utf-8"))
    manifest = json.loads((send_dir / "manifest.json").read_text(encoding="utf-8"))
    scan_report = json.loads((receive_dir / "scan_report.json").read_text(encoding="utf-8"))
    decrypt_report = json.loads((receive_dir / "decrypt_report.json").read_text(encoding="utf-8"))
    assert send_report["success"] is True
    assert send_report["input_sha256"] == _sha256(plain_path)
    assert send_report["payload_sox1"] == str(send_dir / "payload.sox1")
    assert send_report["capture_guide_image"] == str(send_dir / "capture_guide.png")
    assert (send_dir / "capture_guide.png").exists()
    assert manifest["capture_guide_image"] == "capture_guide.png"
    assert manifest["capture_guide"]["contains_key_material"] is False
    assert scan_report["success"] is True
    assert scan_report["missing_chunks"] == []
    assert decrypt_report["success"] is True
    assert decrypt_report["output_sha256"] == _sha256(plain_path)
    assert decrypt_report["output_size"] == len(plain)
    assert (receive_dir / "recovered.sox1").exists()


def test_cm_send_receive_simulated_photo_default_chunk_roundtrip(tmp_path: Path) -> None:
    _require_qr_backend()
    key_path = tmp_path / "key.bin"
    plain_path = tmp_path / "secret.txt"
    send_dir = tmp_path / "send"
    photos_dir = tmp_path / "photos"
    receive_dir = tmp_path / "receive"
    restored_path = tmp_path / "restored.txt"
    key_path.write_bytes(KEY)
    plain_path.write_text("hello cross media encrypted transport", encoding="utf-8")

    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "send",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--output-dir",
            str(send_dir),
            "--mode",
            "qr",
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "scripts/simulate_capture_distortions.py",
            "--input",
            str(send_dir / "pages"),
            "--output",
            str(photos_dir),
            "--jpeg-quality",
            "85",
            "--rotate-deg",
            "1.0",
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "receive",
            "--image-input",
            str(photos_dir),
            "--key-file",
            str(key_path),
            "--output",
            str(restored_path),
            "--work-dir",
            str(receive_dir),
        ],
        check=True,
    )

    assert restored_path.read_bytes() == plain_path.read_bytes()
    send_report = json.loads((send_dir / "send_report.json").read_text(encoding="utf-8"))
    scan_report = json.loads((receive_dir / "scan_report.json").read_text(encoding="utf-8"))
    assert send_report["chunk_chars"] == 450
    assert scan_report["success"] is True
    assert scan_report["missing_chunks"] == []


def test_cm_send_no_debug_sox1_omits_payload_file(tmp_path: Path) -> None:
    _require_qr_backend()
    key_path = tmp_path / "key.bin"
    plain_path = tmp_path / "secret.bin"
    send_dir = tmp_path / "send_no_debug"
    key_path.write_bytes(KEY)
    plain_path.write_bytes(b"no debug sox1 path")

    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "send",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--output-dir",
            str(send_dir),
        ],
        check=True,
    )
    assert (send_dir / "payload.sox1").exists()

    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "send",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--output-dir",
            str(send_dir),
            "--no-debug-sox1",
        ],
        check=True,
    )

    report = json.loads((send_dir / "send_report.json").read_text(encoding="utf-8"))
    assert report["success"] is True
    assert report["payload_sox1"] is None
    assert not (send_dir / "payload.sox1").exists()
    assert list((send_dir / "pages").glob("page_*.png"))


def test_cm_send_multi_qr_repeated_layout_reduces_pages_and_receives(tmp_path: Path) -> None:
    _require_qr_backend()
    key_path = tmp_path / "key.bin"
    plain_path = tmp_path / "secret.bin"
    send_dir = tmp_path / "send_multi"
    receive_dir = tmp_path / "receive_multi"
    restored_path = tmp_path / "restored.bin"
    key_path.write_bytes(KEY)
    plain = (b"multi qr repeated e2e" * 12) + bytes(range(256))
    plain_path.write_bytes(plain)

    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "send",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--output-dir",
            str(send_dir),
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
            "receive",
            "--image-input",
            str(send_dir / "pages"),
            "--key-file",
            str(key_path),
            "--output",
            str(restored_path),
            "--work-dir",
            str(receive_dir),
        ],
        check=True,
    )

    assert restored_path.read_bytes() == plain
    send_report = json.loads((send_dir / "send_report.json").read_text(encoding="utf-8"))
    manifest = json.loads((send_dir / "manifest.json").read_text(encoding="utf-8"))
    scan_report = json.loads((receive_dir / "scan_report.json").read_text(encoding="utf-8"))
    assert send_report["qrs_per_page"] == 6
    assert send_report["repeat_copies"] == 3
    assert send_report["pages"] == manifest["page_count"]
    assert manifest["page_count"] < manifest["transmissions_total"]
    assert scan_report["success"] is True
    assert scan_report["duplicates"] >= manifest["chunks_total"]


def test_cm_receive_wrong_key_fails_and_writes_decrypt_report(tmp_path: Path) -> None:
    _require_qr_backend()
    key_path = tmp_path / "key.bin"
    wrong_key_path = tmp_path / "wrong.bin"
    plain_path = tmp_path / "secret.bin"
    send_dir = tmp_path / "send"
    receive_dir = tmp_path / "receive_wrong"
    restored_path = tmp_path / "restored.bin"
    key_path.write_bytes(KEY)
    wrong_key_path.write_bytes(WRONG_KEY)
    plain_path.write_bytes(b"wrong key receive should fail")
    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "send",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--output-dir",
            str(send_dir),
        ],
        check=True,
    )

    result = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "receive",
            "--image-input",
            str(send_dir / "pages"),
            "--key-file",
            str(wrong_key_path),
            "--output",
            str(restored_path),
            "--work-dir",
            str(receive_dir),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 11
    assert not restored_path.exists()
    assert (receive_dir / "recovered.sox1").exists()
    scan_report = json.loads((receive_dir / "scan_report.json").read_text(encoding="utf-8"))
    decrypt_report = json.loads((receive_dir / "decrypt_report.json").read_text(encoding="utf-8"))
    assert scan_report["success"] is True
    assert decrypt_report["success"] is False
    assert decrypt_report["reason"] == "authenticated_decryption_failed"


def test_simulate_capture_distortions_script_outputs_jpegs(tmp_path: Path) -> None:
    image_module = pytest.importorskip("PIL.Image")
    input_dir = tmp_path / "pages"
    output_dir = tmp_path / "photos"
    input_dir.mkdir()
    image = image_module.new("RGB", (160, 120), "white")
    image.save(input_dir / "page_0001.png")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/simulate_capture_distortions.py",
            "--input",
            str(input_dir),
            "--output",
            str(output_dir),
            "--jpeg-quality",
            "85",
            "--rotate-deg",
            "1.0",
            "--scale",
            "0.75",
            "--blur-radius",
            "0.5",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    report = json.loads(result.stdout)
    outputs = sorted(output_dir.glob("capture_*.jpg"))
    assert report["schema"] == "enc2sop-cross-media-simulated-capture/v1"
    assert report["success"] is True
    assert report["image_count"] == 1
    assert report["jpeg_quality"] == 85
    assert report["rotate_deg"] == 1.0
    assert report["scale"] == 0.75
    assert report["blur_radius"] == 0.5
    assert len(outputs) == 1
    assert outputs[0].stat().st_size > 0

def test_linux_shell_smoke_script_matches_documented_flow() -> None:
    script = Path("scripts/crossmedia_smoke.sh")
    text = script.read_text(encoding="utf-8")

    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text
    assert "SOENC_CM_SMOKE_WORK" in text
    assert "python soenc.py cm keygen" in text
    assert "python soenc.py cm send" in text
    assert "python scripts/simulate_capture_distortions.py" in text
    assert "python soenc.py cm receive" in text
    assert "hashlib.sha256" in text
    assert "CROSSMEDIA_SMOKE_OK" in text

