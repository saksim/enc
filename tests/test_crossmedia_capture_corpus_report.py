#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for P1-S4 capture corpus robustness reporting."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from enc2sop.crossmedia import crypto_envelope
from enc2sop.crossmedia import qr_transport


KEY = bytes(range(32))


def _require_qr_backend() -> None:
    cv2 = pytest.importorskip("cv2")
    pytest.importorskip("PIL")
    if not hasattr(cv2, "QRCodeDetector") or not hasattr(cv2, "QRCodeEncoder_create"):
        pytest.skip("OpenCV QR encoder/detector is not available")


def test_capture_corpus_report_scores_success_and_failure_cases(tmp_path: Path) -> None:
    _require_qr_backend()
    image_module = pytest.importorskip("PIL.Image")
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(
        (b"capture corpus secret" * 20) + bytes(range(128)),
        key=KEY,
        name="capture.bin",
        created_at_utc="2026-06-09T00:00:00Z",
    )
    expected_path = tmp_path / "expected.sox1"
    rendered_dir = tmp_path / "rendered"
    corpus_dir = tmp_path / "corpus"
    good_case = corpus_dir / "good_phone"
    blank_case = corpus_dir / "blank_phone"
    report_path = tmp_path / "capture_report.json"
    expected_path.write_text(sox1 + "\n", encoding="utf-8")

    manifest = qr_transport.render_qr_pages(sox1, rendered_dir, chunk_chars=200)
    good_case.mkdir(parents=True)
    blank_case.mkdir(parents=True)
    for page in sorted((rendered_dir / "pages").glob("page_*.png")):
        shutil.copy2(page, good_case / page.name)
    image_module.new("RGB", (720, 720), "white").save(blank_case / "blank.jpg", quality=90)

    result = subprocess.run(
        [
            sys.executable,
            "scripts/crossmedia_capture_corpus_report.py",
            "--corpus",
            str(corpus_dir),
            "--expected-sox1-file",
            str(expected_path),
            "--output",
            str(report_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 20
    assert "capture_corpus_report=" in result.stdout
    report_text = report_path.read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["schema"] == "enc2sop-cross-media-capture-corpus-report/v1"
    assert report["success"] is False
    assert report["case_count"] == 2
    assert report["successful_cases"] == 1
    assert report["complete_cases"] == 1
    assert report["failed_cases"] == 1
    assert report["expected_artifact_id"] == manifest["artifact_id"]
    assert report["robustness"]["success_rate"] == 0.5
    assert report["robustness"]["total_images"] == manifest["page_count"] + 1

    cases = {case["case"]: case for case in report["cases"]}
    good = cases["good_phone"]
    blank = cases["blank_phone"]
    assert good["success"] is True
    assert good["complete"] is True
    assert good["expected_match"] is True
    assert good["missing_chunks"] == []
    assert good["chunks_total"] == manifest["chunks_total"]
    assert blank["success"] is False
    assert blank["reason"] == "no_valid_qr_chunks"
    assert blank["quality_summary"]["exposure_status_counts"]["overexposed"] == 1
    assert blank["bad_images"][0]["quality"]["schema"] == "enc2sop-cross-media-image-quality/v1"

    assert "capture corpus secret" not in report_text
    assert KEY.hex() not in report_text
