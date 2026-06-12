# -*- coding: utf-8 -*-
"""Tests for P2-B assistive-only visual model boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from enc2sop.crossmedia import cli as crossmedia_cli
from enc2sop.crossmedia import image_scan
from enc2sop.crossmedia import visual_assist


def test_visual_assist_rejects_provider_payload_or_verifier_override() -> None:
    with pytest.raises(visual_assist.VisualAssistError, match="forbidden"):
        visual_assist.sanitize_provider_report(
            {
                "provider_name": "unsafe-model",
                "images": [
                    {
                        "path": "page.png",
                        "payload": "SOX1QR|provider must not supply payload guesses",
                    }
                ],
            }
        )

    with pytest.raises(visual_assist.VisualAssistError, match="forbidden"):
        visual_assist.sanitize_provider_report(
            {
                "provider_name": "unsafe-model",
                "images": [
                    {
                        "path": "page.png",
                        "verifier_override": True,
                    }
                ],
            }
        )


def test_visual_assist_cli_writes_report_with_untrusted_provider_hints(tmp_path: Path) -> None:
    photos_dir = tmp_path / "photos"
    photos_dir.mkdir()
    (photos_dir / "page.png").write_bytes(b"not a real image but still a listed capture file")
    provider_report = tmp_path / "provider.json"
    provider_report.write_text(
        json.dumps(
            {
                "provider_name": "safe-vision-fixture",
                "images": [
                    {
                        "path": "page.png",
                        "qr_regions": [
                            {"bbox": [10, 20, 200, 210], "confidence": 0.85}
                        ],
                        "quality": {"blur": {"status": "warning"}, "crop": {"status": "ok"}},
                        "ocr_candidates": [{"text": "candidate text only", "confidence": 0.5}],
                        "retake_suggestions": ["retake with less reflection"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output_report = tmp_path / "visual_assist.json"

    exit_code = crossmedia_cli.main(
        [
            "visual-assist",
            "--image-input",
            str(photos_dir),
            "--provider-report",
            str(provider_report),
            "--output-report",
            str(output_report),
        ]
    )

    assert exit_code == 0
    report = json.loads(output_report.read_text(encoding="utf-8"))
    assert report["schema"] == visual_assist.VISUAL_ASSIST_SCHEMA
    assert report["provider_report"]["accepted"] is True
    assert "bypass_verifier" in report["forbidden_roles"]
    assert "decrypt" in report["verifier_boundary"]
    image = report["images"][0]
    assert image["provider_hints_accepted"] is True
    assert image["qr_region_hints"][0]["source"] == "provider"
    assert image["ocr_candidate_hints"][0]["untrusted"] is True
    assert image["ocr_candidate_hints"][0]["role"] == "ocr_candidate_generation"
    assert image["quality"]["schema"] == image_scan.IMAGE_QUALITY_SCHEMA
    assert "retake with less reflection" in image["retake_suggestions"]


def test_visual_assist_local_quality_generates_retake_guidance(tmp_path: Path) -> None:
    pytest.importorskip("cv2")
    image_module = pytest.importorskip("PIL.Image")
    photos_dir = tmp_path / "bad_photos"
    photos_dir.mkdir()
    image_module.new("RGB", (640, 640), "white").save(photos_dir / "blank_overexposed.jpg", quality=90)

    report = visual_assist.build_visual_assist_report(photos_dir)

    assert report["success"] is True
    assert report["allowed_roles"] == visual_assist.VISUAL_ASSIST_ALLOWED_ROLES
    assert report["image_count"] == 1
    image = report["images"][0]
    assert image["quality"]["exposure"]["status"] == "overexposed"
    assert image["photo_assessment"]["glare"]["status"] == "risk"
    assert any("glare/overexposure" in item for item in image["retake_suggestions"])
    assert image["verifier_boundary"] == visual_assist.VISUAL_ASSIST_BOUNDARY
