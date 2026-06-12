#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Simulate simple camera/screenshot distortions for cross-media QR smoke tests.

P0 scope is intentionally small: process only files directly under an explicit
input directory, emit deterministic ``capture_XXXX.jpg`` files, and support the
four distortion knobs required by the construction guide.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}
REPORT_SCHEMA = "enc2sop-cross-media-simulated-capture/v1"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Simulate P0 cross-media capture distortions for QR page images.",
    )
    parser.add_argument("--input", required=True, help="Directory containing rendered page images.")
    parser.add_argument("--output", required=True, help="Directory for simulated captured images.")
    parser.add_argument("--jpeg-quality", type=int, default=85, help="JPEG quality, 1..100. Default: 85.")
    parser.add_argument("--rotate-deg", type=float, default=0.0, help="Clockwise rotation in degrees.")
    parser.add_argument("--scale", type=float, default=1.0, help="Scale factor before rotation. Default: 1.0.")
    parser.add_argument("--blur-radius", type=float, default=0.0, help="Gaussian blur radius. Default: 0.0.")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not 1 <= int(args.jpeg_quality) <= 100:
        parser.error("--jpeg-quality must be between 1 and 100")
    if float(args.scale) <= 0:
        parser.error("--scale must be greater than 0")
    if float(args.blur_radius) < 0:
        parser.error("--blur-radius must be greater than or equal to 0")


def _list_input_images(input_dir: Path) -> list[Path]:
    if not input_dir.exists():
        raise FileNotFoundError("input directory not found: {0}".format(input_dir))
    if not input_dir.is_dir():
        raise NotADirectoryError("input path must be a directory: {0}".format(input_dir))
    return sorted(
        (
            item
            for item in input_dir.iterdir()
            if item.is_file() and item.suffix.lower() in IMAGE_SUFFIXES
        ),
        key=lambda item: item.name.lower(),
    )


def _remove_stale_generated_files(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for item in output_dir.iterdir():
        if item.is_file() and item.name.startswith("capture_") and item.suffix.lower() in IMAGE_SUFFIXES:
            item.unlink()


def _resample(image_module, name: str):
    resampling = getattr(image_module, "Resampling", None)
    if resampling is not None:
        return getattr(resampling, name)
    return getattr(image_module, name)


def _process_images(
    *,
    inputs: Iterable[Path],
    output_dir: Path,
    jpeg_quality: int,
    rotate_deg: float,
    scale: float,
    blur_radius: float,
) -> list[Path]:
    try:
        from PIL import Image, ImageFilter, ImageOps
    except Exception as exc:  # pragma: no cover - depends on local optional deps
        raise RuntimeError("Pillow is required for simulated capture distortions") from exc

    outputs: list[Path] = []
    for index, input_path in enumerate(inputs, start=1):
        with Image.open(input_path) as opened:
            image = ImageOps.exif_transpose(opened).convert("RGB")

        if scale != 1.0:
            width, height = image.size
            size = (max(1, int(round(width * scale))), max(1, int(round(height * scale))))
            image = image.resize(size, resample=_resample(Image, "LANCZOS"))

        if rotate_deg:
            image = image.rotate(
                -float(rotate_deg),
                resample=_resample(Image, "BICUBIC"),
                expand=True,
                fillcolor="white",
            )

        if blur_radius > 0:
            image = image.filter(ImageFilter.GaussianBlur(radius=float(blur_radius)))

        output_path = output_dir / "capture_{0:04d}.jpg".format(index)
        image.save(str(output_path), format="JPEG", quality=int(jpeg_quality))
        outputs.append(output_path)
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _validate_args(parser, args)

    input_dir = Path(args.input)
    output_dir = Path(args.output)
    try:
        inputs = _list_input_images(input_dir)
        if not inputs:
            print("simulate capture error: no supported images found in {0}".format(input_dir), file=sys.stderr)
            return 30
        _remove_stale_generated_files(output_dir)
        outputs = _process_images(
            inputs=inputs,
            output_dir=output_dir,
            jpeg_quality=int(args.jpeg_quality),
            rotate_deg=float(args.rotate_deg),
            scale=float(args.scale),
            blur_radius=float(args.blur_radius),
        )
    except RuntimeError as exc:
        print("simulate capture optional dependency error: {0}".format(exc), file=sys.stderr)
        return 40
    except OSError as exc:
        print("simulate capture file error: {0}".format(exc), file=sys.stderr)
        return 30

    report = {
        "schema": REPORT_SCHEMA,
        "success": True,
        "input_dir": str(input_dir),
        "output_dir": str(output_dir),
        "image_count": len(inputs),
        "output_count": len(outputs),
        "jpeg_quality": int(args.jpeg_quality),
        "rotate_deg": float(args.rotate_deg),
        "scale": float(args.scale),
        "blur_radius": float(args.blur_radius),
        "outputs": [path.name for path in outputs],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
