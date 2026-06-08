#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""OpenCV/Pillow QR image scanning for SOX1 visual transport."""

from __future__ import annotations

from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import List
from typing import Tuple

from . import qr_transport


class ImageScanError(ValueError):
    """Raised when an image input path cannot be scanned safely."""


def _load_cv2():
    try:
        import cv2
    except Exception as exc:  # pragma: no cover - exercised only in missing dependency envs
        raise RuntimeError("OpenCV (cv2) is required for P0 QR scan") from exc
    if not hasattr(cv2, "QRCodeDetector"):
        raise RuntimeError("OpenCV QRCodeDetector is required for P0 QR scan")
    return cv2


def _load_pil_modules():
    try:
        from PIL import Image, ImageOps
    except Exception as exc:  # pragma: no cover - exercised only in missing dependency envs
        raise RuntimeError("Pillow is required for P0 QR scan") from exc
    return Image, ImageOps


def list_image_files(image_input: Path) -> List[Path]:
    """Return supported images directly under the explicit image-input directory.

    P0 intentionally avoids recursive traversal so ``--image-input`` cannot
    accidentally enumerate unrelated user directories.
    """

    root = Path(image_input)
    if not root.exists():
        raise ImageScanError("image input not found: {0}".format(root))
    if not root.is_dir():
        raise ImageScanError("image input must be a directory for P0 scan: {0}".format(root))
    images = [
        item
        for item in root.iterdir()
        if item.is_file() and item.suffix.lower() in qr_transport.IMAGE_SUFFIXES
    ]
    return sorted(images, key=lambda item: item.name.lower())


def _relative_report_path(path: Path, root: Path) -> str:
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return Path(path).name


def _dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _pil_image_to_bgr_array(path: Path):
    _image_module, image_ops = _load_pil_modules()
    import numpy as np

    with _image_module.open(path) as opened:
        image = image_ops.exif_transpose(opened).convert("RGB")
    rgb = np.asarray(image)
    cv2 = _load_cv2()
    return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)


def _candidate_arrays(bgr_image):
    cv2 = _load_cv2()
    yield bgr_image
    height, width = bgr_image.shape[:2]
    for crop in _page_crop_candidates(bgr_image):
        yield crop
        crop_height, crop_width = crop.shape[:2]
        for scale in (0.5, 0.75, 1.5):
            scaled_size = (max(1, int(crop_width * scale)), max(1, int(crop_height * scale)))
            yield cv2.resize(crop, scaled_size, interpolation=cv2.INTER_CUBIC)
    for scale in (0.75, 1.5, 2.0):
        scaled_size = (max(1, int(width * scale)), max(1, int(height * scale)))
        yield cv2.resize(bgr_image, scaled_size, interpolation=cv2.INTER_CUBIC)
    for angle in (-2.0, -1.0, 1.0, 2.0):
        yield _rotate_keep_bound(bgr_image, angle)
    gray = cv2.cvtColor(bgr_image, cv2.COLOR_BGR2GRAY)
    yield gray
    for angle in (-2.0, -1.0, 1.0, 2.0):
        yield _rotate_keep_bound(gray, angle)
    yield cv2.GaussianBlur(gray, (3, 3), 0)
    yield cv2.adaptiveThreshold(
        gray,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        2,
    )


def _page_crop_candidates(image_array):
    height, width = image_array.shape[:2]
    boxes = [
        (0, 0, width, max(1, height - int(height * 0.07))),
        (0, 0, width, max(1, height - int(height * 0.10))),
        (0, int(height * 0.08), width, max(int(height * 0.08) + 1, height - int(height * 0.07))),
        (int(width * 0.03), 0, max(int(width * 0.03) + 1, width - int(width * 0.03)), height),
    ]
    side = min(width, height)
    left = max(0, (width - side) // 2)
    top = max(0, (height - side) // 2)
    boxes.append((left, top, left + side, top + side))
    seen = set()
    for left, top, right, bottom in boxes:
        left = max(0, min(int(left), width - 1))
        top = max(0, min(int(top), height - 1))
        right = max(left + 1, min(int(right), width))
        bottom = max(top + 1, min(int(bottom), height))
        key = (left, top, right, bottom)
        if key in seen or (right - left) < 100 or (bottom - top) < 100:
            continue
        seen.add(key)
        yield image_array[top:bottom, left:right]


def _rotate_keep_bound(image_array, angle: float):
    cv2 = _load_cv2()
    height, width = image_array.shape[:2]
    center = (width / 2.0, height / 2.0)
    matrix = cv2.getRotationMatrix2D(center, float(angle), 1.0)
    cos = abs(matrix[0, 0])
    sin = abs(matrix[0, 1])
    new_width = int((height * sin) + (width * cos))
    new_height = int((height * cos) + (width * sin))
    matrix[0, 2] += (new_width / 2.0) - center[0]
    matrix[1, 2] += (new_height / 2.0) - center[1]
    return cv2.warpAffine(
        image_array,
        matrix,
        (new_width, new_height),
        flags=cv2.INTER_CUBIC,
        borderMode=cv2.BORDER_CONSTANT,
        borderValue=255,
    )


def _decode_from_array(detector, image_array) -> List[str]:
    decoded: List[str] = []
    if hasattr(detector, "detectAndDecodeMulti"):
        try:
            multi = detector.detectAndDecodeMulti(image_array)
        except Exception:
            multi = None
        if multi:
            ok = bool(multi[0])
            infos = multi[1] if len(multi) > 1 else []
            if ok:
                decoded.extend(str(item) for item in infos if str(item or "").strip())
    try:
        single = detector.detectAndDecode(image_array)
    except Exception:
        single = None
    if single:
        text = single[0] if isinstance(single, tuple) else single
        if str(text or "").strip():
            decoded.append(str(text))
    return _dedupe_preserve_order(decoded)


def scan_image_file(path: Path) -> Tuple[List[str], str | None]:
    """Scan one image and return decoded SOX1QR payload candidates plus reason.

    The reason is ``None`` on at least one parseable SOX1QR payload; otherwise it
    is suitable for ``scan_report.json`` bad_images entries.
    """

    cv2 = _load_cv2()
    detector = cv2.QRCodeDetector()
    try:
        bgr = _pil_image_to_bgr_array(Path(path))
    except Exception as exc:
        return [], "image_read_failed: {0}".format(exc)

    decoded: List[str] = []
    for candidate in _candidate_arrays(bgr):
        decoded = _decode_from_array(detector, candidate)
        if decoded:
            break
    payloads = [item for item in decoded if item.startswith(qr_transport.QR_MAGIC + "|")]
    if not payloads:
        return [], "qr_not_found_or_not_sox1qr"

    parseable: List[str] = []
    parse_errors: List[str] = []
    for payload in payloads:
        try:
            qr_transport.parse_qr_payload(payload)
        except qr_transport.QrPayloadError as exc:
            parse_errors.append(str(exc))
            parseable.append(payload)
        else:
            parseable.append(payload)
    if parse_errors and len(parse_errors) == len(payloads):
        return parseable, "qr_payload_parse_or_crc_failed"
    return _dedupe_preserve_order(parseable), None


def scan_image_input(image_input: Path) -> Tuple[List[str], Dict[str, object]]:
    root = Path(image_input)
    images = list_image_files(root)
    payloads: List[str] = []
    bad_images: List[Dict[str, object]] = []
    for image_path in images:
        decoded, reason = scan_image_file(image_path)
        payloads.extend(decoded)
        if reason is not None:
            bad_images.append(
                {
                    "path": _relative_report_path(image_path, root),
                    "reason": reason,
                    "suggestion": "retake closer, keep the full QR border visible, avoid glare and motion blur",
                }
            )
    return payloads, {
        "image_count": len(images),
        "payload_count": len(payloads),
        "bad_images": bad_images,
    }


__all__ = [
    "ImageScanError",
    "list_image_files",
    "scan_image_file",
    "scan_image_input",
]
