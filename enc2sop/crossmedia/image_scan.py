#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""OpenCV/Pillow QR image scanning for SOX1 visual transport."""

from __future__ import annotations

from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
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
    height, width = bgr_image.shape[:2]
    for corrected_page in _page_perspective_candidates(bgr_image):
        yield corrected_page
        page_height, page_width = corrected_page.shape[:2]
        if max(page_width, page_height) < 1800:
            scaled_size = (max(1, int(page_width * 1.25)), max(1, int(page_height * 1.25)))
            yield cv2.resize(corrected_page, scaled_size, interpolation=cv2.INTER_CUBIC)
    page_crops = list(_page_crop_candidates(bgr_image))
    for crop in page_crops:
        yield crop
        crop_height, crop_width = crop.shape[:2]
        for scale in (0.75, 1.5):
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
    for source in (bgr_image, *page_crops):
        for tile in _multi_qr_tile_candidates(source):
            yield tile


def _page_perspective_candidates(image_array):
    cv2 = _load_cv2()
    import numpy as np

    gray = cv2.cvtColor(image_array, cv2.COLOR_BGR2GRAY) if len(image_array.shape) == 3 else image_array
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    masks = []
    _threshold, bright = cv2.threshold(blurred, 180, 255, cv2.THRESH_BINARY)
    masks.append(bright)
    edges = cv2.Canny(blurred, 50, 150)
    edges = cv2.dilate(edges, np.ones((5, 5), dtype=np.uint8), iterations=1)
    masks.append(edges)
    image_area = float(max(1, image_array.shape[0] * image_array.shape[1]))
    candidates: List[object] = []
    for mask in masks:
        contours_info = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        contours = contours_info[0] if len(contours_info) == 2 else contours_info[1]
        for contour in contours:
            area = float(cv2.contourArea(contour))
            if area < image_area * 0.12 or area > image_area * 0.98:
                continue
            perimeter = cv2.arcLength(contour, True)
            approx = cv2.approxPolyDP(contour, 0.025 * perimeter, True)
            if len(approx) == 4:
                candidates.append(approx.reshape(4, 2))
                continue
            rect = cv2.minAreaRect(contour)
            box = cv2.boxPoints(rect)
            if abs(float(cv2.contourArea(box))) >= image_area * 0.12:
                candidates.append(box)
    for points in _dedupe_point_sets(candidates):
        warped = _warp_quad_region(image_array, points, min_width=320, min_height=320)
        if warped is not None:
            yield warped


def _warp_quad_region(image_array, points: object, *, min_width: int, min_height: int):
    cv2 = _load_cv2()
    import numpy as np

    try:
        ordered = _order_quad_points(points)
    except Exception:
        return None
    area = abs(float(cv2.contourArea(ordered)))
    if area < float(min_width * min_height) * 0.25:
        return None
    width_top = float(np.linalg.norm(ordered[1] - ordered[0]))
    width_bottom = float(np.linalg.norm(ordered[2] - ordered[3]))
    height_right = float(np.linalg.norm(ordered[2] - ordered[1]))
    height_left = float(np.linalg.norm(ordered[3] - ordered[0]))
    out_width = int(round(max(width_top, width_bottom)))
    out_height = int(round(max(height_right, height_left)))
    if out_width < int(min_width) or out_height < int(min_height):
        return None
    target = np.array(
        [
            [0, 0],
            [out_width - 1, 0],
            [out_width - 1, out_height - 1],
            [0, out_height - 1],
        ],
        dtype="float32",
    )
    matrix = cv2.getPerspectiveTransform(ordered, target)
    border_value = 255 if len(image_array.shape) == 2 else (255, 255, 255)
    return cv2.warpPerspective(
        image_array,
        matrix,
        (out_width, out_height),
        flags=cv2.INTER_CUBIC,
        borderMode=cv2.BORDER_CONSTANT,
        borderValue=border_value,
    )


def _multi_qr_tile_candidates(image_array):
    for tile in _generated_layout_slot_candidates(image_array):
        yield tile
    height, width = image_array.shape[:2]
    margin_x = int(width * 0.02)
    margin_y = int(height * 0.06)
    for rows, cols in _likely_multi_qr_grids(image_array):
        usable_left = margin_x
        usable_top = margin_y
        usable_right = width - margin_x
        usable_bottom = height - margin_y
        usable_width = max(1, usable_right - usable_left)
        usable_height = max(1, usable_bottom - usable_top)
        for row in range(rows):
            for col in range(cols):
                left = usable_left + int((col / cols) * usable_width)
                right = usable_left + int(((col + 1) / cols) * usable_width)
                top = usable_top + int((row / rows) * usable_height)
                bottom = usable_top + int(((row + 1) / rows) * usable_height)
                pad_x = int((right - left) * 0.10)
                pad_y = int((bottom - top) * 0.10)
                left = max(0, left - pad_x)
                right = min(width, right + pad_x)
                top = max(0, top - pad_y)
                bottom = min(height, bottom + pad_y)
                if (right - left) < 120 or (bottom - top) < 120:
                    continue
                yield image_array[top:bottom, left:right]


def _generated_layout_slot_candidates(image_array):
    """Yield deterministic crops for pages generated by ``qr_transport``.

    These constants mirror the renderer's page geometry.  They are intentionally
    used only as scan candidates; photos that deviate from the exact generated
    image still fall back to proportional crops and the general retry pipeline.
    """

    height, width = image_array.shape[:2]
    margin = 48
    cell_gap = 34
    header_height = 170
    footer_height = 118
    if width <= margin * 2 or height <= header_height + footer_height:
        return
    for rows, cols in _likely_multi_qr_grids(image_array):
        usable_width = width - (margin * 2) - ((cols - 1) * cell_gap)
        usable_height = height - header_height - footer_height - ((rows - 1) * cell_gap)
        if usable_width <= 0 or usable_height <= 0:
            continue
        cell_width = usable_width / float(cols)
        cell_height = usable_height / float(rows)
        if cell_width < 120 or cell_height < 120:
            continue
        for row in range(rows):
            for col in range(cols):
                left = int(round(margin + col * (cell_width + cell_gap)))
                top = int(round(header_height + row * (cell_height + cell_gap)))
                right = int(round(left + cell_width))
                bottom = int(round(top + cell_height))
                pad_x = int(cell_width * 0.04)
                pad_y = int(cell_height * 0.04)
                left = max(0, left - pad_x)
                top = max(0, top - pad_y)
                right = min(width, right + pad_x)
                bottom = min(height, bottom + pad_y)
                if (right - left) < 120 or (bottom - top) < 120:
                    continue
                yield image_array[top:bottom, left:right]


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
    decoded, _points = _decode_from_array_with_points(detector, image_array)
    return decoded


def _decode_from_array_with_points(detector, image_array) -> Tuple[List[str], List[object]]:
    decoded: List[str] = []
    point_sets: List[object] = []
    if hasattr(detector, "detectAndDecodeMulti"):
        try:
            multi = detector.detectAndDecodeMulti(image_array)
        except Exception:
            multi = None
        if multi:
            ok = bool(multi[0])
            infos = multi[1] if len(multi) > 1 else []
            if len(multi) > 2:
                point_sets.extend(_normalize_qr_point_sets(multi[2]))
            if ok:
                decoded.extend(str(item) for item in infos if str(item or "").strip())
    try:
        single = detector.detectAndDecode(image_array)
    except Exception:
        single = None
    if single:
        text = single[0] if isinstance(single, tuple) else single
        if isinstance(single, tuple) and len(single) > 1:
            point_sets.extend(_normalize_qr_point_sets(single[1]))
        if str(text or "").strip():
            decoded.append(str(text))
    return _dedupe_preserve_order(decoded), _dedupe_point_sets(point_sets)


def _normalize_qr_point_sets(points: object) -> List[object]:
    if points is None:
        return []
    try:
        import numpy as np

        arr = np.asarray(points, dtype="float32")
    except Exception:
        return []
    if arr.size == 0:
        return []
    arr = arr.squeeze()
    point_sets: List[object] = []
    if arr.ndim == 2 and arr.shape[0] >= 4 and arr.shape[1] >= 2:
        point_sets.append(arr[:4, :2])
    elif arr.ndim == 3 and arr.shape[-2] >= 4 and arr.shape[-1] >= 2:
        for item in arr:
            point_sets.append(item[:4, :2])
    return point_sets


def _dedupe_point_sets(point_sets: Iterable[object]) -> List[object]:
    result: List[object] = []
    seen = set()
    for points in point_sets:
        try:
            import numpy as np

            arr = np.asarray(points, dtype="float32").reshape(4, 2)
        except Exception:
            continue
        key = tuple(round(float(value), 1) for value in arr.flatten())
        if key in seen:
            continue
        seen.add(key)
        result.append(arr)
    return result


def _detect_only_qr_point_sets(detector, image_array) -> List[object]:
    point_sets: List[object] = []
    if hasattr(detector, "detectMulti"):
        try:
            detected = detector.detectMulti(image_array)
        except Exception:
            detected = None
        if detected:
            ok = bool(detected[0])
            if ok and len(detected) > 1:
                point_sets.extend(_normalize_qr_point_sets(detected[1]))
    if hasattr(detector, "detect"):
        try:
            detected = detector.detect(image_array)
        except Exception:
            detected = None
        if detected:
            ok = bool(detected[0])
            if ok and len(detected) > 1:
                point_sets.extend(_normalize_qr_point_sets(detected[1]))
    return _dedupe_point_sets(point_sets)


def _order_quad_points(points: object):
    import numpy as np

    arr = np.asarray(points, dtype="float32").reshape(4, 2)
    ordered = np.zeros((4, 2), dtype="float32")
    sums = arr.sum(axis=1)
    diffs = np.diff(arr, axis=1).reshape(-1)
    ordered[0] = arr[int(np.argmin(sums))]
    ordered[2] = arr[int(np.argmax(sums))]
    ordered[1] = arr[int(np.argmin(diffs))]
    ordered[3] = arr[int(np.argmax(diffs))]
    return ordered


def _perspective_warp_qr_candidate(image_array, points: object):
    cv2 = _load_cv2()
    import numpy as np

    try:
        ordered = _order_quad_points(points)
    except Exception:
        return None
    area = abs(float(cv2.contourArea(ordered)))
    if area < 2500.0:
        return None

    width_top = float(np.linalg.norm(ordered[1] - ordered[0]))
    width_bottom = float(np.linalg.norm(ordered[2] - ordered[3]))
    height_right = float(np.linalg.norm(ordered[2] - ordered[1]))
    height_left = float(np.linalg.norm(ordered[3] - ordered[0]))
    side = int(round(max(width_top, width_bottom, height_right, height_left)))
    if side < 80:
        return None
    quiet = max(18, int(round(side * 0.14)))
    output_size = side + (quiet * 2)
    target = np.array(
        [
            [quiet, quiet],
            [quiet + side - 1, quiet],
            [quiet + side - 1, quiet + side - 1],
            [quiet, quiet + side - 1],
        ],
        dtype="float32",
    )
    matrix = cv2.getPerspectiveTransform(ordered, target)
    border_value = 255 if len(image_array.shape) == 2 else (255, 255, 255)
    return cv2.warpPerspective(
        image_array,
        matrix,
        (output_size, output_size),
        flags=cv2.INTER_CUBIC,
        borderMode=cv2.BORDER_CONSTANT,
        borderValue=border_value,
    )


def _perspective_corrected_candidates(image_array, point_sets: Sequence[object]):
    cv2 = _load_cv2()
    for points in _dedupe_point_sets(point_sets):
        warped = _perspective_warp_qr_candidate(image_array, points)
        if warped is None:
            continue
        yield warped
        height, width = warped.shape[:2]
        for scale in (1.5, 2.0):
            scaled_size = (max(1, int(width * scale)), max(1, int(height * scale)))
            yield cv2.resize(warped, scaled_size, interpolation=cv2.INTER_CUBIC)
        gray = cv2.cvtColor(warped, cv2.COLOR_BGR2GRAY) if len(warped.shape) == 3 else warped
        yield gray
        yield cv2.adaptiveThreshold(
            gray,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            31,
            2,
        )


def _decode_from_detected_points(
    detector,
    image_array,
    *,
    point_sets: Optional[Sequence[object]] = None,
) -> List[str]:
    points = list(point_sets or [])
    points.extend(_detect_only_qr_point_sets(detector, image_array))
    decoded: List[str] = []
    for candidate in _perspective_corrected_candidates(image_array, points):
        decoded.extend(_decode_from_array(detector, candidate))
        payloads = [item for item in _dedupe_preserve_order(decoded) if item.startswith(qr_transport.QR_MAGIC + "|")]
        if _payloads_cover_complete_artifact(payloads):
            break
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

    decoded, initial_point_sets = _decode_from_array_with_points(detector, bgr)
    full_page_payloads = [item for item in decoded if item.startswith(qr_transport.QR_MAGIC + "|")]
    if not full_page_payloads:
        decoded.extend(_decode_from_detected_points(detector, bgr, point_sets=initial_point_sets))
    decoded = _dedupe_preserve_order(decoded)
    full_page_payloads = [item for item in decoded if item.startswith(qr_transport.QR_MAGIC + "|")]
    if full_page_payloads:
        likely_capacity = _likely_multi_qr_capacity(bgr)
        if likely_capacity > 1 and len(_dedupe_preserve_order(full_page_payloads)) >= likely_capacity:
            parseable, parse_errors = _classify_sox1qr_payloads(full_page_payloads)
            if parse_errors and len(parse_errors) == len(full_page_payloads):
                return parseable, "qr_payload_parse_or_crc_failed"
            return _dedupe_preserve_order(parseable), None
        if _payloads_cover_complete_artifact(full_page_payloads):
            parseable, parse_errors = _classify_sox1qr_payloads(full_page_payloads)
            if parse_errors and len(parse_errors) == len(full_page_payloads):
                return parseable, "qr_payload_parse_or_crc_failed"
            return _dedupe_preserve_order(parseable), None
        decoded.extend(_decode_multi_qr_slots(detector, bgr, initial_payloads=full_page_payloads))
        full_page_payloads = [item for item in _dedupe_preserve_order(decoded) if item.startswith(qr_transport.QR_MAGIC + "|")]
        parseable, parse_errors = _classify_sox1qr_payloads(full_page_payloads)
        if parse_errors and len(parse_errors) == len(full_page_payloads):
            return parseable, "qr_payload_parse_or_crc_failed"
        return _dedupe_preserve_order(parseable), None

    decoded = list(decoded)
    for candidate in _candidate_arrays(bgr):
        candidate_decoded, candidate_points = _decode_from_array_with_points(detector, candidate)
        decoded.extend(candidate_decoded)
        candidate_payloads = [
            item
            for item in candidate_decoded
            if item.startswith(qr_transport.QR_MAGIC + "|")
        ]
        if candidate_points and not candidate_payloads and not decoded:
            decoded.extend(_decode_from_detected_points(detector, candidate, point_sets=candidate_points))
        current_payloads = [
            item
            for item in _dedupe_preserve_order(decoded)
            if item.startswith(qr_transport.QR_MAGIC + "|")
        ]
        if _has_valid_sox1qr_payload(current_payloads):
            break
    decoded = _dedupe_preserve_order(decoded)
    payloads = [item for item in decoded if item.startswith(qr_transport.QR_MAGIC + "|")]
    if not payloads:
        return [], "qr_not_found_or_not_sox1qr"

    parseable, parse_errors = _classify_sox1qr_payloads(payloads)
    if parse_errors and len(parse_errors) == len(payloads):
        return parseable, "qr_payload_parse_or_crc_failed"
    return _dedupe_preserve_order(parseable), None


def _classify_sox1qr_payloads(payloads: Iterable[str]) -> Tuple[List[str], List[str]]:
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
    return parseable, parse_errors


def _has_valid_sox1qr_payload(payloads: Iterable[str]) -> bool:
    for payload in payloads:
        try:
            qr_transport.parse_qr_payload(payload)
        except qr_transport.QrPayloadError:
            continue
        return True
    return False


def _payloads_cover_complete_artifact(payloads: Iterable[str]) -> bool:
    groups: Dict[str, Dict[str, object]] = {}
    for payload in payloads:
        try:
            chunk = qr_transport.parse_qr_payload(payload)
        except qr_transport.QrPayloadError:
            continue
        group = groups.setdefault(chunk.artifact_id, {"total": chunk.chunk_total, "indices": set()})
        group["indices"].add(chunk.chunk_index)
    return any(len(group["indices"]) == int(group["total"]) for group in groups.values())


def _decode_multi_qr_slots(detector, bgr_image, *, initial_payloads: Iterable[str] = ()) -> List[str]:
    decoded: List[str] = list(initial_payloads)
    cv2 = _load_cv2()
    for tile in _multi_qr_tile_candidates(bgr_image):
        before = len(_dedupe_preserve_order(decoded))
        decoded.extend(_decode_from_array(detector, tile))
        payloads = [item for item in _dedupe_preserve_order(decoded) if item.startswith(qr_transport.QR_MAGIC + "|")]
        if len(payloads) >= _likely_multi_qr_capacity(bgr_image):
            break
        if len(payloads) > before:
            continue
        height, width = tile.shape[:2]
        scaled = cv2.resize(
            tile,
            (max(1, int(width * 1.5)), max(1, int(height * 1.5))),
            interpolation=cv2.INTER_CUBIC,
        )
        decoded.extend(_decode_from_array(detector, scaled))
        payloads = [item for item in _dedupe_preserve_order(decoded) if item.startswith(qr_transport.QR_MAGIC + "|")]
        if len(payloads) >= _likely_multi_qr_capacity(bgr_image) or _payloads_cover_complete_artifact(payloads):
            break
    return _dedupe_preserve_order(decoded)


def _likely_multi_qr_grids(image_array) -> List[Tuple[int, int]]:
    height, width = image_array.shape[:2]
    ratio = float(width) / float(max(1, height))
    if ratio < 0.72:
        return [(3, 2), (4, 2)]
    if ratio < 0.98:
        return [(2, 2)]
    return [(2, 3), (2, 4)]


def _likely_multi_qr_capacity(image_array) -> int:
    grids = _likely_multi_qr_grids(image_array)
    if not grids:
        return 1
    rows, cols = grids[0]
    return int(rows * cols)


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
