#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Assistive-only visual model boundary for cross-media QR recovery.

P2-B allows visual assistance for locating QR regions, capture quality checks,
OCR candidate hints, and retake guidance. This module deliberately produces
reports only: it never reassembles QR chunks, decrypts SOX1, accepts CRC fixes,
or lets a provider decide verifier outcomes.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional

from . import image_scan

VISUAL_ASSIST_SCHEMA = "enc2sop-cross-media-visual-assist/v1"
VISUAL_ASSIST_ALLOWED_ROLES = [
    "locate_qr_regions",
    "assess_photo_quality",
    "ocr_candidate_generation",
    "retake_suggestion",
]
VISUAL_ASSIST_FORBIDDEN_ROLES = [
    "guess_ciphertext",
    "complete_crc_failed_payload",
    "bypass_verifier",
    "natural_language_crypto_validation",
]
VISUAL_ASSIST_BOUNDARY = (
    "assistive-report-only: visual hints never reassemble, decrypt, validate, "
    "override CRC, or bypass the SOX1/QR verifier"
)

_PROVIDER_TOP_LEVEL_KEYS = {"schema", "provider_name", "generated_at", "allowed_roles", "images"}
_PROVIDER_IMAGE_KEYS = {
    "path",
    "image_id",
    "provider_name",
    "qr_regions",
    "quality",
    "ocr_candidates",
    "retake_suggestions",
}
_PROVIDER_QUALITY_KEYS = {"status", "blur", "glare", "crop", "exposure", "confidence", "score"}
_FORBIDDEN_EXACT_KEYS = {
    "accepted",
    "auth_tag_override",
    "crc_override",
    "crc_bypass",
    "decrypt",
    "decryption",
    "final_payload",
    "key",
    "passphrase",
    "payload",
    "payload_guess",
    "private_key",
    "reassembled_sox1",
    "secret_key",
    "sox1",
    "sox1_string",
    "tag_override",
    "valid_payload",
    "verified",
    "verifier_override",
    "verifier_bypass",
}
_FORBIDDEN_KEY_TOKENS = (
    "ciphertext",
    "plaintext",
    "verifier",
    "payload",
    "sox1",
    "crc_bypass",
    "crc_override",
    "tag_override",
    "decrypt",
    "passphrase",
    "private_key",
    "secret",
)


class VisualAssistError(ValueError):
    """Raised when a visual-assist provider violates the assistive-only boundary."""


def _relative_report_path(path: Path, root: Path) -> str:
    try:
        return str(Path(path).relative_to(root)).replace("\\", "/")
    except ValueError:
        return Path(path).name


def _normalise_key(key: object) -> str:
    return str(key).strip().lower().replace("-", "_").replace(" ", "_")


def _contains_forbidden_key(key: object) -> bool:
    normalised = _normalise_key(key)
    if normalised in _FORBIDDEN_EXACT_KEYS:
        return True
    return any(token in normalised for token in _FORBIDDEN_KEY_TOKENS)


def _assert_no_forbidden_keys(value: Any, *, trail: str = "$", max_depth: int = 16) -> None:
    if max_depth < 0:
        raise VisualAssistError("provider report is too deeply nested at {0}".format(trail))
    if isinstance(value, Mapping):
        for key, nested in value.items():
            child_trail = "{0}.{1}".format(trail, key)
            if _contains_forbidden_key(key):
                raise VisualAssistError("forbidden visual-assist provider field at {0}".format(child_trail))
            _assert_no_forbidden_keys(nested, trail=child_trail, max_depth=max_depth - 1)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_no_forbidden_keys(nested, trail="{0}[{1}]".format(trail, index), max_depth=max_depth - 1)


def _reject_unknown_keys(payload: Mapping[str, Any], allowed: set[str], *, trail: str) -> None:
    unknown = sorted(str(key) for key in payload.keys() if str(key) not in allowed)
    if unknown:
        raise VisualAssistError("unsupported visual-assist provider field at {0}: {1}".format(trail, ", ".join(unknown)))


def _safe_float(value: Any) -> Optional[float]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return number


def _safe_confidence(value: Any) -> Optional[float]:
    number = _safe_float(value)
    if number is None:
        return None
    return round(max(0.0, min(1.0, number)), 4)


def _short_text(value: Any, *, max_len: int = 280) -> str:
    text = str(value or "").strip()
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def _bounded_json(value: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        return "<truncated>"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _short_text(value, max_len=512)
    if isinstance(value, list):
        return [_bounded_json(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, Mapping):
        return {str(key): _bounded_json(nested, depth=depth + 1) for key, nested in list(value.items())[:20]}
    return _short_text(value, max_len=512)


def _dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        text = _short_text(value, max_len=280)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _bbox_from_points(points: List[List[float]]) -> List[float]:
    xs = [point[0] for point in points]
    ys = [point[1] for point in points]
    min_x = min(xs)
    min_y = min(ys)
    max_x = max(xs)
    max_y = max(ys)
    return [round(min_x, 2), round(min_y, 2), round(max_x - min_x, 2), round(max_y - min_y, 2)]


def _coerce_bbox(value: Any) -> Optional[List[float]]:
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        return None
    numbers: List[float] = []
    for item in value:
        number = _safe_float(item)
        if number is None:
            return None
        numbers.append(round(number, 2))
    return numbers


def _coerce_points(value: Any) -> Optional[List[List[float]]]:
    if not isinstance(value, (list, tuple)):
        return None
    points: List[List[float]] = []
    for item in value:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            return None
        x = _safe_float(item[0])
        y = _safe_float(item[1])
        if x is None or y is None:
            return None
        points.append([round(x, 2), round(y, 2)])
    if len(points) < 4:
        return None
    return points[:8]


def _point_set_to_region(points: Any, *, source: str, confidence: Optional[float] = None) -> Optional[Dict[str, Any]]:
    coerced = _coerce_points(points)
    if not coerced:
        return None
    region: Dict[str, Any] = {
        "source": source,
        "points": coerced,
        "bbox": _bbox_from_points(coerced),
    }
    if confidence is not None:
        region["confidence"] = confidence
    return region


def _normalise_detected_point_sets(points: Any) -> List[Any]:
    if points is None:
        return []
    try:
        import numpy as np

        arr = np.asarray(points, dtype="float64")
    except Exception:
        return []
    if arr.size == 0:
        return []
    if arr.ndim == 2 and arr.shape[0] >= 4 and arr.shape[1] >= 2:
        return [arr[:4, :2].tolist()]
    if arr.ndim == 3:
        result = []
        for item in arr:
            if item.ndim == 2 and item.shape[0] >= 4 and item.shape[1] >= 2:
                result.append(item[:4, :2].tolist())
        return result
    return []


def _locate_local_qr_regions(path: Path) -> Dict[str, Any]:
    regions: List[Dict[str, Any]] = []
    try:
        cv2 = image_scan._load_cv2()  # same-package reuse; report-only, no verifier side effects
        detector = cv2.QRCodeDetector()
        bgr = image_scan._pil_image_to_bgr_array(Path(path))
        if hasattr(detector, "detectMulti"):
            try:
                ok, points = detector.detectMulti(bgr)
            except Exception:
                ok, points = False, None
            if ok:
                for point_set in _normalise_detected_point_sets(points):
                    region = _point_set_to_region(point_set, source="local_cv2_detectMulti")
                    if region is not None:
                        regions.append(region)
        try:
            ok, points = detector.detect(bgr)
        except Exception:
            ok, points = False, None
        if ok:
            for point_set in _normalise_detected_point_sets(points):
                region = _point_set_to_region(point_set, source="local_cv2_detect")
                if region is not None:
                    regions.append(region)
    except Exception as exc:
        return {
            "source": "local_cv2",
            "available": False,
            "regions": [],
            "error": str(exc),
        }

    deduped: List[Dict[str, Any]] = []
    seen = set()
    for region in regions:
        key = tuple(region.get("bbox") or [])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(region)
    return {
        "source": "local_cv2",
        "available": True,
        "regions": deduped,
    }


def _sanitize_qr_regions(value: Any, *, provider_name: Optional[str] = None) -> List[Dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise VisualAssistError("provider qr_regions must be a list")
    regions: List[Dict[str, Any]] = []
    for index, item in enumerate(value[:32]):
        if not isinstance(item, Mapping):
            raise VisualAssistError("provider qr_regions[{0}] must be an object".format(index))
        confidence = _safe_confidence(item.get("confidence"))
        bbox = _coerce_bbox(item.get("bbox"))
        if bbox is None and all(key in item for key in ("x", "y", "width", "height")):
            bbox = _coerce_bbox([item.get("x"), item.get("y"), item.get("width"), item.get("height")])
        points = _coerce_points(item.get("points"))
        if bbox is None and points:
            bbox = _bbox_from_points(points)
        if bbox is None and points is None:
            raise VisualAssistError("provider qr_regions[{0}] must contain bbox or points".format(index))
        region: Dict[str, Any] = {
            "source": "provider",
            "untrusted": True,
        }
        if provider_name:
            region["provider_name"] = provider_name
        if bbox is not None:
            region["bbox"] = bbox
        if points is not None:
            region["points"] = points
        if confidence is not None:
            region["confidence"] = confidence
        if item.get("label"):
            region["label"] = _short_text(item.get("label"), max_len=80)
        regions.append(region)
    return regions


def _sanitize_ocr_candidates(value: Any, *, provider_name: Optional[str] = None) -> List[Dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise VisualAssistError("provider ocr_candidates must be a list")
    candidates: List[Dict[str, Any]] = []
    for index, item in enumerate(value[:50]):
        if isinstance(item, str):
            text = _short_text(item, max_len=4096)
            confidence = None
        elif isinstance(item, Mapping):
            text = _short_text(item.get("text"), max_len=4096)
            confidence = _safe_confidence(item.get("confidence"))
        else:
            raise VisualAssistError("provider ocr_candidates[{0}] must be a string or object".format(index))
        if not text:
            continue
        record: Dict[str, Any] = {
            "text": text,
            "role": "ocr_candidate_generation",
            "source": "provider",
            "untrusted": True,
            "verifier_boundary": VISUAL_ASSIST_BOUNDARY,
        }
        if provider_name:
            record["provider_name"] = provider_name
        if confidence is not None:
            record["confidence"] = confidence
        candidates.append(record)
    return candidates


def _sanitize_quality(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise VisualAssistError("provider quality must be an object")
    result: Dict[str, Any] = {}
    for key in _PROVIDER_QUALITY_KEYS:
        if key in value:
            result[key] = _bounded_json(value[key])
    return result


def _sanitize_retake_suggestions(value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise VisualAssistError("provider retake_suggestions must be a list")
    return _dedupe_preserve_order(_short_text(item, max_len=280) for item in value[:20])


def sanitize_provider_report(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate and reduce an external visual-model report to allowed hints only."""

    if not isinstance(payload, Mapping):
        raise VisualAssistError("provider report must be a JSON object")
    _assert_no_forbidden_keys(payload)
    _reject_unknown_keys(payload, _PROVIDER_TOP_LEVEL_KEYS, trail="provider_report")
    images = payload.get("images", [])
    if not isinstance(images, list):
        raise VisualAssistError("provider report images must be a list")
    provider_name = _short_text(payload.get("provider_name") or "external-visual-provider", max_len=80)
    sanitized_images: List[Dict[str, Any]] = []
    for index, image_payload in enumerate(images):
        if not isinstance(image_payload, Mapping):
            raise VisualAssistError("provider image record {0} must be an object".format(index))
        _reject_unknown_keys(image_payload, _PROVIDER_IMAGE_KEYS, trail="provider_report.images[{0}]".format(index))
        image_provider = _short_text(image_payload.get("provider_name") or provider_name, max_len=80)
        record: Dict[str, Any] = {
            "path": _short_text(image_payload.get("path"), max_len=512),
            "provider_name": image_provider,
            "qr_regions": _sanitize_qr_regions(image_payload.get("qr_regions"), provider_name=image_provider),
            "quality": _sanitize_quality(image_payload.get("quality")),
            "ocr_candidates": _sanitize_ocr_candidates(image_payload.get("ocr_candidates"), provider_name=image_provider),
            "retake_suggestions": _sanitize_retake_suggestions(image_payload.get("retake_suggestions")),
        }
        if image_payload.get("image_id"):
            record["image_id"] = _short_text(image_payload.get("image_id"), max_len=128)
        sanitized_images.append(record)
    return {
        "provider_name": provider_name,
        "images": sanitized_images,
        "image_count": len(sanitized_images),
    }


def load_provider_report(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VisualAssistError("provider report is not valid JSON: {0}".format(exc)) from exc
    return sanitize_provider_report(payload)


def _provider_indexes(provider_report: Optional[Dict[str, Any]]) -> tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    by_path: Dict[str, Dict[str, Any]] = {}
    by_name: Dict[str, Dict[str, Any]] = {}
    if not provider_report:
        return by_path, by_name
    for image_record in provider_report.get("images", []):
        if not isinstance(image_record, Mapping):
            continue
        raw_path = str(image_record.get("path") or "").replace("\\", "/")
        if raw_path:
            by_path[raw_path.lower()] = dict(image_record)
            by_name[Path(raw_path).name.lower()] = dict(image_record)
    return by_path, by_name


def _provider_record_for(path: Path, root: Path, by_path: Dict[str, Dict[str, Any]], by_name: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    relative = _relative_report_path(path, root).lower()
    if relative in by_path:
        return by_path[relative]
    name = Path(path).name.lower()
    return by_name.get(name)


def _glare_status(quality: Mapping[str, Any]) -> str:
    exposure = quality.get("exposure") if isinstance(quality.get("exposure"), Mapping) else {}
    status = str(exposure.get("status") or quality.get("status") or "unknown")
    if status in {"overexposed", "glare_risk"}:
        return "risk"
    if status == "ok":
        return "ok"
    return status or "unknown"


def _crop_assessment(quality: Mapping[str, Any], regions: List[Dict[str, Any]]) -> Dict[str, Any]:
    width = _safe_float(quality.get("width"))
    height = _safe_float(quality.get("height"))
    if width is None or height is None or width <= 0 or height <= 0:
        return {"status": "unknown", "reason": "image_dimensions_unavailable"}
    if not regions:
        return {"status": "unknown", "reason": "no_qr_region_detected"}
    margins: List[float] = []
    for region in regions:
        bbox = _coerce_bbox(region.get("bbox"))
        if bbox is None:
            continue
        x, y, box_width, box_height = bbox
        margin = min(x, y, width - (x + box_width), height - (y + box_height))
        margins.append(float(margin) / float(max(1.0, min(width, height))))
    if not margins:
        return {"status": "unknown", "reason": "qr_region_bbox_unavailable"}
    min_margin = min(margins)
    if min_margin < 0.01:
        status = "critical"
    elif min_margin < 0.04:
        status = "warning"
    else:
        status = "ok"
    return {"status": status, "min_edge_margin_ratio": round(min_margin, 4)}


def _photo_assessment(quality: Mapping[str, Any], regions: List[Dict[str, Any]]) -> Dict[str, Any]:
    blur = quality.get("blur") if isinstance(quality.get("blur"), Mapping) else {}
    return {
        "blur": {"status": str(blur.get("status") or quality.get("status") or "unknown")},
        "glare": {"status": _glare_status(quality)},
        "crop": _crop_assessment(quality, regions),
    }


def _local_retake_suggestions(quality: Mapping[str, Any], assessment: Mapping[str, Any]) -> List[str]:
    suggestions: List[str] = []
    blur = quality.get("blur") if isinstance(quality.get("blur"), Mapping) else {}
    exposure = quality.get("exposure") if isinstance(quality.get("exposure"), Mapping) else {}
    blur_status = str(blur.get("status") or "")
    exposure_status = str(exposure.get("status") or "")
    if blur_status in {"warning", "critical"}:
        suggestions.append("hold the camera steady and refocus to reduce motion blur")
    if exposure_status in {"overexposed", "glare_risk"}:
        suggestions.append("tilt the camera or lower screen brightness to avoid glare/overexposure")
    elif exposure_status == "underexposed":
        suggestions.append("add light or increase screen brightness")
    crop = assessment.get("crop") if isinstance(assessment.get("crop"), Mapping) else {}
    if str(crop.get("status") or "") in {"warning", "critical"}:
        suggestions.append("retake with the full QR border and quiet zone visible")
    if str(quality.get("status") or "") == "unreadable":
        suggestions.append("use a supported, uncorrupted image file")
    return _dedupe_preserve_order(suggestions)


def build_visual_assist_report(image_input: Path, *, provider_report_path: Optional[Path] = None) -> Dict[str, Any]:
    provider_report = load_provider_report(provider_report_path) if provider_report_path else None
    provider_by_path, provider_by_name = _provider_indexes(provider_report)
    root = Path(image_input)
    images = image_scan.list_image_files(root)
    image_records: List[Dict[str, Any]] = []
    for image_path in images:
        relative = _relative_report_path(image_path, root)
        quality = image_scan.assess_image_file_quality(image_path)
        local_regions = _locate_local_qr_regions(image_path)
        regions = list(local_regions.get("regions") or [])
        provider_record = _provider_record_for(image_path, root, provider_by_path, provider_by_name)
        provider_quality: Dict[str, Any] = {}
        ocr_candidates: List[Dict[str, Any]] = []
        provider_suggestions: List[str] = []
        provider_accepted = False
        if provider_record:
            provider_accepted = True
            regions.extend(list(provider_record.get("qr_regions") or []))
            provider_quality = dict(provider_record.get("quality") or {})
            ocr_candidates = list(provider_record.get("ocr_candidates") or [])
            provider_suggestions = list(provider_record.get("retake_suggestions") or [])
        assessment = _photo_assessment(quality, regions)
        suggestions = _dedupe_preserve_order(_local_retake_suggestions(quality, assessment) + provider_suggestions)
        record: Dict[str, Any] = {
            "path": relative,
            "quality": quality,
            "photo_assessment": assessment,
            "qr_region_hints": regions,
            "ocr_candidate_hints": ocr_candidates,
            "retake_suggestions": suggestions,
            "local_qr_locator": {
                "source": local_regions.get("source"),
                "available": bool(local_regions.get("available")),
                "region_count": len(local_regions.get("regions") or []),
            },
            "provider_hints_accepted": provider_accepted,
            "verifier_boundary": VISUAL_ASSIST_BOUNDARY,
        }
        if local_regions.get("error"):
            record["local_qr_locator"]["error"] = local_regions.get("error")
        if provider_quality:
            record["provider_quality_hints"] = provider_quality
        image_records.append(record)
    return {
        "schema": VISUAL_ASSIST_SCHEMA,
        "success": True,
        "image_input": str(root),
        "image_count": len(images),
        "allowed_roles": list(VISUAL_ASSIST_ALLOWED_ROLES),
        "forbidden_roles": list(VISUAL_ASSIST_FORBIDDEN_ROLES),
        "verifier_boundary": VISUAL_ASSIST_BOUNDARY,
        "provider_report": {
            "accepted": provider_report is not None,
            "path": str(provider_report_path) if provider_report_path else None,
            "provider_name": provider_report.get("provider_name") if provider_report else None,
            "image_count": int(provider_report.get("image_count") or 0) if provider_report else 0,
        },
        "images": image_records,
    }


__all__ = [
    "VISUAL_ASSIST_ALLOWED_ROLES",
    "VISUAL_ASSIST_BOUNDARY",
    "VISUAL_ASSIST_FORBIDDEN_ROLES",
    "VISUAL_ASSIST_SCHEMA",
    "VisualAssistError",
    "build_visual_assist_report",
    "load_provider_report",
    "sanitize_provider_report",
]
