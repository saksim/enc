"""Transport reliability certification harness."""

import json
import random
import shutil
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from . import protocol


REPORT_SCHEMA = "enc2sop-transport-reliability-report/v1"
CAPTURE_CORPUS_SCHEMA = "enc2sop-transport-capture-corpus/v1"
CAPTURE_KIT_SCHEMA = "enc2sop-transport-capture-kit/v1"
CAPTURE_ATTACHMENT_REPORT_SCHEMA = "enc2sop-transport-capture-attachment-report/v1"
CAPTURE_PERSPECTIVE_CORRECTION_REPORT_SCHEMA = (
    "enc2sop-transport-capture-perspective-correction-report/v1"
)
CAPTURE_VALIDATION_REPORT_SCHEMA = "enc2sop-transport-capture-corpus-validation/v1"
CAPTURE_EVIDENCE_ARCHIVE_SCHEMA = "enc2sop-transport-capture-evidence-archive/v1"
CAPTURE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA = (
    "enc2sop-transport-capture-evidence-archive-verification/v1"
)
CAPTURE_EVIDENCE_ARCHIVE_REPLAY_SCHEMA = (
    "enc2sop-transport-capture-evidence-archive-replay/v1"
)
CERTIFICATION_CLAIMS_SCHEMA = "enc2sop-transport-certification-claims/v1"
CERTIFICATION_STATUS_SCHEMA = "enc2sop-transport-certification-status/v1"
CAPTURE_CERTIFICATION_PIPELINE_SCHEMA = (
    "enc2sop-transport-capture-certification-pipeline/v1"
)
CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA = (
    "enc2sop-transport-capture-corpus-ingestion-report/v1"
)
CAPTURE_METADATA_MANIFEST_SCHEMA = "enc2sop-transport-capture-metadata-manifest/v1"
CAPTURE_RETURN_PACKAGE_EXTRACTION_SCHEMA = (
    "enc2sop-transport-capture-return-package-extraction/v1"
)
CAPTURE_RETURN_PACKAGE_SCHEMA = "enc2sop-transport-capture-return-package/v1"
CAPTURE_RETURN_MANIFEST_SCHEMA = "enc2sop-transport-capture-return-manifest/v1"
DEFAULT_PAYLOAD_SIZES = [128, 4096]
DIGITAL_SIDECAR_PROFILE = "digital-sidecar-v1"
RELIABLE_AIRGAP_PROFILE = "reliable-airgap-v1"
SUPPORTED_PROFILES = [DIGITAL_SIDECAR_PROFILE, RELIABLE_AIRGAP_PROFILE]
RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES = 1
NO_DISTORTION_SUITE = "none"
GENERATED_PAGE_BASIC_DISTORTION_SUITE = "generated-page-basic-v1"
GENERATED_PAGE_STRESS_DISTORTION_SUITE = "generated-page-stress-v1"
SUPPORTED_DISTORTION_SUITES = [
    NO_DISTORTION_SUITE,
    GENERATED_PAGE_BASIC_DISTORTION_SUITE,
    GENERATED_PAGE_STRESS_DISTORTION_SUITE,
]
OPERATOR_CAPTURE_CORPUS_SUITE = "operator-capture-corpus"
SUPPORTED_CORPUS_CLASSIFICATIONS = ["real", "lab", "synthetic", "stress-only"]
SUPPORTED_CAPTURE_MEDIA = ["unspecified", "camera-photo", "print-scan", "mixed"]
SUPPORTED_CERTIFICATION_BACKENDS = ["sidecar", "auto", "tesseract", "easyocr", "external"]
OCR_ONLY_CERTIFICATION_BACKENDS = ["tesseract", "easyocr", "external"]
CAPTURE_IMAGE_SUFFIXES = {".bmp", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"}
CAPTURE_RETURN_METADATA_MANIFEST_CANDIDATES = [
    "operator_capture_metadata_manifest.json",
    "capture_metadata_manifest.json",
    "capture_metadata.json",
    "metadata/operator_capture_metadata_manifest.json",
    "metadata/capture_metadata_manifest.json",
    "instructions/operator_capture_metadata_manifest_template.json",
]
CAPTURE_RETURN_MANIFEST_CANDIDATES = [
    "operator_return_manifest.json",
    "capture_return_manifest.json",
    "return_manifest.json",
    "metadata/operator_return_manifest.json",
    "metadata/capture_return_manifest.json",
]
OCR_ONLY_KIT_PROFILE = "ocr-only-backend-v1"
SUPPORTED_PERSPECTIVE_CORRECTION_MODES = ["copy", "normalize", "four-point"]
CAPTURE_PROVENANCE_SESSION_KEYS = (
    "capture_session_id",
    "session_id",
    "capture_id",
    "evidence_session_id",
)
CAPTURE_PROVENANCE_OPERATOR_KEYS = (
    "operator",
    "operator_id",
    "captured_by",
    "lab_operator",
)
CAPTURE_PROVENANCE_TIMESTAMP_KEYS = (
    "captured_at_utc",
    "capture_time_utc",
    "scan_time_utc",
    "photo_time_utc",
    "captured_at",
    "capture_time",
)
CAPTURE_PROVENANCE_DEVICE_KEYS = (
    "device",
    "camera",
    "camera_model",
    "scanner",
    "scanner_model",
    "scan_device",
    "printer",
    "printer_model",
    "print_device",
)
CAPTURE_PROVENANCE_LOCATION_KEYS = (
    "location",
    "lab",
    "site",
    "environment",
)
TRANSPORT_CERTIFICATION_CLAIMS = [
    "generated-page-sidecar",
    "generated-page-synthetic-stress",
    "physical-print-scan",
    "real-camera-perspective-correction",
    "backend-specific-ocr-only",
]


_DISTORTION_DEFINITIONS = {
    "control": {
        "name": "control",
        "kind": "control",
        "parameters": {},
        "description": "unmodified generated PNG pages",
    },
    "jpeg-q95": {
        "name": "jpeg-q95",
        "kind": "jpeg_recompress",
        "parameters": {"quality": 95},
        "description": "JPEG recompression at quality 95",
    },
    "png-reencode": {
        "name": "png-reencode",
        "kind": "png_reencode",
        "parameters": {"optimize": True},
        "description": "PNG decode/re-encode with optimization",
    },
    "resize-down-90": {
        "name": "resize-down-90",
        "kind": "resize",
        "parameters": {"scale": 0.9},
        "description": "uniform downscale to 90 percent",
    },
    "resize-up-110": {
        "name": "resize-up-110",
        "kind": "resize",
        "parameters": {"scale": 1.1},
        "description": "uniform upscale to 110 percent",
    },
    "blur-radius-0_35": {
        "name": "blur-radius-0_35",
        "kind": "blur",
        "parameters": {"radius": 0.35},
        "description": "mild Gaussian blur",
    },
    "contrast-brightness-lite": {
        "name": "contrast-brightness-lite",
        "kind": "contrast_brightness",
        "parameters": {"contrast": 1.12, "brightness": 1.03},
        "description": "mild contrast and brightness shift",
    },
    "screenshot-lite": {
        "name": "screenshot-lite",
        "kind": "screenshot_like",
        "parameters": {"scale": 0.92, "quality": 96},
        "description": "downscale/upscale plus high-quality recompression",
    },
    "rotate-0_25": {
        "name": "rotate-0_25",
        "kind": "rotate",
        "parameters": {"degrees": 0.25},
        "description": "small rotation without perspective correction",
    },
    "crop-margin-4px": {
        "name": "crop-margin-4px",
        "kind": "crop_margin",
        "parameters": {"pixels": 4},
        "description": "small edge crop to simulate margin loss",
    },
    "perspective-skew-lite": {
        "name": "perspective-skew-lite",
        "kind": "perspective_skew",
        "parameters": {"x_shear": -0.015, "y_shear": 0.01, "x_offset": 20, "y_offset": -15},
        "description": "small deterministic skew approximation",
    },
    "noise-sparse-lite": {
        "name": "noise-sparse-lite",
        "kind": "sparse_noise",
        "parameters": {"density": 0.0002},
        "description": "deterministic sparse salt-and-pepper noise",
    },
    "print-scan-lite": {
        "name": "print-scan-lite",
        "kind": "print_scan_like",
        "parameters": {"contrast": 1.18, "brightness": 1.04, "blur_radius": 0.25},
        "description": "grayscale contrast and mild blur approximation",
    },
}

_DISTORTION_SUITES = {
    NO_DISTORTION_SUITE: ["control"],
    GENERATED_PAGE_BASIC_DISTORTION_SUITE: [
        "control",
        "png-reencode",
        "jpeg-q95",
        "blur-radius-0_35",
        "contrast-brightness-lite",
        "screenshot-lite",
    ],
    GENERATED_PAGE_STRESS_DISTORTION_SUITE: [
        "control",
        "png-reencode",
        "jpeg-q95",
        "resize-down-90",
        "resize-up-110",
        "blur-radius-0_35",
        "contrast-brightness-lite",
        "screenshot-lite",
        "rotate-0_25",
        "crop-margin-4px",
        "perspective-skew-lite",
        "noise-sparse-lite",
        "print-scan-lite",
    ],
}


def _sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    return protocol.sha256_hex(path.read_bytes())


def _safe_relative_path(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except Exception:
        return str(path)


def _write_json(path: Path, data: Dict[str, object]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def _load_json(path: Path) -> Dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha256_text(value: str) -> str:
    return protocol.sha256_hex(value.encode("utf-8"))


def _sha256_bytes(value: bytes) -> str:
    return protocol.sha256_hex(value)


def _deterministic_payload(size: int, seed: int, case_index: int) -> bytes:
    rng = random.Random(int(seed) + (case_index * 1000003) + int(size))
    return bytes(rng.randrange(0, 256) for _ in range(int(size)))


def _normalize_payload_sizes(payload_sizes: Optional[Iterable[int]]) -> List[int]:
    sizes = list(payload_sizes) if payload_sizes is not None else list(DEFAULT_PAYLOAD_SIZES)
    if not sizes:
        raise ValueError("payload_sizes must not be empty")
    normalized = []
    for size in sizes:
        value = int(size)
        if value <= 0:
            raise ValueError("payload sizes must be positive")
        normalized.append(value)
    return normalized


def _resolve_profile_name(profile: Optional[str], backend: str) -> str:
    if profile is None or str(profile).strip() == "":
        return DIGITAL_SIDECAR_PROFILE if backend == "sidecar" else "digital-{}-v1".format(backend)
    value = str(profile).strip().lower()
    if value not in SUPPORTED_PROFILES and not (
        value.startswith("digital-") and value.endswith("-v1")
    ) and value != OCR_ONLY_KIT_PROFILE:
        raise ValueError("unsupported transport reliability profile: {}".format(profile))
    return value


def _resolve_distortion_suite_name(distortion_suite: Optional[str]) -> str:
    value = str(distortion_suite or NO_DISTORTION_SUITE).strip().lower()
    if value not in SUPPORTED_DISTORTION_SUITES:
        raise ValueError("unsupported distortion suite: {}".format(distortion_suite))
    return value


def _distortion_definitions_for_suite(suite_name: str) -> List[Dict[str, object]]:
    names = _DISTORTION_SUITES.get(suite_name, [])
    return [dict(_DISTORTION_DEFINITIONS[name]) for name in names]


def _normalize_label(value: object, fallback: str) -> str:
    text = str(value or "").strip()
    return text if text else fallback


def _label_slug(value: object, fallback: str) -> str:
    label = _normalize_label(value, fallback)
    slug = "".join(ch if ch.isalnum() else "_" for ch in label).strip("_").lower()
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug[:64] or fallback


def _resolve_existing_path(raw_path: object, base_dir: Path, field_name: str) -> Path:
    if raw_path is None or str(raw_path).strip() == "":
        raise ValueError("{} is required".format(field_name))
    path = Path(str(raw_path))
    if not path.is_absolute():
        path = base_dir / path
    path = path.resolve()
    if not path.exists():
        raise ValueError("{} does not exist: {}".format(field_name, path))
    return path


def _resolve_existing_path_cwd_or_base(
    raw_path: object,
    base_dir: Path,
    field_name: str,
) -> Path:
    if raw_path is None or str(raw_path).strip() == "":
        raise ValueError("{} is required".format(field_name))
    path = Path(str(raw_path))
    if path.is_absolute():
        resolved = path.resolve()
    else:
        cwd_candidate = path.resolve()
        resolved = cwd_candidate if cwd_candidate.exists() else (base_dir / path).resolve()
    if not resolved.exists():
        raise ValueError("{} does not exist: {}".format(field_name, resolved))
    return resolved


def _resolve_output_path(raw_path: Optional[str], output_dir: Path, default_name: str) -> Path:
    if raw_path is None or str(raw_path).strip() == "":
        return output_dir / default_name
    path = Path(str(raw_path))
    if not path.is_absolute():
        path = output_dir / path
    return path


def _image_paths_from_capture_input(raw_path: object, base_dir: Path) -> List[Path]:
    path = _resolve_existing_path(raw_path, base_dir, "capture image path")
    if path.is_file():
        if path.suffix.lower() not in CAPTURE_IMAGE_SUFFIXES:
            raise ValueError("capture image file has unsupported suffix: {}".format(path))
        return [path]
    if not path.is_dir():
        raise ValueError("capture image path is not a file or directory: {}".format(path))
    images = [
        item
        for item in sorted(path.iterdir(), key=lambda candidate: candidate.name.lower())
        if item.is_file() and item.suffix.lower() in CAPTURE_IMAGE_SUFFIXES
    ]
    if not images:
        raise ValueError("capture image directory has no supported image files: {}".format(path))
    return images


def _capture_images_from_existing_path(raw_path: object, base_dir: Path) -> List[Path]:
    path = _resolve_existing_path(raw_path, base_dir, "capture image path")
    if path.is_file():
        if path.suffix.lower() not in CAPTURE_IMAGE_SUFFIXES:
            raise ValueError("capture image file has unsupported suffix: {}".format(path))
        return [path]
    if not path.is_dir():
        raise ValueError("capture image path is not a file or directory: {}".format(path))
    return [
        item
        for item in sorted(path.iterdir(), key=lambda candidate: candidate.name.lower())
        if item.is_file() and item.suffix.lower() in CAPTURE_IMAGE_SUFFIXES
    ]


def _collect_capture_images_recursive(raw_path: object, base_dir: Path) -> List[Path]:
    path = _resolve_existing_path(raw_path, base_dir, "capture image path")
    if path.is_file():
        if path.suffix.lower() not in CAPTURE_IMAGE_SUFFIXES:
            raise ValueError("capture image file has unsupported suffix: {}".format(path))
        return [path]
    if not path.is_dir():
        raise ValueError("capture image path is not a file or directory: {}".format(path))
    return [
        item
        for item in sorted(path.iterdir(), key=lambda candidate: candidate.name.lower())
        if item.is_file() and item.suffix.lower() in CAPTURE_IMAGE_SUFFIXES
    ]


def _optional_image_paths_from_capture_input(raw_path: object, base_dir: Path) -> List[Path]:
    if raw_path is None or str(raw_path).strip() == "":
        return []
    return _capture_images_from_existing_path(raw_path, base_dir)


def _optional_image_paths_from_capture_inputs(raw_paths: object, base_dir: Path) -> List[Path]:
    if raw_paths is None or raw_paths == "":
        return []
    values = raw_paths if isinstance(raw_paths, list) else [raw_paths]
    paths: List[Path] = []
    seen = set()
    for raw_path in values:
        for path in _optional_image_paths_from_capture_input(raw_path, base_dir):
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            paths.append(path)
    return paths


def _capture_sidecar_present(manifest: Dict[str, object]) -> Optional[bool]:
    if "sidecar_enabled" in manifest:
        return bool(manifest.get("sidecar_enabled"))
    pages = manifest.get("pages")
    if not isinstance(pages, list):
        render_layout = manifest.get("render_layout")
        pages = render_layout.get("pages") if isinstance(render_layout, dict) else None
    if not isinstance(pages, list):
        return False
    for page in pages:
        if not isinstance(page, dict):
            continue
        lines = page.get("lines")
        if not isinstance(lines, list):
            continue
        for line in lines:
            if isinstance(line, dict) and (
                line.get("sidecar")
                or line.get("binary_box")
            ):
                return True
    return False


def _manifest_has_binary_sidecar(manifest: Dict[str, object]) -> bool:
    pages = manifest.get("pages")
    if not isinstance(pages, list):
        render_layout = manifest.get("render_layout")
        pages = render_layout.get("pages") if isinstance(render_layout, dict) else None
    if not isinstance(pages, list):
        return False
    for page in pages:
        if not isinstance(page, dict):
            continue
        lines = page.get("lines")
        if not isinstance(lines, list):
            continue
        for line in lines:
            if not isinstance(line, dict):
                continue
            if line.get("sidecar") or line.get("binary_box"):
                return True
    return False


def _normalize_metadata_value(value: object) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_normalize_metadata_value(item) for item in value]
    if isinstance(value, dict):
        normalized: Dict[str, object] = {}
        for key, item in value.items():
            text_key = str(key).strip()
            if not text_key:
                raise ValueError("capture corpus metadata keys must be non-empty")
            normalized[text_key] = _normalize_metadata_value(item)
        return normalized
    return str(value)


def _normalize_capture_corpus_metadata(value: object) -> Dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("capture corpus metadata must be an object")
    normalized: Dict[str, object] = {}
    for key, item in value.items():
        text_key = str(key).strip()
        if not text_key:
            raise ValueError("capture corpus metadata keys must be non-empty")
        normalized[text_key] = _normalize_metadata_value(item)
    return normalized


def _boolish(value: object) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in ("1", "true", "yes", "y", "on", "applied", "corrected")


def _first_metadata_value(metadata: Dict[str, object], keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        if key not in metadata:
            continue
        value = str(metadata.get(key) or "").strip()
        if value:
            return value
    return None


def _normalize_perspective_correction(value: object) -> Dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("capture corpus perspective_correction must be an object")
    return _normalize_capture_corpus_metadata(value)


def _normalize_capture_medium(value: object) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "unspecified"
    normalized = text.replace("_", "-").replace(" ", "-")
    aliases = {
        "camera": "camera-photo",
        "camera-photo": "camera-photo",
        "camera-photos": "camera-photo",
        "photo": "camera-photo",
        "photos": "camera-photo",
        "scan": "print-scan",
        "scanner": "print-scan",
        "flatbed": "print-scan",
        "flatbed-scan": "print-scan",
        "print": "print-scan",
        "print-scan": "print-scan",
        "printed-scan": "print-scan",
        "physical-print-scan": "print-scan",
        "mixed": "mixed",
        "unspecified": "unspecified",
        "unknown": "unspecified",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in SUPPORTED_CAPTURE_MEDIA:
        raise ValueError(
            "capture corpus medium must be one of: {}".format(
                ", ".join(SUPPORTED_CAPTURE_MEDIA)
            )
        )
    return normalized


def _capture_medium_from_metadata(metadata: Dict[str, object]) -> str:
    for key in ("capture_medium", "medium", "media", "capture_type"):
        if key in metadata:
            return _normalize_capture_medium(metadata.get(key))
    return "unspecified"


def _merge_capture_metadata(
    corpus_metadata: Dict[str, object],
    case_metadata: Dict[str, object],
) -> Dict[str, object]:
    merged = dict(corpus_metadata)
    merged.update(case_metadata)
    return merged


def _load_capture_metadata_manifest(
    metadata_manifest_file: Optional[str],
    corpus_base: Path,
) -> Dict[str, object]:
    raw_path = str(metadata_manifest_file or "").strip()
    if not raw_path:
        return {
            "file": None,
            "sha256": None,
            "defaults": {},
            "cases_by_label": {},
        }
    manifest_path = Path(raw_path)
    if not manifest_path.is_absolute():
        manifest_path = manifest_path if manifest_path.exists() else corpus_base / manifest_path
    manifest_path = manifest_path.resolve()
    if not manifest_path.exists() or not manifest_path.is_file():
        raise ValueError("capture metadata manifest file does not exist: {}".format(manifest_path))

    manifest = _load_json(manifest_path)
    schema = str(manifest.get("schema") or "").strip()
    if schema != CAPTURE_METADATA_MANIFEST_SCHEMA:
        raise ValueError(
            "capture metadata manifest schema must be {}, got {}".format(
                CAPTURE_METADATA_MANIFEST_SCHEMA,
                schema or "<missing>",
            )
        )

    defaults = _normalize_capture_corpus_metadata(
        manifest.get("capture_metadata_defaults", manifest.get("metadata_defaults"))
    )
    if "capture_medium" in manifest and "capture_medium" not in defaults:
        defaults["capture_medium"] = manifest.get("capture_medium")
    elif "medium" in manifest and "capture_medium" not in defaults:
        defaults["capture_medium"] = manifest.get("medium")

    raw_cases = manifest.get("cases", [])
    if raw_cases is None:
        raw_cases = []
    if not isinstance(raw_cases, list):
        raise ValueError("capture metadata manifest cases must be a list")

    cases_by_label: Dict[str, Dict[str, object]] = {}
    for index, raw_case in enumerate(raw_cases, 1):
        if not isinstance(raw_case, dict):
            raise ValueError("capture metadata manifest case {} must be an object".format(index))
        label = _normalize_label(raw_case.get("label"), "")
        if not label:
            raise ValueError("capture metadata manifest case {} label is required".format(index))
        if label in cases_by_label:
            raise ValueError("capture metadata manifest labels must be unique: {}".format(label))
        case_metadata = _normalize_capture_corpus_metadata(
            raw_case.get("capture_metadata", raw_case.get("metadata"))
        )
        if "capture_medium" in raw_case and "capture_medium" not in case_metadata:
            case_metadata["capture_medium"] = raw_case.get("capture_medium")
        elif "medium" in raw_case and "capture_medium" not in case_metadata:
            case_metadata["capture_medium"] = raw_case.get("medium")
        cases_by_label[label] = {
            "label": label,
            "metadata": case_metadata,
            "capture_medium": (
                _normalize_capture_medium(
                    raw_case.get(
                        "capture_medium",
                        raw_case.get("medium", case_metadata.get("capture_medium")),
                    )
                )
                if any(
                    key in raw_case or key in case_metadata
                    for key in ("capture_medium", "medium")
                )
                else None
            ),
        }

    return {
        "file": manifest_path,
        "sha256": _sha256_file(manifest_path),
        "defaults": defaults,
        "cases_by_label": cases_by_label,
    }


def _capture_case_metadata_defaults(corpus_metadata: Dict[str, object]) -> Dict[str, object]:
    defaults: Dict[str, object] = {}
    raw_defaults = corpus_metadata.get("capture_metadata_defaults")
    if isinstance(raw_defaults, dict):
        defaults.update(_normalize_capture_corpus_metadata(raw_defaults))
    for key in (
        "printer",
        "printer_model",
        "print_device",
        "scanner",
        "scanner_model",
        "scan_device",
        "dpi",
        "scan_dpi",
        "capture_medium",
        "medium",
        "media",
        "capture_type",
        "device",
        "lighting",
    ):
        if key in corpus_metadata and key not in defaults:
            defaults[key] = corpus_metadata[key]
    return defaults


def _normalize_capture_corpus_cases(
    capture_corpus_file: Optional[str],
    allow_empty_capture_images: bool = False,
) -> Optional[Dict[str, object]]:
    if capture_corpus_file is None or str(capture_corpus_file).strip() == "":
        return None

    corpus_path = Path(str(capture_corpus_file)).resolve()
    if not corpus_path.exists() or not corpus_path.is_file():
        raise ValueError("capture corpus file does not exist: {}".format(corpus_path))
    corpus_base = corpus_path.parent
    corpus = _load_json(corpus_path)
    schema = str(corpus.get("schema") or "").strip()
    if schema != CAPTURE_CORPUS_SCHEMA:
        raise ValueError(
            "capture corpus schema must be {}, got {}".format(
                CAPTURE_CORPUS_SCHEMA,
                schema or "<missing>",
            )
        )

    classification = str(corpus.get("classification") or "").strip().lower()
    if classification not in SUPPORTED_CORPUS_CLASSIFICATIONS:
        raise ValueError(
            "capture corpus classification must be one of: {}".format(
                ", ".join(SUPPORTED_CORPUS_CLASSIFICATIONS)
            )
        )

    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("capture corpus cases must be a non-empty list")

    corpus_metadata = _normalize_capture_corpus_metadata(corpus.get("metadata"))
    corpus_medium = _normalize_capture_medium(
        corpus.get("capture_medium", corpus.get("medium", corpus_metadata.get("capture_medium")))
    )

    normalized_cases = []
    seen_labels = set()
    for index, raw_case in enumerate(cases, 1):
        if not isinstance(raw_case, dict):
            raise ValueError("capture corpus case {} must be an object".format(index))

        label = _normalize_label(raw_case.get("label"), "capture_{:04d}".format(index))
        if label in seen_labels:
            raise ValueError("capture corpus labels must be unique: {}".format(label))
        seen_labels.add(label)

        manifest_path = _resolve_existing_path(raw_case.get("manifest_path"), corpus_base, "manifest_path")
        payload_path = _resolve_existing_path(raw_case.get("payload_path"), corpus_base, "payload_path")
        if not payload_path.is_file():
            raise ValueError("payload_path is not a file: {}".format(payload_path))
        if bool(allow_empty_capture_images):
            image_paths = _capture_images_from_existing_path(raw_case.get("image_path"), corpus_base)
        else:
            image_paths = _image_paths_from_capture_input(raw_case.get("image_path"), corpus_base)
        reference_image_paths = _optional_image_paths_from_capture_inputs(
            raw_case.get("reference_image_paths", raw_case.get("reference_image_path")),
            corpus_base,
        )
        raw_image_paths = _optional_image_paths_from_capture_inputs(
            raw_case.get("raw_image_paths", raw_case.get("raw_image_path")),
            corpus_base,
        )

        case_classification = str(raw_case.get("classification") or classification).strip().lower()
        if case_classification not in SUPPORTED_CORPUS_CLASSIFICATIONS:
            raise ValueError(
                "capture corpus case classification must be one of: {}".format(
                    ", ".join(SUPPORTED_CORPUS_CLASSIFICATIONS)
                )
            )

        capture_metadata = _normalize_capture_corpus_metadata(
            raw_case.get("capture_metadata", raw_case.get("metadata"))
        )
        merged_capture_metadata = _merge_capture_metadata(
            _capture_case_metadata_defaults(corpus_metadata),
            capture_metadata,
        )
        case_medium = _normalize_capture_medium(
            raw_case.get(
                "capture_medium",
                raw_case.get(
                    "medium",
                    capture_metadata.get(
                        "capture_medium",
                        _capture_medium_from_metadata(merged_capture_metadata),
                    ),
                ),
            )
        )
        if case_medium == "unspecified" and corpus_medium != "unspecified":
            case_medium = corpus_medium

        normalized_cases.append(
            {
                "label": label,
                "classification": case_classification,
                "capture_medium": case_medium,
                "manifest_path": manifest_path,
                "payload_path": payload_path,
                "image_paths": image_paths,
                "reference_image_paths": reference_image_paths,
                "raw_image_paths": raw_image_paths,
                "capture_metadata": merged_capture_metadata,
                "perspective_correction": _normalize_perspective_correction(
                    raw_case.get("perspective_correction")
                ),
                "description": str(raw_case.get("description") or "").strip() or None,
            }
        )

    return {
        "schema": schema,
        "classification": classification,
        "capture_medium": corpus_medium,
        "path": corpus_path,
        "metadata": corpus_metadata,
        "case_count": len(normalized_cases),
        "cases": normalized_cases,
    }


def _copy_image_set(image_paths: List[Path], target_dir: Path) -> List[Path]:
    target_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for index, source in enumerate(image_paths, 1):
        suffix = source.suffix.lower() or ".png"
        target = target_dir / "case_{:04d}{}".format(index, suffix)
        shutil.copy2(str(source), str(target))
        copied.append(target)
    return copied


def _image_digests(image_paths: List[Path]) -> List[Dict[str, object]]:
    return [
        {
            "path": str(path),
            "sha256": _sha256_file(path),
            "size_bytes": path.stat().st_size if path.exists() else None,
        }
        for path in image_paths
        if path.exists()
    ]


def _absolute_digest_records(paths: List[Path]) -> List[Dict[str, object]]:
    records = []
    for path in paths:
        if not path.exists():
            continue
        records.append(
            {
                "path": str(path.resolve()),
                "sha256": _sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return records


def _normalize_report_digest_record(
    record: object,
    base_dir: Path,
) -> Optional[Dict[str, object]]:
    if not isinstance(record, dict):
        return None
    raw_path = str(record.get("path") or "").strip()
    if not raw_path:
        return None
    path = Path(raw_path)
    if not path.is_absolute():
        path = base_dir / path
    size_value = record.get("size_bytes")
    try:
        size_bytes = int(size_value) if size_value is not None else None
    except Exception:
        size_bytes = None
    return {
        "path": str(path.resolve()),
        "sha256": str(record.get("sha256") or "").strip().lower() or None,
        "size_bytes": size_bytes,
    }


def _record_key(record: Dict[str, object]) -> tuple:
    return (
        str(record.get("path") or ""),
        str(record.get("sha256") or ""),
        record.get("size_bytes"),
    )


def _compare_digest_record_sets(
    current_records: List[Dict[str, object]],
    reported_records: List[Dict[str, object]],
) -> Dict[str, object]:
    current_keys = [_record_key(record) for record in current_records]
    reported_keys = [_record_key(record) for record in reported_records]
    current_counts = Counter(current_keys)
    reported_counts = Counter(reported_keys)
    missing_records = []
    unexpected_records = []
    current_by_key = {key: record for key, record in zip(current_keys, current_records)}
    reported_by_key = {key: record for key, record in zip(reported_keys, reported_records)}
    for key, count in reported_counts.items():
        missing_count = count - current_counts.get(key, 0)
        if missing_count > 0:
            missing_records.extend([reported_by_key[key]] * missing_count)
    for key, count in current_counts.items():
        unexpected_count = count - reported_counts.get(key, 0)
        if unexpected_count > 0:
            unexpected_records.extend([current_by_key[key]] * unexpected_count)
    return {
        "current_count": len(current_records),
        "reported_count": len(reported_records),
        "matching_count": sum((current_counts & reported_counts).values()),
        "exact_match": not missing_records and not unexpected_records,
        "missing_reported_records": missing_records,
        "unexpected_current_records": unexpected_records,
    }


def _attachment_report_case_map(report: Dict[str, object]) -> Dict[str, object]:
    cases = report.get("cases")
    case_map: Dict[str, object] = {}
    duplicates = []
    if isinstance(cases, list):
        for raw_case in cases:
            if not isinstance(raw_case, dict):
                continue
            label = str(raw_case.get("label") or "").strip()
            if not label:
                continue
            if label in case_map:
                duplicates.append(label)
                continue
            case_map[label] = raw_case
    return {"cases": case_map, "duplicate_labels": duplicates}


def _resolve_capture_attachment_report(
    capture_corpus: Optional[Dict[str, object]],
    capture_attachment_report_file: Optional[str],
    require_capture_attachment_report: bool,
) -> Optional[Dict[str, object]]:
    if capture_corpus is None:
        if capture_attachment_report_file or require_capture_attachment_report:
            raise ValueError("capture attachment report requires a capture_corpus_file")
        return None

    corpus_path = Path(str(capture_corpus.get("path"))).resolve()
    corpus_base = corpus_path.parent
    raw_path = str(capture_attachment_report_file or "").strip()
    path: Optional[Path] = None
    explicit = bool(raw_path)
    if raw_path:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = candidate if candidate.exists() else corpus_base / candidate
        path = candidate.resolve()
    else:
        metadata = capture_corpus.get("metadata")
        last_attachment = (
            metadata.get("last_capture_attachment")
            if isinstance(metadata, dict)
            else None
        )
        metadata_report = (
            last_attachment.get("report_file")
            if isinstance(last_attachment, dict)
            else None
        )
        if metadata_report:
            candidate = Path(str(metadata_report))
            if not candidate.is_absolute():
                candidate = corpus_base / candidate
            path = candidate.resolve()
        else:
            candidate = corpus_base / "transport_capture_attachment_report.json"
            if candidate.exists():
                path = candidate.resolve()

    if path is None:
        if require_capture_attachment_report:
            raise ValueError(
                "require_capture_attachment_report requires capture_attachment_report_file "
                "or capture corpus last_capture_attachment.report_file"
            )
        return None
    if not path.exists() or not path.is_file():
        if explicit or require_capture_attachment_report:
            raise ValueError("capture attachment report file does not exist: {}".format(path))
        return None
    report = _load_json(path)
    schema = str(report.get("schema") or "").strip()
    if schema != CAPTURE_ATTACHMENT_REPORT_SCHEMA:
        raise ValueError(
            "capture attachment report schema must be {}, got {}".format(
                CAPTURE_ATTACHMENT_REPORT_SCHEMA,
                schema or "<missing>",
            )
        )
    case_map = _attachment_report_case_map(report)
    return {
        "path": path,
        "report": report,
        "case_map": case_map.get("cases", {}),
        "duplicate_labels": case_map.get("duplicate_labels", []),
        "corpus_base": corpus_base,
        "corpus_path": corpus_path,
    }


def _capture_attachment_report_evidence(
    label: str,
    classification: str,
    capture_medium: str,
    capture_image_paths: List[Path],
    raw_image_paths: List[Path],
    reference_image_paths: List[Path],
    attachment_report: Optional[Dict[str, object]],
    required: bool,
) -> Dict[str, object]:
    current_attached_records = _absolute_digest_records(capture_image_paths)
    current_raw_records = _absolute_digest_records(raw_image_paths)
    current_reference_records = _absolute_digest_records(reference_image_paths)

    if attachment_report is None:
        return {
            "required": bool(required),
            "provided": False,
            "report_file": None,
            "report_sha256": None,
            "case_label": label,
            "checks": [
                _profile_check(
                    "attachment_report_provided",
                    not bool(required),
                    "capture attachment report must be supplied or discoverable",
                    False,
                )
            ],
            "evidence_passed": False,
            "strict_gate_passed": not bool(required),
            "status": "missing-attachment-report" if required else "not-provided",
            "certification_boundary": (
                "Attachment-report lineage proves only that certification measured the same "
                "capture files recorded by soenc transport attach-capture-corpus."
            ),
        }

    report = attachment_report.get("report")
    case_map = attachment_report.get("case_map")
    corpus_base = attachment_report.get("corpus_base")
    corpus_path = attachment_report.get("corpus_path")
    report_path = attachment_report.get("path")
    duplicate_labels = attachment_report.get("duplicate_labels") or []
    if not isinstance(report, dict):
        report = {}
    if not isinstance(case_map, dict):
        case_map = {}
    if not isinstance(corpus_base, Path):
        corpus_base = Path.cwd()
    if not isinstance(corpus_path, Path):
        corpus_path = Path(str(corpus_path or "")).resolve()
    if not isinstance(report_path, Path):
        report_path = Path(str(report_path or "")).resolve()

    report_case = case_map.get(label)
    reported_attached_records = []
    reported_raw_records = []
    reported_reference_records = []
    if isinstance(report_case, dict):
        for raw_record in report_case.get("attached_images", []) or []:
            normalized = _normalize_report_digest_record(raw_record, corpus_base)
            if normalized is not None:
                reported_attached_records.append(normalized)
        for raw_record in report_case.get("raw_images", []) or []:
            normalized = _normalize_report_digest_record(raw_record, corpus_base)
            if normalized is not None:
                reported_raw_records.append(normalized)
        for raw_record in report_case.get("reference_images", []) or []:
            normalized = _normalize_report_digest_record(raw_record, corpus_base)
            if normalized is not None:
                reported_reference_records.append(normalized)

    report_corpus_file = str(report.get("capture_corpus_file") or "").strip()
    report_corpus_path = Path(report_corpus_file) if report_corpus_file else None
    if report_corpus_path is not None and not report_corpus_path.is_absolute():
        report_corpus_path = corpus_base / report_corpus_path
    attached_comparison = _compare_digest_record_sets(
        current_records=current_attached_records,
        reported_records=reported_attached_records,
    )
    raw_comparison = _compare_digest_record_sets(
        current_records=current_raw_records,
        reported_records=reported_raw_records,
    )
    reference_comparison = _compare_digest_record_sets(
        current_records=current_reference_records,
        reported_records=reported_reference_records,
    )
    reported_classification = (
        str(report_case.get("classification") or "").strip().lower()
        if isinstance(report_case, dict)
        else None
    )
    reported_medium = (
        _normalize_capture_medium(report_case.get("capture_medium"))
        if isinstance(report_case, dict)
        else None
    )
    checks = [
        _profile_check(
            "attachment_report_provided",
            True,
            "capture attachment report must be supplied or discoverable",
            str(report_path),
        ),
        _profile_check(
            "attachment_report_success",
            bool(report.get("success")),
            "attachment report must have succeeded",
            report.get("success"),
        ),
        _profile_check(
            "attachment_report_corpus_file_matches",
            bool(report_corpus_path is not None and report_corpus_path.resolve() == corpus_path.resolve()),
            "attachment report must reference the same capture corpus",
            report_corpus_file or None,
        ),
        _profile_check(
            "attachment_report_case_labels_unique",
            not duplicate_labels,
            "attachment report case labels must be unique",
            duplicate_labels,
        ),
        _profile_check(
            "attachment_report_case_present",
            isinstance(report_case, dict),
            "attachment report must contain the capture case label",
            label,
        ),
        _profile_check(
            "attachment_report_case_ready",
            bool(isinstance(report_case, dict) and report_case.get("ready_for_certification")),
            "attachment report case must be ready for certification",
            report_case.get("ready_for_certification") if isinstance(report_case, dict) else None,
        ),
        _profile_check(
            "attachment_report_classification_matches",
            reported_classification == classification,
            "attachment report case classification must match the capture corpus",
            reported_classification,
        ),
        _profile_check(
            "attachment_report_capture_medium_matches",
            reported_medium == capture_medium,
            "attachment report case capture medium must match the capture corpus",
            reported_medium,
        ),
        _profile_check(
            "attached_image_records_match",
            bool(attached_comparison.get("exact_match")),
            "current capture images must match attachment report paths, sizes, and SHA256 values",
            {
                "current_count": attached_comparison.get("current_count"),
                "reported_count": attached_comparison.get("reported_count"),
                "matching_count": attached_comparison.get("matching_count"),
            },
        ),
        _profile_check(
            "raw_image_records_match",
            bool(raw_comparison.get("exact_match")),
            "current raw camera images must match attachment report paths, sizes, and SHA256 values",
            {
                "current_count": raw_comparison.get("current_count"),
                "reported_count": raw_comparison.get("reported_count"),
                "matching_count": raw_comparison.get("matching_count"),
            },
        ),
        _profile_check(
            "reference_image_records_match",
            bool(reference_comparison.get("exact_match")),
            "current reference images must match attachment report paths, sizes, and SHA256 values",
            {
                "current_count": reference_comparison.get("current_count"),
                "reported_count": reference_comparison.get("reported_count"),
                "matching_count": reference_comparison.get("matching_count"),
            },
        ),
    ]
    evidence_passed = all(bool(check.get("passed")) for check in checks)
    if evidence_passed:
        status = "capture-attachment-bound"
    elif not required:
        status = "not-required"
    else:
        failed = [str(check.get("name")) for check in checks if not check.get("passed")]
        status = "mismatch-{}".format(failed[0] if failed else "evidence")
    return {
        "required": bool(required),
        "provided": True,
        "report_file": str(report_path),
        "report_sha256": _sha256_file(report_path),
        "report_generated_at_utc": report.get("generated_at_utc"),
        "case_label": label,
        "attachment_report_success": bool(report.get("success")),
        "attachment_case_ready": bool(
            isinstance(report_case, dict) and report_case.get("ready_for_certification")
        ),
        "current_attached_images": current_attached_records,
        "reported_attached_images": reported_attached_records,
        "attached_image_comparison": attached_comparison,
        "current_raw_images": current_raw_records,
        "reported_raw_images": reported_raw_records,
        "raw_image_comparison": raw_comparison,
        "current_reference_images": current_reference_records,
        "reported_reference_images": reported_reference_records,
        "reference_image_comparison": reference_comparison,
        "checks": checks,
        "evidence_passed": evidence_passed,
        "strict_gate_passed": bool((not required) or evidence_passed),
        "status": status,
        "certification_boundary": (
            "Attachment-report lineage proves only that certification measured the same "
            "capture files recorded by soenc transport attach-capture-corpus. It does not "
            "certify a camera, scanner, OCR backend, or physical medium by itself."
        ),
    }


def _capture_reference_transform(
    reference_image_paths: List[Path],
    capture_image_paths: List[Path],
    require_distinct_capture_images: bool,
    missing_capture_passes_when_not_required: bool = False,
) -> Dict[str, object]:
    reference_records = _image_digests(reference_image_paths)
    capture_records = _image_digests(capture_image_paths)
    reference_by_sha: Dict[str, List[Dict[str, object]]] = {}
    for record in reference_records:
        digest = str(record.get("sha256") or "")
        if not digest:
            continue
        reference_by_sha.setdefault(digest, []).append(record)

    byte_identical_matches = []
    for capture_record in capture_records:
        digest = str(capture_record.get("sha256") or "")
        if not digest or digest not in reference_by_sha:
            continue
        for reference_record in reference_by_sha[digest]:
            byte_identical_matches.append(
                {
                    "capture_path": capture_record.get("path"),
                    "reference_path": reference_record.get("path"),
                    "sha256": digest,
                    "size_bytes": capture_record.get("size_bytes"),
                }
            )

    reference_images_provided = bool(reference_records)
    capture_images_provided = bool(capture_records)
    distinct_from_reference = bool(
        reference_images_provided and capture_images_provided and not byte_identical_matches
    )
    if not reference_images_provided:
        status = "reference-images-missing"
    elif not capture_images_provided:
        status = "capture-images-missing"
    elif byte_identical_matches:
        status = "byte-identical-to-reference"
    else:
        status = "distinct-from-reference"
    strict_passed = (
        (not require_distinct_capture_images)
        or distinct_from_reference
        or (bool(missing_capture_passes_when_not_required) and not capture_images_provided)
    )
    return {
        "reference_images_provided": reference_images_provided,
        "reference_image_count": len(reference_records),
        "capture_image_count": len(capture_records),
        "distinct_required": bool(require_distinct_capture_images),
        "missing_capture_passes_when_not_required": bool(missing_capture_passes_when_not_required),
        "distinct_from_reference": distinct_from_reference,
        "byte_identical_match_count": len(byte_identical_matches),
        "byte_identical_matches": byte_identical_matches,
        "strict_gate_passed": bool(strict_passed),
        "status": status,
    }


def _digest_overlap(
    left_records: List[Dict[str, object]],
    right_records: List[Dict[str, object]],
    left_label: str,
    right_label: str,
) -> List[Dict[str, object]]:
    right_by_sha: Dict[str, List[Dict[str, object]]] = {}
    for record in right_records:
        digest = str(record.get("sha256") or "")
        if digest:
            right_by_sha.setdefault(digest, []).append(record)

    overlaps = []
    for left_record in left_records:
        digest = str(left_record.get("sha256") or "")
        if not digest or digest not in right_by_sha:
            continue
        for right_record in right_by_sha[digest]:
            overlaps.append(
                {
                    "{}_path".format(left_label): left_record.get("path"),
                    "{}_path".format(right_label): right_record.get("path"),
                    "sha256": digest,
                    "size_bytes": left_record.get("size_bytes"),
                }
            )
    return overlaps


def _capture_perspective_correction_evidence(
    classification: str,
    raw_image_paths: List[Path],
    corrected_image_paths: List[Path],
    reference_image_paths: List[Path],
    perspective_correction: Dict[str, object],
    required: bool,
) -> Dict[str, object]:
    raw_records = _image_digests(raw_image_paths)
    corrected_records = _image_digests(corrected_image_paths)
    reference_records = _image_digests(reference_image_paths)
    raw_reference_transform = _capture_reference_transform(
        reference_image_paths=reference_image_paths,
        capture_image_paths=raw_image_paths,
        require_distinct_capture_images=bool(required),
        missing_capture_passes_when_not_required=True,
    )
    corrected_reference_transform = _capture_reference_transform(
        reference_image_paths=reference_image_paths,
        capture_image_paths=corrected_image_paths,
        require_distinct_capture_images=bool(required),
        missing_capture_passes_when_not_required=True,
    )
    raw_corrected_matches = _digest_overlap(
        left_records=raw_records,
        right_records=corrected_records,
        left_label="raw",
        right_label="corrected",
    )
    method = str(
        perspective_correction.get("method")
        or perspective_correction.get("algorithm")
        or ""
    ).strip()
    applied = _boolish(perspective_correction.get("applied"))
    metadata_present = bool(perspective_correction)
    raw_corrected_distinct = bool(raw_records and corrected_records and not raw_corrected_matches)
    checks = [
        _profile_check(
            "classification_real",
            classification == "real",
            "real camera perspective evidence must use corpus classification real",
            classification,
        ),
        _profile_check(
            "raw_camera_images_present",
            bool(raw_records),
            "raw camera/photo images before perspective correction must be attached",
            len(raw_records),
        ),
        _profile_check(
            "corrected_images_present",
            bool(corrected_records),
            "perspective-corrected images used for recovery must be attached",
            len(corrected_records),
        ),
        _profile_check(
            "reference_images_present",
            bool(reference_records),
            "generated reference pages must be declared for camera evidence",
            len(reference_records),
        ),
        _profile_check(
            "perspective_correction_metadata_present",
            metadata_present,
            "case must declare perspective_correction metadata",
            sorted(perspective_correction.keys()),
        ),
        _profile_check(
            "perspective_correction_applied",
            applied,
            "perspective_correction.applied must be true",
            perspective_correction.get("applied"),
        ),
        _profile_check(
            "perspective_correction_method_declared",
            bool(method),
            "perspective correction method or algorithm must be declared",
            method or None,
        ),
        _profile_check(
            "raw_distinct_from_reference",
            bool(raw_reference_transform.get("distinct_from_reference")),
            "raw camera images must not be byte-identical to generated reference pages",
            raw_reference_transform.get("status"),
        ),
        _profile_check(
            "corrected_distinct_from_reference",
            bool(corrected_reference_transform.get("distinct_from_reference")),
            "corrected images must not be byte-identical to generated reference pages",
            corrected_reference_transform.get("status"),
        ),
        _profile_check(
            "raw_distinct_from_corrected",
            raw_corrected_distinct,
            "raw camera images and corrected images must not be byte-identical",
            {"byte_identical_match_count": len(raw_corrected_matches)},
        ),
    ]
    evidence_passed = all(bool(check.get("passed")) for check in checks)
    if evidence_passed:
        status = "real-camera-perspective-correction"
    elif not required:
        status = "not-required"
    else:
        failed = [str(check.get("name")) for check in checks if not check.get("passed")]
        status = "missing-{}".format(failed[0] if failed else "evidence")
    return {
        "required": bool(required),
        "classification": classification,
        "provided": metadata_present or bool(raw_records),
        "applied": applied,
        "method": method or None,
        "metadata": dict(perspective_correction),
        "raw_images": raw_records,
        "corrected_images": corrected_records,
        "reference_images": reference_records,
        "raw_image_count": len(raw_records),
        "corrected_image_count": len(corrected_records),
        "reference_image_count": len(reference_records),
        "raw_reference_transform": raw_reference_transform,
        "corrected_reference_transform": corrected_reference_transform,
        "raw_corrected_byte_identical_match_count": len(raw_corrected_matches),
        "raw_corrected_byte_identical_matches": raw_corrected_matches,
        "raw_distinct_from_corrected": raw_corrected_distinct,
        "checks": checks,
        "evidence_passed": evidence_passed,
        "strict_gate_passed": bool((not required) or evidence_passed),
        "status": status,
    }


def _capture_provenance_evidence(
    classification: str,
    capture_medium: str,
    capture_metadata: Dict[str, object],
    required: bool,
) -> Dict[str, object]:
    metadata = dict(capture_metadata or {})
    session_id = _first_metadata_value(metadata, CAPTURE_PROVENANCE_SESSION_KEYS)
    operator = _first_metadata_value(metadata, CAPTURE_PROVENANCE_OPERATOR_KEYS)
    captured_at = _first_metadata_value(metadata, CAPTURE_PROVENANCE_TIMESTAMP_KEYS)
    device = _first_metadata_value(metadata, CAPTURE_PROVENANCE_DEVICE_KEYS)
    location = _first_metadata_value(metadata, CAPTURE_PROVENANCE_LOCATION_KEYS)
    medium_value = _normalize_capture_medium(capture_medium)
    classification_value = str(classification or "").strip().lower()
    evidence_is_applicable = classification_value in ("lab", "real") or medium_value in (
        "camera-photo",
        "print-scan",
        "mixed",
    )
    checks = [
        _profile_check(
            "classification_lab_or_real",
            classification_value in ("lab", "real"),
            "capture provenance applies to lab or real operator-supplied captures",
            classification_value,
        ),
        _profile_check(
            "capture_medium_declared",
            medium_value != "unspecified",
            "capture medium must be declared",
            medium_value,
        ),
        _profile_check(
            "capture_session_id_present",
            bool(session_id),
            "capture_metadata must include capture_session_id or session_id",
            session_id,
        ),
        _profile_check(
            "operator_present",
            bool(operator),
            "capture_metadata must identify the operator or captured_by identity",
            operator,
        ),
        _profile_check(
            "captured_at_present",
            bool(captured_at),
            "capture_metadata must include captured_at_utc or equivalent capture timestamp",
            captured_at,
        ),
        _profile_check(
            "capture_device_present",
            bool(device),
            "capture_metadata must identify the capture, scanner, printer, or camera device",
            device,
        ),
    ]
    evidence_passed = all(bool(check.get("passed")) for check in checks)
    if evidence_passed:
        status = "capture-provenance-bound"
    elif not required:
        status = "not-required"
    else:
        failed = [str(check.get("name")) for check in checks if not check.get("passed")]
        status = "missing-{}".format(failed[0] if failed else "evidence")
    return {
        "required": bool(required),
        "classification": classification_value,
        "capture_medium": medium_value,
        "provided": bool(metadata),
        "applicable": bool(evidence_is_applicable),
        "session_id": session_id,
        "operator": operator,
        "captured_at": captured_at,
        "device": device,
        "location": location,
        "metadata": metadata,
        "required_metadata_keys": {
            "session": list(CAPTURE_PROVENANCE_SESSION_KEYS),
            "operator": list(CAPTURE_PROVENANCE_OPERATOR_KEYS),
            "captured_at": list(CAPTURE_PROVENANCE_TIMESTAMP_KEYS),
            "device": list(CAPTURE_PROVENANCE_DEVICE_KEYS),
        },
        "checks": checks,
        "evidence_passed": evidence_passed,
        "strict_gate_passed": bool((not required) or evidence_passed),
        "status": status,
        "certification_boundary": (
            "Capture provenance binds the measured corpus to operator/session/device "
            "metadata only. It does not certify any new transport medium without a "
            "passing recovery report and matching certification claim gate."
        ),
    }


def _capture_metadata_manifest_template_defaults(
    capture_metadata: Dict[str, object],
    capture_medium: str,
) -> Dict[str, object]:
    defaults = dict(capture_metadata or {})
    medium_value = _normalize_capture_medium(capture_medium)
    if medium_value != "unspecified":
        defaults.setdefault("capture_medium", medium_value)
    defaults.setdefault("capture_session_id", "")
    defaults.setdefault("operator", "")
    defaults.setdefault("captured_at_utc", "")
    if medium_value in ("print-scan", "mixed"):
        defaults.setdefault("printer", "")
        defaults.setdefault("scanner", "")
        defaults.setdefault("dpi", "")
        if "scanner" not in capture_metadata:
            defaults.setdefault("scanner_model", "")
        if "printer" not in capture_metadata:
            defaults.setdefault("printer_model", "")
    if medium_value in ("camera-photo", "mixed"):
        defaults.setdefault("camera", "")
        defaults.setdefault("camera_model", "")
    return defaults


def _capture_physical_print_scan_evidence(
    classification: str,
    capture_medium: str,
    capture_image_paths: List[Path],
    reference_image_paths: List[Path],
    capture_metadata: Dict[str, object],
    reference_transform: Dict[str, object],
    required: bool,
) -> Dict[str, object]:
    capture_records = _image_digests(capture_image_paths)
    reference_records = _image_digests(reference_image_paths)
    metadata = dict(capture_metadata or {})
    printer_value = str(
        metadata.get("printer")
        or metadata.get("printer_model")
        or metadata.get("print_device")
        or ""
    ).strip()
    scanner_value = str(
        metadata.get("scanner")
        or metadata.get("scanner_model")
        or metadata.get("scan_device")
        or ""
    ).strip()
    dpi_value = str(metadata.get("dpi") or metadata.get("scan_dpi") or "").strip()
    medium_value = _normalize_capture_medium(capture_medium)
    allowed_classification = classification in ("lab", "real")
    checks = [
        _profile_check(
            "classification_lab_or_real",
            allowed_classification,
            "physical print-scan evidence must use corpus classification lab or real",
            classification,
        ),
        _profile_check(
            "capture_medium_print_scan",
            medium_value == "print-scan",
            "capture medium must be print-scan",
            medium_value,
        ),
        _profile_check(
            "capture_images_present",
            bool(capture_records),
            "scanned capture images used for recovery must be attached",
            len(capture_records),
        ),
        _profile_check(
            "reference_images_present",
            bool(reference_records),
            "generated reference pages must be declared for print-scan evidence",
            len(reference_records),
        ),
        _profile_check(
            "scan_distinct_from_reference",
            bool(reference_transform.get("distinct_from_reference")),
            "scan images must not be byte-identical to generated reference pages",
            reference_transform.get("status"),
        ),
        _profile_check(
            "printer_metadata_present",
            bool(printer_value),
            "capture_metadata must identify the printer or print device",
            printer_value or None,
        ),
        _profile_check(
            "scanner_metadata_present",
            bool(scanner_value),
            "capture_metadata must identify the scanner or scan device",
            scanner_value or None,
        ),
        _profile_check(
            "scan_dpi_metadata_present",
            bool(dpi_value),
            "capture_metadata must record scan dpi",
            dpi_value or None,
        ),
    ]
    evidence_passed = all(bool(check.get("passed")) for check in checks)
    if evidence_passed:
        status = "physical-print-scan"
    elif not required:
        status = "not-required"
    else:
        failed = [str(check.get("name")) for check in checks if not check.get("passed")]
        status = "missing-{}".format(failed[0] if failed else "evidence")
    return {
        "required": bool(required),
        "classification": classification,
        "capture_medium": medium_value,
        "provided": bool(capture_records) or medium_value == "print-scan",
        "metadata": metadata,
        "printer": printer_value or None,
        "scanner": scanner_value or None,
        "dpi": dpi_value or None,
        "scan_images": capture_records,
        "reference_images": reference_records,
        "scan_image_count": len(capture_records),
        "reference_image_count": len(reference_records),
        "reference_transform": dict(reference_transform),
        "checks": checks,
        "evidence_passed": evidence_passed,
        "strict_gate_passed": bool((not required) or evidence_passed),
        "status": status,
        "certification_boundary": (
            "This proves only the measured printer/scanner/capture corpus. It does not certify "
            "other print devices, scanners, paper, camera captures, OCR backends, or generic "
            "physical transfer conditions."
        ),
    }


def _capture_ocr_only_evidence(
    backend: str,
    manifest_path: Path,
    manifest: Dict[str, object],
    required: bool,
) -> Dict[str, object]:
    backend_value = str(backend or "").strip().lower()
    sidecar_present = _manifest_has_binary_sidecar(manifest) if isinstance(manifest, dict) else False
    sidecar_enabled = _capture_sidecar_present(manifest) if isinstance(manifest, dict) else None
    checks = [
        _profile_check(
            "backend_is_ocr_only",
            backend_value in OCR_ONLY_CERTIFICATION_BACKENDS,
            "backend must be one of {}".format(", ".join(OCR_ONLY_CERTIFICATION_BACKENDS)),
            backend_value or None,
        ),
        _profile_check(
            "capture_manifest_required",
            manifest_path.exists() and manifest_path.is_file(),
            "operator capture case must bind an existing manifest",
            str(manifest_path),
        ),
        _profile_check(
            "binary_sidecar_absent",
            not sidecar_present,
            "OCR-only captures must not include binary sidecar boxes",
            sidecar_present,
        ),
        _profile_check(
            "sidecar_rendering_disabled",
            sidecar_enabled is False or not sidecar_present,
            "manifest must record sidecar-free page rendering",
            sidecar_enabled,
        ),
    ]
    evidence_passed = all(bool(check.get("passed")) for check in checks)
    if evidence_passed:
        status = "ocr-only-backend-ready"
    elif not required:
        status = "not-required"
    else:
        failed = [str(check.get("name")) for check in checks if not check.get("passed")]
        status = "missing-{}".format(failed[0] if failed else "evidence")
    return {
        "required": bool(required),
        "backend": backend_value or None,
        "supported_backends": list(OCR_ONLY_CERTIFICATION_BACKENDS),
        "provided": bool(manifest),
        "binary_sidecar_present": bool(sidecar_present),
        "sidecar_enabled": sidecar_enabled,
        "checks": checks,
        "evidence_passed": evidence_passed,
        "strict_gate_passed": bool((not required) or evidence_passed),
        "status": status,
        "certification_boundary": (
            "This preflights only sidecar-free backend-specific OCR-only inputs. It does "
            "not run OCR recovery, does not certify generic OCR fallback, and is not a "
            "reliable-airgap-v1 production proof."
        ),
    }


def _relative_digest_records(paths: List[Path], base_dir: Path) -> List[Dict[str, object]]:
    records = []
    for path in paths:
        if not path.exists():
            continue
        records.append(
            {
                "path": _safe_relative_path(path.resolve(), base_dir.resolve()),
                "sha256": _sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return records


def _corpus_relative_path(path: Path, corpus_base: Path) -> str:
    return _safe_relative_path(path.resolve(), corpus_base.resolve())


def _capture_subdir_path(
    root_dir: Path,
    label: str,
    suffixes: Iterable[str] = (),
) -> Optional[Path]:
    candidates = [root_dir / label]
    slug = _label_slug(label, "capture_case")
    if slug != label:
        candidates.append(root_dir / slug)
    for suffix in suffixes:
        suffix_text = str(suffix or "").strip()
        if not suffix_text:
            continue
        candidates.append(root_dir / "{}{}".format(label, suffix_text))
        if slug != label:
            candidates.append(root_dir / "{}{}".format(slug, suffix_text))
    seen = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        if resolved.exists() and (resolved.is_dir() or resolved.is_file()):
            return resolved
    return None


def _capture_subdir_names(label: str, suffixes: Iterable[str] = ()) -> Set[str]:
    names = {str(label)}
    slug = _label_slug(label, "capture_case")
    names.add(slug)
    for suffix in suffixes:
        suffix_text = str(suffix or "").strip()
        if not suffix_text:
            continue
        names.add("{}{}".format(label, suffix_text))
        names.add("{}{}".format(slug, suffix_text))
    return names


def _safe_join_under(base_dir: Path, relative_name: str) -> Optional[Path]:
    target = (base_dir / relative_name).resolve()
    try:
        target.relative_to(base_dir.resolve())
    except ValueError:
        return None
    return target


def _is_sha256_hex(value: object) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _safe_extract_capture_return_package(
    *,
    package_file: str,
    output_dir: Path,
    expected_capture_corpus_file: Optional[str] = None,
    expected_kit_manifest_file: Optional[str] = None,
    expected_capture_return_package_report_file: Optional[str] = None,
    require_capture_return_manifest: bool = False,
    require_capture_return_file_inventory: bool = False,
    require_capture_return_package_report: bool = False,
    report_file: Optional[str] = None,
) -> Dict[str, object]:
    package_path = Path(str(package_file)).resolve()
    if not package_path.exists() or not package_path.is_file():
        raise ValueError("capture return package file does not exist: {}".format(package_path))

    extract_dir = (output_dir / "operator_return_package").resolve()
    extract_dir.mkdir(parents=True, exist_ok=True)
    report_path = _resolve_output_path(
        report_file,
        output_dir,
        "transport_capture_return_package_extraction_report.json",
    ).resolve()

    failures: List[Dict[str, object]] = []
    extracted_files: List[Dict[str, object]] = []
    member_names: List[str] = []
    member_counts: Counter = Counter()
    directory_member_count = 0

    def add_failure(code: str, message: str, **details: object) -> None:
        record: Dict[str, object] = {"code": code, "message": message}
        record.update(details)
        failures.append(record)

    try:
        with zipfile.ZipFile(str(package_path), "r") as archive:
            infos = archive.infolist()
            member_names = [info.filename for info in infos]
            member_counts = Counter(member_names)
            safe_infos: List[zipfile.ZipInfo] = []
            for name, count in member_counts.items():
                if count != 1:
                    add_failure(
                        "duplicate_package_member",
                        "capture return package contains a duplicate member path",
                        package_path=name,
                        count=count,
                    )
            for info in infos:
                file_type = (info.external_attr >> 16) & 0o170000
                if file_type == 0o120000:
                    add_failure(
                        "package_member_is_symlink",
                        "capture return package member is a symlink",
                        package_path=info.filename,
                    )
                    continue
                if _is_safe_archive_directory_member(info.filename):
                    directory_member_count += 1
                    target_dir = _safe_join_under(extract_dir, info.filename.rstrip("/"))
                    if target_dir is None:
                        add_failure(
                            "unsafe_package_extraction_path",
                            "capture return package directory would extract outside output directory",
                            package_path=info.filename,
                        )
                    continue
                if not _is_safe_archive_member(info.filename):
                    add_failure(
                        "unsafe_package_member",
                        "capture return package member path is not a safe relative file path",
                        package_path=info.filename,
                    )
                    continue
                target = _safe_join_under(extract_dir, info.filename)
                if target is None:
                    add_failure(
                        "unsafe_package_extraction_path",
                        "capture return package member would extract outside output directory",
                        package_path=info.filename,
                    )
                    continue
                safe_infos.append(info)
            if not failures:
                for info in safe_infos:
                    target = _safe_join_under(extract_dir, info.filename)
                    if target is None:
                        add_failure(
                            "unsafe_package_extraction_path",
                            "capture return package member would extract outside output directory",
                            package_path=info.filename,
                        )
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    payload = archive.read(info)
                    target.write_bytes(payload)
                    extracted_files.append(
                        {
                            "package_path": info.filename,
                            "path": str(target),
                            "sha256": _sha256_bytes(payload),
                            "size_bytes": len(payload),
                        }
                    )
    except zipfile.BadZipFile:
        add_failure("package_unreadable", "capture return package is not a readable ZIP file")

    capture_root = extract_dir / "captures"
    raw_capture_root = extract_dir / "raw_captures"
    if not capture_root.exists() or not capture_root.is_dir():
        capture_root = extract_dir / "capture_root"
    if not raw_capture_root.exists() or not raw_capture_root.is_dir():
        raw_capture_root = extract_dir / "raw_capture_root"
    if not capture_root.exists() or not capture_root.is_dir():
        add_failure(
            "capture_root_missing",
            "capture return package must contain a captures/ or capture_root/ directory",
        )

    metadata_manifest_path: Optional[Path] = None
    for candidate in CAPTURE_RETURN_METADATA_MANIFEST_CANDIDATES:
        path = extract_dir / candidate
        if path.exists() and path.is_file():
            metadata_manifest_path = path.resolve()
            break

    expected_corpus_path: Optional[Path] = None
    expected_corpus_sha256: Optional[str] = None
    expected_corpus_case_labels: Set[str] = set()
    if expected_capture_corpus_file is not None and str(expected_capture_corpus_file).strip():
        expected_corpus_path = Path(str(expected_capture_corpus_file)).resolve()
        expected_corpus_sha256 = _sha256_file(expected_corpus_path)
        if expected_corpus_path.exists() and expected_corpus_path.is_file():
            try:
                expected_corpus = _load_json(expected_corpus_path)
                raw_expected_cases = expected_corpus.get("cases", [])
                if isinstance(raw_expected_cases, list):
                    for index, raw_case in enumerate(raw_expected_cases, 1):
                        if isinstance(raw_case, dict):
                            expected_corpus_case_labels.add(
                                _normalize_label(
                                    raw_case.get("label"),
                                    "capture_{:04d}".format(index),
                                )
                            )
            except Exception:
                expected_corpus_case_labels = set()

    expected_kit_path: Optional[Path] = None
    expected_kit_sha256: Optional[str] = None
    if expected_kit_manifest_file is not None and str(expected_kit_manifest_file).strip():
        expected_kit_path = Path(str(expected_kit_manifest_file)).resolve()
        expected_kit_sha256 = _sha256_file(expected_kit_path)

    expected_package_report_path: Optional[Path] = None
    expected_package_report_sha256: Optional[str] = None
    package_report: Optional[Dict[str, object]] = None
    package_report_validated = False
    package_report_required = bool(require_capture_return_package_report)
    if (
        expected_capture_return_package_report_file is not None
        and str(expected_capture_return_package_report_file).strip()
    ):
        package_report_required = True
        expected_package_report_path = Path(
            str(expected_capture_return_package_report_file)
        ).resolve()
        if not expected_package_report_path.exists() or not expected_package_report_path.is_file():
            add_failure(
                "capture_return_package_report_missing",
                "capture return package report file does not exist",
                path=str(expected_package_report_path),
            )
        else:
            expected_package_report_sha256 = _sha256_file(expected_package_report_path)
            try:
                package_report = _load_json(expected_package_report_path)
                report_schema = str(package_report.get("schema") or "").strip()
                if report_schema != CAPTURE_RETURN_PACKAGE_SCHEMA:
                    add_failure(
                        "capture_return_package_report_schema_mismatch",
                        "capture return package report schema is not supported",
                        expected_schema=CAPTURE_RETURN_PACKAGE_SCHEMA,
                        observed_schema=report_schema or "<missing>",
                    )
                if not bool(package_report.get("success")):
                    add_failure(
                        "capture_return_package_report_not_successful",
                        "capture return package report must be successful",
                    )
                report_package_sha256 = str(package_report.get("package_sha256") or "").strip()
                if not report_package_sha256:
                    add_failure(
                        "capture_return_package_report_package_sha256_missing",
                        "capture return package report must record package_sha256",
                    )
                elif report_package_sha256 != _sha256_file(package_path):
                    add_failure(
                        "capture_return_package_report_package_sha256_mismatch",
                        "capture return package report does not match the supplied ZIP",
                        expected_sha256=report_package_sha256,
                        observed_sha256=_sha256_file(package_path),
                    )
                report_package_size = package_report.get("package_size_bytes")
                if report_package_size in (None, ""):
                    add_failure(
                        "capture_return_package_report_package_size_missing",
                        "capture return package report must record package_size_bytes",
                    )
                else:
                    try:
                        report_package_size_int = int(report_package_size)
                    except (TypeError, ValueError):
                        add_failure(
                            "capture_return_package_report_package_size_invalid",
                            "capture return package report package_size_bytes is not an integer",
                            observed_size=report_package_size,
                        )
                    else:
                        if report_package_size_int != package_path.stat().st_size:
                            add_failure(
                                "capture_return_package_report_package_size_mismatch",
                                "capture return package report size does not match the supplied ZIP",
                                expected_size_bytes=report_package_size_int,
                                observed_size_bytes=package_path.stat().st_size,
                            )
                report_corpus_sha256 = str(
                    package_report.get("capture_corpus_sha256") or ""
                ).strip()
                if expected_corpus_sha256 is not None:
                    if not report_corpus_sha256:
                        add_failure(
                            "capture_return_package_report_corpus_sha256_missing",
                            "capture return package report must bind the prepared capture corpus",
                        )
                    elif report_corpus_sha256 != expected_corpus_sha256:
                        add_failure(
                            "capture_return_package_report_corpus_sha256_mismatch",
                            "capture return package report does not match the prepared corpus",
                            expected_sha256=expected_corpus_sha256,
                            observed_sha256=report_corpus_sha256,
                        )
                report_kit_sha256 = str(
                    package_report.get("capture_kit_manifest_sha256") or ""
                ).strip()
                if expected_kit_sha256 is not None:
                    if not report_kit_sha256:
                        add_failure(
                            "capture_return_package_report_kit_sha256_missing",
                            "capture return package report must bind the prepared capture kit manifest",
                        )
                    elif report_kit_sha256 != expected_kit_sha256:
                        add_failure(
                            "capture_return_package_report_kit_sha256_mismatch",
                            "capture return package report does not match the prepared capture kit",
                            expected_sha256=expected_kit_sha256,
                            observed_sha256=report_kit_sha256,
                        )
            except Exception as exc:
                add_failure(
                    "capture_return_package_report_unreadable",
                    "capture return package report is not readable JSON",
                    error=str(exc),
                )
    elif package_report_required:
        add_failure(
            "capture_return_package_report_required",
            "capture return package report is required for this extraction gate",
        )

    return_manifest_path: Optional[Path] = None
    for candidate in CAPTURE_RETURN_MANIFEST_CANDIDATES:
        path = extract_dir / candidate
        if path.exists() and path.is_file():
            return_manifest_path = path.resolve()
            break

    return_manifest: Optional[Dict[str, object]] = None
    return_manifest_case_labels: List[str] = []
    return_manifest_file_inventory: List[Dict[str, object]] = []
    return_manifest_capture_file_paths: Set[str] = set()
    return_manifest_raw_file_paths: Set[str] = set()
    return_manifest_file_inventory_declared = False
    return_manifest_file_inventory_required = False
    return_manifest_file_inventory_validated = False
    return_manifest_validated = False
    if return_manifest_path is not None:
        try:
            return_manifest = _load_json(return_manifest_path)
            schema = str(return_manifest.get("schema") or "").strip()
            if schema != CAPTURE_RETURN_MANIFEST_SCHEMA:
                add_failure(
                    "capture_return_manifest_schema_mismatch",
                    "capture return manifest schema is not supported",
                    expected_schema=CAPTURE_RETURN_MANIFEST_SCHEMA,
                    observed_schema=schema or "<missing>",
                )
            raw_corpus_sha256 = str(return_manifest.get("capture_corpus_sha256") or "").strip()
            if expected_corpus_sha256 is not None:
                if not raw_corpus_sha256:
                    add_failure(
                        "capture_return_manifest_corpus_sha256_missing",
                        "capture return manifest must bind the prepared capture corpus SHA256",
                    )
                elif raw_corpus_sha256 != expected_corpus_sha256:
                    add_failure(
                        "capture_return_manifest_corpus_sha256_mismatch",
                        "capture return manifest does not match the prepared capture corpus",
                        expected_sha256=expected_corpus_sha256,
                        observed_sha256=raw_corpus_sha256,
                    )
            raw_kit_sha256 = str(return_manifest.get("capture_kit_manifest_sha256") or "").strip()
            if expected_kit_sha256 is not None and raw_kit_sha256:
                if raw_kit_sha256 != expected_kit_sha256:
                    add_failure(
                        "capture_return_manifest_kit_sha256_mismatch",
                        "capture return manifest does not match the prepared capture kit manifest",
                        expected_sha256=expected_kit_sha256,
                        observed_sha256=raw_kit_sha256,
                    )
            raw_cases = return_manifest.get("cases", [])
            if raw_cases is None:
                raw_cases = []
            if not isinstance(raw_cases, list):
                add_failure(
                    "capture_return_manifest_cases_invalid",
                    "capture return manifest cases must be a list",
                )
            else:
                raw_inventory_settings = return_manifest.get("capture_file_inventory", {})
                if raw_inventory_settings in (None, ""):
                    raw_inventory_settings = {}
                if isinstance(raw_inventory_settings, dict):
                    return_manifest_file_inventory_required = bool(
                        raw_inventory_settings.get("required")
                    )
                else:
                    add_failure(
                        "capture_return_manifest_file_inventory_invalid",
                        "capture return manifest file inventory settings must be an object",
                    )
                if bool(return_manifest.get("require_capture_file_inventory")):
                    return_manifest_file_inventory_required = True

                extracted_by_package_path = {
                    str(item.get("package_path")): item
                    for item in extracted_files
                    if item.get("package_path")
                }

                def expected_prefixes_for(
                    raw_case: Dict[str, object],
                    label: str,
                    role: str,
                ) -> List[str]:
                    field_name = (
                        "expected_raw_capture_directory"
                        if role == "raw_capture"
                        else "expected_capture_directory"
                    )
                    raw_expected_dir = str(raw_case.get(field_name) or "").strip()
                    if raw_expected_dir:
                        expected_dir = raw_expected_dir.replace("\\", "/").rstrip("/")
                        if expected_dir != raw_expected_dir.rstrip("/") or not _is_safe_archive_directory_member(
                            "{}/".format(expected_dir)
                        ):
                            add_failure(
                                "capture_return_manifest_expected_directory_invalid",
                                "capture return manifest expected directory is not a safe package path",
                                label=label,
                                role=role,
                                expected_directory=raw_expected_dir,
                            )
                            return []
                        return ["{}/".format(expected_dir)]
                    root_names = (
                        ["raw_captures", "raw_capture_root"]
                        if role == "raw_capture"
                        else ["captures", "capture_root"]
                    )
                    return [
                        "{}/{}/".format(root_name, subdir_name)
                        for root_name in root_names
                        for subdir_name in _capture_subdir_names(label)
                    ]

                def parse_manifest_file_entries(
                    raw_case: Dict[str, object],
                    label: str,
                    case_index: int,
                    field_name: str,
                    role: str,
                ) -> List[Dict[str, object]]:
                    nonlocal return_manifest_file_inventory_declared
                    raw_entries = raw_case.get(field_name, [])
                    if raw_entries in (None, ""):
                        raw_entries = []
                    if not isinstance(raw_entries, list):
                        add_failure(
                            "capture_return_manifest_file_entries_invalid",
                            "capture return manifest file entries must be a list",
                            label=label,
                            field=field_name,
                        )
                        return []
                    if raw_entries:
                        return_manifest_file_inventory_declared = True

                    expected_prefixes = expected_prefixes_for(raw_case, label, role)
                    parsed: List[Dict[str, object]] = []
                    for entry_index, raw_entry in enumerate(raw_entries, 1):
                        if isinstance(raw_entry, str):
                            raw_path = raw_entry
                            expected_sha256 = ""
                            expected_size: object = None
                        elif isinstance(raw_entry, dict):
                            raw_path = str(
                                raw_entry.get("path")
                                or raw_entry.get("package_path")
                                or raw_entry.get("archive_path")
                                or ""
                            )
                            expected_sha256 = str(raw_entry.get("sha256") or "").strip().lower()
                            expected_size = raw_entry.get("size_bytes")
                        else:
                            add_failure(
                                "capture_return_manifest_file_entry_invalid",
                                "capture return manifest file entry must be a string path or object",
                                label=label,
                                field=field_name,
                                case_index=case_index,
                                entry_index=entry_index,
                            )
                            continue

                        package_path = str(raw_path or "").strip()
                        normalized_path = package_path.replace("\\", "/")
                        if package_path != normalized_path or not _is_safe_archive_member(normalized_path):
                            add_failure(
                                "capture_return_manifest_file_path_invalid",
                                "capture return manifest file path is not a safe package member",
                                label=label,
                                field=field_name,
                                package_path=package_path,
                            )
                            continue
                        if Path(normalized_path).suffix.lower() not in CAPTURE_IMAGE_SUFFIXES:
                            add_failure(
                                "capture_return_manifest_file_suffix_unsupported",
                                "capture return manifest file path does not use a supported capture image suffix",
                                label=label,
                                field=field_name,
                                package_path=normalized_path,
                            )
                            continue
                        if expected_prefixes and not any(
                            normalized_path.startswith(prefix) for prefix in expected_prefixes
                        ):
                            add_failure(
                                "capture_return_manifest_file_directory_mismatch",
                                "capture return manifest file path is outside the expected case directory",
                                label=label,
                                role=role,
                                package_path=normalized_path,
                                expected_prefixes=expected_prefixes,
                            )
                            continue
                        if return_manifest_file_inventory_required and not expected_sha256:
                            add_failure(
                                "capture_return_manifest_file_sha256_missing",
                                "required capture return manifest file inventory must include SHA256",
                                label=label,
                                field=field_name,
                                package_path=normalized_path,
                            )
                            continue
                        if expected_sha256 and not _is_sha256_hex(expected_sha256):
                            add_failure(
                                "capture_return_manifest_file_sha256_invalid",
                                "capture return manifest file SHA256 is not canonical",
                                label=label,
                                field=field_name,
                                package_path=normalized_path,
                            )
                            continue

                        expected_size_int: Optional[int] = None
                        if return_manifest_file_inventory_required and expected_size in (None, ""):
                            add_failure(
                                "capture_return_manifest_file_size_missing",
                                "required capture return manifest file inventory must include byte size",
                                label=label,
                                field=field_name,
                                package_path=normalized_path,
                            )
                            continue
                        if expected_size not in (None, ""):
                            try:
                                expected_size_int = int(expected_size)
                            except (TypeError, ValueError):
                                add_failure(
                                    "capture_return_manifest_file_size_invalid",
                                    "capture return manifest file size is not an integer",
                                    label=label,
                                    field=field_name,
                                    package_path=normalized_path,
                                )
                                continue
                            if expected_size_int < 0:
                                add_failure(
                                    "capture_return_manifest_file_size_invalid",
                                    "capture return manifest file size must be non-negative",
                                    label=label,
                                    field=field_name,
                                    package_path=normalized_path,
                                )
                                continue

                        if normalized_path in return_manifest_capture_file_paths or normalized_path in return_manifest_raw_file_paths:
                            add_failure(
                                "capture_return_manifest_file_duplicate",
                                "capture return manifest file inventory contains a duplicate package path",
                                label=label,
                                field=field_name,
                                package_path=normalized_path,
                            )
                            continue

                        extracted_record = extracted_by_package_path.get(normalized_path)
                        if extracted_record is None:
                            add_failure(
                                "capture_return_manifest_file_missing",
                                "capture return manifest file is missing from the package",
                                label=label,
                                field=field_name,
                                package_path=normalized_path,
                            )
                        else:
                            observed_sha256 = str(extracted_record.get("sha256") or "")
                            observed_size = int(extracted_record.get("size_bytes") or 0)
                            if expected_sha256 and observed_sha256 != expected_sha256:
                                add_failure(
                                    "capture_return_manifest_file_sha256_mismatch",
                                    "capture return manifest file SHA256 does not match package bytes",
                                    label=label,
                                    field=field_name,
                                    package_path=normalized_path,
                                    expected_sha256=expected_sha256,
                                    observed_sha256=observed_sha256,
                                )
                            if expected_size_int is not None and observed_size != expected_size_int:
                                add_failure(
                                    "capture_return_manifest_file_size_mismatch",
                                    "capture return manifest file size does not match package bytes",
                                    label=label,
                                    field=field_name,
                                    package_path=normalized_path,
                                    expected_size_bytes=expected_size_int,
                                    observed_size_bytes=observed_size,
                                )

                        record = {
                            "case_label": label,
                            "role": role,
                            "package_path": normalized_path,
                            "sha256": expected_sha256 or (
                                extracted_record.get("sha256")
                                if isinstance(extracted_record, dict)
                                else None
                            ),
                            "size_bytes": (
                                expected_size_int
                                if expected_size_int is not None
                                else (
                                    extracted_record.get("size_bytes")
                                    if isinstance(extracted_record, dict)
                                    else None
                                )
                            ),
                        }
                        parsed.append(record)
                        return_manifest_file_inventory.append(record)
                        if role == "raw_capture":
                            return_manifest_raw_file_paths.add(normalized_path)
                        else:
                            return_manifest_capture_file_paths.add(normalized_path)
                    return parsed

                seen_manifest_labels: Set[str] = set()
                for index, raw_case in enumerate(raw_cases, 1):
                    if not isinstance(raw_case, dict):
                        add_failure(
                            "capture_return_manifest_case_invalid",
                            "capture return manifest case must be an object",
                            case_index=index,
                        )
                        continue
                    label = _normalize_label(raw_case.get("label"), "")
                    if not label:
                        add_failure(
                            "capture_return_manifest_case_label_missing",
                            "capture return manifest case label is required",
                            case_index=index,
                        )
                        continue
                    if label in seen_manifest_labels:
                        add_failure(
                            "capture_return_manifest_case_label_duplicate",
                            "capture return manifest case labels must be unique",
                            label=label,
                        )
                        continue
                    if expected_corpus_case_labels and label not in expected_corpus_case_labels:
                        add_failure(
                            "capture_return_manifest_case_label_unknown",
                            "capture return manifest case label does not belong to the prepared corpus",
                            label=label,
                        )
                        continue
                    seen_manifest_labels.add(label)
                    return_manifest_case_labels.append(label)
                    capture_entries = parse_manifest_file_entries(
                        raw_case,
                        label,
                        index,
                        "capture_files",
                        "capture",
                    )
                    parse_manifest_file_entries(
                        raw_case,
                        label,
                        index,
                        "raw_capture_files",
                        "raw_capture",
                    )
                    if return_manifest_file_inventory_required and not capture_entries:
                        add_failure(
                            "capture_return_manifest_case_capture_files_missing",
                            "capture return manifest file inventory is required but case lists no capture files",
                            label=label,
                        )

                actual_capture_image_paths = {
                    str(item.get("package_path"))
                    for item in extracted_files
                    if str(item.get("package_path") or "").split("/", 1)[0]
                    in {"captures", "capture_root"}
                    and Path(str(item.get("package_path") or "")).suffix.lower()
                    in CAPTURE_IMAGE_SUFFIXES
                }
                actual_raw_image_paths = {
                    str(item.get("package_path"))
                    for item in extracted_files
                    if str(item.get("package_path") or "").split("/", 1)[0]
                    in {"raw_captures", "raw_capture_root"}
                    and Path(str(item.get("package_path") or "")).suffix.lower()
                    in CAPTURE_IMAGE_SUFFIXES
                }
                if return_manifest_file_inventory_required or return_manifest_file_inventory_declared:
                    return_manifest_file_inventory_declared = True
                    for missing_package_path in sorted(
                        actual_capture_image_paths - return_manifest_capture_file_paths
                    ):
                        add_failure(
                            "capture_return_manifest_unlisted_capture_file",
                            "capture return manifest file inventory omits a capture image from the package",
                            package_path=missing_package_path,
                        )
                    for missing_package_path in sorted(
                        actual_raw_image_paths - return_manifest_raw_file_paths
                    ):
                        add_failure(
                            "capture_return_manifest_unlisted_raw_capture_file",
                            "capture return manifest file inventory omits a raw capture image from the package",
                            package_path=missing_package_path,
                        )
                    if not any(
                        str(item.get("code", "")).startswith("capture_return_manifest_file_")
                        or str(item.get("code", "")).startswith("capture_return_manifest_unlisted_")
                        or str(item.get("code", ""))
                        == "capture_return_manifest_case_capture_files_missing"
                        for item in failures
                    ):
                        return_manifest_file_inventory_validated = True
            if not any(
                str(item.get("code", "")).startswith("capture_return_manifest_")
                for item in failures
            ) and schema == CAPTURE_RETURN_MANIFEST_SCHEMA:
                return_manifest_validated = True
        except Exception as exc:
            add_failure(
                "capture_return_manifest_unreadable",
                "capture return manifest is not readable JSON",
                error=str(exc),
            )
    if bool(require_capture_return_manifest):
        if return_manifest_path is None:
            add_failure(
                "capture_return_manifest_required",
                "capture return manifest is required for this extraction gate",
            )
        elif not bool(return_manifest_validated):
            add_failure(
                "capture_return_manifest_not_validated",
                "capture return manifest must validate before ingestion",
            )
    if bool(require_capture_return_file_inventory):
        if return_manifest_path is None:
            add_failure(
                "capture_return_manifest_file_inventory_required",
                "capture return file inventory requires a capture return manifest",
            )
        elif not bool(return_manifest_file_inventory_declared):
            add_failure(
                "capture_return_manifest_file_inventory_required",
                "capture return manifest must declare exact capture file inventory",
            )
        elif not bool(return_manifest_file_inventory_validated):
            add_failure(
                "capture_return_manifest_file_inventory_not_validated",
                "capture return manifest file inventory must validate before ingestion",
            )

    if isinstance(package_report, dict):
        report_return_manifest_sha256 = str(
            package_report.get("capture_return_manifest_sha256") or ""
        ).strip()
        if report_return_manifest_sha256:
            observed_return_manifest_sha256 = (
                _sha256_file(return_manifest_path)
                if return_manifest_path is not None
                else None
            )
            if observed_return_manifest_sha256 != report_return_manifest_sha256:
                add_failure(
                    "capture_return_package_report_return_manifest_sha256_mismatch",
                    "capture return package report does not match the extracted return manifest",
                    expected_sha256=report_return_manifest_sha256,
                    observed_sha256=observed_return_manifest_sha256,
                )
        else:
            add_failure(
                "capture_return_package_report_return_manifest_sha256_missing",
                "capture return package report must record capture_return_manifest_sha256",
            )
        report_metadata_manifest_sha256 = str(
            package_report.get("capture_metadata_manifest_sha256") or ""
        ).strip()
        if report_metadata_manifest_sha256:
            observed_metadata_manifest_sha256 = (
                _sha256_file(metadata_manifest_path)
                if metadata_manifest_path is not None
                else None
            )
            if observed_metadata_manifest_sha256 != report_metadata_manifest_sha256:
                add_failure(
                    "capture_return_package_report_metadata_manifest_sha256_mismatch",
                    "capture return package report does not match the extracted metadata manifest",
                    expected_sha256=report_metadata_manifest_sha256,
                    observed_sha256=observed_metadata_manifest_sha256,
                )
        else:
            add_failure(
                "capture_return_package_report_metadata_manifest_sha256_missing",
                "capture return package report must record capture_metadata_manifest_sha256",
            )
        if not any(
            str(item.get("code", "")).startswith("capture_return_package_report_")
            for item in failures
        ):
            package_report_validated = True

    report = {
        "schema": CAPTURE_RETURN_PACKAGE_EXTRACTION_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": not failures,
        "package_file": str(package_path),
        "package_sha256": _sha256_file(package_path),
        "package_size_bytes": package_path.stat().st_size,
        "extraction_dir": str(extract_dir),
        "capture_root": str(capture_root.resolve()) if capture_root.exists() else None,
        "raw_capture_root": (
            str(raw_capture_root.resolve()) if raw_capture_root.exists() else None
        ),
        "capture_metadata_manifest_file": (
            str(metadata_manifest_path) if metadata_manifest_path is not None else None
        ),
        "capture_return_manifest_file": (
            str(return_manifest_path) if return_manifest_path is not None else None
        ),
        "capture_return_manifest_sha256": (
            _sha256_file(return_manifest_path) if return_manifest_path is not None else None
        ),
        "expected_capture_corpus_file": (
            str(expected_corpus_path) if expected_corpus_path is not None else None
        ),
        "expected_capture_corpus_sha256": expected_corpus_sha256,
        "expected_capture_corpus_case_labels": sorted(expected_corpus_case_labels),
        "expected_capture_kit_manifest_file": (
            str(expected_kit_path) if expected_kit_path is not None else None
        ),
        "expected_capture_kit_manifest_sha256": expected_kit_sha256,
        "expected_capture_return_package_report_file": (
            str(expected_package_report_path)
            if expected_package_report_path is not None
            else None
        ),
        "expected_capture_return_package_report_sha256": expected_package_report_sha256,
        "summary": {
            "member_count": len(member_names),
            "directory_member_count": directory_member_count,
            "extracted_file_count": len(extracted_files),
            "failure_count": len(failures),
            "capture_root_found": bool(capture_root.exists() and capture_root.is_dir()),
            "raw_capture_root_found": bool(
                raw_capture_root.exists() and raw_capture_root.is_dir()
            ),
            "capture_metadata_manifest_found": metadata_manifest_path is not None,
            "capture_return_manifest_found": return_manifest_path is not None,
            "capture_return_manifest_required": bool(require_capture_return_manifest),
            "capture_return_manifest_validated": bool(return_manifest_validated),
            "capture_return_manifest_case_count": len(return_manifest_case_labels),
            "capture_return_manifest_file_inventory_declared": bool(
                return_manifest_file_inventory_declared
            ),
            "capture_return_manifest_file_inventory_gate_required": bool(
                require_capture_return_file_inventory
            ),
            "capture_return_manifest_file_inventory_required": bool(
                return_manifest_file_inventory_required
            ),
            "capture_return_manifest_file_inventory_validated": bool(
                return_manifest_file_inventory_validated
            ),
            "capture_return_package_report_provided": expected_package_report_path is not None,
            "capture_return_package_report_required": bool(package_report_required),
            "capture_return_package_report_found": bool(
                expected_package_report_path is not None
                and expected_package_report_path.exists()
                and expected_package_report_path.is_file()
            ),
            "capture_return_package_report_validated": bool(package_report_validated),
            "capture_return_manifest_capture_file_count": len(
                return_manifest_capture_file_paths
            ),
            "capture_return_manifest_raw_file_count": len(return_manifest_raw_file_paths),
            "duplicate_member_count": sum(
                int(count) - 1 for count in member_counts.values() if int(count) > 1
            ),
        },
        "capture_return_manifest": {
            "schema": (
                str(return_manifest.get("schema") or "").strip()
                if isinstance(return_manifest, dict)
                else None
            ),
            "case_labels": return_manifest_case_labels,
            "capture_corpus_sha256": (
                return_manifest.get("capture_corpus_sha256")
                if isinstance(return_manifest, dict)
                else None
            ),
            "capture_kit_manifest_sha256": (
                return_manifest.get("capture_kit_manifest_sha256")
                if isinstance(return_manifest, dict)
                else None
            ),
            "validated": bool(return_manifest_validated),
            "file_inventory": {
                "declared": bool(return_manifest_file_inventory_declared),
                "required": bool(return_manifest_file_inventory_required),
                "validated": bool(return_manifest_file_inventory_validated),
                "capture_file_count": len(return_manifest_capture_file_paths),
                "raw_file_count": len(return_manifest_raw_file_paths),
                "files": return_manifest_file_inventory,
            },
        },
        "capture_return_package_report": {
            "file": (
                str(expected_package_report_path)
                if expected_package_report_path is not None
                else None
            ),
            "sha256": expected_package_report_sha256,
            "schema": (
                str(package_report.get("schema") or "").strip()
                if isinstance(package_report, dict)
                else None
            ),
            "validated": bool(package_report_validated),
            "package_sha256": (
                package_report.get("package_sha256")
                if isinstance(package_report, dict)
                else None
            ),
            "capture_corpus_sha256": (
                package_report.get("capture_corpus_sha256")
                if isinstance(package_report, dict)
                else None
            ),
            "capture_kit_manifest_sha256": (
                package_report.get("capture_kit_manifest_sha256")
                if isinstance(package_report, dict)
                else None
            ),
            "capture_return_manifest_sha256": (
                package_report.get("capture_return_manifest_sha256")
                if isinstance(package_report, dict)
                else None
            ),
            "capture_metadata_manifest_sha256": (
                package_report.get("capture_metadata_manifest_sha256")
                if isinstance(package_report, dict)
                else None
            ),
        },
        "files": extracted_files,
        "failures": failures,
        "certification_boundary": (
            "This extracts and hash-records an operator return package only. It does "
            "not certify any transport medium; certification still requires ingestion, "
            "attachment lineage, measured recovery, archive replay, and claim gates."
        ),
    }
    _write_json(report_path, report)
    report["report_file"] = str(report_path)
    report["report_sha256"] = _sha256_file(report_path)
    return report


def _replace_case_image_path(
    raw_case: Dict[str, object],
    corrected_dir: Path,
    corpus_base: Path,
) -> None:
    if isinstance(raw_case.get("image_path"), list):
        raw_case["image_path"] = [_corpus_relative_path(corrected_dir, corpus_base)]
    else:
        raw_case["image_path"] = _corpus_relative_path(corrected_dir, corpus_base)


def _parse_four_point_corners(value: object) -> Optional[List[float]]:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        parts = [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
        if len(parts) != 8:
            raise ValueError(
                "four-point perspective corners must contain 8 numeric values"
            )
        return [float(part) for part in parts]
    if not isinstance(value, list) or len(value) != 4:
        raise ValueError(
            "four-point perspective corners must be a list of four [x,y] points"
        )
    coords: List[float] = []
    for point in value:
        if not isinstance(point, list) or len(point) != 2:
            raise ValueError(
                "four-point perspective corners must be a list of four [x,y] points"
            )
        coords.extend([float(point[0]), float(point[1])])
    return coords


def _perspective_coefficients(
    source_points: List[float],
    destination_points: List[float],
) -> List[float]:
    matrix = []
    vector = []
    for index in range(0, 8, 2):
        x_value = source_points[index]
        y_value = source_points[index + 1]
        u_value = destination_points[index]
        v_value = destination_points[index + 1]
        matrix.append([x_value, y_value, 1.0, 0.0, 0.0, 0.0, -u_value * x_value, -u_value * y_value])
        matrix.append([0.0, 0.0, 0.0, x_value, y_value, 1.0, -v_value * x_value, -v_value * y_value])
        vector.extend([u_value, v_value])

    # Gaussian elimination for the fixed 8x8 homography system avoids adding a runtime dependency.
    for pivot_index in range(8):
        pivot_row = max(
            range(pivot_index, 8),
            key=lambda row_index: abs(matrix[row_index][pivot_index]),
        )
        if abs(matrix[pivot_row][pivot_index]) < 1e-12:
            raise ValueError("four-point perspective corners are degenerate")
        if pivot_row != pivot_index:
            matrix[pivot_index], matrix[pivot_row] = matrix[pivot_row], matrix[pivot_index]
            vector[pivot_index], vector[pivot_row] = vector[pivot_row], vector[pivot_index]
        pivot = matrix[pivot_index][pivot_index]
        matrix[pivot_index] = [value / pivot for value in matrix[pivot_index]]
        vector[pivot_index] = vector[pivot_index] / pivot
        for row_index in range(8):
            if row_index == pivot_index:
                continue
            factor = matrix[row_index][pivot_index]
            if abs(factor) < 1e-15:
                continue
            matrix[row_index] = [
                value - (factor * pivot_value)
                for value, pivot_value in zip(matrix[row_index], matrix[pivot_index])
            ]
            vector[row_index] = vector[row_index] - (factor * vector[pivot_index])
    return [float(item) for item in vector]


def _apply_capture_perspective_correction(
    source_path: Path,
    target_path: Path,
    mode: str,
    corners: Optional[List[float]] = None,
) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    mode_value = str(mode or "").strip().lower()
    if mode_value == "copy":
        shutil.copy2(str(source_path), str(target_path))
        return
    if mode_value == "normalize":
        try:
            from PIL import Image, ImageOps
        except Exception as exc:
            raise RuntimeError(
                "perspective correction mode 'normalize' requires Pillow"
            ) from exc
        with Image.open(source_path) as image:
            corrected = ImageOps.exif_transpose(image)
            corrected.save(target_path)
        return
    if mode_value == "four-point":
        try:
            from PIL import Image
        except Exception as exc:
            raise RuntimeError(
                "perspective correction mode 'four-point' requires Pillow"
            ) from exc
        if not corners:
            raise ValueError(
                "perspective correction mode 'four-point' requires per-case "
                "perspective_correction.source_corners"
            )
        with Image.open(source_path) as image:
            width, height = image.size
            destination = [
                0.0,
                0.0,
                float(width - 1),
                0.0,
                float(width - 1),
                float(height - 1),
                0.0,
                float(height - 1),
            ]
            coefficients = _perspective_coefficients(destination, corners)
            resampling = getattr(Image, "Resampling", Image)
            bicubic = getattr(resampling, "BICUBIC", getattr(Image, "BICUBIC", 3))
            image.transform(
                image.size,
                Image.PERSPECTIVE,
                coefficients,
                resample=bicubic,
            ).save(target_path)
        return
    raise ValueError(
        "perspective correction mode must be one of: {}".format(
            ", ".join(SUPPORTED_PERSPECTIVE_CORRECTION_MODES)
        )
    )


def correct_capture_perspective(
    capture_corpus_file: str,
    output_dir: Optional[str] = None,
    report_file: Optional[str] = None,
    kit_manifest_file: Optional[str] = None,
    method: str = "operator-supplied perspective correction",
    mode: str = "copy",
    require_raw_captures: bool = False,
    require_distinct_from_raw: bool = False,
    update_corpus: bool = True,
    update_kit_manifest: bool = True,
) -> Dict[str, object]:
    """Materialize corrected camera captures from raw-photo paths in a prepared corpus."""

    corpus_path = Path(str(capture_corpus_file)).resolve()
    if not corpus_path.exists() or not corpus_path.is_file():
        raise ValueError("capture corpus file does not exist: {}".format(corpus_path))
    corpus_base = corpus_path.parent
    corpus = _load_json(corpus_path)
    schema = str(corpus.get("schema") or "").strip()
    if schema != CAPTURE_CORPUS_SCHEMA:
        raise ValueError(
            "capture corpus schema must be {}, got {}".format(
                CAPTURE_CORPUS_SCHEMA,
                schema or "<missing>",
            )
        )

    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("capture corpus cases must be a non-empty list")

    mode_value = str(mode or "").strip().lower()
    if mode_value not in SUPPORTED_PERSPECTIVE_CORRECTION_MODES:
        raise ValueError(
            "perspective correction mode must be one of: {}".format(
                ", ".join(SUPPORTED_PERSPECTIVE_CORRECTION_MODES)
            )
        )
    method_value = str(method or "").strip() or "operator-supplied perspective correction"

    report_dir = Path(output_dir).resolve() if output_dir else corpus_base / "corrected_captures"
    report_dir.mkdir(parents=True, exist_ok=True)
    corrected_root = report_dir / "captures"
    report_path = _resolve_output_path(
        report_file,
        report_dir,
        "transport_capture_perspective_correction_report.json",
    )

    corrected_at_utc = protocol.utc_now_iso()
    correction_cases = []
    updated_cases = []
    failures = Counter()
    raw_case_count = 0
    corrected_case_count = 0
    corrected_image_count = 0
    distinct_case_count = 0
    corpus_classification = str(corpus.get("classification") or "").strip().lower()

    for index, raw_case in enumerate(cases, 1):
        if not isinstance(raw_case, dict):
            raise ValueError("capture corpus case {} must be an object".format(index))
        updated_case = dict(raw_case)
        label = _normalize_label(raw_case.get("label"), "capture_{:04d}".format(index))
        slug = _label_slug(label, "capture_{:04d}".format(index))
        case_classification = str(
            raw_case.get("classification") or corpus_classification
        ).strip().lower()
        capture_medium = _normalize_capture_medium(raw_case.get("capture_medium"))
        raw_paths = _optional_image_paths_from_capture_inputs(
            raw_case.get("raw_image_paths", raw_case.get("raw_image_path")),
            corpus_base,
        )
        reference_paths = _optional_image_paths_from_capture_inputs(
            raw_case.get("reference_image_paths", raw_case.get("reference_image_path")),
            corpus_base,
        )
        reasons = []
        exception_message: Optional[str] = None
        if not raw_paths:
            reasons.append("raw_capture_images_missing")
            failures["raw_capture_images_missing"] += 1
        else:
            raw_case_count += 1

        perspective_metadata = _normalize_perspective_correction(
            raw_case.get("perspective_correction")
        )
        source_corners: Optional[List[float]] = None
        if mode_value == "four-point":
            try:
                source_corners = _parse_four_point_corners(
                    perspective_metadata.get("source_corners")
                    if perspective_metadata
                    else raw_case.get("source_corners")
                )
            except Exception as exc:
                reasons.append("perspective_correction_corners_invalid")
                failures["perspective_correction_corners_invalid"] += 1
                exception_message = "{}".format(exc)
            if source_corners is None:
                reasons.append("perspective_correction_corners_missing")
                failures["perspective_correction_corners_missing"] += 1

        corrected_paths: List[Path] = []
        target_dir = corrected_root / slug
        if raw_paths and not any(reason.startswith("perspective_correction_corners") for reason in reasons):
            for raw_index, raw_path in enumerate(raw_paths, 1):
                suffix = raw_path.suffix.lower() or ".png"
                target_path = target_dir / "corrected_{:04d}{}".format(raw_index, suffix)
                try:
                    _apply_capture_perspective_correction(
                        source_path=raw_path,
                        target_path=target_path,
                        mode=mode_value,
                        corners=source_corners,
                    )
                    corrected_paths.append(target_path)
                except Exception as exc:
                    exception_message = "{}".format(exc)
                    reasons.append("perspective_correction_failed")
                    failures["perspective_correction_failed"] += 1
                    break

        raw_records = _absolute_digest_records(raw_paths)
        corrected_records = _absolute_digest_records(corrected_paths)
        reference_records = _absolute_digest_records(reference_paths)
        raw_sha256 = {record["sha256"] for record in raw_records}
        corrected_sha256 = {record["sha256"] for record in corrected_records}
        reference_sha256 = {record["sha256"] for record in reference_records}
        distinct_from_raw = bool(
            raw_records and corrected_records and raw_sha256.isdisjoint(corrected_sha256)
        )
        distinct_from_reference = bool(
            not reference_records
            or (corrected_records and corrected_sha256.isdisjoint(reference_sha256))
        )
        if require_distinct_from_raw and raw_paths and not distinct_from_raw:
            reasons.append("corrected_capture_not_distinct_from_raw")
            failures["corrected_capture_not_distinct_from_raw"] += 1

        evidence_passed = bool(
            raw_paths
            and corrected_paths
            and (not require_distinct_from_raw or distinct_from_raw)
        )
        if corrected_paths:
            corrected_case_count += 1
            corrected_image_count += len(corrected_paths)
            _replace_case_image_path(updated_case, target_dir, corpus_base)
            updated_case["perspective_correction"] = {
                "applied": True,
                "method": method_value,
                "mode": mode_value,
                "source_corners": perspective_metadata.get("source_corners"),
                "corrected_at_utc": corrected_at_utc,
                "correction_report_file": _corpus_relative_path(report_path, corpus_base),
                "source": "soenc transport correct-capture-perspective",
                "evidence_passed": evidence_passed,
                "distinct_from_raw": distinct_from_raw,
            }
            if distinct_from_raw:
                distinct_case_count += 1

        correction_cases.append(
            {
                "label": label,
                "classification": case_classification,
                "capture_medium": capture_medium,
                "success": bool(evidence_passed),
                "failure_reasons": reasons,
                "method": method_value,
                "mode": mode_value,
                "source_corners": source_corners,
                "raw_images": raw_records,
                "corrected_images": corrected_records,
                "reference_images": reference_records,
                "corrected_capture_dir": str(target_dir.resolve()) if corrected_paths else None,
                "distinct_from_raw": distinct_from_raw,
                "distinct_from_reference": distinct_from_reference,
                "exception": exception_message,
                "certification_boundary": (
                    "Perspective correction prepares corrected recovery images only. "
                    "Camera transfer is certified later by attach-capture-corpus, "
                    "validate-capture-corpus, certify, archive-evidence, and "
                    "certification-status gates."
                ),
            }
        )
        updated_cases.append(updated_case)

    success = bool(
        correction_cases
        and not failures
        and (not require_raw_captures or raw_case_count == len(correction_cases))
    )

    if update_corpus:
        updated_metadata = _normalize_capture_corpus_metadata(corpus.get("metadata"))
        updated_metadata["last_perspective_correction"] = {
            "schema": CAPTURE_PERSPECTIVE_CORRECTION_REPORT_SCHEMA,
            "report_file": _corpus_relative_path(report_path, corpus_base),
            "corrected_at_utc": corrected_at_utc,
            "method": method_value,
            "mode": mode_value,
            "case_count": len(correction_cases),
            "raw_capture_case_count": raw_case_count,
            "corrected_case_count": corrected_case_count,
            "corrected_image_count": corrected_image_count,
            "success": success,
        }
        corpus["metadata"] = updated_metadata
        corpus["cases"] = updated_cases
        _write_json(corpus_path, corpus)

    kit_manifest_path: Optional[Path] = None
    raw_kit_path = str(kit_manifest_file or "").strip()
    if raw_kit_path:
        candidate = Path(raw_kit_path)
        if not candidate.is_absolute():
            candidate = candidate if candidate.exists() else corpus_base / candidate
        kit_manifest_path = candidate.resolve()
    else:
        candidate = corpus_base / "capture_kit_manifest.json"
        if candidate.exists():
            kit_manifest_path = candidate.resolve()
    if update_kit_manifest and kit_manifest_path and kit_manifest_path.exists():
        kit_manifest = _load_json(kit_manifest_path)
        kit_manifest["last_perspective_correction"] = {
            "schema": CAPTURE_PERSPECTIVE_CORRECTION_REPORT_SCHEMA,
            "report_file": _safe_relative_path(report_path.resolve(), kit_manifest_path.parent.resolve()),
            "corrected_at_utc": corrected_at_utc,
            "method": method_value,
            "mode": mode_value,
            "success": success,
            "corrected_case_count": corrected_case_count,
            "corrected_image_count": corrected_image_count,
        }
        summary = kit_manifest.get("summary")
        if not isinstance(summary, dict):
            summary = {}
        summary["operator_corrected_capture_case_count"] = corrected_case_count
        summary["operator_corrected_capture_image_count"] = corrected_image_count
        summary["operator_perspective_distinct_from_raw_case_count"] = distinct_case_count
        kit_manifest["summary"] = summary
        _write_json(kit_manifest_path, kit_manifest)

    report = {
        "schema": CAPTURE_PERSPECTIVE_CORRECTION_REPORT_SCHEMA,
        "generated_at_utc": corrected_at_utc,
        "success": success,
        "capture_corpus_file": str(corpus_path),
        "kit_manifest_file": str(kit_manifest_path) if kit_manifest_path else None,
        "output_dir": str(report_dir),
        "parameters": {
            "method": method_value,
            "mode": mode_value,
            "require_raw_captures": bool(require_raw_captures),
            "require_distinct_from_raw": bool(require_distinct_from_raw),
            "update_corpus": bool(update_corpus),
            "update_kit_manifest": bool(update_kit_manifest),
        },
        "summary": {
            "case_count": len(correction_cases),
            "raw_capture_case_count": raw_case_count,
            "corrected_case_count": corrected_case_count,
            "corrected_image_count": corrected_image_count,
            "distinct_from_raw_case_count": distinct_case_count,
            "failures_by_reason": dict(failures),
        },
        "cases": correction_cases,
        "certification_boundary": (
            "This report proves only deterministic creation and SHA256 binding of corrected "
            "capture images from operator raw-photo inputs. It is not recovery certification "
            "and does not certify real camera perspective correction until the corrected corpus "
            "passes the explicit transport certification and archive/status gates."
        ),
    }
    _write_json(report_path, report)
    return report


def ingest_capture_corpus(
    capture_corpus_file: str,
    capture_root: str,
    output_dir: Optional[str] = None,
    report_file: Optional[str] = None,
    kit_manifest_file: Optional[str] = None,
    raw_capture_root: Optional[str] = None,
    classification: Optional[str] = None,
    capture_medium: Optional[str] = None,
    capture_metadata: Optional[Dict[str, object]] = None,
    capture_metadata_manifest_file: Optional[str] = None,
    require_captures: bool = False,
    require_raw_captures: bool = False,
    require_all_case_labels: bool = True,
    update_corpus: bool = True,
    update_kit_manifest: bool = True,
) -> Dict[str, object]:
    """Map externally collected photos/scans into a prepared capture corpus."""

    corpus_path = Path(str(capture_corpus_file)).resolve()
    if not corpus_path.exists() or not corpus_path.is_file():
        raise ValueError("capture corpus file does not exist: {}".format(corpus_path))
    corpus_base = corpus_path.parent
    corpus = _load_json(corpus_path)
    schema = str(corpus.get("schema") or "").strip()
    if schema != CAPTURE_CORPUS_SCHEMA:
        raise ValueError(
            "capture corpus schema must be {}, got {}".format(
                CAPTURE_CORPUS_SCHEMA,
                schema or "<missing>",
            )
        )

    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("capture corpus cases must be a non-empty list")

    capture_root_path = _resolve_existing_path_cwd_or_base(
        capture_root,
        corpus_base,
        "capture_root",
    )
    if not capture_root_path.exists() or not capture_root_path.is_dir():
        raise ValueError("capture_root must be an existing directory: {}".format(capture_root_path))
    raw_capture_root_path: Optional[Path] = None
    if raw_capture_root is not None and str(raw_capture_root).strip():
        raw_capture_root_path = _resolve_existing_path_cwd_or_base(
            raw_capture_root,
            corpus_base,
            "raw_capture_root",
        )
        if not raw_capture_root_path.exists() or not raw_capture_root_path.is_dir():
            raise ValueError(
                "raw_capture_root must be an existing directory: {}".format(raw_capture_root_path)
            )

    classification_value = str(
        classification or corpus.get("classification") or ""
    ).strip().lower()
    if classification_value not in SUPPORTED_CORPUS_CLASSIFICATIONS:
        raise ValueError(
            "capture corpus classification must be one of: {}".format(
                ", ".join(SUPPORTED_CORPUS_CLASSIFICATIONS)
            )
        )
    medium_value = _normalize_capture_medium(
        capture_medium
        if capture_medium is not None
        else corpus.get("capture_medium", corpus.get("medium", "unspecified"))
    )
    classification_explicit = bool(classification is not None and str(classification).strip())
    medium_explicit = bool(capture_medium is not None and str(capture_medium).strip())
    ingest_metadata = _normalize_capture_corpus_metadata(capture_metadata or {})
    metadata_manifest = _load_capture_metadata_manifest(
        capture_metadata_manifest_file,
        corpus_base,
    )
    metadata_manifest_path = metadata_manifest.get("file")
    metadata_manifest_defaults = metadata_manifest.get("defaults")
    if not isinstance(metadata_manifest_defaults, dict):
        metadata_manifest_defaults = {}
    metadata_manifest_cases_by_label = metadata_manifest.get("cases_by_label")
    if not isinstance(metadata_manifest_cases_by_label, dict):
        metadata_manifest_cases_by_label = {}

    report_dir = Path(output_dir).resolve() if output_dir else corpus_base
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = _resolve_output_path(
        report_file,
        report_dir,
        "transport_capture_corpus_ingestion_report.json",
    )
    ingested_at_utc = protocol.utc_now_iso()

    updated_cases = []
    ingest_cases = []
    failures = Counter()
    label_counts = Counter()
    medium_counts = Counter()
    captured_case_count = 0
    raw_captured_case_count = 0
    captured_image_count = 0
    raw_captured_image_count = 0
    metadata_manifest_case_count = len(metadata_manifest_cases_by_label)
    metadata_manifest_matched_case_count = 0
    seen_labels = set()

    for index, raw_case in enumerate(cases, 1):
        if not isinstance(raw_case, dict):
            raise ValueError("capture corpus case {} must be an object".format(index))

        label = _normalize_label(raw_case.get("label"), "capture_{:04d}".format(index))
        if label in seen_labels:
            raise ValueError("capture corpus labels must be unique: {}".format(label))
        seen_labels.add(label)
        label_counts[label] += 1

        updated_case = dict(raw_case)
        case_failures = []
        case_classification = str(
            classification_value
            if classification_explicit
            else raw_case.get("classification") or classification_value
        ).strip().lower()
        if case_classification not in SUPPORTED_CORPUS_CLASSIFICATIONS:
            raise ValueError(
                "capture corpus case classification must be one of: {}".format(
                    ", ".join(SUPPORTED_CORPUS_CLASSIFICATIONS)
                )
            )
        manifest_case = metadata_manifest_cases_by_label.get(label)
        manifest_case_metadata: Dict[str, object] = {}
        manifest_case_medium = None
        if isinstance(manifest_case, dict):
            metadata_manifest_matched_case_count += 1
            raw_manifest_metadata = manifest_case.get("metadata")
            if isinstance(raw_manifest_metadata, dict):
                manifest_case_metadata = raw_manifest_metadata
            manifest_case_medium = manifest_case.get("capture_medium")

        case_medium_source = raw_case.get("capture_medium", raw_case.get("medium", medium_value))
        if "capture_medium" in metadata_manifest_defaults:
            case_medium_source = metadata_manifest_defaults.get("capture_medium")
        if manifest_case_medium is not None:
            case_medium_source = manifest_case_medium
        if medium_explicit:
            case_medium_source = medium_value
        case_medium = _normalize_capture_medium(case_medium_source)
        if case_medium == "unspecified" and medium_value != "unspecified":
            case_medium = medium_value

        capture_source = _capture_subdir_path(
            capture_root_path,
            label,
        )
        capture_paths: List[Path] = []
        if capture_source is None:
            case_failures.append("capture_label_directory_missing")
        else:
            capture_paths = _collect_capture_images_recursive(capture_source, corpus_base)
            if not capture_paths:
                case_failures.append("capture_images_missing")

        raw_source = None
        raw_paths: List[Path] = []
        if raw_capture_root_path is not None:
            raw_source = _capture_subdir_path(
                raw_capture_root_path,
                label,
                suffixes=("__raw", "-raw", "_raw"),
            )
            if raw_source is None:
                case_failures.append("raw_capture_label_directory_missing")
            else:
                raw_paths = _collect_capture_images_recursive(raw_source, corpus_base)
                if not raw_paths:
                    case_failures.append("raw_capture_images_missing")

        if bool(require_captures) and not capture_paths and "capture_images_missing" not in case_failures:
            case_failures.append("capture_images_missing")
        if bool(require_raw_captures) and not raw_paths and "raw_capture_images_missing" not in case_failures:
            case_failures.append("raw_capture_images_missing")

        if capture_paths:
            captured_case_count += 1
            captured_image_count += len(capture_paths)
            updated_case["image_path"] = _corpus_relative_path(
                capture_source if capture_source and capture_source.is_dir() else capture_paths[0],
                corpus_base,
            )
        if raw_paths:
            raw_captured_case_count += 1
            raw_captured_image_count += len(raw_paths)
            updated_case["raw_image_paths"] = _corpus_relative_path(
                raw_source if raw_source and raw_source.is_dir() else raw_paths[0],
                corpus_base,
            )

        existing_case_metadata = _normalize_capture_corpus_metadata(
            raw_case.get("capture_metadata", raw_case.get("metadata"))
        )
        merged_case_metadata = dict(existing_case_metadata)
        merged_case_metadata.update(metadata_manifest_defaults)
        merged_case_metadata.update(manifest_case_metadata)
        merged_case_metadata.update(ingest_metadata)
        if case_medium != "unspecified":
            merged_case_metadata["capture_medium"] = case_medium
        updated_case["capture_metadata"] = merged_case_metadata
        updated_case["classification"] = case_classification
        updated_case["capture_medium"] = case_medium
        updated_case["capture_ingestion"] = {
            "schema": CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA,
            "ingested_at_utc": ingested_at_utc,
            "report_file": _corpus_relative_path(report_path, corpus_base),
            "capture_root": _corpus_relative_path(capture_root_path, corpus_base),
            "raw_capture_root": (
                _corpus_relative_path(raw_capture_root_path, corpus_base)
                if raw_capture_root_path is not None
                else None
            ),
            "capture_image_count": len(capture_paths),
            "raw_image_count": len(raw_paths),
            "capture_metadata_manifest_file": (
                _corpus_relative_path(Path(str(metadata_manifest_path)), corpus_base)
                if isinstance(metadata_manifest_path, Path)
                else None
            ),
            "capture_metadata_manifest_case_matched": bool(manifest_case),
            "ready_for_attachment": not case_failures and bool(capture_paths),
            "failure_reasons": case_failures,
        }
        updated_cases.append(updated_case)

        for reason in case_failures:
            failures[reason] += 1
        medium_counts[case_medium] += 1

        ingest_cases.append(
            {
                "label": label,
                "classification": case_classification,
                "capture_medium": case_medium,
                "capture_source": str(capture_source.resolve()) if capture_source else None,
                "raw_capture_source": str(raw_source.resolve()) if raw_source else None,
                "capture_image_count": len(capture_paths),
                "raw_image_count": len(raw_paths),
                "capture_images": _relative_digest_records(capture_paths, corpus_base),
                "raw_images": _relative_digest_records(raw_paths, corpus_base),
                "capture_metadata_manifest_case_matched": bool(manifest_case),
                "capture_metadata": dict(merged_case_metadata),
                "capture_metadata_keys": sorted(str(key) for key in merged_case_metadata.keys()),
                "failure_reasons": case_failures,
                "ready_for_attachment": not case_failures and bool(capture_paths),
            }
        )

    unmatched_capture_entries = []
    expected_names = set()
    for raw_case in cases:
        if isinstance(raw_case, dict):
            label = _normalize_label(
                raw_case.get("label"),
                "capture_{:04d}".format(len(expected_names) + 1),
            )
            expected_names.update(_capture_subdir_names(label))
    for child in sorted(capture_root_path.iterdir(), key=lambda item: item.name.lower()):
        if not child.is_dir() and not (child.is_file() and child.suffix.lower() in CAPTURE_IMAGE_SUFFIXES):
            continue
        if child.name not in expected_names:
            unmatched_capture_entries.append(str(child.resolve()))
    if bool(require_all_case_labels) and unmatched_capture_entries:
        failures["unexpected_capture_label_entries"] += len(unmatched_capture_entries)

    unmatched_metadata_manifest_labels = sorted(
        str(label)
        for label in metadata_manifest_cases_by_label.keys()
        if str(label) not in seen_labels
    )
    if bool(require_all_case_labels) and unmatched_metadata_manifest_labels:
        failures["unexpected_capture_metadata_manifest_labels"] += len(
            unmatched_metadata_manifest_labels
        )

    success = bool(
        ingest_cases
        and not failures
        and (not bool(require_captures) or captured_case_count == len(ingest_cases))
        and (not bool(require_raw_captures) or raw_captured_case_count == len(ingest_cases))
    )

    report = {
        "schema": CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA,
        "generated_at_utc": ingested_at_utc,
        "success": bool(success),
        "capture_corpus_schema": CAPTURE_CORPUS_SCHEMA,
        "capture_corpus_file": str(corpus_path),
        "capture_root": str(capture_root_path),
        "raw_capture_root": str(raw_capture_root_path) if raw_capture_root_path else None,
        "capture_metadata_manifest_file": (
            str(metadata_manifest_path) if isinstance(metadata_manifest_path, Path) else None
        ),
        "capture_metadata_manifest_sha256": metadata_manifest.get("sha256"),
        "classification": classification_value,
        "capture_medium": medium_value,
        "parameters": {
            "require_captures": bool(require_captures),
            "require_raw_captures": bool(require_raw_captures),
            "require_all_case_labels": bool(require_all_case_labels),
            "update_corpus": bool(update_corpus),
            "update_kit_manifest": bool(update_kit_manifest),
            "capture_metadata_keys": sorted(str(key) for key in ingest_metadata.keys()),
        },
        "summary": {
            "case_count": len(ingest_cases),
            "cases_with_captures": captured_case_count,
            "cases_missing_captures": len(ingest_cases) - captured_case_count,
            "capture_image_count": captured_image_count,
            "cases_with_raw_captures": raw_captured_case_count,
            "cases_missing_raw_captures": len(ingest_cases) - raw_captured_case_count,
            "raw_capture_image_count": raw_captured_image_count,
            "capture_metadata_manifest_case_count": metadata_manifest_case_count,
            "capture_metadata_manifest_matched_case_count": (
                metadata_manifest_matched_case_count
            ),
            "capture_medium_counts": dict(medium_counts),
            "unmatched_capture_entry_count": len(unmatched_capture_entries),
            "unmatched_metadata_manifest_label_count": len(
                unmatched_metadata_manifest_labels
            ),
            "failures_by_reason": dict(failures),
        },
        "unmatched_capture_entries": unmatched_capture_entries,
        "unmatched_metadata_manifest_labels": unmatched_metadata_manifest_labels,
        "certification_boundary": (
            "This report maps external photo/scan folders into capture_corpus.json and "
            "records SHA256 bindings. It is not recovery certification; run "
            "attach-capture-corpus or certify-capture-evidence with the required medium "
            "gate before making any transport claim."
        ),
        "report_file": str(report_path),
        "updated_files": [],
        "cases": ingest_cases,
    }

    if bool(update_corpus):
        updated_corpus = dict(corpus)
        updated_metadata = _normalize_capture_corpus_metadata(updated_corpus.get("metadata"))
        updated_metadata["last_capture_ingestion"] = {
            "schema": CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA,
            "ingested_at_utc": ingested_at_utc,
            "report_file": _corpus_relative_path(report_path, corpus_base),
            "capture_root": _corpus_relative_path(capture_root_path, corpus_base),
            "raw_capture_root": (
                _corpus_relative_path(raw_capture_root_path, corpus_base)
                if raw_capture_root_path is not None
                else None
            ),
            "capture_metadata_manifest_file": (
                _corpus_relative_path(metadata_manifest_path, corpus_base)
                if isinstance(metadata_manifest_path, Path)
                else None
            ),
            "capture_metadata_manifest_sha256": metadata_manifest.get("sha256"),
            "case_count": len(ingest_cases),
            "cases_with_captures": captured_case_count,
            "capture_image_count": captured_image_count,
            "cases_with_raw_captures": raw_captured_case_count,
            "raw_capture_image_count": raw_captured_image_count,
            "success": bool(success),
        }
        updated_corpus["classification"] = classification_value
        if medium_value != "unspecified":
            updated_corpus["capture_medium"] = medium_value
        updated_corpus["metadata"] = updated_metadata
        updated_corpus["cases"] = updated_cases
        _write_json(corpus_path, updated_corpus)
        report["updated_files"].append(str(corpus_path))

    manifest_path: Optional[Path] = None
    raw_kit_manifest = str(kit_manifest_file or "").strip()
    if raw_kit_manifest:
        candidate = Path(raw_kit_manifest)
        if not candidate.is_absolute():
            candidate = candidate if candidate.exists() else corpus_base / candidate
        manifest_path = candidate.resolve()
    else:
        candidate = corpus_base / "capture_kit_manifest.json"
        if candidate.exists():
            manifest_path = candidate.resolve()

    if bool(update_kit_manifest) and manifest_path is not None:
        if not manifest_path.exists() or not manifest_path.is_file():
            raise ValueError("capture kit manifest file does not exist: {}".format(manifest_path))
        kit_manifest = _load_json(manifest_path)
        if str(kit_manifest.get("schema") or "").strip() != CAPTURE_KIT_SCHEMA:
            raise ValueError("capture kit manifest schema must be {}".format(CAPTURE_KIT_SCHEMA))
        summary = kit_manifest.get("summary")
        if not isinstance(summary, dict):
            summary = {}
        summary["operator_ingested_capture_cases"] = captured_case_count
        summary["operator_ingested_capture_image_count"] = captured_image_count
        summary["operator_ingested_raw_capture_cases"] = raw_captured_case_count
        summary["operator_ingested_raw_capture_image_count"] = raw_captured_image_count
        summary["operator_capture_cases_missing"] = len(ingest_cases) - captured_case_count
        summary["operator_raw_capture_cases_missing"] = len(ingest_cases) - raw_captured_case_count
        kit_manifest["summary"] = summary
        kit_manifest["last_capture_ingestion"] = {
            "schema": CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA,
            "ingested_at_utc": ingested_at_utc,
            "report_file": _safe_relative_path(report_path.resolve(), manifest_path.parent.resolve()),
            "capture_corpus_file": _safe_relative_path(corpus_path.resolve(), manifest_path.parent.resolve()),
            "capture_root": _safe_relative_path(capture_root_path.resolve(), manifest_path.parent.resolve()),
            "raw_capture_root": (
                _safe_relative_path(raw_capture_root_path.resolve(), manifest_path.parent.resolve())
                if raw_capture_root_path is not None
                else None
            ),
            "capture_metadata_manifest_file": (
                _safe_relative_path(
                    metadata_manifest_path.resolve(),
                    manifest_path.parent.resolve(),
                )
                if isinstance(metadata_manifest_path, Path)
                else None
            ),
            "capture_metadata_manifest_sha256": metadata_manifest.get("sha256"),
            "success": bool(success),
        }
        _write_json(manifest_path, kit_manifest)
        report["updated_files"].append(str(manifest_path))

    _write_json(report_path, report)
    return report


def _resolve_optional_existing_file(
    raw_path: Optional[str],
    base_dir: Path,
    field_name: str,
) -> Optional[Path]:
    if raw_path is None or str(raw_path).strip() == "":
        return None
    path = Path(str(raw_path))
    if path.is_absolute():
        resolved = path.resolve()
    else:
        cwd_candidate = path.resolve()
        resolved = cwd_candidate if cwd_candidate.exists() else (base_dir / path).resolve()
    if not resolved.exists() or not resolved.is_file():
        raise ValueError("{} does not exist or is not a file: {}".format(field_name, resolved))
    return resolved


def _metadata_manifest_payload_for_return_package(
    *,
    capture_metadata_manifest_file: Optional[str],
    corpus_base: Path,
    capture_metadata: Optional[Dict[str, object]],
    cases: List[Dict[str, object]],
) -> Dict[str, object]:
    manifest_path = _resolve_optional_existing_file(
        capture_metadata_manifest_file,
        corpus_base,
        "capture_metadata_manifest_file",
    )
    if manifest_path is not None:
        manifest = _load_json(manifest_path)
        schema = str(manifest.get("schema") or "").strip()
        if schema != CAPTURE_METADATA_MANIFEST_SCHEMA:
            raise ValueError(
                "capture metadata manifest schema must be {}, got {}".format(
                    CAPTURE_METADATA_MANIFEST_SCHEMA,
                    schema or "<missing>",
                )
            )
        return manifest

    normalized_metadata = _normalize_capture_corpus_metadata(capture_metadata or {})
    return {
        "schema": CAPTURE_METADATA_MANIFEST_SCHEMA,
        "capture_metadata_defaults": normalized_metadata,
        "cases": [
            {
                "label": str(case.get("label") or ""),
                "capture_metadata": {},
            }
            for case in cases
        ],
        "generated_by": "soenc transport package-capture-return",
        "certification_boundary": (
            "This metadata manifest is packaged provenance input only. It does not "
            "certify any transport medium without measured recovery and claim gates."
        ),
    }


def _metadata_manifest_case_metadata(
    metadata_manifest: Dict[str, object],
    label: str,
) -> Dict[str, object]:
    defaults = _normalize_capture_corpus_metadata(
        metadata_manifest.get("capture_metadata_defaults", metadata_manifest.get("metadata_defaults"))
    )
    if "capture_medium" in metadata_manifest and "capture_medium" not in defaults:
        defaults["capture_medium"] = metadata_manifest.get("capture_medium")
    elif "medium" in metadata_manifest and "capture_medium" not in defaults:
        defaults["capture_medium"] = metadata_manifest.get("medium")

    case_metadata: Dict[str, object] = {}
    raw_cases = metadata_manifest.get("cases", [])
    if isinstance(raw_cases, list):
        for raw_case in raw_cases:
            if not isinstance(raw_case, dict):
                continue
            case_label = _normalize_label(raw_case.get("label"), "")
            if case_label != label:
                continue
            case_metadata = _normalize_capture_corpus_metadata(
                raw_case.get("capture_metadata", raw_case.get("metadata"))
            )
            if "capture_medium" in raw_case and "capture_medium" not in case_metadata:
                case_metadata["capture_medium"] = raw_case.get("capture_medium")
            elif "medium" in raw_case and "capture_medium" not in case_metadata:
                case_metadata["capture_medium"] = raw_case.get("medium")
            break

    merged = dict(defaults)
    merged.update(case_metadata)
    return merged


def _return_package_capture_file_record(
    *,
    source_path: Path,
    package_path: str,
) -> Dict[str, object]:
    return {
        "path": package_path,
        "sha256": _sha256_file(source_path),
        "size_bytes": source_path.stat().st_size,
    }


def package_capture_return(
    capture_corpus_file: str,
    output_dir: str,
    capture_root: str,
    raw_capture_root: Optional[str] = None,
    capture_metadata_manifest_file: Optional[str] = None,
    capture_metadata: Optional[Dict[str, object]] = None,
    kit_manifest_file: Optional[str] = None,
    package_file: Optional[str] = None,
    return_manifest_file: Optional[str] = None,
    report_file: Optional[str] = None,
    return_session_id: Optional[str] = None,
    operator: Optional[str] = None,
    returned_at_utc: Optional[str] = None,
    require_captures: bool = True,
    require_raw_captures: bool = False,
    require_capture_provenance: bool = False,
    require_all_case_labels: bool = True,
) -> Dict[str, object]:
    """Assemble an operator return ZIP with a filled exact capture-file inventory."""

    corpus_path = Path(str(capture_corpus_file)).resolve()
    if not corpus_path.exists() or not corpus_path.is_file():
        raise ValueError("capture corpus file does not exist: {}".format(corpus_path))
    corpus_base = corpus_path.parent
    corpus = _load_json(corpus_path)
    schema = str(corpus.get("schema") or "").strip()
    if schema != CAPTURE_CORPUS_SCHEMA:
        raise ValueError(
            "capture corpus schema must be {}, got {}".format(
                CAPTURE_CORPUS_SCHEMA,
                schema or "<missing>",
            )
        )
    raw_cases = corpus.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("capture corpus cases must be a non-empty list")

    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    package_path = _resolve_output_path(package_file, out_dir, "operator_return.zip").resolve()
    return_manifest_path = _resolve_output_path(
        return_manifest_file,
        out_dir,
        "operator_return_manifest.json",
    ).resolve()
    report_path = _resolve_output_path(
        report_file,
        out_dir,
        "transport_capture_return_package_report.json",
    ).resolve()

    capture_root_path = _resolve_existing_path_cwd_or_base(
        capture_root,
        corpus_base,
        "capture_root",
    )
    if not capture_root_path.exists() or not capture_root_path.is_dir():
        raise ValueError("capture_root must be an existing directory: {}".format(capture_root_path))
    raw_capture_root_path: Optional[Path] = None
    if raw_capture_root is not None and str(raw_capture_root).strip():
        raw_capture_root_path = _resolve_existing_path_cwd_or_base(
            raw_capture_root,
            corpus_base,
            "raw_capture_root",
        )
        if not raw_capture_root_path.exists() or not raw_capture_root_path.is_dir():
            raise ValueError(
                "raw_capture_root must be an existing directory: {}".format(raw_capture_root_path)
            )

    kit_path = _resolve_optional_existing_file(
        kit_manifest_file,
        corpus_base,
        "kit_manifest_file",
    )
    metadata_manifest = _metadata_manifest_payload_for_return_package(
        capture_metadata_manifest_file=capture_metadata_manifest_file,
        corpus_base=corpus_base,
        capture_metadata=capture_metadata,
        cases=[case for case in raw_cases if isinstance(case, dict)],
    )

    failures: List[Dict[str, object]] = []

    def add_failure(code: str, message: str, **details: object) -> None:
        record: Dict[str, object] = {"code": code, "message": message}
        record.update(details)
        failures.append(record)

    package_entries: List[Dict[str, object]] = []
    return_cases: List[Dict[str, object]] = []
    expected_capture_names: Set[str] = set()
    expected_raw_capture_names: Set[str] = set()
    seen_labels: Set[str] = set()
    capture_image_count = 0
    raw_capture_image_count = 0
    cases_with_captures = 0
    cases_with_raw_captures = 0
    capture_provenance_evidence_records: List[Dict[str, object]] = []
    capture_provenance_passed_count = 0

    def add_package_entry(source_path: Path, archive_path: str, role: str) -> None:
        if not _is_safe_archive_member(archive_path):
            add_failure(
                "package_archive_path_invalid",
                "generated package archive path is not safe",
                archive_path=archive_path,
            )
            return
        package_entries.append(
            {
                "role": role,
                "source_path": str(source_path),
                "archive_path": archive_path,
                "sha256": _sha256_file(source_path),
                "size_bytes": source_path.stat().st_size,
            }
        )

    for index, raw_case in enumerate(raw_cases, 1):
        if not isinstance(raw_case, dict):
            add_failure(
                "capture_case_invalid",
                "capture corpus case must be an object",
                case_index=index,
            )
            continue
        label = _normalize_label(raw_case.get("label"), "capture_{:04d}".format(index))
        if label in seen_labels:
            add_failure(
                "capture_case_label_duplicate",
                "capture corpus labels must be unique",
                label=label,
            )
            continue
        seen_labels.add(label)
        expected_capture_names.update(_capture_subdir_names(label))
        expected_raw_capture_names.update(_capture_subdir_names(label, suffixes=("__raw", "-raw", "_raw")))

        capture_source = _capture_subdir_path(capture_root_path, label)
        capture_paths: List[Path] = []
        if capture_source is None:
            add_failure(
                "capture_label_directory_missing",
                "capture root does not contain a directory or image for this case",
                label=label,
            )
        else:
            capture_paths = _collect_capture_images_recursive(capture_source, corpus_base)
            if not capture_paths:
                add_failure(
                    "capture_images_missing",
                    "capture case has no supported capture image files",
                    label=label,
                )
        if bool(require_captures) and not capture_paths:
            if not any(
                failure.get("code") == "capture_images_missing"
                and failure.get("label") == label
                for failure in failures
            ):
                add_failure(
                    "capture_images_missing",
                    "capture images are required for every case",
                    label=label,
                )

        raw_source = None
        raw_paths: List[Path] = []
        if raw_capture_root_path is not None:
            raw_source = _capture_subdir_path(
                raw_capture_root_path,
                label,
                suffixes=("__raw", "-raw", "_raw"),
            )
            if raw_source is None:
                add_failure(
                    "raw_capture_label_directory_missing",
                    "raw capture root does not contain a directory or image for this case",
                    label=label,
                )
            else:
                raw_paths = _collect_capture_images_recursive(raw_source, corpus_base)
                if not raw_paths:
                    add_failure(
                        "raw_capture_images_missing",
                        "raw capture case has no supported image files",
                        label=label,
                    )
        if bool(require_raw_captures) and not raw_paths:
            if not any(
                failure.get("code") == "raw_capture_images_missing"
                and failure.get("label") == label
                for failure in failures
            ):
                add_failure(
                    "raw_capture_images_missing",
                    "raw camera capture images are required for every case",
                    label=label,
                )

        capture_records = []
        for source in capture_paths:
            archive_path = "captures/{}/{}".format(label, source.name)
            capture_records.append(
                _return_package_capture_file_record(
                    source_path=source,
                    package_path=archive_path,
                )
            )
            add_package_entry(source, archive_path, "capture")
        raw_records = []
        for source in raw_paths:
            archive_path = "raw_captures/{}/{}".format(label, source.name)
            raw_records.append(
                _return_package_capture_file_record(
                    source_path=source,
                    package_path=archive_path,
                )
            )
            add_package_entry(source, archive_path, "raw_capture")

        if capture_records:
            cases_with_captures += 1
            capture_image_count += len(capture_records)
        if raw_records:
            cases_with_raw_captures += 1
            raw_capture_image_count += len(raw_records)

        return_case: Dict[str, object] = {
            "label": label,
            "expected_capture_directory": "captures/{}".format(label),
            "capture_files": capture_records,
        }
        if raw_records or raw_capture_root_path is not None or bool(require_raw_captures):
            return_case["expected_raw_capture_directory"] = "raw_captures/{}".format(label)
            return_case["raw_capture_files"] = raw_records
        return_cases.append(return_case)

        case_classification = str(
            raw_case.get("classification") or corpus.get("classification") or ""
        ).strip().lower()
        case_medium = _normalize_capture_medium(
            raw_case.get(
                "capture_medium",
                raw_case.get("medium", corpus.get("capture_medium", corpus.get("medium"))),
            )
        )
        merged_metadata = _metadata_manifest_case_metadata(metadata_manifest, label)
        if case_medium == "unspecified":
            case_medium = _capture_medium_from_metadata(merged_metadata)
        provenance_evidence = _capture_provenance_evidence(
            classification=case_classification,
            capture_medium=case_medium,
            capture_metadata=merged_metadata,
            required=bool(require_capture_provenance),
        )
        capture_provenance_evidence_records.append(provenance_evidence)
        if bool(provenance_evidence.get("evidence_passed")):
            capture_provenance_passed_count += 1
        if not bool(provenance_evidence.get("strict_gate_passed", True)):
            add_failure(
                "capture_provenance_missing",
                "capture metadata manifest does not satisfy required capture provenance",
                label=label,
                status=provenance_evidence.get("status"),
            )

    unmatched_capture_entries = []
    for child in sorted(capture_root_path.iterdir(), key=lambda item: item.name.lower()):
        if not child.is_dir() and not (child.is_file() and child.suffix.lower() in CAPTURE_IMAGE_SUFFIXES):
            continue
        if child.name not in expected_capture_names:
            unmatched_capture_entries.append(str(child.resolve()))
    unmatched_raw_entries = []
    if raw_capture_root_path is not None:
        for child in sorted(raw_capture_root_path.iterdir(), key=lambda item: item.name.lower()):
            if not child.is_dir() and not (child.is_file() and child.suffix.lower() in CAPTURE_IMAGE_SUFFIXES):
                continue
            if child.name not in expected_raw_capture_names:
                unmatched_raw_entries.append(str(child.resolve()))
    if bool(require_all_case_labels):
        for entry in unmatched_capture_entries:
            add_failure(
                "unexpected_capture_label_entry",
                "capture root contains an entry that does not match a prepared case label",
                path=entry,
            )
        for entry in unmatched_raw_entries:
            add_failure(
                "unexpected_raw_capture_label_entry",
                "raw capture root contains an entry that does not match a prepared case label",
                path=entry,
            )

    generated_at_utc = protocol.utc_now_iso()
    return_manifest = {
        "schema": CAPTURE_RETURN_MANIFEST_SCHEMA,
        "generated_at_utc": generated_at_utc,
        "generated_by": "soenc transport package-capture-return",
        "capture_corpus_file": str(corpus_path),
        "capture_corpus_sha256": _sha256_file(corpus_path),
        "capture_kit_manifest_file": str(kit_path) if kit_path is not None else None,
        "capture_kit_manifest_sha256": (
            _sha256_file(kit_path) if kit_path is not None else ""
        ),
        "return_session_id": str(return_session_id or "").strip(),
        "operator": str(operator or "").strip(),
        "returned_at_utc": str(returned_at_utc or generated_at_utc).strip(),
        "capture_package_layout": {
            "capture_root": "captures/",
            "raw_capture_root": "raw_captures/",
            "metadata_manifest": "operator_capture_metadata_manifest.json",
        },
        "capture_file_inventory": {
            "required": True,
            "capture_file_count": capture_image_count,
            "raw_capture_file_count": raw_capture_image_count,
        },
        "cases": return_cases,
        "certification_boundary": (
            "This manifest binds the returned ZIP file inventory to a prepared capture "
            "corpus. It is package identity evidence only; certification still requires "
            "ingestion, measured recovery, archive replay, and a matching claim gate."
        ),
    }
    return_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(return_manifest_path, return_manifest)

    metadata_manifest_path = out_dir / "operator_capture_metadata_manifest.json"
    _write_json(metadata_manifest_path, metadata_manifest)

    add_package_entry(return_manifest_path, "operator_return_manifest.json", "return_manifest")
    add_package_entry(
        metadata_manifest_path,
        "operator_capture_metadata_manifest.json",
        "capture_metadata_manifest",
    )

    duplicate_archive_paths = [
        archive_path
        for archive_path, count in Counter(
            str(entry.get("archive_path")) for entry in package_entries
        ).items()
        if count > 1
    ]
    for archive_path in duplicate_archive_paths:
        add_failure(
            "duplicate_package_archive_path",
            "return package would contain duplicate archive paths",
            archive_path=archive_path,
        )

    if not failures:
        package_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(str(package_path), "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for entry in sorted(package_entries, key=lambda item: str(item.get("archive_path"))):
                archive.write(str(entry["source_path"]), str(entry["archive_path"]))

    report = {
        "schema": CAPTURE_RETURN_PACKAGE_SCHEMA,
        "generated_at_utc": generated_at_utc,
        "success": not failures,
        "capture_corpus_file": str(corpus_path),
        "capture_corpus_sha256": _sha256_file(corpus_path),
        "capture_root": str(capture_root_path),
        "raw_capture_root": str(raw_capture_root_path) if raw_capture_root_path else None,
        "capture_metadata_manifest_file": str(metadata_manifest_path),
        "capture_metadata_manifest_sha256": _sha256_file(metadata_manifest_path),
        "capture_return_manifest_file": str(return_manifest_path),
        "capture_return_manifest_sha256": _sha256_file(return_manifest_path),
        "capture_kit_manifest_file": str(kit_path) if kit_path is not None else None,
        "capture_kit_manifest_sha256": (
            _sha256_file(kit_path) if kit_path is not None else None
        ),
        "package_file": str(package_path) if not failures else None,
        "package_sha256": (
            _sha256_file(package_path) if not failures and package_path.exists() else None
        ),
        "package_size_bytes": (
            package_path.stat().st_size if not failures and package_path.exists() else None
        ),
        "parameters": {
            "require_captures": bool(require_captures),
            "require_raw_captures": bool(require_raw_captures),
            "require_capture_provenance": bool(require_capture_provenance),
            "require_all_case_labels": bool(require_all_case_labels),
            "return_session_id": str(return_session_id or "").strip(),
            "operator": str(operator or "").strip(),
        },
        "summary": {
            "case_count": len(return_cases),
            "cases_with_captures": cases_with_captures,
            "cases_with_raw_captures": cases_with_raw_captures,
            "capture_file_count": capture_image_count,
            "raw_capture_file_count": raw_capture_image_count,
            "capture_provenance_required": bool(require_capture_provenance),
            "capture_provenance_passed": bool(
                (not require_capture_provenance)
                or (
                    len(capture_provenance_evidence_records) == len(return_cases)
                    and capture_provenance_passed_count == len(return_cases)
                )
            ),
            "capture_provenance_evidence_count": capture_provenance_passed_count,
            "package_entry_count": len(package_entries),
            "unmatched_capture_entry_count": len(unmatched_capture_entries),
            "unmatched_raw_capture_entry_count": len(unmatched_raw_entries),
            "failure_count": len(failures),
        },
        "unmatched_capture_entries": unmatched_capture_entries,
        "unmatched_raw_capture_entries": unmatched_raw_entries,
        "capture_provenance_evidence": capture_provenance_evidence_records,
        "package_entries": package_entries,
        "failures": failures,
        "report_file": str(report_path),
        "certification_boundary": (
            "This packages operator/lab return files and writes exact SHA256 inventory "
            "for later fail-closed extraction. It does not certify physical print-scan, "
            "real camera, or OCR-only transfer by itself."
        ),
    }
    _write_json(report_path, report)
    return report


def _apply_distortion_to_image(source: Path, target: Path, definition: Dict[str, object], seed: int) -> None:
    kind = str(definition.get("kind") or "")
    parameters = definition.get("parameters") if isinstance(definition.get("parameters"), dict) else {}
    target.parent.mkdir(parents=True, exist_ok=True)
    if kind == "control":
        shutil.copy2(str(source), str(target))
        return

    try:
        from PIL import Image, ImageEnhance, ImageFilter
    except Exception as exc:
        raise RuntimeError("Pillow is required for distortion suite execution") from exc

    resampling = getattr(Image, "Resampling", Image)
    lanczos = getattr(resampling, "LANCZOS", getattr(Image, "LANCZOS", 1))
    bicubic = getattr(resampling, "BICUBIC", getattr(Image, "BICUBIC", 3))

    image = Image.open(str(source)).convert("RGB")
    if kind == "jpeg_recompress":
        quality = int(parameters.get("quality", 95))
        image.save(str(target), "JPEG", quality=quality, optimize=True)
        return

    if kind == "png_reencode":
        optimize = bool(parameters.get("optimize", True))
        image.save(str(target), "PNG", optimize=optimize)
        return

    if kind == "resize":
        scale = float(parameters.get("scale", 1.0))
        width = max(1, int(round(image.width * scale)))
        height = max(1, int(round(image.height * scale)))
        image.resize((width, height), lanczos).save(str(target), "PNG", optimize=True)
        return

    if kind == "blur":
        radius = float(parameters.get("radius", 0.35))
        image.filter(ImageFilter.GaussianBlur(radius=radius)).save(str(target), "PNG", optimize=True)
        return

    if kind == "contrast_brightness":
        contrast = float(parameters.get("contrast", 1.0))
        brightness = float(parameters.get("brightness", 1.0))
        image = ImageEnhance.Contrast(image).enhance(contrast)
        image = ImageEnhance.Brightness(image).enhance(brightness)
        image.save(str(target), "PNG", optimize=True)
        return

    if kind == "screenshot_like":
        scale = float(parameters.get("scale", 0.92))
        quality = int(parameters.get("quality", 96))
        down = image.resize(
            (
                max(1, int(round(image.width * scale))),
                max(1, int(round(image.height * scale))),
            ),
            lanczos,
        )
        image = down.resize((image.width, image.height), lanczos)
        image.save(str(target), "JPEG", quality=quality, optimize=True)
        return

    if kind == "rotate":
        degrees = float(parameters.get("degrees", 0.25))
        image.rotate(degrees, resample=bicubic, expand=False, fillcolor="white").save(
            str(target),
            "PNG",
            optimize=True,
        )
        return

    if kind == "crop_margin":
        pixels = int(parameters.get("pixels", 4))
        pixels = max(0, min(pixels, min(image.width, image.height) // 4))
        cropped = image.crop((pixels, pixels, image.width - pixels, image.height - pixels))
        cropped.resize((image.width, image.height), lanczos).save(str(target), "PNG", optimize=True)
        return

    if kind == "perspective_skew":
        x_shear = float(parameters.get("x_shear", -0.015))
        y_shear = float(parameters.get("y_shear", 0.01))
        x_offset = float(parameters.get("x_offset", 20))
        y_offset = float(parameters.get("y_offset", -15))
        image.transform(
            image.size,
            Image.AFFINE,
            (1.0, x_shear, x_offset, y_shear, 1.0, y_offset),
            resample=bicubic,
            fillcolor="white",
        ).save(str(target), "PNG", optimize=True)
        return

    if kind == "sparse_noise":
        density = float(parameters.get("density", 0.0002))
        noisy = image.load()
        rng = random.Random(int(seed))
        pixel_count = max(1, int(round(image.width * image.height * max(0.0, density))))
        for _index in range(pixel_count):
            x = rng.randrange(0, image.width)
            y = rng.randrange(0, image.height)
            noisy[x, y] = (0, 0, 0) if rng.randrange(0, 2) else (255, 255, 255)
        image.save(str(target), "PNG", optimize=True)
        return

    if kind == "print_scan_like":
        contrast = float(parameters.get("contrast", 1.18))
        brightness = float(parameters.get("brightness", 1.04))
        radius = float(parameters.get("blur_radius", 0.25))
        image = image.convert("L")
        image = ImageEnhance.Contrast(image).enhance(contrast)
        image = ImageEnhance.Brightness(image).enhance(brightness)
        image = image.filter(ImageFilter.GaussianBlur(radius=radius)).convert("RGB")
        image.save(str(target), "PNG", optimize=True)
        return

    raise ValueError("unsupported distortion kind: {}".format(kind))


def _materialize_distortion_images(
    image_paths: List[Path],
    target_dir: Path,
    definition: Dict[str, object],
    seed: int,
) -> List[Path]:
    target_dir.mkdir(parents=True, exist_ok=True)
    kind = str(definition.get("kind") or "")
    suffix = ".jpg" if kind in ("jpeg_recompress", "screenshot_like") else ".png"
    distorted_paths = []
    for index, source in enumerate(image_paths, 1):
        target = target_dir / "case_{:04d}{}".format(index, suffix)
        _apply_distortion_to_image(
            source=source,
            target=target,
            definition=definition,
            seed=int(seed) + index,
        )
        distorted_paths.append(target)
    return distorted_paths


def _profile_check(name: str, passed: bool, requirement: str, observed: object) -> Dict[str, object]:
    return {
        "name": name,
        "passed": bool(passed),
        "requirement": requirement,
        "observed": observed,
    }


def _build_profile_compliance(
    profile: str,
    transport,
    backend: str,
    payload_sizes: List[int],
    redundancy_copies: int,
    parity_group_size: int,
    allow_unsafe_profile: bool,
    allow_ocr_fallback: bool,
    redundancy_threshold_bytes: int,
) -> Dict[str, object]:
    threshold = max(1, int(redundancy_threshold_bytes))
    if profile != RELIABLE_AIRGAP_PROFILE:
        strict_profile = backend == "sidecar" and not bool(allow_ocr_fallback)
        return {
            "profile": profile,
            "passed": True,
            "strict_profile": bool(strict_profile),
            "unsafe_override_accepted": False,
            "allow_ocr_fallback": bool(allow_ocr_fallback),
            "redundancy_threshold_bytes": threshold,
            "checks": [
                _profile_check(
                    "compatibility_profile",
                    True,
                    "non-production compatibility profile keeps legacy behavior",
                    profile,
                )
            ],
            "warnings": [],
        }

    max_payload_size = max(int(size) for size in payload_sizes) if payload_sizes else 0
    redundancy_required = max_payload_size >= threshold
    has_loss_recovery = int(redundancy_copies) >= 2 or int(parity_group_size) >= 2
    backend_allowed = backend == "sidecar" or bool(allow_ocr_fallback)
    strict_profile = backend == "sidecar" and not bool(allow_ocr_fallback)

    checks = [
        _profile_check(
            "sidecar_backend_required",
            backend_allowed,
            "backend must be sidecar unless explicit OCR fallback is allowed",
            backend,
        ),
        _profile_check(
            "render_sidecar_required",
            bool(getattr(transport, "render_sidecar", False)),
            "transport.render_sidecar must be enabled",
            getattr(transport, "render_sidecar", None),
        ),
        _profile_check(
            "manifest_required",
            True,
            "certification must recover with the generated manifest",
            "manifest-guided certification",
        ),
        _profile_check(
            "line_crc_required",
            getattr(transport, "line_crc_mode", None) == "on",
            "line_crc_mode must be on",
            getattr(transport, "line_crc_mode", None),
        ),
        _profile_check(
            "page_crc_metadata_required",
            getattr(transport, "metadata_level", None) == "compact",
            "metadata_level must be compact to retain @PAGECRC and hash metadata",
            getattr(transport, "metadata_level", None),
        ),
        _profile_check(
            "manifest_guided_line_index_required",
            getattr(transport, "line_index_mode", None) != "off",
            "line_index_mode must not be off",
            getattr(transport, "line_index_mode", None),
        ),
        _profile_check(
            "loss_recovery_required",
            (not redundancy_required) or has_loss_recovery,
            "redundancy_copies >= 2 or parity_group_size >= 2 for payloads at/above threshold",
            {
                "max_payload_size": max_payload_size,
                "redundancy_copies": int(redundancy_copies),
                "parity_group_size": int(parity_group_size),
            },
        ),
        _profile_check(
            "sha256_verification_required",
            True,
            "certification must compare payload_sha256 and restored_sha256",
            "enabled",
        ),
    ]
    warnings = []
    if allow_ocr_fallback and backend != "sidecar":
        warnings.append(
            "OCR fallback was explicitly allowed; report is not a strict sidecar-only production proof."
        )
    passed = all(bool(check.get("passed")) for check in checks)
    unsafe_override_accepted = bool(allow_unsafe_profile and not passed)
    compliance = {
        "profile": profile,
        "passed": passed,
        "strict_profile": bool(strict_profile and passed),
        "unsafe_override_accepted": unsafe_override_accepted,
        "allow_ocr_fallback": bool(allow_ocr_fallback),
        "redundancy_threshold_bytes": threshold,
        "checks": checks,
        "warnings": warnings,
    }
    if not passed and not allow_unsafe_profile:
        failed = [
            "{} observed {}".format(check.get("name"), check.get("observed"))
            for check in checks
            if not check.get("passed")
        ]
        raise ValueError(
            "{} profile rejected unsafe settings: {}".format(
                RELIABLE_AIRGAP_PROFILE,
                "; ".join(failed),
            )
        )
    if unsafe_override_accepted:
        compliance["warnings"] = list(warnings) + [
            "Unsafe profile override accepted; report is executable evidence but not production-certified."
        ]
    return compliance


def _claim_record(
    claim: str,
    status: str,
    certified: bool,
    evidence_level: str,
    boundary: str,
    required_gates: List[str],
    passed_gates: List[str],
    missing_gates: Optional[List[str]] = None,
    metrics: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    return {
        "claim": claim,
        "status": status,
        "certified": bool(certified),
        "evidence_level": evidence_level,
        "boundary": boundary,
        "required_gates": list(required_gates),
        "passed_gates": list(passed_gates),
        "missing_gates": list(missing_gates or []),
        "metrics": dict(metrics or {}),
    }


def _build_certification_claims(
    *,
    success: bool,
    profile_name: str,
    profile_certified: bool,
    backend: str,
    distortion_suite_name: str,
    distortion_threshold_passed: bool,
    capture_cases: List[Dict[str, object]],
    capture_classification_counts: Counter,
    capture_medium_counts: Counter,
    capture_success_rates: Dict[str, float],
    require_distinct_capture_images: bool,
    distinct_capture_gate_passed: bool,
    require_physical_print_scan: bool,
    physical_print_scan_gate_passed: bool,
    require_real_camera_perspective_correction: bool,
    real_camera_perspective_gate_passed: bool,
    require_capture_attachment_report: bool,
    capture_attachment_report_gate_passed: bool,
    require_capture_provenance: bool,
    capture_provenance_gate_passed: bool,
    require_ocr_only_backend: bool,
    ocr_only_threshold_passed: bool,
    ocr_only_success_rates: Dict[str, float],
) -> Dict[str, object]:
    claims: List[Dict[str, object]] = []
    passed_report = bool(success)
    profile_gate = bool(profile_certified)
    generated_suite_present = distortion_suite_name in (
        NO_DISTORTION_SUITE,
        GENERATED_PAGE_BASIC_DISTORTION_SUITE,
        GENERATED_PAGE_STRESS_DISTORTION_SUITE,
    )
    generated_page_certified = bool(
        passed_report
        and profile_gate
        and backend == "sidecar"
        and generated_suite_present
        and bool(distortion_threshold_passed)
    )
    generated_page_production = bool(
        generated_page_certified and profile_name == RELIABLE_AIRGAP_PROFILE
    )
    generated_status = (
        "production-certified"
        if generated_page_production
        else "local-certified"
        if generated_page_certified
        else "not-certified"
    )
    claims.append(
        _claim_record(
            claim="generated-page-sidecar",
            status=generated_status,
            certified=generated_page_certified,
            evidence_level="production"
            if generated_page_production
            else "local"
            if generated_page_certified
            else "not-certified",
            boundary=(
                "Generated PNG pages recovered through sidecar/manifest decoding under the "
                "selected profile. Only reliable-airgap-v1 is a production airgap profile. "
                "This does not certify camera photos, physical print-scan, or OCR-only transfer."
            ),
            required_gates=[
                "success",
                "profile_certified",
                "sidecar_backend",
                "distortion_threshold",
            ],
            passed_gates=[
                gate
                for gate, passed in (
                    ("success", passed_report),
                    ("profile_certified", profile_gate),
                    ("sidecar_backend", backend == "sidecar"),
                    ("distortion_threshold", bool(distortion_threshold_passed)),
                )
                if passed
            ],
            missing_gates=[
                gate
                for gate, passed in (
                    ("success", passed_report),
                    ("profile_certified", profile_gate),
                    ("sidecar_backend", backend == "sidecar"),
                    ("distortion_threshold", bool(distortion_threshold_passed)),
                )
                if not passed
            ],
            metrics={
                "profile": profile_name,
                "backend": backend,
                "distortion_suite": distortion_suite_name,
            },
        )
    )

    stress_certified = bool(
        generated_page_certified
        and distortion_suite_name == GENERATED_PAGE_STRESS_DISTORTION_SUITE
    )
    claims.append(
        _claim_record(
            claim="generated-page-synthetic-stress",
            status="synthetic-stress-certified" if stress_certified else "not-certified",
            certified=stress_certified,
            evidence_level="synthetic-stress" if stress_certified else "not-certified",
            boundary=(
                "Synthetic generated-page distortions cover deterministic image transforms "
                "only. They are not real camera/photo, real perspective-correction, or "
                "physical print-scan evidence."
            ),
            required_gates=[
                "generated_page_sidecar_certified",
                "generated-page-stress-v1",
            ],
            passed_gates=[
                gate
                for gate, passed in (
                    ("generated_page_sidecar_certified", generated_page_certified),
                    (
                        "generated-page-stress-v1",
                        distortion_suite_name == GENERATED_PAGE_STRESS_DISTORTION_SUITE,
                    ),
                )
                if passed
            ],
            missing_gates=[
                gate
                for gate, passed in (
                    ("generated_page_sidecar_certified", generated_page_certified),
                    (
                        "generated-page-stress-v1",
                        distortion_suite_name == GENERATED_PAGE_STRESS_DISTORTION_SUITE,
                    ),
                )
                if not passed
            ],
            metrics={"distortion_suite": distortion_suite_name},
        )
    )

    capture_classifications = sorted(str(item) for item in capture_classification_counts)
    capture_media = sorted(str(item) for item in capture_medium_counts)
    attachment_gate_ok = (
        bool(require_capture_attachment_report) and bool(capture_attachment_report_gate_passed)
    )
    provenance_gate_ok = (
        (not bool(require_capture_provenance)) or bool(capture_provenance_gate_passed)
    )
    distinct_gate_ok = (
        not bool(require_distinct_capture_images) or bool(distinct_capture_gate_passed)
    )
    print_scan_classification_ok = any(
        classification in ("lab", "real") for classification in capture_classifications
    )
    print_scan_medium_ok = "print-scan" in capture_media
    physical_print_scan_certified = bool(
        passed_report
        and profile_gate
        and bool(require_physical_print_scan)
        and bool(physical_print_scan_gate_passed)
        and bool(require_distinct_capture_images)
        and bool(distinct_capture_gate_passed)
        and attachment_gate_ok
        and provenance_gate_ok
        and print_scan_classification_ok
        and print_scan_medium_ok
    )
    print_scan_level = (
        "real"
        if physical_print_scan_certified and "real" in capture_classifications
        else "lab"
        if physical_print_scan_certified and "lab" in capture_classifications
        else "not-certified"
    )
    print_scan_status = (
        "{}-certified".format(print_scan_level)
        if physical_print_scan_certified
        else "not-certified"
    )
    claims.append(
        _claim_record(
            claim="physical-print-scan",
            status=print_scan_status,
            certified=physical_print_scan_certified,
            evidence_level=print_scan_level,
            boundary=(
                "Physical print-scan evidence applies only to the measured corpus "
                "classification, devices, DPI, and operator conditions. It does not certify "
                "real camera transfer, perspective correction, OCR-only transfer, or other "
                "scanner/printer combinations."
            ),
            required_gates=[
                "success",
                "profile_certified",
                "require_physical_print_scan",
                "physical_print_scan_passed",
                "require_distinct_capture_images",
                "distinct_capture_images_passed",
                "require_capture_attachment_report",
                "capture_attachment_report_passed",
                "capture_provenance_passed",
                "lab_or_real_classification",
                "print_scan_medium",
            ],
            passed_gates=[
                gate
                for gate, passed in (
                    ("success", passed_report),
                    ("profile_certified", profile_gate),
                    ("require_physical_print_scan", bool(require_physical_print_scan)),
                    ("physical_print_scan_passed", bool(physical_print_scan_gate_passed)),
                    ("require_distinct_capture_images", bool(require_distinct_capture_images)),
                    ("distinct_capture_images_passed", bool(distinct_capture_gate_passed)),
                    ("require_capture_attachment_report", bool(require_capture_attachment_report)),
                    ("capture_attachment_report_passed", attachment_gate_ok),
                    ("capture_provenance_passed", provenance_gate_ok),
                    ("lab_or_real_classification", print_scan_classification_ok),
                    ("print_scan_medium", print_scan_medium_ok),
                )
                if passed
            ],
            missing_gates=[
                gate
                for gate, passed in (
                    ("success", passed_report),
                    ("profile_certified", profile_gate),
                    ("require_physical_print_scan", bool(require_physical_print_scan)),
                    ("physical_print_scan_passed", bool(physical_print_scan_gate_passed)),
                    ("require_distinct_capture_images", bool(require_distinct_capture_images)),
                    ("distinct_capture_images_passed", bool(distinct_capture_gate_passed)),
                    ("require_capture_attachment_report", bool(require_capture_attachment_report)),
                    ("capture_attachment_report_passed", attachment_gate_ok),
                    ("capture_provenance_passed", provenance_gate_ok),
                    ("lab_or_real_classification", print_scan_classification_ok),
                    ("print_scan_medium", print_scan_medium_ok),
                )
                if not passed
            ],
            metrics={
                "capture_classification_counts": dict(capture_classification_counts),
                "capture_medium_counts": dict(capture_medium_counts),
                "success_rates_by_classification": dict(capture_success_rates),
            },
        )
    )

    real_camera_certified = bool(
        passed_report
        and profile_gate
        and bool(require_real_camera_perspective_correction)
        and bool(real_camera_perspective_gate_passed)
        and bool(require_distinct_capture_images)
        and bool(distinct_capture_gate_passed)
        and attachment_gate_ok
        and provenance_gate_ok
        and "real" in capture_classifications
    )
    claims.append(
        _claim_record(
            claim="real-camera-perspective-correction",
            status="real-certified" if real_camera_certified else "not-certified",
            certified=real_camera_certified,
            evidence_level="real" if real_camera_certified else "not-certified",
            boundary=(
                "Real camera perspective-correction evidence requires raw camera photos and "
                "corrected recovery images for the measured real corpus. Synthetic "
                "perspective-skew distortion does not satisfy this claim."
            ),
            required_gates=[
                "success",
                "profile_certified",
                "require_real_camera_perspective_correction",
                "real_camera_perspective_correction_passed",
                "require_distinct_capture_images",
                "distinct_capture_images_passed",
                "require_capture_attachment_report",
                "capture_attachment_report_passed",
                "capture_provenance_passed",
                "real_classification",
            ],
            passed_gates=[
                gate
                for gate, passed in (
                    ("success", passed_report),
                    ("profile_certified", profile_gate),
                    (
                        "require_real_camera_perspective_correction",
                        bool(require_real_camera_perspective_correction),
                    ),
                    (
                        "real_camera_perspective_correction_passed",
                        bool(real_camera_perspective_gate_passed),
                    ),
                    ("require_distinct_capture_images", bool(require_distinct_capture_images)),
                    ("distinct_capture_images_passed", bool(distinct_capture_gate_passed)),
                    ("require_capture_attachment_report", bool(require_capture_attachment_report)),
                    ("capture_attachment_report_passed", attachment_gate_ok),
                    ("capture_provenance_passed", provenance_gate_ok),
                    ("real_classification", "real" in capture_classifications),
                )
                if passed
            ],
            missing_gates=[
                gate
                for gate, passed in (
                    ("success", passed_report),
                    ("profile_certified", profile_gate),
                    (
                        "require_real_camera_perspective_correction",
                        bool(require_real_camera_perspective_correction),
                    ),
                    (
                        "real_camera_perspective_correction_passed",
                        bool(real_camera_perspective_gate_passed),
                    ),
                    ("require_distinct_capture_images", bool(require_distinct_capture_images)),
                    ("distinct_capture_images_passed", bool(distinct_capture_gate_passed)),
                    ("require_capture_attachment_report", bool(require_capture_attachment_report)),
                    ("capture_attachment_report_passed", attachment_gate_ok),
                    ("capture_provenance_passed", provenance_gate_ok),
                    ("real_classification", "real" in capture_classifications),
                )
                if not passed
            ],
            metrics={
                "capture_classification_counts": dict(capture_classification_counts),
                "capture_medium_counts": dict(capture_medium_counts),
                "success_rates_by_classification": dict(capture_success_rates),
            },
        )
    )

    ocr_only_certified = bool(
        passed_report
        and bool(require_ocr_only_backend)
        and bool(ocr_only_threshold_passed)
        and backend in OCR_ONLY_CERTIFICATION_BACKENDS
    )
    claims.append(
        _claim_record(
            claim="backend-specific-ocr-only",
            status="backend-measured" if ocr_only_certified else "not-certified",
            certified=ocr_only_certified,
            evidence_level="backend-specific" if ocr_only_certified else "not-certified",
            boundary=(
                "OCR-only evidence is scoped to the named backend and measured corpus. "
                "It does not certify generic OCR fallback, sidecar production readiness, "
                "camera transfer, or physical print-scan transfer."
            ),
            required_gates=[
                "success",
                "require_ocr_only_backend",
                "ocr_only_threshold_passed",
                "backend_is_ocr_only",
            ],
            passed_gates=[
                gate
                for gate, passed in (
                    ("success", passed_report),
                    ("require_ocr_only_backend", bool(require_ocr_only_backend)),
                    ("ocr_only_threshold_passed", bool(ocr_only_threshold_passed)),
                    ("backend_is_ocr_only", backend in OCR_ONLY_CERTIFICATION_BACKENDS),
                )
                if passed
            ],
            missing_gates=[
                gate
                for gate, passed in (
                    ("success", passed_report),
                    ("require_ocr_only_backend", bool(require_ocr_only_backend)),
                    ("ocr_only_threshold_passed", bool(ocr_only_threshold_passed)),
                    ("backend_is_ocr_only", backend in OCR_ONLY_CERTIFICATION_BACKENDS),
                )
                if not passed
            ],
            metrics={
                "backend": backend,
                "success_rates_by_backend": dict(ocr_only_success_rates),
            },
        )
    )

    certified_claims = [claim for claim in claims if bool(claim.get("certified"))]
    return {
        "schema": CERTIFICATION_CLAIMS_SCHEMA,
        "summary": {
            "certified_claim_count": len(certified_claims),
            "certified_claims": [str(claim.get("claim")) for claim in certified_claims],
            "uncertified_claims": [
                str(claim.get("claim")) for claim in claims if not claim.get("certified")
            ],
            "highest_evidence_level": (
                "production"
                if any(str(claim.get("evidence_level")) == "production" for claim in certified_claims)
                else "real"
                if any(str(claim.get("evidence_level")) == "real" for claim in certified_claims)
                else "lab"
                if any(str(claim.get("evidence_level")) == "lab" for claim in certified_claims)
                else "synthetic-stress"
                if any(
                    str(claim.get("evidence_level")) == "synthetic-stress"
                    for claim in certified_claims
                )
                else "backend-specific"
                if any(
                    str(claim.get("evidence_level")) == "backend-specific"
                    for claim in certified_claims
                )
                else "not-certified"
            ),
        },
        "claims": claims,
        "certification_boundary": (
            "These claim records are a machine-readable launch boundary. A claim is usable "
            "only when its own record is certified=true; other transport modes remain "
            "uncertified even if the overall report succeeded."
        ),
    }


def _capture_manifest_has_sidecar(manifest: Dict[str, object]) -> bool:
    return bool(_capture_sidecar_present(manifest))


def _capture_manifest_metadata_level(manifest: Dict[str, object]) -> Optional[str]:
    value = manifest.get("metadata_level")
    if isinstance(value, str) and value.strip():
        return value.strip()
    pages = manifest.get("pages")
    if isinstance(pages, list):
        for page in pages:
            if isinstance(page, dict) and any(
                key in page for key in ("page_crc", "compressed_sha256", "raw_sha256")
            ):
                return "compact"
    if manifest.get("compressed_sha256") and manifest.get("raw_sha256"):
        return "compact"
    return None


def _capture_manifest_line_crc_mode(manifest: Dict[str, object]) -> Optional[str]:
    values = []
    for key in ("line_crc_mode", "transport_line_crc"):
        value = manifest.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    if values:
        normalized = {value.lower() for value in values}
        if len(normalized) == 1:
            return values[0]
        return "mismatch:{}".format(",".join(sorted(normalized)))
    render_layout = manifest.get("render_layout")
    if isinstance(render_layout, dict):
        pages = render_layout.get("pages")
        if isinstance(pages, list):
            for page in pages:
                if not isinstance(page, dict):
                    continue
                lines = page.get("lines")
                if not isinstance(lines, list):
                    continue
                for line in lines:
                    if isinstance(line, dict) and line.get("expected_crc"):
                        return "on"
    return None


def _capture_manifest_line_index_mode(manifest: Dict[str, object]) -> Optional[str]:
    value = manifest.get("line_index_mode", manifest.get("transport_line_index_mode"))
    if isinstance(value, str) and value.strip():
        return value.strip()
    chunk_locations = manifest.get("chunk_locations")
    if isinstance(chunk_locations, dict) and chunk_locations:
        return "full"
    return None


def _capture_manifest_redundancy_copies(manifest: Dict[str, object]) -> Optional[int]:
    value = manifest.get("redundancy_copies")
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _capture_manifest_parity_group_size(manifest: Dict[str, object]) -> Optional[int]:
    parity = manifest.get("parity")
    if not isinstance(parity, dict):
        return None
    value = parity.get("group_size")
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _capture_profile_compliance(
    profile: str,
    backend: str,
    manifest_path: Path,
    payload_path: Path,
    manifest: Dict[str, object],
    classification: str,
    redundancy_threshold_bytes: int,
    allow_ocr_fallback: bool,
) -> Dict[str, object]:
    threshold = max(1, int(redundancy_threshold_bytes))
    if profile != RELIABLE_AIRGAP_PROFILE:
        strict_profile = backend == "sidecar" and not bool(allow_ocr_fallback)
        return {
            "profile": profile,
            "passed": True,
            "strict_profile": bool(strict_profile),
            "classification": classification,
            "checks": [
                _profile_check(
                    "compatibility_profile",
                    True,
                    "capture corpus is measured under a non-production compatibility profile",
                    profile,
                )
            ],
        }

    raw_size = manifest.get("raw_size")
    try:
        payload_size = int(raw_size) if raw_size is not None else int(payload_path.stat().st_size)
    except Exception:
        payload_size = 0
    sidecar_enabled = _capture_manifest_has_sidecar(manifest)
    line_crc_mode = _capture_manifest_line_crc_mode(manifest)
    metadata_level = _capture_manifest_metadata_level(manifest)
    line_index_mode = _capture_manifest_line_index_mode(manifest)
    redundancy_copies = _capture_manifest_redundancy_copies(manifest)
    parity_group_size = _capture_manifest_parity_group_size(manifest)
    redundancy_required = payload_size >= threshold
    has_loss_recovery = (
        (redundancy_copies is not None and redundancy_copies >= 2)
        or (parity_group_size is not None and parity_group_size >= 2)
    )
    backend_allowed = backend == "sidecar" or bool(allow_ocr_fallback)
    checks = [
        _profile_check(
            "sidecar_backend_required",
            backend_allowed,
            "backend must be sidecar unless explicit OCR fallback is allowed",
            backend,
        ),
        _profile_check(
            "capture_manifest_required",
            manifest_path.exists(),
            "operator capture case must bind an existing manifest",
            str(manifest_path),
        ),
        _profile_check(
            "payload_sha256_required",
            bool(manifest.get("raw_sha256")) and _sha256_file(payload_path) == manifest.get("raw_sha256"),
            "payload bytes must match manifest raw_sha256",
            {"payload_sha256": _sha256_file(payload_path), "manifest_raw_sha256": manifest.get("raw_sha256")},
        ),
        _profile_check(
            "sidecar_layout_required",
            sidecar_enabled,
            "capture manifest must include sidecar layout metadata",
            sidecar_enabled,
        ),
        _profile_check(
            "line_crc_required",
            line_crc_mode == "on",
            "capture manifest line CRC must be on",
            line_crc_mode,
        ),
        _profile_check(
            "page_crc_metadata_required",
            metadata_level == "compact",
            "capture manifest must retain compact page/hash metadata",
            metadata_level,
        ),
        _profile_check(
            "manifest_guided_line_index_required",
            line_index_mode is not None and line_index_mode != "off",
            "capture manifest line indexing must not be off",
            line_index_mode,
        ),
        _profile_check(
            "loss_recovery_required",
            (not redundancy_required) or has_loss_recovery,
            "redundancy_copies >= 2 or parity_group_size >= 2 for payloads at/above threshold",
            {
                "payload_size": payload_size,
                "redundancy_copies": redundancy_copies,
                "parity_group_size": parity_group_size,
            },
        ),
    ]
    return {
        "profile": profile,
        "classification": classification,
        "passed": all(bool(check.get("passed")) for check in checks),
        "strict_profile": bool(
            backend == "sidecar"
            and not bool(allow_ocr_fallback)
            and all(bool(check.get("passed")) for check in checks)
        ),
        "checks": checks,
    }


def _capture_validation_case(
    raw_case: Dict[str, object],
    profile: str,
    backend: str,
    allow_ocr_fallback: bool,
    profile_redundancy_threshold_bytes: int,
    require_captures: bool,
    require_distinct_capture_images: bool,
    require_raw_captures: bool,
    require_capture_attachment_report: bool,
    require_physical_print_scan: bool,
    require_real_camera_perspective_correction: bool,
    require_ocr_only_backend: bool,
    require_capture_provenance: bool,
    attachment_report: Optional[Dict[str, object]],
) -> Dict[str, object]:
    label = str(raw_case.get("label") or "").strip()
    classification = str(raw_case.get("classification") or "").strip().lower()
    capture_medium = _normalize_capture_medium(raw_case.get("capture_medium"))
    manifest_path = raw_case.get("manifest_path")
    payload_path = raw_case.get("payload_path")
    image_paths = raw_case.get("image_paths")
    reference_image_paths = raw_case.get("reference_image_paths")
    raw_image_paths = raw_case.get("raw_image_paths")
    if not isinstance(manifest_path, Path):
        manifest_path = Path(str(manifest_path or "")).resolve()
    if not isinstance(payload_path, Path):
        payload_path = Path(str(payload_path or "")).resolve()
    if not isinstance(image_paths, list):
        image_paths = []
    if not isinstance(reference_image_paths, list):
        reference_image_paths = []
    if not isinstance(raw_image_paths, list):
        raw_image_paths = []
    capture_metadata = raw_case.get("capture_metadata")
    if not isinstance(capture_metadata, dict):
        capture_metadata = {}
    perspective_correction = raw_case.get("perspective_correction")
    if not isinstance(perspective_correction, dict):
        perspective_correction = {}

    manifest = _load_json(manifest_path) if manifest_path.exists() and manifest_path.is_file() else {}
    profile_compliance = _capture_profile_compliance(
        profile=profile,
        backend=backend,
        manifest_path=manifest_path,
        payload_path=payload_path,
        manifest=manifest,
        classification=classification,
        redundancy_threshold_bytes=profile_redundancy_threshold_bytes,
        allow_ocr_fallback=allow_ocr_fallback,
    )
    reference_transform = _capture_reference_transform(
        reference_image_paths=reference_image_paths,
        capture_image_paths=image_paths,
        require_distinct_capture_images=bool(require_distinct_capture_images),
        missing_capture_passes_when_not_required=not (
            bool(require_captures) or bool(require_distinct_capture_images)
        ),
    )
    attachment_evidence = _capture_attachment_report_evidence(
        label=label,
        classification=classification,
        capture_medium=capture_medium,
        capture_image_paths=image_paths,
        raw_image_paths=raw_image_paths,
        reference_image_paths=reference_image_paths,
        attachment_report=attachment_report,
        required=bool(require_capture_attachment_report),
    )
    perspective_evidence = _capture_perspective_correction_evidence(
        classification=classification,
        raw_image_paths=raw_image_paths,
        corrected_image_paths=image_paths,
        reference_image_paths=reference_image_paths,
        perspective_correction=perspective_correction,
        required=bool(require_real_camera_perspective_correction),
    )
    print_scan_evidence = _capture_physical_print_scan_evidence(
        classification=classification,
        capture_medium=capture_medium,
        capture_image_paths=image_paths,
        reference_image_paths=reference_image_paths,
        capture_metadata=capture_metadata,
        reference_transform=reference_transform,
        required=bool(require_physical_print_scan),
    )
    provenance_evidence = _capture_provenance_evidence(
        classification=classification,
        capture_medium=capture_medium,
        capture_metadata=capture_metadata,
        required=bool(require_capture_provenance),
    )
    ocr_only_evidence = _capture_ocr_only_evidence(
        backend=backend,
        manifest_path=manifest_path,
        manifest=manifest,
        required=bool(require_ocr_only_backend),
    )

    failures = []
    if bool(require_captures) and not image_paths:
        failures.append("capture_images_missing")
    if bool(require_raw_captures) and not raw_image_paths:
        failures.append("raw_capture_images_missing")
    if not bool(profile_compliance.get("passed")):
        failures.append("capture_profile_not_certified")
    if not bool(reference_transform.get("strict_gate_passed", True)):
        failures.append("capture_reference_not_distinct")
    if not bool(attachment_evidence.get("strict_gate_passed", True)):
        failures.append("capture_attachment_report_mismatch")
    if not bool(print_scan_evidence.get("strict_gate_passed", True)):
        failures.append("capture_print_scan_evidence_missing")
    if not bool(perspective_evidence.get("strict_gate_passed", True)):
        failures.append("capture_perspective_evidence_missing")
    if not bool(provenance_evidence.get("strict_gate_passed", True)):
        failures.append("capture_provenance_missing")
    if not bool(ocr_only_evidence.get("strict_gate_passed", True)):
        failures.append("ocr_only_evidence_missing")

    ready = bool(image_paths) and not failures
    return {
        "label": label,
        "classification": classification,
        "capture_medium": capture_medium,
        "ready_for_certification": bool(ready),
        "failure_reasons": failures,
        "capture_image_count": len(image_paths),
        "reference_image_count": len(reference_image_paths),
        "raw_image_count": len(raw_image_paths),
        "capture_images": _absolute_digest_records(image_paths),
        "reference_images": _absolute_digest_records(reference_image_paths),
        "raw_images": _absolute_digest_records(raw_image_paths),
        "manifest_file": str(manifest_path),
        "manifest_sha256": _sha256_file(manifest_path),
        "payload_file": str(payload_path),
        "payload_sha256": _sha256_file(payload_path),
        "profile_compliance": profile_compliance,
        "reference_transform": reference_transform,
        "attachment_report_evidence": attachment_evidence,
        "physical_print_scan_evidence": print_scan_evidence,
        "perspective_correction_evidence": perspective_evidence,
        "capture_provenance_evidence": provenance_evidence,
        "ocr_only_evidence": ocr_only_evidence,
    }


def validate_capture_corpus(
    capture_corpus_file: str,
    output_file: Optional[str] = None,
    profile: str = RELIABLE_AIRGAP_PROFILE,
    backend: str = "sidecar",
    allow_ocr_fallback: bool = False,
    profile_redundancy_threshold_bytes: int = RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES,
    require_captures: bool = False,
    require_distinct_capture_images: bool = False,
    require_raw_captures: bool = False,
    capture_attachment_report_file: Optional[str] = None,
    require_capture_attachment_report: bool = False,
    require_capture_provenance: bool = False,
    capture_required_classification: Optional[str] = None,
    require_physical_print_scan: bool = False,
    require_real_camera_perspective_correction: bool = False,
    require_ocr_only_backend: bool = False,
) -> Dict[str, object]:
    """Preflight an operator capture corpus before running recovery certification."""

    backend_value = str(backend or "").strip().lower()
    if backend_value not in SUPPORTED_CERTIFICATION_BACKENDS:
        raise ValueError(
            "unsupported transport certification backend: {}".format(backend)
        )
    if bool(require_ocr_only_backend) and backend_value not in OCR_ONLY_CERTIFICATION_BACKENDS:
        raise ValueError(
            "require_ocr_only_backend requires backend one of: {}".format(
                ", ".join(OCR_ONLY_CERTIFICATION_BACKENDS)
            )
        )
    profile_value = _resolve_profile_name(profile=profile, backend=backend_value)
    capture_corpus = _normalize_capture_corpus_cases(
        capture_corpus_file,
        allow_empty_capture_images=True,
    )
    if capture_corpus is None:
        raise ValueError("capture_corpus_file is required")
    required_classification = str(capture_required_classification or "").strip().lower()
    if required_classification and required_classification not in SUPPORTED_CORPUS_CLASSIFICATIONS:
        raise ValueError(
            "capture_required_classification must be one of: {}".format(
                ", ".join(SUPPORTED_CORPUS_CLASSIFICATIONS)
            )
        )

    attachment_report = _resolve_capture_attachment_report(
        capture_corpus=capture_corpus,
        capture_attachment_report_file=capture_attachment_report_file,
        require_capture_attachment_report=False,
    )

    validation_cases = [
        _capture_validation_case(
            raw_case=case,
            profile=profile_value,
            backend=backend_value,
            allow_ocr_fallback=bool(allow_ocr_fallback),
            profile_redundancy_threshold_bytes=int(profile_redundancy_threshold_bytes),
            require_captures=bool(require_captures),
            require_distinct_capture_images=bool(require_distinct_capture_images),
            require_raw_captures=bool(require_raw_captures),
            require_capture_attachment_report=bool(require_capture_attachment_report),
            require_physical_print_scan=bool(require_physical_print_scan),
            require_real_camera_perspective_correction=bool(
                require_real_camera_perspective_correction
            ),
            require_ocr_only_backend=bool(require_ocr_only_backend),
            require_capture_provenance=bool(require_capture_provenance),
            attachment_report=attachment_report,
        )
        for case in capture_corpus.get("cases", []) or []
    ]
    classification_counts = Counter(
        str(case.get("classification") or "unknown") for case in validation_cases
    )
    capture_medium_counts = Counter(
        str(case.get("capture_medium") or "unspecified") for case in validation_cases
    )
    failures = Counter()
    for case in validation_cases:
        for reason in case.get("failure_reasons", []) or []:
            failures[str(reason)] += 1
    case_count = len(validation_cases)
    ready_case_count = sum(1 for case in validation_cases if case.get("ready_for_certification"))
    attached_case_count = sum(1 for case in validation_cases if int(case.get("capture_image_count") or 0) > 0)
    raw_attached_case_count = sum(1 for case in validation_cases if int(case.get("raw_image_count") or 0) > 0)
    ocr_only_ready_case_count = sum(
        1
        for case in validation_cases
        if bool(case.get("ocr_only_evidence", {}).get("evidence_passed"))
    )
    distinct_case_count = sum(
        1
        for case in validation_cases
        if bool(case.get("reference_transform", {}).get("distinct_from_reference"))
    )
    required_classification_present = (
        not required_classification
        or int(classification_counts.get(required_classification, 0)) > 0
    )
    if not required_classification_present:
        failures["capture_required_classification_missing"] += 1

    success = bool(ready_case_count == case_count and required_classification_present)
    report = {
        "schema": CAPTURE_VALIDATION_REPORT_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": bool(success),
        "capture_corpus_schema": CAPTURE_CORPUS_SCHEMA,
        "capture_corpus_file": str(capture_corpus.get("path")),
        "capture_corpus_sha256": _sha256_file(Path(str(capture_corpus.get("path")))),
        "profile": profile_value,
        "backend": backend_value,
        "parameters": {
            "allow_ocr_fallback": bool(allow_ocr_fallback),
            "profile_redundancy_threshold_bytes": int(profile_redundancy_threshold_bytes),
            "require_captures": bool(require_captures),
            "require_distinct_capture_images": bool(require_distinct_capture_images),
            "require_raw_captures": bool(require_raw_captures),
            "capture_attachment_report_file": (
                str(attachment_report.get("path")) if isinstance(attachment_report, dict) else None
            ),
            "require_capture_attachment_report": bool(require_capture_attachment_report),
            "require_capture_provenance": bool(require_capture_provenance),
            "capture_required_classification": required_classification or None,
            "require_physical_print_scan": bool(require_physical_print_scan),
            "require_real_camera_perspective_correction": bool(
                require_real_camera_perspective_correction
            ),
            "require_ocr_only_backend": bool(require_ocr_only_backend),
        },
        "capture_corpus": {
            "classification": capture_corpus.get("classification"),
            "capture_medium": capture_corpus.get("capture_medium"),
            "metadata": capture_corpus.get("metadata", {}),
            "case_count": case_count,
        },
        "summary": {
            "case_count": case_count,
            "ready_case_count": ready_case_count,
            "blocked_case_count": case_count - ready_case_count,
            "cases_with_attached_captures": attached_case_count,
            "cases_missing_attached_captures": case_count - attached_case_count,
            "cases_with_raw_captures": raw_attached_case_count,
            "cases_missing_raw_captures": case_count - raw_attached_case_count,
            "distinct_capture_case_count": distinct_case_count,
            "ocr_only_ready_case_count": ocr_only_ready_case_count,
            "classification_counts": dict(classification_counts),
            "capture_medium_counts": dict(capture_medium_counts),
            "required_classification_present": bool(required_classification_present),
            "failures_by_reason": dict(failures),
        },
        "certification_boundary": (
            "This report is a preflight validation of corpus files and required gates only. "
            "It does not run transport recovery and does not certify real camera/photo, "
            "physical print-scan, perspective correction, OCR-only reliability, or production "
            "airgap readiness."
        ),
        "cases": validation_cases,
    }
    if output_file is not None and str(output_file).strip():
        _write_json(Path(str(output_file)), report)
    return report


def _ocr_only_evidence(
    required: bool,
    backend_requested: str,
    export_result: Optional[Dict[str, object]],
    recover_result: Optional[Dict[str, object]],
    manifest: Dict[str, object],
) -> Dict[str, object]:
    backend = str(backend_requested or "").strip().lower()
    recovery_ocr = recover_result.get("ocr") if isinstance(recover_result, dict) else {}
    if not isinstance(recovery_ocr, dict):
        recovery_ocr = {}
    backend_selected = (
        str(recover_result.get("backend_selected") or "").strip().lower()
        if isinstance(recover_result, dict)
        else ""
    )
    ocr_backend = str(recovery_ocr.get("backend") or "").strip().lower()
    binary_sidecar_present = _manifest_has_binary_sidecar(manifest) if isinstance(manifest, dict) else False
    export_sidecar_enabled = (
        export_result.get("sidecar_enabled")
        if isinstance(export_result, dict)
        else None
    )
    export_sidecar_disabled = export_sidecar_enabled is False or not binary_sidecar_present
    recovery_success = bool(recover_result.get("success")) if isinstance(recover_result, dict) else False
    checks = [
        _profile_check(
            "explicit_ocr_only_gate",
            bool(required),
            "OCR-only certification must be requested explicitly",
            bool(required),
        ),
        _profile_check(
            "backend_is_ocr_only",
            backend in OCR_ONLY_CERTIFICATION_BACKENDS,
            "backend must be one of {}".format(", ".join(OCR_ONLY_CERTIFICATION_BACKENDS)),
            backend or None,
        ),
        _profile_check(
            "backend_selected_matches_requested",
            backend_selected == backend,
            "recovery must select the requested OCR backend",
            backend_selected or None,
        ),
        _profile_check(
            "ocr_backend_matches_requested",
            ocr_backend == backend,
            "OCR extraction must run the requested OCR backend",
            ocr_backend or None,
        ),
        _profile_check(
            "binary_sidecar_absent",
            not binary_sidecar_present,
            "generated/captured pages must not include binary sidecar boxes",
            binary_sidecar_present,
        ),
        _profile_check(
            "export_sidecar_disabled",
            export_sidecar_disabled,
            "export metadata must show sidecar rendering disabled",
            export_sidecar_enabled,
        ),
        _profile_check(
            "recovery_succeeded",
            recovery_success,
            "OCR-only backend recovery must succeed",
            recovery_success,
        ),
    ]
    evidence_passed = all(bool(check.get("passed")) for check in checks)
    if evidence_passed:
        status = "ocr-only-backend-certified"
    elif not required:
        status = "not-required"
    else:
        failed = [str(check.get("name")) for check in checks if not check.get("passed")]
        status = "missing-{}".format(failed[0] if failed else "evidence")
    return {
        "required": bool(required),
        "backend": backend or None,
        "supported_backends": list(OCR_ONLY_CERTIFICATION_BACKENDS),
        "backend_selected": backend_selected or None,
        "ocr_backend": ocr_backend or None,
        "binary_sidecar_present": bool(binary_sidecar_present),
        "export_sidecar_enabled": export_sidecar_enabled,
        "structured_layout_used": bool(recovery_ocr.get("structured_layout_used")),
        "recovery_succeeded": recovery_success,
        "checks": checks,
        "evidence_passed": evidence_passed,
        "strict_gate_passed": bool((not required) or evidence_passed),
        "status": status,
        "certification_boundary": (
            "This proves only the named OCR backend under the measured corpus and page "
            "conditions. It is not generic OCR fallback certification and is not a "
            "reliable-airgap-v1 production proof."
        ),
    }


def _failure_reason(
    export_result: Optional[Dict[str, object]],
    recover_result: Optional[Dict[str, object]],
    restored_path: Path,
    payload_sha256: str,
    capture_corpus: Optional[Dict[str, object]] = None,
) -> str:
    if not export_result or not export_result.get("success"):
        return "export_failed"
    if int(export_result.get("image_count", 0) or 0) <= 0:
        return "no_generated_images"
    if isinstance(capture_corpus, dict):
        profile_compliance = capture_corpus.get("profile_compliance")
        if isinstance(profile_compliance, dict) and not profile_compliance.get("passed"):
            return "capture_profile_not_certified"
        reference_transform = capture_corpus.get("reference_transform")
        if isinstance(reference_transform, dict) and not reference_transform.get("strict_gate_passed", True):
            return "capture_reference_not_distinct"
        perspective_evidence = capture_corpus.get("perspective_correction_evidence")
        if isinstance(perspective_evidence, dict) and not perspective_evidence.get("strict_gate_passed", True):
            return "capture_perspective_evidence_missing"
        print_scan_evidence = capture_corpus.get("physical_print_scan_evidence")
        if isinstance(print_scan_evidence, dict) and not print_scan_evidence.get("strict_gate_passed", True):
            return "capture_print_scan_evidence_missing"
        provenance_evidence = capture_corpus.get("capture_provenance_evidence")
        if isinstance(provenance_evidence, dict) and not provenance_evidence.get("strict_gate_passed", True):
            return "capture_provenance_missing"
        attachment_evidence = capture_corpus.get("attachment_report_evidence")
        if isinstance(attachment_evidence, dict) and not attachment_evidence.get("strict_gate_passed", True):
            return "capture_attachment_report_mismatch"
    if not recover_result or not recover_result.get("success"):
        return "recover_failed"
    if not restored_path.exists():
        return "output_missing"
    restored_sha256 = _sha256_file(restored_path)
    if restored_sha256 != payload_sha256:
        return "payload_sha256_mismatch"
    return "none"


def _case_artifact_digests(
    payload_path: Path,
    manifest_path: Optional[Path],
    restored_path: Path,
    image_paths: List[Path],
    distorted_image_paths: Optional[List[Path]] = None,
    source_image_paths: Optional[List[Path]] = None,
) -> Dict[str, object]:
    return {
        "payload_sha256": _sha256_file(payload_path),
        "manifest_sha256": _sha256_file(manifest_path) if manifest_path else None,
        "restored_sha256": _sha256_file(restored_path),
        "images": _image_digests(image_paths),
        "distorted_images": _image_digests(distorted_image_paths or []),
        "source_images": _image_digests(source_image_paths or []),
    }


def _extract_recovery_metrics(recover_result: Optional[Dict[str, object]]) -> Dict[str, object]:
    if not isinstance(recover_result, dict):
        return {
            "missing_chunks_count": None,
            "line_error_count": None,
            "line_warning_count": None,
            "page_crc_error_count": None,
            "duplicate_conflict_count": None,
            "correction_required_count": None,
        }
    analyze = recover_result.get("analyze")
    if not isinstance(analyze, dict):
        analyze = {}
    return {
        "missing_chunks_count": analyze.get("missing_chunks_count"),
        "line_error_count": analyze.get("line_error_count"),
        "line_warning_count": analyze.get("line_warning_count"),
        "page_crc_error_count": analyze.get("page_crc_error_count"),
        "duplicate_conflict_count": analyze.get("duplicate_conflict_count"),
        "correction_required_count": analyze.get("correction_required_count"),
        "parity_recovered_count": analyze.get("parity_recovered_count"),
        "package_hash_resolved_count": analyze.get("package_hash_resolved_count"),
    }


def _build_case_record(
    case_id: str,
    case_dir: Path,
    payload_path: Path,
    restored_path: Path,
    payload_size: int,
    payload_sha256: str,
    backend_requested: str,
    export_result: Optional[Dict[str, object]],
    recover_result: Optional[Dict[str, object]],
    elapsed_ms: float,
    exception: Optional[Exception],
    distortion: Optional[Dict[str, object]] = None,
    distorted_image_paths: Optional[List[Path]] = None,
    source_image_paths: Optional[List[Path]] = None,
    capture_corpus: Optional[Dict[str, object]] = None,
    require_ocr_only_backend: bool = False,
) -> Dict[str, object]:
    manifest_path = None
    manifest = {}
    images = []
    if export_result:
        if export_result.get("manifest_path"):
            manifest_path = Path(str(export_result.get("manifest_path")))
            if manifest_path.exists():
                manifest = _load_json(manifest_path)
        for image_path in export_result.get("images", []) or []:
            images.append(Path(str(image_path)))

    profile_not_certified = (
        isinstance(capture_corpus, dict)
        and isinstance(capture_corpus.get("profile_compliance"), dict)
        and not capture_corpus.get("profile_compliance", {}).get("passed")
    )
    capture_reference_not_distinct = (
        isinstance(capture_corpus, dict)
        and isinstance(capture_corpus.get("reference_transform"), dict)
        and not capture_corpus.get("reference_transform", {}).get("strict_gate_passed", True)
    )
    capture_perspective_missing = (
        isinstance(capture_corpus, dict)
        and isinstance(capture_corpus.get("perspective_correction_evidence"), dict)
        and not capture_corpus.get("perspective_correction_evidence", {}).get("strict_gate_passed", True)
    )
    capture_print_scan_missing = (
        isinstance(capture_corpus, dict)
        and isinstance(capture_corpus.get("physical_print_scan_evidence"), dict)
        and not capture_corpus.get("physical_print_scan_evidence", {}).get("strict_gate_passed", True)
    )
    capture_provenance_missing = (
        isinstance(capture_corpus, dict)
        and isinstance(capture_corpus.get("capture_provenance_evidence"), dict)
        and not capture_corpus.get("capture_provenance_evidence", {}).get("strict_gate_passed", True)
    )
    capture_attachment_mismatch = (
        isinstance(capture_corpus, dict)
        and isinstance(capture_corpus.get("attachment_report_evidence"), dict)
        and not capture_corpus.get("attachment_report_evidence", {}).get("strict_gate_passed", True)
    )
    base_failure = (
        "exception"
        if exception is not None
        else _failure_reason(
            export_result=export_result,
            recover_result=recover_result,
            restored_path=restored_path,
            payload_sha256=payload_sha256,
            capture_corpus=capture_corpus,
        )
    )
    ocr_only_record = _ocr_only_evidence(
        required=bool(require_ocr_only_backend),
        backend_requested=backend_requested,
        export_result=export_result,
        recover_result=recover_result,
        manifest=manifest,
    )
    ocr_only_missing = (
        bool(require_ocr_only_backend)
        and base_failure == "none"
        and not bool(ocr_only_record.get("strict_gate_passed"))
    )
    failure = (
        "capture_profile_not_certified"
        if profile_not_certified
        else "capture_reference_not_distinct"
        if capture_reference_not_distinct
        else "capture_perspective_evidence_missing"
        if capture_perspective_missing
        else "capture_print_scan_evidence_missing"
        if capture_print_scan_missing
        else "capture_provenance_missing"
        if capture_provenance_missing
        else "capture_attachment_report_mismatch"
        if capture_attachment_mismatch
        else "ocr_only_evidence_missing"
        if ocr_only_missing
        else base_failure
    )
    success = failure == "none"
    restored_sha256 = _sha256_file(restored_path)
    recovery_metrics = _extract_recovery_metrics(recover_result)
    parity = manifest.get("parity", {}) if isinstance(manifest, dict) else {}
    if not isinstance(parity, dict):
        parity = {}
    distortion_record = distortion or {
        "suite": NO_DISTORTION_SUITE,
        "name": "control",
        "kind": "control",
        "parameters": {},
        "description": "unmodified generated PNG pages",
        "input_image_count": len(images),
        "output_image_count": len(distorted_image_paths or images),
    }
    distortion_record = dict(distortion_record)
    distortion_record.setdefault("input_image_count", len(images))
    distortion_record.setdefault("output_image_count", len(distorted_image_paths or images))
    capture_corpus_record = dict(capture_corpus or {})

    record = {
        "case_id": case_id,
        "case_dir": str(case_dir),
        "success": success,
        "failure_reason": failure,
        "exception": str(exception) if exception is not None else None,
        "distortion": distortion_record,
        "payload_size": int(payload_size),
        "payload_sha256": payload_sha256,
        "restored_sha256": restored_sha256,
        "backend_requested": backend_requested,
        "backend_selected": (
            recover_result.get("backend_selected")
            if isinstance(recover_result, dict)
            else None
        ),
        "elapsed_ms": int(round(elapsed_ms)),
        "export": {
            "success": bool(export_result.get("success")) if isinstance(export_result, dict) else False,
            "artifact_id": export_result.get("artifact_id") if isinstance(export_result, dict) else None,
            "package_dir": export_result.get("output_dir") if isinstance(export_result, dict) else None,
            "manifest_path": str(manifest_path) if manifest_path else None,
            "payload_path": export_result.get("payload_path") if isinstance(export_result, dict) else None,
            "page_text_count": export_result.get("page_text_count") if isinstance(export_result, dict) else None,
            "image_count": export_result.get("image_count") if isinstance(export_result, dict) else None,
            "total_chunks": export_result.get("total_chunks") if isinstance(export_result, dict) else None,
            "total_lines": manifest.get("total_lines") if isinstance(manifest, dict) else None,
            "total_pages": export_result.get("total_pages") if isinstance(export_result, dict) else None,
            "compressed_size": export_result.get("compressed_size") if isinstance(export_result, dict) else None,
            "raw_size": export_result.get("raw_size") if isinstance(export_result, dict) else None,
            "sidecar_enabled": export_result.get("sidecar_enabled") if isinstance(export_result, dict) else None,
            "line_crc_mode": export_result.get("line_crc_mode") if isinstance(export_result, dict) else None,
            "line_index_mode": export_result.get("line_index_mode") if isinstance(export_result, dict) else None,
            "metadata_level": export_result.get("metadata_level") if isinstance(export_result, dict) else None,
            "payload_alphabet_profile": (
                export_result.get("payload_alphabet_profile")
                if isinstance(export_result, dict)
                else None
            ),
            "alphabet": export_result.get("alphabet") if isinstance(export_result, dict) else None,
            "redundancy_copies": export_result.get("redundancy_copies") if isinstance(export_result, dict) else None,
            "interleave_enabled": export_result.get("interleave_enabled") if isinstance(export_result, dict) else None,
            "parity_enabled": export_result.get("parity_enabled") if isinstance(export_result, dict) else None,
            "parity_group_count": export_result.get("parity_group_count") if isinstance(export_result, dict) else None,
            "parity_group_size": parity.get("group_size"),
            "image_paths": [str(path) for path in images],
            "distorted_image_paths": [str(path) for path in (distorted_image_paths or [])],
            "source_image_paths": [str(path) for path in (source_image_paths or [])],
        },
        "recovery": {
            "success": bool(recover_result.get("success")) if isinstance(recover_result, dict) else False,
            "output_file": str(restored_path),
            "backend_selected": (
                recover_result.get("backend_selected")
                if isinstance(recover_result, dict)
                else None
            ),
            "raw_sha256": recover_result.get("raw_sha256") if isinstance(recover_result, dict) else None,
            "ocr_text_output": (
                recover_result.get("ocr", {}).get("ocr_text_output")
                if isinstance(recover_result, dict) and isinstance(recover_result.get("ocr"), dict)
                else None
            ),
            "analysis_report_path": (
                recover_result.get("analyze", {}).get("report_path")
                if isinstance(recover_result, dict) and isinstance(recover_result.get("analyze"), dict)
                else None
            ),
            "missing_file_path": (
                recover_result.get("analyze", {}).get("missing_file_path")
                if isinstance(recover_result, dict) and isinstance(recover_result.get("analyze"), dict)
                else None
            ),
            "metrics": recovery_metrics,
        },
        "artifact_digests": _case_artifact_digests(
            payload_path=payload_path,
            manifest_path=manifest_path,
            restored_path=restored_path,
            image_paths=images,
            distorted_image_paths=distorted_image_paths,
            source_image_paths=source_image_paths,
        ),
    }
    if require_ocr_only_backend or backend_requested in OCR_ONLY_CERTIFICATION_BACKENDS:
        record["ocr_only_evidence"] = ocr_only_record
    if capture_corpus_record:
        record["capture_corpus"] = capture_corpus_record
    return record


def _build_capture_export_result(
    manifest_path: Path,
    payload_path: Path,
    image_paths: List[Path],
) -> Dict[str, object]:
    manifest = _load_json(manifest_path)
    if not isinstance(manifest, dict):
        raise ValueError("capture manifest is not a JSON object: {}".format(manifest_path))
    parity = manifest.get("parity", {})
    if not isinstance(parity, dict):
        parity = {}
    return {
        "success": True,
        "artifact_id": manifest.get("artifact_id"),
        "output_dir": str(manifest_path.parent),
        "manifest_path": str(manifest_path),
        "payload_path": str(payload_path),
        "page_text_count": None,
        "image_count": len(image_paths),
        "total_chunks": manifest.get("total_chunks"),
        "total_pages": manifest.get("total_pages"),
        "compressed_size": manifest.get("compressed_size"),
        "raw_size": manifest.get("raw_size"),
        "sidecar_enabled": _capture_sidecar_present(manifest),
        "line_crc_mode": manifest.get("line_crc_mode"),
        "line_index_mode": manifest.get("line_index_mode"),
        "metadata_level": manifest.get("metadata_level"),
        "payload_alphabet_profile": manifest.get("payload_alphabet_profile"),
        "alphabet": manifest.get("alphabet"),
        "redundancy_copies": manifest.get("redundancy_copies"),
        "interleave_enabled": manifest.get("interleave_enabled"),
        "parity_enabled": bool(parity.get("enabled")) if parity else None,
        "parity_group_count": parity.get("group_count"),
        "images": [str(path) for path in image_paths],
    }


def _run_capture_corpus_cases(
    transport,
    capture_corpus: Dict[str, object],
    cases_dir: Path,
    profile: str,
    backend: str,
    lang: str,
    psm: int,
    ocr_provider_cmd: Optional[str],
    ocr_provider_timeout_sec: int,
    strict_payload_chars: bool,
    max_list: int,
    profile_redundancy_threshold_bytes: int,
    allow_ocr_fallback: bool,
    require_distinct_capture_images: bool,
    require_real_camera_perspective_correction: bool,
    require_physical_print_scan: bool,
    require_capture_provenance: bool,
    capture_attachment_report: Optional[Dict[str, object]],
    require_capture_attachment_report: bool,
    require_ocr_only_backend: bool,
) -> List[Dict[str, object]]:
    records = []
    raw_cases = capture_corpus.get("cases")
    if not isinstance(raw_cases, list):
        return records

    for index, capture_case in enumerate(raw_cases, 1):
        if not isinstance(capture_case, dict):
            continue
        label = _normalize_label(capture_case.get("label"), "capture_{:04d}".format(index))
        case_id = "capture_{:04d}_{}".format(index, "".join(ch if ch.isalnum() else "_" for ch in label)[:48])
        case_dir = cases_dir / case_id
        captures_dir = case_dir / "captures"
        restored_path = case_dir / "restored.bin"
        ocr_text_output = case_dir / "ocr_text.txt"
        analyze_report = case_dir / "analyze_report.json"
        missing_file = case_dir / "missing_chunks.csv"
        case_dir.mkdir(parents=True, exist_ok=True)

        manifest_path = Path(str(capture_case.get("manifest_path")))
        payload_path = Path(str(capture_case.get("payload_path")))
        source_image_paths = [Path(str(path)) for path in capture_case.get("image_paths", []) or []]
        reference_image_paths = [
            Path(str(path)) for path in capture_case.get("reference_image_paths", []) or []
        ]
        raw_image_paths = [Path(str(path)) for path in capture_case.get("raw_image_paths", []) or []]
        payload_sha256 = _sha256_file(payload_path) or ""
        copied_image_paths = []
        recover_result = None
        exception = None
        start = time.perf_counter()
        try:
            copied_image_paths = _copy_image_set(source_image_paths, captures_dir)
            export_result = _build_capture_export_result(
                manifest_path=manifest_path,
                payload_path=payload_path,
                image_paths=copied_image_paths,
            )
            recover_result = transport.recover_from_images(
                manifest_path=str(manifest_path),
                image_input_path=str(captures_dir),
                output_file=str(restored_path),
                backend=backend,
                lang=lang,
                psm=psm,
                ocr_provider_cmd=ocr_provider_cmd,
                ocr_provider_timeout_sec=ocr_provider_timeout_sec,
                strict_payload_chars=strict_payload_chars,
                ocr_text_output=str(ocr_text_output),
                save_analyze_report=str(analyze_report),
                emit_missing_file=str(missing_file),
                max_list=max_list,
            )
        except Exception as exc:
            exception = exc
            export_result = (
                _build_capture_export_result(
                    manifest_path=manifest_path,
                    payload_path=payload_path,
                    image_paths=copied_image_paths,
                )
                if manifest_path.exists() and payload_path.exists()
                else None
            )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        classification = str(capture_case.get("classification") or capture_corpus.get("classification") or "")
        capture_medium = _normalize_capture_medium(
            capture_case.get("capture_medium", capture_corpus.get("capture_medium"))
        )
        capture_metadata = capture_case.get("capture_metadata") or {}
        capture_profile = (
            _capture_profile_compliance(
                profile=profile,
                backend=backend,
                manifest_path=manifest_path,
                payload_path=payload_path,
                manifest=_load_json(manifest_path) if manifest_path.exists() else {},
                classification=classification,
                redundancy_threshold_bytes=profile_redundancy_threshold_bytes,
                allow_ocr_fallback=allow_ocr_fallback,
            )
            if manifest_path.exists()
            else {
                "profile": profile,
                "classification": classification,
                "passed": False,
                "checks": [
                    _profile_check(
                        "capture_manifest_required",
                        False,
                        "operator capture case must bind an existing manifest",
                        str(manifest_path),
                    )
                ],
            }
        )
        reference_transform = _capture_reference_transform(
            reference_image_paths=reference_image_paths,
            capture_image_paths=copied_image_paths,
            require_distinct_capture_images=require_distinct_capture_images,
            missing_capture_passes_when_not_required=not bool(require_distinct_capture_images),
        )
        capture_record = {
            "schema": CAPTURE_CORPUS_SCHEMA,
            "corpus_file": str(capture_corpus.get("path")),
            "label": label,
            "classification": classification,
            "capture_medium": capture_medium,
            "capture_metadata": capture_metadata,
            "description": capture_case.get("description"),
            "profile_compliance": capture_profile,
            "source_images": _image_digests(source_image_paths),
            "reference_images": _image_digests(reference_image_paths),
            "raw_images": _image_digests(raw_image_paths),
            "attached_images": _image_digests(copied_image_paths),
            "source_image_count": len(source_image_paths),
            "reference_image_count": len(reference_image_paths),
            "raw_image_count": len(raw_image_paths),
            "reference_transform": reference_transform,
            "perspective_correction_evidence": _capture_perspective_correction_evidence(
                classification=classification,
                raw_image_paths=raw_image_paths,
                corrected_image_paths=copied_image_paths,
                reference_image_paths=reference_image_paths,
                perspective_correction=(
                    capture_case.get("perspective_correction")
                    if isinstance(capture_case.get("perspective_correction"), dict)
                    else {}
                ),
                required=bool(require_real_camera_perspective_correction),
            ),
            "physical_print_scan_evidence": _capture_physical_print_scan_evidence(
                classification=classification,
                capture_medium=capture_medium,
                capture_image_paths=copied_image_paths,
                reference_image_paths=reference_image_paths,
                capture_metadata=capture_metadata,
                reference_transform=reference_transform,
                required=bool(require_physical_print_scan),
            ),
            "capture_provenance_evidence": _capture_provenance_evidence(
                classification=classification,
                capture_medium=capture_medium,
                capture_metadata=capture_metadata,
                required=bool(require_capture_provenance),
            ),
            "attachment_report_evidence": _capture_attachment_report_evidence(
                label=label,
                classification=classification,
                capture_medium=capture_medium,
                capture_image_paths=source_image_paths,
                raw_image_paths=raw_image_paths,
                reference_image_paths=reference_image_paths,
                attachment_report=capture_attachment_report,
                required=bool(require_capture_attachment_report),
            ),
        }
        distortion_record = {
            "suite": OPERATOR_CAPTURE_CORPUS_SUITE,
            "name": label,
            "kind": "operator_capture",
            "parameters": {
                "classification": classification,
                "corpus_file": str(capture_corpus.get("path")),
            },
            "description": capture_case.get("description") or "operator-supplied capture corpus",
            "input_image_count": len(source_image_paths),
            "output_image_count": len(copied_image_paths),
            "input_images": _image_digests(source_image_paths),
            "output_images": _image_digests(copied_image_paths),
            "output_dir": str(captures_dir),
        }
        records.append(
            _build_case_record(
                case_id=case_id,
                case_dir=case_dir,
                payload_path=payload_path,
                restored_path=restored_path,
                payload_size=payload_path.stat().st_size if payload_path.exists() else 0,
                payload_sha256=payload_sha256,
                backend_requested=backend,
                export_result=export_result,
                recover_result=recover_result,
                elapsed_ms=elapsed_ms,
                exception=exception,
                distortion=distortion_record,
                distorted_image_paths=copied_image_paths,
                source_image_paths=source_image_paths,
                capture_corpus=capture_record,
                require_ocr_only_backend=require_ocr_only_backend,
            )
        )
    return records


def prepare_capture_corpus_kit(
    transport,
    output_dir: str,
    classification: str = "lab",
    capture_medium: str = "unspecified",
    include_raw_capture_dirs: bool = False,
    perspective_correction_method: Optional[str] = None,
    payload_sizes: Optional[Iterable[int]] = None,
    iterations_per_size: int = 1,
    seed: int = 1729,
    redundancy_copies: int = 2,
    interleave: bool = True,
    parity_group_size: int = 4,
    filename_prefix: str = "capture",
    corpus_file: Optional[str] = None,
    kit_manifest_file: Optional[str] = None,
    profile: str = RELIABLE_AIRGAP_PROFILE,
    profile_redundancy_threshold_bytes: int = RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES,
    capture_metadata: Optional[Dict[str, object]] = None,
    case_label_prefix: str = "capture-case",
    ocr_only_backend: Optional[str] = None,
) -> Dict[str, object]:
    """Stage a replayable physical/lab capture kit and ready-to-run corpus manifest."""

    classification_value = str(classification or "").strip().lower()
    if classification_value not in SUPPORTED_CORPUS_CLASSIFICATIONS:
        raise ValueError(
            "capture kit classification must be one of: {}".format(
                ", ".join(SUPPORTED_CORPUS_CLASSIFICATIONS)
            )
        )
    capture_medium_value = _normalize_capture_medium(capture_medium)

    ocr_backend_value = str(ocr_only_backend or "").strip().lower()
    if ocr_backend_value and ocr_backend_value not in OCR_ONLY_CERTIFICATION_BACKENDS:
        raise ValueError(
            "ocr_only_backend must be one of: {}".format(
                ", ".join(OCR_ONLY_CERTIFICATION_BACKENDS)
            )
        )
    requested_profile = str(profile or "").strip().lower()
    if requested_profile == OCR_ONLY_KIT_PROFILE and not ocr_backend_value:
        raise ValueError("ocr-only-backend-v1 capture kits require ocr_only_backend")
    if ocr_backend_value:
        profile_value = OCR_ONLY_KIT_PROFILE
    else:
        profile_value = _resolve_profile_name(
            profile=profile,
            backend=ocr_backend_value or "sidecar",
        )
    sizes = _normalize_payload_sizes(payload_sizes)
    iterations = int(iterations_per_size)
    if iterations <= 0:
        raise ValueError("iterations_per_size must be positive")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payloads_dir = out_dir / "payloads"
    exports_dir = out_dir / "exports"
    captures_dir = out_dir / "captures"
    instructions_dir = out_dir / "instructions"
    for path in (payloads_dir, exports_dir, captures_dir, instructions_dir):
        path.mkdir(parents=True, exist_ok=True)

    capture_metadata_normalized = _normalize_capture_corpus_metadata(capture_metadata or {})
    perspective_method = str(perspective_correction_method or "").strip()
    cases = []
    case_index = 0
    for payload_size in sizes:
        for iteration in range(iterations):
            case_index += 1
            label = "{}-{:04d}-size-{}-iter-{:02d}".format(
                _label_slug(case_label_prefix, "capture_case"),
                case_index,
                int(payload_size),
                iteration + 1,
            )
            payload_bytes = _deterministic_payload(
                size=int(payload_size),
                seed=int(seed),
                case_index=case_index,
            )
            payload_path = payloads_dir / "{}.bin".format(label)
            payload_path.write_bytes(payload_bytes)

            export_dir = exports_dir / label
            original_render_sidecar = getattr(transport, "render_sidecar", None)
            if ocr_backend_value:
                transport.render_sidecar = False
            try:
                export_result = transport.export_artifact(
                    input_file=str(payload_path),
                    output_dir=str(export_dir),
                    filename_prefix=filename_prefix,
                    redundancy_copies=int(redundancy_copies),
                    interleave=bool(interleave),
                    parity_group_size=int(parity_group_size),
                )
            finally:
                if ocr_backend_value and original_render_sidecar is not None:
                    transport.render_sidecar = bool(original_render_sidecar)
            manifest_path = Path(str(export_result.get("manifest_path")))
            source_image_paths = [Path(str(path)) for path in export_result.get("images", []) or []]
            capture_drop_dir = captures_dir / label
            capture_drop_dir.mkdir(parents=True, exist_ok=True)
            raw_capture_drop_dir: Optional[Path] = None
            if bool(include_raw_capture_dirs):
                raw_capture_drop_dir = captures_dir / "{}__raw".format(label)
                raw_capture_drop_dir.mkdir(parents=True, exist_ok=True)
            readme_path = capture_drop_dir / "README.txt"
            readme_lines = [
                "Capture drop directory for {}.".format(label),
                "",
                "Print or display the generated pages from:",
                _safe_relative_path((export_dir / "pages").resolve(), out_dir.resolve()),
                "",
                "Place the images used for recovery in this directory.",
                "For camera perspective-correction runs, place the corrected/deskewed images here.",
                "Keep filenames stable; supported suffixes: {}.".format(
                    ", ".join(sorted(CAPTURE_IMAGE_SUFFIXES))
                ),
                "",
            ]
            if raw_capture_drop_dir is not None:
                readme_lines.extend(
                    [
                        "Raw camera photos before perspective correction go in:",
                        _safe_relative_path(raw_capture_drop_dir.resolve(), out_dir.resolve()),
                        "",
                    ]
                )
            readme_path.write_text("\n".join(readme_lines), encoding="utf-8")
            if raw_capture_drop_dir is not None:
                raw_readme_path = raw_capture_drop_dir / "README.txt"
                raw_readme_path.write_text(
                    "\n".join(
                        [
                            "Raw camera-photo drop directory for {}.".format(label),
                            "",
                            "Place uncorrected camera photos here before running attach-capture-corpus.",
                            "Place perspective-corrected recovery images in the sibling directory:",
                            _safe_relative_path(capture_drop_dir.resolve(), out_dir.resolve()),
                            "",
                            "Keep filenames stable; supported suffixes: {}.".format(
                                ", ".join(sorted(CAPTURE_IMAGE_SUFFIXES))
                            ),
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )

            profile_backend = ocr_backend_value or "sidecar"
            profile_compliance = _capture_profile_compliance(
                profile=profile_value,
                backend=profile_backend,
                manifest_path=manifest_path,
                payload_path=payload_path,
                manifest=_load_json(manifest_path) if manifest_path.exists() else {},
                classification=classification_value,
                redundancy_threshold_bytes=profile_redundancy_threshold_bytes,
                allow_ocr_fallback=False,
            )
            if not profile_compliance.get("passed"):
                failed = [
                    "{} observed {}".format(check.get("name"), check.get("observed"))
                    for check in profile_compliance.get("checks", [])
                    if not check.get("passed")
                ]
                raise ValueError(
                    "capture kit case {} does not satisfy {}: {}".format(
                        label,
                        profile_value,
                        "; ".join(failed),
                    )
                )

            case_record = {
                "label": label,
                "classification": classification_value,
                "capture_medium": capture_medium_value,
                "manifest_path": _safe_relative_path(manifest_path.resolve(), out_dir.resolve()),
                "payload_path": _safe_relative_path(payload_path.resolve(), out_dir.resolve()),
                "image_path": _safe_relative_path(capture_drop_dir.resolve(), out_dir.resolve()),
                "reference_image_paths": [
                    record["path"]
                    for record in _relative_digest_records(source_image_paths, out_dir)
                ],
                "capture_metadata": dict(capture_metadata_normalized),
                "description": (
                    "operator-filled capture directory for printed/scanned or photographed "
                    "pages generated by prepare-capture-corpus"
                ),
                "kit_source": {
                    "generated_pages_dir": _safe_relative_path(
                        (export_dir / "pages").resolve(),
                        out_dir.resolve(),
                    ),
                    "generated_page_images": _relative_digest_records(
                        source_image_paths,
                        out_dir,
                    ),
                    "manifest_sha256": _sha256_file(manifest_path),
                    "payload_sha256": _sha256_file(payload_path),
                    "payload_size": int(payload_size),
                },
            }
            if ocr_backend_value:
                case_record["ocr_only_backend"] = ocr_backend_value
                case_record["ocr_only_evidence"] = {
                    "schema": CERTIFICATION_CLAIMS_SCHEMA,
                    "backend": ocr_backend_value,
                    "sidecar_free_manifest": True,
                    "required_certification_gate": "--require-ocr-only-backend",
                    "certification_boundary": (
                        "staged sidecar-free OCR-only capture inputs are a measurement "
                        "contract only; certification requires a backend run that writes a "
                        "passing transport_reliability_report.json"
                    ),
                }
            if raw_capture_drop_dir is not None:
                case_record["raw_image_paths"] = _safe_relative_path(
                    raw_capture_drop_dir.resolve(),
                    out_dir.resolve(),
                )
                case_record["perspective_correction"] = {
                    "applied": True,
                    "method": perspective_method or "operator-supplied perspective correction",
                }
            cases.append(case_record)

    corpus_payload = {
        "schema": CAPTURE_CORPUS_SCHEMA,
        "classification": classification_value,
        "capture_medium": capture_medium_value,
        "metadata": {
            "profile": profile_value,
            "prepared_by": "soenc transport prepare-capture-corpus",
            "seed": int(seed),
            "payload_sizes": sizes,
            "iterations_per_size": iterations,
            "capture_medium": capture_medium_value,
            "include_raw_capture_dirs": bool(include_raw_capture_dirs),
            "perspective_correction_method": perspective_method or None,
            "capture_metadata_defaults": dict(capture_metadata_normalized),
            "ocr_only_backend": ocr_backend_value or None,
            "certification_boundary": (
                "generated pages and empty capture directories are a capture contract only; "
                "certification starts after operator photos/scans are placed in captures/*"
            ),
        },
        "cases": [
            {
                key: value
                for key, value in case.items()
                if key in (
                    "label",
                    "classification",
                    "capture_medium",
                    "manifest_path",
                    "payload_path",
                    "image_path",
                    "reference_image_paths",
                    "capture_metadata",
                    "description",
                    "raw_image_paths",
                    "perspective_correction",
                    "ocr_only_backend",
                    "ocr_only_evidence",
                )
            }
            for case in cases
        ],
    }
    corpus_path = _resolve_output_path(corpus_file, out_dir, "capture_corpus.json")
    _write_json(corpus_path, corpus_payload)

    metadata_template_path = instructions_dir / "operator_capture_metadata_manifest_template.json"
    metadata_template_defaults = _capture_metadata_manifest_template_defaults(
        capture_metadata_normalized,
        capture_medium_value,
    )
    metadata_template_cases = []
    for case in cases:
        case_metadata = {
            "label": case["label"],
            "capture_metadata": {},
        }
        if ocr_backend_value:
            case_metadata["ocr_only_backend"] = ocr_backend_value
        metadata_template_cases.append(case_metadata)
    metadata_template_payload = {
        "schema": CAPTURE_METADATA_MANIFEST_SCHEMA,
        "capture_metadata_defaults": metadata_template_defaults,
        "cases": metadata_template_cases,
        "instructions": [
            "Fill capture_session_id, operator, captured_at_utc, and the scanner/camera/printer metadata before ingestion.",
            "Pass this file to ingest-capture-corpus or certify-capture-evidence with --capture-metadata-manifest-file.",
            "This metadata manifest is provenance input only; certification still requires measured recovery, archive replay, and a matching claim gate.",
        ],
        "certification_boundary": (
            "This template binds operator/session/device metadata by case label only after "
            "the operator fills real values and ingestion records its SHA256. It does not "
            "certify any transport medium by itself."
        ),
    }
    _write_json(metadata_template_path, metadata_template_payload)
    metadata_template_sha256 = _sha256_file(metadata_template_path)

    return_manifest_template_path = instructions_dir / "operator_return_manifest_template.json"
    return_manifest_template_payload = {
        "schema": CAPTURE_RETURN_MANIFEST_SCHEMA,
        "capture_corpus_file": _safe_relative_path(corpus_path.resolve(), out_dir.resolve()),
        "capture_corpus_sha256": _sha256_file(corpus_path),
        "capture_kit_manifest_file": "capture_kit_manifest.json",
        "capture_kit_manifest_sha256": "",
        "return_session_id": "",
        "operator": "",
        "returned_at_utc": "",
        "capture_package_layout": {
            "capture_root": "captures/",
            "raw_capture_root": "raw_captures/",
            "metadata_manifest": "operator_capture_metadata_manifest.json",
        },
        "capture_file_inventory": {
            "required": True,
            "description": (
                "List every returned capture image and raw camera image by package path. "
                "Fill SHA256 and size_bytes after the lab/operator ZIP is assembled so extraction "
                "can reject missing, extra, or byte-drifted evidence files."
            ),
        },
        "cases": [
            {
                "label": case["label"],
                "expected_capture_directory": "captures/{}".format(case["label"]),
                "expected_raw_capture_directory": "raw_captures/{}".format(case["label"]),
                "capture_files": [
                    {
                        "path": "captures/{}/<returned-scan-or-corrected-photo>.png".format(
                            case["label"]
                        ),
                        "sha256": "",
                        "size_bytes": "",
                    }
                ],
                "raw_capture_files": [
                    {
                        "path": "raw_captures/{}/<returned-raw-camera-photo>.jpg".format(
                            case["label"]
                        ),
                        "sha256": "",
                        "size_bytes": "",
                    }
                ] if case.get("raw_image_paths") else [],
            }
            for case in cases
        ],
        "instructions": [
            "Rename this file to operator_return_manifest.json before packaging the lab/operator ZIP.",
            "Leave capture_corpus_sha256 unchanged; it binds the returned ZIP to the prepared corpus.",
            "Optionally fill capture_kit_manifest_sha256 after the kit manifest is finalized.",
            "Put returned scans/photos under captures/<case-label>/ and raw camera photos under raw_captures/<case-label>/.",
            "Replace capture_files/raw_capture_files placeholders with every returned image path, SHA256, and byte size; remove raw_capture_files when the run is not a camera/raw-photo run.",
        ],
        "certification_boundary": (
            "This return manifest binds a lab/operator ZIP to a prepared corpus and optional "
            "kit manifest. It is package identity evidence only; certification still requires "
            "ingestion, recovery, archive replay, and a matching claim gate."
        ),
    }
    _write_json(return_manifest_template_path, return_manifest_template_payload)
    return_manifest_template_sha256 = _sha256_file(return_manifest_template_path)

    instructions_path = instructions_dir / "NEXT_STEPS.md"
    attach_command = (
        "python .\\soenc.py transport attach-capture-corpus "
        "--capture-corpus-file {} --kit-manifest-file {} "
        "--require-captures --require-distinct-capture-images"
    ).format(
        _safe_relative_path(corpus_path.resolve(), Path.cwd().resolve()),
        _safe_relative_path(
            _resolve_output_path(kit_manifest_file, out_dir, "capture_kit_manifest.json").resolve(),
            Path.cwd().resolve(),
        ),
    )
    certify_command = (
        "python .\\soenc.py transport certify -o {} "
        "--profile {} --backend {} --capture-corpus-file {} "
        "--capture-corpus-only --capture-required-classification {} "
        "--require-distinct-capture-images --require-capture-attachment-report "
        "--redundancy-copies {} --parity-group-size {}{}"
    ).format(
        _safe_relative_path((out_dir / "transport_capture_cert").resolve(), Path.cwd().resolve()),
        profile_value,
        ocr_backend_value or "sidecar",
        _safe_relative_path(corpus_path.resolve(), Path.cwd().resolve()),
        classification_value,
        int(redundancy_copies),
        int(parity_group_size),
        " --require-ocr-only-backend" if ocr_backend_value else "",
    )
    instructions_path.write_text(
        "\n".join(
            [
                "# Capture Corpus Kit Next Steps",
                "",
                "1. Print or display each generated page set under `exports/*/pages`.",
                "2. Place the corresponding corrected camera photos or scan images into each matching `captures/*` directory.",
                "3. Keep the corpus classification honest: `lab` for controlled scanner/bench runs, `real` for real camera/operator runs.",
                "4. Fill `instructions/operator_capture_metadata_manifest_template.json` with the real capture session, operator, timestamp, and scanner/camera/printer metadata; pass it with `--capture-metadata-manifest-file` during ingestion or the one-command pipeline.",
                "5. If returning a ZIP package, rename `instructions/operator_return_manifest_template.json` to `operator_return_manifest.json` at the package root so extraction can bind the return to this prepared corpus.",
                "6. For physical print-scan evidence, set each corpus case `capture_medium` to `print-scan` and record `printer`, `scanner`, and `dpi` in capture metadata.",
                "7. For real camera perspective-correction evidence, keep raw uncorrected photos in `captures/*__raw`, corrected recovery images in the matching `captures/*` directory, and require the camera gate.",
                "8. For OCR-only evidence, keep this kit sidecar-free and require the named OCR backend during certification.",
                "9. From the repository root, bind the files currently in the capture directories:",
                "",
                "```powershell",
                attach_command,
                "```",
                "",
                "10. Run certification from the repository root. Add `--require-distinct-capture-images` and `--require-capture-attachment-report` when claiming physical/lab capture evidence:",
                "",
                "```powershell",
                certify_command,
                "```",
                "",
                "For physical print-scan claims, also add `--require-physical-print-scan` after replacing generated fixtures with real scan files.",
                "For real camera perspective-correction claims, also add `--require-real-camera-perspective-correction` after replacing generated fixtures with raw camera photos and corrected recovery images.",
                "For OCR-only backend claims, run the command with `--backend {}` and `--require-ocr-only-backend`; this remains backend-specific evidence, not generic OCR fallback or reliable-airgap-v1 production proof.".format(ocr_backend_value)
                if ocr_backend_value
                else "For OCR-only backend claims, prepare a separate sidecar-free kit with `--ocr-only-backend` and run certification with `--require-ocr-only-backend`.",
                "",
                "Do not claim real camera/photo or physical print-scan readiness until that command measures non-empty operator captures, confirms they are not byte-identical to generated reference pages, and passes.",
                "Do not claim OCR-only readiness until the named backend measures sidecar-free pages and `certification_claims.backend-specific-ocr-only.certified=true`.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    kit_manifest_path = _resolve_output_path(
        kit_manifest_file,
        out_dir,
        "capture_kit_manifest.json",
    )
    kit_manifest = {
        "schema": CAPTURE_KIT_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": True,
        "profile": profile_value,
        "classification": classification_value,
        "capture_medium": capture_medium_value,
        "output_dir": str(out_dir),
        "corpus_file": str(corpus_path),
        "instructions_file": str(instructions_path),
        "capture_metadata_manifest_template_file": str(metadata_template_path),
        "capture_metadata_manifest_template_sha256": metadata_template_sha256,
        "capture_return_manifest_template_file": str(return_manifest_template_path),
        "capture_return_manifest_template_sha256": return_manifest_template_sha256,
        "parameters": {
            "seed": int(seed),
            "payload_sizes": sizes,
            "iterations_per_size": iterations,
            "redundancy_copies": int(redundancy_copies),
            "interleave": bool(interleave),
            "parity_group_size": int(parity_group_size),
            "filename_prefix": filename_prefix,
            "profile_redundancy_threshold_bytes": int(profile_redundancy_threshold_bytes),
            "capture_medium": capture_medium_value,
            "include_raw_capture_dirs": bool(include_raw_capture_dirs),
            "perspective_correction_method": perspective_method or None,
            "ocr_only_backend": ocr_backend_value or None,
            "capture_metadata_manifest_template_schema": CAPTURE_METADATA_MANIFEST_SCHEMA,
            "capture_return_manifest_template_schema": CAPTURE_RETURN_MANIFEST_SCHEMA,
        },
        "summary": {
            "case_count": len(cases),
            "generated_page_image_count": sum(
                len(case.get("kit_source", {}).get("generated_page_images", []))
                for case in cases
            ),
            "capture_directories_ready": len(cases),
            "raw_capture_directories_ready": sum(
                1 for case in cases if case.get("raw_image_paths")
            ),
            "operator_captures_present": 0,
            "operator_raw_captures_present": 0,
            "ocr_only_backend": ocr_backend_value or None,
            "capture_metadata_manifest_template_ready": True,
            "capture_return_manifest_template_ready": True,
        },
        "certification_boundary": (
            "This kit stages generated source pages and a capture manifest only; "
            "it is not transport certification evidence until operator captures are attached "
            "and soenc transport certify writes a passing transport_reliability_report.json."
        ),
        "cases": cases,
    }
    _write_json(kit_manifest_path, kit_manifest)
    return kit_manifest


def attach_capture_corpus(
    capture_corpus_file: str,
    output_dir: Optional[str] = None,
    report_file: Optional[str] = None,
    kit_manifest_file: Optional[str] = None,
    require_captures: bool = False,
    require_distinct_capture_images: bool = False,
    require_raw_captures: bool = False,
    update_corpus: bool = True,
    update_kit_manifest: bool = True,
) -> Dict[str, object]:
    """Bind current operator capture files to a prepared corpus without running recovery."""

    corpus_path = Path(str(capture_corpus_file)).resolve()
    if not corpus_path.exists() or not corpus_path.is_file():
        raise ValueError("capture corpus file does not exist: {}".format(corpus_path))
    corpus_base = corpus_path.parent
    corpus = _load_json(corpus_path)
    schema = str(corpus.get("schema") or "").strip()
    if schema != CAPTURE_CORPUS_SCHEMA:
        raise ValueError(
            "capture corpus schema must be {}, got {}".format(
                CAPTURE_CORPUS_SCHEMA,
                schema or "<missing>",
            )
        )

    classification = str(corpus.get("classification") or "").strip().lower()
    if classification not in SUPPORTED_CORPUS_CLASSIFICATIONS:
        raise ValueError(
            "capture corpus classification must be one of: {}".format(
                ", ".join(SUPPORTED_CORPUS_CLASSIFICATIONS)
            )
        )
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("capture corpus cases must be a non-empty list")

    report_dir = Path(output_dir).resolve() if output_dir else corpus_base
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = _resolve_output_path(
        report_file,
        report_dir,
        "transport_capture_attachment_report.json",
    )
    attached_at_utc = protocol.utc_now_iso()
    corpus_medium = _normalize_capture_medium(
        corpus.get(
            "capture_medium",
            corpus.get("medium", _normalize_capture_corpus_metadata(corpus.get("metadata")).get("capture_medium")),
        )
    )

    attachment_cases = []
    failures = Counter()
    classification_counts = Counter()
    capture_medium_counts = Counter()
    updated_cases = []
    for index, raw_case in enumerate(cases, 1):
        if not isinstance(raw_case, dict):
            raise ValueError("capture corpus case {} must be an object".format(index))

        label = _normalize_label(raw_case.get("label"), "capture_{:04d}".format(index))
        case_classification = str(raw_case.get("classification") or classification).strip().lower()
        if case_classification not in SUPPORTED_CORPUS_CLASSIFICATIONS:
            raise ValueError(
                "capture corpus case classification must be one of: {}".format(
                    ", ".join(SUPPORTED_CORPUS_CLASSIFICATIONS)
                )
            )
        capture_medium = _normalize_capture_medium(
            raw_case.get("capture_medium", raw_case.get("medium", corpus_medium))
        )
        capture_paths = _capture_images_from_existing_path(raw_case.get("image_path"), corpus_base)
        reference_paths = _optional_image_paths_from_capture_inputs(
            raw_case.get("reference_image_paths", raw_case.get("reference_image_path")),
            corpus_base,
        )
        raw_paths = _optional_image_paths_from_capture_inputs(
            raw_case.get("raw_image_paths", raw_case.get("raw_image_path")),
            corpus_base,
        )
        reference_transform = _capture_reference_transform(
            reference_image_paths=reference_paths,
            capture_image_paths=capture_paths,
            require_distinct_capture_images=bool(require_distinct_capture_images),
            missing_capture_passes_when_not_required=not (
                bool(require_captures) or bool(require_distinct_capture_images)
            ),
        )
        attached_records = _relative_digest_records(capture_paths, corpus_base)
        reference_records = _relative_digest_records(reference_paths, corpus_base)
        raw_records = _relative_digest_records(raw_paths, corpus_base)
        case_failures = []
        if bool(require_captures) and not attached_records:
            case_failures.append("capture_images_missing")
        if bool(require_raw_captures) and not raw_records:
            case_failures.append("raw_capture_images_missing")
        if bool(require_distinct_capture_images) and not reference_transform.get("strict_gate_passed"):
            case_failures.append("capture_reference_not_distinct")
        for reason in case_failures:
            failures[reason] += 1
        classification_counts[case_classification] += 1
        capture_medium_counts[capture_medium] += 1

        attachment_case = {
            "label": label,
            "classification": case_classification,
            "capture_medium": capture_medium,
            "image_path": str(raw_case.get("image_path") or ""),
            "capture_image_count": len(attached_records),
            "reference_image_count": len(reference_records),
            "raw_image_count": len(raw_records),
            "attached_images": attached_records,
            "reference_images": reference_records,
            "raw_images": raw_records,
            "reference_transform": reference_transform,
            "failure_reasons": case_failures,
            "ready_for_certification": not case_failures and bool(attached_records),
        }
        attachment_cases.append(attachment_case)

        updated_case = dict(raw_case)
        updated_case["attached_capture_image_count"] = len(attached_records)
        updated_case["attached_capture_images"] = attached_records
        updated_case["capture_attachment"] = {
            "schema": CAPTURE_ATTACHMENT_REPORT_SCHEMA,
            "attached_at_utc": attached_at_utc,
            "report_file": _safe_relative_path(report_path.resolve(), corpus_base.resolve()),
            "capture_image_count": len(attached_records),
            "reference_image_count": len(reference_records),
            "raw_image_count": len(raw_records),
            "ready_for_certification": not case_failures and bool(attached_records),
            "failure_reasons": case_failures,
        }
        updated_cases.append(updated_case)

    case_count = len(attachment_cases)
    attached_case_count = sum(1 for case in attachment_cases if int(case["capture_image_count"]) > 0)
    attached_image_count = sum(int(case["capture_image_count"]) for case in attachment_cases)
    raw_attached_case_count = sum(1 for case in attachment_cases if int(case["raw_image_count"]) > 0)
    raw_attached_image_count = sum(int(case["raw_image_count"]) for case in attachment_cases)
    distinct_case_count = sum(
        1
        for case in attachment_cases
        if bool(case.get("reference_transform", {}).get("distinct_from_reference"))
    )
    byte_identical_match_count = sum(
        int(case.get("reference_transform", {}).get("byte_identical_match_count") or 0)
        for case in attachment_cases
    )
    success = (
        not failures
        and (not bool(require_captures) or attached_case_count == case_count)
        and (not bool(require_raw_captures) or raw_attached_case_count == case_count)
    )
    boundary = (
        "This report only binds files currently present in the capture directories. "
        "It is not recovery certification and does not certify real camera/photo, "
        "physical print-scan, perspective correction, or OCR-only reliability until "
        "soenc transport certify measures the same corpus with the required gates."
    )
    report = {
        "schema": CAPTURE_ATTACHMENT_REPORT_SCHEMA,
        "generated_at_utc": attached_at_utc,
        "success": bool(success),
        "capture_corpus_schema": CAPTURE_CORPUS_SCHEMA,
        "capture_corpus_file": str(corpus_path),
        "classification": classification,
        "capture_medium": corpus_medium,
        "parameters": {
            "require_captures": bool(require_captures),
            "require_distinct_capture_images": bool(require_distinct_capture_images),
            "require_raw_captures": bool(require_raw_captures),
            "update_corpus": bool(update_corpus),
            "update_kit_manifest": bool(update_kit_manifest),
        },
        "summary": {
            "case_count": case_count,
            "cases_with_attached_captures": attached_case_count,
            "cases_missing_attached_captures": case_count - attached_case_count,
            "attached_capture_image_count": attached_image_count,
            "cases_with_raw_captures": raw_attached_case_count,
            "cases_missing_raw_captures": case_count - raw_attached_case_count,
            "raw_capture_image_count": raw_attached_image_count,
            "distinct_capture_case_count": distinct_case_count,
            "byte_identical_reference_match_count": byte_identical_match_count,
            "classification_counts": dict(classification_counts),
            "capture_medium_counts": dict(capture_medium_counts),
            "failures_by_reason": dict(failures),
        },
        "certification_boundary": boundary,
        "report_file": str(report_path),
        "updated_files": [],
        "cases": attachment_cases,
    }

    if bool(update_corpus):
        updated_corpus = dict(corpus)
        updated_metadata = _normalize_capture_corpus_metadata(updated_corpus.get("metadata"))
        updated_metadata["last_capture_attachment"] = {
            "schema": CAPTURE_ATTACHMENT_REPORT_SCHEMA,
            "attached_at_utc": attached_at_utc,
            "report_file": _safe_relative_path(report_path.resolve(), corpus_base.resolve()),
            "case_count": case_count,
            "cases_with_attached_captures": attached_case_count,
            "attached_capture_image_count": attached_image_count,
            "cases_with_raw_captures": raw_attached_case_count,
            "raw_capture_image_count": raw_attached_image_count,
            "success": bool(success),
        }
        updated_corpus["metadata"] = updated_metadata
        updated_corpus["cases"] = updated_cases
        _write_json(corpus_path, updated_corpus)
        report["updated_files"].append(str(corpus_path))

    manifest_path: Optional[Path] = None
    if kit_manifest_file is not None and str(kit_manifest_file).strip():
        manifest_path = Path(str(kit_manifest_file))
        if not manifest_path.is_absolute():
            manifest_path = manifest_path if manifest_path.exists() else corpus_base / manifest_path
        manifest_path = manifest_path.resolve()
    else:
        candidate = corpus_base / "capture_kit_manifest.json"
        if candidate.exists():
            manifest_path = candidate.resolve()

    if bool(update_kit_manifest) and manifest_path is not None:
        if not manifest_path.exists() or not manifest_path.is_file():
            raise ValueError("capture kit manifest file does not exist: {}".format(manifest_path))
        kit_manifest = _load_json(manifest_path)
        if str(kit_manifest.get("schema") or "").strip() != CAPTURE_KIT_SCHEMA:
            raise ValueError("capture kit manifest schema must be {}".format(CAPTURE_KIT_SCHEMA))
        summary = kit_manifest.get("summary")
        if not isinstance(summary, dict):
            summary = {}
        summary["operator_captures_present"] = attached_case_count
        summary["operator_capture_image_count"] = attached_image_count
        summary["operator_capture_cases_present"] = attached_case_count
        summary["operator_capture_cases_missing"] = case_count - attached_case_count
        summary["operator_raw_captures_present"] = raw_attached_case_count
        summary["operator_raw_capture_image_count"] = raw_attached_image_count
        summary["operator_raw_capture_cases_present"] = raw_attached_case_count
        summary["operator_raw_capture_cases_missing"] = case_count - raw_attached_case_count
        summary["byte_identical_reference_match_count"] = byte_identical_match_count
        kit_manifest["summary"] = summary
        kit_manifest["last_capture_attachment"] = {
            "schema": CAPTURE_ATTACHMENT_REPORT_SCHEMA,
            "attached_at_utc": attached_at_utc,
            "report_file": _safe_relative_path(report_path.resolve(), manifest_path.parent.resolve()),
            "capture_corpus_file": _safe_relative_path(corpus_path.resolve(), manifest_path.parent.resolve()),
            "success": bool(success),
        }
        _write_json(manifest_path, kit_manifest)
        report["updated_files"].append(str(manifest_path))

    _write_json(report_path, report)
    return report


def _collect_existing_paths_from_digest_records(
    records: object,
    base_dir: Path,
) -> List[Path]:
    paths = []
    if not isinstance(records, list):
        return paths
    for record in records:
        if not isinstance(record, dict):
            continue
        raw_path = str(record.get("path") or "").strip()
        if not raw_path:
            continue
        path = Path(raw_path)
        if not path.is_absolute():
            path = base_dir / path
        path = path.resolve()
        if path.exists() and path.is_file():
            paths.append(path)
    return paths


def _collect_path_from_record(raw_path: object, base_dir: Path) -> Optional[Path]:
    if raw_path is None or str(raw_path).strip() == "":
        return None
    path = Path(str(raw_path))
    if not path.is_absolute():
        path = base_dir / path
    path = path.resolve()
    if path.exists() and path.is_file():
        return path
    return None


def _add_archive_file(
    source: Path,
    role: str,
    files: List[Dict[str, object]],
    seen_sources: Set[str],
    used_archive_paths: Set[str],
    archive_prefix: str = "evidence/files",
) -> None:
    source = source.resolve()
    key = str(source)
    if key in seen_sources or not source.exists() or not source.is_file():
        return
    seen_sources.add(key)
    digest = _sha256_file(source) or ""
    target_name = "{}_{}".format(digest[:16] or "missing-digest", source.name)
    archive_path = "{}/{}".format(archive_prefix, target_name)
    counter = 1
    while archive_path in used_archive_paths:
        archive_path = "{}/{}_{}_{}".format(
            archive_prefix,
            digest[:16] or "missing-digest",
            counter,
            source.name,
        )
        counter += 1
    used_archive_paths.add(archive_path)
    files.append(
        {
            "role": role,
            "source_path": str(source),
            "archive_path": archive_path,
            "sha256": digest,
            "size_bytes": source.stat().st_size,
        }
    )


def _is_safe_archive_member(name: object) -> bool:
    text = str(name or "")
    if not text or text != text.strip():
        return False
    normalized = text.replace("\\", "/")
    if normalized != text:
        return False
    if normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
        return False
    if normalized.endswith("/"):
        return False
    if ":" in normalized.split("/", 1)[0]:
        return False
    path = Path(normalized)
    if path.is_absolute():
        return False
    return all(part not in ("", ".", "..") for part in normalized.split("/"))


def _is_safe_archive_directory_member(name: object) -> bool:
    text = str(name or "")
    if not text or text != text.strip():
        return False
    if not text.endswith("/"):
        return False
    normalized = text[:-1].replace("\\", "/")
    if normalized + "/" != text:
        return False
    if not normalized or normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized:
        return False
    if ":" in normalized.split("/", 1)[0]:
        return False
    path = Path(normalized)
    if path.is_absolute():
        return False
    return all(part not in ("", ".", "..") for part in normalized.split("/"))


def _archive_digest_record_from_bytes(
    archive_path: str,
    role: str,
    payload: bytes,
) -> Dict[str, object]:
    return {
        "archive_path": archive_path,
        "role": role,
        "sha256": _sha256_bytes(payload),
        "size_bytes": len(payload),
    }


def _coerce_int_for_verification(
    value: object,
    field_name: str,
    add_failure,
) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        add_failure(
            "integer_field_invalid",
            "archive manifest integer field is not an integer",
            field=field_name,
            value=value,
        )
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        add_failure(
            "integer_field_invalid",
            "archive manifest integer field is not an integer",
            field=field_name,
            value=value,
        )
        return None


def _certification_gate_snapshot(report: Dict[str, object]) -> Dict[str, object]:
    thresholds = report.get("thresholds")
    if not isinstance(thresholds, dict):
        thresholds = {}
    capture_corpus = report.get("capture_corpus")
    if not isinstance(capture_corpus, dict):
        capture_corpus = {}
    summary = report.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    certification_claims = report.get("certification_claims")
    if not isinstance(certification_claims, dict):
        certification_claims = {}
    return {
        "report_success": bool(report.get("success")),
        "profile": report.get("profile"),
        "profile_certified": bool(report.get("profile_certified")),
        "certification_claims": certification_claims,
        "capture_classification": capture_corpus.get("classification"),
        "capture_medium_counts": capture_corpus.get("capture_medium_counts", {}),
        "capture_case_count": summary.get("capture_case_count", 0),
        "capture_required_classification": thresholds.get("capture_required_classification"),
        "capture_required_classification_passed": bool(
            thresholds.get("capture_required_classification_passed")
        ),
        "distinct_capture_images_required": bool(
            thresholds.get("distinct_capture_images_required")
        ),
        "distinct_capture_images_passed": bool(thresholds.get("distinct_capture_images_passed")),
        "capture_attachment_report_required": bool(
            thresholds.get("capture_attachment_report_required")
        ),
        "capture_attachment_report_passed": bool(
            thresholds.get("capture_attachment_report_passed")
        ),
        "physical_print_scan_required": bool(thresholds.get("physical_print_scan_required")),
        "physical_print_scan_passed": bool(thresholds.get("physical_print_scan_passed")),
        "real_camera_perspective_correction_required": bool(
            thresholds.get("real_camera_perspective_correction_required")
        ),
        "real_camera_perspective_correction_passed": bool(
            thresholds.get("real_camera_perspective_correction_passed")
        ),
        "ocr_only_backend_required": bool(thresholds.get("ocr_only_backend_required")),
        "ocr_only_threshold_passed": bool(thresholds.get("ocr_only_threshold_passed")),
    }


def _certification_claim_certified(claims: object, claim_name: str) -> bool:
    if not isinstance(claims, dict):
        return False
    raw_claims = claims.get("claims")
    if not isinstance(raw_claims, list):
        return False
    for claim in raw_claims:
        if not isinstance(claim, dict):
            continue
        if str(claim.get("claim") or "") == claim_name:
            return bool(claim.get("certified"))
    return False


def archive_transport_evidence(
    report_file: str,
    output_dir: str,
    capture_corpus_file: Optional[str] = None,
    capture_attachment_report_file: Optional[str] = None,
    archive_file: Optional[str] = None,
    manifest_file: Optional[str] = None,
    require_successful_report: bool = False,
    require_capture_attachment_report: bool = False,
    require_physical_print_scan: bool = False,
    require_real_camera_perspective_correction: bool = False,
    require_ocr_only_backend: bool = False,
    require_profile_certified: bool = False,
) -> Dict[str, object]:
    """Package a measured transport report plus referenced artifacts for replay."""

    report_path = Path(str(report_file)).resolve()
    if not report_path.exists() or not report_path.is_file():
        raise ValueError("transport reliability report file does not exist: {}".format(report_path))
    report = _load_json(report_path)
    schema = str(report.get("schema") or "").strip()
    if schema != REPORT_SCHEMA:
        raise ValueError(
            "transport reliability report schema must be {}, got {}".format(
                REPORT_SCHEMA,
                schema or "<missing>",
            )
        )
    if bool(require_successful_report) and not bool(report.get("success")):
        raise ValueError("transport reliability report did not pass")
    gate_snapshot = _certification_gate_snapshot(report)
    if bool(require_profile_certified) and not bool(gate_snapshot.get("profile_certified")):
        raise ValueError("transport reliability report is not profile-certified")
    if bool(require_capture_attachment_report) and not (
        bool(gate_snapshot.get("capture_attachment_report_required"))
        and bool(gate_snapshot.get("capture_attachment_report_passed"))
    ):
        raise ValueError(
            "transport reliability report did not require and pass the capture attachment report gate"
        )
    if bool(require_physical_print_scan) and not (
        bool(gate_snapshot.get("physical_print_scan_required"))
        and bool(gate_snapshot.get("physical_print_scan_passed"))
    ):
        raise ValueError(
            "transport reliability report did not require and pass the physical print-scan gate"
        )
    if bool(require_physical_print_scan) and not _certification_claim_certified(
        gate_snapshot.get("certification_claims"),
        "physical-print-scan",
    ):
        raise ValueError(
            "transport reliability report certification claim physical-print-scan is not certified"
        )
    if bool(require_real_camera_perspective_correction) and not (
        bool(gate_snapshot.get("real_camera_perspective_correction_required"))
        and bool(gate_snapshot.get("real_camera_perspective_correction_passed"))
    ):
        raise ValueError(
            "transport reliability report did not require and pass the real camera perspective-correction gate"
        )
    if bool(require_real_camera_perspective_correction) and not _certification_claim_certified(
        gate_snapshot.get("certification_claims"),
        "real-camera-perspective-correction",
    ):
        raise ValueError(
            "transport reliability report certification claim real-camera-perspective-correction is not certified"
        )
    if bool(require_ocr_only_backend) and not (
        bool(gate_snapshot.get("ocr_only_backend_required"))
        and bool(gate_snapshot.get("ocr_only_threshold_passed"))
    ):
        raise ValueError(
            "transport reliability report did not require and pass the OCR-only backend gate"
        )
    if bool(require_ocr_only_backend) and not _certification_claim_certified(
        gate_snapshot.get("certification_claims"),
        "backend-specific-ocr-only",
    ):
        raise ValueError(
            "transport reliability report certification claim backend-specific-ocr-only is not certified"
        )

    out_dir = Path(str(output_dir)).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    archive_path = _resolve_output_path(
        archive_file,
        out_dir,
        "transport_capture_evidence_archive.zip",
    ).resolve()
    manifest_path = _resolve_output_path(
        manifest_file,
        out_dir,
        "transport_capture_evidence_archive_manifest.json",
    ).resolve()
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    report_base = report_path.parent
    raw_corpus_path = str(capture_corpus_file or "").strip()
    if not raw_corpus_path:
        capture_report_block = report.get("capture_corpus")
        if isinstance(capture_report_block, dict):
            raw_corpus_path = str(capture_report_block.get("corpus_file") or "").strip()
    corpus_path: Optional[Path] = None
    corpus: Optional[Dict[str, object]] = None
    if raw_corpus_path:
        candidate = Path(raw_corpus_path)
        if not candidate.is_absolute():
            candidate = report_base / candidate
        candidate = candidate.resolve()
        if not candidate.exists() or not candidate.is_file():
            raise ValueError("capture corpus file does not exist: {}".format(candidate))
        corpus = _load_json(candidate)
        if str(corpus.get("schema") or "").strip() != CAPTURE_CORPUS_SCHEMA:
            raise ValueError("capture corpus schema must be {}".format(CAPTURE_CORPUS_SCHEMA))
        corpus_path = candidate

    raw_attachment_path = str(capture_attachment_report_file or "").strip()
    if not raw_attachment_path:
        parameters = report.get("parameters")
        if isinstance(parameters, dict):
            raw_attachment_path = str(parameters.get("capture_attachment_report_file") or "").strip()
    attachment_path: Optional[Path] = None
    attachment_report: Optional[Dict[str, object]] = None
    if raw_attachment_path:
        candidate = Path(raw_attachment_path)
        if not candidate.is_absolute():
            candidate_base = corpus_path.parent if corpus_path is not None else report_base
            candidate = candidate_base / candidate
        candidate = candidate.resolve()
        if not candidate.exists() or not candidate.is_file():
            raise ValueError("capture attachment report file does not exist: {}".format(candidate))
        attachment_report = _load_json(candidate)
        if str(attachment_report.get("schema") or "").strip() != CAPTURE_ATTACHMENT_REPORT_SCHEMA:
            raise ValueError(
                "capture attachment report schema must be {}".format(
                    CAPTURE_ATTACHMENT_REPORT_SCHEMA
                )
            )
        attachment_path = candidate
    elif bool(require_capture_attachment_report):
        raise ValueError("capture attachment report is required for evidence archive")

    files: List[Dict[str, object]] = []
    seen_sources: Set[str] = set()
    used_archive_paths: Set[str] = set()
    _add_archive_file(report_path, "transport_reliability_report", files, seen_sources, used_archive_paths)
    if corpus_path is not None:
        _add_archive_file(corpus_path, "capture_corpus", files, seen_sources, used_archive_paths)
    if attachment_path is not None:
        _add_archive_file(
            attachment_path,
            "capture_attachment_report",
            files,
            seen_sources,
            used_archive_paths,
        )

    if corpus is not None and corpus_path is not None:
        corpus_base = corpus_path.parent
        corpus_metadata = corpus.get("metadata")
        if isinstance(corpus_metadata, dict):
            last_correction = corpus_metadata.get("last_perspective_correction")
            if isinstance(last_correction, dict):
                correction_report_path = _collect_path_from_record(
                    last_correction.get("report_file"),
                    corpus_base,
                )
                if correction_report_path is not None:
                    _add_archive_file(
                        correction_report_path,
                        "capture_perspective_correction_report",
                        files,
                        seen_sources,
                        used_archive_paths,
                    )
        for raw_case in corpus.get("cases", []) or []:
            if not isinstance(raw_case, dict):
                continue
            role_path_fields = (
                ("manifest", raw_case.get("manifest_path")),
                ("payload", raw_case.get("payload_path")),
            )
            for role, raw_path in role_path_fields:
                path = _collect_path_from_record(raw_path, corpus_base)
                if path is not None:
                    _add_archive_file(path, role, files, seen_sources, used_archive_paths)
            perspective_correction = raw_case.get("perspective_correction")
            if isinstance(perspective_correction, dict):
                correction_report_path = _collect_path_from_record(
                    perspective_correction.get("correction_report_file"),
                    corpus_base,
                )
                if correction_report_path is not None:
                    _add_archive_file(
                        correction_report_path,
                        "capture_perspective_correction_report",
                        files,
                        seen_sources,
                        used_archive_paths,
                    )
            for role, raw_paths in (
                ("capture_image", raw_case.get("image_path")),
                ("reference_image", raw_case.get("reference_image_paths", raw_case.get("reference_image_path"))),
                ("raw_capture_image", raw_case.get("raw_image_paths", raw_case.get("raw_image_path"))),
            ):
                try:
                    paths = _optional_image_paths_from_capture_inputs(raw_paths, corpus_base)
                except ValueError:
                    paths = []
                for path in paths:
                    _add_archive_file(path, role, files, seen_sources, used_archive_paths)

    for raw_case in report.get("cases", []) or []:
        if not isinstance(raw_case, dict):
            continue
        export = raw_case.get("export") if isinstance(raw_case.get("export"), dict) else {}
        recovery = raw_case.get("recovery") if isinstance(raw_case.get("recovery"), dict) else {}
        for role, raw_path in (
            ("reported_manifest", export.get("manifest_path")),
            ("reported_payload", export.get("payload_path")),
            ("restored_payload", recovery.get("output_file")),
            ("ocr_text_output", recovery.get("ocr_text_output")),
            ("analysis_report", recovery.get("analysis_report_path")),
            ("missing_chunks", recovery.get("missing_file_path")),
        ):
            path = _collect_path_from_record(raw_path, report_base)
            if path is not None:
                _add_archive_file(path, role, files, seen_sources, used_archive_paths)
        for role, raw_paths in (
            ("reported_image", export.get("image_paths")),
            ("reported_distorted_image", export.get("distorted_image_paths")),
            ("reported_source_image", export.get("source_image_paths")),
        ):
            values = raw_paths if isinstance(raw_paths, list) else []
            for raw_path in values:
                path = _collect_path_from_record(raw_path, report_base)
                if path is not None:
                    _add_archive_file(path, role, files, seen_sources, used_archive_paths)
        artifact_digests = raw_case.get("artifact_digests")
        if isinstance(artifact_digests, dict):
            for role, records in (
                ("digest_image", artifact_digests.get("images")),
                ("digest_distorted_image", artifact_digests.get("distorted_images")),
                ("digest_source_image", artifact_digests.get("source_images")),
            ):
                for path in _collect_existing_paths_from_digest_records(records, report_base):
                    _add_archive_file(path, role, files, seen_sources, used_archive_paths)
        capture_record = raw_case.get("capture_corpus")
        if isinstance(capture_record, dict):
            for role, records in (
                ("attached_capture_image", capture_record.get("attached_images")),
                ("reference_image", capture_record.get("reference_images")),
                ("raw_capture_image", capture_record.get("raw_images")),
                ("source_capture_image", capture_record.get("source_images")),
            ):
                for path in _collect_existing_paths_from_digest_records(records, report_base):
                    _add_archive_file(path, role, files, seen_sources, used_archive_paths)

    archive_manifest = {
        "schema": CAPTURE_EVIDENCE_ARCHIVE_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": True,
        "transport_report_file": str(report_path),
        "transport_report_sha256": _sha256_file(report_path),
        "capture_corpus_file": str(corpus_path) if corpus_path else None,
        "capture_corpus_sha256": _sha256_file(corpus_path) if corpus_path else None,
        "capture_attachment_report_file": str(attachment_path) if attachment_path else None,
        "capture_attachment_report_sha256": (
            _sha256_file(attachment_path) if attachment_path else None
        ),
        "certification_gates": gate_snapshot,
        "parameters": {
            "require_successful_report": bool(require_successful_report),
            "require_capture_attachment_report": bool(require_capture_attachment_report),
            "require_physical_print_scan": bool(require_physical_print_scan),
            "require_real_camera_perspective_correction": bool(
                require_real_camera_perspective_correction
            ),
            "require_ocr_only_backend": bool(require_ocr_only_backend),
            "require_profile_certified": bool(require_profile_certified),
        },
        "summary": {
            "file_count": len(files),
            "total_size_bytes": sum(int(item.get("size_bytes") or 0) for item in files),
            "roles": dict(Counter(str(item.get("role") or "unknown") for item in files)),
        },
        "certification_boundary": (
            "This archive preserves the exact measured report inputs and outputs for replay. "
            "It does not strengthen or broaden the certification claim beyond the included "
            "transport_reliability_report.json gates and corpus classification."
        ),
        "files": files,
    }
    embedded_manifest_json = json.dumps(
        archive_manifest,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    archive_manifest["embedded_manifest_sha256"] = _sha256_text(embedded_manifest_json)

    with zipfile.ZipFile(str(archive_path), "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "transport_capture_evidence_archive_manifest.json",
            embedded_manifest_json,
        )
        for item in files:
            archive.write(str(item["source_path"]), str(item["archive_path"]))

    archive_manifest["archive_file"] = str(archive_path)
    archive_manifest["archive_sha256"] = _sha256_file(archive_path)
    archive_manifest["archive_size_bytes"] = archive_path.stat().st_size
    archive_manifest["manifest_file"] = str(manifest_path)
    _write_json(manifest_path, archive_manifest)
    return archive_manifest


def verify_transport_evidence_archive(
    archive_file: str,
    manifest_file: Optional[str] = None,
    output_file: Optional[str] = None,
    require_successful_report: bool = False,
    require_capture_attachment_report: bool = False,
    require_physical_print_scan: bool = False,
    require_real_camera_perspective_correction: bool = False,
    require_ocr_only_backend: bool = False,
    require_profile_certified: bool = False,
) -> Dict[str, object]:
    """Verify that a transport evidence archive is intact and gate-coherent."""

    archive_path = Path(str(archive_file)).resolve()
    if not archive_path.exists() or not archive_path.is_file():
        raise ValueError("transport evidence archive file does not exist: {}".format(archive_path))

    raw_manifest_path = str(manifest_file or "").strip()
    manifest_path: Optional[Path] = None
    if raw_manifest_path:
        candidate = Path(raw_manifest_path)
        if not candidate.is_absolute():
            cwd_relative = candidate.resolve()
            candidate = cwd_relative if cwd_relative.exists() else archive_path.parent / candidate
        manifest_path = candidate.resolve()
        if not manifest_path.exists() or not manifest_path.is_file():
            raise ValueError("transport evidence archive manifest file does not exist: {}".format(manifest_path))
    else:
        candidate = archive_path.parent / "transport_capture_evidence_archive_manifest.json"
        if candidate.exists() and candidate.is_file():
            manifest_path = candidate.resolve()

    failures: List[Dict[str, object]] = []

    def add_failure(code: str, message: str, **details: object) -> None:
        record: Dict[str, object] = {"code": code, "message": message}
        record.update(details)
        failures.append(record)

    archive_bytes = archive_path.read_bytes()
    archive_sha256 = _sha256_bytes(archive_bytes)
    archive_size_bytes = archive_path.stat().st_size
    external_manifest: Optional[Dict[str, object]] = None
    if manifest_path is not None:
        external_manifest = _load_json(manifest_path)
        if str(external_manifest.get("schema") or "").strip() != CAPTURE_EVIDENCE_ARCHIVE_SCHEMA:
            add_failure(
                "external_manifest_schema_mismatch",
                "external archive manifest schema is not supported",
                expected=CAPTURE_EVIDENCE_ARCHIVE_SCHEMA,
                actual=str(external_manifest.get("schema") or "").strip() or None,
            )
        expected_archive_sha = str(external_manifest.get("archive_sha256") or "").strip().lower()
        if expected_archive_sha and expected_archive_sha != archive_sha256:
            add_failure(
                "external_archive_sha256_mismatch",
                "archive SHA256 does not match the external manifest",
                expected=expected_archive_sha,
                actual=archive_sha256,
            )
        expected_archive_size = external_manifest.get("archive_size_bytes")
        expected_archive_size_int = _coerce_int_for_verification(
            expected_archive_size,
            "archive_size_bytes",
            add_failure,
        )
        if (
            expected_archive_size_int is not None
            and expected_archive_size_int != archive_size_bytes
        ):
            add_failure(
                "external_archive_size_mismatch",
                "archive byte size does not match the external manifest",
                expected=expected_archive_size_int,
                actual=archive_size_bytes,
            )

    embedded_member_name = "transport_capture_evidence_archive_manifest.json"
    embedded_manifest_payload: Optional[bytes] = None
    embedded_manifest: Optional[Dict[str, object]] = None
    archive_member_names: List[str] = []
    archive_member_name_counts: Counter = Counter()
    archive_payloads: Dict[str, bytes] = {}
    archive_info_by_name: Dict[str, zipfile.ZipInfo] = {}

    try:
        with zipfile.ZipFile(str(archive_path), "r") as archive:
            infos = archive.infolist()
            archive_member_names = [info.filename for info in infos]
            archive_member_name_counts = Counter(archive_member_names)
            for name, count in archive_member_name_counts.items():
                if count != 1:
                    add_failure(
                        "duplicate_archive_member",
                        "archive contains a duplicate member path",
                        archive_path=name,
                        count=count,
                    )
            for info in infos:
                if not _is_safe_archive_member(info.filename):
                    add_failure(
                        "unsafe_archive_member",
                        "archive member path is not a safe relative file path",
                        archive_path=info.filename,
                    )
                    continue
                file_type = (info.external_attr >> 16) & 0o170000
                if file_type == 0o120000:
                    add_failure(
                        "archive_member_is_symlink",
                        "archive member is a symlink",
                        archive_path=info.filename,
                    )
                    continue
                archive_info_by_name[info.filename] = info
            if embedded_member_name not in archive_info_by_name:
                add_failure(
                    "embedded_manifest_missing",
                    "archive is missing the embedded evidence manifest",
                    archive_path=embedded_member_name,
                )
            else:
                embedded_manifest_payload = archive.read(embedded_member_name)
            for name, info in archive_info_by_name.items():
                if name == embedded_member_name:
                    continue
                archive_payloads[name] = archive.read(info)
    except zipfile.BadZipFile:
        add_failure("archive_unreadable", "archive is not a readable ZIP file")

    embedded_manifest_sha256: Optional[str] = None
    if embedded_manifest_payload is not None:
        embedded_manifest_sha256 = _sha256_bytes(embedded_manifest_payload)
        try:
            embedded_manifest = json.loads(embedded_manifest_payload.decode("utf-8-sig"))
        except Exception as exc:
            add_failure(
                "embedded_manifest_invalid_json",
                "embedded archive manifest is not valid JSON",
                error=str(exc),
            )

    if external_manifest is not None and embedded_manifest_payload is not None:
        expected_embedded_sha = str(
            external_manifest.get("embedded_manifest_sha256") or ""
        ).strip().lower()
        if not expected_embedded_sha:
            add_failure(
                "embedded_manifest_sha256_missing",
                "external manifest does not record the embedded manifest SHA256",
            )
        elif expected_embedded_sha != embedded_manifest_sha256:
            add_failure(
                "embedded_manifest_sha256_mismatch",
                "embedded manifest SHA256 does not match the external manifest",
                expected=expected_embedded_sha,
                actual=embedded_manifest_sha256,
            )

    archive_manifest = embedded_manifest if isinstance(embedded_manifest, dict) else external_manifest
    if not isinstance(archive_manifest, dict):
        add_failure(
            "archive_manifest_missing",
            "no usable archive manifest was found in the ZIP or external manifest file",
        )
        archive_manifest = {}
    if str(archive_manifest.get("schema") or "").strip() != CAPTURE_EVIDENCE_ARCHIVE_SCHEMA:
        add_failure(
            "archive_manifest_schema_mismatch",
            "archive manifest schema is not supported",
            expected=CAPTURE_EVIDENCE_ARCHIVE_SCHEMA,
            actual=str(archive_manifest.get("schema") or "").strip() or None,
        )

    if external_manifest is not None and embedded_manifest is not None:
        for field_name in (
            "schema",
            "success",
            "transport_report_sha256",
            "capture_corpus_sha256",
            "capture_attachment_report_sha256",
            "certification_gates",
            "certification_claims",
            "parameters",
            "summary",
            "certification_boundary",
            "files",
        ):
            if external_manifest.get(field_name) != embedded_manifest.get(field_name):
                add_failure(
                    "external_embedded_manifest_mismatch",
                    "external manifest does not match the embedded manifest",
                    field=field_name,
                )

    raw_files = archive_manifest.get("files")
    files = raw_files if isinstance(raw_files, list) else []
    if not isinstance(raw_files, list):
        add_failure("archive_manifest_files_invalid", "archive manifest files must be a list")

    expected_archive_paths: Set[str] = {embedded_member_name}
    file_path_counts: Counter = Counter()
    for item in files:
        if not isinstance(item, dict):
            add_failure("archive_file_record_invalid", "archive file record must be an object")
            continue
        archive_member_path = str(item.get("archive_path") or "").strip()
        if not _is_safe_archive_member(archive_member_path):
            add_failure(
                "archive_file_record_path_unsafe",
                "archive file record has an unsafe archive path",
                archive_path=archive_member_path or None,
            )
            continue
        if archive_member_path == embedded_member_name:
            add_failure(
                "archive_file_record_reserved_path",
                "archive file record targets the reserved embedded manifest path",
                archive_path=archive_member_path,
            )
            continue
        file_path_counts[archive_member_path] += 1
        expected_archive_paths.add(archive_member_path)
    for archive_member_path, count in file_path_counts.items():
        if count != 1:
            add_failure(
                "duplicate_manifest_archive_path",
                "archive manifest files contain duplicate archive paths",
                archive_path=archive_member_path,
                count=count,
            )

    actual_archive_paths = set(archive_member_names)
    missing_archive_paths = sorted(expected_archive_paths - actual_archive_paths)
    extra_archive_paths = sorted(actual_archive_paths - expected_archive_paths)
    if missing_archive_paths:
        add_failure(
            "archive_member_missing",
            "archive is missing manifest-declared members",
            archive_paths=missing_archive_paths,
        )
    if extra_archive_paths:
        add_failure(
            "archive_member_unexpected",
            "archive contains members not declared by the manifest",
            archive_paths=extra_archive_paths,
        )

    verified_files: List[Dict[str, object]] = []
    role_counts: Counter = Counter()
    role_payloads: Dict[str, List[bytes]] = {}
    role_records: Dict[str, List[Dict[str, object]]] = {}
    total_size_verified = 0
    for item in files:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "unknown").strip() or "unknown"
        archive_member_path = str(item.get("archive_path") or "").strip()
        expected_sha = str(item.get("sha256") or "").strip().lower()
        expected_size = item.get("size_bytes")
        if not archive_member_path or archive_member_path not in archive_payloads:
            continue
        payload = archive_payloads[archive_member_path]
        actual_sha = _sha256_bytes(payload)
        actual_size = len(payload)
        if expected_sha != actual_sha:
            add_failure(
                "file_sha256_mismatch",
                "archive member SHA256 does not match its manifest record",
                archive_path=archive_member_path,
                expected=expected_sha,
                actual=actual_sha,
                role=role,
            )
        expected_size_int = _coerce_int_for_verification(
            expected_size,
            "files[].size_bytes",
            add_failure,
        )
        if expected_size_int is None or expected_size_int != actual_size:
            add_failure(
                "file_size_mismatch",
                "archive member byte size does not match its manifest record",
                archive_path=archive_member_path,
                expected=expected_size_int if expected_size_int is not None else expected_size,
                actual=actual_size,
                role=role,
            )
        verified_record = _archive_digest_record_from_bytes(archive_member_path, role, payload)
        verified_files.append(verified_record)
        total_size_verified += actual_size
        role_counts[role] += 1
        role_payloads.setdefault(role, []).append(payload)
        role_records.setdefault(role, []).append(dict(item))

    manifest_summary = archive_manifest.get("summary")
    if not isinstance(manifest_summary, dict):
        add_failure("archive_manifest_summary_invalid", "archive manifest summary must be an object")
        manifest_summary = {}
    summary_file_count = _coerce_int_for_verification(
        manifest_summary.get("file_count"),
        "summary.file_count",
        add_failure,
    )
    if summary_file_count != len(files):
        add_failure(
            "summary_file_count_mismatch",
            "archive manifest summary file_count does not match files length",
            expected=summary_file_count,
            actual=len(files),
        )
    summary_total_size = _coerce_int_for_verification(
        manifest_summary.get("total_size_bytes"),
        "summary.total_size_bytes",
        add_failure,
    )
    if summary_total_size != total_size_verified:
        add_failure(
            "summary_total_size_mismatch",
            "archive manifest summary total size does not match verified members",
            expected=summary_total_size,
            actual=total_size_verified,
        )
    expected_roles = manifest_summary.get("roles") if isinstance(manifest_summary.get("roles"), dict) else {}
    if dict(role_counts) != expected_roles:
        add_failure(
            "summary_roles_mismatch",
            "archive manifest summary role counts do not match verified members",
            expected=expected_roles,
            actual=dict(role_counts),
        )

    for manifest_field, role_name in (
        ("transport_report_sha256", "transport_reliability_report"),
        ("capture_corpus_sha256", "capture_corpus"),
        ("capture_attachment_report_sha256", "capture_attachment_report"),
    ):
        expected_sha = str(archive_manifest.get(manifest_field) or "").strip().lower()
        if not expected_sha:
            continue
        matching_records = role_records.get(role_name, [])
        if not matching_records:
            add_failure(
                "top_level_digest_role_missing",
                "top-level manifest digest has no matching archived file role",
                field=manifest_field,
                role=role_name,
            )
            continue
        if expected_sha != str(matching_records[0].get("sha256") or "").strip().lower():
            add_failure(
                "top_level_digest_mismatch",
                "top-level manifest digest does not match the archived file record",
                field=manifest_field,
                role=role_name,
                expected=expected_sha,
                actual=matching_records[0].get("sha256"),
            )

    gates = archive_manifest.get("certification_gates")
    if not isinstance(gates, dict):
        add_failure(
            "certification_gates_missing",
            "archive manifest does not contain certification gate snapshot",
        )
        gates = {}
    claims = gates.get("certification_claims")
    if claims is None:
        add_failure(
            "certification_claims_missing",
            "archive manifest gate snapshot does not contain certification claims",
        )
        claims = {}
    elif not isinstance(claims, dict):
        add_failure(
            "certification_claims_invalid",
            "archive manifest certification claims must be an object",
        )
        claims = {}
    elif str(claims.get("schema") or "").strip() != CERTIFICATION_CLAIMS_SCHEMA:
        add_failure(
            "certification_claims_schema_mismatch",
            "archive manifest certification claims schema is not supported",
            expected=CERTIFICATION_CLAIMS_SCHEMA,
            actual=str(claims.get("schema") or "").strip() or None,
        )

    transport_payloads = role_payloads.get("transport_reliability_report", [])
    if len(transport_payloads) != 1:
        add_failure(
            "transport_report_role_count_invalid",
            "archive must contain exactly one transport reliability report",
            actual=len(transport_payloads),
        )
    elif transport_payloads:
        try:
            transport_report = json.loads(transport_payloads[0].decode("utf-8-sig"))
            if str(transport_report.get("schema") or "").strip() != REPORT_SCHEMA:
                add_failure(
                    "transport_report_schema_mismatch",
                    "archived transport report schema is not supported",
                    expected=REPORT_SCHEMA,
                    actual=str(transport_report.get("schema") or "").strip() or None,
                )
            if bool(transport_report.get("success")) != bool(gates.get("report_success")):
                add_failure(
                    "transport_report_gate_mismatch",
                    "transport report success does not match certification gate snapshot",
                )
            if bool(transport_report.get("profile_certified")) != bool(
                gates.get("profile_certified")
            ):
                add_failure(
                    "transport_profile_gate_mismatch",
                    "transport report profile certification does not match gate snapshot",
                )
            report_claims = transport_report.get("certification_claims")
            if report_claims != claims:
                add_failure(
                    "transport_claims_gate_mismatch",
                    "transport report certification claims do not match gate snapshot",
                )
        except Exception as exc:
            add_failure(
                "transport_report_invalid_json",
                "archived transport reliability report is not valid JSON",
                error=str(exc),
            )

    for role_name, expected_schema in (
        ("capture_corpus", CAPTURE_CORPUS_SCHEMA),
        ("capture_attachment_report", CAPTURE_ATTACHMENT_REPORT_SCHEMA),
        (
            "capture_perspective_correction_report",
            CAPTURE_PERSPECTIVE_CORRECTION_REPORT_SCHEMA,
        ),
    ):
        for payload in role_payloads.get(role_name, []):
            try:
                document = json.loads(payload.decode("utf-8-sig"))
                if str(document.get("schema") or "").strip() != expected_schema:
                    add_failure(
                        "{}_schema_mismatch".format(role_name),
                        "archived {} schema is not supported".format(role_name),
                        expected=expected_schema,
                        actual=str(document.get("schema") or "").strip() or None,
                    )
            except Exception as exc:
                add_failure(
                    "{}_invalid_json".format(role_name),
                    "archived {} is not valid JSON".format(role_name),
                    error=str(exc),
                )

    if bool(require_successful_report) and not bool(gates.get("report_success")):
        add_failure(
            "required_successful_report_missing",
            "verification requires an archived report with success=true",
        )
    if bool(require_profile_certified) and not bool(gates.get("profile_certified")):
        add_failure(
            "required_profile_certified_missing",
            "verification requires profile_certified=true in the archived report",
        )
    if bool(require_capture_attachment_report):
        if not (
            bool(gates.get("capture_attachment_report_required"))
            and bool(gates.get("capture_attachment_report_passed"))
        ):
            add_failure(
                "required_capture_attachment_report_gate_missing",
                "verification requires the capture attachment report gate to be required and passed",
            )
        if not role_payloads.get("capture_attachment_report"):
            add_failure(
                "required_capture_attachment_report_file_missing",
                "verification requires an archived capture attachment report file",
            )
    if bool(require_physical_print_scan) and not (
        bool(gates.get("physical_print_scan_required"))
        and bool(gates.get("physical_print_scan_passed"))
    ):
        add_failure(
            "required_physical_print_scan_gate_missing",
            "verification requires the physical print-scan gate to be required and passed",
        )
    if bool(require_real_camera_perspective_correction) and not (
        bool(gates.get("real_camera_perspective_correction_required"))
        and bool(gates.get("real_camera_perspective_correction_passed"))
    ):
        add_failure(
            "required_real_camera_perspective_gate_missing",
            "verification requires the real camera perspective-correction gate to be required and passed",
        )
    if bool(require_ocr_only_backend) and not (
        bool(gates.get("ocr_only_backend_required"))
        and bool(gates.get("ocr_only_threshold_passed"))
    ):
        add_failure(
            "required_ocr_only_backend_gate_missing",
            "verification requires the OCR-only backend gate to be required and passed",
        )

    verification = {
        "schema": CAPTURE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": not failures,
        "archive_file": str(archive_path),
        "archive_sha256": archive_sha256,
        "archive_size_bytes": archive_size_bytes,
        "manifest_file": str(manifest_path) if manifest_path else None,
        "embedded_manifest_sha256": embedded_manifest_sha256,
        "certification_gates": gates,
        "certification_claims": claims,
        "parameters": {
            "require_successful_report": bool(require_successful_report),
            "require_capture_attachment_report": bool(require_capture_attachment_report),
            "require_physical_print_scan": bool(require_physical_print_scan),
            "require_real_camera_perspective_correction": bool(
                require_real_camera_perspective_correction
            ),
            "require_ocr_only_backend": bool(require_ocr_only_backend),
            "require_profile_certified": bool(require_profile_certified),
        },
        "checks": {
            "external_manifest_supplied": manifest_path is not None,
            "embedded_manifest_present": embedded_manifest_payload is not None,
            "archive_entries_exact_match": not missing_archive_paths and not extra_archive_paths,
            "file_digests_verified": not any(
                failure.get("code") in ("file_sha256_mismatch", "file_size_mismatch")
                for failure in failures
            ),
            "certification_gates_verified": not any(
                str(failure.get("code") or "").startswith("required_")
                for failure in failures
            ),
        },
        "summary": {
            "archive_entry_count": len(archive_member_names),
            "file_count_reported": len(files),
            "file_count_verified": len(verified_files),
            "total_size_bytes_verified": total_size_verified,
            "roles_verified": dict(role_counts),
            "failure_count": len(failures),
        },
        "files_verified": verified_files,
        "failures": failures,
        "certification_boundary": (
            "This verification proves archive integrity and gate coherence only. It does not "
            "broaden the certification claim beyond the archived transport report and corpus."
        ),
    }
    if output_file is not None and str(output_file).strip():
        _write_json(Path(str(output_file)).resolve(), verification)
    return verification


def _archive_records_by_role(
    archive_manifest: Dict[str, object],
) -> Dict[str, List[Dict[str, object]]]:
    records: Dict[str, List[Dict[str, object]]] = {}
    raw_files = archive_manifest.get("files")
    if not isinstance(raw_files, list):
        return records
    for item in raw_files:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip()
        if not role:
            continue
        records.setdefault(role, []).append(item)
    return records


def _load_archive_manifest_for_replay(archive_file: str) -> Dict[str, object]:
    archive_path = Path(str(archive_file)).resolve()
    embedded_member_name = "transport_capture_evidence_archive_manifest.json"
    with zipfile.ZipFile(str(archive_path), "r") as archive:
        payload = archive.read(embedded_member_name)
    manifest = json.loads(payload.decode("utf-8-sig"))
    if str(manifest.get("schema") or "").strip() != CAPTURE_EVIDENCE_ARCHIVE_SCHEMA:
        raise ValueError(
            "transport evidence archive manifest schema must be {}".format(
                CAPTURE_EVIDENCE_ARCHIVE_SCHEMA
            )
        )
    return manifest


def _single_archive_role_path(
    records_by_role: Dict[str, List[Dict[str, object]]],
    role: str,
    extraction_dir: Path,
) -> Optional[Path]:
    records = records_by_role.get(role, [])
    if not records:
        return None
    archive_member_path = str(records[0].get("archive_path") or "").strip()
    if not _is_safe_archive_member(archive_member_path):
        return None
    return (extraction_dir / archive_member_path).resolve()


def _archive_digest_path_map(
    records_by_role: Dict[str, List[Dict[str, object]]],
    roles: Iterable[str],
    extraction_dir: Path,
) -> Dict[str, Path]:
    by_sha: Dict[str, Path] = {}
    for role in roles:
        for record in records_by_role.get(role, []):
            digest = str(record.get("sha256") or "").strip().lower()
            archive_member_path = str(record.get("archive_path") or "").strip()
            if not digest or not _is_safe_archive_member(archive_member_path):
                continue
            extracted_path = (extraction_dir / archive_member_path).resolve()
            if extracted_path.exists() and extracted_path.is_file():
                by_sha.setdefault(digest, extracted_path)
    return by_sha


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def _rewrite_archive_report_paths(
    report: Dict[str, object],
    report_path: Path,
    corpus_path: Optional[Path],
    attachment_path: Optional[Path],
) -> None:
    report["report_path"] = str(report_path)
    parameters = report.get("parameters")
    if not isinstance(parameters, dict):
        parameters = {}
        report["parameters"] = parameters
    parameters["capture_corpus_file"] = str(corpus_path) if corpus_path else None
    if attachment_path is not None:
        parameters["capture_attachment_report_file"] = str(attachment_path)
    capture_block = report.get("capture_corpus")
    if isinstance(capture_block, dict):
        capture_block["corpus_file"] = str(corpus_path) if corpus_path else None


def _path_for_archived_digest_record(
    record: object,
    digest_to_path: Dict[str, Path],
) -> Optional[str]:
    if not isinstance(record, dict):
        return None
    digest = str(record.get("sha256") or "").strip().lower()
    if not digest:
        return None
    path = digest_to_path.get(digest)
    if path is None:
        return None
    return str(path)


def _paths_for_archived_digest_records(
    records: object,
    digest_to_path: Dict[str, Path],
) -> List[str]:
    paths: List[str] = []
    if not isinstance(records, list):
        return paths
    seen = set()
    for record in records:
        path = _path_for_archived_digest_record(record, digest_to_path)
        if not path or path in seen:
            continue
        seen.add(path)
        paths.append(path)
    return paths


def _rewrite_digest_record_paths(
    records: object,
    digest_to_path: Dict[str, Path],
) -> None:
    if not isinstance(records, list):
        return
    for record in records:
        if not isinstance(record, dict):
            continue
        path = _path_for_archived_digest_record(record, digest_to_path)
        if path:
            record["path"] = path


def _rewrite_archive_attachment_paths(
    attachment_report: Dict[str, object],
    attachment_path: Path,
    corpus_path: Path,
    digest_to_path: Dict[str, Path],
) -> None:
    attachment_report["capture_corpus_file"] = str(corpus_path)
    attachment_report["report_file"] = str(attachment_path)
    for raw_case in attachment_report.get("cases", []) or []:
        if not isinstance(raw_case, dict):
            continue
        _rewrite_digest_record_paths(raw_case.get("attached_images"), digest_to_path)
        _rewrite_digest_record_paths(raw_case.get("reference_images"), digest_to_path)
        _rewrite_digest_record_paths(raw_case.get("raw_images"), digest_to_path)
        attached_paths = _paths_for_archived_digest_records(
            raw_case.get("attached_images"),
            digest_to_path,
        )
        if attached_paths:
            raw_case["image_path"] = attached_paths if len(attached_paths) > 1 else attached_paths[0]


def _rewrite_archive_corpus_paths(
    corpus: Dict[str, object],
    corpus_path: Path,
    attachment_path: Optional[Path],
    digest_to_path: Dict[str, Path],
) -> None:
    metadata = corpus.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        corpus["metadata"] = metadata
    if attachment_path is not None:
        last_attachment = metadata.get("last_capture_attachment")
        if not isinstance(last_attachment, dict):
            last_attachment = {}
        last_attachment["report_file"] = str(attachment_path)
        metadata["last_capture_attachment"] = last_attachment

    for raw_case in corpus.get("cases", []) or []:
        if not isinstance(raw_case, dict):
            continue
        attached_paths = _paths_for_archived_digest_records(
            raw_case.get("attached_capture_images"),
            digest_to_path,
        )
        if attached_paths:
            raw_case["image_path"] = attached_paths if len(attached_paths) > 1 else attached_paths[0]
        reference_paths = _paths_for_archived_digest_records(
            raw_case.get("reference_image_paths"),
            digest_to_path,
        )
        if not reference_paths:
            reference_paths = _paths_for_archived_digest_records(
                raw_case.get("reference_images"),
                digest_to_path,
            )
        if reference_paths:
            raw_case["reference_image_paths"] = reference_paths
        raw_paths = _paths_for_archived_digest_records(
            raw_case.get("raw_capture_images"),
            digest_to_path,
        )
        if not raw_paths:
            raw_paths = _paths_for_archived_digest_records(
                raw_case.get("raw_images"),
                digest_to_path,
            )
        if raw_paths:
            raw_case["raw_image_paths"] = raw_paths


def _rewrite_archive_corpus_paths_from_report(
    corpus: Dict[str, object],
    original_report: Dict[str, object],
    digest_to_path: Dict[str, Path],
) -> None:
    report_cases = {}
    for raw_case in original_report.get("cases", []) or []:
        if not isinstance(raw_case, dict):
            continue
        capture_record = raw_case.get("capture_corpus")
        if not isinstance(capture_record, dict):
            continue
        label = str(capture_record.get("label") or "").strip()
        if label:
            report_cases[label] = raw_case

    for raw_case in corpus.get("cases", []) or []:
        if not isinstance(raw_case, dict):
            continue
        label = str(raw_case.get("label") or "").strip()
        report_case = report_cases.get(label)
        if not isinstance(report_case, dict):
            continue
        capture_record = report_case.get("capture_corpus")
        export_record = report_case.get("export")
        if isinstance(export_record, dict):
            artifact_digests = report_case.get("artifact_digests")
            if not isinstance(artifact_digests, dict):
                artifact_digests = {}
            payload_path = _path_for_archived_digest_record(
                {"sha256": artifact_digests.get("payload_sha256")},
                digest_to_path,
            )
            if payload_path:
                raw_case["payload_path"] = payload_path
            manifest_path = _path_for_archived_digest_record(
                {"sha256": artifact_digests.get("manifest_sha256")},
                digest_to_path,
            )
            if manifest_path:
                raw_case["manifest_path"] = manifest_path
        if not isinstance(capture_record, dict):
            continue
        image_paths = _paths_for_archived_digest_records(
            capture_record.get("source_images"),
            digest_to_path,
        )
        if image_paths:
            raw_case["image_path"] = image_paths if len(image_paths) > 1 else image_paths[0]
        reference_paths = _paths_for_archived_digest_records(
            capture_record.get("reference_images"),
            digest_to_path,
        )
        if reference_paths:
            raw_case["reference_image_paths"] = reference_paths
        raw_paths = _paths_for_archived_digest_records(
            capture_record.get("raw_images"),
            digest_to_path,
        )
        if raw_paths:
            raw_case["raw_image_paths"] = raw_paths


def _case_replay_comparison(
    original_report: Dict[str, object],
    replay_report: Dict[str, object],
) -> Dict[str, object]:
    original_cases = {
        str(case.get("case_id") or ""): case
        for case in original_report.get("cases", []) or []
        if isinstance(case, dict) and str(case.get("case_id") or "")
    }
    replay_cases = {
        str(case.get("case_id") or ""): case
        for case in replay_report.get("cases", []) or []
        if isinstance(case, dict) and str(case.get("case_id") or "")
    }
    mismatches = []
    for case_id in sorted(set(original_cases) | set(replay_cases)):
        original_case = original_cases.get(case_id)
        replay_case = replay_cases.get(case_id)
        if original_case is None:
            mismatches.append({"case_id": case_id, "reason": "unexpected_replay_case"})
            continue
        if replay_case is None:
            mismatches.append({"case_id": case_id, "reason": "missing_replay_case"})
            continue
        comparisons = (
            ("success", bool(original_case.get("success")), bool(replay_case.get("success"))),
            (
                "failure_reason",
                str(original_case.get("failure_reason") or ""),
                str(replay_case.get("failure_reason") or ""),
            ),
            (
                "payload_sha256",
                str(
                    original_case.get("artifact_digests", {}).get("payload_sha256")
                    if isinstance(original_case.get("artifact_digests"), dict)
                    else ""
                ),
                str(
                    replay_case.get("artifact_digests", {}).get("payload_sha256")
                    if isinstance(replay_case.get("artifact_digests"), dict)
                    else ""
                ),
            ),
        )
        for field, expected, actual in comparisons:
            if expected != actual:
                mismatches.append(
                    {
                        "case_id": case_id,
                        "reason": "{}_mismatch".format(field),
                        "expected": expected,
                        "actual": actual,
                    }
                )
        original_digests = original_case.get("artifact_digests")
        replay_digests = replay_case.get("artifact_digests")
        if isinstance(original_digests, dict) and isinstance(replay_digests, dict):
            expected_restored = str(original_digests.get("restored_sha256") or "")
            actual_restored = str(replay_digests.get("restored_sha256") or "")
            if expected_restored and actual_restored and expected_restored != actual_restored:
                mismatches.append(
                    {
                        "case_id": case_id,
                        "reason": "restored_sha256_mismatch",
                        "expected": expected_restored,
                        "actual": actual_restored,
                    }
                )
    return {
        "case_count_expected": len(original_cases),
        "case_count_replayed": len(replay_cases),
        "matching_case_count": max(0, len(original_cases) - len({str(item.get("case_id")) for item in mismatches})),
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "exact_match": not mismatches,
    }


def replay_transport_evidence_archive(
    transport,
    archive_file: str,
    output_dir: str,
    manifest_file: Optional[str] = None,
    replay_report_file: Optional[str] = None,
    output_file: Optional[str] = None,
    require_successful_report: bool = False,
    require_capture_attachment_report: bool = False,
    require_physical_print_scan: bool = False,
    require_real_camera_perspective_correction: bool = False,
    require_ocr_only_backend: bool = False,
    require_profile_certified: bool = False,
) -> Dict[str, object]:
    """Extract an evidence archive, rerun recovery, and compare replay outcomes."""

    archive_path = Path(str(archive_file)).resolve()
    out_dir = Path(str(output_dir)).resolve()
    extraction_dir = out_dir / "extracted"
    replay_dir = out_dir / "replay"
    out_dir.mkdir(parents=True, exist_ok=True)
    extraction_dir.mkdir(parents=True, exist_ok=True)
    replay_dir.mkdir(parents=True, exist_ok=True)
    replay_output_path = _resolve_output_path(
        replay_report_file,
        replay_dir,
        "transport_reliability_replay_report.json",
    ).resolve()
    replay_summary_path = _resolve_output_path(
        output_file,
        out_dir,
        "transport_evidence_archive_replay_report.json",
    ).resolve()

    verification = verify_transport_evidence_archive(
        archive_file=str(archive_path),
        manifest_file=manifest_file,
        output_file=None,
        require_successful_report=require_successful_report,
        require_capture_attachment_report=require_capture_attachment_report,
        require_physical_print_scan=require_physical_print_scan,
        require_real_camera_perspective_correction=require_real_camera_perspective_correction,
        require_ocr_only_backend=require_ocr_only_backend,
        require_profile_certified=require_profile_certified,
    )

    failures: List[Dict[str, object]] = []
    if not bool(verification.get("success")):
        failures.append(
            {
                "code": "archive_verification_failed",
                "message": "archive verification failed before replay",
                "verification_failure_count": verification.get("summary", {}).get("failure_count")
                if isinstance(verification.get("summary"), dict)
                else None,
            }
        )

    original_report: Dict[str, object] = {}
    replay_report: Optional[Dict[str, object]] = None
    comparison = {
        "case_count_expected": 0,
        "case_count_replayed": 0,
        "matching_case_count": 0,
        "mismatch_count": 0,
        "mismatches": [],
        "exact_match": False,
    }
    extracted_report_path: Optional[Path] = None
    extracted_corpus_path: Optional[Path] = None
    extracted_attachment_path: Optional[Path] = None

    if bool(verification.get("success")):
        with zipfile.ZipFile(str(archive_path), "r") as archive:
            for info in archive.infolist():
                if not _is_safe_archive_member(info.filename):
                    continue
                target = (extraction_dir / info.filename).resolve()
                if not _path_is_within(target, extraction_dir):
                    failures.append(
                        {
                            "code": "unsafe_archive_extraction_path",
                            "message": "archive member would extract outside the replay directory",
                            "archive_path": info.filename,
                        }
                    )
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(info))

        if failures:
            replay_summary = {
                "schema": CAPTURE_EVIDENCE_ARCHIVE_REPLAY_SCHEMA,
                "generated_at_utc": protocol.utc_now_iso(),
                "success": False,
                "archive_file": str(archive_path),
                "archive_sha256": _sha256_file(archive_path),
                "manifest_file": str(Path(str(manifest_file)).resolve()) if manifest_file else None,
                "verification": verification,
                "extraction_dir": str(extraction_dir),
                "replay_report_file": None,
                "archived_report_file": None,
                "archived_capture_corpus_file": None,
                "archived_capture_attachment_report_file": None,
                "comparison": comparison,
                "summary": {
                    "archive_verified": bool(verification.get("success")),
                    "replay_executed": False,
                    "replay_success": False,
                    "case_count_expected": comparison.get("case_count_expected"),
                    "case_count_replayed": comparison.get("case_count_replayed"),
                    "mismatch_count": comparison.get("mismatch_count"),
                    "failure_count": len(failures),
                },
                "failures": failures,
                "certification_boundary": (
                    "Replay proves the archived capture corpus can be re-executed from archived "
                    "bytes with matching case outcomes. It does not broaden any transport claim "
                    "beyond the archived report certification_claims and requested gates."
                ),
            }
            _write_json(replay_summary_path, replay_summary)
            return replay_summary

        archive_manifest = _load_archive_manifest_for_replay(str(archive_path))
        records_by_role = _archive_records_by_role(archive_manifest)
        extracted_report_path = _single_archive_role_path(
            records_by_role,
            "transport_reliability_report",
            extraction_dir,
        )
        extracted_corpus_path = _single_archive_role_path(
            records_by_role,
            "capture_corpus",
            extraction_dir,
        )
        extracted_attachment_path = _single_archive_role_path(
            records_by_role,
            "capture_attachment_report",
            extraction_dir,
        )
        if extracted_report_path is None or not extracted_report_path.exists():
            failures.append(
                {
                    "code": "archived_report_missing",
                    "message": "archive replay requires one transport reliability report",
                }
            )
        else:
            original_report = _load_json(extracted_report_path)

        if extracted_corpus_path is None or not extracted_corpus_path.exists():
            failures.append(
                {
                    "code": "archived_capture_corpus_missing",
                    "message": "archive replay requires an archived capture corpus",
                }
            )
        else:
            digest_to_path = _archive_digest_path_map(
                records_by_role,
                (
                    "capture_image",
                    "attached_capture_image",
                    "source_capture_image",
                    "reference_image",
                    "raw_capture_image",
                    "manifest",
                    "payload",
                    "reported_manifest",
                    "reported_payload",
                    "reported_image",
                    "reported_source_image",
                    "digest_image",
                    "digest_source_image",
                ),
                extraction_dir,
            )
            corpus = _load_json(extracted_corpus_path)
            _rewrite_archive_corpus_paths(
                corpus=corpus,
                corpus_path=extracted_corpus_path,
                attachment_path=extracted_attachment_path,
                digest_to_path=digest_to_path,
            )
            if original_report:
                _rewrite_archive_corpus_paths_from_report(
                    corpus=corpus,
                    original_report=original_report,
                    digest_to_path=digest_to_path,
                )
            _write_json(extracted_corpus_path, corpus)

            if extracted_attachment_path is not None and extracted_attachment_path.exists():
                attachment_report = _load_json(extracted_attachment_path)
                _rewrite_archive_attachment_paths(
                    attachment_report=attachment_report,
                    attachment_path=extracted_attachment_path,
                    corpus_path=extracted_corpus_path,
                    digest_to_path=digest_to_path,
                )
                _write_json(extracted_attachment_path, attachment_report)

            if original_report and extracted_report_path is not None:
                _rewrite_archive_report_paths(
                    report=original_report,
                    report_path=extracted_report_path,
                    corpus_path=extracted_corpus_path,
                    attachment_path=extracted_attachment_path,
                )

    if not failures and original_report and extracted_corpus_path is not None:
        parameters = original_report.get("parameters")
        thresholds = original_report.get("thresholds")
        if not isinstance(parameters, dict):
            parameters = {}
        if not isinstance(thresholds, dict):
            thresholds = {}
        replay_report = certify_transport_reliability(
            transport=transport,
            output_dir=str(replay_dir),
            payload_sizes=[],
            iterations_per_size=1,
            seed=int(original_report.get("seed") or 1729),
            backend=str(parameters.get("backend") or "sidecar"),
            redundancy_copies=int(parameters.get("redundancy_copies") or 2),
            interleave=bool(parameters.get("interleave", True)),
            parity_group_size=int(parameters.get("parity_group_size") or 4),
            filename_prefix=str(parameters.get("filename_prefix") or "replay"),
            report_file=str(replay_output_path),
            require_success_rate=float(thresholds.get("required_success_rate", 1.0)),
            lang=str(parameters.get("lang") or "eng"),
            psm=int(parameters.get("psm") or 6),
            ocr_provider_cmd=parameters.get("ocr_provider_cmd"),
            ocr_provider_timeout_sec=int(parameters.get("ocr_provider_timeout_sec") or 120),
            strict_payload_chars=bool(parameters.get("strict_payload_chars", False)),
            max_list=int(parameters.get("max_list") or 200),
            profile=str(parameters.get("profile") or original_report.get("profile") or RELIABLE_AIRGAP_PROFILE),
            allow_unsafe_profile=bool(parameters.get("allow_unsafe_profile", False)),
            allow_ocr_fallback=bool(parameters.get("allow_ocr_fallback", False)),
            profile_redundancy_threshold_bytes=int(
                parameters.get(
                    "profile_redundancy_threshold_bytes",
                    RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES,
                )
            ),
            distortion_suite=NO_DISTORTION_SUITE,
            distortion_required_success_rate=1.0,
            capture_corpus_file=str(extracted_corpus_path),
            include_generated_corpus=False,
            require_distinct_capture_images=bool(
                parameters.get("require_distinct_capture_images", False)
            ),
            require_real_camera_perspective_correction=bool(
                parameters.get("require_real_camera_perspective_correction", False)
            ),
            require_physical_print_scan=bool(
                parameters.get("require_physical_print_scan", False)
            ),
            capture_attachment_report_file=(
                str(extracted_attachment_path)
                if extracted_attachment_path is not None
                else None
            ),
            require_capture_attachment_report=bool(
                parameters.get("require_capture_attachment_report", False)
            ),
            require_capture_provenance=bool(
                parameters.get("require_capture_provenance", False)
            ),
            capture_required_classification=parameters.get("capture_required_classification"),
            capture_required_success_rate=float(
                thresholds.get("capture_required_success_rate", 1.0)
            ),
            require_ocr_only_backend=bool(parameters.get("require_ocr_only_backend", False)),
            ocr_only_required_success_rate=float(
                thresholds.get("ocr_only_required_success_rate", 1.0)
            ),
        )
        comparison = _case_replay_comparison(original_report, replay_report)
        if not bool(comparison.get("exact_match")):
            failures.append(
                {
                    "code": "replay_case_mismatch",
                    "message": "replayed case outcomes do not match the archived report",
                    "mismatch_count": comparison.get("mismatch_count"),
                }
            )

    replay_summary = {
        "schema": CAPTURE_EVIDENCE_ARCHIVE_REPLAY_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": not failures,
        "archive_file": str(archive_path),
        "archive_sha256": _sha256_file(archive_path),
        "manifest_file": str(Path(str(manifest_file)).resolve()) if manifest_file else None,
        "verification": verification,
        "extraction_dir": str(extraction_dir),
        "replay_report_file": str(replay_output_path) if replay_report is not None else None,
        "archived_report_file": str(extracted_report_path) if extracted_report_path else None,
        "archived_capture_corpus_file": str(extracted_corpus_path) if extracted_corpus_path else None,
        "archived_capture_attachment_report_file": (
            str(extracted_attachment_path) if extracted_attachment_path else None
        ),
        "comparison": comparison,
        "summary": {
            "archive_verified": bool(verification.get("success")),
            "replay_executed": replay_report is not None,
            "replay_success": bool(replay_report.get("success")) if isinstance(replay_report, dict) else False,
            "case_count_expected": comparison.get("case_count_expected"),
            "case_count_replayed": comparison.get("case_count_replayed"),
            "mismatch_count": comparison.get("mismatch_count"),
            "failure_count": len(failures),
        },
        "failures": failures,
        "certification_boundary": (
            "Replay proves the archived capture corpus can be re-executed from archived "
            "bytes with matching case outcomes. It does not broaden any transport claim "
            "beyond the archived report certification_claims and requested gates."
        ),
    }
    _write_json(replay_summary_path, replay_summary)
    return replay_summary


def _claims_by_name(certification_claims: object) -> Dict[str, Dict[str, object]]:
    if not isinstance(certification_claims, dict):
        return {}
    raw_claims = certification_claims.get("claims")
    if not isinstance(raw_claims, list):
        return {}
    claims: Dict[str, Dict[str, object]] = {}
    for raw_claim in raw_claims:
        if not isinstance(raw_claim, dict):
            continue
        name = str(raw_claim.get("claim") or "").strip()
        if name:
            claims[name] = raw_claim
    return claims


def _load_transport_certification_status_source(
    *,
    report_file: Optional[str],
    verification_file: Optional[str],
    archive_file: Optional[str],
    manifest_file: Optional[str],
    verify_archive: bool,
) -> Dict[str, object]:
    supplied = [
        name
        for name, value in (
            ("report_file", report_file),
            ("verification_file", verification_file),
            ("archive_file", archive_file),
        )
        if value is not None and str(value).strip()
    ]
    if len(supplied) != 1:
        raise ValueError(
            "provide exactly one of report_file, verification_file, or archive_file"
        )

    if report_file is not None and str(report_file).strip():
        path = Path(str(report_file)).resolve()
        if not path.exists() or not path.is_file():
            raise ValueError("transport reliability report file does not exist: {}".format(path))
        document = _load_json(path)
        schema = str(document.get("schema") or "").strip()
        if schema != REPORT_SCHEMA:
            raise ValueError(
                "transport reliability report schema must be {}, got {}".format(
                    REPORT_SCHEMA,
                    schema or "<missing>",
                )
            )
        return {
            "source_type": "transport_reliability_report",
            "source_file": str(path),
            "source_sha256": _sha256_file(path),
            "document": document,
        }

    if verification_file is not None and str(verification_file).strip():
        path = Path(str(verification_file)).resolve()
        if not path.exists() or not path.is_file():
            raise ValueError(
                "transport evidence archive verification file does not exist: {}".format(path)
            )
        document = _load_json(path)
        schema = str(document.get("schema") or "").strip()
        if schema != CAPTURE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA:
            raise ValueError(
                "transport evidence archive verification schema must be {}, got {}".format(
                    CAPTURE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA,
                    schema or "<missing>",
                )
            )
        return {
            "source_type": "transport_evidence_archive_verification",
            "source_file": str(path),
            "source_sha256": _sha256_file(path),
            "document": document,
        }

    if archive_file is not None and str(archive_file).strip():
        archive_path = Path(str(archive_file)).resolve()
        if not archive_path.exists() or not archive_path.is_file():
            raise ValueError("transport evidence archive file does not exist: {}".format(archive_path))
        if not bool(verify_archive):
            raise ValueError("archive_file status requires verify_archive=true")
        verification = verify_transport_evidence_archive(
            archive_file=str(archive_path),
            manifest_file=manifest_file,
            require_successful_report=False,
            require_capture_attachment_report=False,
            require_physical_print_scan=False,
            require_real_camera_perspective_correction=False,
            require_ocr_only_backend=False,
            require_profile_certified=False,
        )
        return {
            "source_type": "transport_evidence_archive",
            "source_file": str(archive_path),
            "source_sha256": _sha256_file(archive_path),
            "document": verification,
        }

    raise ValueError("provide a transport certification status source")


def _transport_status_recommended_next_steps(
    claim_records: List[Dict[str, object]],
) -> List[str]:
    claim_map = {str(item.get("claim") or ""): item for item in claim_records}
    steps: List[str] = []
    if not bool(claim_map.get("physical-print-scan", {}).get("certified")):
        steps.append(
            "Attach actual lab/real print-scan images, require attachment lineage, "
            "certify with --require-physical-print-scan, then archive and verify that claim."
        )
    if not bool(claim_map.get("real-camera-perspective-correction", {}).get("certified")):
        steps.append(
            "Attach real raw camera photos plus corrected recovery images, require raw capture "
            "attachment, certify with --require-real-camera-perspective-correction, then archive and verify."
        )
    if not bool(claim_map.get("backend-specific-ocr-only", {}).get("certified")):
        steps.append(
            "Run a sidecar-free OCR-only corpus with a named backend and "
            "--require-ocr-only-backend before making any OCR-only claim."
        )
    return steps


def summarize_transport_certification_status(
    *,
    report_file: Optional[str] = None,
    verification_file: Optional[str] = None,
    archive_file: Optional[str] = None,
    manifest_file: Optional[str] = None,
    output_file: Optional[str] = None,
    verify_archive: bool = False,
    required_certified_claims: Optional[Iterable[str]] = None,
) -> Dict[str, object]:
    """Build a product-facing certification status matrix from measured evidence."""

    required_claims = []
    for raw_claim in required_certified_claims or []:
        claim = str(raw_claim or "").strip()
        if not claim:
            continue
        if claim not in TRANSPORT_CERTIFICATION_CLAIMS:
            raise ValueError(
                "required certified claim must be one of: {}".format(
                    ", ".join(TRANSPORT_CERTIFICATION_CLAIMS)
                )
            )
        if claim not in required_claims:
            required_claims.append(claim)

    source = _load_transport_certification_status_source(
        report_file=report_file,
        verification_file=verification_file,
        archive_file=archive_file,
        manifest_file=manifest_file,
        verify_archive=verify_archive,
    )
    document = source["document"]
    if not isinstance(document, dict):
        raise ValueError("transport certification status source must be a JSON object")

    source_type = str(source.get("source_type") or "")
    source_success = bool(document.get("success"))
    certification_claims = document.get("certification_claims")
    if not isinstance(certification_claims, dict):
        raise ValueError("transport certification source does not contain certification_claims")
    if str(certification_claims.get("schema") or "").strip() != CERTIFICATION_CLAIMS_SCHEMA:
        raise ValueError(
            "certification_claims schema must be {}, got {}".format(
                CERTIFICATION_CLAIMS_SCHEMA,
                str(certification_claims.get("schema") or "").strip() or "<missing>",
            )
        )

    claim_map = _claims_by_name(certification_claims)
    claim_records: List[Dict[str, object]] = []
    certified_claims: List[str] = []
    uncertified_claims: List[str] = []
    for claim_name in TRANSPORT_CERTIFICATION_CLAIMS:
        raw_claim = claim_map.get(claim_name, {})
        certified = bool(raw_claim.get("certified"))
        record = {
            "claim": claim_name,
            "certified": certified,
            "status": str(raw_claim.get("status") or "not-certified"),
            "evidence_level": str(raw_claim.get("evidence_level") or "not-certified"),
            "boundary": str(raw_claim.get("boundary") or ""),
            "required_gates": list(raw_claim.get("required_gates") or []),
            "passed_gates": list(raw_claim.get("passed_gates") or []),
            "missing_gates": list(raw_claim.get("missing_gates") or []),
            "metrics": dict(raw_claim.get("metrics") or {}),
        }
        claim_records.append(record)
        if certified:
            certified_claims.append(claim_name)
        else:
            uncertified_claims.append(claim_name)
    missing_required_claims = [
        claim for claim in required_claims if claim not in certified_claims
    ]
    required_claims_passed = not missing_required_claims

    report_profile = None
    report_profile_certified = None
    report_summary: Dict[str, object] = {}
    if source_type == "transport_reliability_report":
        report_profile = document.get("profile")
        report_profile_certified = bool(document.get("profile_certified"))
        report_summary = document.get("summary") if isinstance(document.get("summary"), dict) else {}
    else:
        gates = document.get("certification_gates")
        if isinstance(gates, dict):
            report_profile = gates.get("profile")
            report_profile_certified = bool(gates.get("profile_certified"))
        report_summary = document.get("summary") if isinstance(document.get("summary"), dict) else {}

    status = {
        "schema": CERTIFICATION_STATUS_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": bool(source_success and certification_claims and required_claims_passed),
        "source": {
            "type": source_type,
            "file": source.get("source_file"),
            "sha256": source.get("source_sha256"),
            "archive_verified": (
                bool(document.get("success"))
                if source_type
                in (
                    "transport_evidence_archive",
                    "transport_evidence_archive_verification",
                )
                else None
            ),
            "manifest_file": str(Path(str(manifest_file)).resolve())
            if manifest_file is not None and str(manifest_file).strip()
            else document.get("manifest_file"),
        },
        "report": {
            "success": source_success,
            "profile": report_profile,
            "profile_certified": report_profile_certified,
            "summary": report_summary,
        },
        "summary": {
            "certified_claim_count": len(certified_claims),
            "certified_claims": certified_claims,
            "uncertified_claims": uncertified_claims,
            "highest_evidence_level": certification_claims.get("summary", {}).get(
                "highest_evidence_level"
            )
            if isinstance(certification_claims.get("summary"), dict)
            else "not-certified",
            "production_airgap_ready": "generated-page-sidecar" in certified_claims
            and report_profile == RELIABLE_AIRGAP_PROFILE
            and bool(report_profile_certified),
            "real_camera_ready": "real-camera-perspective-correction" in certified_claims,
            "physical_print_scan_ready": "physical-print-scan" in certified_claims,
            "ocr_only_ready": "backend-specific-ocr-only" in certified_claims,
            "generic_ocr_fallback_ready": False,
            "required_certified_claims": required_claims,
            "required_certified_claims_passed": required_claims_passed,
            "missing_required_certified_claims": missing_required_claims,
        },
        "claim_gate": {
            "required": bool(required_claims),
            "required_certified_claims": required_claims,
            "passed": required_claims_passed,
            "missing_required_certified_claims": missing_required_claims,
            "certification_boundary": (
                "This gate checks only certification_claims rows already present in the "
                "measured report or verified archive. It does not create new evidence."
            ),
        },
        "claims": claim_records,
        "recommended_next_steps": _transport_status_recommended_next_steps(claim_records),
        "certification_boundary": (
            "This status artifact is derived from measured report/archive claims only. "
            "It does not certify any transport mode whose own claim record is not certified=true."
        ),
    }
    if output_file is not None and str(output_file).strip():
        _write_json(Path(str(output_file)).resolve(), status)
    return status


def _capture_pipeline_required_claims(
    *,
    require_physical_print_scan: bool,
    require_real_camera_perspective_correction: bool,
    require_ocr_only_backend: bool,
    required_certified_claims: Optional[Iterable[str]],
) -> List[str]:
    claims: List[str] = []
    for claim, required in (
        ("physical-print-scan", bool(require_physical_print_scan)),
        (
            "real-camera-perspective-correction",
            bool(require_real_camera_perspective_correction),
        ),
        ("backend-specific-ocr-only", bool(require_ocr_only_backend)),
    ):
        if required and claim not in claims:
            claims.append(claim)
    for raw_claim in required_certified_claims or []:
        claim = str(raw_claim or "").strip()
        if not claim:
            continue
        if claim not in TRANSPORT_CERTIFICATION_CLAIMS:
            raise ValueError(
                "required certified claim must be one of: {}".format(
                    ", ".join(TRANSPORT_CERTIFICATION_CLAIMS)
                )
            )
        if claim not in claims:
            claims.append(claim)
    return claims


def _capture_pipeline_step(
    name: str,
    *,
    result: Optional[Dict[str, object]] = None,
    output_file: Optional[Path] = None,
    error: Optional[BaseException] = None,
    skipped: bool = False,
    skip_reason: Optional[str] = None,
) -> Dict[str, object]:
    file_sha256 = _sha256_file(output_file) if output_file is not None else None
    summary = result.get("summary") if isinstance(result, dict) else None
    return {
        "name": name,
        "success": bool(result.get("success")) if isinstance(result, dict) else False,
        "skipped": bool(skipped),
        "skip_reason": str(skip_reason or "") or None,
        "schema": str(result.get("schema") or "") if isinstance(result, dict) else None,
        "output_file": str(output_file) if output_file is not None else None,
        "output_sha256": file_sha256,
        "summary": summary if isinstance(summary, dict) else {},
        "error": str(error) if error is not None else None,
    }


def certify_capture_evidence_pipeline(
    transport,
    capture_corpus_file: str,
    output_dir: str,
    *,
    capture_return_package_file: Optional[str] = None,
    capture_return_package_report_file: Optional[str] = None,
    require_capture_return_manifest: bool = False,
    require_capture_return_file_inventory: bool = False,
    require_capture_return_package_report: bool = False,
    capture_root: Optional[str] = None,
    raw_capture_root: Optional[str] = None,
    capture_medium: Optional[str] = None,
    capture_metadata: Optional[Dict[str, object]] = None,
    capture_metadata_manifest_file: Optional[str] = None,
    require_all_case_labels: bool = True,
    profile: str = RELIABLE_AIRGAP_PROFILE,
    backend: str = "sidecar",
    allow_ocr_fallback: bool = False,
    allow_unsafe_profile: bool = False,
    profile_redundancy_threshold_bytes: int = RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES,
    redundancy_copies: int = 2,
    interleave: bool = True,
    parity_group_size: int = 4,
    require_captures: bool = True,
    require_raw_captures: bool = False,
    require_distinct_capture_images: bool = True,
    require_capture_attachment_report: bool = True,
    require_capture_provenance: bool = False,
    capture_required_classification: Optional[str] = None,
    capture_required_success_rate: Optional[float] = None,
    require_success_rate: float = 1.0,
    require_physical_print_scan: bool = False,
    require_real_camera_perspective_correction: bool = False,
    require_ocr_only_backend: bool = False,
    ocr_only_required_success_rate: Optional[float] = None,
    require_profile_certified: Optional[bool] = None,
    required_certified_claims: Optional[Iterable[str]] = None,
    lang: str = "eng",
    psm: int = 6,
    ocr_provider_cmd: Optional[str] = None,
    ocr_provider_timeout_sec: int = 120,
    strict_payload_chars: bool = False,
    max_list: int = 200,
    kit_manifest_file: Optional[str] = None,
    capture_return_extraction_report_file: Optional[str] = None,
    ingestion_report_file: Optional[str] = None,
    attachment_report_file: Optional[str] = None,
    validation_report_file: Optional[str] = None,
    certification_report_file: Optional[str] = None,
    archive_file: Optional[str] = None,
    archive_manifest_file: Optional[str] = None,
    verification_report_file: Optional[str] = None,
    replay_output_dir: Optional[str] = None,
    replay_report_file: Optional[str] = None,
    replay_summary_file: Optional[str] = None,
    status_report_file: Optional[str] = None,
    pipeline_report_file: Optional[str] = None,
) -> Dict[str, object]:
    """Run the complete operator-capture evidence chain with one gated contract."""

    corpus_path = Path(str(capture_corpus_file)).resolve()
    if not corpus_path.exists() or not corpus_path.is_file():
        raise ValueError("capture corpus file does not exist: {}".format(corpus_path))

    out_dir = Path(str(output_dir)).resolve()
    raw_kit_manifest = str(kit_manifest_file or "").strip()
    resolved_kit_manifest_file: Optional[str] = None
    if raw_kit_manifest:
        kit_candidate = Path(raw_kit_manifest)
        if not kit_candidate.is_absolute():
            cwd_candidate = kit_candidate.resolve()
            kit_candidate = cwd_candidate if cwd_candidate.exists() else corpus_path.parent / kit_candidate
        resolved_kit_manifest_file = str(kit_candidate.resolve())
    return_package_dir = out_dir / "return_package"
    ingest_dir = out_dir / "ingest"
    attach_dir = out_dir / "attach"
    validate_dir = out_dir / "validate"
    cert_dir = out_dir / "cert"
    archive_dir = out_dir / "evidence_archive"
    replay_dir = _resolve_output_path(
        replay_output_dir,
        out_dir,
        "evidence_replay",
    ).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if capture_return_package_file is not None and str(capture_return_package_file).strip():
        return_package_dir.mkdir(parents=True, exist_ok=True)
        ingest_dir.mkdir(parents=True, exist_ok=True)
    if capture_root is not None and str(capture_root).strip():
        ingest_dir.mkdir(parents=True, exist_ok=True)
    attach_dir.mkdir(parents=True, exist_ok=True)
    validate_dir.mkdir(parents=True, exist_ok=True)
    cert_dir.mkdir(parents=True, exist_ok=True)
    archive_dir.mkdir(parents=True, exist_ok=True)
    replay_dir.mkdir(parents=True, exist_ok=True)

    ingestion_path = _resolve_output_path(
        ingestion_report_file,
        ingest_dir,
        "transport_capture_corpus_ingestion_report.json",
    ).resolve()
    attachment_path = _resolve_output_path(
        attachment_report_file,
        attach_dir,
        "transport_capture_attachment_report.json",
    ).resolve()
    validation_path = _resolve_output_path(
        validation_report_file,
        validate_dir,
        "transport_capture_validation_report.json",
    ).resolve()
    certification_path = _resolve_output_path(
        certification_report_file,
        cert_dir,
        "transport_reliability_report.json",
    ).resolve()
    archive_path = _resolve_output_path(
        archive_file,
        archive_dir,
        "transport_capture_evidence_archive.zip",
    ).resolve()
    manifest_path = _resolve_output_path(
        archive_manifest_file,
        archive_dir,
        "transport_capture_evidence_archive_manifest.json",
    ).resolve()
    verification_path = _resolve_output_path(
        verification_report_file,
        archive_dir,
        "transport_evidence_archive_verification_report.json",
    ).resolve()
    replay_report_path = _resolve_output_path(
        replay_report_file,
        replay_dir / "replay",
        "transport_reliability_replay_report.json",
    ).resolve()
    replay_summary_path = _resolve_output_path(
        replay_summary_file,
        replay_dir,
        "transport_evidence_archive_replay_report.json",
    ).resolve()
    return_package_report_path = _resolve_output_path(
        capture_return_extraction_report_file,
        return_package_dir,
        "transport_capture_return_package_extraction_report.json",
    ).resolve()
    status_path = _resolve_output_path(
        status_report_file,
        archive_dir,
        "transport_certification_status.json",
    ).resolve()
    pipeline_path = _resolve_output_path(
        pipeline_report_file,
        out_dir,
        "transport_capture_certification_pipeline_report.json",
    ).resolve()

    inferred_capture_medium = capture_medium
    if inferred_capture_medium is None:
        if require_physical_print_scan:
            inferred_capture_medium = "print-scan"
        elif require_real_camera_perspective_correction:
            inferred_capture_medium = "camera-photo"

    require_profile_gate = (
        bool(profile == RELIABLE_AIRGAP_PROFILE and not bool(require_ocr_only_backend))
        if require_profile_certified is None
        else bool(require_profile_certified)
    )
    claim_gate_claims = _capture_pipeline_required_claims(
        require_physical_print_scan=bool(require_physical_print_scan),
        require_real_camera_perspective_correction=bool(
            require_real_camera_perspective_correction
        ),
        require_ocr_only_backend=bool(require_ocr_only_backend),
        required_certified_claims=required_certified_claims,
    )

    steps: List[Dict[str, object]] = []
    artifacts: Dict[str, object] = {}
    failures: List[Dict[str, object]] = []
    executed = True
    blocked_by_step: Optional[str] = None

    def mark_failure(step_name: str, message: str) -> None:
        nonlocal blocked_by_step
        if blocked_by_step is None:
            blocked_by_step = step_name
        failures.append({"step": step_name, "message": message})

    effective_capture_root = capture_root
    effective_raw_capture_root = raw_capture_root
    effective_metadata_manifest_file = capture_metadata_manifest_file

    return_package_result: Optional[Dict[str, object]] = None
    if capture_return_package_file is not None and str(capture_return_package_file).strip():
        try:
            return_package_result = _safe_extract_capture_return_package(
                package_file=str(capture_return_package_file),
                output_dir=return_package_dir,
                expected_capture_corpus_file=str(corpus_path),
                expected_kit_manifest_file=resolved_kit_manifest_file,
                expected_capture_return_package_report_file=(
                    str(capture_return_package_report_file)
                    if capture_return_package_report_file is not None
                    else None
                ),
                require_capture_return_manifest=bool(require_capture_return_manifest),
                require_capture_return_file_inventory=bool(
                    require_capture_return_file_inventory
                ),
                require_capture_return_package_report=bool(
                    require_capture_return_package_report
                ),
                report_file=str(return_package_report_path),
            )
            steps.append(
                _capture_pipeline_step(
                    "extract-capture-return-package",
                    result=return_package_result,
                    output_file=return_package_report_path,
                )
            )
            artifacts["capture_return_package_extraction_report_file"] = str(
                return_package_report_path
            )
            if not bool(return_package_result.get("success")):
                executed = False
                mark_failure(
                    "extract-capture-return-package",
                    "capture return package extraction failed",
                )
            else:
                if (
                    not (effective_capture_root is not None and str(effective_capture_root).strip())
                    and return_package_result.get("capture_root")
                ):
                    effective_capture_root = str(return_package_result.get("capture_root"))
                if (
                    not (
                        effective_raw_capture_root is not None
                        and str(effective_raw_capture_root).strip()
                    )
                    and return_package_result.get("raw_capture_root")
                ):
                    effective_raw_capture_root = str(
                        return_package_result.get("raw_capture_root")
                    )
                if (
                    not (
                        effective_metadata_manifest_file is not None
                        and str(effective_metadata_manifest_file).strip()
                    )
                    and return_package_result.get("capture_metadata_manifest_file")
                ):
                    effective_metadata_manifest_file = str(
                        return_package_result.get("capture_metadata_manifest_file")
                    )
        except Exception as exc:
            executed = False
            steps.append(
                _capture_pipeline_step(
                    "extract-capture-return-package",
                    output_file=return_package_report_path,
                    error=exc,
                )
            )
            mark_failure("extract-capture-return-package", str(exc))

    ingestion_result: Optional[Dict[str, object]] = None
    if executed and effective_capture_root is not None and str(effective_capture_root).strip():
        try:
            ingestion_result = ingest_capture_corpus(
                capture_corpus_file=str(corpus_path),
                capture_root=str(effective_capture_root),
                output_dir=str(ingest_dir),
                report_file=str(ingestion_path),
                kit_manifest_file=kit_manifest_file,
                raw_capture_root=effective_raw_capture_root,
                classification=capture_required_classification,
                capture_medium=inferred_capture_medium,
                capture_metadata=capture_metadata,
                capture_metadata_manifest_file=effective_metadata_manifest_file,
                require_captures=bool(require_captures),
                require_raw_captures=bool(require_raw_captures),
                require_all_case_labels=bool(require_all_case_labels),
                update_corpus=True,
                update_kit_manifest=True,
            )
            steps.append(
                _capture_pipeline_step(
                    "ingest-capture-corpus",
                    result=ingestion_result,
                    output_file=ingestion_path,
                )
            )
            artifacts["capture_ingestion_report_file"] = str(ingestion_path)
            if not bool(ingestion_result.get("success")):
                executed = False
                mark_failure("ingest-capture-corpus", "capture ingestion failed")
        except Exception as exc:
            executed = False
            steps.append(
                _capture_pipeline_step(
                    "ingest-capture-corpus",
                    output_file=ingestion_path,
                    error=exc,
                )
            )
            mark_failure("ingest-capture-corpus", str(exc))
    elif not executed and capture_return_package_file is not None and str(capture_return_package_file).strip():
        if blocked_by_step == "extract-capture-return-package":
            steps.append(
                _capture_pipeline_step(
                    "ingest-capture-corpus",
                    output_file=ingestion_path,
                    skipped=True,
                    skip_reason="{} failed".format(blocked_by_step),
                )
            )

    attachment_result: Optional[Dict[str, object]] = None
    if executed:
        try:
            attachment_result = attach_capture_corpus(
                capture_corpus_file=str(corpus_path),
                output_dir=str(attach_dir),
                report_file=str(attachment_path),
                kit_manifest_file=kit_manifest_file,
                require_captures=bool(require_captures),
                require_distinct_capture_images=bool(require_distinct_capture_images),
                require_raw_captures=bool(require_raw_captures),
                update_corpus=True,
                update_kit_manifest=True,
            )
            steps.append(
                _capture_pipeline_step(
                    "attach-capture-corpus",
                    result=attachment_result,
                    output_file=attachment_path,
                )
            )
            artifacts["capture_attachment_report_file"] = str(attachment_path)
            if not bool(attachment_result.get("success")):
                executed = False
                mark_failure("attach-capture-corpus", "capture attachment failed")
        except Exception as exc:
            executed = False
            steps.append(
                _capture_pipeline_step(
                    "attach-capture-corpus",
                    output_file=attachment_path,
                    error=exc,
                )
            )
            mark_failure("attach-capture-corpus", str(exc))
    else:
        steps.append(
            _capture_pipeline_step(
                "attach-capture-corpus",
                output_file=attachment_path,
                skipped=True,
                skip_reason="{} failed".format(blocked_by_step or "ingest-capture-corpus"),
            )
        )

    validation_result: Optional[Dict[str, object]] = None
    if executed:
        try:
            validation_result = validate_capture_corpus(
                capture_corpus_file=str(corpus_path),
                output_file=str(validation_path),
                profile=profile,
                backend=backend,
                allow_ocr_fallback=bool(allow_ocr_fallback),
                profile_redundancy_threshold_bytes=int(profile_redundancy_threshold_bytes),
                require_captures=bool(require_captures),
                require_distinct_capture_images=bool(require_distinct_capture_images),
                require_raw_captures=bool(require_raw_captures),
                capture_attachment_report_file=str(attachment_path),
                require_capture_attachment_report=bool(require_capture_attachment_report),
                require_capture_provenance=bool(require_capture_provenance),
                capture_required_classification=capture_required_classification,
                require_physical_print_scan=bool(require_physical_print_scan),
                require_real_camera_perspective_correction=bool(
                    require_real_camera_perspective_correction
                ),
                require_ocr_only_backend=bool(require_ocr_only_backend),
            )
            steps.append(
                _capture_pipeline_step(
                    "validate-capture-corpus",
                    result=validation_result,
                    output_file=validation_path,
                )
            )
            artifacts["capture_validation_report_file"] = str(validation_path)
            if not bool(validation_result.get("success")):
                executed = False
                mark_failure("validate-capture-corpus", "capture validation failed")
        except Exception as exc:
            executed = False
            steps.append(
                _capture_pipeline_step(
                    "validate-capture-corpus",
                    output_file=validation_path,
                    error=exc,
                )
            )
            mark_failure("validate-capture-corpus", str(exc))
    else:
        steps.append(
            _capture_pipeline_step(
                "validate-capture-corpus",
                output_file=validation_path,
                skipped=True,
                skip_reason="{} failed".format(blocked_by_step or "attach-capture-corpus"),
            )
        )

    cert_result: Optional[Dict[str, object]] = None
    if executed:
        try:
            cert_result = certify_transport_reliability(
                transport=transport,
                output_dir=str(cert_dir),
                payload_sizes=[],
                iterations_per_size=1,
                backend=backend,
                redundancy_copies=int(redundancy_copies),
                interleave=bool(interleave),
                parity_group_size=int(parity_group_size),
                report_file=str(certification_path),
                require_success_rate=float(require_success_rate),
                lang=lang,
                psm=int(psm),
                ocr_provider_cmd=ocr_provider_cmd,
                ocr_provider_timeout_sec=int(ocr_provider_timeout_sec),
                strict_payload_chars=bool(strict_payload_chars),
                max_list=int(max_list),
                profile=profile,
                allow_unsafe_profile=bool(allow_unsafe_profile),
                allow_ocr_fallback=bool(allow_ocr_fallback),
                profile_redundancy_threshold_bytes=int(profile_redundancy_threshold_bytes),
                distortion_suite=NO_DISTORTION_SUITE,
                capture_corpus_file=str(corpus_path),
                include_generated_corpus=False,
                require_distinct_capture_images=bool(require_distinct_capture_images),
                require_real_camera_perspective_correction=bool(
                    require_real_camera_perspective_correction
                ),
                require_physical_print_scan=bool(require_physical_print_scan),
                capture_attachment_report_file=str(attachment_path),
                require_capture_attachment_report=bool(require_capture_attachment_report),
                require_capture_provenance=bool(require_capture_provenance),
                capture_required_classification=capture_required_classification,
                capture_required_success_rate=capture_required_success_rate,
                require_ocr_only_backend=bool(require_ocr_only_backend),
                ocr_only_required_success_rate=ocr_only_required_success_rate,
            )
            steps.append(
                _capture_pipeline_step(
                    "certify",
                    result=cert_result,
                    output_file=certification_path,
                )
            )
            artifacts["transport_reliability_report_file"] = str(certification_path)
            if not bool(cert_result.get("success")):
                executed = False
                mark_failure("certify", "transport certification failed")
        except Exception as exc:
            executed = False
            steps.append(
                _capture_pipeline_step(
                    "certify",
                    output_file=certification_path,
                    error=exc,
                )
            )
            mark_failure("certify", str(exc))
    else:
        steps.append(
            _capture_pipeline_step(
                "certify",
                output_file=certification_path,
                skipped=True,
                skip_reason="{} failed".format(blocked_by_step or "validate-capture-corpus"),
            )
        )

    archive_result: Optional[Dict[str, object]] = None
    if executed:
        try:
            archive_result = archive_transport_evidence(
                report_file=str(certification_path),
                output_dir=str(archive_dir),
                capture_corpus_file=str(corpus_path),
                capture_attachment_report_file=str(attachment_path),
                archive_file=str(archive_path),
                manifest_file=str(manifest_path),
                require_successful_report=True,
                require_capture_attachment_report=bool(require_capture_attachment_report),
                require_physical_print_scan=bool(require_physical_print_scan),
                require_real_camera_perspective_correction=bool(
                    require_real_camera_perspective_correction
                ),
                require_ocr_only_backend=bool(require_ocr_only_backend),
                require_profile_certified=bool(require_profile_gate),
            )
            steps.append(
                _capture_pipeline_step(
                    "archive-evidence",
                    result=archive_result,
                    output_file=manifest_path,
                )
            )
            artifacts["transport_evidence_archive_file"] = str(archive_path)
            artifacts["transport_evidence_archive_manifest_file"] = str(manifest_path)
            if not bool(archive_result.get("success")):
                executed = False
                mark_failure("archive-evidence", "transport evidence archive failed")
        except Exception as exc:
            executed = False
            steps.append(
                _capture_pipeline_step(
                    "archive-evidence",
                    output_file=manifest_path,
                    error=exc,
                )
            )
            mark_failure("archive-evidence", str(exc))
    else:
        steps.append(
            _capture_pipeline_step(
                "archive-evidence",
                output_file=manifest_path,
                skipped=True,
                skip_reason="{} failed".format(blocked_by_step or "certify"),
            )
        )

    verification_result: Optional[Dict[str, object]] = None
    if executed:
        try:
            verification_result = verify_transport_evidence_archive(
                archive_file=str(archive_path),
                manifest_file=str(manifest_path),
                output_file=str(verification_path),
                require_successful_report=True,
                require_capture_attachment_report=bool(require_capture_attachment_report),
                require_physical_print_scan=bool(require_physical_print_scan),
                require_real_camera_perspective_correction=bool(
                    require_real_camera_perspective_correction
                ),
                require_ocr_only_backend=bool(require_ocr_only_backend),
                require_profile_certified=bool(require_profile_gate),
            )
            steps.append(
                _capture_pipeline_step(
                    "verify-evidence-archive",
                    result=verification_result,
                    output_file=verification_path,
                )
            )
            artifacts["transport_evidence_archive_verification_file"] = str(verification_path)
            if not bool(verification_result.get("success")):
                executed = False
                mark_failure("verify-evidence-archive", "archive verification failed")
        except Exception as exc:
            executed = False
            steps.append(
                _capture_pipeline_step(
                    "verify-evidence-archive",
                    output_file=verification_path,
                    error=exc,
                )
            )
            mark_failure("verify-evidence-archive", str(exc))
    else:
        steps.append(
            _capture_pipeline_step(
                "verify-evidence-archive",
                output_file=verification_path,
                skipped=True,
                skip_reason="{} failed".format(blocked_by_step or "archive-evidence"),
            )
        )

    replay_result: Optional[Dict[str, object]] = None
    if executed:
        try:
            replay_result = replay_transport_evidence_archive(
                transport=transport,
                archive_file=str(archive_path),
                output_dir=str(replay_dir),
                manifest_file=str(manifest_path),
                replay_report_file=str(replay_report_path),
                output_file=str(replay_summary_path),
                require_successful_report=True,
                require_capture_attachment_report=bool(require_capture_attachment_report),
                require_physical_print_scan=bool(require_physical_print_scan),
                require_real_camera_perspective_correction=bool(
                    require_real_camera_perspective_correction
                ),
                require_ocr_only_backend=bool(require_ocr_only_backend),
                require_profile_certified=bool(require_profile_gate),
            )
            steps.append(
                _capture_pipeline_step(
                    "replay-evidence-archive",
                    result=replay_result,
                    output_file=replay_summary_path,
                )
            )
            artifacts["transport_evidence_archive_replay_file"] = str(replay_summary_path)
            artifacts["transport_reliability_replay_report_file"] = str(replay_report_path)
            if not bool(replay_result.get("success")):
                executed = False
                mark_failure("replay-evidence-archive", "archive replay failed")
        except Exception as exc:
            executed = False
            steps.append(
                _capture_pipeline_step(
                    "replay-evidence-archive",
                    output_file=replay_summary_path,
                    error=exc,
                )
            )
            mark_failure("replay-evidence-archive", str(exc))
    else:
        steps.append(
            _capture_pipeline_step(
                "replay-evidence-archive",
                output_file=replay_summary_path,
                skipped=True,
                skip_reason="{} failed".format(blocked_by_step or "verify-evidence-archive"),
            )
        )

    status_result: Optional[Dict[str, object]] = None
    if executed:
        try:
            status_result = summarize_transport_certification_status(
                verification_file=str(verification_path),
                output_file=str(status_path),
                required_certified_claims=claim_gate_claims,
            )
            steps.append(
                _capture_pipeline_step(
                    "certification-status",
                    result=status_result,
                    output_file=status_path,
                )
            )
            artifacts["transport_certification_status_file"] = str(status_path)
            if not bool(status_result.get("success")):
                executed = False
                mark_failure("certification-status", "certification claim gate failed")
        except Exception as exc:
            executed = False
            steps.append(
                _capture_pipeline_step(
                    "certification-status",
                    output_file=status_path,
                    error=exc,
                )
            )
            mark_failure("certification-status", str(exc))
    else:
        steps.append(
            _capture_pipeline_step(
                "certification-status",
                output_file=status_path,
                skipped=True,
                skip_reason="{} failed".format(blocked_by_step or "replay-evidence-archive"),
            )
        )

    artifacts["pipeline_report_file"] = str(pipeline_path)
    report = {
        "schema": CAPTURE_CERTIFICATION_PIPELINE_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": bool(executed and not failures),
        "capture_corpus_file": str(corpus_path),
        "capture_corpus_sha256": _sha256_file(corpus_path),
        "output_dir": str(out_dir),
        "parameters": {
            "capture_return_package_file": (
                str(capture_return_package_file)
                if capture_return_package_file is not None
                else None
            ),
            "capture_return_package_report_file": (
                str(capture_return_package_report_file)
                if capture_return_package_report_file is not None
                else None
            ),
            "require_capture_return_manifest": bool(require_capture_return_manifest),
            "require_capture_return_file_inventory": bool(
                require_capture_return_file_inventory
            ),
            "require_capture_return_package_report": bool(
                require_capture_return_package_report
            ),
            "capture_return_manifest_file": (
                return_package_result.get("capture_return_manifest_file")
                if isinstance(return_package_result, dict)
                else None
            ),
            "capture_root": str(capture_root) if capture_root is not None else None,
            "raw_capture_root": str(raw_capture_root) if raw_capture_root is not None else None,
            "effective_capture_root": (
                str(effective_capture_root) if effective_capture_root is not None else None
            ),
            "effective_raw_capture_root": (
                str(effective_raw_capture_root)
                if effective_raw_capture_root is not None
                else None
            ),
            "capture_medium": inferred_capture_medium,
            "capture_metadata": dict(capture_metadata or {}),
            "capture_metadata_manifest_file": (
                str(capture_metadata_manifest_file)
                if capture_metadata_manifest_file is not None
                else None
            ),
            "effective_capture_metadata_manifest_file": (
                str(effective_metadata_manifest_file)
                if effective_metadata_manifest_file is not None
                else None
            ),
            "require_all_case_labels": bool(require_all_case_labels),
            "profile": profile,
            "backend": backend,
            "allow_ocr_fallback": bool(allow_ocr_fallback),
            "allow_unsafe_profile": bool(allow_unsafe_profile),
            "profile_redundancy_threshold_bytes": int(profile_redundancy_threshold_bytes),
            "redundancy_copies": int(redundancy_copies),
            "interleave": bool(interleave),
            "parity_group_size": int(parity_group_size),
            "require_captures": bool(require_captures),
            "require_raw_captures": bool(require_raw_captures),
            "require_distinct_capture_images": bool(require_distinct_capture_images),
            "require_capture_attachment_report": bool(require_capture_attachment_report),
            "require_capture_provenance": bool(require_capture_provenance),
            "capture_required_classification": capture_required_classification,
            "capture_required_success_rate": capture_required_success_rate,
            "require_success_rate": float(require_success_rate),
            "require_physical_print_scan": bool(require_physical_print_scan),
            "require_real_camera_perspective_correction": bool(
                require_real_camera_perspective_correction
            ),
            "require_ocr_only_backend": bool(require_ocr_only_backend),
            "ocr_only_required_success_rate": ocr_only_required_success_rate,
            "require_profile_certified": bool(require_profile_gate),
            "required_certified_claims": claim_gate_claims,
        },
        "summary": {
            "step_count": len(steps),
            "completed_step_count": len(
                [step for step in steps if bool(step.get("success")) and not step.get("skipped")]
            ),
            "skipped_step_count": len([step for step in steps if bool(step.get("skipped"))]),
            "failure_count": len(failures),
            "failed_steps": [str(item.get("step")) for item in failures],
            "capture_ingested": bool(
                ingestion_result.get("success")
                if isinstance(ingestion_result, dict)
                else False
            ),
            "capture_return_package_extracted": bool(
                return_package_result.get("success")
                if isinstance(return_package_result, dict)
                else False
            ),
            "capture_return_manifest_validated": bool(
                return_package_result.get("summary", {}).get(
                    "capture_return_manifest_validated"
                )
                if isinstance(return_package_result, dict)
                and isinstance(return_package_result.get("summary"), dict)
                else False
            ),
            "capture_return_manifest_required": bool(
                return_package_result.get("summary", {}).get(
                    "capture_return_manifest_required"
                )
                if isinstance(return_package_result, dict)
                and isinstance(return_package_result.get("summary"), dict)
                else require_capture_return_manifest
            ),
            "capture_return_manifest_file_inventory_validated": bool(
                return_package_result.get("summary", {}).get(
                    "capture_return_manifest_file_inventory_validated"
                )
                if isinstance(return_package_result, dict)
                and isinstance(return_package_result.get("summary"), dict)
                else False
            ),
            "capture_return_manifest_file_inventory_gate_required": bool(
                return_package_result.get("summary", {}).get(
                    "capture_return_manifest_file_inventory_gate_required"
                )
                if isinstance(return_package_result, dict)
                and isinstance(return_package_result.get("summary"), dict)
                else require_capture_return_file_inventory
            ),
            "capture_return_package_report_validated": bool(
                return_package_result.get("summary", {}).get(
                    "capture_return_package_report_validated"
                )
                if isinstance(return_package_result, dict)
                and isinstance(return_package_result.get("summary"), dict)
                else False
            ),
            "capture_return_package_report_required": bool(
                return_package_result.get("summary", {}).get(
                    "capture_return_package_report_required"
                )
                if isinstance(return_package_result, dict)
                and isinstance(return_package_result.get("summary"), dict)
                else require_capture_return_package_report
            ),
            "archive_verified": bool(
                verification_result.get("success")
                if isinstance(verification_result, dict)
                else False
            ),
            "archive_replayed": bool(
                replay_result.get("success")
                if isinstance(replay_result, dict)
                else False
            ),
            "archive_replay_mismatch_count": (
                replay_result.get("comparison", {}).get("mismatch_count")
                if isinstance(replay_result, dict)
                and isinstance(replay_result.get("comparison"), dict)
                else None
            ),
            "status_claim_gate_passed": bool(
                status_result.get("claim_gate", {}).get("passed")
                if isinstance(status_result, dict)
                and isinstance(status_result.get("claim_gate"), dict)
                else False
            ),
            "certified_claims": (
                status_result.get("summary", {}).get("certified_claims", [])
                if isinstance(status_result, dict)
                and isinstance(status_result.get("summary"), dict)
                else []
            ),
        },
        "artifacts": artifacts,
        "steps": steps,
        "failures": failures,
        "certification_boundary": (
            "This pipeline only orchestrates existing fail-closed capture evidence steps. "
            "It does not certify a medium unless the measured transport report, verified "
            "archive, and certification-status claim gate all certify that exact claim."
        ),
    }
    _write_json(pipeline_path, report)
    return report


def _run_generated_corpus_cases(
    transport,
    cases_dir: Path,
    sizes: List[int],
    iterations: int,
    seed: int,
    backend: str,
    redundancy_copies: int,
    interleave: bool,
    parity_group_size: int,
    filename_prefix: str,
    lang: str,
    psm: int,
    ocr_provider_cmd: Optional[str],
    ocr_provider_timeout_sec: int,
    strict_payload_chars: bool,
    max_list: int,
    distortion_suite_name: str,
    distortion_definitions: List[Dict[str, object]],
    require_ocr_only_backend: bool,
) -> List[Dict[str, object]]:
    records = []
    case_index = 0
    for payload_size in sizes:
        for iteration in range(iterations):
            case_index += 1
            case_id = "case_{:04d}_size_{:08d}_iter_{:02d}".format(
                case_index,
                int(payload_size),
                iteration + 1,
            )
            case_dir = cases_dir / case_id
            package_dir = case_dir / "package"
            payload_path = case_dir / "payload.bin"
            restored_path = case_dir / "restored.bin"
            ocr_text_output = case_dir / "ocr_text.txt"
            analyze_report = case_dir / "analyze_report.json"
            missing_file = case_dir / "missing_chunks.csv"
            case_dir.mkdir(parents=True, exist_ok=True)

            payload = _deterministic_payload(int(payload_size), int(seed), case_index)
            payload_path.write_bytes(payload)
            payload_sha256 = protocol.sha256_hex(payload)

            export_result = None
            base_export_result = None
            recover_result = None
            exception = None
            start = time.perf_counter()
            try:
                base_export_result = transport.export_artifact(
                    input_file=str(payload_path),
                    output_dir=str(package_dir),
                    filename_prefix=filename_prefix,
                    redundancy_copies=redundancy_copies,
                    interleave=interleave,
                    parity_group_size=parity_group_size,
                )
                base_image_paths = [
                    Path(str(image_path))
                    for image_path in base_export_result.get("images", []) or []
                ]
                manifest_path = str(base_export_result.get("manifest_path") or "")
                if int(base_export_result.get("image_count", 0) or 0) > 0:
                    for distortion_index, distortion_definition in enumerate(distortion_definitions):
                        distortion_name = str(distortion_definition.get("name") or "unknown")
                        distortion_case_id = "{}_dist_{}".format(case_id, distortion_name)
                        distortion_case_dir = case_dir / "distortions" / distortion_name
                        distorted_images_dir = distortion_case_dir / "pages"
                        distorted_restored_path = distortion_case_dir / "restored.bin"
                        distorted_ocr_text_output = distortion_case_dir / "ocr_text.txt"
                        distorted_analyze_report = distortion_case_dir / "analyze_report.json"
                        distorted_missing_file = distortion_case_dir / "missing_chunks.csv"
                        distortion_recover_result = None
                        distortion_exception = None
                        distorted_image_paths = []
                        distortion_start = time.perf_counter()
                        try:
                            distorted_image_paths = _materialize_distortion_images(
                                image_paths=base_image_paths,
                                target_dir=distorted_images_dir,
                                definition=distortion_definition,
                                seed=(
                                    int(seed)
                                    + (case_index * 1000003)
                                    + (distortion_index * 9176)
                                ),
                            )
                            distortion_recover_result = transport.recover_from_images(
                                manifest_path=manifest_path,
                                image_input_path=str(distorted_images_dir),
                                output_file=str(distorted_restored_path),
                                backend=backend,
                                lang=lang,
                                psm=psm,
                                ocr_provider_cmd=ocr_provider_cmd,
                                ocr_provider_timeout_sec=ocr_provider_timeout_sec,
                                strict_payload_chars=strict_payload_chars,
                                ocr_text_output=str(distorted_ocr_text_output),
                                save_analyze_report=str(distorted_analyze_report),
                                emit_missing_file=str(distorted_missing_file),
                                max_list=max_list,
                            )
                        except Exception as exc:
                            distortion_exception = exc
                        elapsed_ms = (time.perf_counter() - distortion_start) * 1000.0
                        distortion_record = {
                            "suite": distortion_suite_name,
                            "name": distortion_name,
                            "kind": distortion_definition.get("kind"),
                            "parameters": distortion_definition.get("parameters", {}),
                            "description": distortion_definition.get("description"),
                            "input_image_count": len(base_image_paths),
                            "output_image_count": len(distorted_image_paths),
                            "input_images": _image_digests(base_image_paths),
                            "output_images": _image_digests(distorted_image_paths),
                            "output_dir": str(distorted_images_dir),
                        }
                        records.append(
                            _build_case_record(
                                case_id=distortion_case_id,
                                case_dir=distortion_case_dir,
                                payload_path=payload_path,
                                restored_path=distorted_restored_path,
                                payload_size=int(payload_size),
                                payload_sha256=payload_sha256,
                                backend_requested=backend,
                                export_result=base_export_result,
                                recover_result=distortion_recover_result,
                                elapsed_ms=elapsed_ms,
                                exception=distortion_exception,
                                distortion=distortion_record,
                                distorted_image_paths=distorted_image_paths,
                                require_ocr_only_backend=require_ocr_only_backend,
                            )
                        )
                    continue

                export_result = base_export_result
                if int(export_result.get("image_count", 0) or 0) > 0:
                    image_input = str(package_dir / "pages")
                    recover_result = transport.recover_from_images(
                        manifest_path=manifest_path,
                        image_input_path=image_input,
                        output_file=str(restored_path),
                        backend=backend,
                        lang=lang,
                        psm=psm,
                        ocr_provider_cmd=ocr_provider_cmd,
                        ocr_provider_timeout_sec=ocr_provider_timeout_sec,
                        strict_payload_chars=strict_payload_chars,
                        ocr_text_output=str(ocr_text_output),
                        save_analyze_report=str(analyze_report),
                        emit_missing_file=str(missing_file),
                        max_list=max_list,
                    )
            except Exception as exc:
                exception = exc
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            records.append(
                _build_case_record(
                    case_id=case_id,
                    case_dir=case_dir,
                    payload_path=payload_path,
                    restored_path=restored_path,
                    payload_size=int(payload_size),
                    payload_sha256=payload_sha256,
                    backend_requested=backend,
                    export_result=export_result,
                    recover_result=recover_result,
                    elapsed_ms=elapsed_ms,
                    exception=exception,
                    require_ocr_only_backend=require_ocr_only_backend,
                )
            )
    return records


def certify_transport_reliability(
    transport,
    output_dir: str,
    payload_sizes: Optional[Iterable[int]] = None,
    iterations_per_size: int = 1,
    seed: int = 1729,
    backend: str = "sidecar",
    redundancy_copies: int = 2,
    interleave: bool = True,
    parity_group_size: int = 4,
    filename_prefix: str = "case",
    report_file: Optional[str] = None,
    require_success_rate: float = 1.0,
    lang: str = "eng",
    psm: int = 6,
    ocr_provider_cmd: Optional[str] = None,
    ocr_provider_timeout_sec: int = 120,
    strict_payload_chars: bool = False,
    max_list: int = 200,
    profile: Optional[str] = None,
    allow_unsafe_profile: bool = False,
    allow_ocr_fallback: bool = False,
    profile_redundancy_threshold_bytes: int = RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES,
    distortion_suite: str = NO_DISTORTION_SUITE,
    distortion_required_success_rate: Optional[float] = None,
    capture_corpus_file: Optional[str] = None,
    include_generated_corpus: bool = True,
    require_distinct_capture_images: bool = False,
    require_real_camera_perspective_correction: bool = False,
    require_physical_print_scan: bool = False,
    capture_attachment_report_file: Optional[str] = None,
    require_capture_attachment_report: bool = False,
    require_capture_provenance: bool = False,
    capture_required_classification: Optional[str] = None,
    capture_required_success_rate: Optional[float] = None,
    require_ocr_only_backend: bool = False,
    ocr_only_required_success_rate: Optional[float] = None,
) -> Dict[str, object]:
    """Run a deterministic export/recover loop and write a replayable report."""

    include_generated = bool(include_generated_corpus)
    sizes = _normalize_payload_sizes(payload_sizes) if include_generated else []
    iterations = int(iterations_per_size)
    if include_generated and iterations <= 0:
        raise ValueError("iterations_per_size must be positive")
    required_rate = float(require_success_rate)
    if required_rate < 0.0 or required_rate > 1.0:
        raise ValueError("require_success_rate must be between 0.0 and 1.0")
    distortion_required_rate = (
        required_rate
        if distortion_required_success_rate is None
        else float(distortion_required_success_rate)
    )
    if distortion_required_rate < 0.0 or distortion_required_rate > 1.0:
        raise ValueError("distortion_required_success_rate must be between 0.0 and 1.0")
    capture_required_rate = (
        required_rate
        if capture_required_success_rate is None
        else float(capture_required_success_rate)
    )
    if capture_required_rate < 0.0 or capture_required_rate > 1.0:
        raise ValueError("capture_required_success_rate must be between 0.0 and 1.0")
    ocr_only_required_rate = (
        required_rate
        if ocr_only_required_success_rate is None
        else float(ocr_only_required_success_rate)
    )
    if ocr_only_required_rate < 0.0 or ocr_only_required_rate > 1.0:
        raise ValueError("ocr_only_required_success_rate must be between 0.0 and 1.0")
    capture_required_classification_value = (
        str(capture_required_classification or "").strip().lower()
    )
    if (
        capture_required_classification_value
        and capture_required_classification_value not in SUPPORTED_CORPUS_CLASSIFICATIONS
    ):
        raise ValueError(
            "capture_required_classification must be one of: {}".format(
                ", ".join(SUPPORTED_CORPUS_CLASSIFICATIONS)
            )
        )

    backend = str(backend or "sidecar").strip().lower()
    if backend not in SUPPORTED_CERTIFICATION_BACKENDS:
        raise ValueError("unsupported certification backend: {}".format(backend))
    if backend == "external" and not ocr_provider_cmd:
        raise ValueError("external certification backend requires ocr_provider_cmd")
    if bool(require_ocr_only_backend) and backend not in OCR_ONLY_CERTIFICATION_BACKENDS:
        raise ValueError(
            "require_ocr_only_backend requires backend one of: {}".format(
                ", ".join(OCR_ONLY_CERTIFICATION_BACKENDS)
            )
        )
    profile_name = _resolve_profile_name(profile=profile, backend=backend)
    distortion_suite_name = _resolve_distortion_suite_name(distortion_suite)
    distortion_definitions = _distortion_definitions_for_suite(distortion_suite_name)
    capture_corpus = _normalize_capture_corpus_cases(capture_corpus_file)
    if bool(require_real_camera_perspective_correction) and capture_corpus is None:
        raise ValueError(
            "require_real_camera_perspective_correction requires a capture_corpus_file"
        )
    if bool(require_physical_print_scan) and capture_corpus is None:
        raise ValueError("require_physical_print_scan requires a capture_corpus_file")
    capture_attachment_report = _resolve_capture_attachment_report(
        capture_corpus=capture_corpus,
        capture_attachment_report_file=capture_attachment_report_file,
        require_capture_attachment_report=bool(require_capture_attachment_report),
    )
    profile_compliance = _build_profile_compliance(
        profile=profile_name,
        transport=transport,
        backend=backend,
        payload_sizes=sizes,
        redundancy_copies=redundancy_copies,
        parity_group_size=parity_group_size,
        allow_unsafe_profile=allow_unsafe_profile,
        allow_ocr_fallback=allow_ocr_fallback,
        redundancy_threshold_bytes=profile_redundancy_threshold_bytes,
    )

    out_dir = Path(output_dir)
    cases_dir = out_dir / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    report_path = Path(report_file) if report_file else (out_dir / "transport_reliability_report.json")

    cases = []
    if include_generated:
        cases.extend(
            _run_generated_corpus_cases(
                transport=transport,
                cases_dir=cases_dir,
                sizes=sizes,
                iterations=iterations,
                seed=int(seed),
                backend=backend,
                redundancy_copies=redundancy_copies,
                interleave=interleave,
                parity_group_size=parity_group_size,
                filename_prefix=filename_prefix,
                lang=lang,
                psm=psm,
                ocr_provider_cmd=ocr_provider_cmd,
                ocr_provider_timeout_sec=ocr_provider_timeout_sec,
                strict_payload_chars=strict_payload_chars,
                max_list=max_list,
                distortion_suite_name=distortion_suite_name,
                distortion_definitions=distortion_definitions,
                require_ocr_only_backend=bool(require_ocr_only_backend),
            )
        )

    if capture_corpus is not None:
        cases.extend(
            _run_capture_corpus_cases(
                transport=transport,
                capture_corpus=capture_corpus,
                cases_dir=cases_dir,
                profile=profile_name,
                backend=backend,
                lang=lang,
                psm=psm,
                ocr_provider_cmd=ocr_provider_cmd,
                ocr_provider_timeout_sec=ocr_provider_timeout_sec,
                strict_payload_chars=strict_payload_chars,
                max_list=max_list,
                profile_redundancy_threshold_bytes=profile_redundancy_threshold_bytes,
                allow_ocr_fallback=allow_ocr_fallback,
                require_distinct_capture_images=bool(require_distinct_capture_images),
                require_real_camera_perspective_correction=bool(
                    require_real_camera_perspective_correction
                ),
                require_physical_print_scan=bool(require_physical_print_scan),
                require_capture_provenance=bool(require_capture_provenance),
                capture_attachment_report=capture_attachment_report,
                require_capture_attachment_report=bool(require_capture_attachment_report),
                require_ocr_only_backend=bool(require_ocr_only_backend),
            )
        )

    total_cases = len(cases)
    passed_cases = len([case for case in cases if case.get("success")])
    failed_cases = total_cases - passed_cases
    success_rate = float(passed_cases) / float(total_cases) if total_cases else 0.0
    outcome_counts = Counter(str(case.get("failure_reason") or "unknown") for case in cases)
    failure_counts = Counter(
        str(case.get("failure_reason") or "unknown")
        for case in cases
        if str(case.get("failure_reason") or "unknown") != "none"
    )
    backend_counts = Counter(str(case.get("backend_selected") or case.get("backend_requested") or "unknown") for case in cases)
    threshold_passed = success_rate >= required_rate
    distortion_counts = Counter(
        str((case.get("distortion") or {}).get("name") or "unknown")
        for case in cases
    )
    distortion_passed_counts = Counter(
        str((case.get("distortion") or {}).get("name") or "unknown")
        for case in cases
        if case.get("success")
    )
    distortion_failed_counts = Counter(
        str((case.get("distortion") or {}).get("name") or "unknown")
        for case in cases
        if not case.get("success")
    )
    distortion_failure_reason_counts: Dict[str, Dict[str, int]] = {}
    distortion_success_rates: Dict[str, float] = {}
    distortion_thresholds: Dict[str, Dict[str, object]] = {}
    for distortion_name in sorted(distortion_counts):
        total_for_distortion = int(distortion_counts[distortion_name])
        passed_for_distortion = int(distortion_passed_counts.get(distortion_name, 0))
        success_rate_for_distortion = (
            float(passed_for_distortion) / float(total_for_distortion)
            if total_for_distortion
            else 0.0
        )
        distortion_success_rates[distortion_name] = success_rate_for_distortion
        distortion_thresholds[distortion_name] = {
            "required_success_rate": distortion_required_rate,
            "success_rate": success_rate_for_distortion,
            "threshold_passed": success_rate_for_distortion >= distortion_required_rate,
            "total_cases": total_for_distortion,
            "passed_cases": passed_for_distortion,
            "failed_cases": int(distortion_failed_counts.get(distortion_name, 0)),
        }
        distortion_failure_reason_counts[distortion_name] = dict(
            Counter(
                str(case.get("failure_reason") or "unknown")
                for case in cases
                if str((case.get("distortion") or {}).get("name") or "unknown") == distortion_name
                and not case.get("success")
            )
        )
    distortion_threshold_passed = all(
        bool(item.get("threshold_passed")) for item in distortion_thresholds.values()
    )
    capture_cases = [case for case in cases if isinstance(case.get("capture_corpus"), dict)]
    capture_classification_counts = Counter(
        str(case.get("capture_corpus", {}).get("classification") or "unknown")
        for case in capture_cases
    )
    capture_profile_certified_counts = Counter(
        str(case.get("capture_corpus", {}).get("classification") or "unknown")
        for case in capture_cases
        if bool(
            case.get("capture_corpus", {})
            .get("profile_compliance", {})
            .get("strict_profile")
        )
    )
    capture_passed_counts = Counter(
        str(case.get("capture_corpus", {}).get("classification") or "unknown")
        for case in capture_cases
        if case.get("success")
    )
    capture_strict_distinct_counts = Counter(
        str(case.get("capture_corpus", {}).get("classification") or "unknown")
        for case in capture_cases
        if bool(
            case.get("capture_corpus", {})
            .get("reference_transform", {})
            .get("distinct_from_reference")
        )
    )
    capture_perspective_evidence_counts = Counter(
        str(case.get("capture_corpus", {}).get("classification") or "unknown")
        for case in capture_cases
        if bool(
            case.get("capture_corpus", {})
            .get("perspective_correction_evidence", {})
            .get("evidence_passed")
        )
    )
    capture_print_scan_evidence_counts = Counter(
        str(case.get("capture_corpus", {}).get("classification") or "unknown")
        for case in capture_cases
        if bool(
            case.get("capture_corpus", {})
            .get("physical_print_scan_evidence", {})
            .get("evidence_passed")
        )
    )
    capture_attachment_evidence_counts = Counter(
        str(case.get("capture_corpus", {}).get("classification") or "unknown")
        for case in capture_cases
        if bool(
            case.get("capture_corpus", {})
            .get("attachment_report_evidence", {})
            .get("evidence_passed")
        )
    )
    capture_provenance_evidence_counts = Counter(
        str(case.get("capture_corpus", {}).get("classification") or "unknown")
        for case in capture_cases
        if bool(
            case.get("capture_corpus", {})
            .get("capture_provenance_evidence", {})
            .get("evidence_passed")
        )
    )
    capture_medium_counts = Counter(
        str(case.get("capture_corpus", {}).get("capture_medium") or "unspecified")
        for case in capture_cases
    )
    ocr_only_cases = [case for case in cases if isinstance(case.get("ocr_only_evidence"), dict)]
    ocr_only_backend_counts = Counter(
        str(case.get("ocr_only_evidence", {}).get("backend") or "unknown")
        for case in ocr_only_cases
    )
    ocr_only_evidence_counts = Counter(
        str(case.get("ocr_only_evidence", {}).get("backend") or "unknown")
        for case in ocr_only_cases
        if bool(case.get("ocr_only_evidence", {}).get("evidence_passed"))
    )
    ocr_only_passed_counts = Counter(
        str(case.get("ocr_only_evidence", {}).get("backend") or "unknown")
        for case in ocr_only_cases
        if case.get("success")
    )
    capture_success_rates: Dict[str, float] = {}
    capture_thresholds: Dict[str, Dict[str, object]] = {}
    for classification in sorted(capture_classification_counts):
        total_for_classification = int(capture_classification_counts[classification])
        passed_for_classification = int(capture_passed_counts.get(classification, 0))
        capture_success_rates[classification] = (
            float(passed_for_classification) / float(total_for_classification)
            if total_for_classification
            else 0.0
        )
        capture_thresholds[classification] = {
            "required_success_rate": capture_required_rate,
            "success_rate": capture_success_rates[classification],
            "threshold_passed": capture_success_rates[classification] >= capture_required_rate,
            "total_cases": total_for_classification,
            "passed_cases": passed_for_classification,
            "failed_cases": total_for_classification - passed_for_classification,
            "strict_distinct_capture_image_count": int(
                capture_strict_distinct_counts.get(classification, 0)
            ),
            "real_camera_perspective_evidence_count": int(
                capture_perspective_evidence_counts.get(classification, 0)
            ),
            "physical_print_scan_evidence_count": int(
                capture_print_scan_evidence_counts.get(classification, 0)
            ),
            "attachment_report_evidence_count": int(
                capture_attachment_evidence_counts.get(classification, 0)
            ),
            "capture_provenance_evidence_count": int(
                capture_provenance_evidence_counts.get(classification, 0)
            ),
        }
    capture_threshold_passed = all(
        bool(item.get("threshold_passed")) for item in capture_thresholds.values()
    )
    required_classification_case_count = (
        int(capture_classification_counts.get(capture_required_classification_value, 0))
        if capture_required_classification_value
        else 0
    )
    required_classification_passed = bool(
        not capture_required_classification_value or required_classification_case_count > 0
    )
    distinct_capture_gate_passed = bool(
        (not require_distinct_capture_images)
        or all(
            bool(
                case.get("capture_corpus", {})
                .get("reference_transform", {})
                .get("strict_gate_passed")
            )
            for case in capture_cases
        )
    )
    real_camera_perspective_gate_passed = bool(
        (not require_real_camera_perspective_correction)
        or (
            bool(capture_cases)
            and all(
                bool(
                    case.get("capture_corpus", {})
                    .get("perspective_correction_evidence", {})
                    .get("strict_gate_passed")
                )
                for case in capture_cases
            )
        )
    )
    physical_print_scan_gate_passed = bool(
        (not require_physical_print_scan)
        or (
            bool(capture_cases)
            and all(
                bool(
                    case.get("capture_corpus", {})
                    .get("physical_print_scan_evidence", {})
                    .get("strict_gate_passed")
                )
                for case in capture_cases
            )
        )
    )
    capture_attachment_report_gate_passed = bool(
        (not require_capture_attachment_report)
        or (
            bool(capture_cases)
            and all(
                bool(
                    case.get("capture_corpus", {})
                    .get("attachment_report_evidence", {})
                    .get("strict_gate_passed")
                )
                for case in capture_cases
            )
        )
    )
    capture_provenance_gate_passed = bool(
        (not require_capture_provenance)
        or (
            bool(capture_cases)
            and all(
                bool(
                    case.get("capture_corpus", {})
                    .get("capture_provenance_evidence", {})
                    .get("strict_gate_passed")
                )
                for case in capture_cases
            )
        )
    )
    ocr_only_success_rates: Dict[str, float] = {}
    ocr_only_thresholds: Dict[str, Dict[str, object]] = {}
    for ocr_backend_name in sorted(ocr_only_backend_counts):
        total_for_backend = int(ocr_only_backend_counts[ocr_backend_name])
        passed_for_backend = int(ocr_only_passed_counts.get(ocr_backend_name, 0))
        evidence_for_backend = int(ocr_only_evidence_counts.get(ocr_backend_name, 0))
        ocr_only_success_rates[ocr_backend_name] = (
            float(passed_for_backend) / float(total_for_backend)
            if total_for_backend
            else 0.0
        )
        ocr_only_thresholds[ocr_backend_name] = {
            "required_success_rate": ocr_only_required_rate,
            "success_rate": ocr_only_success_rates[ocr_backend_name],
            "threshold_passed": ocr_only_success_rates[ocr_backend_name] >= ocr_only_required_rate,
            "total_cases": total_for_backend,
            "passed_cases": passed_for_backend,
            "failed_cases": total_for_backend - passed_for_backend,
            "evidence_passed_cases": evidence_for_backend,
        }
    ocr_only_threshold_passed = bool(
        (not require_ocr_only_backend)
        or (
            bool(ocr_only_cases)
            and all(bool(item.get("threshold_passed")) for item in ocr_only_thresholds.values())
            and all(
                bool(case.get("ocr_only_evidence", {}).get("strict_gate_passed"))
                for case in ocr_only_cases
            )
        )
    )
    profile_gate_passed = bool(
        profile_compliance.get("passed") or profile_compliance.get("unsafe_override_accepted")
    )
    success = bool(
        total_cases > 0
        and failed_cases == 0
        and threshold_passed
        and distortion_threshold_passed
        and capture_threshold_passed
        and required_classification_passed
        and distinct_capture_gate_passed
        and real_camera_perspective_gate_passed
        and physical_print_scan_gate_passed
        and capture_attachment_report_gate_passed
        and capture_provenance_gate_passed
        and ocr_only_threshold_passed
        and profile_gate_passed
    )
    profile_certified = bool(
        profile_compliance.get("passed") and profile_compliance.get("strict_profile")
    )
    certification_claims = _build_certification_claims(
        success=success,
        profile_name=profile_name,
        profile_certified=profile_certified,
        backend=backend,
        distortion_suite_name=distortion_suite_name,
        distortion_threshold_passed=distortion_threshold_passed,
        capture_cases=capture_cases,
        capture_classification_counts=capture_classification_counts,
        capture_medium_counts=capture_medium_counts,
        capture_success_rates=capture_success_rates,
        require_distinct_capture_images=bool(require_distinct_capture_images),
        distinct_capture_gate_passed=distinct_capture_gate_passed,
        require_physical_print_scan=bool(require_physical_print_scan),
        physical_print_scan_gate_passed=physical_print_scan_gate_passed,
        require_real_camera_perspective_correction=bool(
            require_real_camera_perspective_correction
        ),
        real_camera_perspective_gate_passed=real_camera_perspective_gate_passed,
        require_capture_attachment_report=bool(require_capture_attachment_report),
        capture_attachment_report_gate_passed=capture_attachment_report_gate_passed,
        require_capture_provenance=bool(require_capture_provenance),
        capture_provenance_gate_passed=capture_provenance_gate_passed,
        require_ocr_only_backend=bool(require_ocr_only_backend),
        ocr_only_threshold_passed=ocr_only_threshold_passed,
        ocr_only_success_rates=ocr_only_success_rates,
    )

    report = {
        "schema": REPORT_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": success,
        "profile": profile_name,
        "profile_certified": profile_certified,
        "profile_compliance": profile_compliance,
        "certification_claims": certification_claims,
        "report_path": str(report_path),
        "seed": int(seed),
        "parameters": {
            "profile": profile_name,
            "allow_unsafe_profile": bool(allow_unsafe_profile),
            "allow_ocr_fallback": bool(allow_ocr_fallback),
            "profile_redundancy_threshold_bytes": int(profile_redundancy_threshold_bytes),
            "distortion_suite": distortion_suite_name,
            "distortion_required_success_rate": distortion_required_rate,
            "capture_corpus_file": str(capture_corpus.get("path")) if capture_corpus else None,
            "capture_corpus_classification": (
                capture_corpus.get("classification") if capture_corpus else None
            ),
            "include_generated_corpus": bool(include_generated),
            "capture_required_classification": capture_required_classification_value or None,
            "capture_required_success_rate": capture_required_rate,
            "require_distinct_capture_images": bool(require_distinct_capture_images),
            "require_real_camera_perspective_correction": bool(
                require_real_camera_perspective_correction
            ),
            "require_physical_print_scan": bool(require_physical_print_scan),
            "capture_attachment_report_file": (
                str(capture_attachment_report.get("path"))
                if capture_attachment_report
                else None
            ),
            "require_capture_attachment_report": bool(require_capture_attachment_report),
            "require_capture_provenance": bool(require_capture_provenance),
            "require_ocr_only_backend": bool(require_ocr_only_backend),
            "ocr_only_required_success_rate": ocr_only_required_rate,
            "payload_sizes": sizes,
            "iterations_per_size": iterations,
            "backend": backend,
            "redundancy_copies": int(redundancy_copies),
            "interleave": bool(interleave),
            "parity_group_size": int(parity_group_size),
            "filename_prefix": filename_prefix,
            "lang": lang,
            "psm": int(psm),
            "strict_payload_chars": bool(strict_payload_chars),
            "max_list": int(max_list),
            "transport": {
                "max_compressed_bytes": getattr(transport, "max_compressed_bytes", None),
                "chunk_chars": getattr(transport, "chunk_chars", None),
                "lines_per_page": getattr(transport, "lines_per_page", None),
                "metadata_level": getattr(transport, "metadata_level", None),
                "line_separator": getattr(transport, "line_separator", None),
                "line_index_mode": getattr(transport, "line_index_mode", None),
                "line_crc_mode": getattr(transport, "line_crc_mode", None),
                "payload_alphabet_profile": getattr(
                    transport,
                    "payload_alphabet_profile",
                    None,
                ),
                "alphabet": getattr(transport, "payload_alphabet", None),
                "render_sidecar": getattr(transport, "render_sidecar", None),
                "font_size": getattr(transport, "font_size", None),
                "font_fit_mode": getattr(transport, "font_fit_mode", None),
            },
        },
        "thresholds": {
            "required_success_rate": required_rate,
            "threshold_passed": threshold_passed,
            "distortion_required_success_rate": distortion_required_rate,
            "distortion_threshold_passed": distortion_threshold_passed,
            "distortions": distortion_thresholds,
            "capture_required_success_rate": capture_required_rate,
            "capture_threshold_passed": capture_threshold_passed,
            "capture_required_classification": capture_required_classification_value or None,
            "capture_required_classification_case_count": required_classification_case_count,
            "capture_required_classification_passed": required_classification_passed,
            "distinct_capture_images_required": bool(require_distinct_capture_images),
            "distinct_capture_images_passed": distinct_capture_gate_passed,
            "real_camera_perspective_correction_required": bool(
                require_real_camera_perspective_correction
            ),
            "real_camera_perspective_correction_passed": real_camera_perspective_gate_passed,
            "physical_print_scan_required": bool(require_physical_print_scan),
            "physical_print_scan_passed": physical_print_scan_gate_passed,
            "capture_attachment_report_required": bool(require_capture_attachment_report),
            "capture_attachment_report_passed": capture_attachment_report_gate_passed,
            "capture_provenance_required": bool(require_capture_provenance),
            "capture_provenance_passed": capture_provenance_gate_passed,
            "ocr_only_backend_required": bool(require_ocr_only_backend),
            "ocr_only_required_success_rate": ocr_only_required_rate,
            "ocr_only_threshold_passed": ocr_only_threshold_passed,
            "ocr_only_backends": ocr_only_thresholds,
            "capture_classifications": capture_thresholds,
        },
        "ocr_only_certification": {
            "required": bool(require_ocr_only_backend),
            "backend": backend if backend in OCR_ONLY_CERTIFICATION_BACKENDS else None,
            "supported_backends": list(OCR_ONLY_CERTIFICATION_BACKENDS),
            "case_count": len(ocr_only_cases),
            "backend_counts": dict(ocr_only_backend_counts),
            "evidence_passed_counts": dict(ocr_only_evidence_counts),
            "success_rates_by_backend": ocr_only_success_rates,
            "thresholds_by_backend": ocr_only_thresholds,
            "production_certified": False,
            "certification_boundary": (
                "OCR-only reports are backend-specific measured evidence only. They do not "
                "certify generic OCR fallback, camera transfer, physical print-scan transfer, "
                "or reliable-airgap-v1 production readiness unless those exact media/backend "
                "conditions are separately measured and documented."
            ),
        },
        "capture_corpus": {
            "schema": CAPTURE_CORPUS_SCHEMA,
            "provided": bool(capture_corpus),
            "corpus_file": str(capture_corpus.get("path")) if capture_corpus else None,
            "classification": capture_corpus.get("classification") if capture_corpus else None,
            "case_count": int(capture_corpus.get("case_count", 0)) if capture_corpus else 0,
            "metadata": capture_corpus.get("metadata", {}) if capture_corpus else {},
            "classification_counts": dict(capture_classification_counts),
            "profile_certified_counts": dict(capture_profile_certified_counts),
            "strict_distinct_capture_image_counts": dict(capture_strict_distinct_counts),
            "capture_medium_counts": dict(capture_medium_counts),
            "real_camera_perspective_evidence_counts": dict(
                capture_perspective_evidence_counts
            ),
            "physical_print_scan_evidence_counts": dict(
                capture_print_scan_evidence_counts
            ),
            "attachment_report_evidence_counts": dict(capture_attachment_evidence_counts),
            "capture_provenance_evidence_counts": dict(
                capture_provenance_evidence_counts
            ),
            "success_rates_by_classification": capture_success_rates,
            "thresholds_by_classification": capture_thresholds,
            "certification_boundary": (
                "operator-supplied captures are measured evidence for the declared corpus "
                "classification only; they do not certify other cameras, scanners, printers, "
                "OCR backends, or capture conditions. Physical/lab capture claims should use "
                "--require-distinct-capture-images so generated fixture copies cannot be counted "
                "as scanner/camera evidence. Real camera perspective-correction claims require "
                "--require-real-camera-perspective-correction and per-case raw_image_paths plus "
                "perspective_correction metadata; generated perspective-skew distortions do not "
                "certify real camera correction. Physical print-scan claims require "
                "--require-physical-print-scan, capture_medium=print-scan, printer/scanner/dpi "
                "metadata, reference_image_paths, and byte-distinct scan images. Attachment "
                "lineage claims should use --require-capture-attachment-report so certification "
                "fails closed unless measured files match the attach-capture-corpus report."
            ),
        },
        "distortion_suite": {
            "name": distortion_suite_name,
            "profile": profile_name,
            "backend": backend,
            "distortions": distortion_definitions,
            "supported_but_not_certified": [
                "real-camera-photo",
                "real-camera-perspective-correction",
                "print-scan-full",
                "generic-ocr-only",
            ],
        },
        "summary": {
            "total_cases": total_cases,
            "passed_cases": passed_cases,
            "failed_cases": failed_cases,
            "success_rate": success_rate,
            "outcomes_by_reason": dict(outcome_counts),
            "failures_by_reason": dict(failure_counts),
            "backend_counts": dict(backend_counts),
            "distortion_counts": dict(distortion_counts),
            "distortion_passed_counts": dict(distortion_passed_counts),
            "distortion_failed_counts": dict(distortion_failed_counts),
            "distortion_success_rates": distortion_success_rates,
            "distortion_failures_by_reason": distortion_failure_reason_counts,
            "capture_case_count": len(capture_cases),
            "capture_classification_counts": dict(capture_classification_counts),
            "capture_profile_certified_counts": dict(capture_profile_certified_counts),
            "capture_strict_distinct_counts": dict(capture_strict_distinct_counts),
            "capture_medium_counts": dict(capture_medium_counts),
            "capture_real_camera_perspective_evidence_counts": dict(
                capture_perspective_evidence_counts
            ),
            "capture_physical_print_scan_evidence_counts": dict(
                capture_print_scan_evidence_counts
            ),
            "capture_attachment_report_evidence_counts": dict(
                capture_attachment_evidence_counts
            ),
            "capture_provenance_evidence_counts": dict(
                capture_provenance_evidence_counts
            ),
            "capture_success_rates_by_classification": capture_success_rates,
            "ocr_only_case_count": len(ocr_only_cases),
            "ocr_only_backend_counts": dict(ocr_only_backend_counts),
            "ocr_only_evidence_counts": dict(ocr_only_evidence_counts),
            "ocr_only_success_rates_by_backend": ocr_only_success_rates,
        },
        "cases": cases,
    }
    _write_json(report_path, report)
    return report


__all__ = [
    "REPORT_SCHEMA",
    "CAPTURE_CORPUS_SCHEMA",
    "CAPTURE_KIT_SCHEMA",
    "CAPTURE_ATTACHMENT_REPORT_SCHEMA",
    "CAPTURE_PERSPECTIVE_CORRECTION_REPORT_SCHEMA",
    "CAPTURE_VALIDATION_REPORT_SCHEMA",
    "CAPTURE_EVIDENCE_ARCHIVE_SCHEMA",
    "CAPTURE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA",
    "CAPTURE_EVIDENCE_ARCHIVE_REPLAY_SCHEMA",
    "CERTIFICATION_CLAIMS_SCHEMA",
    "CERTIFICATION_STATUS_SCHEMA",
    "CAPTURE_CERTIFICATION_PIPELINE_SCHEMA",
    "CAPTURE_CORPUS_INGESTION_REPORT_SCHEMA",
    "CAPTURE_METADATA_MANIFEST_SCHEMA",
    "CAPTURE_RETURN_PACKAGE_EXTRACTION_SCHEMA",
    "CAPTURE_RETURN_PACKAGE_SCHEMA",
    "CAPTURE_RETURN_MANIFEST_SCHEMA",
    "DEFAULT_PAYLOAD_SIZES",
    "DIGITAL_SIDECAR_PROFILE",
    "RELIABLE_AIRGAP_PROFILE",
    "SUPPORTED_PROFILES",
    "RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES",
    "NO_DISTORTION_SUITE",
    "GENERATED_PAGE_BASIC_DISTORTION_SUITE",
    "GENERATED_PAGE_STRESS_DISTORTION_SUITE",
    "SUPPORTED_DISTORTION_SUITES",
    "OPERATOR_CAPTURE_CORPUS_SUITE",
    "SUPPORTED_CORPUS_CLASSIFICATIONS",
    "SUPPORTED_CAPTURE_MEDIA",
    "SUPPORTED_CERTIFICATION_BACKENDS",
    "OCR_ONLY_CERTIFICATION_BACKENDS",
    "CAPTURE_PROVENANCE_SESSION_KEYS",
    "CAPTURE_PROVENANCE_OPERATOR_KEYS",
    "CAPTURE_PROVENANCE_TIMESTAMP_KEYS",
    "CAPTURE_PROVENANCE_DEVICE_KEYS",
    "SUPPORTED_PERSPECTIVE_CORRECTION_MODES",
    "TRANSPORT_CERTIFICATION_CLAIMS",
    "certify_transport_reliability",
    "prepare_capture_corpus_kit",
    "package_capture_return",
    "ingest_capture_corpus",
    "attach_capture_corpus",
    "correct_capture_perspective",
    "validate_capture_corpus",
    "archive_transport_evidence",
    "verify_transport_evidence_archive",
    "replay_transport_evidence_archive",
    "summarize_transport_certification_status",
    "certify_capture_evidence_pipeline",
]
