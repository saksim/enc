#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Airgap Transport Layer for encrypted artifacts.

Design goals:
1) only transport already-encrypted small artifacts (do not perform encryption here);
2) produce OCR-friendly canonical text + PNG pages;
3) recover artifact from OCR text with line-level CRC and package-level SHA256 verification.
"""

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import zlib
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from enc2sop.transport import cli as _transport_cli
from enc2sop.transport import certify as _transport_certify
from enc2sop.transport import layout as _transport_layout
from enc2sop.transport import ocr_adapters as _ocr_adapters
from enc2sop.transport import ocr_embedded as _transport_ocr_embedded
from enc2sop.transport import ocr_pipeline as _transport_ocr_pipeline
from enc2sop.transport import ocr_runtime as _transport_ocr_runtime
from enc2sop.transport import parser as _transport_parser
from enc2sop.transport import protocol as _transport_protocol
from enc2sop.transport import recover as _transport_recover
from enc2sop.transport import render as _transport_render

try:
    from PIL import Image, ImageDraw, ImageFont

    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

if PIL_AVAILABLE:
    _RESAMPLING = getattr(Image, "Resampling", Image)
    RESAMPLE_LANCZOS = getattr(_RESAMPLING, "LANCZOS", getattr(Image, "LANCZOS", 1))
else:
    RESAMPLE_LANCZOS = None

pytesseract = None
easyocr = None
np = None


# Protocol primitives extracted to enc2sop.transport.protocol.
PROTOCOL_VERSION = _transport_protocol.PROTOCOL_VERSION
STD_BASE32_ALPHABET = _transport_protocol.STD_BASE32_ALPHABET
SAFE_BASE32_ALPHABET = _transport_protocol.SAFE_BASE32_ALPHABET
OCR_SAFE_HUMAN_CORRECTABLE_PROFILE = _transport_protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE
OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET = _transport_protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET
IMAGE_SUFFIXES = _transport_protocol.IMAGE_SUFFIXES
SIDECAR_BITS_PER_ROW = _transport_protocol.SIDECAR_BITS_PER_ROW
SIDECAR_CELL_SIZE = _transport_protocol.SIDECAR_CELL_SIZE
SIDECAR_CELL_GAP = _transport_protocol.SIDECAR_CELL_GAP
HASH_FRAGMENT_LEN = _transport_protocol.HASH_FRAGMENT_LEN
PAYLOAD_OCR_AMBIGUITIES = _transport_protocol.PAYLOAD_OCR_AMBIGUITIES
SAFE_CHAR_TO_VAL = _transport_protocol.SAFE_CHAR_TO_VAL
SUPPORTED_FIELD_SEPARATORS = _transport_protocol.SUPPORTED_FIELD_SEPARATORS
LINE_PATTERN = _transport_protocol.LINE_PATTERN
LINE_PATTERN_NOCRC = _transport_protocol.LINE_PATTERN_NOCRC
LINE_PATTERN_NOSEP = _transport_protocol.LINE_PATTERN_NOSEP
LINE_PATTERN_NOSEP_NOCRC = _transport_protocol.LINE_PATTERN_NOSEP_NOCRC
LINE_PATTERN_FALLBACK = _transport_protocol.LINE_PATTERN_FALLBACK
LINE_PATTERN_FALLBACK_NOCRC = _transport_protocol.LINE_PATTERN_FALLBACK_NOCRC
CHUNK_PATTERN = _transport_protocol.CHUNK_PATTERN
CHUNK_PATTERN_NOCRC = _transport_protocol.CHUNK_PATTERN_NOCRC
CHUNK_PATTERN_FALLBACK = _transport_protocol.CHUNK_PATTERN_FALLBACK
CHUNK_PATTERN_FALLBACK_NOCRC = _transport_protocol.CHUNK_PATTERN_FALLBACK_NOCRC
PAYLOAD_WITH_CRC_PATTERN = _transport_protocol.PAYLOAD_WITH_CRC_PATTERN
PAYLOAD_WITH_CRC_FALLBACK_PATTERN = _transport_protocol.PAYLOAD_WITH_CRC_FALLBACK_PATTERN
META_PATTERN = _transport_protocol.META_PATTERN
PAGECRC_PATTERN = _transport_protocol.PAGECRC_PATTERN
HASH_COMPACT_PATTERN = _transport_protocol.HASH_COMPACT_PATTERN
PAGE_NO_FROM_NAME_PATTERN = _transport_protocol.PAGE_NO_FROM_NAME_PATTERN

_utc_now_iso = _transport_protocol.utc_now_iso
_sha256_hex = _transport_protocol.sha256_hex
_crc16_hex = _transport_protocol.crc16_hex
_to_ascii_width = _transport_protocol.to_ascii_width
_normalize_ocr_line = _transport_protocol.normalize_ocr_line
_normalize_payload = _transport_protocol.normalize_payload
_normalize_protocol_signature = _transport_protocol.normalize_protocol_signature
_normalize_digit_token = _transport_protocol.normalize_digit_token
_normalize_page_line_token = _transport_protocol.normalize_page_line_token
_normalize_hex_token = _transport_protocol.normalize_hex_token
_parse_cfg_line = _transport_protocol.parse_cfg_line
_parse_hash_fragment_line = _transport_protocol.parse_hash_fragment_line
_parse_hash_compact_line = _transport_protocol.parse_hash_compact_line
_levenshtein_distance = _transport_protocol.levenshtein_distance
_build_easyocr_langs = _ocr_adapters.build_easyocr_langs
_encode_safe_base32 = _transport_protocol.encode_safe_base32
_decode_safe_base32 = _transport_protocol.decode_safe_base32
_encode_payload_for_profile = _transport_protocol.encode_payload_for_profile
_decode_payload_for_profile = _transport_protocol.decode_payload_for_profile
_safe_base32_encoded_length = _transport_protocol.safe_base32_encoded_length
_safe_payload_to_bits = _transport_protocol.safe_payload_to_bits
_bits_to_safe_payload = _transport_protocol.bits_to_safe_payload
_print_json = _transport_cli.print_json
_save_json = _transport_cli.save_json
_save_missing_chunks = _transport_cli.save_missing_chunks


def _module_spec_available(module_name: str) -> bool:
    return _ocr_adapters.is_module_available(module_name)


TESSERACT_PYTHON_AVAILABLE = _module_spec_available("pytesseract")
EASYOCR_AVAILABLE = _module_spec_available("easyocr")
NUMPY_AVAILABLE = _module_spec_available("numpy")
TESSERACT_CMD = _ocr_adapters.TESSERACT_CMD
TESSERACT_CLI_AVAILABLE = bool(TESSERACT_CMD)


def _sync_ocr_adapter_flags() -> None:
    _ocr_adapters.TESSERACT_PYTHON_AVAILABLE = bool(TESSERACT_PYTHON_AVAILABLE)
    _ocr_adapters.EASYOCR_AVAILABLE = bool(EASYOCR_AVAILABLE)
    _ocr_adapters.NUMPY_AVAILABLE = bool(NUMPY_AVAILABLE)
    _ocr_adapters.TESSERACT_CMD = TESSERACT_CMD
    _ocr_adapters.TESSERACT_CLI_AVAILABLE = bool(TESSERACT_CLI_AVAILABLE)


def _load_pytesseract_module():
    global pytesseract
    global TESSERACT_PYTHON_AVAILABLE

    if TESSERACT_PYTHON_AVAILABLE is False:
        return None
    if pytesseract is not None:
        TESSERACT_PYTHON_AVAILABLE = True
        return pytesseract

    _sync_ocr_adapter_flags()
    pytesseract = _ocr_adapters.load_pytesseract_module()
    TESSERACT_PYTHON_AVAILABLE = bool(pytesseract is not None)
    return pytesseract


def _tesseract_python_available() -> bool:
    return bool(TESSERACT_PYTHON_AVAILABLE)


def _load_easyocr_module():
    global easyocr
    global EASYOCR_AVAILABLE

    if EASYOCR_AVAILABLE is False:
        return None
    if easyocr is not None:
        EASYOCR_AVAILABLE = True
        return easyocr

    _sync_ocr_adapter_flags()
    easyocr = _ocr_adapters.load_easyocr_module()
    EASYOCR_AVAILABLE = bool(easyocr is not None)
    return easyocr


def _load_numpy_module():
    global np
    global NUMPY_AVAILABLE

    if NUMPY_AVAILABLE is False:
        return None
    if np is not None:
        NUMPY_AVAILABLE = True
        return np

    _sync_ocr_adapter_flags()
    np = _ocr_adapters.load_numpy_module()
    NUMPY_AVAILABLE = bool(np is not None)
    return np


def _easyocr_available() -> bool:
    return bool(EASYOCR_AVAILABLE)


def _numpy_available() -> bool:
    return bool(NUMPY_AVAILABLE)


def _build_easyocr_reader(lang: str):
    easyocr_mod = _load_easyocr_module()
    if easyocr_mod is None:
        raise RuntimeError("easyocr is not available in current environment")
    reader_langs = _build_easyocr_langs(lang)
    return easyocr_mod.Reader(reader_langs, gpu=False), reader_langs


def _tesseract_runtime_mode() -> str:
    if _tesseract_python_available():
        return "pytesseract"
    if TESSERACT_CLI_AVAILABLE and TESSERACT_CMD:
        return "cli"
    return ""


TESSERACT_AVAILABLE = bool(_tesseract_runtime_mode())

class AirgapTransportLayer(object):
    """
    Export/recover encrypted artifacts via OCR-friendly pages.
    """

    def __init__(
        self,
        max_compressed_kib: int = 64,
        chunk_chars: int = 40,
        lines_per_page: int = 20,
        page_size: Tuple[int, int] = (2480, 3508),
        margin: int = 120,
        font_size: int = 44,
        line_gap: int = 8,
        font_max_size: int = 132,
        fixed_font_size: bool = False,
        font_fit_mode: str = "target",
        line_index_mode: str = "full",
        metadata_level: str = "compact",
        line_separator: str = "|",
        render_sidecar: bool = True,
        line_crc_mode: str = "on",
        payload_alphabet_profile: str = "safe-base32-v1",
    ) -> None:
        self.max_compressed_bytes = max_compressed_kib * 1024
        self.chunk_chars = chunk_chars
        self.lines_per_page = lines_per_page
        self.page_size = page_size
        self.margin = margin
        self.font_size = font_size
        self.line_gap = line_gap
        self.font_max_size = max(16, int(font_max_size))
        self.fixed_font_size = bool(fixed_font_size)
        fit_mode = str(font_fit_mode or "target").strip().lower()
        if self.fixed_font_size:
            fit_mode = "fixed"
        if fit_mode not in ("target", "fit", "fixed"):
            raise ValueError("font_fit_mode must be one of: target, fit, fixed")
        self.font_fit_mode = fit_mode
        line_index_mode = str(line_index_mode or "full").strip().lower()
        if line_index_mode not in ("full", "chunk", "off"):
            raise ValueError("line_index_mode must be one of: full, chunk, off")
        self.line_index_mode = line_index_mode
        self.metadata_level = str(metadata_level or "compact").strip().lower()
        if self.metadata_level not in ("compact", "none"):
            raise ValueError("metadata_level must be one of: compact, none")
        if line_separator not in SUPPORTED_FIELD_SEPARATORS:
            raise ValueError("line_separator must be one of: {}".format(", ".join(SUPPORTED_FIELD_SEPARATORS)))
        self.line_separator = str(line_separator)
        self.render_sidecar = bool(render_sidecar)
        self.line_crc_mode = str(line_crc_mode or "on").strip().lower()
        if self.line_crc_mode not in ("on", "off"):
            raise ValueError("line_crc_mode must be one of: on, off")
        self.payload_alphabet_profile = str(
            payload_alphabet_profile or "safe-base32-v1"
        ).strip().lower()
        self.payload_alphabet = _transport_protocol.payload_alphabet_for_profile(
            self.payload_alphabet_profile
        )

    def export_artifact(
        self,
        input_file: str,
        output_dir: str,
        artifact_id: Optional[str] = None,
        filename_prefix: str = "page",
        redundancy_copies: int = 1,
        interleave: bool = True,
        parity_group_size: int = 0,
    ) -> Dict[str, object]:
        source_path = Path(input_file)
        if not source_path.exists():
            raise FileNotFoundError("artifact not found: {}".format(input_file))

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        pages_dir = out_dir / "pages"
        page_text_dir = out_dir / "pages_txt"
        pages_dir.mkdir(parents=True, exist_ok=True)
        page_text_dir.mkdir(parents=True, exist_ok=True)

        raw = source_path.read_bytes()
        compressed = zlib.compress(raw, 9)
        if len(compressed) > self.max_compressed_bytes:
            raise ValueError(
                "compressed artifact {} bytes exceeds limit {} bytes".format(
                    len(compressed), self.max_compressed_bytes
                )
            )

        if artifact_id is None:
            artifact_id = self._build_artifact_id(source_path, raw)
        artifact_id = artifact_id.upper()

        redundancy_copies = int(redundancy_copies)
        if redundancy_copies < 1:
            raise ValueError("redundancy_copies must be >= 1")
        parity_group_size = int(parity_group_size)
        if parity_group_size < 0:
            raise ValueError("parity_group_size must be >= 0")
        if self.line_index_mode == "off" and self.render_sidecar:
            raise ValueError("line_index_mode=off requires --no-sidecar")

        encoded = _encode_payload_for_profile(compressed, self.payload_alphabet_profile)
        chunks = self._split_chunks(encoded, self.chunk_chars)
        parity_info = self._build_parity_info(chunks=chunks, parity_group_size=parity_group_size)
        raw_sha256 = _sha256_hex(raw)
        compressed_sha256 = _sha256_hex(compressed)

        base_entries = [(idx, payload) for idx, payload in enumerate(chunks)]
        base_entries.extend(parity_info["entries"])
        chunk_entries = self._build_chunk_entries(
            base_entries=base_entries, redundancy_copies=redundancy_copies, interleave=interleave
        )
        total_pages = int(math.ceil(float(len(chunk_entries)) / float(self.lines_per_page))) if self.lines_per_page > 0 else 0
        metadata_lines = []
        include_page_markers = self.metadata_level != "none"
        if self.metadata_level == "compact":
            metadata_lines = self._build_embedded_metadata_lines(
                artifact_id=artifact_id,
                total_chunks=len(chunks),
                total_pages=total_pages,
                raw_size=len(raw),
                compressed_size=len(compressed),
                encoded_payload_len=len(encoded),
                raw_sha256=raw_sha256,
                compressed_sha256=compressed_sha256,
                redundancy_copies=redundancy_copies,
                interleave=bool(interleave),
                parity_group_size=parity_group_size,
                parity_symbol_mode=str(parity_info["manifest"].get("symbol_mode") or ""),
            )
        pages, chunk_locations = self._build_pages(
            artifact_id=artifact_id,
            chunk_entries=chunk_entries,
            total_chunks=len(chunks),
            metadata_lines=metadata_lines,
            include_page_markers=include_page_markers,
            field_separator=self.line_separator,
            include_line_crc=(self.line_crc_mode == "on"),
            line_index_mode=self.line_index_mode,
        )

        manifest_path = out_dir / "{}.manifest.json".format(artifact_id)
        payload_path = out_dir / "{}.payload.txt".format(artifact_id)
        payload_path.write_text(encoded + "\n", encoding="ascii")

        exported_page_texts = []
        exported_images = []
        render_layout_pages = []
        for page_index, lines in enumerate(pages, 1):
            text_path = page_text_dir / "{}_{:04d}.txt".format(filename_prefix, page_index)
            text_path.write_text("\n".join(lines) + "\n", encoding="ascii")
            exported_page_texts.append(str(text_path))

            if PIL_AVAILABLE:
                image_path = pages_dir / "{}_{:04d}.png".format(filename_prefix, page_index)
                render_layout = self._render_page(lines, image_path)
                exported_images.append(str(image_path))
                render_layout["page"] = page_index
                render_layout_pages.append(render_layout)

        manifest = {
            "protocol_version": PROTOCOL_VERSION,
            "artifact_id": artifact_id,
            "artifact_name": source_path.name,
            "created_at_utc": _utc_now_iso(),
            "compression": "zlib",
            "encoding": (
                "safe_base32"
                if self.payload_alphabet_profile == "safe-base32-v1"
                else "profile_base_n"
            ),
            "payload_alphabet_profile": self.payload_alphabet_profile,
            "alphabet": self.payload_alphabet,
            "raw_size": len(raw),
            "compressed_size": len(compressed),
            "encoded_payload_len": len(encoded),
            "raw_sha256": raw_sha256,
            "compressed_sha256": compressed_sha256,
            "chunk_chars": self.chunk_chars,
            "chunk_lengths": [len(chunk) for chunk in chunks],
            "total_chunks": len(chunks),
            "total_lines": len(chunk_entries),
            "total_pages": len(pages),
            "lines_per_page": self.lines_per_page,
            "redundancy_copies": redundancy_copies,
            "interleave_enabled": bool(interleave),
            "chunk_locations": chunk_locations,
            "parity": parity_info["manifest"],
            "transport_line_separator": self.line_separator,
            "transport_line_crc": self.line_crc_mode,
            "transport_line_index_mode": self.line_index_mode,
            "metadata_level": self.metadata_level,
            "line_crc_mode": self.line_crc_mode,
            "line_index_mode": self.line_index_mode,
            "sidecar_enabled": self.render_sidecar,
            "font_fit_mode": self.font_fit_mode,
        }
        if render_layout_pages:
            manifest["render_layout"] = {
                "version": 1,
                "page_size": [int(self.page_size[0]), int(self.page_size[1])],
                "margin": int(self.margin),
                "line_gap": int(self.line_gap),
                "pages": render_layout_pages,
            }
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

        result = {
            "success": True,
            "protocol_version": PROTOCOL_VERSION,
            "artifact_id": artifact_id,
            "input_file": str(source_path),
            "output_dir": str(out_dir),
            "manifest_path": str(manifest_path),
            "payload_path": str(payload_path),
            "page_text_count": len(exported_page_texts),
            "image_count": len(exported_images),
            "total_chunks": len(chunks),
            "total_lines": len(chunk_entries),
            "total_pages": len(pages),
            "redundancy_copies": redundancy_copies,
            "interleave_enabled": bool(interleave),
            "parity_enabled": bool(parity_info["manifest"].get("enabled")),
            "parity_group_count": int(parity_info["manifest"].get("group_count", 0)),
            "metadata_level": self.metadata_level,
            "line_separator": self.line_separator,
            "line_crc_mode": self.line_crc_mode,
            "line_index_mode": self.line_index_mode,
            "sidecar_enabled": self.render_sidecar,
            "font_fit_mode": self.font_fit_mode,
            "payload_alphabet_profile": self.payload_alphabet_profile,
            "alphabet": self.payload_alphabet,
            "raw_size": len(raw),
            "compressed_size": len(compressed),
            "compressed_limit": self.max_compressed_bytes,
            "pillow_enabled": PIL_AVAILABLE,
            "page_texts": exported_page_texts,
            "images": exported_images,
        }
        if not PIL_AVAILABLE:
            result["warning"] = "Pillow is not available; exported pages_txt only and skipped PNG page rendering"
        return result

    def estimate_export_artifact(
        self,
        input_file: str,
        redundancy_copies: int = 1,
        interleave: bool = True,
        parity_group_size: int = 0,
    ) -> Dict[str, object]:
        source_path = Path(input_file)
        if not source_path.exists():
            raise FileNotFoundError("artifact not found: {}".format(input_file))

        raw = source_path.read_bytes()
        compressed = zlib.compress(raw, 9)
        redundancy_copies = int(redundancy_copies)
        if redundancy_copies < 1:
            raise ValueError("redundancy_copies must be >= 1")
        parity_group_size = int(parity_group_size)
        if parity_group_size < 0:
            raise ValueError("parity_group_size must be >= 0")

        encoded = _encode_payload_for_profile(compressed, self.payload_alphabet_profile)
        chunks = self._split_chunks(encoded, self.chunk_chars)
        parity_info = self._build_parity_info(chunks=chunks, parity_group_size=parity_group_size)
        base_entries = [(idx, payload) for idx, payload in enumerate(chunks)]
        base_entries.extend(parity_info["entries"])
        chunk_entries = self._build_chunk_entries(
            base_entries=base_entries, redundancy_copies=redundancy_copies, interleave=interleave
        )
        total_pages = int(math.ceil(float(len(chunk_entries)) / float(max(1, self.lines_per_page))))

        min_required_kib = int(math.ceil(float(len(compressed)) / 1024.0))
        warnings = []
        if len(compressed) > self.max_compressed_bytes:
            warnings.append(
                "compressed artifact exceeds current limit; raise --max-compressed-kib to at least {}".format(
                    min_required_kib
                )
            )
        if self.chunk_chars >= 64:
            warnings.append("large --chunk-chars reduces pages but increases OCR risk")
        if self.lines_per_page >= 40:
            warnings.append("large --lines-per-page reduces pages but makes each page denser")
        if total_pages >= 80:
            warnings.append("high page count; consider splitting the artifact before export")
        if parity_group_size == 0 and redundancy_copies == 1:
            warnings.append("no redundancy and no parity; any OCR loss may block recovery")

        return {
            "success": True,
            "input_file": str(source_path),
            "raw_size": len(raw),
            "compressed_size": len(compressed),
            "compressed_limit": self.max_compressed_bytes,
            "fits_current_limit": len(compressed) <= self.max_compressed_bytes,
            "minimum_recommended_max_compressed_kib": min_required_kib,
                "encoded_chars": len(encoded),
                "chunk_chars": self.chunk_chars,
                "payload_alphabet_profile": self.payload_alphabet_profile,
                "alphabet": self.payload_alphabet,
                "data_chunk_count": len(chunks),
            "parity_enabled": bool(parity_info["manifest"].get("enabled")),
            "parity_chunk_count": int(parity_info["manifest"].get("group_count", 0)),
            "redundancy_copies": redundancy_copies,
            "interleave_enabled": bool(interleave),
            "lines_per_page": self.lines_per_page,
            "total_transport_lines": len(chunk_entries),
            "estimated_total_pages": total_pages,
            "pillow_enabled": PIL_AVAILABLE,
            "warnings": warnings,
        }

    def recover_artifact(
        self,
        manifest_path: Optional[str],
        ocr_input_path: str,
        output_file: str,
        strict_payload_chars: bool = False,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_recover.recover_artifact(
            transport=self,
            manifest_path=manifest_path,
            ocr_input_path=ocr_input_path,
            output_file=output_file,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    def _recover_artifact_against_manifest(
        self,
        manifest: Dict[str, object],
        ocr_input_path: str,
        output_file: str,
        strict_payload_chars: bool = False,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_recover.recover_artifact_against_manifest(
            transport=self,
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            output_file=output_file,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    def verify_ocr_text(
        self,
        manifest_path: Optional[str],
        ocr_input_path: str,
        strict_payload_chars: bool = False,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_recover.verify_ocr_text(
            transport=self,
            manifest_path=manifest_path,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    def _verify_ocr_text_against_manifest(
        self,
        manifest: Dict[str, object],
        ocr_input_path: str,
        strict_payload_chars: bool = False,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_recover.verify_ocr_text_against_manifest(
            transport=self,
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    def replay_ocr_corrections(
        self,
        manifest_path: str,
        ocr_input_path: str,
        corrections_file: str,
        output_file: Optional[str] = None,
        report_file: Optional[str] = None,
        strict_payload_chars: bool = False,
        emit_corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_recover.replay_ocr_corrections(
            transport=self,
            manifest_path=manifest_path,
            ocr_input_path=ocr_input_path,
            corrections_file=corrections_file,
            output_file=output_file,
            report_file=report_file,
            strict_payload_chars=strict_payload_chars,
            emit_corrections_file=emit_corrections_file,
        )

    def verify_ocr_correction_replay_report(
        self,
        report_file: str,
        output_file: Optional[str] = None,
        require_success: bool = True,
    ) -> Dict[str, object]:
        return _transport_recover.verify_ocr_correction_replay_report(
            transport=self,
            report_file=report_file,
            output_file=output_file,
            require_success=require_success,
        )

    def certify_ocr_safe_confusions(
        self,
        output_dir: str,
        report_file: Optional[str] = None,
        payload_size: int = 512,
        seed: int = 20260530,
        redundancy_copies: int = 2,
        parity_group_size: int = 4,
        filename_prefix: str = "ocr_confusion_page",
    ) -> Dict[str, object]:
        return _transport_recover.certify_ocr_safe_confusions(
            transport=self,
            output_dir=output_dir,
            report_file=report_file,
            payload_size=payload_size,
            seed=seed,
            redundancy_copies=redundancy_copies,
            parity_group_size=parity_group_size,
            filename_prefix=filename_prefix,
        )

    def verify_ocr_safe_confusion_report(
        self,
        report_file: str,
        output_file: Optional[str] = None,
        require_success: bool = True,
    ) -> Dict[str, object]:
        return _transport_recover.verify_ocr_safe_confusion_report(
            report_file=report_file,
            output_file=output_file,
            require_success=require_success,
        )

    def archive_ocr_safe_evidence(
        self,
        archive_file: str,
        manifest_file: Optional[str] = None,
        confusion_report_file: Optional[str] = None,
        correction_replay_report_file: Optional[str] = None,
        require_confusion_report: bool = False,
        require_correction_replay_report: bool = False,
        require_source_report_verification: bool = False,
    ) -> Dict[str, object]:
        return _transport_recover.archive_ocr_safe_evidence(
            transport=self,
            archive_file=archive_file,
            manifest_file=manifest_file,
            confusion_report_file=confusion_report_file,
            correction_replay_report_file=correction_replay_report_file,
            require_confusion_report=require_confusion_report,
            require_correction_replay_report=require_correction_replay_report,
            require_source_report_verification=require_source_report_verification,
        )

    def verify_ocr_safe_evidence_archive(
        self,
        archive_file: str,
        manifest_file: Optional[str] = None,
        output_file: Optional[str] = None,
        require_confusion_report: bool = False,
        require_correction_replay_report: bool = False,
        require_source_report_verification: bool = False,
        require_success: bool = True,
    ) -> Dict[str, object]:
        return _transport_recover.verify_ocr_safe_evidence_archive(
            transport=self,
            archive_file=archive_file,
            manifest_file=manifest_file,
            output_file=output_file,
            require_confusion_report=require_confusion_report,
            require_correction_replay_report=require_correction_replay_report,
            require_source_report_verification=require_source_report_verification,
            require_success=require_success,
        )

    def analyze_ocr_text(
        self,
        manifest_path: Optional[str],
        ocr_input_path: str,
        strict_payload_chars: bool = False,
        max_list: int = 200,
        save_report_path: Optional[str] = None,
        emit_missing_file: Optional[str] = None,
        emit_corrections_file: Optional[str] = None,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_recover.analyze_ocr_text(
            transport=self,
            manifest_path=manifest_path,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            max_list=max_list,
            save_report_path=save_report_path,
            emit_missing_file=emit_missing_file,
            emit_corrections_file=emit_corrections_file,
            corrections_file=corrections_file,
        )

    def _analyze_ocr_text_against_manifest(
        self,
        manifest: Dict[str, object],
        ocr_input_path: str,
        strict_payload_chars: bool = False,
        max_list: int = 200,
        save_report_path: Optional[str] = None,
        emit_missing_file: Optional[str] = None,
        emit_corrections_file: Optional[str] = None,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_recover.analyze_ocr_text_against_manifest(
            transport=self,
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            max_list=max_list,
            save_report_path=save_report_path,
            emit_missing_file=emit_missing_file,
            emit_corrections_file=emit_corrections_file,
            corrections_file=corrections_file,
        )

    def extract_text_from_images(
        self,
        image_input_path: str,
        output_text_path: Optional[str],
        backend: str = "tesseract",
        lang: str = "eng",
        psm: int = 6,
        manifest_path: Optional[str] = None,
        ocr_provider_cmd: Optional[str] = None,
        ocr_provider_timeout_sec: int = 120,
    ) -> Dict[str, object]:
        image_files = self._collect_image_files(image_input_path)
        if not image_files:
            raise ValueError("no image files found in {}".format(image_input_path))

        manifest = None
        page_layouts = []
        page_layout_map = {}
        if manifest_path:
            manifest = self._load_manifest(manifest_path)
            page_layouts = self._get_render_layout_pages(manifest)
            page_layout_map = {
                int(item.get("page")): item
                for item in page_layouts
                if isinstance(item, dict) and int(item.get("page", 0)) > 0
            }
        render_layout_sidecar_supported = self._page_layouts_support_sidecar(page_layouts)
        manifest_sidecar_supported = PIL_AVAILABLE and bool(manifest) and self._manifest_has_page_entries(
            manifest
        )
        manifest_structured_supported = bool(manifest) and (
            bool(page_layouts) or self._manifest_has_page_entries(manifest)
        )
        sidecar_supported = render_layout_sidecar_supported or manifest_sidecar_supported
        tesseract_mode = _tesseract_runtime_mode()

        backend = backend.lower().strip()
        if backend == "auto":
            candidates = []
            sidecar_without_manifest_supported = (not manifest) and PIL_AVAILABLE and bool(tesseract_mode)
            if sidecar_supported or sidecar_without_manifest_supported:
                candidates.append("sidecar")
            if manifest_structured_supported and tesseract_mode:
                candidates.append("tesseract")
            if ocr_provider_cmd:
                candidates.append("external")
            if tesseract_mode and "tesseract" not in candidates:
                candidates.append("tesseract")
            if _easyocr_available():
                candidates.append("easyocr")
            if not candidates:
                raise RuntimeError("no OCR backend available for auto mode")
            last_error = None
            for one_backend in candidates:
                try:
                    result = self.extract_text_from_images(
                        image_input_path=image_input_path,
                        output_text_path=output_text_path,
                        backend=one_backend,
                        lang=lang,
                        psm=psm,
                        manifest_path=manifest_path,
                        ocr_provider_cmd=ocr_provider_cmd,
                        ocr_provider_timeout_sec=ocr_provider_timeout_sec,
                    )
                    result["backend_requested"] = "auto"
                    return result
                except Exception as exc:
                    last_error = exc
            raise RuntimeError("auto backend failed: {}".format(last_error))
        if backend == "external" and (not ocr_provider_cmd):
            raise ValueError("external backend requires --ocr-provider-cmd")
        if backend == "tesseract" and not tesseract_mode and not sidecar_supported:
            raise RuntimeError(
                "tesseract backend requires pytesseract or tesseract executable when sidecar is unavailable"
            )
        if backend == "easyocr" and not _easyocr_available() and not sidecar_supported:
            raise RuntimeError("easyocr is not available in current environment")
        if backend == "sidecar":
            if manifest_path:
                if not sidecar_supported:
                    raise RuntimeError("sidecar backend requires manifest render_layout with binary sidecar")
            else:
                if (not PIL_AVAILABLE) or (not tesseract_mode):
                    raise RuntimeError(
                        "sidecar backend without manifest requires Pillow plus pytesseract or tesseract executable"
                    )
        if backend not in ("tesseract", "easyocr", "sidecar", "external", "auto"):
            raise ValueError("unsupported backend: {}".format(backend))

        reader = None
        reader_langs = None
        if backend == "easyocr":
            reader, reader_langs = _build_easyocr_reader(lang)

        texts = []
        structured_layout_used = 0
        for image_index, image_path in enumerate(image_files):
            page_no = self._resolve_image_page_number(
                image_path=image_path,
                image_index=image_index,
                manifest=manifest,
            )
            page_layout = page_layout_map.get(page_no)
            page_entries = self._manifest_page_entries(manifest, page_no) if manifest else []
            if page_layout or page_entries:
                structured_layout_used += 1
            if backend == "external":
                text = self._run_external_ocr_provider(
                    image_path=image_path,
                    page_no=page_no,
                    lang=lang,
                    psm=psm,
                    manifest_path=manifest_path,
                    provider_cmd=str(ocr_provider_cmd),
                    timeout_sec=max(1, int(ocr_provider_timeout_sec)),
                )
            elif backend == "sidecar" and (not manifest):
                text = self._ocr_embedded_metadata_page_tesseract(
                    image_path=image_path,
                    page_no_hint=page_no,
                    lang=lang,
                    prefer_sidecar=True,
                )
            elif backend == "tesseract" and (not manifest) and PIL_AVAILABLE:
                try:
                    text = self._ocr_embedded_metadata_page_tesseract(
                        image_path=image_path,
                        page_no_hint=page_no,
                        lang=lang,
                        prefer_sidecar=True,
                    )
                except Exception:
                    text = self._ocr_single_image(
                        image_path=image_path,
                        backend=backend,
                        lang=lang,
                        psm=psm,
                        reader=reader,
                        page_layout=page_layout,
                    )
            elif backend == "sidecar" and manifest and (not page_layout) and page_entries:
                text = self._ocr_manifest_guided_page_sidecar(
                    image_path=image_path,
                    manifest=manifest,
                    page_no=page_no,
                    page_entries=page_entries,
                )
            elif backend == "tesseract" and manifest and (not page_layout) and page_entries:
                try:
                    text = self._ocr_manifest_guided_page_sidecar(
                        image_path=image_path,
                        manifest=manifest,
                        page_no=page_no,
                        page_entries=page_entries,
                    )
                except Exception:
                    text = self._ocr_manifest_guided_page_tesseract(
                        image_path=image_path,
                        manifest=manifest,
                        page_no=page_no,
                        page_entries=page_entries,
                        lang=lang,
                    )
            else:
                text = self._ocr_single_image(
                    image_path=image_path,
                    backend=backend,
                    lang=lang,
                    psm=psm,
                    reader=reader,
                    page_layout=page_layout,
                )
            texts.append(text)

        merged = "\n".join(texts).strip() + "\n"
        out_path = None
        if output_text_path:
            out_path = Path(output_text_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(merged, encoding="utf-8")

        return {
            "success": True,
            "backend": backend,
            "language": lang,
            "ocr_languages": reader_langs if reader_langs else ([lang] if backend != "sidecar" else []),
            "psm": psm,
            "manifest_path": manifest_path,
            "image_count": len(image_files),
            "image_files": [str(p) for p in image_files],
            "output_text_path": str(out_path) if out_path else None,
            "structured_layout_used": bool(structured_layout_used),
            "structured_page_count": structured_layout_used,
            "sidecar_supported": bool(sidecar_supported),
            "tesseract_mode": tesseract_mode if backend == "tesseract" and tesseract_mode else None,
            "tesseract_command": (
                TESSERACT_CMD if backend == "tesseract" and tesseract_mode == "cli" else None
            ),
            "ocr_provider_mode": "external_cmd" if backend == "external" else None,
            "ocr_provider_cmd": str(ocr_provider_cmd) if backend == "external" else None,
            "text_length": len(merged),
        }

    def recover_from_images(
        self,
        manifest_path: Optional[str],
        image_input_path: str,
        output_file: str,
        backend: str = "tesseract",
        lang: str = "eng",
        psm: int = 6,
        ocr_provider_cmd: Optional[str] = None,
        ocr_provider_timeout_sec: int = 120,
        strict_payload_chars: bool = False,
        ocr_text_output: Optional[str] = None,
        save_analyze_report: Optional[str] = None,
        emit_missing_file: Optional[str] = None,
        emit_corrections_file: Optional[str] = None,
        corrections_file: Optional[str] = None,
        max_list: int = 200,
    ) -> Dict[str, object]:
        backend = backend.lower().strip()
        temp_dir = Path(output_file).parent / ".airgap_tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        manifest = self._load_manifest(manifest_path) if manifest_path else None
        page_layouts = self._get_render_layout_pages(manifest) if manifest else []
        render_layout_sidecar_supported = self._page_layouts_support_sidecar(page_layouts) if manifest else False
        manifest_sidecar_supported = PIL_AVAILABLE and bool(manifest) and self._manifest_has_page_entries(manifest)
        manifest_structured_supported = bool(manifest) and (
            bool(page_layouts) or self._manifest_has_page_entries(manifest)
        )
        sidecar_supported = render_layout_sidecar_supported or manifest_sidecar_supported

        candidates: List[str]
        if backend == "auto":
            candidates = []
            sidecar_without_manifest_supported = (not manifest) and PIL_AVAILABLE and bool(
                _tesseract_runtime_mode()
            )
            if sidecar_supported or sidecar_without_manifest_supported:
                candidates.append("sidecar")
            if manifest_structured_supported and _tesseract_runtime_mode():
                candidates.append("tesseract")
            if ocr_provider_cmd:
                candidates.append("external")
            if _tesseract_runtime_mode():
                if "tesseract" not in candidates:
                    candidates.append("tesseract")
            if _easyocr_available():
                candidates.append("easyocr")
            if not candidates:
                raise RuntimeError("no OCR or sidecar backend available for auto mode")
        else:
            candidates = [backend]

        use_backend_suffix = backend == "auto" and len(candidates) > 1

        def _derive_path(base_path: Optional[str], suffix_tag: str, ext: str) -> str:
            if base_path:
                p = Path(base_path)
                if not use_backend_suffix:
                    return str(p)
                if p.suffix:
                    return str(p.with_name("{}_{}{}".format(p.stem, suffix_tag, p.suffix)))
                return str(p.with_name("{}_{}{}".format(p.name, suffix_tag, ext)))
            if use_backend_suffix:
                return str(temp_dir / "{}_{}{}".format(Path(output_file).stem, suffix_tag, ext))
            return str(temp_dir / "{}{}".format(Path(output_file).stem, ext))

        def _materialize_selected_path(
            requested_path: Optional[str], actual_path: Optional[str]
        ) -> Optional[str]:
            if not actual_path:
                return actual_path
            if not requested_path:
                return actual_path
            src = Path(actual_path)
            if not src.exists():
                return actual_path
            dst = Path(requested_path)
            if src != dst:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(src), str(dst))
            return str(dst)

        def _selected_output_paths(attempt: Dict[str, object]) -> Dict[str, Optional[str]]:
            analyze = attempt.get("analyze", {})
            if not isinstance(analyze, dict):
                analyze = {}
            return {
                "ocr_text_output": _materialize_selected_path(
                    ocr_text_output, attempt.get("ocr_text_output")
                ),
                "report_path": _materialize_selected_path(
                    save_analyze_report, analyze.get("report_path")
                ),
                "missing_file_path": _materialize_selected_path(
                    emit_missing_file, analyze.get("missing_file_path")
                ),
                "corrections_template_path": _materialize_selected_path(
                    emit_corrections_file, analyze.get("corrections_template_path")
                ),
            }

        def _run_backend(one_backend: str) -> Dict[str, object]:
            one_ocr_text_output = _derive_path(ocr_text_output, one_backend, ".txt")
            one_report = _derive_path(save_analyze_report, one_backend, ".json")
            one_missing = _derive_path(emit_missing_file, one_backend, ".csv")
            one_corrections = _derive_path(
                emit_corrections_file,
                one_backend,
                ".csv",
            )

            ocr_result = self.extract_text_from_images(
                image_input_path=image_input_path,
                output_text_path=one_ocr_text_output,
                backend=one_backend,
                lang=lang,
                psm=psm,
                manifest_path=manifest_path,
                ocr_provider_cmd=ocr_provider_cmd,
                ocr_provider_timeout_sec=ocr_provider_timeout_sec,
            )
            analyze = self.analyze_ocr_text(
                manifest_path=manifest_path,
                ocr_input_path=one_ocr_text_output,
                strict_payload_chars=strict_payload_chars,
                max_list=max_list,
                save_report_path=one_report,
                emit_missing_file=one_missing,
                emit_corrections_file=one_corrections,
                corrections_file=corrections_file,
            )
            score = self._analyze_score_tuple(analyze)
            return {
                "backend": one_backend,
                "score": score,
                "ocr": ocr_result,
                "analyze": analyze,
                "ocr_text_output": one_ocr_text_output,
            }

        attempts = []
        for one_backend in candidates:
            try:
                attempt = _run_backend(one_backend)
                attempts.append(attempt)
                if backend == "auto" and attempt["analyze"].get("success"):
                    best = attempt
                    selected_paths = _selected_output_paths(best)
                    recover_result = self.recover_artifact(
                        manifest_path=manifest_path,
                        ocr_input_path=best["ocr_text_output"],
                        output_file=output_file,
                        strict_payload_chars=strict_payload_chars,
                        corrections_file=corrections_file,
                    )
                    return {
                        "success": True,
                        "artifact_id": recover_result["artifact_id"],
                        "output_file": recover_result["output_file"],
                        "raw_size": recover_result["raw_size"],
                        "raw_sha256": recover_result["raw_sha256"],
                        "backend_selected": best["backend"],
                        "backend_mode": backend,
                        "ocr": {
                            "backend": best["backend"],
                            "image_count": best["ocr"].get("image_count", 0),
                            "ocr_text_output": selected_paths["ocr_text_output"],
                            "structured_layout_used": best["ocr"].get(
                                "structured_layout_used", False
                            ),
                            "tesseract_mode": best["ocr"].get("tesseract_mode"),
                            "tesseract_command": best["ocr"].get("tesseract_command"),
                        },
                        "analyze": {
                            "missing_chunks_count": best["analyze"].get("missing_chunks_count", 0),
                            "line_error_count": best["analyze"].get("line_error_count", 0),
                            "line_warning_count": best["analyze"].get("line_warning_count", 0),
                            "page_crc_error_count": best["analyze"].get("page_crc_error_count", 0),
                            "duplicate_conflict_count": best["analyze"].get("duplicate_conflict_count", 0),
                            "parity_recovered_count": best["analyze"].get("parity_recovered_count", 0),
                            "package_hash_resolved_count": best["analyze"].get("package_hash_resolved_count", 0),
                            "report_path": selected_paths["report_path"],
                            "missing_file_path": selected_paths["missing_file_path"],
                            "corrections_template_path": selected_paths[
                                "corrections_template_path"
                            ],
                            "missing_chunk_retake_plan_sample": best["analyze"].get(
                                "missing_chunk_retake_plan_sample", []
                            )[:20],
                        },
                    }
            except Exception as exc:
                attempts.append(
                    {
                        "backend": one_backend,
                        "score": (0, -10**9, -10**9, -10**9, -10**9, -10**9),
                        "ocr": {
                            "success": False,
                            "backend": one_backend,
                            "error": str(exc),
                            "image_count": 0,
                        },
                        "analyze": {
                            "success": False,
                            "message": "backend execution failed",
                            "error": str(exc),
                            "missing_chunks_count": 10**9,
                            "line_error_count": 10**9,
                            "line_warning_count": 10**9,
                            "page_crc_error_count": 10**9,
                            "duplicate_conflict_count": 10**9,
                        },
                        "ocr_text_output": None,
                    }
                )

        attempts_sorted = sorted(attempts, key=lambda x: x["score"], reverse=True)
        best = attempts_sorted[0]

        if not best["analyze"].get("success"):
            selected_paths = _selected_output_paths(best)
            compare = []
            for a in attempts_sorted:
                compare.append(
                    {
                        "backend": a["backend"],
                        "recoverable": bool(a["analyze"].get("success")),
                        "missing_chunks_count": a["analyze"].get("missing_chunks_count", 0),
                        "line_error_count": a["analyze"].get("line_error_count", 0),
                        "line_warning_count": a["analyze"].get("line_warning_count", 0),
                        "page_crc_error_count": a["analyze"].get("page_crc_error_count", 0),
                        "duplicate_conflict_count": a["analyze"].get("duplicate_conflict_count", 0),
                        "report_path": a["analyze"].get("report_path"),
                        "missing_file_path": a["analyze"].get("missing_file_path"),
                        "corrections_template_path": a["analyze"].get(
                            "corrections_template_path"
                        ),
                        "missing_chunk_retake_plan_sample": a["analyze"].get(
                            "missing_chunk_retake_plan_sample", []
                        )[:20],
                        "ocr_text_output": a["ocr_text_output"],
                        "error": a["analyze"].get("error") or a["ocr"].get("error"),
                    }
                )
            return {
                "success": False,
                "message": "ocr analyze not recoverable",
                "artifact_id": best["analyze"].get("artifact_id"),
                "backend_selected": best["backend"],
                "backend_mode": backend,
                "ocr_text_output": selected_paths["ocr_text_output"],
                "report_path": selected_paths["report_path"],
                "missing_file_path": selected_paths["missing_file_path"],
                "corrections_template_path": selected_paths["corrections_template_path"],
                "backends_compared": compare,
            }

        recover_result = self.recover_artifact(
            manifest_path=manifest_path,
            ocr_input_path=best["ocr_text_output"],
            output_file=output_file,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )
        selected_paths = _selected_output_paths(best)
        return {
            "success": True,
            "artifact_id": recover_result["artifact_id"],
            "output_file": recover_result["output_file"],
            "raw_size": recover_result["raw_size"],
            "raw_sha256": recover_result["raw_sha256"],
            "backend_selected": best["backend"],
            "backend_mode": backend,
            "ocr": {
                "backend": best["backend"],
                "image_count": best["ocr"].get("image_count", 0),
                "ocr_text_output": selected_paths["ocr_text_output"],
                "structured_layout_used": best["ocr"].get("structured_layout_used", False),
            },
            "analyze": {
                "missing_chunks_count": best["analyze"].get("missing_chunks_count", 0),
                "line_error_count": best["analyze"].get("line_error_count", 0),
                "line_warning_count": best["analyze"].get("line_warning_count", 0),
                "page_crc_error_count": best["analyze"].get("page_crc_error_count", 0),
                "duplicate_conflict_count": best["analyze"].get("duplicate_conflict_count", 0),
                "parity_recovered_count": best["analyze"].get("parity_recovered_count", 0),
                "package_hash_resolved_count": best["analyze"].get("package_hash_resolved_count", 0),
                "report_path": selected_paths["report_path"],
                "missing_file_path": selected_paths["missing_file_path"],
                "corrections_template_path": selected_paths["corrections_template_path"],
                "missing_chunk_retake_plan_sample": best["analyze"].get(
                    "missing_chunk_retake_plan_sample", []
                )[:20],
            },
        }

    def certify_reliability(
        self,
        output_dir: str,
        payload_sizes: Optional[List[int]] = None,
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
        profile_redundancy_threshold_bytes: int = _transport_certify.RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES,
        distortion_suite: str = _transport_certify.NO_DISTORTION_SUITE,
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
        return _transport_certify.certify_transport_reliability(
            transport=self,
            output_dir=output_dir,
            payload_sizes=payload_sizes,
            iterations_per_size=iterations_per_size,
            seed=seed,
            backend=backend,
            redundancy_copies=redundancy_copies,
            interleave=interleave,
            parity_group_size=parity_group_size,
            filename_prefix=filename_prefix,
            report_file=report_file,
            require_success_rate=require_success_rate,
            lang=lang,
            psm=psm,
            ocr_provider_cmd=ocr_provider_cmd,
            ocr_provider_timeout_sec=ocr_provider_timeout_sec,
            strict_payload_chars=strict_payload_chars,
            max_list=max_list,
            profile=profile,
            allow_unsafe_profile=allow_unsafe_profile,
            allow_ocr_fallback=allow_ocr_fallback,
            profile_redundancy_threshold_bytes=profile_redundancy_threshold_bytes,
            distortion_suite=distortion_suite,
            distortion_required_success_rate=distortion_required_success_rate,
            capture_corpus_file=capture_corpus_file,
            include_generated_corpus=include_generated_corpus,
            require_distinct_capture_images=require_distinct_capture_images,
            require_real_camera_perspective_correction=require_real_camera_perspective_correction,
            require_physical_print_scan=require_physical_print_scan,
            capture_attachment_report_file=capture_attachment_report_file,
            require_capture_attachment_report=require_capture_attachment_report,
            require_capture_provenance=require_capture_provenance,
            capture_required_classification=capture_required_classification,
            capture_required_success_rate=capture_required_success_rate,
            require_ocr_only_backend=require_ocr_only_backend,
            ocr_only_required_success_rate=ocr_only_required_success_rate,
        )

    def prepare_capture_corpus_kit(
        self,
        output_dir: str,
        classification: str = "lab",
        capture_medium: str = "unspecified",
        include_raw_capture_dirs: bool = False,
        perspective_correction_method: Optional[str] = None,
        payload_sizes: Optional[List[int]] = None,
        iterations_per_size: int = 1,
        seed: int = 1729,
        redundancy_copies: int = 2,
        interleave: bool = True,
        parity_group_size: int = 4,
        filename_prefix: str = "capture",
        corpus_file: Optional[str] = None,
        kit_manifest_file: Optional[str] = None,
        profile: str = _transport_certify.RELIABLE_AIRGAP_PROFILE,
        profile_redundancy_threshold_bytes: int = _transport_certify.RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES,
        capture_metadata: Optional[Dict[str, object]] = None,
        case_label_prefix: str = "capture-case",
        ocr_only_backend: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_certify.prepare_capture_corpus_kit(
            transport=self,
            output_dir=output_dir,
            classification=classification,
            capture_medium=capture_medium,
            include_raw_capture_dirs=include_raw_capture_dirs,
            perspective_correction_method=perspective_correction_method,
            payload_sizes=payload_sizes,
            iterations_per_size=iterations_per_size,
            seed=seed,
            redundancy_copies=redundancy_copies,
            interleave=interleave,
            parity_group_size=parity_group_size,
            filename_prefix=filename_prefix,
            corpus_file=corpus_file,
            kit_manifest_file=kit_manifest_file,
            profile=profile,
            profile_redundancy_threshold_bytes=profile_redundancy_threshold_bytes,
            capture_metadata=capture_metadata,
            case_label_prefix=case_label_prefix,
            ocr_only_backend=ocr_only_backend,
        )

    def attach_capture_corpus(
        self,
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
        return _transport_certify.attach_capture_corpus(
            capture_corpus_file=capture_corpus_file,
            output_dir=output_dir,
            report_file=report_file,
            kit_manifest_file=kit_manifest_file,
            require_captures=require_captures,
            require_distinct_capture_images=require_distinct_capture_images,
            require_raw_captures=require_raw_captures,
            update_corpus=update_corpus,
            update_kit_manifest=update_kit_manifest,
        )

    def package_capture_return(
        self,
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
        return _transport_certify.package_capture_return(
            capture_corpus_file=capture_corpus_file,
            output_dir=output_dir,
            capture_root=capture_root,
            raw_capture_root=raw_capture_root,
            capture_metadata_manifest_file=capture_metadata_manifest_file,
            capture_metadata=capture_metadata,
            kit_manifest_file=kit_manifest_file,
            package_file=package_file,
            return_manifest_file=return_manifest_file,
            report_file=report_file,
            return_session_id=return_session_id,
            operator=operator,
            returned_at_utc=returned_at_utc,
            require_captures=require_captures,
            require_raw_captures=require_raw_captures,
            require_capture_provenance=require_capture_provenance,
            require_all_case_labels=require_all_case_labels,
        )

    def ingest_capture_corpus(
        self,
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
        return _transport_certify.ingest_capture_corpus(
            capture_corpus_file=capture_corpus_file,
            capture_root=capture_root,
            output_dir=output_dir,
            report_file=report_file,
            kit_manifest_file=kit_manifest_file,
            raw_capture_root=raw_capture_root,
            classification=classification,
            capture_medium=capture_medium,
            capture_metadata=capture_metadata,
            capture_metadata_manifest_file=capture_metadata_manifest_file,
            require_captures=require_captures,
            require_raw_captures=require_raw_captures,
            require_all_case_labels=require_all_case_labels,
            update_corpus=update_corpus,
            update_kit_manifest=update_kit_manifest,
        )

    def correct_capture_perspective(
        self,
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
        return _transport_certify.correct_capture_perspective(
            capture_corpus_file=capture_corpus_file,
            output_dir=output_dir,
            report_file=report_file,
            kit_manifest_file=kit_manifest_file,
            method=method,
            mode=mode,
            require_raw_captures=require_raw_captures,
            require_distinct_from_raw=require_distinct_from_raw,
            update_corpus=update_corpus,
            update_kit_manifest=update_kit_manifest,
        )

    def validate_capture_corpus(
        self,
        capture_corpus_file: str,
        output_file: Optional[str] = None,
        profile: str = _transport_certify.RELIABLE_AIRGAP_PROFILE,
        backend: str = "sidecar",
        allow_ocr_fallback: bool = False,
        profile_redundancy_threshold_bytes: int = _transport_certify.RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES,
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
        return _transport_certify.validate_capture_corpus(
            capture_corpus_file=capture_corpus_file,
            output_file=output_file,
            profile=profile,
            backend=backend,
            allow_ocr_fallback=allow_ocr_fallback,
            profile_redundancy_threshold_bytes=profile_redundancy_threshold_bytes,
            require_captures=require_captures,
            require_distinct_capture_images=require_distinct_capture_images,
            require_raw_captures=require_raw_captures,
            capture_attachment_report_file=capture_attachment_report_file,
            require_capture_attachment_report=require_capture_attachment_report,
            require_capture_provenance=require_capture_provenance,
            capture_required_classification=capture_required_classification,
            require_physical_print_scan=require_physical_print_scan,
            require_real_camera_perspective_correction=(
                require_real_camera_perspective_correction
            ),
            require_ocr_only_backend=require_ocr_only_backend,
        )

    def archive_transport_evidence(
        self,
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
        return _transport_certify.archive_transport_evidence(
            report_file=report_file,
            output_dir=output_dir,
            capture_corpus_file=capture_corpus_file,
            capture_attachment_report_file=capture_attachment_report_file,
            archive_file=archive_file,
            manifest_file=manifest_file,
            require_successful_report=require_successful_report,
            require_capture_attachment_report=require_capture_attachment_report,
            require_physical_print_scan=require_physical_print_scan,
            require_real_camera_perspective_correction=(
                require_real_camera_perspective_correction
            ),
            require_ocr_only_backend=require_ocr_only_backend,
            require_profile_certified=require_profile_certified,
        )

    def verify_transport_evidence_archive(
        self,
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
        return _transport_certify.verify_transport_evidence_archive(
            archive_file=archive_file,
            manifest_file=manifest_file,
            output_file=output_file,
            require_successful_report=require_successful_report,
            require_capture_attachment_report=require_capture_attachment_report,
            require_physical_print_scan=require_physical_print_scan,
            require_real_camera_perspective_correction=(
                require_real_camera_perspective_correction
            ),
            require_ocr_only_backend=require_ocr_only_backend,
            require_profile_certified=require_profile_certified,
        )

    def replay_transport_evidence_archive(
        self,
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
        return _transport_certify.replay_transport_evidence_archive(
            transport=self,
            archive_file=archive_file,
            output_dir=output_dir,
            manifest_file=manifest_file,
            replay_report_file=replay_report_file,
            output_file=output_file,
            require_successful_report=require_successful_report,
            require_capture_attachment_report=require_capture_attachment_report,
            require_physical_print_scan=require_physical_print_scan,
            require_real_camera_perspective_correction=(
                require_real_camera_perspective_correction
            ),
            require_ocr_only_backend=require_ocr_only_backend,
            require_profile_certified=require_profile_certified,
        )

    def summarize_transport_certification_status(
        self,
        report_file: Optional[str] = None,
        verification_file: Optional[str] = None,
        archive_file: Optional[str] = None,
        manifest_file: Optional[str] = None,
        output_file: Optional[str] = None,
        verify_archive: bool = False,
        required_certified_claims: Optional[Iterable[str]] = None,
    ) -> Dict[str, object]:
        return _transport_certify.summarize_transport_certification_status(
            report_file=report_file,
            verification_file=verification_file,
            archive_file=archive_file,
            manifest_file=manifest_file,
            output_file=output_file,
            verify_archive=verify_archive,
            required_certified_claims=required_certified_claims,
        )

    def certify_capture_evidence_pipeline(
        self,
        capture_corpus_file: str,
        output_dir: str,
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
        profile: str = _transport_certify.RELIABLE_AIRGAP_PROFILE,
        backend: str = "sidecar",
        allow_ocr_fallback: bool = False,
        allow_unsafe_profile: bool = False,
        profile_redundancy_threshold_bytes: int = _transport_certify.RELIABLE_AIRGAP_REDUNDANCY_THRESHOLD_BYTES,
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
        return _transport_certify.certify_capture_evidence_pipeline(
            transport=self,
            capture_corpus_file=capture_corpus_file,
            output_dir=output_dir,
            capture_return_package_file=capture_return_package_file,
            capture_return_package_report_file=capture_return_package_report_file,
            require_capture_return_manifest=require_capture_return_manifest,
            require_capture_return_file_inventory=require_capture_return_file_inventory,
            require_capture_return_package_report=require_capture_return_package_report,
            capture_root=capture_root,
            raw_capture_root=raw_capture_root,
            capture_medium=capture_medium,
            capture_metadata=capture_metadata,
            capture_metadata_manifest_file=capture_metadata_manifest_file,
            require_all_case_labels=require_all_case_labels,
            profile=profile,
            backend=backend,
            allow_ocr_fallback=allow_ocr_fallback,
            allow_unsafe_profile=allow_unsafe_profile,
            profile_redundancy_threshold_bytes=profile_redundancy_threshold_bytes,
            redundancy_copies=redundancy_copies,
            interleave=interleave,
            parity_group_size=parity_group_size,
            require_captures=require_captures,
            require_raw_captures=require_raw_captures,
            require_distinct_capture_images=require_distinct_capture_images,
            require_capture_attachment_report=require_capture_attachment_report,
            require_capture_provenance=require_capture_provenance,
            capture_required_classification=capture_required_classification,
            capture_required_success_rate=capture_required_success_rate,
            require_success_rate=require_success_rate,
            require_physical_print_scan=require_physical_print_scan,
            require_real_camera_perspective_correction=(
                require_real_camera_perspective_correction
            ),
            require_ocr_only_backend=require_ocr_only_backend,
            ocr_only_required_success_rate=ocr_only_required_success_rate,
            require_profile_certified=require_profile_certified,
            required_certified_claims=required_certified_claims,
            lang=lang,
            psm=psm,
            ocr_provider_cmd=ocr_provider_cmd,
            ocr_provider_timeout_sec=ocr_provider_timeout_sec,
            strict_payload_chars=strict_payload_chars,
            max_list=max_list,
            kit_manifest_file=kit_manifest_file,
            capture_return_extraction_report_file=capture_return_extraction_report_file,
            ingestion_report_file=ingestion_report_file,
            attachment_report_file=attachment_report_file,
            validation_report_file=validation_report_file,
            certification_report_file=certification_report_file,
            archive_file=archive_file,
            archive_manifest_file=archive_manifest_file,
            verification_report_file=verification_report_file,
            replay_output_dir=replay_output_dir,
            replay_report_file=replay_report_file,
            replay_summary_file=replay_summary_file,
            status_report_file=status_report_file,
            pipeline_report_file=pipeline_report_file,
        )

    def _build_artifact_id(self, source_path: Path, raw: bytes) -> str:
        digest = hashlib.sha256(raw).hexdigest()[:10].upper()
        stem = re.sub(r"[^A-Z0-9_-]", "_", source_path.stem.upper())
        if not stem:
            stem = "ART"
        return "{}_{}".format(stem[:24], digest)

    def _split_chunks(self, encoded: str, chunk_chars: int) -> List[str]:
        return [encoded[i : i + chunk_chars] for i in range(0, len(encoded), chunk_chars)]

    def _build_embedded_metadata_lines(
        self,
        artifact_id: str,
        total_chunks: int,
        total_pages: int,
        raw_size: int,
        compressed_size: int,
        encoded_payload_len: int,
        raw_sha256: str,
        compressed_sha256: str,
        redundancy_copies: int,
        interleave: bool,
        parity_group_size: int,
        parity_symbol_mode: str,
    ) -> List[str]:
        raw_sha256 = raw_sha256.upper()
        compressed_sha256 = compressed_sha256.upper()
        return [
            "@CFG|AT1|CC={}|LP={}|RC={}|IL={}|PG={}|CS={}|RS={}|PF={}|PM={}|EL={}".format(
                self.chunk_chars,
                self.lines_per_page,
                int(redundancy_copies),
                1 if interleave else 0,
                int(parity_group_size),
                int(compressed_size),
                int(raw_size),
                _transport_protocol.payload_profile_code(self.payload_alphabet_profile),
                _transport_protocol.canonical_parity_symbol_mode(
                    parity_symbol_mode,
                    self.payload_alphabet_profile,
                ),
                int(encoded_payload_len),
            ),
            "@HS1|R={}|C={}".format(
                raw_sha256[:HASH_FRAGMENT_LEN],
                compressed_sha256[:HASH_FRAGMENT_LEN],
            ),
            "@HS2|R={}|C={}".format(
                raw_sha256[HASH_FRAGMENT_LEN: HASH_FRAGMENT_LEN * 2],
                compressed_sha256[HASH_FRAGMENT_LEN: HASH_FRAGMENT_LEN * 2],
            ),
        ]

    def _rebuild_parity_manifest(
        self,
        total_chunks: int,
        chunk_lengths: List[int],
        parity_group_size: int,
        payload_alphabet_profile: Optional[str] = None,
        parity_symbol_mode: Optional[str] = None,
    ) -> Dict[str, object]:
        active_profile = _transport_protocol.canonical_payload_profile(
            payload_alphabet_profile or self.payload_alphabet_profile
        )
        symbol_mode = _transport_protocol.canonical_parity_symbol_mode(
            parity_symbol_mode,
            active_profile,
        )
        if int(parity_group_size) <= 1 or int(total_chunks) <= 0:
            return {
                "enabled": False,
                "group_size": 0,
                "group_count": 0,
                "index_base": 0,
                "symbol_mode": symbol_mode,
                "groups": [],
            }

        group_size = int(parity_group_size)
        index_base = 90000
        groups = []
        group_id = 0
        for start in range(0, int(total_chunks), group_size):
            data_indices = list(range(start, min(start + group_size, int(total_chunks))))
            if not data_indices:
                continue
            parity_len = max(int(chunk_lengths[idx]) for idx in data_indices)
            groups.append(
                {
                    "group_id": group_id,
                    "data_chunk_indices": data_indices,
                    "parity_chunk_index": index_base + group_id,
                    "parity_len": parity_len,
                    "symbol_mode": symbol_mode,
                }
            )
            group_id += 1

        return {
            "enabled": True,
            "group_size": group_size,
            "group_count": len(groups),
            "index_base": index_base,
            "symbol_mode": symbol_mode,
            "groups": groups,
        }

    def _build_parity_info(self, chunks: List[str], parity_group_size: int) -> Dict[str, object]:
        """
        Build optional parity chunks over the active 32-symbol payload alphabet.
        One parity chunk per group can recover one missing chunk in that group.
        """
        if parity_group_size <= 1 or not chunks:
            parity_symbol_mode = _transport_protocol.canonical_parity_symbol_mode(
                None,
                self.payload_alphabet_profile,
            )
            return {
                "entries": [],
                "manifest": {
                    "enabled": False,
                    "group_size": 0,
                    "group_count": 0,
                    "index_base": 0,
                    "symbol_mode": parity_symbol_mode,
                    "groups": [],
                },
            }

        group_size = int(parity_group_size)
        index_base = 90000
        groups = []
        entries = []
        group_id = 0
        payload_alphabet = self.payload_alphabet
        payload_char_to_val = {ch: idx for idx, ch in enumerate(payload_alphabet)}
        parity_symbol_mode = _transport_protocol.canonical_parity_symbol_mode(
            None,
            self.payload_alphabet_profile,
        )
        payload_base = len(payload_alphabet)
        for start in range(0, len(chunks), group_size):
            data_indices = list(range(start, min(start + group_size, len(chunks))))
            if not data_indices:
                continue
            max_len = max(len(chunks[idx]) for idx in data_indices)
            parity_vals = [0] * max_len
            for idx in data_indices:
                payload = chunks[idx]
                for pos, ch in enumerate(payload):
                    if parity_symbol_mode == "modular-sum":
                        parity_vals[pos] = (parity_vals[pos] + payload_char_to_val[ch]) % payload_base
                    else:
                        parity_vals[pos] ^= payload_char_to_val[ch]
            parity_payload = "".join(payload_alphabet[val] for val in parity_vals)
            parity_idx = index_base + group_id
            entries.append((parity_idx, parity_payload))
            groups.append(
                {
                    "group_id": group_id,
                    "data_chunk_indices": data_indices,
                    "parity_chunk_index": parity_idx,
                    "parity_len": len(parity_payload),
                    "symbol_mode": parity_symbol_mode,
                }
            )
            group_id += 1

        return {
            "entries": entries,
            "manifest": {
                "enabled": True,
                "group_size": group_size,
                "group_count": len(groups),
                "index_base": index_base,
                "groups": groups,
                "symbol_mode": parity_symbol_mode,
            },
        }

    def _build_chunk_entries(
        self, base_entries: List[Tuple[int, str]], redundancy_copies: int, interleave: bool
    ) -> List[Tuple[int, str, int]]:
        """
        Build transport entries:
        - each original chunk may appear multiple copies;
        - entries can be interleaved so duplicate copies spread across pages.
        """
        total_entries = len(base_entries)
        if total_entries == 0:
            return [(0, "", 1)]

        entries = []
        copies = max(1, int(redundancy_copies))
        interleave_enabled = bool(interleave) and total_entries > 1
        step = 1
        if interleave_enabled:
            step = (total_entries // 2) + 1
            while math.gcd(step, total_entries) != 1:
                step += 1

        for copy_no in range(copies):
            if interleave_enabled:
                start = (copy_no * step) % total_entries
                for pos in range(total_entries):
                    entry_idx = (start + (pos * step)) % total_entries
                    chunk_idx, payload = base_entries[entry_idx]
                    entries.append((chunk_idx, payload, copy_no + 1))
            else:
                for chunk_idx, payload in base_entries:
                    entries.append((chunk_idx, payload, copy_no + 1))
        return entries

    def _build_pages(
        self,
        artifact_id: str,
        chunk_entries: List[Tuple[int, str, int]],
        total_chunks: int,
        metadata_lines: Optional[List[str]] = None,
        include_page_markers: bool = True,
        field_separator: str = "|",
        include_line_crc: bool = True,
        line_index_mode: str = "full",
    ) -> Tuple[List[List[str]], Dict[str, List[Dict[str, int]]]]:
        pages = []
        page_crc_canonical_pages: List[List[str]] = []
        total_lines = len(chunk_entries)
        if total_lines == 0:
            chunk_entries = [(0, "", 1)]
            total_lines = 1
        if total_chunks <= 0:
            total_chunks = 1
        metadata_lines = list(metadata_lines or [])

        chunk_locations = {}
        cursor = 0
        while cursor < total_lines:
            page_entries = chunk_entries[cursor : cursor + self.lines_per_page]
            page_index = len(pages) + 1
            header = "@META|AT1|ID={}|PAGE={}/{{TOTAL}}|CHUNKS={}|TOTAL={}".format(
                artifact_id, page_index, len(page_entries), total_chunks
            )
            lines = []
            page_crc_canonical = []
            if include_page_markers:
                lines.append(header)
                page_crc_canonical.append(header)
                lines.extend(metadata_lines)
                page_crc_canonical.extend(metadata_lines)
            for line_idx, entry in enumerate(page_entries, 1):
                chunk_index, payload, copy_no = entry
                core = "C{:05d}|{}".format(chunk_index, payload)
                crc = _crc16_hex(core)
                if line_index_mode == "full":
                    exported_line = "P{:03d}L{:03d}{}{}".format(
                        page_index,
                        line_idx,
                        field_separator,
                        core.replace("|", field_separator),
                    )
                elif line_index_mode == "chunk":
                    exported_line = core.replace("|", field_separator)
                else:
                    exported_line = payload
                if include_line_crc:
                    exported_line = "{}{}{}".format(exported_line, field_separator, crc)
                lines.append(exported_line)
                if line_index_mode == "full":
                    if include_line_crc:
                        page_crc_canonical.append(
                            "P{:03d}L{:03d}|{}|{}".format(page_index, line_idx, core, crc)
                        )
                    else:
                        page_crc_canonical.append("P{:03d}L{:03d}|{}".format(page_index, line_idx, core))
                elif line_index_mode == "chunk":
                    if include_line_crc:
                        page_crc_canonical.append("{}|{}".format(core, crc))
                    else:
                        page_crc_canonical.append(core)
                else:
                    if include_line_crc:
                        page_crc_canonical.append("{}|{}".format(payload, crc))
                    else:
                        page_crc_canonical.append(payload)
                key = str(chunk_index)
                chunk_locations.setdefault(key, []).append(
                    {
                        "page": page_index,
                        "line": line_idx,
                        "copy": int(copy_no),
                    }
                )
            # Footer CRC is finalized after total_pages placeholder is resolved.
            if include_page_markers:
                lines.append("@PAGECRC|P{:03d}|0000".format(page_index))
            pages.append(lines)
            page_crc_canonical_pages.append(page_crc_canonical)
            cursor += len(page_entries)

        total_pages = len(pages)
        for i in range(total_pages):
            if include_page_markers:
                pages[i][0] = pages[i][0].replace("{TOTAL}", str(total_pages))
                page_no = i + 1
                canonical_lines = page_crc_canonical_pages[i] if i < len(page_crc_canonical_pages) else None
                if isinstance(canonical_lines, list) and canonical_lines:
                    canonical_lines = list(canonical_lines)
                    canonical_lines[0] = canonical_lines[0].replace("{TOTAL}", str(total_pages))
                    page_crc = _crc16_hex("\n".join(canonical_lines))
                else:
                    content_lines = pages[i][:-1]
                    page_crc = _crc16_hex("\n".join(content_lines))
                pages[i][-1] = "@PAGECRC|P{:03d}|{}".format(page_no, page_crc)

        for key, locations in chunk_locations.items():
            locations.sort(key=lambda x: (int(x["copy"]), int(x["page"]), int(x["line"])))
            for rank, item in enumerate(locations, 1):
                item["priority"] = rank
                item["chunk_index"] = int(key)

        return pages, chunk_locations

    def _load_manifest(self, manifest_path: str) -> Dict[str, object]:
        path = Path(manifest_path)
        if not path.exists():
            raise FileNotFoundError("manifest not found: {}".format(manifest_path))
        manifest = json.loads(path.read_text(encoding="utf-8-sig"))
        required = [
            "protocol_version",
            "artifact_id",
            "compressed_sha256",
            "raw_sha256",
            "raw_size",
            "total_chunks",
        ]
        for key in required:
            if key not in manifest:
                raise ValueError("manifest missing field: {}".format(key))
        if manifest["protocol_version"] != PROTOCOL_VERSION:
            raise ValueError(
                "protocol mismatch: expected {}, got {}".format(
                    PROTOCOL_VERSION, manifest["protocol_version"]
                )
            )
        return manifest

    def _read_ocr_lines(self, ocr_input_path: str) -> List[str]:
        path = Path(ocr_input_path)
        if not path.exists():
            raise FileNotFoundError("ocr input not found: {}".format(ocr_input_path))

        lines = []
        if path.is_file():
            lines.extend(path.read_text(encoding="utf-8", errors="ignore").splitlines())
            return lines

        for item in sorted(path.rglob("*")):
            if not item.is_file():
                continue
            if item.suffix.lower() not in (".txt", ".log", ".ocr"):
                continue
            lines.extend(item.read_text(encoding="utf-8", errors="ignore").splitlines())
        return lines

    def _collect_image_files(self, image_input_path: str) -> List[Path]:
        path = Path(image_input_path)
        if not path.exists():
            raise FileNotFoundError("image input not found: {}".format(image_input_path))
        if path.is_file():
            if path.suffix.lower() in IMAGE_SUFFIXES:
                return [path]
            raise ValueError("file is not an image: {}".format(image_input_path))

        image_files = []
        for item in sorted(path.rglob("*")):
            if item.is_file() and item.suffix.lower() in IMAGE_SUFFIXES:
                image_files.append(item)
        return image_files

    def _get_render_layout_pages(self, manifest: Dict[str, object]) -> List[Dict[str, object]]:
        return _transport_layout.get_render_layout_pages(manifest=manifest)

    def _line_meta_has_sidecar(self, line_meta: Dict[str, object]) -> bool:
        return _transport_layout.line_meta_has_sidecar(line_meta=line_meta)

    def _page_layout_has_sidecar(self, page_layout: Dict[str, object]) -> bool:
        return _transport_layout.page_layout_has_sidecar(page_layout=page_layout)

    def _page_layouts_support_sidecar(self, page_layouts: List[Dict[str, object]]) -> bool:
        return _transport_layout.page_layouts_support_sidecar(page_layouts=page_layouts)

    def _manifest_has_page_entries(self, manifest: Dict[str, object]) -> bool:
        return _transport_layout.manifest_has_page_entries(manifest=manifest)

    def _resolve_image_page_number(
        self,
        image_path: Path,
        image_index: int,
        manifest: Optional[Dict[str, object]],
    ) -> int:
        return _transport_layout.resolve_image_page_number(
            image_path=image_path,
            image_index=image_index,
            manifest=manifest,
        )

    def _manifest_page_entries(
        self,
        manifest: Dict[str, object],
        page_no: int,
    ) -> List[Dict[str, int]]:
        return _transport_layout.manifest_page_entries(
            manifest=manifest,
            page_no=page_no,
        )

    def _manifest_entries_in_transport_order(self, manifest: Dict[str, object]) -> List[Dict[str, int]]:
        return _transport_layout.manifest_entries_in_transport_order(manifest=manifest)

    def _manifest_chunk_payload_length(self, manifest: Dict[str, object], chunk_idx: int) -> int:
        return _transport_layout.manifest_chunk_payload_length(
            manifest=manifest,
            chunk_idx=chunk_idx,
        )
    def _detect_text_bands(self, image) -> List[Dict[str, int]]:
        return _transport_ocr_pipeline.detect_text_bands(image=image)

    def _select_manifest_data_bands(
        self,
        bands: List[Dict[str, int]],
        expected_count: int,
    ) -> List[Dict[str, int]]:
        return _transport_ocr_pipeline.select_manifest_data_bands(
            bands=bands,
            expected_count=expected_count,
        )

    def _crop_primary_text_band(self, image, band: Dict[str, int]):
        return _transport_ocr_pipeline.crop_primary_text_band(
            image=image,
            band=band,
        )

    def _ocr_payload_crop_tesseract(self, image, lang: str) -> str:
        return _transport_ocr_pipeline.ocr_payload_crop_tesseract(
            transport=self,
            image=image,
            lang=lang,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
        )

    def _ocr_crc_crop_tesseract(self, image, lang: str) -> str:
        return _transport_ocr_pipeline.ocr_crc_crop_tesseract(
            transport=self,
            image=image,
            lang=lang,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
        )

    def _ocr_tesseract_variants(
        self,
        image,
        lang: str,
        whitelist: str,
        variants: List[Tuple[int, int, Optional[int]]],
    ) -> List[str]:
        return _transport_ocr_pipeline.ocr_tesseract_variants(
            transport=self,
            image=image,
            lang=lang,
            whitelist=whitelist,
            variants=variants,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
        )

    def _ocr_payload_crop_tesseract_variants(self, image, lang: str) -> List[str]:
        return _transport_ocr_pipeline.ocr_payload_crop_tesseract_variants(
            transport=self,
            image=image,
            lang=lang,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
        )

    def _ocr_crc_crop_tesseract_variants(self, image, lang: str) -> List[str]:
        return _transport_ocr_pipeline.ocr_crc_crop_tesseract_variants(
            transport=self,
            image=image,
            lang=lang,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
        )

    def _ocr_generic_line_tesseract_variants(self, image, lang: str, whitelist: str) -> List[str]:
        return _transport_ocr_pipeline.ocr_generic_line_tesseract_variants(
            transport=self,
            image=image,
            lang=lang,
            whitelist=whitelist,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
        )

    def _ocr_band_tesseract_variants(self, image, band: Dict[str, int], lang: str, whitelist: str) -> List[str]:
        return _transport_ocr_pipeline.ocr_band_tesseract_variants(
            transport=self,
            image=image,
            band=band,
            lang=lang,
            whitelist=whitelist,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
        )

    def _parse_meta_line_candidate(self, raw_texts: List[str]) -> Optional[Dict[str, int]]:
        return _transport_ocr_pipeline.parse_meta_line_candidate(raw_texts=raw_texts)

    def _parse_cfg_line_candidate(self, raw_texts: List[str]) -> Optional[Dict[str, object]]:
        return _transport_ocr_pipeline.parse_cfg_line_candidate(raw_texts=raw_texts)

    def _parse_hash_fragment_candidate(self, raw_texts: List[str], expected_kind: str, expected_part: int) -> Optional[str]:
        return _transport_ocr_pipeline.parse_hash_fragment_candidate(
            raw_texts=raw_texts,
            expected_kind=expected_kind,
            expected_part=expected_part,
        )

    def _parse_hash_compact_candidate(
        self, raw_texts: List[str], expected_part: int
    ) -> Optional[Dict[str, str]]:
        return _transport_ocr_pipeline.parse_hash_compact_candidate(
            raw_texts=raw_texts,
            expected_part=expected_part,
        )

    def _crc_windows_from_hints(self, crc_hints: List[str]) -> List[str]:
        return _transport_ocr_pipeline.crc_windows_from_hints(crc_hints=crc_hints)

    def _score_candidate_crc_against_hints(
        self,
        candidate_crc: str,
        crc_hints: List[str],
    ) -> Tuple[int, int, int, int]:
        return _transport_ocr_pipeline.score_candidate_crc_against_hints(
            candidate_crc=candidate_crc,
            crc_hints=crc_hints,
        )

    def _repair_payload_candidate_by_crc_hint(
        self,
        payload: str,
        core_prefix: str,
        crc_hint: str,
        max_attempts: int = 12000,
    ) -> Tuple[str, str, Tuple[int, int]]:
        return _transport_ocr_pipeline.repair_payload_candidate_by_crc_hint(
            payload=payload,
            core_prefix=core_prefix,
            crc_hint=crc_hint,
            max_attempts=max_attempts,
        )

    def _choose_payload_candidate_with_crc_hint(
        self,
        chunk_idx: int,
        expected_len: int,
        crc_hints: List[str],
        raw_texts: List[str],
    ) -> str:
        return _transport_ocr_pipeline.choose_payload_candidate_with_crc_hint(
            chunk_idx=chunk_idx,
            expected_len=expected_len,
            crc_hints=crc_hints,
            raw_texts=raw_texts,
        )

    def _ocr_manifest_guided_page_tesseract(
        self,
        image_path: Path,
        manifest: Dict[str, object],
        page_no: int,
        page_entries: List[Dict[str, int]],
        lang: str,
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for manifest-guided OCR extraction")
        if not page_entries:
            raise ValueError("manifest page {} does not contain chunk locations".format(page_no))
        return _transport_ocr_pipeline.ocr_manifest_guided_page_tesseract(
            transport=self,
            image_path=image_path,
            manifest=manifest,
            page_no=page_no,
            page_entries=page_entries,
            lang=lang,
            image_module=Image,
        )

    def _ocr_image_crop_tesseract(
        self,
        image,
        box: List[int],
        lang: str,
        whitelist: str,
        psm: int = 7,
    ) -> str:
        return _transport_ocr_pipeline.ocr_image_crop_tesseract(
            transport=self,
            image=image,
            box=box,
            lang=lang,
            whitelist=whitelist,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
            psm=psm,
        )

    def _tesseract_image_to_string(self, image, lang: str, config: str) -> str:
        pytesseract_mod = _load_pytesseract_module()
        if pytesseract_mod is not None:
            return pytesseract_mod.image_to_string(image, lang=lang, config=config)
        return self._tesseract_image_to_string_cli(image=image, lang=lang, config=config)

    def _tesseract_image_to_string_cli(self, image, lang: str, config: str) -> str:
        if not TESSERACT_CMD:
            raise RuntimeError("tesseract executable is not available in current environment")

        temp_path = None
        try:
            if isinstance(image, Path):
                input_path = str(image)
            elif isinstance(image, str):
                input_path = image
            else:
                fd, temp_path = tempfile.mkstemp(suffix=".png")
                os.close(fd)
                image.save(temp_path, format="PNG")
                input_path = temp_path

            cmd = [TESSERACT_CMD, input_path, "stdout"]
            if lang:
                cmd.extend(["-l", lang])
            if config:
                cmd.extend(config.split())

            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    "tesseract cli failed with exit code {}: {}".format(
                        completed.returncode,
                        stderr or "unknown error",
                    )
                )
            return completed.stdout.decode("utf-8", errors="replace")
        finally:
            if temp_path:
                try:
                    Path(temp_path).unlink()
                except Exception:
                    pass

    def _ocr_image_crop_easyocr(self, image, box: List[int], reader) -> str:
        return _transport_ocr_runtime.ocr_image_crop_easyocr(
            image=image,
            box=box,
            reader=reader,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
            load_numpy_module=_load_numpy_module,
        )

    def _decode_sidecar_payload(
        self,
        image,
        page_layout: Dict[str, object],
        line_meta: Dict[str, object],
    ) -> str:
        return _transport_ocr_runtime.decode_sidecar_payload(
            transport=self,
            image=image,
            page_layout=page_layout,
            line_meta=line_meta,
        )

    def _ocr_structured_page_sidecar(
        self,
        image_path: Path,
        page_layout: Dict[str, object],
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for structured sidecar extraction")
        return _transport_ocr_runtime.ocr_structured_page_sidecar(
            transport=self,
            image_path=image_path,
            page_layout=page_layout,
            image_module=Image,
        )

    def _decode_manifest_guided_sidecar_payload(
        self,
        image,
        band: Dict[str, int],
        payload_len: int,
    ) -> str:
        if not PIL_AVAILABLE:
            return ""
        return _transport_ocr_runtime.decode_manifest_guided_sidecar_payload(
            transport=self,
            image=image,
            band=band,
            payload_len=payload_len,
        )

    def _ocr_manifest_guided_page_sidecar(
        self,
        image_path: Path,
        manifest: Dict[str, object],
        page_no: int,
        page_entries: List[Dict[str, int]],
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for manifest-guided sidecar extraction")
        return _transport_ocr_runtime.ocr_manifest_guided_page_sidecar(
            transport=self,
            image_path=image_path,
            manifest=manifest,
            page_no=page_no,
            page_entries=page_entries,
            image_module=Image,
        )

    def _build_inferred_manifest_from_metadata(self, metadata: Dict[str, object]) -> Dict[str, object]:
        return _transport_ocr_embedded.build_inferred_manifest_from_metadata(
            metadata=metadata,
            rebuild_parity_manifest=self._rebuild_parity_manifest,
        )

    def _build_expected_page_entries(
        self,
        manifest: Dict[str, object],
        page_no: int,
        page_chunks: int,
    ) -> List[Dict[str, int]]:
        return _transport_ocr_embedded.build_expected_page_entries(
            manifest=manifest,
            page_no=page_no,
            page_chunks=page_chunks,
            build_chunk_entries=self._build_chunk_entries,
            lines_per_page_default=int(self.lines_per_page),
        )

    def _ocr_embedded_metadata_page_tesseract(
        self,
        image_path: Path,
        page_no_hint: int,
        lang: str,
        prefer_sidecar: bool,
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for embedded metadata extraction")
        return _transport_ocr_embedded.ocr_embedded_metadata_page_tesseract(
            transport=self,
            image_path=image_path,
            page_no_hint=page_no_hint,
            lang=lang,
            prefer_sidecar=prefer_sidecar,
            image_module=Image,
            pil_available=True,
        )

    def _choose_payload_candidate(
        self,
        chunk_idx: int,
        expected_len: int,
        expected_crc: str,
        raw_texts: List[str],
        payload_alphabet_profile: str = "safe-base32-v1",
    ) -> str:
        return _transport_ocr_runtime.choose_payload_candidate(
            transport=self,
            chunk_idx=chunk_idx,
            expected_len=expected_len,
            expected_crc=expected_crc,
            raw_texts=raw_texts,
            payload_alphabet_profile=payload_alphabet_profile,
        )

    def _repair_payload_candidate_by_crc(
        self,
        payload: str,
        core_prefix: str,
        expected_crc: str,
    ) -> str:
        return _transport_ocr_runtime.repair_payload_candidate_by_crc(
            payload=payload,
            core_prefix=core_prefix,
            expected_crc=expected_crc,
        )

    def _ocr_structured_page_tesseract(
        self,
        image_path: Path,
        lang: str,
        page_layout: Dict[str, object],
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for structured OCR extraction")
        return _transport_ocr_runtime.ocr_structured_page_tesseract(
            transport=self,
            image_path=image_path,
            lang=lang,
            page_layout=page_layout,
            image_module=Image,
        )

    def _ocr_structured_page_easyocr(
        self,
        image_path: Path,
        page_layout: Dict[str, object],
        reader,
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for structured OCR extraction")
        return _transport_ocr_runtime.ocr_structured_page_easyocr(
            transport=self,
            image_path=image_path,
            page_layout=page_layout,
            reader=reader,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
            load_numpy_module=_load_numpy_module,
        )

    def _parse_external_ocr_stdout(self, raw_output: str) -> str:
        return _transport_ocr_runtime.parse_external_ocr_stdout(raw_output=raw_output)

    def _run_external_ocr_provider(
        self,
        image_path: Path,
        page_no: int,
        lang: str,
        psm: int,
        manifest_path: Optional[str],
        provider_cmd: str,
        timeout_sec: int,
    ) -> str:
        return _transport_ocr_runtime.run_external_ocr_provider(
            transport=self,
            image_path=image_path,
            page_no=page_no,
            lang=lang,
            psm=psm,
            manifest_path=manifest_path,
            provider_cmd=provider_cmd,
            timeout_sec=timeout_sec,
            subprocess_module=subprocess,
        )

    def _ocr_single_image(
        self,
        image_path: Path,
        backend: str,
        lang: str,
        psm: int,
        reader=None,
        page_layout: Optional[Dict[str, object]] = None,
    ) -> str:
        return _transport_ocr_runtime.ocr_single_image(
            transport=self,
            image_path=image_path,
            backend=backend,
            lang=lang,
            psm=psm,
            reader=reader,
            page_layout=page_layout,
            pil_available=PIL_AVAILABLE,
            image_module=Image,
            resample_lanczos=RESAMPLE_LANCZOS,
            build_easyocr_reader=_build_easyocr_reader,
            load_numpy_module=_load_numpy_module,
        )

    def _score_transport_ocr_text(self, text: str) -> Tuple[int, int]:
        lines = str(text or "").splitlines()
        match = 0
        unmatched = 0
        for raw in lines:
            line = _normalize_protocol_signature(_normalize_ocr_line(raw))
            if not (line.startswith("P") or line.startswith("C")):
                continue
            if (
                LINE_PATTERN.match(line)
                or LINE_PATTERN_NOCRC.match(line)
                or LINE_PATTERN_NOSEP.match(line)
                or LINE_PATTERN_NOSEP_NOCRC.match(line)
                or LINE_PATTERN_FALLBACK.match(line)
                or LINE_PATTERN_FALLBACK_NOCRC.match(line)
                or CHUNK_PATTERN.match(line)
                or CHUNK_PATTERN_NOCRC.match(line)
                or CHUNK_PATTERN_FALLBACK.match(line)
                or CHUNK_PATTERN_FALLBACK_NOCRC.match(line)
            ):
                match += 1
            else:
                unmatched += 1
        return match, unmatched

    def _ocr_transport_page_tesseract_best_effort(self, image, lang: str, psm: int) -> str:
        whitelist = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@$_|=:/,.-"

        def _run(one_psm: int) -> str:
            config = (
                "--oem 3 --psm {} "
                "-c preserve_interword_spaces=1 "
                "-c tessedit_char_whitelist={}"
            ).format(int(one_psm), whitelist)
            return self._tesseract_image_to_string(image=image, lang=lang, config=config)

        tried = []
        best_text = _run(int(psm))
        best_match, best_unmatched = self._score_transport_ocr_text(best_text)
        tried.append(int(psm))
        if best_match >= 20 and best_unmatched <= max(2, best_match // 8):
            return best_text

        for one_psm in (11, 4):
            if int(one_psm) in tried:
                continue
            tried.append(int(one_psm))
            candidate = _run(int(one_psm))
            cand_match, cand_unmatched = self._score_transport_ocr_text(candidate)
            if (cand_match, -cand_unmatched) > (best_match, -best_unmatched):
                best_text = candidate
                best_match = cand_match
                best_unmatched = cand_unmatched
        return best_text

    def _parse_ocr_chunks(
        self,
        manifest: Dict[str, object],
        ocr_input_path: str,
        strict_payload_chars: bool,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_parser.parse_ocr_chunks(
            transport=self,
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    def _parse_ocr_chunks_payload_only_manifest(
        self,
        manifest: Dict[str, object],
        ocr_input_path: str,
        strict_payload_chars: bool,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_parser.parse_ocr_chunks_payload_only_manifest(
            transport=self,
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    def _parse_ocr_chunks_with_total(
        self,
        total_chunks: int,
        ocr_input_path: str,
        strict_payload_chars: bool,
        line_index_mode: str = "full",
        payload_alphabet_profile: Optional[str] = None,
        chunk_lengths: Optional[object] = None,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_parser.parse_ocr_chunks_with_total(
            transport=self,
            total_chunks=total_chunks,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            line_index_mode=line_index_mode,
            payload_alphabet_profile=payload_alphabet_profile,
            chunk_lengths=chunk_lengths,
            corrections_file=corrections_file,
        )

    def _choose_majority_metadata_value(self, label: str, votes: Dict[object, int]) -> Optional[object]:
        return _transport_parser.choose_majority_metadata_value(label=label, votes=votes)

    def _scan_transport_metadata(self, ocr_input_path: str) -> Dict[str, object]:
        return _transport_parser.scan_transport_metadata(transport=self, ocr_input_path=ocr_input_path)

    def _build_inferred_manifest_from_ocr(self, ocr_input_path: str) -> Dict[str, object]:
        return _transport_parser.build_inferred_manifest_from_ocr(
            transport=self,
            ocr_input_path=ocr_input_path,
        )

    def _verify_ocr_text_without_manifest(
        self,
        ocr_input_path: str,
        strict_payload_chars: bool = False,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_recover.verify_ocr_text_without_manifest(
            transport=self,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    def _recover_artifact_without_manifest(
        self,
        ocr_input_path: str,
        output_file: str,
        strict_payload_chars: bool = False,
        corrections_file: Optional[str] = None,
    ) -> Dict[str, object]:
        return _transport_recover.recover_artifact_without_manifest(
            transport=self,
            ocr_input_path=ocr_input_path,
            output_file=output_file,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    def _build_missing_chunk_records(
        self, manifest: Dict[str, object], missing_chunks: List[int]
    ) -> List[Dict[str, int]]:
        return _transport_parser.build_missing_chunk_records(
            transport=self, manifest=manifest, missing_chunks=missing_chunks
        )

    def _build_missing_chunk_retake_plan(self, records: List[Dict[str, int]]) -> List[Dict[str, int]]:
        return _transport_parser.build_missing_chunk_retake_plan(records)

    def _count_chunk_presence(self, chunks: object, total_chunks: int) -> Tuple[int, int]:
        return _transport_parser.count_chunk_presence(chunks=chunks, total_chunks=total_chunks)

    def _apply_parity_recovery(self, manifest: Dict[str, object], parsed: Dict[str, object]) -> List[int]:
        return _transport_parser.apply_parity_recovery(manifest=manifest, parsed=parsed)

    def _analyze_score_tuple(self, analyze: Dict[str, object]) -> Tuple[int, int, int, int, int, int]:
        """
        Higher is better.
        recoverable first, then fewer hard failures, then fewer warnings.
        """
        recoverable = 1 if analyze.get("success") else 0
        missing = -int(analyze.get("missing_chunks_count", 0))
        line_error = -int(analyze.get("line_error_count", 0))
        page_crc = -int(analyze.get("page_crc_error_count", 0))
        dup = -int(analyze.get("duplicate_conflict_count", 0))
        warning = -int(analyze.get("line_warning_count", 0))
        return (recoverable, missing, line_error, page_crc, dup, warning)

    def _downgrade_nonblocking_parity_conflicts(
        self, parsed: Dict[str, object], total_chunks: int
    ) -> None:
        return _transport_parser.downgrade_nonblocking_parity_conflicts(
            parsed=parsed, total_chunks=total_chunks
        )

    def _resolve_conflicts_by_package_hash(
        self,
        manifest: Dict[str, object],
        parsed: Dict[str, object],
        max_conflicts: int = 12,
        max_attempts: int = 20000,
    ) -> List[int]:
        return _transport_parser.resolve_conflicts_by_package_hash(
            transport=self,
            manifest=manifest,
            parsed=parsed,
            max_conflicts=max_conflicts,
            max_attempts=max_attempts,
        )

    def _resolve_conflicts_by_structure(
        self,
        parsed: Dict[str, object],
        total_chunks: int,
        max_conflicts: int = 10,
        max_attempts: int = 20000,
    ) -> List[int]:
        return _transport_parser.resolve_conflicts_by_structure(
            parsed=parsed,
            total_chunks=total_chunks,
            max_conflicts=max_conflicts,
            max_attempts=max_attempts,
        )

    def _raise_parse_errors(self, parsed: Dict[str, object], total_chunks: int) -> None:
        return _transport_parser.raise_parse_errors(parsed=parsed, total_chunks=total_chunks)

    def _recover_encoded_payload(
        self, manifest: Dict[str, object], ocr_input_path: str, strict_payload_chars: bool
    ) -> str:
        return _transport_recover.recover_encoded_payload(
            transport=self,
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
        )

    def _load_font(self, size: int):
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is not available")
        return _transport_render.load_font(size=size, image_font_module=ImageFont)

    def _render_page(self, lines: List[str], output_path: Path) -> Dict[str, object]:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is not available")
        return _transport_render.render_page(
            lines=lines,
            output_path=output_path,
            page_size=self.page_size,
            margin=self.margin,
            font_size=self.font_size,
            line_gap=self.line_gap,
            font_max_size=self.font_max_size,
            font_fit_mode=self.font_fit_mode,
            line_separator=self.line_separator,
            render_sidecar=self.render_sidecar,
            payload_alphabet_profile=self.payload_alphabet_profile,
            image_module=Image,
            image_draw_module=ImageDraw,
            image_font_module=ImageFont,
        )


def _build_parser():
    return _transport_cli.build_parser()


def main(argv: Optional[List[str]] = None) -> int:
    return _transport_cli.run_cli(argv=argv, transport_cls=AirgapTransportLayer)


if __name__ == "__main__":
    raise SystemExit(main())
