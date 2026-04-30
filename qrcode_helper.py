#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Airgap Transport Layer for encrypted artifacts.

Design goals:
1) only transport already-encrypted small artifacts (do not perform encryption here);
2) produce OCR-friendly canonical text + PNG pages;
3) recover artifact from OCR text with line-level CRC and package-level SHA256 verification.
"""

import argparse
import base64
import binascii
import hashlib
import itertools
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import zlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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

try:
    import pytesseract  # type: ignore

    TESSERACT_PYTHON_AVAILABLE = True
except Exception:
    pytesseract = None
    TESSERACT_PYTHON_AVAILABLE = False

TESSERACT_CMD = shutil.which("tesseract")
TESSERACT_CLI_AVAILABLE = bool(TESSERACT_CMD)

try:
    import easyocr  # type: ignore

    EASYOCR_AVAILABLE = True
except Exception:
    EASYOCR_AVAILABLE = False

try:
    import numpy as np  # type: ignore

    NUMPY_AVAILABLE = True
except Exception:
    NUMPY_AVAILABLE = False


def _tesseract_runtime_mode() -> str:
    if TESSERACT_PYTHON_AVAILABLE:
        return "pytesseract"
    if TESSERACT_CLI_AVAILABLE and TESSERACT_CMD:
        return "cli"
    return ""


TESSERACT_AVAILABLE = bool(_tesseract_runtime_mode())


PROTOCOL_VERSION = "AT1"
STD_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
SAFE_BASE32_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp")
SIDECAR_BITS_PER_ROW = 50
SIDECAR_CELL_SIZE = 6
SIDECAR_CELL_GAP = 2
HASH_FRAGMENT_LEN = 32
PAYLOAD_OCR_AMBIGUITIES = {
    "2": "Z",
    "4": "H",
    "5": "S",
    "6": "G",
    "7": "T",
    "8": "B",
    "B": "8",
    "G": "6",
    "H": "4",
    "S": "5",
    "T": "7",
    "Z": "2",
}

if len(set(SAFE_BASE32_ALPHABET)) != 32:
    raise RuntimeError("SAFE_BASE32_ALPHABET must contain exactly 32 unique chars")

STD_TO_SAFE = str.maketrans(STD_BASE32_ALPHABET, SAFE_BASE32_ALPHABET)
SAFE_TO_STD = str.maketrans(SAFE_BASE32_ALPHABET, STD_BASE32_ALPHABET)
SAFE_CHAR_TO_VAL = {ch: idx for idx, ch in enumerate(SAFE_BASE32_ALPHABET)}
SUPPORTED_FIELD_SEPARATORS = ("|", "$", "@")
SEPARATOR_CHAR_CLASS = r"\|$@"
SEPARATOR_FALLBACK_CHAR_CLASS = r"\|I$@T"

LINE_PATTERN = re.compile(
    r"^P(\d{3})L(\d{3})([" + SEPARATOR_CHAR_CLASS + r"])C(\d{5})\3([A-Z0-9]+)\3([0-9A-F]{4})$"
)
LINE_PATTERN_NOCRC = re.compile(
    r"^P(\d{3})L(\d{3})([" + SEPARATOR_CHAR_CLASS + r"])C(\d{5})\3([A-Z0-9]+)$"
)
LINE_PATTERN_NOSEP = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})C([0-9A-Z@]{5})([A-Z0-9]+)([0-9A-FIO]{4})$"
)
LINE_PATTERN_NOSEP_NOCRC = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})C([0-9A-Z@]{5})([A-Z0-9]+)$"
)
LINE_PATTERN_FALLBACK = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])C([0-9A-Z@]{5})\3([A-Z0-9$]+)\3([0-9A-FIO]{4})$"
)
LINE_PATTERN_FALLBACK_NOCRC = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])C([0-9A-Z@]{5})\3([A-Z0-9$]+)$"
)
CHUNK_PATTERN = re.compile(
    r"^C(\d{5})([" + SEPARATOR_CHAR_CLASS + r"])([A-Z0-9]+)\2([0-9A-F]{4})$"
)
CHUNK_PATTERN_NOCRC = re.compile(
    r"^C(\d{5})([" + SEPARATOR_CHAR_CLASS + r"])([A-Z0-9]+)$"
)
CHUNK_PATTERN_FALLBACK = re.compile(
    r"^C([0-9A-Z@]{5})([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])([A-Z0-9$]+)\2([0-9A-FIO]{4})$"
)
CHUNK_PATTERN_FALLBACK_NOCRC = re.compile(
    r"^C([0-9A-Z@]{5})([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])([A-Z0-9$]+)$"
)
PAYLOAD_WITH_CRC_PATTERN = re.compile(
    r"^([A-Z0-9]+)([" + SEPARATOR_CHAR_CLASS + r"])([0-9A-F]{4})$"
)
PAYLOAD_WITH_CRC_FALLBACK_PATTERN = re.compile(
    r"^([A-Z0-9$]+)([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])([0-9A-FIO]{4})$"
)
META_PATTERN = re.compile(
    r"^@META\|AT1\|ID=([A-Z0-9_-]{6,64})\|PAGE=(\d{1,3})/(\d{1,3})\|CHUNKS=(\d{1,6})\|TOTAL=(\d{1,6})$"
)
PAGECRC_PATTERN = re.compile(r"^@PAGECRC\|P(\d{3})\|([0-9A-F]{4})$")
HASH_COMPACT_PATTERN = re.compile(r"^@HS([12])\|R=([0-9A-F]{16,64})\|C=([0-9A-F]{16,64})$")
PAGE_NO_FROM_NAME_PATTERN = re.compile(r"(\d{1,4})(?!.*\d)")


def _utc_now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _crc16_hex(data: str) -> str:
    value = binascii.crc_hqx(data.encode("ascii"), 0)
    return "{:04X}".format(value)


def _to_ascii_width(text: str) -> str:
    """Convert full-width chars to half-width chars."""
    converted = []
    for ch in text:
        code = ord(ch)
        if code == 12288:  # full-width space
            converted.append(" ")
            continue
        if 65281 <= code <= 65374:
            converted.append(chr(code - 65248))
            continue
        converted.append(ch)
    return "".join(converted)


def _normalize_ocr_line(raw_line: str) -> str:
    """Normalize one OCR line into protocol-friendly text."""
    line = _to_ascii_width(raw_line)
    line = line.replace(chr(0x00A6), "|")
    line = line.replace(chr(0xFF5C), "|")
    line = line.replace(chr(0x01C0), "|")
    line = line.replace(chr(0x2223), "|")
    line = line.replace(chr(0xFF0C), ",")
    line = line.replace(chr(0x3002), ".")
    line = line.replace("﻿", "")
    line = line.replace(" ", "").replace("\t", "").replace("\r", "").replace("\n", "")
    line = line.upper()
    return line


def _normalize_payload(payload: str) -> str:
    """
    Conservative payload normalization for OCR confusion.
    The map only targets chars that are impossible in protocol payload.
    """
    # SAFE_BASE32_ALPHABET excludes I/O/0/1 intentionally.
    alias = {
        "0": "Q",
        "O": "Q",
        "1": "L",
        "I": "L",
        "$": "S",
    }
    out = []
    for ch in payload:
        c = alias.get(ch, ch)
        out.append(c)
    return "".join(out)


def _normalize_protocol_signature(line: str) -> str:
    """
    Normalize key protocol markers that OCR commonly confuses.
    Example: P0011001|...  -> P001L001|...
    """
    if not line:
        return line
    # Header/footer separators are often misread as 'I'
    if line.startswith("@METAIAT"):
        line = line.replace("@METAI", "@META|", 1).replace("I|ID=", "|ID=", 1)
        line = line.replace("IPAGE=", "|PAGE=").replace("ICHUNKS=", "|CHUNKS=").replace(
            "ITOTAL=", "|TOTAL="
        )
        line = line.replace("ATLI", "AT1|")
    if line.startswith("@PAGECRCIP"):
        line = line.replace("@PAGECRCIP", "@PAGECRC|P", 1)
    if line.startswith("@CFGIAT"):
        line = line.replace("@CFGI", "@CFG|", 1).replace("ATLI", "AT1|", 1)
        line = (
            line.replace("ICC=", "|CC=")
            .replace("ILP=", "|LP=")
            .replace("IRC=", "|RC=")
            .replace("IIL=", "|IL=")
            .replace("IPG=", "|PG=")
            .replace("ICS=", "|CS=")
            .replace("IRS=", "|RS=")
        )
    line = line.replace("|ATLI|", "|AT1|")
    if line.startswith("@CHI|"):
        line = line.replace("@CHI|", "@CH1|", 1)
    if line.startswith("@CHL|"):
        line = line.replace("@CHL|", "@CH1|", 1)
    if line.startswith("@RHI|"):
        line = line.replace("@RHI|", "@RH1|", 1)
    if line.startswith("@RHL|"):
        line = line.replace("@RHL|", "@RH1|", 1)
    if line.startswith("@CHZ|"):
        line = line.replace("@CHZ|", "@CH2|", 1)
    if line.startswith("@RHZ|"):
        line = line.replace("@RHZ|", "@RH2|", 1)
    if line.startswith("@HSI|"):
        line = line.replace("@HSI|", "@HS1|", 1)
    if line.startswith("@HSL|"):
        line = line.replace("@HSL|", "@HS1|", 1)
    if line.startswith("@HSZ|"):
        line = line.replace("@HSZ|", "@HS2|", 1)

    if line.startswith("P") and len(line) > 8:
        chars = list(line)
        if chars[4] in ("1", "I"):
            chars[4] = "L"
        line = "".join(chars)
    # Chunk-index lines in line_index_mode=chunk start with Cxxxxx<sep>.
    # OCR may confuse the leading "C" as "G/Q/O/D/@".
    if len(line) >= 7 and line[0] in ("G", "Q", "O", "D", "@"):
        sep = line[6]
        if sep in ("|", "$", "@", "I", "T"):
            token = _normalize_digit_token(line[1:6])
            if len(token) == 5 and token.isdigit():
                normalized_sep = "|" if sep in ("I", "T") else sep
                line = "C{}{}{}".format(token, normalized_sep, line[7:])
    return line


def _normalize_digit_token(token: str) -> str:
    alias = {
        "O": "0",
        "Q": "0",
        "D": "0",
        "@": "0",
        "C": "0",
        "I": "1",
        "L": "1",
        "Z": "2",
        "M": "4",
        "H": "4",
        "S": "5",
        "G": "6",
        "T": "7",
        "B": "8",
    }
    return "".join(alias.get(ch, ch) for ch in token)


def _normalize_page_line_token(token: str) -> str:
    """
    OCR normalization for page/line serials (Pxxx/Lxxx).
    Page/line fields are short and bounded, so we collapse more glyph ambiguities
    into a single class to reduce parse failures.
    """
    alias = {
        "O": "0",
        "Q": "0",
        "D": "0",
        "@": "0",
        "G": "0",
        "C": "0",
        "I": "1",
        "L": "1",
        "Z": "2",
        "M": "4",
        "H": "4",
        "S": "5",
        "T": "7",
        "B": "8",
    }
    return "".join(alias.get(ch, ch) for ch in token)


def _normalize_hex_token(token: str) -> str:
    cleaned = []
    for ch in _to_ascii_width(token).upper():
        if ch in (" ", "\t", "\r", "\n"):
            continue
        if ch not in "0123456789ABCDEFOILS":
            continue
        cleaned.append(ch)
    return (
        "".join(cleaned)
        .replace("O", "0")
        .replace("I", "1")
        .replace("L", "1")
        .replace("S", "5")
    )


def _parse_cfg_line(line: str) -> Optional[Dict[str, int]]:
    if not line.startswith("@CFG|AT1|"):
        return None
    parts = line.split("|")
    values: Dict[str, int] = {}
    for item in parts[2:]:
        if "=" not in item:
            return None
        key, value = item.split("=", 1)
        try:
            values[key] = int(_normalize_digit_token(value))
        except Exception:
            return None
    required = {"CC", "LP", "RC", "IL", "PG", "CS", "RS"}
    if not required.issubset(set(values.keys())):
        return None
    return values


def _parse_hash_fragment_line(line: str) -> Optional[Tuple[str, int, str]]:
    if not line.startswith("@") or "|" not in line:
        return None
    tag, payload = line.split("|", 1)
    if len(tag) != 4:
        return None
    kind = tag[1:3]
    if kind not in ("RH", "CH"):
        return None
    try:
        part_no = int(_normalize_digit_token(tag[3]))
    except Exception:
        return None
    if part_no not in (1, 2):
        return None
    normalized = _normalize_hex_token(payload)
    if len(normalized) < HASH_FRAGMENT_LEN:
        return None
    return kind, part_no, normalized[:HASH_FRAGMENT_LEN]


def _parse_hash_compact_line(line: str) -> Optional[Tuple[int, str, str]]:
    match = HASH_COMPACT_PATTERN.match(line)
    if not match:
        return None
    try:
        part_no = int(_normalize_digit_token(match.group(1)))
    except Exception:
        return None
    if part_no not in (1, 2):
        return None
    raw_rh = _normalize_hex_token(match.group(2))
    raw_ch = _normalize_hex_token(match.group(3))
    if len(raw_rh) < HASH_FRAGMENT_LEN or len(raw_ch) < HASH_FRAGMENT_LEN:
        return None
    return part_no, raw_rh[:HASH_FRAGMENT_LEN], raw_ch[:HASH_FRAGMENT_LEN]


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    prev = list(range(len(right) + 1))
    for left_index, left_ch in enumerate(left, 1):
        current = [left_index]
        for right_index, right_ch in enumerate(right, 1):
            substitution = prev[right_index - 1] + (0 if left_ch == right_ch else 1)
            insertion = current[right_index - 1] + 1
            deletion = prev[right_index] + 1
            current.append(min(substitution, insertion, deletion))
        prev = current
    return prev[-1]


def _build_easyocr_langs(lang: str) -> List[str]:
    """
    Map common tesseract-style language codes to EasyOCR language tags.
    Supports separators: + , ; whitespace.
    """
    source = (lang or "").strip()
    if not source:
        source = "eng"
    tokens = re.split(r"[+,;\s]+", source)
    alias = {
        "eng": "en",
        "en": "en",
        "chi_sim": "ch_sim",
        "zh_cn": "ch_sim",
        "ch_sim": "ch_sim",
        "chi_tra": "ch_tra",
        "zh_tw": "ch_tra",
        "ch_tra": "ch_tra",
        "jpn": "ja",
        "ja": "ja",
        "kor": "ko",
        "ko": "ko",
    }
    mapped = []
    for token in tokens:
        if not token:
            continue
        key = token.lower().strip().replace("-", "_")
        mapped.append(alias.get(key, key))

    if not mapped:
        mapped = ["en"]

    # Keep order while de-duplicating.
    uniq = []
    seen = set()
    for item in mapped:
        if item in seen:
            continue
        seen.add(item)
        uniq.append(item)
    return uniq


def _encode_safe_base32(data: bytes) -> str:
    standard = base64.b32encode(data).decode("ascii").rstrip("=")
    return standard.translate(STD_TO_SAFE)


def _decode_safe_base32(data: str) -> bytes:
    standard = data.translate(SAFE_TO_STD)
    padding = (-len(standard)) % 8
    if padding:
        standard = standard + ("=" * padding)
    return base64.b32decode(standard.encode("ascii"))


def _safe_base32_encoded_length(byte_len: int) -> int:
    if byte_len <= 0:
        return 0
    full_groups, remainder = divmod(int(byte_len), 5)
    length = full_groups * 8
    extra = {0: 0, 1: 2, 2: 4, 3: 5, 4: 7}[remainder]
    return length + extra


def _safe_payload_to_bits(payload: str) -> str:
    bits = []
    for ch in payload:
        bits.append("{:05b}".format(SAFE_CHAR_TO_VAL[ch]))
    return "".join(bits)


def _bits_to_safe_payload(bits: str, expected_len: int) -> str:
    out = []
    for index in range(int(expected_len)):
        start = index * 5
        chunk = bits[start : start + 5]
        if len(chunk) != 5:
            return ""
        value = int(chunk, 2)
        if value < 0 or value >= len(SAFE_BASE32_ALPHABET):
            return ""
        out.append(SAFE_BASE32_ALPHABET[value])
    return "".join(out)


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

        encoded = _encode_safe_base32(compressed)
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
                raw_sha256=raw_sha256,
                compressed_sha256=compressed_sha256,
                redundancy_copies=redundancy_copies,
                interleave=bool(interleave),
                parity_group_size=parity_group_size,
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
            "encoding": "safe_base32",
            "alphabet": SAFE_BASE32_ALPHABET,
            "raw_size": len(raw),
            "compressed_size": len(compressed),
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

        encoded = _encode_safe_base32(compressed)
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
    ) -> Dict[str, object]:
        if not manifest_path:
            return self._recover_artifact_without_manifest(
                ocr_input_path=ocr_input_path,
                output_file=output_file,
                strict_payload_chars=strict_payload_chars,
            )

        manifest = self._load_manifest(manifest_path)
        return self._recover_artifact_against_manifest(
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            output_file=output_file,
            strict_payload_chars=strict_payload_chars,
        )

    def _recover_artifact_against_manifest(
        self,
        manifest: Dict[str, object],
        ocr_input_path: str,
        output_file: str,
        strict_payload_chars: bool = False,
    ) -> Dict[str, object]:
        encoded = self._recover_encoded_payload(manifest, ocr_input_path, strict_payload_chars)
        compressed = _decode_safe_base32(encoded)
        compressed_sha = _sha256_hex(compressed)
        if compressed_sha != manifest["compressed_sha256"]:
            raise ValueError(
                "compressed sha256 mismatch: expected {}, got {}".format(
                    manifest["compressed_sha256"], compressed_sha
                )
            )

        raw = zlib.decompress(compressed)
        raw_sha = _sha256_hex(raw)
        if raw_sha != manifest["raw_sha256"]:
            raise ValueError(
                "raw sha256 mismatch: expected {}, got {}".format(manifest["raw_sha256"], raw_sha)
            )
        if len(raw) != int(manifest["raw_size"]):
            raise ValueError(
                "raw size mismatch: expected {}, got {}".format(manifest["raw_size"], len(raw))
            )

        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(raw)

        return {
            "success": True,
            "artifact_id": manifest["artifact_id"],
            "output_file": str(out_path),
            "raw_size": len(raw),
            "raw_sha256": raw_sha,
            "compressed_sha256": compressed_sha,
        }

    def verify_ocr_text(
        self,
        manifest_path: Optional[str],
        ocr_input_path: str,
        strict_payload_chars: bool = False,
    ) -> Dict[str, object]:
        if not manifest_path:
            return self._verify_ocr_text_without_manifest(
                ocr_input_path=ocr_input_path,
                strict_payload_chars=strict_payload_chars,
            )

        manifest = self._load_manifest(manifest_path)
        return self._verify_ocr_text_against_manifest(
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
        )

    def _verify_ocr_text_against_manifest(
        self,
        manifest: Dict[str, object],
        ocr_input_path: str,
        strict_payload_chars: bool = False,
    ) -> Dict[str, object]:
        encoded = self._recover_encoded_payload(manifest, ocr_input_path, strict_payload_chars)
        compressed = _decode_safe_base32(encoded)
        compressed_sha = _sha256_hex(compressed)

        ok = compressed_sha == manifest["compressed_sha256"]
        return {
            "success": ok,
            "artifact_id": manifest["artifact_id"],
            "expected_compressed_sha256": manifest["compressed_sha256"],
            "actual_compressed_sha256": compressed_sha,
            "total_chunks": int(manifest["total_chunks"]),
            "message": "verify ok" if ok else "verify failed",
        }

    def analyze_ocr_text(
        self,
        manifest_path: Optional[str],
        ocr_input_path: str,
        strict_payload_chars: bool = False,
        max_list: int = 200,
        save_report_path: Optional[str] = None,
        emit_missing_file: Optional[str] = None,
    ) -> Dict[str, object]:
        if manifest_path:
            manifest = self._load_manifest(manifest_path)
        else:
            manifest = self._build_inferred_manifest_from_ocr(ocr_input_path)
        return self._analyze_ocr_text_against_manifest(
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            max_list=max_list,
            save_report_path=save_report_path,
            emit_missing_file=emit_missing_file,
        )

    def _analyze_ocr_text_against_manifest(
        self,
        manifest: Dict[str, object],
        ocr_input_path: str,
        strict_payload_chars: bool = False,
        max_list: int = 200,
        save_report_path: Optional[str] = None,
        emit_missing_file: Optional[str] = None,
    ) -> Dict[str, object]:
        parsed = self._parse_ocr_chunks(manifest, ocr_input_path, strict_payload_chars)
        parity_recovered = self._apply_parity_recovery(manifest, parsed)
        hash_resolved = self._resolve_conflicts_by_package_hash(manifest, parsed)
        parity_recovered_after_hash = self._apply_parity_recovery(manifest, parsed)
        total_chunks = int(manifest["total_chunks"])
        self._downgrade_nonblocking_parity_conflicts(parsed, total_chunks)
        parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
        received_data_chunks, received_parity_chunks = self._count_chunk_presence(
            parsed.get("chunks", {}), total_chunks
        )

        missing = parsed["missing_chunks"]
        missing_records = self._build_missing_chunk_records(manifest, missing)
        retake_plan = self._build_missing_chunk_retake_plan(missing_records)
        cap = max(0, int(max_list))
        recoverable = (
            len(parsed["line_errors"]) == 0
            and len(parsed["duplicate_conflicts"]) == 0
            and len(missing) == 0
        )
        if recoverable and len(parsed["page_crc_errors"]) > 0:
            message = "recoverable_with_page_crc_warnings"
        else:
            message = "recoverable" if recoverable else "not recoverable"
        result = {
            "success": recoverable,
            "artifact_id": manifest["artifact_id"],
            "expected_total_chunks": int(manifest["total_chunks"]),
            "received_unique_chunks": received_data_chunks,
            "received_parity_chunks": received_parity_chunks,
            "missing_chunks_count": len(missing),
            "missing_chunks_sample": missing[:cap],
            "missing_chunk_locations_sample": missing_records[:cap],
            "missing_chunk_retake_plan_sample": retake_plan[:cap],
            "parity_recovered_count": len(parity_recovered) + len(parity_recovered_after_hash),
            "parity_recovered_sample": (parity_recovered + parity_recovered_after_hash)[:cap],
            "package_hash_resolved_count": len(hash_resolved),
            "package_hash_resolved_sample": hash_resolved[:cap],
            "line_error_count": len(parsed["line_errors"]),
            "line_errors_sample": parsed["line_errors"][: min(20, cap)],
            "line_warning_count": len(parsed["line_warnings"]),
            "line_warnings_sample": parsed["line_warnings"][: min(20, cap)],
            "page_crc_error_count": len(parsed["page_crc_errors"]),
            "page_crc_errors": parsed["page_crc_errors"][: min(20, cap)],
            "duplicate_conflict_count": len(parsed["duplicate_conflicts"]),
            "duplicate_conflicts": parsed["duplicate_conflicts"][: min(20, cap)],
            "message": message,
        }
        if emit_missing_file:
            result["missing_file_path"] = _save_missing_chunks(emit_missing_file, missing_records)
        if save_report_path:
            result["report_path"] = _save_json(save_report_path, result)
        return result

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
        sidecar_supported = render_layout_sidecar_supported or manifest_sidecar_supported
        tesseract_mode = _tesseract_runtime_mode()

        backend = backend.lower().strip()
        if backend == "auto":
            candidates = []
            if ocr_provider_cmd:
                candidates.append("external")
            if sidecar_supported or PIL_AVAILABLE:
                candidates.append("sidecar")
            if tesseract_mode:
                candidates.append("tesseract")
            if EASYOCR_AVAILABLE:
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
        if backend == "easyocr" and not EASYOCR_AVAILABLE and not sidecar_supported:
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
        if backend == "easyocr" and EASYOCR_AVAILABLE:
            reader_langs = _build_easyocr_langs(lang)
            reader = easyocr.Reader(reader_langs, gpu=False)

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
        max_list: int = 200,
    ) -> Dict[str, object]:
        backend = backend.lower().strip()
        temp_dir = Path(output_file).parent / ".airgap_tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        manifest = self._load_manifest(manifest_path) if manifest_path else None
        page_layouts = self._get_render_layout_pages(manifest) if manifest else []
        render_layout_sidecar_supported = self._page_layouts_support_sidecar(page_layouts) if manifest else False
        manifest_sidecar_supported = PIL_AVAILABLE and bool(manifest) and self._manifest_has_page_entries(manifest)
        sidecar_supported = render_layout_sidecar_supported or manifest_sidecar_supported

        candidates: List[str]
        if backend == "auto":
            candidates = []
            if ocr_provider_cmd:
                candidates.append("external")
            if sidecar_supported:
                candidates.append("sidecar")
            if _tesseract_runtime_mode():
                candidates.append("tesseract")
            if EASYOCR_AVAILABLE:
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
            }

        def _run_backend(one_backend: str) -> Dict[str, object]:
            one_ocr_text_output = _derive_path(ocr_text_output, one_backend, ".txt")
            one_report = _derive_path(save_analyze_report, one_backend, ".json")
            one_missing = _derive_path(emit_missing_file, one_backend, ".csv")

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
                            "report_path": selected_paths["report_path"],
                            "missing_file_path": selected_paths["missing_file_path"],
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
                "backends_compared": compare,
            }

        recover_result = self.recover_artifact(
            manifest_path=manifest_path,
            ocr_input_path=best["ocr_text_output"],
            output_file=output_file,
            strict_payload_chars=strict_payload_chars,
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
                "report_path": selected_paths["report_path"],
                "missing_file_path": selected_paths["missing_file_path"],
                "missing_chunk_retake_plan_sample": best["analyze"].get(
                    "missing_chunk_retake_plan_sample", []
                )[:20],
            },
        }

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
        raw_sha256: str,
        compressed_sha256: str,
        redundancy_copies: int,
        interleave: bool,
        parity_group_size: int,
    ) -> List[str]:
        raw_sha256 = raw_sha256.upper()
        compressed_sha256 = compressed_sha256.upper()
        return [
            "@CFG|AT1|CC={}|LP={}|RC={}|IL={}|PG={}|CS={}|RS={}".format(
                self.chunk_chars,
                self.lines_per_page,
                int(redundancy_copies),
                1 if interleave else 0,
                int(parity_group_size),
                int(compressed_size),
                int(raw_size),
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
        self, total_chunks: int, chunk_lengths: List[int], parity_group_size: int
    ) -> Dict[str, object]:
        if int(parity_group_size) <= 1 or int(total_chunks) <= 0:
            return {
                "enabled": False,
                "group_size": 0,
                "group_count": 0,
                "index_base": 0,
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
                }
            )
            group_id += 1

        return {
            "enabled": True,
            "group_size": group_size,
            "group_count": len(groups),
            "index_base": index_base,
            "groups": groups,
        }

    def _build_parity_info(self, chunks: List[str], parity_group_size: int) -> Dict[str, object]:
        """
        Build optional parity chunks over SAFE_BASE32 symbols.
        One parity chunk per group can recover one missing chunk in that group.
        """
        if parity_group_size <= 1 or not chunks:
            return {
                "entries": [],
                "manifest": {
                    "enabled": False,
                    "group_size": 0,
                    "group_count": 0,
                    "index_base": 0,
                    "groups": [],
                },
            }

        group_size = int(parity_group_size)
        index_base = 90000
        groups = []
        entries = []
        group_id = 0
        for start in range(0, len(chunks), group_size):
            data_indices = list(range(start, min(start + group_size, len(chunks))))
            if not data_indices:
                continue
            max_len = max(len(chunks[idx]) for idx in data_indices)
            parity_vals = [0] * max_len
            for idx in data_indices:
                payload = chunks[idx]
                for pos, ch in enumerate(payload):
                    parity_vals[pos] ^= SAFE_CHAR_TO_VAL[ch]
            parity_payload = "".join(SAFE_BASE32_ALPHABET[val] for val in parity_vals)
            parity_idx = index_base + group_id
            entries.append((parity_idx, parity_payload))
            groups.append(
                {
                    "group_id": group_id,
                    "data_chunk_indices": data_indices,
                    "parity_chunk_index": parity_idx,
                    "parity_len": len(parity_payload),
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
        render_layout = manifest.get("render_layout")
        if not isinstance(render_layout, dict):
            return []
        pages = render_layout.get("pages")
        if not isinstance(pages, list):
            return []

        parsed_pages = []
        for item in pages:
            if not isinstance(item, dict):
                continue
            try:
                page_no = int(item.get("page", 0))
            except Exception:
                continue
            if page_no <= 0:
                continue
            parsed_pages.append(item)

        parsed_pages.sort(key=lambda x: int(x.get("page", 0)))
        return parsed_pages

    def _line_meta_has_sidecar(self, line_meta: Dict[str, object]) -> bool:
        if not isinstance(line_meta, dict):
            return False
        box = line_meta.get("binary_box")
        if not isinstance(box, list) or len(box) != 4:
            return False
        for key in ("binary_rows", "binary_cols", "bit_count", "payload_len"):
            try:
                if int(line_meta.get(key, 0)) <= 0:
                    return False
            except Exception:
                return False
        return True

    def _page_layout_has_sidecar(self, page_layout: Dict[str, object]) -> bool:
        if not isinstance(page_layout, dict):
            return False
        raw_lines = page_layout.get("lines", [])
        if not isinstance(raw_lines, list) or not raw_lines:
            return False

        saw_data = False
        for item in raw_lines:
            if not isinstance(item, dict) or item.get("kind") != "data":
                continue
            saw_data = True
            if not self._line_meta_has_sidecar(item):
                return False
        return saw_data

    def _page_layouts_support_sidecar(self, page_layouts: List[Dict[str, object]]) -> bool:
        if not isinstance(page_layouts, list) or not page_layouts:
            return False
        return all(self._page_layout_has_sidecar(page_layout) for page_layout in page_layouts)

    def _manifest_has_page_entries(self, manifest: Dict[str, object]) -> bool:
        if not isinstance(manifest, dict):
            return False
        chunk_locations = manifest.get("chunk_locations")
        if not isinstance(chunk_locations, dict) or not chunk_locations:
            return False
        for raw_locations in chunk_locations.values():
            if not isinstance(raw_locations, list):
                continue
            for item in raw_locations:
                if not isinstance(item, dict):
                    continue
                try:
                    if int(item.get("page", 0)) > 0 and int(item.get("line", 0)) > 0:
                        return True
                except Exception:
                    continue
        return False

    def _resolve_image_page_number(
        self,
        image_path: Path,
        image_index: int,
        manifest: Optional[Dict[str, object]],
    ) -> int:
        total_pages = 0
        if isinstance(manifest, dict):
            try:
                total_pages = int(manifest.get("total_pages", 0))
            except Exception:
                total_pages = 0

        match = PAGE_NO_FROM_NAME_PATTERN.search(image_path.stem)
        if match:
            try:
                page_no = int(match.group(1))
            except Exception:
                page_no = 0
            else:
                if page_no > 0 and (not total_pages or page_no <= total_pages):
                    return page_no

        fallback = int(image_index) + 1
        if fallback > 0:
            return fallback
        return 1

    def _manifest_page_entries(
        self,
        manifest: Dict[str, object],
        page_no: int,
    ) -> List[Dict[str, int]]:
        chunk_locations = manifest.get("chunk_locations", {})
        if not isinstance(chunk_locations, dict):
            return []

        entries = []
        for chunk_key, raw_locations in chunk_locations.items():
            try:
                chunk_idx = int(chunk_key)
            except Exception:
                continue
            if not isinstance(raw_locations, list):
                continue
            for item in raw_locations:
                if not isinstance(item, dict):
                    continue
                try:
                    item_page = int(item.get("page"))
                    line_no = int(item.get("line"))
                    copy_no = int(item.get("copy", 1))
                    priority = int(item.get("priority", copy_no))
                except Exception:
                    continue
                if item_page != int(page_no):
                    continue
                entries.append(
                    {
                        "page": item_page,
                        "line": line_no,
                        "copy": copy_no,
                        "priority": priority,
                        "chunk_index": chunk_idx,
                    }
                )
        entries.sort(key=lambda x: (int(x["line"]), int(x["priority"]), int(x["chunk_index"])))
        return entries

    def _manifest_entries_in_transport_order(self, manifest: Dict[str, object]) -> List[Dict[str, int]]:
        chunk_locations = manifest.get("chunk_locations", {})
        if not isinstance(chunk_locations, dict):
            return []

        entries: List[Dict[str, int]] = []
        for chunk_key, raw_locations in chunk_locations.items():
            try:
                chunk_idx = int(chunk_key)
            except Exception:
                continue
            if not isinstance(raw_locations, list):
                continue
            for item in raw_locations:
                if not isinstance(item, dict):
                    continue
                try:
                    item_page = int(item.get("page", 0))
                    line_no = int(item.get("line", 0))
                    copy_no = int(item.get("copy", 1))
                    priority = int(item.get("priority", copy_no))
                except Exception:
                    continue
                if item_page <= 0 or line_no <= 0:
                    continue
                entries.append(
                    {
                        "page": item_page,
                        "line": line_no,
                        "copy": copy_no,
                        "priority": priority,
                        "chunk_index": chunk_idx,
                    }
                )
        entries.sort(key=lambda x: (int(x["page"]), int(x["line"]), int(x["copy"]), int(x["chunk_index"])))
        return entries

    def _manifest_chunk_payload_length(self, manifest: Dict[str, object], chunk_idx: int) -> int:
        chunk_lengths = manifest.get("chunk_lengths")
        if isinstance(chunk_lengths, list) and 0 <= int(chunk_idx) < len(chunk_lengths):
            try:
                return int(chunk_lengths[int(chunk_idx)])
            except Exception:
                return 0

        parity = manifest.get("parity", {})
        if not isinstance(parity, dict):
            return 0
        groups = parity.get("groups", [])
        if not isinstance(groups, list):
            return 0
        for group in groups:
            if not isinstance(group, dict):
                continue
            try:
                parity_idx = int(group.get("parity_chunk_index"))
                parity_len = int(group.get("parity_len", 0))
            except Exception:
                continue
            if parity_idx == int(chunk_idx) and parity_len > 0:
                return parity_len
        return 0

    def _detect_text_bands(self, image) -> List[Dict[str, int]]:
        gray = image.convert("L")
        binary = gray.point(lambda p: 0 if p < 180 else 255, mode="1")
        row_threshold = max(8, int(gray.width * 0.01))
        rows = []
        for y in range(gray.height):
            dark = 0
            for x in range(gray.width):
                if binary.getpixel((x, y)) == 0:
                    dark += 1
            rows.append(dark)

        raw_bands = []
        start = None
        for y, dark in enumerate(rows):
            active = dark > row_threshold
            if active and start is None:
                start = y
                continue
            if (not active) and start is not None:
                band_rows = rows[start:y]
                raw_bands.append(
                    {
                        "top": start,
                        "bottom": y - 1,
                        "height": max(1, y - start),
                        "ink_peak": max(band_rows) if band_rows else 0,
                        "ink_sum": sum(band_rows),
                    }
                )
                start = None
        if start is not None:
            band_rows = rows[start:]
            raw_bands.append(
                {
                    "top": start,
                    "bottom": gray.height - 1,
                    "height": max(1, gray.height - start),
                    "ink_peak": max(band_rows) if band_rows else 0,
                    "ink_sum": sum(band_rows),
                }
            )

        merged = []
        merge_gap = 6
        for band in raw_bands:
            if not merged or int(band["top"]) - int(merged[-1]["bottom"]) > merge_gap:
                merged.append(dict(band))
                continue
            merged[-1]["bottom"] = int(band["bottom"])
            merged[-1]["height"] = int(merged[-1]["bottom"]) - int(merged[-1]["top"]) + 1
            merged[-1]["ink_peak"] = max(int(merged[-1]["ink_peak"]), int(band["ink_peak"]))
            merged[-1]["ink_sum"] = int(merged[-1]["ink_sum"]) + int(band["ink_sum"])
        return merged

    def _select_manifest_data_bands(
        self,
        bands: List[Dict[str, int]],
        expected_count: int,
    ) -> List[Dict[str, int]]:
        if expected_count <= 0:
            return []
        if len(bands) < expected_count:
            raise ValueError(
                "detected text bands {} is less than expected lines {}".format(
                    len(bands), expected_count
                )
            )

        working = list(bands)
        if len(working) >= expected_count + 7:
            middle = working[6:-1]
            if len(middle) >= expected_count:
                working = middle
        elif len(working) >= expected_count + 2:
            middle = working[1:-1]
            if len(middle) >= expected_count:
                working = middle

        if len(working) > expected_count:
            # Keep a contiguous run to preserve line order and avoid mixing header/footer bands.
            best_window = None
            best_score = None
            window_count = len(working) - expected_count + 1
            for index in range(window_count):
                window = working[index : index + expected_count]
                tops = [int(item["top"]) for item in window]
                gaps = []
                for gap_index in range(len(tops) - 1):
                    gaps.append(max(1, tops[gap_index + 1] - tops[gap_index]))
                if gaps:
                    gap_span = max(gaps) - min(gaps)
                    avg_gap = float(sum(gaps)) / float(len(gaps))
                else:
                    gap_span = 0
                    avg_gap = 0.0
                ink_total = sum(int(item["ink_sum"]) for item in window)
                score = (gap_span, -ink_total, abs(avg_gap), index)
                if best_score is None or score < best_score:
                    best_score = score
                    best_window = window
            if best_window:
                working = list(best_window)
        return working

    def _crop_primary_text_band(self, image, band: Dict[str, int]):
        top = max(0, int(band["top"]) - 6)
        bottom = min(image.height, int(band["bottom"]) + 7)
        band_crop = image.crop((0, top, image.width, bottom)).convert("L")
        binary = band_crop.point(lambda p: 0 if p < 180 else 255, mode="1")
        # A single dark pixel column is enough here; higher thresholds split thin OCR glyphs.
        col_threshold = 1
        spans = []
        start = None
        for x in range(band_crop.width):
            dark = 0
            for y in range(band_crop.height):
                if binary.getpixel((x, y)) == 0:
                    dark += 1
            active = dark > col_threshold
            if active and start is None:
                start = x
                continue
            if (not active) and start is not None:
                spans.append({"left": start, "right": x - 1, "width": x - start})
                start = None
        if start is not None:
            spans.append({"left": start, "right": band_crop.width - 1, "width": band_crop.width - start})

        merged = []
        merge_gap = 20
        for span in spans:
            if not merged or int(span["left"]) - int(merged[-1]["right"]) > merge_gap:
                merged.append(dict(span))
                continue
            merged[-1]["right"] = int(span["right"])
            merged[-1]["width"] = int(merged[-1]["right"]) - int(merged[-1]["left"]) + 1

        if merged:
            best = sorted(merged, key=lambda item: (-int(item["width"]), int(item["left"])))[0]
            left = max(0, int(best["left"]) - 20)
            right = min(image.width, int(best["right"]) + 21)
        else:
            left = 0
            right = image.width
        return image.crop((left, top, right, bottom)).convert("L")

    def _ocr_payload_crop_tesseract(self, image, lang: str) -> str:
        crop = image.convert("L")
        crop = crop.resize((crop.width * 3, crop.height * 4), RESAMPLE_LANCZOS)
        crop = Image.eval(crop, lambda p: 255 if p > 180 else 0)
        config = (
            "--oem 3 --psm 7 "
            "-c preserve_interword_spaces=0 "
            "-c tessedit_char_whitelist={}"
        ).format(SAFE_BASE32_ALPHABET)
        return self._tesseract_image_to_string(image=crop, lang=lang, config=config)

    def _ocr_crc_crop_tesseract(self, image, lang: str) -> str:
        crop = image.convert("L")
        crop = crop.resize((crop.width * 4, crop.height * 5), RESAMPLE_LANCZOS)
        crop = Image.eval(crop, lambda p: 255 if p > 185 else 0)
        config = (
            "--oem 3 --psm 7 "
            "-c preserve_interword_spaces=0 "
            "-c tessedit_char_whitelist=0123456789ABCDEF"
        )
        return self._tesseract_image_to_string(image=crop, lang=lang, config=config)

    def _ocr_tesseract_variants(
        self,
        image,
        lang: str,
        whitelist: str,
        variants: List[Tuple[int, int, Optional[int]]],
    ) -> List[str]:
        outputs = []
        seen = set()
        base = image.convert("L")
        config = (
            "--oem 3 --psm 7 "
            "-c preserve_interword_spaces=0 "
            "-c tessedit_char_whitelist={}"
        ).format(whitelist)
        for scale_x, scale_y, threshold in variants:
            if scale_x <= 0 or scale_y <= 0:
                continue
            crop = base.resize(
                (max(1, base.width * scale_x), max(1, base.height * scale_y)),
                RESAMPLE_LANCZOS,
            )
            if threshold is not None:
                crop = Image.eval(crop, lambda p, t=threshold: 255 if p > t else 0)
            text = self._tesseract_image_to_string(image=crop, lang=lang, config=config)
            normalized = _normalize_ocr_line(text)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            outputs.append(text)
        return outputs

    def _ocr_payload_crop_tesseract_variants(self, image, lang: str) -> List[str]:
        return self._ocr_tesseract_variants(
            image=image,
            lang=lang,
            whitelist=SAFE_BASE32_ALPHABET,
            variants=[
                (3, 4, 180),
                (4, 5, 170),
                (3, 4, None),
            ],
        )

    def _ocr_crc_crop_tesseract_variants(self, image, lang: str) -> List[str]:
        return self._ocr_tesseract_variants(
            image=image,
            lang=lang,
            whitelist="0123456789ABCDEF",
            variants=[
                (4, 5, 185),
                (4, 5, None),
                (3, 4, 170),
            ],
        )

    def _ocr_generic_line_tesseract_variants(self, image, lang: str, whitelist: str) -> List[str]:
        return self._ocr_tesseract_variants(
            image=image,
            lang=lang,
            whitelist=whitelist,
            variants=[
                (3, 4, 180),
                (4, 5, 170),
                (3, 4, None),
            ],
        )

    def _ocr_band_tesseract_variants(self, image, band: Dict[str, int], lang: str, whitelist: str) -> List[str]:
        text_band = self._crop_primary_text_band(image=image, band=band)
        return self._ocr_generic_line_tesseract_variants(text_band, lang=lang, whitelist=whitelist)

    def _parse_meta_line_candidate(self, raw_texts: List[str]) -> Optional[Dict[str, int]]:
        for raw in raw_texts:
            line = _normalize_protocol_signature(_normalize_ocr_line(raw))
            match = META_PATTERN.match(line)
            if not match:
                continue
            return {
                "artifact_id": match.group(1),
                "page_no": int(match.group(2)),
                "total_pages": int(match.group(3)),
                "page_chunks": int(match.group(4)),
                "total_chunks": int(match.group(5)),
                "canonical": "@META|AT1|ID={}|PAGE={}/{}|CHUNKS={}|TOTAL={}".format(
                    match.group(1),
                    int(match.group(2)),
                    int(match.group(3)),
                    int(match.group(4)),
                    int(match.group(5)),
                ),
            }
        return None

    def _parse_cfg_line_candidate(self, raw_texts: List[str]) -> Optional[Dict[str, object]]:
        for raw in raw_texts:
            line = _normalize_protocol_signature(_normalize_ocr_line(raw))
            cfg = _parse_cfg_line(line)
            if not cfg:
                continue
            return {
                "values": cfg,
                "canonical": "@CFG|AT1|CC={}|LP={}|RC={}|IL={}|PG={}|CS={}|RS={}".format(
                    int(cfg["CC"]),
                    int(cfg["LP"]),
                    int(cfg["RC"]),
                    int(cfg["IL"]),
                    int(cfg["PG"]),
                    int(cfg["CS"]),
                    int(cfg["RS"]),
                ),
            }
        return None

    def _parse_hash_fragment_candidate(self, raw_texts: List[str], expected_kind: str, expected_part: int) -> Optional[str]:
        for raw in raw_texts:
            line = _normalize_protocol_signature(_normalize_ocr_line(raw))
            parsed = _parse_hash_fragment_line(line)
            if not parsed:
                continue
            kind, part_no, fragment = parsed
            if kind == expected_kind and int(part_no) == int(expected_part):
                return "@{}{}|{}".format(expected_kind, int(expected_part), fragment)
        return None

    def _parse_hash_compact_candidate(
        self, raw_texts: List[str], expected_part: int
    ) -> Optional[Dict[str, str]]:
        for raw in raw_texts:
            line = _normalize_protocol_signature(_normalize_ocr_line(raw))
            parsed = _parse_hash_compact_line(line)
            if not parsed:
                continue
            part_no, rh, ch = parsed
            if int(part_no) != int(expected_part):
                continue
            return {
                "canonical": "@HS{}|R={}|C={}".format(int(part_no), rh, ch),
                "RH": rh,
                "CH": ch,
            }
        return None

    def _crc_windows_from_hints(self, crc_hints: List[str]) -> List[str]:
        windows = []
        seen = set()
        for raw_hint in crc_hints:
            normalized = _normalize_hex_token(raw_hint)
            if len(normalized) < 4:
                continue
            for index in range(0, len(normalized) - 3):
                window = normalized[index : index + 4]
                if len(window) != 4 or any(ch not in "0123456789ABCDEF" for ch in window):
                    continue
                if window in seen:
                    continue
                seen.add(window)
                windows.append(window)
        return windows

    def _score_candidate_crc_against_hints(
        self,
        candidate_crc: str,
        crc_hints: List[str],
    ) -> Tuple[int, int, int, int]:
        windows = self._crc_windows_from_hints(crc_hints)
        if not windows:
            return (0, 0, 0, 0)

        diffs = sorted(
            (
                _levenshtein_distance(candidate_crc, window),
                sum(1 for left, right in zip(candidate_crc, window) if left != right),
            )
            for window in windows
        )
        exact_count = sum(1 for item in diffs if item == (0, 0))
        near_count = sum(1 for item in diffs if item[0] <= 1)
        top = diffs[: min(4, len(diffs))]
        return (-exact_count, -near_count, sum(item[0] for item in top), sum(item[1] for item in top))

    def _repair_payload_candidate_by_crc_hint(
        self,
        payload: str,
        core_prefix: str,
        crc_hint: str,
        max_attempts: int = 12000,
    ) -> Tuple[str, str, Tuple[int, int]]:
        actual_crc = _crc16_hex(core_prefix + payload)
        normalized_crc = _normalize_hex_token(crc_hint)
        if not normalized_crc or any(ch not in "0123456789ABCDEF" for ch in normalized_crc):
            return payload, actual_crc, (0, 0)

        hint_windows = []
        if len(normalized_crc) >= 4:
            for index in range(0, len(normalized_crc) - 3):
                hint_windows.append(normalized_crc[index : index + 4])
        else:
            hint_windows.append(normalized_crc)

        def _crc_score(candidate_crc: str) -> Tuple[int, int]:
            edit_distance = _levenshtein_distance(candidate_crc, normalized_crc)
            window_diff = 0
            if hint_windows and all(len(window) == len(candidate_crc) for window in hint_windows):
                window_diff = min(
                    sum(1 for left, right in zip(candidate_crc, window) if left != right)
                    for window in hint_windows
                )
            return (edit_distance, window_diff)

        best_payload = payload
        best_crc = actual_crc
        best_diff = _crc_score(actual_crc)
        if best_diff == (0, 0):
            return best_payload, best_crc, best_diff

        positions = []
        replacements = []
        for index, ch in enumerate(payload):
            alt_text = PAYLOAD_OCR_AMBIGUITIES.get(ch, "")
            alt_chars = [c for c in alt_text if c in SAFE_BASE32_ALPHABET and c != ch]
            if not alt_chars:
                continue
            positions.append(index)
            replacements.append(alt_chars)

        attempts = 0
        base_chars = list(payload)
        max_depth = min(4, len(positions))
        for depth in range(1, max_depth + 1):
            for pos_combo in itertools.combinations(range(len(positions)), depth):
                alt_lists = [replacements[pos_idx] for pos_idx in pos_combo]
                for repl_combo in itertools.product(*alt_lists):
                    attempts += 1
                    if attempts > max_attempts:
                        break
                    candidate_chars = list(base_chars)
                    for rel_idx, repl in zip(pos_combo, repl_combo):
                        candidate_chars[positions[rel_idx]] = repl
                    candidate = "".join(candidate_chars)
                    candidate_crc = _crc16_hex(core_prefix + candidate)
                    diff = _crc_score(candidate_crc)
                    if diff < best_diff:
                        best_payload = candidate
                        best_crc = candidate_crc
                        best_diff = diff
                        if diff == (0, 0):
                            return best_payload, best_crc, best_diff
                if attempts > max_attempts:
                    break
            if attempts > max_attempts:
                break

        # Short payloads are cheap to brute-force for one arbitrary symbol.
        if best_diff != (0, 0) and len(payload) <= 12:
            for index, original in enumerate(payload):
                for repl in SAFE_BASE32_ALPHABET:
                    if repl == original:
                        continue
                    candidate = payload[:index] + repl + payload[index + 1 :]
                    candidate_crc = _crc16_hex(core_prefix + candidate)
                    diff = _crc_score(candidate_crc)
                    if diff < best_diff:
                        best_payload = candidate
                        best_crc = candidate_crc
                        best_diff = diff
                        if diff == (0, 0):
                            return best_payload, best_crc, best_diff

        return best_payload, best_crc, best_diff

    def _choose_payload_candidate_with_crc_hint(
        self,
        chunk_idx: int,
        expected_len: int,
        crc_hints: List[str],
        raw_texts: List[str],
    ) -> str:
        if expected_len <= 0:
            return ""

        sep_chars = {"X", "I", "1", "|"}
        candidates = []
        seen = set()
        all_crc_hints = list(crc_hints or [])

        for raw in raw_texts:
            line = _normalize_protocol_signature(_normalize_ocr_line(raw))
            chunk_match = re.search(r"C[0-9OIL]{5}", line)
            segment = line[chunk_match.end() :] if chunk_match else line
            crc_match = re.search(r"([0-9A-FIOBLS]{4})$", segment)
            parts = []
            if crc_match and crc_match.start(1) > 0:
                all_crc_hints.append(crc_match.group(1))
                parts.append(segment[: crc_match.start(1)])
            parts.append(segment)
            for part in parts:
                if part[:1] in sep_chars:
                    part = part[1:]
                if part[-1:] in sep_chars:
                    part = part[:-1]
                normalized = _normalize_payload(part)
                safe = "".join(ch for ch in normalized if ch in SAFE_BASE32_ALPHABET)
                if not safe:
                    continue
                if len(safe) == expected_len:
                    variants = [safe]
                elif len(safe) > expected_len:
                    if (chunk_match is None) and crc_match:
                        tail_start = len(safe) - expected_len
                        window_start = max(0, tail_start - 2)
                        window_end = min(len(safe) - expected_len, tail_start + 2)
                        variants = [
                            safe[start : start + expected_len]
                            for start in range(window_start, window_end + 1)
                        ]
                    else:
                        variants = [
                            safe[start : start + expected_len]
                            for start in range(0, len(safe) - expected_len + 1)
                        ]
                else:
                    variants = []
                for candidate in variants:
                    if candidate in seen:
                        continue
                    seen.add(candidate)
                    candidates.append(candidate)

        if not candidates:
            return ""

        ranked = []
        core_prefix = "C{:05d}|".format(int(chunk_idx))
        windows = self._crc_windows_from_hints(all_crc_hints)
        for candidate in candidates:
            if windows:
                for one_hint in windows:
                    repaired, actual_crc, diff = self._repair_payload_candidate_by_crc_hint(
                        payload=candidate,
                        core_prefix=core_prefix,
                        crc_hint=one_hint,
                    )
                    ranked.append(
                        (
                            self._score_candidate_crc_against_hints(actual_crc, all_crc_hints),
                            diff,
                            repaired,
                            actual_crc,
                        )
                    )
            else:
                actual_crc = _crc16_hex(core_prefix + candidate)
                ranked.append(((0, 0, 0, 0), (0, 0), candidate, actual_crc))
        ranked.sort(key=lambda item: (item[0], item[1], item[2]))
        return ranked[0][2]

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

        image = Image.open(str(image_path)).convert("L")
        bands = self._detect_text_bands(image)
        data_bands = self._select_manifest_data_bands(bands, len(page_entries))
        if len(data_bands) != len(page_entries):
            raise ValueError(
                "manifest-guided OCR band mismatch: expected {} got {}".format(
                    len(page_entries), len(data_bands)
                )
            )

        lines = []
        for band, entry in zip(data_bands, page_entries):
            chunk_idx = int(entry["chunk_index"])
            payload_len = self._manifest_chunk_payload_length(manifest, chunk_idx)
            if payload_len <= 0:
                raise ValueError("missing chunk length for chunk {}".format(chunk_idx))

            text_band = self._crop_primary_text_band(image=image, band=band)
            total_chars = 16 + payload_len + 1 + 4
            char_width = float(text_band.width) / float(max(1, total_chars))
            pad = max(2, int(round(char_width * 0.25)))

            payload_left = max(0, int(round(16 * char_width)) - pad)
            payload_right = min(
                text_band.width,
                int(round((16 + payload_len) * char_width)) + pad,
            )
            crc_left = max(0, int(round((16 + payload_len + 1) * char_width)) - pad)
            crc_right = min(
                text_band.width,
                int(round((16 + payload_len + 5) * char_width)) + pad,
            )

            payload_crop = text_band.crop((payload_left, 0, max(payload_left + 1, payload_right), text_band.height))
            crc_crop = text_band.crop((crc_left, 0, max(crc_left + 1, crc_right), text_band.height))

            payload_raws = self._ocr_payload_crop_tesseract_variants(payload_crop, lang=lang)
            line_raws = self._ocr_payload_crop_tesseract_variants(text_band, lang=lang)
            crc_hints = self._ocr_crc_crop_tesseract_variants(crc_crop, lang=lang)
            payload = self._choose_payload_candidate_with_crc_hint(
                chunk_idx=chunk_idx,
                expected_len=payload_len,
                crc_hints=crc_hints,
                raw_texts=payload_raws + line_raws,
            )
            if not payload:
                raise ValueError(
                    "manifest-guided OCR failed to recover payload at page={} line={} chunk={}".format(
                        int(entry["page"]), int(entry["line"]), chunk_idx
                    )
                )

            actual_crc = _crc16_hex("C{:05d}|{}".format(chunk_idx, payload))
            lines.append(
                "P{:03d}L{:03d}|C{:05d}|{}|{}".format(
                    int(entry["page"]),
                    int(entry["line"]),
                    chunk_idx,
                    payload,
                    actual_crc,
                )
            )
        return "\n".join(lines)

    def _ocr_image_crop_tesseract(
        self,
        image,
        box: List[int],
        lang: str,
        whitelist: str,
        psm: int = 7,
    ) -> str:
        left = max(0, int(box[0]))
        top = max(0, int(box[1]))
        right = max(left + 1, int(box[2]))
        bottom = max(top + 1, int(box[3]))
        crop = image.crop((left, top, right, bottom)).convert("L")
        scale_x = 3
        scale_y = 4
        crop = crop.resize((crop.width * scale_x, crop.height * scale_y), RESAMPLE_LANCZOS)
        bordered = Image.new("L", (crop.width + 48, crop.height + 32), 255)
        bordered.paste(crop, (24, 16))
        crop = Image.eval(bordered, lambda p: 255 if p > 180 else 0)
        config = (
            "--oem 3 --psm {} "
            "-c preserve_interword_spaces=0 "
            "-c tessedit_char_whitelist={}"
        ).format(int(psm), whitelist)
        return self._tesseract_image_to_string(
            image=crop,
            lang=lang,
            config=config,
        )

    def _tesseract_image_to_string(self, image, lang: str, config: str) -> str:
        if TESSERACT_PYTHON_AVAILABLE:
            return pytesseract.image_to_string(image, lang=lang, config=config)
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
        if reader is None:
            raise RuntimeError("easyocr reader is required for structured OCR extraction")
        if not NUMPY_AVAILABLE:
            raise RuntimeError("numpy is required for structured easyocr extraction")

        left = max(0, int(box[0]))
        top = max(0, int(box[1]))
        right = max(left + 1, int(box[2]))
        bottom = max(top + 1, int(box[3]))
        crop = image.crop((left, top, right, bottom)).convert("L")
        crop = crop.resize((crop.width * 3, crop.height * 4), RESAMPLE_LANCZOS)
        bordered = Image.new("L", (crop.width + 48, crop.height + 32), 255)
        bordered.paste(crop, (24, 16))
        crop_array = np.array(bordered)
        lines = reader.readtext(crop_array, detail=0, paragraph=False)
        return "\n".join(lines)

    def _decode_sidecar_payload(
        self,
        image,
        page_layout: Dict[str, object],
        line_meta: Dict[str, object],
    ) -> str:
        box = line_meta.get("binary_box")
        if not isinstance(box, list) or len(box) != 4:
            return ""

        try:
            rows = int(line_meta.get("binary_rows", 0))
            cols = int(line_meta.get("binary_cols", 0))
            bit_count = int(line_meta.get("bit_count", 0))
            payload_len = int(line_meta.get("payload_len", 0))
        except Exception:
            return ""
        if rows <= 0 or cols <= 0 or bit_count <= 0 or payload_len <= 0:
            return ""

        source_w = max(1, int(page_layout.get("page_width", image.width)))
        source_h = max(1, int(page_layout.get("page_height", image.height)))
        scale_x = float(image.width) / float(source_w)
        scale_y = float(image.height) / float(source_h)

        left = int(round(float(box[0]) * scale_x))
        top = int(round(float(box[1]) * scale_y))
        cell_w = max(1, int(round(float(line_meta.get("binary_cell", SIDECAR_CELL_SIZE)) * scale_x)))
        cell_h = max(1, int(round(float(line_meta.get("binary_cell", SIDECAR_CELL_SIZE)) * scale_y)))
        gap_x = max(0, int(round(float(line_meta.get("binary_gap", SIDECAR_CELL_GAP)) * scale_x)))
        gap_y = max(0, int(round(float(line_meta.get("binary_gap", SIDECAR_CELL_GAP)) * scale_y)))

        gray = image.convert("L")
        bits = []
        for bit_index in range(bit_count):
            row = bit_index // cols
            col = bit_index % cols
            sample_x = left + col * (cell_w + gap_x) + (cell_w // 2)
            sample_y = top + row * (cell_h + gap_y) + (cell_h // 2)
            sample_x = min(max(0, sample_x), gray.width - 1)
            sample_y = min(max(0, sample_y), gray.height - 1)
            pixel = gray.getpixel((sample_x, sample_y))
            bits.append("1" if pixel < 128 else "0")

        return _bits_to_safe_payload("".join(bits), payload_len)

    def _ocr_structured_page_sidecar(
        self,
        image_path: Path,
        page_layout: Dict[str, object],
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for structured sidecar extraction")

        raw_lines = page_layout.get("lines", [])
        if not isinstance(raw_lines, list):
            raw_lines = []
        if not raw_lines:
            raise ValueError("structured sidecar page layout is missing lines")

        image = Image.open(str(image_path)).convert("L")
        data_lines = []
        for item in raw_lines:
            if not isinstance(item, dict) or item.get("kind") != "data":
                continue
            try:
                page_no = int(item.get("page"))
                line_no = int(item.get("line_no"))
                chunk_idx = int(item.get("chunk_index"))
            except Exception:
                continue
            expected_crc = str(item.get("expected_crc", ""))
            payload = self._decode_sidecar_payload(image=image, page_layout=page_layout, line_meta=item)
            if not payload:
                raise ValueError(
                    "structured sidecar payload missing at page={} line={} chunk={}".format(
                        page_no, line_no, chunk_idx
                    )
                )
            data_lines.append(
                "P{:03d}L{:03d}|C{:05d}|{}|{}".format(
                    page_no, line_no, chunk_idx, payload, expected_crc
                )
            )

        if not data_lines:
            raise ValueError("structured sidecar page layout does not contain data lines")
        return "\n".join(data_lines)

    def _decode_manifest_guided_sidecar_payload(
        self,
        image,
        band: Dict[str, int],
        payload_len: int,
    ) -> str:
        if (not PIL_AVAILABLE) or payload_len <= 0:
            return ""

        bit_count = int(payload_len) * 5
        cols = SIDECAR_BITS_PER_ROW
        rows = int(math.ceil(float(bit_count) / float(cols)))
        sidecar_width = cols * SIDECAR_CELL_SIZE + (cols - 1) * SIDECAR_CELL_GAP
        sidecar_height = rows * SIDECAR_CELL_SIZE + (rows - 1) * SIDECAR_CELL_GAP
        left = int(image.width - self.margin - sidecar_width)
        if left < 0:
            return ""

        band_mid = (int(band["top"]) + int(band["bottom"])) // 2
        top = int(max(0, band_mid - (sidecar_height // 2)))
        if top + sidecar_height > image.height:
            top = max(0, image.height - sidecar_height)

        gray = image.convert("L")
        best_payload = ""
        best_score = None
        for offset_x in range(-4, 5):
            for offset_y in range(-8, 9):
                sample_left = left + offset_x
                sample_top = top + offset_y
                if sample_left < 0 or sample_top < 0:
                    continue
                if sample_left + sidecar_width > gray.width or sample_top + sidecar_height > gray.height:
                    continue

                bits = []
                samples = []
                for bit_index in range(bit_count):
                    row = bit_index // cols
                    col = bit_index % cols
                    sample_x = sample_left + col * (SIDECAR_CELL_SIZE + SIDECAR_CELL_GAP) + (
                        SIDECAR_CELL_SIZE // 2
                    )
                    sample_y = sample_top + row * (SIDECAR_CELL_SIZE + SIDECAR_CELL_GAP) + (
                        SIDECAR_CELL_SIZE // 2
                    )
                    pixel = gray.getpixel((sample_x, sample_y))
                    samples.append(int(pixel))
                    bits.append("1" if pixel < 128 else "0")

                if not samples:
                    continue
                dark = sum(1 for pixel in samples if pixel < 128)
                dark_ratio = float(dark) / float(len(samples))
                contrast = max(samples) - min(samples)
                if dark_ratio <= 0.03 or dark_ratio >= 0.97:
                    continue
                if contrast < 80:
                    continue

                payload = _bits_to_safe_payload("".join(bits), payload_len)
                if not payload:
                    continue
                balance_penalty = abs(dark_ratio - 0.5)
                score = (balance_penalty, -contrast, abs(offset_x) + abs(offset_y))
                if best_score is None or score < best_score:
                    best_score = score
                    best_payload = payload

        return best_payload

    def _ocr_manifest_guided_page_sidecar(
        self,
        image_path: Path,
        manifest: Dict[str, object],
        page_no: int,
        page_entries: List[Dict[str, int]],
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for manifest-guided sidecar extraction")
        if not page_entries:
            raise ValueError("manifest page {} does not contain chunk locations".format(page_no))

        image = Image.open(str(image_path)).convert("L")
        bands = self._detect_text_bands(image)
        data_bands = self._select_manifest_data_bands(bands, len(page_entries))
        if len(data_bands) != len(page_entries):
            raise ValueError(
                "manifest-guided sidecar band mismatch: expected {} got {}".format(
                    len(page_entries), len(data_bands)
                )
            )

        lines = []
        for band, entry in zip(data_bands, page_entries):
            chunk_idx = int(entry["chunk_index"])
            payload_len = self._manifest_chunk_payload_length(manifest, chunk_idx)
            payload = self._decode_manifest_guided_sidecar_payload(
                image=image,
                band=band,
                payload_len=payload_len,
            )
            if not payload:
                raise ValueError(
                    "manifest-guided sidecar failed at page={} line={} chunk={}".format(
                        int(entry["page"]), int(entry["line"]), chunk_idx
                    )
                )
            actual_crc = _crc16_hex("C{:05d}|{}".format(chunk_idx, payload))
            lines.append(
                "P{:03d}L{:03d}|C{:05d}|{}|{}".format(
                    int(entry["page"]),
                    int(entry["line"]),
                    chunk_idx,
                    payload,
                    actual_crc,
                )
            )

        return "\n".join(lines)

    def _build_inferred_manifest_from_metadata(self, metadata: Dict[str, object]) -> Dict[str, object]:
        manifest: Dict[str, object] = {
            "protocol_version": PROTOCOL_VERSION,
            "artifact_id": str(metadata["artifact_id"]),
            "total_chunks": int(metadata["total_chunks"]),
            "total_pages": int(metadata.get("total_pages", 0) or 0),
            "lines_per_page": int(metadata["LP"]),
            "transport_line_index_mode": str(metadata.get("transport_line_index_mode", "full")),
            "_metadata_source": "embedded_headers",
            "_embedded_metadata_complete": True,
        }

        chunk_chars = int(metadata["CC"])
        compressed_size = int(metadata["CS"])
        total_chunks = int(metadata["total_chunks"])
        encoded_len = _safe_base32_encoded_length(compressed_size)
        expected_total_chunks = int(math.ceil(float(encoded_len) / float(chunk_chars))) if encoded_len > 0 else 0
        if expected_total_chunks != total_chunks:
            raise ValueError(
                "embedded metadata chunk count mismatch: expected {} got {}".format(expected_total_chunks, total_chunks)
            )

        last_chunk_len = encoded_len - (chunk_chars * (total_chunks - 1))
        if last_chunk_len <= 0:
            last_chunk_len = chunk_chars
        chunk_lengths = [chunk_chars] * max(0, total_chunks - 1)
        chunk_lengths.append(last_chunk_len)

        parity_group_size = int(metadata["PG"])
        manifest.update(
            {
                "compressed_sha256": (str(metadata["CH1"]) + str(metadata["CH2"])).lower(),
                "raw_sha256": (str(metadata["RH1"]) + str(metadata["RH2"])).lower(),
                "raw_size": int(metadata["RS"]),
                "compressed_size": compressed_size,
                "chunk_chars": chunk_chars,
                "chunk_lengths": chunk_lengths,
                "redundancy_copies": int(metadata["RC"]),
                "interleave_enabled": bool(int(metadata["IL"])),
                "parity": self._rebuild_parity_manifest(
                    total_chunks=total_chunks,
                    chunk_lengths=chunk_lengths,
                    parity_group_size=parity_group_size,
                ),
            }
        )
        return manifest

    def _build_expected_page_entries(
        self,
        manifest: Dict[str, object],
        page_no: int,
        page_chunks: int,
    ) -> List[Dict[str, int]]:
        total_chunks = int(manifest["total_chunks"])
        chunk_lengths = [int(value) for value in manifest.get("chunk_lengths", [])]
        if len(chunk_lengths) != total_chunks:
            raise ValueError("chunk_lengths missing for embedded metadata page reconstruction")

        base_entries = [(idx, "A" * int(chunk_lengths[idx])) for idx in range(total_chunks)]
        parity = manifest.get("parity", {})
        if isinstance(parity, dict) and parity.get("enabled"):
            groups = parity.get("groups", [])
            if isinstance(groups, list):
                for group in groups:
                    if not isinstance(group, dict):
                        continue
                    try:
                        parity_idx = int(group.get("parity_chunk_index"))
                        parity_len = int(group.get("parity_len", 0))
                    except Exception:
                        continue
                    if parity_len > 0:
                        base_entries.append((parity_idx, "A" * parity_len))

        chunk_entries = self._build_chunk_entries(
            base_entries=base_entries,
            redundancy_copies=int(manifest.get("redundancy_copies", 1)),
            interleave=bool(manifest.get("interleave_enabled", True)),
        )
        lines_per_page = int(manifest.get("lines_per_page", self.lines_per_page))
        start = max(0, (int(page_no) - 1) * lines_per_page)
        page_entries = chunk_entries[start : start + int(page_chunks)]
        if len(page_entries) != int(page_chunks):
            raise ValueError(
                "embedded metadata page reconstruction mismatch: expected {} entries got {}".format(
                    int(page_chunks), len(page_entries)
                )
            )

        out = []
        for line_no, entry in enumerate(page_entries, 1):
            chunk_idx, _payload, copy_no = entry
            out.append(
                {
                    "page": int(page_no),
                    "line": int(line_no),
                    "chunk_index": int(chunk_idx),
                    "copy": int(copy_no),
                }
            )
        return out

    def _ocr_embedded_metadata_page_tesseract(
        self,
        image_path: Path,
        page_no_hint: int,
        lang: str,
        prefer_sidecar: bool,
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for embedded metadata extraction")

        image = Image.open(str(image_path)).convert("L")
        bands = self._detect_text_bands(image)
        if len(bands) < 5:
            raise ValueError("detected text bands {} is less than minimum embedded layout 5".format(len(bands)))

        meta_whitelist = "@META|AT1IDPAGECHUNKSOTALCFGPRHSC0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_=-/"
        hash_whitelist = "@RHCH|0123456789ABCDEF"
        compact_hash_whitelist = "@HSRC|0123456789ABCDEF="
        pagecrc_whitelist = "@PAGECR|P0123456789ABCDEF"

        meta_line = self._parse_meta_line_candidate(
            self._ocr_band_tesseract_variants(image=image, band=bands[0], lang=lang, whitelist=meta_whitelist)
        )
        if not meta_line:
            raise ValueError("failed to parse embedded @META line from image {}".format(image_path))

        cfg_line = self._parse_cfg_line_candidate(
            self._ocr_band_tesseract_variants(image=image, band=bands[1], lang=lang, whitelist=meta_whitelist)
        )
        if not cfg_line:
            raise ValueError("failed to parse embedded @CFG line from image {}".format(image_path))

        hash_lines: List[str] = []
        hash_values: Dict[str, str] = {}
        data_start_idx = 0

        compact_1 = self._parse_hash_compact_candidate(
            self._ocr_band_tesseract_variants(
                image=image, band=bands[2], lang=lang, whitelist=compact_hash_whitelist
            ),
            expected_part=1,
        )
        compact_2 = None
        if len(bands) > 3:
            compact_2 = self._parse_hash_compact_candidate(
                self._ocr_band_tesseract_variants(
                    image=image, band=bands[3], lang=lang, whitelist=compact_hash_whitelist
                ),
                expected_part=2,
            )

        if compact_1 and compact_2:
            hash_lines.extend([compact_1["canonical"], compact_2["canonical"]])
            hash_values.update(
                {
                    "RH1": compact_1["RH"],
                    "RH2": compact_2["RH"],
                    "CH1": compact_1["CH"],
                    "CH2": compact_2["CH"],
                }
            )
            data_start_idx = 4
        else:
            if len(bands) < 6:
                raise ValueError(
                    "detected text bands {} is less than legacy embedded layout 6".format(len(bands))
                )
            rh1 = self._parse_hash_fragment_candidate(
                self._ocr_band_tesseract_variants(
                    image=image, band=bands[2], lang=lang, whitelist=hash_whitelist
                ),
                expected_kind="RH",
                expected_part=1,
            )
            rh2 = self._parse_hash_fragment_candidate(
                self._ocr_band_tesseract_variants(
                    image=image, band=bands[3], lang=lang, whitelist=hash_whitelist
                ),
                expected_kind="RH",
                expected_part=2,
            )
            ch1 = self._parse_hash_fragment_candidate(
                self._ocr_band_tesseract_variants(
                    image=image, band=bands[4], lang=lang, whitelist=hash_whitelist
                ),
                expected_kind="CH",
                expected_part=1,
            )
            ch2 = self._parse_hash_fragment_candidate(
                self._ocr_band_tesseract_variants(
                    image=image, band=bands[5], lang=lang, whitelist=hash_whitelist
                ),
                expected_kind="CH",
                expected_part=2,
            )
            if not all((rh1, rh2, ch1, ch2)):
                raise ValueError("failed to parse embedded hash fragments from image {}".format(image_path))
            hash_lines.extend([rh1, rh2, ch1, ch2])
            hash_values.update(
                {
                    "RH1": rh1.split("|", 1)[1],
                    "RH2": rh2.split("|", 1)[1],
                    "CH1": ch1.split("|", 1)[1],
                    "CH2": ch2.split("|", 1)[1],
                }
            )
            data_start_idx = 6

        page_chunks = int(meta_line["page_chunks"])
        data_bands = list(bands[data_start_idx : data_start_idx + page_chunks])
        if len(data_bands) != page_chunks:
            raise ValueError(
                "embedded metadata page band mismatch: expected {} got {}".format(page_chunks, len(data_bands))
            )

        footer_candidates_raw = []
        footer_band_index = data_start_idx + page_chunks
        if footer_band_index < len(bands):
            footer_candidates_raw.extend(
                self._ocr_band_tesseract_variants(
                    image=image, band=bands[footer_band_index], lang=lang, whitelist=pagecrc_whitelist
                )
            )
        if bands:
            footer_candidates_raw.extend(
                self._ocr_band_tesseract_variants(
                    image=image, band=bands[-1], lang=lang, whitelist=pagecrc_whitelist
                )
            )

        footer_line = None
        for raw in footer_candidates_raw:
            line = _normalize_protocol_signature(_normalize_ocr_line(raw))
            match = PAGECRC_PATTERN.match(line)
            if match:
                footer_line = "@PAGECRC|P{:03d}|{}".format(int(match.group(1)), match.group(2))
                break

        metadata = {
            "artifact_id": meta_line["artifact_id"],
            "total_chunks": int(meta_line["total_chunks"]),
            "total_pages": int(meta_line["total_pages"]),
            "CC": int(cfg_line["values"]["CC"]),
            "LP": int(cfg_line["values"]["LP"]),
            "RC": int(cfg_line["values"]["RC"]),
            "IL": int(cfg_line["values"]["IL"]),
            "PG": int(cfg_line["values"]["PG"]),
            "CS": int(cfg_line["values"]["CS"]),
            "RS": int(cfg_line["values"]["RS"]),
            "RH1": hash_values["RH1"],
            "RH2": hash_values["RH2"],
            "CH1": hash_values["CH1"],
            "CH2": hash_values["CH2"],
        }
        manifest = self._build_inferred_manifest_from_metadata(metadata)
        page_no = int(meta_line["page_no"]) if int(meta_line["page_no"]) > 0 else int(page_no_hint)
        expected_entries = self._build_expected_page_entries(manifest=manifest, page_no=page_no, page_chunks=page_chunks)

        lines = [
            meta_line["canonical"],
            cfg_line["canonical"],
        ]
        lines.extend(hash_lines)
        for band, entry in zip(data_bands, expected_entries):
            chunk_idx = int(entry["chunk_index"])
            payload_len = self._manifest_chunk_payload_length(manifest, chunk_idx)
            payload = ""
            if prefer_sidecar:
                payload = self._decode_manifest_guided_sidecar_payload(
                    image=image,
                    band=band,
                    payload_len=payload_len,
                )
            if not payload:
                text_band = self._crop_primary_text_band(image=image, band=band)
                total_chars = 16 + payload_len + 1 + 4
                char_width = float(text_band.width) / float(max(1, total_chars))
                pad = max(2, int(round(char_width * 0.25)))

                payload_left = max(0, int(round(16 * char_width)) - pad)
                payload_right = min(text_band.width, int(round((16 + payload_len) * char_width)) + pad)
                crc_left = max(0, int(round((16 + payload_len + 1) * char_width)) - pad)
                crc_right = min(text_band.width, int(round((16 + payload_len + 5) * char_width)) + pad)

                payload_crop = text_band.crop((payload_left, 0, max(payload_left + 1, payload_right), text_band.height))
                crc_crop = text_band.crop((crc_left, 0, max(crc_left + 1, crc_right), text_band.height))
                payload_raws = self._ocr_payload_crop_tesseract_variants(payload_crop, lang=lang)
                line_raws = self._ocr_payload_crop_tesseract_variants(text_band, lang=lang)
                crc_hints = self._ocr_crc_crop_tesseract_variants(crc_crop, lang=lang)
                payload = self._choose_payload_candidate_with_crc_hint(
                    chunk_idx=chunk_idx,
                    expected_len=payload_len,
                    crc_hints=crc_hints,
                    raw_texts=payload_raws + line_raws,
                )
            if not payload:
                raise ValueError(
                    "embedded metadata OCR failed at page={} line={} chunk={}".format(
                        int(entry["page"]), int(entry["line"]), chunk_idx
                    )
                )

            actual_crc = _crc16_hex("C{:05d}|{}".format(chunk_idx, payload))
            lines.append(
                "P{:03d}L{:03d}|C{:05d}|{}|{}".format(
                    int(entry["page"]),
                    int(entry["line"]),
                    chunk_idx,
                    payload,
                    actual_crc,
                )
            )

        if footer_line is None:
            footer_crc = _crc16_hex("\n".join(lines))
            footer_line = "@PAGECRC|P{:03d}|{}".format(page_no, footer_crc)
        lines.append(footer_line)
        return "\n".join(lines)

    def _choose_payload_candidate(
        self,
        chunk_idx: int,
        expected_len: int,
        expected_crc: str,
        raw_texts: List[str],
    ) -> str:
        candidates = []
        seen = set()

        for raw in raw_texts:
            normalized = _normalize_payload(_normalize_ocr_line(raw))
            safe = "".join(ch for ch in normalized if ch in SAFE_BASE32_ALPHABET)
            if not safe:
                continue

            variants = [safe]
            if expected_len > 0 and len(safe) > expected_len:
                for start in range(0, len(safe) - expected_len + 1):
                    variants.append(safe[start : start + expected_len])

            for candidate in variants:
                if candidate in seen:
                    continue
                seen.add(candidate)
                candidates.append(candidate)

        core_prefix = "C{:05d}|".format(int(chunk_idx))
        for candidate in candidates:
            if len(candidate) != expected_len:
                continue
            repaired = self._repair_payload_candidate_by_crc(
                payload=candidate,
                core_prefix=core_prefix,
                expected_crc=expected_crc,
            )
            if _crc16_hex(core_prefix + repaired) == expected_crc:
                return repaired

        return ""

    def _repair_payload_candidate_by_crc(
        self,
        payload: str,
        core_prefix: str,
        expected_crc: str,
    ) -> str:
        if not payload:
            return payload
        if _crc16_hex(core_prefix + payload) == expected_crc:
            return payload

        positions = []
        replacements = []
        for index, ch in enumerate(payload):
            alt_text = PAYLOAD_OCR_AMBIGUITIES.get(ch, "")
            alt_chars = [c for c in alt_text if c in SAFE_BASE32_ALPHABET and c != ch]
            if not alt_chars:
                continue
            positions.append(index)
            replacements.append(alt_chars)

        if not positions:
            return payload

        base_chars = list(payload)
        attempts = 0
        max_attempts = 12000
        max_depth = min(4, len(positions))
        for depth in range(1, max_depth + 1):
            for pos_combo in itertools.combinations(range(len(positions)), depth):
                alt_lists = [replacements[pos_idx] for pos_idx in pos_combo]
                for repl_combo in itertools.product(*alt_lists):
                    attempts += 1
                    if attempts > max_attempts:
                        return payload
                    candidate_chars = list(base_chars)
                    for rel_idx, repl in zip(pos_combo, repl_combo):
                        candidate_chars[positions[rel_idx]] = repl
                    candidate = "".join(candidate_chars)
                    if _crc16_hex(core_prefix + candidate) == expected_crc:
                        return candidate

        return payload

    def _ocr_structured_page_tesseract(
        self,
        image_path: Path,
        lang: str,
        page_layout: Dict[str, object],
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for structured OCR extraction")

        raw_lines = page_layout.get("lines", [])
        if not isinstance(raw_lines, list):
            raw_lines = []
        if not raw_lines:
            raise ValueError("structured OCR page layout is missing lines")

        image = Image.open(str(image_path)).convert("L")
        data_lines = []
        payload_whitelist = SAFE_BASE32_ALPHABET
        for item in raw_lines:
            if not isinstance(item, dict) or item.get("kind") != "data":
                continue
            try:
                page_no = int(item.get("page"))
                line_no = int(item.get("line_no"))
                chunk_idx = int(item.get("chunk_index"))
                payload_len = int(item.get("payload_len"))
            except Exception:
                continue
            expected_crc = str(item.get("expected_crc", ""))
            payload_box = item.get("payload_box")
            line_box = item.get("line_box")
            payload = self._decode_sidecar_payload(image=image, page_layout=page_layout, line_meta=item)
            if (not payload) and isinstance(payload_box, list) and len(payload_box) == 4:
                payload_raw = self._ocr_image_crop_tesseract(
                    image=image,
                    box=payload_box,
                    lang=lang,
                    whitelist=payload_whitelist,
                    psm=7,
                )
                payload = self._choose_payload_candidate(
                    chunk_idx=chunk_idx,
                    expected_len=payload_len,
                    expected_crc=expected_crc,
                    raw_texts=[payload_raw],
                )
            if not payload and isinstance(line_box, list) and len(line_box) == 4:
                line_raw = self._ocr_image_crop_tesseract(
                    image=image,
                    box=line_box,
                    lang=lang,
                    whitelist=payload_whitelist,
                    psm=7,
                )
                payload = self._choose_payload_candidate(
                    chunk_idx=chunk_idx,
                    expected_len=payload_len,
                    expected_crc=expected_crc,
                    raw_texts=[line_raw],
                )
            if not payload and isinstance(payload_box, list) and len(payload_box) == 4:
                payload_raw_wide = self._ocr_image_crop_tesseract(
                    image=image,
                    box=[
                        int(payload_box[0]),
                        max(0, int(payload_box[1]) - 2),
                        int(payload_box[2]) + 20,
                        int(payload_box[3]),
                    ],
                    lang=lang,
                    whitelist=payload_whitelist,
                    psm=7,
                )
                payload = self._choose_payload_candidate(
                    chunk_idx=chunk_idx,
                    expected_len=payload_len,
                    expected_crc=expected_crc,
                    raw_texts=[payload_raw_wide],
                )

            data_lines.append(
                "P{:03d}L{:03d}|C{:05d}|{}|{}".format(
                    page_no, line_no, chunk_idx, payload, expected_crc
                )
            )

        if not data_lines:
            raise ValueError("structured OCR page layout does not contain data lines")
        return "\n".join(data_lines)

    def _ocr_structured_page_easyocr(
        self,
        image_path: Path,
        page_layout: Dict[str, object],
        reader,
    ) -> str:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required for structured OCR extraction")

        raw_lines = page_layout.get("lines", [])
        if not isinstance(raw_lines, list):
            raw_lines = []
        if not raw_lines:
            raise ValueError("structured OCR page layout is missing lines")

        image = Image.open(str(image_path)).convert("L")
        data_lines = []
        for item in raw_lines:
            if not isinstance(item, dict) or item.get("kind") != "data":
                continue
            try:
                page_no = int(item.get("page"))
                line_no = int(item.get("line_no"))
                chunk_idx = int(item.get("chunk_index"))
                payload_len = int(item.get("payload_len"))
            except Exception:
                continue

            expected_crc = str(item.get("expected_crc", ""))
            payload_box = item.get("payload_box")
            line_box = item.get("line_box")
            payload = self._decode_sidecar_payload(image=image, page_layout=page_layout, line_meta=item)
            if (not payload) and isinstance(payload_box, list) and len(payload_box) == 4:
                payload_raw = self._ocr_image_crop_easyocr(image=image, box=payload_box, reader=reader)
                payload = self._choose_payload_candidate(
                    chunk_idx=chunk_idx,
                    expected_len=payload_len,
                    expected_crc=expected_crc,
                    raw_texts=[payload_raw],
                )
            if not payload and isinstance(line_box, list) and len(line_box) == 4:
                line_raw = self._ocr_image_crop_easyocr(image=image, box=line_box, reader=reader)
                payload = self._choose_payload_candidate(
                    chunk_idx=chunk_idx,
                    expected_len=payload_len,
                    expected_crc=expected_crc,
                    raw_texts=[line_raw],
                )
            if not payload and isinstance(payload_box, list) and len(payload_box) == 4:
                payload_raw_wide = self._ocr_image_crop_easyocr(
                    image=image,
                    box=[
                        int(payload_box[0]),
                        max(0, int(payload_box[1]) - 2),
                        int(payload_box[2]) + 20,
                        int(payload_box[3]),
                    ],
                    reader=reader,
                )
                payload = self._choose_payload_candidate(
                    chunk_idx=chunk_idx,
                    expected_len=payload_len,
                    expected_crc=expected_crc,
                    raw_texts=[payload_raw_wide],
                )

            data_lines.append(
                "P{:03d}L{:03d}|C{:05d}|{}|{}".format(
                    page_no, line_no, chunk_idx, payload, expected_crc
                )
            )

        if not data_lines:
            raise ValueError("structured OCR page layout does not contain data lines")
        return "\n".join(data_lines)

    def _parse_external_ocr_stdout(self, raw_output: str) -> str:
        text = str(raw_output or "").strip()
        if not text:
            return ""

        parsed = None
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None

        if isinstance(parsed, dict):
            direct = parsed.get("text")
            if isinstance(direct, str) and direct.strip():
                return direct
            lines = parsed.get("lines")
            if isinstance(lines, list):
                return "\n".join(str(item) for item in lines if str(item).strip())
            output_text_path = parsed.get("output_text_path")
            if isinstance(output_text_path, str):
                candidate = Path(output_text_path)
                if candidate.exists() and candidate.is_file():
                    return candidate.read_text(encoding="utf-8", errors="ignore")

        if ("\n" not in text) and ("\r" not in text):
            candidate = Path(text)
            if candidate.exists() and candidate.is_file():
                return candidate.read_text(encoding="utf-8", errors="ignore")
        return str(raw_output or "")

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
        cmd_template = str(provider_cmd or "").strip()
        if not cmd_template:
            raise ValueError("external OCR provider command is empty")

        mapping = {
            "image_path": str(image_path),
            "image_name": str(image_path.name),
            "page_no": int(page_no),
            "lang": str(lang),
            "psm": int(psm),
            "manifest_path": str(manifest_path or ""),
        }
        try:
            command = cmd_template.format(**mapping)
        except KeyError as exc:
            raise ValueError(
                "unknown placeholder in --ocr-provider-cmd: {}".format(exc)
            )

        completed = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1, int(timeout_sec)),
            check=False,
        )
        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        if completed.returncode != 0:
            raise RuntimeError(
                "external OCR command failed for image {} with exit code {}: {}".format(
                    image_path, completed.returncode, stderr or "no stderr"
                )
            )

        parsed_text = self._parse_external_ocr_stdout(stdout)
        if not str(parsed_text).strip():
            raise RuntimeError("external OCR command returned empty text for image {}".format(image_path))
        return str(parsed_text)

    def _ocr_single_image(
        self,
        image_path: Path,
        backend: str,
        lang: str,
        psm: int,
        reader=None,
        page_layout: Optional[Dict[str, object]] = None,
    ) -> str:
        if backend == "sidecar":
            if not page_layout:
                raise ValueError("sidecar backend requires manifest render_layout metadata")
            return self._ocr_structured_page_sidecar(
                image_path=image_path,
                page_layout=page_layout,
            )

        if backend == "tesseract":
            if not PIL_AVAILABLE:
                raise RuntimeError("Pillow is required for tesseract preprocessing")
            if page_layout:
                return self._ocr_structured_page_tesseract(
                    image_path=image_path,
                    lang=lang,
                    page_layout=page_layout,
                )
            image = Image.open(str(image_path)).convert("L")
            # Improve OCR robustness for camera/screenshot noise.
            image = image.resize((image.width * 2, image.height * 2), RESAMPLE_LANCZOS)
            image = Image.eval(image, lambda p: 255 if p > 170 else 0)
            return self._ocr_transport_page_tesseract_best_effort(
                image=image,
                lang=lang,
                psm=psm,
            )

        if backend == "easyocr":
            if reader is None:
                reader = easyocr.Reader(_build_easyocr_langs(lang), gpu=False)
            if page_layout:
                return self._ocr_structured_page_easyocr(
                    image_path=image_path,
                    page_layout=page_layout,
                    reader=reader,
                )
            lines = reader.readtext(str(image_path), detail=0, paragraph=False)
            return "\n".join(lines)

        raise ValueError("unsupported backend: {}".format(backend))

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

    def _parse_ocr_chunks(self, manifest: Dict[str, object], ocr_input_path: str, strict_payload_chars: bool) -> Dict[str, object]:
        total_chunks = int(manifest["total_chunks"])
        line_index_mode = str(manifest.get("transport_line_index_mode", "full") or "full").strip().lower()
        if line_index_mode == "off":
            return self._parse_ocr_chunks_payload_only_manifest(
                manifest=manifest,
                ocr_input_path=ocr_input_path,
                strict_payload_chars=strict_payload_chars,
            )
        return self._parse_ocr_chunks_with_total(
            total_chunks=total_chunks,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            line_index_mode=line_index_mode,
        )

    def _parse_ocr_chunks_payload_only_manifest(
        self,
        manifest: Dict[str, object],
        ocr_input_path: str,
        strict_payload_chars: bool,
    ) -> Dict[str, object]:
        raw_lines = self._read_ocr_lines(ocr_input_path)
        chunk_votes = {}
        page_lines_for_crc = {}
        page_meta_extra_for_crc = {}
        page_meta = {}
        page_crc_expect = {}
        line_errors = []
        line_warnings = []
        current_page_no = 0

        payload_rows = []
        for source_line_no, raw in enumerate(raw_lines, 1):
            line = _normalize_protocol_signature(_normalize_ocr_line(raw))
            if not line:
                continue

            meta_match = META_PATTERN.match(line)
            if meta_match:
                page_no = int(meta_match.group(2))
                page_meta[page_no] = line
                current_page_no = page_no
                continue

            if _parse_cfg_line(line):
                if current_page_no > 0:
                    page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
                continue

            if _parse_hash_fragment_line(line):
                if current_page_no > 0:
                    page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
                continue
            if _parse_hash_compact_line(line):
                if current_page_no > 0:
                    page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
                continue

            page_crc_match = PAGECRC_PATTERN.match(line)
            if page_crc_match:
                page_no = int(page_crc_match.group(1))
                page_crc_expect[page_no] = page_crc_match.group(2)
                current_page_no = 0
                continue

            has_crc = False
            given_crc = ""
            payload = ""
            m = PAYLOAD_WITH_CRC_PATTERN.match(line)
            if m:
                has_crc = True
                payload = _normalize_payload(m.group(1))
                given_crc = _normalize_hex_token(m.group(3))
            else:
                mf = PAYLOAD_WITH_CRC_FALLBACK_PATTERN.match(line)
                if mf:
                    has_crc = True
                    payload = _normalize_payload(mf.group(1))
                    given_crc = _normalize_hex_token(mf.group(3))
                    line_warnings.append(
                        {
                            "line_no": source_line_no,
                            "reason": "payload_crc_fallback_pattern_used",
                        }
                    )
                else:
                    payload = _normalize_payload(line)

            if strict_payload_chars:
                invalid_chars = [ch for ch in payload if ch not in SAFE_BASE32_ALPHABET]
                if invalid_chars:
                    line_errors.append(
                        {
                            "line_no": source_line_no,
                            "reason": "invalid_payload_chars",
                            "chars": "".join(sorted(set(invalid_chars)))[:50],
                        }
                    )
                    continue
            else:
                payload = "".join(ch for ch in payload if ch in SAFE_BASE32_ALPHABET)

            if not payload:
                line_warnings.append(
                    {
                        "line_no": source_line_no,
                        "reason": "payload_only_empty_after_normalize",
                    }
                )
                continue

            payload_rows.append(
                {
                    "source_line_no": source_line_no,
                    "payload": payload,
                    "has_crc": bool(has_crc),
                    "given_crc": given_crc,
                }
            )

        ordered_entries = self._manifest_entries_in_transport_order(manifest)
        if not ordered_entries:
            total_chunks = int(manifest.get("total_chunks", 0) or 0)
            ordered_entries = [{"page": 1, "line": idx + 1, "chunk_index": idx} for idx in range(total_chunks)]

        if len(payload_rows) > len(ordered_entries):
            line_warnings.append(
                {
                    "reason": "payload_rows_exceed_manifest_entries",
                    "payload_rows": len(payload_rows),
                    "manifest_entries": len(ordered_entries),
                }
            )

        row_count = min(len(payload_rows), len(ordered_entries))
        for idx in range(row_count):
            row = payload_rows[idx]
            entry = ordered_entries[idx]
            chunk_idx = int(entry["chunk_index"])
            page_no = int(entry.get("page", 0) or 0)
            line_no = int(entry.get("line", idx + 1) or (idx + 1))
            payload = str(row["payload"])
            has_crc = bool(row["has_crc"])
            given_crc = str(row["given_crc"])

            core = "C{:05d}|{}".format(chunk_idx, payload)
            expect_crc = _crc16_hex(core)
            if has_crc and expect_crc != given_crc:
                repaired = self._repair_payload_candidate_by_crc(
                    payload=payload,
                    core_prefix="C{:05d}|".format(chunk_idx),
                    expected_crc=given_crc,
                )
                if repaired != payload:
                    payload = repaired
                    core = "C{:05d}|{}".format(chunk_idx, payload)
                    expect_crc = _crc16_hex(core)
                    if expect_crc == given_crc:
                        line_warnings.append(
                            {
                                "line_no": int(row["source_line_no"]),
                                "reason": "payload_crc_repaired",
                                "chunk_idx": chunk_idx,
                            }
                        )
                if has_crc and expect_crc != given_crc:
                    line_errors.append(
                        {
                            "line_no": int(row["source_line_no"]),
                            "reason": "line_crc_mismatch",
                            "chunk_idx": chunk_idx,
                            "expected_crc": expect_crc,
                            "given_crc": given_crc,
                        }
                    )
                    continue

            votes = chunk_votes.setdefault(chunk_idx, {})
            votes[payload] = votes.get(payload, 0) + 1
            if has_crc:
                page_lines_for_crc.setdefault(page_no, []).append(
                    "P{:03d}L{:03d}|{}|{}".format(page_no, line_no, core, given_crc)
                )
            else:
                page_lines_for_crc.setdefault(page_no, []).append(
                    "P{:03d}L{:03d}|{}".format(page_no, line_no, core)
                )

        chunks = {}
        duplicate_conflicts = []
        for chunk_idx in sorted(chunk_votes.keys()):
            votes = chunk_votes[chunk_idx]
            ranked = sorted(votes.items(), key=lambda kv: (-int(kv[1]), kv[0]))
            if not ranked:
                continue
            if len(ranked) == 1:
                chunks[chunk_idx] = ranked[0][0]
                continue

            top_count = int(ranked[0][1])
            top_payloads = [payload for payload, cnt in ranked if int(cnt) == top_count]
            if len(top_payloads) == 1:
                chosen = top_payloads[0]
                chunks[chunk_idx] = chosen
                line_warnings.append(
                    {
                        "reason": "duplicate_payload_resolved_by_majority",
                        "chunk_idx": chunk_idx,
                        "winner_votes": top_count,
                        "total_votes": sum(int(v) for v in votes.values()),
                    }
                )
                continue

            duplicate_conflicts.append(
                {
                    "chunk_idx": chunk_idx,
                    "reason": "duplicate_payload_tie",
                    "candidates": [payload[:40] for payload in top_payloads[:5]],
                    "votes": top_count,
                }
            )

        page_crc_errors = []
        for page_no, expect_crc in page_crc_expect.items():
            header = page_meta.get(page_no)
            lines = page_lines_for_crc.get(page_no, [])
            if not header or not lines:
                continue
            base = [header]
            base.extend(
                sorted(
                    page_meta_extra_for_crc.get(page_no, []),
                    key=lambda item: (
                        0
                        if item.startswith("@CFG|")
                        else 1
                        if item.startswith("@HS1|")
                        else 2
                        if item.startswith("@HS2|")
                        else 3
                        if item.startswith("@RH1|")
                        else 4
                        if item.startswith("@RH2|")
                        else 5
                        if item.startswith("@CH1|")
                        else 6
                        if item.startswith("@CH2|")
                        else 9,
                        item,
                    ),
                )
            )
            base.extend(sorted(lines))
            actual_crc = _crc16_hex("\n".join(base))
            if actual_crc != expect_crc:
                page_crc_errors.append(
                    {
                        "page_no": page_no,
                        "expected_crc": expect_crc,
                        "actual_crc": actual_crc,
                    }
                )

        total_chunks = int(manifest.get("total_chunks", 0) or 0)
        missing_chunks = [idx for idx in range(total_chunks) if idx not in chunks]
        ordered_chunks = [chunks[idx] for idx in range(total_chunks) if idx in chunks]

        return {
            "chunks": chunks,
            "ordered_chunks": ordered_chunks,
            "line_errors": line_errors,
            "line_warnings": line_warnings,
            "duplicate_conflicts": duplicate_conflicts,
            "page_crc_errors": page_crc_errors,
            "missing_chunks": missing_chunks,
            "page_meta_count": len(page_meta),
            "page_crc_count": len(page_crc_expect),
            "chunk_votes": chunk_votes,
        }

    def _parse_ocr_chunks_with_total(
        self,
        total_chunks: int,
        ocr_input_path: str,
        strict_payload_chars: bool,
        line_index_mode: str = "full",
    ) -> Dict[str, object]:
        raw_lines = self._read_ocr_lines(ocr_input_path)
        chunk_votes = {}
        page_lines_for_crc = {}
        page_meta_extra_for_crc = {}
        page_meta = {}
        page_crc_expect = {}
        line_errors = []
        line_warnings = []
        current_page_no = 0

        for source_line_no, raw in enumerate(raw_lines, 1):
            line = _normalize_ocr_line(raw)
            if not line:
                continue
            line = _normalize_protocol_signature(line)

            meta_match = META_PATTERN.match(line)
            if meta_match:
                page_no = int(meta_match.group(2))
                page_meta[page_no] = line
                current_page_no = page_no
                continue

            if _parse_cfg_line(line):
                if current_page_no > 0:
                    page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
                continue

            if _parse_hash_fragment_line(line):
                if current_page_no > 0:
                    page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
                continue
            if _parse_hash_compact_line(line):
                if current_page_no > 0:
                    page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
                continue

            page_crc_match = PAGECRC_PATTERN.match(line)
            if page_crc_match:
                page_no = int(page_crc_match.group(1))
                page_crc_expect[page_no] = page_crc_match.group(2)
                current_page_no = 0
                continue

            match = LINE_PATTERN.match(line)
            match_no_crc = LINE_PATTERN_NOCRC.match(line) if (not match) else None
            match_nosep_no_crc = (
                LINE_PATTERN_NOSEP_NOCRC.match(line)
                if (not match and not match_no_crc)
                else None
            )
            match_nosep = (
                LINE_PATTERN_NOSEP.match(line)
                if (not match and not match_no_crc and not match_nosep_no_crc)
                else None
            )
            chunk_match = (
                CHUNK_PATTERN.match(line)
                if (not match and not match_no_crc and not match_nosep and not match_nosep_no_crc)
                else None
            )
            chunk_no_crc = (
                CHUNK_PATTERN_NOCRC.match(line)
                if (
                    not match
                    and not match_no_crc
                    and not match_nosep
                    and not match_nosep_no_crc
                    and not chunk_match
                )
                else None
            )
            fallback_used = False
            line_has_crc = False
            line_index_kind = "full"
            if not match and not match_no_crc and not match_nosep and not match_nosep_no_crc and not chunk_match and not chunk_no_crc:
                fallback = LINE_PATTERN_FALLBACK.match(line)
                fallback_no_crc = LINE_PATTERN_FALLBACK_NOCRC.match(line) if (not fallback) else None
                chunk_fallback = CHUNK_PATTERN_FALLBACK.match(line) if (not fallback and not fallback_no_crc) else None
                chunk_fallback_no_crc = (
                    CHUNK_PATTERN_FALLBACK_NOCRC.match(line)
                    if (not fallback and not fallback_no_crc and not chunk_fallback)
                    else None
                )
                if fallback:
                    fallback_used = True
                    line_has_crc = True
                    page_token = _normalize_page_line_token(fallback.group(1))
                    line_token = _normalize_page_line_token(fallback.group(2))
                    chunk_token = _normalize_digit_token(fallback.group(4))
                    crc_token = _normalize_hex_token(fallback.group(6))
                    try:
                        page_no = int(page_token)
                        line_no = int(line_token)
                        chunk_idx = int(chunk_token)
                    except Exception:
                        line_warnings.append(
                            {
                                "line_no": source_line_no,
                                "reason": "fallback_numeric_parse_failed",
                                "content": line[:120],
                            }
                        )
                        continue
                    payload = _normalize_payload(fallback.group(5))
                    given_crc = crc_token
                elif fallback_no_crc:
                    fallback_used = True
                    line_has_crc = False
                    page_token = _normalize_page_line_token(fallback_no_crc.group(1))
                    line_token = _normalize_page_line_token(fallback_no_crc.group(2))
                    chunk_token = _normalize_digit_token(fallback_no_crc.group(4))
                    try:
                        page_no = int(page_token)
                        line_no = int(line_token)
                        chunk_idx = int(chunk_token)
                    except Exception:
                        line_warnings.append(
                            {
                                "line_no": source_line_no,
                                "reason": "fallback_numeric_parse_failed",
                                "content": line[:120],
                            }
                        )
                        continue
                    payload = _normalize_payload(fallback_no_crc.group(5))
                    given_crc = ""
                elif chunk_fallback:
                    fallback_used = True
                    line_has_crc = True
                    line_index_kind = "chunk"
                    page_no = int(current_page_no) if current_page_no > 0 else 0
                    line_no = int(source_line_no)
                    chunk_token = _normalize_digit_token(chunk_fallback.group(1))
                    try:
                        chunk_idx = int(chunk_token)
                    except Exception:
                        line_warnings.append(
                            {
                                "line_no": source_line_no,
                                "reason": "fallback_numeric_parse_failed",
                                "content": line[:120],
                            }
                        )
                        continue
                    payload = _normalize_payload(chunk_fallback.group(3))
                    given_crc = _normalize_hex_token(chunk_fallback.group(4))
                elif chunk_fallback_no_crc:
                    fallback_used = True
                    line_has_crc = False
                    line_index_kind = "chunk"
                    page_no = int(current_page_no) if current_page_no > 0 else 0
                    line_no = int(source_line_no)
                    chunk_token = _normalize_digit_token(chunk_fallback_no_crc.group(1))
                    try:
                        chunk_idx = int(chunk_token)
                    except Exception:
                        line_warnings.append(
                            {
                                "line_no": source_line_no,
                                "reason": "fallback_numeric_parse_failed",
                                "content": line[:120],
                            }
                        )
                        continue
                    payload = _normalize_payload(chunk_fallback_no_crc.group(3))
                    given_crc = ""
                else:
                    line_warnings.append(
                        {
                            "line_no": source_line_no,
                            "reason": "unmatched_protocol_line",
                            "content": line[:120],
                        }
                    )
                    continue
            elif match:
                line_has_crc = True
                page_no = int(match.group(1))
                line_no = int(match.group(2))
                chunk_idx = int(match.group(4))
                payload = _normalize_payload(match.group(5))
                given_crc = match.group(6)
                line_index_kind = "full"
            elif match_nosep_no_crc:
                line_has_crc = False
                page_no = int(_normalize_page_line_token(match_nosep_no_crc.group(1)))
                line_no = int(_normalize_page_line_token(match_nosep_no_crc.group(2)))
                chunk_idx = int(_normalize_digit_token(match_nosep_no_crc.group(3)))
                payload = _normalize_payload(match_nosep_no_crc.group(4))
                given_crc = ""
                line_index_kind = "full"
                possible_crc = _normalize_hex_token(payload[-4:]) if len(payload) >= 5 else ""
                if len(possible_crc) == 4:
                    payload_candidate = payload[:-4]
                    core_candidate = "C{:05d}|{}".format(chunk_idx, payload_candidate)
                    if payload_candidate and _crc16_hex(core_candidate) == possible_crc:
                        payload = payload_candidate
                        line_has_crc = True
                        given_crc = possible_crc
                line_warnings.append(
                    {
                        "line_no": source_line_no,
                        "reason": "line_separator_missing",
                        "chunk_idx": chunk_idx,
                    }
                )
            elif match_nosep:
                line_has_crc = True
                page_no = int(_normalize_page_line_token(match_nosep.group(1)))
                line_no = int(_normalize_page_line_token(match_nosep.group(2)))
                chunk_idx = int(_normalize_digit_token(match_nosep.group(3)))
                payload = _normalize_payload(match_nosep.group(4))
                given_crc = _normalize_hex_token(match_nosep.group(5))
                line_index_kind = "full"
                line_warnings.append(
                    {
                        "line_no": source_line_no,
                        "reason": "line_separator_missing",
                        "chunk_idx": chunk_idx,
                    }
                )
            elif chunk_match:
                line_has_crc = True
                line_index_kind = "chunk"
                page_no = int(current_page_no) if current_page_no > 0 else 0
                line_no = int(source_line_no)
                chunk_idx = int(chunk_match.group(1))
                payload = _normalize_payload(chunk_match.group(3))
                given_crc = chunk_match.group(4)
            elif chunk_no_crc:
                line_has_crc = False
                line_index_kind = "chunk"
                page_no = int(current_page_no) if current_page_no > 0 else 0
                line_no = int(source_line_no)
                chunk_idx = int(chunk_no_crc.group(1))
                payload = _normalize_payload(chunk_no_crc.group(3))
                given_crc = ""
            else:
                line_has_crc = False
                page_no = int(match_no_crc.group(1))
                line_no = int(match_no_crc.group(2))
                chunk_idx = int(match_no_crc.group(4))
                payload = _normalize_payload(match_no_crc.group(5))
                given_crc = ""
                line_index_kind = "full"

            if strict_payload_chars:
                invalid_chars = [ch for ch in payload if ch not in SAFE_BASE32_ALPHABET]
                if invalid_chars:
                    line_errors.append(
                        {
                            "line_no": source_line_no,
                            "reason": "invalid_payload_chars",
                            "chunk_idx": chunk_idx,
                            "chars": "".join(sorted(set(invalid_chars)))[:50],
                        }
                    )
                    continue
            else:
                payload = "".join(ch for ch in payload if ch in SAFE_BASE32_ALPHABET)
                if not payload:
                    line_errors.append(
                        {
                            "line_no": source_line_no,
                            "reason": "empty_payload_after_normalize",
                            "chunk_idx": chunk_idx,
                        }
                    )
                    continue

            core = "C{:05d}|{}".format(chunk_idx, payload)
            expect_crc = _crc16_hex(core)
            if line_has_crc and expect_crc != given_crc:
                repaired = self._repair_payload_candidate_by_crc(
                    payload=payload,
                    core_prefix="C{:05d}|".format(chunk_idx),
                    expected_crc=given_crc,
                )
                if repaired != payload:
                    payload = repaired
                    core = "C{:05d}|{}".format(chunk_idx, payload)
                    expect_crc = _crc16_hex(core)
                    if expect_crc == given_crc:
                        line_warnings.append(
                            {
                                "line_no": source_line_no,
                                "reason": "payload_crc_repaired",
                                "chunk_idx": chunk_idx,
                            }
                        )
                if line_has_crc and expect_crc != given_crc:
                    line_errors.append(
                        {
                            "line_no": source_line_no,
                            "reason": "line_crc_mismatch",
                            "chunk_idx": chunk_idx,
                            "expected_crc": expect_crc,
                            "given_crc": given_crc,
                        }
                    )
                    continue

            if fallback_used:
                line_warnings.append(
                    {
                        "line_no": source_line_no,
                        "reason": "fallback_line_pattern_used",
                        "chunk_idx": chunk_idx,
                    }
                )
            if not line_has_crc:
                line_warnings.append(
                    {
                        "line_no": source_line_no,
                        "reason": "line_crc_missing",
                        "chunk_idx": chunk_idx,
                    }
                )

            votes = chunk_votes.setdefault(chunk_idx, {})
            votes[payload] = votes.get(payload, 0) + 1
            if line_has_crc:
                if line_index_kind == "chunk":
                    page_lines_for_crc.setdefault(page_no, []).append("{}|{}".format(core, given_crc))
                else:
                    page_lines_for_crc.setdefault(page_no, []).append(
                        "P{:03d}L{:03d}|{}|{}".format(page_no, line_no, core, given_crc)
                    )
            else:
                if line_index_kind == "chunk":
                    page_lines_for_crc.setdefault(page_no, []).append(core)
                else:
                    page_lines_for_crc.setdefault(page_no, []).append(
                        "P{:03d}L{:03d}|{}".format(page_no, line_no, core)
                    )

        chunks = {}
        duplicate_conflicts = []
        for chunk_idx in sorted(chunk_votes.keys()):
            votes = chunk_votes[chunk_idx]
            ranked = sorted(votes.items(), key=lambda kv: (-int(kv[1]), kv[0]))
            if not ranked:
                continue
            if len(ranked) == 1:
                chunks[chunk_idx] = ranked[0][0]
                continue

            top_count = int(ranked[0][1])
            top_payloads = [payload for payload, cnt in ranked if int(cnt) == top_count]
            if len(top_payloads) == 1:
                chosen = top_payloads[0]
                chunks[chunk_idx] = chosen
                line_warnings.append(
                    {
                        "reason": "duplicate_payload_resolved_by_majority",
                        "chunk_idx": chunk_idx,
                        "winner_votes": top_count,
                        "total_votes": sum(int(v) for v in votes.values()),
                    }
                )
                continue

            duplicate_conflicts.append(
                {
                    "chunk_idx": chunk_idx,
                    "reason": "duplicate_payload_tie",
                    "candidates": [payload[:40] for payload in top_payloads[:5]],
                    "votes": top_count,
                }
            )

        page_crc_errors = []
        for page_no, expect_crc in page_crc_expect.items():
            header = page_meta.get(page_no)
            lines = page_lines_for_crc.get(page_no, [])
            if not header or not lines:
                continue
            base = [header]
            base.extend(
                sorted(
                    page_meta_extra_for_crc.get(page_no, []),
                    key=lambda item: (
                        0 if item.startswith("@CFG|") else 1 if item.startswith("@HS1|") else 2 if item.startswith("@HS2|") else 3 if item.startswith("@RH1|") else 4 if item.startswith("@RH2|") else 5 if item.startswith("@CH1|") else 6 if item.startswith("@CH2|") else 9,
                        item,
                    ),
                )
            )
            base.extend(sorted(lines))
            actual_crc = _crc16_hex("\n".join(base))
            if actual_crc != expect_crc:
                page_crc_errors.append(
                    {
                        "page_no": page_no,
                        "expected_crc": expect_crc,
                        "actual_crc": actual_crc,
                    }
                )

        missing_chunks = [idx for idx in range(total_chunks) if idx not in chunks]
        ordered_chunks = [chunks[idx] for idx in range(total_chunks) if idx in chunks]

        return {
            "chunks": chunks,
            "ordered_chunks": ordered_chunks,
            "line_errors": line_errors,
            "line_warnings": line_warnings,
            "duplicate_conflicts": duplicate_conflicts,
            "page_crc_errors": page_crc_errors,
            "missing_chunks": missing_chunks,
            "page_meta_count": len(page_meta),
            "page_crc_count": len(page_crc_expect),
            "chunk_votes": chunk_votes,
        }

    def _choose_majority_metadata_value(self, label: str, votes: Dict[object, int]) -> Optional[object]:
        if not votes:
            return None
        ranked = sorted(votes.items(), key=lambda kv: (-int(kv[1]), str(kv[0])))
        if len(ranked) > 1 and int(ranked[0][1]) == int(ranked[1][1]) and ranked[0][0] != ranked[1][0]:
            raise ValueError("conflicting {} values in OCR metadata: {}".format(label, [item[0] for item in ranked[:5]]))
        return ranked[0][0]

    def _scan_transport_metadata(self, ocr_input_path: str) -> Dict[str, object]:
        raw_lines = self._read_ocr_lines(ocr_input_path)
        artifact_votes: Dict[str, int] = {}
        total_chunk_votes: Dict[int, int] = {}
        total_page_votes: Dict[int, int] = {}
        cfg_votes: Dict[str, Dict[int, int]] = {
            "CC": {},
            "LP": {},
            "RC": {},
            "IL": {},
            "PG": {},
            "CS": {},
            "RS": {},
        }
        hash_votes: Dict[str, Dict[str, int]] = {
            "RH1": {},
            "RH2": {},
            "CH1": {},
            "CH2": {},
        }
        max_data_chunk_idx = -1
        payload_only_candidates = 0
        full_index_candidates = 0
        chunk_index_candidates = 0

        def _add_vote(bucket: Dict[object, int], value: object) -> None:
            bucket[value] = bucket.get(value, 0) + 1

        for raw in raw_lines:
            line = _normalize_protocol_signature(_normalize_ocr_line(raw))
            if not line:
                continue

            meta_match = META_PATTERN.match(line)
            if meta_match:
                _add_vote(artifact_votes, meta_match.group(1))
                _add_vote(total_page_votes, int(meta_match.group(3)))
                _add_vote(total_chunk_votes, int(meta_match.group(5)))
                continue

            cfg = _parse_cfg_line(line)
            if cfg:
                for key, value in cfg.items():
                    _add_vote(cfg_votes[key], int(value))
                continue

            hash_fragment = _parse_hash_fragment_line(line)
            if hash_fragment:
                kind, part_no, fragment = hash_fragment
                _add_vote(hash_votes["{}{}".format(kind, part_no)], fragment)
                continue

            hash_compact = _parse_hash_compact_line(line)
            if hash_compact:
                part_no, raw_fragment, compressed_fragment = hash_compact
                _add_vote(hash_votes["RH{}".format(part_no)], raw_fragment)
                _add_vote(hash_votes["CH{}".format(part_no)], compressed_fragment)
                continue

            match = LINE_PATTERN.match(line)
            if match:
                full_index_candidates += 1
                chunk_idx = int(match.group(4))
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue
            match_no_crc = LINE_PATTERN_NOCRC.match(line)
            if match_no_crc:
                full_index_candidates += 1
                chunk_idx = int(match_no_crc.group(4))
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue
            match_nosep_no_crc = LINE_PATTERN_NOSEP_NOCRC.match(line)
            if match_nosep_no_crc:
                full_index_candidates += 1
                try:
                    chunk_idx = int(_normalize_digit_token(match_nosep_no_crc.group(3)))
                except Exception:
                    chunk_idx = -1
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue
            match_nosep = LINE_PATTERN_NOSEP.match(line)
            if match_nosep:
                full_index_candidates += 1
                try:
                    chunk_idx = int(_normalize_digit_token(match_nosep.group(3)))
                except Exception:
                    chunk_idx = -1
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue

            chunk_match = CHUNK_PATTERN.match(line)
            if chunk_match:
                chunk_index_candidates += 1
                chunk_idx = int(chunk_match.group(1))
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue
            chunk_no_crc = CHUNK_PATTERN_NOCRC.match(line)
            if chunk_no_crc:
                chunk_index_candidates += 1
                chunk_idx = int(chunk_no_crc.group(1))
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue

            fallback = LINE_PATTERN_FALLBACK.match(line)
            if fallback:
                full_index_candidates += 1
                try:
                    chunk_idx = int(_normalize_digit_token(fallback.group(4)))
                except Exception:
                    continue
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue
            fallback_no_crc = LINE_PATTERN_FALLBACK_NOCRC.match(line)
            if fallback_no_crc:
                full_index_candidates += 1
                try:
                    chunk_idx = int(_normalize_digit_token(fallback_no_crc.group(4)))
                except Exception:
                    continue
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue

            chunk_fallback = CHUNK_PATTERN_FALLBACK.match(line)
            if chunk_fallback:
                chunk_index_candidates += 1
                try:
                    chunk_idx = int(_normalize_digit_token(chunk_fallback.group(1)))
                except Exception:
                    continue
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue
            chunk_fallback_no_crc = CHUNK_PATTERN_FALLBACK_NOCRC.match(line)
            if chunk_fallback_no_crc:
                chunk_index_candidates += 1
                try:
                    chunk_idx = int(_normalize_digit_token(chunk_fallback_no_crc.group(1)))
                except Exception:
                    continue
                if 0 <= chunk_idx < 90000:
                    max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
                continue

            if PAYLOAD_WITH_CRC_PATTERN.match(line) or PAYLOAD_WITH_CRC_FALLBACK_PATTERN.match(line):
                payload_only_candidates += 1
                continue
            if line and (line[0] in SAFE_BASE32_ALPHABET):
                payload_only_candidates += 1

        artifact_id = self._choose_majority_metadata_value("artifact_id", artifact_votes)
        total_chunks = self._choose_majority_metadata_value("total_chunks", total_chunk_votes)
        total_pages = self._choose_majority_metadata_value("total_pages", total_page_votes)

        metadata_source = "meta_header"
        if total_chunks is None:
            if max_data_chunk_idx >= 0:
                total_chunks = max_data_chunk_idx + 1
                metadata_source = "chunk_index_inference"
            else:
                if payload_only_candidates > 0:
                    raise ValueError("cannot infer total chunks from payload-only OCR input without manifest")
                raise ValueError("cannot infer total chunks from OCR input without manifest")

        if artifact_id is None:
            artifact_id = "UNKNOWN"

        metadata = {
            "artifact_id": str(artifact_id),
            "total_chunks": int(total_chunks),
            "total_pages": int(total_pages) if total_pages is not None else 0,
            "metadata_source": metadata_source,
        }
        if payload_only_candidates > 0 and full_index_candidates == 0 and chunk_index_candidates == 0:
            metadata["transport_line_index_mode"] = "off"
        elif chunk_index_candidates > 0 and full_index_candidates == 0:
            metadata["transport_line_index_mode"] = "chunk"
        else:
            metadata["transport_line_index_mode"] = "full"

        for key, bucket in cfg_votes.items():
            value = self._choose_majority_metadata_value(key, bucket)
            if value is not None:
                metadata[key] = int(value)

        for key, bucket in hash_votes.items():
            value = self._choose_majority_metadata_value(key, bucket)
            if value is not None:
                metadata[key] = str(value)

        if all(key in metadata for key in ("RH1", "RH2", "CH1", "CH2", "CC", "LP", "RC", "IL", "PG", "CS", "RS")):
            metadata["metadata_source"] = "embedded_headers"
        return metadata

    def _build_inferred_manifest_from_ocr(self, ocr_input_path: str) -> Dict[str, object]:
        metadata = self._scan_transport_metadata(ocr_input_path)
        manifest: Dict[str, object] = {
            "protocol_version": PROTOCOL_VERSION,
            "artifact_id": metadata["artifact_id"],
            "total_chunks": int(metadata["total_chunks"]),
            "total_pages": int(metadata.get("total_pages", 0) or 0),
            "lines_per_page": int(metadata.get("LP", self.lines_per_page) or self.lines_per_page),
            "transport_line_index_mode": str(metadata.get("transport_line_index_mode", "full")),
            "_metadata_source": metadata["metadata_source"],
            "_embedded_metadata_complete": False,
        }

        required = ("RH1", "RH2", "CH1", "CH2", "CC", "LP", "RC", "IL", "PG", "CS", "RS")
        if not all(key in metadata for key in required):
            return manifest

        chunk_chars = int(metadata["CC"])
        compressed_size = int(metadata["CS"])
        encoded_len = _safe_base32_encoded_length(compressed_size)
        total_chunks = int(metadata["total_chunks"])
        if chunk_chars <= 0:
            return manifest

        expected_total_chunks = int(math.ceil(float(encoded_len) / float(chunk_chars))) if encoded_len > 0 else 0
        if expected_total_chunks != total_chunks:
            manifest["_metadata_error"] = "embedded metadata chunk count mismatch"
            return manifest

        if total_chunks <= 0:
            manifest["_metadata_error"] = "embedded metadata total_chunks must be > 0"
            return manifest

        last_chunk_len = encoded_len - (chunk_chars * (total_chunks - 1))
        if last_chunk_len <= 0:
            last_chunk_len = chunk_chars
        chunk_lengths = [chunk_chars] * max(0, total_chunks - 1)
        chunk_lengths.append(last_chunk_len)

        parity_group_size = int(metadata["PG"])
        manifest.update(
            {
                "compressed_sha256": (str(metadata["CH1"]) + str(metadata["CH2"])).lower(),
                "raw_sha256": (str(metadata["RH1"]) + str(metadata["RH2"])).lower(),
                "raw_size": int(metadata["RS"]),
                "compressed_size": compressed_size,
                "chunk_chars": chunk_chars,
                "chunk_lengths": chunk_lengths,
                "redundancy_copies": int(metadata["RC"]),
                "interleave_enabled": bool(int(metadata["IL"])),
                "parity": self._rebuild_parity_manifest(
                    total_chunks=total_chunks,
                    chunk_lengths=chunk_lengths,
                    parity_group_size=parity_group_size,
                ),
                "_embedded_metadata_complete": True,
            }
        )
        return manifest

    def _verify_ocr_text_without_manifest(
        self,
        ocr_input_path: str,
        strict_payload_chars: bool = False,
    ) -> Dict[str, object]:
        manifest = self._build_inferred_manifest_from_ocr(ocr_input_path)
        if str(manifest.get("transport_line_index_mode", "full")) == "off":
            raise ValueError("payload-only transport requires manifest for verify")
        metadata_source = str(manifest.get("_metadata_source", "unknown"))
        if manifest.get("_embedded_metadata_complete"):
            encoded = self._recover_encoded_payload(manifest, ocr_input_path, strict_payload_chars)
            compressed = _decode_safe_base32(encoded)
            compressed_sha = _sha256_hex(compressed)
            ok = compressed_sha == manifest["compressed_sha256"]
            if not ok:
                return {
                    "success": False,
                    "artifact_id": manifest["artifact_id"],
                    "expected_compressed_sha256": manifest["compressed_sha256"],
                    "actual_compressed_sha256": compressed_sha,
                    "expected_total_chunks": int(manifest["total_chunks"]),
                    "metadata_source": metadata_source,
                    "verification_mode": "embedded_metadata",
                    "message": "verify failed via embedded page metadata",
                }

            raw = zlib.decompress(compressed)
            raw_sha = _sha256_hex(raw)
            if raw_sha != manifest["raw_sha256"]:
                raise ValueError(
                    "raw sha256 mismatch from embedded metadata: expected {}, got {}".format(
                        manifest["raw_sha256"], raw_sha
                    )
                )
            if len(raw) != int(manifest["raw_size"]):
                raise ValueError(
                    "raw size mismatch from embedded metadata: expected {}, got {}".format(
                        manifest["raw_size"], len(raw)
                    )
                )

            return {
                "success": True,
                "artifact_id": manifest["artifact_id"],
                "expected_total_chunks": int(manifest["total_chunks"]),
                "raw_size": len(raw),
                "raw_sha256": raw_sha,
                "expected_compressed_sha256": manifest["compressed_sha256"],
                "actual_compressed_sha256": compressed_sha,
                "metadata_source": metadata_source,
                "verification_mode": "embedded_metadata",
                "message": "verify ok via embedded page metadata",
            }

        total_chunks = int(manifest["total_chunks"])
        parsed = self._parse_ocr_chunks_with_total(
            total_chunks=total_chunks,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
        )
        self._resolve_conflicts_by_structure(parsed=parsed, total_chunks=total_chunks)
        parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
        self._raise_parse_errors(parsed, total_chunks)

        encoded = "".join(parsed["chunks"][i] for i in range(total_chunks))
        compressed = _decode_safe_base32(encoded)
        raw = zlib.decompress(compressed)

        return {
            "success": True,
            "artifact_id": manifest["artifact_id"],
            "expected_total_chunks": total_chunks,
            "received_unique_chunks": len(parsed["chunks"]),
            "raw_size": len(raw),
            "raw_sha256": _sha256_hex(raw),
            "metadata_source": metadata_source,
            "verification_mode": "structural_only",
            "message": "structural verify ok without manifest; sha comparison unavailable",
            "warning": "manifest not provided and embedded metadata was incomplete; verification is structural only",
        }

    def _recover_artifact_without_manifest(
        self,
        ocr_input_path: str,
        output_file: str,
        strict_payload_chars: bool = False,
    ) -> Dict[str, object]:
        manifest = self._build_inferred_manifest_from_ocr(ocr_input_path)
        if str(manifest.get("transport_line_index_mode", "full")) == "off":
            raise ValueError("payload-only transport requires manifest for recover")
        metadata_source = str(manifest.get("_metadata_source", "unknown"))
        if manifest.get("_embedded_metadata_complete"):
            result = self._recover_artifact_against_manifest(
                manifest=manifest,
                ocr_input_path=ocr_input_path,
                output_file=output_file,
                strict_payload_chars=strict_payload_chars,
            )
            result["metadata_source"] = metadata_source
            result["verification_mode"] = "embedded_metadata"
            result["message"] = "recovered without manifest via embedded page metadata"
            return result

        total_chunks = int(manifest["total_chunks"])
        parsed = self._parse_ocr_chunks_with_total(
            total_chunks=total_chunks,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
        )
        self._resolve_conflicts_by_structure(parsed=parsed, total_chunks=total_chunks)
        parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
        self._raise_parse_errors(parsed, total_chunks)

        encoded = "".join(parsed["chunks"][i] for i in range(total_chunks))
        compressed = _decode_safe_base32(encoded)
        raw = zlib.decompress(compressed)

        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(raw)

        return {
            "success": True,
            "artifact_id": manifest["artifact_id"],
            "output_file": str(out_path),
            "raw_size": len(raw),
            "raw_sha256": _sha256_hex(raw),
            "compressed_sha256": _sha256_hex(compressed),
            "metadata_source": metadata_source,
            "verification_mode": "structural_only",
            "message": "recovered without manifest",
            "warning": "manifest not provided and embedded metadata was incomplete; parity recovery and end-to-end sha verification were unavailable",
        }

    def _build_missing_chunk_records(
        self, manifest: Dict[str, object], missing_chunks: List[int]
    ) -> List[Dict[str, int]]:
        records = []
        handled = set()
        chunk_locations = manifest.get("chunk_locations")
        if isinstance(chunk_locations, dict):
            for idx in missing_chunks:
                key = str(int(idx))
                raw_locations = chunk_locations.get(key, [])
                parsed_locations = []
                if isinstance(raw_locations, list):
                    for item in raw_locations:
                        if not isinstance(item, dict):
                            continue
                        try:
                            parsed_locations.append(
                                {
                                    "page": int(item.get("page", 0)),
                                    "line": int(item.get("line", 0)),
                                    "copy": int(item.get("copy", 0)),
                                    "priority": int(item.get("priority", 0)),
                                }
                            )
                        except Exception:
                            continue
                if parsed_locations:
                    parsed_locations.sort(
                        key=lambda x: (
                            int(x.get("priority", 0)),
                            int(x.get("copy", 0)),
                            int(x.get("page", 0)),
                            int(x.get("line", 0)),
                        )
                    )
                    for item in parsed_locations:
                        records.append(
                            {
                                "chunk_index": int(idx),
                                "page": int(item["page"]),
                                "line": int(item["line"]),
                                "copy": int(item["copy"]),
                                "priority": int(item["priority"]),
                            }
                        )
                    handled.add(int(idx))
                    continue

        lines_per_page = int(manifest.get("lines_per_page", self.lines_per_page))
        if lines_per_page <= 0:
            lines_per_page = self.lines_per_page
        for idx in missing_chunks:
            if int(idx) in handled:
                continue
            page = (int(idx) // lines_per_page) + 1
            line = (int(idx) % lines_per_page) + 1
            records.append(
                {
                    "chunk_index": int(idx),
                    "page": page,
                    "line": line,
                    "copy": 1,
                    "priority": 1,
                }
            )
        return records

    def _build_missing_chunk_retake_plan(self, records: List[Dict[str, int]]) -> List[Dict[str, int]]:
        """
        Pick one highest-priority retake point for each missing chunk.
        """
        chosen = {}
        for item in records:
            chunk_idx = int(item.get("chunk_index", -1))
            if chunk_idx < 0:
                continue
            current = chosen.get(chunk_idx)
            if current is None:
                chosen[chunk_idx] = item
                continue
            old_key = (
                int(current.get("priority", 0)),
                int(current.get("copy", 0)),
                int(current.get("page", 0)),
                int(current.get("line", 0)),
            )
            new_key = (
                int(item.get("priority", 0)),
                int(item.get("copy", 0)),
                int(item.get("page", 0)),
                int(item.get("line", 0)),
            )
            if new_key < old_key:
                chosen[chunk_idx] = item

        plan = [chosen[k] for k in sorted(chosen.keys())]
        return plan

    def _count_chunk_presence(self, chunks: object, total_chunks: int) -> Tuple[int, int]:
        data_count = 0
        parity_count = 0
        if not isinstance(chunks, dict):
            return data_count, parity_count
        for chunk_idx in chunks.keys():
            try:
                idx = int(chunk_idx)
            except Exception:
                continue
            if 0 <= idx < total_chunks:
                data_count += 1
            else:
                parity_count += 1
        return data_count, parity_count

    def _apply_parity_recovery(self, manifest: Dict[str, object], parsed: Dict[str, object]) -> List[int]:
        """
        Try to recover missing data chunks from parity groups.
        Returns recovered chunk indices.
        """
        parity = manifest.get("parity")
        if not isinstance(parity, dict) or not parity.get("enabled"):
            return []
        groups = parity.get("groups")
        if not isinstance(groups, list):
            return []
        chunk_lengths = manifest.get("chunk_lengths")
        if not isinstance(chunk_lengths, list):
            return []

        chunks = parsed.get("chunks", {})
        if not isinstance(chunks, dict):
            return []

        recovered = []
        recovered_set = set()
        for group in groups:
            if not isinstance(group, dict):
                continue
            data_indices_raw = group.get("data_chunk_indices", [])
            if not isinstance(data_indices_raw, list):
                continue
            try:
                data_indices = [int(v) for v in data_indices_raw]
            except Exception:
                continue
            try:
                parity_idx = int(group.get("parity_chunk_index"))
            except Exception:
                continue

            parity_payload = chunks.get(parity_idx)
            if not isinstance(parity_payload, str) or not parity_payload:
                continue

            missing_data = [idx for idx in data_indices if idx not in chunks]
            if len(missing_data) != 1:
                continue

            missing_idx = int(missing_data[0])
            if missing_idx < 0 or missing_idx >= len(chunk_lengths):
                continue
            expected_len = int(chunk_lengths[missing_idx])
            parity_len = int(group.get("parity_len", len(parity_payload)))
            if parity_len <= 0:
                continue

            vals = [0] * parity_len
            usable_parity = parity_payload[:parity_len]
            for pos, ch in enumerate(usable_parity):
                if ch not in SAFE_CHAR_TO_VAL:
                    vals = []
                    break
                vals[pos] = SAFE_CHAR_TO_VAL[ch]
            if not vals:
                continue

            ok = True
            for idx in data_indices:
                if idx == missing_idx:
                    continue
                payload = chunks.get(idx)
                if not isinstance(payload, str):
                    ok = False
                    break
                for pos, ch in enumerate(payload[:parity_len]):
                    if ch not in SAFE_CHAR_TO_VAL:
                        ok = False
                        break
                    vals[pos] ^= SAFE_CHAR_TO_VAL[ch]
                if not ok:
                    break
            if not ok:
                continue

            candidate = "".join(SAFE_BASE32_ALPHABET[v] for v in vals)
            candidate = candidate[:expected_len]
            if not candidate:
                continue

            existing = chunks.get(missing_idx)
            if isinstance(existing, str) and existing and existing != candidate:
                parsed.setdefault("duplicate_conflicts", []).append(
                    {
                        "chunk_idx": missing_idx,
                        "existing": existing[:40],
                        "new": candidate[:40],
                        "reason": "parity_recover_conflict",
                    }
                )
                continue

            chunks[missing_idx] = candidate
            if missing_idx not in recovered_set:
                recovered.append(missing_idx)
                recovered_set.add(missing_idx)
                parsed.setdefault("line_warnings", []).append(
                    {
                        "reason": "chunk_recovered_by_parity",
                        "chunk_idx": missing_idx,
                        "parity_chunk_idx": parity_idx,
                    }
                )
        recovered.sort()
        return recovered

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
        duplicate_conflicts = parsed.get("duplicate_conflicts", [])
        if not isinstance(duplicate_conflicts, list) or not duplicate_conflicts:
            return

        blocking = []
        ignored = []
        for item in duplicate_conflicts:
            if not isinstance(item, dict):
                continue
            try:
                chunk_idx = int(item.get("chunk_idx", -1))
            except Exception:
                chunk_idx = -1
            if 0 <= chunk_idx < int(total_chunks):
                blocking.append(item)
            else:
                ignored.append(chunk_idx)

        if ignored:
            parsed.setdefault("line_warnings", []).append(
                {
                    "reason": "parity_duplicate_conflicts_ignored",
                    "count": len(ignored),
                    "chunk_indices": ignored[:20],
                }
            )
        parsed["duplicate_conflicts"] = blocking

    def _resolve_conflicts_by_package_hash(
        self,
        manifest: Dict[str, object],
        parsed: Dict[str, object],
        max_conflicts: int = 12,
        max_attempts: int = 20000,
    ) -> List[int]:
        duplicate_conflicts = parsed.get("duplicate_conflicts", [])
        chunk_votes = parsed.get("chunk_votes", {})
        if not isinstance(duplicate_conflicts, list) or not duplicate_conflicts:
            return []
        if not isinstance(chunk_votes, dict):
            return []

        conflict_items = []
        for item in duplicate_conflicts:
            if not isinstance(item, dict):
                continue
            try:
                chunk_idx = int(item.get("chunk_idx"))
            except Exception:
                continue
            votes = chunk_votes.get(chunk_idx)
            if not isinstance(votes, dict) or not votes:
                continue
            ranked = sorted(votes.items(), key=lambda kv: (-int(kv[1]), kv[0]))
            if not ranked:
                continue
            top_count = int(ranked[0][1])
            candidates = [payload for payload, count in ranked if int(count) == top_count]
            if len(candidates) < 2:
                continue
            conflict_items.append((chunk_idx, candidates))

        if not conflict_items or len(conflict_items) > int(max_conflicts):
            return []

        total_chunks = int(manifest["total_chunks"])
        base_chunks = dict(parsed.get("chunks", {}))
        attempts = 0
        for payload_combo in itertools.product(*[item[1] for item in conflict_items]):
            attempts += 1
            if attempts > int(max_attempts):
                break

            test_parsed = {
                "chunks": dict(base_chunks),
                "duplicate_conflicts": [],
                "line_warnings": [],
            }
            for pair, payload in zip(conflict_items, payload_combo):
                test_parsed["chunks"][pair[0]] = payload

            self._apply_parity_recovery(manifest, test_parsed)
            if any(idx not in test_parsed["chunks"] for idx in range(total_chunks)):
                continue

            try:
                encoded = "".join(test_parsed["chunks"][idx] for idx in range(total_chunks))
                compressed = _decode_safe_base32(encoded)
                if _sha256_hex(compressed) != manifest["compressed_sha256"]:
                    continue
                raw = zlib.decompress(compressed)
            except Exception:
                continue

            if _sha256_hex(raw) != manifest["raw_sha256"]:
                continue
            if len(raw) != int(manifest["raw_size"]):
                continue

            parsed["chunks"] = test_parsed["chunks"]
            parsed["duplicate_conflicts"] = []
            parsed.setdefault("line_warnings", []).append(
                {
                    "reason": "duplicate_conflicts_resolved_by_package_hash",
                    "resolved_count": len(conflict_items),
                    "attempts": attempts,
                }
            )
            return [pair[0] for pair in conflict_items]

        return []

    def _resolve_conflicts_by_structure(
        self,
        parsed: Dict[str, object],
        total_chunks: int,
        max_conflicts: int = 10,
        max_attempts: int = 20000,
    ) -> List[int]:
        duplicate_conflicts = parsed.get("duplicate_conflicts", [])
        chunk_votes = parsed.get("chunk_votes", {})
        if not isinstance(duplicate_conflicts, list) or not duplicate_conflicts:
            return []
        if not isinstance(chunk_votes, dict):
            return []

        conflict_items = []
        for item in duplicate_conflicts:
            if not isinstance(item, dict):
                continue
            try:
                chunk_idx = int(item.get("chunk_idx"))
            except Exception:
                continue
            votes = chunk_votes.get(chunk_idx)
            if not isinstance(votes, dict) or not votes:
                continue
            ranked = sorted(votes.items(), key=lambda kv: (-int(kv[1]), kv[0]))
            if not ranked:
                continue
            top_count = int(ranked[0][1])
            candidates = [payload for payload, count in ranked if int(count) == top_count]
            if len(candidates) < 2:
                continue
            conflict_items.append((chunk_idx, candidates))

        if not conflict_items or len(conflict_items) > int(max_conflicts):
            return []

        base_chunks = dict(parsed.get("chunks", {}))
        attempts = 0
        winners = []
        for payload_combo in itertools.product(*[item[1] for item in conflict_items]):
            attempts += 1
            if attempts > int(max_attempts):
                break
            test_chunks = dict(base_chunks)
            for pair, payload in zip(conflict_items, payload_combo):
                test_chunks[pair[0]] = payload
            if any(idx not in test_chunks for idx in range(int(total_chunks))):
                continue
            try:
                encoded = "".join(test_chunks[idx] for idx in range(int(total_chunks)))
                compressed = _decode_safe_base32(encoded)
                zlib.decompress(compressed)
            except Exception:
                continue
            winners.append(test_chunks)
            if len(winners) > 1:
                break

        if len(winners) != 1:
            return []

        parsed["chunks"] = winners[0]
        resolved = [pair[0] for pair in conflict_items]
        parsed["duplicate_conflicts"] = [
            item
            for item in duplicate_conflicts
            if isinstance(item, dict) and int(item.get("chunk_idx", -1)) not in set(resolved)
        ]
        parsed.setdefault("line_warnings", []).append(
            {
                "reason": "duplicate_conflicts_resolved_by_structure",
                "resolved_count": len(resolved),
                "attempts": attempts,
            }
        )
        return resolved

    def _raise_parse_errors(self, parsed: Dict[str, object], total_chunks: int) -> None:
        line_errors = parsed["line_errors"]
        dup = parsed["duplicate_conflicts"]
        missing = parsed["missing_chunks"]

        if line_errors:
            first = line_errors[0]
            raise ValueError(
                "line parse errors count={} first={}".format(
                    len(line_errors), json.dumps(first, ensure_ascii=False, sort_keys=True)
                )
            )

        if dup:
            first = dup[0]
            raise ValueError(
                "duplicate chunk conflicts count={} first={}".format(
                    len(dup), json.dumps(first, ensure_ascii=False, sort_keys=True)
                )
            )

        if missing:
            sample = ",".join(str(i) for i in missing[:30])
            raise ValueError(
                "missing chunks count={} total={} sample={} (run `analyze` for full report)".format(
                    len(missing), total_chunks, sample
                )
            )

    def _recover_encoded_payload(
        self, manifest: Dict[str, object], ocr_input_path: str, strict_payload_chars: bool
    ) -> str:
        total_chunks = int(manifest["total_chunks"])
        parsed = self._parse_ocr_chunks(manifest, ocr_input_path, strict_payload_chars)
        self._apply_parity_recovery(manifest, parsed)
        self._resolve_conflicts_by_package_hash(manifest, parsed)
        self._apply_parity_recovery(manifest, parsed)
        self._downgrade_nonblocking_parity_conflicts(parsed, total_chunks)
        parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
        self._raise_parse_errors(parsed, total_chunks)
        ordered = [parsed["chunks"][i] for i in range(total_chunks)]
        return "".join(ordered)

    def _load_font(self, size: int):
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is not available")

        pil_font_candidates = []
        try:
            pil_dir = Path(ImageFont.__file__).resolve().parent
            pil_font_candidates.extend(
                [
                    str(pil_dir / "fonts" / "DejaVuSansMono.ttf"),
                    str(pil_dir / "fonts" / "DejaVuSans.ttf"),
                ]
            )
        except Exception:
            pass

        candidates = [
            "CascadiaMono.ttf",
            "Consola.ttf",
            "Courier New.ttf",
            "cour.ttf",
            "OCRAEXT.TTF",
            "DejaVuSansMono.ttf",
            "DejaVuSans.ttf",
        ]
        for name in candidates + pil_font_candidates:
            try:
                return ImageFont.truetype(name, size=size)
            except Exception:
                continue
        try:
            return ImageFont.load_default(size=int(size))  # Pillow>=10
        except Exception:
            return ImageFont.load_default()

    def _render_page(self, lines: List[str], output_path: Path) -> Dict[str, object]:
        width, height = self.page_size
        img = Image.new("RGB", (width, height), "white")
        draw = ImageDraw.Draw(img)

        def _parse_render_data_line(text: str, fallback_line_no: int) -> Optional[Dict[str, object]]:
            if not text or text.startswith("@"):
                return None

            match = LINE_PATTERN.match(text) or LINE_PATTERN_NOCRC.match(text)
            if match:
                return {
                    "mode": "full",
                    "page_no": int(match.group(1)),
                    "line_no": int(match.group(2)),
                    "chunk_idx": int(match.group(4)),
                    "payload": str(match.group(5)),
                    "expected_crc": str(match.group(6)) if match.re == LINE_PATTERN else "",
                }

            match_chunk = CHUNK_PATTERN.match(text) or CHUNK_PATTERN_NOCRC.match(text)
            if match_chunk:
                return {
                    "mode": "chunk",
                    "page_no": 0,
                    "line_no": int(fallback_line_no),
                    "chunk_idx": int(match_chunk.group(1)),
                    "payload": str(match_chunk.group(3)),
                    "expected_crc": str(match_chunk.group(4)) if match_chunk.re == CHUNK_PATTERN else "",
                }

            payload_with_crc = PAYLOAD_WITH_CRC_PATTERN.match(text)
            if payload_with_crc:
                return {
                    "mode": "payload",
                    "page_no": 0,
                    "line_no": int(fallback_line_no),
                    "chunk_idx": -1,
                    "payload": str(payload_with_crc.group(1)),
                    "expected_crc": str(payload_with_crc.group(3)),
                }
            payload_with_crc_fb = PAYLOAD_WITH_CRC_FALLBACK_PATTERN.match(text)
            if payload_with_crc_fb:
                return {
                    "mode": "payload",
                    "page_no": 0,
                    "line_no": int(fallback_line_no),
                    "chunk_idx": -1,
                    "payload": str(payload_with_crc_fb.group(1)),
                    "expected_crc": _normalize_hex_token(str(payload_with_crc_fb.group(3))),
                }

            if all(ch in SAFE_BASE32_ALPHABET for ch in text):
                return {
                    "mode": "payload",
                    "page_no": 0,
                    "line_no": int(fallback_line_no),
                    "chunk_idx": -1,
                    "payload": str(text),
                    "expected_crc": "",
                }
            return None

        parsed_render_lines: List[Optional[Dict[str, object]]] = []
        for idx, line in enumerate(lines, 1):
            parsed_render_lines.append(_parse_render_data_line(line, idx))

        data_lines = [line for idx, line in enumerate(lines) if parsed_render_lines[idx] is not None]
        control_lines = [line for idx, line in enumerate(lines) if parsed_render_lines[idx] is None]
        max_data_len = max((len(line) for line in data_lines), default=0)
        max_control_len = max((len(line) for line in control_lines), default=0)

        usable_w = width - (self.margin * 2)
        usable_h = height - (self.margin * 2)
        sidecar_reserved_w = 0
        if data_lines and self.render_sidecar:
            sidecar_reserved_w = (
                SIDECAR_BITS_PER_ROW * SIDECAR_CELL_SIZE
                + (SIDECAR_BITS_PER_ROW - 1) * SIDECAR_CELL_GAP
                + 24
            )
        data_usable_w = max(120, usable_w - sidecar_reserved_w)

        base_size = max(16, int(self.font_size))
        if self.font_fit_mode == "fixed":
            max_candidate_size = base_size
            min_candidate_size = base_size
        elif self.font_fit_mode == "fit":
            max_candidate_size = max(base_size + 24, min(int(self.font_max_size), base_size * 3))
            min_candidate_size = 12
        else:
            # target mode: prefer --font-size exactly, only shrink when layout overflows.
            max_candidate_size = base_size
            min_candidate_size = 12

        data_font_size = base_size
        control_font_size = max(12, int(round(base_size * 0.62)))
        data_font = self._load_font(data_font_size)
        control_font = self._load_font(control_font_size)
        data_line_h = draw.textbbox((0, 0), "Mg", font=data_font)[3] + self.line_gap
        control_line_gap = max(2, int(round(self.line_gap * 0.45)))
        control_line_h = draw.textbbox((0, 0), "Mg", font=control_font)[3] + control_line_gap

        for candidate_size in range(max_candidate_size, min_candidate_size - 1, -2):
            candidate_data_font = self._load_font(candidate_size)
            candidate_control_size = max(12, int(round(candidate_size * 0.62)))
            candidate_control_font = self._load_font(candidate_control_size)
            candidate_data_line_h = (
                draw.textbbox((0, 0), "Mg", font=candidate_data_font)[3] + self.line_gap
            )
            candidate_control_line_h = (
                draw.textbbox((0, 0), "Mg", font=candidate_control_font)[3] + control_line_gap
            )
            candidate_data_char_w = draw.textbbox((0, 0), "M", font=candidate_data_font)[2]
            candidate_control_char_w = draw.textbbox((0, 0), "M", font=candidate_control_font)[2]

            fits_w = (
                (max_data_len * candidate_data_char_w <= data_usable_w if max_data_len > 0 else True)
                and (max_control_len * candidate_control_char_w <= usable_w if max_control_len > 0 else True)
            )
            fits_h = (
                (len(data_lines) * candidate_data_line_h)
                + (len(control_lines) * candidate_control_line_h)
            ) <= usable_h
            if fits_w and fits_h:
                data_font_size = candidate_size
                control_font_size = candidate_control_size
                data_font = candidate_data_font
                control_font = candidate_control_font
                data_line_h = candidate_data_line_h
                control_line_h = candidate_control_line_h
                break

        x = self.margin
        y = self.margin
        layout_lines = []
        for idx, line in enumerate(lines):
            parsed_line = parsed_render_lines[idx]
            is_data = bool(parsed_line)
            line_font = data_font if is_data else control_font
            line_h = data_line_h if is_data else control_line_h
            line_color = "black" if is_data else (20, 20, 20)

            draw.text((x, y), line, fill=line_color, font=line_font)
            text_bbox = draw.textbbox((x, y), line, font=line_font)
            line_box = [
                int(max(0, text_bbox[0] - 8)),
                int(max(0, y - 4)),
                int(min(width, text_bbox[2] + 8)),
                int(min(height, y + line_h + 4)),
            ]

            meta = {"kind": "other", "line_box": line_box}
            if parsed_line:
                page_no = int(parsed_line.get("page_no", 0))
                line_no = int(parsed_line.get("line_no", idx + 1))
                chunk_idx = int(parsed_line.get("chunk_idx", -1))
                payload = str(parsed_line.get("payload", ""))
                mode = str(parsed_line.get("mode", "full"))
                if mode == "full":
                    prefix = "P{:03d}L{:03d}{}C{:05d}{}".format(
                        page_no, line_no, self.line_separator, chunk_idx, self.line_separator
                    )
                elif mode == "chunk":
                    prefix = "C{:05d}{}".format(chunk_idx, self.line_separator)
                else:
                    prefix = ""
                prefix_bbox = draw.textbbox((x, y), prefix, font=line_font)
                payload_bbox = draw.textbbox((prefix_bbox[2], y), payload, font=line_font)
                sidecar_bits = _safe_payload_to_bits(payload)
                sidecar_rows = int(math.ceil(float(len(sidecar_bits)) / float(SIDECAR_BITS_PER_ROW)))
                sidecar_cols = SIDECAR_BITS_PER_ROW
                sidecar_width = (
                    sidecar_cols * SIDECAR_CELL_SIZE + (sidecar_cols - 1) * SIDECAR_CELL_GAP
                )
                sidecar_height = (
                    sidecar_rows * SIDECAR_CELL_SIZE + (sidecar_rows - 1) * SIDECAR_CELL_GAP
                )
                sidecar_left = int(width - self.margin - sidecar_width)
                min_sidecar_left = int(text_bbox[2] + 24)
                if sidecar_left < min_sidecar_left:
                    sidecar_left = min_sidecar_left
                sidecar_top = int(max(0, y + max(0, (line_h - sidecar_height) // 2)))
                if self.render_sidecar and sidecar_left + sidecar_width <= width - self.margin:
                    for bit_index, bit in enumerate(sidecar_bits):
                        if bit != "1":
                            continue
                        row = bit_index // sidecar_cols
                        col = bit_index % sidecar_cols
                        cell_left = sidecar_left + col * (SIDECAR_CELL_SIZE + SIDECAR_CELL_GAP)
                        cell_top = sidecar_top + row * (SIDECAR_CELL_SIZE + SIDECAR_CELL_GAP)
                        draw.rectangle(
                            (
                                cell_left,
                                cell_top,
                                cell_left + SIDECAR_CELL_SIZE - 1,
                                cell_top + SIDECAR_CELL_SIZE - 1,
                            ),
                            fill="black",
                        )

                meta.update(
                    {
                        "kind": "data",
                        "page": page_no,
                        "line_no": line_no,
                        "chunk_index": chunk_idx,
                        "payload_len": len(payload),
                        "expected_crc": str(parsed_line.get("expected_crc", "")),
                        "font_size": int(data_font_size),
                        "bit_count": len(sidecar_bits),
                        "binary_cell": SIDECAR_CELL_SIZE,
                        "binary_cols": sidecar_cols,
                        "binary_gap": SIDECAR_CELL_GAP,
                        "binary_rows": sidecar_rows,
                        "payload_box": [
                            int(max(0, prefix_bbox[2] + 8)),
                            int(max(0, y - 4)),
                            int(min(width, payload_bbox[2] + 4)),
                            int(min(height, y + line_h + 4)),
                        ],
                    }
                )
                if self.render_sidecar and sidecar_left + sidecar_width <= width - self.margin:
                    meta["binary_box"] = [
                        int(sidecar_left),
                        int(sidecar_top),
                        int(sidecar_left + sidecar_width),
                        int(sidecar_top + sidecar_height),
                    ]
            layout_lines.append(meta)
            y += line_h

        output_path.parent.mkdir(parents=True, exist_ok=True)
        img.save(str(output_path), "PNG", dpi=(300, 300), optimize=True)
        return {
            "font_size": int(data_font_size),
            "control_font_size": int(control_font_size),
            "line_height": int(data_line_h),
            "control_line_height": int(control_line_h),
            "line_count": len(lines),
            "data_line_count": len(data_lines),
            "control_line_count": len(control_lines),
            "page_height": int(height),
            "page_width": int(width),
            "lines": layout_lines,
        }


def _print_json(data: Dict[str, object]) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def _save_json(path: str, data: Dict[str, object]) -> str:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return str(out)


def _save_missing_chunks(path: str, records: List[Dict[str, int]]) -> str:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    preferred = ["chunk_index", "page", "line", "copy", "priority"]
    extra = []
    for item in records:
        for key in item.keys():
            if key in preferred or key in extra:
                continue
            extra.append(key)
    columns = preferred + extra
    lines = [",".join(columns)]
    for item in records:
        row = [str(item.get(col, "")) for col in columns]
        lines.append(",".join(row))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(out)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Airgap transport layer for encrypted small artifacts."
    )
    sub = parser.add_subparsers(dest="cmd")
    # Python 3.6 does not support add_subparsers(..., required=True)
    sub.required = True

    p_export = sub.add_parser("export", help="export artifact bytes to OCR package")
    p_export.add_argument(
        "-i",
        "--input-file",
        required=True,
        help="input artifact path; encrypt first if confidentiality matters",
    )
    p_export.add_argument("-o", "--output-dir", required=True, help="output package directory")
    p_export.add_argument("--artifact-id", default=None, help="optional artifact id")
    p_export.add_argument("--filename-prefix", default="page", help="output page prefix")
    p_export.add_argument("--max-compressed-kib", type=int, default=64)
    p_export.add_argument("--chunk-chars", type=int, default=40)
    p_export.add_argument("--lines-per-page", type=int, default=20)
    p_export.add_argument(
        "--font-size",
        type=int,
        default=44,
        help="target font size for rendered PNG pages (default fit mode: target)",
    )
    p_export.add_argument(
        "--font-max-size",
        type=int,
        default=132,
        help="upper bound used only when --font-fit-mode fit",
    )
    p_export.add_argument(
        "--font-fit-mode",
        choices=["target", "fit", "fixed"],
        default="target",
        help="target: keep --font-size unless overflow; fit: auto enlarge to max; fixed: strict fixed size",
    )
    p_export.add_argument(
        "--fixed-font-size",
        action="store_true",
        help="deprecated alias of --font-fit-mode fixed",
    )
    p_export.add_argument(
        "--metadata-level",
        choices=["compact", "none"],
        default="compact",
        help="page control metadata level: compact keeps @META/@CFG/@HS/@PAGECRC, none keeps data lines only",
    )
    p_export.add_argument(
        "--line-separator",
        choices=list(SUPPORTED_FIELD_SEPARATORS),
        default="|",
        help="field separator in exported data lines",
    )
    p_export.add_argument(
        "--line-index-mode",
        choices=["full", "chunk", "off"],
        default="full",
        help="full: P/L/C, chunk: C only, off: payload only (manifest required for recover/verify)",
    )
    p_export.add_argument(
        "--line-crc-mode",
        choices=["on", "off"],
        default="on",
        help="append per-line CRC suffix in transport lines",
    )
    p_export.add_argument(
        "--no-sidecar",
        action="store_true",
        help="disable rendering right-side sidecar blocks in PNG pages",
    )
    p_export.add_argument(
        "--redundancy-copies",
        type=int,
        default=1,
        help="repeat each chunk N copies for anti-loss transport (default 1)",
    )
    p_export.add_argument(
        "--no-interleave",
        action="store_true",
        help="disable interleaving chunk copies across pages",
    )
    p_export.add_argument(
        "--parity-group-size",
        type=int,
        default=0,
        help="add one parity chunk per N data chunks (0 disables, recommended 8)",
    )

    p_estimate = sub.add_parser("estimate", help="estimate export size, chunk count, and page count")
    p_estimate.add_argument("-i", "--input-file", required=True, help="input artifact path")
    p_estimate.add_argument("--max-compressed-kib", type=int, default=64)
    p_estimate.add_argument("--chunk-chars", type=int, default=40)
    p_estimate.add_argument("--lines-per-page", type=int, default=20)
    p_estimate.add_argument(
        "--redundancy-copies",
        type=int,
        default=1,
        help="repeat each chunk N copies for anti-loss transport (default 1)",
    )
    p_estimate.add_argument(
        "--no-interleave",
        action="store_true",
        help="disable interleaving chunk copies across pages",
    )
    p_estimate.add_argument(
        "--parity-group-size",
        type=int,
        default=0,
        help="add one parity chunk per N data chunks (0 disables, recommended 8)",
    )

    p_recover = sub.add_parser("recover", help="recover artifact from OCR text")
    p_recover.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="manifest json path; optional when OCR text contains embedded export metadata",
    )
    p_recover.add_argument("-t", "--ocr-input", required=True, help="ocr text file/dir")
    p_recover.add_argument("-o", "--output-file", required=True, help="recovered artifact path")
    p_recover.add_argument("--strict-payload-chars", action="store_true")

    p_verify = sub.add_parser("verify", help="verify OCR text against manifest")
    p_verify.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="manifest json path; optional when OCR text contains embedded export metadata",
    )
    p_verify.add_argument("-t", "--ocr-input", required=True, help="ocr text file/dir")
    p_verify.add_argument("--strict-payload-chars", action="store_true")

    p_analyze = sub.add_parser("analyze", help="analyze OCR text quality and missing chunks")
    p_analyze.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="manifest json path; optional when OCR text contains embedded export metadata",
    )
    p_analyze.add_argument("-t", "--ocr-input", required=True, help="ocr text file/dir")
    p_analyze.add_argument("--strict-payload-chars", action="store_true")
    p_analyze.add_argument("--max-list", type=int, default=200, help="max list size in output")
    p_analyze.add_argument("--save-report", default=None, help="optional analyze json output path")
    p_analyze.add_argument(
        "--emit-missing-file",
        default=None,
        help="optional csv output with chunk_index,page,line,copy,priority for recapture",
    )

    p_ocr = sub.add_parser("ocr-extract", help="extract text from images with OCR backend")
    p_ocr.add_argument("-i", "--image-input", required=True, help="image file/dir")
    p_ocr.add_argument("-o", "--output-text", required=True, help="output text file path")
    p_ocr.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="optional manifest to enable structured OCR on self-generated pages",
    )
    p_ocr.add_argument(
        "--backend",
        choices=["tesseract", "easyocr", "sidecar", "external", "auto"],
        default="tesseract",
    )
    p_ocr.add_argument("--lang", default="eng", help="ocr language")
    p_ocr.add_argument("--psm", type=int, default=6, help="tesseract psm mode")
    p_ocr.add_argument(
        "--ocr-provider-cmd",
        default=None,
        help=(
            "external OCR command template used by backend=external/auto; placeholders: "
            "{image_path} {image_name} {page_no} {lang} {psm} {manifest_path}"
        ),
    )
    p_ocr.add_argument(
        "--ocr-provider-timeout-sec",
        type=int,
        default=120,
        help="timeout seconds for one external OCR command call",
    )

    p_recover_images = sub.add_parser(
        "recover-images", help="ocr images then analyze+recover artifact in one command"
    )
    p_recover_images.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="manifest json path; optional when page photos are from exports with embedded metadata",
    )
    p_recover_images.add_argument("-i", "--image-input", required=True, help="image file/dir")
    p_recover_images.add_argument("-o", "--output-file", required=True, help="recovered artifact path")
    p_recover_images.add_argument(
        "--backend",
        choices=["tesseract", "easyocr", "sidecar", "external", "auto"],
        default="auto",
    )
    p_recover_images.add_argument("--lang", default="eng", help="ocr language")
    p_recover_images.add_argument("--psm", type=int, default=6, help="tesseract psm mode")
    p_recover_images.add_argument(
        "--ocr-provider-cmd",
        default=None,
        help=(
            "external OCR command template used by backend=external/auto; placeholders: "
            "{image_path} {image_name} {page_no} {lang} {psm} {manifest_path}"
        ),
    )
    p_recover_images.add_argument(
        "--ocr-provider-timeout-sec",
        type=int,
        default=120,
        help="timeout seconds for one external OCR command call",
    )
    p_recover_images.add_argument("--strict-payload-chars", action="store_true")
    p_recover_images.add_argument(
        "--ocr-text-output", default=None, help="optional extracted OCR text output path"
    )
    p_recover_images.add_argument(
        "--save-analyze-report", default=None, help="optional analyze report json path"
    )
    p_recover_images.add_argument(
        "--emit-missing-file",
        default=None,
        help="optional csv output with chunk_index,page,line,copy,priority for recapture",
    )
    p_recover_images.add_argument("--max-list", type=int, default=200, help="max list size in analyze")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    transport = AirgapTransportLayer(
        max_compressed_kib=getattr(args, "max_compressed_kib", 64),
        chunk_chars=getattr(args, "chunk_chars", 80),
        lines_per_page=getattr(args, "lines_per_page", 28),
        font_size=getattr(args, "font_size", 44),
        font_max_size=getattr(args, "font_max_size", 132),
        fixed_font_size=bool(getattr(args, "fixed_font_size", False)),
        font_fit_mode=getattr(args, "font_fit_mode", "target"),
        metadata_level=getattr(args, "metadata_level", "compact"),
        line_separator=getattr(args, "line_separator", "|"),
        line_index_mode=getattr(args, "line_index_mode", "full"),
        render_sidecar=(not bool(getattr(args, "no_sidecar", False))),
        line_crc_mode=getattr(args, "line_crc_mode", "on"),
    )

    try:
        if args.cmd == "estimate":
            result = transport.estimate_export_artifact(
                input_file=args.input_file,
                redundancy_copies=args.redundancy_copies,
                interleave=(not args.no_interleave),
                parity_group_size=args.parity_group_size,
            )
            _print_json(result)
            return 0

        if args.cmd == "export":
            result = transport.export_artifact(
                input_file=args.input_file,
                output_dir=args.output_dir,
                artifact_id=args.artifact_id,
                filename_prefix=args.filename_prefix,
                redundancy_copies=args.redundancy_copies,
                interleave=(not args.no_interleave),
                parity_group_size=args.parity_group_size,
            )
            _print_json(result)
            return 0

        if args.cmd == "recover":
            result = transport.recover_artifact(
                manifest_path=args.manifest,
                ocr_input_path=args.ocr_input,
                output_file=args.output_file,
                strict_payload_chars=args.strict_payload_chars,
            )
            _print_json(result)
            return 0

        if args.cmd == "verify":
            result = transport.verify_ocr_text(
                manifest_path=args.manifest,
                ocr_input_path=args.ocr_input,
                strict_payload_chars=args.strict_payload_chars,
            )
            _print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "analyze":
            result = transport.analyze_ocr_text(
                manifest_path=args.manifest,
                ocr_input_path=args.ocr_input,
                strict_payload_chars=args.strict_payload_chars,
                max_list=args.max_list,
                save_report_path=args.save_report,
                emit_missing_file=args.emit_missing_file,
            )
            _print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "ocr-extract":
            result = transport.extract_text_from_images(
                image_input_path=args.image_input,
                output_text_path=args.output_text,
                backend=args.backend,
                lang=args.lang,
                psm=args.psm,
                manifest_path=args.manifest,
                ocr_provider_cmd=args.ocr_provider_cmd,
                ocr_provider_timeout_sec=args.ocr_provider_timeout_sec,
            )
            _print_json(result)
            return 0

        if args.cmd == "recover-images":
            result = transport.recover_from_images(
                manifest_path=args.manifest,
                image_input_path=args.image_input,
                output_file=args.output_file,
                backend=args.backend,
                lang=args.lang,
                psm=args.psm,
                ocr_provider_cmd=args.ocr_provider_cmd,
                ocr_provider_timeout_sec=args.ocr_provider_timeout_sec,
                strict_payload_chars=args.strict_payload_chars,
                ocr_text_output=args.ocr_text_output,
                save_analyze_report=args.save_analyze_report,
                emit_missing_file=args.emit_missing_file,
                max_list=args.max_list,
            )
            _print_json(result)
            return 0 if result.get("success") else 2

        parser.print_help()
        return 1

    except Exception as exc:
        err = {"success": False, "error": str(exc), "cmd": args.cmd}
        _print_json(err)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
