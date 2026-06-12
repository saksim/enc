"""Transport OCR runtime/orchestration helpers extracted from qrcode_helper."""

import itertools
import json
import math
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from . import ocr_observations
from . import protocol


def _clamp_int(value: int, low: int, high: int) -> int:
    return min(max(int(value), int(low)), int(high))


def _sidecar_region_mean(gray, left: int, top: int, right: int, bottom: int) -> float:
    left = _clamp_int(left, 0, gray.width - 1)
    top = _clamp_int(top, 0, gray.height - 1)
    right = _clamp_int(right, left + 1, gray.width)
    bottom = _clamp_int(bottom, top + 1, gray.height)

    total = 0
    count = 0
    for y in range(top, bottom):
        for x in range(left, right):
            total += int(gray.getpixel((x, y)))
            count += 1
    if count <= 0:
        return 255.0
    return float(total) / float(count)


def _sidecar_candidate_payload(
    gray,
    left: float,
    top: float,
    cell_w: float,
    cell_h: float,
    gap_x: float,
    gap_y: float,
    cols: int,
    bit_count: int,
    payload_len: int,
    threshold: int,
    payload_alphabet_profile: str = "safe-base32-v1",
):
    bits = []
    samples = []
    inset_x = max(0.0, min(2.0, float(cell_w) / 4.0))
    inset_y = max(0.0, min(2.0, float(cell_h) / 4.0))
    step_x = max(1.0, float(cell_w) + float(gap_x))
    step_y = max(1.0, float(cell_h) + float(gap_y))

    for bit_index in range(bit_count):
        row = bit_index // cols
        col = bit_index % cols
        cell_left = left + col * step_x
        cell_top = top + row * step_y
        mean = _sidecar_region_mean(
            gray=gray,
            left=int(math.floor(cell_left + inset_x)),
            top=int(math.floor(cell_top + inset_y)),
            right=int(math.ceil(cell_left + float(cell_w) - inset_x)),
            bottom=int(math.ceil(cell_top + float(cell_h) - inset_y)),
        )
        samples.append(mean)
        bits.append("1" if mean < threshold else "0")

    if not samples:
        return "", (1.0, 0, 0)

    payload = protocol.bits_to_payload_for_profile(
        "".join(bits),
        payload_len,
        payload_alphabet_profile,
    )
    if not payload:
        return "", (1.0, 0, 0)

    dark = sum(1 for sample in samples if sample < threshold)
    dark_ratio = float(dark) / float(len(samples))
    contrast = max(samples) - min(samples)
    balance_penalty = abs(dark_ratio - 0.5)
    confidence = sum(abs(sample - threshold) for sample in samples) / float(len(samples))
    return payload, (balance_penalty, -int(contrast), -int(confidence))


def _sidecar_crc_matches(chunk_idx: int, payload: str, expected_crc: str) -> bool:
    if not expected_crc:
        return False
    core = "C{:05d}|{}".format(int(chunk_idx), payload)
    return protocol.crc16_hex(core) == expected_crc


def _sidecar_search_offsets(span: int) -> List[int]:
    span = max(0, int(span))
    offsets = []
    seen = set()

    def add(value: int) -> None:
        if -span <= value <= span and value not in seen:
            seen.add(value)
            offsets.append(value)

    for value in (0, -20, 20, -16, 16, -12, 12, -10, 10, -8, 8, -6, 6, -4, 4, -2, 2, -1, 1):
        add(value)
    for value in range(3, span + 1):
        add(-value)
        add(value)
    return offsets


def ocr_image_crop_easyocr(
    image,
    box: List[int],
    reader,
    image_module,
    resample_lanczos,
    load_numpy_module,
) -> str:
    if reader is None:
        raise RuntimeError("easyocr reader is required for structured OCR extraction")
    np_mod = load_numpy_module()
    if np_mod is None:
        raise RuntimeError("numpy is required for structured easyocr extraction")

    left = max(0, int(box[0]))
    top = max(0, int(box[1]))
    right = max(left + 1, int(box[2]))
    bottom = max(top + 1, int(box[3]))
    crop = image.crop((left, top, right, bottom)).convert("L")
    crop = crop.resize((crop.width * 3, crop.height * 4), resample_lanczos)
    bordered = image_module.new("L", (crop.width + 48, crop.height + 32), 255)
    bordered.paste(crop, (24, 16))
    crop_array = np_mod.array(bordered)
    lines = reader.readtext(crop_array, detail=0, paragraph=False)
    return "\n".join(lines)


def decode_sidecar_payload(
    transport,
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
    if bit_count > rows * cols:
        return ""

    source_w = max(1, int(page_layout.get("page_width", image.width)))
    source_h = max(1, int(page_layout.get("page_height", image.height)))
    scale_x = float(image.width) / float(source_w)
    scale_y = float(image.height) / float(source_h)

    left = float(box[0]) * scale_x
    top = float(box[1]) * scale_y
    cell_w = max(
        1.0,
        float(line_meta.get("binary_cell", protocol.SIDECAR_CELL_SIZE)) * scale_x,
    )
    cell_h = max(
        1.0,
        float(line_meta.get("binary_cell", protocol.SIDECAR_CELL_SIZE)) * scale_y,
    )
    gap_x = max(
        0.0,
        float(line_meta.get("binary_gap", protocol.SIDECAR_CELL_GAP)) * scale_x,
    )
    gap_y = max(
        0.0,
        float(line_meta.get("binary_gap", protocol.SIDECAR_CELL_GAP)) * scale_y,
    )

    gray = image.convert("L")
    expected_crc = str(line_meta.get("expected_crc", "")).strip().upper()
    payload_alphabet_profile = str(
        line_meta.get("payload_alphabet_profile") or "safe-base32-v1"
    )
    try:
        chunk_idx = int(line_meta.get("chunk_index", -1))
    except Exception:
        chunk_idx = -1

    sidecar_width = cols * cell_w + (cols - 1) * gap_x
    sidecar_height = rows * cell_h + (rows - 1) * gap_y
    max_offset_x = max(2, min(32, int(round(max(1.0, cell_w + gap_x) * 4.0))))
    max_offset_y = max(2, min(14, int(round(max(1.0, cell_h + gap_y) * 1.75))))
    thresholds = (128, 144, 160, 176)
    scale_factors = (1.0, 0.985, 1.015, 0.97, 1.03)
    best_payload = ""
    best_score = None

    for scale_factor in scale_factors:
        scaled_cell_w = max(1.0, cell_w * scale_factor)
        scaled_cell_h = max(1.0, cell_h * scale_factor)
        scaled_gap_x = max(0.0, gap_x * scale_factor)
        scaled_gap_y = max(0.0, gap_y * scale_factor)
        scaled_width = cols * scaled_cell_w + (cols - 1) * scaled_gap_x
        scaled_height = rows * scaled_cell_h + (rows - 1) * scaled_gap_y
        base_left = left - ((scaled_width - sidecar_width) / 2.0)
        base_top = top - ((scaled_height - sidecar_height) / 2.0)

        if (
            base_left + scaled_width < 0
            or base_top + scaled_height < 0
            or base_left >= gray.width
            or base_top >= gray.height
        ):
            continue

        for offset_x in _sidecar_search_offsets(max_offset_x):
            for offset_y in _sidecar_search_offsets(max_offset_y):
                sample_left = base_left + offset_x
                sample_top = base_top + offset_y
                for threshold in thresholds:
                    payload, score = _sidecar_candidate_payload(
                        gray=gray,
                        left=sample_left,
                        top=sample_top,
                        cell_w=scaled_cell_w,
                        cell_h=scaled_cell_h,
                        gap_x=scaled_gap_x,
                        gap_y=scaled_gap_y,
                        cols=cols,
                        bit_count=bit_count,
                        payload_len=payload_len,
                        threshold=threshold,
                        payload_alphabet_profile=payload_alphabet_profile,
                    )
                    if not payload:
                        continue
                    if chunk_idx >= 0 and _sidecar_crc_matches(chunk_idx, payload, expected_crc):
                        return payload

                    candidate_score = (
                        score[0],
                        score[1],
                        score[2],
                        abs(offset_x) + abs(offset_y),
                        abs(int(round((scale_factor - 1.0) * 1000))),
                    )
                    if best_score is None or candidate_score < best_score:
                        best_score = candidate_score
                        best_payload = payload

    if expected_crc and chunk_idx >= 0:
        return ""
    return best_payload


def ocr_structured_page_sidecar(
    transport,
    image_path: Path,
    page_layout: Dict[str, object],
    image_module,
) -> str:
    raw_lines = page_layout.get("lines", [])
    if not isinstance(raw_lines, list):
        raw_lines = []
    if not raw_lines:
        raise ValueError("structured sidecar page layout is missing lines")

    image = image_module.open(str(image_path)).convert("L")
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
        payload = decode_sidecar_payload(
            transport=transport,
            image=image,
            page_layout=page_layout,
            line_meta=item,
        )
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


def decode_manifest_guided_sidecar_payload(
    transport,
    image,
    band: Dict[str, int],
    payload_len: int,
    payload_alphabet_profile: str = "safe-base32-v1",
) -> str:
    if payload_len <= 0:
        return ""

    bit_count = int(payload_len) * 5
    cols = protocol.SIDECAR_BITS_PER_ROW
    rows = int(math.ceil(float(bit_count) / float(cols)))
    sidecar_width = (
        cols * protocol.SIDECAR_CELL_SIZE + (cols - 1) * protocol.SIDECAR_CELL_GAP
    )
    sidecar_height = (
        rows * protocol.SIDECAR_CELL_SIZE + (rows - 1) * protocol.SIDECAR_CELL_GAP
    )
    left = int(image.width - transport.margin - sidecar_width)
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
            if (
                sample_left + sidecar_width > gray.width
                or sample_top + sidecar_height > gray.height
            ):
                continue

            bits = []
            samples = []
            for bit_index in range(bit_count):
                row = bit_index // cols
                col = bit_index % cols
                sample_x = sample_left + col * (
                    protocol.SIDECAR_CELL_SIZE + protocol.SIDECAR_CELL_GAP
                ) + (protocol.SIDECAR_CELL_SIZE // 2)
                sample_y = sample_top + row * (
                    protocol.SIDECAR_CELL_SIZE + protocol.SIDECAR_CELL_GAP
                ) + (protocol.SIDECAR_CELL_SIZE // 2)
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

            payload = protocol.bits_to_payload_for_profile(
                "".join(bits),
                payload_len,
                payload_alphabet_profile,
            )
            if not payload:
                continue
            balance_penalty = abs(dark_ratio - 0.5)
            score = (balance_penalty, -contrast, abs(offset_x) + abs(offset_y))
            if best_score is None or score < best_score:
                best_score = score
                best_payload = payload

    return best_payload


def ocr_manifest_guided_page_sidecar(
    transport,
    image_path: Path,
    manifest: Dict[str, object],
    page_no: int,
    page_entries: List[Dict[str, int]],
    image_module,
) -> str:
    if not page_entries:
        raise ValueError("manifest page {} does not contain chunk locations".format(page_no))

    image = image_module.open(str(image_path)).convert("L")
    bands = transport._detect_text_bands(image)
    data_bands = transport._select_manifest_data_bands(bands, len(page_entries))
    if len(data_bands) != len(page_entries):
        raise ValueError(
            "manifest-guided sidecar band mismatch: expected {} got {}".format(
                len(page_entries), len(data_bands)
            )
        )

    lines = []
    for band, entry in zip(data_bands, page_entries):
        chunk_idx = int(entry["chunk_index"])
        payload_len = transport._manifest_chunk_payload_length(manifest, chunk_idx)
        payload = decode_manifest_guided_sidecar_payload(
            transport=transport,
            image=image,
            band=band,
            payload_len=payload_len,
            payload_alphabet_profile=str(
                manifest.get("payload_alphabet_profile") or "safe-base32-v1"
            ),
        )
        if not payload:
            raise ValueError(
                "manifest-guided sidecar failed at page={} line={} chunk={}".format(
                    int(entry["page"]), int(entry["line"]), chunk_idx
                )
            )
        actual_crc = protocol.crc16_hex("C{:05d}|{}".format(chunk_idx, payload))
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


def choose_payload_candidate(
    transport,
    chunk_idx: int,
    expected_len: int,
    expected_crc: str,
    raw_texts: List[str],
    payload_alphabet_profile: str = "safe-base32-v1",
) -> str:
    candidates = []
    seen = set()
    profile = str(payload_alphabet_profile or "safe-base32-v1").strip().lower()
    payload_alphabet = protocol.payload_alphabet_for_profile(profile)

    for raw in raw_texts:
        raw_payloads = [str(raw or "")]
        preserved = protocol.normalize_protocol_signature(
            protocol.normalize_ocr_line_preserve_case(str(raw or ""))
        )
        for pattern in (
            protocol.LINE_PATTERN,
            protocol.LINE_PATTERN_NOCRC,
            protocol.LINE_PATTERN_NOSEP,
            protocol.LINE_PATTERN_NOSEP_NOCRC,
            protocol.CHUNK_PATTERN,
            protocol.CHUNK_PATTERN_NOCRC,
            protocol.CHUNK_PATTERN_FALLBACK,
            protocol.CHUNK_PATTERN_FALLBACK_NOCRC,
            protocol.PAYLOAD_WITH_CRC_PATTERN,
            protocol.PAYLOAD_WITH_CRC_FALLBACK_PATTERN,
        ):
            match = pattern.match(preserved)
            if not match:
                continue
            for group in reversed(match.groups()):
                if isinstance(group, str) and any(ch.isalpha() or ch.isdigit() for ch in group):
                    raw_payloads.append(group)
                    break

        if profile == protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
            variants = []
            for raw_payload in raw_payloads:
                candidate_info = protocol.ocr_safe_payload_candidates(raw_payload)
                if candidate_info.get("unexpected_chars") or candidate_info.get(
                    "candidate_limit_exceeded"
                ):
                    continue
                for candidate in candidate_info.get("candidates", []) or []:
                    candidate = str(candidate)
                    if expected_len > 0 and len(candidate) > expected_len:
                        for start in range(0, len(candidate) - expected_len + 1):
                            variants.append(candidate[start : start + expected_len])
                    else:
                        variants.append(candidate)
        else:
            normalized = protocol.normalize_payload(protocol.normalize_ocr_line(raw))
            safe = "".join(ch for ch in normalized if ch in payload_alphabet)
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
        repaired = repair_payload_candidate_by_crc(
            payload=candidate,
            core_prefix=core_prefix,
            expected_crc=expected_crc,
        )
        if protocol.crc16_hex(core_prefix + repaired) == expected_crc:
            return repaired

    return ""


def repair_payload_candidate_by_crc(
    payload: str,
    core_prefix: str,
    expected_crc: str,
) -> str:
    if not payload:
        return payload
    if protocol.crc16_hex(core_prefix + payload) == expected_crc:
        return payload

    positions = []
    replacements = []
    for index, ch in enumerate(payload):
        alt_text = protocol.PAYLOAD_OCR_AMBIGUITIES.get(ch, "")
        alt_chars = [
            c
            for c in alt_text
            if c in protocol.SAFE_BASE32_ALPHABET and c != ch
        ]
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
                if protocol.crc16_hex(core_prefix + candidate) == expected_crc:
                    return candidate

    return payload


def ocr_structured_page_tesseract(
    transport,
    image_path: Path,
    lang: str,
    page_layout: Dict[str, object],
    image_module,
) -> str:
    raw_lines = page_layout.get("lines", [])
    if not isinstance(raw_lines, list):
        raw_lines = []
    if not raw_lines:
        raise ValueError("structured OCR page layout is missing lines")

    image = image_module.open(str(image_path)).convert("L")
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
        payload_alphabet_profile = str(
            item.get("payload_alphabet_profile") or "safe-base32-v1"
        )
        payload_whitelist = protocol.payload_alphabet_for_profile(payload_alphabet_profile)
        payload_box = item.get("payload_box")
        line_box = item.get("line_box")
        payload = decode_sidecar_payload(
            transport=transport,
            image=image,
            page_layout=page_layout,
            line_meta=item,
        )
        if (not payload) and isinstance(payload_box, list) and len(payload_box) == 4:
            payload_raw = transport._ocr_image_crop_tesseract(
                image=image,
                box=payload_box,
                lang=lang,
                whitelist=payload_whitelist,
                psm=7,
            )
            payload = choose_payload_candidate(
                transport=transport,
                chunk_idx=chunk_idx,
                expected_len=payload_len,
                expected_crc=expected_crc,
                raw_texts=[payload_raw],
                payload_alphabet_profile=payload_alphabet_profile,
            )
        if not payload and isinstance(line_box, list) and len(line_box) == 4:
            line_raw = transport._ocr_image_crop_tesseract(
                image=image,
                box=line_box,
                lang=lang,
                whitelist=payload_whitelist,
                psm=7,
            )
            payload = choose_payload_candidate(
                transport=transport,
                chunk_idx=chunk_idx,
                expected_len=payload_len,
                expected_crc=expected_crc,
                raw_texts=[line_raw],
                payload_alphabet_profile=payload_alphabet_profile,
            )
        if not payload and isinstance(payload_box, list) and len(payload_box) == 4:
            payload_raw_wide = transport._ocr_image_crop_tesseract(
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
            payload = choose_payload_candidate(
                transport=transport,
                chunk_idx=chunk_idx,
                expected_len=payload_len,
                expected_crc=expected_crc,
                raw_texts=[payload_raw_wide],
                payload_alphabet_profile=payload_alphabet_profile,
            )

        data_lines.append(
            "P{:03d}L{:03d}|C{:05d}|{}|{}".format(
                page_no, line_no, chunk_idx, payload, expected_crc
            )
        )

    if not data_lines:
        raise ValueError("structured OCR page layout does not contain data lines")
    return "\n".join(data_lines)


def ocr_structured_page_easyocr(
    transport,
    image_path: Path,
    page_layout: Dict[str, object],
    reader,
    image_module,
    resample_lanczos,
    load_numpy_module,
) -> str:
    raw_lines = page_layout.get("lines", [])
    if not isinstance(raw_lines, list):
        raw_lines = []
    if not raw_lines:
        raise ValueError("structured OCR page layout is missing lines")

    image = image_module.open(str(image_path)).convert("L")
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
        payload_alphabet_profile = str(
            item.get("payload_alphabet_profile") or "safe-base32-v1"
        )
        payload_box = item.get("payload_box")
        line_box = item.get("line_box")
        payload = decode_sidecar_payload(
            transport=transport,
            image=image,
            page_layout=page_layout,
            line_meta=item,
        )
        if (not payload) and isinstance(payload_box, list) and len(payload_box) == 4:
            payload_raw = ocr_image_crop_easyocr(
                image=image,
                box=payload_box,
                reader=reader,
                image_module=image_module,
                resample_lanczos=resample_lanczos,
                load_numpy_module=load_numpy_module,
            )
            payload = choose_payload_candidate(
                transport=transport,
                chunk_idx=chunk_idx,
                expected_len=payload_len,
                expected_crc=expected_crc,
                raw_texts=[payload_raw],
                payload_alphabet_profile=payload_alphabet_profile,
            )
        if not payload and isinstance(line_box, list) and len(line_box) == 4:
            line_raw = ocr_image_crop_easyocr(
                image=image,
                box=line_box,
                reader=reader,
                image_module=image_module,
                resample_lanczos=resample_lanczos,
                load_numpy_module=load_numpy_module,
            )
            payload = choose_payload_candidate(
                transport=transport,
                chunk_idx=chunk_idx,
                expected_len=payload_len,
                expected_crc=expected_crc,
                raw_texts=[line_raw],
                payload_alphabet_profile=payload_alphabet_profile,
            )
        if not payload and isinstance(payload_box, list) and len(payload_box) == 4:
            payload_raw_wide = ocr_image_crop_easyocr(
                image=image,
                box=[
                    int(payload_box[0]),
                    max(0, int(payload_box[1]) - 2),
                    int(payload_box[2]) + 20,
                    int(payload_box[3]),
                ],
                reader=reader,
                image_module=image_module,
                resample_lanczos=resample_lanczos,
                load_numpy_module=load_numpy_module,
            )
            payload = choose_payload_candidate(
                transport=transport,
                chunk_idx=chunk_idx,
                expected_len=payload_len,
                expected_crc=expected_crc,
                raw_texts=[payload_raw_wide],
                payload_alphabet_profile=payload_alphabet_profile,
            )

        data_lines.append(
            "P{:03d}L{:03d}|C{:05d}|{}|{}".format(
                page_no, line_no, chunk_idx, payload, expected_crc
            )
        )

    if not data_lines:
        raise ValueError("structured OCR page layout does not contain data lines")
    return "\n".join(data_lines)


def parse_external_ocr_stdout(raw_output: str) -> str:
    text = str(raw_output or "").strip()
    if not text:
        return ""

    parsed = None
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None

    if isinstance(parsed, (dict, list)):
        observations = ocr_observations.observations_from_payload(
            parsed,
            default_provider="external",
        )
        if observations:
            return ocr_observations.observations_to_text(observations)

    if isinstance(parsed, dict):
        direct = parsed.get("text")
        if isinstance(direct, str) and direct.strip():
            return direct
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


def run_external_ocr_provider(
    transport,
    image_path: Path,
    page_no: int,
    lang: str,
    psm: int,
    manifest_path: Optional[str],
    provider_cmd: str,
    timeout_sec: int,
    subprocess_module=subprocess,
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
        raise ValueError("unknown placeholder in --ocr-provider-cmd: {}".format(exc))

    completed = subprocess_module.run(
        command,
        shell=True,
        stdout=subprocess_module.PIPE,
        stderr=subprocess_module.PIPE,
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

    parsed_text = parse_external_ocr_stdout(stdout)
    if not str(parsed_text).strip():
        raise RuntimeError(
            "external OCR command returned empty text for image {}".format(image_path)
        )
    return str(parsed_text)


def ocr_single_image(
    transport,
    image_path: Path,
    backend: str,
    lang: str,
    psm: int,
    reader=None,
    page_layout: Optional[Dict[str, object]] = None,
    pil_available: bool = False,
    image_module=None,
    resample_lanczos=None,
    build_easyocr_reader=None,
    load_numpy_module=None,
) -> str:
    if backend == "sidecar":
        if not page_layout:
            raise ValueError("sidecar backend requires manifest render_layout metadata")
        return ocr_structured_page_sidecar(
            transport=transport,
            image_path=image_path,
            page_layout=page_layout,
            image_module=image_module,
        )

    if backend == "tesseract":
        if not pil_available:
            raise RuntimeError("Pillow is required for tesseract preprocessing")
        if page_layout:
            return ocr_structured_page_tesseract(
                transport=transport,
                image_path=image_path,
                lang=lang,
                page_layout=page_layout,
                image_module=image_module,
            )
        image = image_module.open(str(image_path)).convert("L")
        # Improve OCR robustness for camera/screenshot noise.
        image = image.resize((image.width * 2, image.height * 2), resample_lanczos)
        image = image_module.eval(image, lambda p: 255 if p > 170 else 0)
        return transport._ocr_transport_page_tesseract_best_effort(
            image=image,
            lang=lang,
            psm=psm,
        )

    if backend == "easyocr":
        if reader is None:
            if build_easyocr_reader is None:
                raise RuntimeError("easyocr reader factory is unavailable")
            reader, _reader_langs = build_easyocr_reader(lang)
        if page_layout:
            return ocr_structured_page_easyocr(
                transport=transport,
                image_path=image_path,
                page_layout=page_layout,
                reader=reader,
                image_module=image_module,
                resample_lanczos=resample_lanczos,
                load_numpy_module=load_numpy_module,
            )
        lines = reader.readtext(str(image_path), detail=0, paragraph=False)
        return "\n".join(lines)

    raise ValueError("unsupported backend: {}".format(backend))


__all__ = [
    "ocr_image_crop_easyocr",
    "decode_sidecar_payload",
    "ocr_structured_page_sidecar",
    "decode_manifest_guided_sidecar_payload",
    "ocr_manifest_guided_page_sidecar",
    "choose_payload_candidate",
    "repair_payload_candidate_by_crc",
    "ocr_structured_page_tesseract",
    "ocr_structured_page_easyocr",
    "parse_external_ocr_stdout",
    "run_external_ocr_provider",
    "ocr_single_image",
]
