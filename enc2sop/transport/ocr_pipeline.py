"""Transport OCR/image pipeline helpers extracted from qrcode_helper."""

import itertools
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import protocol


def detect_text_bands(image) -> List[Dict[str, int]]:
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


def select_manifest_data_bands(
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


def crop_primary_text_band(image, band: Dict[str, int]):
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


def ocr_payload_crop_tesseract(
    transport,
    image,
    lang: str,
    image_module,
    resample_lanczos,
) -> str:
    crop = image.convert("L")
    crop = crop.resize((crop.width * 3, crop.height * 4), resample_lanczos)
    crop = image_module.eval(crop, lambda p: 255 if p > 180 else 0)
    config = (
        "--oem 3 --psm 7 "
        "-c preserve_interword_spaces=0 "
        "-c tessedit_char_whitelist={}"
    ).format(protocol.SAFE_BASE32_ALPHABET)
    return transport._tesseract_image_to_string(image=crop, lang=lang, config=config)


def ocr_crc_crop_tesseract(
    transport,
    image,
    lang: str,
    image_module,
    resample_lanczos,
) -> str:
    crop = image.convert("L")
    crop = crop.resize((crop.width * 4, crop.height * 5), resample_lanczos)
    crop = image_module.eval(crop, lambda p: 255 if p > 185 else 0)
    config = (
        "--oem 3 --psm 7 "
        "-c preserve_interword_spaces=0 "
        "-c tessedit_char_whitelist=0123456789ABCDEF"
    )
    return transport._tesseract_image_to_string(image=crop, lang=lang, config=config)


def ocr_tesseract_variants(
    transport,
    image,
    lang: str,
    whitelist: str,
    variants: List[Tuple[int, int, Optional[int]]],
    image_module,
    resample_lanczos,
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
            resample_lanczos,
        )
        if threshold is not None:
            crop = image_module.eval(crop, lambda p, t=threshold: 255 if p > t else 0)
        text = transport._tesseract_image_to_string(image=crop, lang=lang, config=config)
        normalized = protocol.normalize_ocr_line(text)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        outputs.append(text)
    return outputs


def ocr_payload_crop_tesseract_variants(
    transport,
    image,
    lang: str,
    image_module,
    resample_lanczos,
) -> List[str]:
    return ocr_tesseract_variants(
        transport=transport,
        image=image,
        lang=lang,
        whitelist=protocol.SAFE_BASE32_ALPHABET,
        variants=[
            (3, 4, 180),
            (4, 5, 170),
            (3, 4, None),
        ],
        image_module=image_module,
        resample_lanczos=resample_lanczos,
    )


def ocr_crc_crop_tesseract_variants(
    transport,
    image,
    lang: str,
    image_module,
    resample_lanczos,
) -> List[str]:
    return ocr_tesseract_variants(
        transport=transport,
        image=image,
        lang=lang,
        whitelist="0123456789ABCDEF",
        variants=[
            (4, 5, 185),
            (4, 5, None),
            (3, 4, 170),
        ],
        image_module=image_module,
        resample_lanczos=resample_lanczos,
    )


def ocr_generic_line_tesseract_variants(
    transport,
    image,
    lang: str,
    whitelist: str,
    image_module,
    resample_lanczos,
) -> List[str]:
    return ocr_tesseract_variants(
        transport=transport,
        image=image,
        lang=lang,
        whitelist=whitelist,
        variants=[
            (3, 4, 180),
            (4, 5, 170),
            (3, 4, None),
        ],
        image_module=image_module,
        resample_lanczos=resample_lanczos,
    )


def ocr_band_tesseract_variants(
    transport,
    image,
    band: Dict[str, int],
    lang: str,
    whitelist: str,
    image_module,
    resample_lanczos,
) -> List[str]:
    text_band = crop_primary_text_band(image=image, band=band)
    return ocr_generic_line_tesseract_variants(
        transport=transport,
        image=text_band,
        lang=lang,
        whitelist=whitelist,
        image_module=image_module,
        resample_lanczos=resample_lanczos,
    )


def parse_meta_line_candidate(raw_texts: List[str]) -> Optional[Dict[str, int]]:
    for raw in raw_texts:
        line = protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))
        match = protocol.META_PATTERN.match(line)
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


def parse_cfg_line_candidate(raw_texts: List[str]) -> Optional[Dict[str, object]]:
    for raw in raw_texts:
        line = protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))
        cfg = protocol.parse_cfg_line(line)
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


def parse_hash_fragment_candidate(
    raw_texts: List[str],
    expected_kind: str,
    expected_part: int,
) -> Optional[str]:
    for raw in raw_texts:
        line = protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))
        parsed = protocol.parse_hash_fragment_line(line)
        if not parsed:
            continue
        kind, part_no, fragment = parsed
        if kind == expected_kind and int(part_no) == int(expected_part):
            return "@{}{}|{}".format(expected_kind, int(expected_part), fragment)
    return None


def parse_hash_compact_candidate(
    raw_texts: List[str],
    expected_part: int,
) -> Optional[Dict[str, str]]:
    for raw in raw_texts:
        line = protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))
        parsed = protocol.parse_hash_compact_line(line)
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


def crc_windows_from_hints(crc_hints: List[str]) -> List[str]:
    windows = []
    seen = set()
    for raw_hint in crc_hints:
        normalized = protocol.normalize_hex_token(raw_hint)
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


def score_candidate_crc_against_hints(
    candidate_crc: str,
    crc_hints: List[str],
) -> Tuple[int, int, int, int]:
    windows = crc_windows_from_hints(crc_hints)
    if not windows:
        return (0, 0, 0, 0)

    diffs = sorted(
        (
            protocol.levenshtein_distance(candidate_crc, window),
            sum(1 for left, right in zip(candidate_crc, window) if left != right),
        )
        for window in windows
    )
    exact_count = sum(1 for item in diffs if item == (0, 0))
    near_count = sum(1 for item in diffs if item[0] <= 1)
    top = diffs[: min(4, len(diffs))]
    return (-exact_count, -near_count, sum(item[0] for item in top), sum(item[1] for item in top))


def repair_payload_candidate_by_crc_hint(
    payload: str,
    core_prefix: str,
    crc_hint: str,
    max_attempts: int = 12000,
) -> Tuple[str, str, Tuple[int, int]]:
    actual_crc = protocol.crc16_hex(core_prefix + payload)
    normalized_crc = protocol.normalize_hex_token(crc_hint)
    if not normalized_crc or any(ch not in "0123456789ABCDEF" for ch in normalized_crc):
        return payload, actual_crc, (0, 0)

    hint_windows = []
    if len(normalized_crc) >= 4:
        for index in range(0, len(normalized_crc) - 3):
            hint_windows.append(normalized_crc[index : index + 4])
    else:
        hint_windows.append(normalized_crc)

    def _crc_score(candidate_crc: str) -> Tuple[int, int]:
        edit_distance = protocol.levenshtein_distance(candidate_crc, normalized_crc)
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
        alt_text = protocol.PAYLOAD_OCR_AMBIGUITIES.get(ch, "")
        alt_chars = [c for c in alt_text if c in protocol.SAFE_BASE32_ALPHABET and c != ch]
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
                candidate_crc = protocol.crc16_hex(core_prefix + candidate)
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
            for repl in protocol.SAFE_BASE32_ALPHABET:
                if repl == original:
                    continue
                candidate = payload[:index] + repl + payload[index + 1 :]
                candidate_crc = protocol.crc16_hex(core_prefix + candidate)
                diff = _crc_score(candidate_crc)
                if diff < best_diff:
                    best_payload = candidate
                    best_crc = candidate_crc
                    best_diff = diff
                    if diff == (0, 0):
                        return best_payload, best_crc, best_diff

    return best_payload, best_crc, best_diff


def choose_payload_candidate_with_crc_hint(
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
        line = protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))
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
            normalized = protocol.normalize_payload(part)
            safe = "".join(ch for ch in normalized if ch in protocol.SAFE_BASE32_ALPHABET)
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
    windows = crc_windows_from_hints(all_crc_hints)
    for candidate in candidates:
        if windows:
            for one_hint in windows:
                repaired, actual_crc, diff = repair_payload_candidate_by_crc_hint(
                    payload=candidate,
                    core_prefix=core_prefix,
                    crc_hint=one_hint,
                )
                ranked.append(
                    (
                        score_candidate_crc_against_hints(actual_crc, all_crc_hints),
                        diff,
                        repaired,
                        actual_crc,
                    )
                )
        else:
            actual_crc = protocol.crc16_hex(core_prefix + candidate)
            ranked.append(((0, 0, 0, 0), (0, 0), candidate, actual_crc))
    ranked.sort(key=lambda item: (item[0], item[1], item[2]))
    return ranked[0][2]


def ocr_manifest_guided_page_tesseract(
    transport,
    image_path: Path,
    manifest: Dict[str, object],
    page_no: int,
    page_entries: List[Dict[str, int]],
    lang: str,
    image_module,
) -> str:
    image = image_module.open(str(image_path)).convert("L")
    bands = transport._detect_text_bands(image)
    data_bands = transport._select_manifest_data_bands(bands, len(page_entries))
    if len(data_bands) != len(page_entries):
        raise ValueError(
            "manifest-guided OCR band mismatch: expected {} got {}".format(
                len(page_entries), len(data_bands)
            )
        )

    lines = []
    for band, entry in zip(data_bands, page_entries):
        chunk_idx = int(entry["chunk_index"])
        payload_len = transport._manifest_chunk_payload_length(manifest, chunk_idx)
        if payload_len <= 0:
            raise ValueError("missing chunk length for chunk {}".format(chunk_idx))

        text_band = transport._crop_primary_text_band(image=image, band=band)
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

        payload_raws = transport._ocr_payload_crop_tesseract_variants(payload_crop, lang=lang)
        line_raws = transport._ocr_payload_crop_tesseract_variants(text_band, lang=lang)
        crc_hints = transport._ocr_crc_crop_tesseract_variants(crc_crop, lang=lang)
        payload = transport._choose_payload_candidate_with_crc_hint(
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


def ocr_image_crop_tesseract(
    transport,
    image,
    box: List[int],
    lang: str,
    whitelist: str,
    image_module,
    resample_lanczos,
    psm: int = 7,
) -> str:
    left = max(0, int(box[0]))
    top = max(0, int(box[1]))
    right = max(left + 1, int(box[2]))
    bottom = max(top + 1, int(box[3]))
    crop = image.crop((left, top, right, bottom)).convert("L")
    scale_x = 3
    scale_y = 4
    crop = crop.resize((crop.width * scale_x, crop.height * scale_y), resample_lanczos)
    bordered = image_module.new("L", (crop.width + 48, crop.height + 32), 255)
    bordered.paste(crop, (24, 16))
    crop = image_module.eval(bordered, lambda p: 255 if p > 180 else 0)
    config = (
        "--oem 3 --psm {} "
        "-c preserve_interword_spaces=0 "
        "-c tessedit_char_whitelist={}"
    ).format(int(psm), whitelist)
    return transport._tesseract_image_to_string(
        image=crop,
        lang=lang,
        config=config,
    )


__all__ = [
    "detect_text_bands",
    "select_manifest_data_bands",
    "crop_primary_text_band",
    "ocr_payload_crop_tesseract",
    "ocr_crc_crop_tesseract",
    "ocr_tesseract_variants",
    "ocr_payload_crop_tesseract_variants",
    "ocr_crc_crop_tesseract_variants",
    "ocr_generic_line_tesseract_variants",
    "ocr_band_tesseract_variants",
    "parse_meta_line_candidate",
    "parse_cfg_line_candidate",
    "parse_hash_fragment_candidate",
    "parse_hash_compact_candidate",
    "crc_windows_from_hints",
    "score_candidate_crc_against_hints",
    "repair_payload_candidate_by_crc_hint",
    "choose_payload_candidate_with_crc_hint",
    "ocr_manifest_guided_page_tesseract",
    "ocr_image_crop_tesseract",
]
