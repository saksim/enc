"""Transport OCR runtime/orchestration helpers extracted from qrcode_helper."""

import itertools
import json
import math
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from . import protocol


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

    source_w = max(1, int(page_layout.get("page_width", image.width)))
    source_h = max(1, int(page_layout.get("page_height", image.height)))
    scale_x = float(image.width) / float(source_w)
    scale_y = float(image.height) / float(source_h)

    left = int(round(float(box[0]) * scale_x))
    top = int(round(float(box[1]) * scale_y))
    cell_w = max(
        1,
        int(
            round(
                float(line_meta.get("binary_cell", protocol.SIDECAR_CELL_SIZE))
                * scale_x
            )
        ),
    )
    cell_h = max(
        1,
        int(
            round(
                float(line_meta.get("binary_cell", protocol.SIDECAR_CELL_SIZE))
                * scale_y
            )
        ),
    )
    gap_x = max(
        0,
        int(
            round(
                float(line_meta.get("binary_gap", protocol.SIDECAR_CELL_GAP))
                * scale_x
            )
        ),
    )
    gap_y = max(
        0,
        int(
            round(
                float(line_meta.get("binary_gap", protocol.SIDECAR_CELL_GAP))
                * scale_y
            )
        ),
    )

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

    return protocol.bits_to_safe_payload("".join(bits), payload_len)


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

            payload = protocol.bits_to_safe_payload("".join(bits), payload_len)
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
) -> str:
    candidates = []
    seen = set()

    for raw in raw_texts:
        normalized = protocol.normalize_payload(protocol.normalize_ocr_line(raw))
        safe = "".join(ch for ch in normalized if ch in protocol.SAFE_BASE32_ALPHABET)
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
    payload_whitelist = protocol.SAFE_BASE32_ALPHABET
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
