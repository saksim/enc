"""Transport page rendering helpers extracted from qrcode_helper."""

import math
from pathlib import Path
from typing import Dict, List, Optional

from . import protocol


def load_font(size: int, image_font_module):
    """Load a readable monospace-capable font with safe fallbacks."""
    pil_font_candidates = []
    try:
        pil_dir = Path(image_font_module.__file__).resolve().parent
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
            return image_font_module.truetype(name, size=size)
        except Exception:
            continue
    try:
        return image_font_module.load_default(size=int(size))  # Pillow>=10
    except Exception:
        return image_font_module.load_default()


def _parse_render_data_line(text: str, fallback_line_no: int) -> Optional[Dict[str, object]]:
    if not text or text.startswith("@"):
        return None

    match = protocol.LINE_PATTERN.match(text) or protocol.LINE_PATTERN_NOCRC.match(text)
    if match:
        return {
            "mode": "full",
            "page_no": int(match.group(1)),
            "line_no": int(match.group(2)),
            "chunk_idx": int(match.group(4)),
            "payload": str(match.group(5)),
            "expected_crc": str(match.group(6)) if match.re == protocol.LINE_PATTERN else "",
        }

    match_chunk = protocol.CHUNK_PATTERN.match(text) or protocol.CHUNK_PATTERN_NOCRC.match(text)
    if match_chunk:
        return {
            "mode": "chunk",
            "page_no": 0,
            "line_no": int(fallback_line_no),
            "chunk_idx": int(match_chunk.group(1)),
            "payload": str(match_chunk.group(3)),
            "expected_crc": str(match_chunk.group(4)) if match_chunk.re == protocol.CHUNK_PATTERN else "",
        }

    payload_with_crc = protocol.PAYLOAD_WITH_CRC_PATTERN.match(text)
    if payload_with_crc:
        return {
            "mode": "payload",
            "page_no": 0,
            "line_no": int(fallback_line_no),
            "chunk_idx": -1,
            "payload": str(payload_with_crc.group(1)),
            "expected_crc": str(payload_with_crc.group(3)),
        }
    payload_with_crc_fb = protocol.PAYLOAD_WITH_CRC_FALLBACK_PATTERN.match(text)
    if payload_with_crc_fb:
        return {
            "mode": "payload",
            "page_no": 0,
            "line_no": int(fallback_line_no),
            "chunk_idx": -1,
            "payload": str(payload_with_crc_fb.group(1)),
            "expected_crc": protocol.normalize_hex_token(str(payload_with_crc_fb.group(3))),
        }

    if all(ch in protocol.SAFE_BASE32_ALPHABET for ch in text):
        return {
            "mode": "payload",
            "page_no": 0,
            "line_no": int(fallback_line_no),
            "chunk_idx": -1,
            "payload": str(text),
            "expected_crc": "",
        }
    return None


def render_page(
    *,
    lines: List[str],
    output_path: Path,
    page_size,
    margin: int,
    font_size: int,
    line_gap: int,
    font_max_size: int,
    font_fit_mode: str,
    line_separator: str,
    render_sidecar: bool,
    image_module,
    image_draw_module,
    image_font_module,
) -> Dict[str, object]:
    width, height = page_size
    img = image_module.new("RGB", (width, height), "white")
    draw = image_draw_module.Draw(img)

    parsed_render_lines: List[Optional[Dict[str, object]]] = []
    for idx, line in enumerate(lines, 1):
        parsed_render_lines.append(_parse_render_data_line(line, idx))

    data_lines = [line for idx, line in enumerate(lines) if parsed_render_lines[idx] is not None]
    control_lines = [line for idx, line in enumerate(lines) if parsed_render_lines[idx] is None]
    max_data_len = max((len(line) for line in data_lines), default=0)
    max_control_len = max((len(line) for line in control_lines), default=0)

    usable_w = width - (margin * 2)
    usable_h = height - (margin * 2)
    sidecar_reserved_w = 0
    if data_lines and render_sidecar:
        sidecar_reserved_w = (
            protocol.SIDECAR_BITS_PER_ROW * protocol.SIDECAR_CELL_SIZE
            + (protocol.SIDECAR_BITS_PER_ROW - 1) * protocol.SIDECAR_CELL_GAP
            + 24
        )
    data_usable_w = max(120, usable_w - sidecar_reserved_w)

    base_size = max(16, int(font_size))
    if font_fit_mode == "fixed":
        max_candidate_size = base_size
        min_candidate_size = base_size
    elif font_fit_mode == "fit":
        max_candidate_size = max(base_size + 24, min(int(font_max_size), base_size * 3))
        min_candidate_size = 12
    else:
        # target mode: prefer configured size, only shrink on overflow.
        max_candidate_size = base_size
        min_candidate_size = 12

    data_font_size = base_size
    control_font_size = max(12, int(round(base_size * 0.62)))
    data_font = load_font(data_font_size, image_font_module)
    control_font = load_font(control_font_size, image_font_module)
    data_line_h = draw.textbbox((0, 0), "Mg", font=data_font)[3] + line_gap
    control_line_gap = max(2, int(round(line_gap * 0.45)))
    control_line_h = draw.textbbox((0, 0), "Mg", font=control_font)[3] + control_line_gap

    for candidate_size in range(max_candidate_size, min_candidate_size - 1, -2):
        candidate_data_font = load_font(candidate_size, image_font_module)
        candidate_control_size = max(12, int(round(candidate_size * 0.62)))
        candidate_control_font = load_font(candidate_control_size, image_font_module)
        candidate_data_line_h = (
            draw.textbbox((0, 0), "Mg", font=candidate_data_font)[3] + line_gap
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

    x = margin
    y = margin
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
                    page_no, line_no, line_separator, chunk_idx, line_separator
                )
            elif mode == "chunk":
                prefix = "C{:05d}{}".format(chunk_idx, line_separator)
            else:
                prefix = ""
            prefix_bbox = draw.textbbox((x, y), prefix, font=line_font)
            payload_bbox = draw.textbbox((prefix_bbox[2], y), payload, font=line_font)
            sidecar_bits = protocol.safe_payload_to_bits(payload)
            sidecar_rows = int(
                math.ceil(float(len(sidecar_bits)) / float(protocol.SIDECAR_BITS_PER_ROW))
            )
            sidecar_cols = protocol.SIDECAR_BITS_PER_ROW
            sidecar_width = (
                sidecar_cols * protocol.SIDECAR_CELL_SIZE
                + (sidecar_cols - 1) * protocol.SIDECAR_CELL_GAP
            )
            sidecar_height = (
                sidecar_rows * protocol.SIDECAR_CELL_SIZE
                + (sidecar_rows - 1) * protocol.SIDECAR_CELL_GAP
            )
            sidecar_left = int(width - margin - sidecar_width)
            min_sidecar_left = int(text_bbox[2] + 24)
            if sidecar_left < min_sidecar_left:
                sidecar_left = min_sidecar_left
            sidecar_top = int(max(0, y + max(0, (line_h - sidecar_height) // 2)))
            if render_sidecar and sidecar_left + sidecar_width <= width - margin:
                for bit_index, bit in enumerate(sidecar_bits):
                    if bit != "1":
                        continue
                    row = bit_index // sidecar_cols
                    col = bit_index % sidecar_cols
                    cell_left = sidecar_left + col * (
                        protocol.SIDECAR_CELL_SIZE + protocol.SIDECAR_CELL_GAP
                    )
                    cell_top = sidecar_top + row * (
                        protocol.SIDECAR_CELL_SIZE + protocol.SIDECAR_CELL_GAP
                    )
                    draw.rectangle(
                        (
                            cell_left,
                            cell_top,
                            cell_left + protocol.SIDECAR_CELL_SIZE - 1,
                            cell_top + protocol.SIDECAR_CELL_SIZE - 1,
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
                    "binary_cell": protocol.SIDECAR_CELL_SIZE,
                    "binary_cols": sidecar_cols,
                    "binary_gap": protocol.SIDECAR_CELL_GAP,
                    "binary_rows": sidecar_rows,
                    "payload_box": [
                        int(max(0, prefix_bbox[2] + 8)),
                        int(max(0, y - 4)),
                        int(min(width, payload_bbox[2] + 4)),
                        int(min(height, y + line_h + 4)),
                    ],
                }
            )
            if render_sidecar and sidecar_left + sidecar_width <= width - margin:
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


__all__ = ["load_font", "render_page"]
