"""Embedded-metadata OCR helpers extracted from qrcode_helper."""

import math
from pathlib import Path
from typing import Callable, Dict, List, Tuple

from . import protocol


def build_inferred_manifest_from_metadata(
    metadata: Dict[str, object],
    rebuild_parity_manifest: Callable[..., Dict[str, object]],
) -> Dict[str, object]:
    manifest: Dict[str, object] = {
        "protocol_version": protocol.PROTOCOL_VERSION,
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
    payload_alphabet_profile = protocol.canonical_payload_profile(metadata.get("PF"))
    encoded_len = int(
        metadata.get("EL")
        or protocol.encoded_payload_length_for_profile(compressed_size, payload_alphabet_profile)
    )
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
    parity_symbol_mode = protocol.canonical_parity_symbol_mode(
        metadata.get("PM"),
        payload_alphabet_profile,
    )
    manifest.update(
        {
            "compressed_sha256": (str(metadata["CH1"]) + str(metadata["CH2"])).lower(),
            "raw_sha256": (str(metadata["RH1"]) + str(metadata["RH2"])).lower(),
            "raw_size": int(metadata["RS"]),
            "compressed_size": compressed_size,
            "encoded_payload_len": encoded_len,
            "chunk_chars": chunk_chars,
            "chunk_lengths": chunk_lengths,
            "redundancy_copies": int(metadata["RC"]),
            "interleave_enabled": bool(int(metadata["IL"])),
            "payload_alphabet_profile": payload_alphabet_profile,
            "alphabet": protocol.payload_alphabet_for_profile(payload_alphabet_profile),
            "parity": rebuild_parity_manifest(
                total_chunks=total_chunks,
                chunk_lengths=chunk_lengths,
                parity_group_size=parity_group_size,
                payload_alphabet_profile=payload_alphabet_profile,
                parity_symbol_mode=parity_symbol_mode,
            ),
        }
    )
    return manifest


def build_expected_page_entries(
    manifest: Dict[str, object],
    page_no: int,
    page_chunks: int,
    build_chunk_entries: Callable[..., List[Tuple[int, str, int]]],
    lines_per_page_default: int,
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

    chunk_entries = build_chunk_entries(
        base_entries=base_entries,
        redundancy_copies=int(manifest.get("redundancy_copies", 1)),
        interleave=bool(manifest.get("interleave_enabled", True)),
    )
    lines_per_page = int(manifest.get("lines_per_page", lines_per_page_default))
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


def ocr_embedded_metadata_page_tesseract(
    transport,
    image_path: Path,
    page_no_hint: int,
    lang: str,
    prefer_sidecar: bool,
    image_module,
    pil_available: bool,
) -> str:
    if not pil_available:
        raise RuntimeError("Pillow is required for embedded metadata extraction")

    image = image_module.open(str(image_path)).convert("L")
    bands = transport._detect_text_bands(image)
    if len(bands) < 5:
        raise ValueError("detected text bands {} is less than minimum embedded layout 5".format(len(bands)))

    meta_whitelist = "@META|AT1IDPAGECHUNKSOTALCFGPRHSCSELPFMX0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_=-/"
    hash_whitelist = "@RHCH|0123456789ABCDEF"
    compact_hash_whitelist = "@HSRC|0123456789ABCDEF="
    pagecrc_whitelist = "@PAGECR|P0123456789ABCDEF"

    meta_line = transport._parse_meta_line_candidate(
        transport._ocr_band_tesseract_variants(
            image=image,
            band=bands[0],
            lang=lang,
            whitelist=meta_whitelist,
        )
    )
    if not meta_line:
        raise ValueError("failed to parse embedded @META line from image {}".format(image_path))

    cfg_line = transport._parse_cfg_line_candidate(
        transport._ocr_band_tesseract_variants(
            image=image,
            band=bands[1],
            lang=lang,
            whitelist=meta_whitelist,
        )
    )
    if not cfg_line:
        raise ValueError("failed to parse embedded @CFG line from image {}".format(image_path))

    hash_lines: List[str] = []
    hash_values: Dict[str, str] = {}
    data_start_idx = 0

    compact_1 = transport._parse_hash_compact_candidate(
        transport._ocr_band_tesseract_variants(
            image=image,
            band=bands[2],
            lang=lang,
            whitelist=compact_hash_whitelist,
        ),
        expected_part=1,
    )
    compact_2 = None
    if len(bands) > 3:
        compact_2 = transport._parse_hash_compact_candidate(
            transport._ocr_band_tesseract_variants(
                image=image,
                band=bands[3],
                lang=lang,
                whitelist=compact_hash_whitelist,
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
            raise ValueError("detected text bands {} is less than legacy embedded layout 6".format(len(bands)))
        rh1 = transport._parse_hash_fragment_candidate(
            transport._ocr_band_tesseract_variants(
                image=image,
                band=bands[2],
                lang=lang,
                whitelist=hash_whitelist,
            ),
            expected_kind="RH",
            expected_part=1,
        )
        rh2 = transport._parse_hash_fragment_candidate(
            transport._ocr_band_tesseract_variants(
                image=image,
                band=bands[3],
                lang=lang,
                whitelist=hash_whitelist,
            ),
            expected_kind="RH",
            expected_part=2,
        )
        ch1 = transport._parse_hash_fragment_candidate(
            transport._ocr_band_tesseract_variants(
                image=image,
                band=bands[4],
                lang=lang,
                whitelist=hash_whitelist,
            ),
            expected_kind="CH",
            expected_part=1,
        )
        ch2 = transport._parse_hash_fragment_candidate(
            transport._ocr_band_tesseract_variants(
                image=image,
                band=bands[5],
                lang=lang,
                whitelist=hash_whitelist,
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
            transport._ocr_band_tesseract_variants(
                image=image,
                band=bands[footer_band_index],
                lang=lang,
                whitelist=pagecrc_whitelist,
            )
        )
    if bands:
        footer_candidates_raw.extend(
            transport._ocr_band_tesseract_variants(
                image=image,
                band=bands[-1],
                lang=lang,
                whitelist=pagecrc_whitelist,
            )
        )

    footer_line = None
    for raw in footer_candidates_raw:
        line = protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))
        match = protocol.PAGECRC_PATTERN.match(line)
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
    for key in ("PF", "PM", "EL"):
        if key in cfg_line["values"]:
            metadata[key] = cfg_line["values"][key]
    manifest = build_inferred_manifest_from_metadata(
        metadata=metadata,
        rebuild_parity_manifest=transport._rebuild_parity_manifest,
    )
    page_no = int(meta_line["page_no"]) if int(meta_line["page_no"]) > 0 else int(page_no_hint)
    expected_entries = build_expected_page_entries(
        manifest=manifest,
        page_no=page_no,
        page_chunks=page_chunks,
        build_chunk_entries=transport._build_chunk_entries,
        lines_per_page_default=int(getattr(transport, "lines_per_page", 20)),
    )

    lines = [
        meta_line["canonical"],
        cfg_line["canonical"],
    ]
    lines.extend(hash_lines)
    for band, entry in zip(data_bands, expected_entries):
        chunk_idx = int(entry["chunk_index"])
        payload_len = transport._manifest_chunk_payload_length(manifest, chunk_idx)
        payload = ""
        if prefer_sidecar:
            payload = transport._decode_manifest_guided_sidecar_payload(
                image=image,
                band=band,
                payload_len=payload_len,
            )
        if not payload:
            text_band = transport._crop_primary_text_band(image=image, band=band)
            total_chars = 16 + payload_len + 1 + 4
            char_width = float(text_band.width) / float(max(1, total_chars))
            pad = max(2, int(round(char_width * 0.25)))

            payload_left = max(0, int(round(16 * char_width)) - pad)
            payload_right = min(text_band.width, int(round((16 + payload_len) * char_width)) + pad)
            crc_left = max(0, int(round((16 + payload_len + 1) * char_width)) - pad)
            crc_right = min(text_band.width, int(round((16 + payload_len + 5) * char_width)) + pad)

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
                "embedded metadata OCR failed at page={} line={} chunk={}".format(
                    int(entry["page"]),
                    int(entry["line"]),
                    chunk_idx,
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

    if footer_line is None:
        footer_crc = protocol.crc16_hex("\n".join(lines))
        footer_line = "@PAGECRC|P{:03d}|{}".format(page_no, footer_crc)
    lines.append(footer_line)
    return "\n".join(lines)


__all__ = [
    "build_inferred_manifest_from_metadata",
    "build_expected_page_entries",
    "ocr_embedded_metadata_page_tesseract",
]
