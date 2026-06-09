#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""QR chunking, rendering, and reassembly for SOX1 cross-media transport."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

from enc2sop.transport import protocol as transport_protocol

from .crypto_envelope import SOX1_PREFIX
from .crypto_envelope import write_text_atomic

QR_MAGIC = "SOX1QR"
QR_SCHEMA = "enc2sop-cross-media-qr/v1"
SCAN_REPORT_SCHEMA = "enc2sop-cross-media-scan-report/v1"
QR_VERSION = "1"
DEFAULT_CHUNK_CHARS = 700
MIN_CHUNK_CHARS = 200
MAX_CHUNK_CHARS = 1200
MAX_QR_CHUNKS = 500
DEFAULT_QRS_PER_PAGE = 1
SUPPORTED_QRS_PER_PAGE = {1, 4, 6, 8}
DEFAULT_REPEAT_COPIES = 1
MAX_REPEAT_COPIES = 4
DEFAULT_QR_MIN_SIZE_PX = 900
MULTI_QR_MIN_SIZE_PX = 640
DEFAULT_QR_BORDER_MODULES = 4
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}


class QrTransportError(ValueError):
    """Base error for QR visual transport."""


class QrPayloadError(QrTransportError):
    """Raised when one QR payload is malformed or fails CRC."""


class QrReassemblyError(QrTransportError):
    """Raised when chunks cannot be safely reassembled."""


@dataclass(frozen=True)
class QrChunk:
    artifact_id: str
    chunk_index: int
    chunk_total: int
    string_sha16: str
    crc16: str
    data: str

    @property
    def page_number(self) -> int:
        return self.chunk_index + 1


@dataclass(frozen=True)
class QrPagePlacement:
    page_number: int
    slot_index: int
    copy_index: int
    chunk: QrChunk

    @property
    def retake_id(self) -> int:
        return self.chunk.chunk_index + 1


def sox1_sha256(sox1: str) -> str:
    return transport_protocol.sha256_hex(str(sox1).encode("ascii"))


def artifact_id_for_sox1(sox1: str) -> str:
    return sox1_sha256(sox1)[:12]


def _validate_chunk_chars(chunk_chars: int) -> int:
    value = int(chunk_chars)
    if value < MIN_CHUNK_CHARS or value > MAX_CHUNK_CHARS:
        raise QrTransportError(
            "chunk_chars must be between {0} and {1}".format(MIN_CHUNK_CHARS, MAX_CHUNK_CHARS)
        )
    return value


def _validate_qrs_per_page(qrs_per_page: int) -> int:
    value = int(qrs_per_page)
    if value not in SUPPORTED_QRS_PER_PAGE:
        raise QrTransportError(
            "qrs_per_page must be one of {0}".format(
                ",".join(str(item) for item in sorted(SUPPORTED_QRS_PER_PAGE))
            )
        )
    return value


def _validate_repeat_copies(repeat_copies: int) -> int:
    value = int(repeat_copies)
    if value < 1 or value > MAX_REPEAT_COPIES:
        raise QrTransportError(
            "repeat_copies must be between 1 and {0}".format(MAX_REPEAT_COPIES)
        )
    return value


def _grid_for_qrs_per_page(qrs_per_page: int) -> Tuple[int, int]:
    value = _validate_qrs_per_page(qrs_per_page)
    if value == 1:
        return 1, 1
    if value == 4:
        return 2, 2
    if value == 6:
        return 3, 2
    return 4, 2


def split_sox1_string(sox1: str, *, chunk_chars: int = DEFAULT_CHUNK_CHARS) -> List[QrChunk]:
    text = str(sox1 or "").strip()
    if not text.startswith(SOX1_PREFIX):
        raise QrTransportError("QR render input must be a SOX1 string")
    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise QrTransportError("SOX1 QR transport input must be ASCII") from exc
    chunk_size = _validate_chunk_chars(chunk_chars)
    total = int(math.ceil(len(text) / float(chunk_size))) if text else 0
    if total <= 0:
        raise QrTransportError("SOX1 string is empty")
    if total > MAX_QR_CHUNKS:
        raise QrTransportError("SOX1 string requires {0} QR chunks; P0 limit is {1}".format(total, MAX_QR_CHUNKS))
    digest = sox1_sha256(text)
    artifact_id = digest[:12]
    sha16 = digest[:16]
    chunks = []
    for index in range(total):
        data = text[index * chunk_size : (index + 1) * chunk_size]
        chunks.append(
            QrChunk(
                artifact_id=artifact_id,
                chunk_index=index,
                chunk_total=total,
                string_sha16=sha16,
                crc16=transport_protocol.crc16_hex(data),
                data=data,
            )
        )
    return chunks


def encode_qr_payload(chunk: QrChunk) -> str:
    return (
        "{magic}|v={version}|id={artifact_id}|i={index}|n={total}|sha={sha}|crc={crc}|data={data}".format(
            magic=QR_MAGIC,
            version=QR_VERSION,
            artifact_id=chunk.artifact_id,
            index=chunk.chunk_index,
            total=chunk.chunk_total,
            sha=chunk.string_sha16,
            crc=chunk.crc16,
            data=chunk.data,
        )
    )


def parse_qr_payload(payload: str) -> QrChunk:
    text = str(payload or "").strip()
    if not text.startswith(QR_MAGIC + "|"):
        raise QrPayloadError("QR payload missing {0} magic".format(QR_MAGIC))
    parts = text.split("|")
    values: Dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            raise QrPayloadError("QR payload field must use key=value")
        key, value = part.split("=", 1)
        values[key] = value
    required = ["v", "id", "i", "n", "sha", "crc", "data"]
    missing = [key for key in required if key not in values]
    if missing:
        raise QrPayloadError("QR payload missing fields: {0}".format(",".join(missing)))
    if values["v"] != QR_VERSION:
        raise QrPayloadError("unsupported QR payload version")
    try:
        index = int(values["i"])
        total = int(values["n"])
    except ValueError as exc:
        raise QrPayloadError("QR payload index fields must be integers") from exc
    if index < 0 or total <= 0 or index >= total:
        raise QrPayloadError("QR payload index out of range")
    artifact_id = values["id"]
    sha16 = values["sha"]
    crc = values["crc"].upper()
    data = values["data"]
    if not artifact_id or not sha16:
        raise QrPayloadError("QR payload id/sha must be non-empty")
    if transport_protocol.crc16_hex(data) != crc:
        raise QrPayloadError("QR payload CRC mismatch")
    return QrChunk(
        artifact_id=artifact_id,
        chunk_index=index,
        chunk_total=total,
        string_sha16=sha16,
        crc16=crc,
        data=data,
    )


def _report_success(chunk: QrChunk, chunks: Dict[int, QrChunk], duplicates: int, out_string: Optional[Path]) -> Dict[str, object]:
    sox1 = "".join(chunks[index].data for index in range(chunk.chunk_total))
    return {
        "schema": SCAN_REPORT_SCHEMA,
        "success": True,
        "artifact_id": chunk.artifact_id,
        "chunks_total": chunk.chunk_total,
        "chunks_found": len(chunks),
        "duplicates": duplicates,
        "missing_chunks": [],
        "string_sha256": sox1_sha256(sox1),
        "out_string": str(out_string) if out_string is not None else None,
    }


def _report_failure(
    *,
    artifact_id: Optional[str],
    chunks_total: int,
    chunks_found: int,
    duplicates: int,
    missing: Sequence[int],
    reason: str,
    image_count: int = 0,
    bad_images: Optional[List[Dict[str, object]]] = None,
) -> Dict[str, object]:
    return {
        "schema": SCAN_REPORT_SCHEMA,
        "success": False,
        "artifact_id": artifact_id,
        "image_count": image_count,
        "chunks_total": chunks_total,
        "chunks_found": chunks_found,
        "duplicates": duplicates,
        "missing_chunks": list(missing),
        "retake_pages": [index + 1 for index in missing],
        "bad_images": bad_images or [],
        "reason": reason,
    }


def reassemble_chunks(
    payloads: Iterable[str],
    *,
    artifact_id: Optional[str] = None,
    image_count: int = 0,
    bad_images: Optional[List[Dict[str, object]]] = None,
    out_string: Optional[Path] = None,
) -> Tuple[str, Dict[str, object]]:
    groups: Dict[str, Dict[str, object]] = {}
    parse_errors: List[str] = []
    for raw in payloads:
        try:
            chunk = parse_qr_payload(raw)
        except QrPayloadError as exc:
            parse_errors.append(str(exc))
            continue
        if artifact_id is not None and chunk.artifact_id != artifact_id:
            continue
        group = groups.setdefault(
            chunk.artifact_id,
            {
                "total": chunk.chunk_total,
                "sha": chunk.string_sha16,
                "chunks": {},
                "duplicates": 0,
                "conflicts": [],
            },
        )
        if group["total"] != chunk.chunk_total or group["sha"] != chunk.string_sha16:
            group["conflicts"].append("chunk metadata mismatch at index {0}".format(chunk.chunk_index))
            continue
        chunks = group["chunks"]
        existing = chunks.get(chunk.chunk_index)
        if existing is None:
            chunks[chunk.chunk_index] = chunk
        elif existing.data == chunk.data and existing.crc16 == chunk.crc16:
            group["duplicates"] += 1
        else:
            group["conflicts"].append("conflicting duplicate chunk {0}".format(chunk.chunk_index))

    if not groups:
        report = _report_failure(
            artifact_id=artifact_id,
            chunks_total=0,
            chunks_found=0,
            duplicates=0,
            missing=[],
            reason="no_valid_qr_chunks" if not parse_errors else "qr_payload_parse_or_crc_failed",
            image_count=image_count,
            bad_images=bad_images,
        )
        raise QrReassemblyError(json.dumps(report, ensure_ascii=False, sort_keys=True))

    complete: List[Tuple[str, Dict[str, object], str, Dict[str, object]]] = []
    incomplete_reports: List[Dict[str, object]] = []
    for group_id, group in groups.items():
        total = int(group["total"])
        chunks = group["chunks"]
        duplicates = int(group["duplicates"])
        conflicts = list(group["conflicts"])
        missing = [index for index in range(total) if index not in chunks]
        if conflicts:
            report = _report_failure(
                artifact_id=group_id,
                chunks_total=total,
                chunks_found=len(chunks),
                duplicates=duplicates,
                missing=missing,
                reason="conflicting_duplicate_chunks",
                image_count=image_count,
                bad_images=bad_images,
            )
            report["conflicts"] = conflicts
            incomplete_reports.append(report)
            continue
        if missing:
            incomplete_reports.append(
                _report_failure(
                    artifact_id=group_id,
                    chunks_total=total,
                    chunks_found=len(chunks),
                    duplicates=duplicates,
                    missing=missing,
                    reason="missing_or_crc_failed_chunks",
                    image_count=image_count,
                    bad_images=bad_images,
                )
            )
            continue
        first_chunk = chunks[0]
        sox1 = "".join(chunks[index].data for index in range(total))
        digest = sox1_sha256(sox1)
        if digest[:16] != first_chunk.string_sha16 or digest[:12] != first_chunk.artifact_id:
            incomplete_reports.append(
                _report_failure(
                    artifact_id=group_id,
                    chunks_total=total,
                    chunks_found=len(chunks),
                    duplicates=duplicates,
                    missing=[],
                    reason="string_sha256_mismatch",
                    image_count=image_count,
                    bad_images=bad_images,
                )
            )
            continue
        complete.append((group_id, group, sox1, _report_success(first_chunk, chunks, duplicates, out_string)))

    if len(complete) == 1:
        _, _, sox1, report = complete[0]
        if bad_images:
            report["image_count"] = image_count
            report["bad_images"] = bad_images
        return sox1, report
    if len(complete) > 1:
        report = _report_failure(
            artifact_id=None,
            chunks_total=0,
            chunks_found=sum(len(item[1]["chunks"]) for item in complete),
            duplicates=sum(int(item[1]["duplicates"]) for item in complete),
            missing=[],
            reason="multiple_complete_artifacts",
            image_count=image_count,
            bad_images=bad_images,
        )
        report["complete_artifact_ids"] = [item[0] for item in complete]
        raise QrReassemblyError(json.dumps(report, ensure_ascii=False, sort_keys=True))

    best = max(incomplete_reports, key=lambda item: int(item.get("chunks_found") or 0))
    raise QrReassemblyError(json.dumps(best, ensure_ascii=False, sort_keys=True))


def _load_cv2():
    try:
        import cv2
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("OpenCV (cv2) is required for P0 QR render/scan") from exc
    if not hasattr(cv2, "QRCodeDetector") or not hasattr(cv2, "QRCodeEncoder_create"):
        raise RuntimeError("OpenCV QRCodeDetector and QRCodeEncoder_create are required for P0 QR render/scan")
    return cv2


def render_qr_payload_image(payload: str, *, min_size_px: int = DEFAULT_QR_MIN_SIZE_PX, border_modules: int = DEFAULT_QR_BORDER_MODULES):
    cv2 = _load_cv2()
    encoder = cv2.QRCodeEncoder_create()
    image = encoder.encode(payload)
    image = cv2.copyMakeBorder(image, border_modules, border_modules, border_modules, border_modules, cv2.BORDER_CONSTANT, value=255)
    module_size = max(1, int(math.ceil(float(min_size_px) / float(min(image.shape[:2])))))
    image = cv2.resize(image, (image.shape[1] * module_size, image.shape[0] * module_size), interpolation=cv2.INTER_NEAREST)
    return image


def _placements_for_pages(
    chunks: Sequence[QrChunk],
    *,
    qrs_per_page: int,
    repeat_copies: int,
) -> List[QrPagePlacement]:
    per_page = _validate_qrs_per_page(qrs_per_page)
    copies = _validate_repeat_copies(repeat_copies)
    placements: List[QrPagePlacement] = []
    transmission_index = 0
    for copy_index in range(copies):
        chunk_count = len(chunks)
        if chunk_count <= 0:
            break
        if copy_index % 2 == 0:
            ordered_chunks = list(chunks)
        else:
            ordered_chunks = list(reversed(chunks))
        offset = (copy_index * max(1, per_page // 2)) % chunk_count
        ordered_chunks = ordered_chunks[offset:] + ordered_chunks[:offset]
        for chunk in ordered_chunks:
            placements.append(
                QrPagePlacement(
                    page_number=(transmission_index // per_page) + 1,
                    slot_index=transmission_index % per_page,
                    copy_index=copy_index,
                    chunk=chunk,
                )
            )
            transmission_index += 1
    return placements


def _qr_min_size_for_layout(qrs_per_page: int) -> int:
    if int(qrs_per_page) == 1:
        return DEFAULT_QR_MIN_SIZE_PX
    return MULTI_QR_MIN_SIZE_PX


def _pil_font(size: int):
    try:
        from PIL import ImageFont
    except Exception:  # pragma: no cover
        return None
    for font_name in ("arial.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(font_name, int(size))
        except Exception:
            continue
    return ImageFont.load_default()


def _render_qr_page_image(
    placements: Sequence[QrPagePlacement],
    *,
    artifact_id: str,
    page_number: int,
    page_count: int,
    chunk_total: int,
    qrs_per_page: int,
    repeat_copies: int,
):
    cv2 = _load_cv2()
    from PIL import Image, ImageDraw

    rows, cols = _grid_for_qrs_per_page(qrs_per_page)
    qr_size = _qr_min_size_for_layout(qrs_per_page)
    rendered_items = []
    for placement in placements:
        payload = encode_qr_payload(placement.chunk)
        qr = render_qr_payload_image(payload, min_size_px=qr_size)
        qr_rgb = cv2.cvtColor(qr, cv2.COLOR_GRAY2RGB)
        rendered_items.append((placement, Image.fromarray(qr_rgb)))

    sample_width = rendered_items[0][1].width if rendered_items else qr_size
    sample_height = rendered_items[0][1].height if rendered_items else qr_size
    margin = 48
    cell_gap = 34
    cell_pad = 22
    label_height = 54
    header_height = 170
    footer_height = 118
    cell_width = sample_width + (cell_pad * 2)
    cell_height = sample_height + label_height + (cell_pad * 2)
    page_width = margin * 2 + cols * cell_width + (cols - 1) * cell_gap
    page_height = header_height + rows * cell_height + (rows - 1) * cell_gap + footer_height
    page = Image.new("RGB", (page_width, page_height), "white")
    draw = ImageDraw.Draw(page)
    title_font = _pil_font(36)
    body_font = _pil_font(24)
    small_font = _pil_font(20)
    title = "SOX1QR {0} page {1} / {2}".format(artifact_id, page_number, page_count)
    subtitle = "chunks={0} | qrs/page={1} | repeat copies={2}".format(
        chunk_total,
        qrs_per_page,
        repeat_copies,
    )
    hint = "Keep all QR borders visible; avoid glare; one photo per physical page."
    draw.text((margin, 30), title, fill="black", font=title_font)
    draw.text((margin, 86), subtitle, fill="black", font=body_font)
    draw.text((margin, 122), hint, fill="black", font=small_font)

    by_slot = {placement.slot_index: (placement, image) for placement, image in rendered_items}
    for slot_index in range(rows * cols):
        row = slot_index // cols
        col = slot_index % cols
        x0 = margin + col * (cell_width + cell_gap)
        y0 = header_height + row * (cell_height + cell_gap)
        draw.rectangle((x0, y0, x0 + cell_width, y0 + cell_height), outline=(205, 205, 205), width=2)
        item = by_slot.get(slot_index)
        if item is None:
            draw.text((x0 + cell_pad, y0 + cell_pad), "empty slot", fill=(120, 120, 120), font=small_font)
            continue
        placement, qr_image = item
        label = "retake ID {0} | chunk {1}/{2} | copy {3}/{4}".format(
            placement.retake_id,
            placement.chunk.chunk_index + 1,
            placement.chunk.chunk_total,
            placement.copy_index + 1,
            repeat_copies,
        )
        draw.text((x0 + cell_pad, y0 + cell_pad), label, fill="black", font=small_font)
        qr_x = x0 + (cell_width - qr_image.width) // 2
        qr_y = y0 + cell_pad + label_height
        page.paste(qr_image, (qr_x, qr_y))

    retake_ids = sorted({placement.retake_id for placement in placements})
    footer = "Retake IDs on this page: {0}".format(",".join(str(item) for item in retake_ids))
    footer_y = header_height + rows * cell_height + (rows - 1) * cell_gap + 30
    draw.text((margin, footer_y), footer, fill="black", font=body_font)
    draw.text(
        (margin, footer_y + 40),
        "If scan reports missing chunk/retake ID X, recapture a page containing X.",
        fill="black",
        font=small_font,
    )
    return page


def write_json_atomic(path: Path, payload: Dict[str, object]) -> Path:
    return write_text_atomic(Path(path), json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def render_qr_pages(
    sox1: str,
    output_dir: Path,
    *,
    chunk_chars: int = DEFAULT_CHUNK_CHARS,
    qrs_per_page: int = DEFAULT_QRS_PER_PAGE,
    repeat_copies: int = DEFAULT_REPEAT_COPIES,
) -> Dict[str, object]:
    _load_cv2()
    try:
        import PIL  # noqa: F401
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("Pillow is required to render titled QR pages") from exc
    chunks = split_sox1_string(sox1, chunk_chars=chunk_chars)
    per_page = _validate_qrs_per_page(qrs_per_page)
    copies = _validate_repeat_copies(repeat_copies)
    placements = _placements_for_pages(chunks, qrs_per_page=per_page, repeat_copies=copies)
    page_count = int(math.ceil(len(placements) / float(per_page)))
    output = Path(output_dir)
    pages_dir = output / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)
    for old_page in pages_dir.glob("page_*.png"):
        if old_page.is_file():
            old_page.unlink()
    page_records = []
    for page_number in range(1, page_count + 1):
        page_placements = [placement for placement in placements if placement.page_number == page_number]
        page = _render_qr_page_image(
            page_placements,
            artifact_id=chunks[0].artifact_id,
            page_number=page_number,
            page_count=page_count,
            chunk_total=len(chunks),
            qrs_per_page=per_page,
            repeat_copies=copies,
        )
        page_path = pages_dir / "page_{0:04d}.png".format(page_number)
        page.save(str(page_path), format="PNG")
        items = [
            {
                "slot": placement.slot_index,
                "copy": placement.copy_index + 1,
                "chunk_index": placement.chunk.chunk_index,
                "retake_id": placement.retake_id,
                "payload_crc16": placement.chunk.crc16,
            }
            for placement in page_placements
        ]
        page_record = {
            "page": page_number,
            "path": str(page_path.relative_to(output)),
            "qrs": len(page_placements),
            "retake_ids": sorted({placement.retake_id for placement in page_placements}),
            "items": items,
        }
        if len(page_placements) == 1:
            only = page_placements[0]
            page_record.update(
                {
                    "chunk_index": only.chunk.chunk_index,
                    "payload_crc16": only.chunk.crc16,
                }
            )
        page_records.append(page_record)
    manifest = {
        "schema": QR_SCHEMA,
        "version": 1,
        "artifact_id": chunks[0].artifact_id,
        "string_sha256": sox1_sha256(sox1),
        "string_sha16": chunks[0].string_sha16,
        "chunk_chars": int(chunk_chars),
        "qrs_per_page": per_page,
        "repeat_copies": copies,
        "chunks_total": len(chunks),
        "transmissions_total": len(placements),
        "page_count": page_count,
        "pages": page_records,
        "recovery_requires_manifest": False,
    }
    write_json_atomic(output / "manifest.json", manifest)
    write_text_atomic(
        output / "instructions.md",
        "# SOX1QR Capture Instructions\n\n"
        "- Capture each page fully.\n"
        "- A page may contain multiple QR codes; keep every QR quiet zone inside the photo.\n"
        "- Repeated copies are intentional and improve recovery after lost/blurred pages.\n"
        "- Avoid glare, motion blur, and cropped QR borders.\n"
        "- Recovery does not require this manifest; photos are self-contained.\n",
    )
    return manifest


__all__ = [
    "DEFAULT_CHUNK_CHARS",
    "DEFAULT_QRS_PER_PAGE",
    "DEFAULT_REPEAT_COPIES",
    "IMAGE_SUFFIXES",
    "MAX_CHUNK_CHARS",
    "MAX_QR_CHUNKS",
    "MAX_REPEAT_COPIES",
    "MIN_CHUNK_CHARS",
    "MULTI_QR_MIN_SIZE_PX",
    "QR_MAGIC",
    "QR_SCHEMA",
    "QR_VERSION",
    "QrChunk",
    "QrPagePlacement",
    "QrPayloadError",
    "QrReassemblyError",
    "QrTransportError",
    "artifact_id_for_sox1",
    "encode_qr_payload",
    "parse_qr_payload",
    "reassemble_chunks",
    "render_qr_pages",
    "render_qr_payload_image",
    "sox1_sha256",
    "split_sox1_string",
    "write_json_atomic",
]
