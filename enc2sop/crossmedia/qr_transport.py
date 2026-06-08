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
DEFAULT_QR_MIN_SIZE_PX = 900
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


def write_json_atomic(path: Path, payload: Dict[str, object]) -> Path:
    return write_text_atomic(Path(path), json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def render_qr_pages(sox1: str, output_dir: Path, *, chunk_chars: int = DEFAULT_CHUNK_CHARS) -> Dict[str, object]:
    cv2 = _load_cv2()
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("Pillow is required to render titled QR pages") from exc
    chunks = split_sox1_string(sox1, chunk_chars=chunk_chars)
    output = Path(output_dir)
    pages_dir = output / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)
    for old_page in pages_dir.glob("page_*.png"):
        if old_page.is_file():
            old_page.unlink()
    page_records = []
    for chunk in chunks:
        payload = encode_qr_payload(chunk)
        qr = render_qr_payload_image(payload)
        qr_rgb = cv2.cvtColor(qr, cv2.COLOR_GRAY2RGB)
        qr_image = Image.fromarray(qr_rgb)
        margin = 48
        header_height = 150
        footer_height = 90
        page = Image.new("RGB", (qr_image.width + margin * 2, qr_image.height + header_height + footer_height), "white")
        draw = ImageDraw.Draw(page)
        try:
            title_font = ImageFont.truetype("arial.ttf", 36)
            body_font = ImageFont.truetype("arial.ttf", 24)
        except Exception:
            title_font = ImageFont.load_default()
            body_font = ImageFont.load_default()
        title = "SOX1QR {0} page {1} / {2}".format(chunk.artifact_id, chunk.page_number, chunk.chunk_total)
        hint = "Keep full border visible, avoid glare, capture one page at a time."
        draw.text((margin, 34), title, fill="black", font=title_font)
        draw.text((margin, 92), hint, fill="black", font=body_font)
        page.paste(qr_image, (margin, header_height))
        draw.text((margin, header_height + qr_image.height + 28), "Retake page {0} if scan reports missing chunk {1}.".format(chunk.page_number, chunk.chunk_index), fill="black", font=body_font)
        page_path = pages_dir / "page_{0:04d}.png".format(chunk.page_number)
        page.save(str(page_path), format="PNG")
        page_records.append(
            {
                "page": chunk.page_number,
                "chunk_index": chunk.chunk_index,
                "payload_crc16": chunk.crc16,
                "path": str(page_path.relative_to(output)),
            }
        )
    manifest = {
        "schema": QR_SCHEMA,
        "version": 1,
        "artifact_id": chunks[0].artifact_id,
        "string_sha256": sox1_sha256(sox1),
        "string_sha16": chunks[0].string_sha16,
        "chunk_chars": int(chunk_chars),
        "chunks_total": len(chunks),
        "pages": page_records,
        "recovery_requires_manifest": False,
    }
    write_json_atomic(output / "manifest.json", manifest)
    write_text_atomic(
        output / "instructions.md",
        "# SOX1QR Capture Instructions\n\n"
        "- Capture each page fully.\n"
        "- Avoid glare, motion blur, and cropped QR borders.\n"
        "- Recovery does not require this manifest; photos are self-contained.\n",
    )
    return manifest


__all__ = [
    "DEFAULT_CHUNK_CHARS",
    "IMAGE_SUFFIXES",
    "MAX_CHUNK_CHARS",
    "MAX_QR_CHUNKS",
    "MIN_CHUNK_CHARS",
    "QR_MAGIC",
    "QR_SCHEMA",
    "QR_VERSION",
    "QrChunk",
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
