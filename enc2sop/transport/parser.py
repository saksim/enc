"""Transport parser/conflict helpers extracted from qrcode_helper."""

import csv
import math
import itertools
import json
import re
import zlib
from typing import Dict, List, Optional, Tuple

from . import protocol


class CorrectionFileError(ValueError):
    """Raised when a filled OCR correction CSV is structurally invalid."""

    def __init__(self, reason: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.reason = reason
        self.details = dict(details)


def _payload_profile(profile: Optional[str]) -> str:
    return str(profile or "safe-base32-v1").strip().lower()


def _line_for_payload_profile(raw: str, payload_alphabet_profile: Optional[str]) -> str:
    if _payload_profile(payload_alphabet_profile) == protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        return protocol.normalize_protocol_signature(
            protocol.normalize_ocr_line_preserve_case(raw)
        )
    return protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))


def _normalize_extracted_payload(raw_payload: str, payload_alphabet_profile: Optional[str]) -> str:
    if _payload_profile(payload_alphabet_profile) == protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        return str(raw_payload or "")
    return protocol.normalize_payload(str(raw_payload or ""))


def _ocr_safe_has_crc_line_shape(line: str) -> bool:
    return bool(
        protocol.LINE_PATTERN.match(line)
        or protocol.LINE_PATTERN_NOSEP.match(line)
        or protocol.LINE_PATTERN_FALLBACK.match(line)
        or protocol.CHUNK_PATTERN.match(line)
        or protocol.CHUNK_PATTERN_FALLBACK.match(line)
    )


def _ocr_safe_no_crc_line_shape(line: str) -> bool:
    return bool(
        protocol.LINE_PATTERN_NOCRC.match(line)
        or protocol.LINE_PATTERN_NOSEP_NOCRC.match(line)
        or protocol.LINE_PATTERN_FALLBACK_NOCRC.match(line)
        or protocol.CHUNK_PATTERN_NOCRC.match(line)
        or protocol.CHUNK_PATTERN_FALLBACK_NOCRC.match(line)
    )


def _coalesce_ocr_safe_line_break_drift(raw_lines: List[str]) -> List[str]:
    merged: List[str] = []
    index = 0
    while index < len(raw_lines):
        raw = str(raw_lines[index] or "")
        if index + 1 < len(raw_lines):
            first = _line_for_payload_profile(raw, protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE)
            combined = _line_for_payload_profile(
                raw + str(raw_lines[index + 1] or ""),
                protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            )
            if _ocr_safe_no_crc_line_shape(first) and _ocr_safe_has_crc_line_shape(combined):
                merged.append(raw + str(raw_lines[index + 1] or ""))
                index += 2
                continue
        merged.append(raw)
        index += 1
    return merged


_OCR_SAFE_FULL_LINE_PREFIX = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})([\|$@IT])C([0-9A-Z@]{5})\3(.+)$"
)
_OCR_SAFE_FULL_LINE_NOSEP = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})C([0-9A-Z@]{5})(.+)$"
)
_OCR_SAFE_CHUNK_LINE_PREFIX = re.compile(
    r"^C([0-9A-Z@]{5})([\|$@IT])(.+)$"
)


def _split_ocr_safe_payload_crc_tail(value: str) -> Tuple[str, str, bool]:
    tail = str(value or "")
    if len(tail) >= 6 and tail[-5] in ("|", "$", "@", "I", "T"):
        crc = protocol.normalize_hex_token(tail[-4:])
        if len(crc) == 4:
            return tail[:-5], crc, True
    return tail, "", False


def _parse_ocr_safe_structured_line(
    line: str,
    *,
    current_page_no: int,
    source_line_no: int,
) -> Optional[Dict[str, object]]:
    """Parse OCR-safe data lines whose payload may contain separator-like glyphs."""
    match = _OCR_SAFE_FULL_LINE_PREFIX.match(line)
    if match:
        try:
            page_no = int(protocol.normalize_page_line_token(match.group(1)))
            line_no = int(protocol.normalize_page_line_token(match.group(2)))
            chunk_idx = int(protocol.normalize_digit_token(match.group(4)))
        except Exception:
            return None
        payload, given_crc, line_has_crc = _split_ocr_safe_payload_crc_tail(match.group(5))
        return {
            "page_no": page_no,
            "line_no": line_no,
            "chunk_idx": chunk_idx,
            "payload": payload,
            "given_crc": given_crc,
            "line_has_crc": bool(line_has_crc),
            "line_index_kind": "full",
        }

    match = _OCR_SAFE_FULL_LINE_NOSEP.match(line)
    if match:
        try:
            page_no = int(protocol.normalize_page_line_token(match.group(1)))
            line_no = int(protocol.normalize_page_line_token(match.group(2)))
            chunk_idx = int(protocol.normalize_digit_token(match.group(3)))
        except Exception:
            return None
        payload = str(match.group(4))
        given_crc = ""
        line_has_crc = False
        possible_crc = protocol.normalize_hex_token(payload[-4:]) if len(payload) >= 5 else ""
        if len(possible_crc) == 4:
            payload = payload[:-4]
            given_crc = possible_crc
            line_has_crc = True
        return {
            "page_no": page_no,
            "line_no": line_no,
            "chunk_idx": chunk_idx,
            "payload": payload,
            "given_crc": given_crc,
            "line_has_crc": bool(line_has_crc),
            "line_index_kind": "full",
            "separator_missing": True,
        }

    match = _OCR_SAFE_CHUNK_LINE_PREFIX.match(line)
    if match:
        try:
            chunk_idx = int(protocol.normalize_digit_token(match.group(1)))
        except Exception:
            return None
        payload, given_crc, line_has_crc = _split_ocr_safe_payload_crc_tail(match.group(3))
        return {
            "page_no": int(current_page_no) if current_page_no > 0 else 0,
            "line_no": int(source_line_no),
            "chunk_idx": chunk_idx,
            "payload": payload,
            "given_crc": given_crc,
            "line_has_crc": bool(line_has_crc),
            "line_index_kind": "chunk",
        }

    return None


def _append_correction_record(
    correction_records: List[Dict[str, object]],
    *,
    page_no: int,
    line_no: int,
    raw_text: str,
    normalized_text: str,
    candidates: List[str],
    status: str,
    expected_crc: str,
    actual_crc: str,
) -> None:
    correction_records.append(
        {
            "page": int(page_no),
            "line": int(line_no),
            "raw_text": str(raw_text or ""),
            "normalized_text": str(normalized_text or ""),
            "candidates": list(candidates[:25]),
            "candidate_count": len(candidates),
            "status": str(status),
            "expected_crc": str(expected_crc or ""),
            "actual_crc": str(actual_crc or ""),
            "corrected_text": "",
        }
    )


def _load_operator_corrections(
    corrections_file: Optional[str],
) -> Tuple[Dict[Tuple[int, int], Dict[str, str]], Dict[str, object]]:
    metadata: Dict[str, object] = {
        "source_file": str(corrections_file) if corrections_file else None,
        "source_sha256": None,
        "source_size": None,
        "row_count": 0,
        "filled_row_count": 0,
    }
    if not corrections_file:
        return {}, metadata

    rows: Dict[Tuple[int, int], Dict[str, str]] = {}
    with open(str(corrections_file), "rb") as handle:
        correction_bytes = handle.read()
    metadata["source_sha256"] = protocol.sha256_hex(correction_bytes)
    metadata["source_size"] = len(correction_bytes)
    with open(str(corrections_file), newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = set(reader.fieldnames or [])
        required = {"page", "line", "corrected_text"}
        missing = sorted(required - fieldnames)
        if missing:
            raise CorrectionFileError(
                "corrections_file_missing_required_columns",
                "corrections file missing required columns: {}".format(
                    ", ".join(missing)
                ),
                missing_columns=missing,
            )
        for row_number, raw_row in enumerate(reader, 2):
            metadata["row_count"] = int(metadata["row_count"]) + 1
            corrected_text = str(raw_row.get("corrected_text") or "").strip()
            if not corrected_text:
                continue
            try:
                page_no = int(str(raw_row.get("page") or "").strip())
                line_no = int(str(raw_row.get("line") or "").strip())
            except Exception as exc:
                raise CorrectionFileError(
                    "correction_row_location_invalid",
                    "invalid correction row location at csv row {}".format(row_number),
                    row_number=row_number,
                ) from exc
            if page_no < 0 or line_no < 0:
                raise CorrectionFileError(
                    "correction_row_location_invalid",
                    "invalid correction row location at csv row {}".format(row_number),
                    row_number=row_number,
                    page=str(raw_row.get("page") or "").strip(),
                    line=str(raw_row.get("line") or "").strip(),
                )
            key = (page_no, line_no)
            if key in rows:
                raise CorrectionFileError(
                    "duplicate_filled_correction_row",
                    "duplicate filled correction for page {}, line {}".format(
                        page_no, line_no
                    ),
                    row_number=row_number,
                    page=page_no,
                    line=line_no,
                )
            rows[key] = {
                "row_number": str(row_number),
                "page": str(page_no),
                "line": str(line_no),
                "raw_text": str(raw_row.get("raw_text") or ""),
                "normalized_text": str(raw_row.get("normalized_text") or ""),
                "status": str(raw_row.get("status") or "").strip(),
                "expected_crc": str(raw_row.get("expected_crc") or "").strip(),
                "actual_crc": str(raw_row.get("actual_crc") or "").strip(),
                "corrected_text": corrected_text,
                "corrected_text_sha256": protocol.sha256_hex(
                    corrected_text.encode("utf-8")
                ),
            }
            metadata["filled_row_count"] = int(metadata["filled_row_count"]) + 1
    metadata["filled_rows"] = [
        {
            "row_number": int(row.get("row_number") or 0),
            "page": int(row.get("page") or 0),
            "line": int(row.get("line") or 0),
            "expected_crc": str(row.get("expected_crc") or ""),
            "corrected_text_sha256": str(row.get("corrected_text_sha256") or ""),
        }
        for row in sorted(
            rows.values(),
            key=lambda item: (
                int(item.get("row_number") or 0),
                int(item.get("page") or 0),
                int(item.get("line") or 0),
            ),
        )
    ]
    return rows, metadata


def _correction_replay_summary(
    metadata: Dict[str, object],
    applied: List[Dict[str, object]],
    invalid: List[Dict[str, object]],
) -> Dict[str, object]:
    filled_rows = metadata.get("filled_rows")
    if not isinstance(filled_rows, list):
        filled_rows = []
    used_row_numbers = {
        int(item.get("row_number") or 0)
        for item in list(applied) + list(invalid)
        if isinstance(item, dict)
    }
    unused = [
        row
        for row in filled_rows
        if isinstance(row, dict)
        and int(row.get("row_number") or 0) not in used_row_numbers
    ]
    return {
        "source_file": metadata.get("source_file"),
        "source_sha256": metadata.get("source_sha256"),
        "source_size": metadata.get("source_size"),
        "row_count": int(metadata.get("row_count") or 0),
        "filled_row_count": int(metadata.get("filled_row_count") or 0),
        "applied_count": len(applied),
        "invalid_count": len(invalid),
        "unused_count": len(unused),
        "applied_sample": applied[:20],
        "invalid_sample": invalid[:20],
        "unused_sample": unused[:20],
    }


def _operator_corrected_payload_text(
    corrected_text: str,
    *,
    page_no: int,
    line_no: int,
    source_line_no: int,
    expected_crc: str,
) -> str:
    corrected_text = str(corrected_text or "").strip()
    if not corrected_text:
        return ""
    normalized = _line_for_payload_profile(
        corrected_text,
        protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
    )
    parsed = _parse_ocr_safe_structured_line(
        normalized,
        current_page_no=page_no,
        source_line_no=source_line_no,
    )
    if parsed is not None:
        parsed_page = int(parsed.get("page_no", page_no) or page_no)
        parsed_line = int(parsed.get("line_no", line_no) or line_no)
        parsed_crc = protocol.normalize_hex_token(str(parsed.get("given_crc") or ""))
        if (
            parsed_page == int(page_no)
            and parsed_line == int(line_no)
            and (not parsed_crc or parsed_crc == expected_crc)
        ):
            return str(parsed.get("payload") or "")
    payload, tail_crc, has_crc = _split_ocr_safe_payload_crc_tail(normalized)
    if has_crc and protocol.normalize_hex_token(tail_crc) == expected_crc:
        return payload
    return corrected_text


def _try_operator_correction(
    *,
    correction_rows: Dict[Tuple[int, int], Dict[str, str]],
    correction_applied: List[Dict[str, object]],
    correction_invalid: List[Dict[str, object]],
    page_no: int,
    line_no: int,
    source_line_no: int,
    chunk_idx: int,
    core_prefix: str,
    expected_crc: str,
    expected_len: Optional[int],
    raw_text: str,
    normalized_text: str,
    correction_status: str,
    actual_crc: str,
) -> Optional[str]:
    correction = correction_rows.get((int(page_no), int(line_no)))
    if correction is None:
        return None

    expected_crc = protocol.normalize_hex_token(str(expected_crc or ""))
    row_expected_crc = protocol.normalize_hex_token(
        str(correction.get("expected_crc") or "")
    )

    def _invalid(reason: str, **extra: object) -> None:
        event = {
            "page": int(page_no),
            "line": int(line_no),
            "source_line_no": int(source_line_no),
            "chunk_idx": int(chunk_idx),
            "row_number": int(correction.get("row_number") or 0),
            "reason": reason,
            "expected_crc": expected_crc,
        }
        event.update(extra)
        correction_invalid.append(event)

    if row_expected_crc and expected_crc and row_expected_crc != expected_crc:
        _invalid(
            "correction_expected_crc_mismatch",
            correction_expected_crc=row_expected_crc,
        )
        return None
    row_raw_text = str(correction.get("raw_text") or "")
    if row_raw_text and row_raw_text != str(raw_text or ""):
        _invalid("correction_raw_text_mismatch")
        return None
    row_normalized_text = str(correction.get("normalized_text") or "")
    if row_normalized_text and row_normalized_text != str(normalized_text or ""):
        _invalid("correction_normalized_text_mismatch")
        return None
    row_status = str(correction.get("status") or "").strip()
    if row_status and row_status != str(correction_status or "").strip():
        _invalid(
            "correction_status_mismatch",
            correction_status=row_status,
            current_status=str(correction_status or "").strip(),
        )
        return None
    row_actual_crc = str(correction.get("actual_crc") or "").strip()
    if row_actual_crc and row_actual_crc != str(actual_crc or "").strip():
        _invalid(
            "correction_actual_crc_mismatch",
            correction_actual_crc=row_actual_crc,
            current_actual_crc=str(actual_crc or "").strip(),
        )
        return None
    if len(expected_crc) != 4:
        _invalid("correction_line_crc_required")
        return None

    corrected_text = _operator_corrected_payload_text(
        str(correction.get("corrected_text") or ""),
        page_no=page_no,
        line_no=line_no,
        source_line_no=source_line_no,
        expected_crc=expected_crc,
    )
    candidate_info = protocol.ocr_safe_payload_candidates(corrected_text)
    if str(candidate_info.get("unexpected_chars") or ""):
        _invalid(
            "correction_unexpected_chars",
            chars=str(candidate_info.get("unexpected_chars") or ""),
        )
        return None
    if bool(candidate_info.get("candidate_limit_exceeded")):
        _invalid("correction_candidate_limit_exceeded")
        return None

    candidates = [str(item) for item in candidate_info.get("candidates", []) or []]
    if expected_len is not None and int(expected_len) > 0:
        candidates = [item for item in candidates if len(item) == int(expected_len)]
    unique_candidates = sorted(set(candidates))
    if len(unique_candidates) != 1:
        _invalid(
            "correction_not_unique",
            candidate_count=len(unique_candidates),
        )
        return None

    corrected_payload = unique_candidates[0]
    actual_crc = protocol.crc16_hex(core_prefix + corrected_payload)
    if actual_crc != expected_crc:
        _invalid(
            "correction_line_crc_mismatch",
            actual_crc=actual_crc,
        )
        return None

    correction_applied.append(
        {
            "page": int(page_no),
            "line": int(line_no),
            "source_line_no": int(source_line_no),
            "chunk_idx": int(chunk_idx),
            "row_number": int(correction.get("row_number") or 0),
            "expected_crc": expected_crc,
            "actual_crc": actual_crc,
            "corrected_text_sha256": protocol.sha256_hex(
                corrected_payload.encode("ascii")
            ),
            "corrected_text_length": len(corrected_payload),
        }
    )
    return corrected_payload


def _resolve_ocr_safe_payload(
    *,
    raw_payload: str,
    raw_text: str,
    core_prefix: str,
    expected_crc: str,
    line_has_crc: bool,
    expected_len: Optional[int],
    page_no: int,
    line_no: int,
    source_line_no: int,
    chunk_idx: int,
    line_errors: List[Dict[str, object]],
    line_warnings: List[Dict[str, object]],
    correction_records: List[Dict[str, object]],
    correction_rows: Dict[Tuple[int, int], Dict[str, str]],
    correction_applied: List[Dict[str, object]],
    correction_invalid: List[Dict[str, object]],
) -> Optional[str]:
    candidate_info = protocol.ocr_safe_payload_candidates(raw_payload)
    normalized_text = str(candidate_info.get("normalized_text") or "")
    candidates = [str(item) for item in candidate_info.get("candidates", []) or []]
    if expected_len is not None and int(expected_len) > 0:
        candidates = [item for item in candidates if len(item) == int(expected_len)]
    expected_crc = str(expected_crc or "").strip().upper()

    unexpected_chars = str(candidate_info.get("unexpected_chars") or "")
    status = ""
    if unexpected_chars:
        status = "unexpected-chars"
        reason = "ocr_safe_unexpected_chars"
    elif bool(candidate_info.get("candidate_limit_exceeded")):
        status = "candidate-limit-exceeded"
        reason = "ocr_safe_candidate_limit_exceeded"
    elif not line_has_crc:
        status = "line-crc-missing"
        reason = "ocr_safe_line_crc_missing"
    else:
        reason = ""

    actual_crcs = []
    for candidate in candidates[:25]:
        actual_crcs.append(protocol.crc16_hex(core_prefix + candidate))
    actual_crc_text = ";".join(actual_crcs[:8])

    if status:
        operator_payload = _try_operator_correction(
            correction_rows=correction_rows,
            correction_applied=correction_applied,
            correction_invalid=correction_invalid,
            page_no=page_no,
            line_no=line_no,
            source_line_no=source_line_no,
            chunk_idx=chunk_idx,
            core_prefix=core_prefix,
            expected_crc=expected_crc,
            expected_len=expected_len,
            raw_text=raw_text,
            normalized_text=normalized_text,
            correction_status=status,
            actual_crc=actual_crc_text,
        )
        if operator_payload is not None:
            line_warnings.append(
                {
                    "line_no": source_line_no,
                    "reason": "ocr_safe_operator_correction_applied",
                    "chunk_idx": chunk_idx,
                }
            )
            return operator_payload
        _append_correction_record(
            correction_records,
            page_no=page_no,
            line_no=line_no,
            raw_text=raw_text,
            normalized_text=normalized_text,
            candidates=candidates,
            status=status,
            expected_crc=expected_crc,
            actual_crc=actual_crc_text,
        )
        line_errors.append(
            {
                "line_no": source_line_no,
                "reason": reason,
                "chunk_idx": chunk_idx,
                "expected_crc": expected_crc,
                "chars": unexpected_chars,
            }
        )
        return None

    passing = [
        candidate
        for candidate in candidates
        if protocol.crc16_hex(core_prefix + candidate) == expected_crc
    ]
    unique_passing = sorted(set(passing))
    if len(unique_passing) == 1:
        if (
            int(candidate_info.get("ambiguous_count") or 0) > 0
            or unique_passing[0] != normalized_text
        ):
            line_warnings.append(
                {
                    "line_no": source_line_no,
                    "reason": "ocr_safe_line_crc_resolved",
                    "chunk_idx": chunk_idx,
                    "candidate_count": len(candidates),
                    "ambiguous_count": int(candidate_info.get("ambiguous_count") or 0),
                }
            )
        return unique_passing[0]

    operator_payload = _try_operator_correction(
        correction_rows=correction_rows,
        correction_applied=correction_applied,
        correction_invalid=correction_invalid,
        page_no=page_no,
        line_no=line_no,
        source_line_no=source_line_no,
        chunk_idx=chunk_idx,
        core_prefix=core_prefix,
        expected_crc=expected_crc,
        expected_len=expected_len,
        raw_text=raw_text,
        normalized_text=normalized_text,
        correction_status=(
            "multi-pass" if len(unique_passing) > 1 else "unresolved"
        ),
        actual_crc=actual_crc_text,
    )
    if operator_payload is not None:
        line_warnings.append(
            {
                "line_no": source_line_no,
                "reason": "ocr_safe_operator_correction_applied",
                "chunk_idx": chunk_idx,
            }
        )
        return operator_payload

    status = "multi-pass" if len(unique_passing) > 1 else "unresolved"
    _append_correction_record(
        correction_records,
        page_no=page_no,
        line_no=line_no,
        raw_text=raw_text,
        normalized_text=normalized_text,
        candidates=candidates,
        status=status,
        expected_crc=expected_crc,
        actual_crc=actual_crc_text,
    )
    line_errors.append(
        {
            "line_no": source_line_no,
            "reason": (
                "ocr_safe_line_crc_multiple_candidates"
                if len(unique_passing) > 1
                else "ocr_safe_line_crc_unresolved"
            ),
            "chunk_idx": chunk_idx,
            "expected_crc": expected_crc,
            "candidate_count": len(candidates),
            "passing_candidate_count": len(unique_passing),
        }
    )
    return None


def parse_ocr_chunks(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    total_chunks = int(manifest["total_chunks"])
    line_index_mode = str(manifest.get("transport_line_index_mode", "full") or "full").strip().lower()
    payload_alphabet_profile = manifest.get("payload_alphabet_profile")
    if line_index_mode == "off":
        return parse_ocr_chunks_payload_only_manifest(
            transport=transport,
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )
    return parse_ocr_chunks_with_total(
        transport=transport,
        total_chunks=total_chunks,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
        line_index_mode=line_index_mode,
        payload_alphabet_profile=payload_alphabet_profile,
        chunk_lengths=manifest.get("chunk_lengths"),
        corrections_file=corrections_file,
    )


def parse_ocr_chunks_payload_only_manifest(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    raw_lines = transport._read_ocr_lines(ocr_input_path)
    payload_alphabet_profile = manifest.get("payload_alphabet_profile")
    payload_alphabet = protocol.payload_alphabet_for_profile(payload_alphabet_profile)
    ocr_safe_profile = (
        _payload_profile(payload_alphabet_profile)
        == protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE
    )
    chunk_votes = {}
    page_lines_for_crc = {}
    page_meta_extra_for_crc = {}
    page_meta = {}
    page_crc_expect = {}
    line_errors = []
    line_warnings = []
    correction_records: List[Dict[str, object]] = []
    correction_rows, correction_metadata = _load_operator_corrections(corrections_file)
    correction_applied: List[Dict[str, object]] = []
    correction_invalid: List[Dict[str, object]] = []
    current_page_no = 0

    payload_rows = []
    for source_line_no, raw in enumerate(raw_lines, 1):
        line = protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))
        payload_line = _line_for_payload_profile(raw, payload_alphabet_profile)
        if not line:
            continue

        meta_match = protocol.META_PATTERN.match(line)
        if meta_match:
            page_no = int(meta_match.group(2))
            page_meta[page_no] = line
            current_page_no = page_no
            continue

        if protocol.parse_cfg_line(line):
            if current_page_no > 0:
                page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
            continue

        if protocol.parse_hash_fragment_line(line):
            if current_page_no > 0:
                page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
            continue
        if protocol.parse_hash_compact_line(line):
            if current_page_no > 0:
                page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
            continue

        page_crc_match = protocol.PAGECRC_PATTERN.match(line)
        if page_crc_match:
            page_no = int(page_crc_match.group(1))
            page_crc_expect[page_no] = page_crc_match.group(2)
            current_page_no = 0
            continue

        has_crc = False
        given_crc = ""
        payload = ""
        match_with_crc = None
        if ocr_safe_profile:
            payload_candidate, crc_candidate, crc_present = _split_ocr_safe_payload_crc_tail(
                payload_line
            )
            if crc_present:
                has_crc = True
                payload = _normalize_extracted_payload(
                    payload_candidate,
                    payload_alphabet_profile,
                )
                given_crc = crc_candidate
        if not has_crc:
            match_with_crc = protocol.PAYLOAD_WITH_CRC_PATTERN.match(payload_line)
        if match_with_crc:
            has_crc = True
            payload = _normalize_extracted_payload(
                match_with_crc.group(1),
                payload_alphabet_profile,
            )
            given_crc = protocol.normalize_hex_token(match_with_crc.group(3))
        elif not has_crc:
            match_fallback_crc = protocol.PAYLOAD_WITH_CRC_FALLBACK_PATTERN.match(payload_line)
            if match_fallback_crc:
                has_crc = True
                payload = _normalize_extracted_payload(
                    match_fallback_crc.group(1),
                    payload_alphabet_profile,
                )
                given_crc = protocol.normalize_hex_token(match_fallback_crc.group(3))
                line_warnings.append(
                    {
                        "line_no": source_line_no,
                        "reason": "payload_crc_fallback_pattern_used",
                    }
                )
            else:
                payload = _normalize_extracted_payload(payload_line, payload_alphabet_profile)

        if (not ocr_safe_profile) and strict_payload_chars:
            invalid_chars = [ch for ch in payload if ch not in payload_alphabet]
            if invalid_chars:
                line_errors.append(
                    {
                        "line_no": source_line_no,
                        "reason": "invalid_payload_chars",
                        "chars": "".join(sorted(set(invalid_chars)))[:50],
                    }
                )
                continue
        elif not ocr_safe_profile:
            payload = "".join(ch for ch in payload if ch in payload_alphabet)

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
                "raw_text": str(raw),
                "has_crc": bool(has_crc),
                "given_crc": given_crc,
            }
        )

    ordered_entries = transport._manifest_entries_in_transport_order(manifest)
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
        expected_len = None
        raw_chunk_lengths = manifest.get("chunk_lengths")
        if isinstance(raw_chunk_lengths, list) and 0 <= chunk_idx < len(raw_chunk_lengths):
            try:
                expected_len = int(raw_chunk_lengths[chunk_idx])
            except Exception:
                expected_len = None

        core = "C{:05d}|{}".format(chunk_idx, payload)
        expect_crc = protocol.crc16_hex(core)
        if ocr_safe_profile:
            resolved_payload = _resolve_ocr_safe_payload(
                raw_payload=payload,
                raw_text=str(row.get("raw_text") or ""),
                core_prefix="C{:05d}|".format(chunk_idx),
                expected_crc=given_crc,
                line_has_crc=has_crc,
                expected_len=expected_len,
                page_no=page_no,
                line_no=line_no,
                source_line_no=int(row["source_line_no"]),
                chunk_idx=chunk_idx,
                line_errors=line_errors,
                line_warnings=line_warnings,
                correction_records=correction_records,
                correction_rows=correction_rows,
                correction_applied=correction_applied,
                correction_invalid=correction_invalid,
            )
            if resolved_payload is None:
                continue
            payload = resolved_payload
            core = "C{:05d}|{}".format(chunk_idx, payload)
            expect_crc = protocol.crc16_hex(core)
        elif has_crc and expect_crc != given_crc:
            repaired = transport._repair_payload_candidate_by_crc(
                payload=payload,
                core_prefix="C{:05d}|".format(chunk_idx),
                expected_crc=given_crc,
            )
            if repaired != payload:
                payload = repaired
                core = "C{:05d}|{}".format(chunk_idx, payload)
                expect_crc = protocol.crc16_hex(core)
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
        actual_crc = protocol.crc16_hex("\n".join(base))
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
        "correction_records": correction_records,
        "correction_replay": _correction_replay_summary(
            correction_metadata,
            correction_applied,
            correction_invalid,
        ),
    }


def parse_ocr_chunks_with_total(
    transport,
    total_chunks: int,
    ocr_input_path: str,
    strict_payload_chars: bool,
    line_index_mode: str = "full",
    payload_alphabet_profile: Optional[str] = None,
    chunk_lengths: Optional[object] = None,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    raw_lines = transport._read_ocr_lines(ocr_input_path)
    if _payload_profile(payload_alphabet_profile) == protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        raw_lines = _coalesce_ocr_safe_line_break_drift(raw_lines)
    payload_alphabet = protocol.payload_alphabet_for_profile(payload_alphabet_profile)
    ocr_safe_profile = (
        _payload_profile(payload_alphabet_profile)
        == protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE
    )
    chunk_votes = {}
    page_lines_for_crc = {}
    page_meta_extra_for_crc = {}
    page_meta = {}
    page_crc_expect = {}
    line_errors = []
    line_warnings = []
    correction_records: List[Dict[str, object]] = []
    correction_rows, correction_metadata = _load_operator_corrections(corrections_file)
    correction_applied: List[Dict[str, object]] = []
    correction_invalid: List[Dict[str, object]] = []
    current_page_no = 0

    for source_line_no, raw in enumerate(raw_lines, 1):
        line = protocol.normalize_ocr_line(raw)
        if not line:
            continue
        line = protocol.normalize_protocol_signature(line)
        payload_line = _line_for_payload_profile(raw, payload_alphabet_profile)

        meta_match = protocol.META_PATTERN.match(line)
        if meta_match:
            page_no = int(meta_match.group(2))
            page_meta[page_no] = line
            current_page_no = page_no
            continue

        if protocol.parse_cfg_line(line):
            if current_page_no > 0:
                page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
            continue

        if protocol.parse_hash_fragment_line(line):
            if current_page_no > 0:
                page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
            continue
        if protocol.parse_hash_compact_line(line):
            if current_page_no > 0:
                page_meta_extra_for_crc.setdefault(current_page_no, []).append(line)
            continue

        page_crc_match = protocol.PAGECRC_PATTERN.match(line)
        if page_crc_match:
            page_no = int(page_crc_match.group(1))
            page_crc_expect[page_no] = page_crc_match.group(2)
            current_page_no = 0
            continue

        match = protocol.LINE_PATTERN.match(payload_line)
        match_no_crc = protocol.LINE_PATTERN_NOCRC.match(payload_line) if (not match) else None
        match_nosep_no_crc = (
            protocol.LINE_PATTERN_NOSEP_NOCRC.match(payload_line)
            if (not match and not match_no_crc)
            else None
        )
        match_nosep = (
            protocol.LINE_PATTERN_NOSEP.match(payload_line)
            if (not match and not match_no_crc and not match_nosep_no_crc)
            else None
        )
        chunk_match = (
            protocol.CHUNK_PATTERN.match(payload_line)
            if (not match and not match_no_crc and not match_nosep and not match_nosep_no_crc)
            else None
        )
        chunk_no_crc = (
            protocol.CHUNK_PATTERN_NOCRC.match(payload_line)
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
        ocr_safe_flexible = None
        if (
            ocr_safe_profile
            and not match
            and not match_no_crc
            and not match_nosep
            and not match_nosep_no_crc
            and not chunk_match
            and not chunk_no_crc
        ):
            ocr_safe_flexible = _parse_ocr_safe_structured_line(
                payload_line,
                current_page_no=current_page_no,
                source_line_no=source_line_no,
            )
        if ocr_safe_flexible is not None:
            fallback_used = True
            line_has_crc = bool(ocr_safe_flexible.get("line_has_crc"))
            line_index_kind = str(ocr_safe_flexible.get("line_index_kind") or "full")
            page_no = int(ocr_safe_flexible.get("page_no", 0))
            line_no = int(ocr_safe_flexible.get("line_no", source_line_no))
            chunk_idx = int(ocr_safe_flexible.get("chunk_idx", -1))
            payload = _normalize_extracted_payload(
                str(ocr_safe_flexible.get("payload") or ""),
                payload_alphabet_profile,
            )
            given_crc = str(ocr_safe_flexible.get("given_crc") or "")
            if bool(ocr_safe_flexible.get("separator_missing")):
                line_warnings.append(
                    {
                        "line_no": source_line_no,
                        "reason": "line_separator_missing",
                        "chunk_idx": chunk_idx,
                    }
                )
        elif (
            not match
            and not match_no_crc
            and not match_nosep
            and not match_nosep_no_crc
            and not chunk_match
            and not chunk_no_crc
        ):
            fallback = protocol.LINE_PATTERN_FALLBACK.match(payload_line)
            fallback_no_crc = protocol.LINE_PATTERN_FALLBACK_NOCRC.match(payload_line) if (not fallback) else None
            chunk_fallback = (
                protocol.CHUNK_PATTERN_FALLBACK.match(payload_line) if (not fallback and not fallback_no_crc) else None
            )
            chunk_fallback_no_crc = (
                protocol.CHUNK_PATTERN_FALLBACK_NOCRC.match(payload_line)
                if (not fallback and not fallback_no_crc and not chunk_fallback)
                else None
            )
            if fallback:
                fallback_used = True
                line_has_crc = True
                page_token = protocol.normalize_page_line_token(fallback.group(1))
                line_token = protocol.normalize_page_line_token(fallback.group(2))
                chunk_token = protocol.normalize_digit_token(fallback.group(4))
                crc_token = protocol.normalize_hex_token(fallback.group(6))
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
                payload = _normalize_extracted_payload(
                    fallback.group(5),
                    payload_alphabet_profile,
                )
                given_crc = crc_token
            elif fallback_no_crc:
                fallback_used = True
                line_has_crc = False
                page_token = protocol.normalize_page_line_token(fallback_no_crc.group(1))
                line_token = protocol.normalize_page_line_token(fallback_no_crc.group(2))
                chunk_token = protocol.normalize_digit_token(fallback_no_crc.group(4))
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
                payload = _normalize_extracted_payload(
                    fallback_no_crc.group(5),
                    payload_alphabet_profile,
                )
                given_crc = ""
            elif chunk_fallback:
                fallback_used = True
                line_has_crc = True
                line_index_kind = "chunk"
                page_no = int(current_page_no) if current_page_no > 0 else 0
                line_no = int(source_line_no)
                chunk_token = protocol.normalize_digit_token(chunk_fallback.group(1))
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
                payload = _normalize_extracted_payload(
                    chunk_fallback.group(3),
                    payload_alphabet_profile,
                )
                given_crc = protocol.normalize_hex_token(chunk_fallback.group(4))
            elif chunk_fallback_no_crc:
                fallback_used = True
                line_has_crc = False
                line_index_kind = "chunk"
                page_no = int(current_page_no) if current_page_no > 0 else 0
                line_no = int(source_line_no)
                chunk_token = protocol.normalize_digit_token(chunk_fallback_no_crc.group(1))
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
                payload = _normalize_extracted_payload(
                    chunk_fallback_no_crc.group(3),
                    payload_alphabet_profile,
                )
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
            payload = _normalize_extracted_payload(match.group(5), payload_alphabet_profile)
            given_crc = match.group(6)
            line_index_kind = "full"
        elif match_nosep_no_crc:
            line_has_crc = False
            page_no = int(protocol.normalize_page_line_token(match_nosep_no_crc.group(1)))
            line_no = int(protocol.normalize_page_line_token(match_nosep_no_crc.group(2)))
            chunk_idx = int(protocol.normalize_digit_token(match_nosep_no_crc.group(3)))
            payload = _normalize_extracted_payload(
                match_nosep_no_crc.group(4),
                payload_alphabet_profile,
            )
            given_crc = ""
            line_index_kind = "full"
            possible_crc = protocol.normalize_hex_token(payload[-4:]) if len(payload) >= 5 else ""
            if len(possible_crc) == 4:
                payload_candidate = payload[:-4]
                core_candidate = "C{:05d}|{}".format(chunk_idx, payload_candidate)
                if payload_candidate and protocol.crc16_hex(core_candidate) == possible_crc:
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
            page_no = int(protocol.normalize_page_line_token(match_nosep.group(1)))
            line_no = int(protocol.normalize_page_line_token(match_nosep.group(2)))
            chunk_idx = int(protocol.normalize_digit_token(match_nosep.group(3)))
            payload = _normalize_extracted_payload(
                match_nosep.group(4),
                payload_alphabet_profile,
            )
            given_crc = protocol.normalize_hex_token(match_nosep.group(5))
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
            payload = _normalize_extracted_payload(chunk_match.group(3), payload_alphabet_profile)
            given_crc = chunk_match.group(4)
        elif chunk_no_crc:
            line_has_crc = False
            line_index_kind = "chunk"
            page_no = int(current_page_no) if current_page_no > 0 else 0
            line_no = int(source_line_no)
            chunk_idx = int(chunk_no_crc.group(1))
            payload = _normalize_extracted_payload(chunk_no_crc.group(3), payload_alphabet_profile)
            given_crc = ""
        else:
            line_has_crc = False
            page_no = int(match_no_crc.group(1))
            line_no = int(match_no_crc.group(2))
            chunk_idx = int(match_no_crc.group(4))
            payload = _normalize_extracted_payload(match_no_crc.group(5), payload_alphabet_profile)
            given_crc = ""
            line_index_kind = "full"

        if (not ocr_safe_profile) and strict_payload_chars:
            invalid_chars = [ch for ch in payload if ch not in payload_alphabet]
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
        elif not ocr_safe_profile:
            payload = "".join(ch for ch in payload if ch in payload_alphabet)
            if not payload:
                line_errors.append(
                    {
                        "line_no": source_line_no,
                        "reason": "empty_payload_after_normalize",
                        "chunk_idx": chunk_idx,
                    }
                )
                continue

        expected_len = None
        if isinstance(chunk_lengths, list) and 0 <= chunk_idx < len(chunk_lengths):
            try:
                expected_len = int(chunk_lengths[chunk_idx])
            except Exception:
                expected_len = None

        core = "C{:05d}|{}".format(chunk_idx, payload)
        expect_crc = protocol.crc16_hex(core)
        if ocr_safe_profile:
            resolved_payload = _resolve_ocr_safe_payload(
                raw_payload=payload,
                raw_text=str(raw),
                core_prefix="C{:05d}|".format(chunk_idx),
                expected_crc=given_crc,
                line_has_crc=line_has_crc,
                expected_len=expected_len,
                page_no=page_no,
                line_no=line_no,
                source_line_no=source_line_no,
                chunk_idx=chunk_idx,
                line_errors=line_errors,
                line_warnings=line_warnings,
                correction_records=correction_records,
                correction_rows=correction_rows,
                correction_applied=correction_applied,
                correction_invalid=correction_invalid,
            )
            if resolved_payload is None:
                continue
            payload = resolved_payload
            core = "C{:05d}|{}".format(chunk_idx, payload)
            expect_crc = protocol.crc16_hex(core)
        elif line_has_crc and expect_crc != given_crc:
            repaired = transport._repair_payload_candidate_by_crc(
                payload=payload,
                core_prefix="C{:05d}|".format(chunk_idx),
                expected_crc=given_crc,
            )
            if repaired != payload:
                payload = repaired
                core = "C{:05d}|{}".format(chunk_idx, payload)
                expect_crc = protocol.crc16_hex(core)
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
        actual_crc = protocol.crc16_hex("\n".join(base))
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
        "correction_records": correction_records,
        "correction_replay": _correction_replay_summary(
            correction_metadata,
            correction_applied,
            correction_invalid,
        ),
    }


def choose_majority_metadata_value(label: str, votes: Dict[object, int]) -> Optional[object]:
    if not votes:
        return None
    ranked = sorted(votes.items(), key=lambda kv: (-int(kv[1]), str(kv[0])))
    if len(ranked) > 1 and int(ranked[0][1]) == int(ranked[1][1]) and ranked[0][0] != ranked[1][0]:
        raise ValueError("conflicting {} values in OCR metadata: {}".format(label, [item[0] for item in ranked[:5]]))
    return ranked[0][0]


def scan_transport_metadata(transport, ocr_input_path: str) -> Dict[str, object]:
    raw_lines = transport._read_ocr_lines(ocr_input_path)
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
        "EL": {},
    }
    cfg_text_votes: Dict[str, Dict[str, int]] = {
        "PF": {},
        "PM": {},
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
        line = protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))
        if not line:
            continue

        meta_match = protocol.META_PATTERN.match(line)
        if meta_match:
            _add_vote(artifact_votes, meta_match.group(1))
            _add_vote(total_page_votes, int(meta_match.group(3)))
            _add_vote(total_chunk_votes, int(meta_match.group(5)))
            continue

        cfg = protocol.parse_cfg_line(line)
        if cfg:
            for key, value in cfg.items():
                if key in cfg_text_votes:
                    _add_vote(cfg_text_votes[key], str(value))
                else:
                    _add_vote(cfg_votes[key], int(value))
            continue

        hash_fragment = protocol.parse_hash_fragment_line(line)
        if hash_fragment:
            kind, part_no, fragment = hash_fragment
            _add_vote(hash_votes["{}{}".format(kind, part_no)], fragment)
            continue

        hash_compact = protocol.parse_hash_compact_line(line)
        if hash_compact:
            part_no, raw_fragment, compressed_fragment = hash_compact
            _add_vote(hash_votes["RH{}".format(part_no)], raw_fragment)
            _add_vote(hash_votes["CH{}".format(part_no)], compressed_fragment)
            continue

        match = protocol.LINE_PATTERN.match(line)
        if match:
            full_index_candidates += 1
            chunk_idx = int(match.group(4))
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue
        match_no_crc = protocol.LINE_PATTERN_NOCRC.match(line)
        if match_no_crc:
            full_index_candidates += 1
            chunk_idx = int(match_no_crc.group(4))
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue
        match_nosep_no_crc = protocol.LINE_PATTERN_NOSEP_NOCRC.match(line)
        if match_nosep_no_crc:
            full_index_candidates += 1
            try:
                chunk_idx = int(protocol.normalize_digit_token(match_nosep_no_crc.group(3)))
            except Exception:
                chunk_idx = -1
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue
        match_nosep = protocol.LINE_PATTERN_NOSEP.match(line)
        if match_nosep:
            full_index_candidates += 1
            try:
                chunk_idx = int(protocol.normalize_digit_token(match_nosep.group(3)))
            except Exception:
                chunk_idx = -1
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue

        chunk_match = protocol.CHUNK_PATTERN.match(line)
        if chunk_match:
            chunk_index_candidates += 1
            chunk_idx = int(chunk_match.group(1))
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue
        chunk_no_crc = protocol.CHUNK_PATTERN_NOCRC.match(line)
        if chunk_no_crc:
            chunk_index_candidates += 1
            chunk_idx = int(chunk_no_crc.group(1))
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue

        fallback = protocol.LINE_PATTERN_FALLBACK.match(line)
        if fallback:
            full_index_candidates += 1
            try:
                chunk_idx = int(protocol.normalize_digit_token(fallback.group(4)))
            except Exception:
                continue
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue
        fallback_no_crc = protocol.LINE_PATTERN_FALLBACK_NOCRC.match(line)
        if fallback_no_crc:
            full_index_candidates += 1
            try:
                chunk_idx = int(protocol.normalize_digit_token(fallback_no_crc.group(4)))
            except Exception:
                continue
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue

        chunk_fallback = protocol.CHUNK_PATTERN_FALLBACK.match(line)
        if chunk_fallback:
            chunk_index_candidates += 1
            try:
                chunk_idx = int(protocol.normalize_digit_token(chunk_fallback.group(1)))
            except Exception:
                continue
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue
        chunk_fallback_no_crc = protocol.CHUNK_PATTERN_FALLBACK_NOCRC.match(line)
        if chunk_fallback_no_crc:
            chunk_index_candidates += 1
            try:
                chunk_idx = int(protocol.normalize_digit_token(chunk_fallback_no_crc.group(1)))
            except Exception:
                continue
            if 0 <= chunk_idx < 90000:
                max_data_chunk_idx = max(max_data_chunk_idx, chunk_idx)
            continue

        if protocol.PAYLOAD_WITH_CRC_PATTERN.match(line) or protocol.PAYLOAD_WITH_CRC_FALLBACK_PATTERN.match(line):
            payload_only_candidates += 1
            continue
        if line and (line[0] in protocol.SAFE_BASE32_ALPHABET):
            payload_only_candidates += 1

    artifact_id = choose_majority_metadata_value("artifact_id", artifact_votes)
    total_chunks = choose_majority_metadata_value("total_chunks", total_chunk_votes)
    total_pages = choose_majority_metadata_value("total_pages", total_page_votes)

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
        value = choose_majority_metadata_value(key, bucket)
        if value is not None:
            metadata[key] = int(value)

    for key, bucket in cfg_text_votes.items():
        value = choose_majority_metadata_value(key, bucket)
        if value is not None:
            metadata[key] = str(value)

    for key, bucket in hash_votes.items():
        value = choose_majority_metadata_value(key, bucket)
        if value is not None:
            metadata[key] = str(value)

    if all(key in metadata for key in ("RH1", "RH2", "CH1", "CH2", "CC", "LP", "RC", "IL", "PG", "CS", "RS")):
        metadata["metadata_source"] = "embedded_headers"
    return metadata


def build_inferred_manifest_from_ocr(transport, ocr_input_path: str) -> Dict[str, object]:
    metadata = scan_transport_metadata(transport, ocr_input_path)
    manifest: Dict[str, object] = {
        "protocol_version": protocol.PROTOCOL_VERSION,
        "artifact_id": metadata["artifact_id"],
        "total_chunks": int(metadata["total_chunks"]),
        "total_pages": int(metadata.get("total_pages", 0) or 0),
        "lines_per_page": int(metadata.get("LP", transport.lines_per_page) or transport.lines_per_page),
        "transport_line_index_mode": str(metadata.get("transport_line_index_mode", "full")),
        "_metadata_source": metadata["metadata_source"],
        "_embedded_metadata_complete": False,
    }

    required = ("RH1", "RH2", "CH1", "CH2", "CC", "LP", "RC", "IL", "PG", "CS", "RS")
    if not all(key in metadata for key in required):
        return manifest

    chunk_chars = int(metadata["CC"])
    compressed_size = int(metadata["CS"])
    payload_alphabet_profile = protocol.canonical_payload_profile(metadata.get("PF"))
    encoded_len = int(
        metadata.get("EL")
        or protocol.encoded_payload_length_for_profile(compressed_size, payload_alphabet_profile)
    )
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
            "parity": transport._rebuild_parity_manifest(
                total_chunks=total_chunks,
                chunk_lengths=chunk_lengths,
                parity_group_size=parity_group_size,
                payload_alphabet_profile=payload_alphabet_profile,
                parity_symbol_mode=parity_symbol_mode,
            ),
            "_embedded_metadata_complete": True,
        }
    )
    return manifest


def build_missing_chunk_records(
    transport, manifest: Dict[str, object], missing_chunks: List[int]
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

    lines_per_page = int(manifest.get("lines_per_page", transport.lines_per_page))
    if lines_per_page <= 0:
        lines_per_page = transport.lines_per_page
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


def build_missing_chunk_retake_plan(records: List[Dict[str, int]]) -> List[Dict[str, int]]:
    """Pick one highest-priority retake point for each missing chunk."""
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


def count_chunk_presence(chunks: object, total_chunks: int) -> Tuple[int, int]:
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


def apply_parity_recovery(manifest: Dict[str, object], parsed: Dict[str, object]) -> List[int]:
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
    payload_alphabet_profile = manifest.get("payload_alphabet_profile")
    value_map = protocol.payload_value_map_for_profile(payload_alphabet_profile)
    payload_base = len(value_map)
    parity_symbol_mode = str(parity.get("symbol_mode") or "").strip().lower()
    if not parity_symbol_mode:
        parity_symbol_mode = (
            "modular-sum"
            if _payload_profile(payload_alphabet_profile)
            == protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE
            else "xor"
        )

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
            if ch not in value_map:
                vals = []
                break
            vals[pos] = value_map[ch]
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
                if ch not in value_map:
                    ok = False
                    break
                if parity_symbol_mode == "modular-sum":
                    vals[pos] = (vals[pos] - value_map[ch]) % payload_base
                else:
                    vals[pos] ^= value_map[ch]
            if not ok:
                break
        if not ok:
            continue

        candidate = "".join(
            protocol.payload_char_for_value(payload_alphabet_profile, v) for v in vals
        )
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


def downgrade_nonblocking_parity_conflicts(parsed: Dict[str, object], total_chunks: int) -> None:
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


def resolve_conflicts_by_package_hash(
    transport,
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

        transport._apply_parity_recovery(manifest, test_parsed)
        if any(idx not in test_parsed["chunks"] for idx in range(total_chunks)):
            continue

        try:
            encoded = "".join(test_parsed["chunks"][idx] for idx in range(total_chunks))
            compressed = protocol.decode_payload_for_profile(
                encoded,
                manifest.get("payload_alphabet_profile"),
            )
            if protocol.sha256_hex(compressed) != manifest["compressed_sha256"]:
                continue
            raw = zlib.decompress(compressed)
        except Exception:
            continue

        if protocol.sha256_hex(raw) != manifest["raw_sha256"]:
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


def resolve_conflicts_by_structure(
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
            compressed = protocol.decode_safe_base32(encoded)
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


def raise_parse_errors(parsed: Dict[str, object], total_chunks: int) -> None:
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


__all__ = [
    "parse_ocr_chunks",
    "parse_ocr_chunks_payload_only_manifest",
    "parse_ocr_chunks_with_total",
    "choose_majority_metadata_value",
    "scan_transport_metadata",
    "build_inferred_manifest_from_ocr",
    "build_missing_chunk_records",
    "build_missing_chunk_retake_plan",
    "count_chunk_presence",
    "apply_parity_recovery",
    "downgrade_nonblocking_parity_conflicts",
    "resolve_conflicts_by_package_hash",
    "resolve_conflicts_by_structure",
    "raise_parse_errors",
]
