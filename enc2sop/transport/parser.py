"""Transport parser/conflict helpers extracted from qrcode_helper."""

import math
import itertools
import json
import zlib
from typing import Dict, List, Optional, Tuple

from . import protocol


def parse_ocr_chunks(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool,
) -> Dict[str, object]:
    total_chunks = int(manifest["total_chunks"])
    line_index_mode = str(manifest.get("transport_line_index_mode", "full") or "full").strip().lower()
    if line_index_mode == "off":
        return parse_ocr_chunks_payload_only_manifest(
            transport=transport,
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
        )
    return parse_ocr_chunks_with_total(
        transport=transport,
        total_chunks=total_chunks,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
        line_index_mode=line_index_mode,
    )


def parse_ocr_chunks_payload_only_manifest(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool,
) -> Dict[str, object]:
    raw_lines = transport._read_ocr_lines(ocr_input_path)
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
        line = protocol.normalize_protocol_signature(protocol.normalize_ocr_line(raw))
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
        match_with_crc = protocol.PAYLOAD_WITH_CRC_PATTERN.match(line)
        if match_with_crc:
            has_crc = True
            payload = protocol.normalize_payload(match_with_crc.group(1))
            given_crc = protocol.normalize_hex_token(match_with_crc.group(3))
        else:
            match_fallback_crc = protocol.PAYLOAD_WITH_CRC_FALLBACK_PATTERN.match(line)
            if match_fallback_crc:
                has_crc = True
                payload = protocol.normalize_payload(match_fallback_crc.group(1))
                given_crc = protocol.normalize_hex_token(match_fallback_crc.group(3))
                line_warnings.append(
                    {
                        "line_no": source_line_no,
                        "reason": "payload_crc_fallback_pattern_used",
                    }
                )
            else:
                payload = protocol.normalize_payload(line)

        if strict_payload_chars:
            invalid_chars = [ch for ch in payload if ch not in protocol.SAFE_BASE32_ALPHABET]
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
            payload = "".join(ch for ch in payload if ch in protocol.SAFE_BASE32_ALPHABET)

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

        core = "C{:05d}|{}".format(chunk_idx, payload)
        expect_crc = protocol.crc16_hex(core)
        if has_crc and expect_crc != given_crc:
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
    }


def parse_ocr_chunks_with_total(
    transport,
    total_chunks: int,
    ocr_input_path: str,
    strict_payload_chars: bool,
    line_index_mode: str = "full",
) -> Dict[str, object]:
    raw_lines = transport._read_ocr_lines(ocr_input_path)
    chunk_votes = {}
    page_lines_for_crc = {}
    page_meta_extra_for_crc = {}
    page_meta = {}
    page_crc_expect = {}
    line_errors = []
    line_warnings = []
    current_page_no = 0

    for source_line_no, raw in enumerate(raw_lines, 1):
        line = protocol.normalize_ocr_line(raw)
        if not line:
            continue
        line = protocol.normalize_protocol_signature(line)

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

        match = protocol.LINE_PATTERN.match(line)
        match_no_crc = protocol.LINE_PATTERN_NOCRC.match(line) if (not match) else None
        match_nosep_no_crc = (
            protocol.LINE_PATTERN_NOSEP_NOCRC.match(line)
            if (not match and not match_no_crc)
            else None
        )
        match_nosep = (
            protocol.LINE_PATTERN_NOSEP.match(line)
            if (not match and not match_no_crc and not match_nosep_no_crc)
            else None
        )
        chunk_match = (
            protocol.CHUNK_PATTERN.match(line)
            if (not match and not match_no_crc and not match_nosep and not match_nosep_no_crc)
            else None
        )
        chunk_no_crc = (
            protocol.CHUNK_PATTERN_NOCRC.match(line)
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
        if (
            not match
            and not match_no_crc
            and not match_nosep
            and not match_nosep_no_crc
            and not chunk_match
            and not chunk_no_crc
        ):
            fallback = protocol.LINE_PATTERN_FALLBACK.match(line)
            fallback_no_crc = protocol.LINE_PATTERN_FALLBACK_NOCRC.match(line) if (not fallback) else None
            chunk_fallback = (
                protocol.CHUNK_PATTERN_FALLBACK.match(line) if (not fallback and not fallback_no_crc) else None
            )
            chunk_fallback_no_crc = (
                protocol.CHUNK_PATTERN_FALLBACK_NOCRC.match(line)
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
                payload = protocol.normalize_payload(fallback.group(5))
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
                payload = protocol.normalize_payload(fallback_no_crc.group(5))
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
                payload = protocol.normalize_payload(chunk_fallback.group(3))
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
                payload = protocol.normalize_payload(chunk_fallback_no_crc.group(3))
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
            payload = protocol.normalize_payload(match.group(5))
            given_crc = match.group(6)
            line_index_kind = "full"
        elif match_nosep_no_crc:
            line_has_crc = False
            page_no = int(protocol.normalize_page_line_token(match_nosep_no_crc.group(1)))
            line_no = int(protocol.normalize_page_line_token(match_nosep_no_crc.group(2)))
            chunk_idx = int(protocol.normalize_digit_token(match_nosep_no_crc.group(3)))
            payload = protocol.normalize_payload(match_nosep_no_crc.group(4))
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
            payload = protocol.normalize_payload(match_nosep.group(4))
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
            payload = protocol.normalize_payload(chunk_match.group(3))
            given_crc = chunk_match.group(4)
        elif chunk_no_crc:
            line_has_crc = False
            line_index_kind = "chunk"
            page_no = int(current_page_no) if current_page_no > 0 else 0
            line_no = int(source_line_no)
            chunk_idx = int(chunk_no_crc.group(1))
            payload = protocol.normalize_payload(chunk_no_crc.group(3))
            given_crc = ""
        else:
            line_has_crc = False
            page_no = int(match_no_crc.group(1))
            line_no = int(match_no_crc.group(2))
            chunk_idx = int(match_no_crc.group(4))
            payload = protocol.normalize_payload(match_no_crc.group(5))
            given_crc = ""
            line_index_kind = "full"

        if strict_payload_chars:
            invalid_chars = [ch for ch in payload if ch not in protocol.SAFE_BASE32_ALPHABET]
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
            payload = "".join(ch for ch in payload if ch in protocol.SAFE_BASE32_ALPHABET)
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
        expect_crc = protocol.crc16_hex(core)
        if line_has_crc and expect_crc != given_crc:
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
    encoded_len = protocol.safe_base32_encoded_length(compressed_size)
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
            "parity": transport._rebuild_parity_manifest(
                total_chunks=total_chunks,
                chunk_lengths=chunk_lengths,
                parity_group_size=parity_group_size,
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
            if ch not in protocol.SAFE_CHAR_TO_VAL:
                vals = []
                break
            vals[pos] = protocol.SAFE_CHAR_TO_VAL[ch]
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
                if ch not in protocol.SAFE_CHAR_TO_VAL:
                    ok = False
                    break
                vals[pos] ^= protocol.SAFE_CHAR_TO_VAL[ch]
            if not ok:
                break
        if not ok:
            continue

        candidate = "".join(protocol.SAFE_BASE32_ALPHABET[v] for v in vals)
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
            compressed = protocol.decode_safe_base32(encoded)
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
