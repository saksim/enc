"""Transport recover/verify/analyze orchestration extracted from qrcode_helper."""

import zlib
from pathlib import Path
from typing import Dict, Optional

from . import cli
from . import parser
from . import protocol


def recover_artifact(
    transport,
    manifest_path: Optional[str],
    ocr_input_path: str,
    output_file: str,
    strict_payload_chars: bool = False,
) -> Dict[str, object]:
    if not manifest_path:
        return recover_artifact_without_manifest(
            transport=transport,
            ocr_input_path=ocr_input_path,
            output_file=output_file,
            strict_payload_chars=strict_payload_chars,
        )

    manifest = transport._load_manifest(manifest_path)
    return recover_artifact_against_manifest(
        transport=transport,
        manifest=manifest,
        ocr_input_path=ocr_input_path,
        output_file=output_file,
        strict_payload_chars=strict_payload_chars,
    )


def recover_artifact_against_manifest(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    output_file: str,
    strict_payload_chars: bool = False,
) -> Dict[str, object]:
    encoded = recover_encoded_payload(transport, manifest, ocr_input_path, strict_payload_chars)
    compressed = protocol.decode_safe_base32(encoded)
    compressed_sha = protocol.sha256_hex(compressed)
    if compressed_sha != manifest["compressed_sha256"]:
        raise ValueError(
            "compressed sha256 mismatch: expected {}, got {}".format(
                manifest["compressed_sha256"], compressed_sha
            )
        )

    raw = zlib.decompress(compressed)
    raw_sha = protocol.sha256_hex(raw)
    if raw_sha != manifest["raw_sha256"]:
        raise ValueError(
            "raw sha256 mismatch: expected {}, got {}".format(manifest["raw_sha256"], raw_sha)
        )
    if len(raw) != int(manifest["raw_size"]):
        raise ValueError("raw size mismatch: expected {}, got {}".format(manifest["raw_size"], len(raw)))

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
    transport,
    manifest_path: Optional[str],
    ocr_input_path: str,
    strict_payload_chars: bool = False,
) -> Dict[str, object]:
    if not manifest_path:
        return verify_ocr_text_without_manifest(
            transport=transport,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
        )

    manifest = transport._load_manifest(manifest_path)
    return verify_ocr_text_against_manifest(
        transport=transport,
        manifest=manifest,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
    )


def verify_ocr_text_against_manifest(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool = False,
) -> Dict[str, object]:
    encoded = recover_encoded_payload(transport, manifest, ocr_input_path, strict_payload_chars)
    compressed = protocol.decode_safe_base32(encoded)
    compressed_sha = protocol.sha256_hex(compressed)

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
    transport,
    manifest_path: Optional[str],
    ocr_input_path: str,
    strict_payload_chars: bool = False,
    max_list: int = 200,
    save_report_path: Optional[str] = None,
    emit_missing_file: Optional[str] = None,
) -> Dict[str, object]:
    if manifest_path:
        manifest = transport._load_manifest(manifest_path)
    else:
        manifest = transport._build_inferred_manifest_from_ocr(ocr_input_path)
    return analyze_ocr_text_against_manifest(
        transport=transport,
        manifest=manifest,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
        max_list=max_list,
        save_report_path=save_report_path,
        emit_missing_file=emit_missing_file,
    )


def analyze_ocr_text_against_manifest(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool = False,
    max_list: int = 200,
    save_report_path: Optional[str] = None,
    emit_missing_file: Optional[str] = None,
) -> Dict[str, object]:
    parsed = transport._parse_ocr_chunks(manifest, ocr_input_path, strict_payload_chars)
    parity_recovered = parser.apply_parity_recovery(manifest, parsed)
    hash_resolved = parser.resolve_conflicts_by_package_hash(transport, manifest, parsed)
    parity_recovered_after_hash = parser.apply_parity_recovery(manifest, parsed)
    total_chunks = int(manifest["total_chunks"])
    parser.downgrade_nonblocking_parity_conflicts(parsed, total_chunks)
    parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
    received_data_chunks, received_parity_chunks = parser.count_chunk_presence(
        parsed.get("chunks", {}), total_chunks
    )

    missing = parsed["missing_chunks"]
    missing_records = parser.build_missing_chunk_records(transport, manifest, missing)
    retake_plan = parser.build_missing_chunk_retake_plan(missing_records)
    cap = max(0, int(max_list))
    recoverable = (
        len(parsed["line_errors"]) == 0 and len(parsed["duplicate_conflicts"]) == 0 and len(missing) == 0
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
        result["missing_file_path"] = cli.save_missing_chunks(emit_missing_file, missing_records)
    if save_report_path:
        result["report_path"] = cli.save_json(save_report_path, result)
    return result


def verify_ocr_text_without_manifest(
    transport,
    ocr_input_path: str,
    strict_payload_chars: bool = False,
) -> Dict[str, object]:
    manifest = transport._build_inferred_manifest_from_ocr(ocr_input_path)
    if str(manifest.get("transport_line_index_mode", "full")) == "off":
        raise ValueError("payload-only transport requires manifest for verify")
    metadata_source = str(manifest.get("_metadata_source", "unknown"))
    if manifest.get("_embedded_metadata_complete"):
        encoded = recover_encoded_payload(transport, manifest, ocr_input_path, strict_payload_chars)
        compressed = protocol.decode_safe_base32(encoded)
        compressed_sha = protocol.sha256_hex(compressed)
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
        raw_sha = protocol.sha256_hex(raw)
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
    parsed = transport._parse_ocr_chunks_with_total(
        total_chunks=total_chunks,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
    )
    parser.resolve_conflicts_by_structure(parsed=parsed, total_chunks=total_chunks)
    parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
    parser.raise_parse_errors(parsed, total_chunks)

    encoded = "".join(parsed["chunks"][i] for i in range(total_chunks))
    compressed = protocol.decode_safe_base32(encoded)
    raw = zlib.decompress(compressed)

    return {
        "success": True,
        "artifact_id": manifest["artifact_id"],
        "expected_total_chunks": total_chunks,
        "received_unique_chunks": len(parsed["chunks"]),
        "raw_size": len(raw),
        "raw_sha256": protocol.sha256_hex(raw),
        "metadata_source": metadata_source,
        "verification_mode": "structural_only",
        "message": "structural verify ok without manifest; sha comparison unavailable",
        "warning": "manifest not provided and embedded metadata was incomplete; verification is structural only",
    }


def recover_artifact_without_manifest(
    transport,
    ocr_input_path: str,
    output_file: str,
    strict_payload_chars: bool = False,
) -> Dict[str, object]:
    manifest = transport._build_inferred_manifest_from_ocr(ocr_input_path)
    if str(manifest.get("transport_line_index_mode", "full")) == "off":
        raise ValueError("payload-only transport requires manifest for recover")
    metadata_source = str(manifest.get("_metadata_source", "unknown"))
    if manifest.get("_embedded_metadata_complete"):
        result = recover_artifact_against_manifest(
            transport=transport,
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
    parsed = transport._parse_ocr_chunks_with_total(
        total_chunks=total_chunks,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
    )
    parser.resolve_conflicts_by_structure(parsed=parsed, total_chunks=total_chunks)
    parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
    parser.raise_parse_errors(parsed, total_chunks)

    encoded = "".join(parsed["chunks"][i] for i in range(total_chunks))
    compressed = protocol.decode_safe_base32(encoded)
    raw = zlib.decompress(compressed)

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(raw)

    return {
        "success": True,
        "artifact_id": manifest["artifact_id"],
        "output_file": str(out_path),
        "raw_size": len(raw),
        "raw_sha256": protocol.sha256_hex(raw),
        "compressed_sha256": protocol.sha256_hex(compressed),
        "metadata_source": metadata_source,
        "verification_mode": "structural_only",
        "message": "recovered without manifest",
        "warning": "manifest not provided and embedded metadata was incomplete; parity recovery and end-to-end sha verification were unavailable",
    }


def recover_encoded_payload(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool,
) -> str:
    total_chunks = int(manifest["total_chunks"])
    parsed = transport._parse_ocr_chunks(manifest, ocr_input_path, strict_payload_chars)
    parser.apply_parity_recovery(manifest, parsed)
    parser.resolve_conflicts_by_package_hash(transport, manifest, parsed)
    parser.apply_parity_recovery(manifest, parsed)
    parser.downgrade_nonblocking_parity_conflicts(parsed, total_chunks)
    parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
    parser.raise_parse_errors(parsed, total_chunks)
    ordered = [parsed["chunks"][i] for i in range(total_chunks)]
    return "".join(ordered)


__all__ = [
    "recover_artifact",
    "recover_artifact_against_manifest",
    "verify_ocr_text",
    "verify_ocr_text_against_manifest",
    "analyze_ocr_text",
    "analyze_ocr_text_against_manifest",
    "verify_ocr_text_without_manifest",
    "recover_artifact_without_manifest",
    "recover_encoded_payload",
]
