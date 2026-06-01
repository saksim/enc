#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Prepare and certify a real-capture text transport round trip.

This script is an operator harness around the existing platform primitives:

1. encrypt text with encryption_helper.encrypt_snippet()
2. export the encrypted artifact as OCR-safe transport pages
3. wait for an operator to put photos/scans in a prepared capture directory
4. run the existing capture evidence pipeline and verify the recovered text hash

It is intentionally not a new transport protocol and does not broaden any
production claim. Production claims still require the matching
certify-capture-evidence gate and a replayable evidence archive.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Crypto.Cipher import AES

import encryption_helper
import qrcode_helper
from enc2sop.keys import get_key_provider
from enc2sop.transport import certify as transport_certify
from enc2sop.transport import protocol


TEXT_ARTIFACT_SCHEMA = "enc2sop-real-capture-text-artifact/v1"
FLOW_MANIFEST_SCHEMA = "enc2sop-real-capture-text-flow/v1"
ROUNDTRIP_VERIFICATION_SCHEMA = "enc2sop-real-capture-text-roundtrip-verification/v1"

DEFAULT_LABEL = "text-capture-0001"
DEFAULT_PROFILE = "reliable-airgap-v1"
DEFAULT_PAYLOAD_ALPHABET_PROFILE = "ocr-safe-human-correctable-v1"
CLAIM_NONE = "none"
CLAIM_PHYSICAL_PRINT_SCAN = "physical-print-scan"
CLAIM_REAL_CAMERA_PERSPECTIVE = "real-camera-perspective-correction"
SUPPORTED_CLAIMS = (
    CLAIM_NONE,
    CLAIM_PHYSICAL_PRINT_SCAN,
    CLAIM_REAL_CAMERA_PERSPECTIVE,
)
SUPPORTED_CAPTURE_KINDS = ("camera-photo", "print-scan")


def _repo_root() -> Path:
    return REPO_ROOT


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    return _sha256_bytes(path.read_bytes())


def _write_json(path: Path, payload: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _safe_relative(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve())).replace("\\", "/")
    except Exception:
        return str(path.resolve()).replace("\\", "/")


def _label_slug(value: str) -> str:
    text = str(value or "").strip()
    text = re.sub(r"[^0-9A-Za-z_.-]+", "-", text).strip(".-")
    return text or DEFAULT_LABEL


def _parse_metadata_items(items: Optional[Iterable[str]]) -> Dict[str, str]:
    metadata: Dict[str, str] = {}
    for raw in items or []:
        key, sep, value = str(raw).partition("=")
        key = key.strip()
        if not sep or not key:
            raise ValueError("capture metadata must use KEY=VALUE form: {}".format(raw))
        metadata[key] = value.strip()
    return metadata


def _read_text_input(args: argparse.Namespace) -> str:
    if args.text_file:
        return Path(args.text_file).read_text(encoding=args.encoding)
    return str(args.text)


def _build_encrypted_text_artifact(
    text: str,
    *,
    label: str,
    key_mode: str = "local-embedded",
) -> Dict[str, Any]:
    text_bytes = text.encode("utf-8")
    encrypted_payload, key_bytes = encryption_helper.encrypt_snippet(text)
    key_ref = encryption_helper.pack_key_reference(key_bytes, key_mode)
    return {
        "schema": TEXT_ARTIFACT_SCHEMA,
        "created_at_utc": protocol.utc_now_iso(),
        "label": label,
        "plaintext": {
            "encoding": "utf-8",
            "size_bytes": len(text_bytes),
            "sha256": _sha256_bytes(text_bytes),
        },
        "encryption": {
            "implementation": "encryption_helper.encrypt_snippet",
            "algorithm": "aes-256-gcm",
            "key_mode": key_mode,
            "payload": list(encrypted_payload),
            "key_ref": key_ref,
        },
        "certification_boundary": (
            "This is a self-contained encrypted text artifact for transport "
            "round-trip testing. It is not a production release bundle and "
            "does not certify any capture medium without a passing transport "
            "evidence pipeline and matching claim gate."
        ),
    }


def _decrypt_text_artifact_bytes(raw: bytes) -> Dict[str, Any]:
    artifact = json.loads(raw.decode("utf-8-sig"))
    if artifact.get("schema") != TEXT_ARTIFACT_SCHEMA:
        raise ValueError("unsupported text artifact schema")
    encryption = artifact.get("encryption")
    if not isinstance(encryption, dict):
        raise ValueError("text artifact encryption block missing")
    payload = encryption.get("payload")
    if not isinstance(payload, list) or len(payload) != 3:
        raise ValueError("text artifact payload must contain nonce, tag, and body")
    key_ref = encryption.get("key_ref")
    if not isinstance(key_ref, dict):
        raise ValueError("text artifact key_ref missing")
    key_mode = str(key_ref.get("mode") or "").strip()
    key = get_key_provider(key_mode).resolve_key(key_ref)
    nonce_b64, tag_b64, body_b64 = payload
    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=base64.b64decode(nonce_b64))
    plaintext = cipher.decrypt_and_verify(
        base64.b64decode(body_b64),
        base64.b64decode(tag_b64),
    )
    return {
        "text": plaintext.decode("utf-8"),
        "plaintext_sha256": _sha256_bytes(plaintext),
        "expected_plaintext_sha256": str(
            artifact.get("plaintext", {}).get("sha256") or ""
        ),
    }


def _default_classification(capture_kind: str) -> str:
    return "real" if capture_kind == "camera-photo" else "lab"


def _base_capture_metadata(args: argparse.Namespace, capture_kind: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    metadata.update(_parse_metadata_items(args.capture_metadata))
    if args.capture_session_id:
        metadata["capture_session_id"] = args.capture_session_id
    if args.operator:
        metadata["operator"] = args.operator
    if args.captured_at_utc:
        metadata["captured_at_utc"] = args.captured_at_utc
    if args.device:
        metadata["device"] = args.device
    if capture_kind == "camera-photo":
        if args.camera or args.device:
            metadata["camera"] = args.camera or args.device
    if capture_kind == "print-scan":
        if args.printer:
            metadata["printer"] = args.printer
        if args.scanner or args.device:
            metadata["scanner"] = args.scanner or args.device
        if args.dpi:
            metadata["dpi"] = args.dpi
    return metadata


def _transport_params_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "max_compressed_kib": int(args.max_compressed_kib),
        "chunk_chars": int(args.chunk_chars),
        "lines_per_page": int(args.lines_per_page),
        "font_size": int(args.font_size),
        "font_max_size": int(args.font_max_size),
        "font_fit_mode": args.font_fit_mode,
        "metadata_level": "compact",
        "line_index_mode": "full",
        "line_crc_mode": "on",
        "line_separator": "|",
        "render_sidecar": True,
        "payload_alphabet_profile": args.payload_alphabet_profile,
        "redundancy_copies": int(args.redundancy_copies),
        "interleave": not bool(args.no_interleave),
        "parity_group_size": int(args.parity_group_size),
        "filename_prefix": args.filename_prefix,
    }


def _transport_from_params(params: Dict[str, Any]) -> qrcode_helper.AirgapTransportLayer:
    return qrcode_helper.AirgapTransportLayer(
        max_compressed_kib=int(params.get("max_compressed_kib", 64)),
        chunk_chars=int(params.get("chunk_chars", 24)),
        lines_per_page=int(params.get("lines_per_page", 8)),
        font_size=int(params.get("font_size", 44)),
        font_max_size=int(params.get("font_max_size", 132)),
        font_fit_mode=str(params.get("font_fit_mode") or "target"),
        metadata_level=str(params.get("metadata_level") or "compact"),
        line_index_mode=str(params.get("line_index_mode") or "full"),
        line_crc_mode=str(params.get("line_crc_mode") or "on"),
        line_separator=str(params.get("line_separator") or "|"),
        render_sidecar=bool(params.get("render_sidecar", True)),
        payload_alphabet_profile=str(
            params.get("payload_alphabet_profile") or DEFAULT_PAYLOAD_ALPHABET_PROFILE
        ),
    )


def _relative_digest_records(paths: Iterable[Path], base: Path) -> List[Dict[str, Any]]:
    records = []
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        records.append(
            {
                "path": _safe_relative(path, base),
                "sha256": _sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return records


def _write_metadata_template(path: Path, *, capture_kind: str, label: str) -> Path:
    defaults: Dict[str, Any] = {
        "capture_session_id": "",
        "operator": "",
        "captured_at_utc": "",
        "device": "",
    }
    if capture_kind == "camera-photo":
        defaults["camera"] = ""
    else:
        defaults["printer"] = ""
        defaults["scanner"] = ""
        defaults["dpi"] = ""
    payload = {
        "schema": "enc2sop-real-capture-text-metadata-template/v1",
        "capture_metadata_defaults": defaults,
        "cases": [{"label": label, "capture_metadata": dict(defaults)}],
        "instructions": [
            "Fill real operator/session/timestamp/device values before a production claim run.",
            "Equivalent CLI form: --capture-metadata KEY=VALUE repeated on the certify command.",
        ],
        "certification_boundary": (
            "Metadata is provenance input only. It does not certify a medium "
            "unless the recovery pipeline and requested claim gate pass."
        ),
    }
    return _write_json(path, payload)


def _write_instructions(
    path: Path,
    *,
    work_dir: Path,
    label: str,
    capture_kind: str,
    generated_pages_dir: Path,
    capture_dir: Path,
    raw_capture_dir: Optional[Path],
) -> Path:
    lines = [
        "# Real Capture Text Transport Flow",
        "",
        "1. Use the generated PNG pages from:",
        "   {}".format(generated_pages_dir),
        "2. Photograph or scan every page through the target cross-platform path.",
        "3. Put recovery images in:",
        "   {}".format(capture_dir),
    ]
    if raw_capture_dir is not None:
        lines.extend(
            [
                "4. For a real camera perspective-correction claim, put raw uncorrected photos in:",
                "   {}".format(raw_capture_dir),
                "   Put corrected/deskewed recovery images in the capture directory above.",
            ]
        )
    lines.extend(
        [
            "",
            "Then run one of these commands from the repository root:",
            "",
            "Measured transfer, no production medium claim:",
            "python scripts\\real_capture_text_transport.py certify --work-dir \"{}\" --claim none".format(
                work_dir
            ),
            "",
            "Physical print-scan claim after real printer/scanner metadata is present:",
            "python scripts\\real_capture_text_transport.py certify --work-dir \"{}\" --claim physical-print-scan --capture-metadata captured_at_utc=<UTC> --capture-metadata printer=<printer> --capture-metadata scanner=<scanner> --capture-metadata dpi=<dpi>".format(
                work_dir
            ),
            "",
            "Real camera perspective-correction claim after raw and corrected images are present:",
            "python scripts\\real_capture_text_transport.py certify --work-dir \"{}\" --claim real-camera-perspective-correction --capture-metadata captured_at_utc=<UTC> --capture-metadata camera=<camera>".format(
                work_dir
            ),
            "",
            "Supported capture suffixes: {}.".format(
                ", ".join(sorted(transport_certify.CAPTURE_IMAGE_SUFFIXES))
            ),
            "",
            "Certification boundary: this harness only proves the measured files in this work directory.",
            "It does not certify real camera/photo, physical print-scan, or backend OCR unless the matching claim gate passes and the produced archive/status reports say certified=true.",
            "",
            "Case label: {}".format(label),
            "Capture kind: {}".format(capture_kind),
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def prepare_flow(
    args: argparse.Namespace,
    *,
    transport_factory: Callable[[Dict[str, Any]], qrcode_helper.AirgapTransportLayer] = _transport_from_params,
) -> Dict[str, Any]:
    work_dir = Path(args.work_dir).resolve()
    label = _label_slug(args.label)
    capture_kind = args.capture_kind
    classification = args.classification or _default_classification(capture_kind)

    encrypted_dir = work_dir / "encrypted"
    export_dir = work_dir / "export"
    captures_dir = work_dir / "captures"
    raw_captures_dir = work_dir / "raw_captures"
    instructions_dir = work_dir / "instructions"
    capture_dir = captures_dir / label
    raw_capture_dir = raw_captures_dir / label if capture_kind == "camera-photo" else None
    for path in (encrypted_dir, export_dir, capture_dir, instructions_dir):
        path.mkdir(parents=True, exist_ok=True)
    if raw_capture_dir is not None:
        raw_capture_dir.mkdir(parents=True, exist_ok=True)

    text = _read_text_input(args)
    artifact = _build_encrypted_text_artifact(text, label=label, key_mode=args.key_mode)
    artifact_path = encrypted_dir / "encrypted_text_artifact.json"
    _write_json(artifact_path, artifact)

    params = _transport_params_from_args(args)
    transport = transport_factory(params)
    export_result = transport.export_artifact(
        input_file=str(artifact_path),
        output_dir=str(export_dir),
        artifact_id=args.artifact_id,
        filename_prefix=str(params["filename_prefix"]),
        redundancy_copies=int(params["redundancy_copies"]),
        interleave=bool(params["interleave"]),
        parity_group_size=int(params["parity_group_size"]),
    )
    image_paths = [Path(str(path)) for path in export_result.get("images", []) or []]
    if not image_paths:
        raise RuntimeError(
            "transport export did not produce PNG pages; install Pillow or run from a Pillow-enabled environment"
        )

    metadata = _base_capture_metadata(args, capture_kind)
    manifest_path = Path(str(export_result["manifest_path"]))
    generated_pages_dir = export_dir / "pages"
    case_record: Dict[str, Any] = {
        "label": label,
        "classification": classification,
        "capture_medium": capture_kind,
        "manifest_path": _safe_relative(manifest_path, work_dir),
        "payload_path": _safe_relative(artifact_path, work_dir),
        "image_path": _safe_relative(capture_dir, work_dir),
        "reference_image_paths": [
            record["path"] for record in _relative_digest_records(image_paths, work_dir)
        ],
        "capture_metadata": metadata,
        "description": "operator-supplied photos/scans for encrypted text transport round trip",
    }
    if raw_capture_dir is not None:
        case_record["raw_image_paths"] = _safe_relative(raw_capture_dir, work_dir)
        case_record["perspective_correction"] = {
            "applied": True,
            "method": args.perspective_correction_method,
        }

    corpus_path = work_dir / "capture_corpus.json"
    corpus = {
        "schema": transport_certify.CAPTURE_CORPUS_SCHEMA,
        "classification": classification,
        "capture_medium": capture_kind,
        "metadata": {
            "prepared_by": "scripts/real_capture_text_transport.py",
            "profile": DEFAULT_PROFILE,
            "payload_alphabet_profile": params["payload_alphabet_profile"],
            "encrypted_text_artifact_sha256": _sha256_file(artifact_path),
            "plaintext_sha256": artifact["plaintext"]["sha256"],
            "certification_boundary": (
                "Generated pages and empty capture directories are a capture contract only. "
                "Certification starts after operator photos/scans are placed in the capture directories."
            ),
        },
        "cases": [case_record],
    }
    _write_json(corpus_path, corpus)

    kit_manifest_path = work_dir / "capture_kit_manifest.json"
    kit_manifest = {
        "schema": transport_certify.CAPTURE_KIT_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "prepared_by": "scripts/real_capture_text_transport.py prepare",
        "capture_corpus_file": _safe_relative(corpus_path, work_dir),
        "capture_corpus_sha256": _sha256_file(corpus_path),
        "summary": {
            "case_count": 1,
            "classification": classification,
            "capture_medium": capture_kind,
            "generated_page_image_count": len(image_paths),
            "operator_captures_present": 0,
            "operator_raw_captures_present": 0,
        },
        "artifacts": {
            "encrypted_text_artifact_file": _safe_relative(artifact_path, work_dir),
            "encrypted_text_artifact_sha256": _sha256_file(artifact_path),
            "transport_manifest_file": _safe_relative(manifest_path, work_dir),
            "transport_manifest_sha256": _sha256_file(manifest_path),
            "generated_pages_dir": _safe_relative(generated_pages_dir, work_dir),
        },
        "transport_parameters": params,
        "cases": [
            {
                "label": label,
                "capture_dir": _safe_relative(capture_dir, work_dir),
                "raw_capture_dir": (
                    _safe_relative(raw_capture_dir, work_dir)
                    if raw_capture_dir is not None
                    else None
                ),
                "generated_page_images": _relative_digest_records(image_paths, work_dir),
            }
        ],
        "certification_boundary": (
            "This kit proves only that an encrypted-text capture contract was staged. "
            "It is not real camera/photo or physical print-scan evidence until the "
            "capture pipeline measures operator-supplied files and the requested claim gate passes."
        ),
    }
    _write_json(kit_manifest_path, kit_manifest)

    metadata_template_path = _write_metadata_template(
        instructions_dir / "capture_metadata_template.json",
        capture_kind=capture_kind,
        label=label,
    )
    instructions_path = _write_instructions(
        instructions_dir / "NEXT_STEPS_REAL_CAPTURE_TEXT.md",
        work_dir=work_dir,
        label=label,
        capture_kind=capture_kind,
        generated_pages_dir=generated_pages_dir,
        capture_dir=capture_dir,
        raw_capture_dir=raw_capture_dir,
    )
    flow_manifest_path = work_dir / "real_capture_text_flow.json"
    flow_manifest = {
        "schema": FLOW_MANIFEST_SCHEMA,
        "created_at_utc": protocol.utc_now_iso(),
        "work_dir": str(work_dir),
        "label": label,
        "classification": classification,
        "capture_kind": capture_kind,
        "profile": DEFAULT_PROFILE,
        "plaintext_sha256": artifact["plaintext"]["sha256"],
        "encrypted_text_artifact_file": _safe_relative(artifact_path, work_dir),
        "encrypted_text_artifact_sha256": _sha256_file(artifact_path),
        "capture_corpus_file": _safe_relative(corpus_path, work_dir),
        "capture_kit_manifest_file": _safe_relative(kit_manifest_path, work_dir),
        "capture_dir": _safe_relative(capture_dir, work_dir),
        "raw_capture_dir": (
            _safe_relative(raw_capture_dir, work_dir) if raw_capture_dir is not None else None
        ),
        "generated_pages_dir": _safe_relative(generated_pages_dir, work_dir),
        "generated_page_images": _relative_digest_records(image_paths, work_dir),
        "metadata_template_file": _safe_relative(metadata_template_path, work_dir),
        "instructions_file": _safe_relative(instructions_path, work_dir),
        "transport_parameters": params,
        "certification_boundary": kit_manifest["certification_boundary"],
    }
    _write_json(flow_manifest_path, flow_manifest)

    return {
        "schema": "enc2sop-real-capture-text-prepare-result/v1",
        "success": True,
        "work_dir": str(work_dir),
        "flow_manifest_file": str(flow_manifest_path),
        "capture_corpus_file": str(corpus_path),
        "capture_kit_manifest_file": str(kit_manifest_path),
        "encrypted_text_artifact_file": str(artifact_path),
        "generated_pages_dir": str(generated_pages_dir),
        "capture_dir": str(capture_dir),
        "raw_capture_dir": str(raw_capture_dir) if raw_capture_dir is not None else None,
        "instructions_file": str(instructions_path),
        "plaintext_sha256": artifact["plaintext"]["sha256"],
        "generated_page_image_count": len(image_paths),
        "next_command": (
            'python scripts\\real_capture_text_transport.py certify --work-dir "{}" --claim none'.format(
                work_dir
            )
        ),
        "certification_boundary": flow_manifest["certification_boundary"],
    }


def _update_corpus_metadata(
    corpus_path: Path,
    metadata: Dict[str, Any],
    *,
    claim: str,
    perspective_correction_method: Optional[str],
) -> None:
    if not metadata and claim != CLAIM_REAL_CAMERA_PERSPECTIVE:
        return
    corpus = _read_json(corpus_path)
    updated = False
    cases = corpus.get("cases")
    if not isinstance(cases, list):
        raise ValueError("capture corpus cases must be a list")
    for case in cases:
        if not isinstance(case, dict):
            continue
        case_metadata = case.get("capture_metadata")
        if not isinstance(case_metadata, dict):
            case_metadata = {}
        if metadata:
            case_metadata.update(metadata)
            case["capture_metadata"] = case_metadata
            updated = True
        if claim == CLAIM_REAL_CAMERA_PERSPECTIVE:
            perspective = case.get("perspective_correction")
            if not isinstance(perspective, dict):
                perspective = {}
            perspective["applied"] = True
            if perspective_correction_method:
                perspective["method"] = perspective_correction_method
            else:
                perspective.setdefault("method", "operator-supplied perspective correction")
            case["perspective_correction"] = perspective
            updated = True
    if updated:
        _write_json(corpus_path, corpus)


def _claim_gate_options(
    args: argparse.Namespace,
    flow_manifest: Dict[str, Any],
) -> Dict[str, Any]:
    claim = args.claim
    classification = args.capture_required_classification or str(
        flow_manifest.get("classification") or _default_classification(
            str(flow_manifest.get("capture_kind") or "camera-photo")
        )
    )
    return {
        "claim": claim,
        "require_physical_print_scan": claim == CLAIM_PHYSICAL_PRINT_SCAN,
        "require_real_camera_perspective_correction": claim == CLAIM_REAL_CAMERA_PERSPECTIVE,
        "require_raw_captures": bool(args.require_raw_captures)
        or claim == CLAIM_REAL_CAMERA_PERSPECTIVE,
        "require_capture_provenance": bool(args.require_capture_provenance)
        or claim in (CLAIM_PHYSICAL_PRINT_SCAN, CLAIM_REAL_CAMERA_PERSPECTIVE),
        "capture_required_classification": classification,
        "required_certified_claims": [] if claim == CLAIM_NONE else [claim],
    }


def _verify_text_roundtrip(
    *,
    work_dir: Path,
    pipeline_result: Dict[str, Any],
    output_dir: Path,
) -> Dict[str, Any]:
    flow_manifest = _read_json(work_dir / "real_capture_text_flow.json")
    source_artifact = (work_dir / str(flow_manifest["encrypted_text_artifact_file"])).resolve()
    source_artifact_sha = _sha256_file(source_artifact)
    transport_report_file = Path(
        str(
            pipeline_result.get("artifacts", {}).get(
                "transport_reliability_report_file",
                output_dir / "cert" / "transport_reliability_report.json",
            )
        )
    )
    recovered_records: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    if not transport_report_file.exists():
        failures.append(
            {
                "reason": "transport_report_missing",
                "path": str(transport_report_file),
            }
        )
    else:
        report = _read_json(transport_report_file)
        for case in report.get("cases", []) or []:
            if not isinstance(case, dict):
                continue
            output_file = (
                case.get("recovery", {}).get("output_file")
                if isinstance(case.get("recovery"), dict)
                else None
            )
            record: Dict[str, Any] = {
                "case_id": case.get("case_id"),
                "case_success": bool(case.get("success")),
                "failure_reason": case.get("failure_reason"),
                "recovered_artifact_file": output_file,
            }
            if not output_file or not Path(str(output_file)).exists():
                record["plaintext_sha256_verified"] = False
                record["failure"] = "recovered_artifact_missing"
                recovered_records.append(record)
                failures.append(
                    {
                        "reason": "recovered_artifact_missing",
                        "case_id": case.get("case_id"),
                    }
                )
                continue
            recovered_path = Path(str(output_file))
            recovered_sha = _sha256_file(recovered_path)
            record["source_artifact_sha256"] = source_artifact_sha
            record["recovered_artifact_sha256"] = recovered_sha
            record["artifact_sha256_verified"] = recovered_sha == source_artifact_sha
            try:
                decrypted = _decrypt_text_artifact_bytes(recovered_path.read_bytes())
                record["plaintext_sha256"] = decrypted["plaintext_sha256"]
                record["expected_plaintext_sha256"] = decrypted[
                    "expected_plaintext_sha256"
                ]
                record["plaintext_sha256_verified"] = (
                    decrypted["plaintext_sha256"]
                    == decrypted["expected_plaintext_sha256"]
                    == flow_manifest.get("plaintext_sha256")
                )
            except Exception as exc:
                record["plaintext_sha256_verified"] = False
                record["failure"] = "text_artifact_decrypt_failed"
                record["exception"] = str(exc)
            if not bool(record.get("artifact_sha256_verified")) or not bool(
                record.get("plaintext_sha256_verified")
            ):
                failures.append(
                    {
                        "reason": "text_roundtrip_mismatch",
                        "case_id": case.get("case_id"),
                    }
                )
            recovered_records.append(record)
    success = bool(pipeline_result.get("success")) and bool(recovered_records) and not failures
    return {
        "schema": ROUNDTRIP_VERIFICATION_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": success,
        "work_dir": str(work_dir),
        "transport_pipeline_success": bool(pipeline_result.get("success")),
        "transport_report_file": str(transport_report_file),
        "source_artifact_file": str(source_artifact),
        "source_artifact_sha256": source_artifact_sha,
        "plaintext_sha256": flow_manifest.get("plaintext_sha256"),
        "recovered_artifacts": recovered_records,
        "failure_count": len(failures),
        "failures": failures,
        "certification_boundary": (
            "This report verifies the encrypted text payload recovered from the measured "
            "capture files in this work directory. It does not certify any broader camera, "
            "print-scan, or OCR backend claim."
        ),
    }


def certify_flow(args: argparse.Namespace) -> Dict[str, Any]:
    work_dir = Path(args.work_dir).resolve()
    flow_manifest_path = work_dir / "real_capture_text_flow.json"
    if not flow_manifest_path.exists():
        raise FileNotFoundError("flow manifest not found: {}".format(flow_manifest_path))
    flow_manifest = _read_json(flow_manifest_path)
    if flow_manifest.get("schema") != FLOW_MANIFEST_SCHEMA:
        raise ValueError("unsupported flow manifest schema")

    output_dir = Path(args.output_dir).resolve() if args.output_dir else work_dir / "capture_pipeline"
    corpus_path = (work_dir / str(flow_manifest["capture_corpus_file"])).resolve()
    kit_manifest_path = (work_dir / str(flow_manifest["capture_kit_manifest_file"])).resolve()
    cli_metadata = _parse_metadata_items(args.capture_metadata)
    if args.captured_at_utc:
        cli_metadata["captured_at_utc"] = args.captured_at_utc
    if args.operator:
        cli_metadata["operator"] = args.operator
    if args.device:
        cli_metadata["device"] = args.device
    if args.camera:
        cli_metadata["camera"] = args.camera
    if args.printer:
        cli_metadata["printer"] = args.printer
    if args.scanner:
        cli_metadata["scanner"] = args.scanner
    if args.dpi:
        cli_metadata["dpi"] = args.dpi

    _update_corpus_metadata(
        corpus_path,
        cli_metadata,
        claim=args.claim,
        perspective_correction_method=args.perspective_correction_method,
    )

    params = dict(flow_manifest.get("transport_parameters") or {})
    transport = _transport_from_params(params)
    claim_options = _claim_gate_options(args, flow_manifest)
    pipeline_result = transport.certify_capture_evidence_pipeline(
        capture_corpus_file=str(corpus_path),
        output_dir=str(output_dir),
        profile=DEFAULT_PROFILE,
        backend=args.backend,
        redundancy_copies=int(params.get("redundancy_copies", 2)),
        interleave=bool(params.get("interleave", True)),
        parity_group_size=int(params.get("parity_group_size", 4)),
        require_captures=True,
        require_raw_captures=bool(claim_options["require_raw_captures"]),
        require_distinct_capture_images=not bool(args.allow_reference_identical_captures),
        require_capture_attachment_report=True,
        require_capture_provenance=bool(claim_options["require_capture_provenance"]),
        capture_required_classification=str(
            claim_options["capture_required_classification"]
        ),
        capture_required_success_rate=float(args.capture_required_success_rate),
        require_success_rate=float(args.require_success_rate),
        require_physical_print_scan=bool(
            claim_options["require_physical_print_scan"]
        ),
        require_real_camera_perspective_correction=bool(
            claim_options["require_real_camera_perspective_correction"]
        ),
        require_profile_certified=True,
        required_certified_claims=claim_options["required_certified_claims"],
        strict_payload_chars=True,
        max_list=int(args.max_list),
        kit_manifest_file=str(kit_manifest_path),
    )
    roundtrip = _verify_text_roundtrip(
        work_dir=work_dir,
        pipeline_result=pipeline_result,
        output_dir=output_dir,
    )
    roundtrip_path = _write_json(work_dir / "text_roundtrip_verification.json", roundtrip)
    result = {
        "schema": "enc2sop-real-capture-text-certify-result/v1",
        "success": bool(pipeline_result.get("success")) and bool(roundtrip.get("success")),
        "work_dir": str(work_dir),
        "claim": args.claim,
        "pipeline_success": bool(pipeline_result.get("success")),
        "roundtrip_success": bool(roundtrip.get("success")),
        "pipeline_report_file": pipeline_result.get("artifacts", {}).get(
            "pipeline_report_file"
        ),
        "text_roundtrip_verification_file": str(roundtrip_path),
        "transport_reliability_report_file": pipeline_result.get("artifacts", {}).get(
            "transport_reliability_report_file"
        ),
        "transport_certification_status_file": pipeline_result.get("artifacts", {}).get(
            "transport_certification_status_file"
        ),
        "failures": list(pipeline_result.get("failures", [])) + list(
            roundtrip.get("failures", [])
        ),
        "certification_boundary": roundtrip["certification_boundary"],
    }
    return result


def _add_common_transport_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--chunk-chars", type=int, default=24)
    parser.add_argument("--lines-per-page", type=int, default=8)
    parser.add_argument("--max-compressed-kib", type=int, default=64)
    parser.add_argument("--font-size", type=int, default=44)
    parser.add_argument("--font-max-size", type=int, default=132)
    parser.add_argument(
        "--font-fit-mode",
        choices=("target", "fit", "fixed"),
        default="target",
    )
    parser.add_argument(
        "--payload-alphabet-profile",
        choices=("safe-base32-v1", DEFAULT_PAYLOAD_ALPHABET_PROFILE),
        default=DEFAULT_PAYLOAD_ALPHABET_PROFILE,
    )
    parser.add_argument("--redundancy-copies", type=int, default=2)
    parser.add_argument("--no-interleave", action="store_true")
    parser.add_argument("--parity-group-size", type=int, default=4)
    parser.add_argument("--filename-prefix", default="text_capture")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare or certify a real photo/scan text transport round trip."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="encrypt text and generate capture pages")
    text_group = prepare.add_mutually_exclusive_group(required=True)
    text_group.add_argument("--text", help="text to encrypt and transport")
    text_group.add_argument("--text-file", help="UTF-8 text file to encrypt and transport")
    prepare.add_argument("--encoding", default="utf-8")
    prepare.add_argument("--work-dir", required=True)
    prepare.add_argument("--label", default=DEFAULT_LABEL)
    prepare.add_argument("--artifact-id")
    prepare.add_argument("--key-mode", choices=("local-embedded",), default="local-embedded")
    prepare.add_argument(
        "--capture-kind",
        choices=SUPPORTED_CAPTURE_KINDS,
        default="camera-photo",
    )
    prepare.add_argument("--classification", choices=("real", "lab"))
    prepare.add_argument("--capture-session-id")
    prepare.add_argument("--operator")
    prepare.add_argument("--captured-at-utc")
    prepare.add_argument("--device")
    prepare.add_argument("--camera")
    prepare.add_argument("--printer")
    prepare.add_argument("--scanner")
    prepare.add_argument("--dpi")
    prepare.add_argument("--capture-metadata", action="append", default=[])
    prepare.add_argument(
        "--perspective-correction-method",
        default="operator-supplied perspective correction",
    )
    _add_common_transport_args(prepare)

    certify = sub.add_parser("certify", help="read returned captures and run evidence chain")
    certify.add_argument("--work-dir", required=True)
    certify.add_argument("--output-dir")
    certify.add_argument("--claim", choices=SUPPORTED_CLAIMS, default=CLAIM_NONE)
    certify.add_argument("--backend", choices=("sidecar", "auto"), default="sidecar")
    certify.add_argument("--capture-metadata", action="append", default=[])
    certify.add_argument("--captured-at-utc")
    certify.add_argument("--operator")
    certify.add_argument("--device")
    certify.add_argument("--camera")
    certify.add_argument("--printer")
    certify.add_argument("--scanner")
    certify.add_argument("--dpi")
    certify.add_argument(
        "--perspective-correction-method",
        default="operator-supplied perspective correction",
    )
    certify.add_argument("--require-raw-captures", action="store_true")
    certify.add_argument("--require-capture-provenance", action="store_true")
    certify.add_argument("--allow-reference-identical-captures", action="store_true")
    certify.add_argument("--capture-required-classification", choices=("real", "lab"))
    certify.add_argument("--capture-required-success-rate", type=float, default=1.0)
    certify.add_argument("--require-success-rate", type=float, default=1.0)
    certify.add_argument("--max-list", type=int, default=200)

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare_flow(args)
        elif args.command == "certify":
            result = certify_flow(args)
        else:  # pragma: no cover - argparse enforces this
            raise ValueError("unsupported command: {}".format(args.command))
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.get("success") else 2


if __name__ == "__main__":
    raise SystemExit(main())
