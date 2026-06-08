#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Lightweight CLI skeleton for cross-media encrypted transport."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional
from typing import Sequence

from . import crypto_envelope
from . import image_scan
from . import key_material
from . import qr_transport

SEND_REPORT_SCHEMA = "enc2sop-cross-media-send-report/v1"
DECRYPT_REPORT_SCHEMA = "enc2sop-cross-media-decrypt-report/v1"


def _count_selected_key_modes(args: argparse.Namespace, names: Sequence[str]) -> int:
    return sum(1 for name in names if bool(getattr(args, name, None)))


def _resolve_encrypt_key(args: argparse.Namespace) -> tuple[bytes, str, Optional[dict], Optional[dict]]:
    selected = _count_selected_key_modes(args, ("key_file", "passphrase", "recipient_public_key"))
    if selected != 1:
        raise ValueError("use exactly one of --key-file, --passphrase, or --recipient-public-key")
    if getattr(args, "key_file", None):
        return key_material.load_key_file(Path(args.key_file)), "key-file", None, None
    if getattr(args, "recipient_public_key", None):
        public_key = key_material.load_public_key(Path(args.recipient_public_key))
        data_key = os.urandom(key_material.KEY_LEN)
        wrapped = key_material.wrap_data_key_rsa_oaep_sha256(public_key, data_key)
        key_wrap = {
            "algorithm": key_material.PUBLIC_KEY_WRAP_ALGORITHM,
            "encrypted_key_b64u": crypto_envelope.b64u_encode(wrapped),
            "recipient_public_key_sha256": key_material.public_key_sha256_hex(public_key),
        }
        return data_key, key_material.PUBLIC_KEY_MODE, None, key_wrap
    salt = os.urandom(key_material.SCRYPT_SALT_BYTES)
    passphrase = key_material.passphrase_from_env()
    salt_b64u = crypto_envelope.b64u_encode(salt)
    kdf = key_material.build_scrypt_kdf_metadata(salt_b64u)
    key = key_material.derive_key_from_passphrase(
        passphrase,
        salt,
        n=int(kdf["n"]),
        r=int(kdf["r"]),
        p=int(kdf["p"]),
        key_len=int(kdf["key_len"]),
    )
    return key, "passphrase-scrypt", kdf, None


def _resolve_decrypt_key(args: argparse.Namespace, envelope: dict) -> bytes:
    selected = _count_selected_key_modes(args, ("key_file", "passphrase", "private_key"))
    if selected != 1:
        raise ValueError("use exactly one of --key-file, --passphrase, or --private-key")
    if getattr(args, "key_file", None):
        return key_material.load_key_file(Path(args.key_file))
    crypto = envelope.get("crypto")
    if not isinstance(crypto, dict):
        raise crypto_envelope.Sox1EnvelopeError("SOX1 envelope missing crypto metadata")
    if getattr(args, "private_key", None):
        if crypto.get("key_mode") != key_material.PUBLIC_KEY_MODE:
            raise crypto_envelope.Sox1EnvelopeError("SOX1 envelope is not encrypted for public-key mode")
        key_wrap = crypto.get("key_wrap")
        if not isinstance(key_wrap, dict):
            raise crypto_envelope.Sox1EnvelopeError("SOX1 envelope missing public-key key_wrap metadata")
        if key_wrap.get("algorithm") != key_material.PUBLIC_KEY_WRAP_ALGORITHM:
            raise crypto_envelope.Sox1EnvelopeError("unsupported public-key wrap algorithm")
        wrapped = crypto_envelope.b64u_decode(str(key_wrap.get("encrypted_key_b64u") or ""))
        private_key = key_material.load_private_key(Path(args.private_key))
        try:
            return key_material.unwrap_data_key_rsa_oaep_sha256(private_key, wrapped)
        except key_material.KeyUnwrapError as exc:
            raise crypto_envelope.Sox1DecryptError("SOX1 data key unwrap failed") from exc
    kdf = crypto.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("name") != key_material.SCRYPT_NAME:
        raise crypto_envelope.Sox1EnvelopeError("SOX1 envelope does not contain passphrase scrypt metadata")
    salt = crypto_envelope.b64u_decode(str(kdf.get("salt_b64u") or ""))
    return key_material.derive_key_from_passphrase(
        key_material.passphrase_from_env(),
        salt,
        n=int(kdf.get("n")),
        r=int(kdf.get("r")),
        p=int(kdf.get("p")),
        key_len=int(kdf.get("key_len")),
    )


def _run_keygen(args: argparse.Namespace) -> int:
    path = key_material.generate_key_file(Path(args.key_file), overwrite=bool(args.overwrite))
    print("key_file={0}".format(path))
    print("key_bytes={0}".format(key_material.KEY_LEN))
    return 0


def _run_keygen_public(args: argparse.Namespace) -> int:
    public_path, private_path = key_material.generate_public_key_pair(
        public_path=Path(args.public),
        private_path=Path(args.private),
        overwrite=bool(args.overwrite),
    )
    public_key = key_material.load_public_key(public_path)
    print("public_key={0}".format(public_path))
    print("private_key={0}".format(private_path))
    print("algorithm={0}".format(key_material.PUBLIC_KEY_WRAP_ALGORITHM))
    print("recipient_public_key_sha256={0}".format(key_material.public_key_sha256_hex(public_key)))
    return 0


def _run_encrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    plaintext = input_path.read_bytes()
    key, key_mode, kdf, key_wrap = _resolve_encrypt_key(args)
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(
        plaintext,
        key=key,
        name=input_path.name,
        key_mode=key_mode,
        kdf=kdf,
        key_wrap=key_wrap,
    )
    out_path = crypto_envelope.write_text_atomic(Path(args.out_string), sox1 + "\n")
    print("out_string={0}".format(out_path))
    print("sox1_chars={0}".format(len(sox1)))
    print("plaintext_sha256={0}".format(crypto_envelope.decode_sox1_envelope(sox1)["content"]["plaintext_sha256"]))
    return 0


def _run_decrypt(args: argparse.Namespace) -> int:
    sox1 = crypto_envelope.read_sox1_string(args.input_string, input_string_file=Path(args.input_string_file) if args.input_string_file else None)
    envelope = crypto_envelope.decode_sox1_envelope(sox1)
    key = _resolve_decrypt_key(args, envelope)
    plaintext, envelope = crypto_envelope.decrypt_sox1_to_bytes(sox1, key=key)
    out_path = crypto_envelope.write_bytes_atomic(Path(args.output), plaintext)
    content = envelope.get("content") if isinstance(envelope.get("content"), dict) else {}
    print("output={0}".format(out_path))
    print("output_size={0}".format(len(plaintext)))
    print("output_sha256={0}".format(content.get("plaintext_sha256")))
    return 0


def _decrypt_sox1_to_output(args: argparse.Namespace, sox1: str, *, output_path: Path) -> tuple[bytes, dict]:
    envelope = crypto_envelope.decode_sox1_envelope(sox1)
    key = _resolve_decrypt_key(args, envelope)
    plaintext, envelope = crypto_envelope.decrypt_sox1_to_bytes(sox1, key=key)
    crypto_envelope.write_bytes_atomic(output_path, plaintext)
    return plaintext, envelope


def _run_render(args: argparse.Namespace) -> int:
    if args.mode != "qr":
        raise qr_transport.QrTransportError("P0-S2 only supports --mode qr")
    sox1 = crypto_envelope.read_sox1_string(
        args.input_string,
        input_string_file=Path(args.input_string_file) if args.input_string_file else None,
    )
    output_dir = Path(args.output_dir)
    manifest = qr_transport.render_qr_pages(sox1, output_dir, chunk_chars=int(args.chunk_chars))
    print("output_dir={0}".format(output_dir))
    print("pages_dir={0}".format(output_dir / "pages"))
    print("artifact_id={0}".format(manifest.get("artifact_id")))
    print("chunks_total={0}".format(manifest.get("chunks_total")))
    return 0


def _parse_reassembly_report(exc: qr_transport.QrReassemblyError) -> dict:
    try:
        payload = json.loads(str(exc))
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    payload.setdefault("schema", qr_transport.SCAN_REPORT_SCHEMA)
    payload.setdefault("success", False)
    payload.setdefault("reason", "qr_reassembly_failed")
    payload.setdefault("detail", str(exc))
    return payload


def _scan_exit_code(report: dict) -> int:
    reason = str(report.get("reason") or "")
    if reason == "multiple_complete_artifacts":
        return 22
    if reason in {
        "conflicting_duplicate_chunks",
        "qr_payload_parse_or_crc_failed",
        "string_sha256_mismatch",
    }:
        return 21
    return 20


def _recover_sox1_from_images(
    *,
    image_input: Path,
    out_string: Path,
    report_path: Path,
    artifact_id: Optional[str] = None,
) -> tuple[int, Optional[str], dict]:
    payloads, scan_meta = image_scan.scan_image_input(image_input)
    bad_images = scan_meta.get("bad_images") if isinstance(scan_meta.get("bad_images"), list) else []
    try:
        sox1, report = qr_transport.reassemble_chunks(
            payloads,
            artifact_id=artifact_id,
            image_count=int(scan_meta.get("image_count") or 0),
            bad_images=bad_images,
            out_string=out_string,
        )
    except qr_transport.QrReassemblyError as exc:
        report = _parse_reassembly_report(exc)
        report["scan_report"] = str(report_path)
        qr_transport.write_json_atomic(report_path, report)
        return _scan_exit_code(report), None, report

    crypto_envelope.write_text_atomic(out_string, sox1 + "\n")
    report["image_count"] = int(scan_meta.get("image_count") or 0)
    report["bad_images"] = bad_images
    report["scan_report"] = str(report_path)
    qr_transport.write_json_atomic(report_path, report)
    return 0, sox1, report


def _scan_report_path(args: argparse.Namespace) -> Path:
    if getattr(args, "work_dir", None):
        work_dir = Path(args.work_dir)
    else:
        work_dir = Path(args.out_string).parent
    work_dir.mkdir(parents=True, exist_ok=True)
    return work_dir / "scan_report.json"


def _run_scan(args: argparse.Namespace) -> int:
    out_string = Path(args.out_string)
    report_path = _scan_report_path(args)
    exit_code, _sox1, report = _recover_sox1_from_images(
        image_input=Path(args.image_input),
        out_string=out_string,
        report_path=report_path,
        artifact_id=getattr(args, "artifact_id", None),
    )
    if exit_code != 0:
        print(
            "cross-media scan error: {0}; retake_pages={1}; scan_report={2}".format(
                report.get("reason"),
                report.get("retake_pages", []),
                report_path,
            ),
            file=sys.stderr,
        )
        return exit_code

    print("out_string={0}".format(out_string))
    print("scan_report={0}".format(report_path))
    print("artifact_id={0}".format(report.get("artifact_id")))
    print("chunks_total={0}".format(report.get("chunks_total")))
    print("duplicates={0}".format(report.get("duplicates")))
    return 0


def _run_send(args: argparse.Namespace) -> int:
    if args.mode != "qr":
        raise qr_transport.QrTransportError("P0-S3 send only supports --mode qr")
    key, key_mode, kdf, key_wrap = _resolve_encrypt_key(args)
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    plaintext = input_path.read_bytes()
    input_sha256 = hashlib.sha256(plaintext).hexdigest()
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(
        plaintext,
        key=key,
        name=input_path.name,
        key_mode=key_mode,
        kdf=kdf,
        key_wrap=key_wrap,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    payload_path: Optional[Path] = None
    if not getattr(args, "no_debug_sox1", False):
        payload_path = output_dir / "payload.sox1"
        crypto_envelope.write_text_atomic(payload_path, sox1 + "\n")
    else:
        stale_payload = output_dir / "payload.sox1"
        if stale_payload.exists() and stale_payload.is_file():
            stale_payload.unlink()
    manifest = qr_transport.render_qr_pages(sox1, output_dir, chunk_chars=qr_transport.DEFAULT_CHUNK_CHARS)
    report = {
        "schema": SEND_REPORT_SCHEMA,
        "success": True,
        "input": str(input_path),
        "input_size": len(plaintext),
        "input_sha256": input_sha256,
        "artifact_id": manifest.get("artifact_id"),
        "pages": manifest.get("chunks_total"),
        "mode": args.mode,
        "output_dir": str(output_dir),
        "pages_dir": str(output_dir / "pages"),
        "payload_sox1": str(payload_path) if payload_path is not None else None,
        "manifest": str(output_dir / "manifest.json"),
    }
    report_path = output_dir / "send_report.json"
    qr_transport.write_json_atomic(report_path, report)
    print("output_dir={0}".format(output_dir))
    print("pages_dir={0}".format(output_dir / "pages"))
    print("send_report={0}".format(report_path))
    print("artifact_id={0}".format(report.get("artifact_id")))
    print("pages={0}".format(report.get("pages")))
    print("input_sha256={0}".format(input_sha256))
    return 0


def _decrypt_success_report(
    *,
    output_path: Path,
    recovered_sox1_path: Path,
    plaintext: bytes,
    envelope: dict,
) -> dict:
    content = envelope.get("content") if isinstance(envelope.get("content"), dict) else {}
    return {
        "schema": DECRYPT_REPORT_SCHEMA,
        "success": True,
        "output": str(output_path),
        "output_sha256": hashlib.sha256(plaintext).hexdigest(),
        "output_size": len(plaintext),
        "content_name": content.get("name"),
        "recovered_sox1": str(recovered_sox1_path),
    }


def _decrypt_failure_report(
    *,
    output_path: Path,
    recovered_sox1_path: Path,
    reason: str,
    error: Exception,
) -> dict:
    return {
        "schema": DECRYPT_REPORT_SCHEMA,
        "success": False,
        "output": str(output_path),
        "recovered_sox1": str(recovered_sox1_path),
        "reason": reason,
        "error": str(error),
    }


def _preflight_receive_key(args: argparse.Namespace) -> None:
    if getattr(args, "key_file", None):
        key_material.load_key_file(Path(args.key_file))
    elif getattr(args, "passphrase", False):
        key_material.passphrase_from_env()


def _run_receive(args: argparse.Namespace) -> int:
    if _count_selected_key_modes(args, ("key_file", "passphrase")) != 1:
        raise ValueError("use exactly one of --key-file or --passphrase")
    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    recovered_sox1 = work_dir / "recovered.sox1"
    scan_report = work_dir / "scan_report.json"
    decrypt_report = work_dir / "decrypt_report.json"
    output_path = Path(args.output)
    try:
        _preflight_receive_key(args)
    except key_material.KeyMaterialError as exc:
        report = _decrypt_failure_report(
            output_path=output_path,
            recovered_sox1_path=recovered_sox1,
            reason="key_material_error",
            error=exc,
        )
        qr_transport.write_json_atomic(decrypt_report, report)
        print("cross-media receive key error: {0}; decrypt_report={1}".format(exc, decrypt_report), file=sys.stderr)
        return 10
    exit_code, sox1, scan_payload = _recover_sox1_from_images(
        image_input=Path(args.image_input),
        out_string=recovered_sox1,
        report_path=scan_report,
    )
    if exit_code != 0:
        print(
            "cross-media receive scan error: {0}; retake_pages={1}; scan_report={2}".format(
                scan_payload.get("reason"),
                scan_payload.get("retake_pages", []),
                scan_report,
            ),
            file=sys.stderr,
        )
        return exit_code
    assert sox1 is not None
    try:
        plaintext, envelope = _decrypt_sox1_to_output(args, sox1, output_path=output_path)
    except key_material.KeyMaterialError as exc:
        report = _decrypt_failure_report(
            output_path=output_path,
            recovered_sox1_path=recovered_sox1,
            reason="key_material_error",
            error=exc,
        )
        qr_transport.write_json_atomic(decrypt_report, report)
        print("cross-media receive key error: {0}; decrypt_report={1}".format(exc, decrypt_report), file=sys.stderr)
        return 10
    except crypto_envelope.Sox1DecryptError as exc:
        report = _decrypt_failure_report(
            output_path=output_path,
            recovered_sox1_path=recovered_sox1,
            reason="authenticated_decryption_failed",
            error=exc,
        )
        qr_transport.write_json_atomic(decrypt_report, report)
        print("cross-media receive decrypt error: {0}; decrypt_report={1}".format(exc, decrypt_report), file=sys.stderr)
        return 11
    except crypto_envelope.Sox1EnvelopeError as exc:
        report = _decrypt_failure_report(
            output_path=output_path,
            recovered_sox1_path=recovered_sox1,
            reason="sox1_envelope_error",
            error=exc,
        )
        qr_transport.write_json_atomic(decrypt_report, report)
        print("cross-media receive envelope error: {0}; decrypt_report={1}".format(exc, decrypt_report), file=sys.stderr)
        return 11

    report = _decrypt_success_report(
        output_path=output_path,
        recovered_sox1_path=recovered_sox1,
        plaintext=plaintext,
        envelope=envelope,
    )
    qr_transport.write_json_atomic(decrypt_report, report)
    print("output={0}".format(output_path))
    print("scan_report={0}".format(scan_report))
    print("decrypt_report={0}".format(decrypt_report))
    print("output_size={0}".format(len(plaintext)))
    print("output_sha256={0}".format(report.get("output_sha256")))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soenc cm",
        description=(
            "Cross-media encrypted transport commands: SOX1 envelope, QR visual "
            "transport, and P0 send/receive workflows."
        ),
    )
    subparsers = parser.add_subparsers(dest="cm_command")

    keygen_parser = subparsers.add_parser("keygen", help="Generate a 32-byte key file (P0-S1).")
    keygen_parser.add_argument("--key-file", required=True, help="Output key file path.")
    keygen_parser.add_argument("--overwrite", action="store_true", help="Overwrite an existing key file.")
    keygen_parser.set_defaults(handler=_run_keygen)

    keygen_public_parser = subparsers.add_parser("keygen-public", help="Generate an RSA-OAEP public/private key pair (P1-S1).")
    keygen_public_parser.add_argument("--public", required=True, help="Output public PEM path.")
    keygen_public_parser.add_argument("--private", required=True, help="Output private PEM path.")
    keygen_public_parser.add_argument("--overwrite", action="store_true", help="Overwrite existing PEM files.")
    keygen_public_parser.set_defaults(handler=_run_keygen_public)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt bytes into a SOX1 string (P0-S1).")
    encrypt_parser.add_argument("--input", required=True, help="Input plaintext file.")
    encrypt_parser.add_argument("--key-file", help="32-byte key file.")
    encrypt_parser.add_argument("--passphrase", action="store_true", help="Read passphrase without putting it in shell history.")
    encrypt_parser.add_argument("--recipient-public-key", help="Recipient public PEM for P1 hybrid public-key encryption.")
    encrypt_parser.add_argument("--out-string", required=True, help="Output SOX1 string file.")
    encrypt_parser.set_defaults(handler=_run_encrypt)

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a SOX1 string into bytes (P0-S1).")
    decrypt_parser.add_argument("--input-string", help="SOX1 string literal or file path.")
    decrypt_parser.add_argument("--input-string-file", help="SOX1 string file path.")
    decrypt_parser.add_argument("--key-file", help="32-byte key file.")
    decrypt_parser.add_argument("--passphrase", action="store_true", help="Read passphrase without putting it in shell history.")
    decrypt_parser.add_argument("--private-key", help="Private PEM for P1 hybrid public-key decryption.")
    decrypt_parser.add_argument("--output", required=True, help="Output plaintext file.")
    decrypt_parser.set_defaults(handler=_run_decrypt)

    render_parser = subparsers.add_parser("render", help="Render a SOX1 string into QR pages (P0-S2).")
    render_parser.add_argument("--input-string", help="SOX1 string literal or file path.")
    render_parser.add_argument("--input-string-file", help="SOX1 string file path.")
    render_parser.add_argument("--output-dir", required=True, help="Output directory for pages.")
    render_parser.add_argument("--mode", choices=["qr"], default="qr", help="Visual transport mode.")
    render_parser.add_argument("--chunk-chars", type=int, default=700, help="SOX1 chars per QR chunk.")
    render_parser.set_defaults(handler=_run_render)

    scan_parser = subparsers.add_parser("scan", help="Scan QR photos back into a SOX1 string (P0-S2).")
    scan_parser.add_argument("--image-input", required=True, help="Directory containing captured images.")
    scan_parser.add_argument("--out-string", required=True, help="Output recovered SOX1 string file.")
    scan_parser.add_argument("--work-dir", help="Directory for scan_report.json and intermediates.")
    scan_parser.add_argument("--artifact-id", help="Require a specific artifact id when multiple batches are present.")
    scan_parser.set_defaults(handler=_run_scan)

    send_parser = subparsers.add_parser("send", help="Encrypt and render pages in one command (P0-S3).")
    send_parser.add_argument("--input", required=True, help="Input plaintext file.")
    send_parser.add_argument("--key-file", help="32-byte key file.")
    send_parser.add_argument("--passphrase", action="store_true", help="Read passphrase without putting it in shell history.")
    send_parser.add_argument("--output-dir", required=True, help="Output send package directory.")
    send_parser.add_argument("--mode", choices=["qr"], default="qr", help="Visual transport mode.")
    send_parser.add_argument("--no-debug-sox1", action="store_true", help="Do not persist payload.sox1 debug output.")
    send_parser.set_defaults(handler=_run_send)

    receive_parser = subparsers.add_parser("receive", help="Scan and decrypt in one command (P0-S3).")
    receive_parser.add_argument("--image-input", required=True, help="Directory containing captured images.")
    receive_parser.add_argument("--key-file", help="32-byte key file.")
    receive_parser.add_argument("--passphrase", action="store_true", help="Read passphrase without putting it in shell history.")
    receive_parser.add_argument("--output", required=True, help="Output plaintext file.")
    receive_parser.add_argument("--work-dir", required=True, help="Directory for reports and intermediates.")
    receive_parser.set_defaults(handler=_run_receive)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    try:
        return int(handler(args))
    except key_material.KeyMaterialError as exc:
        print("cross-media key error: {0}".format(exc), file=sys.stderr)
        return 10
    except crypto_envelope.Sox1DecryptError as exc:
        print("cross-media decrypt error: {0}".format(exc), file=sys.stderr)
        return 11
    except crypto_envelope.Sox1EnvelopeError as exc:
        print("cross-media envelope error: {0}".format(exc), file=sys.stderr)
        return 11
    except image_scan.ImageScanError as exc:
        print("cross-media scan input error: {0}".format(exc), file=sys.stderr)
        return 30
    except qr_transport.QrTransportError as exc:
        print("cross-media QR transport error: {0}".format(exc), file=sys.stderr)
        return 21
    except OSError as exc:
        print("cross-media file error: {0}".format(exc), file=sys.stderr)
        return 30
    except ValueError as exc:
        print("cross-media argument error: {0}".format(exc), file=sys.stderr)
        return 2
    except RuntimeError as exc:
        message = str(exc)
        if "OpenCV" in message or "Pillow" in message or "cryptography" in message:
            print("cross-media optional dependency error: {0}".format(exc), file=sys.stderr)
            return 40
        raise


__all__ = ["build_parser", "main"]
