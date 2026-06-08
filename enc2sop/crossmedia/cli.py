#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Lightweight CLI skeleton for cross-media encrypted transport."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional
from typing import Sequence

from . import crypto_envelope
from . import key_material


_NOT_IMPLEMENTED_BY_STAGE = {
    "render": "P0-S2 QR visual transport is not implemented yet.",
    "scan": "P0-S2 QR visual transport is not implemented yet.",
    "send": "P0-S3 send workflow is not implemented yet.",
    "receive": "P0-S3 receive workflow is not implemented yet.",
}


class CrossMediaNotImplemented(NotImplementedError):
    """Raised when a documented cross-media command is not implemented in the current stage."""


def _run_not_implemented(args: argparse.Namespace) -> int:
    command = str(getattr(args, "cm_command", "") or "")
    message = _NOT_IMPLEMENTED_BY_STAGE.get(command, "Cross-media command is not implemented yet.")
    raise CrossMediaNotImplemented(message)


def _resolve_encrypt_key(args: argparse.Namespace) -> tuple[bytes, str, Optional[dict]]:
    if bool(getattr(args, "key_file", None)) == bool(getattr(args, "passphrase", False)):
        raise ValueError("use exactly one of --key-file or --passphrase")
    if getattr(args, "key_file", None):
        return key_material.load_key_file(Path(args.key_file)), "key-file", None
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
    return key, "passphrase-scrypt", kdf


def _resolve_decrypt_key(args: argparse.Namespace, envelope: dict) -> bytes:
    if bool(getattr(args, "key_file", None)) == bool(getattr(args, "passphrase", False)):
        raise ValueError("use exactly one of --key-file or --passphrase")
    if getattr(args, "key_file", None):
        return key_material.load_key_file(Path(args.key_file))
    crypto = envelope.get("crypto")
    if not isinstance(crypto, dict):
        raise crypto_envelope.Sox1EnvelopeError("SOX1 envelope missing crypto metadata")
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


def _run_encrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    plaintext = input_path.read_bytes()
    key, key_mode, kdf = _resolve_encrypt_key(args)
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(
        plaintext,
        key=key,
        name=input_path.name,
        key_mode=key_mode,
        kdf=kdf,
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soenc cm",
        description=(
            "Cross-media encrypted transport commands. P0-S0 provides this lightweight "
            "entrypoint; SOX1/QR/send/receive land in the next documented stages."
        ),
    )
    subparsers = parser.add_subparsers(dest="cm_command")

    keygen_parser = subparsers.add_parser("keygen", help="Generate a 32-byte key file (P0-S1).")
    keygen_parser.add_argument("--key-file", required=True, help="Output key file path.")
    keygen_parser.add_argument("--overwrite", action="store_true", help="Overwrite an existing key file.")
    keygen_parser.set_defaults(handler=_run_keygen)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt bytes into a SOX1 string (P0-S1).")
    encrypt_parser.add_argument("--input", required=True, help="Input plaintext file.")
    encrypt_parser.add_argument("--key-file", help="32-byte key file.")
    encrypt_parser.add_argument("--passphrase", action="store_true", help="Read passphrase without putting it in shell history.")
    encrypt_parser.add_argument("--out-string", required=True, help="Output SOX1 string file.")
    encrypt_parser.set_defaults(handler=_run_encrypt)

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a SOX1 string into bytes (P0-S1).")
    decrypt_parser.add_argument("--input-string", help="SOX1 string literal or file path.")
    decrypt_parser.add_argument("--input-string-file", help="SOX1 string file path.")
    decrypt_parser.add_argument("--key-file", help="32-byte key file.")
    decrypt_parser.add_argument("--passphrase", action="store_true", help="Read passphrase without putting it in shell history.")
    decrypt_parser.add_argument("--output", required=True, help="Output plaintext file.")
    decrypt_parser.set_defaults(handler=_run_decrypt)

    render_parser = subparsers.add_parser("render", help="Render a SOX1 string into QR pages (P0-S2).")
    render_parser.add_argument("--input-string", help="SOX1 string literal or file path.")
    render_parser.add_argument("--input-string-file", help="SOX1 string file path.")
    render_parser.add_argument("--output-dir", required=True, help="Output directory for pages.")
    render_parser.add_argument("--mode", choices=["qr"], default="qr", help="Visual transport mode.")
    render_parser.add_argument("--chunk-chars", type=int, default=700, help="SOX1 chars per QR chunk.")
    render_parser.set_defaults(handler=_run_not_implemented)

    scan_parser = subparsers.add_parser("scan", help="Scan QR photos back into a SOX1 string (P0-S2).")
    scan_parser.add_argument("--image-input", required=True, help="Directory containing captured images.")
    scan_parser.add_argument("--out-string", required=True, help="Output recovered SOX1 string file.")
    scan_parser.add_argument("--work-dir", help="Directory for scan_report.json and intermediates.")
    scan_parser.add_argument("--artifact-id", help="Require a specific artifact id when multiple batches are present.")
    scan_parser.set_defaults(handler=_run_not_implemented)

    send_parser = subparsers.add_parser("send", help="Encrypt and render pages in one command (P0-S3).")
    send_parser.add_argument("--input", required=True, help="Input plaintext file.")
    send_parser.add_argument("--key-file", help="32-byte key file.")
    send_parser.add_argument("--passphrase", action="store_true", help="Read passphrase without putting it in shell history.")
    send_parser.add_argument("--output-dir", required=True, help="Output send package directory.")
    send_parser.add_argument("--mode", choices=["qr"], default="qr", help="Visual transport mode.")
    send_parser.add_argument("--no-debug-sox1", action="store_true", help="Do not persist payload.sox1 debug output.")
    send_parser.set_defaults(handler=_run_not_implemented)

    receive_parser = subparsers.add_parser("receive", help="Scan and decrypt in one command (P0-S3).")
    receive_parser.add_argument("--image-input", required=True, help="Directory containing captured images.")
    receive_parser.add_argument("--key-file", help="32-byte key file.")
    receive_parser.add_argument("--passphrase", action="store_true", help="Read passphrase without putting it in shell history.")
    receive_parser.add_argument("--output", required=True, help="Output plaintext file.")
    receive_parser.add_argument("--work-dir", required=True, help="Directory for reports and intermediates.")
    receive_parser.set_defaults(handler=_run_not_implemented)

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
    except CrossMediaNotImplemented as exc:
        print("cross-media command not implemented: {0}".format(exc), file=sys.stderr)
        return 40
    except OSError as exc:
        print("cross-media file error: {0}".format(exc), file=sys.stderr)
        return 30


__all__ = ["CrossMediaNotImplemented", "build_parser", "main"]
