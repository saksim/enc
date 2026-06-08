#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""SOX1 crypto envelope for cross-media encrypted transport."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import zlib
from pathlib import Path
from typing import Dict
from typing import Optional
from typing import Tuple

from enc2sop.transport import protocol as transport_protocol

SOX1_PREFIX = "SOX1."
ENVELOPE_SCHEMA = "enc2sop-cross-media-envelope/v1"
ENVELOPE_VERSION = 1
AES_GCM_ALGORITHM = "AES-256-GCM"
ZLIB_ALGORITHM = "zlib"
DEFAULT_MAX_PLAINTEXT_BYTES = 256 * 1024
DEFAULT_MAX_SOX1_CHARS = 2 * 1024 * 1024


class Sox1EnvelopeError(ValueError):
    """Raised when a SOX1 envelope is malformed or fails validation."""


class Sox1DecryptError(Sox1EnvelopeError):
    """Raised when authenticated decryption fails."""


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    raw = str(text or "").encode("ascii")
    raw += b"=" * ((4 - len(raw) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(raw)
    except Exception as exc:
        raise Sox1EnvelopeError("invalid base64url payload") from exc


def canonical_json_bytes(payload: Dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise Sox1EnvelopeError("AES-256-GCM key must be bytes")
    key_bytes = bytes(key)
    if len(key_bytes) != 32:
        raise Sox1EnvelopeError("AES-256-GCM key must be exactly 32 bytes")
    return key_bytes


def _load_aesgcm_class():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as exc:  # pragma: no cover - exercised only in missing dependency envs
        raise RuntimeError("cryptography is required for SOX1 AES-256-GCM envelopes") from exc
    return AESGCM


def _build_aad_payload(
    *,
    created_at_utc: str,
    name: Optional[str],
    original_size: int,
    plaintext_sha256: str,
    compression_enabled: bool,
    compressed_size: int,
    crypto_algorithm: str,
    key_mode: str,
    kdf: Optional[Dict[str, object]],
    key_wrap: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    payload = {
        "schema": ENVELOPE_SCHEMA,
        "version": ENVELOPE_VERSION,
        "created_at_utc": created_at_utc,
        "compression_algorithm": ZLIB_ALGORITHM,
        "compression_enabled": bool(compression_enabled),
        "compressed_size": int(compressed_size),
        "crypto_algorithm": crypto_algorithm,
        "key_mode": key_mode,
        "kdf": kdf,
        "content_name": name,
        "original_size": int(original_size),
        "plaintext_sha256": plaintext_sha256,
    }
    if key_wrap is not None:
        payload["key_wrap"] = key_wrap
    return payload


def encrypt_bytes_to_sox1(
    plaintext: bytes,
    *,
    key: bytes,
    name: Optional[str] = None,
    created_at_utc: Optional[str] = None,
    compress: bool = True,
    key_mode: str = "key-file",
    kdf: Optional[Dict[str, object]] = None,
    key_wrap: Optional[Dict[str, object]] = None,
    max_plaintext_bytes: int = DEFAULT_MAX_PLAINTEXT_BYTES,
) -> str:
    key_bytes = _require_key(key)
    plaintext_bytes = bytes(plaintext)
    if len(plaintext_bytes) > int(max_plaintext_bytes):
        raise Sox1EnvelopeError(
            "plaintext is too large for P0 SOX1 envelope; max {0} bytes".format(max_plaintext_bytes)
        )

    plaintext_sha256 = transport_protocol.sha256_hex(plaintext_bytes)
    payload_bytes = zlib.compress(plaintext_bytes) if compress else plaintext_bytes
    timestamp = created_at_utc or transport_protocol.utc_now_iso()
    aad_payload = _build_aad_payload(
        created_at_utc=timestamp,
        name=name,
        original_size=len(plaintext_bytes),
        plaintext_sha256=plaintext_sha256,
        compression_enabled=bool(compress),
        compressed_size=len(payload_bytes),
        crypto_algorithm=AES_GCM_ALGORITHM,
        key_mode=key_mode,
        kdf=kdf,
        key_wrap=key_wrap,
    )
    aad = canonical_json_bytes(aad_payload)
    nonce = os.urandom(12)
    aesgcm = _load_aesgcm_class()(key_bytes)
    encrypted = aesgcm.encrypt(nonce, payload_bytes, aad)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    crypto_payload = {
        "algorithm": AES_GCM_ALGORITHM,
        "key_mode": key_mode,
        "kdf": kdf,
        "nonce_b64u": b64u_encode(nonce),
        "aad_b64u": b64u_encode(aad),
        "ciphertext_b64u": b64u_encode(ciphertext),
        "tag_b64u": b64u_encode(tag),
    }
    if key_wrap is not None:
        crypto_payload["key_wrap"] = key_wrap
    envelope = {
        "schema": ENVELOPE_SCHEMA,
        "version": ENVELOPE_VERSION,
        "created_at_utc": timestamp,
        "content": {
            "name": name,
            "original_size": len(plaintext_bytes),
            "plaintext_sha256": plaintext_sha256,
        },
        "compression": {
            "algorithm": ZLIB_ALGORITHM,
            "enabled": bool(compress),
            "compressed_size": len(payload_bytes),
        },
        "crypto": crypto_payload,
    }
    return SOX1_PREFIX + b64u_encode(canonical_json_bytes(envelope))


def decode_sox1_envelope(sox1: str, *, max_sox1_chars: int = DEFAULT_MAX_SOX1_CHARS) -> Dict[str, object]:
    text = str(sox1 or "").strip()
    if len(text) > int(max_sox1_chars):
        raise Sox1EnvelopeError("SOX1 string is too large for P0 envelope")
    if not text.startswith(SOX1_PREFIX):
        raise Sox1EnvelopeError("SOX1 envelope must start with {0}".format(SOX1_PREFIX))
    raw_json = b64u_decode(text[len(SOX1_PREFIX) :])
    try:
        payload = json.loads(raw_json.decode("utf-8"))
    except Exception as exc:
        raise Sox1EnvelopeError("SOX1 envelope JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise Sox1EnvelopeError("SOX1 envelope JSON root must be an object")
    if payload.get("schema") != ENVELOPE_SCHEMA:
        raise Sox1EnvelopeError("unsupported SOX1 envelope schema")
    if payload.get("version") != ENVELOPE_VERSION:
        raise Sox1EnvelopeError("unsupported SOX1 envelope version")
    return payload


def _expect_dict(parent: Dict[str, object], key: str) -> Dict[str, object]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise Sox1EnvelopeError("SOX1 envelope missing object field: {0}".format(key))
    return value


def decrypt_sox1_to_bytes(sox1: str, *, key: bytes) -> Tuple[bytes, Dict[str, object]]:
    key_bytes = _require_key(key)
    envelope = decode_sox1_envelope(sox1)
    content = _expect_dict(envelope, "content")
    compression = _expect_dict(envelope, "compression")
    crypto = _expect_dict(envelope, "crypto")

    if crypto.get("algorithm") != AES_GCM_ALGORITHM:
        raise Sox1EnvelopeError("unsupported crypto algorithm")
    if compression.get("algorithm") != ZLIB_ALGORITHM:
        raise Sox1EnvelopeError("unsupported compression algorithm")
    if crypto.get("key_mode") == "local-embedded":
        raise Sox1EnvelopeError("local-embedded key mode is forbidden for SOX1 cross-media envelopes")

    nonce = b64u_decode(str(crypto.get("nonce_b64u") or ""))
    aad = b64u_decode(str(crypto.get("aad_b64u") or ""))
    ciphertext = b64u_decode(str(crypto.get("ciphertext_b64u") or ""))
    tag = b64u_decode(str(crypto.get("tag_b64u") or ""))
    if len(nonce) != 12:
        raise Sox1EnvelopeError("AES-GCM nonce must be 12 bytes")
    if len(tag) != 16:
        raise Sox1EnvelopeError("AES-GCM tag must be 16 bytes")

    expected_aad_payload = _build_aad_payload(
        created_at_utc=str(envelope.get("created_at_utc") or ""),
        name=content.get("name") if content.get("name") is not None else None,
        original_size=int(content.get("original_size")),
        plaintext_sha256=str(content.get("plaintext_sha256") or ""),
        compression_enabled=bool(compression.get("enabled")),
        compressed_size=int(compression.get("compressed_size")),
        crypto_algorithm=str(crypto.get("algorithm") or ""),
        key_mode=str(crypto.get("key_mode") or ""),
        kdf=crypto.get("kdf") if isinstance(crypto.get("kdf"), dict) else None,
        key_wrap=crypto.get("key_wrap") if isinstance(crypto.get("key_wrap"), dict) else None,
    )
    expected_aad = canonical_json_bytes(expected_aad_payload)
    if aad != expected_aad:
        raise Sox1EnvelopeError("SOX1 AAD does not match envelope metadata")

    aesgcm = _load_aesgcm_class()(key_bytes)
    try:
        compressed_or_plain = aesgcm.decrypt(nonce, ciphertext + tag, aad)
    except Exception as exc:
        raise Sox1DecryptError("SOX1 authenticated decryption failed") from exc

    if compression.get("enabled"):
        try:
            plaintext = zlib.decompress(compressed_or_plain)
        except Exception as exc:
            raise Sox1EnvelopeError("SOX1 zlib decompression failed") from exc
    else:
        plaintext = compressed_or_plain

    expected_size = int(content.get("original_size"))
    expected_sha256 = str(content.get("plaintext_sha256") or "")
    if len(plaintext) != expected_size:
        raise Sox1EnvelopeError("SOX1 plaintext size mismatch")
    if hashlib.sha256(plaintext).hexdigest() != expected_sha256:
        raise Sox1EnvelopeError("SOX1 plaintext sha256 mismatch")
    return plaintext, envelope


def read_sox1_string(value: Optional[str] = None, *, input_string_file: Optional[Path] = None) -> str:
    if value and input_string_file:
        raise Sox1EnvelopeError("use only one of --input-string or --input-string-file")
    if input_string_file is not None:
        return Path(input_string_file).read_text(encoding="utf-8").strip()
    if not value:
        raise Sox1EnvelopeError("SOX1 input string is required")
    candidate = Path(value)
    if not str(value).startswith(SOX1_PREFIX) and candidate.exists() and candidate.is_file():
        return candidate.read_text(encoding="utf-8").strip()
    return str(value).strip()


def write_text_atomic(path: Path, text: str) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(out)
    return out


def write_bytes_atomic(path: Path, data: bytes) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(out)
    return out


__all__ = [
    "AES_GCM_ALGORITHM",
    "DEFAULT_MAX_PLAINTEXT_BYTES",
    "DEFAULT_MAX_SOX1_CHARS",
    "ENVELOPE_SCHEMA",
    "ENVELOPE_VERSION",
    "SOX1_PREFIX",
    "Sox1DecryptError",
    "Sox1EnvelopeError",
    "b64u_decode",
    "b64u_encode",
    "canonical_json_bytes",
    "decode_sox1_envelope",
    "decrypt_sox1_to_bytes",
    "encrypt_bytes_to_sox1",
    "read_sox1_string",
    "write_bytes_atomic",
    "write_text_atomic",
]
