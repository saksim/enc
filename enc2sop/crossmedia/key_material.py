#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Key material helpers for cross-media SOX1 envelopes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path
from typing import Dict
from typing import Optional

KEY_LEN = 32
PASSPHRASE_ENV = "SOENC_CM_PASSPHRASE"
SCRYPT_NAME = "scrypt"
SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_BYTES = 16
SCRYPT_MAXMEM = 128 * 1024 * 1024


class KeyMaterialError(ValueError):
    """Raised when key material is missing or invalid."""


def _strip_text_key(raw: bytes) -> str:
    try:
        return raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return ""


def _decode_text_key(text: str) -> Optional[bytes]:
    cleaned = "".join(str(text or "").split())
    if not cleaned:
        return None
    if len(cleaned) == KEY_LEN * 2 and all(ch in "0123456789abcdefABCDEF" for ch in cleaned):
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return None
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        padded = cleaned + ("=" * ((4 - len(cleaned) % 4) % 4))
        try:
            return decoder(padded.encode("ascii"))
        except (binascii.Error, ValueError):
            continue
    return None


def normalize_key_bytes(raw: bytes) -> bytes:
    if len(raw) == KEY_LEN:
        return raw
    text = _strip_text_key(raw)
    decoded = _decode_text_key(text) if text else None
    if decoded is None or len(decoded) != KEY_LEN:
        raise KeyMaterialError("key material must decode to exactly 32 bytes")
    return decoded


def load_key_file(path: Path) -> bytes:
    key_path = Path(path)
    if not key_path.exists():
        raise KeyMaterialError("key file not found: {0}".format(key_path))
    if not key_path.is_file():
        raise KeyMaterialError("key path is not a file: {0}".format(key_path))
    return normalize_key_bytes(key_path.read_bytes())


def generate_key_file(path: Path, *, overwrite: bool = False) -> Path:
    key_path = Path(path)
    if key_path.exists() and not overwrite:
        raise KeyMaterialError("key file already exists; use --overwrite to replace it: {0}".format(key_path))
    key_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = key_path.with_suffix(key_path.suffix + ".tmp")
    tmp.write_bytes(os.urandom(KEY_LEN))
    tmp.replace(key_path)
    return key_path


def derive_key_from_passphrase(
    passphrase: str,
    salt: bytes,
    *,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
    key_len: int = KEY_LEN,
) -> bytes:
    if not passphrase:
        raise KeyMaterialError("passphrase must be non-empty")
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=bytes(salt),
        n=int(n),
        r=int(r),
        p=int(p),
        dklen=int(key_len),
        maxmem=SCRYPT_MAXMEM,
    )


def build_scrypt_kdf_metadata(salt_b64u: str) -> Dict[str, object]:
    return {
        "name": SCRYPT_NAME,
        "salt_b64u": salt_b64u,
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "key_len": KEY_LEN,
    }


def passphrase_from_env(env: Optional[dict] = None) -> str:
    source = os.environ if env is None else env
    value = str(source.get(PASSPHRASE_ENV) or "")
    if not value:
        raise KeyMaterialError("--passphrase requires {0} environment variable in non-interactive P0 CLI".format(PASSPHRASE_ENV))
    return value


__all__ = [
    "KEY_LEN",
    "KeyMaterialError",
    "PASSPHRASE_ENV",
    "SCRYPT_N",
    "SCRYPT_NAME",
    "SCRYPT_MAXMEM",
    "SCRYPT_P",
    "SCRYPT_R",
    "SCRYPT_SALT_BYTES",
    "build_scrypt_kdf_metadata",
    "derive_key_from_passphrase",
    "generate_key_file",
    "load_key_file",
    "normalize_key_bytes",
    "passphrase_from_env",
]
