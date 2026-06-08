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
PUBLIC_KEY_MODE = "recipient-public-key-rsa-oaep-sha256"
PUBLIC_KEY_WRAP_ALGORITHM = "RSA-OAEP-SHA256"
DEFAULT_RSA_KEY_SIZE = 3072


class KeyMaterialError(ValueError):
    """Raised when key material is missing or invalid."""


class KeyUnwrapError(KeyMaterialError):
    """Raised when a wrapped data key cannot be decrypted by a private key."""


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


def _write_bytes_atomic(path: Path, data: bytes) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(out)
    return out


def _load_serialization_module():
    try:
        from cryptography.hazmat.primitives import serialization
    except Exception as exc:  # pragma: no cover - exercised only in missing dependency envs
        raise RuntimeError("cryptography is required for P1 public-key mode") from exc
    return serialization


def _load_rsa_module():
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
    except Exception as exc:  # pragma: no cover - exercised only in missing dependency envs
        raise RuntimeError("cryptography RSA support is required for P1 public-key mode") from exc
    return rsa


def generate_public_key_pair(
    *,
    public_path: Path,
    private_path: Path,
    overwrite: bool = False,
    key_size: int = DEFAULT_RSA_KEY_SIZE,
) -> tuple[Path, Path]:
    """Generate an RSA-OAEP key pair for P1 hybrid public-key envelopes."""

    public_out = Path(public_path)
    private_out = Path(private_path)
    if public_out.exists() and not overwrite:
        raise KeyMaterialError("public key already exists; use --overwrite to replace it: {0}".format(public_out))
    if private_out.exists() and not overwrite:
        raise KeyMaterialError("private key already exists; use --overwrite to replace it: {0}".format(private_out))
    rsa = _load_rsa_module()
    serialization = _load_serialization_module()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=int(key_size))
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_bytes_atomic(private_out, private_pem)
    _write_bytes_atomic(public_out, public_pem)
    return public_out, private_out


def load_public_key(path: Path):
    serialization = _load_serialization_module()
    key_path = Path(path)
    if not key_path.exists():
        raise KeyMaterialError("public key file not found: {0}".format(key_path))
    try:
        public_key = serialization.load_pem_public_key(key_path.read_bytes())
    except Exception as exc:
        raise KeyMaterialError("public key PEM is invalid: {0}".format(key_path)) from exc
    if not hasattr(public_key, "encrypt"):
        raise KeyMaterialError("public key does not support encryption: {0}".format(key_path))
    return public_key


def load_private_key(path: Path):
    serialization = _load_serialization_module()
    key_path = Path(path)
    if not key_path.exists():
        raise KeyMaterialError("private key file not found: {0}".format(key_path))
    try:
        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except Exception as exc:
        raise KeyMaterialError("private key PEM is invalid: {0}".format(key_path)) from exc
    if not hasattr(private_key, "decrypt"):
        raise KeyMaterialError("private key does not support decryption: {0}".format(key_path))
    return private_key


def public_key_sha256_hex(public_key) -> str:
    serialization = _load_serialization_module()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).hexdigest()


def _rsa_oaep_sha256_padding():
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except Exception as exc:  # pragma: no cover - exercised only in missing dependency envs
        raise RuntimeError("cryptography RSA-OAEP support is required for P1 public-key mode") from exc
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def wrap_data_key_rsa_oaep_sha256(public_key, data_key: bytes) -> bytes:
    raw_key = normalize_key_bytes(bytes(data_key))
    try:
        return public_key.encrypt(raw_key, _rsa_oaep_sha256_padding())
    except Exception as exc:
        raise KeyMaterialError("failed to wrap data key with recipient public key") from exc


def unwrap_data_key_rsa_oaep_sha256(private_key, wrapped_data_key: bytes) -> bytes:
    try:
        data_key = private_key.decrypt(bytes(wrapped_data_key), _rsa_oaep_sha256_padding())
    except Exception as exc:
        raise KeyUnwrapError("wrapped data key could not be unwrapped by private key") from exc
    return normalize_key_bytes(data_key)


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
    "DEFAULT_RSA_KEY_SIZE",
    "KeyMaterialError",
    "KeyUnwrapError",
    "PASSPHRASE_ENV",
    "PUBLIC_KEY_MODE",
    "PUBLIC_KEY_WRAP_ALGORITHM",
    "SCRYPT_N",
    "SCRYPT_NAME",
    "SCRYPT_MAXMEM",
    "SCRYPT_P",
    "SCRYPT_R",
    "SCRYPT_SALT_BYTES",
    "build_scrypt_kdf_metadata",
    "derive_key_from_passphrase",
    "generate_key_file",
    "generate_public_key_pair",
    "load_key_file",
    "load_private_key",
    "load_public_key",
    "normalize_key_bytes",
    "passphrase_from_env",
    "public_key_sha256_hex",
    "unwrap_data_key_rsa_oaep_sha256",
    "wrap_data_key_rsa_oaep_sha256",
]
