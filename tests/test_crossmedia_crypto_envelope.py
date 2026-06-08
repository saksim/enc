#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for SOX1 cross-media crypto envelopes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from enc2sop.crossmedia import crypto_envelope
from enc2sop.crossmedia import key_material


KEY = bytes(range(32))
WRONG_KEY = bytes(reversed(range(32)))


def test_encrypt_decrypt_roundtrip_key_file() -> None:
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(b"hello sox1", key=KEY, name="hello.txt", created_at_utc="2026-06-08T00:00:00Z")
    restored, envelope = crypto_envelope.decrypt_sox1_to_bytes(sox1, key=KEY)

    assert restored == b"hello sox1"
    assert sox1.startswith(crypto_envelope.SOX1_PREFIX)
    assert envelope["schema"] == crypto_envelope.ENVELOPE_SCHEMA
    assert envelope["crypto"]["algorithm"] == crypto_envelope.AES_GCM_ALGORITHM


def test_encrypt_decrypt_roundtrip_passphrase() -> None:
    salt = b"s" * key_material.SCRYPT_SALT_BYTES
    key = key_material.derive_key_from_passphrase("correct horse battery staple", salt)
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(
        b"passphrase payload",
        key=key,
        key_mode="passphrase-scrypt",
        kdf=key_material.build_scrypt_kdf_metadata(crypto_envelope.b64u_encode(salt)),
        created_at_utc="2026-06-08T00:00:00Z",
    )
    restored, envelope = crypto_envelope.decrypt_sox1_to_bytes(sox1, key=key)

    assert restored == b"passphrase payload"
    assert envelope["crypto"]["key_mode"] == "passphrase-scrypt"
    assert envelope["crypto"]["kdf"]["name"] == "scrypt"


def test_decrypt_fails_with_wrong_key() -> None:
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(b"secret", key=KEY, created_at_utc="2026-06-08T00:00:00Z")

    with pytest.raises(crypto_envelope.Sox1DecryptError):
        crypto_envelope.decrypt_sox1_to_bytes(sox1, key=WRONG_KEY)


def _mutate_sox1_json(sox1: str, mutator) -> str:
    payload = crypto_envelope.decode_sox1_envelope(sox1)
    mutator(payload)
    return crypto_envelope.SOX1_PREFIX + crypto_envelope.b64u_encode(crypto_envelope.canonical_json_bytes(payload))


def test_decrypt_fails_after_ciphertext_tamper() -> None:
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(b"secret", key=KEY, created_at_utc="2026-06-08T00:00:00Z")

    def mutate(payload: dict) -> None:
        ciphertext = payload["crypto"]["ciphertext_b64u"]
        payload["crypto"]["ciphertext_b64u"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]

    tampered = _mutate_sox1_json(sox1, mutate)
    with pytest.raises(crypto_envelope.Sox1DecryptError):
        crypto_envelope.decrypt_sox1_to_bytes(tampered, key=KEY)


def test_decrypt_fails_after_aad_tamper() -> None:
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(b"secret", key=KEY, name="a.bin", created_at_utc="2026-06-08T00:00:00Z")

    def mutate(payload: dict) -> None:
        payload["content"]["name"] = "b.bin"

    tampered = _mutate_sox1_json(sox1, mutate)
    with pytest.raises(crypto_envelope.Sox1EnvelopeError, match="AAD"):
        crypto_envelope.decrypt_sox1_to_bytes(tampered, key=KEY)


def test_decrypt_fails_after_unencrypted_metadata_tamper() -> None:
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(b"secret", key=KEY, created_at_utc="2026-06-08T00:00:00Z")

    def mutate(payload: dict) -> None:
        payload["compression"]["compressed_size"] = int(payload["compression"]["compressed_size"]) + 1

    tampered = _mutate_sox1_json(sox1, mutate)
    with pytest.raises(crypto_envelope.Sox1EnvelopeError, match="AAD"):
        crypto_envelope.decrypt_sox1_to_bytes(tampered, key=KEY)


def test_envelope_does_not_embed_key_material() -> None:
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(b"not the key", key=KEY, created_at_utc="2026-06-08T00:00:00Z")
    envelope_json = json.dumps(crypto_envelope.decode_sox1_envelope(sox1), sort_keys=True)

    assert KEY.hex() not in envelope_json
    assert crypto_envelope.b64u_encode(KEY) not in envelope_json
    assert "not the key" not in sox1
    assert "local-embedded" not in envelope_json


def test_binary_file_roundtrip(tmp_path: Path) -> None:
    key_path = tmp_path / "key.bin"
    plain_path = tmp_path / "plain.bin"
    sox1_path = tmp_path / "payload.sox1"
    restored_path = tmp_path / "restored.bin"
    key_path.write_bytes(KEY)
    plain = bytes(range(256)) * 3
    plain_path.write_bytes(plain)

    subprocess.run(
        [sys.executable, "soenc.py", "cm", "encrypt", "--input", str(plain_path), "--key-file", str(key_path), "--out-string", str(sox1_path)],
        check=True,
    )
    subprocess.run(
        [sys.executable, "soenc.py", "cm", "decrypt", "--input-string-file", str(sox1_path), "--key-file", str(key_path), "--output", str(restored_path)],
        check=True,
    )

    assert restored_path.read_bytes() == plain


def test_rejects_bad_sox1_prefix() -> None:
    with pytest.raises(crypto_envelope.Sox1EnvelopeError, match="SOX1"):
        crypto_envelope.decrypt_sox1_to_bytes("BAD.payload", key=KEY)


def test_rejects_unknown_schema_version() -> None:
    sox1 = crypto_envelope.encrypt_bytes_to_sox1(b"secret", key=KEY, created_at_utc="2026-06-08T00:00:00Z")

    def mutate(payload: dict) -> None:
        payload["version"] = 999

    tampered = _mutate_sox1_json(sox1, mutate)
    with pytest.raises(crypto_envelope.Sox1EnvelopeError, match="version"):
        crypto_envelope.decode_sox1_envelope(tampered)


def test_key_file_requires_32_bytes_after_decoding(tmp_path: Path) -> None:
    bad_key = tmp_path / "bad.key"
    bad_key.write_bytes(b"short")

    with pytest.raises(key_material.KeyMaterialError):
        key_material.load_key_file(bad_key)


def test_key_file_accepts_hex_and_base64_text(tmp_path: Path) -> None:
    hex_key = tmp_path / "key.hex"
    b64_key = tmp_path / "key.b64"
    hex_key.write_text(KEY.hex(), encoding="ascii")
    b64_key.write_text(crypto_envelope.b64u_encode(KEY), encoding="ascii")

    assert key_material.load_key_file(hex_key) == KEY
    assert key_material.load_key_file(b64_key) == KEY


def test_cli_keygen_creates_raw_32_byte_key(tmp_path: Path) -> None:
    key_path = tmp_path / "generated.key"
    subprocess.run([sys.executable, "soenc.py", "cm", "keygen", "--key-file", str(key_path)], check=True)

    assert key_path.exists()
    assert len(key_path.read_bytes()) == 32


def test_cli_wrong_key_returns_decrypt_error_code(tmp_path: Path) -> None:
    key_path = tmp_path / "key.bin"
    wrong_path = tmp_path / "wrong.bin"
    plain_path = tmp_path / "plain.bin"
    sox1_path = tmp_path / "payload.sox1"
    restored_path = tmp_path / "restored.bin"
    key_path.write_bytes(KEY)
    wrong_path.write_bytes(WRONG_KEY)
    plain_path.write_bytes(b"secret")

    subprocess.run(
        [sys.executable, "soenc.py", "cm", "encrypt", "--input", str(plain_path), "--key-file", str(key_path), "--out-string", str(sox1_path)],
        check=True,
    )
    result = subprocess.run(
        [sys.executable, "soenc.py", "cm", "decrypt", "--input-string-file", str(sox1_path), "--key-file", str(wrong_path), "--output", str(restored_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 11
    assert "authenticated decryption failed" in result.stderr
    assert not restored_path.exists()
