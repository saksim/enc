#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for P1-S1 hybrid public-key SOX1 envelopes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from enc2sop.crossmedia import crypto_envelope
from enc2sop.crossmedia import key_material


def _require_public_key_backend() -> None:
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")


def test_cli_public_key_encrypt_decrypt_roundtrip(tmp_path: Path) -> None:
    _require_public_key_backend()
    public_path = tmp_path / "recipient.public.pem"
    private_path = tmp_path / "recipient.private.pem"
    plain_path = tmp_path / "secret.bin"
    sox1_path = tmp_path / "secret.sox1"
    restored_path = tmp_path / "restored.bin"
    plain = b"public key encrypted cross media payload" + bytes(range(32))
    plain_path.write_bytes(plain)

    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "keygen-public",
            "--public",
            str(public_path),
            "--private",
            str(private_path),
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "encrypt",
            "--input",
            str(plain_path),
            "--recipient-public-key",
            str(public_path),
            "--out-string",
            str(sox1_path),
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "decrypt",
            "--input-string-file",
            str(sox1_path),
            "--private-key",
            str(private_path),
            "--output",
            str(restored_path),
        ],
        check=True,
    )

    assert restored_path.read_bytes() == plain
    envelope = crypto_envelope.decode_sox1_envelope(sox1_path.read_text(encoding="utf-8"))
    crypto = envelope["crypto"]
    key_wrap = crypto["key_wrap"]
    assert crypto["key_mode"] == key_material.PUBLIC_KEY_MODE
    assert key_wrap["algorithm"] == key_material.PUBLIC_KEY_WRAP_ALGORITHM
    assert key_wrap["encrypted_key_b64u"]
    assert "recipient_public_key_sha256" in key_wrap
    envelope_json = json.dumps(envelope, sort_keys=True)
    assert plain.decode("latin1", errors="ignore") not in envelope_json
    assert private_path.read_text(encoding="utf-8").strip() not in envelope_json


def test_cli_public_key_wrong_private_key_fails_without_output(tmp_path: Path) -> None:
    _require_public_key_backend()
    public_path = tmp_path / "recipient.public.pem"
    private_path = tmp_path / "recipient.private.pem"
    wrong_public_path = tmp_path / "wrong.public.pem"
    wrong_private_path = tmp_path / "wrong.private.pem"
    plain_path = tmp_path / "secret.bin"
    sox1_path = tmp_path / "secret.sox1"
    restored_path = tmp_path / "restored.bin"
    plain_path.write_bytes(b"wrong private key must not decrypt")

    subprocess.run(
        [sys.executable, "soenc.py", "cm", "keygen-public", "--public", str(public_path), "--private", str(private_path)],
        check=True,
    )
    subprocess.run(
        [sys.executable, "soenc.py", "cm", "keygen-public", "--public", str(wrong_public_path), "--private", str(wrong_private_path)],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "encrypt",
            "--input",
            str(plain_path),
            "--recipient-public-key",
            str(public_path),
            "--out-string",
            str(sox1_path),
        ],
        check=True,
    )

    result = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "decrypt",
            "--input-string-file",
            str(sox1_path),
            "--private-key",
            str(wrong_private_path),
            "--output",
            str(restored_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 11
    assert "data key unwrap failed" in result.stderr
    assert not restored_path.exists()


def test_cli_public_key_rejects_ambiguous_encrypt_key_modes(tmp_path: Path) -> None:
    _require_public_key_backend()
    public_path = tmp_path / "recipient.public.pem"
    private_path = tmp_path / "recipient.private.pem"
    key_path = tmp_path / "key.bin"
    plain_path = tmp_path / "plain.bin"
    sox1_path = tmp_path / "payload.sox1"
    key_path.write_bytes(bytes(range(32)))
    plain_path.write_bytes(b"ambiguous key modes")
    key_material.generate_public_key_pair(public_path=public_path, private_path=private_path)

    result = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "encrypt",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--recipient-public-key",
            str(public_path),
            "--out-string",
            str(sox1_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "use exactly one" in result.stderr
