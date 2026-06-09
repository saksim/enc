#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for P1-S2 SOX1 large-file volume groups."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


KEY = bytes(range(32))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cli_volume_encrypt_decrypt_roundtrip_large_file(tmp_path: Path) -> None:
    key_path = tmp_path / "key.bin"
    plain_path = tmp_path / "large.bin"
    volumes_dir = tmp_path / "volumes"
    restored_path = tmp_path / "restored.bin"
    key_path.write_bytes(KEY)
    plain = (bytes(range(256)) * 1200) + b"tail"
    plain_path.write_bytes(plain)

    encrypt = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "volume-encrypt",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--output-dir",
            str(volumes_dir),
            "--volume-bytes",
            "100000",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    decrypt = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "volume-decrypt",
            "--input-dir",
            str(volumes_dir),
            "--key-file",
            str(key_path),
            "--output",
            str(restored_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    manifest = json.loads((volumes_dir / "group_manifest.json").read_text(encoding="utf-8"))
    volume_files = sorted(volumes_dir.glob("volume_*.sox1"))
    assert restored_path.read_bytes() == plain
    assert _sha256(restored_path) == _sha256(plain_path)
    assert manifest["schema"] == "enc2sop-cross-media-volume-manifest/v1"
    assert manifest["volume_count"] == len(volume_files)
    assert manifest["volume_count"] > 1
    assert manifest["plaintext_sha256"] == _sha256(plain_path)
    assert all(path.read_text(encoding="utf-8").startswith("SOX1.") for path in volume_files)
    assert "volumes=" in encrypt.stdout
    assert "output_sha256=" in decrypt.stdout


def test_cli_volume_decrypt_missing_volume_fails_without_output(tmp_path: Path) -> None:
    key_path = tmp_path / "key.bin"
    plain_path = tmp_path / "large.bin"
    volumes_dir = tmp_path / "volumes"
    restored_path = tmp_path / "restored.bin"
    key_path.write_bytes(KEY)
    plain_path.write_bytes(bytes(range(256)) * 600)
    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "volume-encrypt",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--output-dir",
            str(volumes_dir),
            "--volume-bytes",
            "65536",
        ],
        check=True,
    )
    sorted(volumes_dir.glob("volume_*.sox1"))[0].unlink()

    result = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "volume-decrypt",
            "--input-dir",
            str(volumes_dir),
            "--key-file",
            str(key_path),
            "--output",
            str(restored_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 21
    assert "volume file missing" in result.stderr
    assert not restored_path.exists()


def test_cli_volume_decrypt_rejects_manifest_sha_tamper(tmp_path: Path) -> None:
    key_path = tmp_path / "key.bin"
    plain_path = tmp_path / "large.bin"
    volumes_dir = tmp_path / "volumes"
    restored_path = tmp_path / "restored.bin"
    key_path.write_bytes(KEY)
    plain_path.write_bytes(b"manifest sha tamper" * 10000)
    subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "volume-encrypt",
            "--input",
            str(plain_path),
            "--key-file",
            str(key_path),
            "--output-dir",
            str(volumes_dir),
            "--volume-bytes",
            "50000",
        ],
        check=True,
    )
    manifest_path = volumes_dir / "group_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["plaintext_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "soenc.py",
            "cm",
            "volume-decrypt",
            "--input-dir",
            str(volumes_dir),
            "--key-file",
            str(key_path),
            "--output",
            str(restored_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 21
    assert "restored file sha256" in result.stderr
    assert not restored_path.exists()
