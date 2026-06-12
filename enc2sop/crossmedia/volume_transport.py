#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""P1-S2 large-file SOX1 volume transport helpers.

The construction guide defines P1 large-file support as a sequence of
independently authenticated SOX1 envelopes plus a group manifest that verifies
the final restored file SHA256.  This module deliberately does not know about
QR/images; each volume remains a normal SOX1 string that can be rendered by the
existing visual transport layer later.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict
from typing import Optional

from . import crypto_envelope

VOLUME_MANIFEST_SCHEMA = "enc2sop-cross-media-volume-manifest/v1"
VOLUME_MANIFEST_NAME = "group_manifest.json"
DEFAULT_VOLUME_BYTES = 128 * 1024
MIN_VOLUME_BYTES = 1
MAX_VOLUME_BYTES = crypto_envelope.DEFAULT_MAX_PLAINTEXT_BYTES


class VolumeTransportError(ValueError):
    """Raised when a volume group cannot be safely produced or restored."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(str(text).encode("ascii")).hexdigest()


def _validate_volume_bytes(value: int) -> int:
    volume_bytes = int(value)
    if volume_bytes < MIN_VOLUME_BYTES or volume_bytes > MAX_VOLUME_BYTES:
        raise VolumeTransportError(
            "volume_bytes must be between {0} and {1}; each volume must fit one SOX1 envelope".format(
                MIN_VOLUME_BYTES,
                MAX_VOLUME_BYTES,
            )
        )
    return volume_bytes


def _write_json_atomic(path: Path, payload: Dict[str, object]) -> Path:
    return crypto_envelope.write_text_atomic(
        Path(path),
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _remove_stale_volume_outputs(output_dir: Path) -> None:
    for item in output_dir.glob("volume_*.sox1"):
        if item.is_file():
            item.unlink()
    manifest = output_dir / VOLUME_MANIFEST_NAME
    if manifest.is_file():
        manifest.unlink()


def encrypt_file_to_volumes(
    *,
    input_path: Path,
    output_dir: Path,
    key: bytes,
    volume_bytes: int = DEFAULT_VOLUME_BYTES,
    key_mode: str = "key-file",
    kdf: Optional[Dict[str, object]] = None,
    key_wrap: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    """Encrypt one file into independent SOX1 volume files and a manifest."""

    source = Path(input_path)
    if not source.exists():
        raise FileNotFoundError("input file not found: {0}".format(source))
    if not source.is_file():
        raise VolumeTransportError("input path must be a file: {0}".format(source))
    chunk_size = _validate_volume_bytes(volume_bytes)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    _remove_stale_volume_outputs(output)

    full_hasher = hashlib.sha256()
    volumes = []
    offset = 0
    index = 0
    with source.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk and index > 0:
                break
            index += 1
            full_hasher.update(chunk)
            volume_name = "volume_{0:04d}.sox1".format(index)
            sox1 = crypto_envelope.encrypt_bytes_to_sox1(
                chunk,
                key=key,
                name="{0}.volume_{1:04d}".format(source.name, index),
                key_mode=key_mode,
                kdf=kdf,
                key_wrap=key_wrap,
            )
            crypto_envelope.write_text_atomic(output / volume_name, sox1 + "\n")
            volumes.append(
                {
                    "index": index - 1,
                    "name": volume_name,
                    "plaintext_offset": offset,
                    "plaintext_size": len(chunk),
                    "plaintext_sha256": _sha256_hex(chunk),
                    "sox1_sha256": _sha256_text(sox1),
                }
            )
            offset += len(chunk)
            if not chunk:
                break

    manifest = {
        "schema": VOLUME_MANIFEST_SCHEMA,
        "version": 1,
        "source_name": source.name,
        "original_size": offset,
        "plaintext_sha256": full_hasher.hexdigest(),
        "volume_bytes": chunk_size,
        "volume_count": len(volumes),
        "volumes": volumes,
    }
    _write_json_atomic(output / VOLUME_MANIFEST_NAME, manifest)
    return manifest


def load_group_manifest(input_dir: Path) -> Dict[str, object]:
    manifest_path = Path(input_dir) / VOLUME_MANIFEST_NAME
    if not manifest_path.exists():
        raise VolumeTransportError("volume group manifest not found: {0}".format(manifest_path))
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise VolumeTransportError("volume group manifest JSON is invalid") from exc
    if not isinstance(manifest, dict):
        raise VolumeTransportError("volume group manifest root must be an object")
    if manifest.get("schema") != VOLUME_MANIFEST_SCHEMA:
        raise VolumeTransportError("unsupported volume group manifest schema")
    if manifest.get("version") != 1:
        raise VolumeTransportError("unsupported volume group manifest version")
    volumes = manifest.get("volumes")
    if not isinstance(volumes, list) or not volumes:
        raise VolumeTransportError("volume group manifest must contain at least one volume")
    if int(manifest.get("volume_count")) != len(volumes):
        raise VolumeTransportError("volume group manifest volume_count mismatch")
    return manifest


def _safe_volume_path(input_dir: Path, name: object) -> Path:
    text = str(name or "")
    candidate = Path(text)
    if not text or candidate.is_absolute() or candidate.name != text:
        raise VolumeTransportError("unsafe volume file name in manifest: {0}".format(text))
    if not text.startswith("volume_") or not text.endswith(".sox1"):
        raise VolumeTransportError("unexpected volume file name in manifest: {0}".format(text))
    return Path(input_dir) / text


def decrypt_volumes_to_file(
    *,
    input_dir: Path,
    output_path: Path,
    key: bytes,
) -> Dict[str, object]:
    """Decrypt a SOX1 volume group and verify final group SHA256."""

    root = Path(input_dir)
    manifest = load_group_manifest(root)
    volumes = manifest["volumes"]
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    full_hasher = hashlib.sha256()
    total_size = 0

    try:
        with tmp.open("wb") as restored:
            for expected_index, record in enumerate(volumes):
                if not isinstance(record, dict):
                    raise VolumeTransportError("volume manifest entry must be an object")
                if int(record.get("index")) != expected_index:
                    raise VolumeTransportError("volume manifest index sequence mismatch")
                volume_path = _safe_volume_path(root, record.get("name"))
                if not volume_path.exists():
                    raise VolumeTransportError("volume file missing: {0}".format(volume_path.name))
                sox1 = volume_path.read_text(encoding="utf-8").strip()
                if _sha256_text(sox1) != str(record.get("sox1_sha256") or ""):
                    raise VolumeTransportError("volume SOX1 sha256 mismatch: {0}".format(volume_path.name))
                chunk, _envelope = crypto_envelope.decrypt_sox1_to_bytes(sox1, key=key)
                expected_size = int(record.get("plaintext_size"))
                expected_sha = str(record.get("plaintext_sha256") or "")
                if len(chunk) != expected_size:
                    raise VolumeTransportError("volume plaintext size mismatch: {0}".format(volume_path.name))
                if _sha256_hex(chunk) != expected_sha:
                    raise VolumeTransportError("volume plaintext sha256 mismatch: {0}".format(volume_path.name))
                restored.write(chunk)
                full_hasher.update(chunk)
                total_size += len(chunk)

        if total_size != int(manifest.get("original_size")):
            raise VolumeTransportError("restored file size does not match group manifest")
        if full_hasher.hexdigest() != str(manifest.get("plaintext_sha256") or ""):
            raise VolumeTransportError("restored file sha256 does not match group manifest")
        tmp.replace(output)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise

    return {
        "schema": "enc2sop-cross-media-volume-restore-report/v1",
        "success": True,
        "output": str(output),
        "output_size": total_size,
        "output_sha256": full_hasher.hexdigest(),
        "volume_count": len(volumes),
        "manifest": str(root / VOLUME_MANIFEST_NAME),
    }


__all__ = [
    "DEFAULT_VOLUME_BYTES",
    "MAX_VOLUME_BYTES",
    "MIN_VOLUME_BYTES",
    "VOLUME_MANIFEST_NAME",
    "VOLUME_MANIFEST_SCHEMA",
    "VolumeTransportError",
    "decrypt_volumes_to_file",
    "encrypt_file_to_volumes",
    "load_group_manifest",
]
