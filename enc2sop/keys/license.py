#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""License-file key provider for non-embedded runtime key delivery."""

import base64
import hashlib
import json
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Dict
from typing import Optional

from enc2sop.keys.provider import KeyProvider
from enc2sop.keys.provider import register_key_provider

LICENSE_FILE_ENV = "SOENC_LICENSE_FILE"
DEFAULT_LICENSE_FILE = "soenc.license.json"
LICENSE_SCHEMA = "enc2sop-license/v1"
LICENSE_VERSION = 1


def _canonical_json_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _decode_key_b64(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("license key entry must be a non-empty base64 string")
    try:
        key = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("license key entry is not valid base64") from exc
    if len(key) not in (16, 24, 32):
        raise ValueError("license key entry must decode to 16/24/32-byte AES key")
    return key


def _normalize_license_file(value):
    text = str(value or DEFAULT_LICENSE_FILE).strip().replace("\\", "/")
    if not text:
        text = DEFAULT_LICENSE_FILE
    path = Path(text)
    if path.is_absolute():
        raise ValueError("license file path must be relative to output directory")
    normalized = path.as_posix()
    if normalized.startswith("../") or normalized == "..":
        raise ValueError("license file path must not escape output directory")
    return normalized


def _utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


class LicenseFileKeyProvider(KeyProvider):
    """Provider that stores wrapped runtime keys in an external license file."""

    mode = "license-file"

    def __init__(self):
        self._key_entries = {}  # type: Dict[str, str]
        self._license_id = None  # type: Optional[str]
        self._license_file = DEFAULT_LICENSE_FILE
        self._active = False

    def begin_run(self, context):
        context = context if isinstance(context, dict) else {}
        self._key_entries = {}
        self._license_id = str(context.get("license_id") or "").strip() or ("lic_" + secrets.token_hex(8))
        self._license_file = _normalize_license_file(context.get("license_file"))
        self._active = True

    def pack_key(self, key_bytes):
        if not key_bytes:
            raise ValueError("key_bytes must not be empty")
        if not self._active:
            self.begin_run({})
        key_id = "k_" + secrets.token_hex(8)
        self._key_entries[key_id] = base64.b64encode(bytes(key_bytes)).decode("ascii")
        return {
            "mode": self.mode,
            "license_id": self._license_id,
            "license_file": self._license_file,
            "key_id": key_id,
        }

    def resolve_key(self, key_ref):
        if not isinstance(key_ref, dict):
            raise ValueError("key_ref must be a dict")
        if str(key_ref.get("mode") or "").strip().lower() != self.mode:
            raise ValueError("key_ref mode mismatch")
        key_id = str(key_ref.get("key_id") or "").strip()
        if not key_id:
            raise ValueError("license-file key_ref missing key_id")
        key_b64 = self._key_entries.get(key_id)
        if key_b64 is None:
            raise ValueError("unknown key_id for current provider run: {0}".format(key_id))
        return _decode_key_b64(key_b64)

    def finalize_run(self, output_dir, manifest):
        if not self._active:
            return manifest

        output_root = Path(output_dir).resolve()
        license_path = (output_root / self._license_file).resolve()
        try:
            license_path.relative_to(output_root)
        except ValueError as exc:
            raise ValueError("license file path escapes output directory") from exc

        payload = {
            "schema": LICENSE_SCHEMA,
            "version": LICENSE_VERSION,
            "mode": self.mode,
            "license_id": self._license_id,
            "issued_at": _utc_now_iso(),
            "keys": dict(self._key_entries),
        }
        payload["integrity"] = {
            "algorithm": "sha256",
            "digest_hex": hashlib.sha256(_canonical_json_bytes(payload)).hexdigest(),
        }
        license_path.parent.mkdir(parents=True, exist_ok=True)
        license_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

        merged_manifest = dict(manifest)
        key_management = dict(merged_manifest.get("key_management") or {})
        key_management.update(
            {
                "mode": self.mode,
                "provider": "enc2sop.keys.license",
                "license_file": self._license_file,
                "license_id": self._license_id,
                "license_schema": LICENSE_SCHEMA,
                "license_key_count": len(self._key_entries),
                "runtime_env": LICENSE_FILE_ENV,
            }
        )
        merged_manifest["key_management"] = key_management
        return merged_manifest


register_key_provider(LicenseFileKeyProvider())
