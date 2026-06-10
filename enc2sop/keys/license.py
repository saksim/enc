#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""License-file key provider for non-embedded runtime key delivery."""

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Dict
from typing import Optional

from enc2sop.keys.provider import KeyProvider
from enc2sop.keys.provider import register_key_provider

LICENSE_FILE_ENV = "SOENC_LICENSE_FILE"
LICENSE_MACHINE_FINGERPRINT_ENV = "SOENC_MACHINE_FINGERPRINT"
LICENSE_REVOCATION_FILE_ENV = "SOENC_LICENSE_REVOCATION_FILE"
LICENSE_VERIFY_KEY_ENV = "SOENC_LICENSE_VERIFY_KEY_B64"
DEFAULT_LICENSE_FILE = "soenc.license.json"
LICENSE_SCHEMA = "enc2sop-license/v1"
LICENSE_VERSION = 1
LICENSE_PATH_POLICY_ENV_ONLY = "env-only"
LICENSE_PATH_POLICY_BUNDLED_RELATIVE = "bundled-relative"
LICENSE_SIGNATURE_ALGORITHM = "hmac-sha256"
DEFAULT_LICENSE_SIGNATURE_KEY_ID = "license-hmac-v1"


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


def _sha256_text(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


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
        self._bundle_license = False
        self._machine_fingerprint = None  # type: Optional[str]
        self._license_sign_key = None  # type: Optional[bytes]
        self._license_sign_key_id = DEFAULT_LICENSE_SIGNATURE_KEY_ID
        self._active = False

    def begin_run(self, context):
        context = context if isinstance(context, dict) else {}
        self._key_entries = {}
        self._license_id = str(context.get("license_id") or "").strip() or ("lic_" + secrets.token_hex(8))
        self._license_file = _normalize_license_file(context.get("license_file"))
        self._bundle_license = bool(context.get("bundle_license"))
        machine_fingerprint = str(context.get("license_machine_fingerprint") or "").strip()
        self._machine_fingerprint = machine_fingerprint or None
        sign_key = context.get("license_sign_key")
        if sign_key is not None:
            sign_key = bytes(sign_key).strip()
            if len(sign_key) < 16:
                raise ValueError("license signing key must be at least 16 bytes")
        self._license_sign_key = sign_key
        self._license_sign_key_id = (
            str(context.get("license_sign_key_id") or "").strip() or DEFAULT_LICENSE_SIGNATURE_KEY_ID
        )
        self._active = True

    def pack_key(self, key_bytes):
        if not key_bytes:
            raise ValueError("key_bytes must not be empty")
        if not self._active:
            self.begin_run({})
        key_id = "k_" + secrets.token_hex(8)
        self._key_entries[key_id] = base64.b64encode(bytes(key_bytes)).decode("ascii")
        key_ref = {
            "mode": self.mode,
            "license_id": self._license_id,
            "license_file": self._license_file,
            "license_path_policy": (
                LICENSE_PATH_POLICY_BUNDLED_RELATIVE if self._bundle_license else LICENSE_PATH_POLICY_ENV_ONLY
            ),
            "runtime_env": LICENSE_FILE_ENV,
            "machine_fingerprint_env": LICENSE_MACHINE_FINGERPRINT_ENV,
            "revocation_env": LICENSE_REVOCATION_FILE_ENV,
            "key_id": key_id,
        }
        if self._license_sign_key is not None:
            key_ref["license_signature"] = {
                "required": True,
                "algorithm": LICENSE_SIGNATURE_ALGORITHM,
                "key_id": self._license_sign_key_id,
                "verify_key_env": LICENSE_VERIFY_KEY_ENV,
            }
        return key_ref

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
            "status": "active",
            "revoked": False,
            "machine_binding": {
                "required": self._machine_fingerprint is not None,
                "algorithm": "sha256-exact-env-v1",
                "env": LICENSE_MACHINE_FINGERPRINT_ENV,
                "fingerprint_sha256": _sha256_text(self._machine_fingerprint) if self._machine_fingerprint else None,
            },
            "revocation": {
                "env": LICENSE_REVOCATION_FILE_ENV,
                "format": "json-list-or-object-revoked_license_ids",
            },
            "keys": dict(self._key_entries),
        }
        payload["integrity"] = {
            "algorithm": "sha256",
            "digest_hex": hashlib.sha256(_canonical_json_bytes(payload)).hexdigest(),
        }
        if self._license_sign_key is not None:
            payload["signature"] = {
                "algorithm": LICENSE_SIGNATURE_ALGORITHM,
                "key_id": self._license_sign_key_id,
                "verify_key_env": LICENSE_VERIFY_KEY_ENV,
                "digest_hex": hmac.new(
                    self._license_sign_key,
                    _canonical_json_bytes(payload),
                    hashlib.sha256,
                ).hexdigest(),
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
                "license_path_policy": (
                    LICENSE_PATH_POLICY_BUNDLED_RELATIVE if self._bundle_license else LICENSE_PATH_POLICY_ENV_ONLY
                ),
                "license_schema": LICENSE_SCHEMA,
                "license_key_count": len(self._key_entries),
                "runtime_env": LICENSE_FILE_ENV,
                "bundle_license": self._bundle_license,
                "machine_binding": {
                    "required": self._machine_fingerprint is not None,
                    "env": LICENSE_MACHINE_FINGERPRINT_ENV,
                },
                "revocation_env": LICENSE_REVOCATION_FILE_ENV,
                "license_signature_required": self._license_sign_key is not None,
                "license_signature_key_id": self._license_sign_key_id if self._license_sign_key is not None else None,
                "license_verify_key_env": LICENSE_VERIFY_KEY_ENV if self._license_sign_key is not None else None,
            }
        )
        merged_manifest["key_management"] = key_management
        return merged_manifest


register_key_provider(LicenseFileKeyProvider())
