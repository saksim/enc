#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Runtime core for protected Python modules.

This file is intentionally small. The build tool copies an equivalent runtime
into a randomized .pyx file and compiles it into a native extension.

V0.3 Code Protection Layer boundary:
  - This runtime owns protected-module payload decryption, compile/exec
    injection, license-file lookup, and runtime integrity checks.
  - It is not an OCR/QR scanner and is not part of SOX1 cross-media recovery.
  - It must remain decoupled from `soenc cm receive`; possession of this runtime
    never substitutes for keeping key-file/passphrase/private-key material out
    of images, manifests, reports, logs, and dist artifacts.
"""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime
from datetime import timezone
from pathlib import Path
from typing import Iterable
from typing import MutableMapping
from typing import Sequence
from typing import Tuple

from Crypto.Cipher import AES

Payload = Tuple[str, str, str]
LICENSE_FILE_ENV = "SOENC_LICENSE_FILE"
LICENSE_MACHINE_FINGERPRINT_ENV = "SOENC_MACHINE_FINGERPRINT"
LICENSE_REVOCATION_FILE_ENV = "SOENC_LICENSE_REVOCATION_FILE"
LICENSE_VERIFY_KEY_ENV = "SOENC_LICENSE_VERIFY_KEY_B64"
LICENSE_SCHEMA = "enc2sop-license/v1"
LICENSE_VERSION = 1
LICENSE_PATH_POLICY_ENV_ONLY = "env-only"
LICENSE_PATH_POLICY_BUNDLED_RELATIVE = "bundled-relative"
LICENSE_SIGNATURE_ALGORITHM = "hmac-sha256"
REMOTE_KMS_MODE = "remote-kms"
REMOTE_KMS_RESPONSE_SCHEMA = "enc2sop-kms-response/v1"
SOENC_RUNTIME_API_MARKER = "enc2sop-runtime-core-v1"
SOENC_RUNTIME_API_VERSION = 1


def _join_key(parts: Sequence[str]) -> bytes:
    """Rebuild a key from XOR shards without storing the raw key contiguously."""
    if not parts:
        raise ValueError("missing key parts")

    decoded = [base64.b64decode(part) for part in parts]
    key_len = len(decoded[0])
    if any(len(part) != key_len for part in decoded):
        raise ValueError("invalid key parts")

    out = bytearray(decoded[0])
    for part in decoded[1:]:
        for index, value in enumerate(part):
            out[index] ^= value
    return bytes(out)


def _canonical_json_bytes(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _decode_license_key(key_b64) -> bytes:
    if not isinstance(key_b64, str) or not key_b64.strip():
        raise ValueError("license key entry must be a non-empty base64 string")
    try:
        key = base64.b64decode(key_b64, validate=True)
    except Exception as exc:
        raise ValueError("license key entry is not valid base64") from exc
    if len(key) not in (16, 24, 32):
        raise ValueError("license key entry must decode to 16/24/32-byte AES key")
    return key


def _decode_license_verify_key(key_b64) -> bytes:
    if not isinstance(key_b64, str) or not key_b64.strip():
        raise ValueError("{0} is required for signed license verification".format(LICENSE_VERIFY_KEY_ENV))
    try:
        key = base64.b64decode(key_b64, validate=True)
    except Exception as exc:
        raise ValueError("{0} is not valid base64".format(LICENSE_VERIFY_KEY_ENV)) from exc
    key = key.strip()
    if len(key) < 16:
        raise ValueError("license verify key must be at least 16 bytes")
    return key


def _resolve_license_path(key_ref) -> Path:
    env_override = os.environ.get(LICENSE_FILE_ENV, "").strip()
    if env_override:
        return Path(env_override).expanduser().resolve()

    path_policy = str(key_ref.get("license_path_policy") or LICENSE_PATH_POLICY_ENV_ONLY).strip().lower()
    if path_policy == LICENSE_PATH_POLICY_ENV_ONLY:
        raise ValueError("{0} is required for license-file key mode".format(LICENSE_FILE_ENV))
    if path_policy != LICENSE_PATH_POLICY_BUNDLED_RELATIVE:
        raise ValueError("unsupported license path policy: {0}".format(path_policy or "<empty>"))

    license_file = str(key_ref.get("license_file") or "").strip().replace("\\", "/")
    if not license_file:
        raise ValueError("license-file key_ref missing license_file")
    relative = Path(license_file)
    if relative.is_absolute():
        raise ValueError("license_file in key_ref must be relative")
    if ".." in relative.parts:
        raise ValueError("license_file in key_ref must not contain parent traversal")

    runtime_dir = Path(__file__).resolve().parent
    for base in (runtime_dir, *runtime_dir.parents):
        candidate = (base / relative).resolve()
        if candidate.exists():
            return candidate
    raise ValueError("license file not found: {0}".format(license_file))


def _verify_license_signature(payload) -> None:
    signature = payload.get("signature")
    if not isinstance(signature, dict):
        raise ValueError("license signature missing")
    if signature.get("algorithm") != LICENSE_SIGNATURE_ALGORITHM:
        raise ValueError("unsupported license signature algorithm")
    digest_hex = signature.get("digest_hex")
    if not isinstance(digest_hex, str) or not digest_hex:
        raise ValueError("license signature digest missing")
    signing_payload = dict(payload)
    signing_payload.pop("signature", None)
    key = _decode_license_verify_key(os.environ.get(LICENSE_VERIFY_KEY_ENV, ""))
    expected = hmac.new(key, _canonical_json_bytes(signing_payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, digest_hex):
        raise ValueError("license signature mismatch")


def _license_revocation_ids(payload):
    revocation_path = os.environ.get(LICENSE_REVOCATION_FILE_ENV, "").strip()
    if not revocation_path:
        return set()
    try:
        data = json.loads(Path(revocation_path).expanduser().read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("failed to parse license revocation file: {0}".format(revocation_path)) from exc
    if isinstance(data, list):
        return {str(item).strip() for item in data if str(item).strip()}
    if isinstance(data, dict):
        ids = data.get("revoked_license_ids", data.get("revoked"))
        if isinstance(ids, list):
            return {str(item).strip() for item in ids if str(item).strip()}
    raise ValueError("license revocation file must be a JSON list or object with revoked_license_ids")


def _validate_license_status(payload) -> None:
    status = str(payload.get("status") or "active").strip().lower()
    if payload.get("revoked") is True or status == "revoked":
        raise ValueError("license has been revoked")
    if status not in ("active",):
        raise ValueError("unsupported license status: {0}".format(status or "<empty>"))
    license_id = str(payload.get("license_id") or "").strip()
    if license_id and license_id in _license_revocation_ids(payload):
        raise ValueError("license has been revoked")


def _validate_license_expiry(payload) -> None:
    expires_at = str(payload.get("expires_at") or "").strip()
    if not expires_at:
        return
    parse_text = expires_at[:-1] + "+00:00" if expires_at.endswith("Z") else expires_at
    try:
        expires = datetime.fromisoformat(parse_text)
    except ValueError as exc:
        raise ValueError("license expires_at is invalid") from exc
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires.astimezone(timezone.utc):
        raise ValueError("license has expired")


def _validate_machine_binding(payload) -> None:
    binding = payload.get("machine_binding")
    if not isinstance(binding, dict) or not binding.get("required"):
        return
    if binding.get("algorithm") != "sha256-exact-env-v1":
        raise ValueError("unsupported license machine binding algorithm")
    expected = str(binding.get("fingerprint_sha256") or "").strip().lower()
    if not expected:
        raise ValueError("license machine fingerprint digest missing")
    observed = os.environ.get(str(binding.get("env") or LICENSE_MACHINE_FINGERPRINT_ENV), "").strip()
    if not observed:
        raise ValueError("{0} is required by this license".format(binding.get("env") or LICENSE_MACHINE_FINGERPRINT_ENV))
    actual = hashlib.sha256(observed.encode("utf-8")).hexdigest()
    if actual != expected:
        raise ValueError("license machine fingerprint mismatch")


def _load_license_payload(key_ref):
    license_path = _resolve_license_path(key_ref)
    try:
        payload = json.loads(license_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError("license file not found: {0}".format(license_path)) from exc
    except Exception as exc:
        raise ValueError("failed to parse license file: {0}".format(license_path)) from exc
    if not isinstance(payload, dict):
        raise ValueError("license payload must be a JSON object")
    return payload


def _license_key_from_ref(key_ref) -> bytes:
    if not isinstance(key_ref, dict):
        raise ValueError("license-file key_ref must be a dict")
    key_id = str(key_ref.get("key_id") or "").strip()
    if not key_id:
        raise ValueError("license-file key_ref missing key_id")

    payload = _load_license_payload(key_ref)
    if payload.get("schema") != LICENSE_SCHEMA:
        raise ValueError("unsupported license schema")
    if payload.get("version") != LICENSE_VERSION:
        raise ValueError("unsupported license version")
    if str(payload.get("mode") or "").strip().lower() != "license-file":
        raise ValueError("license mode mismatch")
    license_id = str(key_ref.get("license_id") or "").strip()
    if license_id and str(payload.get("license_id") or "").strip() != license_id:
        raise ValueError("license_id mismatch")

    integrity = payload.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError("license integrity missing")
    if integrity.get("algorithm") != "sha256":
        raise ValueError("unsupported license integrity algorithm")
    digest_hex = integrity.get("digest_hex")
    if not isinstance(digest_hex, str) or not digest_hex:
        raise ValueError("license integrity digest missing")
    unsigned = dict(payload)
    unsigned.pop("integrity", None)
    unsigned.pop("signature", None)
    expected = hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()
    if expected != digest_hex:
        raise ValueError("license integrity mismatch")

    signature_policy = key_ref.get("license_signature")
    signature_required = bool(signature_policy.get("required")) if isinstance(signature_policy, dict) else False
    if signature_required or (payload.get("signature") is not None and os.environ.get(LICENSE_VERIFY_KEY_ENV, "").strip()):
        _verify_license_signature(payload)

    _validate_license_status(payload)
    _validate_license_expiry(payload)
    _validate_machine_binding(payload)

    keys = payload.get("keys")
    if not isinstance(keys, dict):
        raise ValueError("license keys missing")
    key_b64 = keys.get(key_id)
    if key_b64 is None:
        raise ValueError("license missing key_id: {0}".format(key_id))
    return _decode_license_key(key_b64)


def _decode_remote_plaintext_key(value) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("remote-kms response plaintext_key_b64 must be a non-empty base64 string")
    try:
        key = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("remote-kms response plaintext_key_b64 is not valid base64") from exc
    if len(key) not in (16, 24, 32):
        raise ValueError("remote-kms response plaintext_key_b64 must decode to 16/24/32-byte AES key")
    return key


def _remote_kms_retryable_http_status(status_code) -> bool:
    return int(status_code) in (408, 429, 500, 502, 503, 504)


def _remote_kms_unwrap_key(key_ref):
    if not isinstance(key_ref, dict):
        raise ValueError("remote-kms key_ref must be a dict")
    required = ("key_handle", "key_id", "request", "response", "retry_policy", "error_policy")
    missing = [name for name in required if key_ref.get(name) in (None, "")]
    if missing:
        raise ValueError("remote-kms key_ref missing required fields: {0}".format(", ".join(sorted(missing))))
    request = key_ref.get("request")
    if not isinstance(request, dict):
        raise ValueError("remote-kms key_ref request must be a dict")
    if request.get("operation") != "unwrap_data_key":
        raise ValueError("remote-kms request.operation must be unwrap_data_key")
    endpoint = str(request.get("endpoint") or "").strip()
    if not endpoint:
        raise ValueError("remote-kms request.endpoint must be a non-empty string")
    if endpoint.startswith("stub://"):
        raise RuntimeError("remote-kms endpoint is still stubbed: {0}".format(endpoint))
    if not (endpoint.startswith("https://") or endpoint.startswith("http://")):
        raise ValueError("remote-kms request.endpoint must be http(s)")
    token_env = str(request.get("token_env") or "").strip()
    if not token_env:
        raise ValueError("remote-kms request.token_env must be a non-empty string")
    token = os.environ.get(token_env, "").strip()
    if not token:
        raise RuntimeError("remote-kms token env var is missing: {0}".format(token_env))
    response_contract = key_ref.get("response")
    if not isinstance(response_contract, dict):
        raise ValueError("remote-kms key_ref response must be a dict")
    if response_contract.get("schema") != REMOTE_KMS_RESPONSE_SCHEMA:
        raise ValueError("remote-kms response schema mismatch")
    plaintext_field = str(response_contract.get("plaintext_key_field") or "plaintext_key_b64").strip()
    if not plaintext_field:
        raise ValueError("remote-kms response plaintext field must be non-empty")
    retry_policy = key_ref.get("retry_policy") if isinstance(key_ref.get("retry_policy"), dict) else {}
    max_retries = int(retry_policy.get("max_retries") or 0)
    backoff_ms = int(retry_policy.get("backoff_ms") or 0)
    timeout_sec = float(request.get("timeout_sec") or 3.0)
    body = json.dumps(
        {
            "schema": request.get("schema") or "enc2sop-kms-request/v1",
            "operation": "unwrap_data_key",
            "profile": request.get("profile"),
            "key_handle": key_ref.get("key_handle"),
            "key_id": key_ref.get("key_id"),
            "wrapped_key": key_ref.get("wrapped_key"),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    headers = {
        "Authorization": "Bearer {0}".format(token),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    last_error = None
    for attempt in range(max_retries + 1):
        try:
            http_request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(http_request, timeout=timeout_sec) as response:
                raw = response.read()
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                raise ValueError("remote-kms response must be valid JSON") from exc
            if not isinstance(payload, dict):
                raise ValueError("remote-kms response must be a JSON object")
            if payload.get("schema") != REMOTE_KMS_RESPONSE_SCHEMA:
                raise ValueError("remote-kms response schema mismatch")
            key = _decode_remote_plaintext_key(payload.get(plaintext_field))
            expected_fingerprint = str((key_ref.get("wrapped_key") or {}).get("fingerprint_sha256") or "").strip().lower()
            if expected_fingerprint:
                actual_fingerprint = hashlib.sha256(key).hexdigest().lower()
                if actual_fingerprint != expected_fingerprint:
                    raise ValueError("remote-kms plaintext key fingerprint mismatch")
            return key
        except urllib.error.HTTPError as exc:
            last_error = exc
            if _remote_kms_retryable_http_status(exc.code) and attempt < max_retries:
                if backoff_ms > 0:
                    time.sleep(backoff_ms / 1000.0)
                continue
            raise RuntimeError("remote-kms request failed: http {0}".format(exc.code)) from exc
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt < max_retries:
                if backoff_ms > 0:
                    time.sleep(backoff_ms / 1000.0)
                continue
            raise RuntimeError("remote-kms request failed: {0}".format(exc.reason)) from exc
    raise RuntimeError("remote-kms request failed: {0}".format(last_error))


def _resolve_key(key_ref) -> bytes:
    """Resolve key bytes from provider key_ref payload."""
    if isinstance(key_ref, dict):
        mode = str(key_ref.get("mode") or "").strip().lower()
        if mode == "local-embedded":
            parts = key_ref.get("parts")
            if not isinstance(parts, list):
                raise ValueError("local-embedded key_ref missing parts")
            return _join_key(parts)
        if mode == "license-file":
            return _license_key_from_ref(key_ref)
        if mode == REMOTE_KMS_MODE:
            return _remote_kms_unwrap_key(key_ref)
        raise ValueError("unsupported key provider mode: {0}".format(mode or "<empty>"))
    # Backward compatibility for historical protected files that passed raw parts.
    return _join_key(key_ref)


def _x(payloads: Iterable[Payload], key_ref, namespace: MutableMapping[str, object]) -> None:
    """Decrypt payloads and execute them inside the caller module namespace."""
    key = _resolve_key(key_ref)
    key_buf = bytearray(key)
    try:
        key = bytes(key_buf)
        for nonce_b64, tag_b64, body_b64 in payloads:
            cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(nonce_b64))
            source = cipher.decrypt_and_verify(base64.b64decode(body_b64), base64.b64decode(tag_b64))
            exec(compile(source.decode("utf-8"), "<protected>", "exec"), namespace)
    finally:
        for index in range(len(key_buf)):
            key_buf[index] = 0
        key = b""


def runtime_pyx_source() -> str:
    """Return the Cython runtime source used by encryption_helper.py."""
    return '''# cython: language_level=3, binding=False, embedsignature=False
import base64 as _b
import hashlib as _h
import hmac as _hm
import json as _jso
import os as _os
import time as _time
import urllib.error as _urlerr
import urllib.request as _urlreq
from datetime import datetime as _dt, timezone as _tz
from pathlib import Path as _P
from Crypto.Cipher import AES as _A

_ENV = "SOENC_LICENSE_FILE"
_MENV = "SOENC_MACHINE_FINGERPRINT"
_RENV = "SOENC_LICENSE_REVOCATION_FILE"
_VENV = "SOENC_LICENSE_VERIFY_KEY_B64"
_SCHEMA = "enc2sop-license/v1"
_VER = 1
_POLICY_ENV = "env-only"
_POLICY_BUNDLED = "bundled-relative"
_SIG_ALGO = "hmac-sha256"
_KMS_MODE = "remote-kms"
_KMS_RESP_SCHEMA = "enc2sop-kms-response/v1"
SOENC_RUNTIME_API_MARKER = "enc2sop-runtime-core-v1"
SOENC_RUNTIME_API_VERSION = 1


def _j(_parts):
    if not _parts:
        raise ValueError("missing key parts")
    _raw = [_b.b64decode(_p) for _p in _parts]
    _n = len(_raw[0])
    for _p in _raw:
        if len(_p) != _n:
            raise ValueError("invalid key parts")
    _out = bytearray(_raw[0])
    for _p in _raw[1:]:
        for _i, _v in enumerate(_p):
            _out[_i] ^= _v
    return bytes(_out)


def _c(_payload):
    return _jso.dumps(_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _dk(_key_b64):
    if not isinstance(_key_b64, str) or not _key_b64.strip():
        raise ValueError("license key entry must be a non-empty base64 string")
    try:
        _key = _b.b64decode(_key_b64, validate=True)
    except Exception as _exc:
        raise ValueError("license key entry is not valid base64") from _exc
    if len(_key) not in (16, 24, 32):
        raise ValueError("license key entry must decode to 16/24/32-byte AES key")
    return _key


def _dv(_key_b64):
    if not isinstance(_key_b64, str) or not _key_b64.strip():
        raise ValueError("{0} is required for signed license verification".format(_VENV))
    try:
        _key = _b.b64decode(_key_b64, validate=True)
    except Exception as _exc:
        raise ValueError("{0} is not valid base64".format(_VENV)) from _exc
    _key = _key.strip()
    if len(_key) < 16:
        raise ValueError("license verify key must be at least 16 bytes")
    return _key


def _vs(_payload):
    _sig = _payload.get("signature")
    if not isinstance(_sig, dict):
        raise ValueError("license signature missing")
    if _sig.get("algorithm") != _SIG_ALGO:
        raise ValueError("unsupported license signature algorithm")
    _digest = _sig.get("digest_hex")
    if not isinstance(_digest, str) or not _digest:
        raise ValueError("license signature digest missing")
    _unsigned = dict(_payload)
    _unsigned.pop("signature", None)
    _key = _dv(_os.environ.get(_VENV, ""))
    _expected = _hm.new(_key, _c(_unsigned), _h.sha256).hexdigest()
    if not _hm.compare_digest(_expected, _digest):
        raise ValueError("license signature mismatch")


def _rev(_payload):
    _path = _os.environ.get(_RENV, "").strip()
    if not _path:
        return set()
    try:
        _data = _jso.loads(_P(_path).expanduser().read_text(encoding="utf-8"))
    except Exception as _exc:
        raise ValueError("failed to parse license revocation file: {0}".format(_path)) from _exc
    if isinstance(_data, list):
        return {str(_item).strip() for _item in _data if str(_item).strip()}
    if isinstance(_data, dict):
        _ids = _data.get("revoked_license_ids", _data.get("revoked"))
        if isinstance(_ids, list):
            return {str(_item).strip() for _item in _ids if str(_item).strip()}
    raise ValueError("license revocation file must be a JSON list or object with revoked_license_ids")


def _vl(_payload):
    _status = str(_payload.get("status") or "active").strip().lower()
    if _payload.get("revoked") is True or _status == "revoked":
        raise ValueError("license has been revoked")
    if _status not in ("active",):
        raise ValueError("unsupported license status: {0}".format(_status or "<empty>"))
    _lic = str(_payload.get("license_id") or "").strip()
    if _lic and _lic in _rev(_payload):
        raise ValueError("license has been revoked")


def _ve(_payload):
    _expires = str(_payload.get("expires_at") or "").strip()
    if not _expires:
        return
    _parse = _expires[:-1] + "+00:00" if _expires.endswith("Z") else _expires
    try:
        _dt_value = _dt.fromisoformat(_parse)
    except ValueError as _exc:
        raise ValueError("license expires_at is invalid") from _exc
    if _dt_value.tzinfo is None:
        _dt_value = _dt_value.replace(tzinfo=_tz.utc)
    if _dt.now(_tz.utc) > _dt_value.astimezone(_tz.utc):
        raise ValueError("license has expired")


def _vm(_payload):
    _binding = _payload.get("machine_binding")
    if not isinstance(_binding, dict) or not _binding.get("required"):
        return
    if _binding.get("algorithm") != "sha256-exact-env-v1":
        raise ValueError("unsupported license machine binding algorithm")
    _expected = str(_binding.get("fingerprint_sha256") or "").strip().lower()
    if not _expected:
        raise ValueError("license machine fingerprint digest missing")
    _env = str(_binding.get("env") or _MENV)
    _observed = _os.environ.get(_env, "").strip()
    if not _observed:
        raise ValueError("{0} is required by this license".format(_env))
    _actual = _h.sha256(_observed.encode("utf-8")).hexdigest()
    if _actual != _expected:
        raise ValueError("license machine fingerprint mismatch")


def _lp(_key_ref):
    _env = _os.environ.get(_ENV, "").strip()
    if _env:
        return _P(_env).expanduser().resolve()
    _policy = str(_key_ref.get("license_path_policy") or _POLICY_ENV).strip().lower()
    if _policy == _POLICY_ENV:
        raise ValueError("{0} is required for license-file key mode".format(_ENV))
    if _policy != _POLICY_BUNDLED:
        raise ValueError("unsupported license path policy: {0}".format(_policy or "<empty>"))
    _license_file = str(_key_ref.get("license_file") or "").strip().replace("\\\\", "/")
    if not _license_file:
        raise ValueError("license-file key_ref missing license_file")
    _rel = _P(_license_file)
    if _rel.is_absolute():
        raise ValueError("license_file in key_ref must be relative")
    if ".." in _rel.parts:
        raise ValueError("license_file in key_ref must not contain parent traversal")
    _runtime_dir = _P(__file__).resolve().parent
    for _base in (_runtime_dir, *_runtime_dir.parents):
        _candidate = (_base / _rel).resolve()
        if _candidate.exists():
            return _candidate
    raise ValueError("license file not found: {0}".format(_license_file))


def _lk(_key_ref):
    if not isinstance(_key_ref, dict):
        raise ValueError("license-file key_ref must be a dict")
    _key_id = str(_key_ref.get("key_id") or "").strip()
    if not _key_id:
        raise ValueError("license-file key_ref missing key_id")
    _path = _lp(_key_ref)
    try:
        _payload = _jso.loads(_path.read_text(encoding="utf-8"))
    except FileNotFoundError as _exc:
        raise ValueError("license file not found: {0}".format(_path)) from _exc
    except Exception as _exc:
        raise ValueError("failed to parse license file: {0}".format(_path)) from _exc
    if not isinstance(_payload, dict):
        raise ValueError("license payload must be a JSON object")
    if _payload.get("schema") != _SCHEMA:
        raise ValueError("unsupported license schema")
    if _payload.get("version") != _VER:
        raise ValueError("unsupported license version")
    if str(_payload.get("mode") or "").strip().lower() != "license-file":
        raise ValueError("license mode mismatch")
    _license_id = str(_key_ref.get("license_id") or "").strip()
    if _license_id and str(_payload.get("license_id") or "").strip() != _license_id:
        raise ValueError("license_id mismatch")
    _integrity = _payload.get("integrity")
    if not isinstance(_integrity, dict):
        raise ValueError("license integrity missing")
    if _integrity.get("algorithm") != "sha256":
        raise ValueError("unsupported license integrity algorithm")
    _digest_hex = _integrity.get("digest_hex")
    if not isinstance(_digest_hex, str) or not _digest_hex:
        raise ValueError("license integrity digest missing")
    _unsigned = dict(_payload)
    _unsigned.pop("integrity", None)
    _unsigned.pop("signature", None)
    _expected = _h.sha256(_c(_unsigned)).hexdigest()
    if _expected != _digest_hex:
        raise ValueError("license integrity mismatch")
    _sig_policy = _key_ref.get("license_signature")
    _sig_required = bool(_sig_policy.get("required")) if isinstance(_sig_policy, dict) else False
    if _sig_required or (_payload.get("signature") is not None and _os.environ.get(_VENV, "").strip()):
        _vs(_payload)
    _vl(_payload)
    _ve(_payload)
    _vm(_payload)
    _keys = _payload.get("keys")
    if not isinstance(_keys, dict):
        raise ValueError("license keys missing")
    _key_b64 = _keys.get(_key_id)
    if _key_b64 is None:
        raise ValueError("license missing key_id: {0}".format(_key_id))
    return _dk(_key_b64)


def _dkms(_value):
    if not isinstance(_value, str) or not _value.strip():
        raise ValueError("remote-kms response plaintext_key_b64 must be a non-empty base64 string")
    try:
        _key = _b.b64decode(_value, validate=True)
    except Exception as _exc:
        raise ValueError("remote-kms response plaintext_key_b64 is not valid base64") from _exc
    if len(_key) not in (16, 24, 32):
        raise ValueError("remote-kms response plaintext_key_b64 must decode to 16/24/32-byte AES key")
    return _key


def _kr(_code):
    return int(_code) in (408, 429, 500, 502, 503, 504)


def _rk(_key_ref):
    if not isinstance(_key_ref, dict):
        raise ValueError("remote-kms key_ref must be a dict")
    _required = ("key_handle", "key_id", "request", "response", "retry_policy", "error_policy")
    _missing = [_name for _name in _required if _key_ref.get(_name) in (None, "")]
    if _missing:
        raise ValueError("remote-kms key_ref missing required fields: {0}".format(", ".join(sorted(_missing))))
    _request = _key_ref.get("request")
    if not isinstance(_request, dict):
        raise ValueError("remote-kms key_ref request must be a dict")
    if _request.get("operation") != "unwrap_data_key":
        raise ValueError("remote-kms request.operation must be unwrap_data_key")
    _endpoint = str(_request.get("endpoint") or "").strip()
    if not _endpoint:
        raise ValueError("remote-kms request.endpoint must be a non-empty string")
    if _endpoint.startswith("stub://"):
        raise RuntimeError("remote-kms endpoint is still stubbed: {0}".format(_endpoint))
    if not (_endpoint.startswith("https://") or _endpoint.startswith("http://")):
        raise ValueError("remote-kms request.endpoint must be http(s)")
    _token_env = str(_request.get("token_env") or "").strip()
    if not _token_env:
        raise ValueError("remote-kms request.token_env must be a non-empty string")
    _token = _os.environ.get(_token_env, "").strip()
    if not _token:
        raise RuntimeError("remote-kms token env var is missing: {0}".format(_token_env))
    _response_contract = _key_ref.get("response")
    if not isinstance(_response_contract, dict):
        raise ValueError("remote-kms key_ref response must be a dict")
    if _response_contract.get("schema") != _KMS_RESP_SCHEMA:
        raise ValueError("remote-kms response schema mismatch")
    _plaintext_field = str(_response_contract.get("plaintext_key_field") or "plaintext_key_b64").strip()
    if not _plaintext_field:
        raise ValueError("remote-kms response plaintext field must be non-empty")
    _retry_policy = _key_ref.get("retry_policy") if isinstance(_key_ref.get("retry_policy"), dict) else {}
    _max_retries = int(_retry_policy.get("max_retries") or 0)
    _backoff_ms = int(_retry_policy.get("backoff_ms") or 0)
    _timeout_sec = float(_request.get("timeout_sec") or 3.0)
    _body = _jso.dumps(
        {
            "schema": _request.get("schema") or "enc2sop-kms-request/v1",
            "operation": "unwrap_data_key",
            "profile": _request.get("profile"),
            "key_handle": _key_ref.get("key_handle"),
            "key_id": _key_ref.get("key_id"),
            "wrapped_key": _key_ref.get("wrapped_key"),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    _headers = {
        "Authorization": "Bearer {0}".format(_token),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    _last_error = None
    for _attempt in range(_max_retries + 1):
        try:
            _http_request = _urlreq.Request(_endpoint, data=_body, headers=_headers, method="POST")
            with _urlreq.urlopen(_http_request, timeout=_timeout_sec) as _response:
                _raw = _response.read()
            try:
                _payload = _jso.loads(_raw.decode("utf-8"))
            except Exception as _exc:
                raise ValueError("remote-kms response must be valid JSON") from _exc
            if not isinstance(_payload, dict):
                raise ValueError("remote-kms response must be a JSON object")
            if _payload.get("schema") != _KMS_RESP_SCHEMA:
                raise ValueError("remote-kms response schema mismatch")
            _key = _dkms(_payload.get(_plaintext_field))
            _wrapped = _key_ref.get("wrapped_key") or {}
            if not isinstance(_wrapped, dict):
                raise ValueError("remote-kms wrapped_key must be a dict")
            _expected_fp = str(_wrapped.get("fingerprint_sha256") or "").strip().lower()
            if _expected_fp:
                _actual_fp = _h.sha256(_key).hexdigest().lower()
                if _actual_fp != _expected_fp:
                    raise ValueError("remote-kms plaintext key fingerprint mismatch")
            return _key
        except _urlerr.HTTPError as _exc:
            _last_error = _exc
            if _kr(_exc.code) and _attempt < _max_retries:
                if _backoff_ms > 0:
                    _time.sleep(_backoff_ms / 1000.0)
                continue
            raise RuntimeError("remote-kms request failed: http {0}".format(_exc.code)) from _exc
        except _urlerr.URLError as _exc:
            _last_error = _exc
            if _attempt < _max_retries:
                if _backoff_ms > 0:
                    _time.sleep(_backoff_ms / 1000.0)
                continue
            raise RuntimeError("remote-kms request failed: {0}".format(_exc.reason)) from _exc
    raise RuntimeError("remote-kms request failed: {0}".format(_last_error))


def _r(_key_ref):
    if isinstance(_key_ref, dict):
        _mode = str(_key_ref.get("mode") or "").strip().lower()
        if _mode == "local-embedded":
            _parts = _key_ref.get("parts")
            if not isinstance(_parts, list):
                raise ValueError("local-embedded key_ref missing parts")
            return _j(_parts)
        if _mode == "license-file":
            return _lk(_key_ref)
        if _mode == _KMS_MODE:
            return _rk(_key_ref)
        raise ValueError("unsupported key provider mode: {0}".format(_mode or "<empty>"))
    return _j(_key_ref)


def _x(_payloads, _key_ref, _ns):
    _key = _r(_key_ref)
    _key_buf = bytearray(_key)
    try:
        _key = bytes(_key_buf)
        for _nonce, _tag, _body in _payloads:
            _cipher = _A.new(_key, _A.MODE_GCM, nonce=_b.b64decode(_nonce))
            _src = _cipher.decrypt_and_verify(_b.b64decode(_body), _b.b64decode(_tag))
            exec(compile(_src.decode("utf-8"), "<protected>", "exec"), _ns)
    finally:
        for _idx in range(len(_key_buf)):
            _key_buf[_idx] = 0
        _key = b""
'''


def runtime_py_source() -> str:
    """Return the pure-Python runtime source used by encrypted staging files."""
    return '''#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64 as _b
import hashlib as _h
import hmac as _hm
import json as _jso
import os as _os
import time as _time
import urllib.error as _urlerr
import urllib.request as _urlreq
from datetime import datetime as _dt, timezone as _tz
from pathlib import Path as _P
from Crypto.Cipher import AES as _A

_ENV = "SOENC_LICENSE_FILE"
_MENV = "SOENC_MACHINE_FINGERPRINT"
_RENV = "SOENC_LICENSE_REVOCATION_FILE"
_VENV = "SOENC_LICENSE_VERIFY_KEY_B64"
_SCHEMA = "enc2sop-license/v1"
_VER = 1
_POLICY_ENV = "env-only"
_POLICY_BUNDLED = "bundled-relative"
_SIG_ALGO = "hmac-sha256"
_KMS_MODE = "remote-kms"
_KMS_RESP_SCHEMA = "enc2sop-kms-response/v1"
SOENC_RUNTIME_API_MARKER = "enc2sop-runtime-core-v1"
SOENC_RUNTIME_API_VERSION = 1


def _j(_parts):
    if not _parts:
        raise ValueError("missing key parts")
    _raw = [_b.b64decode(_p) for _p in _parts]
    _n = len(_raw[0])
    for _p in _raw:
        if len(_p) != _n:
            raise ValueError("invalid key parts")
    _out = bytearray(_raw[0])
    for _p in _raw[1:]:
        for _i, _v in enumerate(_p):
            _out[_i] ^= _v
    return bytes(_out)


def _c(_payload):
    return _jso.dumps(_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _dk(_key_b64):
    if not isinstance(_key_b64, str) or not _key_b64.strip():
        raise ValueError("license key entry must be a non-empty base64 string")
    try:
        _key = _b.b64decode(_key_b64, validate=True)
    except Exception as _exc:
        raise ValueError("license key entry is not valid base64") from _exc
    if len(_key) not in (16, 24, 32):
        raise ValueError("license key entry must decode to 16/24/32-byte AES key")
    return _key


def _dv(_key_b64):
    if not isinstance(_key_b64, str) or not _key_b64.strip():
        raise ValueError("{0} is required for signed license verification".format(_VENV))
    try:
        _key = _b.b64decode(_key_b64, validate=True)
    except Exception as _exc:
        raise ValueError("{0} is not valid base64".format(_VENV)) from _exc
    _key = _key.strip()
    if len(_key) < 16:
        raise ValueError("license verify key must be at least 16 bytes")
    return _key


def _vs(_payload):
    _sig = _payload.get("signature")
    if not isinstance(_sig, dict):
        raise ValueError("license signature missing")
    if _sig.get("algorithm") != _SIG_ALGO:
        raise ValueError("unsupported license signature algorithm")
    _digest = _sig.get("digest_hex")
    if not isinstance(_digest, str) or not _digest:
        raise ValueError("license signature digest missing")
    _unsigned = dict(_payload)
    _unsigned.pop("signature", None)
    _key = _dv(_os.environ.get(_VENV, ""))
    _expected = _hm.new(_key, _c(_unsigned), _h.sha256).hexdigest()
    if not _hm.compare_digest(_expected, _digest):
        raise ValueError("license signature mismatch")


def _rev(_payload):
    _path = _os.environ.get(_RENV, "").strip()
    if not _path:
        return set()
    try:
        _data = _jso.loads(_P(_path).expanduser().read_text(encoding="utf-8"))
    except Exception as _exc:
        raise ValueError("failed to parse license revocation file: {0}".format(_path)) from _exc
    if isinstance(_data, list):
        return {str(_item).strip() for _item in _data if str(_item).strip()}
    if isinstance(_data, dict):
        _ids = _data.get("revoked_license_ids", _data.get("revoked"))
        if isinstance(_ids, list):
            return {str(_item).strip() for _item in _ids if str(_item).strip()}
    raise ValueError("license revocation file must be a JSON list or object with revoked_license_ids")


def _vl(_payload):
    _status = str(_payload.get("status") or "active").strip().lower()
    if _payload.get("revoked") is True or _status == "revoked":
        raise ValueError("license has been revoked")
    if _status not in ("active",):
        raise ValueError("unsupported license status: {0}".format(_status or "<empty>"))
    _lic = str(_payload.get("license_id") or "").strip()
    if _lic and _lic in _rev(_payload):
        raise ValueError("license has been revoked")


def _ve(_payload):
    _expires = str(_payload.get("expires_at") or "").strip()
    if not _expires:
        return
    _parse = _expires[:-1] + "+00:00" if _expires.endswith("Z") else _expires
    try:
        _dt_value = _dt.fromisoformat(_parse)
    except ValueError as _exc:
        raise ValueError("license expires_at is invalid") from _exc
    if _dt_value.tzinfo is None:
        _dt_value = _dt_value.replace(tzinfo=_tz.utc)
    if _dt.now(_tz.utc) > _dt_value.astimezone(_tz.utc):
        raise ValueError("license has expired")


def _vm(_payload):
    _binding = _payload.get("machine_binding")
    if not isinstance(_binding, dict) or not _binding.get("required"):
        return
    if _binding.get("algorithm") != "sha256-exact-env-v1":
        raise ValueError("unsupported license machine binding algorithm")
    _expected = str(_binding.get("fingerprint_sha256") or "").strip().lower()
    if not _expected:
        raise ValueError("license machine fingerprint digest missing")
    _env = str(_binding.get("env") or _MENV)
    _observed = _os.environ.get(_env, "").strip()
    if not _observed:
        raise ValueError("{0} is required by this license".format(_env))
    _actual = _h.sha256(_observed.encode("utf-8")).hexdigest()
    if _actual != _expected:
        raise ValueError("license machine fingerprint mismatch")


def _lp(_key_ref):
    _env = _os.environ.get(_ENV, "").strip()
    if _env:
        return _P(_env).expanduser().resolve()
    _policy = str(_key_ref.get("license_path_policy") or _POLICY_ENV).strip().lower()
    if _policy == _POLICY_ENV:
        raise ValueError("{0} is required for license-file key mode".format(_ENV))
    if _policy != _POLICY_BUNDLED:
        raise ValueError("unsupported license path policy: {0}".format(_policy or "<empty>"))
    _license_file = str(_key_ref.get("license_file") or "").strip().replace("\\\\", "/")
    if not _license_file:
        raise ValueError("license-file key_ref missing license_file")
    _rel = _P(_license_file)
    if _rel.is_absolute():
        raise ValueError("license_file in key_ref must be relative")
    if ".." in _rel.parts:
        raise ValueError("license_file in key_ref must not contain parent traversal")
    _runtime_dir = _P(__file__).resolve().parent
    for _base in (_runtime_dir, *_runtime_dir.parents):
        _candidate = (_base / _rel).resolve()
        if _candidate.exists():
            return _candidate
    raise ValueError("license file not found: {0}".format(_license_file))


def _lk(_key_ref):
    if not isinstance(_key_ref, dict):
        raise ValueError("license-file key_ref must be a dict")
    _key_id = str(_key_ref.get("key_id") or "").strip()
    if not _key_id:
        raise ValueError("license-file key_ref missing key_id")
    _path = _lp(_key_ref)
    try:
        _payload = _jso.loads(_path.read_text(encoding="utf-8"))
    except FileNotFoundError as _exc:
        raise ValueError("license file not found: {0}".format(_path)) from _exc
    except Exception as _exc:
        raise ValueError("failed to parse license file: {0}".format(_path)) from _exc
    if not isinstance(_payload, dict):
        raise ValueError("license payload must be a JSON object")
    if _payload.get("schema") != _SCHEMA:
        raise ValueError("unsupported license schema")
    if _payload.get("version") != _VER:
        raise ValueError("unsupported license version")
    if str(_payload.get("mode") or "").strip().lower() != "license-file":
        raise ValueError("license mode mismatch")
    _license_id = str(_key_ref.get("license_id") or "").strip()
    if _license_id and str(_payload.get("license_id") or "").strip() != _license_id:
        raise ValueError("license_id mismatch")
    _integrity = _payload.get("integrity")
    if not isinstance(_integrity, dict):
        raise ValueError("license integrity missing")
    if _integrity.get("algorithm") != "sha256":
        raise ValueError("unsupported license integrity algorithm")
    _digest_hex = _integrity.get("digest_hex")
    if not isinstance(_digest_hex, str) or not _digest_hex:
        raise ValueError("license integrity digest missing")
    _unsigned = dict(_payload)
    _unsigned.pop("integrity", None)
    _unsigned.pop("signature", None)
    _expected = _h.sha256(_c(_unsigned)).hexdigest()
    if _expected != _digest_hex:
        raise ValueError("license integrity mismatch")
    _sig_policy = _key_ref.get("license_signature")
    _sig_required = bool(_sig_policy.get("required")) if isinstance(_sig_policy, dict) else False
    if _sig_required or (_payload.get("signature") is not None and _os.environ.get(_VENV, "").strip()):
        _vs(_payload)
    _vl(_payload)
    _ve(_payload)
    _vm(_payload)
    _keys = _payload.get("keys")
    if not isinstance(_keys, dict):
        raise ValueError("license keys missing")
    _key_b64 = _keys.get(_key_id)
    if _key_b64 is None:
        raise ValueError("license missing key_id: {0}".format(_key_id))
    return _dk(_key_b64)


def _dkms(_value):
    if not isinstance(_value, str) or not _value.strip():
        raise ValueError("remote-kms response plaintext_key_b64 must be a non-empty base64 string")
    try:
        _key = _b.b64decode(_value, validate=True)
    except Exception as _exc:
        raise ValueError("remote-kms response plaintext_key_b64 is not valid base64") from _exc
    if len(_key) not in (16, 24, 32):
        raise ValueError("remote-kms response plaintext_key_b64 must decode to 16/24/32-byte AES key")
    return _key


def _kr(_code):
    return int(_code) in (408, 429, 500, 502, 503, 504)


def _rk(_key_ref):
    if not isinstance(_key_ref, dict):
        raise ValueError("remote-kms key_ref must be a dict")
    _required = ("key_handle", "key_id", "request", "response", "retry_policy", "error_policy")
    _missing = [_name for _name in _required if _key_ref.get(_name) in (None, "")]
    if _missing:
        raise ValueError("remote-kms key_ref missing required fields: {0}".format(", ".join(sorted(_missing))))
    _request = _key_ref.get("request")
    if not isinstance(_request, dict):
        raise ValueError("remote-kms key_ref request must be a dict")
    if _request.get("operation") != "unwrap_data_key":
        raise ValueError("remote-kms request.operation must be unwrap_data_key")
    _endpoint = str(_request.get("endpoint") or "").strip()
    if not _endpoint:
        raise ValueError("remote-kms request.endpoint must be a non-empty string")
    if _endpoint.startswith("stub://"):
        raise RuntimeError("remote-kms endpoint is still stubbed: {0}".format(_endpoint))
    if not (_endpoint.startswith("https://") or _endpoint.startswith("http://")):
        raise ValueError("remote-kms request.endpoint must be http(s)")
    _token_env = str(_request.get("token_env") or "").strip()
    if not _token_env:
        raise ValueError("remote-kms request.token_env must be a non-empty string")
    _token = _os.environ.get(_token_env, "").strip()
    if not _token:
        raise RuntimeError("remote-kms token env var is missing: {0}".format(_token_env))
    _response_contract = _key_ref.get("response")
    if not isinstance(_response_contract, dict):
        raise ValueError("remote-kms key_ref response must be a dict")
    if _response_contract.get("schema") != _KMS_RESP_SCHEMA:
        raise ValueError("remote-kms response schema mismatch")
    _plaintext_field = str(_response_contract.get("plaintext_key_field") or "plaintext_key_b64").strip()
    if not _plaintext_field:
        raise ValueError("remote-kms response plaintext field must be non-empty")
    _retry_policy = _key_ref.get("retry_policy") if isinstance(_key_ref.get("retry_policy"), dict) else {}
    _max_retries = int(_retry_policy.get("max_retries") or 0)
    _backoff_ms = int(_retry_policy.get("backoff_ms") or 0)
    _timeout_sec = float(_request.get("timeout_sec") or 3.0)
    _body = _jso.dumps(
        {
            "schema": _request.get("schema") or "enc2sop-kms-request/v1",
            "operation": "unwrap_data_key",
            "profile": _request.get("profile"),
            "key_handle": _key_ref.get("key_handle"),
            "key_id": _key_ref.get("key_id"),
            "wrapped_key": _key_ref.get("wrapped_key"),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    _headers = {
        "Authorization": "Bearer {0}".format(_token),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    _last_error = None
    for _attempt in range(_max_retries + 1):
        try:
            _http_request = _urlreq.Request(_endpoint, data=_body, headers=_headers, method="POST")
            with _urlreq.urlopen(_http_request, timeout=_timeout_sec) as _response:
                _raw = _response.read()
            try:
                _payload = _jso.loads(_raw.decode("utf-8"))
            except Exception as _exc:
                raise ValueError("remote-kms response must be valid JSON") from _exc
            if not isinstance(_payload, dict):
                raise ValueError("remote-kms response must be a JSON object")
            if _payload.get("schema") != _KMS_RESP_SCHEMA:
                raise ValueError("remote-kms response schema mismatch")
            _key = _dkms(_payload.get(_plaintext_field))
            _wrapped = _key_ref.get("wrapped_key") or {}
            if not isinstance(_wrapped, dict):
                raise ValueError("remote-kms wrapped_key must be a dict")
            _expected_fp = str(_wrapped.get("fingerprint_sha256") or "").strip().lower()
            if _expected_fp:
                _actual_fp = _h.sha256(_key).hexdigest().lower()
                if _actual_fp != _expected_fp:
                    raise ValueError("remote-kms plaintext key fingerprint mismatch")
            return _key
        except _urlerr.HTTPError as _exc:
            _last_error = _exc
            if _kr(_exc.code) and _attempt < _max_retries:
                if _backoff_ms > 0:
                    _time.sleep(_backoff_ms / 1000.0)
                continue
            raise RuntimeError("remote-kms request failed: http {0}".format(_exc.code)) from _exc
        except _urlerr.URLError as _exc:
            _last_error = _exc
            if _attempt < _max_retries:
                if _backoff_ms > 0:
                    _time.sleep(_backoff_ms / 1000.0)
                continue
            raise RuntimeError("remote-kms request failed: {0}".format(_exc.reason)) from _exc
    raise RuntimeError("remote-kms request failed: {0}".format(_last_error))


def _r(_key_ref):
    if isinstance(_key_ref, dict):
        _mode = str(_key_ref.get("mode") or "").strip().lower()
        if _mode == "local-embedded":
            _parts = _key_ref.get("parts")
            if not isinstance(_parts, list):
                raise ValueError("local-embedded key_ref missing parts")
            return _j(_parts)
        if _mode == "license-file":
            return _lk(_key_ref)
        if _mode == _KMS_MODE:
            return _rk(_key_ref)
        raise ValueError("unsupported key provider mode: {0}".format(_mode or "<empty>"))
    return _j(_key_ref)


def _x(_payloads, _key_ref, _ns):
    _key = _r(_key_ref)
    _key_buf = bytearray(_key)
    try:
        _key = bytes(_key_buf)
        for _nonce, _tag, _body in _payloads:
            _cipher = _A.new(_key, _A.MODE_GCM, nonce=_b.b64decode(_nonce))
            _src = _cipher.decrypt_and_verify(_b.b64decode(_body), _b.b64decode(_tag))
            exec(compile(_src.decode("utf-8"), "<protected>", "exec"), _ns)
    finally:
        for _idx in range(len(_key_buf)):
            _key_buf[_idx] = 0
        _key = b""
'''


__all__ = ["_x", "runtime_pyx_source", "runtime_py_source"]
