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
import json
import os
from pathlib import Path
from typing import Iterable
from typing import MutableMapping
from typing import Sequence
from typing import Tuple

from Crypto.Cipher import AES

Payload = Tuple[str, str, str]
LICENSE_FILE_ENV = "SOENC_LICENSE_FILE"
LICENSE_SCHEMA = "enc2sop-license/v1"
LICENSE_VERSION = 1
REMOTE_KMS_MODE = "remote-kms"
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


def _resolve_license_path(key_ref) -> Path:
    env_override = os.environ.get(LICENSE_FILE_ENV, "").strip()
    if env_override:
        return Path(env_override).expanduser().resolve()

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
    expected = hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()
    if expected != digest_hex:
        raise ValueError("license integrity mismatch")

    keys = payload.get("keys")
    if not isinstance(keys, dict):
        raise ValueError("license keys missing")
    key_b64 = keys.get(key_id)
    if key_b64 is None:
        raise ValueError("license missing key_id: {0}".format(key_id))
    return _decode_license_key(key_b64)


def _remote_kms_stub_error(key_ref):
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
    token_env = str(request.get("token_env") or "").strip()
    if not token_env:
        raise ValueError("remote-kms request.token_env must be a non-empty string")
    if not os.environ.get(token_env, "").strip():
        raise RuntimeError("remote-kms token env var is missing: {0}".format(token_env))
    raise RuntimeError(
        "remote-kms provider is configured but runtime integration is stubbed; "
        "implement remote unwrap client for key_handle={0}".format(key_ref.get("key_handle"))
    )


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
            return _remote_kms_stub_error(key_ref)
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
import json as _jso
import os as _os
from pathlib import Path as _P
from Crypto.Cipher import AES as _A

_ENV = "SOENC_LICENSE_FILE"
_SCHEMA = "enc2sop-license/v1"
_VER = 1
_KMS_MODE = "remote-kms"
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


def _lp(_key_ref):
    _env = _os.environ.get(_ENV, "").strip()
    if _env:
        return _P(_env).expanduser().resolve()
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
    _expected = _h.sha256(_c(_unsigned)).hexdigest()
    if _expected != _digest_hex:
        raise ValueError("license integrity mismatch")
    _keys = _payload.get("keys")
    if not isinstance(_keys, dict):
        raise ValueError("license keys missing")
    _key_b64 = _keys.get(_key_id)
    if _key_b64 is None:
        raise ValueError("license missing key_id: {0}".format(_key_id))
    return _dk(_key_b64)


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
    _token_env = str(_request.get("token_env") or "").strip()
    if not _token_env:
        raise ValueError("remote-kms request.token_env must be a non-empty string")
    if not _os.environ.get(_token_env, "").strip():
        raise RuntimeError("remote-kms token env var is missing: {0}".format(_token_env))
    raise RuntimeError(
        "remote-kms provider is configured but runtime integration is stubbed; "
        "implement remote unwrap client for key_handle={0}".format(_key_ref.get("key_handle"))
    )


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
import json as _jso
import os as _os
from pathlib import Path as _P
from Crypto.Cipher import AES as _A

_ENV = "SOENC_LICENSE_FILE"
_SCHEMA = "enc2sop-license/v1"
_VER = 1
_KMS_MODE = "remote-kms"
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


def _lp(_key_ref):
    _env = _os.environ.get(_ENV, "").strip()
    if _env:
        return _P(_env).expanduser().resolve()
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
    _expected = _h.sha256(_c(_unsigned)).hexdigest()
    if _expected != _digest_hex:
        raise ValueError("license integrity mismatch")
    _keys = _payload.get("keys")
    if not isinstance(_keys, dict):
        raise ValueError("license keys missing")
    _key_b64 = _keys.get(_key_id)
    if _key_b64 is None:
        raise ValueError("license missing key_id: {0}".format(_key_id))
    return _dk(_key_b64)


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
    _token_env = str(_request.get("token_env") or "").strip()
    if not _token_env:
        raise ValueError("remote-kms request.token_env must be a non-empty string")
    if not _os.environ.get(_token_env, "").strip():
        raise RuntimeError("remote-kms token env var is missing: {0}".format(_token_env))
    raise RuntimeError(
        "remote-kms provider is configured but runtime integration is stubbed; "
        "implement remote unwrap client for key_handle={0}".format(_key_ref.get("key_handle"))
    )


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
