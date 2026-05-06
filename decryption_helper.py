#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Runtime core for protected Python modules.

This file is intentionally small. The build tool copies an equivalent runtime
into a randomized .pyx file and compiles it into a native extension.
"""

import base64
from typing import Iterable
from typing import MutableMapping
from typing import Sequence
from typing import Tuple

from Crypto.Cipher import AES

Payload = Tuple[str, str, str]


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


def _resolve_key(key_ref) -> bytes:
    """Resolve key bytes from provider key_ref payload."""
    if isinstance(key_ref, dict):
        mode = str(key_ref.get("mode") or "").strip().lower()
        if mode == "local-embedded":
            parts = key_ref.get("parts")
            if not isinstance(parts, list):
                raise ValueError("local-embedded key_ref missing parts")
            return _join_key(parts)
        raise ValueError("unsupported key provider mode: {0}".format(mode or "<empty>"))
    # Backward compatibility for historical protected files that passed raw parts.
    return _join_key(key_ref)


def _x(payloads: Iterable[Payload], key_ref, namespace: MutableMapping[str, object]) -> None:
    """Decrypt payloads and execute them inside the caller module namespace."""
    key = _resolve_key(key_ref)
    for nonce_b64, tag_b64, body_b64 in payloads:
        cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(nonce_b64))
        source = cipher.decrypt_and_verify(base64.b64decode(body_b64), base64.b64decode(tag_b64))
        exec(compile(source.decode("utf-8"), "<protected>", "exec"), namespace)


def runtime_pyx_source() -> str:
    """Return the Cython runtime source used by encryption_helper.py."""
    return '''# cython: language_level=3, binding=False, embedsignature=False
import base64 as _b
from Crypto.Cipher import AES as _A


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


def _r(_key_ref):
    if isinstance(_key_ref, dict):
        _mode = str(_key_ref.get("mode") or "").strip().lower()
        if _mode == "local-embedded":
            _parts = _key_ref.get("parts")
            if not isinstance(_parts, list):
                raise ValueError("local-embedded key_ref missing parts")
            return _j(_parts)
        raise ValueError("unsupported key provider mode: {0}".format(_mode or "<empty>"))
    return _j(_key_ref)


def _x(_payloads, _key_ref, _ns):
    _key = _r(_key_ref)
    for _nonce, _tag, _body in _payloads:
        _cipher = _A.new(_key, _A.MODE_GCM, nonce=_b.b64decode(_nonce))
        _src = _cipher.decrypt_and_verify(_b.b64decode(_body), _b.b64decode(_tag))
        exec(compile(_src.decode("utf-8"), "<protected>", "exec"), _ns)
'''


def runtime_py_source() -> str:
    """Return the pure-Python runtime source used by encrypted staging files."""
    return '''#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64 as _b
from Crypto.Cipher import AES as _A


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


def _r(_key_ref):
    if isinstance(_key_ref, dict):
        _mode = str(_key_ref.get("mode") or "").strip().lower()
        if _mode == "local-embedded":
            _parts = _key_ref.get("parts")
            if not isinstance(_parts, list):
                raise ValueError("local-embedded key_ref missing parts")
            return _j(_parts)
        raise ValueError("unsupported key provider mode: {0}".format(_mode or "<empty>"))
    return _j(_key_ref)


def _x(_payloads, _key_ref, _ns):
    _key = _r(_key_ref)
    for _nonce, _tag, _body in _payloads:
        _cipher = _A.new(_key, _A.MODE_GCM, nonce=_b.b64decode(_nonce))
        _src = _cipher.decrypt_and_verify(_b.b64decode(_body), _b.b64decode(_tag))
        exec(compile(_src.decode("utf-8"), "<protected>", "exec"), _ns)
'''


__all__ = ["_x", "runtime_pyx_source", "runtime_py_source"]
