#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Local embedded key provider used by the initial platform baseline."""

import base64
from typing import Dict
from typing import Sequence

from Crypto.Random import get_random_bytes

from enc2sop.keys.provider import KeyProvider
from enc2sop.keys.provider import register_key_provider


def _join_parts(parts):
    if not parts:
        raise ValueError("missing key parts")
    decoded = [base64.b64decode(part) for part in parts]
    key_len = len(decoded[0])
    if any(len(item) != key_len for item in decoded):
        raise ValueError("invalid key parts")
    out = bytearray(decoded[0])
    for part in decoded[1:]:
        for index, value in enumerate(part):
            out[index] ^= value
    return bytes(out)


class LocalEmbeddedKeyProvider(KeyProvider):
    """Default provider that wraps key material as XOR shards."""

    mode = "local-embedded"

    def pack_key(self, key_bytes):
        if not key_bytes:
            raise ValueError("key_bytes must not be empty")
        shards = [get_random_bytes(len(key_bytes)) for _ in range(3)]
        final = bytearray(key_bytes)
        for shard in shards:
            for index, value in enumerate(shard):
                final[index] ^= value
        shards.append(bytes(final))
        return {
            "mode": self.mode,
            "parts": [base64.b64encode(item).decode("ascii") for item in shards],
        }

    def resolve_key(self, key_ref):
        if not isinstance(key_ref, dict):
            raise ValueError("key_ref must be a dict")
        if str(key_ref.get("mode") or "").strip().lower() != self.mode:
            raise ValueError("key_ref mode mismatch")
        parts = key_ref.get("parts")
        if not isinstance(parts, list):
            raise ValueError("local-embedded key_ref missing parts list")
        return _join_parts(tuple(parts))


def unpack_local_embedded_key(parts):
    return _join_parts(parts)


register_key_provider(LocalEmbeddedKeyProvider())

