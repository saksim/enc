#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Provider registry for enc2sop key acquisition."""

from typing import Any
from typing import Dict


class KeyProvider(object):
    """Abstract provider contract for wrapped key material."""

    mode = "abstract"

    def pack_key(self, key_bytes):  # pragma: no cover - interface only
        raise NotImplementedError

    def resolve_key(self, key_ref):  # pragma: no cover - interface only
        raise NotImplementedError


_PROVIDERS = {}  # type: Dict[str, KeyProvider]


def register_key_provider(provider):
    if not isinstance(provider, KeyProvider):
        raise TypeError("provider must inherit KeyProvider")
    mode = str(provider.mode or "").strip().lower()
    if not mode:
        raise ValueError("provider mode must be a non-empty string")
    _PROVIDERS[mode] = provider


def get_key_provider(mode):
    if mode is None:
        raise ValueError("key provider mode must not be empty")
    normalized = str(mode).strip().lower()
    provider = _PROVIDERS.get(normalized)
    if provider is None:
        raise ValueError("unsupported key provider mode: {0}".format(mode))
    return provider


def provider_modes():
    return tuple(sorted(_PROVIDERS.keys()))

