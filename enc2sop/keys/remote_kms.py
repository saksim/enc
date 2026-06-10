#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Remote-KMS key provider contract and HTTP JSON unwrap metadata."""

import hashlib
import secrets
from typing import Dict
from typing import Optional

from enc2sop.keys.provider import KeyProvider
from enc2sop.keys.provider import register_key_provider

REMOTE_KMS_MODE = "remote-kms"
REMOTE_KMS_REQUEST_SCHEMA = "enc2sop-kms-request/v1"
REMOTE_KMS_RESPONSE_SCHEMA = "enc2sop-kms-response/v1"
REMOTE_KMS_TOKEN_ENV = "SOENC_KMS_TOKEN"
REMOTE_KMS_DEFAULT_PROFILE = "default"
REMOTE_KMS_DEFAULT_ENDPOINT = ""
REMOTE_KMS_DEFAULT_KEY_ID = "kms-key-default"
REMOTE_KMS_DEFAULT_TIMEOUT_SEC = 3.0
REMOTE_KMS_DEFAULT_MAX_RETRIES = 2
REMOTE_KMS_DEFAULT_RETRY_BACKOFF_MS = 250


def _normalize_text(value, field_name):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        raise ValueError("{0} must be a non-empty string when provided".format(field_name))
    return text


def _normalize_timeout(value):
    if value is None:
        return REMOTE_KMS_DEFAULT_TIMEOUT_SEC
    try:
        timeout = float(value)
    except Exception as exc:
        raise ValueError("kms_timeout_sec must be numeric") from exc
    if timeout <= 0:
        raise ValueError("kms_timeout_sec must be > 0")
    return timeout


def _normalize_non_negative_int(value, field_name, default_value):
    if value is None:
        return default_value
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("{0} must be an integer".format(field_name))
    if value < 0:
        raise ValueError("{0} must be >= 0".format(field_name))
    return value


class RemoteKmsKeyProvider(KeyProvider):
    """
    Provider for remote-KMS runtime key unwrap integration.

    Key refs include the HTTP JSON request/response/retry/error contract used
    by the protected-module runtime. This provider never resolves remote keys
    locally; runtime must call the configured KMS endpoint and fail closed.
    """

    mode = REMOTE_KMS_MODE

    def __init__(self):
        self._active = False
        self._kms_profile = REMOTE_KMS_DEFAULT_PROFILE
        self._kms_endpoint = REMOTE_KMS_DEFAULT_ENDPOINT
        self._kms_key_id = REMOTE_KMS_DEFAULT_KEY_ID
        self._kms_token_env = REMOTE_KMS_TOKEN_ENV
        self._kms_timeout_sec = REMOTE_KMS_DEFAULT_TIMEOUT_SEC
        self._kms_max_retries = REMOTE_KMS_DEFAULT_MAX_RETRIES
        self._kms_retry_backoff_ms = REMOTE_KMS_DEFAULT_RETRY_BACKOFF_MS
        self._wrapped_key_count = 0

    def begin_run(self, context):
        context = context if isinstance(context, dict) else {}
        self._kms_profile = _normalize_text(context.get("kms_profile"), "kms_profile") or REMOTE_KMS_DEFAULT_PROFILE
        self._kms_endpoint = _normalize_text(context.get("kms_endpoint"), "kms_endpoint") or REMOTE_KMS_DEFAULT_ENDPOINT
        if not self._kms_endpoint:
            raise ValueError("kms_endpoint is required when keys.mode=remote-kms")
        if not (self._kms_endpoint.startswith("https://") or self._kms_endpoint.startswith("http://")):
            raise ValueError("kms_endpoint must be http(s)")
        self._kms_key_id = _normalize_text(context.get("kms_key_id"), "kms_key_id") or REMOTE_KMS_DEFAULT_KEY_ID
        self._kms_token_env = _normalize_text(context.get("kms_token_env"), "kms_token_env") or REMOTE_KMS_TOKEN_ENV
        self._kms_timeout_sec = _normalize_timeout(context.get("kms_timeout_sec"))
        self._kms_max_retries = _normalize_non_negative_int(
            context.get("kms_max_retries"),
            "kms_max_retries",
            REMOTE_KMS_DEFAULT_MAX_RETRIES,
        )
        self._kms_retry_backoff_ms = _normalize_non_negative_int(
            context.get("kms_retry_backoff_ms"),
            "kms_retry_backoff_ms",
            REMOTE_KMS_DEFAULT_RETRY_BACKOFF_MS,
        )
        self._wrapped_key_count = 0
        self._active = True

    def pack_key(self, key_bytes):
        if not key_bytes:
            raise ValueError("key_bytes must not be empty")
        if not self._active:
            self.begin_run({})

        key_handle = "rk_" + secrets.token_hex(8)
        self._wrapped_key_count += 1
        return {
            "mode": self.mode,
            "key_handle": key_handle,
            "key_id": self._kms_key_id,
            "wrapped_key": {
                "scheme": "kms-handle-v1",
                "fingerprint_sha256": hashlib.sha256(bytes(key_bytes)).hexdigest(),
            },
            "request": {
                "schema": REMOTE_KMS_REQUEST_SCHEMA,
                "operation": "unwrap_data_key",
                "profile": self._kms_profile,
                "endpoint": self._kms_endpoint,
                "token_env": self._kms_token_env,
                "timeout_sec": self._kms_timeout_sec,
            },
            "response": {
                "schema": REMOTE_KMS_RESPONSE_SCHEMA,
                "plaintext_key_field": "plaintext_key_b64",
            },
            "retry_policy": {
                "max_retries": self._kms_max_retries,
                "backoff_ms": self._kms_retry_backoff_ms,
                "retryable_errors": ["timeout", "unavailable", "throttled"],
            },
            "error_policy": {
                "mode": "fail-closed",
                "fatal_errors": ["unauthorized", "not_found", "integrity_error", "contract_error"],
            },
        }

    def resolve_key(self, key_ref):
        raise RuntimeError(
            "remote-kms provider cannot resolve keys locally; runtime must call an external KMS integration"
        )

    def finalize_run(self, output_dir, manifest):
        if not self._active:
            return manifest
        merged_manifest = dict(manifest)
        key_management = dict(merged_manifest.get("key_management") or {})
        key_management.update(
            {
                "mode": self.mode,
                "provider": "enc2sop.keys.remote_kms",
                "kms_profile": self._kms_profile,
                "kms_endpoint": self._kms_endpoint,
                "kms_key_id": self._kms_key_id,
                "kms_token_env": self._kms_token_env,
                "kms_request_schema": REMOTE_KMS_REQUEST_SCHEMA,
                "kms_response_schema": REMOTE_KMS_RESPONSE_SCHEMA,
                "kms_retry_policy": {
                    "max_retries": self._kms_max_retries,
                    "backoff_ms": self._kms_retry_backoff_ms,
                    "retryable_errors": ["timeout", "unavailable", "throttled"],
                },
                "kms_error_policy": {
                    "mode": "fail-closed",
                    "fatal_errors": ["unauthorized", "not_found", "integrity_error", "contract_error"],
                },
                "kms_runtime_client": {
                    "implemented": True,
                    "protocol": "http-json-unwrap-v1",
                    "auth": "bearer-token-env",
                    "plaintext_key_field": "plaintext_key_b64",
                    "fail_closed": True,
                },
                "kms_server_requirements": {
                    "identity_auth": True,
                    "audit_logging": True,
                    "revocation": True,
                    "rate_limiting": True,
                    "no_long_term_master_key_to_client": True,
                },
                "wrapped_key_count": self._wrapped_key_count,
            }
        )
        merged_manifest["key_management"] = key_management
        return merged_manifest


register_key_provider(RemoteKmsKeyProvider())
