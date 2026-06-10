import base64
import hashlib
import os
import unittest
import json
import urllib.error
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from enc2sop.keys import LicenseFileKeyProvider
from enc2sop.keys import LocalEmbeddedKeyProvider
from enc2sop.keys import RemoteKmsKeyProvider
from enc2sop.keys import get_key_provider
from enc2sop.keys import unpack_local_embedded_key
from enc2sop.keys.provider import KeyProvider
from enc2sop.keys.provider import register_key_provider
from decryption_helper import _license_key_from_ref
from decryption_helper import _remote_kms_unwrap_key
from decryption_helper import _resolve_key
from decryption_helper import runtime_py_source
from decryption_helper import runtime_pyx_source


class _UnitTestProvider(KeyProvider):
    mode = "unit-test-provider"

    def pack_key(self, key_bytes):
        return {"mode": self.mode, "parts": ["AA=="]}

    def resolve_key(self, key_ref):
        return b"\x00"


class _MockHttpResponse:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._payload


def _remote_kms_key_ref(
    key,
    *,
    endpoint="https://kms.example.local/v1/unwrap",
    token_env="SOENC_KMS_TEST_TOKEN",
    max_retries=0,
    backoff_ms=0,
):
    return {
        "mode": "remote-kms",
        "key_handle": "rk_test_handle",
        "key_id": "main-key",
        "wrapped_key": {
            "scheme": "kms-handle-v1",
            "fingerprint_sha256": hashlib.sha256(key).hexdigest(),
        },
        "request": {
            "schema": "enc2sop-kms-request/v1",
            "operation": "unwrap_data_key",
            "profile": "prod",
            "endpoint": endpoint,
            "token_env": token_env,
            "timeout_sec": 4.5,
        },
        "response": {
            "schema": "enc2sop-kms-response/v1",
            "plaintext_key_field": "plaintext_key_b64",
        },
        "retry_policy": {
            "max_retries": max_retries,
            "backoff_ms": backoff_ms,
            "retryable_errors": ["timeout", "unavailable", "throttled"],
        },
        "error_policy": {
            "mode": "fail-closed",
            "fatal_errors": ["unauthorized", "not_found", "integrity_error", "contract_error"],
        },
    }


class KeyProviderTests(unittest.TestCase):
    def test_local_embedded_pack_and_unpack_roundtrip(self):
        provider = LocalEmbeddedKeyProvider()
        key = b"0123456789abcdef0123456789abcdef"
        key_ref = provider.pack_key(key)

        self.assertEqual(key_ref["mode"], "local-embedded")
        self.assertIsInstance(key_ref["parts"], list)
        self.assertEqual(unpack_local_embedded_key(tuple(key_ref["parts"])), key)
        self.assertEqual(provider.resolve_key(key_ref), key)

    def test_provider_registry_returns_local_embedded(self):
        provider = get_key_provider("local-embedded")
        self.assertEqual(provider.mode, "local-embedded")

    def test_register_custom_provider(self):
        register_key_provider(_UnitTestProvider())
        provider = get_key_provider("unit-test-provider")
        self.assertEqual(provider.mode, "unit-test-provider")

    def test_license_file_provider_writes_license_and_manifest_metadata(self):
        provider = LicenseFileKeyProvider()
        with TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            provider.begin_run({"license_file": "keys/runtime.license.json", "license_id": "lic-team"})
            key_ref = provider.pack_key(b"0123456789abcdef0123456789abcdef")

            self.assertEqual(key_ref["mode"], "license-file")
            self.assertEqual(key_ref["license_file"], "keys/runtime.license.json")
            self.assertEqual(key_ref["license_id"], "lic-team")
            self.assertTrue(key_ref["key_id"].startswith("k_"))

            manifest = {"key_management": {"mode": "license-file"}}
            updated = provider.finalize_run(out_dir, manifest)
            license_path = out_dir / "keys" / "runtime.license.json"

            self.assertTrue(license_path.exists())
            payload = json.loads(license_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "enc2sop-license/v1")
            self.assertEqual(payload["mode"], "license-file")
            self.assertEqual(payload["license_id"], "lic-team")
            self.assertIn(key_ref["key_id"], payload["keys"])
            self.assertEqual(
                updated["key_management"]["license_file"],
                "keys/runtime.license.json",
            )
            self.assertEqual(updated["key_management"]["license_path_policy"], "env-only")
            self.assertEqual(updated["key_management"]["runtime_env"], "SOENC_LICENSE_FILE")
            self.assertEqual(key_ref["license_path_policy"], "env-only")

    def test_license_file_runtime_requires_env_by_default(self):
        provider = LicenseFileKeyProvider()
        key = b"0123456789abcdef0123456789abcdef"
        with TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            provider.begin_run({"license_file": "runtime.license.json", "license_id": "lic-env"})
            key_ref = provider.pack_key(key)
            provider.finalize_run(out_dir, {"key_management": {"mode": "license-file"}})

            old_license = os.environ.pop("SOENC_LICENSE_FILE", None)
            try:
                with self.assertRaisesRegex(ValueError, "SOENC_LICENSE_FILE is required"):
                    _license_key_from_ref(key_ref)
                os.environ["SOENC_LICENSE_FILE"] = str(out_dir / "runtime.license.json")
                self.assertEqual(_license_key_from_ref(key_ref), key)
            finally:
                if old_license is None:
                    os.environ.pop("SOENC_LICENSE_FILE", None)
                else:
                    os.environ["SOENC_LICENSE_FILE"] = old_license

    def test_license_file_provider_supports_binding_signature_and_revocation(self):
        provider = LicenseFileKeyProvider()
        key = b"0123456789abcdef0123456789abcdef"
        sign_key = b"fedcba9876543210fedcba9876543210"
        with TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            provider.begin_run(
                {
                    "license_file": "runtime.license.json",
                    "license_id": "lic-bound",
                    "license_subject": "customer-a",
                    "license_expires_at": "2099-01-01T00:00:00Z",
                    "license_allowed_module_hashes": ["pkg/mod.py:sha256:abc123"],
                    "license_machine_fingerprint": "machine-a",
                    "license_sign_key": sign_key,
                    "license_sign_key_id": "lic-signer",
                }
            )
            key_ref = provider.pack_key(key)
            provider.finalize_run(out_dir, {"key_management": {"mode": "license-file"}})
            license_path = out_dir / "runtime.license.json"
            payload = json.loads(license_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["subject"], "customer-a")
            self.assertEqual(payload["expires_at"], "2099-01-01T00:00:00Z")
            self.assertEqual(payload["allowed_module_hashes"], ["pkg/mod.py:sha256:abc123"])
            self.assertEqual(payload["key_envelope"]["format"], "key-id-to-aes-key-b64-map-v1")
            revocation_path = out_dir / "revoked.json"

            old_env = {
                name: os.environ.get(name)
                for name in (
                    "SOENC_LICENSE_FILE",
                    "SOENC_MACHINE_FINGERPRINT",
                    "SOENC_LICENSE_VERIFY_KEY_B64",
                    "SOENC_LICENSE_REVOCATION_FILE",
                )
            }
            try:
                os.environ["SOENC_LICENSE_FILE"] = str(license_path)
                os.environ["SOENC_MACHINE_FINGERPRINT"] = "wrong-machine"
                os.environ["SOENC_LICENSE_VERIFY_KEY_B64"] = base64.b64encode(sign_key).decode("ascii")
                with self.assertRaisesRegex(ValueError, "machine fingerprint mismatch"):
                    _license_key_from_ref(key_ref)

                os.environ["SOENC_MACHINE_FINGERPRINT"] = "machine-a"
                self.assertEqual(_license_key_from_ref(key_ref), key)

                revocation_path.write_text(
                    json.dumps({"revoked_license_ids": ["lic-bound"]}),
                    encoding="utf-8",
                )
                os.environ["SOENC_LICENSE_REVOCATION_FILE"] = str(revocation_path)
                with self.assertRaisesRegex(ValueError, "license has been revoked"):
                    _license_key_from_ref(key_ref)
            finally:
                for name, value in old_env.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value

    def test_license_file_runtime_rejects_expired_license(self):
        provider = LicenseFileKeyProvider()
        key = b"0123456789abcdef0123456789abcdef"
        with TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            provider.begin_run(
                {
                    "license_file": "runtime.license.json",
                    "license_id": "lic-expired",
                    "license_expires_at": "2000-01-01T00:00:00Z",
                }
            )
            key_ref = provider.pack_key(key)
            provider.finalize_run(out_dir, {"key_management": {"mode": "license-file"}})

            old_license = os.environ.get("SOENC_LICENSE_FILE")
            try:
                os.environ["SOENC_LICENSE_FILE"] = str(out_dir / "runtime.license.json")
                with self.assertRaisesRegex(ValueError, "license has expired"):
                    _license_key_from_ref(key_ref)
            finally:
                if old_license is None:
                    os.environ.pop("SOENC_LICENSE_FILE", None)
                else:
                    os.environ["SOENC_LICENSE_FILE"] = old_license

    def test_remote_kms_provider_contract_and_manifest_metadata(self):
        provider = RemoteKmsKeyProvider()
        with TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir)
            provider.begin_run(
                {
                    "kms_profile": "prod",
                    "kms_endpoint": "https://kms.example.local/v1",
                    "kms_key_id": "main-key",
                    "kms_token_env": "CUSTOM_KMS_TOKEN",
                    "kms_timeout_sec": 4.5,
                    "kms_max_retries": 5,
                    "kms_retry_backoff_ms": 900,
                }
            )
            key_ref = provider.pack_key(b"0123456789abcdef0123456789abcdef")

            self.assertEqual(key_ref["mode"], "remote-kms")
            self.assertEqual(key_ref["key_id"], "main-key")
            self.assertEqual(key_ref["request"]["operation"], "unwrap_data_key")
            self.assertEqual(key_ref["request"]["profile"], "prod")
            self.assertEqual(key_ref["request"]["endpoint"], "https://kms.example.local/v1")
            self.assertEqual(key_ref["request"]["token_env"], "CUSTOM_KMS_TOKEN")
            self.assertEqual(key_ref["request"]["timeout_sec"], 4.5)
            self.assertEqual(key_ref["response"]["schema"], "enc2sop-kms-response/v1")
            self.assertEqual(key_ref["retry_policy"]["max_retries"], 5)
            self.assertEqual(key_ref["retry_policy"]["backoff_ms"], 900)
            self.assertIn("fingerprint_sha256", key_ref["wrapped_key"])

            with self.assertRaisesRegex(RuntimeError, "cannot resolve keys locally"):
                provider.resolve_key(key_ref)

            updated = provider.finalize_run(out_dir, {"key_management": {"mode": "remote-kms"}})
            key_mgmt = updated["key_management"]
            self.assertEqual(key_mgmt["mode"], "remote-kms")
            self.assertEqual(key_mgmt["provider"], "enc2sop.keys.remote_kms")
            self.assertEqual(key_mgmt["kms_profile"], "prod")
            self.assertEqual(key_mgmt["kms_endpoint"], "https://kms.example.local/v1")
            self.assertEqual(key_mgmt["kms_key_id"], "main-key")
            self.assertEqual(key_mgmt["kms_token_env"], "CUSTOM_KMS_TOKEN")
            self.assertEqual(key_mgmt["kms_request_schema"], "enc2sop-kms-request/v1")
            self.assertEqual(key_mgmt["kms_response_schema"], "enc2sop-kms-response/v1")
            self.assertTrue(key_mgmt["kms_runtime_client"]["implemented"])
            self.assertEqual(key_mgmt["kms_runtime_client"]["protocol"], "http-json-unwrap-v1")
            self.assertTrue(key_mgmt["kms_runtime_client"]["fail_closed"])
            self.assertNotIn("kms_stub", key_mgmt)
            self.assertEqual(key_mgmt["wrapped_key_count"], 1)

    def test_remote_kms_provider_requires_real_endpoint(self):
        provider = RemoteKmsKeyProvider()
        with self.assertRaisesRegex(ValueError, "kms_endpoint is required"):
            provider.begin_run({})
        with self.assertRaisesRegex(ValueError, "kms_endpoint must be a non-empty string"):
            provider.begin_run({"kms_endpoint": ""})
        with self.assertRaisesRegex(ValueError, "kms_endpoint must be http"):
            provider.begin_run({"kms_endpoint": "stub://enc2sop/remote-kms"})

    def test_remote_kms_runtime_unwraps_http_json_response(self):
        key = b"0123456789abcdef0123456789abcdef"
        key_ref = _remote_kms_key_ref(key)
        calls = []

        def fake_urlopen(request, timeout):
            calls.append((request, timeout))
            self.assertEqual(timeout, 4.5)
            self.assertEqual(request.full_url, "https://kms.example.local/v1/unwrap")
            self.assertEqual(request.get_header("Authorization"), "Bearer token-value")
            self.assertEqual(request.get_header("Content-type"), "application/json")
            body = json.loads(request.data.decode("utf-8"))
            self.assertEqual(body["schema"], "enc2sop-kms-request/v1")
            self.assertEqual(body["operation"], "unwrap_data_key")
            self.assertEqual(body["profile"], "prod")
            self.assertEqual(body["key_handle"], "rk_test_handle")
            self.assertEqual(body["key_id"], "main-key")
            return _MockHttpResponse(
                json.dumps(
                    {
                        "schema": "enc2sop-kms-response/v1",
                        "plaintext_key_b64": base64.b64encode(key).decode("ascii"),
                    }
                ).encode("utf-8")
            )

        with mock.patch.dict(os.environ, {"SOENC_KMS_TEST_TOKEN": "token-value"}, clear=False):
            with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
                self.assertEqual(_remote_kms_unwrap_key(key_ref), key)

        self.assertEqual(len(calls), 1)

    def test_remote_kms_runtime_rejects_missing_endpoint_and_token_without_local_fallback(self):
        key = b"0123456789abcdef0123456789abcdef"
        missing_endpoint_ref = _remote_kms_key_ref(key, endpoint="")
        with self.assertRaisesRegex(ValueError, "request.endpoint"):
            _remote_kms_unwrap_key(missing_endpoint_ref)

        missing_token_ref = _remote_kms_key_ref(key)
        missing_token_ref["parts"] = ["AA=="]
        old_token = os.environ.pop("SOENC_KMS_TEST_TOKEN", None)
        try:
            with self.assertRaisesRegex(RuntimeError, "token env var is missing"):
                _resolve_key(missing_token_ref)
        finally:
            if old_token is not None:
                os.environ["SOENC_KMS_TEST_TOKEN"] = old_token

    def test_remote_kms_runtime_rejects_invalid_json_and_schema(self):
        key = b"0123456789abcdef0123456789abcdef"
        key_ref = _remote_kms_key_ref(key)

        with mock.patch.dict(os.environ, {"SOENC_KMS_TEST_TOKEN": "token-value"}, clear=False):
            with mock.patch(
                "urllib.request.urlopen",
                return_value=_MockHttpResponse(b"not-json"),
            ):
                with self.assertRaisesRegex(ValueError, "response must be valid JSON"):
                    _remote_kms_unwrap_key(key_ref)

            with mock.patch(
                "urllib.request.urlopen",
                return_value=_MockHttpResponse(b'{"schema":"wrong"}'),
            ):
                with self.assertRaisesRegex(ValueError, "response schema mismatch"):
                    _remote_kms_unwrap_key(key_ref)

            with mock.patch(
                "urllib.request.urlopen",
                return_value=_MockHttpResponse(b'{"schema":"enc2sop-kms-response/v1"}'),
            ):
                with self.assertRaisesRegex(ValueError, "plaintext_key_b64"):
                    _remote_kms_unwrap_key(key_ref)

    def test_remote_kms_runtime_rejects_plaintext_fingerprint_mismatch(self):
        key = b"0123456789abcdef0123456789abcdef"
        key_ref = _remote_kms_key_ref(key)
        wrong_key = b"abcdef0123456789abcdef0123456789"

        with mock.patch.dict(os.environ, {"SOENC_KMS_TEST_TOKEN": "token-value"}, clear=False):
            with mock.patch(
                "urllib.request.urlopen",
                return_value=_MockHttpResponse(
                    json.dumps(
                        {
                            "schema": "enc2sop-kms-response/v1",
                            "plaintext_key_b64": base64.b64encode(wrong_key).decode("ascii"),
                        }
                    ).encode("utf-8")
                ),
            ):
                with self.assertRaisesRegex(ValueError, "fingerprint mismatch"):
                    _remote_kms_unwrap_key(key_ref)

    def test_remote_kms_runtime_fails_closed_on_http_error_and_retries_retryable_status(self):
        key = b"0123456789abcdef0123456789abcdef"
        key_ref = _remote_kms_key_ref(key, max_retries=1, backoff_ms=10)
        retryable_error = urllib.error.HTTPError(
            key_ref["request"]["endpoint"],
            503,
            "Service Unavailable",
            hdrs=None,
            fp=None,
        )

        with mock.patch.dict(os.environ, {"SOENC_KMS_TEST_TOKEN": "token-value"}, clear=False):
            with mock.patch("time.sleep") as sleep_mock:
                with mock.patch(
                    "urllib.request.urlopen",
                    side_effect=[
                        retryable_error,
                        _MockHttpResponse(
                            json.dumps(
                                {
                                    "schema": "enc2sop-kms-response/v1",
                                    "plaintext_key_b64": base64.b64encode(key).decode("ascii"),
                                }
                            ).encode("utf-8")
                        ),
                    ],
                ) as urlopen_mock:
                    self.assertEqual(_remote_kms_unwrap_key(key_ref), key)

        self.assertEqual(urlopen_mock.call_count, 2)
        sleep_mock.assert_called_once()

        fatal_ref = _remote_kms_key_ref(key, max_retries=3, backoff_ms=10)
        fatal_error = urllib.error.HTTPError(
            fatal_ref["request"]["endpoint"],
            401,
            "Unauthorized",
            hdrs=None,
            fp=None,
        )
        with mock.patch.dict(os.environ, {"SOENC_KMS_TEST_TOKEN": "token-value"}, clear=False):
            with mock.patch("urllib.request.urlopen", side_effect=fatal_error) as urlopen_mock:
                with self.assertRaisesRegex(RuntimeError, "http 401"):
                    _remote_kms_unwrap_key(fatal_ref)
        self.assertEqual(urlopen_mock.call_count, 1)

    def test_remote_kms_generated_runtime_sources_are_not_stubbed(self):
        for source in (runtime_py_source(), runtime_pyx_source()):
            self.assertIn("remote-kms endpoint is still stubbed", source)
            self.assertIn("remote-kms response must be valid JSON", source)
            self.assertIn("_urlreq.urlopen", source)
            self.assertNotIn("runtime integration is stubbed", source)


if __name__ == "__main__":
    unittest.main()
