import base64
import os
import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from enc2sop.keys import LicenseFileKeyProvider
from enc2sop.keys import LocalEmbeddedKeyProvider
from enc2sop.keys import RemoteKmsKeyProvider
from enc2sop.keys import get_key_provider
from enc2sop.keys import unpack_local_embedded_key
from enc2sop.keys.provider import KeyProvider
from enc2sop.keys.provider import register_key_provider
from decryption_helper import _license_key_from_ref


class _UnitTestProvider(KeyProvider):
    mode = "unit-test-provider"

    def pack_key(self, key_bytes):
        return {"mode": self.mode, "parts": ["AA=="]}

    def resolve_key(self, key_ref):
        return b"\x00"


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
                    "license_machine_fingerprint": "machine-a",
                    "license_sign_key": sign_key,
                    "license_sign_key_id": "lic-signer",
                }
            )
            key_ref = provider.pack_key(key)
            provider.finalize_run(out_dir, {"key_management": {"mode": "license-file"}})
            license_path = out_dir / "runtime.license.json"
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
            self.assertTrue(key_mgmt["kms_stub"]["enabled"])
            self.assertEqual(key_mgmt["wrapped_key_count"], 1)


if __name__ == "__main__":
    unittest.main()
