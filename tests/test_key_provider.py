import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from enc2sop.keys import LicenseFileKeyProvider
from enc2sop.keys import LocalEmbeddedKeyProvider
from enc2sop.keys import get_key_provider
from enc2sop.keys import unpack_local_embedded_key
from enc2sop.keys.provider import KeyProvider
from enc2sop.keys.provider import register_key_provider


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


if __name__ == "__main__":
    unittest.main()
