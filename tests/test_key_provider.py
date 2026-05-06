import unittest

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


if __name__ == "__main__":
    unittest.main()

