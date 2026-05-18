import unittest

import decryption_helper
import encryption_helper
from enc2sop.keys.local import unpack_local_embedded_key


class DecryptionHelperTests(unittest.TestCase):
    def test_runtime_exports_api_marker_and_version(self):
        self.assertEqual(decryption_helper.SOENC_RUNTIME_API_MARKER, "enc2sop-runtime-core-v1")
        self.assertGreaterEqual(decryption_helper.SOENC_RUNTIME_API_VERSION, 1)

    def test_runtime_exec_decrypts_payload_after_key_buffer_hardening(self):
        source = "VALUE = 11\n"
        payload, key = encryption_helper.encrypt_snippet(source)
        key_ref = encryption_helper.pack_key_reference(key, "local-embedded")
        parts = key_ref["parts"]
        namespace = {}

        decryption_helper._x((payload,), parts, namespace)

        self.assertEqual(namespace["VALUE"], 11)

    def test_runtime_decrypt_supports_local_embedded_provider_key_ref_dict(self):
        source = "VALUE = 19\n"
        payload, key = encryption_helper.encrypt_snippet(source)
        key_ref = encryption_helper.pack_key_reference(key, "local-embedded")

        namespace = {}
        decryption_helper._x((payload,), key_ref, namespace)

        self.assertEqual(namespace["VALUE"], 19)
        self.assertEqual(unpack_local_embedded_key(tuple(key_ref["parts"])), key)


if __name__ == "__main__":
    unittest.main()
