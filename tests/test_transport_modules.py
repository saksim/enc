import unittest
from unittest import mock

import qrcode_helper
from enc2sop.transport import ocr_adapters, protocol


class TransportModuleExtractionTests(unittest.TestCase):
    def test_protocol_base32_roundtrip(self) -> None:
        raw = b"enc2sop-transport-roundtrip"
        encoded = protocol.encode_safe_base32(raw)
        self.assertTrue(encoded)
        self.assertEqual(protocol.decode_safe_base32(encoded), raw)

    def test_protocol_signature_normalization(self) -> None:
        normalized = protocol.normalize_protocol_signature("P0011001|C00001|ABCDEFGH|FF8F")
        self.assertTrue(normalized.startswith("P001L001"))

    def test_ocr_adapter_language_mapping(self) -> None:
        langs = ocr_adapters.build_easyocr_langs("eng+chi_sim+jpn")
        self.assertEqual(langs, ["en", "ch_sim", "ja"])

    def test_qrcode_helper_protocol_aliases_use_transport_module(self) -> None:
        self.assertIs(qrcode_helper.LINE_PATTERN, protocol.LINE_PATTERN)
        self.assertIs(qrcode_helper.META_PATTERN, protocol.META_PATTERN)
        self.assertIs(qrcode_helper._normalize_ocr_line, protocol.normalize_ocr_line)
        self.assertEqual(qrcode_helper.SAFE_BASE32_ALPHABET, protocol.SAFE_BASE32_ALPHABET)

    def test_qrcode_helper_module_spec_wrapper_delegates_to_adapter(self) -> None:
        with mock.patch.object(ocr_adapters, "is_module_available", autospec=True, return_value=True) as mocked:
            self.assertTrue(qrcode_helper._module_spec_available("demo_mod"))
        mocked.assert_called_once_with("demo_mod")


if __name__ == "__main__":
    unittest.main()
