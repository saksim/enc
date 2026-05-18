import unittest
from unittest import mock

from enc2sop import plugin_registry


class PluginRegistryTests(unittest.TestCase):
    def test_transport_plugin_registered(self):
        names = [item.name for item in plugin_registry.list_plugins()]
        self.assertIn("transport", names)
        spec = plugin_registry.get_plugin_spec("transport")
        self.assertEqual(spec.module_check, "qrcode_helper")
        self.assertEqual(spec.entrypoint, "enc2sop.transport_plugin:main")

    def test_invoke_transport_plugin_loads_entrypoint(self):
        mocked_handler = mock.Mock(return_value=7)
        with mock.patch.object(plugin_registry, "_is_module_available", autospec=True, return_value=True), mock.patch.object(
            plugin_registry, "_load_entrypoint", autospec=True, return_value=mocked_handler
        ) as mocked_loader:
            code = plugin_registry.invoke_plugin_command("transport", ["export", "-i", "a.bin", "-o", "out"])

        self.assertEqual(code, 7)
        mocked_loader.assert_called_once_with("enc2sop.transport_plugin:main")
        mocked_handler.assert_called_once_with(["export", "-i", "a.bin", "-o", "out"])

    def test_invoke_transport_plugin_fails_closed_when_missing(self):
        with mock.patch.object(plugin_registry, "_is_module_available", autospec=True, return_value=False):
            with self.assertRaisesRegex(RuntimeError, "transport plugin is unavailable"):
                plugin_registry.invoke_plugin_command("transport", ["export"])


if __name__ == "__main__":
    unittest.main()
