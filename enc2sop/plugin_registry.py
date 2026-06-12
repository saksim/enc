#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Optional plugin registry for non-mainline command extensions."""

import importlib
from importlib import util as importlib_util
from typing import Callable
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Sequence


class PluginSpec(NamedTuple):
    name: str
    module_check: str
    entrypoint: str
    description: str
    install_hint: str


_PLUGIN_SPECS = {
    "transport": PluginSpec(
        name="transport",
        module_check="qrcode_helper",
        entrypoint="enc2sop.transport_plugin:main",
        description="airgap transport workflows (export/recover/verify/analyze/ocr/certify)",
        install_hint=(
            "transport plugin is unavailable. Ensure qrcode transport files are present "
            "or install a build that includes optional transport support."
        ),
    ),
}  # type: Dict[str, PluginSpec]


def list_plugins() -> List[PluginSpec]:
    return sorted(_PLUGIN_SPECS.values(), key=lambda item: item.name)


def get_plugin_spec(name: str) -> PluginSpec:
    plugin_name = str(name or "").strip().lower()
    if not plugin_name:
        raise ValueError("plugin name is required")
    spec = _PLUGIN_SPECS.get(plugin_name)
    if spec is None:
        available = ", ".join(sorted(_PLUGIN_SPECS.keys()))
        raise ValueError("unknown plugin '{0}'. available plugins: {1}".format(plugin_name, available))
    return spec


def _is_module_available(module_name: str) -> bool:
    try:
        return importlib_util.find_spec(module_name) is not None
    except Exception:
        return False


def plugin_available(name: str) -> bool:
    spec = get_plugin_spec(name)
    return _is_module_available(spec.module_check)


def _load_entrypoint(entrypoint: str) -> Callable[[Optional[Sequence[str]]], int]:
    module_name, func_name = entrypoint.split(":", 1)
    module = importlib.import_module(module_name)
    handler = getattr(module, func_name, None)
    if handler is None or not callable(handler):
        raise RuntimeError("plugin entrypoint is invalid: {0}".format(entrypoint))
    return handler


def invoke_plugin_command(name: str, argv: Optional[Sequence[str]] = None) -> int:
    spec = get_plugin_spec(name)
    if not _is_module_available(spec.module_check):
        raise RuntimeError(spec.install_hint)
    handler = _load_entrypoint(spec.entrypoint)
    return int(handler(argv))


def plugin_help_rows() -> List[str]:
    rows = []
    for spec in list_plugins():
        state = "available" if plugin_available(spec.name) else "unavailable"
        rows.append("{0}: {1} ({2})".format(spec.name, spec.description, state))
    return rows


__all__ = [
    "PluginSpec",
    "get_plugin_spec",
    "invoke_plugin_command",
    "list_plugins",
    "plugin_help_rows",
    "plugin_available",
]
