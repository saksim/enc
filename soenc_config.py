#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unified soenc.toml loader for enc2sop mainline configuration."""

import os
import sys
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Iterable
from typing import Mapping
from typing import NamedTuple
from typing import Optional
from typing import Tuple

from toolchain_profile import SUPPORTED_BUILD_PROFILES

DEFAULT_CONFIG_FILENAME = "soenc.toml"
SUPPORTED_KEY_MODES = (
    "local-embedded",
    "local-provider",
    "license-file",
    "remote-kms",
)
KEY_MODE_ALIASES = {
    "local-provider": "local-embedded",
}


class SoencConfigError(ValueError):
    """Raised when soenc.toml has schema or type violations."""


class SoencProjectConfig(NamedTuple):
    path: Path
    cli_defaults: Dict[str, Any]
    key_mode: Optional[str]
    package_metadata: Dict[str, str]


def discover_config_path(
    config_path: Optional[str] = None,
    base_dir: Optional[Path] = None,
) -> Optional[Path]:
    root = base_dir.resolve() if base_dir is not None else Path.cwd().resolve()
    if config_path:
        candidate = Path(config_path).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
        if not resolved.exists():
            raise FileNotFoundError("config file not found: {0}".format(resolved))
        return resolved
    default_path = (root / DEFAULT_CONFIG_FILENAME).resolve()
    return default_path if default_path.exists() else None


def _load_toml_payload(path: Path) -> Dict[str, Any]:
    source = path.read_text(encoding="utf-8")
    if sys.version_info >= (3, 11):
        import tomllib

        payload = tomllib.loads(source)
    else:
        try:
            import tomli as tomllib  # type: ignore
        except Exception as exc:  # pragma: no cover - only for old runtimes without tomli
            raise RuntimeError(
                "TOML parsing requires Python 3.11+ or 'tomli' package for older interpreters."
            ) from exc
        payload = tomllib.loads(source)
    if not isinstance(payload, dict):
        raise SoencConfigError("config root must be a TOML table")
    return payload


def _as_table(payload: Mapping[str, Any], key: str) -> Dict[str, Any]:
    table = payload.get(key, {})
    if table is None:
        return {}
    if not isinstance(table, dict):
        raise SoencConfigError("section [{0}] must be a TOML table".format(key))
    return dict(table)


def _reject_unknown_keys(section: str, table: Mapping[str, Any], allowed_keys: Iterable[str]) -> None:
    allowed = set(allowed_keys)
    unknown = sorted(set(table.keys()) - allowed)
    if unknown:
        raise SoencConfigError("section [{0}] has unsupported keys: {1}".format(section, ", ".join(unknown)))


def _optional_text(value: Any, field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SoencConfigError("{0} must be a string".format(field_name))
    text = value.strip()
    return text if text else None


def _optional_bool(value: Any, field_name: str) -> Optional[bool]:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise SoencConfigError("{0} must be a boolean".format(field_name))
    return value


def _string_list(value: Any, field_name: str) -> Optional[Tuple[str, ...]]:
    if value is None:
        return None
    if not isinstance(value, list):
        raise SoencConfigError("{0} must be an array of strings".format(field_name))
    items = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SoencConfigError("{0} must contain only non-empty strings".format(field_name))
        items.append(item.strip())
    return tuple(items)


def _resolve_path_text(value: Optional[str], config_dir: Path) -> Optional[str]:
    if value is None:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = config_dir / path
    return str(path.resolve())


def _parse_project_section(project_table: Mapping[str, Any], config_dir: Path) -> Dict[str, Any]:
    _reject_unknown_keys(
        "project",
        project_table,
        (
            "target",
            "scope_config",
            "namespace_root",
            "infer_namespace",
            "functions",
            "classes",
        ),
    )

    target = _resolve_path_text(_optional_text(project_table.get("target"), "project.target"), config_dir)
    scope_config = _resolve_path_text(_optional_text(project_table.get("scope_config"), "project.scope_config"), config_dir)
    namespace_root = _optional_text(project_table.get("namespace_root"), "project.namespace_root")
    infer_namespace = _optional_bool(project_table.get("infer_namespace"), "project.infer_namespace")
    functions = _string_list(project_table.get("functions"), "project.functions")
    classes = _string_list(project_table.get("classes"), "project.classes")

    return {
        "target": target,
        "scope_config": scope_config,
        "namespace_root": namespace_root,
        "infer_namespace": infer_namespace,
        "function": list(functions) if functions is not None else None,
        "classes": list(classes) if classes is not None else None,
    }


def _parse_build_section(build_table: Mapping[str, Any], config_dir: Path) -> Dict[str, Any]:
    _reject_unknown_keys(
        "build",
        build_table,
        (
            "output_dir",
            "dist_dir",
            "compile",
            "precheck_only",
            "skip_bad_files",
            "python_exe",
            "build_profile",
            "vcvars_path",
        ),
    )

    output_dir = _resolve_path_text(_optional_text(build_table.get("output_dir"), "build.output_dir"), config_dir)
    dist_dir = _resolve_path_text(_optional_text(build_table.get("dist_dir"), "build.dist_dir"), config_dir)
    compile_enabled = _optional_bool(build_table.get("compile"), "build.compile")
    precheck_only = _optional_bool(build_table.get("precheck_only"), "build.precheck_only")
    skip_bad_files = _optional_bool(build_table.get("skip_bad_files"), "build.skip_bad_files")
    python_exe = _resolve_path_text(_optional_text(build_table.get("python_exe"), "build.python_exe"), config_dir)
    build_profile = _optional_text(build_table.get("build_profile"), "build.build_profile")
    if build_profile is not None:
        normalized = build_profile.lower()
        if normalized not in SUPPORTED_BUILD_PROFILES:
            raise SoencConfigError(
                "build.build_profile must be one of: {0}".format(", ".join(SUPPORTED_BUILD_PROFILES))
            )
        build_profile = normalized
    vcvars_path = _resolve_path_text(_optional_text(build_table.get("vcvars_path"), "build.vcvars_path"), config_dir)

    return {
        "output_dir": output_dir,
        "dist_dir": dist_dir,
        "compile": compile_enabled,
        "precheck_only": precheck_only,
        "skip_bad_files": skip_bad_files,
        "python_exe": python_exe,
        "build_profile": build_profile,
        "vcvars_path": vcvars_path,
    }


def _parse_keys_section(keys_table: Mapping[str, Any], config_dir: Path) -> Dict[str, Any]:
    _reject_unknown_keys(
        "keys",
        keys_table,
        (
            "mode",
            "manifest_sign_key_file",
            "manifest_key_id",
            "require_manifest_signature",
            "license_file",
            "license_id",
        ),
    )
    key_mode = _optional_text(keys_table.get("mode"), "keys.mode")
    normalized_mode = None
    if key_mode is not None:
        normalized_mode = key_mode.lower()
        normalized_mode = KEY_MODE_ALIASES.get(normalized_mode, normalized_mode)
        if normalized_mode not in SUPPORTED_KEY_MODES:
            raise SoencConfigError("keys.mode must be one of: {0}".format(", ".join(SUPPORTED_KEY_MODES)))
    manifest_sign_key_file = _resolve_path_text(
        _optional_text(keys_table.get("manifest_sign_key_file"), "keys.manifest_sign_key_file"),
        config_dir,
    )
    manifest_key_id = _optional_text(keys_table.get("manifest_key_id"), "keys.manifest_key_id")
    require_manifest_signature = _optional_bool(
        keys_table.get("require_manifest_signature"),
        "keys.require_manifest_signature",
    )
    license_file = _optional_text(keys_table.get("license_file"), "keys.license_file")
    license_id = _optional_text(keys_table.get("license_id"), "keys.license_id")
    return {
        "mode": normalized_mode,
        "manifest_sign_key_file": manifest_sign_key_file,
        "manifest_key_id": manifest_key_id,
        "require_manifest_signature": require_manifest_signature,
        "license_file": license_file,
        "license_id": license_id,
    }


def _parse_package_section(package_table: Mapping[str, Any]) -> Dict[str, str]:
    _reject_unknown_keys(
        "package",
        package_table,
        (
            "name",
            "version",
            "vendor",
            "channel",
        ),
    )
    metadata = {}
    for key in ("name", "version", "vendor", "channel"):
        value = _optional_text(package_table.get(key), "package.{0}".format(key))
        if value is not None:
            metadata[key] = value
    return metadata


def load_project_config(
    config_path: Optional[str] = None,
    base_dir: Optional[Path] = None,
) -> Optional[SoencProjectConfig]:
    resolved_path = discover_config_path(config_path=config_path, base_dir=base_dir)
    if resolved_path is None:
        return None

    payload = _load_toml_payload(resolved_path)
    _reject_unknown_keys("root", payload, ("project", "build", "keys", "package"))
    config_dir = resolved_path.parent

    cli_defaults = {}  # type: Dict[str, Any]
    cli_defaults.update(_parse_project_section(_as_table(payload, "project"), config_dir))
    cli_defaults.update(_parse_build_section(_as_table(payload, "build"), config_dir))
    keys = _parse_keys_section(_as_table(payload, "keys"), config_dir)
    key_mode = keys.get("mode")
    cli_defaults.update(
        {
            "manifest_sign_key_file": keys.get("manifest_sign_key_file"),
            "manifest_key_id": keys.get("manifest_key_id"),
            "require_manifest_signature": keys.get("require_manifest_signature"),
            "license_file": keys.get("license_file"),
            "license_id": keys.get("license_id"),
        }
    )
    package_metadata = _parse_package_section(_as_table(payload, "package"))
    return SoencProjectConfig(
        path=resolved_path,
        cli_defaults=cli_defaults,
        key_mode=key_mode,
        package_metadata=package_metadata,
    )
