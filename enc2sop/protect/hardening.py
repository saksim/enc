#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""P2-C native build hardening helpers for the Code Protection Layer.

These helpers only raise the reverse-engineering cost of native artifacts. They
must not be documented as a substitute for key security, remote KMS, license
controls, or runtime integrity checks.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable
from typing import Mapping
from typing import MutableSequence

HARDENING_PROFILE_OFF = "off"
HARDENING_PROFILE_BALANCED = "balanced"
SUPPORTED_HARDENING_PROFILES = (
    HARDENING_PROFILE_OFF,
    HARDENING_PROFILE_BALANCED,
)
HARDENING_CAVEAT = (
    "P2-C hardening raises reverse-engineering cost only; it does not replace "
    "key management, remote KMS, license controls, or runtime integrity."
)
NATIVE_EXTENSION_SUFFIXES = (".pyd", ".so", ".dll", ".dylib")


def normalize_hardening_profile(value) -> str:
    text = str(value or HARDENING_PROFILE_OFF).strip().lower()
    if not text:
        text = HARDENING_PROFILE_OFF
    if text not in SUPPORTED_HARDENING_PROFILES:
        raise ValueError(
            "hardening_profile must be one of: {0}".format(
                ", ".join(SUPPORTED_HARDENING_PROFILES)
            )
        )
    return text


def cython_compiler_directives(profile) -> Mapping[str, object]:
    normalized = normalize_hardening_profile(profile)
    directives = {"always_allow_keywords": True}
    if normalized == HARDENING_PROFILE_BALANCED:
        directives.update(
            {
                "binding": False,
                "embedsignature": False,
                "emit_code_comments": False,
            }
        )
    return directives


def native_extension_hardening_options(profile, *, platform_name=None, os_name=None) -> Mapping[str, object]:
    normalized = normalize_hardening_profile(profile)
    if normalized == HARDENING_PROFILE_OFF:
        return {
            "compile_args": (),
            "link_args": (),
            "strip_symbols": False,
            "strip_args": (),
        }

    platform_name = str(platform_name or sys.platform).lower()
    os_name = str(os_name or os.name).lower()
    if os_name == "nt" or platform_name.startswith("win"):
        return {
            "compile_args": ("/O2",),
            "link_args": ("/OPT:REF", "/OPT:ICF"),
            "strip_symbols": False,
            "strip_args": (),
        }
    if platform_name == "darwin":
        return {
            "compile_args": ("-O2", "-fvisibility=hidden"),
            "link_args": ("-Wl,-x",),
            "strip_symbols": True,
            "strip_args": ("-x",),
        }
    return {
        "compile_args": ("-O2", "-fvisibility=hidden"),
        "link_args": ("-Wl,-s",),
        "strip_symbols": True,
        "strip_args": ("--strip-unneeded",),
    }


def _append_unique(target: MutableSequence[str], values: Iterable[str]) -> None:
    seen = set(str(item) for item in target)
    for value in values:
        text = str(value)
        if text not in seen:
            target.append(text)
            seen.add(text)


def apply_native_extension_hardening(ext_modules, profile):
    options = native_extension_hardening_options(profile)
    compile_args = tuple(options.get("compile_args") or ())
    link_args = tuple(options.get("link_args") or ())
    for ext in ext_modules or ():
        if not hasattr(ext, "extra_compile_args") or ext.extra_compile_args is None:
            ext.extra_compile_args = []
        if not hasattr(ext, "extra_link_args") or ext.extra_link_args is None:
            ext.extra_link_args = []
        _append_unique(ext.extra_compile_args, compile_args)
        _append_unique(ext.extra_link_args, link_args)
    return options


def hardening_manifest(profile) -> Mapping[str, object]:
    normalized = normalize_hardening_profile(profile)
    options = native_extension_hardening_options(normalized)
    return {
        "profile": normalized,
        "cython_directives": dict(cython_compiler_directives(normalized)),
        "native_compile_args": list(options.get("compile_args") or ()),
        "native_link_args": list(options.get("link_args") or ()),
        "strip_symbols": bool(options.get("strip_symbols")),
        "native_build_required": normalized != HARDENING_PROFILE_OFF,
        "caveat": HARDENING_CAVEAT,
    }


def _native_artifact_paths(build_dir):
    root = Path(build_dir)
    if not root.exists():
        return []
    suffixes = {item.lower() for item in NATIVE_EXTENSION_SUFFIXES}
    return sorted(path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in suffixes)


def strip_native_symbols(build_dir, profile, *, strip_tool=None):
    normalized = normalize_hardening_profile(profile)
    options = native_extension_hardening_options(normalized)
    if not options.get("strip_symbols"):
        return {
            "attempted": False,
            "tool": None,
            "files": [],
            "skipped_reason": "profile does not enable strip_symbols",
        }
    tool = strip_tool or shutil.which("strip")
    if not tool:
        return {
            "attempted": False,
            "tool": None,
            "files": [],
            "skipped_reason": "strip tool not found",
        }
    stripped = []
    failures = []
    strip_args = list(options.get("strip_args") or ())
    for artifact in _native_artifact_paths(build_dir):
        command = [tool, *strip_args, str(artifact)]
        completed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if completed.returncode == 0:
            stripped.append(str(artifact))
        else:
            failures.append({"file": str(artifact), "returncode": completed.returncode, "stderr": completed.stderr})
    return {
        "attempted": True,
        "tool": tool,
        "files": stripped,
        "failures": failures,
        "skipped_reason": None,
    }


__all__ = [
    "HARDENING_CAVEAT",
    "HARDENING_PROFILE_BALANCED",
    "HARDENING_PROFILE_OFF",
    "SUPPORTED_HARDENING_PROFILES",
    "apply_native_extension_hardening",
    "cython_compiler_directives",
    "hardening_manifest",
    "native_extension_hardening_options",
    "normalize_hardening_profile",
    "strip_native_symbols",
]
