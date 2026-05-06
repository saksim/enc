#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build profile and toolchain discovery helpers for enc2sop."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import Optional
from typing import Tuple
from typing import Union

DEFAULT_BUILD_PROFILE = "auto"
BUILD_PROFILE_WINDOWS_MSVC = "windows-msvc"
BUILD_PROFILE_NATIVE = "native"
SUPPORTED_BUILD_PROFILES = (
    DEFAULT_BUILD_PROFILE,
    BUILD_PROFILE_WINDOWS_MSVC,
    BUILD_PROFILE_NATIVE,
)

ENV_BUILD_PROFILE = "SOENC_BUILD_PROFILE"
ENV_PYTHON_EXE = "SOENC_PYTHON_EXE"
ENV_VCVARS64 = "SOENC_VCVARS64"
ENV_VSWHERE_EXE = "SOENC_VSWHERE_EXE"
ENV_PREPARED = "PY2SO_PREPARED_ENV"

WINDOWS_VCVARS_RELATIVE_PATH = Path("VC") / "Auxiliary" / "Build" / "vcvars64.bat"
WINDOWS_VS_EDITIONS = ("BuildTools", "Community", "Professional", "Enterprise")
WINDOWS_VS_VERSIONS = ("2022", "2019", "2017")


def normalize_path(value: Union[str, Path]) -> Path:
    text = os.fspath(value).strip().strip('"')
    if os.name == "nt":
        match = re.match(r"^/([a-zA-Z])/(.*)$", text)
        if match:
            drive, rest = match.groups()
            text = "{0}:/{1}".format(drive.upper(), rest)
    return Path(text).expanduser().resolve()


def resolve_build_profile(profile: Optional[str] = None, environ: Optional[Dict[str, str]] = None) -> str:
    env = environ if environ is not None else os.environ
    selected = profile if profile is not None else env.get(ENV_BUILD_PROFILE, DEFAULT_BUILD_PROFILE)
    selected = str(selected).strip().lower()
    if selected in {"", "default"}:
        selected = DEFAULT_BUILD_PROFILE
    if selected not in SUPPORTED_BUILD_PROFILES:
        raise ValueError(
            "invalid build profile: {0}; expected one of {1}".format(
                selected, ", ".join(SUPPORTED_BUILD_PROFILES)
            )
        )
    return selected


def resolve_python_executable(python_exe: Optional[Union[str, Path]] = None, environ: Optional[Dict[str, str]] = None) -> Path:
    env = environ if environ is not None else os.environ
    if python_exe:
        return normalize_path(python_exe)
    env_python = (env.get(ENV_PYTHON_EXE) or "").strip()
    if env_python:
        return normalize_path(env_python)
    return Path(sys.executable).resolve()


def _base_program_files_paths(environ: Optional[Dict[str, str]] = None) -> Tuple[Path, ...]:
    env = environ if environ is not None else os.environ
    roots = []
    for key in ("ProgramFiles(x86)", "ProgramFiles"):
        value = (env.get(key) or "").strip().strip('"')
        if value:
            roots.append(Path(value))
    unique = []
    seen = set()
    for root in roots:
        norm = str(root)
        if norm in seen:
            continue
        seen.add(norm)
        unique.append(root)
    return tuple(unique)


def _query_vswhere_install_paths(vswhere_exe: Path) -> Tuple[Path, ...]:
    try:
        completed = subprocess.run(
            [
                str(vswhere_exe),
                "-latest",
                "-products",
                "*",
                "-property",
                "installationPath",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return tuple()
    paths = []
    for line in completed.stdout.splitlines():
        text = line.strip().strip('"')
        if not text:
            continue
        paths.append(Path(text))
    return tuple(paths)


def _find_vswhere_executable(environ: Optional[Dict[str, str]] = None) -> Optional[Path]:
    env = environ if environ is not None else os.environ
    explicit = (env.get(ENV_VSWHERE_EXE) or "").strip()
    if explicit:
        path = normalize_path(explicit)
        if path.exists():
            return path

    path_lookup = shutil.which("vswhere.exe")
    if path_lookup:
        found = Path(path_lookup).resolve()
        if found.exists():
            return found

    for base in _base_program_files_paths(env):
        candidate = base / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
        if candidate.exists():
            return candidate.resolve()
    return None


def _iter_default_vcvars_candidates(environ: Optional[Dict[str, str]] = None) -> Iterable[Path]:
    env = environ if environ is not None else os.environ
    vsinstalldir = (env.get("VSINSTALLDIR") or "").strip().strip('"')
    if vsinstalldir:
        yield Path(vsinstalldir) / WINDOWS_VCVARS_RELATIVE_PATH

    vswhere = _find_vswhere_executable(env)
    if vswhere is not None:
        for install_path in _query_vswhere_install_paths(vswhere):
            yield install_path / WINDOWS_VCVARS_RELATIVE_PATH

    for base in _base_program_files_paths(env):
        root = base / "Microsoft Visual Studio"
        for version in WINDOWS_VS_VERSIONS:
            for edition in WINDOWS_VS_EDITIONS:
                yield root / version / edition / WINDOWS_VCVARS_RELATIVE_PATH


def discover_vcvars64(
    vcvars_path: Optional[Union[str, Path]] = None,
    environ: Optional[Dict[str, str]] = None,
) -> Optional[Path]:
    if os.name != "nt":
        return None
    env = environ if environ is not None else os.environ

    if vcvars_path:
        explicit = normalize_path(vcvars_path)
        return explicit if explicit.exists() else None

    env_override = (env.get(ENV_VCVARS64) or "").strip()
    if env_override:
        candidate = normalize_path(env_override)
        if candidate.exists():
            return candidate

    seen = set()
    for candidate in _iter_default_vcvars_candidates(env):
        resolved = candidate.expanduser().resolve()
        key = str(resolved).lower()
        if key in seen:
            continue
        seen.add(key)
        if resolved.exists():
            return resolved
    return None


def _capture_vcvars_environment(vcvars_path: Path, working_dir: Path, environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    dump_cmd = working_dir / "_dump_windows_env.cmd"
    dump_cmd.write_text(
        "\r\n".join(
            [
                "@echo off",
                'call "{0}" >nul'.format(vcvars_path),
                "set",
                "",
            ]
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", dump_cmd.name],
        cwd=working_dir,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=environ or os.environ.copy(),
    )
    merged = (environ or os.environ).copy()
    for line in completed.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        merged[key] = value
    merged["DISTUTILS_USE_SDK"] = "1"
    merged["MSSdk"] = "1"
    merged[ENV_PREPARED] = "1"
    return merged


def prepare_windows_build_env(
    output_dir: Path,
    profile: Optional[str] = None,
    vcvars_path: Optional[Union[str, Path]] = None,
    environ: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, str]]:
    if os.name != "nt":
        return None
    env = environ if environ is not None else os.environ
    resolved_profile = resolve_build_profile(profile=profile, environ=env)
    if resolved_profile == BUILD_PROFILE_NATIVE:
        return env.copy()

    if shutil.which("cl.exe", path=env.get("PATH", "")):
        prepared = env.copy()
        prepared[ENV_PREPARED] = prepared.get(ENV_PREPARED, "0")
        return prepared

    vcvars = discover_vcvars64(vcvars_path=vcvars_path, environ=env)
    if vcvars is None:
        raise RuntimeError(
            "MSVC toolchain not found. Install Visual Studio Build Tools (C++ workload), "
            "or provide --vcvars-path, or set {0}.".format(ENV_VCVARS64)
        )
    return _capture_vcvars_environment(vcvars, output_dir, environ=env)
