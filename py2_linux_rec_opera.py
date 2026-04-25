#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Batch compile a Python tree into .pyd/.so files with Cython."""

import os
import shutil
import sys
import sysconfig
import time
from pathlib import Path
from typing import List

from setuptools import setup
from Cython.Build import cythonize
from setuptools.command.build_ext import build_ext as _build_ext

WINDOWS_CL_PATH = r"D:\code_environment\visual_studio\enterprise\VC\Tools\MSVC\14.29.30133\bin\HostX64\x64"
WINDOWS_RC_PATH = r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64"
WINDOWS_INCLUDE = (
    r"D:\code_environment\visual_studio\enterprise\VC\Tools\MSVC\14.29.30133\ATLMFC\include;"
    r"D:\code_environment\visual_studio\enterprise\VC\Tools\MSVC\14.29.30133\include;"
    r"C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\include\um;"
    r"C:\Program Files (x86)\Windows Kits\10\include\10.0.19041.0\ucrt;"
    r"C:\Program Files (x86)\Windows Kits\10\include\10.0.19041.0\shared;"
    r"C:\Program Files (x86)\Windows Kits\10\include\10.0.19041.0\um;"
    r"C:\Program Files (x86)\Windows Kits\10\include\10.0.19041.0\winrt;"
    r"C:\Program Files (x86)\Windows Kits\10\include\10.0.19041.0\cppwinrt"
)
WINDOWS_LIB = (
    r"D:\code_environment\visual_studio\enterprise\VC\Tools\MSVC\14.29.30133\ATLMFC\lib\x64;"
    r"D:\code_environment\visual_studio\enterprise\VC\Tools\MSVC\14.29.30133\lib\x64;"
    r"C:\Program Files (x86)\Windows Kits\NETFXSDK\4.8\lib\um\x64;"
    r"C:\Program Files (x86)\Windows Kits\10\lib\10.0.19041.0\ucrt\x64;"
    r"C:\Program Files (x86)\Windows Kits\10\lib\10.0.19041.0\um\x64"
)


def inject_msvc_env():
    if os.name != "nt":
        return
    if "64" not in __import__("platform").architecture()[0]:
        return

    os.environ["INCLUDE"] = WINDOWS_INCLUDE
    os.environ["LIB"] = WINDOWS_LIB
    os.environ["PATH"] = WINDOWS_CL_PATH + ";" + WINDOWS_RC_PATH + ";" + os.environ.get("PATH", "")
    os.environ["DISTUTILS_USE_SDK"] = "1"
    os.environ["MSSdk"] = "1"


class BuildExtWithoutPlatformSuffix(_build_ext):
    @staticmethod
    def _strip_platform_suffix(filename):
        name, ext = os.path.splitext(filename)
        ext_suffix = sysconfig.get_config_var("EXT_SUFFIX")
        if os.name == "nt":
            temp_name, _ = os.path.splitext(name)
            return temp_name + ext
        if ext_suffix == ext:
            return filename
        ext_suffix = ext_suffix.replace(ext, "")
        index = name.find(ext_suffix)
        if index == -1:
            return filename
        return name[:index] + ext

    def get_ext_filename(self, ext_name):
        return self._strip_platform_suffix(super().get_ext_filename(ext_name))


class Py2SoUtil:
    def __init__(self):
        self.starttime = time.time()
        self.self_file = Path(__file__).resolve()
        self.invalid_module_paths = []  # type: List[str]

    @staticmethod
    def is_valid_module_path(root, path):
        relative = path.relative_to(root).with_suffix("")
        return all(part.isidentifier() for part in relative.parts)

    def iter_python_sources(self, root):
        items = []  # type: List[str]
        for path in root.rglob("*"):
            if path.is_dir():
                if path.name.startswith(".") or path.name == "build":
                    continue
                continue
            if path.suffix not in {".py", ".pyx"}:
                continue
            if path.resolve() == self.self_file:
                continue
            if path.name.startswith("__") and path.name != "__init__.py":
                continue
            if path.name == "__init__.py":
                continue
            if not self.is_valid_module_path(root, path):
                self.invalid_module_paths.append(str(path.relative_to(root)).replace("\\", "/"))
                continue
            items.append(str(path))
        return sorted(items)

    def copy_support_files(self, root, build_dir):
        for path in root.rglob("*"):
            if path.is_dir():
                continue
            relative = path.relative_to(root)
            if "build" in relative.parts:
                continue
            target = build_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix in {".py", ".pyx", ".c"} and path.name != "__init__.py":
                continue
            shutil.copy2(path, target)

    def cleanup_generated_c(self, root):
        for path in root.rglob("*.c"):
            try:
                if path.stat().st_mtime > self.starttime:
                    path.unlink()
            except OSError as exc:
                print(f"warning: skip removing {path}: {exc}")

    def run(self, current_path="."):
        inject_msvc_env()
        target_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(current_path).resolve()
        parent_dir = target_dir.parent
        build_dir = target_dir / "build"
        build_temp_dir = build_dir / "temp"

        print("start:", parent_dir, target_dir.name, build_dir)
        os.chdir(parent_dir)

        module_list = self.iter_python_sources(target_dir)
        print([str(Path(item).relative_to(parent_dir)) for item in module_list])
        if self.invalid_module_paths:
            print("skip_invalid_module_names={0}".format(len(self.invalid_module_paths)))
            for item in self.invalid_module_paths:
                print("invalid_module_name={0}".format(item))

        try:
            setup(
                ext_modules=cythonize(
                    module_list,
                    language_level="3",
                    compiler_directives={"always_allow_keywords": True},
                ),
                cmdclass={"build_ext": BuildExtWithoutPlatformSuffix},
                script_args=["build_ext", "-b", str(build_dir), "-t", str(build_temp_dir)],
            )
            self.copy_support_files(target_dir, build_dir)
        finally:
            print("cleaning......")
            self.cleanup_generated_c(target_dir)
            if build_temp_dir.exists():
                try:
                    shutil.rmtree(build_temp_dir)
                except OSError as exc:
                    print(f"warning: skip removing {build_temp_dir}: {exc}")

        print(f"Complete batch cython build in {time.time() - self.starttime:.2f}s")


if __name__ == "__main__":
    Py2SoUtil().run()
