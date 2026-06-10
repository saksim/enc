#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Batch compile a Python tree into .pyd/.so files with Cython.

V0.3 Code Protection Layer boundary:
  - This utility owns native packaging of an already protected staging tree into
    .so/.pyd artifacts.
  - It is not part of SOX1, QR, OCR, scan_report, or retake_plan flows.
  - Missing Cython/native build tooling must not prevent `soenc cm` or legacy
    `soenc transport` help/startup from working.
"""

import os
import shutil
import sys
import sysconfig
import time
from pathlib import Path
from typing import List

from setuptools import setup
from setuptools import Extension
from Cython.Build import cythonize
from setuptools.command.build_ext import build_ext as _build_ext
from toolchain_profile import DEFAULT_BUILD_PROFILE
from toolchain_profile import ENV_PREPARED
from toolchain_profile import SUPPORTED_BUILD_PROFILES
from toolchain_profile import prepare_windows_build_env
from toolchain_profile import resolve_build_profile
from enc2sop.protect.hardening import SUPPORTED_HARDENING_PROFILES
from enc2sop.protect.hardening import apply_native_extension_hardening
from enc2sop.protect.hardening import cython_compiler_directives
from enc2sop.protect.hardening import normalize_hardening_profile
from enc2sop.protect.hardening import strip_native_symbols


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
            items.append(str(path.relative_to(root)))
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

    @staticmethod
    def parse_args(argv=None):
        import argparse

        parser = argparse.ArgumentParser(description="Batch-compile a Python tree into native modules.")
        parser.add_argument("target", nargs="?", default=".", help="Staging directory to compile.")
        parser.add_argument(
            "--build-profile",
            default=DEFAULT_BUILD_PROFILE,
            choices=SUPPORTED_BUILD_PROFILES,
            help="Build profile used for toolchain assumptions.",
        )
        parser.add_argument("--vcvars-path", help="Optional explicit vcvars64.bat for windows-msvc profile.")
        parser.add_argument(
            "--hardening-profile",
            default="off",
            choices=SUPPORTED_HARDENING_PROFILES,
            help="P2-C native hardening profile for Cython directives, compiler/linker flags, and best-effort strip.",
        )
        return parser.parse_args(argv)

    def run(self, argv=None, current_path="."):
        args = self.parse_args(argv)
        if os.name == "nt":
            prepared = prepare_windows_build_env(
                output_dir=Path(args.target).resolve(),
                profile=resolve_build_profile(args.build_profile),
                vcvars_path=args.vcvars_path,
            )
            if prepared:
                os.environ.update(prepared)
        target_dir = Path(args.target).resolve() if args.target else Path(current_path).resolve()
        parent_dir = target_dir.parent
        build_dir = target_dir / "build"
        build_temp_dir = build_dir / "temp"

        print("start:", parent_dir, target_dir.name, build_dir)
        print("build_profile={0}".format(resolve_build_profile(args.build_profile)))
        print("prepared_env={0}".format(os.environ.get(ENV_PREPARED, "0")))
        os.chdir(target_dir)

        module_list = self.iter_python_sources(target_dir)
        print(module_list)
        if self.invalid_module_paths:
            print("skip_invalid_module_names={0}".format(len(self.invalid_module_paths)))
            for item in self.invalid_module_paths:
                print("invalid_module_name={0}".format(item))

        try:
            hardening_profile = normalize_hardening_profile(args.hardening_profile)
            compiler_directives = dict(cython_compiler_directives(hardening_profile))
            extensions = [
                Extension(".".join(Path(item).with_suffix("").parts), [item])
                for item in module_list
            ]
            ext_modules = cythonize(
                extensions,
                language_level="3",
                compiler_directives=compiler_directives,
            )
            hardening_options = apply_native_extension_hardening(ext_modules, hardening_profile)
            print("hardening_profile={0}".format(hardening_profile))
            print("hardening_compile_args={0}".format(",".join(hardening_options.get("compile_args") or ())))
            print("hardening_link_args={0}".format(",".join(hardening_options.get("link_args") or ())))
            print("hardening_strip_symbols={0}".format(bool(hardening_options.get("strip_symbols"))))
            setup(
                ext_modules=ext_modules,
                cmdclass={"build_ext": BuildExtWithoutPlatformSuffix},
                script_args=["build_ext", "-b", str(build_dir), "-t", str(build_temp_dir)],
            )
            self.copy_support_files(target_dir, build_dir)
            strip_result = strip_native_symbols(build_dir, hardening_profile)
            if strip_result.get("attempted"):
                print("hardening_stripped_files={0}".format(len(strip_result.get("files") or ())))
                if strip_result.get("failures"):
                    print("hardening_strip_failures={0}".format(len(strip_result.get("failures") or ())))
            elif strip_result.get("skipped_reason"):
                print("hardening_strip_skipped={0}".format(strip_result.get("skipped_reason")))
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
    Py2SoUtil().run(sys.argv[1:])
