#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""P0-B6 runtime integrity smoke.

This smoke exercises the import-time runtime hardening generated for
``--runtime-native-loader`` without requiring a local native compiler.  It uses
the real generated preamble and a stub runtime module whose ``__file__`` points
at synthetic .pyd artifacts, so the decisive branches are the same:

* runtime module path replacement fails closed;
* manifest fingerprint path tampering fails closed;
* digest mismatch fails closed.

This is hardening evidence only.  It is not a strong-secrecy claim and does not
touch the QR/OCR/SOX1 cross-media path.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Callable
from typing import Dict
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import encryption_helper  # noqa: E402


RUNTIME_MODULE = "enc_rt_demo"
PACKAGE_NAME = "pkg"
HELPER_NAME = "__enc_exec_runtime_integrity_smoke"


class RuntimeStub:
    """Tiny runtime object returned by the patched importlib.import_module."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(131072)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _write_manifest(root: Path, *, compiled_relative_path: str, digest_hex: str) -> None:
    payload = {
        "runtime_delivery": {
            "compiled_runtime_fingerprints": [
                {
                    "module_name": RUNTIME_MODULE,
                    "compiled_relative_path": compiled_relative_path,
                    "algorithm": encryption_helper.RUNTIME_FINGERPRINT_ALGORITHM_SHA256,
                    "digest_hex": digest_hex,
                }
            ],
            "trust_policy": {
                "require_runtime_fingerprint": True,
                "runtime_path_policy": encryption_helper.RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR,
                "runtime_suffix_policy": encryption_helper.RUNTIME_SUFFIX_POLICY_STRICT_SINGLE,
                "runtime_native_suffixes": [".pyd"],
            },
        }
    }
    (root / "build_manifest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _make_runtime_stub(runtime_file: Path) -> RuntimeStub:
    runtime = RuntimeStub()
    runtime.__name__ = f"{PACKAGE_NAME}.{RUNTIME_MODULE}"
    runtime.__file__ = str(runtime_file)
    runtime.__spec__ = SimpleNamespace(origin=str(runtime_file))
    runtime.SOENC_RUNTIME_API_MARKER = encryption_helper.RUNTIME_API_MARKER
    runtime.SOENC_RUNTIME_API_VERSION = encryption_helper.RUNTIME_API_VERSION

    def _x(_payloads, _parts, namespace):
        namespace["RUNTIME_INTEGRITY_SMOKE_EXECUTED"] = True

    runtime._x = _x
    return runtime


def _invoke_generated_guard(root: Path, runtime_file: Path) -> Dict[str, object]:
    pkg_dir = root / PACKAGE_NAME
    pkg_dir.mkdir(parents=True, exist_ok=True)
    module_file = pkg_dir / "mod.py"
    module_file.write_text("", encoding="utf-8")

    source = encryption_helper.render_module_preamble(
        runtime_module=RUNTIME_MODULE,
        helper_name=HELPER_NAME,
        require_native_runtime_loader=True,
    )
    module_globals: Dict[str, object] = {
        "__name__": f"{PACKAGE_NAME}.mod",
        "__package__": PACKAGE_NAME,
        "__file__": str(module_file),
        "__builtins__": __builtins__,
    }
    runtime = _make_runtime_stub(runtime_file)
    original_import_module: Callable[..., object] = importlib.import_module

    def _patched_import_module(name: str, package: Optional[str] = None):
        if name == f"{PACKAGE_NAME}.{RUNTIME_MODULE}":
            return runtime
        return original_import_module(name, package)

    importlib.import_module = _patched_import_module
    try:
        exec(source, module_globals, module_globals)
        module_globals[HELPER_NAME](("nonce", "tag", "body"), {"mode": "local-embedded", "parts": []})
    finally:
        importlib.import_module = original_import_module
    return module_globals


def _case_happy_path(root: Path) -> None:
    runtime_file = root / PACKAGE_NAME / f"{RUNTIME_MODULE}.pyd"
    runtime_file.parent.mkdir(parents=True, exist_ok=True)
    runtime_file.write_bytes(b"runtime-native-v1")
    _write_manifest(
        root,
        compiled_relative_path=f"{PACKAGE_NAME}/{RUNTIME_MODULE}.pyd",
        digest_hex=_sha256_file(runtime_file),
    )

    module_globals = _invoke_generated_guard(root, runtime_file)
    if module_globals.get("RUNTIME_INTEGRITY_SMOKE_EXECUTED") is not True:
        raise AssertionError("runtime guard did not call runtime _x")


def _expect_failure(case_name: str, root: Path, setup: Callable[[Path], Path], expected_text: str) -> None:
    runtime_file = setup(root)
    try:
        _invoke_generated_guard(root, runtime_file)
    except RuntimeError as exc:
        message = str(exc)
        if expected_text not in message:
            raise AssertionError(f"{case_name} failed with unexpected error: {message}") from exc
        return
    raise AssertionError(f"{case_name} did not fail closed")


def _setup_runtime_replaced(root: Path) -> Path:
    runtime_file = root / "other_pkg" / f"{RUNTIME_MODULE}.pyd"
    runtime_file.parent.mkdir(parents=True, exist_ok=True)
    runtime_file.write_bytes(b"runtime-replaced")
    _write_manifest(
        root,
        compiled_relative_path=f"other_pkg/{RUNTIME_MODULE}.pyd",
        digest_hex=_sha256_file(runtime_file),
    )
    return runtime_file


def _setup_manifest_tampered(root: Path) -> Path:
    runtime_file = root / PACKAGE_NAME / f"{RUNTIME_MODULE}.pyd"
    runtime_file.parent.mkdir(parents=True, exist_ok=True)
    runtime_file.write_bytes(b"runtime-native-v1")
    _write_manifest(
        root,
        compiled_relative_path=f"{PACKAGE_NAME}/{RUNTIME_MODULE}_tampered.pyd",
        digest_hex=_sha256_file(runtime_file),
    )
    return runtime_file


def _setup_digest_mismatch(root: Path) -> Path:
    runtime_file = root / PACKAGE_NAME / f"{RUNTIME_MODULE}.pyd"
    runtime_file.parent.mkdir(parents=True, exist_ok=True)
    runtime_file.write_bytes(b"runtime-native-v1")
    _write_manifest(
        root,
        compiled_relative_path=f"{PACKAGE_NAME}/{RUNTIME_MODULE}.pyd",
        digest_hex=hashlib.sha256(b"different-runtime").hexdigest(),
    )
    return runtime_file


def _case_root(work_root: Path, case_name: str) -> Path:
    root = work_root / case_name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    return root


def run_smoke(work_root: Path) -> None:
    cases = [
        ("happy_path", lambda root: _case_happy_path(root), None),
        (
            "runtime_replaced",
            lambda root: _expect_failure(
                "runtime_replaced",
                root,
                _setup_runtime_replaced,
                "runtime module path escaped expected package directory",
            ),
            "failed_closed",
        ),
        (
            "manifest_tampered",
            lambda root: _expect_failure(
                "manifest_tampered",
                root,
                _setup_manifest_tampered,
                "runtime fingerprint path mismatch",
            ),
            "failed_closed",
        ),
        (
            "digest_mismatch",
            lambda root: _expect_failure(
                "digest_mismatch",
                root,
                _setup_digest_mismatch,
                "runtime fingerprint mismatch",
            ),
            "failed_closed",
        ),
    ]
    for case_name, runner, expected in cases:
        runner(_case_root(work_root, case_name))
        if expected:
            print(f"check={case_name} {expected}")
        else:
            print(f"check={case_name} passed")
    print("RUNTIME_INTEGRITY_SMOKE_PASSED")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="P0-B6 runtime integrity smoke.")
    parser.add_argument("--work-dir", help="Optional work directory. Defaults to a temporary directory.")
    parser.add_argument("--keep", action="store_true", help="Keep the temporary work directory.")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.work_dir:
        work_root = Path(args.work_dir).expanduser().resolve()
        work_root.mkdir(parents=True, exist_ok=True)
        run_smoke(work_root)
        print(f"work_dir={work_root}")
        return 0

    if args.keep:
        work_root = Path(tempfile.mkdtemp(prefix="soenc_runtime_integrity_")).resolve()
        run_smoke(work_root)
        print(f"work_dir={work_root}")
        return 0

    with tempfile.TemporaryDirectory(prefix="soenc_runtime_integrity_") as temp_dir:
        work_root = Path(temp_dir).resolve()
        run_smoke(work_root)
        print(f"work_dir={work_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
