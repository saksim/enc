#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""P0-B2 smoke for the V0.3 Code Protection Layer.

Default behavior is strict: prove this chain end-to-end or fail:

    original .py -> protected staging -> .so/.pyd -> import -> behavior match

If native build dependencies are unavailable, the script writes a diagnostic
report and exits with 20. Use ``--allow-blocked`` only when collecting evidence
on a machine that is not expected to have Cython/native build tooling.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional


REPORT_SCHEMA = "enc2sop-code-protection-smoke/v1"
BLOCKED_EXIT_CODE = 20
NATIVE_SUFFIXES = (".pyd", ".so", ".dll", ".dylib")
WORK_DIR_PREFIX = ".tmp_code_protection_smoke"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_under_workspace(root: Path, path_text: Optional[str]) -> Path:
    if path_text:
        path = Path(path_text).expanduser()
        if not path.is_absolute():
            path = root / path
        resolved = path.resolve()
    else:
        suffix = time.strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:8]
        resolved = (root / (".tmp_code_protection_smoke_" + suffix)).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("refuse to operate outside workspace: {0}".format(resolved)) from exc
    if resolved == root:
        raise ValueError("refuse to use workspace root as smoke work dir")
    if not resolved.name.startswith(WORK_DIR_PREFIX):
        raise ValueError(
            "work dir name must start with {0!r}: {1}".format(
                WORK_DIR_PREFIX,
                resolved,
            )
        )
    return resolved


def _resolve_report_path(root: Path, path_text: Optional[str], work_dir: Path) -> Path:
    if not path_text:
        return work_dir / "smoke_code_protection_report.json"
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("report path must stay under workspace: {0}".format(resolved)) from exc
    if resolved == root:
        raise ValueError("refuse to write smoke report to workspace root")
    return resolved


def _demo_module_source() -> str:
    return "\n".join(
        [
            "def add(a, b):",
            "    return a + b",
            "",
            "class Demo:",
            "    def __init__(self, value):",
            "        self.value = value",
            "",
            "    def scale(self, factor):",
            "        return self.value * factor",
            "",
        ]
    )


def _run(command: Iterable[str], *, cwd: Path, env: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    items = [str(item) for item in command]
    completed = subprocess.run(
        items,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return {
        "command": items,
        "returncode": int(completed.returncode),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _dependency_probe(python_exe: str, *, cwd: Path) -> Dict[str, object]:
    probe = (
        "import importlib, importlib.util, json\n"
        "mods = {}\n"
        "for name in ['Crypto', 'setuptools', 'Cython']:\n"
        "    spec = importlib.util.find_spec(name)\n"
        "    row = {'spec': bool(spec), 'origin': getattr(spec, 'origin', None)}\n"
        "    try:\n"
        "        mod = importlib.import_module(name)\n"
        "        row['import_ok'] = True\n"
        "        row['file'] = getattr(mod, '__file__', None)\n"
        "        row['version'] = getattr(mod, '__version__', None)\n"
        "    except Exception as exc:\n"
        "        row['import_ok'] = False\n"
        "        row['error'] = type(exc).__name__ + ': ' + str(exc)\n"
        "    mods[name] = row\n"
        "print(json.dumps(mods, sort_keys=True))\n"
    )
    result = _run([python_exe, "-c", probe], cwd=cwd)
    if result["returncode"] != 0:
        return {
            "ok": False,
            "error": "dependency probe command failed",
            "command": result["command"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
        }
    try:
        payload = json.loads(str(result["stdout"]).strip() or "{}")
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "error": "dependency probe output was not JSON: {0}".format(exc),
            "stdout": result["stdout"],
            "stderr": result["stderr"],
        }
    missing = [
        name
        for name in ("Crypto", "setuptools", "Cython")
        if not bool(payload.get(name, {}).get("import_ok"))
    ]
    return {
        "ok": not missing,
        "missing_or_broken": missing,
        "modules": payload,
    }


def _native_outputs(build_dir: Path) -> List[str]:
    if not build_dir.exists():
        return []
    outputs = [
        str(path.relative_to(build_dir)).replace("\\", "/")
        for path in build_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in NATIVE_SUFFIXES
    ]
    return sorted(outputs)


def _write_report(report_path: Path, report: Dict[str, object]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the P0-B2 code-protection native packaging smoke.")
    parser.add_argument("--work-dir", help="Workspace-local temporary directory. Defaults to .tmp_code_protection_smoke_*.")
    parser.add_argument("--python-exe", default=sys.executable, help="Python interpreter used for protect/build/import.")
    parser.add_argument("--build-profile", default="native", choices=("auto", "windows-msvc", "native"))
    parser.add_argument("--report", help="Output JSON report path. Defaults to <work-dir>/smoke_code_protection_report.json.")
    parser.add_argument(
        "--allow-blocked",
        action="store_true",
        help="Return 0 when native dependencies are missing, while still writing BLOCKED status to the report.",
    )
    parser.add_argument("--keep-work", action="store_true", help="Retain the work directory after success.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    root = _repo_root()
    work_dir = _resolve_under_workspace(root, args.work_dir)
    report_path = _resolve_report_path(root, args.report, work_dir)

    run_suffix = time.strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:8]
    run_dir = work_dir / ("run_" + run_suffix)
    src_dir = run_dir / "src"
    staging_dir = run_dir / "staging"
    build_dir = staging_dir / "build"
    clean_import_dir = run_dir / "clean_import"
    src_dir.mkdir(parents=True, exist_ok=True)
    clean_import_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "demo_module.py").write_text(_demo_module_source(), encoding="utf-8")

    report: Dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "success": False,
        "status": "running",
        "work_dir": str(work_dir),
        "run_dir": str(run_dir),
        "python_exe": str(args.python_exe),
        "build_profile": str(args.build_profile),
        "steps": {},
    }

    protect = _run(
        [
            args.python_exe,
            "soenc.py",
            "protect",
            "-t",
            str(src_dir),
            "-o",
            str(staging_dir),
            "--namespace-root",
            "demo_pkg",
            "--dev-insecure-ok",
        ],
        cwd=root,
        env=os.environ.copy(),
    )
    report["steps"]["protect"] = protect
    if protect["returncode"] != 0:
        report["status"] = "failed"
        report["reason"] = "protect_failed"
        _write_report(report_path, report)
        print("CODE_PROTECTION_SMOKE_FAILED reason=protect_failed report={0}".format(report_path))
        return 1

    deps = _dependency_probe(args.python_exe, cwd=root)
    report["steps"]["native_dependency_probe"] = deps
    if not deps.get("ok"):
        report["status"] = "blocked"
        report["reason"] = "native_dependencies_unavailable"
        _write_report(report_path, report)
        missing = ",".join(str(item) for item in deps.get("missing_or_broken", []))
        print(
            "CODE_PROTECTION_SMOKE_BLOCKED reason=native_dependencies_unavailable missing_or_broken={0} report={1}".format(
                missing,
                report_path,
            )
        )
        return 0 if args.allow_blocked else BLOCKED_EXIT_CODE

    build = _run(
        [
            args.python_exe,
            "soenc.py",
            "build",
            "--staging-dir",
            str(staging_dir),
            "--build-profile",
            str(args.build_profile),
            "--python-exe",
            str(args.python_exe),
        ],
        cwd=root,
        env=os.environ.copy(),
    )
    report["steps"]["build"] = build
    if build["returncode"] != 0:
        report["status"] = "failed"
        report["reason"] = "native_build_failed"
        _write_report(report_path, report)
        print("CODE_PROTECTION_SMOKE_FAILED reason=native_build_failed report={0}".format(report_path))
        return 1

    natives = _native_outputs(build_dir)
    report["native_outputs"] = natives
    if not natives:
        report["status"] = "failed"
        report["reason"] = "no_native_outputs"
        _write_report(report_path, report)
        print("CODE_PROTECTION_SMOKE_FAILED reason=no_native_outputs report={0}".format(report_path))
        return 1

    import_code = (
        "import json, sys\n"
        "sys.path.insert(0, r'{build_dir}')\n"
        "from demo_pkg.demo_module import Demo, add\n"
        "print(json.dumps({{'add': add(2, 3), 'scale': Demo(7).scale(6)}}))\n"
    ).format(build_dir=str(build_dir))
    import_result = _run([args.python_exe, "-c", import_code], cwd=clean_import_dir, env=os.environ.copy())
    report["steps"]["clean_import"] = import_result
    if import_result["returncode"] != 0:
        report["status"] = "failed"
        report["reason"] = "clean_import_failed"
        _write_report(report_path, report)
        print("CODE_PROTECTION_SMOKE_FAILED reason=clean_import_failed report={0}".format(report_path))
        return 1
    try:
        observed = json.loads(str(import_result["stdout"]).strip())
    except json.JSONDecodeError as exc:
        report["status"] = "failed"
        report["reason"] = "clean_import_output_not_json"
        report["json_error"] = str(exc)
        _write_report(report_path, report)
        print("CODE_PROTECTION_SMOKE_FAILED reason=clean_import_output_not_json report={0}".format(report_path))
        return 1

    expected = {"add": 5, "scale": 42}
    report["expected"] = expected
    report["observed"] = observed
    if observed != expected:
        report["status"] = "failed"
        report["reason"] = "behavior_mismatch"
        _write_report(report_path, report)
        print("CODE_PROTECTION_SMOKE_FAILED reason=behavior_mismatch report={0}".format(report_path))
        return 1

    report["success"] = True
    report["status"] = "passed"
    _write_report(report_path, report)
    print("CODE_PROTECTION_SMOKE_OK report={0}".format(report_path))
    if args.keep_work or report_path.resolve().is_relative_to(work_dir.resolve()):
        print("work_dir={0}".format(work_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
