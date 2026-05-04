#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Protect Python source files and batch-compile them with Cython.

New workflow:
  original .py -> encrypted .py staging tree -> batch Cython -> .pyd/.so
"""

import argparse
import ast
import base64
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tokenize
from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Set
from typing import Tuple
from typing import Union

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from decryption_helper import runtime_py_source

DEFAULT_WINDOWS_PYTHON = r"D:\code_environment\anaconda_all_css\py311\python.exe"
DEFAULT_EXCLUDED_DIRS = {"__pycache__", ".git", ".idea", ".pytest_cache", "build", "dist"}
WINDOWS_VCVARS_CANDIDATES = (
    r"D:\code_environment\visual_studio\enterprise\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
)


class SymbolRange(NamedTuple):
    name: str
    kind: str
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int


class FileProcessResult(NamedTuple):
    relative_path: str
    protected_symbols: Tuple[str, ...]
    runtime_module: Optional[str]


class SyntaxIssue(NamedTuple):
    relative_path: str
    line: int
    offset: int
    message: str


class BuildResult(NamedTuple):
    output_dir: Path
    build_dir: Optional[Path]
    dist_dir: Optional[Path]
    runtime_modules: Tuple[str, ...]
    processed_files: Tuple[FileProcessResult, ...]
    native_files: Tuple[Path, ...] = ()


def normalize_path(value):
    text = os.fspath(value).strip().strip('"')
    if os.name == "nt":
        match = re.match(r"^/([a-zA-Z])/(.*)$", text)
        if match:
            drive, rest = match.groups()
            text = f"{drive.upper()}:/{rest}"
    return Path(text).expanduser().resolve()


def safe_identifier(value: str, fallback: str = "protected_mod") -> str:
    value = re.sub(r"\W+", "_", value).strip("_")
    if not value or value[0].isdigit():
        value = fallback
    return value


def parse_namespace_package(value):
    if value is None:
        return tuple()
    text = str(value).strip()
    if not text:
        return tuple()
    text = text.replace("\\", "/").replace(".", "/")
    parts = [part.strip() for part in text.split("/") if part.strip()]
    if not parts:
        return tuple()
    normalized = []
    for part in parts:
        if not part.isidentifier():
            raise ValueError("invalid namespace segment: {0}".format(part))
        normalized.append(part)
    return tuple(normalized)


def default_namespace_package_parts(target):
    if target.is_file():
        return tuple()
    init_file = target / "__init__.py"
    if init_file.exists():
        if not target.name.isidentifier():
            raise ValueError("target package directory name is not a valid identifier: {0}".format(target.name))
        return (target.name,)
    return tuple()


def infer_namespace_package_parts(target):
    """
    Best-effort namespace inference for directory targets.
    Examples:
      A_py -> A
      A-src -> A
      A.enc -> A
    """
    base = default_namespace_package_parts(target)
    if not base:
        return tuple()
    name = base[0]
    candidates = []

    # Strip common suffixes from right side.
    lowered = name.lower()
    for suffix in ("_py", "-py", ".py", "_src", "-src", "_source", "-source"):
        if lowered.endswith(suffix):
            candidates.append(name[: -len(suffix)])
    candidates.append(name)

    for item in candidates:
        cleaned = re.sub(r"[^0-9A-Za-z_]", "_", item).strip("_")
        if cleaned and cleaned.isidentifier():
            return (cleaned,)
    return base


def load_scope_config(path):
    if path is None:
        return {}
    # Accept UTF-8 with or without BOM so scope.json works from PowerShell/Notepad defaults.
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("scope config must be a JSON object")
    normalized = {}  # type: Dict[str, Dict[str, object]]
    for raw_key, raw_value in data.items():
        if not isinstance(raw_key, str) or not isinstance(raw_value, dict):
            raise ValueError("scope config items must be {relative_path: {...}}")
        key = raw_key.replace("\\", "/")
        normalized[key] = raw_value
    return normalized


def project_python_files(target, excluded_paths):
    files = []  # type: List[Path]
    if target.is_file():
        return [target]

    for path in target.rglob("*.py"):
        if path in excluded_paths:
            continue
        if any(part.startswith(".") and part not in {".", ".."} for part in path.relative_to(target).parts):
            continue
        if any(part in DEFAULT_EXCLUDED_DIRS for part in path.relative_to(target).parts):
            continue
        files.append(path)
    return sorted(files)


def read_source(path: Path) -> str:
    # Accept UTF-8 source files saved with BOM by Windows editors.
    source = path.read_text(encoding="utf-8-sig")
    ast.parse(source, filename=str(path))
    return source


def validate_generated_source(source, filename):
    compile(source, filename, "exec")


def syntax_issue_from_exception(root, path, exc):
    relative_path = str(path.relative_to(root)).replace("\\", "/")
    return SyntaxIssue(
        relative_path=relative_path,
        line=getattr(exc, "lineno", 0) or 0,
        offset=getattr(exc, "offset", 0) or 0,
        message=str(exc),
    )


def precheck_python_files(files, root):
    valid_files = []  # type: List[Path]
    issues = []  # type: List[SyntaxIssue]
    for path in files:
        try:
            source = path.read_text(encoding="utf-8-sig")
            compile(source, str(path), "exec")
            valid_files.append(path)
        except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
            issues.append(syntax_issue_from_exception(root, path, exc))
    return valid_files, issues


def print_precheck_report(issues, valid_count, total_count):
    print("precheck_total={0}".format(total_count))
    print("precheck_valid={0}".format(valid_count))
    print("precheck_invalid={0}".format(len(issues)))
    for issue in issues:
        print(
            "syntax_error={0}:{1}:{2}: {3}".format(
                issue.relative_path,
                issue.line,
                issue.offset,
                issue.message,
            )
        )


def node_end_lineno(node):
    end_lineno = getattr(node, "end_lineno", None)
    if end_lineno is not None:
        return end_lineno
    max_lineno = getattr(node, "lineno", 1)
    for child in ast.walk(node):
        child_line = getattr(child, "lineno", None)
        if child_line is not None and child_line > max_lineno:
            max_lineno = child_line
    return max_lineno


def node_start_lineno(node):
    start_lineno = getattr(node, "lineno", 1)
    decorator_list = getattr(node, "decorator_list", None) or []
    for decorator in decorator_list:
        decorator_line = getattr(decorator, "lineno", start_lineno)
        if decorator_line < start_lineno:
            start_lineno = decorator_line
    return start_lineno


def line_offsets(source):
    offsets = [0]
    running = 0
    for line in source.splitlines(True):
        running += len(line)
        offsets.append(running)
    return offsets


def is_docstring_expr(node):
    if not isinstance(node, ast.Expr):
        return False
    value = node.value
    if isinstance(value, ast.Str):
        return True
    constant_type = getattr(ast, "Constant", None)
    return constant_type is not None and isinstance(value, constant_type) and isinstance(value.value, str)


def top_level_string_token_spans(source):
    spans = []  # type: List[Tuple[int, int]]
    indent = 0
    reader = io.StringIO(source).readline
    try:
        for token_info in tokenize.generate_tokens(reader):
            if token_info.type == tokenize.INDENT:
                indent += 1
            elif token_info.type == tokenize.DEDENT:
                indent = max(0, indent - 1)
            elif token_info.type == tokenize.STRING and indent == 0 and token_info.start[1] == 0:
                spans.append((token_info.start[0], token_info.end[0]))
    except tokenize.TokenError:
        return spans
    return spans


def body_start_lines(source, body):
    spans = top_level_string_token_spans(source)
    string_index = 0
    starts = []  # type: List[int]
    for node in body:
        if is_docstring_expr(node) and string_index < len(spans):
            starts.append(spans[string_index][0])
            string_index += 1
        else:
            starts.append(node_start_lineno(node))
    return starts


def top_level_symbols(source):
    tree = ast.parse(source)
    symbols = []  # type: List[SymbolRange]
    offsets = line_offsets(source)
    body = list(tree.body)
    total_lines = len(source.splitlines())
    starts = body_start_lines(source, body)
    for index, node in enumerate(body):
        start_line = starts[index]
        next_line = starts[index + 1] if index + 1 < len(body) else total_lines + 1
        end_line = max(start_line, next_line - 1)
        start_offset = offsets[start_line - 1]
        end_offset = offsets[end_line] if end_line < len(offsets) else len(source)
        if isinstance(node, ast.ClassDef):
            symbols.append(SymbolRange(node.name, "class", start_line, end_line, start_offset, end_offset))
        elif isinstance(node, ast.FunctionDef):
            symbols.append(SymbolRange(node.name, "function", start_line, end_line, start_offset, end_offset))
        elif isinstance(node, ast.AsyncFunctionDef):
            symbols.append(SymbolRange(node.name, "async_function", start_line, end_line, start_offset, end_offset))
    return symbols


def insertion_line(source):
    tree = ast.parse(source)
    total_lines = len(source.splitlines())
    insert_after = 0
    body = list(tree.body)
    starts = body_start_lines(source, body)
    if body and is_docstring_expr(body[0]):
        insert_after = node_end_lineno(body[0])
        body = body[1:]
        starts = starts[1:]

    first_non_import = None
    first_non_import_line = None
    for index, node in enumerate(body):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        first_non_import = node
        first_non_import_line = starts[index]
        break

    if first_non_import is not None:
        insert_after = max(insert_after, first_non_import_line - 1)
    else:
        if body:
            insert_after = total_lines

    return insert_after


def insertion_offset(source):
    offsets = line_offsets(source)
    line_no = insertion_line(source)
    if line_no <= 0:
        return 0
    if line_no >= len(offsets):
        return len(source)
    return offsets[line_no]


def encrypt_snippet(source):
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    body, tag = cipher.encrypt_and_digest(source.encode("utf-8"))
    payload = (
        base64.b64encode(cipher.nonce).decode("ascii"),
        base64.b64encode(tag).decode("ascii"),
        base64.b64encode(body).decode("ascii"),
    )
    shards = [get_random_bytes(len(key)) for _ in range(3)]
    final = bytearray(key)
    for shard in shards:
        for index, value in enumerate(shard):
            final[index] ^= value
    shards.append(bytes(final))
    parts = tuple(base64.b64encode(item).decode("ascii") for item in shards)
    return payload, parts


def file_scope_entry(
    relative_path,
    config,
    cli_functions,
    cli_classes,
    target_is_file,
):
    if target_is_file and (cli_functions or cli_classes):
        return {
            "functions": list(cli_functions),
            "classes": list(cli_classes),
            "all": False,
        }
    return config.get(relative_path.replace("\\", "/"), {})


def selected_symbols(symbols, entry):
    all_default = bool(entry.get("all", False))
    function_names = set(entry.get("functions", []))
    class_names = set(entry.get("classes", []))

    if not entry:
        return symbols
    if all_default:
        return symbols
    if not function_names and not class_names:
        return symbols

    chosen = []  # type: List[SymbolRange]
    for symbol in symbols:
        if symbol.kind in {"function", "async_function"} and symbol.name in function_names:
            chosen.append(symbol)
        elif symbol.kind == "class" and symbol.name in class_names:
            chosen.append(symbol)
    return chosen


def render_module_preamble(runtime_module, helper_name):
    return (
        f"def {helper_name}(_payload, _parts):\n"
        f"    import importlib as _enc_importlib\n"
        f"    _enc_mod_name = f\"{{__package__}}.{runtime_module}\" if __package__ else \"{runtime_module}\"\n"
        f"    _enc_runtime = _enc_importlib.import_module(_enc_mod_name)\n"
        f"    _enc_runtime._x((_payload,), _parts, globals())\n"
        f"    del _enc_importlib, _enc_mod_name, _enc_runtime\n"
    )


def render_symbol_stub(symbol):
    if symbol.kind in ("function", "async_function"):
        return (
            "def {0}(*args, **kwargs):\n"
            "    raise RuntimeError('encrypted symbol stub invoked before real definition: {0}')\n"
        ).format(symbol.name)
    return "class {0}(object):\n    pass\n".format(symbol.name)


def render_exec_block(helper_name, payload, parts):
    return f"{helper_name}({payload!r}, {parts!r})"


def protect_source(source, runtime_module, symbols_to_encrypt):
    if not symbols_to_encrypt:
        return source

    helper_name = f"__enc_exec_{secrets.token_hex(4)}"
    stubs = []  # type: List[str]
    replacements = []  # type: List[Tuple[int, int, str]]

    for symbol in symbols_to_encrypt:
        snippet = source[symbol.start_offset:symbol.end_offset]
        payload, parts = encrypt_snippet(snippet)
        stubs.append(render_symbol_stub(symbol).rstrip())
        replacement = render_exec_block(helper_name, payload, parts)
        if snippet.endswith("\n") and not replacement.endswith("\n"):
            replacement += "\n"
        replacements.append((symbol.start_offset, symbol.end_offset, replacement))

    new_source = source
    for start_offset, end_offset, replacement in sorted(replacements, key=lambda item: item[0], reverse=True):
        new_source = new_source[:start_offset] + replacement + new_source[end_offset:]

    preamble = render_module_preamble(runtime_module, helper_name).splitlines()
    if stubs:
        preamble.extend([""] + "\n\n".join(stubs).splitlines())
    preamble_text = "\n".join(preamble + [""])
    insert_index = insertion_offset(source)
    if insert_index > 0 and insert_index < len(new_source) and new_source[insert_index] not in ("\n", "\r"):
        preamble.append("")
        preamble_text = "\n".join(preamble + [""])
    final_source = new_source[:insert_index] + preamble_text + new_source[insert_index:]
    return final_source.rstrip() + "\n"


def ensure_parent(path):
    path.parent.mkdir(parents=True, exist_ok=True)


def force_rmtree(path):
    if not path.exists():
        return

    def _onerror(func, value, exc_info):
        try:
            os.chmod(value, 0o700)
        except OSError:
            pass
        func(value)

    shutil.rmtree(path, onerror=_onerror)


def reset_directory(path):
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        return path
    try:
        force_rmtree(path)
    except OSError:
        stale = path.parent / (path.name + ".stale_" + secrets.token_hex(4))
        try:
            path.rename(stale)
            print("warning: moved locked directory to {0}".format(stale))
        except OSError:
            fallback = path.parent / (path.name + ".run_" + secrets.token_hex(4))
            print("warning: directory {0} is locked; using fallback output {1}".format(path, fallback))
            fallback.mkdir(parents=True, exist_ok=True)
            return fallback
    path.mkdir(parents=True, exist_ok=True)
    return path


def runtime_module_map(files, root):
    directories = sorted({file.parent for file in files})
    mapping = {}  # type: Dict[Path, str]
    for directory in directories:
        rel = directory.relative_to(root)
        seed = "root" if str(rel) == "." else "_".join(rel.parts)
        mapping[directory] = safe_identifier(f"__enc_rt_{seed}_{secrets.token_hex(4)}", "__enc_rt")
    return mapping


def namespaced_relative_path(relative, namespace_package_parts):
    if not namespace_package_parts:
        return relative
    return Path(*namespace_package_parts) / relative


def protect_project(
    target,
    output_dir,
    scope_config,
    cli_functions,
    cli_classes,
    valid_files,
    syntax_issues,
    skip_bad_files,
    namespace_package_parts,
):
    output_dir = reset_directory(output_dir)

    root = target.parent if target.is_file() else target
    runtimes = runtime_module_map(valid_files, root)
    results = []  # type: List[FileProcessResult]
    generated_issues = list(syntax_issues)  # type: List[SyntaxIssue]
    for source_path in valid_files:
        relative = source_path.relative_to(root)
        relative_text = str(relative).replace("\\", "/")
        relative_for_output = namespaced_relative_path(relative, namespace_package_parts)
        source = read_source(source_path)
        symbols = top_level_symbols(source)
        entry = file_scope_entry(relative_text, scope_config, cli_functions, cli_classes, target.is_file())
        chosen = selected_symbols(symbols, entry)

        runtime_name = runtimes[source_path.parent]
        protected_source = protect_source(source, runtime_name, chosen)
        destination = output_dir / relative_for_output
        ensure_parent(destination)
        try:
            validate_generated_source(protected_source, str(destination))
        except (SyntaxError, ValueError) as exc:
            issue = SyntaxIssue(relative_text, getattr(exc, "lineno", 0) or 0, getattr(exc, "offset", 0) or 0, str(exc))
            generated_issues.append(issue)
            print(
                "generated_syntax_error={0}:{1}:{2}: {3}".format(
                    issue.relative_path,
                    issue.line,
                    issue.offset,
                    issue.message,
                )
            )
            if skip_bad_files:
                continue
            raise
        destination.write_text(protected_source, encoding="utf-8")

        results.append(
            FileProcessResult(
                relative_path=str(relative_for_output).replace("\\", "/"),
                protected_symbols=tuple(f"{item.kind}:{item.name}" for item in chosen),
                runtime_module=runtime_name if chosen else None,
            )
        )

    # Write runtime files into mirrored output tree after encrypted modules exist.
    output_runtimes = []  # type: List[str]
    for directory, module_name in runtimes.items():
        runtime_relative = namespaced_relative_path(directory.relative_to(root), namespace_package_parts)
        runtime_destination = output_dir / runtime_relative / f"{module_name}.py"
        ensure_parent(runtime_destination)
        runtime_destination.write_text(runtime_py_source(), encoding="utf-8")
        output_runtimes.append(str(runtime_destination.relative_to(output_dir)).replace("\\", "/"))

    manifest = {
        "target": str(target),
        "mode": "file" if target.is_file() else "directory",
        "namespace_package": ".".join(namespace_package_parts) if namespace_package_parts else "",
        "processed_files": [
            {
                "relative_path": result.relative_path,
                "protected_symbols": list(result.protected_symbols),
                "runtime_module": result.runtime_module,
            }
            for result in results
        ],
        "runtime_files": output_runtimes,
        "skipped_files": [issue.relative_path for issue in generated_issues],
        "syntax_issues": [
            {
                "relative_path": issue.relative_path,
                "line": issue.line,
                "offset": issue.offset,
                "message": issue.message,
            }
            for issue in generated_issues
        ],
        "note": "Encrypted staging files are .py. Batch compilation is delegated to py2_linux_rec_opera.py.",
    }
    (output_dir / "build_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    return output_dir, tuple(results), tuple(sorted(output_runtimes)), tuple(generated_issues)


def find_vcvars64():
    if os.name != "nt":
        return None
    for candidate in WINDOWS_VCVARS_CANDIDATES:
        path = Path(candidate)
        if path.exists():
            return path
    return None


def load_windows_build_env(output_dir):
    vcvars = find_vcvars64()
    if vcvars is None:
        return None
    dump_cmd = output_dir / "_dump_windows_env.cmd"
    dump_cmd.write_text(
        "\r\n".join([
            "@echo off",
            f'call "{vcvars}" >nul',
            "set",
            "",
        ]),
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", dump_cmd.name],
        cwd=output_dir,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    env = os.environ.copy()
    for line in completed.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key] = value
    env["PATH"] = os.environ.get("PATH", "") if "PATH" not in env else env["PATH"]
    windows_cl = r"D:\code_environment\visual_studio\enterprise\VC\Tools\MSVC\14.29.30133\bin\HostX64\x64"
    windows_rc = r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64"
    env["PATH"] = windows_cl + os.pathsep + windows_rc + os.pathsep + env.get("PATH", "")
    env["DISTUTILS_USE_SDK"] = "1"
    env["MSSdk"] = "1"
    env["PY2SO_PREPARED_ENV"] = "1"
    return env


def compile_with_batch_builder(python_exe, output_dir):
    builder = Path(__file__).resolve().parent / "py2_linux_rec_opera.py"
    env = load_windows_build_env(output_dir) if os.name == "nt" else None
    subprocess.run(
        [str(python_exe), str(builder), str(output_dir)],
        check=True,
        cwd=output_dir.parent,
        env=env or os.environ.copy(),
    )
    build_dir = output_dir / "build"
    if not build_dir.exists():
        raise RuntimeError("batch cython build did not create build directory")
    sync_package_init_files(output_dir, build_dir)
    return build_dir


def sync_package_init_files(source_root, build_root):
    for path in source_root.rglob("__init__.py"):
        relative = path.relative_to(source_root)
        if "build" in relative.parts or "__pycache__" in relative.parts:
            continue
        target = build_root / relative
        ensure_parent(target)
        shutil.copy2(path, target)


def native_extension_files(root):
    suffixes = (".pyd", ".so", ".dll", ".dylib")
    found = [path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in suffixes]
    return tuple(sorted(found))


def copy_release(build_dir, dist_dir, staging_dir):
    dist_dir = reset_directory(dist_dir)

    copied = []  # type: List[Path]
    for native_file in native_extension_files(build_dir):
        relative = native_file.relative_to(build_dir)
        target = dist_dir / relative
        ensure_parent(target)
        shutil.copy2(native_file, target)
        copied.append(target)

    for init_file in build_dir.rglob("__init__.py"):
        relative = init_file.relative_to(build_dir)
        target = dist_dir / relative
        ensure_parent(target)
        shutil.copy2(init_file, target)

    manifest = staging_dir / "build_manifest.json"
    if manifest.exists():
        shutil.copy2(manifest, dist_dir / manifest.name)
        copied.append(dist_dir / manifest.name)
    return dist_dir, tuple(copied)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Generate encrypted .py staging files and batch-compile them with Cython.")
    parser.add_argument("--target", "-t", required=True, help="Target Python file or directory.")
    parser.add_argument("--output-dir", "-o", default="protected_build", help="Encrypted staging output directory.")
    parser.add_argument(
        "--namespace-root",
        help="Logical package root name for output namespace (e.g. A). If omitted, directory target defaults to its own package name when __init__.py exists.",
    )
    parser.add_argument(
        "--infer-namespace",
        action="store_true",
        help="Infer namespace from target directory name (e.g. A_py -> A) when --namespace-root is not provided.",
    )
    parser.add_argument("--python-exe", default=DEFAULT_WINDOWS_PYTHON, help="Python interpreter used for optional batch compile.")
    parser.add_argument("--precheck-only", action="store_true", help="Only scan Python syntax issues and print a report.")
    parser.add_argument("--skip-bad-files", action="store_true", help="Skip syntax-invalid .py files instead of aborting the whole run.")
    parser.add_argument("--compile", action="store_true", help="Compile the encrypted staging tree with py2_linux_rec_opera.py.")
    parser.add_argument("--dist-dir", help="Copy compiled native artifacts and manifest into a clean release directory.")
    parser.add_argument("--function", action="append", default=[], help="Single-file mode: protect only these top-level function names.")
    parser.add_argument("--class", dest="classes", action="append", default=[], help="Single-file mode: protect only these top-level class names.")
    parser.add_argument("--scope-config", help="JSON file that maps relative paths to {functions, classes, all}.")
    return parser.parse_args(argv)


def is_subpath(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def main(argv=None):
    args = parse_args(argv)
    target = normalize_path(args.target)
    output_dir = normalize_path(args.output_dir)
    python_exe = normalize_path(args.python_exe) if args.python_exe else Path(sys.executable)
    dist_dir = normalize_path(args.dist_dir) if args.dist_dir else None
    scope_config = load_scope_config(normalize_path(args.scope_config) if args.scope_config else None)

    if not target.exists():
        raise FileNotFoundError(f"target not found: {target}")
    if target.is_dir() and (args.function or args.classes):
        raise ValueError("--function/--class only support single-file target; directory mode uses --scope-config")
    if target.is_dir() and is_subpath(output_dir, target):
        raise ValueError("output_dir must not be inside target directory")
    if dist_dir and not args.compile:
        raise ValueError("--dist-dir requires --compile")
    if dist_dir and dist_dir == output_dir:
        raise ValueError("--dist-dir must be different from --output-dir")
    if args.precheck_only and args.compile:
        raise ValueError("--precheck-only cannot be combined with --compile")
    if args.precheck_only and args.dist_dir:
        raise ValueError("--precheck-only cannot be combined with --dist-dir")
    if args.compile and not python_exe.exists():
        raise FileNotFoundError(f"python executable not found: {python_exe}")
    if target.is_file() and args.namespace_root:
        raise ValueError("--namespace-root only supports directory target")
    if target.is_file() and args.infer_namespace:
        raise ValueError("--infer-namespace only supports directory target")
    if args.namespace_root is not None:
        namespace_package_parts = parse_namespace_package(args.namespace_root)
    elif args.infer_namespace:
        namespace_package_parts = infer_namespace_package_parts(target)
    else:
        namespace_package_parts = default_namespace_package_parts(target)

    script_dir = Path(__file__).resolve().parent
    excluded_paths = {
        Path(__file__).resolve(),
        (script_dir / "decryption_helper.py").resolve(),
        (script_dir / "py2_linux_rec_opera.py").resolve(),
    }
    candidate_files = project_python_files(target, excluded_paths)
    if not candidate_files:
        raise FileNotFoundError(f"no python files found under target: {target}")
    root = target.parent if target.is_file() else target
    valid_files, syntax_issues = precheck_python_files(candidate_files, root)
    print_precheck_report(syntax_issues, len(valid_files), len(candidate_files))
    if args.precheck_only:
        return 0 if not syntax_issues else 2
    if syntax_issues and not args.skip_bad_files:
        raise RuntimeError("syntax precheck failed; rerun with --skip-bad-files to continue with valid files only")
    if not valid_files:
        raise RuntimeError("syntax precheck found no valid python files to process")

    actual_output_dir, processed_files, runtime_modules, syntax_issues = protect_project(
        target=target,
        output_dir=output_dir,
        scope_config=scope_config,
        cli_functions=tuple(args.function),
        cli_classes=tuple(args.classes),
        valid_files=valid_files,
        syntax_issues=syntax_issues,
        skip_bad_files=args.skip_bad_files,
        namespace_package_parts=namespace_package_parts,
    )

    build_dir = None  # type: Optional[Path]
    native_files = ()  # type: Tuple[Path, ...]
    actual_dist_dir = dist_dir
    if args.compile:
        build_dir = compile_with_batch_builder(python_exe, actual_output_dir)
        if dist_dir:
            actual_dist_dir, native_files = copy_release(build_dir, dist_dir, actual_output_dir)
        else:
            native_files = native_extension_files(build_dir)

    result = BuildResult(
        output_dir=actual_output_dir,
        build_dir=build_dir,
        dist_dir=actual_dist_dir,
        runtime_modules=runtime_modules,
        processed_files=processed_files,
        native_files=native_files,
    )

    namespace_text = ".".join(namespace_package_parts)
    print(f"output_dir={result.output_dir}")
    print("namespace_package={0}".format(namespace_text if namespace_text else "<root>"))
    print(f"processed_files={len(result.processed_files)}")
    print("skipped_files={0}".format(len(syntax_issues)))
    for item in result.processed_files:
        print(f"file={item.relative_path}")
        print(f"protected={','.join(item.protected_symbols) if item.protected_symbols else 'none'}")
    for runtime_name in result.runtime_modules:
        print(f"runtime={runtime_name}")
    if result.build_dir:
        print(f"build_dir={result.build_dir}")
    if result.dist_dir:
        print(f"dist_dir={result.dist_dir}")
    for native_file in result.native_files:
        print(f"native={native_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
