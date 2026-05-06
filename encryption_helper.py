#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Protect Python source files and batch-compile them with Cython.

New workflow:
  original .py -> encrypted .py staging tree -> batch Cython -> .pyd/.so
"""

import argparse
import ast
import base64
import hashlib
import hmac
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

from enc2sop.keys import get_key_provider
from decryption_helper import runtime_py_source
from soenc_config import SoencProjectConfig
from soenc_config import load_project_config
from toolchain_profile import BUILD_PROFILE_WINDOWS_MSVC
from toolchain_profile import DEFAULT_BUILD_PROFILE
from toolchain_profile import SUPPORTED_BUILD_PROFILES
from toolchain_profile import discover_vcvars64
from toolchain_profile import prepare_windows_build_env
from toolchain_profile import resolve_python_executable

DEFAULT_EXCLUDED_DIRS = {"__pycache__", ".git", ".idea", ".pytest_cache", "build", "dist"}
DEFAULT_OUTPUT_DIR = "protected_build"
DEFAULT_KEY_MODE = "local-embedded"
RUNTIME_MODULE_PREFIX = "enc_rt"
RUNTIME_DELIVERY_MODE = "compiled_native_extension"
NATIVE_EXTENSION_SUFFIXES = (".pyd", ".so", ".dll", ".dylib")
DEFAULT_MANIFEST_KEY_ID = "local-hmac-v1"
SIGNATURE_ALGORITHM_HMAC_SHA256 = "hmac-sha256"


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


def is_compile_eligible_module_name(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name)) and not name.startswith("__")


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


def _canonical_json_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_manifest_sign_key(key_file=None, key_b64=None):
    if key_file and key_b64:
        raise ValueError("manifest signing key must be provided by either file or base64 string, not both")
    raw = None
    if key_file:
        raw = key_file.read_bytes()
    elif key_b64:
        try:
            raw = base64.b64decode(key_b64, validate=True)
        except Exception as exc:
            raise ValueError("manifest signing key is not valid base64") from exc
    if raw is None:
        return None
    key = raw.strip()
    if not key:
        raise ValueError("manifest signing key must not be empty")
    if len(key) < 16:
        raise ValueError("manifest signing key must be at least 16 bytes")
    return key


def _manifest_payload_without_signature(manifest):
    if "signature" not in manifest:
        return manifest
    payload = dict(manifest)
    payload.pop("signature", None)
    return payload


def compute_manifest_signature(manifest, signing_key):
    payload = _manifest_payload_without_signature(manifest)
    canonical = _canonical_json_bytes(payload)
    return hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()


def sign_manifest_dict(manifest, signing_key, key_id):
    signature_hex = compute_manifest_signature(manifest, signing_key)
    signed = dict(manifest)
    signed["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM_HMAC_SHA256,
        "key_id": key_id or DEFAULT_MANIFEST_KEY_ID,
        "digest_hex": signature_hex,
    }
    return signed


def verify_manifest_signature_dict(manifest, signing_key):
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        raise RuntimeError("manifest signature missing")
    algorithm = signature.get("algorithm")
    if algorithm != SIGNATURE_ALGORITHM_HMAC_SHA256:
        raise RuntimeError("unsupported manifest signature algorithm: {0}".format(algorithm))
    digest_hex = signature.get("digest_hex")
    if not isinstance(digest_hex, str) or not digest_hex:
        raise RuntimeError("manifest signature digest is missing")
    expected = compute_manifest_signature(manifest, signing_key)
    if not hmac.compare_digest(expected, digest_hex):
        raise RuntimeError("manifest signature mismatch")
    return signature


def write_manifest(output_dir, manifest, signing_key=None, key_id=None):
    manifest_path = output_dir / "build_manifest.json"
    payload = sign_manifest_dict(manifest, signing_key, key_id) if signing_key is not None else manifest
    manifest_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest_path


def read_manifest(manifest_path):
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def verify_manifest_signature_file(manifest_path, signing_key):
    manifest = read_manifest(manifest_path)
    signature = verify_manifest_signature_dict(manifest, signing_key)
    return manifest, signature


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
    return payload, key


def pack_key_reference(key_bytes, key_mode):
    provider = get_key_provider(key_mode or "local-embedded")
    key_ref = provider.pack_key(key_bytes)
    if not isinstance(key_ref, dict):
        raise ValueError("key provider must return dict key_ref")
    mode = str(key_ref.get("mode") or "").strip().lower()
    if not mode:
        raise ValueError("key provider key_ref missing mode")
    return key_ref


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


def render_exec_block(helper_name, payload, key_ref):
    return f"{helper_name}({payload!r}, {key_ref!r})"


def protect_source(source, runtime_module, symbols_to_encrypt, key_mode):
    if not symbols_to_encrypt:
        return source

    helper_name = f"__enc_exec_{secrets.token_hex(4)}"
    stubs = []  # type: List[str]
    replacements = []  # type: List[Tuple[int, int, str]]

    for symbol in symbols_to_encrypt:
        snippet = source[symbol.start_offset:symbol.end_offset]
        payload, key_bytes = encrypt_snippet(snippet)
        key_ref = pack_key_reference(key_bytes, key_mode)
        stubs.append(render_symbol_stub(symbol).rstrip())
        replacement = render_exec_block(helper_name, payload, key_ref)
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
        runtime_name = safe_identifier(
            f"{RUNTIME_MODULE_PREFIX}_{seed}_{secrets.token_hex(4)}",
            f"{RUNTIME_MODULE_PREFIX}_module",
        )
        if not is_compile_eligible_module_name(runtime_name):
            raise ValueError("generated runtime module name is not compile-eligible: {0}".format(runtime_name))
        mapping[directory] = runtime_name
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
    key_mode,
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
        protected_source = protect_source(source, runtime_name, chosen, key_mode=key_mode)
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
    runtime_records = []  # type: List[Dict[str, str]]
    for directory, module_name in runtimes.items():
        runtime_relative = namespaced_relative_path(directory.relative_to(root), namespace_package_parts)
        runtime_destination = output_dir / runtime_relative / f"{module_name}.py"
        ensure_parent(runtime_destination)
        runtime_destination.write_text(runtime_py_source(), encoding="utf-8")
        runtime_source_relative = str(runtime_destination.relative_to(output_dir)).replace("\\", "/")
        output_runtimes.append(runtime_source_relative)
        runtime_records.append(
            {
                "module_name": module_name,
                "source_relative_path": runtime_source_relative,
                "package_relative_path": str(runtime_relative).replace("\\", "/"),
            }
        )

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
        "runtime_modules": runtime_records,
        "runtime_delivery": {
            "mode": RUNTIME_DELIVERY_MODE,
            "module_prefix": RUNTIME_MODULE_PREFIX,
            "compile_skip_rule": "dunder modules are skipped by batch builder; runtime names must not start with '__'",
            "validation": "build must contain compiled runtime extensions for all runtime_files",
        },
        "key_management": {
            "mode": key_mode,
            "provider": "enc2sop.keys.{0}".format(key_mode.replace("-", "_")),
        },
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
    write_manifest(output_dir, manifest)

    return output_dir, tuple(results), tuple(sorted(output_runtimes)), tuple(generated_issues)


def _runtime_native_candidates(source_relative_path):
    source_rel = Path(source_relative_path)
    return tuple(source_rel.with_suffix(suffix) for suffix in NATIVE_EXTENSION_SUFFIXES)


def validate_runtime_delivery(staging_dir, build_dir, signing_key=None, require_manifest_signature=False):
    manifest_path = staging_dir / "build_manifest.json"
    if not manifest_path.exists():
        raise RuntimeError("build manifest missing in staging directory: {0}".format(staging_dir))

    manifest = read_manifest(manifest_path)
    if signing_key is not None:
        verify_manifest_signature_dict(manifest, signing_key)
    elif require_manifest_signature:
        raise RuntimeError("manifest signature is required but no signing key was provided")
    runtime_files = manifest.get("runtime_files") or []
    if not runtime_files:
        return tuple()

    compiled_runtime_files = []  # type: List[str]
    missing_runtime_files = []  # type: List[str]
    for runtime_file in runtime_files:
        matched = None
        for candidate in _runtime_native_candidates(runtime_file):
            if (build_dir / candidate).exists():
                matched = str(candidate).replace("\\", "/")
                break
        if matched is None:
            missing_runtime_files.append(str(runtime_file))
        else:
            compiled_runtime_files.append(matched)

    if missing_runtime_files:
        raise RuntimeError(
            "compiled runtime modules missing from build output: {0}".format(", ".join(sorted(missing_runtime_files)))
        )

    runtime_delivery = manifest.get("runtime_delivery") or {}
    runtime_delivery["compiled_runtime_files"] = sorted(compiled_runtime_files)
    runtime_delivery["validated"] = True
    manifest["runtime_delivery"] = runtime_delivery
    write_manifest(staging_dir, manifest, signing_key=signing_key, key_id=(manifest.get("signature") or {}).get("key_id"))
    return tuple(Path(path) for path in sorted(compiled_runtime_files))


def find_vcvars64():
    return discover_vcvars64()


def compile_with_batch_builder(
    python_exe,
    output_dir,
    build_profile,
    vcvars_path=None,
    manifest_sign_key=None,
    require_manifest_signature=False,
):
    builder = Path(__file__).resolve().parent / "py2_linux_rec_opera.py"
    env = prepare_windows_build_env(
        output_dir=output_dir,
        profile=build_profile,
        vcvars_path=vcvars_path,
    ) if os.name == "nt" else None
    command = [
        str(python_exe),
        str(builder),
        str(output_dir),
        "--build-profile",
        build_profile,
    ]
    if vcvars_path:
        command.extend(["--vcvars-path", str(vcvars_path)])
    subprocess.run(
        command,
        check=True,
        cwd=output_dir.parent,
        env=env or os.environ.copy(),
    )
    build_dir = output_dir / "build"
    if not build_dir.exists():
        raise RuntimeError("batch cython build did not create build directory")
    sync_package_init_files(output_dir, build_dir)
    validate_runtime_delivery(
        output_dir,
        build_dir,
        signing_key=manifest_sign_key,
        require_manifest_signature=require_manifest_signature,
    )
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
    found = [path for path in root.rglob("*") if path.is_file() and path.suffix.lower() in NATIVE_EXTENSION_SUFFIXES]
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


def add_tristate_flag(parser, name, enable_help, disable_help):
    group = parser.add_mutually_exclusive_group()
    group.add_argument(f"--{name}", dest=name.replace("-", "_"), action="store_true", help=enable_help)
    group.add_argument(f"--no-{name}", dest=name.replace("-", "_"), action="store_false", help=disable_help)
    parser.set_defaults(**{name.replace("-", "_"): None})


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Generate encrypted .py staging files and batch-compile them with Cython.")
    parser.add_argument("--config", "-c", help="Path to soenc.toml. Defaults to ./soenc.toml when present.")
    parser.add_argument("--target", "-t", help="Target Python file or directory (or set [project].target in soenc.toml).")
    parser.add_argument("--output-dir", "-o", help="Encrypted staging output directory.")
    parser.add_argument(
        "--namespace-root",
        help="Logical package root name for output namespace (e.g. A). If omitted, directory target defaults to its own package name when __init__.py exists.",
    )
    add_tristate_flag(
        parser,
        "infer-namespace",
        "Infer namespace from target directory name (e.g. A_py -> A) when --namespace-root is not provided.",
        "Disable namespace inference even if enabled in soenc.toml.",
    )
    parser.add_argument(
        "--python-exe",
        help="Python interpreter used for optional batch compile. Defaults to current interpreter or SOENC_PYTHON_EXE.",
    )
    parser.add_argument(
        "--build-profile",
        default=None,
        choices=SUPPORTED_BUILD_PROFILES,
        help=(
            "Build toolchain profile for native compile. "
            "Use 'auto' for discovery, 'windows-msvc' to require MSVC prep, or 'native' to rely on current shell."
        ),
    )
    parser.add_argument(
        "--vcvars-path",
        help="Optional explicit vcvars64.bat path for windows-msvc profile.",
    )
    add_tristate_flag(
        parser,
        "precheck-only",
        "Only scan Python syntax issues and print a report.",
        "Disable precheck-only mode even if enabled in soenc.toml.",
    )
    add_tristate_flag(
        parser,
        "skip-bad-files",
        "Skip syntax-invalid .py files instead of aborting the whole run.",
        "Disable skip-bad-files even if enabled in soenc.toml.",
    )
    add_tristate_flag(
        parser,
        "compile",
        "Compile the encrypted staging tree with py2_linux_rec_opera.py.",
        "Disable compile step even if enabled in soenc.toml.",
    )
    parser.add_argument("--dist-dir", help="Copy compiled native artifacts and manifest into a clean release directory.")
    parser.add_argument("--function", action="append", default=None, help="Single-file mode: protect only these top-level function names.")
    parser.add_argument("--class", dest="classes", action="append", default=None, help="Single-file mode: protect only these top-level class names.")
    parser.add_argument("--scope-config", help="JSON file that maps relative paths to {functions, classes, all}.")
    parser.add_argument(
        "--manifest-sign-key-file",
        help="Path to manifest signing key bytes. Enables signed build_manifest.json (HMAC-SHA256).",
    )
    parser.add_argument(
        "--manifest-sign-key-b64",
        help="Base64-encoded manifest signing key bytes. Alternative to --manifest-sign-key-file.",
    )
    parser.add_argument(
        "--manifest-key-id",
        default=None,
        help="Signature key identifier recorded in build_manifest.json.",
    )
    add_tristate_flag(
        parser,
        "require-manifest-signature",
        "Require build_manifest.json to contain a valid signature during compile verification.",
        "Disable mandatory signature verification even if enabled in soenc.toml.",
    )
    return parser.parse_args(argv)


def merge_args_with_project_config(args, project_config):
    if project_config is None:
        return args
    for field, config_value in project_config.cli_defaults.items():
        if config_value is None:
            continue
        if getattr(args, field, None) is None:
            setattr(args, field, config_value)
    return args


def finalize_arg_defaults(args):
    if args.output_dir is None:
        args.output_dir = DEFAULT_OUTPUT_DIR
    if args.build_profile is None:
        args.build_profile = DEFAULT_BUILD_PROFILE
    if args.compile is None:
        args.compile = False
    if args.precheck_only is None:
        args.precheck_only = False
    if args.skip_bad_files is None:
        args.skip_bad_files = False
    if args.infer_namespace is None:
        args.infer_namespace = False
    if args.require_manifest_signature is None:
        args.require_manifest_signature = False
    if args.function is None:
        args.function = []
    if args.classes is None:
        args.classes = []
    return args


def is_subpath(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def main(argv=None):
    args = parse_args(argv)
    project_config = load_project_config(config_path=args.config, base_dir=Path.cwd())
    args = merge_args_with_project_config(args, project_config)
    args = finalize_arg_defaults(args)

    if not args.target:
        raise ValueError("target is required (set --target or [project].target in soenc.toml)")

    target = normalize_path(args.target)
    output_dir = normalize_path(args.output_dir)
    python_exe = resolve_python_executable(args.python_exe)
    dist_dir = normalize_path(args.dist_dir) if args.dist_dir else None
    scope_config = load_scope_config(normalize_path(args.scope_config) if args.scope_config else None)
    vcvars_path = normalize_path(args.vcvars_path) if args.vcvars_path else None
    manifest_sign_key_file = normalize_path(args.manifest_sign_key_file) if args.manifest_sign_key_file else None
    manifest_sign_key = _load_manifest_sign_key(
        key_file=manifest_sign_key_file,
        key_b64=args.manifest_sign_key_b64,
    )
    key_mode = (project_config.key_mode if project_config is not None and project_config.key_mode else DEFAULT_KEY_MODE)
    get_key_provider(key_mode)

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
    if args.vcvars_path and args.build_profile not in {DEFAULT_BUILD_PROFILE, BUILD_PROFILE_WINDOWS_MSVC}:
        raise ValueError("--vcvars-path supports only auto/windows-msvc build profiles")
    if args.require_manifest_signature and manifest_sign_key is None:
        raise ValueError("--require-manifest-signature requires --manifest-sign-key-file or --manifest-sign-key-b64")
    if vcvars_path and os.name == "nt" and not vcvars_path.exists():
        raise FileNotFoundError(f"vcvars path not found: {vcvars_path}")
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
        key_mode=key_mode,
    )
    if project_config is not None:
        manifest_path = actual_output_dir / "build_manifest.json"
        manifest = read_manifest(manifest_path)
        manifest["config"] = {
            "source": str(project_config.path),
            "key_mode": key_mode,
            "package_metadata": project_config.package_metadata,
        }
        write_manifest(
            actual_output_dir,
            manifest,
            signing_key=manifest_sign_key,
            key_id=args.manifest_key_id or DEFAULT_MANIFEST_KEY_ID,
        )
    elif manifest_sign_key is not None:
        manifest_path = actual_output_dir / "build_manifest.json"
        manifest = read_manifest(manifest_path)
        write_manifest(
            actual_output_dir,
            manifest,
            signing_key=manifest_sign_key,
            key_id=args.manifest_key_id or DEFAULT_MANIFEST_KEY_ID,
        )

    build_dir = None  # type: Optional[Path]
    native_files = ()  # type: Tuple[Path, ...]
    actual_dist_dir = dist_dir
    if args.compile:
        build_dir = compile_with_batch_builder(
            python_exe=python_exe,
            output_dir=actual_output_dir,
            build_profile=args.build_profile,
            vcvars_path=vcvars_path,
            manifest_sign_key=manifest_sign_key,
            require_manifest_signature=args.require_manifest_signature,
        )
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
    if project_config is not None:
        print(f"config={project_config.path}")
        print(f"key_mode={key_mode}")
        if project_config.package_metadata:
            print("package_metadata={0}".format(json.dumps(project_config.package_metadata, ensure_ascii=False)))
    else:
        print(f"key_mode={key_mode}")
    if manifest_sign_key is not None:
        print("manifest_signature=enabled")
    else:
        print("manifest_signature=disabled")
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
