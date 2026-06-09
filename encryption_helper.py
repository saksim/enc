#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Protect Python source files and batch-compile them with Cython.

New workflow:
  original .py -> encrypted .py staging tree -> batch Cython -> .pyd/.so

V0.3 Code Protection Layer boundary:
  - This module owns source selection, snippet encryption, protected staging
    generation, build manifests, and release/package integrity helpers.
  - It is intentionally separate from cross-media SOX1/QR transport; `soenc cm`
    and legacy `soenc transport` must not import this module for help/startup.
  - Cython/native packaging raises reverse-engineering cost only. It does not
    replace SOX1 data encryption and must not be documented as absolute
    protection against strong reverse engineering.
"""

import argparse
import ast
import base64
from datetime import datetime
from datetime import timezone
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
import sysconfig
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
LICENSE_FILE_MODE = "license-file"
REMOTE_KMS_MODE = "remote-kms"
RUNTIME_LOADER_MODE_DEFAULT = "python-import-default"
RUNTIME_LOADER_MODE_NATIVE_ONLY = "native-extension-required"
RUNTIME_API_MARKER = "enc2sop-runtime-core-v1"
RUNTIME_API_VERSION = 1
RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR = "same-package-dir"
RUNTIME_PATH_POLICY_TRUSTED_RELOCATION = "trusted-relocation"
RUNTIME_FINGERPRINT_ALGORITHM_SHA256 = "sha256"
RUNTIME_FINGERPRINT_BINDING_MANIFEST_COMPILED = "manifest-compiled-runtime-v1"
RUNTIME_SUFFIX_POLICY_STRICT_SINGLE = "strict-single-platform"
RUNTIME_SUFFIX_POLICY_PREFER_HOST = "prefer-host-platform"
RELEASE_BUNDLE_SCHEMA = "enc2sop-release-bundle/v1"
RELEASE_BUNDLE_FILENAME = "release_bundle.json"
RELEASE_LAYOUT_VERSION = "v1"
RELEASE_RECEIPT_SCHEMA = "enc2sop-release-receipt/v1"
RELEASE_RECEIPT_FILENAME = "release_receipt.json"
RELEASE_APPROVAL_SCHEMA = "enc2sop-release-approval/v1"
DEFAULT_RELEASE_APPROVAL_KEY_ID = "release-approval-hmac-v1"
GITHUB_CONTEXT_KEYS = (
    "GITHUB_REPOSITORY",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_REF_PROTECTED",
    "GITHUB_ACTIONS",
    "CI",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
    "RUNNER_ARCH",
    "RUNNER_NAME",
    "GITHUB_SHA",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_NUMBER",
    "GITHUB_RETENTION_DAYS",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_EVENT_NAME",
    "GITHUB_SERVER_URL",
    "GITHUB_API_URL",
    "GITHUB_GRAPHQL_URL",
    "GITHUB_JOB",
    "GITHUB_ACTOR",
    "GITHUB_TRIGGERING_ACTOR",
    "GITHUB_ACTOR_ID",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_REPOSITORY_OWNER_ID",
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


def load_release_approval_key(key_file=None, key_b64=None):
    return _load_manifest_sign_key(key_file=key_file, key_b64=key_b64)


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


def _provider_begin_run(provider, context):
    hook = getattr(provider, "begin_run", None)
    if callable(hook):
        hook(context)


def _provider_finalize_run(provider, output_dir, manifest):
    hook = getattr(provider, "finalize_run", None)
    if callable(hook):
        finalized = hook(output_dir, manifest)
        if finalized is not None:
            if not isinstance(finalized, dict):
                raise ValueError("key provider finalize_run must return dict manifest or None")
            return finalized
    return manifest


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


def render_module_preamble(runtime_module, helper_name, require_native_runtime_loader=False):
    lines = [
        f"def {helper_name}(_payload, _parts):",
        "    import importlib as _enc_importlib",
        "    import os as _enc_os",
        f"    _enc_mod_name = f\"{{__package__}}.{runtime_module}\" if __package__ else \"{runtime_module}\"",
        "    _enc_runtime = _enc_importlib.import_module(_enc_mod_name)",
    ]
    cleanup_vars = ["_enc_importlib", "_enc_os", "_enc_mod_name", "_enc_runtime"]
    if require_native_runtime_loader:
        lines.extend(
            [
                "    import hashlib as _enc_hashlib",
                "    import json as _enc_json",
            ]
        )
        lines.extend(
            [
                "    _enc_runtime_name = str(getattr(_enc_runtime, '__name__', '') or '')",
                "    if _enc_runtime_name != _enc_mod_name:",
                f"        raise RuntimeError('runtime module name mismatch for module: {runtime_module}')",
                "    _enc_runtime_file = str(getattr(_enc_runtime, '__file__', '') or '')",
                "    _enc_runtime_file_lower = _enc_runtime_file.lower()",
                f"    _enc_native_suffixes = {NATIVE_EXTENSION_SUFFIXES!r}",
                "    _enc_runtime_suffix = ''",
                "    if (not _enc_runtime_file_lower) or (not _enc_runtime_file_lower.endswith(_enc_native_suffixes)):",
                f"        raise RuntimeError('native runtime loader required for module: {runtime_module}')",
                f"    if getattr(_enc_runtime, 'SOENC_RUNTIME_API_MARKER', None) != {RUNTIME_API_MARKER!r}:",
                f"        raise RuntimeError('runtime api marker mismatch for module: {runtime_module}')",
                f"    if int(getattr(_enc_runtime, 'SOENC_RUNTIME_API_VERSION', 0) or 0) < {RUNTIME_API_VERSION}:",
                f"        raise RuntimeError('runtime api version mismatch for module: {runtime_module}')",
                "    _enc_runtime_file_norm = _enc_os.path.normcase(_enc_os.path.normpath(_enc_os.path.abspath(_enc_runtime_file)))",
                "    _enc_spec = getattr(_enc_runtime, '__spec__', None)",
                "    _enc_origin = str(getattr(_enc_spec, 'origin', '') or '')",
                "    _enc_origin_norm = ''",
                "    if _enc_origin:",
                "        _enc_origin_norm = _enc_os.path.normcase(_enc_os.path.normpath(_enc_os.path.abspath(_enc_origin)))",
                "        if _enc_origin_norm != _enc_runtime_file_norm:",
                f"            raise RuntimeError('runtime module origin mismatch for module: {runtime_module}')",
                "    _enc_module_file = str(globals().get('__file__', '') or '')",
                "    _enc_expected_dir = _enc_os.path.normcase(_enc_os.path.normpath(_enc_os.path.abspath(_enc_os.path.dirname(_enc_runtime_file))))",
                "    _enc_runtime_dir = _enc_expected_dir",
                "    if _enc_module_file:",
                "        _enc_expected_dir = _enc_os.path.normcase(_enc_os.path.normpath(_enc_os.path.abspath(_enc_os.path.dirname(_enc_module_file))))",
                "        _enc_runtime_dir = _enc_os.path.normcase(_enc_os.path.normpath(_enc_os.path.abspath(_enc_os.path.dirname(_enc_runtime_file))))",
                "    _enc_manifest_probe = _enc_expected_dir",
                "    _enc_package = str(globals().get('__package__', '') or '')",
                "    _enc_pkg_parts = [item for item in _enc_package.split('.') if item]",
                "    _enc_index = -1",
                "    for _enc_index in range(len(_enc_pkg_parts)):",
                "        _enc_manifest_probe = _enc_os.path.dirname(_enc_manifest_probe)",
                "    _enc_manifest_path = ''",
                "    _enc_manifest_candidate = ''",
                "    _enc_manifest_walk = ''",
                "    _enc_manifest_parent = ''",
                "    _enc_manifest_candidate = _enc_os.path.join(_enc_manifest_probe, 'build_manifest.json')",
                "    if _enc_os.path.isfile(_enc_manifest_candidate):",
                "        _enc_manifest_path = _enc_manifest_candidate",
                "    else:",
                "        _enc_manifest_walk = _enc_expected_dir",
                "        while _enc_manifest_walk:",
                "            _enc_manifest_candidate = _enc_os.path.join(_enc_manifest_walk, 'build_manifest.json')",
                "            if _enc_os.path.isfile(_enc_manifest_candidate):",
                "                _enc_manifest_path = _enc_manifest_candidate",
                "                break",
                "            _enc_manifest_parent = _enc_os.path.dirname(_enc_manifest_walk)",
                "            if _enc_manifest_parent == _enc_manifest_walk:",
                "                break",
                "            _enc_manifest_walk = _enc_manifest_parent",
                "    if not _enc_manifest_path:",
                f"        raise RuntimeError('runtime fingerprint manifest missing for module: {runtime_module}')",
                "    with open(_enc_manifest_path, 'r', encoding='utf-8') as _enc_manifest_file:",
                "        _enc_manifest = _enc_json.load(_enc_manifest_file)",
                "    _enc_runtime_delivery = _enc_manifest.get('runtime_delivery') if isinstance(_enc_manifest, dict) else None",
                "    _enc_trust_policy = _enc_runtime_delivery.get('trust_policy') if isinstance(_enc_runtime_delivery, dict) else None",
                "    _enc_require_fp = bool((_enc_trust_policy or {}).get('require_runtime_fingerprint', True))",
                f"    _enc_suffix_policy = str((_enc_trust_policy or {{}}).get('runtime_suffix_policy', {RUNTIME_SUFFIX_POLICY_STRICT_SINGLE!r}) or {RUNTIME_SUFFIX_POLICY_STRICT_SINGLE!r}).strip()",
                "    _enc_suffixes_raw = (_enc_trust_policy or {}).get('runtime_native_suffixes', _enc_native_suffixes)",
                "    if isinstance(_enc_suffixes_raw, str):",
                "        _enc_suffixes_raw = [_enc_suffixes_raw]",
                "    _enc_suffixes = []",
                "    _enc_suffix = ''",
                "    _enc_suffix_text = ''",
                "    if isinstance(_enc_suffixes_raw, list):",
                "        for _enc_suffix in _enc_suffixes_raw:",
                "            _enc_suffix_text = str(_enc_suffix or '').strip().lower()",
                "            if not _enc_suffix_text:",
                "                continue",
                "            if not _enc_suffix_text.startswith('.'):",
                "                _enc_suffix_text = '.' + _enc_suffix_text",
                "            if _enc_suffix_text not in _enc_suffixes:",
                "                _enc_suffixes.append(_enc_suffix_text)",
                "    if not _enc_suffixes:",
                "        _enc_suffixes = list(_enc_native_suffixes)",
                "    _enc_runtime_suffix = _enc_os.path.splitext(_enc_runtime_file_lower)[1]",
                "    if _enc_runtime_suffix not in _enc_suffixes:",
                f"        raise RuntimeError('runtime native suffix not allowed for module: {runtime_module}')",
                f"    if _enc_suffix_policy not in ({RUNTIME_SUFFIX_POLICY_STRICT_SINGLE!r}, {RUNTIME_SUFFIX_POLICY_PREFER_HOST!r}):",
                f"        raise RuntimeError('unsupported runtime suffix policy for module: {runtime_module}')",
                f"    _enc_path_policy = str((_enc_trust_policy or {{}}).get('runtime_path_policy', {RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR!r}) or {RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR!r}).strip()",
                "    _enc_allow_reloc = bool((_enc_trust_policy or {}).get('runtime_relocation_allowed', False))",
                "    _enc_roots_raw = (_enc_trust_policy or {}).get('trusted_runtime_roots', [])",
                "    if isinstance(_enc_roots_raw, str):",
                "        _enc_roots_raw = [_enc_roots_raw]",
                "    _enc_roots = []",
                "    _enc_root = ''",
                "    _enc_root_text = ''",
                "    if isinstance(_enc_roots_raw, list):",
                "        for _enc_root in _enc_roots_raw:",
                "            _enc_root_text = str(_enc_root or '').strip().replace('\\\\', '/')",
                "            while _enc_root_text.startswith('./'):",
                "                _enc_root_text = _enc_root_text[2:]",
                "            _enc_root_text = _enc_root_text.strip('/')",
                "            if _enc_root_text and (_enc_root_text not in _enc_roots):",
                "                _enc_roots.append(_enc_root_text)",
                "    _enc_is_trusted_root = False",
                "    _enc_root_norm = ''",
                "    _enc_root_prefix = ''",
                "    _enc_manifest_root = _enc_os.path.dirname(_enc_manifest_path)",
                "    _enc_runtime_rel = ''",
                "    if _enc_path_policy == 'same-package-dir':",
                "        if _enc_runtime_dir != _enc_expected_dir:",
                f"            raise RuntimeError('runtime module path escaped expected package directory for module: {runtime_module}')",
                "    elif _enc_path_policy == 'trusted-relocation':",
                "        if not _enc_allow_reloc:",
                f"            raise RuntimeError('runtime relocation is not allowed for module: {runtime_module}')",
                "        if not _enc_roots:",
                f"            raise RuntimeError('runtime trusted relocation roots missing for module: {runtime_module}')",
                "        try:",
                "            _enc_runtime_rel = _enc_os.path.relpath(_enc_runtime_file, _enc_manifest_root)",
                "        except ValueError:",
                f"            raise RuntimeError('runtime relocation root not trusted for module: {runtime_module}')",
                "        _enc_runtime_rel = _enc_runtime_rel.replace('\\\\', '/').lstrip('./')",
                "        for _enc_root in _enc_roots:",
                "            _enc_root_norm = str(_enc_root).replace('\\\\', '/').strip('/')",
                "            if not _enc_root_norm:",
                "                continue",
                "            _enc_root_prefix = _enc_root_norm + '/'",
                "            if (_enc_runtime_rel == _enc_root_norm) or _enc_runtime_rel.startswith(_enc_root_prefix):",
                "                _enc_is_trusted_root = True",
                "                break",
                "        if not _enc_is_trusted_root:",
                f"            raise RuntimeError('runtime relocation root not trusted for module: {runtime_module}')",
                "    else:",
                f"        raise RuntimeError('unsupported runtime path policy for module: {runtime_module}')",
                "    _enc_entries = []",
                "    _enc_expected_digest = ''",
                f"    _enc_expected_algo = {RUNTIME_FINGERPRINT_ALGORITHM_SHA256!r}",
                "    _enc_expected_rel = ''",
                "    _enc_expected_suffix = ''",
                "    _enc_runtime_rel_base = ''",
                "    _enc_expected_rel_base = ''",
                "    _enc_entry = None",
                "    _enc_hasher = None",
                "    _enc_runtime_stream = None",
                "    _enc_chunk = b''",
                "    _enc_actual_digest = ''",
                "    if _enc_require_fp:",
                "        _enc_entries = _enc_runtime_delivery.get('compiled_runtime_fingerprints') if isinstance(_enc_runtime_delivery, dict) else None",
                "        if not isinstance(_enc_entries, list):",
                f"            raise RuntimeError('runtime fingerprint metadata missing for module: {runtime_module}')",
                "        for _enc_entry in _enc_entries:",
                "            if not isinstance(_enc_entry, dict):",
                "                continue",
                f"            if str(_enc_entry.get('module_name') or '') != {runtime_module!r}:",
                "                continue",
                "            _enc_expected_digest = str(_enc_entry.get('digest_hex') or '').strip().lower()",
                f"            _enc_expected_algo = str(_enc_entry.get('algorithm') or {RUNTIME_FINGERPRINT_ALGORITHM_SHA256!r}).strip().lower()",
                "            _enc_expected_rel = str(_enc_entry.get('compiled_relative_path') or '').strip().replace('\\\\', '/')",
                "            break",
                "        if not _enc_expected_digest:",
                f"            raise RuntimeError('runtime fingerprint missing for module: {runtime_module}')",
                f"        if _enc_expected_algo != {RUNTIME_FINGERPRINT_ALGORITHM_SHA256!r}:",
                f"            raise RuntimeError('unsupported runtime fingerprint algorithm for module: {runtime_module}')",
                "        if (_enc_suffix_policy == 'strict-single-platform') and _enc_expected_rel:",
                "            _enc_expected_suffix = _enc_os.path.splitext(_enc_expected_rel.lower())[1]",
                "            if (_enc_expected_suffix and _enc_runtime_suffix) and (_enc_expected_suffix != _enc_runtime_suffix):",
                f"                raise RuntimeError('runtime native suffix mismatch for module: {runtime_module}')",
                "        _enc_hasher = _enc_hashlib.sha256()",
                "        with open(_enc_runtime_file, 'rb') as _enc_runtime_stream:",
                "            while True:",
                "                _enc_chunk = _enc_runtime_stream.read(131072)",
                "                if not _enc_chunk:",
                "                    break",
                "                _enc_hasher.update(_enc_chunk)",
                "        _enc_actual_digest = _enc_hasher.hexdigest().lower()",
                "        if _enc_actual_digest != _enc_expected_digest:",
                f"            raise RuntimeError('runtime fingerprint mismatch for module: {runtime_module}')",
                "        if _enc_expected_rel:",
                "            if not _enc_runtime_rel:",
                "                try:",
                "                    _enc_runtime_rel = _enc_os.path.relpath(_enc_runtime_file, _enc_manifest_root)",
                "                except ValueError:",
                f"                    raise RuntimeError('runtime fingerprint path mismatch for module: {runtime_module}')",
                "            _enc_runtime_rel = _enc_runtime_rel.replace('\\\\', '/').lstrip('./')",
                "            if _enc_suffix_policy == 'strict-single-platform':",
                "                if _enc_runtime_rel != _enc_expected_rel:",
                f"                    raise RuntimeError('runtime fingerprint path mismatch for module: {runtime_module}')",
                "            else:",
                "                _enc_runtime_rel_base = _enc_os.path.splitext(_enc_runtime_rel)[0]",
                "                _enc_expected_rel_base = _enc_os.path.splitext(_enc_expected_rel)[0]",
                "                if _enc_runtime_rel_base != _enc_expected_rel_base:",
                f"                    raise RuntimeError('runtime fingerprint path mismatch for module: {runtime_module}')",
            ]
        )
        cleanup_vars.extend(
            [
                "_enc_hashlib",
                "_enc_json",
                "_enc_runtime_name",
                "_enc_runtime_file",
                "_enc_runtime_file_lower",
                "_enc_native_suffixes",
                "_enc_runtime_suffix",
                "_enc_runtime_file_norm",
                "_enc_spec",
                "_enc_origin",
                "_enc_origin_norm",
                "_enc_module_file",
                "_enc_expected_dir",
                "_enc_runtime_dir",
                "_enc_manifest_probe",
                "_enc_package",
                "_enc_pkg_parts",
                "_enc_index",
                "_enc_manifest_path",
                "_enc_manifest_candidate",
                "_enc_manifest_walk",
                "_enc_manifest_parent",
                "_enc_manifest_file",
                "_enc_manifest",
                "_enc_runtime_delivery",
                "_enc_trust_policy",
                "_enc_require_fp",
                "_enc_suffix_policy",
                "_enc_suffixes_raw",
                "_enc_suffixes",
                "_enc_suffix",
                "_enc_suffix_text",
                "_enc_path_policy",
                "_enc_allow_reloc",
                "_enc_roots_raw",
                "_enc_roots",
                "_enc_root",
                "_enc_root_text",
                "_enc_is_trusted_root",
                "_enc_root_norm",
                "_enc_root_prefix",
                "_enc_entries",
                "_enc_expected_digest",
                "_enc_expected_algo",
                "_enc_expected_rel",
                "_enc_expected_suffix",
                "_enc_runtime_rel_base",
                "_enc_expected_rel_base",
                "_enc_entry",
                "_enc_hasher",
                "_enc_runtime_stream",
                "_enc_chunk",
                "_enc_actual_digest",
                "_enc_manifest_root",
                "_enc_runtime_rel",
            ]
        )
    lines.append("    _enc_runtime._x((_payload,), _parts, globals())")
    lines.append("    del {0}".format(", ".join(cleanup_vars)))
    return "\n".join(lines) + "\n"

def render_symbol_stub(symbol):
    if symbol.kind in ("function", "async_function"):
        return (
            "def {0}(*args, **kwargs):\n"
            "    raise RuntimeError('encrypted symbol stub invoked before real definition: {0}')\n"
        ).format(symbol.name)
    return "class {0}(object):\n    pass\n".format(symbol.name)


def render_exec_block(helper_name, payload, key_ref):
    return f"{helper_name}({payload!r}, {key_ref!r})"


def protect_source(source, runtime_module, symbols_to_encrypt, key_mode, require_native_runtime_loader=False):
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

    preamble = render_module_preamble(
        runtime_module,
        helper_name,
        require_native_runtime_loader=require_native_runtime_loader,
    ).splitlines()
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
    key_provider,
    require_native_runtime_loader,
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
        protected_source = protect_source(
            source,
            runtime_name,
            chosen,
            key_mode=key_mode,
            require_native_runtime_loader=require_native_runtime_loader,
        )
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
            "loader_mode": (
                RUNTIME_LOADER_MODE_NATIVE_ONLY if require_native_runtime_loader else RUNTIME_LOADER_MODE_DEFAULT
            ),
            "loader_enforced": bool(require_native_runtime_loader),
            "trust_policy": {
                "runtime_api_marker": RUNTIME_API_MARKER,
                "runtime_api_version": RUNTIME_API_VERSION,
                "runtime_path_policy": RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR,
                "runtime_relocation_allowed": False,
                "trusted_runtime_roots": [],
                "runtime_suffix_policy": RUNTIME_SUFFIX_POLICY_STRICT_SINGLE,
                "runtime_native_suffixes": list(runtime_host_native_suffixes()),
                "spec_origin_match": True,
                "runtime_fingerprint_algorithm": RUNTIME_FINGERPRINT_ALGORITHM_SHA256,
                "runtime_fingerprint_binding": RUNTIME_FINGERPRINT_BINDING_MANIFEST_COMPILED,
                "require_runtime_fingerprint": bool(require_native_runtime_loader),
            },
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
    manifest = _provider_finalize_run(key_provider, output_dir, manifest)
    write_manifest(output_dir, manifest)

    return output_dir, tuple(results), tuple(sorted(output_runtimes)), tuple(generated_issues)


def _runtime_native_candidates(source_relative_path):
    source_rel = Path(source_relative_path)
    return tuple(source_rel.with_suffix(suffix) for suffix in NATIVE_EXTENSION_SUFFIXES)


def runtime_host_native_suffixes():
    suffixes = []  # type: List[str]
    ext_suffix = str(sysconfig.get_config_var("EXT_SUFFIX") or "").strip().lower()
    if ext_suffix:
        ext = os.path.splitext(ext_suffix)[1]
        if ext and ext not in suffixes:
            suffixes.append(ext)
    for suffix in NATIVE_EXTENSION_SUFFIXES:
        text = str(suffix).strip().lower()
        if not text.startswith("."):
            text = "." + text
        if text and text not in suffixes:
            suffixes.append(text)
    return tuple(suffixes)


def _normalize_native_suffixes(raw_suffixes):
    if isinstance(raw_suffixes, str):
        raw_suffixes = [raw_suffixes]
    if not isinstance(raw_suffixes, list):
        return tuple()
    normalized = []  # type: List[str]
    for item in raw_suffixes:
        text = str(item).strip().lower()
        if not text:
            continue
        if not text.startswith("."):
            text = "." + text
        if text not in normalized:
            normalized.append(text)
    return tuple(normalized)


def _normalize_trusted_runtime_roots(raw_roots):
    if isinstance(raw_roots, str):
        raw_roots = [raw_roots]
    if not isinstance(raw_roots, list):
        return tuple()
    normalized = []  # type: List[str]
    for item in raw_roots:
        text = str(item).strip().replace("\\", "/")
        if not text:
            continue
        while text.startswith("./"):
            text = text[2:]
        text = text.strip("/")
        if not text:
            continue
        path = Path(text)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError("trusted runtime root must be a relative path inside release root: {0}".format(item))
        value = str(path).replace("\\", "/")
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def _runtime_native_candidates_for_suffixes(source_relative_path, native_suffixes):
    source_rel = Path(source_relative_path)
    return tuple(source_rel.with_suffix(suffix) for suffix in native_suffixes)


def _pick_compiled_runtime_candidate(build_dir, runtime_file, native_suffixes, suffix_policy):
    existing = []  # type: List[Tuple[str, str]]
    for candidate in _runtime_native_candidates_for_suffixes(runtime_file, native_suffixes):
        candidate_path = build_dir / candidate
        if candidate_path.exists():
            suffix = candidate.suffix.lower()
            existing.append((_normalized_relpath_text(candidate), suffix))
    # Cython module paths are package-shaped only when package discovery is unambiguous.
    # For directories without __init__.py (for example tests/ on modern projects),
    # extension artifacts can land at build root: tests/enc_rt_x.py -> enc_rt_x.so
    # Keep this fallback scoped to runtime loader stubs only.
    runtime_source = Path(runtime_file)
    runtime_name = runtime_source.stem
    runtime_parent = runtime_source.parent
    if runtime_parent != Path(".") and runtime_name.startswith(RUNTIME_MODULE_PREFIX + "_"):
        for suffix in native_suffixes:
            candidate = Path(runtime_name).with_suffix(suffix)
            candidate_path = build_dir / candidate
            if candidate_path.exists():
                suffix_text = candidate.suffix.lower()
                existing.append((_normalized_relpath_text(candidate), suffix_text))

    if not existing:
        return None

    by_suffix = {}  # type: Dict[str, str]
    for candidate_text, suffix in existing:
        by_suffix[suffix] = candidate_text

    host_suffixes = runtime_host_native_suffixes()
    host_suffix = host_suffixes[0] if host_suffixes else (native_suffixes[0] if native_suffixes else "")
    if suffix_policy == RUNTIME_SUFFIX_POLICY_STRICT_SINGLE:
        if len(by_suffix) > 1:
            raise RuntimeError(
                "mixed-platform runtime artifacts detected for {0}: {1}".format(
                    runtime_file,
                    ", ".join(sorted(by_suffix.keys())),
                )
            )
        if host_suffix and host_suffix not in by_suffix:
            raise RuntimeError(
                "runtime native suffix mismatch for host platform on {0}: expected {1}, found {2}".format(
                    runtime_file,
                    host_suffix,
                    ", ".join(sorted(by_suffix.keys())),
                )
            )
        return by_suffix.get(host_suffix) if host_suffix else next(iter(by_suffix.values()))

    if suffix_policy != RUNTIME_SUFFIX_POLICY_PREFER_HOST:
        raise RuntimeError("unsupported runtime suffix policy: {0}".format(suffix_policy))

    for suffix in host_suffixes:
        candidate = by_suffix.get(suffix)
        if candidate is not None:
            return candidate
    return sorted(by_suffix.values())[0]


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(131072)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_relpath_text(value):
    return str(value).replace("\\", "/")


def _utc_now_iso8601_seconds():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _github_context_snapshot():
    context = {}
    for key in GITHUB_CONTEXT_KEYS:
        value = os.environ.get(key)
        if value:
            context[key] = value
    return context


def _select_release_runtime_fingerprints(manifest, native_relative_set):
    delivery = (manifest.get("runtime_delivery") or {}) if isinstance(manifest, dict) else {}
    entries = delivery.get("compiled_runtime_fingerprints")
    if not isinstance(entries, list):
        return []
    selected = []  # type: List[Dict[str, str]]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        compiled_relative = _normalized_relpath_text(entry.get("compiled_relative_path") or "").strip()
        if not compiled_relative:
            continue
        if compiled_relative not in native_relative_set:
            continue
        selected.append(
            {
                "module_name": str(entry.get("module_name") or ""),
                "source_relative_path": str(entry.get("source_relative_path") or ""),
                "compiled_relative_path": compiled_relative,
                "package_relative_path": str(entry.get("package_relative_path") or ""),
                "algorithm": str(entry.get("algorithm") or RUNTIME_FINGERPRINT_ALGORITHM_SHA256),
                "digest_hex": str(entry.get("digest_hex") or ""),
            }
        )
    return sorted(selected, key=lambda item: (item.get("module_name") or "", item.get("compiled_relative_path") or ""))


def build_release_bundle_metadata(
    *,
    dist_dir,
    staging_dir,
    build_dir,
    manifest,
    package_metadata=None,
    license_relative_path=None,
):
    release_root = normalize_path(dist_dir)
    staging_root = normalize_path(staging_dir)
    build_root = normalize_path(build_dir)

    runtime_files = []  # type: List[str]
    runtime_delivery = manifest.get("runtime_delivery") if isinstance(manifest, dict) else None
    if isinstance(runtime_delivery, dict):
        values = runtime_delivery.get("compiled_runtime_files")
        if isinstance(values, list):
            runtime_files = [
                _normalized_relpath_text(item).strip()
                for item in values
                if isinstance(item, str) and _normalized_relpath_text(item).strip()
            ]

    native_files = []  # type: List[str]
    for native_path in native_extension_files(release_root):
        native_files.append(_normalized_relpath_text(native_path.relative_to(release_root)))
    native_files = sorted(set(native_files))
    native_set = set(native_files)

    package_inits = []  # type: List[str]
    for init_path in release_root.rglob("__init__.py"):
        package_inits.append(_normalized_relpath_text(init_path.relative_to(release_root)))
    package_inits = sorted(set(package_inits))

    package_metadata_payload = {}
    if isinstance(package_metadata, dict):
        for key, value in package_metadata.items():
            if value is None:
                continue
            text = str(value).strip()
            if text:
                package_metadata_payload[str(key)] = text

    license_payload = None
    if license_relative_path:
        license_payload = {
            "relative_path": _normalized_relpath_text(license_relative_path),
            "required_for_runtime": True,
        }

    build_manifest_payload = {
        "relative_path": "build_manifest.json",
        "is_signed": isinstance(manifest.get("signature"), dict),
        "signature": manifest.get("signature"),
    }

    runtime_fingerprints = _select_release_runtime_fingerprints(manifest, native_set)

    return {
        "schema": RELEASE_BUNDLE_SCHEMA,
        "layout_version": RELEASE_LAYOUT_VERSION,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "release_root": str(release_root),
        "source": {
            "staging_dir": str(staging_root),
            "build_dir": str(build_root),
        },
        "build_manifest": build_manifest_payload,
        "bundle_contents": {
            "native_extension_files": native_files,
            "runtime_compiled_files": sorted(set(item for item in runtime_files if item in native_set)),
            "package_init_files": package_inits,
            "license_file": license_payload,
        },
        "runtime_integrity": {
            "validation_required": True,
            "compiled_runtime_fingerprints": runtime_fingerprints,
            "validated": bool((runtime_delivery or {}).get("validated")) if isinstance(runtime_delivery, dict) else False,
        },
        "key_management": manifest.get("key_management"),
        "config": manifest.get("config"),
        "package_metadata": package_metadata_payload,
    }


def write_release_bundle_metadata(
    *,
    dist_dir,
    staging_dir,
    build_dir,
    manifest,
    package_metadata=None,
    license_relative_path=None,
):
    release_root = normalize_path(dist_dir)
    payload = build_release_bundle_metadata(
        dist_dir=release_root,
        staging_dir=staging_dir,
        build_dir=build_dir,
        manifest=manifest,
        package_metadata=package_metadata,
        license_relative_path=license_relative_path,
    )
    metadata_path = release_root / RELEASE_BUNDLE_FILENAME
    metadata_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return metadata_path


def release_bundle_path(dist_dir):
    release_dir = normalize_path(dist_dir)
    return release_dir / RELEASE_BUNDLE_FILENAME


def release_receipt_path(dist_dir):
    release_dir = normalize_path(dist_dir)
    return release_dir / RELEASE_RECEIPT_FILENAME


def write_release_approval(
    *,
    dist_dir,
    approvers,
    approval_key,
    approval_file=None,
    approval_key_id=None,
    approved_at_utc=None,
    notes=None,
):
    release_dir = normalize_path(dist_dir)
    if not release_dir.exists():
        raise FileNotFoundError("release directory not found: {0}".format(release_dir))
    bundle_path = release_bundle_path(release_dir)
    if not bundle_path.exists():
        raise RuntimeError("release bundle metadata missing: {0}".format(bundle_path))
    if approval_key is None:
        raise ValueError("release approval signing key is required")

    normalized_approvers = []  # type: List[str]
    for item in approvers or ():
        text = str(item).strip()
        if text:
            normalized_approvers.append(text)
    if not normalized_approvers:
        raise ValueError("release approval requires at least one approver")
    normalized_approvers = sorted(set(normalized_approvers))

    approved_at = str(approved_at_utc or "").strip() or _utc_now_iso8601_seconds()
    key_id = str(approval_key_id or "").strip() or DEFAULT_RELEASE_APPROVAL_KEY_ID
    payload = {
        "schema": RELEASE_APPROVAL_SCHEMA,
        "approved_at_utc": approved_at,
        "release_bundle_relative_path": RELEASE_BUNDLE_FILENAME,
        "release_bundle_sha256": _sha256_file(bundle_path),
        "approvers": normalized_approvers,
    }
    github_context = _github_context_snapshot()
    if github_context:
        payload["github_context"] = github_context
    notes_text = str(notes or "").strip()
    if notes_text:
        payload["notes"] = notes_text

    signature_digest = hmac.new(
        approval_key,
        _canonical_json_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    payload["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM_HMAC_SHA256,
        "key_id": key_id,
        "digest_hex": signature_digest,
    }

    approval_path = normalize_path(approval_file) if approval_file is not None else (release_dir / "release_approval.json")
    ensure_parent(approval_path)
    approval_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return approval_path, payload


def write_release_receipt(
    *,
    dist_dir,
    required_manifest_signature=False,
    key_mode=None,
    package_metadata=None,
    require_approval=False,
    approval_file=None,
    approval_key=None,
    approval_key_id=None,
):
    release_dir = normalize_path(dist_dir)
    if not release_dir.exists():
        raise FileNotFoundError("release directory not found: {0}".format(release_dir))

    bundle_path = release_bundle_path(release_dir)
    if not bundle_path.exists():
        raise RuntimeError("release bundle metadata missing: {0}".format(bundle_path))
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    if bundle.get("schema") != RELEASE_BUNDLE_SCHEMA:
        raise RuntimeError("unsupported release bundle schema: {0}".format(bundle.get("schema")))
    if bundle.get("layout_version") != RELEASE_LAYOUT_VERSION:
        raise RuntimeError("unsupported release bundle layout_version: {0}".format(bundle.get("layout_version")))

    manifest_path = release_dir / "build_manifest.json"
    if not manifest_path.exists():
        raise RuntimeError("build_manifest.json missing in release directory: {0}".format(release_dir))
    manifest = read_manifest(manifest_path)

    manifest_signature = manifest.get("signature")
    has_manifest_signature = isinstance(manifest_signature, dict)
    if required_manifest_signature and not has_manifest_signature:
        raise RuntimeError("build manifest signature is required for release")

    bundle_manifest = bundle.get("build_manifest") or {}
    if not isinstance(bundle_manifest, dict):
        raise RuntimeError("release bundle build_manifest metadata is invalid")
    if _normalized_relpath_text(bundle_manifest.get("relative_path") or "") != "build_manifest.json":
        raise RuntimeError("release bundle build_manifest.relative_path must be build_manifest.json")
    if bool(bundle_manifest.get("is_signed")) != has_manifest_signature:
        raise RuntimeError("release bundle signed-manifest state does not match build_manifest.json")
    if has_manifest_signature:
        bundle_sig = bundle_manifest.get("signature")
        if bundle_sig != manifest_signature:
            raise RuntimeError("release bundle manifest signature metadata does not match build_manifest.json")

    bundle_contents = bundle.get("bundle_contents") or {}
    if not isinstance(bundle_contents, dict):
        raise RuntimeError("release bundle bundle_contents metadata is invalid")
    runtime_delivery = (manifest.get("runtime_delivery") or {}) if isinstance(manifest, dict) else {}
    runtime_files = manifest.get("runtime_files") or []
    if runtime_files:
        if not isinstance(runtime_delivery, dict) or not runtime_delivery.get("validated"):
            raise RuntimeError("runtime delivery is not validated in build_manifest.json")
        if not runtime_delivery.get("compiled_runtime_files"):
            raise RuntimeError("runtime delivery compiled_runtime_files missing in build_manifest.json")

    native_rel = sorted(
        set(_normalized_relpath_text(path.relative_to(release_dir)) for path in native_extension_files(release_dir))
    )
    if native_rel != sorted(set(_normalized_relpath_text(item) for item in bundle_contents.get("native_extension_files") or [])):
        raise RuntimeError("release bundle native_extension_files do not match release directory contents")

    runtime_compiled_rel = sorted(
        set(_normalized_relpath_text(item) for item in runtime_delivery.get("compiled_runtime_files") or [])
    )
    if runtime_compiled_rel:
        missing_runtime = [item for item in runtime_compiled_rel if not (release_dir / item).exists()]
        if missing_runtime:
            raise RuntimeError("release runtime artifact missing from release directory: {0}".format(", ".join(missing_runtime)))
    bundle_runtime_rel = sorted(
        set(_normalized_relpath_text(item) for item in bundle_contents.get("runtime_compiled_files") or [])
    )
    if bundle_runtime_rel != runtime_compiled_rel:
        raise RuntimeError("release bundle runtime_compiled_files do not match validated manifest metadata")

    package_init_rel = sorted(
        set(_normalized_relpath_text(path.relative_to(release_dir)) for path in release_dir.rglob("__init__.py"))
    )
    bundle_package_init_rel = sorted(
        set(_normalized_relpath_text(item) for item in bundle_contents.get("package_init_files") or [])
    )
    if bundle_package_init_rel != package_init_rel:
        raise RuntimeError("release bundle package_init_files do not match release directory contents")

    key_mgmt = manifest.get("key_management") if isinstance(manifest, dict) else None
    key_mode_resolved = str(key_mode or "").strip() or str((key_mgmt or {}).get("mode") or "").strip()
    if not key_mode_resolved:
        key_mode_resolved = DEFAULT_KEY_MODE
    license_declared = bool((key_mgmt or {}).get("license_file"))
    license_payload = bundle_contents.get("license_file")
    if license_declared:
        if not isinstance(license_payload, dict):
            raise RuntimeError("release bundle license_file metadata missing for license-file key mode")
        license_rel = _normalized_relpath_text(license_payload.get("relative_path") or "").strip()
        if not license_rel:
            raise RuntimeError("release bundle license_file.relative_path is required")
        if not (release_dir / license_rel).exists():
            raise RuntimeError("release license sidecar missing from release directory: {0}".format(license_rel))
    elif license_payload is not None:
        raise RuntimeError("release bundle license_file metadata present but build_manifest.json has no license_file")

    runtime_integrity = bundle.get("runtime_integrity") or {}
    if not isinstance(runtime_integrity, dict):
        raise RuntimeError("release bundle runtime_integrity metadata is invalid")
    if bool(runtime_integrity.get("validated")) != bool(runtime_delivery.get("validated")):
        raise RuntimeError("release bundle runtime_integrity.validated mismatch with build_manifest.json")
    bundle_fingerprints = runtime_integrity.get("compiled_runtime_fingerprints") or []
    if not isinstance(bundle_fingerprints, list):
        raise RuntimeError("release bundle runtime_integrity.compiled_runtime_fingerprints must be a list")
    bundle_fingerprint_by_path = {}
    for entry in bundle_fingerprints:
        if not isinstance(entry, dict):
            continue
        rel = _normalized_relpath_text(entry.get("compiled_relative_path") or "").strip()
        if not rel:
            continue
        bundle_fingerprint_by_path[rel] = entry
    for runtime_rel in runtime_compiled_rel:
        bundle_entry = bundle_fingerprint_by_path.get(runtime_rel)
        if bundle_entry is None:
            raise RuntimeError("release bundle fingerprint missing for runtime artifact: {0}".format(runtime_rel))
        algorithm = str(bundle_entry.get("algorithm") or "").strip().lower()
        if algorithm != RUNTIME_FINGERPRINT_ALGORITHM_SHA256:
            raise RuntimeError("unsupported runtime fingerprint algorithm for release artifact {0}".format(runtime_rel))
        digest_hex = str(bundle_entry.get("digest_hex") or "").strip().lower()
        actual_digest = _sha256_file(release_dir / runtime_rel)
        if digest_hex != actual_digest:
            raise RuntimeError("release runtime fingerprint mismatch for artifact: {0}".format(runtime_rel))

    current_bundle_digest = _sha256_file(bundle_path)
    release_approval_sha256 = None
    approval_signature_digest = None
    approval_github_context = None
    release_github_context = _github_context_snapshot()

    if require_approval:
        approval_path = normalize_path(approval_file) if approval_file is not None else (release_dir / "release_approval.json")
        if not approval_path.exists():
            raise RuntimeError("release approval file missing: {0}".format(approval_path))
        approval_payload = json.loads(approval_path.read_text(encoding="utf-8"))
        if approval_payload.get("schema") != RELEASE_APPROVAL_SCHEMA:
            raise RuntimeError("unsupported release approval schema: {0}".format(approval_payload.get("schema")))
        approval_release_bundle = _normalized_relpath_text(approval_payload.get("release_bundle_relative_path") or "").strip()
        if approval_release_bundle != RELEASE_BUNDLE_FILENAME:
            raise RuntimeError("release approval file must target release_bundle.json")
        approval_digest = str(approval_payload.get("release_bundle_sha256") or "").strip().lower()
        if len(approval_digest) != 64 or any(ch not in "0123456789abcdef" for ch in approval_digest):
            raise RuntimeError("release approval file has invalid release_bundle_sha256")
        if approval_digest != current_bundle_digest:
            raise RuntimeError("release approval bundle digest mismatch")
        approvers = approval_payload.get("approvers")
        if not isinstance(approvers, list) or not approvers or not all(isinstance(item, str) and item.strip() for item in approvers):
            raise RuntimeError("release approval file requires non-empty approvers list")
        signature = approval_payload.get("signature")
        if not isinstance(signature, dict):
            raise RuntimeError("release approval signature missing")
        algorithm = str(signature.get("algorithm") or "").strip().lower()
        if algorithm != SIGNATURE_ALGORITHM_HMAC_SHA256:
            raise RuntimeError("unsupported release approval signature algorithm: {0}".format(algorithm))
        digest_hex = str(signature.get("digest_hex") or "").strip().lower()
        if len(digest_hex) != 64 or any(ch not in "0123456789abcdef" for ch in digest_hex):
            raise RuntimeError("release approval signature digest is invalid")
        if approval_key is None:
            raise RuntimeError("release approval validation key is required")
        signed_payload = dict(approval_payload)
        signed_payload.pop("signature", None)
        expected_digest = hmac.new(approval_key, _canonical_json_bytes(signed_payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_digest, digest_hex):
            raise RuntimeError("release approval signature mismatch")
        actual_approval_key_id = str(signature.get("key_id") or "").strip() or None
        expected_approval_key_id = str(approval_key_id or "").strip() or None
        if expected_approval_key_id is not None and actual_approval_key_id != expected_approval_key_id:
            raise RuntimeError(
                "release approval key_id mismatch: expected {0}, got {1}".format(
                    expected_approval_key_id,
                    actual_approval_key_id,
                )
            )
        approval_verified = True
        approval_file_value = str(approval_path)
        release_approval_sha256 = _sha256_file(approval_path)
        approval_signature_digest = digest_hex
        approval_github_context = approval_payload.get("github_context")
    else:
        approval_verified = False
        actual_approval_key_id = None
        approval_file_value = None

    package_payload = {}
    if isinstance(package_metadata, dict):
        for key, value in package_metadata.items():
            if value is None:
                continue
            text = str(value).strip()
            if text:
                package_payload[str(key)] = text

    receipt = {
        "schema": RELEASE_RECEIPT_SCHEMA,
        "generated_at_utc": _utc_now_iso8601_seconds(),
        "github_context": release_github_context if isinstance(release_github_context, dict) else None,
        "release_root": str(release_dir),
        "build_manifest_relative_path": "build_manifest.json",
        "release_bundle_relative_path": RELEASE_BUNDLE_FILENAME,
        "release_bundle_sha256": current_bundle_digest,
        "bundle_schema": RELEASE_BUNDLE_SCHEMA,
        "layout_version": RELEASE_LAYOUT_VERSION,
        "manifest_signature_required": bool(required_manifest_signature),
        "manifest_signature_present": has_manifest_signature,
        "manifest_signature_key_id": manifest_signature.get("key_id") if has_manifest_signature else None,
        "runtime_artifacts_verified": len(runtime_compiled_rel),
        "native_artifacts_verified": len(native_rel),
        "package_init_files_verified": len(package_init_rel),
        "key_mode": key_mode_resolved,
        "release_approval_required": bool(require_approval),
        "release_approval_verified": approval_verified,
        "release_approval_file": approval_file_value,
        "release_approval_sha256": release_approval_sha256,
        "release_approval_key_id": actual_approval_key_id,
        "release_approval_signature_digest": approval_signature_digest,
        "release_approval_github_context": approval_github_context if isinstance(approval_github_context, dict) else None,
        "package_metadata": package_payload,
    }
    receipt_path = release_receipt_path(release_dir)
    receipt_path.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    return receipt_path, receipt


def _runtime_fingerprints_from_manifest(manifest, build_dir, source_to_compiled):
    fingerprints = []  # type: List[Dict[str, str]]
    runtime_modules = manifest.get("runtime_modules")
    if isinstance(runtime_modules, list):
        for entry in runtime_modules:
            if not isinstance(entry, dict):
                continue
            source_relative = _normalized_relpath_text(entry.get("source_relative_path") or "").strip()
            if not source_relative:
                continue
            compiled_relative = source_to_compiled.get(source_relative)
            if not compiled_relative:
                continue
            module_name = str(entry.get("module_name") or "").strip() or Path(source_relative).stem
            package_relative = _normalized_relpath_text(entry.get("package_relative_path") or "").strip()
            if package_relative == ".":
                package_relative = ""
            compiled_path = build_dir / Path(compiled_relative)
            fingerprints.append(
                {
                    "module_name": module_name,
                    "source_relative_path": source_relative,
                    "package_relative_path": package_relative,
                    "compiled_relative_path": compiled_relative,
                    "algorithm": RUNTIME_FINGERPRINT_ALGORITHM_SHA256,
                    "digest_hex": _sha256_file(compiled_path),
                }
            )
    if fingerprints:
        return sorted(fingerprints, key=lambda item: (item["module_name"], item["compiled_relative_path"]))

    for source_relative, compiled_relative in source_to_compiled.items():
        source_path = Path(source_relative)
        package_relative = _normalized_relpath_text(source_path.parent)
        if package_relative == ".":
            package_relative = ""
        compiled_path = build_dir / Path(compiled_relative)
        fingerprints.append(
            {
                "module_name": source_path.stem,
                "source_relative_path": source_relative,
                "package_relative_path": package_relative,
                "compiled_relative_path": compiled_relative,
                "algorithm": RUNTIME_FINGERPRINT_ALGORITHM_SHA256,
                "digest_hex": _sha256_file(compiled_path),
            }
        )
    return sorted(fingerprints, key=lambda item: (item["module_name"], item["compiled_relative_path"]))


def _runtime_fingerprint_entry_map(entries):
    mapped = {}  # type: Dict[str, Dict[str, str]]
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("runtime fingerprint entries must be JSON objects")
        source_relative = _normalized_relpath_text(str(entry.get("source_relative_path") or "")).strip()
        if not source_relative:
            raise RuntimeError("runtime fingerprint entry missing source_relative_path")
        if source_relative in mapped:
            raise RuntimeError("duplicate runtime fingerprint entry for source: {0}".format(source_relative))
        mapped[source_relative] = {
            "source_relative_path": source_relative,
            "compiled_relative_path": _normalized_relpath_text(str(entry.get("compiled_relative_path") or "")).strip(),
            "algorithm": str(entry.get("algorithm") or "").strip().lower(),
            "digest_hex": str(entry.get("digest_hex") or "").strip().lower(),
            "module_name": str(entry.get("module_name") or "").strip(),
            "package_relative_path": _normalized_relpath_text(str(entry.get("package_relative_path") or "")).strip(),
        }
    return mapped


def _validate_existing_runtime_fingerprints(existing_entries, expected_entries):
    if not isinstance(existing_entries, list) or not existing_entries:
        return
    existing_by_source = _runtime_fingerprint_entry_map(existing_entries)
    expected_by_source = _runtime_fingerprint_entry_map(expected_entries)
    existing_sources = set(existing_by_source.keys())
    expected_sources = set(expected_by_source.keys())
    if existing_sources != expected_sources:
        missing_sources = sorted(expected_sources - existing_sources)
        extra_sources = sorted(existing_sources - expected_sources)
        raise RuntimeError(
            "runtime fingerprint source set mismatch: missing={0} extra={1}".format(
                ",".join(missing_sources) if missing_sources else "<none>",
                ",".join(extra_sources) if extra_sources else "<none>",
            )
        )
    for source_relative in sorted(expected_sources):
        existing = existing_by_source[source_relative]
        expected = expected_by_source[source_relative]
        for field in (
            "compiled_relative_path",
            "algorithm",
            "module_name",
            "package_relative_path",
        ):
            if existing[field] != expected[field]:
                raise RuntimeError(
                    "runtime fingerprint metadata mismatch for {0}: {1} expected={2} actual={3}".format(
                        source_relative,
                        field,
                        expected[field],
                        existing[field],
                    )
                )
        if not hmac.compare_digest(existing["digest_hex"], expected["digest_hex"]):
            raise RuntimeError(
                "runtime fingerprint digest mismatch for {0}".format(source_relative)
            )


def _validate_existing_compiled_runtime_files(existing_files, expected_files):
    if not isinstance(existing_files, list) or not existing_files:
        return
    normalized_existing = sorted(
        _normalized_relpath_text(str(item)).strip()
        for item in existing_files
        if str(item).strip()
    )
    normalized_expected = sorted(
        _normalized_relpath_text(str(item)).strip()
        for item in expected_files
        if str(item).strip()
    )
    if normalized_existing != normalized_expected:
        raise RuntimeError(
            "runtime compiled artifact set mismatch: expected={0} actual={1}".format(
                ",".join(normalized_expected),
                ",".join(normalized_existing),
            )
        )


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

    runtime_delivery = manifest.get("runtime_delivery") or {}
    runtime_delivery.setdefault("loader_mode", RUNTIME_LOADER_MODE_DEFAULT)
    runtime_delivery["loader_enforced"] = bool(runtime_delivery.get("loader_enforced", False))
    trust_policy = runtime_delivery.get("trust_policy")
    if not isinstance(trust_policy, dict):
        trust_policy = {}
    trust_policy.setdefault("runtime_api_marker", RUNTIME_API_MARKER)
    trust_policy.setdefault("runtime_api_version", RUNTIME_API_VERSION)
    trust_policy.setdefault("runtime_path_policy", RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR)
    trust_policy.setdefault("runtime_relocation_allowed", False)
    trust_policy.setdefault("trusted_runtime_roots", [])
    trust_policy.setdefault("runtime_suffix_policy", RUNTIME_SUFFIX_POLICY_STRICT_SINGLE)
    trust_policy.setdefault("runtime_native_suffixes", list(runtime_host_native_suffixes()))
    trust_policy.setdefault("spec_origin_match", True)
    trust_policy.setdefault("runtime_fingerprint_algorithm", RUNTIME_FINGERPRINT_ALGORITHM_SHA256)
    trust_policy.setdefault("runtime_fingerprint_binding", RUNTIME_FINGERPRINT_BINDING_MANIFEST_COMPILED)
    trust_policy.setdefault("require_runtime_fingerprint", runtime_delivery["loader_enforced"])
    runtime_delivery["trust_policy"] = trust_policy

    runtime_suffix_policy = str(trust_policy.get("runtime_suffix_policy") or RUNTIME_SUFFIX_POLICY_STRICT_SINGLE).strip()
    if runtime_suffix_policy not in {RUNTIME_SUFFIX_POLICY_STRICT_SINGLE, RUNTIME_SUFFIX_POLICY_PREFER_HOST}:
        raise RuntimeError("unsupported runtime suffix policy: {0}".format(runtime_suffix_policy))
    runtime_native_suffixes = _normalize_native_suffixes(trust_policy.get("runtime_native_suffixes"))
    if not runtime_native_suffixes:
        runtime_native_suffixes = runtime_host_native_suffixes()
    trust_policy["runtime_native_suffixes"] = list(runtime_native_suffixes)
    trust_policy["runtime_suffix_policy"] = runtime_suffix_policy

    runtime_path_policy = str(trust_policy.get("runtime_path_policy") or RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR).strip()
    if runtime_path_policy not in {RUNTIME_PATH_POLICY_SAME_PACKAGE_DIR, RUNTIME_PATH_POLICY_TRUSTED_RELOCATION}:
        raise RuntimeError("unsupported runtime path policy: {0}".format(runtime_path_policy))
    trusted_runtime_roots = _normalize_trusted_runtime_roots(trust_policy.get("trusted_runtime_roots"))
    runtime_relocation_allowed = bool(trust_policy.get("runtime_relocation_allowed", False))
    if runtime_path_policy == RUNTIME_PATH_POLICY_TRUSTED_RELOCATION:
        if not runtime_relocation_allowed:
            raise RuntimeError("trusted-relocation path policy requires runtime_relocation_allowed=true")
        if not trusted_runtime_roots:
            raise RuntimeError("trusted-relocation path policy requires trusted_runtime_roots")
    trust_policy["runtime_relocation_allowed"] = runtime_relocation_allowed
    trust_policy["trusted_runtime_roots"] = list(trusted_runtime_roots)
    trust_policy["runtime_path_policy"] = runtime_path_policy

    compiled_runtime_files = []  # type: List[str]
    source_to_compiled = {}  # type: Dict[str, str]
    missing_runtime_files = []  # type: List[str]
    for runtime_file in runtime_files:
        runtime_source_relative = _normalized_relpath_text(runtime_file)
        matched = _pick_compiled_runtime_candidate(
            build_dir=build_dir,
            runtime_file=runtime_file,
            native_suffixes=runtime_native_suffixes,
            suffix_policy=runtime_suffix_policy,
        )
        if matched is None:
            missing_runtime_files.append(runtime_source_relative)
        else:
            compiled_runtime_files.append(matched)
            source_to_compiled[runtime_source_relative] = matched

    if missing_runtime_files:
        raise RuntimeError(
            "compiled runtime modules missing from build output: {0}".format(", ".join(sorted(missing_runtime_files)))
        )

    resolved_compiled_runtime_files = sorted(compiled_runtime_files)
    resolved_runtime_fingerprints = _runtime_fingerprints_from_manifest(
        manifest,
        build_dir,
        source_to_compiled,
    )
    _validate_existing_compiled_runtime_files(
        runtime_delivery.get("compiled_runtime_files"),
        resolved_compiled_runtime_files,
    )
    _validate_existing_runtime_fingerprints(
        runtime_delivery.get("compiled_runtime_fingerprints"),
        resolved_runtime_fingerprints,
    )
    runtime_delivery["compiled_runtime_files"] = resolved_compiled_runtime_files
    runtime_delivery["compiled_runtime_fingerprints"] = resolved_runtime_fingerprints
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


def copy_release(
    build_dir,
    dist_dir,
    staging_dir,
    package_metadata=None,
    require_manifest_signature=False,
):
    build_dir = normalize_path(build_dir)
    staging_dir = normalize_path(staging_dir)
    dist_dir = reset_directory(dist_dir)

    manifest = staging_dir / "build_manifest.json"
    if not manifest.exists():
        raise RuntimeError("build manifest missing in staging directory: {0}".format(staging_dir))
    payload = read_manifest(manifest)
    if require_manifest_signature and not isinstance(payload.get("signature"), dict):
        raise RuntimeError("build manifest signature is required for release packaging")

    runtime_files = payload.get("runtime_files") or []
    runtime_delivery = payload.get("runtime_delivery") or {}
    if runtime_files:
        if not isinstance(runtime_delivery, dict) or not runtime_delivery.get("validated"):
            raise RuntimeError("runtime delivery must be validated before release packaging")
        compiled_runtime_files = runtime_delivery.get("compiled_runtime_files") or []
        if not compiled_runtime_files:
            raise RuntimeError("runtime delivery compiled files missing; run soenc build/verify before package")

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
        copied.append(target)

    shutil.copy2(manifest, dist_dir / manifest.name)
    copied.append(dist_dir / manifest.name)

    license_file = ((payload.get("key_management") or {}).get("license_file")) or None
    copied_license_relative = None
    if license_file:
        source_license = (staging_dir / license_file).resolve()
        try:
            source_license.relative_to(staging_dir.resolve())
        except ValueError:
            raise RuntimeError("license_file escapes staging directory: {0}".format(license_file))
        if not source_license.exists():
            raise RuntimeError("license_file declared in manifest but missing: {0}".format(license_file))
        target_license = dist_dir / license_file
        ensure_parent(target_license)
        shutil.copy2(source_license, target_license)
        copied.append(target_license)
        copied_license_relative = license_file

    bundle_path = write_release_bundle_metadata(
        dist_dir=dist_dir,
        staging_dir=staging_dir,
        build_dir=build_dir,
        manifest=payload,
        package_metadata=package_metadata,
        license_relative_path=copied_license_relative,
    )
    copied.append(bundle_path)
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
    add_tristate_flag(
        parser,
        "runtime-native-loader",
        "Require protected symbols to load decrypt runtime from compiled native extension modules only.",
        "Allow Python runtime module fallback for protected symbols.",
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
    parser.add_argument(
        "--license-file",
        default=None,
        help="Relative output path for generated license JSON when keys.mode=license-file.",
    )
    parser.add_argument(
        "--license-id",
        default=None,
        help="Optional stable license identifier recorded in key refs when keys.mode=license-file.",
    )
    parser.add_argument(
        "--kms-profile",
        default=None,
        help="Remote KMS profile name when keys.mode=remote-kms.",
    )
    parser.add_argument(
        "--kms-endpoint",
        default=None,
        help="Remote KMS endpoint URI when keys.mode=remote-kms.",
    )
    parser.add_argument(
        "--kms-key-id",
        default=None,
        help="Remote KMS key identifier used for wrapped data keys.",
    )
    parser.add_argument(
        "--kms-token-env",
        default=None,
        help="Environment variable name for runtime KMS auth token (default: SOENC_KMS_TOKEN).",
    )
    parser.add_argument(
        "--kms-timeout-sec",
        type=float,
        default=None,
        help="Remote KMS request timeout in seconds when keys.mode=remote-kms.",
    )
    parser.add_argument(
        "--kms-max-retries",
        type=int,
        default=None,
        help="Remote KMS max retries when keys.mode=remote-kms.",
    )
    parser.add_argument(
        "--kms-retry-backoff-ms",
        type=int,
        default=None,
        help="Remote KMS retry backoff in milliseconds when keys.mode=remote-kms.",
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
    if args.runtime_native_loader is None:
        args.runtime_native_loader = False
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
    key_provider = get_key_provider(key_mode)
    if key_mode != LICENSE_FILE_MODE and (args.license_file or args.license_id):
        raise ValueError("--license-file/--license-id require keys.mode=license-file")
    kms_args = (
        args.kms_profile,
        args.kms_endpoint,
        args.kms_key_id,
        args.kms_token_env,
        args.kms_timeout_sec,
        args.kms_max_retries,
        args.kms_retry_backoff_ms,
    )
    if key_mode != REMOTE_KMS_MODE and any(value is not None for value in kms_args):
        raise ValueError(
            "--kms-profile/--kms-endpoint/--kms-key-id/--kms-token-env/--kms-timeout-sec/"
            "--kms-max-retries/--kms-retry-backoff-ms require keys.mode=remote-kms"
        )
    _provider_begin_run(
        key_provider,
        {
            "license_file": args.license_file if key_mode == LICENSE_FILE_MODE else None,
            "license_id": args.license_id if key_mode == LICENSE_FILE_MODE else None,
            "kms_profile": args.kms_profile if key_mode == REMOTE_KMS_MODE else None,
            "kms_endpoint": args.kms_endpoint if key_mode == REMOTE_KMS_MODE else None,
            "kms_key_id": args.kms_key_id if key_mode == REMOTE_KMS_MODE else None,
            "kms_token_env": args.kms_token_env if key_mode == REMOTE_KMS_MODE else None,
            "kms_timeout_sec": args.kms_timeout_sec if key_mode == REMOTE_KMS_MODE else None,
            "kms_max_retries": args.kms_max_retries if key_mode == REMOTE_KMS_MODE else None,
            "kms_retry_backoff_ms": args.kms_retry_backoff_ms if key_mode == REMOTE_KMS_MODE else None,
        },
    )

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
        key_provider=key_provider,
        require_native_runtime_loader=args.runtime_native_loader,
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
    print(
        "runtime_loader_mode={0}".format(
            RUNTIME_LOADER_MODE_NATIVE_ONLY if args.runtime_native_loader else RUNTIME_LOADER_MODE_DEFAULT
        )
    )
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
