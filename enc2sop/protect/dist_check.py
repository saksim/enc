#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""P0-B3 dist no-source-leakage checks for protected native packages."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict
from typing import Iterable
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Sequence
from typing import Set


REPORT_SCHEMA = "enc2sop-dist-no-source-leak/v1"
DEFAULT_ALLOWED_PY_BASENAMES = {"__init__.py"}
FORBIDDEN_SUFFIXES = {".c", ".pyx"}
FORBIDDEN_SECRET_SUFFIXES = {".env", ".key", ".p12", ".pem", ".pfx", ".secret"}
FORBIDDEN_DIR_NAMES = {"build", "__pycache__", ".pytest_cache", "tests"}
REQUIRED_RELEASE_METADATA_FILES = ("release_bundle.json", "release_tamper_report.json")
DEFAULT_FORBIDDEN_TOKENS = (
    "BEGIN PRIVATE KEY",
    "PRIVATE KEY-----",
    "passphrase",
    "private_key",
    "key shard",
    "key_shard",
    "debug key",
    "local key",
    "license secret",
    "payload dump",
)


class DistLeakIssue(NamedTuple):
    code: str
    relative_path: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "relative_path": self.relative_path,
            "detail": self.detail,
        }


def _relpath(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _normalize_allow_py(values: Optional[Iterable[str]]) -> Set[str]:
    allowed = set(DEFAULT_ALLOWED_PY_BASENAMES)
    for value in values or ():
        text = str(value or "").strip().replace("\\", "/")
        if text:
            allowed.add(text)
            allowed.add(Path(text).name)
    return allowed


def _read_bytes(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(max_bytes + 1)


def _token_hits(data: bytes, tokens: Sequence[str]) -> List[str]:
    lowered = data.lower()
    hits = []
    for token in tokens:
        raw = str(token or "").strip()
        if not raw:
            continue
        if raw.lower().encode("utf-8", errors="ignore") in lowered:
            hits.append(raw)
    return hits


def _json_object_from_file(path: Path) -> Optional[Dict[str, object]]:
    if path.suffix.lower() != ".json":
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if isinstance(payload, dict):
        return payload
    return None


def _metadata_issues(path: Path, root: Path) -> List[DistLeakIssue]:
    rel = _relpath(path, root)
    payload = _json_object_from_file(path)
    if payload is None:
        return []

    issues: List[DistLeakIssue] = []
    if payload.get("schema") == "enc2sop-license/v1":
        issues.append(DistLeakIssue("license_bundle_file", rel, "license bundle files must stay external to release dist"))

    if path.name == "build_manifest.json":
        key_management = payload.get("key_management")
        if isinstance(key_management, dict):
            if key_management.get("mode") == "local-embedded":
                issues.append(DistLeakIssue("local_embedded_key_mode", rel, "local-embedded key mode is not allowed in release dist"))
            if key_management.get("bundle_license") is True:
                issues.append(DistLeakIssue("license_bundle_enabled", rel, "license bundling must be disabled for release dist"))

    if path.name == "release_bundle.json":
        bundle_contents = payload.get("bundle_contents")
        license_file = bundle_contents.get("license_file") if isinstance(bundle_contents, dict) else None
        if isinstance(license_file, dict):
            if license_file.get("bundled") is True:
                issues.append(DistLeakIssue("release_bundle_license_bundled", rel, "release bundle must not include bundled license files"))
            if license_file.get("externalized") is not True:
                issues.append(DistLeakIssue("release_bundle_license_not_externalized", rel, "release bundle must mark license_file.externalized=true"))

    if path.name == "release_tamper_report.json" and payload.get("success") is not True:
        issues.append(DistLeakIssue("release_tamper_report_failed", rel, "release tamper report must have success=true"))

    return issues


def check_dist_no_source_leak(
    dist_dir,
    *,
    allowed_py: Optional[Iterable[str]] = None,
    forbidden_tokens: Optional[Iterable[str]] = None,
    scan_bytes_limit: int = 2 * 1024 * 1024,
    require_release_metadata: bool = False,
) -> List[DistLeakIssue]:
    root = Path(dist_dir).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError("dist directory not found: {0}".format(root))
    if not root.is_dir():
        raise NotADirectoryError("dist path is not a directory: {0}".format(root))

    allowed_py_set = _normalize_allow_py(allowed_py)
    tokens = tuple(DEFAULT_FORBIDDEN_TOKENS) + tuple(str(item) for item in (forbidden_tokens or ()))
    issues: List[DistLeakIssue] = []

    for path in sorted(root.rglob("*")):
        rel = _relpath(path, root)
        if path.is_dir():
            if path.name in FORBIDDEN_DIR_NAMES or path.name.startswith(".tmp"):
                issues.append(DistLeakIssue("forbidden_temp_dir", rel, "temporary build/cache/test directory is not allowed in dist"))
            continue
        if not path.is_file():
            continue

        suffix = path.suffix.lower()
        if suffix == ".py":
            if path.name not in allowed_py_set and rel not in allowed_py_set:
                issues.append(DistLeakIssue("python_source_file", rel, "only __init__.py or explicit --allow-py entries are allowed"))
        elif suffix in FORBIDDEN_SUFFIXES:
            issues.append(DistLeakIssue("generated_source_file", rel, "{0} source artifacts are not allowed in dist".format(suffix)))
        elif suffix in FORBIDDEN_SECRET_SUFFIXES:
            issues.append(DistLeakIssue("secret_material_file", rel, "{0} secret/key artifacts are not allowed in dist".format(suffix)))

        issues.extend(_metadata_issues(path, root))

        data = _read_bytes(path, max(0, int(scan_bytes_limit)))
        hits = _token_hits(data, tokens)
        for token in hits:
            issues.append(DistLeakIssue("forbidden_token", rel, "forbidden token found: {0}".format(token)))

    if require_release_metadata:
        for filename in REQUIRED_RELEASE_METADATA_FILES:
            if not (root / filename).is_file():
                issues.append(DistLeakIssue("release_metadata_missing", filename, "required release metadata file is missing"))

    return issues


def build_report(dist_dir, issues: Sequence[DistLeakIssue]) -> Dict[str, object]:
    root = Path(dist_dir).expanduser().resolve()
    return {
        "schema": REPORT_SCHEMA,
        "dist_dir": str(root),
        "passed": not issues,
        "summary": {
            "total_issues": len(issues),
        },
        "issues": [issue.to_dict() for issue in issues],
    }


def run_dist_no_source_leak_check(
    dist_dir,
    *,
    allowed_py: Optional[Iterable[str]] = None,
    forbidden_tokens: Optional[Iterable[str]] = None,
    scan_bytes_limit: int = 2 * 1024 * 1024,
    require_release_metadata: bool = False,
) -> Dict[str, object]:
    issues = check_dist_no_source_leak(
        dist_dir,
        allowed_py=allowed_py,
        forbidden_tokens=forbidden_tokens,
        scan_bytes_limit=scan_bytes_limit,
        require_release_metadata=require_release_metadata,
    )
    return build_report(dist_dir, issues)


def write_report(path, report: Dict[str, object]) -> Path:
    report_path = Path(path).expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report_path
