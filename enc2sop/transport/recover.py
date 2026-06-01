"""Transport recover/verify/analyze orchestration extracted from qrcode_helper."""

import json
import random
import tempfile
import zipfile
import zlib
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import cli
from . import parser
from . import protocol

CORRECTION_REPLAY_REPORT_SCHEMA = "enc2sop-transport-ocr-correction-replay/v1"
CORRECTION_REPLAY_VERIFICATION_SCHEMA = (
    "enc2sop-transport-ocr-correction-replay-verification/v1"
)
OCR_SAFE_CONFUSION_REPORT_SCHEMA = "enc2sop-transport-ocr-safe-confusion-report/v1"
OCR_SAFE_CONFUSION_VERIFICATION_SCHEMA = (
    "enc2sop-transport-ocr-safe-confusion-report-verification/v1"
)
OCR_SAFE_EVIDENCE_ARCHIVE_SCHEMA = "enc2sop-transport-ocr-safe-evidence-archive/v1"
OCR_SAFE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA = (
    "enc2sop-transport-ocr-safe-evidence-archive-verification/v1"
)
OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST = "ocr_safe_evidence_archive_manifest.json"
OCR_SAFE_SYNTHETIC_CONFUSION_SUITE = "ocr-safe-human-correctable-v1-synthetic-confusions"
OCR_SAFE_EVIDENCE_ARCHIVE_BOUNDARY = (
    "This archive packages replayable OCR-safe synthetic confusion and/or "
    "correction replay evidence only. It does not certify real camera/photo, "
    "physical print-scan, or backend-specific OCR transfer."
)
OCR_SAFE_EVIDENCE_ARCHIVE_FIXED_ROLE_PATHS = {
    "ocr_safe_confusion_report_rewritten": "synthetic_ocr_confusion_report.json",
    "correction_replay_report_rewritten": "transport_ocr_correction_replay_report.json",
    "ocr_safe_confusion_source_verification_report": (
        "synthetic_ocr_confusion_source_verification.json"
    ),
    "correction_replay_source_verification_report": (
        "transport_ocr_correction_replay_source_verification.json"
    ),
}
OCR_SAFE_EVIDENCE_ARCHIVE_PREFIX_ROLES = {
    "payload",
    "manifest",
    "encoded_payload",
    "source_page_text",
    "confusion_ocr_input",
    "confusion_analyze_report",
    "confusion_recovered_output",
    "correction_ocr_input",
    "corrections_file",
    "correction_recovered_output",
    "refreshed_corrections_template",
    "ocr_safe_confusion_source_report",
    "correction_replay_source_report",
}
OCR_SAFE_EVIDENCE_ARCHIVE_FILE_ROLES = (
    set(OCR_SAFE_EVIDENCE_ARCHIVE_FIXED_ROLE_PATHS)
    | OCR_SAFE_EVIDENCE_ARCHIVE_PREFIX_ROLES
)


def _sha256_file(path: Path) -> Optional[str]:
    try:
        if not path.exists() or not path.is_file():
            return None
        return protocol.sha256_hex(path.read_bytes())
    except Exception:
        return None


def _correction_file_digest(corrections_file: str) -> Dict[str, object]:
    try:
        correction_bytes = Path(corrections_file).read_bytes()
    except Exception:
        return {"sha256": None, "size": None}
    return {
        "sha256": protocol.sha256_hex(correction_bytes),
        "size": len(correction_bytes),
    }


def _load_json_file(path: Path) -> Dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("expected JSON object in {}".format(path))
    return data


def _is_canonical_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if text != value or not text.endswith("Z"):
        return False
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == text


def _resolve_evidence_path(report_base: Path, raw_path: object) -> Optional[Path]:
    text = str(raw_path or "").strip()
    if not text:
        return None
    candidate = Path(text)
    if candidate.is_absolute():
        return candidate.resolve()
    parts = candidate.parts
    if parts and parts[0] == report_base.name:
        report_root_candidate = report_base.joinpath(*parts[1:]).resolve()
        if report_root_candidate.exists():
            return report_root_candidate
    report_relative_candidate = (report_base / candidate).resolve()
    if report_relative_candidate.exists():
        return report_relative_candidate
    cwd_candidate = candidate.resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return report_relative_candidate


def _json_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _is_non_negative_int(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _require_json_bool(value: object, field: str, context: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError("{} {} must be a JSON boolean".format(context, field))
    return value


def _require_json_non_negative_int(value: object, field: str, context: str) -> int:
    if not _is_non_negative_int(value):
        raise ValueError(
            "{} {} must be a non-negative JSON integer".format(context, field)
        )
    return int(value)


def _canonical_sha256_text(value: object) -> Optional[str]:
    text = str(value or "").strip()
    if len(text) != 64:
        return None
    if any(ch not in "0123456789abcdef" for ch in text):
        return None
    return text


def _portable_basename(value: object) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    return text.rsplit("/", 1)[-1]


def _normalize_optional_path(value: object) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def _is_safe_archive_member(name: object) -> bool:
    text = str(name or "").strip().replace("\\", "/")
    if not text or text.endswith("/"):
        return False
    if text.startswith("/") or text.startswith("../") or "/../" in text:
        return False
    path = Path(text)
    if path.is_absolute():
        return False
    parts = [part for part in text.split("/") if part]
    if not parts or any(part in (".", "..") for part in parts):
        return False
    return text == "/".join(parts)


def _archive_file_role_path_status(role: object, archive_path: object) -> Tuple[bool, str]:
    role_text = str(role or "").strip()
    path_text = str(archive_path or "").strip().replace("\\", "/")
    if not role_text:
        return False, "archive_file_record_role_missing_or_invalid"
    if role_text not in OCR_SAFE_EVIDENCE_ARCHIVE_FILE_ROLES:
        return False, "archive_file_record_role_unknown"
    fixed_path = OCR_SAFE_EVIDENCE_ARCHIVE_FIXED_ROLE_PATHS.get(role_text)
    if fixed_path is not None:
        if path_text != fixed_path:
            return False, "archive_file_record_role_path_mismatch"
        return True, ""
    if path_text.startswith("{}/".format(role_text)):
        return True, ""
    return False, "archive_file_record_role_path_mismatch"


def _safe_archive_member_for_path(path: Path, role: str, used: set) -> str:
    safe_name = "".join(
        ch if ch.isalnum() or ch in ("-", "_", ".") else "_"
        for ch in path.name
    ).strip("._")
    if not safe_name:
        safe_name = "artifact"
    role_dir = "".join(
        ch if ch.isalnum() or ch in ("-", "_") else "_"
        for ch in str(role or "artifact")
    ).strip("_") or "artifact"
    candidate = "{}/{}".format(role_dir, safe_name)
    index = 1
    while candidate in used or candidate == OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST:
        stem = Path(safe_name).stem or "artifact"
        suffix = Path(safe_name).suffix
        candidate = "{}/{}_{:03d}{}".format(role_dir, stem, index, suffix)
        index += 1
    used.add(candidate)
    return candidate


def _archive_digest_record(path: Path, role: str, used: set) -> Dict[str, object]:
    payload = path.read_bytes()
    return {
        "role": role,
        "source_path": str(path),
        "archive_path": _safe_archive_member_for_path(path, role, used),
        "sha256": protocol.sha256_hex(payload),
        "size_bytes": len(payload),
    }


def _collect_report_evidence_files(
    report: Dict[str, object],
    report_path: Path,
    role: str,
    files: List[Dict[str, object]],
    used_sources: set,
    used_archive_paths: set,
) -> None:
    def _add(raw_path: object, file_role: str) -> None:
        path = _resolve_evidence_path(report_path.parent, raw_path)
        if path is None or not path.exists() or not path.is_file():
            return
        resolved = path.resolve()
        if resolved in used_sources:
            return
        used_sources.add(resolved)
        files.append(_archive_digest_record(resolved, file_role, used_archive_paths))

    if role == "ocr_safe_confusion_report":
        for field, file_role in [
            ("payload_file", "payload"),
            ("manifest_path", "manifest"),
            ("export_payload_path", "encoded_payload"),
        ]:
            _add(report.get(field), file_role)
        for record in report.get("source_page_texts", []) or []:
            if isinstance(record, dict):
                _add(record.get("path"), "source_page_text")
        for case in report.get("cases", []) or []:
            if not isinstance(case, dict):
                continue
            _add(case.get("ocr_input_path"), "confusion_ocr_input")
            _add(case.get("analyze_report_path"), "confusion_analyze_report")
            _add(case.get("recovered_output_path"), "confusion_recovered_output")
        return

    if role == "correction_replay_report":
        for field, file_role in [
            ("manifest_path", "manifest"),
            ("ocr_input_path", "correction_ocr_input"),
            ("corrections_file", "corrections_file"),
            ("output_file", "correction_recovered_output"),
            (
                "refreshed_corrections_template_path",
                "refreshed_corrections_template",
            ),
        ]:
            _add(report.get(field), file_role)


def _rewrite_report_paths_for_archive(
    report: Dict[str, object],
    file_by_source: Dict[str, Dict[str, object]],
) -> Dict[str, object]:
    rewritten = json.loads(json.dumps(report))

    def _rewrite_value(value: object) -> object:
        text = str(value or "").strip()
        if not text:
            return value
        path = Path(text)
        try:
            resolved = str(path.resolve())
        except Exception:
            return value
        record = file_by_source.get(resolved)
        if record is None:
            return value
        return str(record["archive_path"])

    for field in [
        "output_dir",
        "report_file",
        "report_path",
        "payload_file",
        "manifest_path",
        "export_payload_path",
        "requested_output_file",
        "output_file",
        "ocr_input_path",
        "corrections_file",
        "refreshed_corrections_template_path",
    ]:
        if field in rewritten:
            rewritten[field] = _rewrite_value(rewritten.get(field))

    for record in rewritten.get("source_page_texts", []) or []:
        if isinstance(record, dict) and "path" in record:
            record["path"] = _rewrite_value(record.get("path"))
    for case in rewritten.get("cases", []) or []:
        if not isinstance(case, dict):
            continue
        for field in [
            "ocr_input_path",
            "analyze_report_path",
            "recovered_output_path",
        ]:
            if field in case:
                case[field] = _rewrite_value(case.get(field))
    return rewritten


def _expected_rewritten_report_role(report_role: str) -> Optional[str]:
    if report_role == "ocr_safe_confusion_report":
        return "ocr_safe_confusion_report_rewritten"
    if report_role == "correction_replay_report":
        return "correction_replay_report_rewritten"
    return None


def _source_verification_archive_role(report_role: str) -> Optional[str]:
    if report_role == "ocr_safe_confusion_report":
        return "ocr_safe_confusion_source_verification_report"
    if report_role == "correction_replay_report":
        return "correction_replay_source_verification_report"
    return None


def _source_report_archive_role(report_role: str) -> Optional[str]:
    if report_role == "ocr_safe_confusion_report":
        return "ocr_safe_confusion_source_report"
    if report_role == "correction_replay_report":
        return "correction_replay_source_report"
    return None


def _rewrite_source_verification_for_archive(
    verification: Dict[str, object],
    source_report_record: Optional[Dict[str, object]],
) -> Dict[str, object]:
    rewritten = json.loads(json.dumps(verification))
    if source_report_record is not None:
        rewritten["report_file"] = str(source_report_record.get("archive_path") or "")
    return rewritten


def _archive_member_reference(value: object) -> Optional[str]:
    text = str(value or "").strip().replace("\\", "/")
    if not _is_safe_archive_member(text):
        return None
    return text


def _verify_archived_report_path_bindings(
    *,
    role: str,
    archived_report: Dict[str, object],
    archive_payloads: Dict[str, bytes],
    failure_callback,
) -> Tuple[bool, int]:
    ok = True
    checked_count = 0

    def _check(
        field: str,
        value: object,
        *,
        required: bool = True,
        index: Optional[int] = None,
        case: Optional[str] = None,
    ) -> None:
        nonlocal ok, checked_count
        raw_text = str(value or "").strip()
        if not raw_text:
            if required:
                ok = False
                failure_callback(
                    "archived_report_path_missing",
                    role=role,
                    field=field,
                    index=index,
                    case=case,
                )
            return
        checked_count += 1
        archive_member = _archive_member_reference(value)
        if archive_member is None:
            ok = False
            failure_callback(
                "archived_report_path_not_archive_relative",
                role=role,
                field=field,
                path=raw_text,
                index=index,
                case=case,
            )
            return
        if archive_member not in archive_payloads:
            ok = False
            failure_callback(
                "archived_report_path_member_missing",
                role=role,
                field=field,
                archive_path=archive_member,
                index=index,
                case=case,
            )

    if role == "ocr_safe_confusion_report":
        for field in ["payload_file", "manifest_path"]:
            _check(field, archived_report.get(field), required=True)
        _check(
            "export_payload_path",
            archived_report.get("export_payload_path"),
            required=False,
        )
        source_page_texts = archived_report.get("source_page_texts")
        if isinstance(source_page_texts, list):
            for index, record in enumerate(source_page_texts):
                if isinstance(record, dict):
                    _check(
                        "source_page_texts[].path",
                        record.get("path"),
                        required=True,
                        index=index,
                    )
        cases = archived_report.get("cases")
        if isinstance(cases, list):
            for index, case_record in enumerate(cases):
                if not isinstance(case_record, dict):
                    continue
                case_name = str(case_record.get("name") or "")
                for field in ["ocr_input_path", "analyze_report_path"]:
                    _check(
                        "cases[].{}".format(field),
                        case_record.get(field),
                        required=True,
                        index=index,
                        case=case_name or None,
                    )
                _check(
                    "cases[].recovered_output_path",
                    case_record.get("recovered_output_path"),
                    required=bool(case_record.get("success")),
                    index=index,
                    case=case_name or None,
                )
        return ok, checked_count

    if role == "correction_replay_report":
        for field in ["manifest_path", "ocr_input_path", "corrections_file"]:
            _check(field, archived_report.get(field), required=True)
        for field in [
            "output_file",
            "refreshed_corrections_template_path",
        ]:
            _check(field, archived_report.get(field), required=False)
        requested_output = archived_report.get("requested_output_file")
        if requested_output and archived_report.get("output_file"):
            _check("requested_output_file", requested_output, required=False)
        return ok, checked_count

    return False, checked_count


def _zip_info_is_symlink(info: zipfile.ZipInfo) -> bool:
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def _ocr_safe_confusion_case_definitions() -> List[Dict[str, object]]:
    return [
        {"name": "six-as-upper-g", "family": "6/G/g", "kind": "replace", "target": "6", "replacement": "G"},
        {"name": "six-as-lower-g", "family": "6/G/g", "kind": "replace", "target": "6", "replacement": "g"},
        {"name": "nine-as-lower-g", "family": "9/g/q", "kind": "replace", "target": "9", "replacement": "g"},
        {"name": "nine-as-lower-q", "family": "9/g/q", "kind": "replace", "target": "9", "replacement": "q"},
        {"name": "two-as-upper-z", "family": "2/7/Z/z", "kind": "replace", "target": "2", "replacement": "Z"},
        {"name": "seven-as-upper-z", "family": "2/7/Z/z", "kind": "replace", "target": "7", "replacement": "Z"},
        {"name": "seven-as-lower-z", "family": "2/7/Z/z", "kind": "replace", "target": "7", "replacement": "z"},
        {"name": "o-as-zero", "family": "O/0/o/Q/D", "kind": "replace", "target": "O", "replacement": "0"},
        {"name": "o-as-lower-o", "family": "O/0/o/Q/D", "kind": "replace", "target": "O", "replacement": "o"},
        {"name": "o-as-upper-q", "family": "O/0/o/Q/D", "kind": "replace", "target": "O", "replacement": "Q"},
        {"name": "o-as-upper-d", "family": "O/0/o/Q/D", "kind": "replace", "target": "O", "replacement": "D"},
        {"name": "one-as-upper-i", "family": "1/I/i/l/L", "kind": "replace", "target": "1", "replacement": "I"},
        {"name": "one-as-lower-i", "family": "1/I/i/l/L", "kind": "replace", "target": "1", "replacement": "i"},
        {"name": "one-as-lower-l", "family": "1/I/i/l/L", "kind": "replace", "target": "1", "replacement": "l"},
        {"name": "one-as-upper-l", "family": "1/I/i/l/L", "kind": "replace", "target": "1", "replacement": "L"},
        {"name": "one-as-pipe", "family": "1/I/i/l/L", "kind": "replace", "target": "1", "replacement": "|"},
        {"name": "one-as-bang", "family": "1/I/i/l/L", "kind": "replace", "target": "1", "replacement": "!"},
        {"name": "five-as-upper-s", "family": "5/S/s", "kind": "replace", "target": "5", "replacement": "S"},
        {"name": "five-as-lower-s", "family": "5/S/s", "kind": "replace", "target": "5", "replacement": "s"},
        {"name": "eight-as-upper-b", "family": "8/B/b", "kind": "replace", "target": "8", "replacement": "B"},
        {"name": "eight-as-lower-b", "family": "8/B/b", "kind": "replace", "target": "8", "replacement": "b"},
        {"name": "whitespace-insertion", "family": "whitespace-insertion", "kind": "insert", "insert": " "},
        {"name": "dash-noise-insertion", "family": "dash-noise-insertion", "kind": "insert", "insert": "-"},
        {"name": "line-break-drift", "family": "line-break-drift", "kind": "line_break"},
    ]


def _ocr_safe_required_case_records() -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    for case in _ocr_safe_confusion_case_definitions():
        record: Dict[str, object] = {
            "name": str(case.get("name") or ""),
            "family": str(case.get("family") or ""),
            "kind": str(case.get("kind") or ""),
        }
        for field in ["target", "replacement", "insert"]:
            if case.get(field):
                record[field] = str(case.get(field) or "")
        records.append(record)
    return records


def _ocr_safe_required_symbol_counts() -> Dict[str, int]:
    required: Dict[str, int] = {}
    for case in _ocr_safe_confusion_case_definitions():
        target = str(case.get("target") or "")
        if target:
            required[target] = max(required.get(target, 0), 1)
    return required


def _deterministic_ocr_safe_payload(payload_size: int, seed: int) -> Tuple[bytes, str, int]:
    rng = random.Random(int(seed))
    payload_size = max(1, int(payload_size))
    required = _ocr_safe_required_symbol_counts()
    for attempt in range(5000):
        raw = bytes(rng.randrange(0, 256) for _ in range(payload_size))
        encoded = protocol.encode_payload_for_profile(
            zlib.compress(raw, 9),
            protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
        )
        if all(encoded.count(ch) >= count for ch, count in required.items()):
            return raw, encoded, attempt
    raise ValueError(
        "could not generate deterministic OCR-safe payload containing required symbols"
    )


def _read_exported_page_lines(export: Dict[str, object]) -> List[str]:
    lines: List[str] = []
    for raw_path in sorted(str(path) for path in export.get("page_texts", []) or []):
        lines.extend(Path(raw_path).read_text(encoding="ascii").splitlines())
    return lines


def _exported_page_text_records(export: Dict[str, object]) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    for raw_path in sorted(str(path) for path in export.get("page_texts", []) or []):
        path = Path(raw_path)
        data = path.read_bytes()
        text = data.decode("ascii")
        records.append(
            {
                "path": str(path),
                "sha256": protocol.sha256_hex(data),
                "size": len(data),
                "line_count": len(text.splitlines()),
            }
        )
    return records


def _split_full_transport_line(line: str) -> Optional[Tuple[str, str, str]]:
    if not (line.startswith("P") and "|C" in line and line.count("|") >= 3):
        return None
    try:
        prefix, payload_text, crc = line.rsplit("|", 2)
    except ValueError:
        return None
    if not payload_text:
        return None
    return prefix, payload_text, crc


def _parse_line_location(prefix: str) -> Dict[str, Optional[int]]:
    page_no: Optional[int] = None
    line_no: Optional[int] = None
    try:
        if prefix.startswith("P") and "L" in prefix:
            left = prefix.split("|", 1)[0]
            page_no = int(left[1:4])
            line_no = int(left.split("L", 1)[1][:3])
    except Exception:
        page_no = None
        line_no = None
    return {"page": page_no, "line": line_no}


def _mutate_ocr_confusion_lines(
    base_lines: List[str],
    case: Dict[str, object],
) -> Tuple[List[str], Dict[str, object]]:
    kind = str(case.get("kind") or "")
    target = str(case.get("target") or "")
    replacement = str(case.get("replacement") or "")
    insert_value = str(case.get("insert") or "")
    mutated: List[str] = []
    applied = False
    evidence: Dict[str, object] = {
        "kind": kind,
        "target": target or None,
        "replacement": replacement or None,
        "insert": insert_value or None,
    }

    for source_line_no, line in enumerate(base_lines, 1):
        if applied:
            mutated.append(line)
            continue
        parts = _split_full_transport_line(line)
        if parts is None:
            mutated.append(line)
            continue
        prefix, payload_text, crc = parts
        if kind == "replace":
            if target not in payload_text:
                mutated.append(line)
                continue
            index = payload_text.index(target)
            changed_payload = payload_text[:index] + replacement + payload_text[index + 1 :]
            changed_line = "{}|{}|{}".format(prefix, changed_payload, crc)
            mutated.append(changed_line)
            evidence.update(
                {
                    "source_line_no": source_line_no,
                    "payload_offset": index,
                    "original_line_sha256": protocol.sha256_hex(line.encode("utf-8")),
                    "mutated_line_sha256": protocol.sha256_hex(
                        changed_line.encode("utf-8")
                    ),
                }
            )
            evidence.update(_parse_line_location(prefix))
            applied = True
            continue

        if kind == "insert":
            if len(payload_text) < 4:
                mutated.append(line)
                continue
            index = max(1, min(len(payload_text) - 1, len(payload_text) // 2))
            changed_payload = payload_text[:index] + insert_value + payload_text[index:]
            changed_line = "{}|{}|{}".format(prefix, changed_payload, crc)
            mutated.append(changed_line)
            evidence.update(
                {
                    "source_line_no": source_line_no,
                    "payload_offset": index,
                    "original_line_sha256": protocol.sha256_hex(line.encode("utf-8")),
                    "mutated_line_sha256": protocol.sha256_hex(
                        changed_line.encode("utf-8")
                    ),
                }
            )
            evidence.update(_parse_line_location(prefix))
            applied = True
            continue

        if kind == "line_break":
            if len(payload_text) < 8:
                mutated.append(line)
                continue
            split_at = max(2, min(len(payload_text) - 2, len(payload_text) // 2))
            first_line = "{}|{}".format(prefix, payload_text[:split_at])
            second_line = "{}|{}".format(payload_text[split_at:], crc)
            mutated.append(first_line)
            mutated.append(second_line)
            evidence.update(
                {
                    "source_line_no": source_line_no,
                    "payload_offset": split_at,
                    "original_line_sha256": protocol.sha256_hex(line.encode("utf-8")),
                    "mutated_line_sha256": protocol.sha256_hex(
                        (first_line + "\n" + second_line).encode("utf-8")
                    ),
                    "line_break_count": 1,
                }
            )
            evidence.update(_parse_line_location(prefix))
            applied = True
            continue

        mutated.append(line)

    if not applied:
        raise ValueError("could not apply OCR confusion case: {}".format(case.get("name")))
    return mutated, evidence


def _verify_ocr_confusion_mutation_replay(
    *,
    report_base: Path,
    report: Dict[str, object],
    case: Dict[str, object],
    base_lines: List[str],
) -> Tuple[bool, Optional[Dict[str, object]]]:
    case_name = str(case.get("name") or "")
    case_definition = None
    for candidate in _ocr_safe_confusion_case_definitions():
        if str(candidate.get("name") or "") == case_name:
            case_definition = candidate
            break
    if case_definition is None:
        return False, {"reason": "case_definition_missing", "case": case_name}

    try:
        replayed_lines, replayed_mutation = _mutate_ocr_confusion_lines(
            base_lines,
            case_definition,
        )
    except Exception as exc:
        return False, {
            "reason": "case_mutation_replay_failed",
            "case": case_name,
            "message": str(exc),
        }

    mutation = case.get("mutation")
    if not isinstance(mutation, dict):
        mutation = {}
    for field in [
        "kind",
        "target",
        "replacement",
        "insert",
        "source_line_no",
        "payload_offset",
        "original_line_sha256",
        "mutated_line_sha256",
        "line_break_count",
        "page",
        "line",
    ]:
        if field in replayed_mutation and mutation.get(field) != replayed_mutation.get(field):
            return False, {
                "reason": "case_mutation_field_mismatch",
                "case": case_name,
                "field": field,
                "expected": mutation.get(field),
                "actual": replayed_mutation.get(field),
            }

    expected_text = "\n".join(replayed_lines) + "\n"
    expected_sha256 = protocol.sha256_hex(expected_text.encode("utf-8"))
    if case.get("ocr_input_sha256") and case.get("ocr_input_sha256") != expected_sha256:
        return False, {
            "reason": "case_mutation_ocr_sha256_mismatch",
            "case": case_name,
            "expected": case.get("ocr_input_sha256"),
            "actual": expected_sha256,
        }

    ocr_input_path = _resolve_evidence_path(report_base, case.get("ocr_input_path"))
    if ocr_input_path is None or not ocr_input_path.exists() or not ocr_input_path.is_file():
        return False, {
            "reason": "case_mutation_ocr_input_missing",
            "case": case_name,
            "path": str(ocr_input_path) if ocr_input_path else None,
        }
    actual_text = ocr_input_path.read_text(encoding="utf-8")
    if actual_text != expected_text:
        return False, {
            "reason": "case_mutation_ocr_input_mismatch",
            "case": case_name,
            "expected_sha256": expected_sha256,
            "actual_sha256": protocol.sha256_hex(actual_text.encode("utf-8")),
        }

    return True, None


def certify_ocr_safe_confusions(
    transport,
    output_dir: str,
    report_file: Optional[str] = None,
    payload_size: int = 512,
    seed: int = 20260530,
    redundancy_copies: int = 2,
    parity_group_size: int = 4,
    filename_prefix: str = "ocr_confusion_page",
) -> Dict[str, object]:
    if str(transport.payload_alphabet_profile or "").strip().lower() != (
        protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE
    ):
        raise ValueError(
            "certify-ocr-confusion requires payload_alphabet_profile={}".format(
                protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE
            )
        )
    if str(getattr(transport, "line_crc_mode", "on")).strip().lower() != "on":
        raise ValueError("certify-ocr-confusion requires line_crc_mode=on")
    if str(getattr(transport, "line_index_mode", "full")).strip().lower() != "full":
        raise ValueError("certify-ocr-confusion requires line_index_mode=full")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if report_file is None:
        report_file = str(out_dir / "synthetic_ocr_confusion_report.json")
    cases_dir = out_dir / "synthetic_ocr_cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    raw_payload, encoded_payload, payload_attempt = _deterministic_ocr_safe_payload(
        payload_size=payload_size,
        seed=seed,
    )
    payload_path = out_dir / "synthetic_payload.bin"
    payload_path.write_bytes(raw_payload)
    export = transport.export_artifact(
        input_file=str(payload_path),
        output_dir=str(out_dir / "package"),
        filename_prefix=filename_prefix,
        redundancy_copies=redundancy_copies,
        parity_group_size=parity_group_size,
    )
    manifest_path = str(export["manifest_path"])
    manifest = transport._load_manifest(manifest_path)
    source_page_texts = _exported_page_text_records(export)
    base_lines = _read_exported_page_lines(export)
    expected_raw_sha256 = protocol.sha256_hex(raw_payload)

    case_results: List[Dict[str, object]] = []
    for case in _ocr_safe_confusion_case_definitions():
        case_name = str(case["name"])
        case_dir = cases_dir / case_name
        case_dir.mkdir(parents=True, exist_ok=True)
        ocr_input_path = case_dir / "ocr_text.txt"
        analyze_report_path = case_dir / "analyze_report.json"
        recovered_path = case_dir / "recovered_payload.bin"
        case_result: Dict[str, object] = {
            "name": case_name,
            "family": str(case.get("family") or ""),
            "success": False,
            "mutation": {},
            "ocr_input_path": str(ocr_input_path),
            "ocr_input_sha256": None,
            "ocr_input_size": None,
            "analyze_report_path": str(analyze_report_path),
            "analyze_report_sha256": None,
            "analyze_report_size": None,
            "recovered_output_path": str(recovered_path),
            "recovered_output_sha256": None,
            "recovered_output_size": None,
            "analyze_success": False,
            "recover_success": False,
            "final_payload_sha256_verified": False,
            "correction_required_count": None,
            "line_error_count": None,
            "line_warning_count": None,
            "warning_reasons": [],
            "error": None,
        }
        try:
            mutated_lines, mutation = _mutate_ocr_confusion_lines(base_lines, case)
            case_result["mutation"] = mutation
            ocr_input_path.write_bytes(("\n".join(mutated_lines) + "\n").encode("utf-8"))
            analyze = transport.analyze_ocr_text(
                manifest_path=manifest_path,
                ocr_input_path=str(ocr_input_path),
                strict_payload_chars=True,
                save_report_path=str(analyze_report_path),
            )
            case_result["analyze_success"] = bool(analyze.get("success"))
            case_result["correction_required_count"] = int(
                analyze.get("correction_required_count") or 0
            )
            case_result["line_error_count"] = int(analyze.get("line_error_count") or 0)
            case_result["line_warning_count"] = int(analyze.get("line_warning_count") or 0)
            warnings = analyze.get("line_warnings_sample", [])
            if not isinstance(warnings, list):
                warnings = []
            case_result["warning_reasons"] = sorted(
                {
                    str(item.get("reason") or "")
                    for item in warnings
                    if isinstance(item, dict) and item.get("reason")
                }
            )
            if analyze.get("success") and int(analyze.get("correction_required_count") or 0) == 0:
                recovered = transport.recover_artifact(
                    manifest_path=manifest_path,
                    ocr_input_path=str(ocr_input_path),
                    output_file=str(recovered_path),
                    strict_payload_chars=True,
                )
                case_result["recover_success"] = bool(recovered.get("success"))
                actual_raw_sha256 = str(recovered.get("raw_sha256") or "")
                case_result["actual_raw_sha256"] = actual_raw_sha256
                case_result["final_payload_sha256_verified"] = (
                    actual_raw_sha256 == expected_raw_sha256
                    and recovered_path.exists()
                    and recovered_path.read_bytes() == raw_payload
                )
            case_result["success"] = (
                bool(case_result["analyze_success"])
                and bool(case_result["recover_success"])
                and bool(case_result["final_payload_sha256_verified"])
                and int(case_result["correction_required_count"] or 0) == 0
                and int(case_result["line_error_count"] or 0) == 0
            )
        except Exception as exc:
            case_result["error"] = str(exc)
        for field_prefix, path in [
            ("ocr_input", ocr_input_path),
            ("analyze_report", analyze_report_path),
            ("recovered_output", recovered_path),
        ]:
            if path.exists() and path.is_file():
                data = path.read_bytes()
                case_result["{}_sha256".format(field_prefix)] = protocol.sha256_hex(
                    data
                )
                case_result["{}_size".format(field_prefix)] = len(data)
        case_results.append(case_result)

    required_families = sorted(
        {str(case["family"]) for case in _ocr_safe_confusion_case_definitions()}
    )
    required_cases = _ocr_safe_required_case_records()
    covered_families = {}
    for family in required_families:
        family_cases = [item for item in case_results if item.get("family") == family]
        covered_families[family] = bool(family_cases) and all(
            bool(item.get("success")) for item in family_cases
        )
    missing_families = [
        family for family, covered in covered_families.items() if not covered
    ]
    passed_count = len([item for item in case_results if item.get("success")])

    result: Dict[str, object] = {
        "schema": OCR_SAFE_CONFUSION_REPORT_SCHEMA,
        "success": passed_count == len(case_results) and not missing_families,
        "suite": OCR_SAFE_SYNTHETIC_CONFUSION_SUITE,
        "generated_at_utc": protocol.utc_now_iso(),
        "payload_alphabet_profile": protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
        "alphabet": protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET,
        "output_dir": str(out_dir),
        "report_file": str(report_file),
        "seed": int(seed),
        "payload_size": len(raw_payload),
        "payload_generation_attempt": int(payload_attempt),
        "payload_file": str(payload_path),
        "payload_file_size": len(raw_payload),
        "payload_file_sha256": expected_raw_sha256,
        "payload_sha256": expected_raw_sha256,
        "encoded_payload_length": len(encoded_payload),
        "manifest_path": manifest_path,
        "manifest_sha256": _sha256_file(Path(manifest_path)),
        "export_payload_path": str(export.get("payload_path") or ""),
        "export_payload_sha256": _sha256_file(Path(str(export.get("payload_path") or ""))),
        "export_page_text_count": int(export.get("page_text_count") or 0),
        "export_image_count": int(export.get("image_count") or 0),
        "source_page_text_count": len(source_page_texts),
        "source_page_texts": source_page_texts,
        "artifact_id": manifest["artifact_id"],
        "compressed_sha256": manifest["compressed_sha256"],
        "total_chunks": int(manifest["total_chunks"]),
        "line_crc_mode": manifest.get("line_crc_mode"),
        "line_index_mode": manifest.get("line_index_mode"),
        "redundancy_copies": int(manifest.get("redundancy_copies") or 0),
        "parity": manifest.get("parity"),
        "required_confusion_families": required_families,
        "required_confusion_cases": required_cases,
        "covered_confusion_families": covered_families,
        "missing_confusion_families": missing_families,
        "case_count": len(case_results),
        "passed_count": passed_count,
        "failed_count": len(case_results) - passed_count,
        "cases": case_results,
        "certification_boundary": (
            "This report proves deterministic synthetic OCR text-confusion recovery for "
            "ocr-safe-human-correctable-v1 only. It does not certify real camera/photo, "
            "physical print-scan, or backend-specific OCR transfer; those require measured "
            "capture/backend evidence and claim-gated transport reports."
        ),
    }
    result["report_path"] = cli.save_json(str(report_file), result)
    return result


def verify_ocr_safe_confusion_report(
    report_file: str,
    output_file: Optional[str] = None,
    require_success: bool = True,
) -> Dict[str, object]:
    report_path = Path(report_file).resolve()
    report_base = report_path.parent
    failures: List[Dict[str, object]] = []

    def _failure(reason: str, **details: object) -> None:
        event = {"reason": reason}
        event.update(details)
        failures.append(event)

    try:
        report = _load_json_file(report_path)
    except Exception as exc:
        report = {}
        _failure("report_json_invalid", message=str(exc))

    if report.get("schema") != OCR_SAFE_CONFUSION_REPORT_SCHEMA:
        _failure(
            "report_schema_mismatch",
            expected=OCR_SAFE_CONFUSION_REPORT_SCHEMA,
            actual=report.get("schema"),
        )
    if report.get("suite") != OCR_SAFE_SYNTHETIC_CONFUSION_SUITE:
        _failure(
            "report_suite_mismatch",
            expected=OCR_SAFE_SYNTHETIC_CONFUSION_SUITE,
            actual=report.get("suite"),
        )
    if report.get("payload_alphabet_profile") != protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        _failure(
            "payload_alphabet_profile_mismatch",
            expected=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            actual=report.get("payload_alphabet_profile"),
        )
    if report.get("alphabet") != protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET:
        _failure(
            "alphabet_mismatch",
            expected=protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET,
            actual=report.get("alphabet"),
        )
    if require_success and not bool(report.get("success")):
        _failure("report_success_required")

    required_families = sorted(
        {str(case["family"]) for case in _ocr_safe_confusion_case_definitions()}
    )
    report_required_families = sorted(
        str(item) for item in report.get("required_confusion_families", []) or []
    )
    missing_report_families = [
        family for family in required_families if family not in report_required_families
    ]
    if missing_report_families:
        _failure(
            "required_confusion_families_missing",
            families=missing_report_families,
        )

    required_cases = _ocr_safe_required_case_records()
    required_case_by_name = {
        str(case["name"]): case for case in required_cases
    }
    report_required_cases = report.get("required_confusion_cases")
    if not isinstance(report_required_cases, list):
        report_required_cases = []
        _failure("required_confusion_cases_missing")
    report_required_case_by_name: Dict[str, Dict[str, object]] = {}
    for index, case in enumerate(report_required_cases):
        if not isinstance(case, dict):
            _failure("required_confusion_case_invalid", index=index)
            continue
        name = str(case.get("name") or "")
        if not name:
            _failure("required_confusion_case_name_missing", index=index)
            continue
        if name in report_required_case_by_name:
            _failure("required_confusion_case_duplicate", case=name)
        report_required_case_by_name[name] = case
    for name, expected_case in required_case_by_name.items():
        actual_case = report_required_case_by_name.get(name)
        if actual_case is None:
            _failure("required_confusion_case_missing", case=name)
            continue
        for field, expected_value in expected_case.items():
            if actual_case.get(field) != expected_value:
                _failure(
                    "required_confusion_case_field_mismatch",
                    case=name,
                    field=field,
                    expected=expected_value,
                    actual=actual_case.get(field),
                )
    for name in report_required_case_by_name:
        if name not in required_case_by_name:
            _failure("required_confusion_case_unknown", case=name)

    payload_path = _resolve_evidence_path(report_base, report.get("payload_file"))
    if payload_path is None:
        output_dir = _resolve_evidence_path(report_base, report.get("output_dir"))
        if output_dir is not None:
            payload_path = (output_dir / "synthetic_payload.bin").resolve()
    payload_verified = False
    if payload_path is None or not payload_path.exists() or not payload_path.is_file():
        _failure("payload_file_missing", path=str(payload_path) if payload_path else None)
    else:
        payload_bytes = payload_path.read_bytes()
        payload_sha256 = protocol.sha256_hex(payload_bytes)
        payload_verified = payload_sha256 == str(report.get("payload_sha256") or "")
        if not payload_verified:
            _failure(
                "payload_sha256_mismatch",
                expected=report.get("payload_sha256"),
                actual=payload_sha256,
            )
        if "payload_file_size" in report and len(payload_bytes) != _json_int(
            report.get("payload_file_size")
        ):
            _failure(
                "payload_file_size_mismatch",
                expected=report.get("payload_file_size"),
                actual=len(payload_bytes),
            )

    manifest_path = _resolve_evidence_path(report_base, report.get("manifest_path"))
    manifest_verified = False
    if manifest_path is None or not manifest_path.exists() or not manifest_path.is_file():
        _failure("manifest_missing", path=str(manifest_path) if manifest_path else None)
    else:
        manifest_sha256 = _sha256_file(manifest_path)
        manifest_verified = manifest_sha256 == str(report.get("manifest_sha256") or "")
        if not manifest_verified:
            _failure(
                "manifest_sha256_mismatch",
                expected=report.get("manifest_sha256"),
                actual=manifest_sha256,
            )
        try:
            manifest = _load_json_file(manifest_path)
            for field in [
                "artifact_id",
                "compressed_sha256",
                "total_chunks",
                "line_crc_mode",
                "line_index_mode",
                "redundancy_copies",
                "parity",
            ]:
                if manifest.get(field) != report.get(field):
                    _failure(
                        "manifest_field_mismatch",
                        field=field,
                        expected=report.get(field),
                        actual=manifest.get(field),
                    )
        except Exception as exc:
            _failure("manifest_json_invalid", message=str(exc))

    source_page_texts = report.get("source_page_texts")
    if not isinstance(source_page_texts, list):
        source_page_texts = []
        _failure("source_page_texts_missing")
    if _json_int(report.get("source_page_text_count"), -1) != len(source_page_texts):
        _failure(
            "source_page_text_count_mismatch",
            expected=report.get("source_page_text_count"),
            actual=len(source_page_texts),
        )
    source_lines: List[str] = []
    source_page_texts_verified = True
    for index, record in enumerate(source_page_texts):
        if not isinstance(record, dict):
            _failure("source_page_text_record_invalid", index=index)
            source_page_texts_verified = False
            continue
        source_path = _resolve_evidence_path(report_base, record.get("path"))
        if source_path is None or not source_path.exists() or not source_path.is_file():
            _failure(
                "source_page_text_missing",
                index=index,
                path=str(source_path) if source_path else None,
            )
            source_page_texts_verified = False
            continue
        data = source_path.read_bytes()
        actual_sha = protocol.sha256_hex(data)
        if record.get("sha256") != actual_sha:
            _failure(
                "source_page_text_sha256_mismatch",
                index=index,
                expected=record.get("sha256"),
                actual=actual_sha,
            )
            source_page_texts_verified = False
        if record.get("size") is not None and len(data) != _json_int(record.get("size")):
            _failure(
                "source_page_text_size_mismatch",
                index=index,
                expected=record.get("size"),
                actual=len(data),
            )
            source_page_texts_verified = False
        try:
            lines = data.decode("ascii").splitlines()
        except Exception as exc:
            _failure("source_page_text_decode_failed", index=index, message=str(exc))
            source_page_texts_verified = False
            continue
        if record.get("line_count") is not None and len(lines) != _json_int(
            record.get("line_count")
        ):
            _failure(
                "source_page_text_line_count_mismatch",
                index=index,
                expected=record.get("line_count"),
                actual=len(lines),
            )
            source_page_texts_verified = False
        source_lines.extend(lines)

    cases = report.get("cases", [])
    if not isinstance(cases, list):
        cases = []
        _failure("cases_not_list")
    case_names_seen: Dict[str, int] = {}
    case_by_name: Dict[str, Dict[str, object]] = {}
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            continue
        case_name = str(case.get("name") or "")
        if not case_name:
            _failure("case_name_missing", index=index)
            continue
        case_names_seen[case_name] = case_names_seen.get(case_name, 0) + 1
        if case_name in case_by_name:
            _failure("case_duplicate", case=case_name)
            continue
        case_by_name[case_name] = case
    for name, count in case_names_seen.items():
        if count > 1:
            _failure("case_name_count_mismatch", case=name, count=count)
    for name, expected_case in required_case_by_name.items():
        actual_case = case_by_name.get(name)
        if actual_case is None:
            _failure("case_required_missing", case=name)
            continue
        for field in ["family"]:
            if actual_case.get(field) != expected_case.get(field):
                _failure(
                    "case_required_field_mismatch",
                    case=name,
                    field=field,
                    expected=expected_case.get(field),
                    actual=actual_case.get(field),
                )
    for name in case_by_name:
        if name not in required_case_by_name:
            _failure("case_unknown", case=name)
    passed_count = len([case for case in cases if isinstance(case, dict) and case.get("success")])
    if _json_int(report.get("case_count")) != len(cases):
        _failure(
            "case_count_mismatch",
            expected=report.get("case_count"),
            actual=len(cases),
        )
    if _json_int(report.get("passed_count")) != passed_count:
        _failure(
            "passed_count_mismatch",
            expected=report.get("passed_count"),
            actual=passed_count,
        )
    if _json_int(report.get("failed_count")) != len(cases) - passed_count:
        _failure(
            "failed_count_mismatch",
            expected=report.get("failed_count"),
            actual=len(cases) - passed_count,
        )

    covered_families: Dict[str, bool] = {}
    mutation_replay_verified_count = 0
    verified_case_count = 0
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            _failure("case_not_object", index=index)
            continue
        case_name = str(case.get("name") or "")
        family = str(case.get("family") or "")
        if require_success and not bool(case.get("success")):
            _failure("case_success_required", case=case_name)
        if bool(case.get("success")):
            for flag in ["analyze_success", "recover_success", "final_payload_sha256_verified"]:
                if not bool(case.get(flag)):
                    _failure("case_flag_mismatch", case=case_name, field=flag)
            if _json_int(case.get("correction_required_count"), -1) != 0:
                _failure("case_correction_required", case=case_name)
            if _json_int(case.get("line_error_count"), -1) != 0:
                _failure("case_line_errors", case=case_name)

        for field_prefix, path_field, required in [
            ("ocr_input", "ocr_input_path", True),
            ("analyze_report", "analyze_report_path", True),
            ("recovered_output", "recovered_output_path", bool(case.get("success"))),
        ]:
            artifact_path = _resolve_evidence_path(report_base, case.get(path_field))
            if artifact_path is None or not artifact_path.exists() or not artifact_path.is_file():
                if required:
                    _failure(
                        "case_artifact_missing",
                        case=case_name,
                        field=path_field,
                        path=str(artifact_path) if artifact_path else None,
                    )
                continue
            artifact_bytes = artifact_path.read_bytes()
            actual_sha = protocol.sha256_hex(artifact_bytes)
            expected_sha = case.get("{}_sha256".format(field_prefix))
            if expected_sha and actual_sha != expected_sha:
                _failure(
                    "case_artifact_sha256_mismatch",
                    case=case_name,
                    field=path_field,
                    expected=expected_sha,
                    actual=actual_sha,
                )
            expected_size = case.get("{}_size".format(field_prefix))
            if expected_size is not None and len(artifact_bytes) != _json_int(expected_size):
                _failure(
                    "case_artifact_size_mismatch",
                    case=case_name,
                    field=path_field,
                    expected=expected_size,
                    actual=len(artifact_bytes),
                )
            if field_prefix == "recovered_output" and bool(case.get("success")):
                payload_sha = str(report.get("payload_sha256") or "")
                if actual_sha != payload_sha:
                    _failure(
                        "case_recovered_payload_sha256_mismatch",
                        case=case_name,
                        expected=payload_sha,
                        actual=actual_sha,
                    )
                else:
                    verified_case_count += 1

        analyze_report_path = _resolve_evidence_path(
            report_base, case.get("analyze_report_path")
        )
        if analyze_report_path and analyze_report_path.exists():
            try:
                analyze_report = _load_json_file(analyze_report_path)
                if bool(analyze_report.get("success")) != bool(case.get("analyze_success")):
                    _failure(
                        "case_analyze_success_mismatch",
                        case=case_name,
                        expected=case.get("analyze_success"),
                        actual=analyze_report.get("success"),
                    )
                if _json_int(analyze_report.get("correction_required_count")) != _json_int(
                    case.get("correction_required_count")
                ):
                    _failure("case_analyze_correction_count_mismatch", case=case_name)
                if _json_int(analyze_report.get("line_error_count")) != _json_int(
                    case.get("line_error_count")
                ):
                    _failure("case_analyze_line_error_count_mismatch", case=case_name)
            except Exception as exc:
                _failure(
                    "case_analyze_report_json_invalid",
                    case=case_name,
                    message=str(exc),
                )
        if source_page_texts_verified and source_lines:
            mutation_ok, mutation_failure = _verify_ocr_confusion_mutation_replay(
                report_base=report_base,
                report=report,
                case=case,
                base_lines=source_lines,
            )
            if mutation_ok:
                mutation_replay_verified_count += 1
            elif mutation_failure:
                _failure(**mutation_failure)
        else:
            _failure("case_mutation_source_unavailable", case=case_name)
        if family:
            covered_families[family] = covered_families.get(family, True) and bool(
                case.get("success")
            )

    for family in required_families:
        if not covered_families.get(family, False):
            _failure("confusion_family_not_verified", family=family)

    success = not failures
    result: Dict[str, object] = {
        "schema": OCR_SAFE_CONFUSION_VERIFICATION_SCHEMA,
        "success": bool(success),
        "verified_at_utc": protocol.utc_now_iso(),
        "report_file": str(report_path),
        "report_sha256": _sha256_file(report_path),
        "source_report_schema": report.get("schema"),
        "suite": report.get("suite"),
        "payload_alphabet_profile": report.get("payload_alphabet_profile"),
        "alphabet": report.get("alphabet"),
        "require_success": bool(require_success),
        "payload_verified": bool(payload_verified),
        "manifest_verified": bool(manifest_verified),
        "source_page_texts_verified": bool(
            source_page_texts_verified and bool(source_page_texts)
        ),
        "mutation_replay_verified_count": mutation_replay_verified_count,
        "case_count": len(cases),
        "passed_count": passed_count,
        "verified_case_output_count": verified_case_count,
        "required_confusion_families": required_families,
        "required_confusion_cases": required_cases,
        "covered_confusion_families": covered_families,
        "failure_count": len(failures),
        "failures": failures[:50],
        "message": (
            "synthetic OCR confusion report verified"
            if success
            else "synthetic OCR confusion report verification failed"
        ),
        "certification_boundary": (
            "This verification checks replayability and artifact integrity for synthetic "
            "OCR-safe text-confusion evidence only. It does not certify real camera/photo, "
            "physical print-scan, or backend-specific OCR transfer."
        ),
    }
    if output_file:
        result["output_file"] = cli.save_json(output_file, result)
    return result


def _correction_file_error_report(
    *,
    manifest: Dict[str, object],
    manifest_path: str,
    ocr_input_path: str,
    corrections_file: str,
    output_file: Optional[str],
    report_file: Optional[str],
    exc: parser.CorrectionFileError,
) -> Dict[str, object]:
    digest = _correction_file_digest(corrections_file)
    invalid_sample = [
        {
            "reason": exc.reason,
            "message": str(exc),
            "details": dict(exc.details),
        }
    ]
    result: Dict[str, object] = {
        "schema": CORRECTION_REPLAY_REPORT_SCHEMA,
        "success": False,
        "artifact_id": manifest["artifact_id"],
        "payload_alphabet_profile": manifest.get("payload_alphabet_profile"),
        "alphabet": protocol.payload_alphabet_for_profile(
            manifest.get("payload_alphabet_profile")
        ),
        "manifest_path": str(manifest_path),
        "ocr_input_path": str(ocr_input_path),
        "corrections_file": str(corrections_file),
        "corrections_file_sha256": digest["sha256"],
        "corrections_file_size": digest["size"],
        "correction_file_valid": False,
        "correction_file_error": invalid_sample[0],
        "requested_output_file": str(output_file) if output_file else None,
        "output_file": None,
        "output_suppressed_reason": (
            "correction_file_invalid" if output_file else None
        ),
        "expected_total_chunks": int(manifest["total_chunks"]),
        "received_unique_chunks": 0,
        "received_parity_chunks": 0,
        "parity_recovered_count": 0,
        "parity_recovered_sample": [],
        "package_hash_resolved_count": 0,
        "package_hash_resolved_sample": [],
        "line_error_count": 0,
        "line_errors_sample": [],
        "line_warning_count": 0,
        "line_warnings_sample": [],
        "correction_required_count": 0,
        "refreshed_corrections_template_path": None,
        "refreshed_corrections_template_record_count": 0,
        "unused_filled_correction_count": 0,
        "unused_filled_correction_rows_sample": [],
        "correction_records_sample": [],
        "correction_replay": {
            "source_file": str(corrections_file),
            "source_sha256": digest["sha256"],
            "source_size": digest["size"],
            "row_count": 0,
            "filled_row_count": 0,
            "applied_count": 0,
            "invalid_count": 1,
            "unused_count": 0,
            "applied_sample": [],
            "invalid_sample": invalid_sample,
            "unused_sample": [],
        },
        "page_crc_error_count": 0,
        "page_crc_errors": [],
        "duplicate_conflict_count": 0,
        "duplicate_conflicts": [],
        "missing_chunks_count": int(manifest["total_chunks"]),
        "missing_chunks_sample": [],
        "expected_compressed_sha256": manifest["compressed_sha256"],
        "actual_compressed_sha256": None,
        "expected_raw_sha256": manifest["raw_sha256"],
        "actual_raw_sha256": None,
        "expected_raw_size": int(manifest["raw_size"]),
        "actual_raw_size": None,
        "final_payload_sha256_verified": False,
        "decode_error": None,
        "message": "correction replay failed: correction file invalid",
        "certification_boundary": (
            "Synthetic or operator OCR correction replay verifies corrected text against line "
            "CRC and final payload SHA256 only. It does not certify real camera/photo, "
            "physical print-scan, or backend-specific OCR transfer."
        ),
    }
    if report_file:
        result["report_path"] = cli.save_json(report_file, result)
    return result


def recover_artifact(
    transport,
    manifest_path: Optional[str],
    ocr_input_path: str,
    output_file: str,
    strict_payload_chars: bool = False,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    if not manifest_path:
        return recover_artifact_without_manifest(
            transport=transport,
            ocr_input_path=ocr_input_path,
            output_file=output_file,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    manifest = transport._load_manifest(manifest_path)
    return recover_artifact_against_manifest(
        transport=transport,
        manifest=manifest,
        ocr_input_path=ocr_input_path,
        output_file=output_file,
        strict_payload_chars=strict_payload_chars,
        corrections_file=corrections_file,
    )


def recover_artifact_against_manifest(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    output_file: str,
    strict_payload_chars: bool = False,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    encoded = recover_encoded_payload(
        transport,
        manifest,
        ocr_input_path,
        strict_payload_chars,
        corrections_file=corrections_file,
    )
    compressed = protocol.decode_payload_for_profile(
        encoded,
        manifest.get("payload_alphabet_profile"),
    )
    compressed_sha = protocol.sha256_hex(compressed)
    if compressed_sha != manifest["compressed_sha256"]:
        raise ValueError(
            "compressed sha256 mismatch: expected {}, got {}".format(
                manifest["compressed_sha256"], compressed_sha
            )
        )

    raw = zlib.decompress(compressed)
    raw_sha = protocol.sha256_hex(raw)
    if raw_sha != manifest["raw_sha256"]:
        raise ValueError(
            "raw sha256 mismatch: expected {}, got {}".format(manifest["raw_sha256"], raw_sha)
        )
    if len(raw) != int(manifest["raw_size"]):
        raise ValueError("raw size mismatch: expected {}, got {}".format(manifest["raw_size"], len(raw)))

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(raw)

    return {
        "success": True,
        "artifact_id": manifest["artifact_id"],
        "output_file": str(out_path),
        "raw_size": len(raw),
        "raw_sha256": raw_sha,
        "compressed_sha256": compressed_sha,
    }


def replay_ocr_corrections(
    transport,
    manifest_path: str,
    ocr_input_path: str,
    corrections_file: str,
    output_file: Optional[str] = None,
    report_file: Optional[str] = None,
    strict_payload_chars: bool = False,
    emit_corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    manifest = transport._load_manifest(manifest_path)
    if str(manifest.get("payload_alphabet_profile") or "").strip().lower() != (
        protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE
    ):
        raise ValueError(
            "replay-corrections requires payload_alphabet_profile={}".format(
                protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE
            )
        )

    total_chunks = int(manifest["total_chunks"])
    try:
        parsed = transport._parse_ocr_chunks(
            manifest,
            ocr_input_path,
            strict_payload_chars,
            corrections_file=corrections_file,
        )
    except parser.CorrectionFileError as exc:
        return _correction_file_error_report(
            manifest=manifest,
            manifest_path=manifest_path,
            ocr_input_path=ocr_input_path,
            corrections_file=corrections_file,
            output_file=output_file,
            report_file=report_file,
            exc=exc,
        )
    parity_recovered = parser.apply_parity_recovery(manifest, parsed)
    hash_resolved = parser.resolve_conflicts_by_package_hash(transport, manifest, parsed)
    parity_recovered_after_hash = parser.apply_parity_recovery(manifest, parsed)
    parser.downgrade_nonblocking_parity_conflicts(parsed, total_chunks)
    parsed["missing_chunks"] = [
        idx for idx in range(total_chunks) if idx not in parsed["chunks"]
    ]

    correction_replay = parsed.get("correction_replay", {})
    if not isinstance(correction_replay, dict):
        correction_replay = {}
    line_errors = parsed.get("line_errors", [])
    if not isinstance(line_errors, list):
        line_errors = []
    duplicate_conflicts = parsed.get("duplicate_conflicts", [])
    if not isinstance(duplicate_conflicts, list):
        duplicate_conflicts = []
    missing_chunks = parsed.get("missing_chunks", [])
    if not isinstance(missing_chunks, list):
        missing_chunks = []
    page_crc_errors = parsed.get("page_crc_errors", [])
    if not isinstance(page_crc_errors, list):
        page_crc_errors = []
    line_warnings = parsed.get("line_warnings", [])
    if not isinstance(line_warnings, list):
        line_warnings = []

    compressed = b""
    raw = b""
    compressed_sha = ""
    raw_sha = ""
    recovered = False
    decode_error = None
    if not line_errors and not duplicate_conflicts and not missing_chunks:
        try:
            ordered = [parsed["chunks"][i] for i in range(total_chunks)]
            encoded = "".join(ordered)
            compressed = protocol.decode_payload_for_profile(
                encoded,
                manifest.get("payload_alphabet_profile"),
            )
            compressed_sha = protocol.sha256_hex(compressed)
            raw = zlib.decompress(compressed)
            raw_sha = protocol.sha256_hex(raw)
            recovered = (
                compressed_sha == manifest["compressed_sha256"]
                and raw_sha == manifest["raw_sha256"]
                and len(raw) == int(manifest["raw_size"])
            )
        except Exception as exc:
            decode_error = str(exc)

    correction_applied_count = int(correction_replay.get("applied_count") or 0)
    correction_invalid_count = int(correction_replay.get("invalid_count") or 0)
    filled_correction_count = int(correction_replay.get("filled_row_count") or 0)
    correction_source_sha256 = correction_replay.get("source_sha256")
    correction_source_size = correction_replay.get("source_size")
    unused_rows = correction_replay.get("unused_sample")
    if not isinstance(unused_rows, list):
        unused_rows = []
    unused_filled_correction_count = int(
        correction_replay.get("unused_count")
        if correction_replay.get("unused_count") is not None
        else max(
            0,
            filled_correction_count - correction_applied_count - correction_invalid_count,
        )
    )
    correction_required_count = len(parsed.get("correction_records", []) or [])
    final_sha_verified = recovered and bool(compressed_sha) and bool(raw_sha)
    success = (
        recovered
        and final_sha_verified
        and correction_applied_count > 0
        and unused_filled_correction_count == 0
        and correction_invalid_count == 0
        and correction_required_count == 0
    )

    output_path = None
    output_suppressed_reason = None
    if output_file:
        if success:
            out = Path(output_file)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(raw)
            output_path = str(out)
        elif recovered and final_sha_verified:
            output_suppressed_reason = "correction_replay_not_accepted"
        else:
            output_suppressed_reason = "final_payload_sha256_not_verified"

    correction_records = parsed.get("correction_records", []) or []
    if not isinstance(correction_records, list):
        correction_records = []
    refreshed_corrections_path = None
    if (not success) and correction_records:
        correction_path = emit_corrections_file
        if not correction_path and report_file:
            correction_path = str(Path(report_file).with_name("corrections_template_retry.csv"))
        if correction_path:
            refreshed_corrections_path = cli.save_corrections_template(
                correction_path,
                correction_records,
            )

    result: Dict[str, object] = {
        "schema": CORRECTION_REPLAY_REPORT_SCHEMA,
        "success": bool(success),
        "artifact_id": manifest["artifact_id"],
        "payload_alphabet_profile": manifest.get("payload_alphabet_profile"),
        "alphabet": protocol.payload_alphabet_for_profile(
            manifest.get("payload_alphabet_profile")
        ),
        "manifest_path": str(manifest_path),
        "ocr_input_path": str(ocr_input_path),
        "corrections_file": str(corrections_file),
        "corrections_file_sha256": correction_source_sha256,
        "corrections_file_size": correction_source_size,
        "correction_file_valid": True,
        "correction_file_error": None,
        "requested_output_file": str(output_file) if output_file else None,
        "output_file": output_path,
        "output_suppressed_reason": output_suppressed_reason,
        "expected_total_chunks": total_chunks,
        "received_unique_chunks": len(
            [idx for idx in parsed.get("chunks", {}) if 0 <= int(idx) < total_chunks]
        ),
        "received_parity_chunks": len(
            [idx for idx in parsed.get("chunks", {}) if int(idx) >= total_chunks]
        ),
        "parity_recovered_count": len(parity_recovered)
        + len(parity_recovered_after_hash),
        "parity_recovered_sample": (
            parity_recovered + parity_recovered_after_hash
        )[:20],
        "package_hash_resolved_count": len(hash_resolved),
        "package_hash_resolved_sample": hash_resolved[:20],
        "line_error_count": len(line_errors),
        "line_errors_sample": line_errors[:20],
        "line_warning_count": len(line_warnings),
        "line_warnings_sample": line_warnings[:20],
        "correction_required_count": correction_required_count,
        "refreshed_corrections_template_path": refreshed_corrections_path,
        "refreshed_corrections_template_record_count": (
            len(correction_records) if refreshed_corrections_path else 0
        ),
        "unused_filled_correction_count": unused_filled_correction_count,
        "unused_filled_correction_rows_sample": unused_rows[:20],
        "correction_records_sample": correction_records[:20],
        "correction_replay": correction_replay,
        "page_crc_error_count": len(page_crc_errors),
        "page_crc_errors": page_crc_errors[:20],
        "duplicate_conflict_count": len(duplicate_conflicts),
        "duplicate_conflicts": duplicate_conflicts[:20],
        "missing_chunks_count": len(missing_chunks),
        "missing_chunks_sample": missing_chunks[:20],
        "expected_compressed_sha256": manifest["compressed_sha256"],
        "actual_compressed_sha256": compressed_sha or None,
        "expected_raw_sha256": manifest["raw_sha256"],
        "actual_raw_sha256": raw_sha or None,
        "expected_raw_size": int(manifest["raw_size"]),
        "actual_raw_size": len(raw) if raw else None,
        "final_payload_sha256_verified": bool(final_sha_verified),
        "decode_error": decode_error,
        "message": "correction replay verified" if success else "correction replay failed",
        "certification_boundary": (
            "Synthetic or operator OCR correction replay verifies corrected text against line "
            "CRC and final payload SHA256 only. It does not certify real camera/photo, "
            "physical print-scan, or backend-specific OCR transfer."
        ),
    }
    if report_file:
        result["report_path"] = cli.save_json(report_file, result)
    return result


def verify_ocr_correction_replay_report(
    transport,
    report_file: str,
    output_file: Optional[str] = None,
    require_success: bool = True,
) -> Dict[str, object]:
    report_path = Path(report_file).resolve()
    report_base = report_path.parent
    failures: List[Dict[str, object]] = []

    def _failure(reason: str, **details: object) -> None:
        event = {"reason": reason}
        event.update(details)
        failures.append(event)

    try:
        report = _load_json_file(report_path)
    except Exception as exc:
        report = {}
        _failure("report_json_invalid", message=str(exc))

    if report.get("schema") != CORRECTION_REPLAY_REPORT_SCHEMA:
        _failure(
            "report_schema_mismatch",
            expected=CORRECTION_REPLAY_REPORT_SCHEMA,
            actual=report.get("schema"),
        )
    if report.get("payload_alphabet_profile") != protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        _failure(
            "payload_alphabet_profile_mismatch",
            expected=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
            actual=report.get("payload_alphabet_profile"),
        )
    if report.get("alphabet") != protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET:
        _failure(
            "alphabet_mismatch",
            expected=protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET,
            actual=report.get("alphabet"),
        )
    if require_success and not bool(report.get("success")):
        _failure("report_success_required")

    manifest_path = _resolve_evidence_path(report_base, report.get("manifest_path"))
    ocr_input_path = _resolve_evidence_path(report_base, report.get("ocr_input_path"))
    corrections_path = _resolve_evidence_path(report_base, report.get("corrections_file"))
    manifest_verified = False
    ocr_input_verified = False
    corrections_file_verified = False

    if manifest_path is None or not manifest_path.exists() or not manifest_path.is_file():
        _failure(
            "manifest_missing",
            path=str(manifest_path) if manifest_path else None,
        )
    else:
        manifest_verified = True
        try:
            manifest = _load_json_file(manifest_path)
            for field, report_field in [
                ("artifact_id", "artifact_id"),
                ("payload_alphabet_profile", "payload_alphabet_profile"),
                ("total_chunks", "expected_total_chunks"),
                ("compressed_sha256", "expected_compressed_sha256"),
                ("raw_sha256", "expected_raw_sha256"),
                ("raw_size", "expected_raw_size"),
            ]:
                actual = manifest.get(field)
                expected = report.get(report_field)
                if field in ("total_chunks", "raw_size"):
                    actual = _json_int(actual)
                    expected = _json_int(expected)
                if actual != expected:
                    _failure(
                        "manifest_field_mismatch",
                        field=field,
                        expected=expected,
                        actual=actual,
                    )
        except Exception as exc:
            manifest_verified = False
            _failure("manifest_json_invalid", message=str(exc))

    if ocr_input_path is None or not ocr_input_path.exists() or not ocr_input_path.is_file():
        _failure(
            "ocr_input_missing",
            path=str(ocr_input_path) if ocr_input_path else None,
        )
    else:
        ocr_input_verified = True

    if corrections_path is None or not corrections_path.exists() or not corrections_path.is_file():
        _failure(
            "corrections_file_missing",
            path=str(corrections_path) if corrections_path else None,
        )
    else:
        correction_bytes = corrections_path.read_bytes()
        actual_corrections_sha = protocol.sha256_hex(correction_bytes)
        actual_corrections_size = len(correction_bytes)
        corrections_file_verified = (
            actual_corrections_sha == report.get("corrections_file_sha256")
            and actual_corrections_size == _json_int(
                report.get("corrections_file_size"), -1
            )
        )
        if actual_corrections_sha != report.get("corrections_file_sha256"):
            _failure(
                "corrections_file_sha256_mismatch",
                expected=report.get("corrections_file_sha256"),
                actual=actual_corrections_sha,
            )
        if actual_corrections_size != _json_int(report.get("corrections_file_size"), -1):
            _failure(
                "corrections_file_size_mismatch",
                expected=report.get("corrections_file_size"),
                actual=actual_corrections_size,
            )

    replay_verified = False
    replay_result: Dict[str, object] = {}
    if manifest_path and ocr_input_path and corrections_path:
        try:
            replay_result = replay_ocr_corrections(
                transport=transport,
                manifest_path=str(manifest_path),
                ocr_input_path=str(ocr_input_path),
                corrections_file=str(corrections_path),
                output_file=None,
                report_file=None,
                strict_payload_chars=True,
            )
            replay_verified = True
        except Exception as exc:
            _failure("correction_replay_reexecution_failed", message=str(exc))

    if replay_result:
        field_pairs = [
            ("success", "success"),
            ("correction_file_valid", "correction_file_valid"),
            ("final_payload_sha256_verified", "final_payload_sha256_verified"),
            ("unused_filled_correction_count", "unused_filled_correction_count"),
            ("correction_required_count", "correction_required_count"),
            ("line_error_count", "line_error_count"),
            ("missing_chunks_count", "missing_chunks_count"),
            ("actual_compressed_sha256", "actual_compressed_sha256"),
            ("actual_raw_sha256", "actual_raw_sha256"),
            ("actual_raw_size", "actual_raw_size"),
            ("decode_error", "decode_error"),
        ]
        for replay_field, report_field in field_pairs:
            if replay_result.get(replay_field) != report.get(report_field):
                _failure(
                    "replay_field_mismatch",
                    field=report_field,
                    expected=report.get(report_field),
                    actual=replay_result.get(replay_field),
                )
        report_replay = report.get("correction_replay")
        if not isinstance(report_replay, dict):
            _failure("correction_replay_summary_missing")
            report_replay = {}
        actual_replay = replay_result.get("correction_replay")
        if not isinstance(actual_replay, dict):
            actual_replay = {}
        for field in [
            "source_sha256",
            "source_size",
            "row_count",
            "filled_row_count",
            "applied_count",
            "invalid_count",
            "unused_count",
        ]:
            if actual_replay.get(field) != report_replay.get(field):
                _failure(
                    "correction_replay_summary_mismatch",
                    field=field,
                    expected=report_replay.get(field),
                    actual=actual_replay.get(field),
                )

    requested_output = _normalize_optional_path(report.get("requested_output_file"))
    reported_output = _normalize_optional_path(report.get("output_file"))
    output_file_verified = False
    output_suppression_verified = False
    if reported_output:
        output_path = _resolve_evidence_path(report_base, reported_output)
        if output_path is None or not output_path.exists() or not output_path.is_file():
            _failure(
                "output_file_missing",
                path=str(output_path) if output_path else reported_output,
            )
        else:
            output_sha = protocol.sha256_hex(output_path.read_bytes())
            output_file_verified = output_sha == report.get("actual_raw_sha256")
            if output_sha != report.get("actual_raw_sha256"):
                _failure(
                    "output_file_sha256_mismatch",
                    expected=report.get("actual_raw_sha256"),
                    actual=output_sha,
                )
            if not bool(report.get("success")):
                _failure("unsuccessful_report_has_output_file", output_file=reported_output)
    elif requested_output and report.get("output_suppressed_reason"):
        requested_path = _resolve_evidence_path(report_base, requested_output)
        if requested_path and requested_path.exists():
            _failure(
                "suppressed_output_file_exists",
                path=str(requested_path),
            )
        else:
            output_suppression_verified = True
    elif requested_output and bool(report.get("success")):
        _failure("successful_report_missing_output_file", requested_output=requested_output)

    if not bool(report.get("correction_file_valid", True)) and not report.get(
        "correction_file_error"
    ):
        _failure("invalid_correction_file_error_missing")
    if bool(report.get("success")) and not bool(report.get("final_payload_sha256_verified")):
        _failure("successful_report_without_final_sha")
    if bool(report.get("success")) and _json_int(report.get("correction_required_count"), -1) != 0:
        _failure("successful_report_has_remaining_corrections")
    if bool(report.get("success")) and _json_int(report.get("unused_filled_correction_count"), -1) != 0:
        _failure("successful_report_has_unused_corrections")

    success = not failures
    result: Dict[str, object] = {
        "schema": CORRECTION_REPLAY_VERIFICATION_SCHEMA,
        "success": bool(success),
        "verified_at_utc": protocol.utc_now_iso(),
        "report_file": str(report_path),
        "report_sha256": _sha256_file(report_path),
        "source_report_schema": report.get("schema"),
        "payload_alphabet_profile": report.get("payload_alphabet_profile"),
        "alphabet": report.get("alphabet"),
        "require_success": bool(require_success),
        "manifest_verified": bool(manifest_verified),
        "ocr_input_verified": bool(ocr_input_verified),
        "corrections_file_verified": bool(corrections_file_verified),
        "correction_replay_reexecuted": bool(replay_verified),
        "final_payload_sha256_verified": bool(
            report.get("final_payload_sha256_verified")
        ),
        "output_file_verified": bool(output_file_verified),
        "output_suppression_verified": bool(output_suppression_verified),
        "failure_count": len(failures),
        "failures": failures[:50],
        "message": (
            "correction replay report verified"
            if success
            else "correction replay report verification failed"
        ),
        "certification_boundary": (
            "This verification checks replayability and artifact integrity for OCR-safe "
            "correction replay evidence only. It does not certify real camera/photo, "
            "physical print-scan, or backend-specific OCR transfer."
        ),
    }
    if output_file:
        result["output_file"] = cli.save_json(output_file, result)
    return result


def archive_ocr_safe_evidence(
    *,
    transport=None,
    archive_file: str,
    manifest_file: Optional[str] = None,
    confusion_report_file: Optional[str] = None,
    correction_replay_report_file: Optional[str] = None,
    require_confusion_report: bool = False,
    require_correction_replay_report: bool = False,
    require_source_report_verification: bool = False,
) -> Dict[str, object]:
    if not confusion_report_file and not correction_replay_report_file:
        raise ValueError(
            "archive-ocr-safe-evidence requires at least one report file"
        )

    archive_path = Path(archive_file).resolve()
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path = (
        Path(manifest_file).resolve()
        if manifest_file
        else archive_path.with_name("ocr_safe_evidence_archive_manifest.json")
    )

    reports: List[Tuple[str, Path, Dict[str, object], Optional[Dict[str, object]]]] = []
    if confusion_report_file:
        path = Path(confusion_report_file).resolve()
        report = _load_json_file(path)
        if report.get("schema") != OCR_SAFE_CONFUSION_REPORT_SCHEMA:
            raise ValueError("unsupported synthetic OCR confusion report schema")
        report_success = _require_json_bool(
            report.get("success"),
            "success",
            "synthetic OCR confusion report",
        )
        if require_confusion_report and not report_success:
            raise ValueError("synthetic OCR confusion report success is required")
        verification = None
        if require_source_report_verification:
            verification = verify_ocr_safe_confusion_report(report_file=str(path))
            verification_success = _require_json_bool(
                verification.get("success"),
                "success",
                "synthetic OCR confusion source verification",
            )
            _require_json_non_negative_int(
                verification.get("failure_count"),
                "failure_count",
                "synthetic OCR confusion source verification",
            )
            if not verification_success:
                raise ValueError(
                    "synthetic OCR confusion report source verification failed"
                )
        reports.append(("ocr_safe_confusion_report", path, report, verification))
    elif require_confusion_report:
        raise ValueError("synthetic OCR confusion report is required")

    if correction_replay_report_file:
        path = Path(correction_replay_report_file).resolve()
        report = _load_json_file(path)
        if report.get("schema") != CORRECTION_REPLAY_REPORT_SCHEMA:
            raise ValueError("unsupported OCR correction replay report schema")
        report_success = _require_json_bool(
            report.get("success"),
            "success",
            "OCR correction replay report",
        )
        if require_correction_replay_report and not report_success:
            raise ValueError("OCR correction replay report success is required")
        verification = None
        if require_source_report_verification:
            if transport is None:
                raise ValueError(
                    "source verification for correction replay reports requires a transport"
                )
            verification = verify_ocr_correction_replay_report(
                transport=transport,
                report_file=str(path),
            )
            verification_success = _require_json_bool(
                verification.get("success"),
                "success",
                "OCR correction replay source verification",
            )
            _require_json_non_negative_int(
                verification.get("failure_count"),
                "failure_count",
                "OCR correction replay source verification",
            )
            if not verification_success:
                raise ValueError(
                    "OCR correction replay report source verification failed"
                )
        reports.append(("correction_replay_report", path, report, verification))
    elif require_correction_replay_report:
        raise ValueError("OCR correction replay report is required")

    files: List[Dict[str, object]] = []
    used_sources = set()
    used_archive_paths = {OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST}
    report_entries: List[Dict[str, object]] = []
    for role, report_path, report, _verification in reports:
        _collect_report_evidence_files(
            report=report,
            report_path=report_path,
            role=role,
            files=files,
            used_sources=used_sources,
            used_archive_paths=used_archive_paths,
        )
        report_entry = {
            "role": role,
            "source_path": str(report_path),
            "source_sha256": _sha256_file(report_path),
            "schema": report.get("schema"),
            "success": _require_json_bool(
                report.get("success"),
                "success",
                "{} source report".format(role),
            ),
            "source_verification_required": bool(require_source_report_verification),
        }
        if _verification is not None:
            report_entry["source_verification"] = {
                "schema": _verification.get("schema"),
                "success": _require_json_bool(
                    _verification.get("success"),
                    "success",
                    "{} source verification".format(role),
                ),
                "report_sha256": _verification.get("report_sha256"),
                "failure_count": _require_json_non_negative_int(
                    _verification.get("failure_count"),
                    "failure_count",
                    "{} source verification".format(role),
                ),
            }
        report_entries.append(report_entry)

    file_by_source = {str(item["source_path"]): item for item in files}
    rewritten_reports: List[Tuple[str, Dict[str, object], Dict[str, object]]] = []
    source_verification_reports: List[Tuple[str, Dict[str, object], Dict[str, object]]] = []
    source_report_records: Dict[str, Dict[str, object]] = {}
    for role, report_path, report, _verification in reports:
        if _verification is not None:
            source_report_role = _source_report_archive_role(role)
            if source_report_role is not None:
                source_report_record = _archive_digest_record(
                    report_path,
                    source_report_role,
                    used_archive_paths,
                )
                files.append(source_report_record)
                source_report_records[role] = source_report_record
                for entry in report_entries:
                    if entry["role"] == role:
                        entry["source_report_archive"] = {
                            "role": source_report_role,
                            "archive_path": source_report_record["archive_path"],
                            "sha256": source_report_record["sha256"],
                            "size_bytes": source_report_record["size_bytes"],
                        }
                        break
        rewritten = _rewrite_report_paths_for_archive(report, file_by_source)
        rewritten_bytes = json.dumps(
            rewritten,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        archive_report_path = (
            "synthetic_ocr_confusion_report.json"
            if role == "ocr_safe_confusion_report"
            else "transport_ocr_correction_replay_report.json"
        )
        rewritten_record = {
            "role": "{}_rewritten".format(role),
            "source_path": None,
            "archive_path": archive_report_path,
            "sha256": protocol.sha256_hex(rewritten_bytes),
            "size_bytes": len(rewritten_bytes),
        }
        files.append(rewritten_record)
        rewritten_reports.append((archive_report_path, rewritten, rewritten_record))
        for entry in report_entries:
            if entry["role"] == role:
                entry["archive_report_path"] = archive_report_path
                entry["archive_report_sha256"] = rewritten_record["sha256"]
                break
        if _verification is not None:
            verification_role = _source_verification_archive_role(role)
            if verification_role is None:
                continue
            verification_archive_path = (
                "synthetic_ocr_confusion_source_verification.json"
                if role == "ocr_safe_confusion_report"
                else "transport_ocr_correction_replay_source_verification.json"
            )
            archived_verification = _rewrite_source_verification_for_archive(
                _verification,
                source_report_records.get(role),
            )
            verification_bytes = json.dumps(
                archived_verification,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            verification_record = {
                "role": verification_role,
                "source_path": None,
                "archive_path": verification_archive_path,
                "sha256": protocol.sha256_hex(verification_bytes),
                "size_bytes": len(verification_bytes),
            }
            files.append(verification_record)
            source_verification_reports.append(
                (verification_archive_path, archived_verification, verification_record)
            )
            for entry in report_entries:
                if entry["role"] == role:
                    source_verification = entry.get("source_verification")
                    if isinstance(source_verification, dict):
                        source_verification["archive_path"] = verification_archive_path
                        source_verification["archive_sha256"] = verification_record[
                            "sha256"
                        ]
                        source_verification["archive_size_bytes"] = verification_record[
                            "size_bytes"
                        ]
                        source_report_record = source_report_records.get(role)
                        if source_report_record is not None:
                            source_verification["source_report_archive_path"] = (
                                source_report_record["archive_path"]
                            )
                            source_verification["source_report_archive_sha256"] = (
                                source_report_record["sha256"]
                            )
                            source_verification["source_report_archive_size_bytes"] = (
                                source_report_record["size_bytes"]
                            )
                    break

    manifest: Dict[str, object] = {
        "schema": OCR_SAFE_EVIDENCE_ARCHIVE_SCHEMA,
        "generated_at_utc": protocol.utc_now_iso(),
        "success": True,
        "payload_alphabet_profile": protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
        "alphabet": protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET,
        "reports": report_entries,
        "parameters": {
            "require_confusion_report": bool(require_confusion_report),
            "require_correction_replay_report": bool(
                require_correction_replay_report
            ),
            "require_source_report_verification": bool(
                require_source_report_verification
            ),
        },
        "summary": {
            "report_count": len(report_entries),
            "report_roles": dict(
                Counter(str(item.get("role") or "unknown") for item in report_entries)
            ),
            "source_report_verification_count": sum(
                1
                for item in report_entries
                if isinstance(item.get("source_verification"), dict)
            ),
            "source_report_verification_roles": dict(
                Counter(
                    str(item.get("role") or "unknown")
                    for item in report_entries
                    if isinstance(item.get("source_verification"), dict)
                )
            ),
            "file_count": len(files),
            "total_size_bytes": sum(int(item.get("size_bytes") or 0) for item in files),
            "roles": dict(Counter(str(item.get("role") or "unknown") for item in files)),
        },
        "files": files,
        "certification_boundary": OCR_SAFE_EVIDENCE_ARCHIVE_BOUNDARY,
    }
    embedded_manifest_json = json.dumps(
        manifest,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    manifest["embedded_manifest_sha256"] = protocol.sha256_hex(
        embedded_manifest_json.encode("utf-8")
    )

    with zipfile.ZipFile(str(archive_path), "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST, embedded_manifest_json)
        for item in files:
            archive_path_name = str(item.get("archive_path") or "")
            rewritten_match = [
                (path, rewritten)
                for path, rewritten, _record in rewritten_reports
                if path == archive_path_name
            ]
            if rewritten_match:
                archive.writestr(
                    archive_path_name,
                    json.dumps(
                        rewritten_match[0][1],
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    ),
                )
                continue
            verification_match = [
                verification
                for path, verification, _record in source_verification_reports
                if path == archive_path_name
            ]
            if verification_match:
                archive.writestr(
                    archive_path_name,
                    json.dumps(
                        verification_match[0],
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    ),
                )
                continue
            source_path = item.get("source_path")
            if source_path:
                archive.write(str(source_path), archive_path_name)

    manifest["archive_file"] = str(archive_path)
    manifest["archive_sha256"] = _sha256_file(archive_path)
    manifest["archive_size_bytes"] = archive_path.stat().st_size
    manifest["manifest_file"] = str(manifest_path)
    cli.save_json(str(manifest_path), manifest)
    return manifest


def verify_ocr_safe_evidence_archive(
    *,
    transport=None,
    archive_file: str,
    manifest_file: Optional[str] = None,
    output_file: Optional[str] = None,
    require_confusion_report: bool = False,
    require_correction_replay_report: bool = False,
    require_source_report_verification: bool = False,
    require_success: bool = True,
) -> Dict[str, object]:
    archive_path = Path(archive_file).resolve()
    if not archive_path.exists() or not archive_path.is_file():
        raise ValueError("OCR-safe evidence archive file does not exist: {}".format(archive_path))
    actual_archive_sha = _sha256_file(archive_path)
    actual_archive_size = archive_path.stat().st_size

    failures: List[Dict[str, object]] = []

    def _failure(reason: str, **details: object) -> None:
        event = {"reason": reason}
        event.update(details)
        failures.append(event)

    external_manifest: Optional[Dict[str, object]] = None
    external_manifest_path: Optional[Path] = None
    external_manifest_verified = False

    def _external_failure(reason: str, **details: object) -> None:
        nonlocal external_manifest_verified
        external_manifest_verified = False
        _failure(reason, **details)

    if manifest_file:
        external_manifest_path = Path(manifest_file).resolve()
        external_manifest_verified = True
        if not external_manifest_path.exists() or not external_manifest_path.is_file():
            raise ValueError(
                "OCR-safe evidence archive manifest file does not exist: {}".format(
                    external_manifest_path
                )
            )
        try:
            external_manifest = _load_json_file(external_manifest_path)
        except Exception as exc:
            external_manifest = {}
            _external_failure("external_manifest_json_invalid", message=str(exc))
        if external_manifest.get("schema") != OCR_SAFE_EVIDENCE_ARCHIVE_SCHEMA:
            _external_failure(
                "external_manifest_schema_mismatch",
                expected=OCR_SAFE_EVIDENCE_ARCHIVE_SCHEMA,
                actual=external_manifest.get("schema"),
            )
        expected_archive_sha_raw = str(external_manifest.get("archive_sha256") or "").strip()
        expected_archive_sha = _canonical_sha256_text(expected_archive_sha_raw)
        if not expected_archive_sha_raw:
            _external_failure("external_archive_sha256_missing")
        elif expected_archive_sha is None:
            _external_failure(
                "external_archive_sha256_invalid",
                actual=external_manifest.get("archive_sha256"),
            )
        elif expected_archive_sha != actual_archive_sha:
            _external_failure(
                "external_archive_sha256_mismatch",
                expected=expected_archive_sha,
                actual=actual_archive_sha,
            )
        expected_archive_size = external_manifest.get("archive_size_bytes")
        if (
            isinstance(expected_archive_size, bool)
            or not isinstance(expected_archive_size, int)
            or expected_archive_size < 0
        ):
            _external_failure(
                "external_archive_size_missing_or_invalid",
                actual=expected_archive_size,
            )
        elif expected_archive_size != actual_archive_size:
            _external_failure(
                "external_archive_size_mismatch",
                expected=expected_archive_size,
                actual=actual_archive_size,
            )
        expected_archive_file_name = _portable_basename(
            external_manifest.get("archive_file")
        )
        if not expected_archive_file_name:
            _external_failure("external_archive_file_missing")
        elif expected_archive_file_name != archive_path.name:
            _external_failure(
                "external_archive_file_name_mismatch",
                expected=expected_archive_file_name,
                actual=archive_path.name,
            )
        expected_manifest_file_name = _portable_basename(
            external_manifest.get("manifest_file")
        )
        if not expected_manifest_file_name:
            _external_failure("external_manifest_file_missing")
        elif expected_manifest_file_name != external_manifest_path.name:
            _external_failure(
                "external_manifest_file_name_mismatch",
                expected=expected_manifest_file_name,
                actual=external_manifest_path.name,
            )

    archive_payloads: Dict[str, bytes] = {}
    member_names: List[str] = []
    embedded_manifest: Dict[str, object] = {}
    embedded_manifest_payload: Optional[bytes] = None
    embedded_manifest_sha: Optional[str] = None
    try:
        with zipfile.ZipFile(str(archive_path), "r") as archive:
            infos = archive.infolist()
            member_names = [info.filename for info in infos]
            counts = Counter(member_names)
            for name, count in counts.items():
                if count != 1:
                    _failure("duplicate_archive_member", archive_path=name, count=count)
            for info in infos:
                if not _is_safe_archive_member(info.filename):
                    _failure("unsafe_archive_member", archive_path=info.filename)
                    continue
                if _zip_info_is_symlink(info):
                    _failure("archive_member_is_symlink", archive_path=info.filename)
                    continue
                payload = archive.read(info)
                if info.filename == OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST:
                    embedded_manifest_payload = payload
                else:
                    archive_payloads[info.filename] = payload
    except zipfile.BadZipFile:
        _failure("archive_unreadable")

    if embedded_manifest_payload is None:
        _failure("embedded_manifest_missing")
    else:
        embedded_manifest_sha = protocol.sha256_hex(embedded_manifest_payload)
        if external_manifest is not None:
            expected_embedded_sha_raw = str(
                external_manifest.get("embedded_manifest_sha256") or ""
            ).strip()
            expected_embedded_sha = _canonical_sha256_text(expected_embedded_sha_raw)
            if not expected_embedded_sha_raw:
                _external_failure("embedded_manifest_sha256_missing")
            elif expected_embedded_sha is None:
                _external_failure(
                    "embedded_manifest_sha256_invalid",
                    actual=external_manifest.get("embedded_manifest_sha256"),
                )
            elif expected_embedded_sha != embedded_manifest_sha:
                _external_failure(
                    "embedded_manifest_sha256_mismatch",
                    expected=expected_embedded_sha,
                    actual=embedded_manifest_sha,
                )
        try:
            embedded_manifest = json.loads(embedded_manifest_payload.decode("utf-8"))
            if not isinstance(embedded_manifest, dict):
                embedded_manifest = {}
                _failure("embedded_manifest_not_object")
        except Exception as exc:
            embedded_manifest = {}
            _failure("embedded_manifest_json_invalid", message=str(exc))

    manifest = embedded_manifest if embedded_manifest else (external_manifest or {})
    if manifest.get("schema") != OCR_SAFE_EVIDENCE_ARCHIVE_SCHEMA:
        _failure(
            "archive_manifest_schema_mismatch",
            expected=OCR_SAFE_EVIDENCE_ARCHIVE_SCHEMA,
            actual=manifest.get("schema"),
        )
    if manifest.get("payload_alphabet_profile") != protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        _failure("payload_alphabet_profile_mismatch")
    if manifest.get("alphabet") != protocol.OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET:
        _failure("alphabet_mismatch")
    generated_at_verified = _is_canonical_utc_timestamp(
        manifest.get("generated_at_utc")
    )
    if not generated_at_verified:
        _failure(
            "archive_generated_at_utc_missing_or_invalid",
            actual=manifest.get("generated_at_utc"),
        )
    manifest_success_verified = manifest.get("success") is True
    if not manifest_success_verified:
        _failure("archive_success_not_true", actual=manifest.get("success"))
    certification_boundary_verified = (
        manifest.get("certification_boundary") == OCR_SAFE_EVIDENCE_ARCHIVE_BOUNDARY
    )
    if not certification_boundary_verified:
        _failure(
            "archive_certification_boundary_mismatch",
            expected=OCR_SAFE_EVIDENCE_ARCHIVE_BOUNDARY,
            actual=manifest.get("certification_boundary"),
        )

    if external_manifest and embedded_manifest:
        for field in [
            "schema",
            "generated_at_utc",
            "success",
            "payload_alphabet_profile",
            "alphabet",
            "reports",
            "parameters",
            "summary",
            "files",
            "certification_boundary",
        ]:
            if external_manifest.get(field) != embedded_manifest.get(field):
                _external_failure("external_embedded_manifest_mismatch", field=field)

    files = manifest.get("files")
    if not isinstance(files, list):
        files = []
        _failure("archive_manifest_files_invalid")
    expected_members = {OCR_SAFE_EVIDENCE_ARCHIVE_MANIFEST}
    archive_file_counts: Counter = Counter()
    manifest_file_role_counts: Counter = Counter()
    verified_file_count = 0
    total_size_verified = 0
    manifest_file_metadata_verified = True
    archive_file_roles_verified = True
    for item in files:
        if not isinstance(item, dict):
            _failure("archive_file_record_invalid")
            continue
        role = str(item.get("role") or "")
        manifest_file_role_counts[role or "unknown"] += 1
        member = str(item.get("archive_path") or "")
        if not _is_safe_archive_member(member):
            _failure("archive_file_record_path_unsafe", archive_path=member or None)
            continue
        role_path_ok, role_path_failure = _archive_file_role_path_status(role, member)
        if not role_path_ok:
            archive_file_roles_verified = False
            _failure(
                role_path_failure,
                role=role or None,
                archive_path=member,
            )
        expected_sha = item.get("sha256")
        if _canonical_sha256_text(expected_sha) is None:
            manifest_file_metadata_verified = False
            _failure(
                "archive_file_record_sha256_missing_or_invalid",
                archive_path=member,
                actual=expected_sha,
            )
        expected_size = item.get("size_bytes")
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            manifest_file_metadata_verified = False
            _failure(
                "archive_file_record_size_missing_or_invalid",
                archive_path=member,
                actual=expected_size,
            )
        archive_file_counts[member] += 1
        expected_members.add(member)
        payload = archive_payloads.get(member)
        if payload is None:
            continue
        actual_sha = protocol.sha256_hex(payload)
        actual_size = len(payload)
        if actual_sha != str(item.get("sha256") or ""):
            _failure(
                "file_sha256_mismatch",
                archive_path=member,
                expected=item.get("sha256"),
                actual=actual_sha,
            )
        if isinstance(expected_size, int) and not isinstance(expected_size, bool):
            expected_size_int = expected_size
        else:
            expected_size_int = -1
        if actual_size != expected_size_int:
            _failure(
                "file_size_mismatch",
                archive_path=member,
                expected=item.get("size_bytes"),
                actual=actual_size,
            )
        verified_file_count += 1
        total_size_verified += actual_size
    for member, count in archive_file_counts.items():
        if count != 1:
            _failure("duplicate_manifest_archive_path", archive_path=member, count=count)

    actual_members = set(member_names)
    missing_members = sorted(expected_members - actual_members)
    unexpected_members = sorted(actual_members - expected_members)
    if missing_members:
        _failure("archive_member_missing", archive_paths=missing_members)
    if unexpected_members:
        _failure("archive_member_unexpected", archive_paths=unexpected_members)

    parameters = manifest.get("parameters")
    if not isinstance(parameters, dict):
        parameters = {}
        _failure("archive_parameters_invalid")
    archive_parameters_verified = True
    manifest_parameter_values: Dict[str, bool] = {}
    for key in [
        "require_confusion_report",
        "require_correction_replay_report",
        "require_source_report_verification",
    ]:
        value = parameters.get(key)
        if not isinstance(value, bool):
            archive_parameters_verified = False
            _failure(
                "archive_parameter_missing_or_invalid",
                parameter=key,
                actual=value,
            )
            manifest_parameter_values[key] = False
        else:
            manifest_parameter_values[key] = value
    manifest_requires_confusion_report = bool(
        manifest_parameter_values.get("require_confusion_report")
    )
    manifest_requires_correction_replay_report = bool(
        manifest_parameter_values.get("require_correction_replay_report")
    )
    manifest_requires_source_verification = bool(
        manifest_parameter_values.get("require_source_report_verification")
    )
    if require_confusion_report and not manifest_requires_confusion_report:
        _failure("confusion_report_not_required_by_archive")
        archive_parameters_verified = False
    if (
        require_correction_replay_report
        and not manifest_requires_correction_replay_report
    ):
        _failure("correction_replay_report_not_required_by_archive")
        archive_parameters_verified = False
    if require_source_report_verification and not manifest_requires_source_verification:
        _failure("source_report_verification_not_required_by_archive")
        archive_parameters_verified = False

    reports = manifest.get("reports")
    if not isinstance(reports, list):
        reports = []
        _failure("archive_reports_invalid")
    roles: set = set()
    manifest_report_role_counts: Counter = Counter()
    rewritten_report_members: Dict[Tuple[str, str], Dict[str, object]] = {}
    source_verification_members: Dict[Tuple[str, str], Dict[str, object]] = {}
    source_report_members: Dict[Tuple[str, str], Dict[str, object]] = {}
    archive_report_states_verified = True
    archive_report_metadata_verified = True
    for item in files:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "")
        for report_role in ["ocr_safe_confusion_report", "correction_replay_report"]:
            if role == _expected_rewritten_report_role(report_role):
                rewritten_report_members[(report_role, str(item.get("archive_path") or ""))] = item
            if role == _source_verification_archive_role(report_role):
                source_verification_members[
                    (report_role, str(item.get("archive_path") or ""))
                ] = item
            if role == _source_report_archive_role(report_role):
                source_report_members[
                    (report_role, str(item.get("archive_path") or ""))
                ] = item

    for report in reports:
        if not isinstance(report, dict):
            _failure("archive_report_record_invalid")
            continue
        role = str(report.get("role") or "")
        manifest_report_role_counts[role or "unknown"] += 1
        archive_report_path = str(report.get("archive_report_path") or "")
        schema = str(report.get("schema") or "")
        expected_schema = (
            OCR_SAFE_CONFUSION_REPORT_SCHEMA
            if role == "ocr_safe_confusion_report"
            else CORRECTION_REPLAY_REPORT_SCHEMA
            if role == "correction_replay_report"
            else None
        )
        if role in roles:
            _failure("duplicate_archive_report_role", role=role)
        roles.add(role)
        if expected_schema is None:
            _failure("unknown_report_role", role=role)
            continue
        if schema != expected_schema:
            _failure(
                "archive_report_schema_mismatch",
                role=role,
                expected=expected_schema,
                actual=schema or None,
            )
        report_success = report.get("success")
        if not isinstance(report_success, bool):
            archive_report_states_verified = False
            _failure(
                "archive_report_success_missing_or_invalid",
                role=role,
                actual=report_success,
            )
        if _canonical_sha256_text(report.get("source_sha256")) is None:
            archive_report_metadata_verified = False
            _failure(
                "archive_report_source_sha256_missing_or_invalid",
                role=role,
                actual=report.get("source_sha256"),
            )
        if _canonical_sha256_text(report.get("archive_report_sha256")) is None:
            archive_report_metadata_verified = False
            _failure(
                "archive_report_sha256_missing_or_invalid",
                role=role,
                actual=report.get("archive_report_sha256"),
            )
        if not _is_safe_archive_member(archive_report_path):
            archive_report_metadata_verified = False
            _failure(
                "report_archive_path_unsafe",
                role=role,
                archive_path=archive_report_path or None,
            )
            continue
        rewritten_record = rewritten_report_members.get((role, archive_report_path))
        if rewritten_record is None:
            _failure(
                "archive_report_file_record_missing",
                role=role,
                archive_path=archive_report_path,
            )
            continue
        expected_rewritten_role = _expected_rewritten_report_role(role)
        if rewritten_record.get("role") != expected_rewritten_role:
            _failure(
                "archive_report_file_role_mismatch",
                role=role,
                expected=expected_rewritten_role,
                actual=rewritten_record.get("role"),
            )
        payload = archive_payloads.get(archive_report_path)
        if payload is None:
            continue
        actual_report_sha = protocol.sha256_hex(payload)
        actual_report_size = len(payload)
        if actual_report_sha != str(report.get("archive_report_sha256") or ""):
            _failure(
                "archive_report_sha256_mismatch",
                role=role,
                archive_path=archive_report_path,
                expected=report.get("archive_report_sha256"),
                actual=actual_report_sha,
            )
        if actual_report_sha != str(rewritten_record.get("sha256") or ""):
            _failure(
                "archive_report_file_sha256_mismatch",
                role=role,
                archive_path=archive_report_path,
                expected=rewritten_record.get("sha256"),
                actual=actual_report_sha,
            )
        if actual_report_size != _json_int(rewritten_record.get("size_bytes"), -1):
            _failure(
                "archive_report_file_size_mismatch",
                role=role,
                archive_path=archive_report_path,
                expected=rewritten_record.get("size_bytes"),
                actual=actual_report_size,
            )
        try:
            archived_report = json.loads(payload.decode("utf-8"))
            if not isinstance(archived_report, dict):
                _failure(
                    "archive_report_json_not_object",
                    role=role,
                    archive_path=archive_report_path,
                )
                archived_report = {}
        except Exception as exc:
            _failure(
                "archive_report_json_invalid",
                role=role,
                archive_path=archive_report_path,
                message=str(exc),
            )
            archived_report = {}
        if archived_report:
            if archived_report.get("schema") != expected_schema:
                _failure(
                    "archive_report_member_schema_mismatch",
                    role=role,
                    expected=expected_schema,
                    actual=archived_report.get("schema"),
                )
            archived_report_success = archived_report.get("success")
            if not isinstance(archived_report_success, bool):
                archive_report_states_verified = False
                _failure(
                    "archive_report_member_success_missing_or_invalid",
                    role=role,
                    archive_path=archive_report_path,
                    actual=archived_report_success,
                )
            elif isinstance(report_success, bool) and archived_report_success != report_success:
                archive_report_states_verified = False
                _failure(
                    "archive_report_success_mismatch",
                    role=role,
                    expected=report_success,
                    actual=archived_report_success,
                )
    if require_confusion_report and "ocr_safe_confusion_report" not in roles:
        _failure("required_confusion_report_missing")
    if (
        require_correction_replay_report
        and "correction_replay_report" not in roles
    ):
        _failure("required_correction_replay_report_missing")
    if manifest_requires_confusion_report and "ocr_safe_confusion_report" not in roles:
        _failure(
            "archive_parameter_required_report_missing",
            parameter="require_confusion_report",
            role="ocr_safe_confusion_report",
        )
        archive_parameters_verified = False
    if (
        manifest_requires_correction_replay_report
        and "correction_replay_report" not in roles
    ):
        _failure(
            "archive_parameter_required_report_missing",
            parameter="require_correction_replay_report",
            role="correction_replay_report",
        )
        archive_parameters_verified = False

    source_verification_count = 0
    source_report_verification_states_verified = True
    source_report_archive_metadata_parity_verified = True
    manifest_source_verification_role_counts: Counter = Counter()
    source_verification_required = (
        require_source_report_verification or manifest_requires_source_verification
    )
    if source_verification_required:
        for report in reports:
            if not isinstance(report, dict):
                continue
            role = str(report.get("role") or "")
            expected_schema = (
                OCR_SAFE_CONFUSION_VERIFICATION_SCHEMA
                if role == "ocr_safe_confusion_report"
                else CORRECTION_REPLAY_VERIFICATION_SCHEMA
                if role == "correction_replay_report"
                else None
            )
            if expected_schema is None:
                continue
            source_verification_required_value = report.get(
                "source_verification_required"
            )
            if not isinstance(source_verification_required_value, bool):
                source_report_verification_states_verified = False
                _failure(
                    "source_report_verification_required_flag_missing_or_invalid",
                    role=role,
                    actual=source_verification_required_value,
                )
            elif not source_verification_required_value:
                source_report_verification_states_verified = False
                _failure("source_report_verification_flag_missing", role=role)
            source_verification = report.get("source_verification")
            if not isinstance(source_verification, dict):
                source_report_verification_states_verified = False
                _failure("source_report_verification_missing", role=role)
                continue
            manifest_source_verification_role_counts[role or "unknown"] += 1
            if source_verification.get("schema") != expected_schema:
                _failure(
                    "source_report_verification_schema_mismatch",
                    role=role,
                    expected=expected_schema,
                    actual=source_verification.get("schema"),
                )
            source_verification_success = source_verification.get("success")
            if not isinstance(source_verification_success, bool):
                source_report_verification_states_verified = False
                _failure(
                    "source_report_verification_success_missing_or_invalid",
                    role=role,
                    actual=source_verification_success,
                )
            elif not source_verification_success:
                source_report_verification_states_verified = False
                _failure("source_report_verification_unsuccessful", role=role)
            source_verification_failure_count = source_verification.get(
                "failure_count"
            )
            if (
                isinstance(source_verification_failure_count, bool)
                or not isinstance(source_verification_failure_count, int)
            ):
                source_report_verification_states_verified = False
                _failure(
                    "source_report_verification_failure_count_missing_or_invalid",
                    role=role,
                    actual=source_verification_failure_count,
                )
            elif source_verification_failure_count != 0:
                source_report_verification_states_verified = False
                _failure(
                    "source_report_verification_failure_count_mismatch",
                    role=role,
                    actual=source_verification_failure_count,
                )
            if source_verification.get("report_sha256") != report.get("source_sha256"):
                _failure(
                    "source_report_verification_sha256_mismatch",
                    role=role,
                    expected=report.get("source_sha256"),
                    actual=source_verification.get("report_sha256"),
                )
            source_report_archive = report.get("source_report_archive")
            if not isinstance(source_report_archive, dict):
                source_report_archive = {}
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure("source_report_archive_missing", role=role)
            source_report_archive_path = str(
                source_verification.get("source_report_archive_path")
                or source_report_archive.get("archive_path")
                or ""
            )
            declared_source_report_archive_path = str(
                source_report_archive.get("archive_path") or ""
            )
            declared_source_report_sha = source_report_archive.get("sha256")
            declared_source_report_size = source_report_archive.get("size_bytes")
            source_report_verification_source_path = str(
                source_verification.get("source_report_archive_path") or ""
            )
            source_report_verification_source_sha = source_verification.get(
                "source_report_archive_sha256"
            )
            source_report_verification_source_size = source_verification.get(
                "source_report_archive_size_bytes"
            )
            if not _is_safe_archive_member(declared_source_report_archive_path):
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure(
                    "source_report_archive_metadata_path_missing_or_invalid",
                    role=role,
                    archive_path=declared_source_report_archive_path or None,
                )
            if _canonical_sha256_text(declared_source_report_sha) is None:
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure(
                    "source_report_archive_metadata_sha256_missing_or_invalid",
                    role=role,
                    actual=declared_source_report_sha,
                )
            if not _is_non_negative_int(declared_source_report_size):
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure(
                    "source_report_archive_metadata_size_missing_or_invalid",
                    role=role,
                    actual=declared_source_report_size,
                )
            if _canonical_sha256_text(source_report_verification_source_sha) is None:
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure(
                    "source_report_verification_source_report_sha256_missing_or_invalid",
                    role=role,
                    actual=source_report_verification_source_sha,
                )
            if not _is_non_negative_int(source_report_verification_source_size):
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure(
                    "source_report_verification_source_report_size_missing_or_invalid",
                    role=role,
                    actual=source_report_verification_source_size,
                )
            if not _is_safe_archive_member(source_report_verification_source_path):
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure(
                    "source_report_verification_source_report_path_missing_or_invalid",
                    role=role,
                    archive_path=source_report_verification_source_path or None,
                )
            if (
                _is_safe_archive_member(declared_source_report_archive_path)
                and _is_safe_archive_member(source_report_verification_source_path)
                and declared_source_report_archive_path
                != source_report_verification_source_path
            ):
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure(
                    "source_report_archive_metadata_path_mismatch",
                    role=role,
                    expected=declared_source_report_archive_path,
                    actual=source_report_verification_source_path,
                )
            declared_source_report_sha_text = _canonical_sha256_text(
                declared_source_report_sha
            )
            source_report_verification_source_sha_text = _canonical_sha256_text(
                source_report_verification_source_sha
            )
            if (
                declared_source_report_sha_text is not None
                and source_report_verification_source_sha_text is not None
                and declared_source_report_sha_text
                != source_report_verification_source_sha_text
            ):
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure(
                    "source_report_archive_metadata_sha256_mismatch",
                    role=role,
                    expected=declared_source_report_sha_text,
                    actual=source_report_verification_source_sha_text,
                )
            if (
                _is_non_negative_int(declared_source_report_size)
                and _is_non_negative_int(source_report_verification_source_size)
                and declared_source_report_size
                != source_report_verification_source_size
            ):
                archive_report_metadata_verified = False
                source_report_archive_metadata_parity_verified = False
                _failure(
                    "source_report_archive_metadata_size_mismatch",
                    role=role,
                    expected=declared_source_report_size,
                    actual=source_report_verification_source_size,
                )
            if not _is_safe_archive_member(source_report_archive_path):
                archive_report_metadata_verified = False
                _failure(
                    "source_report_archive_path_missing",
                    role=role,
                    archive_path=source_report_archive_path or None,
                )
            else:
                source_report_record = source_report_members.get(
                    (role, source_report_archive_path)
                )
                if source_report_record is None:
                    _failure(
                        "source_report_archive_file_record_missing",
                        role=role,
                        archive_path=source_report_archive_path,
                    )
                source_report_payload = archive_payloads.get(source_report_archive_path)
                if source_report_payload is None:
                    _failure(
                        "source_report_archive_member_missing",
                        role=role,
                        archive_path=source_report_archive_path,
                    )
                else:
                    source_report_sha = protocol.sha256_hex(source_report_payload)
                    source_report_size = len(source_report_payload)
                    if source_report_sha != str(report.get("source_sha256") or ""):
                        _failure(
                            "source_report_archive_sha256_mismatch",
                            role=role,
                            archive_path=source_report_archive_path,
                            expected=report.get("source_sha256"),
                            actual=source_report_sha,
                        )
                    if source_report_sha != str(
                        source_verification.get("source_report_archive_sha256")
                        or source_report_archive.get("sha256")
                        or ""
                    ):
                        _failure(
                            "source_report_archive_metadata_sha256_mismatch",
                            role=role,
                            archive_path=source_report_archive_path,
                        )
                    expected_source_report_size = (
                        source_verification.get("source_report_archive_size_bytes")
                        if source_verification.get(
                            "source_report_archive_size_bytes"
                        )
                        is not None
                        else source_report_archive.get("size_bytes")
                    )
                    if source_report_size != _json_int(
                        expected_source_report_size, -1
                    ):
                        _failure(
                            "source_report_archive_metadata_size_mismatch",
                            role=role,
                            archive_path=source_report_archive_path,
                            expected=expected_source_report_size,
                            actual=source_report_size,
                        )
                    if source_report_record is not None:
                        if source_report_record.get("role") != _source_report_archive_role(role):
                            _failure(
                                "source_report_archive_file_role_mismatch",
                                role=role,
                                archive_path=source_report_archive_path,
                                expected=_source_report_archive_role(role),
                                actual=source_report_record.get("role"),
                            )
                        if source_report_sha != str(source_report_record.get("sha256") or ""):
                            _failure(
                                "source_report_archive_file_sha256_mismatch",
                                role=role,
                                archive_path=source_report_archive_path,
                                expected=source_report_record.get("sha256"),
                                actual=source_report_sha,
                            )
                        if source_report_size != _json_int(
                            source_report_record.get("size_bytes"), -1
                        ):
                            _failure(
                                "source_report_archive_file_size_mismatch",
                                role=role,
                                archive_path=source_report_archive_path,
                                expected=source_report_record.get("size_bytes"),
                                actual=source_report_size,
                            )
            verification_archive_path = str(
                source_verification.get("archive_path") or ""
            )
            if _canonical_sha256_text(source_verification.get("archive_sha256")) is None:
                archive_report_metadata_verified = False
                _failure(
                    "source_report_verification_archive_sha256_missing_or_invalid",
                    role=role,
                    actual=source_verification.get("archive_sha256"),
                )
            if not _is_non_negative_int(source_verification.get("archive_size_bytes")):
                archive_report_metadata_verified = False
                _failure(
                    "source_report_verification_archive_size_missing_or_invalid",
                    role=role,
                    actual=source_verification.get("archive_size_bytes"),
                )
            if not _is_safe_archive_member(verification_archive_path):
                archive_report_metadata_verified = False
                _failure(
                    "source_report_verification_archive_path_missing",
                    role=role,
                    archive_path=verification_archive_path or None,
                )
                source_verification_count += 1
                continue
            verification_record = source_verification_members.get(
                (role, verification_archive_path)
            )
            if verification_record is None:
                _failure(
                    "source_report_verification_file_record_missing",
                    role=role,
                    archive_path=verification_archive_path,
                )
            verification_payload = archive_payloads.get(verification_archive_path)
            if verification_payload is None:
                _failure(
                    "source_report_verification_archive_member_missing",
                    role=role,
                    archive_path=verification_archive_path,
                )
                source_verification_count += 1
                continue
            verification_sha = protocol.sha256_hex(verification_payload)
            verification_size = len(verification_payload)
            if verification_sha != str(source_verification.get("archive_sha256") or ""):
                _failure(
                    "source_report_verification_archive_sha256_mismatch",
                    role=role,
                    archive_path=verification_archive_path,
                    expected=source_verification.get("archive_sha256"),
                    actual=verification_sha,
                )
            if verification_size != _json_int(
                source_verification.get("archive_size_bytes"), -1
            ):
                _failure(
                    "source_report_verification_archive_size_mismatch",
                    role=role,
                    archive_path=verification_archive_path,
                    expected=source_verification.get("archive_size_bytes"),
                    actual=verification_size,
                )
            if verification_record is not None:
                if verification_record.get("role") != _source_verification_archive_role(role):
                    _failure(
                        "source_report_verification_file_role_mismatch",
                        role=role,
                        archive_path=verification_archive_path,
                        expected=_source_verification_archive_role(role),
                        actual=verification_record.get("role"),
                    )
                if verification_sha != str(verification_record.get("sha256") or ""):
                    _failure(
                        "source_report_verification_file_sha256_mismatch",
                        role=role,
                        archive_path=verification_archive_path,
                        expected=verification_record.get("sha256"),
                        actual=verification_sha,
                    )
                if verification_size != _json_int(
                    verification_record.get("size_bytes"), -1
                ):
                    _failure(
                        "source_report_verification_file_size_mismatch",
                        role=role,
                        archive_path=verification_archive_path,
                        expected=verification_record.get("size_bytes"),
                        actual=verification_size,
                    )
            try:
                archived_source_verification = json.loads(
                    verification_payload.decode("utf-8")
                )
                if not isinstance(archived_source_verification, dict):
                    archived_source_verification = {}
                    _failure(
                        "source_report_verification_json_not_object",
                        role=role,
                        archive_path=verification_archive_path,
                    )
            except Exception as exc:
                archived_source_verification = {}
                _failure(
                    "source_report_verification_json_invalid",
                    role=role,
                    archive_path=verification_archive_path,
                    message=str(exc),
                )
            if archived_source_verification:
                if archived_source_verification.get("schema") != expected_schema:
                    _failure(
                        "source_report_verification_member_schema_mismatch",
                        role=role,
                        archive_path=verification_archive_path,
                        expected=expected_schema,
                        actual=archived_source_verification.get("schema"),
                    )
                archived_source_verification_success = (
                    archived_source_verification.get("success")
                )
                if not isinstance(archived_source_verification_success, bool):
                    source_report_verification_states_verified = False
                    _failure(
                        "source_report_verification_member_success_missing_or_invalid",
                        role=role,
                        archive_path=verification_archive_path,
                        actual=archived_source_verification_success,
                    )
                elif (
                    isinstance(source_verification_success, bool)
                    and archived_source_verification_success
                    != source_verification_success
                ):
                    source_report_verification_states_verified = False
                    _failure(
                        "source_report_verification_member_success_mismatch",
                        role=role,
                        archive_path=verification_archive_path,
                        expected=source_verification_success,
                        actual=archived_source_verification_success,
                    )
                archived_source_verification_failure_count = (
                    archived_source_verification.get("failure_count")
                )
                if (
                    isinstance(archived_source_verification_failure_count, bool)
                    or not isinstance(archived_source_verification_failure_count, int)
                ):
                    source_report_verification_states_verified = False
                    _failure(
                        "source_report_verification_member_failure_count_missing_or_invalid",
                        role=role,
                        archive_path=verification_archive_path,
                        actual=archived_source_verification_failure_count,
                    )
                elif (
                    isinstance(source_verification_failure_count, int)
                    and not isinstance(source_verification_failure_count, bool)
                    and archived_source_verification_failure_count
                    != source_verification_failure_count
                ):
                    source_report_verification_states_verified = False
                    _failure(
                        "source_report_verification_member_failure_count_mismatch",
                        role=role,
                        archive_path=verification_archive_path,
                        expected=source_verification_failure_count,
                        actual=archived_source_verification_failure_count,
                    )
                if archived_source_verification.get("report_sha256") != report.get(
                    "source_sha256"
                ):
                    _failure(
                        "source_report_verification_member_report_sha256_mismatch",
                        role=role,
                        archive_path=verification_archive_path,
                        expected=report.get("source_sha256"),
                        actual=archived_source_verification.get("report_sha256"),
                    )
                member_report_file = str(
                    archived_source_verification.get("report_file") or ""
                )
                member_report_archive_path = _archive_member_reference(
                    member_report_file
                )
                if member_report_archive_path is None:
                    _failure(
                        "source_report_verification_report_path_not_archive_relative",
                        role=role,
                        archive_path=verification_archive_path,
                        path=member_report_file or None,
                    )
                elif member_report_archive_path != source_report_archive_path:
                    _failure(
                        "source_report_verification_report_path_mismatch",
                        role=role,
                        archive_path=verification_archive_path,
                        expected=source_report_archive_path,
                        actual=member_report_archive_path,
                    )
                elif member_report_archive_path not in archive_payloads:
                    _failure(
                        "source_report_verification_report_path_member_missing",
                        role=role,
                        archive_path=member_report_archive_path,
                    )
            source_verification_count += 1

    confusion_verified = False
    correction_replay_verified = False
    report_verifications: List[Dict[str, object]] = []
    archived_report_path_binding_count = 0
    archived_report_paths_verified = False
    if archive_payloads and not missing_members:
        with tempfile.TemporaryDirectory() as tmp:
            extract_root = Path(tmp)
            for member, payload in archive_payloads.items():
                target = extract_root / member
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
            for report in reports:
                if not isinstance(report, dict):
                    continue
                role = str(report.get("role") or "")
                archive_report_path = str(report.get("archive_report_path") or "")
                if not _is_safe_archive_member(archive_report_path):
                    _failure(
                        "report_archive_path_unsafe",
                        role=role,
                        archive_path=archive_report_path or None,
                    )
                    continue
                report_path = extract_root / archive_report_path
                if not report_path.exists() or not report_path.is_file():
                    _failure(
                        "report_archive_member_missing",
                        role=role,
                        archive_path=archive_report_path,
                    )
                    continue
                try:
                    archived_report_for_paths = _load_json_file(report_path)
                except Exception as exc:
                    _failure(
                        "archive_report_json_invalid",
                        role=role,
                        archive_path=archive_report_path,
                        message=str(exc),
                    )
                    archived_report_for_paths = {}
                if archived_report_for_paths:
                    paths_ok, path_count = _verify_archived_report_path_bindings(
                        role=role,
                        archived_report=archived_report_for_paths,
                        archive_payloads=archive_payloads,
                        failure_callback=_failure,
                    )
                    archived_report_path_binding_count += path_count
                    if not paths_ok:
                        continue
                if role == "ocr_safe_confusion_report":
                    verification = verify_ocr_safe_confusion_report(
                        report_file=str(report_path),
                        require_success=require_success,
                    )
                    confusion_verified = bool(verification.get("success"))
                elif role == "correction_replay_report":
                    if transport is None:
                        _failure("transport_required_for_correction_replay_verification")
                        continue
                    verification = verify_ocr_correction_replay_report(
                        transport=transport,
                        report_file=str(report_path),
                        require_success=require_success,
                    )
                    correction_replay_verified = bool(verification.get("success"))
                else:
                    _failure("unknown_report_role", role=role)
                    continue
                report_verifications.append(
                    {
                        "role": role,
                        "archive_report_path": archive_report_path,
                        "success": bool(verification.get("success")),
                        "schema": verification.get("schema"),
                        "failure_count": int(verification.get("failure_count") or 0),
                    }
                )
                if not bool(verification.get("success")):
                    _failure(
                        "embedded_report_verification_failed",
                        role=role,
                        failures=verification.get("failures", [])[:10],
                    )
    archived_report_paths_verified = (
        len(report_verifications) == len(reports)
        and archived_report_path_binding_count > 0
    )

    expected_summary = manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}
    expected_report_count = expected_summary.get("report_count")
    summary_report_count_verified = False
    if (
        isinstance(expected_report_count, bool)
        or not isinstance(expected_report_count, int)
        or expected_report_count < 0
    ):
        _failure(
            "summary_report_count_missing_or_invalid",
            actual=expected_report_count,
        )
    elif expected_report_count != len(reports):
        _failure(
            "summary_report_count_mismatch",
            expected=expected_report_count,
            actual=len(reports),
        )
    else:
        summary_report_count_verified = True

    expected_report_roles = expected_summary.get("report_roles")
    normalized_expected_report_roles: Dict[str, int] = {}
    summary_report_roles_valid = isinstance(expected_report_roles, dict)
    if not isinstance(expected_report_roles, dict):
        _failure("summary_report_roles_missing_or_invalid")
    else:
        for role, count in expected_report_roles.items():
            role_text = str(role or "").strip()
            if (
                not role_text
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                summary_report_roles_valid = False
                _failure(
                    "summary_report_role_count_invalid",
                    role=role_text or None,
                    actual=count,
                )
                continue
            normalized_expected_report_roles[role_text] = count
        actual_report_roles = dict(sorted(manifest_report_role_counts.items()))
        if (
            summary_report_roles_valid
            and normalized_expected_report_roles != actual_report_roles
        ):
            _failure(
                "summary_report_roles_mismatch",
                expected=dict(sorted(normalized_expected_report_roles.items())),
                actual=actual_report_roles,
            )

    expected_source_verification_count = expected_summary.get(
        "source_report_verification_count"
    )
    summary_source_verification_count_verified = False
    if (
        isinstance(expected_source_verification_count, bool)
        or not isinstance(expected_source_verification_count, int)
        or expected_source_verification_count < 0
    ):
        _failure(
            "summary_source_report_verification_count_missing_or_invalid",
            actual=expected_source_verification_count,
        )
    elif expected_source_verification_count != source_verification_count:
        _failure(
            "summary_source_report_verification_count_mismatch",
            expected=expected_source_verification_count,
            actual=source_verification_count,
        )
    else:
        summary_source_verification_count_verified = True

    expected_source_verification_roles = expected_summary.get(
        "source_report_verification_roles"
    )
    normalized_expected_source_verification_roles: Dict[str, int] = {}
    summary_source_verification_roles_valid = isinstance(
        expected_source_verification_roles, dict
    )
    if not isinstance(expected_source_verification_roles, dict):
        _failure("summary_source_report_verification_roles_missing_or_invalid")
    else:
        for role, count in expected_source_verification_roles.items():
            role_text = str(role or "").strip()
            if (
                not role_text
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                summary_source_verification_roles_valid = False
                _failure(
                    "summary_source_report_verification_role_count_invalid",
                    role=role_text or None,
                    actual=count,
                )
                continue
            normalized_expected_source_verification_roles[role_text] = count
        actual_source_verification_roles = dict(
            sorted(manifest_source_verification_role_counts.items())
        )
        if (
            summary_source_verification_roles_valid
            and normalized_expected_source_verification_roles
            != actual_source_verification_roles
        ):
            _failure(
                "summary_source_report_verification_roles_mismatch",
                expected=dict(
                    sorted(normalized_expected_source_verification_roles.items())
                ),
                actual=actual_source_verification_roles,
            )

    expected_file_count = expected_summary.get("file_count")
    summary_file_count_verified = False
    if (
        isinstance(expected_file_count, bool)
        or not isinstance(expected_file_count, int)
        or expected_file_count < 0
    ):
        _failure(
            "summary_file_count_missing_or_invalid",
            actual=expected_file_count,
        )
    elif expected_file_count != len(files):
        _failure(
            "summary_file_count_mismatch",
            expected=expected_file_count,
            actual=len(files),
        )
    else:
        summary_file_count_verified = True

    expected_total_size = expected_summary.get("total_size_bytes")
    summary_total_size_verified = False
    if (
        isinstance(expected_total_size, bool)
        or not isinstance(expected_total_size, int)
        or expected_total_size < 0
    ):
        _failure(
            "summary_total_size_missing_or_invalid",
            actual=expected_total_size,
        )
    elif expected_total_size != total_size_verified:
        _failure(
            "summary_total_size_mismatch",
            expected=expected_total_size,
            actual=total_size_verified,
        )
    else:
        summary_total_size_verified = True
    expected_roles = expected_summary.get("roles")
    normalized_expected_roles: Dict[str, int] = {}
    summary_roles_valid = isinstance(expected_roles, dict)
    if not isinstance(expected_roles, dict):
        _failure("summary_roles_missing_or_invalid")
    else:
        for role, count in expected_roles.items():
            role_text = str(role or "").strip()
            if (
                not role_text
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                summary_roles_valid = False
                _failure(
                    "summary_role_count_invalid",
                    role=role_text or None,
                    actual=count,
                )
                continue
            normalized_expected_roles[role_text] = count
        actual_roles = dict(sorted(manifest_file_role_counts.items()))
        if summary_roles_valid and normalized_expected_roles != actual_roles:
            _failure(
                "summary_roles_mismatch",
                expected=dict(sorted(normalized_expected_roles.items())),
                actual=actual_roles,
            )

    success = not failures
    result: Dict[str, object] = {
        "schema": OCR_SAFE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA,
        "success": bool(success),
        "verified_at_utc": protocol.utc_now_iso(),
        "archive_file": str(archive_path),
        "archive_sha256": actual_archive_sha,
        "archive_size_bytes": int(actual_archive_size),
        "manifest_file": str(external_manifest_path) if external_manifest_path else None,
        "external_manifest_supplied": bool(external_manifest_path is not None),
        "external_manifest_verified": bool(
            external_manifest_path is not None and external_manifest_verified
        ),
        "embedded_manifest_sha256": embedded_manifest_sha,
        "source_archive_schema": manifest.get("schema"),
        "payload_alphabet_profile": manifest.get("payload_alphabet_profile"),
        "alphabet": manifest.get("alphabet"),
        "require_success": bool(require_success),
        "require_confusion_report": bool(require_confusion_report),
        "require_correction_replay_report": bool(require_correction_replay_report),
        "require_source_report_verification": bool(
            require_source_report_verification
        ),
        "source_report_verification_required_by_manifest": bool(
            manifest_requires_source_verification
        ),
        "source_report_verification_count": int(source_verification_count),
        "source_report_verification_states_verified": bool(
            source_report_verification_states_verified
        ),
        "source_report_archive_metadata_parity_verified": bool(
            source_report_archive_metadata_parity_verified
        ),
        "summary_source_report_verification_count_verified": bool(
            summary_source_verification_count_verified
        ),
        "summary_source_report_verification_roles_verified": bool(
            summary_source_verification_roles_valid
            and normalized_expected_source_verification_roles
            == dict(sorted(manifest_source_verification_role_counts.items()))
        ),
        "verified_source_report_verification_roles": dict(
            sorted(manifest_source_verification_role_counts.items())
        ),
        "archive_report_states_verified": bool(archive_report_states_verified),
        "archive_report_metadata_verified": bool(archive_report_metadata_verified),
        "archive_generated_at_verified": bool(generated_at_verified),
        "archive_success_verified": bool(manifest_success_verified),
        "certification_boundary_verified": bool(certification_boundary_verified),
        "archive_parameters_verified": bool(archive_parameters_verified),
        "archive_parameter_gates": dict(sorted(manifest_parameter_values.items())),
        "manifest_file_metadata_verified": bool(manifest_file_metadata_verified),
        "archive_file_roles_verified": bool(archive_file_roles_verified),
        "report_count": len(reports),
        "verified_report_count": len(report_verifications),
        "summary_report_count_verified": bool(summary_report_count_verified),
        "summary_report_roles_verified": bool(
            summary_report_roles_valid
            and normalized_expected_report_roles
            == dict(sorted(manifest_report_role_counts.items()))
        ),
        "verified_report_roles": dict(sorted(manifest_report_role_counts.items())),
        "archived_report_paths_verified": bool(archived_report_paths_verified),
        "archived_report_path_binding_count": int(
            archived_report_path_binding_count
        ),
        "file_count": len(files),
        "verified_file_count": verified_file_count,
        "verified_total_size_bytes": int(total_size_verified),
        "summary_file_count_verified": bool(summary_file_count_verified),
        "summary_total_size_verified": bool(summary_total_size_verified),
        "summary_roles_verified": bool(
            summary_roles_valid
            and normalized_expected_roles == dict(sorted(manifest_file_role_counts.items()))
        ),
        "verified_roles": dict(sorted(manifest_file_role_counts.items())),
        "report_verifications": report_verifications,
        "confusion_report_verified": bool(confusion_verified),
        "correction_replay_report_verified": bool(correction_replay_verified),
        "failure_count": len(failures),
        "failures": failures[:50],
        "message": (
            "OCR-safe evidence archive verified"
            if success
            else "OCR-safe evidence archive verification failed"
        ),
        "certification_boundary": (
            "This verification checks package integrity and replays included OCR-safe "
            "synthetic/correction evidence only. It does not certify real camera/photo, "
            "physical print-scan, or backend-specific OCR transfer."
        ),
    }
    if output_file:
        result["output_file"] = cli.save_json(output_file, result)
    return result


def verify_ocr_text(
    transport,
    manifest_path: Optional[str],
    ocr_input_path: str,
    strict_payload_chars: bool = False,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    if not manifest_path:
        return verify_ocr_text_without_manifest(
            transport=transport,
            ocr_input_path=ocr_input_path,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )

    manifest = transport._load_manifest(manifest_path)
    return verify_ocr_text_against_manifest(
        transport=transport,
        manifest=manifest,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
        corrections_file=corrections_file,
    )


def verify_ocr_text_against_manifest(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool = False,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    encoded = recover_encoded_payload(
        transport,
        manifest,
        ocr_input_path,
        strict_payload_chars,
        corrections_file=corrections_file,
    )
    compressed = protocol.decode_payload_for_profile(
        encoded,
        manifest.get("payload_alphabet_profile"),
    )
    compressed_sha = protocol.sha256_hex(compressed)

    ok = compressed_sha == manifest["compressed_sha256"]
    return {
        "success": ok,
        "artifact_id": manifest["artifact_id"],
        "expected_compressed_sha256": manifest["compressed_sha256"],
        "actual_compressed_sha256": compressed_sha,
        "total_chunks": int(manifest["total_chunks"]),
        "message": "verify ok" if ok else "verify failed",
    }


def analyze_ocr_text(
    transport,
    manifest_path: Optional[str],
    ocr_input_path: str,
    strict_payload_chars: bool = False,
    max_list: int = 200,
    save_report_path: Optional[str] = None,
    emit_missing_file: Optional[str] = None,
    emit_corrections_file: Optional[str] = None,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    if manifest_path:
        manifest = transport._load_manifest(manifest_path)
    else:
        manifest = transport._build_inferred_manifest_from_ocr(ocr_input_path)
    return analyze_ocr_text_against_manifest(
        transport=transport,
        manifest=manifest,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
        max_list=max_list,
        save_report_path=save_report_path,
        emit_missing_file=emit_missing_file,
        emit_corrections_file=emit_corrections_file,
        corrections_file=corrections_file,
    )


def analyze_ocr_text_against_manifest(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool = False,
    max_list: int = 200,
    save_report_path: Optional[str] = None,
    emit_missing_file: Optional[str] = None,
    emit_corrections_file: Optional[str] = None,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    parsed = transport._parse_ocr_chunks(
        manifest,
        ocr_input_path,
        strict_payload_chars,
        corrections_file=corrections_file,
    )
    parity_recovered = parser.apply_parity_recovery(manifest, parsed)
    hash_resolved = parser.resolve_conflicts_by_package_hash(transport, manifest, parsed)
    parity_recovered_after_hash = parser.apply_parity_recovery(manifest, parsed)
    total_chunks = int(manifest["total_chunks"])
    parser.downgrade_nonblocking_parity_conflicts(parsed, total_chunks)
    parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
    received_data_chunks, received_parity_chunks = parser.count_chunk_presence(
        parsed.get("chunks", {}), total_chunks
    )

    missing = parsed["missing_chunks"]
    missing_records = parser.build_missing_chunk_records(transport, manifest, missing)
    retake_plan = parser.build_missing_chunk_retake_plan(missing_records)
    cap = max(0, int(max_list))
    correction_records = parsed.get("correction_records", [])
    if not isinstance(correction_records, list):
        correction_records = []
    correction_replay = parsed.get("correction_replay", {})
    if not isinstance(correction_replay, dict):
        correction_replay = {}
    recoverable = (
        len(parsed["line_errors"]) == 0 and len(parsed["duplicate_conflicts"]) == 0 and len(missing) == 0
    )
    if recoverable and len(parsed["page_crc_errors"]) > 0:
        message = "recoverable_with_page_crc_warnings"
    else:
        message = "recoverable" if recoverable else "not recoverable"
    result = {
        "success": recoverable,
        "artifact_id": manifest["artifact_id"],
        "expected_total_chunks": int(manifest["total_chunks"]),
        "received_unique_chunks": received_data_chunks,
        "received_parity_chunks": received_parity_chunks,
        "missing_chunks_count": len(missing),
        "missing_chunks_sample": missing[:cap],
        "missing_chunk_locations_sample": missing_records[:cap],
        "missing_chunk_retake_plan_sample": retake_plan[:cap],
        "parity_recovered_count": len(parity_recovered) + len(parity_recovered_after_hash),
        "parity_recovered_sample": (parity_recovered + parity_recovered_after_hash)[:cap],
        "package_hash_resolved_count": len(hash_resolved),
        "package_hash_resolved_sample": hash_resolved[:cap],
        "line_error_count": len(parsed["line_errors"]),
        "line_errors_sample": parsed["line_errors"][: min(20, cap)],
        "line_warning_count": len(parsed["line_warnings"]),
        "line_warnings_sample": parsed["line_warnings"][: min(20, cap)],
        "correction_required_count": len(correction_records),
        "correction_records_sample": correction_records[: min(20, cap)],
        "correction_replay": correction_replay,
        "page_crc_error_count": len(parsed["page_crc_errors"]),
        "page_crc_errors": parsed["page_crc_errors"][: min(20, cap)],
        "duplicate_conflict_count": len(parsed["duplicate_conflicts"]),
        "duplicate_conflicts": parsed["duplicate_conflicts"][: min(20, cap)],
        "message": message,
    }
    if emit_missing_file:
        result["missing_file_path"] = cli.save_missing_chunks(emit_missing_file, missing_records)
    correction_path = emit_corrections_file
    if not correction_path and save_report_path and correction_records:
        correction_path = str(Path(save_report_path).with_name("corrections_template.csv"))
    if correction_path and correction_records:
        result["corrections_template_path"] = cli.save_corrections_template(
            correction_path,
            correction_records,
        )
    if save_report_path:
        result["report_path"] = cli.save_json(save_report_path, result)
    return result


def verify_ocr_text_without_manifest(
    transport,
    ocr_input_path: str,
    strict_payload_chars: bool = False,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    manifest = transport._build_inferred_manifest_from_ocr(ocr_input_path)
    if str(manifest.get("transport_line_index_mode", "full")) == "off":
        raise ValueError("payload-only transport requires manifest for verify")
    metadata_source = str(manifest.get("_metadata_source", "unknown"))
    if manifest.get("_embedded_metadata_complete"):
        encoded = recover_encoded_payload(
            transport,
            manifest,
            ocr_input_path,
            strict_payload_chars,
            corrections_file=corrections_file,
        )
        compressed = protocol.decode_payload_for_profile(
            encoded,
            manifest.get("payload_alphabet_profile"),
        )
        compressed_sha = protocol.sha256_hex(compressed)
        ok = compressed_sha == manifest["compressed_sha256"]
        if not ok:
            return {
                "success": False,
                "artifact_id": manifest["artifact_id"],
                "expected_compressed_sha256": manifest["compressed_sha256"],
                "actual_compressed_sha256": compressed_sha,
                "expected_total_chunks": int(manifest["total_chunks"]),
                "metadata_source": metadata_source,
                "verification_mode": "embedded_metadata",
                "message": "verify failed via embedded page metadata",
            }

        raw = zlib.decompress(compressed)
        raw_sha = protocol.sha256_hex(raw)
        if raw_sha != manifest["raw_sha256"]:
            raise ValueError(
                "raw sha256 mismatch from embedded metadata: expected {}, got {}".format(
                    manifest["raw_sha256"], raw_sha
                )
            )
        if len(raw) != int(manifest["raw_size"]):
            raise ValueError(
                "raw size mismatch from embedded metadata: expected {}, got {}".format(
                    manifest["raw_size"], len(raw)
                )
            )

        return {
            "success": True,
            "artifact_id": manifest["artifact_id"],
            "expected_total_chunks": int(manifest["total_chunks"]),
            "raw_size": len(raw),
            "raw_sha256": raw_sha,
            "expected_compressed_sha256": manifest["compressed_sha256"],
            "actual_compressed_sha256": compressed_sha,
            "metadata_source": metadata_source,
            "verification_mode": "embedded_metadata",
            "message": "verify ok via embedded page metadata",
        }

    total_chunks = int(manifest["total_chunks"])
    parsed = transport._parse_ocr_chunks_with_total(
        total_chunks=total_chunks,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
        corrections_file=corrections_file,
    )
    parser.resolve_conflicts_by_structure(parsed=parsed, total_chunks=total_chunks)
    parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
    parser.raise_parse_errors(parsed, total_chunks)

    encoded = "".join(parsed["chunks"][i] for i in range(total_chunks))
    compressed = protocol.decode_payload_for_profile(
        encoded,
        manifest.get("payload_alphabet_profile"),
    )
    raw = zlib.decompress(compressed)

    return {
        "success": True,
        "artifact_id": manifest["artifact_id"],
        "expected_total_chunks": total_chunks,
        "received_unique_chunks": len(parsed["chunks"]),
        "raw_size": len(raw),
        "raw_sha256": protocol.sha256_hex(raw),
        "metadata_source": metadata_source,
        "verification_mode": "structural_only",
        "message": "structural verify ok without manifest; sha comparison unavailable",
        "warning": "manifest not provided and embedded metadata was incomplete; verification is structural only",
    }


def recover_artifact_without_manifest(
    transport,
    ocr_input_path: str,
    output_file: str,
    strict_payload_chars: bool = False,
    corrections_file: Optional[str] = None,
) -> Dict[str, object]:
    manifest = transport._build_inferred_manifest_from_ocr(ocr_input_path)
    if str(manifest.get("transport_line_index_mode", "full")) == "off":
        raise ValueError("payload-only transport requires manifest for recover")
    metadata_source = str(manifest.get("_metadata_source", "unknown"))
    if manifest.get("_embedded_metadata_complete"):
        result = recover_artifact_against_manifest(
            transport=transport,
            manifest=manifest,
            ocr_input_path=ocr_input_path,
            output_file=output_file,
            strict_payload_chars=strict_payload_chars,
            corrections_file=corrections_file,
        )
        result["metadata_source"] = metadata_source
        result["verification_mode"] = "embedded_metadata"
        result["message"] = "recovered without manifest via embedded page metadata"
        return result

    total_chunks = int(manifest["total_chunks"])
    parsed = transport._parse_ocr_chunks_with_total(
        total_chunks=total_chunks,
        ocr_input_path=ocr_input_path,
        strict_payload_chars=strict_payload_chars,
        corrections_file=corrections_file,
    )
    parser.resolve_conflicts_by_structure(parsed=parsed, total_chunks=total_chunks)
    parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
    parser.raise_parse_errors(parsed, total_chunks)

    encoded = "".join(parsed["chunks"][i] for i in range(total_chunks))
    compressed = protocol.decode_payload_for_profile(
        encoded,
        manifest.get("payload_alphabet_profile"),
    )
    raw = zlib.decompress(compressed)

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(raw)

    return {
        "success": True,
        "artifact_id": manifest["artifact_id"],
        "output_file": str(out_path),
        "raw_size": len(raw),
        "raw_sha256": protocol.sha256_hex(raw),
        "compressed_sha256": protocol.sha256_hex(compressed),
        "metadata_source": metadata_source,
        "verification_mode": "structural_only",
        "message": "recovered without manifest",
        "warning": "manifest not provided and embedded metadata was incomplete; parity recovery and end-to-end sha verification were unavailable",
    }


def recover_encoded_payload(
    transport,
    manifest: Dict[str, object],
    ocr_input_path: str,
    strict_payload_chars: bool,
    corrections_file: Optional[str] = None,
) -> str:
    total_chunks = int(manifest["total_chunks"])
    parsed = transport._parse_ocr_chunks(
        manifest,
        ocr_input_path,
        strict_payload_chars,
        corrections_file=corrections_file,
    )
    parser.apply_parity_recovery(manifest, parsed)
    parser.resolve_conflicts_by_package_hash(transport, manifest, parsed)
    parser.apply_parity_recovery(manifest, parsed)
    parser.downgrade_nonblocking_parity_conflicts(parsed, total_chunks)
    parsed["missing_chunks"] = [idx for idx in range(total_chunks) if idx not in parsed["chunks"]]
    parser.raise_parse_errors(parsed, total_chunks)
    ordered = [parsed["chunks"][i] for i in range(total_chunks)]
    return "".join(ordered)


__all__ = [
    "recover_artifact",
    "recover_artifact_against_manifest",
    "verify_ocr_text",
    "verify_ocr_text_against_manifest",
    "replay_ocr_corrections",
    "CORRECTION_REPLAY_REPORT_SCHEMA",
    "verify_ocr_correction_replay_report",
    "CORRECTION_REPLAY_VERIFICATION_SCHEMA",
    "certify_ocr_safe_confusions",
    "OCR_SAFE_CONFUSION_REPORT_SCHEMA",
    "verify_ocr_safe_confusion_report",
    "OCR_SAFE_CONFUSION_VERIFICATION_SCHEMA",
    "archive_ocr_safe_evidence",
    "OCR_SAFE_EVIDENCE_ARCHIVE_SCHEMA",
    "verify_ocr_safe_evidence_archive",
    "OCR_SAFE_EVIDENCE_ARCHIVE_VERIFICATION_SCHEMA",
    "OCR_SAFE_EVIDENCE_ARCHIVE_BOUNDARY",
    "OCR_SAFE_SYNTHETIC_CONFUSION_SUITE",
    "analyze_ocr_text",
    "analyze_ocr_text_against_manifest",
    "verify_ocr_text_without_manifest",
    "recover_artifact_without_manifest",
    "recover_encoded_payload",
]
