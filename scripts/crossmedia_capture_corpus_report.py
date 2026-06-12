#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build a P1-S4 robustness report for a real SOX1QR capture corpus.

The construction guide keeps crypto and visual transport separated.  This
script therefore evaluates only ``photos -> SOX1`` recoverability and optional
SOX1 hash matching; it never reads keys, decrypts plaintext, or depends on a
render manifest.

Corpus layout is intentionally shallow and explicit:

* images directly under ``--corpus`` are treated as one case named ``.``;
* each immediate child directory with supported images is treated as one case;
* no recursive traversal is performed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from enc2sop.crossmedia import crypto_envelope
from enc2sop.crossmedia import image_scan
from enc2sop.crossmedia import qr_transport

REPORT_SCHEMA = "enc2sop-cross-media-capture-corpus-report/v1"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate a shallow real/simulated phone capture corpus for SOX1QR "
            "recoverability and emit a robustness JSON report."
        ),
    )
    parser.add_argument("--corpus", required=True, help="Directory containing capture case images or case subdirectories.")
    parser.add_argument("--expected-sox1-file", help="Optional expected SOX1 string file for hash comparison.")
    parser.add_argument("--artifact-id", help="Optional SOX1QR artifact id to require during reassembly.")
    parser.add_argument("--output", help="Optional JSON report path. Without it, JSON is printed to stdout.")
    return parser


def _relative_report_path(path: Path, root: Path) -> str:
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return Path(path).name


def _case_image_dirs(corpus: Path) -> list[tuple[str, Path]]:
    root = Path(corpus)
    if not root.exists():
        raise image_scan.ImageScanError("capture corpus not found: {0}".format(root))
    if not root.is_dir():
        raise image_scan.ImageScanError("capture corpus must be a directory: {0}".format(root))

    cases: list[tuple[str, Path]] = []
    if image_scan.list_image_files(root):
        cases.append((".", root))

    for child in sorted((item for item in root.iterdir() if item.is_dir()), key=lambda item: item.name.lower()):
        if image_scan.list_image_files(child):
            cases.append((_relative_report_path(child, root), child))

    if not cases:
        raise image_scan.ImageScanError("capture corpus contains no supported images: {0}".format(root))
    return cases


def _counter_increment(counter: dict[str, int], value: object) -> None:
    key = str(value or "unknown")
    counter[key] = int(counter.get(key, 0)) + 1


def _quality_summary(per_image_quality: Iterable[dict[str, object]]) -> dict[str, object]:
    image_count = 0
    unreadable = 0
    scores: list[int] = []
    blur_status_counts: dict[str, int] = {}
    exposure_status_counts: dict[str, int] = {}

    for item in per_image_quality:
        quality = item.get("quality") if isinstance(item.get("quality"), dict) else {}
        image_count += 1
        score = quality.get("score")
        if isinstance(score, (int, float)):
            scores.append(max(0, min(100, int(score))))
        if str(quality.get("status") or "") == "unreadable":
            unreadable += 1
        blur = quality.get("blur") if isinstance(quality.get("blur"), dict) else {}
        exposure = quality.get("exposure") if isinstance(quality.get("exposure"), dict) else {}
        _counter_increment(blur_status_counts, blur.get("status") or quality.get("status"))
        _counter_increment(exposure_status_counts, exposure.get("status") or quality.get("status"))

    average_score: Optional[float]
    lowest_score: Optional[int]
    if scores:
        average_score = round(sum(scores) / float(len(scores)), 2)
        lowest_score = min(scores)
    else:
        average_score = None
        lowest_score = None

    return {
        "schema": image_scan.IMAGE_QUALITY_SCHEMA,
        "image_count": image_count,
        "average_score": average_score,
        "lowest_score": lowest_score,
        "unreadable": unreadable,
        "blur_status_counts": blur_status_counts,
        "exposure_status_counts": exposure_status_counts,
    }


def _collect_case_quality(case_dir: Path) -> list[dict[str, object]]:
    root = Path(case_dir)
    records: list[dict[str, object]] = []
    for image_path in image_scan.list_image_files(root):
        records.append(
            {
                "path": _relative_report_path(image_path, root),
                "quality": image_scan.assess_image_file_quality(image_path),
            }
        )
    return records


def _parse_reassembly_error(exc: qr_transport.QrReassemblyError) -> dict[str, object]:
    try:
        payload = json.loads(str(exc))
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    payload.setdefault("schema", qr_transport.SCAN_REPORT_SCHEMA)
    payload.setdefault("success", False)
    payload.setdefault("reason", "qr_reassembly_failed")
    payload.setdefault("detail", str(exc))
    return payload


def _case_result_from_reassembly(
    *,
    case_name: str,
    case_dir: Path,
    corpus: Path,
    scan_meta: dict[str, object],
    report: dict[str, object],
    quality_records: list[dict[str, object]],
    complete: bool,
    expected_sha256: Optional[str],
    sox1: Optional[str],
) -> dict[str, object]:
    string_sha256 = qr_transport.sox1_sha256(sox1) if sox1 is not None else None
    expected_match = None if expected_sha256 is None or string_sha256 is None else string_sha256 == expected_sha256
    success = bool(complete and report.get("success") is True and (expected_match is not False))
    reason = report.get("reason")
    if complete and expected_match is False:
        reason = "expected_sox1_mismatch"

    result = {
        "case": case_name,
        "path": _relative_report_path(case_dir, corpus),
        "success": success,
        "complete": bool(complete),
        "expected_match": expected_match,
        "reason": reason,
        "image_count": int(scan_meta.get("image_count") or report.get("image_count") or 0),
        "payload_count": int(scan_meta.get("payload_count") or 0),
        "artifact_id": report.get("artifact_id"),
        "chunks_total": int(report.get("chunks_total") or 0),
        "chunks_found": int(report.get("chunks_found") or 0),
        "duplicates": int(report.get("duplicates") or 0),
        "missing_chunks": list(report.get("missing_chunks") or []),
        "retake_pages": list(report.get("retake_pages") or []),
        "string_sha256": string_sha256 or report.get("string_sha256"),
        "bad_images": list(scan_meta.get("bad_images") or report.get("bad_images") or []),
        "quality_summary": _quality_summary(quality_records),
        "per_image_quality": quality_records,
    }
    if "complete_artifact_ids" in report:
        result["complete_artifact_ids"] = report.get("complete_artifact_ids")
    if "conflicts" in report:
        result["conflicts"] = report.get("conflicts")
    return result


def _evaluate_case(
    *,
    case_name: str,
    case_dir: Path,
    corpus: Path,
    artifact_id: Optional[str],
    expected_sha256: Optional[str],
) -> dict[str, object]:
    quality_records = _collect_case_quality(case_dir)
    payloads, scan_meta = image_scan.scan_image_input(case_dir)
    bad_images = scan_meta.get("bad_images") if isinstance(scan_meta.get("bad_images"), list) else []
    try:
        sox1, report = qr_transport.reassemble_chunks(
            payloads,
            artifact_id=artifact_id,
            image_count=int(scan_meta.get("image_count") or 0),
            bad_images=bad_images,
        )
    except qr_transport.QrReassemblyError as exc:
        report = _parse_reassembly_error(exc)
        return _case_result_from_reassembly(
            case_name=case_name,
            case_dir=case_dir,
            corpus=corpus,
            scan_meta=scan_meta,
            report=report,
            quality_records=quality_records,
            complete=False,
            expected_sha256=expected_sha256,
            sox1=None,
        )

    return _case_result_from_reassembly(
        case_name=case_name,
        case_dir=case_dir,
        corpus=corpus,
        scan_meta=scan_meta,
        report=report,
        quality_records=quality_records,
        complete=True,
        expected_sha256=expected_sha256,
        sox1=sox1,
    )


def build_report(
    *,
    corpus: Path,
    expected_sox1: Optional[str] = None,
    artifact_id: Optional[str] = None,
) -> dict[str, object]:
    expected_sha256 = qr_transport.sox1_sha256(expected_sox1) if expected_sox1 else None
    expected_artifact_id = qr_transport.artifact_id_for_sox1(expected_sox1) if expected_sox1 else None
    case_dirs = _case_image_dirs(corpus)
    cases = [
        _evaluate_case(
            case_name=case_name,
            case_dir=case_dir,
            corpus=Path(corpus),
            artifact_id=artifact_id,
            expected_sha256=expected_sha256,
        )
        for case_name, case_dir in case_dirs
    ]
    case_count = len(cases)
    successful_cases = sum(1 for case in cases if bool(case.get("success")))
    complete_cases = sum(1 for case in cases if bool(case.get("complete")))
    expected_matches = sum(1 for case in cases if case.get("expected_match") is True)
    failed_cases = case_count - successful_cases
    total_images = sum(int(case.get("image_count") or 0) for case in cases)
    total_bad_images = sum(len(case.get("bad_images") or []) for case in cases)

    return {
        "schema": REPORT_SCHEMA,
        "success": failed_cases == 0,
        "corpus": str(corpus),
        "case_count": case_count,
        "successful_cases": successful_cases,
        "complete_cases": complete_cases,
        "failed_cases": failed_cases,
        "expected_sox1_sha256": expected_sha256,
        "expected_artifact_id": expected_artifact_id,
        "artifact_id_filter": artifact_id,
        "robustness": {
            "success_rate": round(successful_cases / float(case_count), 4) if case_count else 0.0,
            "complete_rate": round(complete_cases / float(case_count), 4) if case_count else 0.0,
            "expected_match_rate": (
                round(expected_matches / float(case_count), 4)
                if case_count and expected_sha256 is not None
                else None
            ),
            "total_images": total_images,
            "total_bad_images": total_bad_images,
        },
        "cases": cases,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    expected_sox1: Optional[str] = None
    if args.expected_sox1_file:
        expected_sox1 = crypto_envelope.read_sox1_string(
            input_string_file=Path(args.expected_sox1_file)
        )
        if not expected_sox1.startswith(crypto_envelope.SOX1_PREFIX):
            parser.error("--expected-sox1-file must contain a SOX1 string")

    try:
        report = build_report(
            corpus=Path(args.corpus),
            expected_sox1=expected_sox1,
            artifact_id=args.artifact_id,
        )
    except RuntimeError as exc:
        print("capture corpus optional dependency error: {0}".format(exc), file=sys.stderr)
        return 40
    except (OSError, image_scan.ImageScanError) as exc:
        print("capture corpus file/input error: {0}".format(exc), file=sys.stderr)
        return 30

    if args.output:
        output = qr_transport.write_json_atomic(Path(args.output), report)
        print("capture_corpus_report={0}".format(output))
        print("success={0}".format(str(bool(report.get("success"))).lower()))
        print("case_count={0}".format(report.get("case_count")))
        print("failed_cases={0}".format(report.get("failed_cases")))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))

    return 0 if bool(report.get("success")) else 20


if __name__ == "__main__":
    raise SystemExit(main())
