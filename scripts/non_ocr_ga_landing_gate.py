#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CLI wrapper for the non-OCR GA landing gate."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from enc2sop.ga_landing import run_ga_landing_gate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify non-OCR GA landing evidence and promotion bundle integrity.")
    parser.add_argument("--smoke-report", help="Path to non_ocr_ga_governance_smoke_report.json.")
    parser.add_argument("--promotion-bundle", help="Path to promotion_artifact_bundle.zip. Defaults to smoke report value.")
    parser.add_argument("--expected-bundle-sha256", help="Optional expected sha256 for promotion_artifact_bundle.zip.")
    parser.add_argument("--report", help="Optional JSON report output path.")
    parser.add_argument(
        "--allow-rotation-not-requested",
        action="store_true",
        help="Do not require rotation_rehearsal_report.status=passed. GA release workflows should not use this.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report_path, report = run_ga_landing_gate(
        smoke_report_file=args.smoke_report,
        promotion_artifact_bundle_file=args.promotion_bundle,
        expected_bundle_sha256=args.expected_bundle_sha256,
        report_file=args.report,
        require_rotation_pass=not args.allow_rotation_not_requested,
        repo_root=REPO_ROOT,
    )
    if report_path is not None:
        print("non_ocr_ga_landing_gate_report={0}".format(report_path))
    print("promotion_artifact_bundle={0}".format(report.get("promotion_artifact_bundle_file")))
    print("promotion_artifact_bundle_sha256={0}".format(report.get("promotion_artifact_bundle_sha256")))
    summary = report.get("summary") or {}
    print("license_file_e2e_passed={0}".format(bool(summary.get("license_file_e2e_passed"))))
    print("reverse_cost_check_passed={0}".format(bool(summary.get("reverse_cost_check_passed"))))
    if report.get("passed"):
        print("NON_OCR_GA_LANDING_GATE_OK")
        return 0
    failures = report.get("failures") or []
    print("NON_OCR_GA_LANDING_GATE_FAILED failures={0}".format(len(failures)))
    for failure in failures:
        print("failure={0}".format(failure))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
