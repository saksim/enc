#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CLI wrapper for the V0.3 P0-B3 dist no-source-leakage check."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from enc2sop.protect.dist_check import run_dist_no_source_leak_check
from enc2sop.protect.dist_check import write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check a native dist directory for source/key leakage.")
    parser.add_argument("dist_dir", help="Release/native dist directory to inspect.")
    parser.add_argument(
        "--allow-py",
        action="append",
        default=None,
        help="Explicit allowed .py relative path or basename. __init__.py is always allowed.",
    )
    parser.add_argument(
        "--forbid-token",
        action="append",
        default=None,
        help="Additional source snippet or secret token that must not appear in dist files.",
    )
    parser.add_argument("--report", help="Optional JSON report output path.")
    parser.add_argument(
        "--scan-bytes-limit",
        type=int,
        default=2 * 1024 * 1024,
        help="Maximum bytes scanned per file for forbidden tokens.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_dist_no_source_leak_check(
        args.dist_dir,
        allowed_py=args.allow_py,
        forbidden_tokens=args.forbid_token,
        scan_bytes_limit=args.scan_bytes_limit,
    )
    if args.report:
        report_path = write_report(args.report, report)
        print("dist_leak_report={0}".format(report_path))
    issues = report.get("issues") or []
    if issues:
        print("DIST_NO_SOURCE_LEAK_FAILED issues={0}".format(len(issues)))
        for issue in issues:
            print("issue={code}:{relative_path}:{detail}".format(**issue))
        return 1
    print("DIST_NO_SOURCE_LEAK_OK dist_dir={0}".format(Path(args.dist_dir).expanduser().resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
