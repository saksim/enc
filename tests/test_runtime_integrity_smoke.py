#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for P0-B6 runtime integrity smoke."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_runtime_integrity_smoke_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/smoke_runtime_integrity.py"],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "RUNTIME_INTEGRITY_SMOKE_PASSED" in result.stdout
    assert "check=happy_path passed" in result.stdout
    assert "check=runtime_replaced failed_closed" in result.stdout
    assert "check=manifest_tampered failed_closed" in result.stdout
    assert "check=digest_mismatch failed_closed" in result.stdout
