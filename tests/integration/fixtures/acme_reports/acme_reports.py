"""Acme report store: a tiny library whose supported API reads a stored report.

Integration fixture for the code-finding -> runtime-proof flow. ``read_report``
joins a caller-supplied name onto the report directory without containing it,
so ``../private/canary.txt`` escapes the store (CWE-22).
"""
from __future__ import annotations

from pathlib import Path

REPORT_ROOT = Path(__file__).resolve().parent / "reports"


def read_report(name: str) -> str:
    """Return the text of the stored report called ``name``."""
    return (REPORT_ROOT / name).read_text(encoding="utf-8")
