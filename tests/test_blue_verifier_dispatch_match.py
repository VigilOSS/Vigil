"""``vigil blue verify`` looks for an incident-verifier dispatch of the finding.

The dispatch names the finding in its structured ``finding_slugs`` list or as a
whole slug in its task. A slug that merely begins with the finding's (``VA-10``
for ``VA-1``) names a different finding and must not count.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from vigil_cli import blue


def _listing(monkeypatch: pytest.MonkeyPatch, rows: list[dict]) -> None:
    stdout = "".join(json.dumps(row) + "\n" for row in rows)
    monkeypatch.setattr(blue, "_build_assess_argv", lambda *_a: ["vigil", "assess"])
    monkeypatch.setattr(
        blue.subprocess, "run",
        lambda *_a, **_k: subprocess.CompletedProcess([], 0, stdout=stdout, stderr=""),
    )


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"agent_id": "IV-1", "task": "verify VA-1", "finding_slugs": []}, True),
        ({"agent_id": "IV-1", "task": "verify VA-1.", "finding_slugs": []}, True),
        ({"agent_id": "IV-1", "task": "triage", "finding_slugs": ["VA-1"]}, True),
        ({"agent_id": "IV-1", "task": "verify VA-10", "finding_slugs": []}, False),
        ({"agent_id": "IV-1", "task": "triage", "finding_slugs": ["VA-10"]}, False),
        ({"agent_id": "IV-VA-1x", "task": "verify XVA-1", "finding_slugs": []}, False),
    ],
)
def test_the_verifier_dispatch_names_the_exact_finding(
    monkeypatch, tmp_path: Path, row: dict, expected: bool
) -> None:
    _listing(monkeypatch, [row])

    assert blue._has_verifier_dispatch_for(tmp_path, tmp_path, "VA-1") is expected
