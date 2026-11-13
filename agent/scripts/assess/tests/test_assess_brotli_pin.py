"""The assess CLI's brotli pin matches the backend dev environment its tests run in.

The CLI decodes brotli-encoded stored responses on the host (``lib/stored_responses.py``)
with the ``brotli`` distribution its PEP 723 header pins; the backend dev extra mirrors
the pin so the test environment exercises the same decoder.
"""
from __future__ import annotations

import re
import tomllib
from importlib.metadata import version
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[4]


def test_brotli_pin_matches_across_the_cli_header_and_backend_dev_extra():
    header = (_REPO_ROOT / "agent" / "scripts" / "assess.py").read_text(encoding="utf-8")
    cli_pins = dict(re.findall(r'^#\s+"(brotli)==([^"=<>]+)",$', header, re.M))
    backend = tomllib.loads(
        (_REPO_ROOT / "orchestrator" / "backend" / "pyproject.toml").read_text(encoding="utf-8")
    )
    backend_pins = dict(
        dependency.split("==", 1)
        for dependency in backend["project"]["optional-dependencies"]["dev"]
        if dependency.startswith("brotli==")
    )

    assert cli_pins.get("brotli")
    assert backend_pins == cli_pins
    assert version("brotli") == cli_pins["brotli"]
