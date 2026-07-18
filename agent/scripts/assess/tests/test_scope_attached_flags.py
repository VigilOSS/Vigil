"""Regression: Go/pflag-style attached option values (`-u=x`, `-l=list.txt`)
must be extracted as target tokens before scope enforcement, exactly like their
space-separated (`-u x`) equivalents. Otherwise `raw_targets` stays empty and an
out-of-scope / no-fire target slips past `enforce_execution_policy` unchecked.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from assess.lib import scope


def _tokens(cmd, tool, tmp_path: Path):
    return scope._command_target_tokens(
        cmd, tool_name=tool, engagement_dir=tmp_path, engagement_key="eng-1"
    )


@pytest.mark.parametrize("tool", ["httpx", "nuclei", "sqlmap", "ffuf"])
def test_attached_direct_target_flag_is_extracted(tool, tmp_path):
    attached = _tokens([tool, "-u=https://evil.test"], tool, tmp_path)
    spaced = _tokens([tool, "-u", "https://evil.test"], tool, tmp_path)
    assert "https://evil.test" in attached
    assert attached == spaced


def test_attached_long_target_flag_is_extracted(tmp_path):
    assert "https://evil.test" in _tokens(
        ["nuclei", "--target=https://evil.test"], "nuclei", tmp_path
    )


def test_attached_list_flag_reads_the_target_file(tmp_path):
    (tmp_path / "targets.txt").write_text(
        "https://in.test\nhttps://evil.test\n", encoding="utf-8"
    )
    tokens = _tokens(["httpx", "-l=targets.txt"], "httpx", tmp_path)
    assert tokens == ["https://in.test", "https://evil.test"]


def test_attached_list_flag_missing_file_is_rejected(tmp_path):
    with pytest.raises(scope.ScopePolicyError):
        _tokens(["nuclei", "-list=absent.txt"], "nuclei", tmp_path)
