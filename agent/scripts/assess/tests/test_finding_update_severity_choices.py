"""`finding update --severity` accepts only the severity vocabulary, in any case."""
from __future__ import annotations

import argparse

import pytest

from assess.commands import update_finding
from assess.lib.contracts import FINDING_SEVERITIES


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    update_finding.register(parser.add_subparsers(dest="action"))
    return parser


@pytest.mark.parametrize("value", ["moderate", "severe", "p1", ""])
def test_update_severity_refuses_a_value_outside_the_vocabulary(value, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        _parser().parse_args(["update", "VA-001", "--severity", value])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "--severity" in err
    assert all(severity in err for severity in FINDING_SEVERITIES)


@pytest.mark.parametrize(("value", "expected"), [("HIGH", "high"), ("Critical", "critical"), ("info", "info")])
def test_update_severity_resolves_any_case_to_the_canonical_band(value, expected) -> None:
    args = _parser().parse_args(["update", "VA-001", "--severity", value])

    assert args.severity == expected
