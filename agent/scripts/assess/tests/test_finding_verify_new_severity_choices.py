"""`finding verify --new-severity` accepts only the severity vocabulary, in any case."""
from __future__ import annotations

import argparse

import pytest

from assess.commands import verify_finding
from assess.lib.contracts import FINDING_SEVERITIES


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    verify_finding.register(parser.add_subparsers(dest="action"))
    return parser


@pytest.mark.parametrize("value", ["moderate", "severe", "p1", ""])
def test_verify_new_severity_refuses_a_value_outside_the_vocabulary(value, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        _parser().parse_args(
            ["verify", "VA-001", "--status", "downgraded", "--new-severity", value]
        )

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "--new-severity" in err
    assert all(severity in err for severity in FINDING_SEVERITIES)


@pytest.mark.parametrize(("value", "expected"), [("LOW", "low"), ("Medium", "medium"), ("info", "info")])
def test_verify_new_severity_resolves_any_case_to_the_canonical_band(value, expected) -> None:
    args = _parser().parse_args(
        ["verify", "VA-001", "--status", "downgraded", "--new-severity", value]
    )

    assert args.new_severity == expected


def test_verify_without_new_severity_leaves_it_unset() -> None:
    args = _parser().parse_args(["verify", "VA-001", "--status", "confirmed"])

    assert args.new_severity is None
