"""Drift guards for the coverage/probe recording verbs.

These live in the backend suite (not the assess-CLI suite) because they need BOTH
`app.*` (the backend CoverageStatus enum) and `assess.*` (the CLI verbs +
contracts) importable, which only the backend venv provides. They fail loudly if:

1. the CLI's mirrored coverage-status list drifts from the backend enum,
2. cli.py stops registering `record-probe` / `resolve` (the merged verbs),
3. the "no raw fallback" redirect for probe-runs / coverage-items is removed,
4. the probe-attempt read (`coverage --attempts`, folded-in list-attempts) is
   removed.
"""
from __future__ import annotations

import argparse


def _cli_registered_commands() -> set[str]:
    """The top-level commands the whole `vigil assess` parser tree registers."""
    from assess import cli

    parser = cli._build_parser(None, [])
    (commands,) = (
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    return set(commands.choices)


def test_coverage_statuses_mirror_backend_enum() -> None:
    """resolve's coverage-item status list must equal backend CoverageStatus."""
    from app.services.state_manager.coverage import CoverageStatus
    from assess.commands import resolve

    backend = {s.value for s in CoverageStatus}
    assert set(resolve._COVERAGE_STATUSES) == backend, (
        "resolve _COVERAGE_STATUSES drifted from backend CoverageStatus"
    )


def test_surface_statuses_mirror_backend_enum() -> None:
    """lib/surfaces.py's status sets must equal backend SurfaceStatus.

    ``VALID_STATUSES`` mirrors the full ``SurfaceStatus`` vocabulary and
    ``RESOLVABLE_STATUSES`` mirrors ``SURFACE_RESOLUTION_STATUSES`` (the full
    set minus the ``discovered`` seed state). The CLI cannot import the backend,
    so this guard fails loudly if either mirror drifts.
    """
    from app.services.state_manager.coverage import (
        SURFACE_RESOLUTION_STATUSES,
        SurfaceStatus,
    )
    from assess.lib import surfaces

    assert surfaces.VALID_STATUSES == {s.value for s in SurfaceStatus}, (
        "surfaces.VALID_STATUSES drifted from backend SurfaceStatus"
    )
    assert surfaces.RESOLVABLE_STATUSES == {s.value for s in SURFACE_RESOLUTION_STATUSES}, (
        "surfaces.RESOLVABLE_STATUSES drifted from backend SURFACE_RESOLUTION_STATUSES"
    )


def test_surface_create_statuses_match_the_backend_create_contract() -> None:
    """record-surface must not advertise update-only lifecycle values."""
    from assess.lib import surfaces

    assert surfaces.CREATABLE_STATUSES == {
        "covered",
        "deferred",
        "discovered",
        "not_applicable",
    }


def test_cli_registers_merged_probe_coverage_verbs() -> None:
    registered = _cli_registered_commands()
    for cmd in ("record-probe", "resolve"):
        assert cmd in registered, f"`vigil assess {cmd}` is not registered"


def test_raw_probe_and_coverage_paths_are_redirected() -> None:
    """No fallback: raw POST probe-runs / PATCH coverage-items/{id} must redirect."""
    from assess.lib import contracts

    post_err = contracts.raw_endpoint_error("POST", "probe-runs", {})
    assert post_err and "record-probe" in post_err

    patch_err = contracts.raw_endpoint_error("PATCH", "coverage-items/42", {})
    assert patch_err and "resolve coverage-item" in patch_err


def test_probe_coverage_verbs_have_contracts() -> None:
    from assess.lib import contracts

    for name in ("record-probe", "resolve"):
        assert contracts.get_contract(name) is not None, f"missing CommandContract for {name}"


def test_attempts_read_folded_into_coverage() -> None:
    """A4a: the probe-attempt read (former list-attempts) is now `coverage
    --attempts` — `coverage` must stay registered and its contract must document
    the --attempts view."""
    assert "coverage" in _cli_registered_commands(), (
        "`vigil assess coverage` is not registered"
    )
    from assess.lib import contracts

    contract = contracts.get_contract("coverage")
    assert contract is not None
    blob = " ".join(contract.summary.split()) + " " + " ".join(contract.notes)
    assert "--attempts" in blob, "coverage contract no longer documents the --attempts read"
