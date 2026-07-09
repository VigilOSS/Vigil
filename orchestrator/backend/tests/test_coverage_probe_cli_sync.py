"""Drift guards for the WS1 coverage/probe recording verbs.

These live in the backend suite (not the assess-CLI suite) because they need BOTH
`app.*` (the backend CoverageStatus enum) and `assess.*` (the CLI verbs +
contracts) importable, which only the backend venv provides. They fail loudly if:

1. the CLI's mirrored coverage-status list drifts from the backend enum,
2. cli.py stops registering `record-probe` / `resolve-coverage-item`,
3. the "no raw fallback" redirect for probe-runs / coverage-items is removed.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI_PATH = REPO_ROOT / "agent" / "scripts" / "assess" / "cli.py"


def _cli_imported_commands() -> set[str]:
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "assess.commands":
            imported.update(alias.name for alias in node.names)
    return imported


def _cli_registered_commands() -> set[str]:
    """Names iterated by the `for mod in (...)` register loop(s) in cli.py.

    A command in the import block but omitted from the register loop is a silent
    bug (imported, never wired) — so the drift guard must check BOTH, not just
    imports.
    """
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    registered: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.For) and isinstance(node.iter, (ast.Tuple, ast.List)):
            registered.update(
                elt.id for elt in node.iter.elts if isinstance(elt, ast.Name)
            )
    return registered


def test_coverage_statuses_mirror_backend_enum() -> None:
    """resolve-coverage-item's status list must equal backend CoverageStatus."""
    from app.services.state_manager.coverage import CoverageStatus
    from assess.commands import resolve_coverage_item

    backend = {s.value for s in CoverageStatus}
    assert set(resolve_coverage_item.COVERAGE_STATUSES) == backend, (
        "resolve-coverage-item COVERAGE_STATUSES drifted from backend CoverageStatus"
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


def test_cli_registers_new_probe_coverage_verbs() -> None:
    imported = _cli_imported_commands()
    registered = _cli_registered_commands()
    for cmd in ("record_probe", "resolve_coverage_item"):
        assert cmd in imported, f"{cmd} not imported in cli.py 'from assess.commands import ...' block"
        assert cmd in registered, f"{cmd} imported but missing from the cli.py 'for mod in (...)' register loop"


def test_raw_probe_and_coverage_paths_are_redirected() -> None:
    """No fallback: raw POST probe-runs / PATCH coverage-items/{id} must redirect."""
    from assess.lib import contracts

    post_err = contracts.raw_endpoint_error("POST", "probe-runs", {})
    assert post_err and "record-probe" in post_err and "record-attempt" in post_err

    patch_err = contracts.raw_endpoint_error("PATCH", "coverage-items/42", {})
    assert patch_err and "resolve-coverage-item" in patch_err


def test_probe_coverage_verbs_have_contracts() -> None:
    from assess.lib import contracts

    for name in ("record-probe", "resolve-coverage-item"):
        assert contracts.get_contract(name) is not None, f"missing CommandContract for {name}"


def test_cli_registers_list_attempts() -> None:
    """A4a: `list-attempts` (read side of the probe-recording verbs) must be
    BOTH imported and wired into the register loop in cli.py."""
    imported = _cli_imported_commands()
    registered = _cli_registered_commands()
    assert "list_attempts" in imported, (
        "list_attempts not imported in cli.py 'from assess.commands import ...' block"
    )
    assert "list_attempts" in registered, (
        "list_attempts imported but missing from the cli.py 'for mod in (...)' register loop"
    )


def test_list_attempts_has_contract() -> None:
    """The anti-drift rule: a registered command must carry a CommandContract so
    `vigil assess contract list-attempts` stays accurate."""
    from assess.lib import contracts

    assert contracts.get_contract("list-attempts") is not None, (
        "missing CommandContract for list-attempts"
    )
