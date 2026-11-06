"""`--inherited-from` reaches the whole read it is pointed at, and says so.

``GET code/coverage/inherited`` accepts ``path_prefix`` alongside ``limit`` and
``offset``, but the CLI refused ``--path-prefix`` beside ``--inherited-from``
and documented all three as ``--by-path`` options. On a large repository that
left the inherited read unnarrowable — the one read whose whole purpose is to
find the already-reviewed files inside a directory an operator is about to
re-queue — and the flag help pointed at the wrong view while the flags
themselves worked.
"""
from __future__ import annotations

import argparse
from types import SimpleNamespace
from urllib.parse import parse_qsl

import pytest

from assess.commands import code_coverage

# The flags the inherited read and the by-path view BOTH honour, and so must
# both be documented for.
_SHARED_VIEW_FLAGS = ("--path-prefix", "--limit", "--offset", "--json")


def _args(**overrides) -> SimpleNamespace:
    """A complete `code-coverage --inherited-from` namespace, as `run` sees it."""
    base = {
        "engagement_dir": "",
        "repo_id": None,
        "inherited_from": 7,
        "by_path": False,
        "depth": None,
        "path_prefix": None,
        "limit": None,
        "offset": None,
        "as_json": False,
        "cwe_matrix": False,
        "require_gate_pass": False,
        "require_transition_ready": None,
        "debt_paths": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _coverage_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    code_coverage.register(subparsers)
    return subparsers.choices["code-coverage"]


def _flag_help(flag: str) -> str:
    action = next(
        action
        for action in _coverage_parser()._actions
        if flag in action.option_strings
    )
    return action.help or ""


def test_the_inherited_read_can_be_narrowed_by_path_prefix() -> None:
    """The endpoint takes `path_prefix`; the flag that spells it is admitted."""
    args = _args(path_prefix=["src/web", "src/auth"], limit=25, offset=50)

    code_coverage._refuse_misplaced_by_path_options(args)

    path, _separator, query = code_coverage._inherited_endpoint(args).partition("?")
    assert path == "code/coverage/inherited"
    assert parse_qsl(query) == [
        ("generation", "7"),
        ("path_prefix", "src/auth"),
        ("path_prefix", "src/web"),
        ("limit", "25"),
        ("offset", "50"),
    ]


def test_depth_remains_a_by_path_only_grouping_flag() -> None:
    """`--depth` groups directories, which the inherited file list has no rows for."""
    with pytest.raises(SystemExit) as excinfo:
        code_coverage._refuse_misplaced_by_path_options(_args(depth=3))

    assert excinfo.value.code == 2


def test_a_view_flag_passed_with_neither_view_names_both_views() -> None:
    """The refusal has to name every view that honours the flag, or it misdirects."""
    with pytest.raises(SystemExit) as excinfo:
        code_coverage._refuse_misplaced_by_path_options(
            _args(inherited_from=None, limit=10)
        )

    assert excinfo.value.code == 2


@pytest.mark.parametrize("flag", _SHARED_VIEW_FLAGS)
def test_each_shared_flag_documents_the_inherited_read_it_serves(flag: str) -> None:
    """Help that names only `--by-path` is help for a surface the flag outgrew."""
    help_text = _flag_help(flag)

    assert "--inherited-from" in help_text, (
        f"{flag} is honoured by --inherited-from but its help names only: "
        f"{help_text!r}"
    )


def test_every_query_parameter_the_inherited_read_sends_is_declared() -> None:
    """A parameter the route does not declare is SILENTLY dropped by FastAPI.

    Mounting the router on a throwaway app and reading its OpenAPI document is
    how ``test_fetch_route_catalog`` holds the paging tables to the real routes;
    the same probe is what keeps a CLI flag from becoming a query string the
    backend ignores. The assess suite runs on the backend venv, so the router
    is importable here.
    """
    from fastapi import FastAPI

    from app.api.code_analysis import router as code_analysis_router

    probe = FastAPI()
    probe.include_router(code_analysis_router)
    inherited = next(
        operations["get"]
        for path, operations in probe.openapi()["paths"].items()
        if path.endswith("/coverage/inherited") and "get" in operations
    )
    declared = {parameter["name"] for parameter in inherited.get("parameters", ())}

    sent = {
        key
        for key, _value in parse_qsl(
            code_coverage._inherited_endpoint(
                _args(repo_id=3, path_prefix=["src/auth"], limit=25, offset=50)
            ).partition("?")[2]
        )
    }

    assert sent <= declared, (
        "the inherited read sends query parameters the route does not declare, "
        f"so the backend ignores them: {sorted(sent - declared)}"
    )
    assert "path_prefix" in declared
