"""Every route the CLI pages through declares the keys the pager sends.

Every backend GET refuses a query key it does not declare (HTTP 400), and
``AssessmentClient.get_all_pages`` appends ``limit`` and ``offset`` to the
endpoint it walks. A call site that pages a route without those params, or
that adds a filter key the route does not read, fails on its first page. The
call sites are read from the CLI source and checked against the live route
table, so a new pager call or a route change is held to the same rule.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from test_fetch_route_catalog import _backend_assessment_get_routes

_ASSESS_ROOT = Path(__file__).resolve().parents[1]
_PAGER_NAMES = {"get_all_pages", "_get_all_pages"}
_QUERY_KEY_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]*)=")
# Pager calls whose endpoint is the caller's argument rather than a literal.
# `fetch` pages only routes in its own paging tables, which
# test_fetch_route_catalog checks against the same route table.
_DYNAMIC_ENDPOINTS = {("commands/fetch.py", "paged_endpoint")}


def _module_constants(tree: ast.Module) -> dict[str, str]:
    return {
        target.id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        for target in node.targets if isinstance(target, ast.Name)
    }


def _endpoint(node: ast.expr, constants: dict[str, str]) -> tuple[str, set[str]] | None:
    """The literal path and the query keys an endpoint expression sends."""
    if isinstance(node, ast.Name) and node.id in constants:
        node = ast.Constant(constants[node.id])
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        text, keys = node.value, set()
    elif isinstance(node, ast.JoinedStr):
        text, keys = "", set()
        for part in node.values:
            if isinstance(part, ast.Constant):
                text += str(part.value)
                continue
            value = part.value
            if (
                isinstance(value, ast.Call) and getattr(value.func, "id", "") == "urlencode"
                and value.args and isinstance(value.args[0], ast.Dict)
            ):
                keys.update(
                    key.value for key in value.args[0].keys if isinstance(key, ast.Constant)
                )
            text += "{}"
    else:
        return None
    path, _sep, query = text.partition("?")
    keys.update(_QUERY_KEY_RE.findall("?" + query) if query else ())
    return path.strip("/"), keys


def _pager_calls() -> list[tuple[str, int, ast.Call, dict[str, str]]]:
    calls = []
    for source in sorted(_ASSESS_ROOT.rglob("*.py")):
        relative = source.relative_to(_ASSESS_ROOT).as_posix()
        if relative.startswith("tests/"):
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        constants = _module_constants(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name in _PAGER_NAMES and node.args:
                calls.append((relative, node.lineno, node, constants))
    return calls


def test_every_paged_cli_read_sends_only_keys_its_route_declares() -> None:
    routes = _backend_assessment_get_routes()
    problems: list[str] = []
    checked = 0
    for relative, line, call, constants in _pager_calls():
        # `_get_all_pages(client, endpoint)` wrappers take the client first.
        endpoint_arg = call.args[-1] if getattr(call.func, "id", "") == "_get_all_pages" else call.args[0]
        if isinstance(endpoint_arg, ast.Name) and (relative, endpoint_arg.id) in _DYNAMIC_ENDPOINTS:
            continue
        resolved = _endpoint(endpoint_arg, constants)
        if resolved is None:
            problems.append(f"{relative}:{line}: endpoint is not a literal this check can read")
            continue
        path, keys = resolved
        declared = routes.get(path)
        if declared is None:
            problems.append(f"{relative}:{line}: {path} is not a backend assessment GET route")
            continue
        unknown = sorted((keys | {"limit", "offset"}) - set(declared))
        if unknown:
            problems.append(f"{relative}:{line}: {path} does not declare {', '.join(unknown)}")
        page_size = next(
            (kw.value.value for kw in call.keywords
             if kw.arg == "page_size" and isinstance(kw.value, ast.Constant)),
            5000,
        )
        maximum = declared.get("limit", {}).get("maximum")
        if maximum is not None and page_size > maximum:
            problems.append(f"{relative}:{line}: page_size {page_size} > {path} limit {maximum}")
        checked += 1

    assert checked, "no pager call sites found; the scan no longer sees the CLI source"
    assert not problems, "\n".join(problems)
