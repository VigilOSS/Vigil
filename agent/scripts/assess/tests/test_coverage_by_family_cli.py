"""`coverage --by-family` / `--for-dispatch`: the grid read either succeeds or fails loudly.

A failed or malformed backend read must never render as an empty grid: "(no
application-units recorded yet)" is a statement about the engagement, and an
operator pasting a `--for-dispatch` block into a specialist prompt would hand
over "treat the whole surface as open" for an engagement that is already
mapped. `--for-dispatch` asks the backend for the one host/prefix it renders,
so the backend scopes the grid instead of building every unit's row.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from _fake_client import StubClient
from assess.commands import coverage as coverage_cmd
from assess.lib.client import AssessError
from assess.lib.config import Config

_UNIT = {
    "application_unit_id": 7,
    "host": "app.example.com",
    "port_class": "web",
    "path_prefix": "/api",
    "deep_required": True,
    "families": [
        {
            "family": "injection",
            "expected_reason": "endpoint carries params",
            "status": "covered",
            "probe_count": 2,
            "covering_probe_count": 1,
            "has_finding": False,
            "finding_id": None,
        },
        {
            "family": "access-control",
            "expected_reason": "id-bearing params",
            "status": "missing_block",
            "probe_count": 0,
            "covering_probe_count": 0,
            "has_finding": False,
            "finding_id": None,
        },
    ],
}


class _GridClient(StubClient):
    def __init__(self, response):
        self.response = response
        self.reads: list[str] = []

    def get(self, endpoint: str):
        self.reads.append(endpoint)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _args(**over) -> SimpleNamespace:
    base = dict(
        engagement_dir="eng", attempts=False, by_family=False, for_dispatch=False,
        host="", path_prefix="", as_json=False,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _install(monkeypatch, client: _GridClient) -> None:
    monkeypatch.setattr(
        coverage_cmd, "load_config",
        lambda _flag: Config(
            base_url="http://127.0.0.1:18000",
            engagement_dir="eng",
            engagement_key="eng",
            agent_root="agent",
        ),
    )
    monkeypatch.setattr(coverage_cmd, "AssessmentClient", lambda *a, **k: client)


@pytest.mark.parametrize(
    "mode",
    [
        {"by_family": True},
        {"by_family": True, "as_json": True},
        {"for_dispatch": True, "host": "app.example.com"},
        {"for_dispatch": True, "host": "app.example.com", "as_json": True},
    ],
)
def test_failed_grid_read_exits_non_zero_without_rendering(monkeypatch, capsys, mode):
    _install(monkeypatch, _GridClient(AssessError("read timed out")))

    with pytest.raises(AssessError) as raised:
        coverage_cmd.run(_args(**mode))

    assert "coverage-readiness/by-family" in str(raised.value)
    assert "read timed out" in str(raised.value)
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("payload", [[], {"units": "nope", "totals": {}}, {"units": []}])
def test_malformed_grid_payload_exits_non_zero(monkeypatch, capsys, payload):
    _install(monkeypatch, _GridClient(payload))

    with pytest.raises(AssessError) as raised:
        coverage_cmd.run(_args(by_family=True))

    assert "malformed" in str(raised.value)
    assert capsys.readouterr().out == ""


def test_for_dispatch_asks_the_backend_for_its_host_and_prefix(monkeypatch, capsys):
    client = _GridClient({
        "scope": {"host": "app.example.com", "path_prefix": "/api"},
        "units": [_UNIT],
        "totals": {"units": 1},
    })
    _install(monkeypatch, client)

    coverage_cmd.run(_args(for_dispatch=True, host="App.Example.com", path_prefix="/api"))

    assert client.reads == [
        "coverage-readiness/by-family?host=App.Example.com&path_prefix=%2Fapi"
    ]
    out = capsys.readouterr().out
    assert "unit app.example.com/api [deep-required]" in out
    assert "covered: injection" in out
    assert "OPEN gaps: access-control" in out


def test_for_dispatch_json_keeps_its_scoped_shape_and_totals(monkeypatch, capsys):
    client = _GridClient({
        "scope": {"host": "app.example.com", "path_prefix": None},
        "units": [_UNIT],
        "totals": {"units": 1},
    })
    _install(monkeypatch, client)

    coverage_cmd.run(_args(for_dispatch=True, host="app.example.com", as_json=True))

    assert client.reads == ["coverage-readiness/by-family?host=app.example.com"]
    # The totals are the backend's own for the scoped read, so a consumer of the
    # JSON sees how many units and cells the block summarises.
    assert json.loads(capsys.readouterr().out) == {
        "scope": {"host": "app.example.com", "path_prefix": None},
        "units": [_UNIT],
        "totals": {"units": 1},
    }


def test_by_family_reads_the_whole_grid(monkeypatch, capsys):
    client = _GridClient({"units": [_UNIT], "totals": {"units": 1, "cells": 2}})
    _install(monkeypatch, client)

    coverage_cmd.run(_args(by_family=True, as_json=True))

    assert client.reads == ["coverage-readiness/by-family"]
    assert json.loads(capsys.readouterr().out)["units"] == [_UNIT]


def test_by_family_asks_the_backend_for_the_host_and_prefix_it_was_given(monkeypatch, capsys):
    client = _GridClient({"units": [_UNIT], "totals": {}})
    _install(monkeypatch, client)

    coverage_cmd.run(_args(by_family=True, host="app.example.com", path_prefix="/api"))

    assert client.reads == ["coverage-readiness/by-family?host=app.example.com&path_prefix=%2Fapi"]


@pytest.mark.parametrize(
    ("mode", "flag"),
    [({}, "--host"), ({}, "--path-prefix"), ({"attempts": True}, "--path-prefix")],
)
def test_a_scope_flag_a_view_cannot_apply_is_refused(monkeypatch, capsys, mode, flag):
    _install(monkeypatch, _GridClient({"units": [], "totals": {}}))
    scoped = {"--host": {"host": "app.example.com"}, "--path-prefix": {"path_prefix": "/api"}}[flag]

    with pytest.raises(SystemExit) as exited:
        coverage_cmd.run(_args(**mode, **scoped))

    assert exited.value.code == 2
    err = capsys.readouterr().err
    assert flag in err and "--by-family" in err
