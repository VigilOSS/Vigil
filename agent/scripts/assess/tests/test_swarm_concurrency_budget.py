"""`agent start-swarm` warns when a swarm would exceed the client's subagent budget.

A native client runs a bounded number of subagents at once (Claude Code: 20).
Rows past that budget are recorded and launched, but their specialists queue
inside the client, so the swarm's wall-clock and the operator's expectation of
it diverge silently. The warning is advisory: the rows are still recorded.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from assess.commands import agent
from test_cli_canonical_shapes import _agent_parser, _DispatchClient


class _BusyClient(_DispatchClient):
    def __init__(self, in_progress: int) -> None:
        self.in_progress = in_progress
        self.filters: list[dict] = []
        self.recorded = 0

    def list_dispatches(self, **filters) -> list[dict]:
        self.filters.append(filters)
        if filters.get("status") != "in-progress":
            return []
        return [{"agent_id": f"busy-{i}", "status": "in-progress"} for i in range(self.in_progress)]

    def record_dispatch(self, payload: dict) -> dict:
        self.recorded += 1
        return super().record_dispatch(payload)


def _run(monkeypatch, tmp_path, *, workers: int, in_progress: int) -> _BusyClient:
    items = tmp_path / "items.txt"
    items.write_text("\n".join(f"item-{i}" for i in range(workers)), encoding="utf-8")
    args = _agent_parser().parse_args([
        "agent", "start-swarm", "--role", "code-vuln-hunter",
        "--task", "review assigned files", "--workers", str(workers),
        "--batch-size", "1", "--items-file", str(items), "--no-target-traffic",
    ])
    client = _BusyClient(in_progress)
    monkeypatch.setattr(
        agent.dispatch, "_client_for",
        lambda _args: (client, SimpleNamespace(engagement_dir=str(tmp_path))),
    )
    monkeypatch.setattr(agent, "_attach_dispatch_provenance", lambda *_args: [])
    monkeypatch.setattr(agent, "_code_source_identity_lines", lambda *_args, **_kwargs: [])
    agent._start_swarm(args)
    return client


def _budget_warnings(err: str) -> list[str]:
    return [line for line in err.splitlines() if "concurrency budget" in line]


def test_a_swarm_past_the_default_budget_warns_and_still_records_every_row(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.delenv("VIGIL_CLIENT_CONCURRENCY_BUDGET", raising=False)
    client = _run(monkeypatch, tmp_path, workers=12, in_progress=10)
    captured = capsys.readouterr()
    warnings = _budget_warnings(captured.err)
    assert len(warnings) == 1
    assert "12" in warnings[0] and "10" in warnings[0] and "20" in warnings[0]
    assert "VIGIL_CLIENT_CONCURRENCY_BUDGET" in warnings[0]
    assert client.recorded == 12
    assert len(json.loads(captured.out.splitlines()[0])["swarm"]) == 12


def test_a_swarm_within_the_budget_is_silent(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("VIGIL_CLIENT_CONCURRENCY_BUDGET", raising=False)
    _run(monkeypatch, tmp_path, workers=10, in_progress=10)
    assert _budget_warnings(capsys.readouterr().err) == []


def test_the_budget_is_configurable_from_the_environment(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VIGIL_CLIENT_CONCURRENCY_BUDGET", "40")
    _run(monkeypatch, tmp_path, workers=12, in_progress=10)
    assert _budget_warnings(capsys.readouterr().err) == []


def test_the_budget_is_configurable_from_vigil_config(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("VIGIL_CLIENT_CONCURRENCY_BUDGET", raising=False)
    config = tmp_path / "vigil-config.json"
    config.write_text(json.dumps({"client.concurrency_budget": 8}), encoding="utf-8")
    monkeypatch.setenv("VIGIL_CONFIG", str(config))
    _run(monkeypatch, tmp_path, workers=5, in_progress=4)
    warnings = _budget_warnings(capsys.readouterr().err)
    assert len(warnings) == 1 and " 8" in warnings[0]


@pytest.mark.parametrize("value", ["zero", "0", "-3"])
def test_an_unusable_budget_value_falls_back_to_the_default_and_says_so(
    monkeypatch, tmp_path, capsys, value
):
    monkeypatch.setenv("VIGIL_CLIENT_CONCURRENCY_BUDGET", value)
    _run(monkeypatch, tmp_path, workers=12, in_progress=10)
    err = capsys.readouterr().err
    assert len(_budget_warnings(err)) == 1
    assert repr(value) in err


def test_an_unreadable_dispatch_listing_skips_the_advisory_and_records_the_swarm(
    monkeypatch, tmp_path, capsys
):
    class _NoListing(_BusyClient):
        def list_dispatches(self, **filters) -> list[dict]:
            raise RuntimeError("listing unavailable")

    items = tmp_path / "items.txt"
    items.write_text("a\nb\n", encoding="utf-8")
    args = _agent_parser().parse_args([
        "agent", "start-swarm", "--role", "code-vuln-hunter",
        "--task", "review assigned files", "--workers", "2",
        "--batch-size", "1", "--items-file", str(items), "--no-target-traffic",
    ])
    client = _NoListing(0)
    monkeypatch.setattr(
        agent.dispatch, "_client_for",
        lambda _args: (client, SimpleNamespace(engagement_dir=str(tmp_path))),
    )
    monkeypatch.setattr(agent, "_attach_dispatch_provenance", lambda *_args: [])
    monkeypatch.setattr(agent, "_code_source_identity_lines", lambda *_args, **_kwargs: [])
    agent._start_swarm(args)
    assert client.recorded == 2
    assert _budget_warnings(capsys.readouterr().err) == []


def test_an_unreadable_vigil_config_falls_back_to_the_default_and_records_the_swarm(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.delenv("VIGIL_CLIENT_CONCURRENCY_BUDGET", raising=False)
    config = tmp_path / "vigil-config.json"
    config.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("VIGIL_CONFIG", str(config))
    client = _run(monkeypatch, tmp_path, workers=12, in_progress=10)
    err = capsys.readouterr().err
    assert client.recorded == 12
    assert "client.concurrency_budget" in err and "20" in err


@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_budget_environment_value_counts_as_unset(monkeypatch, tmp_path, value):
    monkeypatch.setenv("VIGIL_CLIENT_CONCURRENCY_BUDGET", value)
    config = tmp_path / "vigil-config.json"
    config.write_text(json.dumps({"client.concurrency_budget": 8}), encoding="utf-8")
    monkeypatch.setenv("VIGIL_CONFIG", str(config))
    assert agent._client_concurrency_budget() == 8


class _PagedBusyClient(_BusyClient):
    """Honours limit/offset like the backend, so one page is not the whole set."""

    def list_dispatches(self, **filters) -> list[dict]:
        rows = super().list_dispatches(**{k: v for k, v in filters.items() if k == "status"})
        self.filters[-1] = filters
        offset = int(filters.get("offset") or 0)
        limit = int(filters.get("limit") or len(rows))
        return rows[offset:offset + limit]


def test_the_in_progress_count_reads_every_page(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("VIGIL_CLIENT_CONCURRENCY_BUDGET", raising=False)
    items = tmp_path / "items.txt"
    items.write_text("item-0", encoding="utf-8")
    args = _agent_parser().parse_args([
        "agent", "start-swarm", "--role", "code-vuln-hunter",
        "--task", "review assigned files", "--workers", "1",
        "--batch-size", "1", "--items-file", str(items), "--no-target-traffic",
    ])
    client = _PagedBusyClient(1005)
    monkeypatch.setattr(
        agent.dispatch, "_client_for",
        lambda _args: (client, SimpleNamespace(engagement_dir=str(tmp_path))),
    )
    monkeypatch.setattr(agent, "_attach_dispatch_provenance", lambda *_args: [])
    monkeypatch.setattr(agent, "_code_source_identity_lines", lambda *_args, **_kwargs: [])

    agent._start_swarm(args)

    [warning] = _budget_warnings(capsys.readouterr().err)
    assert "plus 1005 in-progress" in warning
