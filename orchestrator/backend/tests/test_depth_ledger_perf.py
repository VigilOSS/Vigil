"""Depth-ledger scaling regression.

The ledger used to be O(units x dispatches x probes): `_unit_ledger` re-scanned
the full `probes` list several times per unit, and `_dedicated_dispatch_satisfied`
re-scanned every probe per completed dispatch — so at ~900 probes the consume/verify
`--depth` gate and `app-unit depth-ledger` timed out. The fix buckets each unit's
mapped probes/coverage/findings ONCE and collapses dispatch work-evidence to a
per-unit boolean, with byte-identical output (pinned by `test_depth_ledger.py`).

This test proves the complexity fix directly and without a brittle wall-clock
bound: the number of `_probe_maps_to_unit` evaluations per unit must be EXACTLY
the probe count (one bucketing pass) and must NOT grow with the number of
dispatches (the old dispatch-evidence rescan is gone).
"""
from __future__ import annotations

import importlib

# The package re-exports the `depth_ledger` FUNCTION, which shadows the submodule
# of the same name — even `import ... as`. Pull the real module out of sys.modules
# so we can reach the private helpers + monkeypatch them.
depth_ledger = importlib.import_module("app.services.state_manager.depth_ledger")


def _unit(uid: int = 1, host: str = "app.example.com", prefix: str = "/api") -> dict:
    return {
        "id": uid, "host": host, "port_class": "web", "path_prefix": prefix,
        "risk_score": 5, "depth_tier": "app-unit", "structure_score": 3,
        "total_score": 8, "confidence": "high",
    }


def _probe(pid: int, uid: int = 1, host: str = "app.example.com") -> dict:
    # Maps to the unit via the denormalized application_unit_id FK (the O(1) path).
    return {
        "id": pid, "application_unit_id": uid, "request_variant_id": None,
        "attack_family": "sqli", "result_status": "tested", "tool_name": "sqlmap",
        "target_host": host, "target_path": f"/api/{pid}", "target_port": 443,
        "auth_context": "anonymous",
    }


def _dispatch(did: int, unit_id: int = 1) -> dict:
    return {
        "id": did, "agent_id": f"agent-{did}", "agent_role": "vulnerability-analyst",
        "application_unit_id": unit_id, "vuln_classes": "sqli",
        "skills": "", "status": "completed", "finding_slugs_json": "[]",
    }


def test_dispatch_unit_match_uses_concrete_application_unit_identity():
    assert depth_ledger._dispatch_targets_unit(_dispatch(1, unit_id=7), 7) is True
    assert depth_ledger._dispatch_targets_unit(_dispatch(1, unit_id=7), 8) is False


def _count_probe_maps(monkeypatch, *, probes: list, dispatches: list) -> tuple[int, dict]:
    calls = {"n": 0}
    real = depth_ledger._probe_maps_to_unit

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(depth_ledger, "_probe_maps_to_unit", counting)
    ledger = depth_ledger._unit_ledger(
        _unit(),
        variant_by_id={},
        status_by_variant={},
        parsed_surfaces=[],
        cred_hosts=set(),
        coverage_items=[],
        probes=probes,
        dispatches=dispatches,
        findings=[],
        active_deferrals=[],
    )
    return calls["n"], ledger


def test_probe_map_calls_are_one_pass_and_independent_of_dispatch_count(monkeypatch):
    probe_count = 50
    probes = [_probe(i) for i in range(probe_count)]

    n_no_dispatch, ledger0 = _count_probe_maps(monkeypatch, probes=probes, dispatches=[])
    n_many_dispatch, ledger1 = _count_probe_maps(
        monkeypatch, probes=probes, dispatches=[_dispatch(d) for d in range(20)]
    )

    # Exactly one bucketing pass over the probes — never re-scanned.
    assert n_no_dispatch == probe_count
    # The regression guard: 20 completed dispatches must NOT multiply the probe
    # scans. Old behavior re-scanned every probe per dispatch, so this would have
    # been ~ probe_count * (1 + 20). Now it is flat.
    assert n_many_dispatch == probe_count

    # The unit is still correctly evaluated (covering probes make it touched).
    assert ledger0["touched"] is True
    assert ledger1["touched"] is True


def test_completed_dispatch_without_evidence_does_not_touch_unit(monkeypatch):
    # Pins the removed (provably-dead) `touched` dispatch-branch: a completed
    # dispatch that CONTAINS the unit but has NO covering probe / finding under
    # it is not work evidence, so the unit stays untouched and dedicated-dispatch
    # stays unsatisfied. Guards the byte-identical refactor against future edits
    # that might reintroduce "a bare completed dispatch counts as work".
    _, ledger = _count_probe_maps(monkeypatch, probes=[], dispatches=[_dispatch(1)])
    assert ledger["touched"] is False
    assert ledger["dedicated_dispatch_satisfied"] is False
