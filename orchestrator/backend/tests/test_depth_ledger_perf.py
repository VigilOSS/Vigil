"""Depth-ledger scaling regressions.

The depth ledger and the by-family grid attribute every probe, coverage item,
variant, surface, finding and dispatch to application units through an index
built once per request, then bucket each unit's rows ONCE; dispatch work
evidence is a per-unit boolean. Output is pinned byte-for-byte by
`test_depth_ledger_golden.py`.

These tests prove the complexity directly and without a brittle wall-clock
bound: the number of `_probe_maps_to_unit` evaluations per unit is EXACTLY the
probe count mapped to it and does NOT grow with the number of dispatches, and
across an engagement the attribution checks grow with rows, not units x rows.
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
    index = depth_ledger._AttributionIndex(
        variants=[],
        observations=[],
        surfaces=[],
        coverage_items=[],
        probes=probes,
        findings=[],
        dispatches=dispatches,
    )
    ledger = depth_ledger._unit_ledger(
        _unit(), index=index, cred_hosts=set(), active_deferrals=[],
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


# --------------------------------------------------------------------------- #
# Engagement-scale attribution: every row is indexed once, not rescanned per unit
# --------------------------------------------------------------------------- #

_SCALE_HOSTS = tuple(f"h{index}.example.com" for index in range(5))
_SCALE_PREFIXES_PER_HOST = 40
_SCALE_ROUTES_PER_PREFIX = 10
_SCALE_PROBES = 4000
_SCALE_COVERAGE_ITEMS = 4000
_SCALE_ENGAGEMENT_KEY = "2026-11-12-091500-ledger-scale"


def _seed_scale_fixture(client, isolate_settings) -> tuple[int, dict[str, int]]:
    import json

    from app.services import state_manager
    from tests.test_engagements_api import write_engagement

    eng_dir = write_engagement(isolate_settings["engagements_dir"], key=_SCALE_ENGAGEMENT_KEY)
    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    scope["engagement_type"] = "web"
    scope["scope_hosts"] = list(_SCALE_HOSTS)
    scope["scope"] = list(_SCALE_HOSTS)
    (eng_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    response = client.get(f"/engagements/{_SCALE_ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    eng_id = int(response.json()["id"])

    units = []
    variants = []
    for host in _SCALE_HOSTS:
        for prefix_index in range(_SCALE_PREFIXES_PER_HOST):
            units.append((len(units) + 1, eng_id, host, f"/m{prefix_index}"))
            for route in range(_SCALE_ROUTES_PER_PREFIX):
                seq = len(variants)
                variants.append((
                    seq + 1, eng_id, "https", host, 443, "GET",
                    f"/m{prefix_index}/r{route}", json.dumps({"id": "int"} if seq % 2 else {}),
                    f"p{seq}", f"b{seq}",
                ))
    probes = []
    for index in range(_SCALE_PROBES):
        variant = variants[(index * 7) % len(variants)]
        mode = index % 3
        probes.append((
            index + 1, eng_id,
            variant[0] if mode == 1 else None,
            units[index % len(units)][0] if mode == 0 else None,
            ("alice", "bob")[index % 2], ("sqli", "idor", "xss")[index % 3],
            f"scale-{index}", "curl", "tested",
            variant[3] if mode == 2 else "", variant[6] if mode == 2 else "",
        ))
    coverage = []
    for index in range(_SCALE_COVERAGE_ITEMS):
        coverage.append((
            index + 1, eng_id,
            variants[(index * 13) % len(variants)][0] if index % 2 else None,
            units[(index * 3) % len(units)][0] if index % 2 == 0 else None,
            f"slot-{index}", ("sqli", "ssrf", "lfi")[index % 3], "covered", "reviewed",
        ))

    with state_manager.get_connection() as connection:
        connection.executemany(
            "INSERT INTO assessment_application_units "
            "(id, engagement_id, host, port_class, path_prefix, deep_required, confidence) "
            "VALUES (?, ?, ?, 'web', ?, 1, 'high')",
            units,
        )
        connection.executemany(
            "INSERT INTO assessment_request_variants "
            "(id, engagement_id, scheme, host, port, method, normalized_path, "
            "query_schema_json, params_schema_hash, body_schema_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            variants,
        )
        connection.executemany(
            "INSERT INTO assessment_probe_runs "
            "(id, engagement_id, request_variant_id, application_unit_id, auth_context, "
            "attack_family, probe_key, tool_name, result_status, target_host, target_path) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            probes,
        )
        connection.executemany(
            "INSERT INTO assessment_coverage_items "
            "(id, engagement_id, request_variant_id, application_unit_id, input_slot, "
            "attack_family, status, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            coverage,
        )
    sizes = {
        "units": len(units), "variants": len(variants),
        "probes": len(probes), "coverage_items": len(coverage),
    }
    return eng_id, sizes


def test_unit_attribution_work_scales_with_rows_not_units_times_rows(
    client, isolate_settings, monkeypatch,
):
    from app.services import state_manager

    eng_id, sizes = _seed_scale_fixture(client, isolate_settings)
    steps = {"n": 0}

    def _counted(name: str):
        real = getattr(depth_ledger, name)

        def counting(*args, **kwargs):
            steps["n"] += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(depth_ledger, name, counting)

    # Every per-row attribution check the projections can make against a unit.
    for name in (
        "_path_under_prefix", "_probe_maps_to_unit",
        "_coverage_maps_to_unit", "_finding_maps_to_unit",
    ):
        _counted(name)

    rows = sizes["variants"] + sizes["probes"] + sizes["coverage_items"]

    with state_manager.get_connection() as connection:
        grid = depth_ledger.by_family_coverage(connection, eng_id)
    assert grid["totals"]["units"] == sizes["units"]
    by_family_steps = steps["n"]

    steps["n"] = 0
    ledger = depth_ledger.depth_ledger(eng_id)
    assert ledger["summary"]["deep_required"] == sizes["units"]
    ledger_steps = steps["n"]

    # Each row reaches at most a few units here (its own unit id, its variant's
    # unit, its target-path unit), so attribution work is a small multiple of the
    # row count. Rescanning every row per unit would be units x rows (~2M).
    assert by_family_steps <= 4 * rows, by_family_steps
    assert ledger_steps <= 4 * rows, ledger_steps


def test_attribution_index_matches_a_full_scan_on_edge_case_paths():
    """The index only narrows which rows are checked: for every unit, each bucket
    equals the full-scan result of the same predicate, in row order."""
    from itertools import product

    paths = ["", "/", "//", "/api", "/api/", "/api//v2", "api/v2", "/apix", "/api/v2/x",
             "/API/v2", "/files/up load", "/a/b/c/d"]
    prefixes = ["/", "", "//", "/api", "/api/", "api", "/api/v2", "/apix", "/a/b", "/API"]
    hosts = ["app.example.com", "APP.example.com", "shop.example.com"]
    variants = [
        {"id": index + 1, "scheme": scheme, "host": host, "port": port, "method": "GET",
         "normalized_path": path}
        for index, (host, path, (scheme, port)) in enumerate(
            product(hosts, paths, [("https", 443), ("http", 8080)])
        )
    ]
    probes = [
        {"id": index + 1, "application_unit_id": (index % 7) or None,
         "request_variant_id": (index * 5) % len(variants) or None,
         "target_host": (host if index % 3 else ""), "target_path": path,
         "target_port": (None, 443, 8080, 0)[index % 4]}
        for index, (host, path) in enumerate(product([*hosts, " App.Example.com "], paths))
    ]
    coverage_items = [
        {"id": index + 1, "application_unit_id": (index % 5) or None,
         "request_variant_id": (index * 3) % len(variants) or None}
        for index in range(60)
    ]
    findings = [
        {"slug": f"VA-{index}", "canonical_location": location}
        for index, location in enumerate(
            [f"https://{host}{path}" for host, path in product(hosts, paths)]
            + ["", "app.example.com /api/v2", "not a url"]
        )
    ]
    surfaces = [
        {"surface_type": f"type-{index}", "target_descriptor": f"https://{host}{path}"}
        for index, (host, path) in enumerate(product(hosts, paths))
    ]
    index = depth_ledger._AttributionIndex(
        variants=variants, observations=[], surfaces=surfaces,
        coverage_items=coverage_items, probes=probes, findings=findings, dispatches=[],
    )

    matched = {"variants": 0, "surfaces": 0, "probes": 0, "coverage": 0, "findings": 0}
    unit_id = 0
    for host, prefix, port_class in product(hosts, prefixes, ["web", "port-8080"]):
        unit_id += 1
        unit = {"id": unit_id, "host": host, "port_class": port_class, "path_prefix": prefix}
        scope = depth_ledger._unit_scope(unit, index=index)
        h, pc, pre = scope["host"], scope["port_class"], scope["prefix"]
        assert scope["unit_variants"] == [
            v for v in variants
            if str(v["host"]).lower() == h
            and depth_ledger._port_class(v["scheme"], v["port"]) == pc
            and depth_ledger._path_under_prefix(v["normalized_path"] or "/", pre)
        ]
        assert scope["unit_surface_types"] == {
            surface_type
            for s_host, s_path, surface_type in (
                (*depth_ledger._surface_host_path(s["target_descriptor"]), s["surface_type"])
                for s in surfaces
            )
            if s_host == h and depth_ledger._path_under_prefix(s_path, pre)
        }
        ids = scope["unit_variant_ids"]
        assert index.unit_probes(unit_id, ids, h, pc, pre) == [
            p for p in probes
            if depth_ledger._probe_maps_to_unit(p, unit_id, ids, h, pc, pre)
        ]
        assert index.unit_coverage(unit_id, ids) == [
            ci for ci in coverage_items
            if depth_ledger._coverage_maps_to_unit(ci, unit_id, ids)
        ]
        assert index.unit_findings(h, pre) == [
            f for f in findings if depth_ledger._finding_maps_to_unit(f, h, pre)
        ]
        matched["variants"] += len(scope["unit_variants"])
        matched["surfaces"] += len(scope["unit_surface_types"])
        matched["probes"] += len(index.unit_probes(unit_id, ids, h, pc, pre))
        matched["coverage"] += len(index.unit_coverage(unit_id, ids))
        matched["findings"] += len(index.unit_findings(h, pre))
    # Every bucket kind is exercised with real matches, not only empty answers.
    assert all(matched.values()), matched
