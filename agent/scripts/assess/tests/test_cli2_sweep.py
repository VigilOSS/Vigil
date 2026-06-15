"""CLI-2 — value-agnostic batch/sweep verb + response clustering.

Covers value expansion (list + range, --max-values cap), the placeholder guard,
the audit-row-per-value fan-out (kali_exec reused verbatim, one call per value
with a distinct batch-tagged intent), the value-agnostic reject-line guarantee,
the response clustering by distinct signature (reusing the reachability /
detect_transport_error taxonomy), the dns-failure vs connection-refused vs
reachable split, JSON run_id linkage, and the concurrency politeness guard.
"""
from __future__ import annotations

import contextlib
import io
import json
from types import SimpleNamespace

import pytest

from assess.commands import kali_sweep as ks
from assess.lib.client import AssessError
from assess.lib.kali_output import KaliResult


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _mk_result(
    *,
    run_id: int = 1,
    stdout: str = "",
    stderr: str = "",
    rc: int = 0,
    transport_error: bool = False,
    transport_error_detail: str = "",
    timed_out: bool = False,
    tool_name: str = "curl",
) -> KaliResult:
    result = KaliResult(
        run_id=run_id,
        status="completed",
        return_code=rc,
        stdout_path="",
        stderr_path="",
        duration_ms=10,
        peak_rss_bytes=None,
        stdout_preview=stdout,
        stderr_preview=stderr,
        timed_out=timed_out,
        partial_results=False,
        transport_error=transport_error,
        transport_error_detail=transport_error_detail,
    )
    setattr(result, "tool_name", tool_name)
    return result


def _sweep_args(**overrides) -> SimpleNamespace:
    base = dict(
        values="1,2,3",
        values_file=None,
        max_values=200,
        placeholder="{}",
        concurrency=1,
        allow_concurrent=False,
        as_json=False,
        command=["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://t/item/{}"],
        technique="RECON",
        intent="id sweep",
        probe_kind="baseline",
        phase="recon",
        timeout=30,
        destructive=False,
        force=False,
        container_name="vigil",
        identity=None,
        kali_agent_name=None,
        kali_agent_id=None,
        engagement_dir=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# --------------------------------------------------------------------------- #
# 1. value expansion: list + inclusive range; --max-values cap
# --------------------------------------------------------------------------- #


def test_expand_values_list_and_range():
    args = SimpleNamespace(values="1,2,7-9", values_file=None, max_values=200)
    assert ks._expand_values(args) == ["1", "2", "7", "8", "9"]


def test_expand_values_max_cap_raises():
    args = SimpleNamespace(values="1-300", values_file=None, max_values=200)
    with pytest.raises(AssessError) as exc:
        ks._expand_values(args)
    assert "max-values" in str(exc.value)


def test_expand_values_never_empty():
    args = SimpleNamespace(values="", values_file=None, max_values=200)
    with pytest.raises(AssessError):
        ks._expand_values(args)


# --------------------------------------------------------------------------- #
# 2. template must contain the placeholder
# --------------------------------------------------------------------------- #


def test_template_requires_placeholder():
    with pytest.raises(AssessError) as exc:
        ks._require_placeholder(["curl", "http://t/item/1"], "{}")
    assert "placeholder" in str(exc.value)
    # A template WITH the placeholder passes.
    ks._require_placeholder(["curl", "http://t/item/{}"], "{}")


# --------------------------------------------------------------------------- #
# 3. one audit row per value, value substituted, distinct batch-tagged intent
# --------------------------------------------------------------------------- #


def test_sweep_one_audit_row_per_value(monkeypatch):
    calls = []

    def recorder(cmd, *, tool_name, intent, **kwargs):
        calls.append({"cmd": list(cmd), "tool_name": tool_name, "intent": intent, "kwargs": kwargs})
        return _mk_result(run_id=len(calls), stdout="200 body", rc=0)

    monkeypatch.setattr(ks, "kali_exec", recorder)

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ks.run(_sweep_args(values="1,2,3"))

    assert len(calls) == 3
    # Each call substituted the value into the template.
    assert [c["cmd"][-1] for c in calls] == [
        "http://t/item/1",
        "http://t/item/2",
        "http://t/item/3",
    ]
    # Each call carries a distinct intent embedding the (shared) batch id + value.
    intents = [c["intent"] for c in calls]
    assert all("[sweep " in i and "value=" in i for i in intents)
    assert intents[0].endswith("value=1]")
    assert intents[2].endswith("value=3]")
    # Single shared batch id across the fan-out.
    import re

    batch_ids = {re.search(r"\[sweep (\w+) value=", i).group(1) for i in intents}
    assert len(batch_ids) == 1


# --------------------------------------------------------------------------- #
# 4. value-agnostic: never adds values the operator did not supply
# --------------------------------------------------------------------------- #


def test_sweep_values_agnostic(monkeypatch):
    calls = []

    def recorder(cmd, *, tool_name, intent, **kwargs):
        calls.append(list(cmd))
        return _mk_result(run_id=len(calls), stdout="200", rc=0)

    monkeypatch.setattr(ks, "kali_exec", recorder)

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ks.run(_sweep_args(values="5"))

    # Exactly one call, exactly the value supplied — no seed/ID expansion.
    assert len(calls) == 1
    assert calls[0][-1] == "http://t/item/5"


# --------------------------------------------------------------------------- #
# 5. clustering groups identical response signatures
# --------------------------------------------------------------------------- #


def test_clustering_groups_identical_signatures():
    results = [
        ("1", _mk_result(run_id=1, stdout="200 hello", rc=0)),
        ("2", _mk_result(run_id=2, stdout="200 hello", rc=0)),
        ("3", _mk_result(run_id=3, stdout="403 denied", rc=0)),
        ("4", _mk_result(run_id=4, stdout="403 denied", rc=0)),
        ("5", _mk_result(run_id=5, stdout="403 denied", rc=0)),
        ("11", _mk_result(run_id=11, stdout="000", stderr="curl: (7) Failed to connect: Connection refused", rc=7)),
        ("99", _mk_result(run_id=99, stdout="000", stderr="curl: (6) Could not resolve host: x", rc=6)),
    ]
    clusters = ks.cluster_results(results)

    by_class = {c["reachability_class"]: c for c in clusters}
    # 4 distinct signatures: reachable-200, filter-rejected-403, conn-refused, dns-fail.
    assert len(clusters) == 4
    assert by_class["reachable"]["count"] == 2
    assert by_class["reachable"]["status"] == "200"
    # The repeated identical 403 body is annotated filter-rejected purely by
    # clustering (deny-shaped status + identical marker across >1 value).
    assert by_class["filter-rejected"]["count"] == 3
    assert by_class["filter-rejected"]["status"] == "403"
    assert by_class["connection-refused"]["count"] == 1
    assert by_class["dns-failure"]["count"] == 1
    # Ordered by count DESC — biggest cluster first.
    assert clusters[0]["count"] >= clusters[-1]["count"]


def test_clustering_filter_rejected_needs_repeat():
    # A single deny-shaped reachable response is NOT filter-rejected — the label
    # is clustering-derived (identical body repeated), not a status-family rule.
    results = [("1", _mk_result(run_id=1, stdout="403 denied", rc=0))]
    clusters = ks.cluster_results(results)
    assert len(clusters) == 1
    assert clusters[0]["reachability_class"] == "reachable"


# --------------------------------------------------------------------------- #
# 6. transport classes map from the EXISTING detector (reuse, not reinvention)
# --------------------------------------------------------------------------- #


def test_clustering_distinguishes_transport_classes():
    reachable = _mk_result(stdout="200 ok", rc=0)
    dns = _mk_result(stdout="000", stderr="curl: (6) Could not resolve host: nope.invalid", rc=6)
    refused = _mk_result(
        stdout="000",
        stderr="curl: (7) Failed to connect to 10.0.0.9 port 80: Connection refused",
        rc=7,
    )
    assert ks._classify_reachability(reachable) == "reachable"
    assert ks._classify_reachability(dns) == "dns-failure"
    assert ks._classify_reachability(refused) == "connection-refused"


# --------------------------------------------------------------------------- #
# 7. --json cluster objects carry per-value run_ids for audit recovery
# --------------------------------------------------------------------------- #


def test_sweep_json_links_run_ids(monkeypatch):
    counter = {"n": 0}

    def recorder(cmd, *, tool_name, intent, **kwargs):
        counter["n"] += 1
        # Two distinct response bodies so we get two clusters.
        marker = "A" if counter["n"] % 2 else "B"
        return _mk_result(run_id=counter["n"], stdout=f"200 body-{marker}", rc=0)

    monkeypatch.setattr(ks, "kali_exec", recorder)

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        ks.run(_sweep_args(values="1,2,3,4", as_json=True))

    payload = json.loads(out.getvalue())
    assert payload["total"] == 4
    assert "batch_id" in payload
    all_run_ids = [rid for c in payload["clusters"] for rid in c["run_ids"]]
    # Every value's run_id is linked back through some cluster.
    assert sorted(all_run_ids) == [1, 2, 3, 4]
    for cluster in payload["clusters"]:
        assert len(cluster["run_ids"]) == cluster["count"]


# --------------------------------------------------------------------------- #
# 8. concurrency politeness guard (I-013)
# --------------------------------------------------------------------------- #


def test_concurrency_guard():
    with pytest.raises(AssessError) as exc:
        ks._resolve_concurrency(SimpleNamespace(concurrency=2, allow_concurrent=False))
    assert "allow-concurrent" in str(exc.value)


def test_concurrency_allowed_with_override():
    assert ks._resolve_concurrency(SimpleNamespace(concurrency=2, allow_concurrent=True)) == 2
    assert ks._resolve_concurrency(SimpleNamespace(concurrency=1, allow_concurrent=False)) == 1


def test_concurrency_cap():
    with pytest.raises(AssessError):
        ks._resolve_concurrency(SimpleNamespace(concurrency=99, allow_concurrent=True))
