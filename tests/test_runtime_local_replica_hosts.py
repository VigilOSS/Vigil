"""Local `.local` replica routing: scope.json -> docker `extra_hosts`.

A local replica host (`*.com.local` / `*.us.local`, resolving to loopback on the
host) is reachable inside the shared runtime only through an `--add-host
<host>:host-gateway` mapping generated from the engagements' scope.json at
container creation. Covers the union/selection logic, the argv rendering, the
running-container extra_hosts read, and the restart-needed notice.

New, distinctly-named file (no edits to existing tests) per the workstream
isolation constraint.
"""
from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

from vigil_cli import docker
from vigil_cli import runtime
from vigil_cli.docker import DockerResult


def _write_scope(install_root: Path, key: str, scope: dict) -> None:
    eng_dir = install_root / "agent" / "engagements" / key
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(json.dumps(scope))


def test_local_replica_hosts_unions_local_names_and_excludes_wildcards(
    tmp_path: Path, monkeypatch
) -> None:
    # `developer.dev.acme.example` carries no `.local` suffix, so it reaches the
    # resolution selector. Stubbed to answer nothing, because the HOST's own
    # resolver decides the outcome otherwise: a runner that sinkholes unknown
    # names to 127.0.0.1 would read it as a local replica and admit it.
    monkeypatch.setattr(runtime.socket, "getaddrinfo", _fake_getaddrinfo({}))
    _write_scope(
        tmp_path,
        "eng-a",
        {
            "engagement_type": "web",
            "hosts": [
                "www.acme.example.local",
                "api.acme.example.local",
                "*.acme.example.local",  # wildcard — never injectable
                "developer.dev.acme.example",  # non-local host — never injectable
            ],
        },
    )
    _write_scope(
        tmp_path,
        "eng-b",
        {
            "engagement_type": "web",
            "hosts": ["app.acme-health.example.local", "www.acme.example.local"],  # dup across engagements
        },
    )

    assert runtime.local_replica_hosts(tmp_path) == [
        "api.acme.example.local",
        "app.acme-health.example.local",
        "www.acme.example.local",
    ]


def test_local_replica_hosts_skips_archived_and_malformed(tmp_path: Path) -> None:
    _write_scope(
        tmp_path,
        "archived",
        {"engagement_type": "web", "status": "archived", "hosts": ["gone.com.local"]},
    )
    _write_scope(tmp_path, "live", {"engagement_type": "web", "hosts": ["here.com.local"]})
    (tmp_path / "agent" / "engagements" / "broken").mkdir(parents=True)
    (tmp_path / "agent" / "engagements" / "broken" / "scope.json").write_text("{not json")

    assert runtime.local_replica_hosts(tmp_path) == ["here.com.local"]


def test_local_replica_hosts_empty_without_engagements(tmp_path: Path) -> None:
    assert runtime.local_replica_hosts(tmp_path) == []


def test_extra_host_run_args_map_to_host_gateway() -> None:
    assert runtime._extra_host_run_args(["a.com.local", "b.us.local"]) == [
        "--add-host=a.com.local:host-gateway",
        "--add-host=b.us.local:host-gateway",
    ]


def _runner(*, running: bool, extra_hosts: list[str]):
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["docker", "ps"]:
            return DockerResult(0, "vigil\n" if running else "", "")
        if argv[:3] == ["docker", "inspect", "-f"]:
            return DockerResult(0, "".join(f"{h}\n" for h in extra_hosts), "")
        return DockerResult(0, "", "")

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


def test_warn_no_notice_when_runtime_not_running(tmp_path: Path, capsys) -> None:
    _write_scope(tmp_path, "eng", {"engagement_type": "web", "hosts": ["a.com.local"]})
    missing = runtime.warn_if_local_hosts_need_restart(
        tmp_path, runner=_runner(running=False, extra_hosts=[])
    )
    assert missing == []
    assert capsys.readouterr().err == ""


def test_warn_no_notice_when_all_hosts_already_injected(tmp_path: Path, capsys) -> None:
    _write_scope(tmp_path, "eng", {"engagement_type": "web", "hosts": ["a.com.local"]})
    missing = runtime.warn_if_local_hosts_need_restart(
        tmp_path,
        runner=_runner(running=True, extra_hosts=["a.com.local:host-gateway", "host.docker.internal:host-gateway"]),
    )
    assert missing == []
    assert capsys.readouterr().err == ""


def test_warn_lists_missing_local_hosts_and_names_restart(tmp_path: Path, capsys) -> None:
    _write_scope(
        tmp_path, "eng", {"engagement_type": "web", "hosts": ["a.com.local", "b.com.local"]}
    )
    missing = runtime.warn_if_local_hosts_need_restart(
        tmp_path,
        runner=_runner(running=True, extra_hosts=["a.com.local:host-gateway"]),
    )
    assert missing == ["b.com.local"]
    err = capsys.readouterr().err
    assert "b.com.local" in err
    assert "a.com.local" not in err
    assert "vigil runtime restart" in err
    assert "other engagement" in err


def test_container_extra_hosts_parses_host_labels() -> None:
    def runner(argv, **kwargs):
        return DockerResult(0, "a.com.local:host-gateway\nhost.docker.internal:host-gateway\n", "")

    assert docker.container_extra_hosts("vigil", runner=runner) == {
        "a.com.local",
        "host.docker.internal",
    }


def test_container_extra_hosts_empty_on_inspect_failure() -> None:
    assert docker.container_extra_hosts("vigil", runner=lambda argv, **k: DockerResult(1, "", "no such container")) == set()


# ── loopback-resolving hosts that do NOT end `.local` ────────────────────────
#
# The `.local` suffix is a convention, not the mechanism. What makes a scoped
# host a local replica is that the HOST resolves it to loopback (typically a
# line in the host's /etc/hosts). Selecting on the suffix alone left a host
# like `replica.acme.example` with no `extra_hosts` entry — and
# `kali_resolve.apply_resolve_pin` deliberately emits no pin for a loopback
# answer either — so in-container DNS resolved the name through public DNS and
# the probe silently left the replica for the LIVE host. That is a
# scope-correctness surprise, not a failure the operator can see.


def _fake_getaddrinfo(answers: dict[str, list[str]]):
    """A `socket.getaddrinfo` stand-in driven by a host -> addresses map."""
    def getaddrinfo(host, *_args, **_kwargs):
        addresses = answers.get(str(host))
        if not addresses:
            raise socket.gaierror(-2, "Name or service not known")
        out = []
        for address in addresses:
            if ":" in address:
                out.append(
                    (socket.AF_INET6, socket.SOCK_STREAM,
                     socket.IPPROTO_TCP, "", (address, 0, 0, 0))
                )
            else:
                out.append(
                    (socket.AF_INET, socket.SOCK_STREAM,
                     socket.IPPROTO_TCP, "", (address, 0))
                )
        return out

    return getaddrinfo


def test_local_replica_hosts_include_a_loopback_resolving_host_without_the_suffix(
    tmp_path: Path, monkeypatch
) -> None:
    _write_scope(
        tmp_path,
        "eng",
        {
            "engagement_type": "web",
            "hosts": [
                "replica.acme.example",  # 127.0.0.1 on the host — a replica
                "v6replica.acme.example",  # ::1 on the host — also a replica
                "live.acme.example",  # routable — must stay on public DNS
                "*.acme.example",  # wildcard — extra_hosts cannot express one
                "www.acme.example.local",  # suffix path, no resolution needed
            ],
        },
    )
    monkeypatch.setattr(
        runtime.socket,
        "getaddrinfo",
        _fake_getaddrinfo(
            {
                "replica.acme.example": ["127.0.0.1"],
                "v6replica.acme.example": ["::1"],
                "live.acme.example": ["203.0.113.10"],
                "*.acme.example": ["127.0.0.1"],
            }
        ),
    )

    assert runtime.local_replica_hosts(tmp_path) == [
        "replica.acme.example",
        "v6replica.acme.example",
        "www.acme.example.local",
    ]


def test_a_host_answering_with_both_loopback_and_a_routable_address_is_not_a_replica(
    tmp_path: Path, monkeypatch
) -> None:
    """Complementary to the `--resolve` pin, which pins the routable candidate.

    `kali_resolve.apply_resolve_pin` drops loopback candidates and pins what is
    left, so a mixed answer IS pinned to its routable address. An `extra_hosts`
    entry for the same name would point every other tool at the host gateway
    instead — two mechanisms disagreeing about where the probe goes. Only a
    host whose every answer is loopback is treated as a replica.
    """
    _write_scope(tmp_path, "eng", {"engagement_type": "web", "hosts": ["mixed.acme.example"]})
    monkeypatch.setattr(
        runtime.socket,
        "getaddrinfo",
        _fake_getaddrinfo({"mixed.acme.example": ["127.0.0.1", "203.0.113.10"]}),
    )

    assert runtime.local_replica_hosts(tmp_path) == []


def test_a_local_suffix_host_needs_no_resolution_at_all(
    tmp_path: Path, monkeypatch
) -> None:
    """The suffix declaration stands on its own; a dead resolver cannot drop it."""
    _write_scope(tmp_path, "eng", {"engagement_type": "web", "hosts": ["www.acme.example.local"]})
    resolved: list[str] = []

    def record(host, *_args, **_kwargs):
        # Recorded and asserted on the calling thread: the probe sweeps on a
        # worker thread, where `pytest` turns a raised AssertionError into a
        # warning instead of a failure.
        resolved.append(str(host))
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(runtime.socket, "getaddrinfo", record)

    assert runtime.local_replica_hosts(tmp_path) == ["www.acme.example.local"]
    assert resolved == [], f"a `.local` host must not be resolved; resolved {resolved}"


# How long one stalled `getaddrinfo` is held for below. The measured stall that
# motivated the bound: a single 8-second resolver call made `local_replica_hosts`
# take 8.0s against a 3.0s budget, because the budget was consulted only
# BETWEEN hosts and `socket.getaddrinfo` accepts no timeout of its own.
_STALLED_RESOLVER_SECONDS = 8.0


def test_loopback_probe_is_bounded_and_fails_open(tmp_path: Path, monkeypatch) -> None:
    """`vigil runtime start` must not be stallable by a slow resolver.

    One name that never resolves must not hold the call for longer than the
    probe's whole budget, so the budget has to bound the sweep from the
    outside. The probe is advisory: the host it could not answer for is simply
    not admitted, exactly as before the probe existed, while the suffix set
    still renders — it does not raise and it does not hang.
    """
    _write_scope(
        tmp_path,
        "eng",
        {"engagement_type": "web", "hosts": ["stalled.acme.example", "www.acme.example.local"]},
    )
    released = threading.Event()

    def stalled_getaddrinfo(host, *_args, **_kwargs):
        # Released once the assertions are made, so the abandoned probe ends
        # with the test instead of outliving it.
        released.wait(_STALLED_RESOLVER_SECONDS)
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(runtime.socket, "getaddrinfo", stalled_getaddrinfo)
    monkeypatch.setattr(runtime, "_LOOPBACK_PROBE_BUDGET_SECONDS", 0.25)

    started = time.monotonic()
    try:
        hosts = runtime.local_replica_hosts(tmp_path)
    finally:
        elapsed = time.monotonic() - started
        released.set()

    assert hosts == ["www.acme.example.local"]
    # Generous against CI jitter; 0.25s is expected and the unbounded call took
    # the resolver's full stall.
    assert elapsed < _STALLED_RESOLVER_SECONDS / 2, (
        f"one stalled resolver call held local_replica_hosts for {elapsed:.1f}s "
        f"against a {runtime._LOOPBACK_PROBE_BUDGET_SECONDS}s budget"
    )


def test_an_exhausted_loopback_probe_budget_still_renders_the_suffix_set(
    tmp_path: Path, monkeypatch
) -> None:
    """No budget left means no sweep, and the declared hosts are unaffected."""
    _write_scope(
        tmp_path,
        "eng",
        {"engagement_type": "web", "hosts": ["replica.acme.example", "www.acme.example.local"]},
    )
    monkeypatch.setattr(
        runtime.socket,
        "getaddrinfo",
        _fake_getaddrinfo({"replica.acme.example": ["127.0.0.1"]}),
    )
    monkeypatch.setattr(runtime, "_LOOPBACK_PROBE_BUDGET_SECONDS", 0.0)

    assert runtime.local_replica_hosts(tmp_path) == ["www.acme.example.local"]
