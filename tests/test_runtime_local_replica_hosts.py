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
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1] / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from vigil_cli.docker import DockerResult  # noqa: E402
from vigil_cli import runtime  # noqa: E402


def _write_scope(install_root: Path, key: str, scope: dict) -> None:
    eng_dir = install_root / "agent" / "engagements" / key
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(json.dumps(scope))


def test_local_replica_hosts_unions_local_names_and_excludes_wildcards(tmp_path: Path) -> None:
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
    from vigil_cli import docker

    def runner(argv, **kwargs):
        return DockerResult(0, "a.com.local:host-gateway\nhost.docker.internal:host-gateway\n", "")

    assert docker.container_extra_hosts("vigil", runner=runner) == {
        "a.com.local",
        "host.docker.internal",
    }


def test_container_extra_hosts_empty_on_inspect_failure() -> None:
    from vigil_cli import docker

    assert docker.container_extra_hosts("vigil", runner=lambda argv, **k: DockerResult(1, "", "no such container")) == set()
