from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest


def test_oob_relay_module_imports_when_fcntl_is_unavailable() -> None:
    script = """
import builtins
real_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == 'fcntl':
        raise ModuleNotFoundError('simulated Windows')
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
import vigil_cli.oob_relay
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
    )
    assert result.returncode == 0, result.stderr


def test_windows_file_lock_backend_locks_a_real_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import vigil_cli.oob_relay as relay

    class FakeMsvcrt:
        LK_LOCK = 1
        LK_UNLCK = 2

        def __init__(self) -> None:
            self.calls: list[tuple[int, int]] = []

        def locking(self, _fd: int, mode: int, count: int) -> None:
            self.calls.append((mode, count))

    backend = FakeMsvcrt()
    monkeypatch.setattr(relay, "_fcntl", None)
    monkeypatch.setattr(relay, "_msvcrt", backend)
    with (tmp_path / "route.lock").open("a+", encoding="utf-8") as handle:
        relay._lock_file(handle)
        relay._unlock_file(handle)

    assert backend.calls == [(backend.LK_LOCK, 1), (backend.LK_UNLCK, 1)]
    assert (tmp_path / "route.lock").stat().st_size == 1


def test_fresh_slot_allocation_is_sanitized_stable_and_persisted(tmp_path: Path) -> None:
    from vigil_cli.oob_relay import allocate_relay_route

    install_root = tmp_path / "Customer Alpha"
    registry = tmp_path / "allocations.json"

    first = allocate_relay_route(
        install_root,
        slot_name=" Customer Alpha ",
        base_domain="oob.example.test",
        registry_path=registry,
        identity_factory=lambda: "install-identity-a",
    )
    second = allocate_relay_route(
        install_root,
        slot_name="ignored-after-first-write",
        base_domain="changed.example.test",
        registry_path=registry,
        identity_factory=lambda: "must-not-be-used",
    )

    assert first == second
    assert first.slot_prefix == "customer-alpha-be3e46b6d1911ed7"
    assert first.oob_domain == "customer-alpha-be3e46b6d1911ed7.oob.example.test"
    assert first.dns_remote_port != 53
    assert first.reverse_remote_port == first.dns_remote_port + 1
    assert first.metadata_path == install_root / ".runtime-data/oob/relay-routing.json"
    assert json.loads(first.metadata_path.read_text())["slot_prefix"] == first.slot_prefix


@pytest.mark.parametrize("slot", ["", "   ", ".", "../escape", "a/b", "🔥"])
def test_slot_allocation_rejects_malformed_identity(tmp_path: Path, slot: str) -> None:
    from vigil_cli.oob_relay import allocate_relay_route

    with pytest.raises(SystemExit, match="relay slot identity"):
        allocate_relay_route(
            tmp_path / "install",
            slot_name=slot,
            registry_path=tmp_path / "allocations.json",
        )


def test_colliding_candidate_slot_moves_to_next_free_block(tmp_path: Path) -> None:
    from vigil_cli.oob_relay import allocate_relay_route

    registry = tmp_path / "allocations.json"
    one = allocate_relay_route(
        tmp_path / "one",
        slot_name="one",
        registry_path=registry,
        identity_factory=lambda: "identity-one",
        slot_candidates=lambda _identity: [7, 8],
    )
    two = allocate_relay_route(
        tmp_path / "two",
        slot_name="two",
        registry_path=registry,
        identity_factory=lambda: "identity-two",
        slot_candidates=lambda _identity: [7, 8],
    )

    assert one.allocation_slot == 7
    assert two.allocation_slot == 8
    assert one.port_range != two.port_range
    assert one.oob_domain != two.oob_domain


def test_duplicate_install_identity_cannot_overwrite_another_slot(tmp_path: Path) -> None:
    from vigil_cli.oob_relay import allocate_relay_route

    registry = tmp_path / "allocations.json"
    first = allocate_relay_route(
        tmp_path / "one", slot_name="one", registry_path=registry,
        identity_factory=lambda: "same-install-id", slot_candidates=lambda _: [1],
    )
    with pytest.raises(SystemExit, match="identity collision"):
        allocate_relay_route(
            tmp_path / "two", slot_name="two", registry_path=registry,
            identity_factory=lambda: "same-install-id", slot_candidates=lambda _: [2],
        )
    payload = json.loads(registry.read_text())
    assert payload["allocations"]["same-install-id"]["oob_domain"] == first.oob_domain


def test_concurrent_allocation_of_one_install_returns_one_identity(tmp_path: Path) -> None:
    from vigil_cli.oob_relay import allocate_relay_route

    install_root = tmp_path / "shared"
    registry = tmp_path / "allocations.json"
    identities = iter(f"identity-{index}" for index in range(20))

    def allocate():
        return allocate_relay_route(
            install_root,
            slot_name="shared",
            registry_path=registry,
            identity_factory=lambda: next(identities),
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        routes = list(pool.map(lambda _index: allocate(), range(16)))

    assert len({route.install_id for route in routes}) == 1
    assert len({route.allocation_slot for route in routes}) == 1
    assert len(json.loads(registry.read_text())["allocations"]) == 1


def test_live_oob_state_without_metadata_pins_legacy_route_and_preserves_clients(
    tmp_path: Path,
) -> None:
    """Per-client correlation state is what the legacy pin protects."""
    from vigil_cli.oob_relay import initialize_relay_route

    install_root = tmp_path / "existing"
    legacy_client = install_root / ".runtime-data/oob/clients/ssrf.session"
    legacy_client.parent.mkdir(parents=True)
    legacy_client.write_text("correlation material", encoding="utf-8")

    route = initialize_relay_route(
        install_root,
        base_domain="oob.example.test",
        registry_path=tmp_path / "allocations.json",
    )

    assert route.legacy is True
    assert route.oob_domain == "oob.example.test"
    assert route.dns_remote_port == 53
    assert route.reverse_remote_port == 8443
    assert legacy_client.read_text() == "correlation material"


def test_an_interrupted_allocations_leftovers_are_not_mistaken_for_live_oob(
    tmp_path: Path,
) -> None:
    """Routing bookkeeping is not evidence that callbacks ever ran.

    An allocation that died between taking its lock and publishing its record
    leaves `.lock` and temporary siblings in the same directory `vigil oob
    start` writes to. Counting those as live OOB state would strand the retry
    on the shared 53/8443 route for a root that never routed anything.
    """
    from vigil_cli.oob_relay import initialize_relay_route

    install_root = tmp_path / "interrupted"
    oob_dir = install_root / ".runtime-data/oob"
    oob_dir.mkdir(parents=True)
    (oob_dir / "relay-routing.lock").write_text("", encoding="utf-8")
    (oob_dir / ".relay-routing.json.tmp").write_text("{}", encoding="utf-8")
    (oob_dir / "tenant-routing.lock").write_text("", encoding="utf-8")

    route = initialize_relay_route(
        install_root,
        base_domain="oob.example.test",
        registry_path=tmp_path / "allocations.json",
    )

    assert route.legacy is False, (
        "a stale lock from an interrupted allocation is not a live OOB channel"
    )
    assert route.oob_domain == f"{route.slot_prefix}.oob.example.test"


def test_failed_metadata_publish_rolls_back_registry_allocation(tmp_path: Path) -> None:
    import vigil_cli.oob_relay as relay_module

    registry = tmp_path / "allocations.json"

    def fail_metadata(path: Path, payload: dict[str, object]) -> None:
        if path.name == "relay-routing.json":
            raise OSError("disk full")
        relay_module._atomic_write_json_real(path, payload)

    with pytest.raises(OSError, match="disk full"):
        relay_module.allocate_relay_route(
            tmp_path / "broken",
            slot_name="broken",
            registry_path=registry,
            atomic_writer=fail_metadata,
        )

    payload = json.loads(registry.read_text())
    assert payload["allocations"] == {}
    assert not (tmp_path / "broken/.runtime-data/oob/relay-routing.json").exists()


def test_relay_metadata_rejects_corrupt_or_silently_changed_routing(tmp_path: Path) -> None:
    from vigil_cli.oob_relay import RELAY_METADATA_RELATIVE_PATH, load_relay_route

    install_root = tmp_path / "install"
    path = install_root / RELAY_METADATA_RELATIVE_PATH
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "install_id": "id",
                "slot_name": "alpha",
                "slot_prefix": "alpha-00000000",
                "base_domain": "oob.example.test",
                "oob_domain": "evil.example.test",
                "allocation_slot": 2,
                "dns_remote_port": 20004,
                "reverse_remote_port": 20005,
                "legacy": False,
            }
        )
    )

    with pytest.raises(SystemExit, match="routing metadata"):
        load_relay_route(install_root)


def test_edge_routing_config_is_deterministic_and_slot_specific(tmp_path: Path) -> None:
    from vigil_cli.oob_relay import allocate_relay_route, render_edge_routing

    route = allocate_relay_route(
        tmp_path / "slot",
        slot_name="Acme",
        base_domain="oob.example.test",
        registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "acme-id",
        slot_candidates=lambda _identity: [11],
    )
    rendered = render_edge_routing(route, frp_http_vhost_port=8080)

    assert rendered == render_edge_routing(route, frp_http_vhost_port=8080)
    assert route.oob_domain in rendered["caddy"]
    assert f"*.*.{route.oob_domain}" in rendered["caddy"]
    assert f"http://{route.oob_domain}" in rendered["caddy"]
    assert "on_demand" in rendered["caddy"]
    assert "127.0.0.1:8080" in rendered["caddy"]
    assert f"127.0.0.1:{route.dns_remote_port}" in rendered["dns"]
    assert "prefer_udp" in rendered["dns"]
    assert str(route.reverse_remote_port) in rendered["routing_json"]


def test_oob_options_and_assess_environment_consume_resolved_relay_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module
    from vigil_cli.oob import oob_options
    from vigil_cli.oob_relay import allocate_relay_route

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    install_root = tmp_path / "slot"
    route = allocate_relay_route(
        install_root,
        slot_name="Acme",
        base_domain="oob.example.test",
        registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "acme-id",
        slot_candidates=lambda _identity: [11],
    )

    options = oob_options(install_root)
    env = main_module._assess_exec_environment(install_root)

    assert options.oob_domain == route.oob_domain
    assert options.dns_remote_port == route.dns_remote_port
    assert options.reverse_remote_port == route.reverse_remote_port
    assert env["VIGIL_OOB_DOMAIN"] == route.oob_domain
    assert env["VIGIL_OOB_SLOT"] == route.slot_prefix
    assert env["VIGIL_OOB_DNS_PORT"] == str(route.dns_remote_port)
    assert env["VIGIL_OOB_REVERSE_PORT"] == str(route.reverse_remote_port)


def test_external_domain_override_cannot_replace_persisted_vigil_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.oob import oob_options
    from vigil_cli.oob_relay import allocate_relay_route

    install_root = tmp_path / "slot"
    route = allocate_relay_route(
        install_root, slot_name="Acme", registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "acme-id", slot_candidates=lambda _: [11],
    )
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "public-interactsh.example")

    with pytest.raises(SystemExit, match="cannot override persisted"):
        oob_options(install_root)
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", route.oob_domain)
    assert oob_options(install_root).oob_domain == route.oob_domain


def test_fresh_install_accepts_ambient_value_as_its_persisted_base_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob import oob_options

    source_root = tmp_path / "source"
    install_root = tmp_path / "fresh"
    (source_root / "agent").mkdir(parents=True)
    (source_root / "orchestrator").mkdir(exist_ok=True)
    (source_root / "agent/README").write_text("managed", encoding="utf-8")
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "custom.example.test")

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=install_root,
            verify_docker_image=False,
        )
    )

    options = oob_options(install_root)
    assert options.relay_route is not None
    assert options.relay_route.base_domain == "custom.example.test"
    assert options.oob_domain.endswith(".custom.example.test")


def test_install_reads_relative_config_from_caller_context_before_pinning_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import load_relay_route

    caller_root = tmp_path / "caller"
    config_path = caller_root / "config" / "vigil.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        json.dumps(
            {
                "oob.domain": "oob.example.test",
                "oob.slot": "caller-configured-slot",
            }
        ),
        encoding="utf-8",
    )
    source_root = tmp_path / "source"
    (source_root / "agent").mkdir(parents=True)
    (source_root / "orchestrator").mkdir(exist_ok=True)
    (source_root / "agent/README").write_text("managed", encoding="utf-8")
    install_root = tmp_path / "install"
    monkeypatch.chdir(caller_root)
    monkeypatch.setenv("VIGIL_CONFIG", "config/vigil.json")

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=install_root,
            verify_docker_image=False,
        )
    )

    route = load_relay_route(install_root)
    assert route is not None
    assert route.slot_name == "caller-configured-slot"
    registry_path = config_path.with_name("oob-allocations.json")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    assert registry["allocations"][route.install_id]["install_root"] == str(
        install_root
    )
    assert Path.cwd() == caller_root


def test_fresh_install_without_oob_configuration_does_not_persist_owner_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob import oob_options, start_oob
    from vigil_cli.oob_relay import load_relay_route

    source_root = tmp_path / "source"
    install_root = tmp_path / "fresh"
    (source_root / "agent").mkdir(parents=True)
    (source_root / "orchestrator").mkdir(exist_ok=True)
    (source_root / "agent/README").write_text("managed", encoding="utf-8")
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)
    monkeypatch.delenv("VIGIL_FRP_HOST", raising=False)

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=install_root,
            verify_docker_image=False,
        )
    )

    assert load_relay_route(install_root) is None
    options = oob_options(install_root)
    assert options.frp_host == ""
    assert options.oob_domain == ""

    calls: list[list[str]] = []

    def runner(argv, **_):
        calls.append(list(argv))
        raise AssertionError("unconfigured OOB must fail before Docker access")

    # (?s) so `.` spans the checklist's newlines; the abort now names the
    # token too, so an operator is not refused a second time for it.
    with pytest.raises(
        SystemExit,
        match=r"(?s)config set oob\.frp_host.*config set oob\.domain"
        r".*config set oob\.frp_token",
    ):
        start_oob(options, runner=runner)
    assert calls == []


def test_fresh_install_allocates_route_but_live_oob_state_pins_legacy_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import load_relay_route

    source_root = tmp_path / "source"
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.test")
    (source_root / "agent").mkdir(parents=True)
    (source_root / "orchestrator").mkdir(exist_ok=True)
    (source_root / "agent/README").write_text("managed", encoding="utf-8")
    fresh_root = tmp_path / "fresh-slot"
    fresh = install_from_source(
        InstallOptions(source_root=source_root, install_root=fresh_root, verify_docker_image=False)
    )
    fresh_route = load_relay_route(fresh_root)
    assert fresh.is_upgrade is False
    assert fresh_route is not None and fresh_route.legacy is False

    upgrade_root = tmp_path / "upgrade"
    (upgrade_root / "agent/engagements/existing").mkdir(parents=True)
    correlation = upgrade_root / ".runtime-data/oob/clients/a.session"
    correlation.parent.mkdir(parents=True)
    correlation.write_text("keep", encoding="utf-8")
    upgraded = install_from_source(
        InstallOptions(source_root=source_root, install_root=upgrade_root, verify_docker_image=False)
    )
    upgrade_route = load_relay_route(upgrade_root)
    assert upgraded.is_upgrade is True
    assert upgrade_route is not None and upgrade_route.legacy is True
    assert correlation.read_text() == "keep"


def test_runtime_frp_and_client_metadata_use_relay_route(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, _render_runtime_files, start_oob_client

    commands: list[str] = []
    runtime_route = json.dumps(
        {
            "version": 1,
            "slot_prefix": "acme-12345678",
            "oob_domain": "acme-12345678.oob.example.test",
            "dns_remote_port": 20120,
            "reverse_remote_port": 20121,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if command.startswith("cat ") and "active-relay-routing.json" in command:
            return DockerResult(0, runtime_route, "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(1, "", "")
        return DockerResult(0, "", "")

    options = OobOptions(
        install_root=tmp_path,
        frp_token="secret",
        oob_domain="acme-12345678.oob.example.test",
        slot_prefix="acme-12345678",
        dns_remote_port=20120,
        reverse_remote_port=20121,
    )
    _render_runtime_files(options, runner=runner)
    start_oob_client(options, "agent-a", engagement="eng", runner=runner)
    rendered = "\n".join(commands)
    assert "remotePort = 20120" in rendered
    assert "remotePort = 20121" in rendered
    assert '"slot_prefix": "acme-12345678"' in rendered
    assert '"dns_remote_port": 20120' in rendered
    assert "/data/oob/active-relay-routing.json" in rendered
    assert "Path('/data/oob/relay-routing.json').write_text" not in rendered
    assert "-server acme-12345678.oob.example.test" in rendered


def test_oob_poll_refuses_client_owned_by_another_engagement(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, poll_client_payload_host

    metadata = json.dumps(
        {
            "name": "agent-a",
            "engagement": "engagement-b",
            "agent": "analyst",
            "server": "acme.oob.example.test",
            "slot_prefix": "acme",
            "dns_remote_port": 20120,
            "reverse_remote_port": 20121,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        if "/clients/agent-a.json" in command:
            return DockerResult(0, metadata, "")
        return DockerResult(0, "", "")

    options = OobOptions(
        install_root=tmp_path,
        frp_token="secret",
        oob_domain="acme.oob.example.test",
        slot_prefix="acme",
        dns_remote_port=20120,
        reverse_remote_port=20121,
    )

    with pytest.raises(SystemExit, match="engagement-b"):
        poll_client_payload_host(
            options,
            "agent-a",
            engagement="engagement-a",
            runner=runner,
        )


def test_oob_start_refuses_route_switch_while_unverifiable_client_is_running(
    tmp_path: Path,
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob
    from vigil_cli.oob_relay import allocate_relay_route

    commands: list[str] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "tmux has-session -t oob-server" in command:
            return DockerResult(1, "", "")
        if "tmux has-session -t frpc" in command:
            return DockerResult(1, "", "")
        if "tmux list-sessions" in command:
            return DockerResult(0, "legacy-agent\n", "")
        if "active-relay-routing.json" in command:
            return DockerResult(1, "", "")
        if "/clients/legacy-agent.json" in command:
            return DockerResult(1, "", "")
        return DockerResult(0, "", "")

    # The install this switches TO holds a real slot; the running client is what
    # is in question here, not the reservation gate ahead of it.
    route = allocate_relay_route(
        tmp_path,
        slot_name="slot-new",
        base_domain="oob.example.test",
        registry_path=tmp_path / "allocations.json",
    )
    with pytest.raises(SystemExit, match="running OOB client.*cannot be verified"):
        start_oob(
            OobOptions(
                install_root=tmp_path,
                frp_host="frp.example.test",
                frp_token="secret",
                slot_prefix=route.slot_prefix,
                oob_domain=route.oob_domain,
                dns_remote_port=route.dns_remote_port,
                reverse_remote_port=route.reverse_remote_port,
                relay_route=route,
            ),
            runner=runner,
            frpc_ready_timeout=0,
        )

    assert not any("frpc.toml" in command for command in commands)
    assert not any("tmux new-session" in command for command in commands)


def test_oob_client_start_refuses_mismatched_runtime_route_before_writing_metadata(
    tmp_path: Path,
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob_client

    commands: list[str] = []
    old_route = json.dumps(
        {
            "version": 1,
            "slot_prefix": "slot-old",
            "oob_domain": "slot-old.oob.example.test",
            "dns_remote_port": 20010,
            "reverse_remote_port": 20011,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "active-relay-routing.json" in command:
            return DockerResult(0, old_route, "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="runtime route.*does not match"):
        start_oob_client(
            OobOptions(
                install_root=tmp_path,
                slot_prefix="slot-new",
                oob_domain="slot-new.oob.example.test",
                dns_remote_port=20120,
                reverse_remote_port=20121,
            ),
            "agent-a",
            runner=runner,
        )

    assert not any("/clients/agent-a.json" in command for command in commands)
    assert not any("tmux new-session" in command for command in commands)


def test_oob_client_start_never_overwrites_mismatched_running_session_metadata(
    tmp_path: Path,
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob_client

    commands: list[str] = []
    requested_route = {
        "version": 1,
        "slot_prefix": "slot-new",
        "oob_domain": "slot-new.oob.example.test",
        "dns_remote_port": 20120,
        "reverse_remote_port": 20121,
    }
    old_client_metadata = json.dumps(
        {
            "name": "agent-a",
            "engagement": "old-engagement",
            "agent": "old-agent",
            "server": "slot-old.oob.example.test",
            "slot_prefix": "slot-old",
            "dns_remote_port": 20010,
            "reverse_remote_port": 20011,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "active-relay-routing.json" in command:
            return DockerResult(0, json.dumps(requested_route), "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(0, "", "")
        if "/clients/agent-a.json" in command and command.startswith("cat "):
            return DockerResult(0, old_client_metadata, "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="running OOB client.*another relay route"):
        start_oob_client(
            OobOptions(
                install_root=tmp_path,
                slot_prefix="slot-new",
                oob_domain="slot-new.oob.example.test",
                dns_remote_port=20120,
                reverse_remote_port=20121,
            ),
            "agent-a",
            engagement="new-engagement",
            agent="new-agent",
            runner=runner,
        )

    metadata_writes = [
        command
        for command in commands
        if "/clients/agent-a.json" in command and "write_text" in command
    ]
    assert metadata_writes == []


def test_oob_client_start_reuses_exact_running_session_without_mutation(
    tmp_path: Path,
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob_client

    commands: list[str] = []
    route = {
        "version": 1,
        "slot_prefix": "slot-a",
        "oob_domain": "slot-a.oob.example.test",
        "dns_remote_port": 20010,
        "reverse_remote_port": 20011,
    }
    metadata = {
        "name": "agent-a",
        "engagement": "eng-a",
        "agent": "hunter",
        "server": route["oob_domain"],
        "slot_prefix": route["slot_prefix"],
        "dns_remote_port": route["dns_remote_port"],
        "reverse_remote_port": route["reverse_remote_port"],
    }

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "active-relay-routing.json" in command:
            return DockerResult(0, json.dumps(route), "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(0, "", "")
        if command.startswith("cat ") and "/clients/agent-a.json" in command:
            return DockerResult(0, json.dumps(metadata), "")
        return DockerResult(0, "", "")

    start_oob_client(
        OobOptions(
            install_root=tmp_path,
            slot_prefix="slot-a",
            oob_domain="slot-a.oob.example.test",
            dns_remote_port=20010,
            reverse_remote_port=20011,
        ),
        "agent-a",
        engagement="eng-a",
        agent="hunter",
        runner=runner,
    )

    assert not any("write_text" in command for command in commands)
    assert not any("tmux new-session" in command for command in commands)


def test_oob_client_start_reuses_constrained_pre_wave2_legacy_metadata_without_mutation(
    tmp_path: Path,
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob_client

    commands: list[str] = []
    route = {
        "version": 1,
        "slot_prefix": "legacy",
        "oob_domain": "oob.example.test",
        "dns_remote_port": 53,
        "reverse_remote_port": 8443,
    }
    legacy_metadata = {
        "name": "agent-a",
        "engagement": "eng-a",
        "agent": "hunter",
        "server": "oob.example.test",
    }

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "active-relay-routing.json" in command:
            return DockerResult(0, json.dumps(route), "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(0, "", "")
        if command.startswith("cat ") and "/clients/agent-a.json" in command:
            return DockerResult(0, json.dumps(legacy_metadata), "")
        return DockerResult(0, "", "")

    start_oob_client(
        OobOptions(
            install_root=tmp_path,
            slot_prefix="legacy",
            oob_domain="oob.example.test",
            dns_remote_port=53,
            reverse_remote_port=8443,
        ),
        "agent-a",
        engagement="eng-a",
        agent="hunter",
        runner=runner,
    )

    assert not any("write_text" in command for command in commands)
    assert not any("tmux new-session" in command for command in commands)


def test_oob_start_admits_constrained_pre_wave2_legacy_client_ownership(
    tmp_path: Path,
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob

    commands: list[str] = []
    legacy_metadata = {
        "name": "agent-a",
        "engagement": "eng-a",
        "agent": "hunter",
        "server": "oob.example.test",
    }

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if command in {
            "tmux has-session -t oob-server",
            "tmux has-session -t frpc",
        }:
            return DockerResult(1, "", "")
        if "tmux list-sessions" in command:
            return DockerResult(0, "agent-a\n", "")
        if command.startswith("cat ") and "active-relay-routing.json" in command:
            return DockerResult(1, "", "")
        if command.startswith("cat ") and "/clients/agent-a.json" in command:
            return DockerResult(0, json.dumps(legacy_metadata), "")
        return DockerResult(0, "", "")

    # A pre-wave2 client only exists on a root that was already running OOB
    # before relay routing existed — the population the shared 53/8443 route is
    # for, and the one `start_oob` warns rather than refuses.
    _seed_live_oob_state(tmp_path)
    start_oob(
        OobOptions(
            install_root=tmp_path,
            frp_host="frp.example.test",
            frp_token="secret",
            slot_prefix="legacy",
            oob_domain="oob.example.test",
            dns_remote_port=53,
            reverse_remote_port=8443,
        ),
        runner=runner,
        frpc_ready_timeout=0,
    )

    assert any("frpc.toml" in command for command in commands)
    assert not any(
        "/clients/agent-a.json" in command and "write_text" in command
        for command in commands
    )


@pytest.mark.parametrize(
    ("options_kwargs", "metadata_server"),
    [
        (
            {
                "slot_prefix": "legacy",
                "oob_domain": "oob.example.test",
                "dns_remote_port": 53,
                "reverse_remote_port": 8443,
            },
            "foreign.example.test",
        ),
        (
            {
                "slot_prefix": "legacy",
                "oob_domain": "oob.example.test",
                "dns_remote_port": 20010,
                "reverse_remote_port": 20011,
            },
            "oob.example.test",
        ),
        (
            {
                "slot_prefix": "slot-a",
                "oob_domain": "slot-a.oob.example.test",
                "dns_remote_port": 20010,
                "reverse_remote_port": 20011,
            },
            "slot-a.oob.example.test",
        ),
    ],
    ids=["foreign-domain", "nonlegacy-ports", "nonlegacy-slot"],
)
def test_oob_client_start_rejects_pre_wave2_metadata_outside_legacy_constraints(
    tmp_path: Path,
    options_kwargs: dict[str, object],
    metadata_server: str,
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, start_oob_client

    commands: list[str] = []
    route = {"version": 1, **options_kwargs}
    route["oob_domain"] = options_kwargs["oob_domain"]
    legacy_metadata = {
        "name": "agent-a",
        "engagement": "eng-a",
        "agent": "hunter",
        "server": metadata_server,
    }

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "active-relay-routing.json" in command:
            return DockerResult(0, json.dumps(route), "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(0, "", "")
        if command.startswith("cat ") and "/clients/agent-a.json" in command:
            return DockerResult(0, json.dumps(legacy_metadata), "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="another relay route"):
        start_oob_client(
            OobOptions(install_root=tmp_path, **options_kwargs),
            "agent-a",
            engagement="eng-a",
            agent="hunter",
            runner=runner,
        )

    assert not any("write_text" in command for command in commands)


def test_health_status_and_doctor_surface_relay_routing(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import oob_status
    from vigil_cli.oob_relay import allocate_relay_route
    from vigil_cli.status import _oob_relay_check

    route = allocate_relay_route(
        tmp_path / "slot", slot_name="Acme", registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "acme-id", slot_candidates=lambda _: [11],
    )

    def runner(_argv: list[str], **_: object) -> DockerResult:
        return DockerResult(0, "", "")

    payload = oob_status(
        oob_domain=route.oob_domain,
        slot_prefix=route.slot_prefix,
        dns_remote_port=route.dns_remote_port,
        reverse_remote_port=route.reverse_remote_port,
        runner=runner,
        deep=False,
    )
    assert payload["slot_prefix"] == route.slot_prefix
    assert payload["port_range"] == [route.dns_remote_port, route.reverse_remote_port]
    check = _oob_relay_check(tmp_path / "slot")
    assert check.status == "OK"
    assert route.slot_prefix in check.detail


def test_oob_routing_cli_emits_deployment_metadata_without_mutating_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module
    from vigil_cli.oob_relay import allocate_relay_route

    install_root = tmp_path / "slot"
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    route = allocate_relay_route(
        install_root, slot_name="Acme", registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "acme-id", slot_candidates=lambda _: [11],
    )

    main_module.main(["--root", str(install_root), "oob", "routing", "--format", "json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["domain"] == route.oob_domain
    assert payload["dns_upstream"].endswith(str(route.dns_remote_port))
    assert payload["reverse_tcp_port"] == route.reverse_remote_port


def test_cross_slot_client_payload_and_correlation_are_isolated(tmp_path: Path) -> None:
    from vigil_cli.oob import (
        interactions_for_domain,
        match_interactions_to_nonces,
        parse_client_payload_host,
        parse_interactsh_log,
    )
    from vigil_cli.oob_relay import allocate_relay_route

    registry = tmp_path / "allocations.json"
    alpha = allocate_relay_route(
        tmp_path / "alpha", slot_name="alpha", registry_path=registry,
        identity_factory=lambda: "alpha-id", slot_candidates=lambda _: [1],
    )
    beta = allocate_relay_route(
        tmp_path / "beta", slot_name="beta", registry_path=registry,
        identity_factory=lambda: "beta-id", slot_candidates=lambda _: [2],
    )
    alpha_id = "a" * 33
    beta_id = "b" * 33

    assert parse_client_payload_host(f"[INF] {alpha_id}.{alpha.oob_domain}\n", alpha.oob_domain)
    assert parse_client_payload_host(f"[INF] {beta_id}.{beta.oob_domain}\n", alpha.oob_domain) == ""
    callback = parse_interactsh_log(
        f"[{beta_id}shared-nonce.{beta.oob_domain}] Received DNS interaction (A) from 192.0.2.2 at 2026-01-01T00:00:00Z\n"
    )
    admitted = interactions_for_domain(callback, alpha.oob_domain)
    matched, _ = match_interactions_to_nonces(admitted, ["shared-nonce"])
    assert matched == []


def test_slot_filter_admits_compact_interactsh_client_callback() -> None:
    """Current interactsh -v logs omit the configured domain from callback brackets."""
    from vigil_cli.oob import interactions_for_domain, parse_interactsh_log

    callback = parse_interactsh_log(
        "[eng-probe.client-correlation-id] Received DNS interaction (A) "
        "from 192.0.2.2 at 2026-07-16T21:35:00Z\n"
    )

    admitted = interactions_for_domain(
        callback,
        "slot.oob.example.com",
        client_payload_host="client-correlation-id.slot.oob.example.com",
    )

    assert admitted == callback


def test_slot_filter_rejects_compact_callback_for_another_client() -> None:
    """A short callback has no slot suffix and must match the selected client."""
    from vigil_cli.oob import interactions_for_domain, parse_interactsh_log

    callback = parse_interactsh_log(
        "[alpha-probe.beta-client-id] Received DNS interaction (A) "
        "from 192.0.2.2 at 2026-07-16T21:35:00Z\n"
    )

    admitted = interactions_for_domain(
        callback,
        "alpha.oob.example.com",
        client_payload_host="alpha-client-id.alpha.oob.example.com",
    )

    assert admitted == []


def test_existing_route_repairs_missing_registry_entry_before_new_allocation(
    tmp_path: Path,
) -> None:
    from vigil_cli.oob_relay import allocate_relay_route

    registry = tmp_path / "allocations.json"
    original = allocate_relay_route(
        tmp_path / "original",
        slot_name="original",
        registry_path=registry,
        identity_factory=lambda: "original-id",
        slot_candidates=lambda _: [9],
    )
    registry.write_text(json.dumps({"version": 1, "allocations": {}}), encoding="utf-8")

    restored = allocate_relay_route(
        tmp_path / "original",
        slot_name="ignored",
        registry_path=registry,
        identity_factory=lambda: pytest.fail("existing metadata must supply identity"),
    )
    newcomer = allocate_relay_route(
        tmp_path / "newcomer",
        slot_name="newcomer",
        registry_path=registry,
        identity_factory=lambda: "newcomer-id",
        slot_candidates=lambda _: [9, 10],
    )

    assert restored == original
    assert newcomer.allocation_slot == 10
    assert set(json.loads(registry.read_text())["allocations"]) == {
        "original-id",
        "newcomer-id",
    }


def test_copied_live_install_metadata_is_rejected_by_registry(tmp_path: Path) -> None:
    from vigil_cli.oob_relay import RELAY_METADATA_RELATIVE_PATH, allocate_relay_route

    registry = tmp_path / "allocations.json"
    original_root = tmp_path / "original"
    clone_root = tmp_path / "clone"
    allocate_relay_route(
        original_root,
        slot_name="original",
        registry_path=registry,
        identity_factory=lambda: "shared-id",
        slot_candidates=lambda _: [4],
    )
    clone_path = clone_root / RELAY_METADATA_RELATIVE_PATH
    clone_path.parent.mkdir(parents=True)
    shutil.copy2(original_root / RELAY_METADATA_RELATIVE_PATH, clone_path)

    with pytest.raises(SystemExit, match="another install root"):
        allocate_relay_route(
            clone_root,
            slot_name="clone",
            registry_path=registry,
        )


@pytest.mark.parametrize(
    "domain",
    ["", ".", "*.example.test", "bad_domain.test", "evil.test\n}\nattacker {"],
)
def test_allocator_rejects_non_dns_base_domains(tmp_path: Path, domain: str) -> None:
    from vigil_cli.oob_relay import allocate_relay_route

    with pytest.raises(SystemExit, match="domain"):
        allocate_relay_route(
            tmp_path / "install",
            slot_name="slot",
            base_domain=domain,
            registry_path=tmp_path / "allocations.json",
        )


def test_allocator_rejects_base_domain_when_slot_domain_exceeds_dns_limit(
    tmp_path: Path,
) -> None:
    from vigil_cli.oob_relay import allocate_relay_route

    base_domain = f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 61}"
    assert len(base_domain) == 253
    with pytest.raises(SystemExit, match="domain"):
        allocate_relay_route(
            tmp_path / "install",
            slot_name="slot",
            base_domain=base_domain,
            registry_path=tmp_path / "allocations.json",
            identity_factory=lambda: "slot-id",
            slot_candidates=lambda _: [1],
        )


def test_upgrade_pins_ambient_domain_that_was_effective_before_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import load_relay_route

    source_root = tmp_path / "source"
    install_root = tmp_path / "upgrade"
    (source_root / "agent").mkdir(parents=True)
    (source_root / "orchestrator").mkdir(exist_ok=True)
    (source_root / "agent/README").write_text("managed", encoding="utf-8")
    (install_root / "agent/engagements/existing").mkdir(parents=True)
    # The state a pre-routing `vigil oob start` left on that ambient domain —
    # what makes this a legacy install rather than a merely pre-existing root.
    frpc = install_root / ".runtime-data/oob/frpc.toml"
    frpc.parent.mkdir(parents=True)
    frpc.write_text("serverAddr = 'relay'\n", encoding="utf-8")
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "legacy.custom.test")

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=install_root,
            verify_docker_image=False,
        )
    )

    route = load_relay_route(install_root)
    assert route is not None and route.legacy
    assert route.oob_domain == "legacy.custom.test"


def test_metadata_parent_symlink_cannot_escape_install_root(tmp_path: Path) -> None:
    from vigil_cli.oob_relay import allocate_relay_route

    install_root = tmp_path / "install"
    outside = tmp_path / "outside"
    outside.mkdir()
    install_root.mkdir()
    (install_root / ".runtime-data").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SystemExit, match="escapes install root"):
        allocate_relay_route(
            install_root,
            slot_name="slot",
            registry_path=tmp_path / "allocations.json",
        )
    assert not (outside / "oob/relay-routing.json").exists()


def test_metadata_file_symlink_is_rejected(tmp_path: Path) -> None:
    from vigil_cli.oob_relay import (
        RELAY_METADATA_RELATIVE_PATH,
        allocate_relay_route,
        load_relay_route,
    )

    source_root = tmp_path / "source"
    source = allocate_relay_route(
        source_root,
        slot_name="source",
        registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "source-id",
        slot_candidates=lambda _: [1],
    )
    install_root = tmp_path / "install"
    linked = install_root / RELAY_METADATA_RELATIVE_PATH
    linked.parent.mkdir(parents=True)
    linked.symlink_to(source.metadata_path)

    with pytest.raises(SystemExit, match="symlink"):
        load_relay_route(install_root)


def test_atomic_writer_tolerates_unsupported_directory_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import vigil_cli.oob_relay as relay

    real_open = relay.os.open

    def portable_open(path: object, flags: int, *args: object) -> int:
        if Path(path) == tmp_path and flags == os.O_RDONLY:
            raise PermissionError("directory handles are unsupported")
        return real_open(path, flags, *args)

    monkeypatch.setattr(relay.os, "open", portable_open)
    destination = tmp_path / "routing.json"
    relay._atomic_write_json_real(destination, {"safe": True})

    assert json.loads(destination.read_text(encoding="utf-8")) == {"safe": True}


def test_atomic_writer_does_not_follow_predictable_temporary_symlink(
    tmp_path: Path,
) -> None:
    import vigil_cli.oob_relay as relay

    destination = tmp_path / "routing.json"
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    temporary.symlink_to(victim)

    with pytest.raises(FileExistsError):
        relay._atomic_write_json_real(destination, {"safe": True})
    assert victim.read_text(encoding="utf-8") == "keep"


def test_frp_proxy_names_are_stable_and_derived_from_slot_not_container(
    tmp_path: Path,
) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, _render_runtime_files

    commands: list[str] = []

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv[-1])
        return DockerResult(0, "", "")

    _render_runtime_files(
        OobOptions(
            install_root=tmp_path,
            slot_prefix="slot-a-0123456789abcdef",
            oob_domain="slot-a-0123456789abcdef.oob.example.test",
        ),
        runner=runner,
    )
    rendered = "\n".join(commands)
    assert "prefix = socket.gethostname" not in rendered
    assert 'name = "vigil-' in rendered


def test_oob_status_degrades_when_live_runtime_belongs_to_another_slot() -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import oob_status

    runtime_route = json.dumps(
        {
            "slot_prefix": "slot-a",
            "oob_domain": "slot-a.oob.example.test",
            "dns_remote_port": 20010,
            "reverse_remote_port": 20011,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "tmux has-session" in command:
            return DockerResult(0, "", "")
        if "relay-routing.json" in command:
            return DockerResult(0, runtime_route, "")
        if "tmux list-sessions" in command:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    payload = oob_status(
        oob_domain="slot-b.oob.example.test",
        slot_prefix="slot-b",
        dns_remote_port=20020,
        reverse_remote_port=20021,
        runner=runner,
        deep=False,
    )
    assert payload["route_matches"] is False
    assert payload["health"] == "degraded"
    assert any("another relay route" in issue for issue in payload["issues"])


def test_oob_status_treats_malformed_runtime_marker_as_route_mismatch() -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import oob_status

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "tmux has-session" in command:
            return DockerResult(0, "", "")
        if "relay-routing.json" in command:
            return DockerResult(0, "{not-json", "")
        return DockerResult(0, "", "")

    payload = oob_status(runner=runner, deep=False)

    assert payload["route_matches"] is False
    assert payload["health"] == "degraded"
    assert any("marker is invalid" in issue for issue in payload["issues"])


def test_up_refuses_to_reuse_active_oob_sessions_from_another_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import up
    from vigil_cli.oob import OobOptions

    monkeypatch.setattr(
        up,
        "_oob_options",
        lambda _root: OobOptions(
            install_root=tmp_path,
            slot_prefix="slot-b",
            oob_domain="slot-b.oob.example.test",
            dns_remote_port=20020,
            reverse_remote_port=20021,
        ),
    )
    monkeypatch.setattr(
        up,
        "oob_status",
        lambda **_kwargs: {"server": True, "frpc": True, "route_matches": False},
    )
    monkeypatch.setattr(
        up,
        "start_oob",
        lambda *_args, **_kwargs: pytest.fail("must not mutate another relay slot's sessions"),
    )

    with pytest.raises(SystemExit, match="another relay slot"):
        up._start_oob_if_needed(tmp_path, runner=lambda _argv: None)


def test_up_skips_oob_for_an_install_that_never_reserved_a_relay_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Starting here would be the one thing that makes the remedy unusable.

    `vigil up` skips rather than propagating `start_oob`'s refusal: the runtime,
    orchestrator and proxy are already up by this point, and OOB is one optional
    service — a non-zero exit would claim the whole bring-up failed.
    """
    from vigil_cli import up
    from vigil_cli.oob import OobOptions

    monkeypatch.setattr(
        up,
        "_oob_options",
        lambda _root: OobOptions(
            install_root=tmp_path,
            frp_host="frp.example.test",
            frp_token="secret",
            slot_prefix="legacy",
            oob_domain="oob.example.test",
            dns_remote_port=53,
            reverse_remote_port=8443,
        ),
    )
    monkeypatch.setattr(up, "oob_status", lambda **_kwargs: {"server": False, "frpc": False})
    monkeypatch.setattr(
        up,
        "start_oob",
        lambda *_args, **_kwargs: pytest.fail(
            "must not render OOB state for an install with no reserved slot"
        ),
    )

    up._start_oob_if_needed(tmp_path, runner=lambda _argv: None)

    out = capsys.readouterr().out
    assert "no relay slot reserved" in out
    assert "vigil install" in out


def test_doctor_names_the_real_remedy_when_oob_domain_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The remedy must be actionable, not a no-op loop.

    `vigil install` allocates a route only when `oob.domain` is already set
    (`install.py`), so telling an operator with no domain configured to "run
    `vigil install`" sends them round a loop that cannot clear the warning.
    Name the missing input instead.
    """
    from vigil_cli import status as status_module
    from vigil_cli.status import _oob_relay_check

    monkeypatch.setattr(status_module, "get_config_value", lambda *_a, **_k: None)
    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)

    check = _oob_relay_check(tmp_path / "install")

    assert check.status == "WARN"
    assert "oob.domain" in check.detail, (
        "the warning must name the setting that unblocks it"
    )
    assert "run `vigil install` to pin" not in check.detail, (
        "must not point back at the command that just ran"
    )


def test_doctor_still_points_at_install_when_domain_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a domain set, `vigil install` IS the remedy — keep saying so."""
    from vigil_cli import status as status_module
    from vigil_cli.status import _oob_relay_check

    monkeypatch.setattr(
        status_module,
        "get_config_value",
        lambda key, *_a, **_k: "oob.example.com" if key == "oob.domain" else None,
    )

    check = _oob_relay_check(tmp_path / "install")

    assert check.status == "WARN"
    assert "vigil install" in check.detail


def test_install_says_why_it_allocated_no_oob_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Silence here is the ordering trap that strands operators on a legacy route.

    Route allocation happens during `vigil install`, and only when `oob.domain`
    is already configured. Configure OOB afterwards — the order the docs imply —
    and there is no allocation and no message saying so; the install silently
    falls back to the globally contended legacy ports, and re-running install
    pins that fallback rather than fixing it. Say it out loud instead.
    """
    from vigil_cli.install import InstallOptions, install_from_source

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)
    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator").mkdir(exist_ok=True)
    (source / "orchestrator" / "backend" / "data").mkdir(parents=True)
    (source / "README.md").write_text("managed source\n", encoding="utf-8")

    install_from_source(
        InstallOptions(
            source_root=source,
            install_root=tmp_path / "install",
            verify_docker_image=False,
        )
    )

    err = capsys.readouterr().err
    assert "oob.domain" in err, "must name the unset setting"
    assert "no relay route" in err.lower(), "must say no route was allocated"
    assert "vigil config set oob.domain" in err, "must name the step that sets it"
    assert "vigil install" in err, "must name the step that then allocates"


def test_up_skip_message_names_every_key_oob_start_requires(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Following this message verbatim must not land on a second failure.

    `vigil oob start` aborts without a token just as it aborts without a host or
    domain, so a checklist that names only two of the three sends the operator
    to `vigil oob start` to be refused again.
    """
    from vigil_cli import up as up_module

    up_module._print_oob_configuration_help()

    out = capsys.readouterr().out
    for key in ("oob.frp_host", "oob.domain", "oob.frp_token"):
        assert key in out, f"{key} is required by `vigil oob start` but unlisted"


def test_doctor_missing_token_says_how_to_set_it() -> None:
    """A bare `MISSING oob.frp_token` row tells the operator nothing actionable."""
    from vigil_cli import status as status_module

    check = status_module._oob_token_check()

    assert check.status == "MISSING"
    assert "oob.frp_token" in check.detail


# --- pre-rename ("tenant") compatibility -------------------------------------
# The OOB relay slot was called a "tenant" until it collided with the blue
# engagement meaning of the word. Installs allocated before the rename keep
# their on-disk records and config keys, so every read path must still see them.


def _pre_rename_record(payload: dict[str, object]) -> dict[str, object]:
    """Re-spell a current routing record the way a pre-rename install wrote it."""
    legacy = dict(payload)
    legacy["tenant_name"] = legacy.pop("slot_name")
    legacy["tenant_prefix"] = legacy.pop("slot_prefix")
    return legacy


def _allocated_route(tmp_path: Path, install_root: Path):
    from vigil_cli.oob_relay import allocate_relay_route

    return allocate_relay_route(
        install_root,
        slot_name="Acme",
        base_domain="oob.example.test",
        registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "acme-id",
        slot_candidates=lambda _identity: [11],
    )


def test_load_relay_route_reads_pre_rename_metadata_without_rewriting_it(
    tmp_path: Path,
) -> None:
    from vigil_cli.oob_relay import (
        LEGACY_RELAY_METADATA_RELATIVE_PATH,
        RELAY_METADATA_RELATIVE_PATH,
        load_relay_route,
    )

    install_root = tmp_path / "install"
    route = _allocated_route(tmp_path, install_root)
    legacy_path = install_root / LEGACY_RELAY_METADATA_RELATIVE_PATH
    legacy_path.write_text(
        json.dumps(_pre_rename_record(route.serializable()), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (install_root / RELAY_METADATA_RELATIVE_PATH).unlink()
    before = legacy_path.read_bytes()

    loaded = load_relay_route(install_root)

    assert loaded is not None
    assert loaded.slot_name == route.slot_name
    assert loaded.slot_prefix == route.slot_prefix
    assert loaded.oob_domain == route.oob_domain
    assert loaded.dns_remote_port == route.dns_remote_port
    assert loaded.metadata_path == legacy_path
    # A read must not migrate the operator's file behind their back.
    assert legacy_path.read_bytes() == before
    assert not (install_root / RELAY_METADATA_RELATIVE_PATH).exists()


def test_pre_rename_metadata_keeps_its_route_through_allocation(tmp_path: Path) -> None:
    """A pre-rename install must never be handed a second, different slot."""
    from vigil_cli.oob_relay import (
        LEGACY_RELAY_METADATA_RELATIVE_PATH,
        RELAY_METADATA_RELATIVE_PATH,
        allocate_relay_route,
    )

    install_root = tmp_path / "install"
    registry = tmp_path / "allocations.json"
    route = _allocated_route(tmp_path, install_root)
    (install_root / LEGACY_RELAY_METADATA_RELATIVE_PATH).write_text(
        json.dumps(_pre_rename_record(route.serializable()), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (install_root / RELAY_METADATA_RELATIVE_PATH).unlink()

    reallocated = allocate_relay_route(
        install_root,
        slot_name="ignored-after-first-write",
        base_domain="changed.example.test",
        registry_path=registry,
        identity_factory=lambda: "must-not-be-used",
    )

    assert reallocated.slot_prefix == route.slot_prefix
    assert reallocated.oob_domain == route.oob_domain
    assert reallocated.dns_remote_port == route.dns_remote_port


def test_allocation_registry_accepts_pre_rename_rows(tmp_path: Path) -> None:
    """A pre-rename row must reconcile as-is, and new rows use the current key."""
    from vigil_cli.oob_relay import (
        allocate_relay_route,
        load_relay_route,
        reconcile_relay_route_registry,
    )

    install_root = tmp_path / "install"
    registry = tmp_path / "allocations.json"
    route = _allocated_route(tmp_path, install_root)
    persisted = json.loads(registry.read_text(encoding="utf-8"))
    row = persisted["allocations"][route.install_id]
    row["tenant_prefix"] = row.pop("slot_prefix")
    registry.write_text(json.dumps(persisted, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    loaded = load_relay_route(install_root)
    assert loaded is not None
    reconciled = reconcile_relay_route_registry(
        loaded, install_root, registry_path=registry
    )
    assert reconciled.slot_prefix == route.slot_prefix

    # A second install writing the same registry must neither trip over the
    # pre-rename row nor be handed its slot. This write is the one flow allowed to
    # normalize the older row, because it rewrites the whole registry anyway.
    newcomer = allocate_relay_route(
        tmp_path / "newcomer",
        slot_name="Newcomer",
        base_domain="oob.example.test",
        registry_path=registry,
        identity_factory=lambda: "newcomer-id",
        slot_candidates=lambda _identity: [11, 12],
    )

    rewritten = json.loads(registry.read_text(encoding="utf-8"))["allocations"]
    assert newcomer.allocation_slot != route.allocation_slot
    assert rewritten[newcomer.install_id]["slot_prefix"] == newcomer.slot_prefix
    assert rewritten[route.install_id]["slot_prefix"] == route.slot_prefix


def test_install_honours_pre_rename_oob_tenant_config_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import load_relay_route

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"oob.domain": "oob.example.test", "oob.tenant": "pre-rename-slot"}),
        encoding="utf-8",
    )
    source_root = tmp_path / "source"
    (source_root / "agent").mkdir(parents=True)
    (source_root / "orchestrator").mkdir(exist_ok=True)
    (source_root / "agent/README").write_text("managed", encoding="utf-8")
    install_root = tmp_path / "install"
    monkeypatch.setenv("VIGIL_CONFIG", str(config_path))

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=install_root,
            verify_docker_image=False,
        )
    )

    route = load_relay_route(install_root)
    assert route is not None
    assert route.slot_name == "pre-rename-slot"
    assert route.slot_prefix.startswith("pre-rename-slot-")


def test_current_oob_slot_config_key_wins_over_the_pre_rename_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import load_relay_route

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "oob.domain": "oob.example.test",
                "oob.slot": "current-slot",
                "oob.tenant": "pre-rename-slot",
            }
        ),
        encoding="utf-8",
    )
    source_root = tmp_path / "source"
    (source_root / "agent").mkdir(parents=True)
    (source_root / "orchestrator").mkdir(exist_ok=True)
    (source_root / "agent/README").write_text("managed", encoding="utf-8")
    install_root = tmp_path / "install"
    monkeypatch.setenv("VIGIL_CONFIG", str(config_path))

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=install_root,
            verify_docker_image=False,
        )
    )

    route = load_relay_route(install_root)
    assert route is not None
    assert route.slot_name == "current-slot"


def test_assess_environment_still_exports_the_pre_rename_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`vigil assess` execs the INSTALLED agent tree, which may predate the rename."""
    from vigil_cli import main as main_module

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    install_root = tmp_path / "install"
    route = _allocated_route(tmp_path, install_root)

    env = main_module._assess_exec_environment(install_root)

    assert env["VIGIL_OOB_SLOT"] == route.slot_prefix
    assert env["VIGIL_OOB_TENANT"] == route.slot_prefix


def test_runtime_route_marker_falls_back_to_the_pre_rename_file_and_key() -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import _runtime_relay_route

    commands: list[str] = []
    legacy_marker = json.dumps(
        {
            "version": 1,
            "tenant_prefix": "acme-0123456789abcdef",
            "oob_domain": "acme-0123456789abcdef.oob.example.test",
            "dns_remote_port": 20022,
            "reverse_remote_port": 20023,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        commands.append(argv[-1])
        if "active-relay-routing.json" in argv[-1]:
            return DockerResult(0, legacy_marker, "")
        return DockerResult(0, "", "")

    route, issue = _runtime_relay_route("vigil", runner=runner)

    assert issue is None
    assert route == {
        "slot_prefix": "acme-0123456789abcdef",
        "oob_domain": "acme-0123456789abcdef.oob.example.test",
        "dns_remote_port": 20022,
        "reverse_remote_port": 20023,
    }
    # The pre-rename marker is still looked for; `/data` is a host bind mount, so a
    # runtime started before the rename keeps that filename across an upgrade.
    assert any("active-tenant-routing.json" in command for command in commands)


def test_client_metadata_falls_back_to_the_pre_rename_route_key() -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, _client_metadata_matches_options, _read_oob_client_metadata

    legacy_metadata = json.dumps(
        {
            "name": "demo",
            "engagement": None,
            "agent": None,
            "server": "acme-0123456789abcdef.oob.example.test",
            "tenant_prefix": "acme-0123456789abcdef",
            "dns_remote_port": 20022,
            "reverse_remote_port": 20023,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        if argv[-1].startswith("cat ") and "clients/demo.json" in argv[-1]:
            return DockerResult(0, legacy_metadata, "")
        return DockerResult(0, "", "")

    metadata, issue = _read_oob_client_metadata("vigil", "demo", runner=runner)

    assert issue is None
    assert metadata is not None
    assert metadata["slot_prefix"] == "acme-0123456789abcdef"
    assert "tenant_prefix" not in metadata
    assert _client_metadata_matches_options(
        metadata,
        OobOptions(
            install_root=Path("/install"),
            slot_prefix="acme-0123456789abcdef",
            oob_domain="acme-0123456789abcdef.oob.example.test",
            dns_remote_port=20022,
            reverse_remote_port=20023,
        ),
    )


def _quiet_oob_runner(commands: list[str]):
    """A `docker exec` runner that lets `start_oob` reach the end unchanged."""
    from vigil_cli.docker import DockerResult

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if command in {
            "tmux has-session -t oob-server",
            "tmux has-session -t frpc",
        }:
            return DockerResult(1, "", "")
        if "tmux list-sessions" in command:
            return DockerResult(0, "", "")
        if command.startswith("cat ") and "active-relay-routing.json" in command:
            return DockerResult(1, "", "")
        return DockerResult(0, "", "")

    return runner


def _unreserved_oob_options(install_root: Path):
    """What `oob_options` resolves for a configured domain with no routing record."""
    from vigil_cli.oob import OobOptions

    return OobOptions(
        install_root=install_root,
        frp_host="frp.example.test",
        frp_token="secret",
        slot_prefix="legacy",
        oob_domain="oob.example.test",
        dns_remote_port=53,
        reverse_remote_port=8443,
    )


def test_start_oob_refuses_a_root_that_never_reserved_a_relay_slot(
    tmp_path: Path,
) -> None:
    """Reaching `oob start` without the allocating install must not proceed.

    With `oob.domain` configured and no routing record, `oob_options` resolves
    the SHARED legacy route — and so does every other install in that state, on
    the same subdomain and the same 53/8443, which makes their callbacks
    indistinguishable. Warning and continuing made that permanent: the rendered
    `frpc.toml` and active-route marker this start leaves in `/data/oob` are
    precisely what `has_pre_routing_oob_state` reads as proof the root is
    already live on the shared route, so the `vigil install` the warning named
    would then pin the legacy route instead of allocating a slot. Doing what the
    message says, in the order it says it, is what stopped it working.
    """
    from vigil_cli.oob import start_oob

    commands: list[str] = []
    with pytest.raises(SystemExit) as excinfo:
        start_oob(
            _unreserved_oob_options(tmp_path),
            runner=_quiet_oob_runner(commands),
            frpc_ready_timeout=0,
        )

    message = str(excinfo.value)
    assert "no relay slot reserved" in message
    assert "vigil install" in message
    assert "53/8443" in message
    # The refusal is only worth anything before the state it warns about exists.
    assert commands == []


def test_a_refused_oob_start_leaves_vigil_install_free_to_allocate_a_slot(
    tmp_path: Path,
) -> None:
    """The remedy the refusal names has to actually work afterwards."""
    from vigil_cli.oob import start_oob
    from vigil_cli.oob_relay import initialize_relay_route

    with pytest.raises(SystemExit):
        start_oob(
            _unreserved_oob_options(tmp_path),
            runner=_quiet_oob_runner([]),
            frpc_ready_timeout=0,
        )

    route = initialize_relay_route(
        tmp_path,
        slot_name="reserved",
        base_domain="oob.example.test",
        registry_path=tmp_path / "allocations.json",
    )
    assert route.legacy is False
    assert (route.dns_remote_port, route.reverse_remote_port) != (53, 8443)


def test_start_oob_still_starts_a_root_already_live_on_the_shared_route(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The legacy population keeps its channel; the refusal is not for them.

    `has_pre_routing_oob_state` identifies exactly the installs whose callbacks
    are already live on 53/8443 and whose correlation would break if their ports
    moved. Starting again does not change what they are, so it is not the start
    that traps them — they warn and continue, and `vigil install` pins the same
    route they are already on.
    """
    from vigil_cli.oob import start_oob

    _seed_live_oob_state(tmp_path)
    start_oob(
        _unreserved_oob_options(tmp_path),
        runner=_quiet_oob_runner([]),
        frpc_ready_timeout=0,
    )

    err = capsys.readouterr().err
    assert "no relay slot reserved" in err
    assert "vigil install" in err
    assert "53/8443" in err


def test_start_oob_is_quiet_when_a_slot_is_reserved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A reserved slot is the normal state and earns no warning."""
    from vigil_cli.oob import OobOptions, start_oob
    from vigil_cli.oob_relay import allocate_relay_route

    route = allocate_relay_route(
        tmp_path,
        slot_name="reserved",
        base_domain="oob.example.test",
        registry_path=tmp_path / "allocations.json",
    )

    start_oob(
        OobOptions(
            install_root=tmp_path,
            frp_host="frp.example.test",
            frp_token="secret",
            slot_prefix=route.slot_prefix,
            oob_domain=route.oob_domain,
            dns_remote_port=route.dns_remote_port,
            reverse_remote_port=route.reverse_remote_port,
            relay_route=route,
        ),
        runner=_quiet_oob_runner([]),
        frpc_ready_timeout=0,
    )

    assert "no relay slot reserved" not in capsys.readouterr().err


def test_start_oob_abort_names_every_key_it_requires(tmp_path: Path) -> None:
    """One refusal, not two — and it must name the token.

    `start_oob` checks host/domain first and the token later, so an operator who
    fixes the two keys the first message names is refused a second time for the
    token. This abort is reachable directly through `vigil oob start`, not only
    via `vigil up`, so it needs the same complete checklist.
    """
    from vigil_cli.oob import OobOptions, start_oob

    with pytest.raises(SystemExit) as excinfo:
        start_oob(OobOptions(install_root=tmp_path, frp_host="", oob_domain="", frp_token=""))

    message = str(excinfo.value)
    for key in ("oob.frp_host", "oob.domain", "oob.frp_token"):
        assert key in message, f"{key} is required but unlisted in the abort"


def test_start_oob_abort_mentions_the_configure_before_install_ordering(tmp_path: Path) -> None:
    """The route is allocated during `vigil install`, and only with a domain set."""
    from vigil_cli.oob import OobOptions, start_oob

    with pytest.raises(SystemExit) as excinfo:
        start_oob(OobOptions(install_root=tmp_path, frp_host="", oob_domain="", frp_token=""))

    assert "vigil install" in str(excinfo.value)


def test_configuring_oob_after_the_first_install_allocates_a_dedicated_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The documented "set `oob.domain`, then `vigil install`" order must work.

    A root that merely exists is not a legacy OOB install: nothing has ever been
    routed through it, so there are no live callbacks whose ports must be held
    still. The retry has to reserve this install its own slot rather than pin
    the shared 53/8443 route every other install would also land on.
    """
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import PORT_BLOCK_START, load_relay_route

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)
    monkeypatch.delenv("VIGIL_RUNTIME_DATA_DIR", raising=False)
    monkeypatch.delenv("KALI_MCP_DATA_DIR", raising=False)
    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator").mkdir(exist_ok=True)
    (source / "orchestrator" / "backend" / "data").mkdir(parents=True)
    (source / "README.md").write_text("managed\n", encoding="utf-8")
    install_root = tmp_path / "install"

    # First install: no domain configured, so no route is written.
    install_from_source(
        InstallOptions(
            source_root=source, install_root=install_root, verify_docker_image=False
        )
    )
    assert load_relay_route(install_root) is None
    assert "oob.domain" in capsys.readouterr().err

    # Operator now follows the guidance: configure the domain, re-run install.
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.com")
    install_from_source(
        InstallOptions(
            source_root=source, install_root=install_root, verify_docker_image=False
        )
    )

    route = load_relay_route(install_root)
    assert route is not None
    assert route.legacy is False, (
        "a root that never ran OOB must be allocated its own slot, not the shared route"
    )
    assert route.base_domain == "oob.example.com"
    assert route.oob_domain == f"{route.slot_prefix}.oob.example.com"
    assert route.dns_remote_port >= PORT_BLOCK_START
    assert route.reverse_remote_port == route.dns_remote_port + 1
    registry = json.loads(
        (tmp_path / "oob-allocations.json").read_text(encoding="utf-8")
    )
    assert registry["allocations"][route.install_id]["install_root"] == str(
        install_root
    )


def test_install_preserves_the_legacy_route_of_a_root_that_already_ran_oob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A root with live OOB state keeps the shared 53/8443 route it is using.

    `vigil oob start` with no routing record resolves the shared legacy route
    (`oob.oob_options`), so this install's callbacks are already correlating on
    the base domain and those ports. Moving them to a fresh slot would break
    in-flight correlation for a running engagement.
    """
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import load_relay_route

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)
    monkeypatch.delenv("VIGIL_RUNTIME_DATA_DIR", raising=False)
    monkeypatch.delenv("KALI_MCP_DATA_DIR", raising=False)
    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator").mkdir(exist_ok=True)
    (source / "README.md").write_text("managed\n", encoding="utf-8")
    install_root = tmp_path / "install"

    install_from_source(
        InstallOptions(
            source_root=source, install_root=install_root, verify_docker_image=False
        )
    )

    # What a pre-routing `vigil oob start` leaves behind on this host.
    oob_state = install_root / ".runtime-data" / "oob"
    (oob_state / "clients").mkdir(parents=True)
    (oob_state / "frpc.toml").write_text("serverAddr = 'relay'\n", encoding="utf-8")
    (oob_state / "clients" / "ssrf.session").write_text("correlation", encoding="utf-8")

    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.com")
    install_from_source(
        InstallOptions(
            source_root=source, install_root=install_root, verify_docker_image=False
        )
    )

    route = load_relay_route(install_root)
    assert route is not None
    assert route.legacy is True
    assert route.oob_domain == "oob.example.com"
    assert (route.dns_remote_port, route.reverse_remote_port) == (53, 8443)
    assert (oob_state / "clients" / "ssrf.session").read_text() == "correlation"
    # A pinned legacy route owns no slot, so it must claim no registry block.
    assert not (tmp_path / "oob-allocations.json").exists()


def test_relocated_runtime_data_dir_still_proves_a_live_legacy_oob_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OOB state follows the container's `/data` mount, which is relocatable.

    With `VIGIL_RUNTIME_DATA_DIR` set, `frpc.toml` and the per-client files land
    outside `<install>/.runtime-data`. Looking only there would read a live
    legacy install as never-configured and move its ports.
    """
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import load_relay_route

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.com")
    data_dir = tmp_path / "elsewhere"
    monkeypatch.setenv("VIGIL_RUNTIME_DATA_DIR", str(data_dir))
    monkeypatch.delenv("KALI_MCP_DATA_DIR", raising=False)
    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator").mkdir(exist_ok=True)
    (source / "README.md").write_text("managed\n", encoding="utf-8")
    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements" / "existing").mkdir(parents=True)
    (data_dir / "oob" / "clients").mkdir(parents=True)
    (data_dir / "oob" / "frpc.log").write_text("start proxy success\n", encoding="utf-8")

    install_from_source(
        InstallOptions(
            source_root=source, install_root=install_root, verify_docker_image=False
        )
    )

    route = load_relay_route(install_root)
    assert route is not None
    assert route.legacy is True
    assert (route.dns_remote_port, route.reverse_remote_port) == (53, 8443)


def test_deferred_configuration_leaves_an_allocated_slot_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once a slot exists, further installs reconcile it and change nothing."""
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import load_relay_route

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.com")
    monkeypatch.delenv("VIGIL_RUNTIME_DATA_DIR", raising=False)
    monkeypatch.delenv("KALI_MCP_DATA_DIR", raising=False)
    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator").mkdir(exist_ok=True)
    (source / "README.md").write_text("managed\n", encoding="utf-8")
    install_root = tmp_path / "install"

    install_from_source(
        InstallOptions(
            source_root=source, install_root=install_root, verify_docker_image=False
        )
    )
    allocated = load_relay_route(install_root)
    assert allocated is not None and allocated.legacy is False

    # A later `vigil oob start` leaves state behind; that must not now be read
    # as legacy evidence and re-pin a route this install already owns.
    (install_root / ".runtime-data" / "oob" / "frpc.log").write_text(
        "start proxy success\n", encoding="utf-8"
    )
    install_from_source(
        InstallOptions(
            source_root=source, install_root=install_root, verify_docker_image=False
        )
    )

    assert load_relay_route(install_root) == allocated
    registry = json.loads(
        (tmp_path / "oob-allocations.json").read_text(encoding="utf-8")
    )
    assert list(registry["allocations"]) == [allocated.install_id]


def test_deferred_configuration_keeps_a_pre_rename_record_and_slot_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deferred path must still read `tenant-routing.json` and `oob.tenant`.

    An install that allocated before the relay-slot rename owns its slot under
    the old spellings; configuring `oob.domain` afterwards must reconcile that
    record rather than mint a second one, and the pre-rename config key must
    still name the slot when nothing has been allocated yet.
    """
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import (
        LEGACY_RELAY_METADATA_RELATIVE_PATH,
        RELAY_METADATA_RELATIVE_PATH,
        load_relay_route,
    )

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"oob.domain": "oob.example.test", "oob.tenant": "pre-rename-slot"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("VIGIL_CONFIG", str(config_path))
    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)
    monkeypatch.delenv("VIGIL_RUNTIME_DATA_DIR", raising=False)
    monkeypatch.delenv("KALI_MCP_DATA_DIR", raising=False)
    source = tmp_path / "source"
    (source / "agent" / "engagements").mkdir(parents=True)
    (source / "orchestrator").mkdir(exist_ok=True)
    (source / "README.md").write_text("managed\n", encoding="utf-8")

    # A root whose only routing record is the pre-rename file.
    pre_rename_root = tmp_path / "pre-rename"
    existing = _allocated_route(tmp_path, pre_rename_root)
    (pre_rename_root / LEGACY_RELAY_METADATA_RELATIVE_PATH).write_text(
        json.dumps(_pre_rename_record(existing.serializable()), indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (pre_rename_root / RELAY_METADATA_RELATIVE_PATH).unlink()

    install_from_source(
        InstallOptions(
            source_root=source,
            install_root=pre_rename_root,
            verify_docker_image=False,
        )
    )

    kept = load_relay_route(pre_rename_root)
    assert kept is not None
    assert kept.slot_prefix == existing.slot_prefix
    assert kept.oob_domain == existing.oob_domain
    assert kept.metadata_path == pre_rename_root / LEGACY_RELAY_METADATA_RELATIVE_PATH
    assert not (pre_rename_root / RELAY_METADATA_RELATIVE_PATH).exists()

    # A never-configured root under the same config allocates under the
    # pre-rename slot name.
    fresh_root = tmp_path / "fresh"
    fresh_root.mkdir()
    (fresh_root / ".runtime-data").mkdir()
    install_from_source(
        InstallOptions(
            source_root=source, install_root=fresh_root, verify_docker_image=False
        )
    )

    allocated = load_relay_route(fresh_root)
    assert allocated is not None
    assert allocated.legacy is False
    assert allocated.slot_name == "pre-rename-slot"
    assert allocated.slot_prefix.startswith("pre-rename-slot-")


def _seed_live_oob_state(install_root: Path) -> None:
    """Leave behind exactly what `vigil oob start` leaves behind.

    A rendered ``frpc.toml`` is the discriminator ``has_pre_routing_oob_state``
    reads; routing records are bookkeeping and deliberately do not count.
    """
    from vigil_cli.oob_relay import OOB_STATE_RELATIVE_PATH

    state_dir = install_root / OOB_STATE_RELATIVE_PATH
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "frpc.toml").write_text("[common]\n", encoding="utf-8")


def test_doctor_route_row_omits_the_legacy_reassurance_on_a_fresh_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The parenthetical describes state a fresh root does not have.

    `install.py` already makes the equivalent sentence conditional; the doctor
    row has to agree, or the two halves of the same answer contradict each other.
    """
    from vigil_cli.status import _oob_relay_check

    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)
    install_root = tmp_path / "fresh"
    install_root.mkdir()

    check = _oob_relay_check(install_root)

    assert check.status == "WARN"
    assert "53/8443" not in check.detail
    assert "reserves this install its own relay slot" in check.detail


def test_doctor_route_row_keeps_the_legacy_reassurance_for_a_root_running_oob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.status import _oob_relay_check

    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)
    install_root = tmp_path / "legacy"
    install_root.mkdir()
    _seed_live_oob_state(install_root)

    check = _oob_relay_check(install_root)

    assert check.status == "WARN"
    assert "keeps that route instead" in check.detail


def test_doctor_metadata_row_names_allocation_or_pinning_but_never_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a domain set, the remedy depends on whether callbacks are already live."""
    from vigil_cli.status import _oob_relay_check

    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example")
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    _seed_live_oob_state(legacy)

    fresh_detail = _oob_relay_check(fresh).detail
    legacy_detail = _oob_relay_check(legacy).detail

    assert "allocate this install's slot" in fresh_detail
    assert "53/8443" not in fresh_detail
    assert "pin the shared 53/8443 route" in legacy_detail
    assert "allocate" not in legacy_detail
