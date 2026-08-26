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


def test_oob_tenant_module_imports_when_fcntl_is_unavailable() -> None:
    script = """
import builtins
real_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == 'fcntl':
        raise ModuleNotFoundError('simulated Windows')
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
import vigil_cli.oob_tenants
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
    import vigil_cli.oob_tenants as tenants

    class FakeMsvcrt:
        LK_LOCK = 1
        LK_UNLCK = 2

        def __init__(self) -> None:
            self.calls: list[tuple[int, int]] = []

        def locking(self, _fd: int, mode: int, count: int) -> None:
            self.calls.append((mode, count))

    backend = FakeMsvcrt()
    monkeypatch.setattr(tenants, "_fcntl", None)
    monkeypatch.setattr(tenants, "_msvcrt", backend)
    with (tmp_path / "route.lock").open("a+", encoding="utf-8") as handle:
        tenants._lock_file(handle)
        tenants._unlock_file(handle)

    assert backend.calls == [(backend.LK_LOCK, 1), (backend.LK_UNLCK, 1)]
    assert (tmp_path / "route.lock").stat().st_size == 1


def test_fresh_tenant_allocation_is_sanitized_stable_and_persisted(tmp_path: Path) -> None:
    from vigil_cli.oob_tenants import allocate_tenant_route

    install_root = tmp_path / "Customer Alpha"
    registry = tmp_path / "allocations.json"

    first = allocate_tenant_route(
        install_root,
        tenant_name=" Customer Alpha ",
        base_domain="oob.example.test",
        registry_path=registry,
        identity_factory=lambda: "install-identity-a",
    )
    second = allocate_tenant_route(
        install_root,
        tenant_name="ignored-after-first-write",
        base_domain="changed.example.test",
        registry_path=registry,
        identity_factory=lambda: "must-not-be-used",
    )

    assert first == second
    assert first.tenant_prefix == "customer-alpha-be3e46b6d1911ed7"
    assert first.oob_domain == "customer-alpha-be3e46b6d1911ed7.oob.example.test"
    assert first.dns_remote_port != 53
    assert first.reverse_remote_port == first.dns_remote_port + 1
    assert first.metadata_path == install_root / ".runtime-data/oob/tenant-routing.json"
    assert json.loads(first.metadata_path.read_text())["tenant_prefix"] == first.tenant_prefix


@pytest.mark.parametrize("tenant", ["", "   ", ".", "../escape", "a/b", "🔥"])
def test_tenant_allocation_rejects_malformed_identity(tmp_path: Path, tenant: str) -> None:
    from vigil_cli.oob_tenants import allocate_tenant_route

    with pytest.raises(SystemExit, match="tenant"):
        allocate_tenant_route(
            tmp_path / "install",
            tenant_name=tenant,
            registry_path=tmp_path / "allocations.json",
        )


def test_colliding_candidate_slot_moves_to_next_free_block(tmp_path: Path) -> None:
    from vigil_cli.oob_tenants import allocate_tenant_route

    registry = tmp_path / "allocations.json"
    one = allocate_tenant_route(
        tmp_path / "one",
        tenant_name="one",
        registry_path=registry,
        identity_factory=lambda: "identity-one",
        slot_candidates=lambda _identity: [7, 8],
    )
    two = allocate_tenant_route(
        tmp_path / "two",
        tenant_name="two",
        registry_path=registry,
        identity_factory=lambda: "identity-two",
        slot_candidates=lambda _identity: [7, 8],
    )

    assert one.allocation_slot == 7
    assert two.allocation_slot == 8
    assert one.port_range != two.port_range
    assert one.oob_domain != two.oob_domain


def test_duplicate_install_identity_cannot_overwrite_another_tenant(tmp_path: Path) -> None:
    from vigil_cli.oob_tenants import allocate_tenant_route

    registry = tmp_path / "allocations.json"
    first = allocate_tenant_route(
        tmp_path / "one", tenant_name="one", registry_path=registry,
        identity_factory=lambda: "same-install-id", slot_candidates=lambda _: [1],
    )
    with pytest.raises(SystemExit, match="identity collision"):
        allocate_tenant_route(
            tmp_path / "two", tenant_name="two", registry_path=registry,
            identity_factory=lambda: "same-install-id", slot_candidates=lambda _: [2],
        )
    payload = json.loads(registry.read_text())
    assert payload["allocations"]["same-install-id"]["oob_domain"] == first.oob_domain


def test_concurrent_allocation_of_one_install_returns_one_identity(tmp_path: Path) -> None:
    from vigil_cli.oob_tenants import allocate_tenant_route

    install_root = tmp_path / "shared"
    registry = tmp_path / "allocations.json"
    identities = iter(f"identity-{index}" for index in range(20))

    def allocate():
        return allocate_tenant_route(
            install_root,
            tenant_name="shared",
            registry_path=registry,
            identity_factory=lambda: next(identities),
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        routes = list(pool.map(lambda _index: allocate(), range(16)))

    assert len({route.install_id for route in routes}) == 1
    assert len({route.allocation_slot for route in routes}) == 1
    assert len(json.loads(registry.read_text())["allocations"]) == 1


def test_upgrade_without_metadata_pins_legacy_route_and_preserves_clients(tmp_path: Path) -> None:
    from vigil_cli.oob_tenants import initialize_tenant_route

    install_root = tmp_path / "existing"
    legacy_client = install_root / ".runtime-data/oob/clients/ssrf.session"
    legacy_client.parent.mkdir(parents=True)
    legacy_client.write_text("correlation material", encoding="utf-8")

    route = initialize_tenant_route(
        install_root,
        is_upgrade=True,
        base_domain="oob.example.test",
        registry_path=tmp_path / "allocations.json",
    )

    assert route.legacy is True
    assert route.oob_domain == "oob.example.test"
    assert route.dns_remote_port == 53
    assert route.reverse_remote_port == 8443
    assert legacy_client.read_text() == "correlation material"


def test_failed_metadata_publish_rolls_back_registry_allocation(tmp_path: Path) -> None:
    import vigil_cli.oob_tenants as tenant_module

    registry = tmp_path / "allocations.json"

    def fail_metadata(path: Path, payload: dict[str, object]) -> None:
        if path.name == "tenant-routing.json":
            raise OSError("disk full")
        tenant_module._atomic_write_json_real(path, payload)

    with pytest.raises(OSError, match="disk full"):
        tenant_module.allocate_tenant_route(
            tmp_path / "broken",
            tenant_name="broken",
            registry_path=registry,
            atomic_writer=fail_metadata,
        )

    payload = json.loads(registry.read_text())
    assert payload["allocations"] == {}
    assert not (tmp_path / "broken/.runtime-data/oob/tenant-routing.json").exists()


def test_tenant_metadata_rejects_corrupt_or_silently_changed_routing(tmp_path: Path) -> None:
    from vigil_cli.oob_tenants import TENANT_METADATA_RELATIVE_PATH, load_tenant_route

    install_root = tmp_path / "install"
    path = install_root / TENANT_METADATA_RELATIVE_PATH
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "install_id": "id",
                "tenant_name": "alpha",
                "tenant_prefix": "alpha-00000000",
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
        load_tenant_route(install_root)


def test_edge_routing_config_is_deterministic_and_tenant_specific(tmp_path: Path) -> None:
    from vigil_cli.oob_tenants import allocate_tenant_route, render_edge_routing

    route = allocate_tenant_route(
        tmp_path / "tenant",
        tenant_name="Acme",
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


def test_oob_options_and_assess_environment_consume_resolved_tenant_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import main as main_module
    from vigil_cli.oob import oob_options
    from vigil_cli.oob_tenants import allocate_tenant_route

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    install_root = tmp_path / "tenant"
    route = allocate_tenant_route(
        install_root,
        tenant_name="Acme",
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
    assert env["VIGIL_OOB_TENANT"] == route.tenant_prefix
    assert env["VIGIL_OOB_DNS_PORT"] == str(route.dns_remote_port)
    assert env["VIGIL_OOB_REVERSE_PORT"] == str(route.reverse_remote_port)


def test_external_domain_override_cannot_replace_persisted_vigil_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.oob import oob_options
    from vigil_cli.oob_tenants import allocate_tenant_route

    install_root = tmp_path / "tenant"
    route = allocate_tenant_route(
        install_root, tenant_name="Acme", registry_path=tmp_path / "allocations.json",
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
    assert options.tenant_route is not None
    assert options.tenant_route.base_domain == "custom.example.test"
    assert options.oob_domain.endswith(".custom.example.test")


def test_fresh_install_allocates_route_but_upgrade_pins_legacy_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_tenants import load_tenant_route

    source_root = tmp_path / "source"
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    (source_root / "agent").mkdir(parents=True)
    (source_root / "agent/README").write_text("managed", encoding="utf-8")
    fresh_root = tmp_path / "fresh-tenant"
    fresh = install_from_source(
        InstallOptions(source_root=source_root, install_root=fresh_root, verify_docker_image=False)
    )
    fresh_route = load_tenant_route(fresh_root)
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
    upgrade_route = load_tenant_route(upgrade_root)
    assert upgraded.is_upgrade is True
    assert upgrade_route is not None and upgrade_route.legacy is True
    assert correlation.read_text() == "keep"


def test_runtime_frp_and_client_metadata_use_tenant_route(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import OobOptions, _render_runtime_files, start_oob_client

    commands: list[str] = []
    runtime_route = json.dumps(
        {
            "version": 1,
            "tenant_prefix": "acme-12345678",
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
        if command.startswith("cat ") and "active-tenant-routing.json" in command:
            return DockerResult(0, runtime_route, "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(1, "", "")
        return DockerResult(0, "", "")

    options = OobOptions(
        install_root=tmp_path,
        frp_token="secret",
        oob_domain="acme-12345678.oob.example.test",
        tenant_prefix="acme-12345678",
        dns_remote_port=20120,
        reverse_remote_port=20121,
    )
    _render_runtime_files(options, runner=runner)
    start_oob_client(options, "agent-a", engagement="eng", runner=runner)
    rendered = "\n".join(commands)
    assert "remotePort = 20120" in rendered
    assert "remotePort = 20121" in rendered
    assert '"tenant_prefix": "acme-12345678"' in rendered
    assert '"dns_remote_port": 20120' in rendered
    assert "/data/oob/active-tenant-routing.json" in rendered
    assert "Path('/data/oob/tenant-routing.json').write_text" not in rendered
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
            "tenant_prefix": "acme",
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
        tenant_prefix="acme",
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
        if "active-tenant-routing.json" in command:
            return DockerResult(1, "", "")
        if "/clients/legacy-agent.json" in command:
            return DockerResult(1, "", "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="running OOB client.*cannot be verified"):
        start_oob(
            OobOptions(
                install_root=tmp_path,
                frp_token="secret",
                tenant_prefix="tenant-new",
                oob_domain="tenant-new.oob.example.test",
                dns_remote_port=20120,
                reverse_remote_port=20121,
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
            "tenant_prefix": "tenant-old",
            "oob_domain": "tenant-old.oob.example.test",
            "dns_remote_port": 20010,
            "reverse_remote_port": 20011,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "active-tenant-routing.json" in command:
            return DockerResult(0, old_route, "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="runtime route.*does not match"):
        start_oob_client(
            OobOptions(
                install_root=tmp_path,
                tenant_prefix="tenant-new",
                oob_domain="tenant-new.oob.example.test",
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
        "tenant_prefix": "tenant-new",
        "oob_domain": "tenant-new.oob.example.test",
        "dns_remote_port": 20120,
        "reverse_remote_port": 20121,
    }
    old_client_metadata = json.dumps(
        {
            "name": "agent-a",
            "engagement": "old-engagement",
            "agent": "old-agent",
            "server": "tenant-old.oob.example.test",
            "tenant_prefix": "tenant-old",
            "dns_remote_port": 20010,
            "reverse_remote_port": 20011,
        }
    )

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "active-tenant-routing.json" in command:
            return DockerResult(0, json.dumps(requested_route), "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(0, "", "")
        if "/clients/agent-a.json" in command and command.startswith("cat "):
            return DockerResult(0, old_client_metadata, "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="running OOB client.*another tenant route"):
        start_oob_client(
            OobOptions(
                install_root=tmp_path,
                tenant_prefix="tenant-new",
                oob_domain="tenant-new.oob.example.test",
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
        "tenant_prefix": "tenant-a",
        "oob_domain": "tenant-a.oob.example.test",
        "dns_remote_port": 20010,
        "reverse_remote_port": 20011,
    }
    metadata = {
        "name": "agent-a",
        "engagement": "eng-a",
        "agent": "hunter",
        "server": route["oob_domain"],
        "tenant_prefix": route["tenant_prefix"],
        "dns_remote_port": route["dns_remote_port"],
        "reverse_remote_port": route["reverse_remote_port"],
    }

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        commands.append(command)
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "active-tenant-routing.json" in command:
            return DockerResult(0, json.dumps(route), "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(0, "", "")
        if command.startswith("cat ") and "/clients/agent-a.json" in command:
            return DockerResult(0, json.dumps(metadata), "")
        return DockerResult(0, "", "")

    start_oob_client(
        OobOptions(
            install_root=tmp_path,
            tenant_prefix="tenant-a",
            oob_domain="tenant-a.oob.example.test",
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
        "tenant_prefix": "legacy",
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
        if "active-tenant-routing.json" in command:
            return DockerResult(0, json.dumps(route), "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(0, "", "")
        if command.startswith("cat ") and "/clients/agent-a.json" in command:
            return DockerResult(0, json.dumps(legacy_metadata), "")
        return DockerResult(0, "", "")

    start_oob_client(
        OobOptions(
            install_root=tmp_path,
            tenant_prefix="legacy",
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
        if command.startswith("cat ") and "active-tenant-routing.json" in command:
            return DockerResult(1, "", "")
        if command.startswith("cat ") and "/clients/agent-a.json" in command:
            return DockerResult(0, json.dumps(legacy_metadata), "")
        return DockerResult(0, "", "")

    start_oob(
        OobOptions(
            install_root=tmp_path,
            frp_token="secret",
            tenant_prefix="legacy",
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
                "tenant_prefix": "legacy",
                "oob_domain": "oob.example.test",
                "dns_remote_port": 53,
                "reverse_remote_port": 8443,
            },
            "foreign.example.test",
        ),
        (
            {
                "tenant_prefix": "legacy",
                "oob_domain": "oob.example.test",
                "dns_remote_port": 20010,
                "reverse_remote_port": 20011,
            },
            "oob.example.test",
        ),
        (
            {
                "tenant_prefix": "tenant-a",
                "oob_domain": "tenant-a.oob.example.test",
                "dns_remote_port": 20010,
                "reverse_remote_port": 20011,
            },
            "tenant-a.oob.example.test",
        ),
    ],
    ids=["foreign-domain", "nonlegacy-ports", "nonlegacy-tenant"],
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
        if "active-tenant-routing.json" in command:
            return DockerResult(0, json.dumps(route), "")
        if command == "tmux has-session -t oob-client-agent-a":
            return DockerResult(0, "", "")
        if command.startswith("cat ") and "/clients/agent-a.json" in command:
            return DockerResult(0, json.dumps(legacy_metadata), "")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit, match="another tenant route"):
        start_oob_client(
            OobOptions(install_root=tmp_path, **options_kwargs),
            "agent-a",
            engagement="eng-a",
            agent="hunter",
            runner=runner,
        )

    assert not any("write_text" in command for command in commands)


def test_health_status_and_doctor_surface_tenant_routing(tmp_path: Path) -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import oob_status
    from vigil_cli.oob_tenants import allocate_tenant_route
    from vigil_cli.status import _oob_tenant_check

    route = allocate_tenant_route(
        tmp_path / "tenant", tenant_name="Acme", registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "acme-id", slot_candidates=lambda _: [11],
    )

    def runner(_argv: list[str], **_: object) -> DockerResult:
        return DockerResult(0, "", "")

    payload = oob_status(
        oob_domain=route.oob_domain,
        tenant_prefix=route.tenant_prefix,
        dns_remote_port=route.dns_remote_port,
        reverse_remote_port=route.reverse_remote_port,
        runner=runner,
        deep=False,
    )
    assert payload["tenant_prefix"] == route.tenant_prefix
    assert payload["port_range"] == [route.dns_remote_port, route.reverse_remote_port]
    check = _oob_tenant_check(tmp_path / "tenant")
    assert check.status == "OK"
    assert route.tenant_prefix in check.detail


def test_oob_routing_cli_emits_deployment_metadata_without_mutating_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli import main as main_module
    from vigil_cli.oob_tenants import allocate_tenant_route

    install_root = tmp_path / "tenant"
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    route = allocate_tenant_route(
        install_root, tenant_name="Acme", registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "acme-id", slot_candidates=lambda _: [11],
    )

    main_module.main(["--root", str(install_root), "oob", "routing", "--format", "json"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["domain"] == route.oob_domain
    assert payload["dns_upstream"].endswith(str(route.dns_remote_port))
    assert payload["reverse_tcp_port"] == route.reverse_remote_port


def test_cross_tenant_client_payload_and_correlation_are_isolated(tmp_path: Path) -> None:
    from vigil_cli.oob import (
        interactions_for_domain,
        match_interactions_to_nonces,
        parse_client_payload_host,
        parse_interactsh_log,
    )
    from vigil_cli.oob_tenants import allocate_tenant_route

    registry = tmp_path / "allocations.json"
    alpha = allocate_tenant_route(
        tmp_path / "alpha", tenant_name="alpha", registry_path=registry,
        identity_factory=lambda: "alpha-id", slot_candidates=lambda _: [1],
    )
    beta = allocate_tenant_route(
        tmp_path / "beta", tenant_name="beta", registry_path=registry,
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


def test_tenant_filter_admits_compact_interactsh_client_callback() -> None:
    """Current interactsh -v logs omit the configured domain from callback brackets."""
    from vigil_cli.oob import interactions_for_domain, parse_interactsh_log

    callback = parse_interactsh_log(
        "[eng-probe.client-correlation-id] Received DNS interaction (A) "
        "from 192.0.2.2 at 2026-07-16T21:35:00Z\n"
    )

    admitted = interactions_for_domain(
        callback,
        "tenant.oob.example.com",
        client_payload_host="client-correlation-id.tenant.oob.example.com",
    )

    assert admitted == callback


def test_tenant_filter_rejects_compact_callback_for_another_client() -> None:
    """A short callback has no tenant suffix and must match the selected client."""
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
    from vigil_cli.oob_tenants import allocate_tenant_route

    registry = tmp_path / "allocations.json"
    original = allocate_tenant_route(
        tmp_path / "original",
        tenant_name="original",
        registry_path=registry,
        identity_factory=lambda: "original-id",
        slot_candidates=lambda _: [9],
    )
    registry.write_text(json.dumps({"version": 1, "allocations": {}}), encoding="utf-8")

    restored = allocate_tenant_route(
        tmp_path / "original",
        tenant_name="ignored",
        registry_path=registry,
        identity_factory=lambda: pytest.fail("existing metadata must supply identity"),
    )
    newcomer = allocate_tenant_route(
        tmp_path / "newcomer",
        tenant_name="newcomer",
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
    from vigil_cli.oob_tenants import TENANT_METADATA_RELATIVE_PATH, allocate_tenant_route

    registry = tmp_path / "allocations.json"
    original_root = tmp_path / "original"
    clone_root = tmp_path / "clone"
    allocate_tenant_route(
        original_root,
        tenant_name="original",
        registry_path=registry,
        identity_factory=lambda: "shared-id",
        slot_candidates=lambda _: [4],
    )
    clone_path = clone_root / TENANT_METADATA_RELATIVE_PATH
    clone_path.parent.mkdir(parents=True)
    shutil.copy2(original_root / TENANT_METADATA_RELATIVE_PATH, clone_path)

    with pytest.raises(SystemExit, match="another install root"):
        allocate_tenant_route(
            clone_root,
            tenant_name="clone",
            registry_path=registry,
        )


@pytest.mark.parametrize(
    "domain",
    ["", ".", "*.example.test", "bad_domain.test", "evil.test\n}\nattacker {"],
)
def test_allocator_rejects_non_dns_base_domains(tmp_path: Path, domain: str) -> None:
    from vigil_cli.oob_tenants import allocate_tenant_route

    with pytest.raises(SystemExit, match="domain"):
        allocate_tenant_route(
            tmp_path / "install",
            tenant_name="tenant",
            base_domain=domain,
            registry_path=tmp_path / "allocations.json",
        )


def test_allocator_rejects_base_domain_when_tenant_domain_exceeds_dns_limit(
    tmp_path: Path,
) -> None:
    from vigil_cli.oob_tenants import allocate_tenant_route

    base_domain = f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 61}"
    assert len(base_domain) == 253
    with pytest.raises(SystemExit, match="domain"):
        allocate_tenant_route(
            tmp_path / "install",
            tenant_name="tenant",
            base_domain=base_domain,
            registry_path=tmp_path / "allocations.json",
            identity_factory=lambda: "tenant-id",
            slot_candidates=lambda _: [1],
        )


def test_upgrade_pins_ambient_domain_that_was_effective_before_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_tenants import load_tenant_route

    source_root = tmp_path / "source"
    install_root = tmp_path / "upgrade"
    (source_root / "agent").mkdir(parents=True)
    (source_root / "agent/README").write_text("managed", encoding="utf-8")
    (install_root / "agent/engagements/existing").mkdir(parents=True)
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "legacy.custom.test")

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=install_root,
            verify_docker_image=False,
        )
    )

    route = load_tenant_route(install_root)
    assert route is not None and route.legacy
    assert route.oob_domain == "legacy.custom.test"


def test_metadata_parent_symlink_cannot_escape_install_root(tmp_path: Path) -> None:
    from vigil_cli.oob_tenants import allocate_tenant_route

    install_root = tmp_path / "install"
    outside = tmp_path / "outside"
    outside.mkdir()
    install_root.mkdir()
    (install_root / ".runtime-data").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SystemExit, match="escapes install root"):
        allocate_tenant_route(
            install_root,
            tenant_name="tenant",
            registry_path=tmp_path / "allocations.json",
        )
    assert not (outside / "oob/tenant-routing.json").exists()


def test_metadata_file_symlink_is_rejected(tmp_path: Path) -> None:
    from vigil_cli.oob_tenants import (
        TENANT_METADATA_RELATIVE_PATH,
        allocate_tenant_route,
        load_tenant_route,
    )

    source_root = tmp_path / "source"
    source = allocate_tenant_route(
        source_root,
        tenant_name="source",
        registry_path=tmp_path / "allocations.json",
        identity_factory=lambda: "source-id",
        slot_candidates=lambda _: [1],
    )
    install_root = tmp_path / "install"
    linked = install_root / TENANT_METADATA_RELATIVE_PATH
    linked.parent.mkdir(parents=True)
    linked.symlink_to(source.metadata_path)

    with pytest.raises(SystemExit, match="symlink"):
        load_tenant_route(install_root)


def test_atomic_writer_tolerates_unsupported_directory_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import vigil_cli.oob_tenants as tenants

    real_open = tenants.os.open

    def portable_open(path: object, flags: int, *args: object) -> int:
        if Path(path) == tmp_path and flags == os.O_RDONLY:
            raise PermissionError("directory handles are unsupported")
        return real_open(path, flags, *args)

    monkeypatch.setattr(tenants.os, "open", portable_open)
    destination = tmp_path / "routing.json"
    tenants._atomic_write_json_real(destination, {"safe": True})

    assert json.loads(destination.read_text(encoding="utf-8")) == {"safe": True}


def test_atomic_writer_does_not_follow_predictable_temporary_symlink(
    tmp_path: Path,
) -> None:
    import vigil_cli.oob_tenants as tenants

    destination = tmp_path / "routing.json"
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    temporary.symlink_to(victim)

    with pytest.raises(FileExistsError):
        tenants._atomic_write_json_real(destination, {"safe": True})
    assert victim.read_text(encoding="utf-8") == "keep"


def test_frp_proxy_names_are_stable_and_derived_from_tenant_not_container(
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
            tenant_prefix="tenant-a-0123456789abcdef",
            oob_domain="tenant-a-0123456789abcdef.oob.example.test",
        ),
        runner=runner,
    )
    rendered = "\n".join(commands)
    assert "prefix = socket.gethostname" not in rendered
    assert 'name = "vigil-' in rendered


def test_oob_status_degrades_when_live_runtime_belongs_to_another_tenant() -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import oob_status

    runtime_route = json.dumps(
        {
            "tenant_prefix": "tenant-a",
            "oob_domain": "tenant-a.oob.example.test",
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
        if "tenant-routing.json" in command:
            return DockerResult(0, runtime_route, "")
        if "tmux list-sessions" in command:
            return DockerResult(0, "", "")
        return DockerResult(0, "", "")

    payload = oob_status(
        oob_domain="tenant-b.oob.example.test",
        tenant_prefix="tenant-b",
        dns_remote_port=20020,
        reverse_remote_port=20021,
        runner=runner,
        deep=False,
    )
    assert payload["route_matches"] is False
    assert payload["health"] == "degraded"
    assert any("another tenant" in issue for issue in payload["issues"])


def test_oob_status_treats_malformed_runtime_marker_as_route_mismatch() -> None:
    from vigil_cli.docker import DockerResult
    from vigil_cli.oob import oob_status

    def runner(argv: list[str], **_: object) -> DockerResult:
        command = argv[-1] if argv else ""
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if "tmux has-session" in command:
            return DockerResult(0, "", "")
        if "tenant-routing.json" in command:
            return DockerResult(0, "{not-json", "")
        return DockerResult(0, "", "")

    payload = oob_status(runner=runner, deep=False)

    assert payload["route_matches"] is False
    assert payload["health"] == "degraded"
    assert any("marker is invalid" in issue for issue in payload["issues"])


def test_up_refuses_to_reuse_active_oob_sessions_from_another_tenant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from vigil_cli import up
    from vigil_cli.oob import OobOptions

    monkeypatch.setattr(
        up,
        "_oob_options",
        lambda _root: OobOptions(
            install_root=tmp_path,
            tenant_prefix="tenant-b",
            oob_domain="tenant-b.oob.example.test",
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
        lambda *_args, **_kwargs: pytest.fail("must not mutate another tenant's sessions"),
    )

    with pytest.raises(SystemExit, match="another tenant"):
        up._start_oob_if_needed(tmp_path, runner=lambda _argv: None)
