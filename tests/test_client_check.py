"""Client diagnostics remain useful without activating any engagement."""
from __future__ import annotations

import json
import hashlib
import plistlib
import subprocess
from pathlib import Path

import pytest

from vigil_cli import main as cli
from vigil_cli import client_checks


@pytest.fixture(autouse=True)
def isolated_client_discovery(monkeypatch):
    monkeypatch.setattr(client_checks.shutil, "which", lambda name: None)
    monkeypatch.setattr(client_checks.sys, "platform", "linux")
    monkeypatch.delenv("VIGIL_CLIENT_CONTEXT", raising=False)
    monkeypatch.delenv("VIGIL_SESSION_ENGAGEMENT_DIR", raising=False)


@pytest.mark.parametrize("client", ["opencode", "zcode"])
def test_client_check_is_available_without_an_active_engagement(tmp_path, monkeypatch, capsys, client):
    monkeypatch.setattr(cli, "_preflight_engagement_start", lambda *a, **k: pytest.fail("preflight must not run"))
    monkeypatch.setattr(cli, "start_engagement", lambda *a, **k: pytest.fail("client must not start"))
    from vigil_cli import application
    monkeypatch.setattr(application, "materialize_bundle", lambda *a, **k: pytest.fail("no materialization"))
    before = sorted(tmp_path.rglob("*"))
    with pytest.raises(SystemExit) as outcome:
        cli.main(["--root", str(tmp_path), "engagement", "client-check", "--client", client, "--json"])
    assert outcome.value.code == 1, "missing required native clients must be reported through the exit status"
    report = json.loads(capsys.readouterr().out)
    assert report["client"] == client
    assert all(set(row) == {"name", "status", "detail", "required"} for row in report["checks"])
    assert next(row for row in report["checks"] if row["name"] == "authentication-model")["status"] == "UNVERIFIED"
    assert sorted(tmp_path.rglob("*")) == before


@pytest.mark.parametrize(("version", "status"), [
    ("1.18.10\n", "OK"), ("1.19.3\n", "OK"), ("1.18.9\n", "FAIL"),
    ("2.0.0\n", "FAIL"), ("1.19.3-beta\n", "UNVERIFIED"),
])
def test_opencode_version_is_bounded_and_never_contacts_a_provider(monkeypatch, version, status):
    calls = []
    monkeypatch.setattr(client_checks.shutil, "which", lambda name: "/usr/local/bin/opencode")
    def probe(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, version, "")
    monkeypatch.setattr(client_checks.subprocess, "run", probe)
    assert client_checks.collect_client_checks("opencode")[0].status == status
    assert len(calls) == 1
    assert calls[0][0] == ["/usr/local/bin/opencode", "--version"]
    assert calls[0][1]["timeout"] == client_checks.PROBE_TIMEOUT_SECONDS


@pytest.mark.parametrize("failure", [OSError("not executable"), subprocess.TimeoutExpired("opencode", 10)])
def test_opencode_probe_failure_is_reported_not_raised(monkeypatch, failure):
    monkeypatch.setattr(client_checks.shutil, "which", lambda name: "/usr/local/bin/opencode")
    def probe(*args, **kwargs):
        raise failure
    monkeypatch.setattr(client_checks.subprocess, "run", probe)
    assert client_checks.collect_client_checks("opencode")[0].status == "UNVERIFIED"


def test_zcode_metadata_check_does_not_activate_application(tmp_path, monkeypatch):
    application = tmp_path / "Applications/ZCode.app"
    info = application / "Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "3.15.3"}))
    monkeypatch.setattr(client_checks.sys, "platform", "darwin")
    monkeypatch.setattr(client_checks.Path, "home", lambda: tmp_path)
    # Hide a real system app so the test selects its synthetic user application.
    original_is_file = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda path: False if path == Path("/Applications/ZCode.app/Contents/Info.plist") else original_is_file(path))
    monkeypatch.setattr(client_checks.subprocess, "run", lambda *a, **k: pytest.fail("must not activate native app"))
    check = client_checks.collect_client_checks("zcode")[0]
    assert (check.status, check.detail) == ("OK", "3.15.3")


def test_unsupported_client_is_rejected():
    with pytest.raises(ValueError, match="Unsupported client"):
        client_checks.collect_client_checks("unknown")


def test_zcode_unreadable_application_directory_reports_failure(monkeypatch):
    monkeypatch.setattr(client_checks.sys, "platform", "darwin")
    def inaccessible(path):
        raise PermissionError("application directory is not readable")
    monkeypatch.setattr(Path, "is_file", inaccessible)
    try:
        checks = client_checks.collect_client_checks("zcode")
    except PermissionError:
        pytest.fail("An unreadable application must produce an actionable diagnostic, not crash")
    assert checks[0].status == "FAIL"
    assert "metadata" in checks[0].detail


@pytest.fixture
def observed_context(tmp_path, monkeypatch):
    root = tmp_path / "private"
    engagement = root / "engagements/acme"
    workspace = engagement / "client-context" / ("a" * 24) / "zcode"
    workspace.mkdir(parents=True)
    application = tmp_path / "application"
    provenance = {"root": str(application), "version": "1.0.0", "content_sha256": "b" * 64}
    (application / "agent").mkdir(parents=True)
    (engagement / "scope.json").write_text('{"status":"in_progress"}')
    tools = {}
    for name in ("uv", "bash", "jq", "node"):
        tool = tmp_path / "tools" / name
        tool.parent.mkdir(exist_ok=True)
        tool.write_text("#!/bin/sh\nexit 0\n")
        tool.chmod(0o755)
        tools[name] = str(tool)
    from vigil_cli import application as application_module
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    monkeypatch.setattr(application_module, "application_provenance", lambda path: provenance)
    binding = {"schema_version": 1, "client": "zcode", "mode": "code",
        "workspace": str(workspace), "engagement_dir": str(engagement), "engagement_key": "acme",
        "install_root": str(root), "application": provenance, "agent_root": str(application / "agent"),
        "release_id": "c" * 64, "vigil_cli": str(workspace / "bin/vigil"), "tools": tools}
    (workspace / "bin").mkdir()
    (workspace / "bin/vigil").write_text("#!/bin/sh\nexit 0\n")
    (workspace / "bin/vigil").chmod(0o755)
    (workspace / "agent").symlink_to(application / "agent")
    (workspace / "scope.json").symlink_to(engagement / "scope.json")
    plugin = root / "client-plugins" / ("c" * 24) / "zcode"
    plugin.mkdir(parents=True)
    plugin_manifest = {}
    for name in (".zcode-plugin/plugin.json", "marketplace.json", "hooks/hooks.json", "hooks/context.mjs", "vigil-release.json"):
        destination = plugin / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps({"release_id": "c" * 64}) if name == "vigil-release.json" else "{}")
        plugin_manifest[name] = hashlib.sha256(destination.read_bytes()).hexdigest()
    (plugin / ".vigil-managed-files.json").write_text(json.dumps(plugin_manifest))
    (workspace / "plugin").symlink_to(plugin)
    encoded = json.dumps(binding).encode()
    (workspace / ".vigil-client-context.json").write_bytes(encoded)
    manifest = {".vigil-client-context.json": hashlib.sha256(encoded).hexdigest()}
    (workspace / ".vigil-managed-files.json").write_text(json.dumps(manifest))
    session = "native-example"
    health = {"schema_version": 1, "client": "zcode", "session_id": session,
        "release_id": binding["release_id"], "binding_sha256": hashlib.sha256(encoded).hexdigest(),
        "startup_observed": True, "compact_observed": True, "context_injected": True}
    receipt = workspace / (".vigil-health-" + hashlib.sha256(session.encode()).hexdigest() + ".json")
    receipt.write_text(json.dumps(health))
    return root, engagement, workspace, health, receipt


def test_observed_context_reports_proof_levels_without_writing(observed_context):
    root, engagement, workspace, _, _ = observed_context
    before = {path: path.read_bytes() for path in workspace.rglob("*") if path.is_file() and not path.is_symlink()}
    try:
        checks = client_checks.collect_client_checks("zcode", engagement=engagement, mode="code", install_root=root)
    except TypeError:
        pytest.fail("client-check must support pure observational engagement diagnostics")
    indexed = {check.name: check for check in checks}
    assert indexed["startup-hook"].status == "OBSERVED"
    assert indexed["compact-hook"].status == "OBSERVED"
    assert indexed["context-injection"].status == "OBSERVED"
    assert indexed["native-build-validation"].status == "UNVERIFIED"
    assert indexed["backend-hydration"].status == "UNVERIFIED"
    assert {path: path.read_bytes() for path in workspace.rglob("*") if path.is_file() and not path.is_symlink()} == before


@pytest.mark.parametrize("summary_id", ["summary-acme", None])
def test_opencode_observations_keep_native_lifecycle_distinct(observed_context, summary_id):
    root, engagement, workspace, health, receipt = observed_context
    binding_path = workspace / ".vigil-client-context.json"
    binding = json.loads(binding_path.read_text())
    binding["client"] = "opencode"
    binding_path.write_text(json.dumps(binding))
    encoded = binding_path.read_bytes()
    (workspace / ".vigil-managed-files.json").write_text(json.dumps({
        ".vigil-client-context.json": hashlib.sha256(encoded).hexdigest()}))
    # Context paths use the client basename as an integrity invariant.
    native = workspace.with_name("opencode")
    workspace.rename(native)
    binding.update(workspace=str(native), vigil_cli=str(native / "bin/vigil"))
    encoded = json.dumps(binding).encode()
    (native / ".vigil-client-context.json").write_bytes(encoded)
    (native / ".vigil-managed-files.json").write_text(json.dumps({
        ".vigil-client-context.json": hashlib.sha256(encoded).hexdigest()}))
    health.update(client="opencode", binding_sha256=hashlib.sha256(encoded).hexdigest(),
                  request_observed=True, compacting_observed=True, last_summary_id=summary_id)
    (native / receipt.name).write_text(json.dumps(health))
    checks = client_checks.collect_client_checks("opencode", engagement=engagement, mode="code", install_root=root)
    indexed = {check.name: check for check in checks}
    for name in ("request-hook", "preservation-hook"):
        assert indexed[name].status == "OBSERVED"
    assert indexed["summary-recovery"].status == ("OBSERVED" if summary_id else "UNVERIFIED")
    assert indexed["native-build-validation"].status == "UNVERIFIED"
    assert indexed["backend-hydration"].status == "UNVERIFIED"


def test_receipt_does_not_prove_different_selected_mode(observed_context):
    root, engagement, _, _, _ = observed_context
    try:
        checks = client_checks.collect_client_checks("zcode", engagement=engagement, mode="web", install_root=root)
    except TypeError:
        pytest.fail("client-check must correlate receipts with the selected context mode")
    assert next(check for check in checks if check.name == "startup-hook").status == "UNVERIFIED"
    assert next(check for check in checks if check.name == "client-context").status == "MISSING"


@pytest.mark.parametrize("field", ["binding_sha256", "release_id", "client", "session_id"])
def test_receipt_mismatches_never_prove_hook_execution(observed_context, field):
    root, engagement, _, health, receipt = observed_context
    health[field] = "wrong-example"
    receipt.write_text(json.dumps(health))
    indexed = {check.name: check for check in client_checks.collect_client_checks(
        "zcode", engagement=engagement, mode="code", install_root=root)}
    assert indexed["client-context"].status == "FAIL"
    assert indexed["startup-hook"].status == "UNVERIFIED"


def test_missing_manifest_is_not_asset_integrity_proof(observed_context):
    root, engagement, workspace, _, _ = observed_context
    (workspace / ".vigil-managed-files.json").unlink()
    indexed = {check.name: check for check in client_checks.collect_client_checks(
        "zcode", engagement=engagement, mode="code", install_root=root)}
    assert indexed["managed-assets"].status == "UNVERIFIED"
    assert indexed["backend-hydration"].status == "UNVERIFIED"


def test_no_explicit_application_pin_does_not_materialize_or_accept_receipts(observed_context, monkeypatch):
    root, engagement, _, _, _ = observed_context
    monkeypatch.delenv("VIGIL_APPLICATION_DIR")
    from vigil_cli import application
    monkeypatch.setattr(application, "resolve_application_root", lambda *a, **k: pytest.fail("no resolver"))
    indexed = {check.name: check for check in client_checks.collect_client_checks(
        "zcode", engagement=engagement, mode="code", install_root=root)}
    assert indexed["pinned-release"].status == "UNVERIFIED"
    assert indexed["startup-hook"].status == "UNVERIFIED"


def test_linked_context_is_reported_without_reading_or_changing_its_target(observed_context, tmp_path):
    root, engagement, workspace, _, _ = observed_context
    external = tmp_path / "outside-example.json"
    external.write_text('{"example":"do not change"}')
    context = workspace / ".vigil-client-context.json"
    context.unlink()
    context.symlink_to(external)
    before = external.read_bytes()
    indexed = {check.name: check for check in client_checks.collect_client_checks(
        "zcode", engagement=engagement, mode="code", install_root=root)}
    assert indexed["client-context"].status == "FAIL"
    assert external.read_bytes() == before


def test_different_pinned_release_does_not_borrow_old_hook_proof(observed_context, monkeypatch):
    root, engagement, _, _, _ = observed_context
    from vigil_cli import application
    original = application.application_provenance
    monkeypatch.setattr(application, "application_provenance", lambda path: {**original(path), "version": "2.0.0"})
    checks = client_checks.collect_client_checks("zcode", engagement=engagement, mode="code", install_root=root)
    indexed = {check.name: check for check in checks}
    assert indexed["startup-hook"].status == "UNVERIFIED"
    assert indexed["client-context"].status == "MISSING"
    assert any(check.status == "STALE" for check in checks)


def test_standalone_reports_required_gui_tool_dependencies():
    checks = client_checks.collect_client_checks("zcode")
    indexed = {check.name: check for check in checks}
    for name in ("uv", "bash", "jq", "node"):
        assert f"dependency:{name}" in indexed, "missing dependencies must be diagnosed before workspace preparation"
        assert indexed[f"dependency:{name}"].status == "MISSING"
        assert indexed[f"dependency:{name}"].required is True


def test_missing_plugin_hook_file_is_not_healthy_installed_assets(observed_context):
    root, engagement, workspace, _, _ = observed_context
    (workspace / "plugin/hooks/context.mjs").unlink()
    indexed = {check.name: check for check in client_checks.collect_client_checks(
        "zcode", engagement=engagement, mode="code", install_root=root)}
    assert indexed["client-context"].status == "FAIL"


@pytest.mark.parametrize("foreign", [False, True])
def test_omitted_key_uses_only_explicit_bound_context(observed_context, monkeypatch, capsys, foreign):
    root, engagement, workspace, _, _ = observed_context
    context_file = workspace / ".vigil-client-context.json"
    monkeypatch.setenv("VIGIL_CLIENT_CONTEXT", str(context_file if not foreign else workspace.parent / "foreign.json"))
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(engagement))
    monkeypatch.setattr(cli, "resolve_engagement_path", lambda *a, **k: pytest.fail("no active/key resolver"))
    with pytest.raises(SystemExit) as outcome:
        cli.main(["--root", str(root), "engagement", "client-check", "--client", "zcode", "--json"])
    assert outcome.value.code == 1  # Synthetic platform/dependencies are deliberately unavailable.
    report = json.loads(capsys.readouterr().out)
    indexed = {check["name"]: check for check in report["checks"]}
    assert "client-context" in indexed, "a bound helper must inspect its explicit workspace without an engagement key"
    assert indexed["client-context"]["status"] == ("FAIL" if foreign else "OK")


@pytest.mark.parametrize("damage", ["missing", "nonexecutable", "symlink"])
def test_bound_dependencies_must_remain_regular_executables(observed_context, damage, tmp_path):
    root, engagement, workspace, _, _ = observed_context
    binding = json.loads((workspace / ".vigil-client-context.json").read_bytes())
    tool = Path(binding["tools"]["node"])
    if damage == "nonexecutable":
        tool.chmod(0o600)
    else:
        tool.unlink()
        if damage == "symlink":
            other = tmp_path / "other-node"
            other.write_text("#!/bin/sh\nexit 0\n")
            other.chmod(0o755)
            tool.symlink_to(other)
    indexed = {check.name: check for check in client_checks.collect_client_checks(
        "zcode", engagement=engagement, mode="code", install_root=root)}
    assert indexed["bound-dependency:node"].status == "FAIL"
    assert indexed["bound-dependency:node"].required


def test_bound_helper_requires_executable_mode(observed_context):
    root, engagement, workspace, _, _ = observed_context
    (workspace / "bin/vigil").chmod(0o600)
    checks = client_checks.collect_client_checks("zcode", engagement=engagement, mode="code", install_root=root)
    assert next(check for check in checks if check.name == "bound-helper").status == "FAIL"


@pytest.mark.parametrize("name", ["agent", "scope.json", "plugin"])
def test_managed_pointers_must_match_the_bound_canonical_destination(observed_context, name, tmp_path):
    root, engagement, workspace, _, _ = observed_context
    pointer = workspace / name
    pointer.unlink()
    pointer.symlink_to(tmp_path)
    checks = client_checks.collect_client_checks("zcode", engagement=engagement, mode="code", install_root=root)
    assert next(check for check in checks if check.name == "client-context").status == "FAIL"


def test_plugin_inventory_cannot_omit_its_native_hook(observed_context):
    root, engagement, workspace, _, _ = observed_context
    manifest = workspace / "plugin/.vigil-managed-files.json"
    inventory = json.loads(manifest.read_bytes())
    inventory.pop("hooks/context.mjs")
    manifest.write_text(json.dumps(inventory))
    checks = client_checks.collect_client_checks("zcode", engagement=engagement, mode="code", install_root=root)
    assert next(check for check in checks if check.name == "client-context").status == "FAIL"


def test_plugin_release_must_match_even_with_consistent_file_digests(observed_context):
    root, engagement, workspace, _, _ = observed_context
    release = workspace / "plugin/vigil-release.json"
    release.write_text(json.dumps({"release_id": "d" * 64}))
    manifest = workspace / "plugin/.vigil-managed-files.json"
    inventory = json.loads(manifest.read_bytes())
    inventory["vigil-release.json"] = hashlib.sha256(release.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(inventory))
    checks = client_checks.collect_client_checks("zcode", engagement=engagement, mode="code", install_root=root)
    assert next(check for check in checks if check.name == "client-context").status == "FAIL"
