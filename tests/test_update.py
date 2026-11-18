"""`vigil update`: verified release install, re-exec, and restart of stale running services."""
import hashlib
import io
import subprocess
from pathlib import Path

import pytest

from vigil_cli import update
from vigil_cli.paths import engagements_root
from vigil_cli.restart_manifest import ConsumerState

WHEEL_BYTES = b"wheel-bytes"
WHEEL_SHA = hashlib.sha256(WHEEL_BYTES).hexdigest()


def _release_payload(version="9.1.0", digest=f"sha256:{WHEEL_SHA}"):
    name = f"vigil-{version}-py3-none-any.whl"
    return {
        "tag_name": f"v{version}",
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": f"vigil-{version}.tar.gz", "digest": "sha256:" + "0" * 64,
             "browser_download_url": f"https://github.example/v{version}/vigil-{version}.tar.gz"},
            {"name": name, "digest": digest,
             "browser_download_url": f"https://github.example/v{version}/{name}"},
        ],
    }


def test_latest_release_selects_the_wheel_and_its_published_digest():
    seen = []

    def fetch(url):
        seen.append(url)
        return _release_payload()

    release = update.resolve_release(None, fetch_json=fetch)
    assert seen == [f"{update.RELEASES_API}/latest"]
    assert release == update.Release(
        version="9.1.0",
        wheel_name="vigil-9.1.0-py3-none-any.whl",
        wheel_url="https://github.example/v9.1.0/vigil-9.1.0-py3-none-any.whl",
        sha256=WHEEL_SHA,
    )


def test_pinned_version_reads_its_tag():
    seen = []
    update.resolve_release("v9.0.0", fetch_json=lambda url: seen.append(url) or _release_payload("9.0.0"))
    assert seen == [f"{update.RELEASES_API}/tags/v9.0.0"]


def test_release_without_a_sha256_digest_is_refused():
    with pytest.raises(SystemExit, match="SHA256"):
        update.resolve_release(None, fetch_json=lambda url: _release_payload(digest=None))


def test_download_verifies_the_digest(tmp_path):
    release = update.resolve_release(None, fetch_json=lambda url: _release_payload())
    wheel = update.download_wheel(release, tmp_path, open_url=lambda url: io.BytesIO(WHEEL_BYTES))
    assert wheel == tmp_path / release.wheel_name
    assert wheel.read_bytes() == WHEEL_BYTES


def test_download_with_a_wrong_digest_leaves_no_wheel(tmp_path):
    release = update.resolve_release(None, fetch_json=lambda url: _release_payload())
    with pytest.raises(SystemExit, match="digest"):
        update.download_wheel(release, tmp_path, open_url=lambda url: io.BytesIO(b"tampered"))
    assert list(tmp_path.iterdir()) == []


class Recorder:
    def __init__(self, bin_dir: Path):
        self.calls: list[list[str]] = []
        self.bin_dir = bin_dir

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[1:4] == ["tool", "dir", "--bin"]:
            return subprocess.CompletedProcess(argv, 0, f"{self.bin_dir}\n", "")
        if argv[1:3] == ["tool", "install"]:
            wheel = Path(argv[argv.index("--from") + 1])
            assert wheel.read_bytes() == WHEEL_BYTES  # verified file exists while uv installs it
        return subprocess.CompletedProcess(argv, 0, "", "")


def _install_kwargs(tmp_path, recorder, execs, *, payload=None):
    return dict(
        fetch_json=lambda url: payload or _release_payload(),
        open_url=lambda url: io.BytesIO(WHEEL_BYTES),
        run=recorder.run,
        which=lambda name: "/opt/uv/bin/uv" if name == "uv" else None,
        execve=lambda path, argv, env: execs.append((path, argv, env)),
        cli_package=tmp_path / "venv" / "site-packages" / "vigil_cli",
        environ={},
    )


def test_newer_release_is_installed_then_the_new_cli_finishes(tmp_path):
    recorder, execs = Recorder(tmp_path / "bin"), []
    options = update.UpdateOptions(root_argv=("--root", str(tmp_path / "ws")), restart=False)
    update.install_newest_release(options, running_version="9.0.0", **_install_kwargs(tmp_path, recorder, execs))

    install = next(call for call in recorder.calls if call[1:3] == ["tool", "install"])
    assert install[:5] == ["/opt/uv/bin/uv", "tool", "install", "--force", "--from"]
    assert Path(install[5]).name == "vigil-9.1.0-py3-none-any.whl"
    assert install[6:] == ["vigil"]
    [(path, argv, env)] = execs
    assert path == str(tmp_path / "bin" / "vigil")
    assert argv == [path, "--root", str(tmp_path / "ws"), "update", "--no-restart"]
    assert env[update.REEXEC_ENV] == "9.1.0"


def test_current_release_installs_nothing(tmp_path):
    recorder, execs = Recorder(tmp_path / "bin"), []
    update.install_newest_release(
        update.UpdateOptions(), running_version="9.1.0", **_install_kwargs(tmp_path, recorder, execs)
    )
    assert recorder.calls == [] and execs == []


def test_newer_running_cli_is_not_downgraded_without_a_pin(tmp_path):
    recorder, execs = Recorder(tmp_path / "bin"), []
    update.install_newest_release(
        update.UpdateOptions(), running_version="9.2.0", **_install_kwargs(tmp_path, recorder, execs)
    )
    assert recorder.calls == [] and execs == []


def test_explicit_version_installs_even_when_older(tmp_path):
    recorder, execs = Recorder(tmp_path / "bin"), []
    update.install_newest_release(
        update.UpdateOptions(version="9.0.0"), running_version="9.2.0",
        **_install_kwargs(tmp_path, recorder, execs, payload=_release_payload("9.0.0")),
    )
    assert execs and execs[0][1][-2:] == ["--release", "9.0.0"]


def test_reexecuted_cli_must_report_the_installed_version(tmp_path):
    recorder, execs = Recorder(tmp_path / "bin"), []
    kwargs = _install_kwargs(tmp_path, recorder, execs)
    kwargs["environ"] = {update.REEXEC_ENV: "9.1.0"}
    with pytest.raises(SystemExit, match="9.1.0"):
        update.install_newest_release(update.UpdateOptions(), running_version="9.0.0", **kwargs)
    assert recorder.calls == [] and execs == []


def test_reexecuted_cli_at_the_installed_version_continues_without_fetching(tmp_path):
    recorder, execs = Recorder(tmp_path / "bin"), []
    kwargs = _install_kwargs(tmp_path, recorder, execs)
    kwargs["environ"] = environ = {update.REEXEC_ENV: "9.1.0"}
    kwargs["fetch_json"] = lambda url: pytest.fail("the re-executed CLI must not query releases again")
    update.install_newest_release(update.UpdateOptions(), running_version="9.1.0", **kwargs)
    assert update.REEXEC_ENV not in environ
    assert recorder.calls == [] and execs == []


def test_source_checkout_cli_is_never_replaced_by_a_release(tmp_path):
    checkout = tmp_path / "checkout"
    (checkout / "src" / "vigil_cli").mkdir(parents=True)
    (checkout / "pyproject.toml").write_text("[project]\nname = 'vigil'\n")
    recorder, execs = Recorder(tmp_path / "bin"), []
    kwargs = _install_kwargs(tmp_path, recorder, execs)
    kwargs["cli_package"] = checkout / "src" / "vigil_cli"
    kwargs["fetch_json"] = lambda url: pytest.fail("a checkout CLI must not query releases")
    update.install_newest_release(update.UpdateOptions(), running_version="9.0.0", **kwargs)
    assert recorder.calls == [] and execs == []


def test_missing_uv_names_the_manual_command(tmp_path):
    recorder, execs = Recorder(tmp_path / "bin"), []
    kwargs = _install_kwargs(tmp_path, recorder, execs)
    kwargs["which"] = lambda name: None
    with pytest.raises(SystemExit, match="uv tool install --force --from https://github.example/"):
        update.install_newest_release(update.UpdateOptions(), running_version="9.0.0", **kwargs)


def _state(key, state, remedy=""):
    return ConsumerState(key, key, state, remedy, "")


def _states(**overrides):
    states = {key: "current" for key in (
        "cli", "backend", "frontend", "report", "runtime-image", "proxy-image",
        "runtime-container", "proxy-container", "client-sessions", "agent-tree",
    )}
    states.update(overrides)
    remedies = {"backend": "vigil orchestrator restart"}
    return [_state(key, value, remedies.get(key, "") if value == "stale" else "") for key, value in states.items()]


@pytest.fixture
def actions(monkeypatch):
    calls = []
    monkeypatch.setattr(update, "restart_orchestrator", lambda root: calls.append(("backend", root)))
    monkeypatch.setattr(update, "start_runtime",
                        lambda options, **kw: calls.append(("runtime", options.install_root, options.recreate)))
    monkeypatch.setattr(update, "start_proxy",
                        lambda options, **kw: calls.append(("proxy", options.install_root, options.engagements_root)))
    return calls


def _running(*containers):
    return lambda name, **kw: name in containers


def test_only_stale_running_services_restart(tmp_path, actions):
    restarted = update.restart_stale_services(
        tmp_path,
        states=_states(backend="stale", **{"runtime-container": "stale", "proxy-container": "not-running"}),
        container_running=_running("vigil"),
    )
    assert restarted == ["backend", "runtime"]
    assert actions == [("backend", tmp_path), ("runtime", tmp_path, True)]


def test_stale_images_restart_only_their_running_containers(tmp_path, actions, monkeypatch):
    monkeypatch.setattr(update, "default_runtime_container", lambda: "vigil")
    restarted = update.restart_stale_services(
        tmp_path,
        states=_states(**{"runtime-image": "stale", "proxy-image": "stale"}),
        container_running=_running("vigil-proxy"),
    )
    assert restarted == ["proxy"]
    assert actions == [("proxy", tmp_path, engagements_root(tmp_path))]


def test_current_unknown_and_stopped_services_are_left_alone(tmp_path, actions):
    states = _states(backend="unknown", **{"runtime-container": "not-running", "proxy-image": "unknown"})
    assert update.restart_stale_services(tmp_path, states=states, container_running=_running()) == []
    assert actions == []


def test_remote_backend_without_a_local_restart_is_left_alone(tmp_path, actions):
    states = [_state("backend", "stale", "")] + [s for s in _states() if s.key != "backend"]
    assert update.restart_stale_services(tmp_path, states=states, container_running=_running()) == []
    assert actions == []


@pytest.mark.parametrize("no_restart", [False, True])
def test_cli_installs_then_reconciles_then_restarts(tmp_path, monkeypatch, no_restart):
    from vigil_cli import main as cli
    from vigil_cli.install import InstallResult

    workspace = tmp_path / "ws"
    calls = []
    monkeypatch.setattr(cli, "install_newest_release",
                        lambda options, running_version: calls.append(("release", options)))
    monkeypatch.setattr(cli, "install_from_source", lambda options: calls.append(("install", options)) or InstallResult(
        install_root=options.install_root, is_upgrade=True, image_built=False))
    monkeypatch.setattr(cli, "_record_default_workspace", lambda root, make_default: calls.append(("default", make_default)))
    monkeypatch.setattr(cli, "restart_stale_services", lambda root: calls.append(("restart", root)))
    monkeypatch.setattr(cli, "_print_post_install", lambda result: calls.append(("summary", result.install_root)))

    cli.main(["--root", str(workspace), "update", "--release", "9.0.0", *(["--no-restart"] if no_restart else [])])

    (_, options), (_, install), *rest = calls
    assert options == update.UpdateOptions(
        root_argv=("--root", str(workspace)), version="9.0.0", restart=not no_restart)
    assert install.install_root == workspace and install.render_client_trees
    expected = [("default", False)] + ([] if no_restart else [("restart", workspace)]) + [("summary", workspace)]
    assert rest == expected


def test_cli_update_refuses_a_source_application(tmp_path):
    from vigil_cli import main as cli

    with pytest.raises(SystemExit, match="installs a release"):
        cli.main(["--root", str(tmp_path), "--source", str(tmp_path), "update"])
