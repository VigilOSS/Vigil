"""Behavior tests for restart/staleness detection.

Two invariants carry this suite:

1. **An install that changed nothing must oblige nothing.** ``vigil install``
   rewrites every managed file unconditionally, so every consumer judged by an
   mtime high-water mark reads as stale after every install. Each "…only
   rewrites mtimes…" test replays exactly that — a byte-identical rewrite — and
   asserts the consumer stays ``current``.
2. **A hand-maintained input list must be machine-checked.** The Dockerfile
   coverage tests turn ``runtime_image_inputs`` and the proxy build context from
   lists someone has to remember to update into lists a test updates them about.
"""
from __future__ import annotations

import io
import re
from pathlib import Path

import pytest

from vigil_cli import orchestrator, restart_manifest, runtime
from vigil_cli.docker import DockerResult

REPO_ROOT = Path(__file__).resolve().parents[1]

# Captured before the autouse fixture stubs it, so a test that wants the REAL
# lookup (driving it via a fake /readyz snapshot) can put it back.
_REAL_READYZ_BACKEND_RUNTIME = restart_manifest._readyz_backend_runtime


class FakeStream(io.StringIO):
    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.fixture(autouse=True)
def _styled_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """A baseline where styling is permitted, so each test opts out explicitly.

    Mirrors the fixture in `test_term.py`. Without it the TTY assertions here
    read the MAINTAINER's shell: an operator who exports `NO_COLOR`, or a CI
    runner with `TERM=dumb`, gets the plain row from a stream whose `isatty()`
    is True, and the escape-code assertion fails for a supported configuration
    rather than for a real defect.
    """
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", "80")


@pytest.fixture(autouse=True)
def _no_live_orchestrator(monkeypatch: pytest.MonkeyPatch):
    """Keep the backend consumer hermetic.

    ``_backend_state`` asks the real ``/readyz``, so on a maintainer's box with a
    live orchestrator these assertions would read that process instead of the
    fixture. Tests that care about a reachable backend override this.

    The refusal is paired with a positively-stopped local process, because that
    is the combination that yields ``not-running`` — the hermetic default these
    tests were written against.
    """
    monkeypatch.setattr(
        restart_manifest,
        "_readyz_backend_runtime",
        lambda _root: restart_manifest.BackendProbe(
            reachable=False, unreachable_reason="refused"
        ),
    )
    monkeypatch.setattr(
        orchestrator,
        "orchestrator_status_payload",
        lambda _root, **_kw: {"state": "stopped", "pid": None, "port_in_use": False},
    )


def _rewrite_in_place(*paths: Path) -> None:
    """Replay what ``vigil install`` does to every managed file: same bytes, new mtime."""
    for path in paths:
        path.write_bytes(path.read_bytes())


def _frontend_root(tmp_path: Path) -> Path:
    frontend = tmp_path / "orchestrator" / "frontend"
    (frontend / "src").mkdir(parents=True)
    (frontend / "package.json").write_text('{"name": "vigil-frontend"}\n', encoding="utf-8")
    (frontend / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    (frontend / "index.html").write_text("<html></html>\n", encoding="utf-8")
    (frontend / "vite.config.ts").write_text("export default {}\n", encoding="utf-8")
    (frontend / "src" / "main.tsx").write_text("export const main = 1\n", encoding="utf-8")
    return frontend


def _report_root(tmp_path: Path) -> Path:
    report = tmp_path / "orchestrator" / "report"
    (report / "src").mkdir(parents=True)
    (report / "package.json").write_text('{"name": "vigil-report"}\n', encoding="utf-8")
    (report / "index.html").write_text("<html></html>\n", encoding="utf-8")
    (report / "vite.config.ts").write_text("export default {}\n", encoding="utf-8")
    (report / "tsconfig.json").write_text("{}\n", encoding="utf-8")
    (report / "src" / "main.ts").write_text("export const main = 1\n", encoding="utf-8")
    return report


def _mark_frontend_built(install_root: Path) -> None:
    dist = install_root / "orchestrator" / "frontend" / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "index.html").write_text("built\n", encoding="utf-8")
    restart_manifest.record_frontend_build(install_root)


def _mark_report_built(install_root: Path) -> None:
    dist = install_root / "orchestrator" / "report" / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "template.html").write_text("built\n", encoding="utf-8")
    restart_manifest.record_report_build(install_root)


# --- frontend / report content freshness --------------------------------------


def test_frontend_is_current_after_an_install_that_only_rewrites_mtimes(tmp_path: Path) -> None:
    frontend = _frontend_root(tmp_path)
    _mark_frontend_built(tmp_path)
    assert restart_manifest.frontend_build_state(tmp_path) == "current"

    _rewrite_in_place(
        frontend / "package.json", frontend / "index.html", frontend / "src" / "main.tsx"
    )

    assert restart_manifest.frontend_build_state(tmp_path) == "current"
    assert orchestrator._frontend_build_needed(tmp_path) is False


def test_frontend_is_stale_when_source_content_changes(tmp_path: Path) -> None:
    frontend = _frontend_root(tmp_path)
    _mark_frontend_built(tmp_path)

    (frontend / "src" / "main.tsx").write_text("export const main = 2\n", encoding="utf-8")

    assert restart_manifest.frontend_build_state(tmp_path) == "stale"
    assert orchestrator._frontend_build_needed(tmp_path) is True


def test_frontend_is_stale_when_a_source_file_is_deleted(tmp_path: Path) -> None:
    frontend = _frontend_root(tmp_path)
    _mark_frontend_built(tmp_path)

    (frontend / "src" / "main.tsx").unlink()

    assert restart_manifest.frontend_build_state(tmp_path) == "stale"


def test_frontend_dist_without_a_stamp_is_unknown_and_rebuilds_once(tmp_path: Path) -> None:
    _frontend_root(tmp_path)
    dist = tmp_path / "orchestrator" / "frontend" / "dist"
    dist.mkdir(parents=True)
    (dist / "index.html").write_text("built by an older vigil\n", encoding="utf-8")

    assert restart_manifest.frontend_build_state(tmp_path) == "unknown"
    assert orchestrator._frontend_build_needed(tmp_path) is True


def test_frontend_without_dist_is_missing(tmp_path: Path) -> None:
    _frontend_root(tmp_path)
    assert restart_manifest.frontend_build_state(tmp_path) == "missing"
    assert orchestrator._frontend_build_needed(tmp_path) is True


def test_report_is_current_after_an_install_that_only_rewrites_mtimes(tmp_path: Path) -> None:
    report = _report_root(tmp_path)
    _mark_report_built(tmp_path)

    _rewrite_in_place(report / "package.json", report / "src" / "main.ts")

    assert restart_manifest.report_build_state(tmp_path) == "current"
    assert orchestrator._report_build_needed(tmp_path) is False


def test_report_is_stale_when_source_content_changes(tmp_path: Path) -> None:
    report = _report_root(tmp_path)
    _mark_report_built(tmp_path)

    (report / "src" / "main.ts").write_text("export const main = 9\n", encoding="utf-8")

    assert restart_manifest.report_build_state(tmp_path) == "stale"
    assert orchestrator._report_build_needed(tmp_path) is True


def test_absent_report_package_is_not_a_build(tmp_path: Path) -> None:
    """An install predating the report template has nothing to build or restart."""
    assert restart_manifest.report_build_state(tmp_path) == "not-packaged"
    assert orchestrator._report_build_needed(tmp_path) is False


def test_force_rebuilds_even_when_current(tmp_path: Path) -> None:
    _frontend_root(tmp_path)
    _mark_frontend_built(tmp_path)
    _report_root(tmp_path)
    _mark_report_built(tmp_path)

    assert orchestrator._frontend_build_needed(tmp_path, force=True) is True
    assert orchestrator._report_build_needed(tmp_path, force=True) is True


# --- maintenance guards over hand-maintained input lists ----------------------


_COPY_FLAG = re.compile(r"^--[a-zA-Z-]+(=|$)")


def _dockerfile_copy_sources(dockerfile: Path) -> list[str]:
    """Host-context sources of every ``COPY`` in a Dockerfile.

    ``COPY --from=<stage>`` reads from a previous build stage, not the host
    build context, so it is not a build input and is skipped. The final token of
    a COPY is its destination.
    """
    sources: list[str] = []
    for raw in dockerfile.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.upper().startswith("COPY "):
            continue
        tokens = line.split()[1:]
        if any(token.startswith("--from=") for token in tokens):
            continue
        operands = [token for token in tokens if not _COPY_FLAG.match(token)]
        sources.extend(operands[:-1])
    return sources


def test_runtime_dockerfile_copy_sources_are_declared_runtime_image_inputs() -> None:
    """Every host path baked into the runtime image is a declared build input.

    ``runtime_image_inputs`` is hand-maintained; the Dockerfile is the authority
    on what is actually baked in. Without this, adding a ``COPY`` silently leaves
    ``vigil:latest`` reading ``current`` after that file changes.
    """
    dockerfile = REPO_ROOT / "agent" / "docker" / "runtime-full" / "Dockerfile"
    declared = {path.resolve() for path in runtime.runtime_image_inputs(REPO_ROOT)}

    sources = _dockerfile_copy_sources(dockerfile)
    assert sources, "no COPY sources parsed; the parser or the Dockerfile moved"

    missing = [src for src in sources if (REPO_ROOT / src).resolve() not in declared]
    assert not missing, (
        f"{dockerfile} COPYs these paths but runtime_image_inputs() does not declare "
        f"them: {missing}"
    )
    assert dockerfile.resolve() in declared, "the Dockerfile itself must be an input"


def test_mitmproxy_dockerfile_copy_sources_all_exist_in_the_staged_build_context(
    tmp_path: Path,
) -> None:
    """Every proxy-image COPY resolves inside the context the builder stages.

    The proxy Dockerfile's COPY paths are context-relative, so the authority is
    the staged context itself rather than a transcribed path table: staging it
    and resolving each COPY against it checks the declared input list and the
    staging code together.
    """
    from vigil_cli import mitmproxy

    for relative in (
        Path("agent/docker/mitmproxy/Dockerfile"),
        Path("agent/scripts/proxy_addon.py"),
        Path("agent/scripts/assess/__init__.py"),
        Path("src/vigil_cli/scope_entries.py"),
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPO_ROOT / relative).read_bytes())

    dockerfile = REPO_ROOT / "agent" / "docker" / "mitmproxy" / "Dockerfile"
    sources = _dockerfile_copy_sources(dockerfile)
    assert sources, "no COPY sources parsed; the parser or the Dockerfile moved"

    with mitmproxy._proxy_build_context(tmp_path) as context:
        missing = [src for src in sources if not (context / src).exists()]
    assert not missing, (
        f"{dockerfile} COPYs these context paths but the staged build context does not "
        f"provide them: {missing}"
    )


def test_proxy_and_runtime_images_pin_the_same_mitmproxy_version() -> None:
    runtime_dockerfile = (
        REPO_ROOT / "agent" / "docker" / "runtime-full" / "Dockerfile"
    ).read_text(encoding="utf-8")
    proxy_dockerfile = (
        REPO_ROOT / "agent" / "docker" / "mitmproxy" / "Dockerfile"
    ).read_text(encoding="utf-8")
    runtime_match = re.search(
        r"^ARG MITMPROXY_VERSION=([^\s]+)$", runtime_dockerfile, re.MULTILINE
    )
    proxy_match = re.search(r'mitmproxy==([^"\s]+)', proxy_dockerfile)

    assert runtime_match is not None
    assert proxy_match is not None
    assert proxy_match.group(1) == runtime_match.group(1)


def test_frontend_build_config_files_are_all_declared_inputs() -> None:
    """A new top-level build-config file must join the declared frontend inputs.

    Vite reads its config from the package root, so a newly added
    ``tailwind.config.ts``/``postcss.config.js`` changes the build output while
    being invisible to a transcribed list. This fails the moment one appears.
    """
    frontend_dir = REPO_ROOT / "orchestrator" / "frontend"
    declared = {path.name for path in restart_manifest.frontend_build_inputs(frontend_dir)}
    present = {
        entry.name
        for entry in frontend_dir.iterdir()
        if entry.is_file() and restart_manifest.is_build_config_name(entry.name)
    }
    # Non-vacuity: `present` is built WITH the predicate under test, so a
    # predicate that answered False for everything would make the subset
    # assertion below trivially true and the guard silently inert.
    assert present, "no frontend build config detected; is_build_config_name has gone blind"
    assert {"package.json", "index.html"} <= present, sorted(present)
    assert present <= declared, f"undeclared frontend build config: {sorted(present - declared)}"


def _declared_directory_names(inputs: list[Path]) -> set[str]:
    return {path.name for path in inputs if path.is_dir()}


def _source_directory_names(package_dir: Path) -> set[str]:
    """Top-level directories that are source rather than build output.

    `dist` and `node_modules` are outputs; everything else beside them is
    something the build reads — Vite's default `publicDir` (`public/`) being the
    one that would otherwise slip in unnoticed.
    """
    from vigil_cli.image_freshness import is_excluded_input

    return {
        entry.name
        for entry in package_dir.iterdir()
        if entry.is_dir() and not is_excluded_input(entry.name)
    }


def test_frontend_source_directories_are_all_declared_inputs() -> None:
    frontend = REPO_ROOT / "orchestrator" / "frontend"
    declared = _declared_directory_names(restart_manifest.frontend_build_inputs(frontend))
    present = _source_directory_names(frontend)
    assert present <= declared, f"undeclared frontend source dir: {sorted(present - declared)}"


def test_report_source_directories_are_all_declared_inputs() -> None:
    report = REPO_ROOT / "orchestrator" / "report"
    declared = _declared_directory_names(restart_manifest.report_build_inputs(report))
    present = _source_directory_names(report)
    assert present <= declared, f"undeclared report source dir: {sorted(present - declared)}"


def test_the_backend_and_the_cli_agree_on_what_a_source_file_is() -> None:
    """Two projects, one definition of "build artifact, not input".

    The backend is a separate uv project and cannot import `vigil_cli`, so it
    carries its own exclusion set. If the two drift, the same tree is source to
    one and junk to the other — which is how `__pycache__` churn made an earlier
    freshness check rebuild forever.
    """
    from app.main import _NOT_SOURCE_NAMES
    from vigil_cli.image_freshness import EXCLUDED_INPUT_NAMES

    assert _NOT_SOURCE_NAMES <= EXCLUDED_INPUT_NAMES


def test_report_build_config_files_are_all_declared_inputs() -> None:
    report_dir = REPO_ROOT / "orchestrator" / "report"
    declared = {path.name for path in restart_manifest.report_build_inputs(report_dir)}
    present = {
        entry.name
        for entry in report_dir.iterdir()
        if entry.is_file() and restart_manifest.is_build_config_name(entry.name)
    }
    assert present <= declared, f"undeclared report build config: {sorted(present - declared)}"


# --- consumer_states ----------------------------------------------------------


def _fake_runner(
    *,
    images: dict[str, str] | None = None,
    containers: dict[str, str] | None = None,
    daemon: bool = True,
):
    """A docker runner answering only the metadata queries these checks make."""
    images = images or {}
    containers = containers or {}

    def run(argv: list[str], **_: object) -> DockerResult:
        if argv[:2] == ["docker", "info"]:
            return DockerResult(0, "", "") if daemon else DockerResult(124, "", "timed out")
        if argv[:3] == ["docker", "image", "inspect"]:
            image = argv[-1]
            if image not in images:
                return DockerResult(1, "", "No such image")
            if "{{.Id}}" in argv:
                return DockerResult(0, f"sha256:image-{image}\n", "")
            return DockerResult(0, f"{images[image]}\n", "")
        if argv[:2] == ["docker", "inspect"] and "--type" in argv:
            return DockerResult(0 if argv[-1] in images else 1, "", "")
        if argv[:2] == ["docker", "inspect"]:
            name = argv[-1]
            if name not in containers:
                return DockerResult(1, "", "No such object")
            return DockerResult(0, f"{containers[name]}\n", "")
        if argv[:2] == ["docker", "ps"]:
            return DockerResult(0, "\n".join(containers) + "\n", "")
        if argv[:3] == ["docker", "images", "-q"]:
            return DockerResult(0, "" if argv[-1] not in images else "abc123\n", "")
        return DockerResult(1, "", "unsupported")

    return run


def _states(install_root: Path, **kwargs: object) -> dict[str, restart_manifest.ConsumerState]:
    return {
        state.key: state
        for state in restart_manifest.consumer_states(install_root, **kwargs)  # type: ignore[arg-type]
    }


def test_consumer_states_cover_every_declared_key(tmp_path: Path) -> None:
    states = _states(tmp_path, runner=_fake_runner())
    assert set(states) == set(restart_manifest.CONSUMER_KEYS)
    for state in states.values():
        assert state.state in restart_manifest.CONSUMER_STATES
        assert state.label


def test_a_stopped_runtime_container_is_never_stale(tmp_path: Path) -> None:
    """Nobody should be told to restart a service that is not running."""
    runner = _fake_runner(images={"vigil:latest": "deadbeef"}, containers={})
    states = _states(tmp_path, runner=runner)
    assert states["runtime-container"].state == "not-running"
    assert states["runtime-container"].remedy == ""


def test_a_drifted_runtime_container_asks_for_a_restart(tmp_path: Path) -> None:
    runner = _fake_runner(
        images={"vigil:latest": "deadbeef"}, containers={"vigil": "sha256:an-older-image"}
    )
    states = _states(tmp_path, runner=runner)
    assert states["runtime-container"].state == "stale"
    assert states["runtime-container"].remedy == "vigil runtime restart"


def test_a_missing_runtime_image_is_missing_not_stale(tmp_path: Path) -> None:
    states = _states(tmp_path, runner=_fake_runner())
    assert states["runtime-image"].state == "missing"


def test_a_runtime_image_built_from_current_inputs_is_current(tmp_path: Path, monkeypatch) -> None:
    for path in runtime.runtime_image_inputs(tmp_path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("baked\n", encoding="utf-8")
    digest = runtime.runtime_inputs_digest(tmp_path)
    (tmp_path / "orchestrator").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(tmp_path))
    states = _states(tmp_path, runner=_fake_runner(images={"vigil:latest": digest}))
    assert states["runtime-image"].state == "current"


def test_the_backend_is_not_running_when_readyz_is_unreachable(tmp_path: Path) -> None:
    states = _states(tmp_path, runner=_fake_runner())
    assert states["backend"].state == "not-running"
    assert states["backend"].remedy == ""


def test_the_backend_is_stale_when_readyz_says_restart_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        restart_manifest,
        "_readyz_backend_runtime",
        lambda root: restart_manifest.BackendProbe(
            reachable=True,
            runtime={
                "install_root": str(root),
                "application_root": str(REPO_ROOT),
                "restart_required": True,
                "changed_inputs": ["app/db.py", "uv.lock"],
            },
        ),
    )
    states = _states(tmp_path, runner=_fake_runner())
    assert states["backend"].state == "stale"
    assert states["backend"].remedy == "vigil orchestrator restart"
    assert "app/db.py" in states["backend"].detail


def test_the_cli_is_current_when_it_runs_the_resolved_source(tmp_path: Path) -> None:
    state = restart_manifest.cli_state(source_root=REPO_ROOT)
    assert state.key == "cli"
    assert state.state == "current", state.detail


def test_the_cli_is_stale_when_the_source_package_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_source = tmp_path / "source"
    package = fake_source / "src" / "vigil_cli"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("__version__ = 'newer'\n", encoding="utf-8")

    state = restart_manifest.cli_state(source_root=fake_source)
    assert state.state == "stale"
    # The re-run is part of the remedy: replacing the binary changes what the
    # consumers judged THROUGH it should be compared against, and nothing
    # re-runs this summary on its own. It reinstalls from the checkout this
    # verdict was computed against, not from whichever one discovery finds.
    assert state.remedy == f"uv tool install --force --editable {fake_source} && vigil --source {fake_source} install"


def test_the_cli_is_unknown_without_a_resolvable_source(tmp_path: Path) -> None:
    state = restart_manifest.cli_state(source_root=None)
    assert state.state == "unknown"
    assert state.remedy == ""


def test_cli_matches_retained_release_snapshot_without_digesting_asset_bundle(tmp_path, monkeypatch):
    running = tmp_path / "installed/vigil_cli"
    snapshot = tmp_path / "release/cli/vigil_cli"
    for package in (running, snapshot):
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("VERSION = 'matched'\n")
    assets = running / "_bundle"
    assets.mkdir()
    (assets / "bundle.json").write_text('{"content_sha256":"assets"}')
    # Running any installed CLI command writes bytecode the snapshot never has.
    (running / "__pycache__").mkdir()
    (running / "__pycache__/__init__.cpython-312.pyc").write_bytes(b"bytecode")
    monkeypatch.setattr(restart_manifest, "_running_cli_package", lambda: running)
    monkeypatch.setattr(restart_manifest, "loaded_module_files", lambda **kwargs: set())
    state = restart_manifest.cli_state(source_root=tmp_path / "release")
    assert state.state == "current"


# --- post-install presentation ------------------------------------------------


def _post_install_output(states: list[restart_manifest.ConsumerState], *, tty: bool) -> str:
    from vigil_cli import main as main_module
    from vigil_cli.install import InstallResult

    stream = FakeStream(tty=tty)
    result = InstallResult(install_root=Path("/tmp/vigil"), is_upgrade=True, image_built=False)
    main_module._print_post_install(result, states=states, stream=stream)
    return stream.getvalue()


def _current(key: str, label: str) -> restart_manifest.ConsumerState:
    return restart_manifest.ConsumerState(key=key, label=label, state="current", remedy="", detail="")


def _undetermined(key: str, label: str) -> restart_manifest.ConsumerState:
    """A consumer that could not be checked at all — the Docker-down shape."""
    return restart_manifest.ConsumerState(
        key=key,
        label=label,
        state="unknown",
        remedy="",
        detail="the Docker daemon is not responding",
    )


def test_post_install_does_not_call_an_unchecked_consumer_current() -> None:
    """A consumer we could not reach is not a consumer we cleared.

    With Docker stopped, the three Docker-backed consumers come back `unknown`
    with no remedy — there is no command to offer while the daemon is down. They
    are dropped from `actionable` for that reason, and the bare "nothing to
    restart" that followed asserted something this install never checked. That
    is precisely the class of false claim this module exists to stop making.
    """
    states = [
        _current("backend", "orchestrator backend"),
        _undetermined("runtime-image", "Kali runtime image"),
        _undetermined("proxy-image", "mitmproxy image"),
        _undetermined("runtime-container", "Kali runtime container"),
    ]
    text = _post_install_output(states, tty=False)

    assert "nothing to restart" not in text.lower()
    assert "Docker daemon is not responding" in text
    for label in ("Kali runtime image", "mitmproxy image", "Kali runtime container"):
        assert label in text, f"{label} was checked-but-unreachable and must be named"
    # The one consumer we DID clear must not be reported as uncertain.
    assert "orchestrator backend" not in text


def test_post_install_says_nothing_to_restart_only_when_all_were_checked() -> None:
    """The clean claim survives — it just now requires having actually checked."""
    states = [
        _current("backend", "orchestrator backend"),
        _current("runtime-image", "Kali runtime image"),
    ]
    assert "nothing to restart" in _post_install_output(states, tty=False).lower()


def test_post_install_says_nothing_to_restart_in_one_line(capsys: pytest.CaptureFixture) -> None:
    states = [_current("backend", "orchestrator backend"), _current("cli", "vigil CLI")]
    text = _post_install_output(states, tty=False)

    assert "nothing to restart" in text.lower()
    assert "vigil orchestrator restart" not in text
    assert "vigil runtime restart" not in text
    # The two-layer explainer is boilerplate when nothing is out of date.
    assert "uv tool upgrade vigil" not in text
    assert len([line for line in text.splitlines() if line.strip()]) == 1


def test_post_install_lists_only_the_consumers_that_need_action() -> None:
    states = [
        _current("cli", "vigil CLI"),
        restart_manifest.ConsumerState(
            key="backend",
            label="orchestrator backend",
            state="stale",
            remedy="vigil orchestrator restart",
            detail="app/db.py changed",
        ),
        restart_manifest.ConsumerState(
            key="runtime-container",
            label="Kali runtime",
            state="not-running",
            remedy="",
            detail="container stopped",
        ),
    ]
    text = _post_install_output(states, tty=False)

    assert "vigil orchestrator restart" in text
    assert "Kali runtime" not in text
    assert "vigil runtime restart" not in text


def test_post_install_reports_cli_upgrade_remedy() -> None:
    states = [
        restart_manifest.ConsumerState(
            key="cli",
            label="vigil CLI binary",
            state="stale",
            remedy="uv tool upgrade vigil",
            detail="binary predates this source",
        )
    ]
    text = _post_install_output(states, tty=False)

    assert "uv tool upgrade vigil" in text
    assert "binary predates this source" in text


def test_post_install_rows_are_tab_separated_off_a_tty() -> None:
    states = [
        restart_manifest.ConsumerState(
            key="backend",
            label="orchestrator backend",
            state="stale",
            remedy="vigil orchestrator restart",
            detail="app/db.py changed",
        )
    ]
    text = _post_install_output(states, tty=False)

    assert "\x1b" not in text
    row = next(line for line in text.splitlines() if "orchestrator backend" in line)
    assert row.startswith("WARN\t")


def test_post_install_paints_rows_on_a_tty() -> None:
    states = [
        restart_manifest.ConsumerState(
            key="backend",
            label="orchestrator backend",
            state="stale",
            remedy="vigil orchestrator restart",
            detail="app/db.py changed",
        )
    ]
    text = _post_install_output(states, tty=True)

    assert "\x1b[" in text
    assert "orchestrator backend" in text


def test_post_install_writes_nothing_to_stdout(
    capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`root=$(vigil install …)` captures stdout; this block must not pollute it."""
    from vigil_cli import main as main_module
    from vigil_cli.install import InstallResult

    monkeypatch.setattr(
        main_module.restart_manifest,
        "consumer_states",
        lambda *_args, **_kwargs: [_current("cli", "vigil CLI")],
    )
    result = InstallResult(install_root=Path("/tmp/vigil"), is_upgrade=True, image_built=False)
    main_module._print_post_install(result)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip()


def test_post_install_says_so_when_it_cannot_determine_the_answer(
    capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A summary that cannot be computed must not claim "nothing to restart"."""
    from vigil_cli import main as main_module
    from vigil_cli.install import InstallResult

    def boom(*_args: object, **_kwargs: object) -> list[restart_manifest.ConsumerState]:
        raise OSError("input vanished mid-walk")

    monkeypatch.setattr(main_module.restart_manifest, "consumer_states", boom)
    result = InstallResult(install_root=Path("/tmp/vigil"), is_upgrade=True, image_built=False)

    main_module._print_post_install(result)

    err = capsys.readouterr().err
    assert "could not determine" in err
    assert "input vanished mid-walk" in err
    assert "nothing to restart" not in err


def test_a_wedged_docker_daemon_reads_as_unknown_not_as_a_missing_image(
    tmp_path: Path,
) -> None:
    """"No answer" and "no image" are different facts, and only one is actionable."""
    states = _states(tmp_path, runner=_fake_runner(daemon=False))

    for key in ("runtime-image", "proxy-image", "runtime-container"):
        assert states[key].state == "unknown", key
        assert states[key].remedy == "", key
        assert "Docker daemon" in states[key].detail


def test_an_unreachable_daemon_is_not_reported_as_something_to_rebuild(
    tmp_path: Path,
) -> None:
    from vigil_cli import main as main_module
    from vigil_cli.install import InstallResult

    states = restart_manifest.consumer_states(tmp_path, runner=_fake_runner(daemon=False))
    stream = FakeStream(tty=False)
    main_module._print_post_install(
        InstallResult(install_root=tmp_path, is_upgrade=True, image_built=False),
        states=states,
        stream=stream,
    )

    text = stream.getvalue()
    assert "vigil runtime build" not in text
    assert "vigil mitmproxy build" not in text


# --- backend reachability and identity ----------------------------------------


def _readiness(**fields: object) -> dict[str, object]:
    base: dict[str, object] = {"reachable": True, "http_status": 200}
    base.update(fields)
    return base


def _backend_state_for(
    monkeypatch: pytest.MonkeyPatch,
    readiness: dict[str, object],
    *,
    install_root: Path,
    process: dict[str, object] | None = None,
) -> restart_manifest.ConsumerState:
    from vigil_cli import status as status_module

    monkeypatch.setattr(
        restart_manifest, "_readyz_backend_runtime", _REAL_READYZ_BACKEND_RUNTIME
    )
    monkeypatch.setattr(
        status_module,
        "_orchestrator_readyz_snapshot",
        lambda _root: (bool(readiness.get("reachable")), readiness),
    )
    # Local evidence about the process itself. Default: nothing running and
    # nothing holding the port — the positively-stopped shape.
    payload: dict[str, object] = {"state": "stopped", "pid": None, "port_in_use": False}
    payload.update(process or {})
    monkeypatch.setattr(
        orchestrator, "orchestrator_status_payload", lambda _root, **_kw: payload
    )
    return restart_manifest._backend_state(install_root)


def test_a_reachable_backend_with_no_runtime_block_is_unknown_not_cleared(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An older backend answers /readyz without `backend_runtime`.

    That is precisely the upgrade this feature exists for, and it must not read
    as "checked and fine". `not-running` would be worse than wrong here: it is
    in neither the actionable nor the unreachable list, so the summary silently
    drops the backend and claims nothing needs restarting.
    """
    state = _backend_state_for(monkeypatch, _readiness(), install_root=tmp_path)
    assert state.state == "unknown"
    assert state.remedy == ""
    assert state.detail


def test_backend_keeps_old_release_and_reports_restart_after_upgrade(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    application = tmp_path / "new-release"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    readiness = _readiness(backend_runtime={
        "install_root": str(workspace),
        "application_root": str(tmp_path / "old-release"),
        "restart_required": False,
    })
    state = _backend_state_for(monkeypatch, readiness, install_root=workspace)
    assert state.state == "stale"
    assert state.remedy == "vigil orchestrator restart"
    assert "old-release" in state.detail


def test_an_unreachable_backend_is_not_running(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A stopped orchestrator genuinely needs no restart — this branch must survive."""
    state = _backend_state_for(
        monkeypatch,
        {"reachable": False, "http_status": None, "unreachable_reason": "refused"},
        install_root=tmp_path,
    )
    assert state.state == "not-running"


# `not-running` is the ONE backend verdict the install summary drops entirely: a
# stopped orchestrator picks the install up when it next starts, so there is
# nothing to say. That makes it the most dangerous verdict to reach by
# assumption — every test below pins a case where the probe failed but the
# process was never established as stopped, and the summary must therefore say
# it could not check rather than that there is nothing to do.


def test_a_refused_probe_against_a_live_process_is_unknown_not_stopped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The pidfile says the orchestrator is up; /readyz refused the connection.

    A process that is alive but not yet (or no longer) serving is the opposite
    of stopped: it keeps running whatever code it loaded, so an install may well
    have invalidated it. Calling it `not-running` drops it from the summary and
    asserts a restart is pointless without having established that anything
    stopped.
    """
    state = _backend_state_for(
        monkeypatch,
        {"reachable": False, "http_status": None, "unreachable_reason": "refused"},
        install_root=tmp_path,
        process={"state": "running", "pid": 4242, "port_in_use": False},
    )
    assert state.state == "unknown"
    assert state.remedy == ""
    assert "4242" in state.detail


def test_a_refused_probe_while_the_port_is_held_is_unknown_not_stopped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No pidfile, but something owns 18000 — a direct `uvicorn` backend does this."""
    state = _backend_state_for(
        monkeypatch,
        {"reachable": False, "http_status": None, "unreachable_reason": "refused"},
        install_root=tmp_path,
        process={"state": "stopped", "pid": None, "port_in_use": True},
    )
    assert state.state == "unknown"
    assert state.remedy == ""


def test_a_timed_out_probe_is_unknown_even_with_no_local_process_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A timeout is not a refusal.

    Something accepted the connection and then did not answer — a wedged or
    heavily loaded backend. It is precisely the live process whose loaded code
    an install can invalidate, and the probe establishes nothing about whether
    it stopped.
    """
    state = _backend_state_for(
        monkeypatch,
        {"reachable": False, "http_status": None, "unreachable_reason": "timeout"},
        install_root=tmp_path,
    )
    assert state.state == "unknown"
    assert state.remedy == ""
    assert "timed out" in state.detail.lower() or "timeout" in state.detail.lower()


def test_an_unclassifiable_probe_failure_is_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state = _backend_state_for(
        monkeypatch,
        {
            "reachable": False,
            "http_status": None,
            "unreachable_reason": "error",
            "unreachable_detail": "[Errno 65] No route to host",
        },
        install_root=tmp_path,
    )
    assert state.state == "unknown"
    assert state.remedy == ""


def test_readyz_records_why_it_could_not_be_reached(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The snapshot must keep the OSError apart, not collapse it into one bool.

    `_backend_state` cannot separate a refusal from a timeout if the only thing
    it is handed is `reachable: False`.
    """
    import urllib.request

    from vigil_cli import status as status_module

    def _refuse(*_args: object, **_kwargs: object) -> object:
        raise ConnectionRefusedError(61, "Connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", _refuse)
    _, readiness = status_module._orchestrator_readyz_snapshot(tmp_path)
    assert readiness["reachable"] is False
    assert readiness["unreachable_reason"] == "refused"

    def _time_out(*_args: object, **_kwargs: object) -> object:
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", _time_out)
    _, readiness = status_module._orchestrator_readyz_snapshot(tmp_path)
    assert readiness["unreachable_reason"] == "timeout"


def test_a_backend_serving_another_install_root_cannot_clear_this_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The orchestrator base URL is a fixed 127.0.0.1:18000 for every root.

    So the backend that answers may be serving a DIFFERENT working root, and
    its `restart_required: false` says nothing about this one. `/readyz`
    publishes `install_root` for exactly this reason.
    """
    readiness = _readiness(
        backend_runtime={
            "install_root": "/somewhere/else/vigil",
            "restart_required": False,
        }
    )
    state = _backend_state_for(monkeypatch, readiness, install_root=tmp_path)
    assert state.state == "unknown"
    assert state.remedy == ""
    assert "install root" in state.detail.lower()


def test_a_backend_serving_this_install_root_is_authoritative(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    readiness = _readiness(
        backend_runtime={"install_root": str(tmp_path), "application_root": str(REPO_ROOT), "restart_required": False}
    )
    assert _backend_state_for(monkeypatch, readiness, install_root=tmp_path).state == "current"


def test_legacy_backend_without_release_pin_requires_restart(monkeypatch, tmp_path):
    readiness = _readiness(backend_runtime={"install_root": str(tmp_path), "restart_required": False})
    state = _backend_state_for(monkeypatch, readiness, install_root=tmp_path)
    assert state.state == "stale"
    assert state.remedy == "vigil orchestrator restart"


def test_a_stale_backend_for_this_root_still_reports_its_remedy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    readiness = _readiness(
        backend_runtime={
            "install_root": str(tmp_path),
            "application_root": str(REPO_ROOT),
            "restart_required": True,
            "changed_inputs": ["app/main.py"],
        }
    )
    state = _backend_state_for(monkeypatch, readiness, install_root=tmp_path)
    assert state.state == "stale"
    assert state.remedy == "vigil orchestrator restart"


def test_post_install_names_a_backend_it_could_not_determine(tmp_path: Path) -> None:
    """The generalisation of the Docker-down finding: `unknown` must never vanish."""
    states = [
        _current("cli", "vigil CLI"),
        restart_manifest.ConsumerState(
            key="backend",
            label="orchestrator backend",
            state="unknown",
            remedy="",
            detail="/readyz did not report backend_runtime",
        ),
    ]
    text = _post_install_output(states, tty=False)
    assert "nothing to restart" not in text.lower()
    assert "orchestrator backend" in text


@pytest.mark.parametrize(
    "name",
    [
        "package.json",
        "package-lock.json",
        "index.html",
        "tsconfig.json",
        "tsconfig.app.json",
        "vite.config.ts",
        "vite.config.js",
        "vite.config.mjs",
        "tailwind.config.ts",
        "postcss.config.js",
    ],
)
def test_is_build_config_name_recognises_a_build_input(name: str) -> None:
    """The predicate the frontend/report guards lean on, tested directly.

    Without this, stubbing it to a constant `False` leaves both guards passing:
    they build their `present` set with it, so a blind predicate makes the
    subset assertion vacuous rather than failing.
    """
    assert restart_manifest.is_build_config_name(name) is True


@pytest.mark.parametrize(
    "name",
    ["README.md", "src", "main.tsx", "config.ts", "package.json.bak", "vite.config.txt"],
)
def test_is_build_config_name_rejects_a_non_config(name: str) -> None:
    """Over-broad is its own failure: it would drag unrelated files into every digest."""
    assert restart_manifest.is_build_config_name(name) is False


# Context-relative COPY source -> the declared input that must cover it. The
# proxy Dockerfile's COPY paths address the STAGED context, while
# `mitmproxy_image_inputs` names paths in the install root, so the mapping is
# what ties the two together. A new COPY with no entry here fails the test
# below, which is the point: it forces a decision about the digest list rather
# than letting a new baked file go undigested.
_PROXY_COPY_TO_DECLARED = {
    "scripts/assess": "agent/scripts/assess",
    "scripts/proxy_addon.py": "agent/scripts/proxy_addon.py",
    "vigil_cli/scope_entries.py": "src/vigil_cli/scope_entries.py",
}


def test_every_proxy_dockerfile_copy_is_covered_by_the_declared_image_inputs() -> None:
    """The proxy's DIGEST list must cover every file baked into the image.

    The sibling test proves each COPY resolves inside the staged context; it
    never touches `mitmproxy_image_inputs`, so a new COPY that `_proxy_build_context`
    happens to stage would still be absent from the content digest — and the
    image would read `current` after that file changed. This closes that gap.
    """
    from vigil_cli import mitmproxy

    install_root = REPO_ROOT
    declared = mitmproxy.mitmproxy_image_inputs(install_root)
    declared_relative = set()
    for path in declared:
        try:
            declared_relative.add(path.relative_to(install_root).as_posix())
        except ValueError:
            declared_relative.add(None)  # an absolute, install-independent input

    dockerfile = REPO_ROOT / "agent" / "docker" / "mitmproxy" / "Dockerfile"
    sources = _dockerfile_copy_sources(dockerfile)
    assert sources, "no COPY sources parsed; the parser or the Dockerfile moved"

    unmapped = [src for src in sources if src not in _PROXY_COPY_TO_DECLARED]
    assert not unmapped, (
        f"{dockerfile} COPYs {unmapped}, which no entry in _PROXY_COPY_TO_DECLARED "
        "maps to a declared image input. Add it to `mitmproxy_image_inputs` (so the "
        "content digest covers it) and record the mapping here."
    )
    for src in sources:
        expected = _PROXY_COPY_TO_DECLARED[src]
        assert expected in declared_relative, (
            f"{dockerfile} COPYs {src}, but `mitmproxy_image_inputs` does not declare "
            f"{expected!r}; a change to that file would leave the proxy image reading current"
        )
    # The Dockerfile is itself an input: editing it must move the digest.
    assert "agent/docker/mitmproxy/Dockerfile" in declared_relative


# --- a remedy must finish the job ---------------------------------------------


def _remedy(states: dict, key: str) -> str:
    return states[key].remedy


def test_a_stale_runtime_image_under_a_running_container_prescribes_the_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`vigil runtime build` retags; it does not recreate the container.

    While the image is stale but not yet rebuilt, the container still matches
    the tag, so the container consumer reads `current` and the build is the only
    row. An operator who does exactly what the summary says is still running the
    old baked tools, and nothing told them otherwise.
    """
    monkeypatch.setattr(restart_manifest, "runtime_image_build_state", lambda *a, **k: "stale")
    monkeypatch.setattr(restart_manifest.docker, "daemon_available", lambda **k: True)
    monkeypatch.setattr(restart_manifest.docker, "container_running", lambda *a, **k: True)

    state = restart_manifest._runtime_image_state(
        tmp_path, runner=_fake_runner(), docker_ok=True
    )

    assert state.state == "stale"
    assert "vigil runtime build" in state.remedy
    assert "vigil runtime restart" in state.remedy, (
        "a rebuilt image that no running container picks up is not a fixed install"
    )


def test_a_stale_runtime_image_with_no_container_does_not_prescribe_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never tell someone to restart a service that is not running."""
    monkeypatch.setattr(restart_manifest, "runtime_image_build_state", lambda *a, **k: "stale")
    monkeypatch.setattr(restart_manifest.docker, "container_running", lambda *a, **k: False)

    state = restart_manifest._runtime_image_state(
        tmp_path, runner=_fake_runner(), docker_ok=True
    )

    assert state.remedy == "vigil runtime build"


def test_a_stale_proxy_image_under_a_running_proxy_prescribes_a_rebuild_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The proxy had no container consumer at all, so the build stood alone."""
    monkeypatch.setattr(
        restart_manifest.image_freshness, "image_inputs_state", lambda *a, **k: "stale"
    )
    monkeypatch.setattr(restart_manifest.docker, "container_running", lambda *a, **k: True)
    parser = tmp_path / "cli/vigil_cli/scope_entries.py"
    parser.parent.mkdir(parents=True)
    parser.write_text("release parser")

    state = restart_manifest._proxy_image_state(
        tmp_path, runner=_fake_runner(), docker_ok=True
    )

    assert state.state == "stale"
    assert "vigil mitmproxy start --build" in state.remedy


def test_a_running_proxy_on_a_superseded_image_is_its_own_consumer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Image drift after a rebuild needs its own row, as the runtime already has."""
    monkeypatch.setattr(restart_manifest.docker, "container_running", lambda *a, **k: True)
    monkeypatch.setattr(
        restart_manifest.image_freshness, "proxy_image_drift", lambda **k: True
    )

    state = restart_manifest._proxy_container_state(runner=_fake_runner(), docker_ok=True)

    assert state.key == "proxy-container"
    assert state.state == "stale"
    assert state.remedy == "vigil mitmproxy start"


def test_a_stopped_proxy_container_needs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(restart_manifest.docker, "container_running", lambda *a, **k: False)

    state = restart_manifest._proxy_container_state(runner=_fake_runner(), docker_ok=True)

    assert state.state == "not-running"
    assert state.remedy == ""


def test_proxy_image_state_uses_explicit_application_when_cli_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The application supplies its own pinned parser, independently of the CLI."""
    monkeypatch.setattr(
        restart_manifest.image_freshness, "image_inputs_state", lambda *a, **k: "current"
    )
    monkeypatch.setattr(restart_manifest.docker, "container_running", lambda *a, **k: False)
    parser = tmp_path / "cli/vigil_cli/scope_entries.py"
    parser.parent.mkdir(parents=True)
    parser.write_text("pinned application parser")

    state = restart_manifest._proxy_image_state(
        tmp_path, runner=_fake_runner(), docker_ok=True
    )

    assert state.state == "current"
    assert state.remedy == ""
    assert state.detail == ""


def test_a_current_cli_leaves_the_proxy_verdict_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        restart_manifest.image_freshness, "image_inputs_state", lambda *a, **k: "current"
    )
    monkeypatch.setattr(restart_manifest.docker, "container_running", lambda *a, **k: False)
    parser = tmp_path / "cli/vigil_cli/scope_entries.py"
    parser.parent.mkdir(parents=True)
    parser.write_text("release parser")

    state = restart_manifest._proxy_image_state(
        tmp_path, runner=_fake_runner(), docker_ok=True
    )

    assert state.state == "current"


def test_the_cli_remedy_reruns_the_install_that_recomputes_everything() -> None:
    """Upgrading the binary changes what the other consumers are judged against.

    Nothing re-runs the summary on its own, so the CLI remedy has to carry the
    re-run — otherwise every verdict computed through the old binary stands
    unchallenged after the binary is replaced.
    """
    from vigil_cli import restart_manifest as rm

    running = Path("/opt/venv/vigil_cli")
    state = rm.ConsumerState(
        key="cli",
        label=rm._CLI_LABEL,
        state="stale",
        remedy=rm._cli_stale_remedy(Path("/checkout")),
        detail="",
    )
    assert "uv tool install --force --from https://github.com/VigilOSS/Vigil/releases/download/" in state.remedy
    assert "vigil --source /checkout install" in state.remedy, (
        "after the binary moves, the working root's verdicts must be recomputed"
    )
    del running


def test_cli_release_remedy_installs_matched_wheel_not_unpublished_registry_package(tmp_path):
    import json

    release = tmp_path / "release"
    release.mkdir()
    (release / "bundle.json").write_text(json.dumps({"version": "1.1.0"}))
    remedy = restart_manifest._cli_stale_remedy(release)
    assert "--from https://github.com/VigilOSS/Vigil/releases/download/v1.1.0/vigil-1.1.0-py3-none-any.whl vigil" in remedy
    assert "uv tool upgrade vigil" not in remedy


# --- the source this install actually copied from -----------------------------


def _fake_cli_source(root: Path, body: str) -> Path:
    """A checkout shaped just enough for `cli_state` to digest its CLI package."""
    package = root / "src" / "vigil_cli"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text(body, encoding="utf-8")
    return root


def test_the_post_install_verdict_compares_against_the_source_it_installed_from(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`vigil install --source X` must be judged against X, and nothing else.

    `consumer_states` used to rediscover a source through environment, config,
    the running package, and the current directory — so with two checkouts on
    the box, or an explicit `--source`, the root whose bytes were just copied
    could be compared against a DIFFERENT checkout and reported stale. The
    remedy it then prints (`uv tool upgrade vigil && vigil install`) repeats the
    mismatch or silently switches sources.
    """
    installed_from = _fake_cli_source(tmp_path / "chosen", "VERSION = 'chosen'\n")
    other_checkout = _fake_cli_source(tmp_path / "other", "VERSION = 'other'\n")

    seen: list[Path | None] = []

    def _record(*, source_root: Path | None) -> restart_manifest.ConsumerState:
        seen.append(source_root)
        return _current("cli", "vigil CLI")

    monkeypatch.setattr(restart_manifest, "cli_state", _record)
    monkeypatch.setattr(
        "vigil_cli.status._resolve_source_root_offline", lambda _root: other_checkout
    )

    restart_manifest.consumer_states(
        tmp_path / "root", runner=_fake_runner(), source_root=installed_from
    )
    assert seen == [installed_from]


def test_a_real_install_records_the_source_its_bytes_came_from(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Workspace initialization records the selected application's provenance."""
    from vigil_cli.install import InstallOptions, install_from_source

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)
    installed_from = _fake_cli_source(tmp_path / "chosen", "VERSION = 'chosen'\n")
    (installed_from / "agent").mkdir(parents=True, exist_ok=True)
    (installed_from / "orchestrator").mkdir()
    (installed_from / "agent" / "README").write_text("managed", encoding="utf-8")
    _fake_cli_source(tmp_path / "other", "VERSION = 'other'\n")

    result = install_from_source(
        InstallOptions(
            source_root=installed_from,
            install_root=tmp_path / "install",
            verify_docker_image=False,
        )
    )
    assert result.source_root == installed_from


def test_post_install_judges_the_cli_against_the_installed_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End to end: `_print_post_install` hands the result's source down."""
    from vigil_cli import main as main_module
    from vigil_cli.install import InstallResult

    installed_from = _fake_cli_source(tmp_path / "chosen", "VERSION = 'chosen'\n")
    seen: list[Path | None] = []

    def _capture(install_root: Path, **kwargs: object) -> list[restart_manifest.ConsumerState]:
        seen.append(kwargs.get("source_root"))  # type: ignore[arg-type]
        return [_current("cli", "vigil CLI")]

    monkeypatch.setattr(main_module.restart_manifest, "consumer_states", _capture)
    main_module._print_post_install(
        InstallResult(
            install_root=tmp_path,
            is_upgrade=True,
            image_built=False,
            source_root=installed_from,
        ),
        stream=FakeStream(tty=False),
    )
    assert seen == [installed_from]


def test_consumer_states_still_discovers_a_source_when_none_is_supplied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`vigil status` has no install to name a source, and must keep working."""
    discovered = _fake_cli_source(tmp_path / "discovered", "VERSION = 'discovered'\n")
    seen: list[Path | None] = []

    def _record(*, source_root: Path | None) -> restart_manifest.ConsumerState:
        seen.append(source_root)
        return _current("cli", "vigil CLI")

    monkeypatch.setattr(restart_manifest, "cli_state", _record)
    monkeypatch.setattr(
        "vigil_cli.status._resolve_source_root_offline", lambda _root: discovered
    )
    restart_manifest.consumer_states(tmp_path / "root", runner=_fake_runner())
    assert seen == [discovered]


def test_the_cli_remedy_reinstalls_from_the_source_it_was_judged_against(
    tmp_path: Path,
) -> None:
    """A bare `vigil install` re-resolves its source and can pick a different one.

    On a box with two application overrides the remedy must install the CLI
    from the same explicit development checkout used for this comparison.
    """
    import shlex

    installed_from = _fake_cli_source(tmp_path / "chosen", "VERSION = 'chosen'\n")

    state = restart_manifest.cli_state(source_root=installed_from)

    assert state.state == "stale"
    assert state.remedy == (
        f"uv tool install --force --editable {shlex.quote(str(installed_from))} && vigil --source "
        f"{shlex.quote(str(installed_from))} install"
    )


def test_the_reinstall_remedy_stays_bare_when_no_source_was_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With nothing to name, the remedy must not invent a `--source`."""
    monkeypatch.setattr(
        "vigil_cli.status._resolve_source_root_offline", lambda _root: None
    )
    monkeypatch.setattr(
        "vigil_cli.status.install_staleness", lambda *_a, **_k: {"state": "stale"}
    )

    states = _states(tmp_path / "root", runner=_fake_runner())

    assert states["agent-tree"].remedy == "vigil install"


def test_the_reinstall_remedy_survives_a_checkout_path_with_a_space(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The remedy is pasted into a shell, so an unquoted path is a broken command.

    `~/Library/Mobile Documents` and `/Volumes/My Passport` are ordinary places
    to keep a checkout, and a shipped guard in this repository was once disabled
    outright by exactly that assumption.
    """
    installed_from = _fake_cli_source(tmp_path / "two words", "VERSION = 'x'\n")
    monkeypatch.setattr(
        "vigil_cli.status.install_staleness", lambda *_a, **_k: {"state": "stale"}
    )

    states = _states(
        tmp_path / "root", runner=_fake_runner(), source_root=installed_from
    )

    assert states["agent-tree"].remedy == f"vigil --source '{installed_from}' install"


def test_the_working_root_is_judged_against_the_source_it_was_installed_from(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`_agent_tree_state` is the second consumer that compares against a checkout.

    `install_staleness` rediscovers one when it is not given one, so the working
    root `vigil install --source B` has just written is compared against
    whichever checkout discovery lands on — and reported stale against a tree it
    was never installed from.
    """
    installed_from = _fake_cli_source(tmp_path / "chosen", "VERSION = 'chosen'\n")
    other_checkout = _fake_cli_source(tmp_path / "other", "VERSION = 'other'\n")
    seen: list[Path | None] = []

    def _record(_install_root: Path, *, source_root: Path | None = None) -> dict[str, object]:
        seen.append(source_root)
        return {"state": "current"}

    monkeypatch.setattr("vigil_cli.status.install_staleness", _record)
    monkeypatch.setattr(
        "vigil_cli.status._resolve_source_root_offline", lambda _root: other_checkout
    )

    restart_manifest.consumer_states(
        tmp_path / "root", runner=_fake_runner(), source_root=installed_from
    )

    assert seen == [installed_from]


def test_the_working_root_remedy_names_the_source_it_was_judged_against(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Both stale-ish working-root verdicts prescribe the same pinned reinstall.

    `no-stamp` matters as much as `stale`: an install predating content stamping
    is exactly the one an operator is most likely to repair from the wrong tree.
    """
    import shlex

    installed_from = _fake_cli_source(tmp_path / "chosen", "VERSION = 'chosen'\n")
    expected = f"vigil --source {shlex.quote(str(installed_from))} install"

    for reported in ("stale", "no-stamp"):
        monkeypatch.setattr(
            "vigil_cli.status.install_staleness",
            lambda *_a, _reported=reported, **_k: {"state": _reported},
        )
        states = _states(
            tmp_path / "root", runner=_fake_runner(), source_root=installed_from
        )
        assert states["agent-tree"].remedy == expected, reported


def test_proxy_release_state_is_independent_of_a_different_cli_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Comparing a CLI checkout cannot change the pinned proxy application."""

    installed_from = _fake_cli_source(tmp_path / "chosen", "VERSION = 'chosen'\n")
    monkeypatch.setattr(
        restart_manifest.image_freshness, "image_inputs_state", lambda *a, **k: "current"
    )
    monkeypatch.setattr(restart_manifest.docker, "container_running", lambda *a, **k: False)

    # Driven through `consumer_states`, not the helper: the defect this pins is
    # the WIRING, and a direct call passing `source_root` by hand proves only
    # that the parameter exists.
    states = _states(
        tmp_path / "root", runner=_fake_runner(), source_root=installed_from
    )

    assert states["cli"].state == "stale"
    assert states["proxy-image"].state == "current"
    assert states["proxy-image"].detail == ""


def test_the_pinned_reinstall_remedy_is_a_command_the_cli_actually_accepts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A remedy is a promise that this exact string runs and does that exact thing.

    `--source` is a TOP-LEVEL option, so `vigil install --source X` is an
    argparse error, not a slower spelling. Rendering the remedy and running it
    is the only check that survives someone moving the option onto the
    subparser: a wrong remedy is worse than a bare one, because the operator
    only learns it was wrong after the install they were told to run fails.
    """
    import shlex

    from vigil_cli import main as main_module
    from vigil_cli.install import InstallResult

    named = tmp_path / "chosen"
    for root in (named, tmp_path / "other"):
        (root / "agent").mkdir(parents=True)
        (root / "orchestrator").mkdir(parents=True)
    monkeypatch.setenv("VIGIL_SOURCE_DIR", str(tmp_path / "other"))
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))

    seen: list[Path] = []

    def _capture(options: object) -> InstallResult:
        seen.append(options.source_root)  # type: ignore[attr-defined]
        return InstallResult(install_root=tmp_path / "root", is_upgrade=True, image_built=False)

    monkeypatch.setattr(main_module, "install_from_source", _capture)
    monkeypatch.setattr(main_module, "_print_post_install", lambda *a, **k: None)

    remedy = restart_manifest._install_remedy(named)
    argv = shlex.split(remedy)
    assert argv[0] == "vigil"
    monkeypatch.setattr("sys.argv", [*argv, str(tmp_path / "root")])
    main_module.main()

    assert seen == [named], "the remedy must reinstall from the checkout it names"


def test_the_clean_summary_asserts_no_cause_it_did_not_measure() -> None:
    """"Nothing to restart" is a verdict; "because X changed" is a measurement.

    Consumer state records what each consumer NEEDS, never which files this
    install rewrote — so "this install changed only files that are read live"
    was inferred from the absence of remedies. A backend-source upgrade
    performed while the backend is stopped reaches the same branch and makes the
    claim plainly false.
    """
    text = _post_install_output(
        [_current("backend", "orchestrator backend"), _current("cli", "vigil CLI")],
        tty=False,
    ).lower()
    assert "nothing to restart" in text
    assert "read live" not in text
    assert "changed only" not in text
