"""Content provenance and restart requirements for each workspace consumer.

Application inputs belong to the matched release, while service identity and
engagement data belong to the private workspace. Image and UI freshness use
declared SHA256 input digests. Backend freshness also asks the process which
release it retained and which cross-tree modules it loaded, including imports
first loaded after startup. No comparison depends on file timestamps.

An upgraded CLI leaves existing services on their retained application paths;
the backend row names the intentional restart that moves one to the current
release. ``consumer_states`` owns these verdicts and remedies, and presenters
choose which rows to display.
"""
from __future__ import annotations

import re
import json
import shlex
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import docker, image_freshness
from .paths import default_runtime_container
from .runtime import runtime_image_build_state

# Filename written inside a built `dist/` carrying the sha256 of the inputs that
# build was produced from — the frontend/report analogue of
# `image_freshness.IMAGE_INPUTS_LABEL`. It lives INSIDE `dist/` on purpose:
# `dist` is excluded from its own build inputs, and the package builder retains
# both prebuilt assets and their stamps in every immutable application release.
BUILD_INPUTS_STAMP = ".vigil-inputs"

_BACKEND_LABEL = "orchestrator backend"

_RUNTIME_IMAGE = "vigil:latest"
_PROXY_IMAGE = "vigil-proxy:latest"
_PROXY_CONTAINER = "vigil-proxy"

# Declaration order for `consumer_states`, read top-down as "the thing the
# operator runs" → "the services it drives" → "the trees underneath them".
CONSUMER_KEYS = (
    "cli",
    "backend",
    "frontend",
    "report",
    "runtime-image",
    "proxy-image",
    "runtime-container",
    "proxy-container",
    "client-sessions",
    "agent-tree",
)

# `current`/`stale`/`unknown` carry the same meanings they do in
# `image_freshness.image_inputs_state`. The two extra values separate the cases
# an operator must never be nagged about: `not-running` is a service that is
# stopped (restarting it is not a remedy for anything), and `missing` is an
# artifact that was never built (this install did not invalidate it).
CONSUMER_STATES = ("current", "stale", "unknown", "not-running", "missing")


@dataclass(frozen=True, slots=True)
class ConsumerState:
    """One consumer of the install, and what (if anything) it now needs.

    ``remedy`` is the exact command to run, or empty when no command helps —
    a stopped service and an unresolvable comparison both leave the operator
    with nothing to do, and printing a command anyway is how a notice earns
    its way into being ignored.
    """

    key: str
    label: str
    state: str
    remedy: str
    detail: str


@dataclass(frozen=True, slots=True)
class BackendProbe:
    """What one ``/readyz`` probe established — and what it did not.

    Three outcomes have to stay distinguishable, because each answers a
    different question. ``reachable`` with a ``runtime`` block is the only one
    that says anything about staleness; ``reachable`` without one is an older
    or malformed backend, i.e. an open question; and unreachable is not one
    outcome but several — ``unreachable_reason`` keeps a refusal (nothing
    accepted the connection) apart from a timeout (something did, and then went
    quiet), which is the difference between a stopped backend and a live one
    running code this install just replaced.
    """

    reachable: bool
    runtime: dict[str, object] | None = None
    unreachable_reason: str = ""
    unreachable_detail: str = ""


# --- the running process's own loaded modules ---------------------------------


def loaded_module_files(*, under: Path | None = None, prefix: str = "") -> set[Path]:
    """Resolved ``__file__`` of every module this process has imported.

    ``under`` restricts the result to a subtree, ``prefix`` to a module-name
    prefix. This is the only honest answer to "what code is this process
    running": a path table can be wrong the moment someone adds a cross-tree
    import, and ``sys.modules`` cannot be.
    """
    found: set[Path] = set()
    for name, module in list(sys.modules.items()):
        if prefix and not (name == prefix or name.startswith(f"{prefix}.")):
            continue
        raw = getattr(module, "__file__", None)
        if not raw:
            continue
        try:
            path = Path(raw).resolve()
        except (OSError, ValueError):
            continue
        if under is not None and not path.is_relative_to(under):
            continue
        found.add(path)
    return found


# --- frontend / report build inputs -------------------------------------------

_CONFIG_SUFFIX = re.compile(r".+\.config\.(ts|js|mjs|cjs|mts|cts)\Z")


def is_build_config_name(name: str) -> bool:
    """True for a top-level filename a Vite package's build reads as config.

    Used by the maintenance guard that fails when a new ``tailwind.config.ts``
    or ``postcss.config.js`` appears beside a declared input list without
    joining it. The declared lists below are the only hand-maintained ones this
    module adds, and this predicate is what keeps them honest.
    """
    if name in {"package.json", "package-lock.json", "index.html"}:
        return True
    if name.startswith("tsconfig") and name.endswith(".json"):
        return True
    return bool(_CONFIG_SUFFIX.match(name))


def frontend_build_inputs(frontend_dir: Path) -> list[Path]:
    """Everything ``npm run build`` reads for the orchestrator frontend.

    ``node_modules`` is deliberately absent: it is reproduced from
    ``package-lock.json``, which IS declared, and walking it would cost seconds
    per check. A declared path that does not exist still contributes to the
    digest (``image_freshness.input_entries`` yields it as absent), which is what
    makes ADDING a ``vite.config.js`` move the digest.
    """
    return [
        frontend_dir / "package.json",
        frontend_dir / "package-lock.json",
        frontend_dir / "index.html",
        frontend_dir / "vite.config.ts",
        frontend_dir / "vite.config.js",
        frontend_dir / "tsconfig.json",
        frontend_dir / "tsconfig.app.json",
        frontend_dir / "tsconfig.node.json",
        frontend_dir / "src",
    ]


def report_build_inputs(report_dir: Path) -> list[Path]:
    """Everything ``npm run build`` reads for the single-file report template."""
    return [
        report_dir / "package.json",
        report_dir / "package-lock.json",
        report_dir / "index.html",
        report_dir / "vite.config.ts",
        report_dir / "tsconfig.json",
        report_dir / "scripts",
        report_dir / "src",
    ]


def frontend_dir(install_root: Path) -> Path:
    return install_root / "orchestrator" / "frontend"


def report_dir(install_root: Path) -> Path:
    return install_root / "orchestrator" / "report"


def frontend_inputs_digest(install_root: Path) -> str:
    package = frontend_dir(install_root)
    return image_freshness.inputs_digest(frontend_build_inputs(package), root=package)


def report_inputs_digest(install_root: Path) -> str:
    package = report_dir(install_root)
    return image_freshness.inputs_digest(report_build_inputs(package), root=package)


def frontend_build_state(install_root: Path) -> str:
    """``missing`` | ``unknown`` | ``stale`` | ``current`` for ``frontend/dist``."""
    package = frontend_dir(install_root)
    return _stamped_build_state(
        built_marker=package / "dist" / "index.html",
        stamp=package / "dist" / BUILD_INPUTS_STAMP,
        digest=lambda: frontend_inputs_digest(install_root),
    )


def report_build_state(install_root: Path) -> str:
    """``not-packaged`` | ``missing`` | ``unknown`` | ``stale`` | ``current``.

    ``not-packaged`` is its own answer because an install predating the report
    template has nothing to build: treating that as ``missing`` would print a
    build command for a package that does not exist.
    """
    package = report_dir(install_root)
    if not package.is_dir():
        return "not-packaged"
    return _stamped_build_state(
        built_marker=package / "dist" / "template.html",
        stamp=package / "dist" / BUILD_INPUTS_STAMP,
        digest=lambda: report_inputs_digest(install_root),
    )


def record_frontend_build(install_root: Path) -> None:
    """Stamp the inputs the frontend was just built from beside its output."""
    _write_stamp(
        frontend_dir(install_root) / "dist" / BUILD_INPUTS_STAMP,
        frontend_inputs_digest(install_root),
    )


def record_report_build(install_root: Path) -> None:
    """Stamp the inputs the report template was just built from beside its output."""
    _write_stamp(
        report_dir(install_root) / "dist" / BUILD_INPUTS_STAMP,
        report_inputs_digest(install_root),
    )


def _stamped_build_state(
    *, built_marker: Path, stamp: Path, digest: Callable[[], str]
) -> str:
    if not built_marker.exists():
        return "missing"
    try:
        baked = stamp.read_text(encoding="utf-8").strip()
    except OSError:
        baked = ""
    if not baked:
        # Built before stamping. Nothing can be PROVEN about it, so it reads as
        # outdated exactly like an unstamped image: the caller rebuilds once,
        # the rebuild stamps, and every later check is decisive.
        return "unknown"
    try:
        return "current" if baked == digest() else "stale"
    except OSError:
        # An input vanished mid-walk. "Cannot tell" is the honest answer, and it
        # still rebuilds once — far better than failing the command that asked.
        return "unknown"


def _write_stamp(stamp: Path, digest: str) -> None:
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(f"{digest}\n", encoding="utf-8")


# --- per-consumer state -------------------------------------------------------

_CLI_LABEL = "vigil CLI binary"


def _install_remedy(source_root: Path | None) -> str:
    """Initialize/adopt against the same explicit application used by the check."""
    if source_root is None:
        return "vigil install"
    return f"vigil --source {shlex.quote(str(source_root))} install"


def _cli_stale_remedy(source_root: Path | None) -> str:
    """Install the matched release/development CLI, then recompute adoption."""
    if source_root is not None and (source_root / "src/vigil_cli").is_dir():
        upgrade = shlex.join(["uv", "tool", "install", "--force", "--editable", str(source_root)])
    else:
        from . import __version__

        version = __version__
        if source_root is not None and (source_root / "bundle.json").is_file():
            version = json.loads((source_root / "bundle.json").read_text())["version"]
        wheel = f"https://github.com/VigilOSS/Vigil/releases/download/v{version}/vigil-{version}-py3-none-any.whl"
        upgrade = shlex.join(["uv", "tool", "install", "--force", "--from", wheel, "vigil"])
    return f"{upgrade} && {_install_remedy(source_root)}"


def cli_state(*, source_root: Path | None) -> ConsumerState:
    """Does the imported CLI match the editable or retained release snapshot?

    The package directory covers lazily imported modules as well. Embedded
    assets are verified separately and excluded from this code-only comparison.
    """
    running = _running_cli_package()
    if running is None:
        return _cli_unknown("the running CLI package has no resolvable location")
    stray = [
        path
        for path in loaded_module_files(prefix="vigil_cli")
        if not path.is_relative_to(running)
    ]
    if stray:
        return _cli_unknown(f"{len(stray)} vigil_cli module(s) loaded from outside {running}")
    if source_root is None:
        return _cli_unknown("no local source checkout to compare against")
    source_package = (source_root / "cli" / "vigil_cli").expanduser()
    if not source_package.is_dir():
        source_package = (source_root / "src" / "vigil_cli").expanduser()
    if not source_package.is_dir():
        return _cli_unknown(f"no CLI package at {source_package}")
    source_package = source_package.resolve()
    if source_package == running:
        return ConsumerState(
            key="cli",
            label=_CLI_LABEL,
            state="current",
            remedy="",
            detail=f"running from the source tree ({running})",
        )
    # Both digests label files relative to their own package directory, so an
    # editable checkout and a uv-tool venv copy land in the same label space and
    # only CONTENT can separate them.
    running_digest = _cli_inputs_digest(running)
    source_digest = _cli_inputs_digest(source_package)
    if running_digest == source_digest:
        return ConsumerState(key="cli", label=_CLI_LABEL, state="current", remedy="", detail="")
    return ConsumerState(
        key="cli",
        label=_CLI_LABEL,
        state="stale",
        remedy=_cli_stale_remedy(source_root),
        detail=f"the installed binary at {running} predates {source_package}",
    )


def _cli_inputs_digest(package: Path) -> str:
    # Embedded application assets and bytecode caches do not belong to the
    # executable CLI snapshot.
    inputs = sorted(
        entry for entry in package.iterdir()
        if entry.name != "_bundle" and not image_freshness.is_excluded_input(entry.name)
    )
    return image_freshness.inputs_digest(inputs, root=package.parent)


def _cli_unknown(detail: str) -> ConsumerState:
    """Cannot prove the binary current — and cannot name a command that helps."""
    return ConsumerState(key="cli", label=_CLI_LABEL, state="unknown", remedy="", detail=detail)


def _running_cli_package() -> Path | None:
    module = sys.modules.get("vigil_cli")
    raw = getattr(module, "__file__", None) if module is not None else None
    if not raw:
        return None
    try:
        return Path(raw).resolve().parent
    except (OSError, ValueError):
        return None


def _backend_state(install_root: Path) -> ConsumerState:
    """Ask the running backend; it is the only thing that knows what it imported.

    The comparison is deliberately server-side. The backend snapshots a digest of
    its declared inputs plus its cross-tree loaded modules at process start and
    re-derives it per request, so no second implementation of the input set has
    to agree with it from out here.
    """
    return _backend_state_from_probe(install_root, _readyz_backend_runtime(install_root))


def backend_state_from_readiness(install_root: Path, readiness: dict[str, object]) -> ConsumerState:
    """Derive release/restart truth from a readiness snapshot already fetched."""
    return _backend_state_from_probe(install_root, _backend_probe_from_readiness(readiness))


def _backend_state_from_probe(install_root: Path, probe: BackendProbe) -> ConsumerState:
    if not probe.reachable:
        return _backend_offline_state(install_root, probe)
    runtime_block = probe.runtime
    if runtime_block is None:
        # Reachable but unusable — an older backend with no `backend_runtime`
        # block, or a malformed body. That is the UPGRADE case this consumer
        # exists for, so it must not read as checked-and-fine. `unknown` with no
        # remedy puts it in the caller's "could not be checked" list instead.
        return _backend_unknown("/readyz did not report a usable backend_runtime block")
    # The orchestrator base URL is a fixed 127.0.0.1:18000 for every working
    # root, so the backend that answered may be serving a DIFFERENT one — and
    # its restart_required says nothing about this install. `/readyz` publishes
    # `install_root` precisely so this can be checked.
    served = runtime_block.get("install_root")
    if not isinstance(served, str) or not served:
        return _backend_unknown("/readyz did not report which install root it serves")
    if Path(served).resolve() != install_root.resolve():
        return _backend_unknown(f"the backend on this port serves a different install root ({served})")
    from .application import application_root_for_workspace

    serving_application = runtime_block.get("application_root")
    application_root = application_root_for_workspace(install_root)
    if not isinstance(serving_application, str) or not serving_application:
        return ConsumerState(
            key="backend",
            label=_BACKEND_LABEL,
            state="stale",
            remedy="vigil orchestrator restart",
            detail="running a legacy backend without a pinned application release",
        )
    if isinstance(serving_application, str) and Path(serving_application).resolve() != application_root.resolve():
        return ConsumerState(
            key="backend",
            label=_BACKEND_LABEL,
            state="stale",
            remedy="vigil orchestrator restart",
            detail=f"running retained application release {serving_application}; current release is {application_root}",
        )
    if not runtime_block.get("restart_required"):
        return ConsumerState(
            key="backend",
            label=_BACKEND_LABEL,
            state="current",
            remedy="",
            detail="",
        )
    changed = runtime_block.get("changed_inputs")
    return ConsumerState(
        key="backend",
        label=_BACKEND_LABEL,
        state="stale",
        remedy="vigil orchestrator restart",
        detail=_changed_summary(changed if isinstance(changed, list) else []),
    )


def _backend_offline_state(install_root: Path, probe: BackendProbe) -> ConsumerState:
    """No answer from ``/readyz`` — which is not the same as "stopped".

    ``not-running`` is the one backend verdict `vigil install` drops entirely,
    on the grounds that a stopped orchestrator picks this install up when it
    next starts. Reaching it from a failed probe alone asserted something the
    probe never measured: a backend that is wedged, still starting, or merely
    slower than the one-second timeout keeps running the code it loaded, and
    that loaded code is exactly what an install invalidates. So the process is
    asked locally, on the same host and port the probe used, and only a
    positively stopped one clears the row.
    """
    from . import orchestrator

    host, port = _orchestrator_host_port(install_root)
    payload = orchestrator.orchestrator_status_payload(install_root, host=host, port=port)
    pid = payload.get("pid")
    process_running = payload.get("state") == "running"
    port_held = bool(payload.get("port_in_use"))
    if probe.unreachable_reason == "refused" and not process_running and not port_held:
        # Nothing accepted the connection, no pidfile claims a live process, and
        # nothing holds the port. That is a stopped backend, established rather
        # than assumed.
        return ConsumerState(
            key="backend",
            label=_BACKEND_LABEL,
            state="not-running",
            remedy="",
            detail="",
        )
    return _backend_unknown(
        _backend_offline_detail(probe, process_running, pid, port_held, host, port)
    )


def _backend_offline_detail(
    probe: BackendProbe,
    process_running: bool,
    pid: object,
    port_held: bool,
    host: str,
    port: int,
) -> str:
    """Name the exact shape of the failure, so the operator can act on it."""
    if probe.unreachable_reason == "timeout":
        probe_phrase = "/readyz timed out"
    elif probe.unreachable_reason == "refused":
        probe_phrase = "/readyz refused the connection"
    else:
        suffix = f" ({probe.unreachable_detail})" if probe.unreachable_detail else ""
        probe_phrase = f"/readyz could not be reached{suffix}"
    if process_running:
        return f"the orchestrator process (PID {pid}) is running but {probe_phrase}"
    if port_held:
        return f"{host}:{port} is held by another process but {probe_phrase}"
    return f"{probe_phrase}; this backend was never established as stopped"


def _orchestrator_host_port(install_root: Path) -> tuple[str, int]:
    """The host and port ``/readyz`` was actually probed on.

    `orchestrator_status_payload` defaults to 127.0.0.1:18000, but the base URL
    is configurable through five layers — checking whether the DEFAULT port is
    held would be evidence about a different service entirely.
    """
    from urllib.parse import urlsplit

    from .paths import DEFAULT_ORCHESTRATOR_BASE_URL, resolve_orchestrator_base_url

    for candidate in (resolve_orchestrator_base_url(install_root), DEFAULT_ORCHESTRATOR_BASE_URL):
        parts = urlsplit(candidate)
        if parts.hostname:
            return parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    return "127.0.0.1", 18000


def _backend_unknown(detail: str) -> ConsumerState:
    """Reachable, but it could not tell us anything we may act on.

    Deliberately not ``not-running``: that state means "needs no restart", and
    the caller drops it. A backend we reached but could not read is the opposite
    — an open question — so it carries no remedy and gets named as unchecked.
    """
    return ConsumerState(
        key="backend",
        label=_BACKEND_LABEL,
        state="unknown",
        remedy="",
        detail=detail,
    )


def _readyz_backend_runtime(install_root: Path) -> BackendProbe:
    """What ``/readyz`` was able to tell us, with the failure kinds kept apart.

    Three cases must stay separable, because each one clears a different amount
    of the question. "An answer we cannot use" collapsed into "no answer" once,
    and made an older backend — the very thing an upgrade produces — read as a
    stopped one, which the install summary drops as needing nothing. "No answer
    at all" then hid the same defect one level down: a refused connection and a
    timed-out one are not the same claim about whether a process is running.
    """
    from .status import _orchestrator_readyz_snapshot

    _, readiness = _orchestrator_readyz_snapshot(install_root)
    return _backend_probe_from_readiness(readiness)


def _backend_probe_from_readiness(readiness: dict[str, object]) -> BackendProbe:
    if not readiness.get("reachable"):
        reason = readiness.get("unreachable_reason")
        detail = readiness.get("unreachable_detail")
        return BackendProbe(
            reachable=False,
            runtime=None,
            unreachable_reason=reason if isinstance(reason, str) else "error",
            unreachable_detail=detail if isinstance(detail, str) else "",
        )
    block = readiness.get("backend_runtime")
    return BackendProbe(reachable=True, runtime=block if isinstance(block, dict) else None)


def _frontend_state(install_root: Path) -> ConsumerState:
    state = frontend_build_state(install_root)
    return ConsumerState(
        key="frontend",
        label="orchestrator frontend",
        state=state,
        remedy="" if state in {"current", "missing"} else "vigil orchestrator build",
        detail="built before input stamping" if state == "unknown" else "",
    )


def _report_state(install_root: Path) -> ConsumerState:
    state = report_build_state(install_root)
    if state == "not-packaged":
        return ConsumerState(
            key="report",
            label="report template",
            state="missing",
            remedy="",
            detail="this install has no report package",
        )
    return ConsumerState(
        key="report",
        label="report template",
        state=state,
        remedy="" if state in {"current", "missing"} else "vigil orchestrator build",
        detail="built before input stamping" if state == "unknown" else "",
    )


def _docker_unavailable(key: str, label: str) -> ConsumerState:
    """What every Docker-backed consumer says when the daemon will not answer.

    Not ``missing``: `docker.image_exists` reports False for a wedged daemon
    exactly as it does for an absent image, so without this probe an
    unresponsive Docker Desktop would have `vigil install` quietly report that
    the runtime image was never built.
    """
    return ConsumerState(
        key=key,
        label=label,
        state="unknown",
        remedy="",
        detail="the Docker daemon is not responding",
    )


def _runtime_image_state(
    install_root: Path, *, runner: docker.Runner, docker_ok: bool
) -> ConsumerState:
    if not docker_ok:
        return _docker_unavailable("runtime-image", "Kali runtime image")
    state = runtime_image_build_state(install_root, image=_RUNTIME_IMAGE, runner=runner)
    remedy = "" if state in {"current", "missing"} else "vigil runtime build"
    if remedy and docker.container_running(default_runtime_container(), runner=runner):
        # `vigil runtime build` retags the image; it does not recreate the
        # container. While the image is stale-but-not-yet-rebuilt the container
        # still matches the tag, so `_runtime_container_state` reads `current`
        # and contributes no row — an operator who does exactly what this
        # summary says is still running the old baked tools. The restart is a
        # DEPENDENT action of the build, so it belongs on this remedy rather
        # than waiting for a later status check to discover the new drift.
        remedy = "vigil runtime build && vigil runtime restart"
    return ConsumerState(
        key="runtime-image",
        label="Kali runtime image",
        state=state,
        remedy=remedy,
        detail="built before input stamping" if state == "unknown" else "",
    )


def _proxy_image_state(
    install_root: Path,
    *,
    runner: docker.Runner,
    docker_ok: bool,
) -> ConsumerState:
    from .mitmproxy import mitmproxy_image_inputs

    if not docker_ok:
        return _docker_unavailable("proxy-image", "mitmproxy image")
    try:
        inputs = mitmproxy_image_inputs(install_root)
    except SystemExit as exc:
        # The proxy manifest covers the installed canonical scope parser, which
        # a frozen/zipped CLI may not expose as a file. That is a reason to say
        # "cannot tell", never a reason to fail an install summary.
        return ConsumerState(
            key="proxy-image",
            label="mitmproxy image",
            state="unknown",
            remedy="",
            detail=str(exc),
        )
    state = image_freshness.image_inputs_state(
        _PROXY_IMAGE, inputs, root=install_root, runner=runner
    )
    remedy = "" if state in {"current", "missing"} else "vigil mitmproxy build"
    if remedy and docker.container_running(_PROXY_CONTAINER, runner=runner):
        # `vigil mitmproxy start` is documented as "Start (or restart) the shared
        # proxy container", and `--build` rebuilds first — so one command does
        # what a bare `build` cannot: leave the LIVE proxy running the addon and
        # scope parser this install just wrote.
        remedy = "vigil mitmproxy start --build"
    return ConsumerState(
        key="proxy-image",
        label="mitmproxy image",
        state=state,
        remedy=remedy,
        detail="built before input stamping" if state == "unknown" else "",
    )


def _proxy_container_state(*, runner: docker.Runner, docker_ok: bool) -> ConsumerState:
    """Is the running ``vigil-proxy`` still the one ``vigil-proxy:latest`` points at?

    The runtime has had this consumer from the start; the proxy did not, so a
    proxy rebuilt by some earlier command left a live container on the old image
    with nothing reporting it. Same rule as the runtime: a stopped proxy needs
    nothing, because the next start picks up the current image.
    """
    if not docker_ok:
        return _docker_unavailable("proxy-container", "mitmproxy container")
    if not docker.container_running(_PROXY_CONTAINER, runner=runner):
        return ConsumerState(
            key="proxy-container",
            label="mitmproxy container",
            state="not-running",
            remedy="",
            detail="",
        )
    if not image_freshness.proxy_image_drift(runner=runner):
        return ConsumerState(
            key="proxy-container",
            label="mitmproxy container",
            state="current",
            remedy="",
            detail="",
        )
    return ConsumerState(
        key="proxy-container",
        label="mitmproxy container",
        state="stale",
        remedy="vigil mitmproxy start",
        detail="running an image the tag has since replaced",
    )


def _runtime_container_state(*, runner: docker.Runner, docker_ok: bool) -> ConsumerState:
    """Is the running Kali container still the one ``vigil:latest`` points at?

    A stopped container is ``not-running`` with no remedy: the next
    ``vigil runtime start`` picks up the current image, and telling someone to
    restart a stopped service is the kind of wrong advice this module exists to
    stop printing.
    """
    if not docker_ok:
        return _docker_unavailable("runtime-container", "Kali runtime container")
    container = default_runtime_container()
    if not docker.container_running(container, runner=runner):
        return ConsumerState(
            key="runtime-container",
            label="Kali runtime container",
            state="not-running",
            remedy="",
            detail="",
        )
    running_image = docker.container_image_id(container, runner=runner)
    tagged_image = docker.image_id(_RUNTIME_IMAGE, runner=runner)
    if not running_image or not tagged_image:
        return ConsumerState(
            key="runtime-container",
            label="Kali runtime container",
            state="unknown",
            remedy="",
            detail="docker did not report both image ids",
        )
    if running_image == tagged_image:
        return ConsumerState(
            key="runtime-container",
            label="Kali runtime container",
            state="current",
            remedy="",
            detail="",
        )
    return ConsumerState(
        key="runtime-container",
        label="Kali runtime container",
        state="stale",
        remedy="vigil runtime restart",
        detail=f"running an image older than {_RUNTIME_IMAGE}",
    )


def _agent_tree_state(install_root: Path, *, source_root: Path | None) -> ConsumerState:
    """Report whether workspace adoption/provenance matches its application."""
    from .status import install_staleness

    try:
        staleness = install_staleness(install_root, source_root=source_root)
    except Exception:  # noqa: BLE001 — a summary must never break an install
        staleness = {"state": "unknown"}
    state = str(staleness.get("state") or "unknown")
    if state == "current":
        return ConsumerState(
            key="agent-tree",
            label="working root",
            state="current",
            remedy="",
            detail="",
        )
    if state == "stale":
        return ConsumerState(
            key="agent-tree",
            label="working root",
            state="stale",
            remedy=_install_remedy(source_root),
            detail="installed content differs from the live source",
        )
    if state == "no-stamp":
        return ConsumerState(
            key="agent-tree",
            label="working root",
            state="unknown",
            remedy=_install_remedy(source_root),
            detail="this install predates content stamping",
        )
    return ConsumerState(
        key="agent-tree",
        label="working root",
        state="unknown",
        remedy="",
        detail="no local source checkout to compare against",
    )


def _changed_summary(changed: list[object], *, limit: int = 3) -> str:
    if not changed:
        return ""
    preview = ", ".join(str(item) for item in changed[:limit])
    more = len(changed) - limit
    return f"{preview} +{more} more changed" if more > 0 else f"{preview} changed"


def client_sessions_state(install_root: Path) -> ConsumerState:
    """One release comparison for retained official client processes."""
    from .application import application_provenance, application_root_for_workspace
    from .client_sessions import active_client_sessions

    sessions = active_client_sessions(install_root)
    if not sessions:
        return ConsumerState("client-sessions", "client sessions", "not-running", "", "no registered live sessions")
    try:
        current = application_provenance(application_root_for_workspace(install_root))
    except (OSError, SystemExit, ValueError) as exc:
        return ConsumerState("client-sessions", "client sessions", "unknown", "", str(exc))
    older = [session for session in sessions if (
        session["application"]["version"], session["application"]["content_sha256"]
    ) != (current["version"], current["content_sha256"])]
    if not older:
        return ConsumerState("client-sessions", "client sessions", "current", "", f"{len(sessions)} live session(s) use the current application")
    detail = "; ".join(
        f"{Path(session['engagement']).name}: release={session['application']['version']} pid={session['pid']}"
        for session in older
    )
    commands = [shlex.join([
        "vigil", "engagement", "start", Path(session["engagement"]).name,
        "--client", str(session.get("client") or "claude"),
        "--mode", str(session.get("mode") or "web"), "--root", str(install_root),
    ]) for session in older]
    return ConsumerState("client-sessions", "client sessions", "stale",
                         "End the listed sessions, then " + "; ".join(commands), detail)


def consumer_states(
    install_root: Path,
    *,
    runner: docker.Runner = docker.run_command,
    source_root: Path | None = None,
) -> list[ConsumerState]:
    """Every consumer of this install, and what each one now needs.

    Detection only — no printing, no filtering. The caller decides which rows an
    operator should see, which is why ``not-running`` and ``missing`` are
    reported rather than suppressed here: ``vigil status`` wants the full
    inventory and ``vigil install`` wants only the obligations.

    ``source_root`` is an explicit application comparison override. Otherwise
    the imported release selects code independently of workspace data.
    """
    # `status` imports `orchestrator`, which imports this module for the
    # frontend/report build state — so these two reach in at call time. By then
    # both modules are fully initialised and the cycle cannot bite.
    from .status import _resolve_source_root_offline
    from .application import application_root_for_workspace

    install_root = install_root.expanduser().resolve()
    application_root = application_root_for_workspace(install_root)
    # One probe up front rather than eleven bounded queries that each wait out
    # the daemon timeout, and — the reason it is here rather than an
    # optimisation — the only thing that separates "no image" from "no answer".
    docker_ok = docker.daemon_available(runner=runner)
    # Resolved ONCE, then handed to every consumer that compares against a
    # checkout or names one in a command. Each such consumer used to rediscover
    # its own, so one summary could judge the CLI against the installed source
    # and the working root against a sibling — and print two different reinstall
    # commands for one install.
    resolved_source = (
        source_root if source_root is not None else _resolve_source_root_offline(install_root)
    )
    cli = cli_state(source_root=resolved_source)
    return [
        cli,
        _backend_state(install_root),
        _frontend_state(application_root),
        _report_state(application_root),
        _runtime_image_state(application_root, runner=runner, docker_ok=docker_ok),
        _proxy_image_state(
            application_root,
            runner=runner,
            docker_ok=docker_ok,
        ),
        _runtime_container_state(runner=runner, docker_ok=docker_ok),
        _proxy_container_state(runner=runner, docker_ok=docker_ok),
        client_sessions_state(install_root),
        _agent_tree_state(install_root, source_root=resolved_source),
    ]
