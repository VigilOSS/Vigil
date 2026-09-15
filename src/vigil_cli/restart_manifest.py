"""What this install actually invalidated — per consumer, derived, not asserted.

``vigil install`` used to end with a fixed list telling the operator to restart
the runtime, restart the orchestrator, and consider rebuilding the image. It
said that after every install, including the overwhelmingly common one that
changed nothing but prompt markdown under ``agent/`` — which needs no restart at
all, because ``vigil assess`` re-execs the working root on every call and
``/engagements`` is a bind mount. A notice that is wrong nearly every time
trains the operator to skip it, which is worse than printing nothing: the one
install that *does* need a restart looks identical.

This module computes the answer instead. Every consumer is judged by the same
mechanism :mod:`image_freshness` established for Docker images — **a sha256
content digest over a declared input set, stamped onto the consumer when it is
built, re-derived and compared on every check** — because ``install.py`` rewrites
every managed file unconditionally (``_sync_dir_fds`` → ``copy_regular_file`` →
``atomic_write_bytes``, with no content comparison). Every ``vigil install``
therefore bumps the mtime of every managed file, and any mtime high-water mark
reads as stale immediately afterwards. That defect had already shipped twice
(see the :mod:`image_freshness` docstring) and twice more here: ``/readyz``
reported ``restart_required`` with twenty files listed for a byte-identical
backend, and ``vigil up`` ran a full ``npm run build`` for a byte-identical
frontend.

Where a consumer's inputs live outside its own tree, the digest cannot be
derived from a path table. ``taxonomy_bridge`` puts ``agent/scripts`` on
``sys.path`` and imports ``assess.lib.vuln_taxonomy`` at module import time, so a
file under ``agent/`` genuinely *is* loaded into the backend process and
"``agent/**`` is only prompts" is not universally true. The robust way to know
what a running process loaded is to ask it: :func:`loaded_module_files` walks
``sys.modules``. That catches this cross-tree import for free and needs no
maintenance when the next one appears.

:func:`consumer_states` is the seam between detection and presentation. It
answers only "what is the state of each consumer, and what command fixes it";
choosing which rows are worth an operator's attention belongs to the caller.
"""
from __future__ import annotations

import re
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
# `dist` is in `EXCLUDED_INPUT_NAMES`, so `vigil install` never copies over it
# and the stamp survives an upgrade exactly as the built assets beside it do.
BUILD_INPUTS_STAMP = ".vigil-inputs"

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
# The re-run is part of the remedy, not an optional extra. Several consumers are
# judged THROUGH the running binary, so replacing it changes what they should be
# compared against — and nothing re-runs this summary on its own.
_CLI_STALE_REMEDY = "uv tool upgrade vigil && vigil install"


def cli_state(*, source_root: Path | None) -> ConsumerState:
    """Is the ``vigil`` binary running this checkout's CLI code?

    ``vigil install`` upgrades the WORKING ROOT; ``uv tool upgrade vigil``
    upgrades the CLI binary. When the source moves ahead of the installed tool,
    the operator is running old code against a new working root, and the
    two-layer model is exactly the thing they need told.

    ``sys.modules`` locates the package this process actually imported — not a
    guess from ``sys.path`` — and the package DIRECTORY is then digested, because
    for ``vigil_cli`` the directory is a strict superset of the loaded set
    (lazily imported submodules included). A module loaded from OUTSIDE that
    directory means the superset claim is false, and the honest answer is then
    ``unknown`` rather than a comparison over the wrong files.
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
    running_digest = image_freshness.inputs_digest([running], root=running.parent)
    source_digest = image_freshness.inputs_digest([source_package], root=source_package.parent)
    if running_digest == source_digest:
        return ConsumerState(key="cli", label=_CLI_LABEL, state="current", remedy="", detail="")
    return ConsumerState(
        key="cli",
        label=_CLI_LABEL,
        state="stale",
        remedy=_CLI_STALE_REMEDY,
        detail=f"the installed binary at {running} predates {source_package}",
    )


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
    reachable, runtime_block = _readyz_backend_runtime(install_root)
    if not reachable:
        # Genuinely nothing to restart: a stopped orchestrator picks up this
        # install when it next starts.
        return ConsumerState(
            key="backend",
            label="orchestrator backend",
            state="not-running",
            remedy="",
            detail="",
        )
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
    if not runtime_block.get("restart_required"):
        return ConsumerState(
            key="backend",
            label="orchestrator backend",
            state="current",
            remedy="",
            detail="",
        )
    changed = runtime_block.get("changed_inputs")
    return ConsumerState(
        key="backend",
        label="orchestrator backend",
        state="stale",
        remedy="vigil orchestrator restart",
        detail=_changed_summary(changed if isinstance(changed, list) else []),
    )


def _backend_unknown(detail: str) -> ConsumerState:
    """Reachable, but it could not tell us anything we may act on.

    Deliberately not ``not-running``: that state means "needs no restart", and
    the caller drops it. A backend we reached but could not read is the opposite
    — an open question — so it carries no remedy and gets named as unchecked.
    """
    return ConsumerState(
        key="backend",
        label="orchestrator backend",
        state="unknown",
        remedy="",
        detail=detail,
    )


def _readyz_backend_runtime(install_root: Path) -> tuple[bool, dict[str, object] | None]:
    """``(reachable, backend_runtime)`` from ``/readyz``.

    The two halves must stay separable. Collapsing "no answer" and "an answer we
    cannot use" into one None made an older backend — the very thing an upgrade
    produces — read as a stopped one, and a stopped one is dropped from the
    install summary as needing nothing.
    """
    from .status import _orchestrator_readyz_snapshot

    _, readiness = _orchestrator_readyz_snapshot(install_root)
    if not readiness.get("reachable"):
        return False, None
    block = readiness.get("backend_runtime")
    return True, block if isinstance(block, dict) else None


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
    install_root: Path, *, runner: docker.Runner, docker_ok: bool, cli_stale: bool = False
) -> ConsumerState:
    from .mitmproxy import mitmproxy_image_inputs

    if not docker_ok:
        return _docker_unavailable("proxy-image", "mitmproxy image")
    if cli_stale:
        # `mitmproxy_image_inputs` resolves the canonical scope parser through
        # the IMPORTED `vigil_cli.scope_entries` — the old binary's copy while
        # the CLI lags — and `_proxy_build_context` bakes that same copy. So an
        # upgrade touching only the parser compares old against old and reads
        # `current`, while the upgrade the summary prescribes is precisely what
        # changes the answer. Digesting the install root's copy instead would be
        # worse: the build would still use the binary's, so the mismatch would
        # name a rebuild that cannot clear it.
        return ConsumerState(
            key="proxy-image",
            label="mitmproxy image",
            state="unknown",
            remedy="",
            detail=(
                "its baked scope parser comes from the CLI binary; re-check after "
                "`uv tool upgrade vigil && vigil install`"
            ),
        )

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


def _agent_tree_state(install_root: Path) -> ConsumerState:
    """The residual: does the working root itself still match its source?

    This is the ONE consumer that normally needs no restart — ``vigil assess``
    re-execs the working root on every call and ``/engagements`` is a bind mount,
    so a prompt or skill edit is live the moment ``vigil install`` copies it. It
    is listed anyway because the install that FAILED to land is the case an
    operator cannot otherwise see.
    """
    from .status import install_staleness

    try:
        staleness = install_staleness(install_root)
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
            remedy="vigil install",
            detail="installed content differs from the live source",
        )
    if state == "no-stamp":
        return ConsumerState(
            key="agent-tree",
            label="working root",
            state="unknown",
            remedy="vigil install",
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


def consumer_states(
    install_root: Path, *, runner: docker.Runner = docker.run_command
) -> list[ConsumerState]:
    """Every consumer of this install, and what each one now needs.

    Detection only — no printing, no filtering. The caller decides which rows an
    operator should see, which is why ``not-running`` and ``missing`` are
    reported rather than suppressed here: ``vigil status`` wants the full
    inventory and ``vigil install`` wants only the obligations.
    """
    # `status` imports `orchestrator`, which imports this module for the
    # frontend/report build state — so these two reach in at call time. By then
    # both modules are fully initialised and the cycle cannot bite.
    from .status import _resolve_source_root_offline

    install_root = install_root.expanduser().resolve()
    # One probe up front rather than eleven bounded queries that each wait out
    # the daemon timeout, and — the reason it is here rather than an
    # optimisation — the only thing that separates "no image" from "no answer".
    docker_ok = docker.daemon_available(runner=runner)
    cli = cli_state(source_root=_resolve_source_root_offline(install_root))
    return [
        cli,
        _backend_state(install_root),
        _frontend_state(install_root),
        _report_state(install_root),
        _runtime_image_state(install_root, runner=runner, docker_ok=docker_ok),
        _proxy_image_state(
            install_root, runner=runner, docker_ok=docker_ok, cli_stale=cli.state == "stale"
        ),
        _runtime_container_state(runner=runner, docker_ok=docker_ok),
        _proxy_container_state(runner=runner, docker_ok=docker_ok),
        _agent_tree_state(install_root),
    ]
