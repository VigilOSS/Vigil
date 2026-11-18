"""`vigil update`: install the newest release, then restart what it left stale.

The running process has the old CLI imported, so it only installs the verified
release wheel and re-executes the newly installed `vigil update`. That process
reconciles the workspace and restarts the running services `consumer_states`
proves stale. A CLI that runs from a source checkout is never replaced: the
checkout supplies the application, and its owner updates it with their VCS.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Callable, Iterable, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from . import docker
from .mitmproxy import MitmproxyOptions, start_proxy
from .orchestrator import restart_orchestrator
from .paths import default_runtime_container, engagements_root
from .restart_manifest import ConsumerState, consumer_states
from .runtime import RuntimeOptions, start_runtime

RELEASES_API = "https://api.github.com/repos/VigilOSS/Vigil/releases"
# Set on the re-executed CLI to the version just installed; only that process
# skips the release lookup, and it must actually report that version.
REEXEC_ENV = "VIGIL_UPDATE_INSTALLED_VERSION"
_PROXY_CONTAINER = "vigil-proxy"


@dataclass(frozen=True, slots=True)
class Release:
    version: str
    wheel_name: str
    wheel_url: str
    sha256: str


@dataclass(frozen=True, slots=True)
class UpdateOptions:
    # Global arguments forwarded to the re-executed CLI, such as `--root <path>`.
    root_argv: tuple[str, ...] = ()
    version: str | None = None
    restart: bool = True


def _fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "vigil-cli"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except OSError as exc:
        raise SystemExit(f"Cannot read Vigil releases from {url}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"{url} did not return a release")
    return payload


def _open_url(url: str) -> IO[bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": "vigil-cli"})
    return urllib.request.urlopen(request, timeout=120)


def resolve_release(
    version: str | None, *, fetch_json: Callable[[str], dict[str, Any]] = _fetch_json
) -> Release:
    """The latest published release, or the pinned one, with its wheel digest."""
    url = f"{RELEASES_API}/latest" if version is None else f"{RELEASES_API}/tags/v{version.removeprefix('v')}"
    payload = fetch_json(url)
    tag = str(payload.get("tag_name") or "")
    if not tag.startswith("v") or payload.get("draft") or payload.get("prerelease"):
        raise SystemExit(f"{url} is not a published Vigil release (tag {tag or 'missing'})")
    resolved = tag.removeprefix("v")
    wheel_name = f"vigil-{resolved}-py3-none-any.whl"
    asset = next(
        (item for item in payload.get("assets") or [] if isinstance(item, dict) and item.get("name") == wheel_name),
        None,
    )
    if asset is None:
        raise SystemExit(f"Release {tag} has no {wheel_name}")
    digest = str(asset.get("digest") or "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SystemExit(f"Release {tag} publishes no SHA256 digest for {wheel_name}; refusing an unverified install")
    return Release(resolved, wheel_name, str(asset["browser_download_url"]), digest.removeprefix("sha256:"))


def download_wheel(
    release: Release, directory: Path, *, open_url: Callable[[str], IO[bytes]] = _open_url
) -> Path:
    """Download the wheel and keep it only when its content matches the release digest."""
    target = directory / release.wheel_name
    partial = target.with_name(target.name + ".part")
    sha = hashlib.sha256()
    try:
        with open_url(release.wheel_url) as response, partial.open("wb") as handle:
            for chunk in iter(lambda: response.read(1 << 20), b""):
                sha.update(chunk)
                handle.write(chunk)
    except OSError as exc:
        partial.unlink(missing_ok=True)
        raise SystemExit(f"Cannot download {release.wheel_url}: {exc}") from exc
    if sha.hexdigest() != release.sha256:
        partial.unlink(missing_ok=True)
        raise SystemExit(
            f"{release.wheel_name} digest {sha.hexdigest()} does not match the release digest {release.sha256}"
        )
    partial.replace(target)
    return target


def source_checkout(cli_package: Path) -> Path | None:
    """The checkout an editable CLI runs from, or None for an installed release."""
    checkout = cli_package.parent.parent
    if cli_package.parent.name == "src" and (checkout / "pyproject.toml").is_file():
        return checkout
    return None


def _version_key(version: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"(\d+(?:\.\d+)*)", version)
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def install_newest_release(
    options: UpdateOptions,
    *,
    running_version: str,
    fetch_json: Callable[[str], dict[str, Any]] = _fetch_json,
    open_url: Callable[[str], IO[bytes]] = _open_url,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
    execve: Callable[[str, list[str], dict[str, str]], object] = os.execve,
    cli_package: Path | None = None,
    environ: MutableMapping[str, str] = os.environ,
) -> None:
    """Install the release and re-execute into it; return once this CLI is the one to finish.

    Returns without installing when this CLI is already that release, is newer
    than the latest release (no downgrade without an explicit version), or runs
    from a source checkout.
    """
    installed = environ.pop(REEXEC_ENV, None)
    if installed is not None:
        if running_version != installed:
            raise SystemExit(
                f"Installed vigil {installed}, but the `vigil` that ran next reports {running_version}. "
                "Check `uv tool list` and which `vigil` your PATH selects."
            )
        print(f"[vigil] Installed vigil {installed}", file=sys.stderr)
        return
    package = cli_package if cli_package is not None else Path(__file__).resolve().parent
    checkout = source_checkout(package)
    if checkout is not None:
        print(
            f"[vigil] This vigil runs from the source checkout {checkout}; update the checkout with your VCS. "
            "Reconciling the workspace and restarting stale services from it.",
            file=sys.stderr,
        )
        return
    release = resolve_release(options.version, fetch_json=fetch_json)
    if release.version == running_version:
        print(f"[vigil] vigil {running_version} is current", file=sys.stderr)
        return
    running_key, release_key = _version_key(running_version), _version_key(release.version)
    if options.version is None and running_key and release_key and running_key > release_key:
        print(
            f"[vigil] vigil {running_version} is newer than the latest release {release.version}; "
            "pass --release to install that release",
            file=sys.stderr,
        )
        return
    manual = shlex.join(["uv", "tool", "install", "--force", "--from", release.wheel_url, "vigil"])
    uv = which("uv")
    if uv is None:
        raise SystemExit(f"uv is not on PATH. Install the release with `{manual}`, then run `vigil update`.")
    print(f"[vigil] Installing vigil {release.version} (from {running_version})", file=sys.stderr)
    with tempfile.TemporaryDirectory(prefix="vigil-update-") as scratch:
        wheel = download_wheel(release, Path(scratch), open_url=open_url)
        installed_run = run([uv, "tool", "install", "--force", "--from", str(wheel), "vigil"], check=False)
        if installed_run.returncode != 0:
            raise SystemExit(f"uv tool install failed (exit {installed_run.returncode}); retry with `{manual}`")
    bin_dir = run([uv, "tool", "dir", "--bin"], capture_output=True, text=True, check=False)
    if bin_dir.returncode != 0 or not bin_dir.stdout.strip():
        raise SystemExit("Installed the release, but `uv tool dir --bin` failed; run `vigil update` again.")
    executable = str(Path(bin_dir.stdout.strip()) / "vigil")
    argv = [executable, *options.root_argv, "update"]
    if not options.restart:
        argv.append("--no-restart")
    if options.version is not None:
        argv += ["--release", release.version]
    sys.stdout.flush()
    sys.stderr.flush()
    execve(executable, argv, {**environ, REEXEC_ENV: release.version})


def restart_stale_services(
    install_root: Path,
    *,
    states: Iterable[ConsumerState] | None = None,
    container_running: Callable[..., bool] = docker.container_running,
) -> list[str]:
    """Restart each running local service whose code or image is proven stale.

    Stopped services pick up the release when they next start, and `unknown`
    verdicts stay with the install summary, which names them.
    """
    by_key = {state.key: state for state in (consumer_states(install_root) if states is None else states)}

    def stale(key: str) -> bool:
        state = by_key.get(key)
        return state is not None and state.state == "stale"

    restarted: list[str] = []
    backend = by_key.get("backend")
    if backend is not None and stale("backend") and backend.remedy == "vigil orchestrator restart":
        print("[vigil] Restarting the orchestrator backend", file=sys.stderr)
        restart_orchestrator(install_root)
        restarted.append("backend")
    if stale("runtime-container") or (stale("runtime-image") and container_running(default_runtime_container())):
        print("[vigil] Restarting the Kali runtime; in-flight `vigil assess kali` jobs stop", file=sys.stderr)
        start_runtime(RuntimeOptions(install_root=install_root, recreate=True))
        restarted.append("runtime")
    if stale("proxy-container") or (stale("proxy-image") and container_running(_PROXY_CONTAINER)):
        print("[vigil] Restarting the mitmproxy capture proxy", file=sys.stderr)
        directory = engagements_root(install_root)
        directory.mkdir(parents=True, exist_ok=True)
        start_proxy(MitmproxyOptions(install_root=install_root, engagements_root=directory))
        restarted.append("proxy")
    return restarted
