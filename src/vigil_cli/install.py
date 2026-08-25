from __future__ import annotations

import platform
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from . import docker
from . import config as config_module
from .client_rosters import repair_engagement_client_rosters
from .image_freshness import is_excluded_input
from .oob import DEFAULT_OOB_DOMAIN
from .oob_tenants import initialize_tenant_route
from .runtime import build_runtime
from .status import INSTALL_META_FILENAME, write_install_meta


def _rmtree(path: Path) -> None:
    """shutil.rmtree with a single retry on macOS for Spotlight/Finder races."""
    try:
        shutil.rmtree(path)
    except OSError:
        if platform.system() == "Darwin":
            time.sleep(0.5)
            shutil.rmtree(path)
        else:
            raise

ROOT_MANAGED_NAMES = {
    "README.md",
    "CODE-MAP.md",
    "TODOs",
    "agent",
    "orchestrator",
    "docker",
    "pyproject.toml",
    "src",
}

ROOT_PRESERVE_NAMES = {
    ".env",
    ".orchestrator.env",
    ".runtime-data",
    ".git",
    ".jj",
}

# Directories/files only a PRIOR Vigil install or run leaves behind. Source-tree
# directory names ("agent", "orchestrator", ".claude", ".codex") are NOT a
# signal: when the install root IS the source checkout they exist before Vigil
# has ever run there, so the FIRST in-place install reported an upgrade and
# `initialize_tenant_route` pinned the legacy shared OOB domain (ports 53/8443)
# instead of allocating a tenant-specific route — two fresh in-place developer
# installs then collided at the FRP/OOB edge.
PRIOR_INSTALL_MARKERS = (
    INSTALL_META_FILENAME,  # stamped by every install_from_source
    ".runtime-data",  # created by _ensure_install_dirs on every install
)

LEGACY_INSTALLER_NAME = "install" ".sh"


@dataclass(frozen=True, slots=True)
class InstallOptions:
    source_root: Path
    install_root: Path
    dry_run: bool = False
    force_image: bool = False
    verify_docker_image: bool = True


@dataclass(frozen=True, slots=True)
class InstallResult:
    install_root: Path
    is_upgrade: bool
    image_built: bool


def _is_excluded(path: Path) -> bool:
    """Build artifacts and caches are never copied into an install — and are
    never image build inputs either. `image_freshness` owns that single
    judgement so the copier and the freshness digest cannot drift apart."""
    return is_excluded_input(path.name)


def _has_engagement_directories(install_root: Path) -> bool:
    """True when `agent/engagements/` holds at least one real engagement.

    An engagement is a DIRECTORY created by Vigil at engagement time; a pristine
    checkout carries only the tracked `.gitkeep` placeholder file. This is the
    marker that still recognises an install predating `.runtime-data` and the
    install stamp — the case the legacy shared OOB route exists for.
    """
    engagements = install_root / "agent" / "engagements"
    try:
        return any(
            child.is_dir() and not child.name.startswith(".")
            for child in engagements.iterdir()
        )
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return False


def has_prior_install_state(install_root: Path) -> bool:
    """True when a previous Vigil install/run left its own state in this root.

    This is the honest upgrade signal: every marker is Vigil-created, so all are
    absent in a pristine source checkout and at least one is present in any root
    Vigil has installed into or run an engagement from.
    """
    if any((install_root / name).exists() for name in PRIOR_INSTALL_MARKERS):
        return True
    return _has_engagement_directories(install_root)


def _has_preserved_descendant(child_name: str, preserve_rel_paths: set[Path]) -> bool:
    child = Path(child_name)
    return any(path == child or (path.parts and path.parts[0] == child_name) for path in preserve_rel_paths)


def _sync_dir(src: Path, dest: Path, *, preserve_rel_paths: set[Path]) -> None:
    dest.mkdir(parents=True, exist_ok=True)

    src_names = {item.name for item in src.iterdir()}
    for child in list(dest.iterdir()):
        if _has_preserved_descendant(child.name, preserve_rel_paths):
            remaining = {
                Path(*path.parts[1:])
                for path in preserve_rel_paths
                if path.parts and path.parts[0] == child.name and len(path.parts) > 1
            }
            if remaining and child.is_dir() and (src / child.name).is_dir():
                _sync_dir(src / child.name, child, preserve_rel_paths=remaining)
            continue
        if child.name not in src_names and not _is_excluded(child):
            if child.is_dir():
                _rmtree(child)
            else:
                child.unlink(missing_ok=True)

    for child in src.iterdir():
        if _is_excluded(child):
            continue
        rel = Path(child.name)
        if rel in preserve_rel_paths:
            continue
        target = dest / child.name
        child_preserve = {
            Path(*path.parts[1:])
            for path in preserve_rel_paths
            if path.parts and path.parts[0] == child.name and len(path.parts) > 1
        }
        if child.is_dir():
            _sync_dir(child, target, preserve_rel_paths=child_preserve)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(child, target)


def install_from_source(options: InstallOptions, *, runner: docker.Runner = docker.run_command) -> InstallResult:
    source_root = options.source_root.resolve()
    install_root = options.install_root.expanduser().resolve()
    if options.dry_run:
        return InstallResult(install_root=install_root, is_upgrade=False, image_built=False)

    # Computed BEFORE any directory is created below — `_ensure_install_dirs`
    # creates `.runtime-data`, which would otherwise make every install look
    # like an upgrade to itself.
    is_upgrade = has_prior_install_state(install_root)

    install_root.mkdir(parents=True, exist_ok=True)
    if source_root == install_root:
        _ensure_install_dirs(install_root)
    else:
        for stale_root_file in (LEGACY_INSTALLER_NAME,):
            (install_root / stale_root_file).unlink(missing_ok=True)

        for child in list(install_root.iterdir()):
            if child.name in ROOT_PRESERVE_NAMES:
                continue
            if child.name in ROOT_MANAGED_NAMES and not (source_root / child.name).exists():
                if child.is_dir():
                    _rmtree(child)
                else:
                    child.unlink(missing_ok=True)

        for name in ROOT_MANAGED_NAMES:
            src = source_root / name
            if not src.exists() or _is_excluded(src):
                continue
            dest = install_root / name
            if src.is_dir():
                preserve: set[Path] = set()
                if name == "agent":
                    preserve.add(Path("engagements"))
                elif name == "orchestrator":
                    preserve.add(Path("backend") / "data")
                _sync_dir(src, dest, preserve_rel_paths=preserve)
            else:
                shutil.copy2(src, dest)
        _copy_client_entrypoints(source_root, install_root)
        _ensure_install_dirs(install_root)

    repair_engagement_client_rosters(install_root)
    initialize_tenant_route(
        install_root,
        is_upgrade=is_upgrade,
        tenant_name=config_module.get_config_value("oob.tenant") or install_root.name,
        base_domain=(
            os.environ.get("VIGIL_OOB_DOMAIN")
            or config_module.get_config_value("oob.domain", DEFAULT_OOB_DOMAIN)
            or DEFAULT_OOB_DOMAIN
        ),
    )

    # Stamp the synced source commit HERE, in the function that performs the
    # sync, so every caller leaves the same record. Stamping from the CLI
    # dispatch table instead is what let `vigil up` sync the working root without
    # re-stamping it: the recorded sha stayed pinned at the last explicit
    # `vigil install`, so `vigil status` reported a permanent false "stale" and
    # real install drift became invisible.
    write_install_meta(install_root, source_root)

    image_built = False
    if options.verify_docker_image:
        image = "vigil:latest"
        if options.force_image or not docker.image_exists(image, runner=runner):
            # Build via build_runtime so the install-built image carries the
            # com.vigil.runtime-inputs-sha256 label. A bare `docker build` here
            # leaves the image unstamped, and the next upgrade's build-state
            # check then reports `unknown` for an image Vigil itself built —
            # unable to give the stale/current verdict until a manual rebuild.
            build_runtime(install_root, runner=runner)
            image_built = True
    return InstallResult(install_root=install_root, is_upgrade=is_upgrade, image_built=image_built)


def _ensure_install_dirs(install_root: Path) -> None:
    (install_root / ".runtime-data" / "logs").mkdir(parents=True, exist_ok=True)
    (install_root / ".runtime-data" / "pids").mkdir(parents=True, exist_ok=True)
    (install_root / "agent" / "engagements").mkdir(parents=True, exist_ok=True)
    (install_root / "orchestrator" / "backend" / "data").mkdir(parents=True, exist_ok=True)


def _copy_client_entrypoints(source_root: Path, install_root: Path) -> None:
    for filename in ("AGENTS.md", "CLAUDE.md"):
        src = source_root / "agent" / filename
        if src.exists():
            shutil.copy2(src, install_root / filename)
    for dirname in (".codex", ".claude"):
        src = source_root / "agent" / dirname
        dest = install_root / dirname
        if src.exists():
            if dest.exists():
                _rmtree(dest)
            shutil.copytree(src, dest)
