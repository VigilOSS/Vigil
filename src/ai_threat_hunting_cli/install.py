from __future__ import annotations

import platform
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from . import docker


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
    "ISSUES.md",
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

EXCLUDED_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    ".venv",
    "*.egg-info",
}

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
    name = path.name
    if name in EXCLUDED_NAMES:
        return True
    return name.endswith(".egg-info") or name.endswith(".pyc")


def _has_preserved_descendant(child_name: str, preserve_rel_paths: set[Path]) -> bool:
    child = Path(child_name)
    return any(path == child or (path.parts and path.parts[0] == child_name) for path in preserve_rel_paths)


def _sync_dir(src: Path, dest: Path, *, preserve_rel_paths: set[Path]) -> None:
    dest.mkdir(parents=True, exist_ok=True)

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
        if child.name not in {item.name for item in src.iterdir()} or not _is_excluded(child):
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

    is_upgrade = any(
        (install_root / name).exists()
        for name in ("agent", "orchestrator", ".claude", ".codex")
    )

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

    image_built = False
    if options.verify_docker_image:
        image = "security-research:latest"
        if options.force_image or not docker.image_exists(image, runner=runner):
            argv = ["docker", "build", "-t", image, "-f", str(install_root / "agent" / "docker" / "runtime-full" / "Dockerfile"), str(install_root)]
            docker.require_success(runner(argv), argv)
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
