"""Resolve and execute host tools without trusting repository-controlled state."""
from __future__ import annotations

import os
import stat
from pathlib import Path

_UNSAFE_LOADER_ENV_PREFIXES = ("DYLD_", "LD_")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def resolve_trusted_tool(
    name: str,
    *,
    source_root: str | os.PathLike[str],
    path: str | None = None,
) -> str | None:
    """Return an absolute executable outside *source_root*.

    Empty and relative PATH entries are working-directory lookups. They are
    excluded, as are executables whose resolved target lives in the supplied
    source tree.
    """
    if not name or os.path.basename(name) != name:
        raise ValueError("tool name must be one basename")
    source = Path(source_root).resolve()
    for raw_entry in (os.environ.get("PATH", "") if path is None else path).split(os.pathsep):
        if not raw_entry or not os.path.isabs(raw_entry):
            continue
        entry = Path(os.path.abspath(raw_entry))
        if _is_within(entry, source):
            continue
        candidate = entry / name
        try:
            resolved = candidate.resolve(strict=True)
            resolved_stat = resolved.stat()
        except OSError:
            continue
        if not (stat.S_ISREG(resolved_stat.st_mode) and os.access(resolved, os.X_OK)):
            continue
        if _is_within(resolved, source):
            continue
        return str(resolved)
    return None


def trusted_environment(
    *,
    source_root: str | os.PathLike[str],
    path: str | None = None,
) -> dict[str, str]:
    """Return an execution environment without Git or loader injection knobs."""
    source = Path(source_root).resolve()
    safe_path: list[str] = []
    for raw_entry in (os.environ.get("PATH", "") if path is None else path).split(os.pathsep):
        if not raw_entry or not os.path.isabs(raw_entry):
            continue
        entry = Path(os.path.abspath(raw_entry))
        if _is_within(entry, source):
            continue
        try:
            resolved = entry.resolve(strict=True)
        except OSError:
            continue
        if _is_within(resolved, source):
            continue
        safe_path.append(str(resolved))

    environment: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if (
            upper.startswith(("GIT_", "CTAGS_", *_UNSAFE_LOADER_ENV_PREFIXES))
            or upper in {"CTAGS", "ETAGS"}
        ):
            continue
        environment[key] = value
    environment["PATH"] = os.pathsep.join(dict.fromkeys(safe_path))
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
    return environment


SAFE_GIT_PREFIX = (
    "--no-pager",
    "--no-optional-locks",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.pager=cat",
)


def git_command(
    git_path: str,
    repo_path: str | os.PathLike[str],
    *arguments: str,
) -> list[str]:
    git = Path(git_path)
    if not git.is_absolute():
        raise ValueError("trusted Git path must be absolute")
    repo = Path(repo_path).resolve()
    return [str(git), "-C", str(repo), *SAFE_GIT_PREFIX, *arguments]
