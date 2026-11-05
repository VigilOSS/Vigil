"""Resolve and execute host tools without trusting repository-controlled state."""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


# Kept on every invocation as a second line behind TargetGit's private
# metadata directory, which carries none of these settings to begin with.
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


# --------------------------------------------------------------------------- #
# Git over a target repository
# --------------------------------------------------------------------------- #
#
# A repository delivered with its `.git` controls that directory, and several of
# its settings name programs Git runs: filter and diff drivers (selected by
# attribute names only the repository knows, so `-c` cannot disable them),
# core.fsmonitor, gpg.program under log.showSignature, core.sshCommand and
# remote helpers for a partial clone's lazy fetch, hooks, pagers, credential and
# askpass helpers, and include.path files that add any of these. A submodule's
# metadata directory carries the same settings, and `git status` runs a child
# Git under them.
#
# TargetGit therefore never lets Git open a target metadata directory as its
# GIT_DIR. It points GIT_DIR at a private directory whose config Vigil writes,
# reads objects and the index in place, and links the refs, worktree list,
# shallow boundary and info/ files Git reads as data. Every ref, HEAD, worktree
# HEAD, grafts file and exclude rule therefore means what it means to the
# repository's own Git; only the settings in _CARRIED_CONFIG and _FORMAT_CONFIG
# cross over, each validated as a value no program can hide in.
#
# Every Git call over source Vigil ingests goes through TargetGit. Git calls on
# the operator's own checkout (remediation_vcs.py and remediation_regression.py,
# which run that checkout's own test suite by design) are the operator's
# repository and stay plain invocations. See ADR 0039.

_GIT_METADATA_MAX_BYTES = 64 * 1024
_GIT_CONFIG_MAX_BYTES = 1024 * 1024
_GIT_CONFIG_TIMEOUT_SECONDS = 30

_COMMON_METADATA = ("refs", "packed-refs", "reftable", "worktrees", "info", "shallow")
# A linked worktree keeps its own HEAD, index, per-worktree refs (bisect,
# worktree, rewritten) and info/sparse-checkout beside a `commondir` pointer.
_WORKTREE_METADATA = ("refs", "info")

_BOOLEAN_SPELLINGS = {
    "true": "true", "yes": "true", "on": "true", "1": "true",
    "false": "false", "no": "false", "off": "false", "0": "false",
}

# Settings that shape what status, rev-list and log report without naming a
# program: filesystem probes `git init` records, line-ending and stat policy
# that decide whether a racily clean file re-hashes equal, sparse checkout, and
# extra ignore/attribute files (read as patterns, never executed). A value is a
# boolean, one of a closed set, or a path.
_CARRIED_CONFIG: dict[str, str | frozenset[str]] = {
    "core.filemode": "bool",
    "core.symlinks": "bool",
    "core.ignorecase": "bool",
    "core.precomposeunicode": "bool",
    "core.trustctime": "bool",
    "core.sparsecheckout": "bool",
    "core.sparsecheckoutcone": "bool",
    "index.sparse": "bool",
    "core.autocrlf": frozenset({"true", "false", "input"}),
    "core.eol": frozenset({"lf", "crlf", "native"}),
    "core.checkstat": frozenset({"default", "minimal"}),
    "core.excludesfile": "path",
    "core.attributesfile": "path",
}
# Repository format, honored only under repositoryformatversion 1. Other
# extensions are not carried: partialClone in particular is what arms a lazy
# fetch, so a missing object fails the read instead of reaching the network.
_FORMAT_CONFIG: dict[str, frozenset[str]] = {
    "extensions.objectformat": frozenset({"sha1", "sha256"}),
    "extensions.refstorage": frozenset({"files", "reftable"}),
}


@dataclass(frozen=True)
class GitLayout:
    """Where a worktree's Git metadata lives."""

    worktree: Path
    git_dir: Path
    common_dir: Path


def _read_git_metadata(path: Path) -> bytes:
    """Read one small regular metadata file without following a symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise ValueError(f"cannot read Git metadata {path}: {exc}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _GIT_METADATA_MAX_BYTES:
            raise ValueError(f"Git metadata is not a small regular file: {path}")
        data = os.read(fd, _GIT_METADATA_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > _GIT_METADATA_MAX_BYTES:
        raise ValueError(f"Git metadata is not a small regular file: {path}")
    return data


def git_layout(worktree: str | os.PathLike[str]) -> GitLayout | None:
    """Resolve *worktree*'s metadata directories, or None when it has none.

    A `.git` directory or a `gitdir:` file is a worktree marker; a gitfile whose
    directory does not exist is an unpopulated submodule, as Git treats it. A
    symlinked or malformed marker is refused.
    """
    root = Path(worktree).resolve()
    marker = root / ".git"
    try:
        marker_stat = marker.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"cannot inspect Git marker {marker}: {exc}") from exc
    if stat.S_ISDIR(marker_stat.st_mode):
        git_dir = marker
    elif stat.S_ISREG(marker_stat.st_mode):
        content = os.fsdecode(_read_git_metadata(marker).strip())
        if not content.startswith("gitdir:"):
            raise ValueError(f"Git marker file has no gitdir: line: {marker}")
        git_dir = root / content[len("gitdir:"):].strip()
    else:
        raise ValueError(f"Git marker is not a directory or gitfile: {marker}")
    if not git_dir.is_dir():
        return None
    git_dir = git_dir.resolve()
    common_dir = git_dir
    if (git_dir / "commondir").exists():
        common_dir = (git_dir / os.fsdecode(_read_git_metadata(git_dir / "commondir").strip())).resolve()
    if not (common_dir / "objects").is_dir():
        raise ValueError(f"Git metadata directory has no object store: {common_dir}")
    return GitLayout(worktree=root, git_dir=git_dir, common_dir=common_dir)


def _carried_value(kind: str | frozenset[str], raw: str | None) -> str | None:
    if kind == "path":
        if raw is None or not raw or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
            return None
        return '"' + raw.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if raw is None:
        return "true" if kind == "bool" else None
    value = raw.strip().lower()
    if kind == "bool":
        return _BOOLEAN_SPELLINGS.get(value)
    value = _BOOLEAN_SPELLINGS.get(value, value)
    return value if value in kind else None


class TargetGit:
    """Git over one target worktree, under configuration only Vigil writes.

    Use as a context manager: entering builds the private metadata directory,
    leaving removes it. `run` executes Git with the hardened argv and the
    isolated environment; nothing the caller passes can replace that
    environment.
    """

    def __init__(
        self,
        git_path: str,
        worktree: str | os.PathLike[str],
        *,
        source_root: str | os.PathLike[str] | None = None,
    ) -> None:
        if not Path(git_path).is_absolute():
            raise ValueError("trusted Git path must be absolute")
        self.git_path = str(git_path)
        self.worktree = Path(worktree).resolve()
        self.source_root = Path(source_root).resolve() if source_root else self.worktree
        self.environment: dict[str, str] = {}
        self._private: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> TargetGit:
        layout = git_layout(self.worktree)
        if layout is None:
            raise ValueError(f"no usable Git metadata directory for {self.worktree}")
        self._private = tempfile.TemporaryDirectory(prefix="vigil-git-")
        try:
            self.environment = self._isolate(layout, Path(self._private.name))
        except BaseException:
            self._private.cleanup()
            self._private = None
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._private is not None:
            self._private.cleanup()
            self._private = None

    def run(self, arguments: list[str], **options: Any) -> subprocess.CompletedProcess:
        if self._private is None:
            raise RuntimeError("TargetGit.run outside its context")
        if "env" in options:
            raise ValueError("TargetGit owns the Git environment")
        return subprocess.run(
            git_command(self.git_path, self.worktree, *arguments),
            check=False,
            env=self.environment,
            **options,
        )

    def _isolate(self, layout: GitLayout, root: Path) -> dict[str, str]:
        common = root / "common"
        common.mkdir()
        for name in _COMMON_METADATA:
            if (layout.common_dir / name).exists():
                (common / name).symlink_to(layout.common_dir / name)
        if not (common / "refs").exists():
            (common / "refs").mkdir()
        (common / "HEAD").write_bytes(_read_git_metadata(layout.common_dir / "HEAD"))
        private = common
        if layout.git_dir != layout.common_dir:
            private = root / "worktree"
            private.mkdir()
            (private / "commondir").write_bytes(os.fsencode(common) + b"\n")
            (private / "HEAD").write_bytes(_read_git_metadata(layout.git_dir / "HEAD"))
            for name in _WORKTREE_METADATA:
                if (layout.git_dir / name).exists():
                    (private / name).symlink_to(layout.git_dir / name)
        (common / "config").write_bytes(os.fsencode(self._config(layout, root)))
        environment = trusted_environment(source_root=self.source_root)
        environment.update(
            {
                "GIT_DIR": str(private),
                "GIT_WORK_TREE": str(layout.worktree),
                "GIT_INDEX_FILE": str(layout.git_dir / "index"),
                "GIT_OBJECT_DIRECTORY": str(layout.common_dir / "objects"),
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_ATTR_NOSYSTEM": "1",
            }
        )
        return environment

    def _read_config(self, path: Path, cwd: Path) -> list[tuple[str, str | None]]:
        """The entries of one target config file, its include directives unread."""
        if not path.exists():
            return []
        try:
            metadata = path.stat()
        except OSError as exc:
            raise ValueError(f"cannot read Git config {path}: {exc}") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _GIT_CONFIG_MAX_BYTES:
            raise ValueError(f"Git config is not a regular file within size bounds: {path}")
        environment = trusted_environment(source_root=self.source_root)
        # `git config --file` needs no repository; the ceiling stops discovery
        # at the empty private directory it runs in.
        environment["GIT_CEILING_DIRECTORIES"] = str(cwd.parent)
        result = subprocess.run(
            [self.git_path, "config", "--file", str(path), "--no-includes", "--null", "--list"],
            cwd=cwd,
            env=environment,
            capture_output=True,
            check=False,
            timeout=_GIT_CONFIG_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"cannot read Git config {path}: {detail}")
        entries: list[tuple[str, str | None]] = []
        for raw in result.stdout.split(b"\0"):
            if not raw:
                continue
            key, newline, value = raw.decode("utf-8", errors="surrogateescape").partition("\n")
            entries.append((key, value if newline else None))
        return entries

    def _config(self, layout: GitLayout, root: Path) -> str:
        entries = self._read_config(layout.common_dir / "config", root)
        settings = dict(entries)
        worktree_config = settings.get("extensions.worktreeconfig", "false")
        if _carried_value("bool", worktree_config) == "true":
            entries += self._read_config(layout.git_dir / "config.worktree", root)
            settings = dict(entries)
        version = settings.get("core.repositoryformatversion") or "0"
        sections: dict[str, list[str]] = {
            "core": [
                f"repositoryformatversion = {version if version in ('0', '1') else '0'}",
                "bare = false",
                "hooksPath = /dev/null",
                "fsmonitor = false",
            ]
        }
        carried: dict[str, str | frozenset[str]] = dict(_CARRIED_CONFIG)
        if version == "1":
            carried.update(_FORMAT_CONFIG)
        for key, kind in carried.items():
            if key not in settings:
                continue
            value = _carried_value(kind, settings[key])
            if value is None:
                continue
            section, name = key.split(".", 1)
            sections.setdefault(section, []).append(f"{name} = {value}")
        return "".join(
            f"[{section}]\n" + "".join(f"\t{line}\n" for line in lines)
            for section, lines in sections.items()
        )


def run_target_git(
    git_path: str,
    worktree: str | os.PathLike[str],
    arguments: list[str],
    *,
    source_root: str | os.PathLike[str] | None = None,
    **options: Any,
) -> subprocess.CompletedProcess:
    """Run one Git command over a target worktree through TargetGit."""
    with TargetGit(git_path, worktree, source_root=source_root) as git:
        return git.run(arguments, **options)
