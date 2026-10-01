"""Git/Jujutsu repository mechanics for defensive remediation evidence.

Jujutsu snapshots filesystem edits into commits. Evidence therefore identifies
immutable Git commit IDs, never mutable change IDs; empty single-parent working
copy children retain the identity of the content they test.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from urllib.parse import urlsplit


def _jj_root(path: Path) -> Path | None:
    resolved = path.resolve()
    return next(
        (
            parent
            for parent in (resolved, *resolved.parents)
            if (parent / ".jj").exists()
        ),
        None,
    )


def is_jj(path: Path) -> bool:
    return _jj_root(path) is not None


def command(path: Path, *args: str) -> list[str]:
    return [
        "jj",
        "--no-pager",
        "--color=never",
        "-R",
        str(_jj_root(path) or path),
        *args,
    ]


def _run(args: list[str]) -> str:
    result = subprocess.run(
        args, check=True, capture_output=True, text=True, timeout=30
    )
    if args[0] == "jj" and "Refused to snapshot some files:" in result.stderr:
        raise ValueError(result.stderr.strip())
    return result.stdout.strip()


def root(path: Path) -> Path:
    args = (
        command(path, "workspace", "root")
        if is_jj(path)
        else ["git", "-C", str(path), "rev-parse", "--show-toplevel"]
    )
    return Path(_run(args)).resolve()


def _log(path: Path, expression: str, template: str = "commit_id") -> str:
    value = _run(
        command(
            path, "log", "-r", expression, "--no-graph", "-T", template + ' ++ "\\n"'
        )
    )
    if not value or "\n" in value:
        raise ValueError("Revision must resolve to exactly one commit")
    return value


def resolve_revision(path: Path, ref: str) -> str:
    if 7 <= len(ref) <= 64 and all(char in "0123456789abcdefABCDEF" for char in ref):
        ref = ref.lower()
    if is_jj(path):
        return _log(path, ref)
    return _run(
        [
            "git",
            "-C",
            str(path),
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{ref}^{{commit}}",
        ]
    )


def revision(path: Path) -> str:
    if not is_jj(path):
        return resolve_revision(path, "HEAD")
    current = _log(path, "@")
    while _log(path, current, "empty") == "true":
        parents = _run(
            command(
                path,
                "log",
                "-r",
                f"parents({current})",
                "--no-graph",
                "-T",
                'commit_id ++ "\\n"',
            )
        ).splitlines()
        if len(parents) != 1:
            break
        current = parents[0]
    return current


def status(path: Path) -> str:
    if is_jj(path):
        return _run(
            command(
                path,
                "log",
                "-r",
                "@ & conflicts()",
                "--no-graph",
                "-T",
                'commit_id ++ "\\n"',
            )
        )
    return _run(
        ["git", "-C", str(path), "status", "--porcelain", "--untracked-files=all"]
    )


def _jj_store(path: Path) -> Path:
    marker = root(path) / ".jj" / "repo"
    return (
        marker.resolve()
        if marker.is_dir()
        else (marker.parent / marker.read_text().strip()).resolve()
    )


def registered(repo: Path, path: Path) -> bool:
    if path.is_symlink():
        return False
    try:
        if root(path) != path.resolve() or is_jj(repo) != is_jj(path):
            return False
        if is_jj(repo):
            if _jj_store(repo) != _jj_store(path):
                return False
            names = _run(
                command(repo, "workspace", "list", "-T", 'name ++ "\\n"')
            ).splitlines()
            return any(
                Path(_run(command(repo, "workspace", "root", "--name", name))).resolve()
                == path.resolve()
                for name in names
            )

        def common(directory: Path) -> str:
            return _run(
                [
                    "git",
                    "-C",
                    str(directory),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                ]
            )

        if common(repo) != common(path):
            return False
        listed = _run(["git", "-C", str(repo), "worktree", "list", "--porcelain", "-z"])
        return any(
            Path(entry.removeprefix("worktree ")).resolve() == path.resolve()
            for entry in listed.split("\0")
            if entry.startswith("worktree ")
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def branch_matches(path: Path, name: str) -> bool:
    try:
        if is_jj(path):
            target = _log(path, f"bookmarks(exact:{json.dumps(name)})")
            return bool(
                _run(
                    command(
                        path,
                        "log",
                        "-r",
                        f"{target} & ancestors(@)",
                        "--no-graph",
                        "-T",
                        "commit_id",
                    )
                )
            )
        return (
            _run(["git", "-C", str(path), "symbolic-ref", "--quiet", "--short", "HEAD"])
            == name
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def create_workspace(repo: Path, path: Path, name: str, base: str) -> None:
    if is_jj(repo):
        existing = _run(
            command(repo, "bookmark", "list", f"exact:{name}", "-T", 'name ++ "\\n"')
        )
        if existing:
            raise ValueError("Case bookmark already exists")
        resolved = resolve_revision(repo, base)
        # The workspace identifier is independent of the slash-containing bookmark.
        workspace_name = (
            "remediation-"
            + hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:16]
        )
        _run(
            command(
                repo,
                "workspace",
                "add",
                "--name",
                workspace_name,
                "-r",
                resolved,
                str(path),
            )
        )
        _run(command(path, "bookmark", "create", name, "-r", "@"))
    else:
        _run(["git", "-C", str(repo), "worktree", "add", "-b", name, str(path), base])


def push(path: Path, name: str, approved: str) -> None:
    if is_jj(path):
        if revision(path) != approved or status(path) or not branch_matches(path, name):
            raise ValueError("Worktree changed after approval")
        _run(command(path, "bookmark", "move", name, "--to", approved))
        _run(
            command(
                path, "git", "push", "--remote", "origin", "--bookmark", f"exact:{name}"
            )
        )
    else:
        _run(["git", "-C", str(path), "push", "-u", "origin", name])


def ancestor(path: Path, older: str, newer: str) -> bool:
    a, b = resolve_revision(path, older), resolve_revision(path, newer)
    if a == b:
        return False
    if is_jj(path):
        return bool(
            _run(
                command(
                    path,
                    "log",
                    "-r",
                    f"{a} & ancestors({b})",
                    "--no-graph",
                    "-T",
                    "commit_id",
                )
            )
        )
    return (
        subprocess.run(
            ["git", "-C", str(path), "merge-base", "--is-ancestor", a, b],
            capture_output=True,
            timeout=10,
        ).returncode
        == 0
    )


def diff_command(path: Path, *revisions: str) -> list[str]:
    if not is_jj(path):
        return ["git", "-C", str(path), "diff", "--binary", "--no-ext-diff", *revisions]
    refs = [
        revision(path) if ref == "HEAD" else resolve_revision(path, ref)
        for ref in revisions
    ]
    return command(
        path,
        "diff",
        "--git",
        "--from",
        refs[0],
        "--to",
        refs[1] if len(refs) > 1 else "@",
    )


def untracked(path: Path) -> list[bytes]:
    if is_jj(path):
        # jj snapshots new files into @ before revision/diff is read.
        return []
    return subprocess.run(
        ["git", "-C", str(path), "ls-files", "--others", "--exclude-standard", "-z"],
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout.split(b"\0")


def review_base(path: Path) -> str:
    if is_jj(path):
        for candidate in ("main@origin", "main"):
            try:
                main = resolve_revision(path, candidate)
                return _log(path, f"heads(ancestors(@) & ancestors({main}))")
            except (ValueError, subprocess.CalledProcessError):
                continue
        raise ValueError("Main bookmark is unavailable for review")
    for candidate in ("refs/remotes/origin/main", "refs/heads/main"):
        try:
            resolve_revision(path, candidate)
            return _run(["git", "-C", str(path), "merge-base", "HEAD", candidate])
        except subprocess.CalledProcessError:
            continue
    raise ValueError("Main branch is unavailable for review")


def github_repository(path: Path) -> str:
    """Resolve the exact GitHub host/owner/repository from a JJ origin."""
    remotes = _run(command(path, "git", "remote", "list"))
    origins = [
        line.split(maxsplit=1)[1]
        for line in remotes.splitlines()
        if line.split(maxsplit=1)[0] == "origin" and len(line.split(maxsplit=1)) == 2
    ]
    if len(origins) != 1:
        raise ValueError(
            "JJ repository requires one origin remote for GitHub pull requests"
        )
    remote = origins[0]
    if "://" in remote:
        parsed = urlsplit(remote)
        if (
            parsed.scheme not in {"https", "http", "ssh", "git"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Origin must identify a GitHub repository URL")
        host, location = parsed.hostname, parsed.path
    else:
        authority, separator, location = remote.partition(":")
        host = authority.rsplit("@", 1)[-1] if separator else None
    parts = location.strip("/").removesuffix(".git").split("/")
    if (
        not host
        or len(parts) != 2
        or any(not part or part in {".", ".."} for part in parts)
    ):
        raise ValueError("Origin must identify a GitHub host/owner/repository")
    return "/".join([host, *parts])
