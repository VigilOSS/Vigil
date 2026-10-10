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


def _base_candidates(path: Path, branch: str) -> tuple[str, str]:
    if is_jj(path):
        return f'{json.dumps(branch)}@origin', f'bookmarks(exact:{json.dumps(branch)})'
    return f'refs/remotes/origin/{branch}', f'refs/heads/{branch}'


def create_workspace(repo: Path, path: Path, name: str, base: str) -> None:
    for candidate in _base_candidates(repo, base):
        try:
            resolved = resolve_revision(repo, candidate)
            break
        except (ValueError, subprocess.CalledProcessError):
            continue
    else:
        raise ValueError(f'Base branch {base!r} is unavailable for workspace creation')
    if is_jj(repo):
        existing = _run(
            command(repo, "bookmark", "list", f"exact:{name}", "-T", 'name ++ "\\n"')
        )
        if existing:
            raise ValueError("Case bookmark already exists")
        path.parent.mkdir(parents=True, exist_ok=True)
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
        _run(["git", "-C", str(repo), "worktree", "add", "-b", name, str(path), resolved])


def push(path: Path, name: str, approved: str, *, expected_remote_revision: str | None = None) -> None:
    if revision(path) != approved or status(path) or not branch_matches(path, name):
        raise ValueError("Worktree changed after approval")
    if expected_remote_revision is not None:
        if origin_revision(path, name) != expected_remote_revision:
            raise ValueError("The remote branch changed since the recorded pull request revision")
        if is_jj(path):
            tracked = resolve_revision(path, f'{json.dumps(name)}@origin')
            if tracked != expected_remote_revision:
                raise ValueError("The remote bookmark tracking revision is stale; fetch it before retrying")
    if is_jj(path):
        _run(command(path, "bookmark", "move", f"exact:{name}", "--to", approved, "--allow-backwards"))
        operation = _run(command(path, "op", "log", "--limit", "1", "--no-graph", "-T", "id"))
        target = _run(command(path, "--at-operation", operation, "log", "-r",
                              f"bookmarks(exact:{json.dumps(name)})", "--no-graph", "-T", "commit_id"))
        if target != approved:
            raise ValueError("Case bookmark changed after approval")
        # Pin the operation as well as the commit: a concurrently moved local
        # bookmark must never change the revision published under this name.
        _run(
            command(
                path, "--at-operation", operation, "git", "push", "--remote", "origin", "--bookmark", f"exact:{name}"
            )
        )
    else:
        lease = [f"--force-with-lease=refs/heads/{name}:{expected_remote_revision}"] if expected_remote_revision is not None else []
        _run(["git", "-C", str(path), "push", *lease, "origin", f"{approved}:refs/heads/{name}"])


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


def review_base(path: Path, base_branch: str = "main", base_revision: str | None = None) -> str:
    if base_revision:
        base = resolve_revision(path, base_revision)
        head = revision(path)
        if base != head and not ancestor(path, base, head):
            raise ValueError("Stored review base is not an ancestor of the case revision")
        return base
    if is_jj(path):
        for candidate in _base_candidates(path, base_branch):
            try:
                base = resolve_revision(path, candidate)
                return _log(path, f"heads(ancestors(@) & ancestors({base}))")
            except (ValueError, subprocess.CalledProcessError):
                continue
        raise ValueError(f"Base bookmark {base_branch!r} is unavailable for review")
    for candidate in _base_candidates(path, base_branch):
        try:
            base = resolve_revision(path, candidate)
            return _run(["git", "-C", str(path), "merge-base", "HEAD", base])
        except subprocess.CalledProcessError:
            continue
    raise ValueError(f"Base branch {base_branch!r} is unavailable for review")


def _origin_url(path: Path) -> str:
    if not is_jj(path):
        urls = _run(["git", "-C", str(path), "remote", "get-url", "--push", "--all", "origin"]).splitlines()
        if len(urls) != 1:
            raise ValueError("Repository requires one origin push URL")
        return urls[0]
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
    return origins[0]


def origin_revision(path: Path, name: str) -> str:
    """Read exactly the branch on the origin used for publishing."""
    ref = f"refs/heads/{name}"
    try:
        observed = _run(["git", "ls-remote", "--exit-code", "--", _origin_url(path), ref])
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 2:
            raise ValueError(f"The origin branch {name!r} does not exist") from exc
        raise
    lines = [line.split() for line in observed.splitlines()]
    if len(lines) != 1 or len(lines[0]) != 2 or lines[0][1] != ref:
        raise ValueError(f"The origin branch {name!r} is ambiguous")
    return lines[0][0]


def github_repository(path: Path) -> str:
    """Resolve the exact GitHub host/owner/repository from the publishing origin."""
    remote = _origin_url(path)
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
