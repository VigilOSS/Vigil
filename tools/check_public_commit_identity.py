#!/usr/bin/env python3
"""Configure and enforce Vigil's public maintainer commit identity."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable, Sequence


APPROVED_NAME = "Vigil OSS Maintainers"
APPROVED_EMAIL = "vigil.oss@proton.me"
_JJ_PRIVATE_COMMITS = "~(" + " & ".join(
    f'{role}_{field}(exact:"{value}")'
    for role in ("author", "committer")
    for field, value in (("name", APPROVED_NAME), ("email", APPROVED_EMAIL))
) + ")"
# Local tags must not exempt unpublished commits from identity checks.
_JJ_IMMUTABLE_HEADS = "remote_bookmarks(remote=origin)"
_ZERO_OID = "0" * 40
_OID = re.compile(r"^[0-9a-f]{40}$")
@dataclass(frozen=True)
class CommitIdentity:
    oid: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str


def identity_errors(
    records: Iterable[CommitIdentity], *, allow_contributors: bool = False
) -> list[str]:
    errors: list[str] = []
    for record in records:
        identities = (
            ("author", record.author_name, record.author_email),
            ("committer", record.committer_name, record.committer_email),
        )
        for role, name, email in identities:
            if allow_contributors and name != APPROVED_NAME:
                continue
            if (name, email) != (APPROVED_NAME, APPROVED_EMAIL):
                errors.append(
                    f"{record.oid}: {role} must use {APPROVED_NAME} <{APPROVED_EMAIL}>"
                )
    return errors


def pre_push_revisions(lines: Iterable[str]) -> list[str]:
    revisions: list[str] = []
    for raw_line in lines:
        fields = raw_line.split()
        if len(fields) != 4:
            raise ValueError(f"invalid pre-push input: {raw_line.rstrip()!r}")
        _local_ref, local_oid, _remote_ref, remote_oid = fields
        if not _OID.fullmatch(local_oid) or not _OID.fullmatch(remote_oid):
            raise ValueError(f"invalid pre-push object id: {raw_line.rstrip()!r}")
        if local_oid == _ZERO_OID:
            continue
        revisions.append(local_oid if remote_oid == _ZERO_OID else f"{remote_oid}..{local_oid}")
    return revisions


def _run(command: Sequence[str]) -> str:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return completed.stdout.rstrip("\n")


def _check_local_config() -> list[str]:
    errors: list[str] = []
    configured_name = _local_config("user.name")
    configured_email = _local_config("user.email")
    if configured_name != APPROVED_NAME:
        errors.append(f"local user.name must be {APPROVED_NAME!r}, got {configured_name!r}")
    if configured_email != APPROVED_EMAIL:
        errors.append(f"local user.email must be {APPROVED_EMAIL!r}, got {configured_email!r}")
    expected = f"{APPROVED_NAME} <{APPROVED_EMAIL}>"
    for role, variable in (("author", "GIT_AUTHOR_IDENT"), ("committer", "GIT_COMMITTER_IDENT")):
        identity = _run(("git", "var", variable))
        if identity.rsplit(" ", 2)[0] != expected:
            errors.append(f"effective Git {role} must be {expected!r}")
    if (Path.cwd() / ".jj").is_dir():
        for key, value in (("user.name", APPROVED_NAME), ("user.email", APPROVED_EMAIL)):
            if _run(("jj", "config", "get", key)) != value:
                errors.append(f"effective jj {key} must be {value!r}")
        if _run(("jj", "config", "get", "git.private-commits")) != _JJ_PRIVATE_COMMITS:
            errors.append("effective jj push policy must reject non-maintainer identities")
        if _run(("jj", "config", "get", 'revset-aliases."immutable_heads()"')) != _JJ_IMMUTABLE_HEADS:
            errors.append("effective jj immutability must follow the canonical remote")
    return errors


def _local_config(key: str) -> str:
    completed = subprocess.run(
        ("git", "config", "--local", "--get", key),
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.rstrip("\n") if completed.returncode == 0 else ""


def _commit_records(revisions: Sequence[str]) -> list[CommitIdentity]:
    if not revisions:
        return []
    output = _run(
        (
            "git",
            "log",
            "--no-show-signature",
            "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce",
            *revisions,
        )
    )
    if not output:
        return []
    records: list[CommitIdentity] = []
    for line in output.splitlines():
        fields = line.split("\x1f")
        if len(fields) != 5:
            raise ValueError(f"unexpected git log identity record: {line!r}")
        records.append(CommitIdentity(*fields))
    return records


def _install(repo_root: Path) -> None:
    commands = (
        ("git", "config", "--local", "user.name", APPROVED_NAME),
        ("git", "config", "--local", "user.email", APPROVED_EMAIL),
        ("git", "config", "--local", "user.useConfigOnly", "true"),
        ("git", "config", "--local", "core.hooksPath", ".githooks"),
    )
    for command in commands:
        subprocess.run(command, cwd=repo_root, check=True)
    if (repo_root / ".jj").is_dir():
        subprocess.run(
            ("jj", "config", "set", "--repo", "user.name", APPROVED_NAME),
            cwd=repo_root,
            check=True,
        )
        subprocess.run(
            ("jj", "config", "set", "--repo", "user.email", APPROVED_EMAIL),
            cwd=repo_root,
            check=True,
        )
        subprocess.run(
            ("jj", "config", "set", "--repo", "git.private-commits", _JJ_PRIVATE_COMMITS),
            cwd=repo_root,
            check=True,
        )
        subprocess.run(
            ("jj", "config", "set", "--repo", 'revset-aliases."immutable_heads()"', _JJ_IMMUTABLE_HEADS),
            cwd=repo_root,
            check=True,
        )


def _print_errors(errors: Sequence[str]) -> int:
    if not errors:
        return 0
    print("Vigil public commit identity check failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    print(
        "Run `python3 tools/check_public_commit_identity.py --install` in this clone.",
        file=sys.stderr,
    )
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--install", action="store_true", help="Configure this clone and its hooks.")
    mode.add_argument("--config", action="store_true", help="Check this clone's local identity.")
    mode.add_argument("--pre-push", action="store_true", help="Check refs received on stdin.")
    mode.add_argument("--revision", action="append", help="Audit a revision or revision range.")
    parser.add_argument("--allow-contributors", action="store_true",
                        help="Allow contributor attribution in fork and PR history.")
    args = parser.parse_args(argv)

    if args.install:
        _install(Path.cwd())
        return _print_errors(_check_local_config())
    if args.config:
        return _print_errors(_check_local_config())
    if args.pre_push:
        revisions = pre_push_revisions(sys.stdin)
        return _print_errors(_check_local_config() + identity_errors(_commit_records(revisions)))
    return _print_errors(identity_errors(_commit_records(args.revision), allow_contributors=args.allow_contributors))


if __name__ == "__main__":
    raise SystemExit(main())
