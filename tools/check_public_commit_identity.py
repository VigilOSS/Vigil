#!/usr/bin/env python3
"""Configure and enforce Vigil's public maintainer commit identity."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable, Sequence


APPROVED_NAME = "Vigil OSS Maintainers"
APPROVED_EMAIL = "vigil.oss@proton.me"
_ZERO_OID = "0" * 40
_OID = re.compile(r"^[0-9a-f]{40}$")
_BANNED_NAME_DIGESTS = {
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
}
_BANNED_EMAIL_DIGESTS = {
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
}


@dataclass(frozen=True)
class CommitIdentity:
    oid: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str


def identity_errors(records: Iterable[CommitIdentity]) -> list[str]:
    errors: list[str] = []
    for record in records:
        identities = (
            ("author", record.author_name, record.author_email),
            ("committer", record.committer_name, record.committer_email),
        )
        for role, name, email in identities:
            name_digest = hashlib.sha256(name.lower().encode()).hexdigest()
            email_digest = hashlib.sha256(email.lower().encode()).hexdigest()
            if name_digest in _BANNED_NAME_DIGESTS:
                errors.append(f"{record.oid}: private {role} name")
            if email_digest in _BANNED_EMAIL_DIGESTS:
                errors.append(f"{record.oid}: private {role} email")
            if name == APPROVED_NAME and email != APPROVED_EMAIL:
                errors.append(
                    f"{record.oid}: {role} {APPROVED_NAME!r} must use {APPROVED_EMAIL!r}"
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
    args = parser.parse_args(argv)

    if args.install:
        _install(Path.cwd())
        return _print_errors(_check_local_config())
    if args.config:
        return _print_errors(_check_local_config())
    if args.pre_push:
        revisions = pre_push_revisions(sys.stdin)
        return _print_errors(_check_local_config() + identity_errors(_commit_records(revisions)))
    return _print_errors(identity_errors(_commit_records(args.revision)))


if __name__ == "__main__":
    raise SystemExit(main())
