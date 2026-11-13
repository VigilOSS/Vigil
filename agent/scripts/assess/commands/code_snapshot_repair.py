"""vigil assess code-snapshot-repair — rebind sealed manifests to their relative source.

Seals made before the relative ``source`` binding recorded the absolute path of the
engagement they were sealed in. Readers still accept that binding while it names
the same ``<repo_key>/<digest>/source``; this verb rewrites it in place so the seal
no longer depends on where the engagement lived, and records each rewrite.
"""
from __future__ import annotations

import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assess.lib.code_audit import write_json_snapshot
from assess.lib.code_snapshot import (
    SNAPSHOT_SOURCE_BINDING,
    SourceRebind,
    SourceRebindUnverified,
    SourceSnapshotRaceError,
    rebind_snapshot_source,
    validate_repo_key,
)
from assess.lib.config import resolve_engagement_dir

REPAIR_AUDIT_SCHEMA = "code-snapshot-repair/v1"
_SNAPSHOTS = ("tools", "analysis-state", "code-snapshots")


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "code-snapshot-repair",
        help=(
            "Rewrite sealed code-snapshot manifests that bind their source by an absolute "
            "engagement path to the relative binding, in place and audited"
        ),
        epilog=(
            "Each snapshot under tools/analysis-state/code-snapshots/ is validated in full "
            "before its manifest is touched; one that does not validate is refused and left "
            "as it is. The content address is unchanged. Run it while no code-ingest is "
            "running: a refresh attesting a snapshot during its rewrite is refused and can "
            "be retried."
        ),
    )
    parser.add_argument("--repo-key", default=None, help="Repair only this repository's snapshots")
    parser.add_argument("--actor", default="operator", help="Actor recorded in the audit entry")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate and report what would be rewritten without writing anything",
    )
    parser.set_defaults(func=run)


def _snapshot_roots(snapshots: Path, repo_key: str | None) -> tuple[list[Path], int]:
    """Every published snapshot root, and how many in-progress staging dirs were skipped."""
    try:
        snapshots_stat = snapshots.lstat()
    except FileNotFoundError:
        return [], 0
    if not stat.S_ISDIR(snapshots_stat.st_mode):
        raise SystemExit(f"code-snapshot-repair: {snapshots} is not a directory")
    if repo_key is not None:
        repo_dirs = [snapshots / validate_repo_key(repo_key)]
    else:
        repo_dirs = sorted(snapshots.iterdir())
    roots: list[Path] = []
    staging = 0
    for repo_dir in repo_dirs:
        try:
            repo_stat = repo_dir.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(repo_stat.st_mode):
            # A symlinked or special repository entry is refused as one snapshot.
            roots.append(repo_dir)
            continue
        for entry in sorted(repo_dir.iterdir()):
            if entry.name.startswith("."):
                staging += 1
            else:
                roots.append(entry)
    return roots, staging


def _rebind_row(rebind: SourceRebind, root: Path, engagement: Path) -> dict[str, Any]:
    return {
        "repo_key": rebind.repo_key,
        "snapshot_digest": rebind.snapshot_digest,
        "manifest_path": str((root / "manifest.json").relative_to(engagement)),
        "previous_source_path": rebind.previous_source_path,
        "source_path": SNAPSHOT_SOURCE_BINDING,
        "manifest_sha256_before": rebind.manifest_sha256_before,
        "manifest_sha256_after": rebind.manifest_sha256_after,
    }


def run(args) -> None:
    engagement = Path(resolve_engagement_dir(getattr(args, "engagement_dir", None)))
    snapshots = engagement.joinpath(*_SNAPSHOTS)
    try:
        roots, staging = _snapshot_roots(snapshots, args.repo_key)
    except ValueError as exc:
        raise SystemExit(f"code-snapshot-repair: {exc}") from exc
    rebound: list[dict[str, Any]] = []
    refused: list[dict[str, str]] = []
    current = 0
    audit_path: Path | None = None
    try:
        for root in roots:
            label = f"{root.parent.name}/{root.name}"
            try:
                if root.parent.is_symlink() or not stat.S_ISDIR(root.lstat().st_mode):
                    raise ValueError(f"not a sealed snapshot directory: {root}")
                rebind = rebind_snapshot_source(root, dry_run=args.dry_run)
            except SourceRebindUnverified as exc:
                # The manifest on disk was rewritten: the audit records the
                # rewrite and the failed check, never an unchanged seal.
                rebound.append({
                    **_rebind_row(exc.rebind, root, engagement),
                    "post_rewrite_validation": exc.reason,
                })
                refused.append({"snapshot": label, "reason": str(exc), "rewritten": True})
                print(f"refused {label}: {exc}", file=sys.stderr)
                continue
            except (OSError, ValueError, SourceSnapshotRaceError) as exc:
                refused.append({"snapshot": label, "reason": str(exc)})
                print(f"refused {label}: {exc}", file=sys.stderr)
                continue
            if rebind is None:
                current += 1
                continue
            rebound.append(_rebind_row(rebind, root, engagement))
            verb = "would rebind" if args.dry_run else "rebound"
            print(f"{verb} {label}: source binding {rebind.previous_source_path} -> {SNAPSHOT_SOURCE_BINDING}")
    finally:
        # Every rewrite is recorded, including those before a failure stopped the run.
        if rebound and not args.dry_run:
            audit_path = write_json_snapshot(
                os.fspath(engagement),
                category="code-snapshot-repair",
                label="source-binding",
                payload={
                    "schema": REPAIR_AUDIT_SCHEMA,
                    "operation": "rebind-sealed-source",
                    "actor": args.actor,
                    "repaired_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "rebound": rebound,
                    "refused": refused,
                },
                metadata={"rebound": len(rebound), "refused": len(refused)},
            )
    counted = f"{len(rebound)} would be repaired" if args.dry_run else f"{len(rebound)} repaired"
    summary = f"code-snapshot-repair: {counted}, {current} already relative, {len(refused)} refused"
    if staging:
        summary += f", {staging} in-progress staging dir(s) skipped"
    if audit_path is not None:
        summary += f"; audit: {audit_path.relative_to(engagement)}"
    print(summary)
    if refused:
        rewritten = [row for row in refused if row.get("rewritten")]
        if len(rewritten) < len(refused):
            print(
                "Refused snapshots that failed validation were left unchanged; each reason is "
                "above. Re-ingest the source to seal a fresh copy; a snapshot another repair "
                "was rewriting can be retried.",
                file=sys.stderr,
            )
        if rewritten:
            print(
                f"{len(rewritten)} snapshot(s) were rewritten but did not validate afterwards; "
                "the audit records each rewrite and its failed check. Re-ingest the source "
                "to seal a fresh copy.",
                file=sys.stderr,
            )
        raise SystemExit(1)
