"""aith assess work-buffer — local cases.db work-buffer operations."""
from __future__ import annotations

import sys

from assess.commands import dispatch
from assess.lib.config import anchor_engagement_relative


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "work-buffer",
        help="Operate on the local cases.db work-buffer queue.",
        usage="aith assess work-buffer <cases.db> <action> [args...]",
    )
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument("action", choices=dispatch._DB_ACTIONS)  # noqa: SLF001 - migration wrapper over existing implementation.
    p.add_argument("extra", nargs="*", help="Action-specific arguments")
    p.add_argument("--reason", default="", help="Reason for defer-cluster / defer-items.")
    p.add_argument(
        "--by",
        default="status",
        choices=("status", "source", "cluster", "host"),
        help="Group axis for stats.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    # Anchor a relative cases.db to the engagement dir so a subagent whose cwd
    # drifted between bash calls can't silently mutate the wrong (empty) DB.
    anchored = anchor_engagement_relative(args.db_path, getattr(args, "engagement_dir", None))
    if anchored != args.db_path:
        print(f"work-buffer: anchored relative db path '{args.db_path}' -> '{anchored}'", file=sys.stderr)
    args.db_path = anchored
    dispatch.run(args)
