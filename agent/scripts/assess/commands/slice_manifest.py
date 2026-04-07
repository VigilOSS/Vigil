"""assess.py slice-manifest — manage the local slice manifest for Phase 2→3 handoff."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.config import load_config


MANIFEST_REL = "tools/analysis-state/slice-manifest.json"


def _manifest_path(engagement_dir: str) -> Path:
    return Path(engagement_dir) / MANIFEST_REL


def _load(path: Path) -> list[dict]:
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return []


def _save(path: Path, data: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def register(subparsers) -> None:
    p = subparsers.add_parser("slice-manifest", help="Manage the slice manifest (Phase 2→3 handoff)")
    sp = p.add_subparsers(dest="action")

    # record: add a slice entry
    rec = sp.add_parser("record", help="Record a completed slice in the manifest")
    rec.add_argument("queue_item_id", type=int, help="Queue item ID this slice covers")
    rec.add_argument("target_function", help="Target function name")
    rec.add_argument("slice_path", help="Relative path to the .slice file")
    rec.add_argument("--files-included", type=int, default=0, help="Number of source files in the slice")
    rec.add_argument("--line-count", type=int, default=0, help="Total lines in the slice")
    rec.add_argument("--trimmed", action="store_true", help="Whether the slice was trimmed to fit budget")
    rec.add_argument("--unresolved", nargs="*", default=[], help="Unresolved external references")
    rec.set_defaults(func=run_record)

    # lookup: find slice path for a queue item
    lk = sp.add_parser("lookup", help="Look up slice path for a queue item ID")
    lk.add_argument("queue_item_id", type=int, help="Queue item ID to look up")
    lk.set_defaults(func=run_lookup)

    # list: show all manifest entries
    ls = sp.add_parser("list", help="List all manifest entries")
    ls.set_defaults(func=run_list)

    # stats: summary counts
    st = sp.add_parser("stats", help="Show manifest statistics")
    st.set_defaults(func=run_stats)

    p.set_defaults(func=lambda a: p.print_help())


def run_record(args) -> None:
    cfg = load_config(args.engagement_dir)
    mp = _manifest_path(cfg.engagement_dir)
    manifest = _load(mp)

    # Dedup: replace if queue_item_id already exists
    manifest = [e for e in manifest if e.get("queue_item_id") != args.queue_item_id]
    manifest.append({
        "queue_item_id": args.queue_item_id,
        "target_function": args.target_function,
        "slice_path": args.slice_path,
        "files_included": args.files_included,
        "line_count": args.line_count,
        "trimmed": args.trimmed,
        "unresolved_refs": args.unresolved or [],
    })
    _save(mp, manifest)
    print(f"Recorded: {args.target_function} → {args.slice_path} (queue item {args.queue_item_id})")


def run_lookup(args) -> None:
    cfg = load_config(args.engagement_dir)
    mp = _manifest_path(cfg.engagement_dir)
    manifest = _load(mp)
    for entry in manifest:
        if entry.get("queue_item_id") == args.queue_item_id:
            print(json.dumps(entry, indent=2, ensure_ascii=False))
            return
    print(f"No slice found for queue item {args.queue_item_id}", file=sys.stderr)
    sys.exit(1)


def run_list(args) -> None:
    cfg = load_config(args.engagement_dir)
    mp = _manifest_path(cfg.engagement_dir)
    manifest = _load(mp)
    if not manifest:
        print("Slice manifest is empty.")
        return
    print(f"{'ID':>6}  {'Function':<40}  {'Lines':>6}  {'Trimmed':>7}  Path")
    print(f"{'─'*6}  {'─'*40}  {'─'*6}  {'─'*7}  {'─'*50}")
    for e in manifest:
        trimmed = "yes" if e.get("trimmed") else "no"
        print(f"{e['queue_item_id']:>6}  {e['target_function']:<40}  {e.get('line_count', 0):>6}  {trimmed:>7}  {e['slice_path']}")


def run_stats(args) -> None:
    cfg = load_config(args.engagement_dir)
    mp = _manifest_path(cfg.engagement_dir)
    manifest = _load(mp)
    total = len(manifest)
    trimmed = sum(1 for e in manifest if e.get("trimmed"))
    unresolved = sum(1 for e in manifest if e.get("unresolved_refs"))
    total_lines = sum(e.get("line_count", 0) for e in manifest)
    print(f"Slices: {total} | Trimmed: {trimmed} | With unresolved refs: {unresolved} | Total lines: {total_lines}")
