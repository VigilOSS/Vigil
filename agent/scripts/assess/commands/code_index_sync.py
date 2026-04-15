"""assess.py code-index-sync — push structural index metadata to the backend."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "code-index-sync",
        help="Sync structural index metadata (function/entry-point/sink/export counts) to the backend",
    )
    p.add_argument(
        "--manifest",
        default=None,
        help="Path to structural-index-manifest.json "
             "(default: <engagement_dir>/tools/analysis-state/structural-index-manifest.json)",
    )
    p.add_argument(
        "--index-dir",
        default=None,
        help="Path to structural-index directory "
             "(default: <engagement_dir>/tools/analysis-state/structural-index/)",
    )
    p.add_argument(
        "--repo-id",
        default=None,
        type=int,
        help="Repo ID to scope file lookups (required if multiple repos exist)",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)

    manifest_path = args.manifest
    if not manifest_path:
        eng_dir = args.engagement_dir or cfg.engagement_dir
        if not eng_dir:
            print("Cannot determine engagement directory. Use --engagement-dir or set ENGAGEMENT_DIR.", file=sys.stderr)
            sys.exit(1)
        manifest_path = str(Path(eng_dir) / "tools" / "analysis-state" / "structural-index-manifest.json")

    manifest_file = Path(manifest_path)
    if not manifest_file.is_file():
        print(f"Manifest not found: {manifest_path}", file=sys.stderr)
        print("Run code-index first to generate the structural index.", file=sys.stderr)
        sys.exit(1)

    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    path_to_index = manifest.get("path_to_index", {})

    if not path_to_index:
        print("Manifest has no indexed files.", file=sys.stderr)
        sys.exit(0)

    index_dir = args.index_dir
    if not index_dir:
        index_dir = str(manifest_file.parent / "structural-index")
    index_dir_path = Path(index_dir)

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        if not args.repo_id:
            repos = client.get("code/repos")
            if not isinstance(repos, list):
                print(f"Unexpected backend response type for repos: {type(repos)}", file=sys.stderr)
                sys.exit(1)
            if len(repos) > 1:
                print(
                    "Multiple repos found for this engagement. Re-run code-index-sync with --repo-id "
                    "to avoid syncing structural metadata to duplicate relative paths across repos.",
                    file=sys.stderr,
                )
                sys.exit(1)

        path_to_file_id: dict[str, int] = {}
        page_size = 5000
        offset = 0
        while True:
            try:
                query = f"code/files?limit={page_size}&offset={offset}"
                if args.repo_id:
                    query += f"&repo_id={args.repo_id}"
                page = client.get(query)
            except Exception as exc:
                print(f"Failed to fetch files from backend: {exc}", file=sys.stderr)
                sys.exit(1)

            if not isinstance(page, list):
                print(f"Unexpected backend response type: {type(page)}", file=sys.stderr)
                sys.exit(1)

            for bf in page:
                fp = bf.get("file_path", "")
                fid = bf.get("id")
                if fp and fid is not None:
                    path_to_file_id[fp] = int(fid)

            if len(page) < page_size:
                break
            offset += page_size

        updates: list[dict] = []
        for rel_path, index_filename in path_to_index.items():
            file_id = path_to_file_id.get(rel_path)
            if file_id is None:
                continue

            index_file = index_dir_path / index_filename
            if not index_file.is_file():
                continue

            try:
                idx = json.loads(index_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            updates.append({
                "file_id": file_id,
                "total_functions": idx.get("total_functions", 0),
                "total_entry_points": len(idx.get("entry_points", [])),
                "total_sinks": len(idx.get("security_sinks", [])),
                "total_exports": len(idx.get("exports", [])),
            })

        if not updates:
            print("No files matched between structural index and backend.", file=sys.stderr)
            sys.exit(0)

        try:
            result = client.post("code/files/bulk-structural-metadata", {"updates": updates})
        except Exception as exc:
            print(f"Failed to sync structural metadata: {exc}", file=sys.stderr)
            sys.exit(1)
    finally:
        client.close()

    updated = result.get("updated", 0) if isinstance(result, dict) else 0
    skipped = result.get("skipped", 0) if isinstance(result, dict) else 0
    print(f"Structural metadata synced: {updated} files updated, {skipped} skipped", file=sys.stderr)
