"""aith assess code-index — tree-sitter structural indexing for a code repository."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from assess.commands.code_ingest import (
    SKIP_DIRS,
    SKIP_EXTENSIONS,
    _is_regular_file,
    _should_skip_file,
)
from assess.lib.config import resolve_engagement_dir
from assess.lib.treesitter_index import (
    SUPPORTED_LANGUAGES,
    index_file,
    language_for_file,
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "code-index",
        help="Build a tree-sitter structural index for a code repository",
    )
    p.add_argument("repo_path", help="Path to the repository root")
    p.add_argument(
        "--repo-id",
        default=None,
        help="Repository ID (used in output directory naming)",
    )
    p.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for structural index JSON files "
             "(default: <engagement_dir>/tools/analysis-state/)",
    )
    p.add_argument(
        "--file-list",
        default=None,
        help="Path to a JSON file with pre-enumerated files "
             '(array of objects with "file_path" and optional "language")',
    )
    p.set_defaults(func=run)


def _walk_repo(repo_path: str) -> list[dict[str, str]]:
    """Walk *repo_path* and collect files with supported tree-sitter languages."""
    files: list[dict[str, str]] = []

    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        dirnames[:] = [
            d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))
        ]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if not _is_regular_file(filepath):
                continue

            rel_path = os.path.relpath(filepath, repo_path)
            if _should_skip_file(rel_path, filename):
                continue

            lang = language_for_file(filename)
            if lang and lang in SUPPORTED_LANGUAGES:
                files.append({"file_path": rel_path, "language": lang})

    return files


def _file_id(rel_path: str) -> str:
    """Produce a short deterministic identifier for a file path."""
    return hashlib.sha256(rel_path.encode("utf-8")).hexdigest()[:16]


def run(args) -> None:
    # --- Check tree-sitter availability early --------------------------------
    try:
        import tree_sitter  # noqa: F401
    except ImportError:
        print(
            "Error: tree-sitter is unavailable in the current aith assess runtime. "
            "Run code-index through aith assess or repair the local uv "
            "environment instead of skipping structural indexing.",
            file=sys.stderr,
        )
        sys.exit(1)

    repo_path = os.path.abspath(args.repo_path)
    if not os.path.isdir(repo_path):
        print(f"Repository path not found: {repo_path}", file=sys.stderr)
        sys.exit(1)

    # --- Determine file list -------------------------------------------------
    if args.file_list:
        fl_path = Path(args.file_list)
        if not fl_path.is_file():
            print(f"File list not found: {args.file_list}", file=sys.stderr)
            sys.exit(1)
        file_list = json.loads(fl_path.read_text(encoding="utf-8"))
        if not isinstance(file_list, list):
            print("--file-list must contain a JSON array", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Walking {repo_path} for supported source files ...", file=sys.stderr)
        file_list = _walk_repo(repo_path)
        print(f"  found {len(file_list)} files with supported languages", file=sys.stderr)

    if not file_list:
        print("No files with supported languages found.", file=sys.stderr)
        sys.exit(0)

    # --- Resolve output directory --------------------------------------------
    if args.output_dir:
        out_base = Path(args.output_dir)
    else:
        try:
            eng_dir = resolve_engagement_dir(getattr(args, "engagement_dir", None))
        except SystemExit:
            print(
                "Cannot resolve engagement directory for default code-index output. "
                "Pass --engagement-dir or set ENGAGEMENT_DIR so the structural index "
                "is written to tools/analysis-state, or pass --output-dir explicitly.",
                file=sys.stderr,
            )
            sys.exit(1)
        out_base = Path(eng_dir) / "tools" / "analysis-state"

    idx_dir = out_base / "structural-index"
    idx_dir.mkdir(parents=True, exist_ok=True)

    # --- Index each file -----------------------------------------------------
    lang_counts: dict[str, int] = {}
    total_functions = 0
    total_entry_points = 0
    total_sinks = 0
    total_exports = 0
    sinks_by_cat: dict[str, int] = {}
    indexed = 0
    skipped_unsupported = 0
    path_to_index: dict[str, str] = {}

    for entry in file_list:
        rel_path = entry["file_path"]
        lang = entry.get("language") or language_for_file(rel_path)
        if not lang or lang not in SUPPORTED_LANGUAGES:
            skipped_unsupported += 1
            continue

        abs_path = os.path.join(repo_path, rel_path)
        idx = index_file(abs_path, lang)
        idx["file_path"] = rel_path  # store relative path

        # Write per-file JSON
        fid = _file_id(rel_path)
        out_path = idx_dir / f"{fid}.json"
        out_path.write_text(
            json.dumps(idx, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        path_to_index[rel_path] = f"{fid}.json"

        # Accumulate stats
        indexed += 1
        lang_counts[lang] = lang_counts.get(lang, 0) + 1
        total_functions += idx["total_functions"]
        total_entry_points += len(idx["entry_points"])
        total_sinks += len(idx["security_sinks"])
        total_exports += len(idx.get("exports", []))
        for sink in idx["security_sinks"]:
            kind = sink["kind"]
            sinks_by_cat[kind] = sinks_by_cat.get(kind, 0) + 1

    # --- Write manifest ------------------------------------------------------
    manifest = {
        "repo_path": repo_path,
        "indexed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_files": len(file_list),
        "indexed_files": indexed,
        "skipped_unsupported": skipped_unsupported,
        "languages": lang_counts,
        "total_functions": total_functions,
        "total_entry_points": total_entry_points,
        "total_security_sinks": total_sinks,
        "total_exports": total_exports,
        "sinks_by_category": sinks_by_cat,
        "path_to_index": path_to_index,
    }

    manifest_path = out_base / "structural-index-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # --- Print summary -------------------------------------------------------
    print(f"\n=== Structural Index Summary ===", file=sys.stderr)
    print(f"Repository: {repo_path}", file=sys.stderr)
    print(f"Total files: {len(file_list)}  |  Indexed: {indexed}  |  Skipped (unsupported): {skipped_unsupported}", file=sys.stderr)
    print(f"Languages: {json.dumps(lang_counts)}", file=sys.stderr)
    print(f"Functions: {total_functions}  |  Entry points: {total_entry_points}  |  Security sinks: {total_sinks}  |  Exports: {total_exports}", file=sys.stderr)
    if sinks_by_cat:
        print(f"Sinks by category: {json.dumps(sinks_by_cat)}", file=sys.stderr)
    print(f"\nIndex written to: {idx_dir}", file=sys.stderr)
    print(f"Manifest written to: {manifest_path}", file=sys.stderr)
    print(f"\nRun 'code-index-sync' to push structural metadata to the backend.", file=sys.stderr)
