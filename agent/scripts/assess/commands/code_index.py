"""vigil assess code-index — tree-sitter structural indexing for a code repository."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from assess.commands.code_ingest import (
    SKIP_DIRS,
    _is_regular_file,
    _repo_key_for_path,
    _should_skip_file,
)
from assess.lib.config import resolve_engagement_dir
from assess.lib.treesitter_index import (
    SUPPORTED_LANGUAGES,
    index_file,
    language_for_file,
)


def register(subparsers) -> None:
    from assess.commands import code_index_sync

    p = subparsers.add_parser(
        "code-index",
        help="Tree-sitter structural index for a code repository: build | sync",
    )
    action_sub = p.add_subparsers(dest="code_index_action")
    _register_build(action_sub)
    code_index_sync.register_sync(action_sub)

    def _print_help(_args) -> None:
        p.print_help()
        sys.exit(1)

    p.set_defaults(func=_print_help)


def _register_build(subparsers) -> None:
    p = subparsers.add_parser(
        "build",
        help="Build a tree-sitter structural index for a code repository",
    )
    p.add_argument("repo_path", help="Path to the repository root")
    p.add_argument(
        "--repo-id",
        default=None,
        help="Repository ID (numeric, used in output directory naming)",
    )
    p.add_argument(
        "--repo-key",
        default=None,
        help="Stable repository key (default: derived from repo name + canonical path "
             "via the same scheme as code-ingest). Used to name the per-repo index "
             "directory and manifest so multiple repos don't collide.",
    )
    p.add_argument(
        "--repo-name",
        default=None,
        help="Repository name (default: directory basename). Used only for "
             "repo_key derivation and human-readable manifest labeling.",
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


def _file_id(repo_key: str, rel_path: str) -> str:
    """Produce a short deterministic identifier for a (repo, file_path) pair.

    Includes ``repo_key`` in the hash so the same relative path across repos
    (e.g. ``test/common.js`` in vast-service and beacon-processor) doesn't collide.
    """
    composite = f"{repo_key}::{rel_path}"
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()[:16]


def _merge_languages(dst: dict[str, int], src: dict[str, int]) -> None:
    for k, v in src.items():
        dst[k] = dst.get(k, 0) + int(v)


def _update_aggregate_manifest(
    aggregate_path: Path,
    repo_key: str,
    per_repo_entry: dict,
) -> dict:
    """Load (or initialize) the engagement aggregate manifest, set the entry for
    *repo_key*, recompute aggregate totals, and write it back.

    The aggregate file lists every repo indexed in this engagement; its shape is::

        {
          "schema": "structural-index-aggregate/v1",
          "updated_at": "...",
          "repos": {"<repo_key>": { ... per-repo summary ... }, ...},
          "aggregate": { totals over all repos }
        }

    A legacy single-repo manifest (with top-level ``path_to_index``) is treated
    as one entry and folded in on first write so older engagements upgrade
    cleanly.
    """
    if aggregate_path.is_file():
        try:
            existing = json.loads(aggregate_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = {}
    else:
        existing = {}

    repos: dict[str, dict] = existing.get("repos") if isinstance(existing.get("repos"), dict) else {}

    # Migrate legacy single-repo shape: fold its summary into ``repos`` under a
    # synthetic key derived from its repo_path, then overwrite below if it
    # matches the repo we're writing now.
    if not repos and existing.get("path_to_index"):
        legacy_repo_path = existing.get("repo_path", "")
        legacy_name = Path(legacy_repo_path).name or "legacy"
        try:
            legacy_key = _repo_key_for_path(legacy_name, legacy_repo_path) if legacy_repo_path else "legacy"
        except Exception:
            legacy_key = "legacy"
        repos[legacy_key] = {
            **{k: v for k, v in existing.items() if k != "path_to_index"},
            "manifest_path": None,  # legacy manifest was the file itself; no per-repo file exists
            "index_dir": None,
            "is_legacy": True,
        }

    repos[repo_key] = per_repo_entry

    # Recompute aggregate totals across all repos.
    aggregate = {
        "total_files": 0,
        "indexed_files": 0,
        "skipped_unsupported": 0,
        "languages": {},
        "total_functions": 0,
        "total_entry_points": 0,
        "total_security_sinks": 0,
        "total_exports": 0,
        "sinks_by_category": {},
        "repo_count": len(repos),
    }
    for entry in repos.values():
        aggregate["total_files"] += int(entry.get("total_files", 0) or 0)
        aggregate["indexed_files"] += int(entry.get("indexed_files", 0) or 0)
        aggregate["skipped_unsupported"] += int(entry.get("skipped_unsupported", 0) or 0)
        aggregate["total_functions"] += int(entry.get("total_functions", 0) or 0)
        aggregate["total_entry_points"] += int(entry.get("total_entry_points", 0) or 0)
        aggregate["total_security_sinks"] += int(entry.get("total_security_sinks", 0) or 0)
        aggregate["total_exports"] += int(entry.get("total_exports", 0) or 0)
        _merge_languages(aggregate["languages"], entry.get("languages", {}) or {})
        _merge_languages(aggregate["sinks_by_category"], entry.get("sinks_by_category", {}) or {})

    payload = {
        "schema": "structural-index-aggregate/v1",
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repos": repos,
        "aggregate": aggregate,
    }
    aggregate_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return payload


def run(args) -> None:
    # --- Check tree-sitter availability early --------------------------------
    try:
        import tree_sitter  # noqa: F401
    except ImportError:
        print(
            "Error: tree-sitter is unavailable in the current vigil assess runtime. "
            "Run code-index through vigil assess or repair the local uv "
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
                "Pass --engagement-dir or start from a Vigil launcher session so the structural index "
                "is written to tools/analysis-state, or pass --output-dir explicitly.",
                file=sys.stderr,
            )
            sys.exit(1)
        out_base = Path(eng_dir) / "tools" / "analysis-state"

    # --- Derive repo identity ------------------------------------------------
    repo_name = getattr(args, "repo_name", None) or os.path.basename(repo_path.rstrip(os.sep)) or "repo"
    repo_key = getattr(args, "repo_key", None) or _repo_key_for_path(repo_name, repo_path)

    structural_root = out_base / "structural-index"
    structural_root.mkdir(parents=True, exist_ok=True)
    idx_dir = structural_root / repo_key
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
        idx["repo_key"] = repo_key   # tag the per-file index so it stays self-describing if relocated

        # Write per-file JSON under the per-repo subdirectory.
        fid = _file_id(repo_key, rel_path)
        out_path = idx_dir / f"{fid}.json"
        out_path.write_text(
            json.dumps(idx, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        # Manifest path is relative to the structural-index root so consumers
        # can resolve it without knowing the repo_key.
        path_to_index[rel_path] = f"{repo_key}/{fid}.json"

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

    # --- Write per-repo manifest --------------------------------------------
    per_repo_manifest = {
        "schema": "structural-index/v2",
        "repo_key": repo_key,
        "repo_name": repo_name,
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

    per_repo_manifest_path = structural_root / f"{repo_key}-manifest.json"
    per_repo_manifest_path.write_text(
        json.dumps(per_repo_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # --- Update aggregate manifest ------------------------------------------
    aggregate_path = out_base / "structural-index-manifest.json"
    aggregate_entry = {
        k: v for k, v in per_repo_manifest.items() if k != "path_to_index"
    }
    aggregate_entry["manifest_path"] = f"structural-index/{repo_key}-manifest.json"
    aggregate_entry["index_dir"] = f"structural-index/{repo_key}/"
    _update_aggregate_manifest(aggregate_path, repo_key, aggregate_entry)

    # --- Print summary -------------------------------------------------------
    print("\n=== Structural Index Summary ===", file=sys.stderr)
    print(f"Repository: {repo_name} ({repo_key})  path: {repo_path}", file=sys.stderr)
    print(f"Total files: {len(file_list)}  |  Indexed: {indexed}  |  Skipped (unsupported): {skipped_unsupported}", file=sys.stderr)
    print(f"Languages: {json.dumps(lang_counts)}", file=sys.stderr)
    print(f"Functions: {total_functions}  |  Entry points: {total_entry_points}  |  Security sinks: {total_sinks}  |  Exports: {total_exports}", file=sys.stderr)
    if sinks_by_cat:
        print(f"Sinks by category: {json.dumps(sinks_by_cat)}", file=sys.stderr)
    print(f"\nPer-file indexes: {idx_dir}", file=sys.stderr)
    print(f"Per-repo manifest: {per_repo_manifest_path}", file=sys.stderr)
    print(f"Aggregate manifest: {aggregate_path}", file=sys.stderr)
    print("\nRun 'code-index sync' to push structural metadata to the backend.", file=sys.stderr)
