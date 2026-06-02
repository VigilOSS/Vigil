"""aith assess code-index-sync — push structural index metadata to the backend."""
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
             "(default: <engagement_dir>/tools/analysis-state/structural-index-manifest.json). "
             "Accepts both the v2 aggregate shape and the legacy single-repo shape.",
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
        help="Restrict sync to a specific backend repo_id. Useful for re-syncing one repo "
             "without touching the others.",
    )
    p.add_argument(
        "--repo-key",
        default=None,
        help="Restrict sync to a specific repo_key (matched against per-repo manifests).",
    )
    p.set_defaults(func=run)


def _load_manifest(path: Path) -> dict:
    if not path.is_file():
        print(f"Manifest not found: {path}", file=sys.stderr)
        print("Run code-index first to generate the structural index.", file=sys.stderr)
        sys.exit(1)
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_per_repo_manifests(top: dict, top_path: Path) -> list[tuple[str, dict]]:
    """Return list of (repo_key, per_repo_manifest_dict) entries from the top-level manifest.

    Supports v2 aggregate ({"schema": "structural-index-aggregate/v1", "repos": {...}})
    and legacy single-repo ({"path_to_index": {...}, "repo_path": ...}).
    """
    if isinstance(top.get("repos"), dict):
        out: list[tuple[str, dict]] = []
        for repo_key, summary in top["repos"].items():
            if summary.get("is_legacy"):
                # Legacy entry folded into aggregate at upgrade time — it has no
                # per-repo manifest path; the index_dir is empty so we cannot resolve
                # path_to_index. Skip with a warning.
                print(f"  warn: skipping legacy aggregate entry {repo_key} (no per-repo manifest)",
                      file=sys.stderr)
                continue
            manifest_rel = summary.get("manifest_path")
            if not manifest_rel:
                continue
            mpath = top_path.parent / manifest_rel
            if not mpath.is_file():
                print(f"  warn: missing per-repo manifest for {repo_key}: {mpath}", file=sys.stderr)
                continue
            try:
                m = json.loads(mpath.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                print(f"  warn: cannot parse {mpath}: {exc}", file=sys.stderr)
                continue
            out.append((repo_key, m))
        return out
    # Legacy single-repo manifest
    return [(top.get("repo_key") or "_legacy", top)]


def _find_backend_repo(repos: list[dict], repo_key: str | None, repo_id: int | None,
                       repo_path: str | None) -> dict | None:
    """Match a backend repo row by repo_id, repo_key, repo_path, or safe legacy fallback."""
    if repo_id is not None:
        for r in repos:
            if r.get("id") == repo_id or r.get("repo_id") == repo_id:
                return r
        return None
    if repo_key and repo_key != "_legacy":
        for r in repos:
            if r.get("repo_key") == repo_key:
                return r
    if repo_path:
        for r in repos:
            if r.get("repo_path") == repo_path:
                return r
    if (not repo_key or repo_key == "_legacy") and not repo_path and len(repos) == 1:
        return repos[0]
    return None


def _per_repo_matches_backend(repo_key: str, per_repo: dict, backend_repo: dict) -> bool:
    """Return whether a per-repo manifest identifies the selected backend repo."""
    manifest_repo_key = per_repo.get("repo_key") or repo_key
    backend_repo_key = backend_repo.get("repo_key")
    if manifest_repo_key and manifest_repo_key != "_legacy" and backend_repo_key:
        return manifest_repo_key == backend_repo_key

    manifest_repo_path = per_repo.get("repo_path")
    backend_repo_path = backend_repo.get("repo_path")
    if manifest_repo_path and backend_repo_path:
        return manifest_repo_path == backend_repo_path

    return False


def _per_repo_has_identity(repo_key: str, per_repo: dict) -> bool:
    manifest_repo_key = per_repo.get("repo_key") or repo_key
    return bool((manifest_repo_key and manifest_repo_key != "_legacy") or per_repo.get("repo_path"))


def _sync_one_repo(client: AssessmentClient, backend_repo: dict, per_repo: dict,
                   index_root: Path) -> tuple[int, int]:
    """Sync structural metadata for one repo. Returns (updated, skipped)."""
    repo_id = backend_repo.get("id") or backend_repo.get("repo_id")
    if not repo_id:
        return 0, 0

    path_to_index = per_repo.get("path_to_index", {})
    if not path_to_index:
        return 0, 0

    # Build path -> file_id map by paging through backend files for this repo only.
    path_to_file_id: dict[str, int] = {}
    page_size = 5000
    offset = 0
    while True:
        page = client.get(f"code/files?limit={page_size}&offset={offset}&repo_id={repo_id}")
        if not isinstance(page, list):
            print(f"  warn: unexpected files response shape for repo {repo_id}: {type(page)}",
                  file=sys.stderr)
            break
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
        index_file_path = index_root / index_filename
        if not index_file_path.is_file():
            continue
        try:
            idx = json.loads(index_file_path.read_text(encoding="utf-8"))
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
        return 0, 0

    result = client.post("code/files/bulk-structural-metadata", {"updates": updates})
    updated = result.get("updated", 0) if isinstance(result, dict) else 0
    skipped = result.get("skipped", 0) if isinstance(result, dict) else 0
    return int(updated), int(skipped)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)

    manifest_path = args.manifest
    if not manifest_path:
        eng_dir = args.engagement_dir or cfg.engagement_dir
        if not eng_dir:
            print("Cannot determine engagement directory. Use --engagement-dir or set ENGAGEMENT_DIR.",
                  file=sys.stderr)
            sys.exit(1)
        manifest_path = str(Path(eng_dir) / "tools" / "analysis-state" / "structural-index-manifest.json")

    manifest_file = Path(manifest_path)
    top = _load_manifest(manifest_file)

    index_root = Path(args.index_dir) if args.index_dir else (manifest_file.parent / "structural-index")

    per_repos = _resolve_per_repo_manifests(top, manifest_file)
    if not per_repos:
        print("Manifest contains no per-repo entries to sync.", file=sys.stderr)
        sys.exit(0)

    # Optional restriction
    requested_repo_key = getattr(args, "repo_key", None)
    if requested_repo_key:
        per_repos = [(k, m) for k, m in per_repos if k == requested_repo_key or m.get("repo_key") == requested_repo_key]
        if not per_repos:
            print(f"No per-repo manifest matched --repo-key {requested_repo_key}", file=sys.stderr)
            sys.exit(1)

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        repos = client.get("code/repos")
        if not isinstance(repos, list):
            print(f"Unexpected backend response type for repos: {type(repos)}", file=sys.stderr)
            sys.exit(1)

        requested_repo_id = getattr(args, "repo_id", None)
        if requested_repo_id is not None:
            requested_backend = _find_backend_repo(
                repos,
                repo_key=None,
                repo_id=requested_repo_id,
                repo_path=None,
            )
            if requested_backend is None:
                print(f"No backend repo matched --repo-id {requested_repo_id}", file=sys.stderr)
                sys.exit(1)
            if len(per_repos) > 1:
                per_repos = [
                    (repo_key, per_repo)
                    for repo_key, per_repo in per_repos
                    if _per_repo_matches_backend(repo_key, per_repo, requested_backend)
                ]
                if not per_repos:
                    print(
                        f"--repo-id {requested_repo_id} did not match any per-repo manifest. "
                        "Pass --repo-key with aggregate manifests or rebuild the index so "
                        "repo_key/repo_path metadata matches the backend repo.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
            else:
                repo_key, per_repo = per_repos[0]
                if (
                    _per_repo_has_identity(repo_key, per_repo)
                    and not _per_repo_matches_backend(repo_key, per_repo, requested_backend)
                ):
                    print(
                        f"--repo-id {requested_repo_id} does not match per-repo manifest {repo_key}. "
                        "Use the matching --repo-key/--repo-id pair or omit --repo-id.",
                        file=sys.stderr,
                    )
                    sys.exit(1)

        if (
            len(per_repos) == 1
            and per_repos[0][0] == "_legacy"
            and not per_repos[0][1].get("repo_path")
            and getattr(args, "repo_id", None) is None
            and len(repos) > 1
        ):
            print(
                "Legacy structural-index manifest has no repo identity, but multiple repos "
                "exist for this engagement. Re-run code-index-sync with --repo-id or rebuild "
                "the index with current code-index so repo_key metadata is recorded.",
                file=sys.stderr,
            )
            sys.exit(1)

        if not index_root.is_dir():
            print(f"Structural-index directory not found: {index_root}", file=sys.stderr)
            sys.exit(1)

        total_updated = 0
        total_skipped = 0
        processed = 0
        for repo_key, per_repo in per_repos:
            backend = _find_backend_repo(
                repos,
                repo_key=per_repo.get("repo_key") or repo_key,
                repo_id=args.repo_id,
                repo_path=per_repo.get("repo_path"),
            )
            if backend is None:
                print(f"  warn: no backend repo matched {repo_key}; skipping", file=sys.stderr)
                continue
            try:
                upd, skp = _sync_one_repo(client, backend, per_repo, index_root)
            except Exception as exc:
                print(f"  error: sync failed for {repo_key}: {exc}", file=sys.stderr)
                continue
            label = backend.get("name") or repo_key
            print(f"  sync {label} (repo_id={backend.get('id')}): {upd} updated, {skp} skipped",
                  file=sys.stderr)
            total_updated += upd
            total_skipped += skp
            processed += 1

    if processed == 0:
        print("No repos were synced. Verify backend has matching repo_key entries.", file=sys.stderr)
        sys.exit(0)

    print(f"\nStructural metadata synced across {processed} repos: "
          f"{total_updated} files updated, {total_skipped} skipped", file=sys.stderr)
