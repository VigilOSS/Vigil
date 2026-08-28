"""Extract embedded source-map content into an immutable tree for code-ingest."""

from __future__ import annotations

import collections
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import sys
import uuid
from urllib.parse import urlsplit

from assess.lib.config import resolve_engagement_dir


_SNAPSHOT_FORMAT_VERSION = 1
_MAP_SUFFIXES = (".js.map", ".css.map")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[/\\]")
_EXTRACTED_STATUSES = frozenset({"extracted", "extracted_duplicate"})


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "code-sourcemap-extract",
        help="Safely extract sourcesContent for explicit code-ingest",
    )
    parser.add_argument("map_root", help="Directory containing .js.map/.css.map files")
    parser.add_argument(
        "--output-root",
        default=None,
        help=(
            "Snapshot parent (default: "
            "<engagement>/tools/analysis-state/source-maps/<map-root-name>)"
        ),
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Allow changed map input to create a new immutable hash snapshot",
    )
    parser.set_defaults(func=run)


def _map_files(map_root: Path) -> list[Path]:
    matches: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(map_root):
        dirnames[:] = sorted(
            dirname
            for dirname in dirnames
            if not (Path(dirpath) / dirname).is_symlink()
        )
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            if path.is_symlink() or not path.is_file():
                continue
            if filename.lower().endswith(_MAP_SUFFIXES):
                matches.append(path)
    return sorted(matches, key=lambda path: path.relative_to(map_root).as_posix())


def _snapshot_hash(map_root: Path, map_files: list[Path]) -> str:
    digest = hashlib.sha256(f"v{_SNAPSHOT_FORMAT_VERSION}\0".encode())
    for map_path in map_files:
        relative = map_path.relative_to(map_root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(map_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _safe_source_path(
    source_root: object,
    source: object,
    map_dir_parts: tuple[str, ...] = (),
) -> PurePosixPath | None:
    if not isinstance(source, str) or not source.strip():
        return None
    source_value = source.strip()
    components: list[str] = []
    if source_root not in (None, "") and not urlsplit(source_value).scheme:
        if not isinstance(source_root, str):
            return None
        components.append(source_root.strip())
    components.append(source_value)
    raw = "/".join(components).replace("\\", "/")
    if "\0" in raw:
        return None
    parsed = urlsplit(raw)
    anchor: tuple[str, ...] = map_dir_parts
    if parsed.scheme == "webpack":
        # webpack:// paths are virtual source identifiers, not network URLs.
        # Preserve a non-empty bundle namespace while normalizing the common
        # webpack:///./src form into the extracted tree. They are absolute
        # within their bundle namespace, so the map's own directory is not
        # their anchor.
        raw = "/".join(part for part in (parsed.netloc, parsed.path) if part)
        raw = raw.lstrip("/")
        anchor = ()
    elif parsed.scheme or parsed.netloc or raw.startswith("//"):
        return None
    if raw.startswith("/") or _WINDOWS_ABSOLUTE.match(raw):
        return None
    raw_parts = [part for part in raw.split("/") if part not in {"", "."}]
    if not raw_parts:
        return None
    # A map's `sources` are defined relative to the map file's own location, so
    # `..` is resolved against that directory — the single most common Rollup /
    # Vite / tsc shape — instead of being refused on sight. A path that climbs
    # past the extracted tree root has no faithful location here, so it still
    # fails closed.
    resolved: list[str] = list(anchor)
    for part in raw_parts:
        if part != "..":
            resolved.append(part)
            continue
        if not resolved:
            return None
        resolved.pop()
    if not resolved:
        return None
    return PurePosixPath(*resolved)


def _collision_path(
    relative: PurePosixPath, content_hash: str, hash_length: int = 12
) -> PurePosixPath:
    suffix = relative.suffix
    stem = relative.name[: -len(suffix)] if suffix else relative.name
    name = f"{stem}__dup-{content_hash[:hash_length]}{suffix}"
    return relative.with_name(name)


def _map_payloads(payload: object):
    if not isinstance(payload, dict):
        return
    sections = payload.get("sections")
    if not isinstance(sections, list):
        yield "", payload
        return
    if "sources" in payload or "sourcesContent" in payload:
        yield "", payload
    for index, section in enumerate(sections):
        if isinstance(section, dict) and isinstance(section.get("map"), dict):
            yield f"sections[{index}]", section["map"]


def _extracted_count(records: list[dict[str, object]]) -> int:
    return sum(1 for record in records if record.get("status") in _EXTRACTED_STATUSES)


def _status_census(records: list[dict[str, object]]) -> str:
    counts = collections.Counter(str(record.get("status") or "unknown") for record in records)
    return ", ".join(f"{status}: {count}" for status, count in sorted(counts.items()))


def _repo_key(map_root: Path) -> str:
    source_identity = hashlib.sha256(str(map_root).encode("utf-8")).hexdigest()[:12]
    return f"sourcemap-{map_root.name.lower().replace(' ', '-')}-{source_identity}"


def _ingest_command(map_root: Path, snapshot_dir: Path) -> str:
    """Compose the code-ingest handoff for a PUBLISHED snapshot directory."""
    return (
        f"vigil assess code-ingest {shlex.quote(str(snapshot_dir / 'sources'))} "
        f"--name {shlex.quote(map_root.name + '-source-map')} "
        f"--repo-key {shlex.quote(_repo_key(map_root))}"
    )


def _extract_snapshot(
    map_root: Path,
    staging_dir: Path,
    publish_dir: Path,
    map_files: list[Path],
    digest: str,
) -> list[dict[str, object]]:
    """Extract into `staging_dir`, addressing the handoff at `publish_dir`.

    The two directories differ: extraction writes into a private `.tmp-<uuid>`
    that is renamed to the content-addressed snapshot afterwards, so every path
    recorded for a later reader must name the post-rename location.
    """
    source_dir = staging_dir / "sources"
    source_dir.mkdir(parents=True)
    records: list[dict[str, object]] = []
    claimed_paths: dict[str, str] = {}

    for map_path in map_files:
        map_relative = map_path.relative_to(map_root).as_posix()
        map_dir_parts = PurePosixPath(map_relative).parent.parts
        try:
            payload = json.loads(map_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            records.append({
                "map_path": map_relative,
                "status": "malformed_map",
                "detail": str(exc)[:500],
            })
            continue

        payload_count = 0
        for section_name, section_payload in _map_payloads(payload):
            payload_count += 1
            sources = section_payload.get("sources")
            source_root = section_payload.get("sourceRoot", "")
            if not isinstance(sources, list):
                records.append({
                    "map_path": map_relative,
                    "section": section_name,
                    "status": "missing_sources",
                })
                continue
            content_values = section_payload.get("sourcesContent")
            if not isinstance(content_values, list):
                for source in sources:
                    records.append({
                        "map_path": map_relative,
                        "section": section_name,
                        "source": source if isinstance(source, str) else "",
                        "status": "missing_sources_content",
                    })
                continue

            for index, source in enumerate(sources):
                base_record: dict[str, object] = {
                    "map_path": map_relative,
                    "section": section_name,
                    "source": source if isinstance(source, str) else "",
                    "source_index": index,
                }
                relative = _safe_source_path(source_root, source, map_dir_parts)
                if relative is None:
                    records.append({**base_record, "status": "rejected_path"})
                    continue
                content = content_values[index] if index < len(content_values) else None
                if not isinstance(content, str):
                    records.append({**base_record, "status": "missing_content"})
                    continue

                content_bytes = content.encode("utf-8")
                content_hash = hashlib.sha256(content_bytes).hexdigest()
                output_relative = relative
                claimed_hash = claimed_paths.get(output_relative.as_posix())
                status = "extracted"
                if claimed_hash is not None:
                    if claimed_hash == content_hash:
                        records.append({
                            **base_record,
                            "status": "duplicate_identical",
                            "output_path": output_relative.as_posix(),
                            "content_sha256": content_hash,
                        })
                        continue
                    for hash_length in range(12, 65, 4):
                        output_relative = _collision_path(
                            relative, content_hash, hash_length
                        )
                        duplicate_hash = claimed_paths.get(output_relative.as_posix())
                        if duplicate_hash is None:
                            break
                        if duplicate_hash == content_hash:
                            records.append({
                                **base_record,
                                "status": "duplicate_identical",
                                "output_path": output_relative.as_posix(),
                                "content_sha256": content_hash,
                            })
                            break
                    if duplicate_hash == content_hash:
                        continue
                    status = "extracted_duplicate"

                output_path = source_dir.joinpath(*output_relative.parts)
                resolved_output = output_path.resolve()
                if source_dir.resolve() not in resolved_output.parents:
                    records.append({**base_record, "status": "rejected_path"})
                    continue
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(content_bytes)
                claimed_paths[output_relative.as_posix()] = content_hash
                records.append({
                    **base_record,
                    "status": status,
                    "output_path": output_relative.as_posix(),
                    "content_sha256": content_hash,
                })
        if payload_count == 0:
            records.append({"map_path": map_relative, "status": "malformed_map"})

    manifest: dict[str, object] = {
        "format_version": _SNAPSHOT_FORMAT_VERSION,
        "snapshot_sha256": digest,
        "map_root": str(map_root),
        "map_files": [path.relative_to(map_root).as_posix() for path in map_files],
        "policy": {
            "extracted_sources_are_source_equivalents": True,
            "ingest_extracted_tree_only": True,
            "mapped_minified_artifacts_are_non_covering": True,
            "publish_via_code_ingest_only": True,
        },
        "records": records,
    }
    # An empty extraction gets no handoff — in the manifest either, so a reader
    # that never sees the console cannot ingest an empty tree as if it were the
    # product's source.
    if _extracted_count(records):
        manifest["next_step"] = {
            "kind": "explicit_code_ingest",
            "command": _ingest_command(map_root, publish_dir),
            "repo_key": _repo_key(map_root),
            "repo_path": str(publish_dir / "sources"),
        }
    (staging_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return records


def _report_outcome(
    map_root: Path,
    snapshot_dir: Path,
    records: list[dict[str, object]],
    map_count: int,
) -> None:
    """Print the extraction census and either the handoff or a loud refusal.

    An extraction that produced nothing must not look like one that succeeded,
    and must never hand a downstream `code-ingest` an empty tree — that is what
    turns a visible failure into a durable "this product has no source".
    """
    census = _status_census(records) or "no source records"
    extracted = _extracted_count(records)
    if extracted == 0:
        print(
            f"Extracted 0 source file(s) from {map_count} source map(s): nothing to ingest.",
            file=sys.stderr,
        )
        print(f"Source-record census: {census}", file=sys.stderr)
        print(f"Snapshot (audit only): {snapshot_dir}", file=sys.stderr)
        print(f"Manifest: {snapshot_dir / 'manifest.json'}", file=sys.stderr)
        print(
            "No code-ingest handoff is emitted for an empty extraction; inspect "
            "the manifest's records[].source before re-running.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(
        f"Extracted {extracted} source file(s) from {map_count} source map(s) "
        f"into immutable snapshot: {snapshot_dir}"
    )
    print(f"Source-record census: {census}")
    print(f"Manifest: {snapshot_dir / 'manifest.json'}")
    print(f"Next step (not run automatically): {_ingest_command(map_root, snapshot_dir)}")


def run(args) -> None:
    map_root = Path(args.map_root).expanduser().resolve()
    if not map_root.is_dir():
        print(f"Source-map root not found: {map_root}", file=sys.stderr)
        raise SystemExit(1)
    map_files = _map_files(map_root)
    if not map_files:
        print(f"No .js.map/.css.map files found under {map_root}", file=sys.stderr)
        raise SystemExit(1)

    if args.output_root:
        output_root = Path(args.output_root).expanduser().resolve()
    else:
        engagement_root = Path(resolve_engagement_dir(args.engagement_dir))
        output_root = (
            engagement_root
            / "tools"
            / "analysis-state"
            / "source-maps"
            / map_root.name
        )
    output_root.mkdir(parents=True, exist_ok=True)
    digest = _snapshot_hash(map_root, map_files)
    snapshot_dir = output_root / digest
    if snapshot_dir.is_dir():
        print(f"Reused immutable source-map snapshot: {snapshot_dir}")
        manifest = json.loads((snapshot_dir / "manifest.json").read_text(encoding="utf-8"))
        # The handoff is recomposed from the snapshot's real location rather than
        # replayed from the manifest: manifests written before the staging-path
        # fix name a `.tmp-<uuid>` directory that no longer exists.
        records = manifest.get("records")
        _report_outcome(
            map_root,
            snapshot_dir,
            records if isinstance(records, list) else [],
            len(map_files),
        )
        return

    prior_snapshots = [
        path
        for path in output_root.iterdir()
        if path.is_dir() and not path.name.startswith(".tmp-")
    ]
    if prior_snapshots and not args.refresh:
        print(
            "Source-map inputs changed; use --refresh to create a new immutable snapshot",
            file=sys.stderr,
        )
        raise SystemExit(1)

    temporary = output_root / f".tmp-{uuid.uuid4()}"
    try:
        records = _extract_snapshot(map_root, temporary, snapshot_dir, map_files, digest)
        try:
            temporary.rename(snapshot_dir)
        except FileExistsError:
            shutil.rmtree(temporary)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    _report_outcome(map_root, snapshot_dir, records, len(map_files))
