"""vigil assess code-dependencies — derive the shipped/reachable dependency picture.

I/O only. Every decision lives in `assess.lib.dependency_manifests` (readers)
and `assess.lib.dependency_picture` (derivation); this module walks a sealed
source tree, hands bytes to those libs, and renders what comes back.
"""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path, PurePosixPath

from assess.lib import dependency_manifests as manifests
from assess.lib.code_snapshot import RootedSourceTree, SourceSnapshotRaceError
from assess.lib.dependency_picture import (
    IndexedFile,
    build_dependency_picture,
)

PICTURE_SCHEMA = "code-dependency-picture/v1"

# A dependency-declaring file is small; anything larger is not one we can read
# usefully and is reported as a gap rather than loaded into memory.
MAX_MANIFEST_BYTES = 8 * 1024 * 1024

# Walking a tree with a committed `node_modules/` can enumerate hundreds of
# thousands of paths. Both bounds exist so the command cannot be turned into an
# OOM by its own input; exceeding either is a reported gap, never a silently
# shorter picture.
MAX_INVENTORY_PATHS = 400_000
MAX_MANIFESTS = 2_000

# Manifests inside an installed module tree are that module's own build files,
# not this project's. What is installed there is already derived from the path
# inventory, so reading tens of thousands of them buys nothing.
_INSTALLED_MODULE_DIRS = frozenset({"node_modules"})

# Version-control metadata holds no build file and can be enormous.
_SKIP_DIRS = frozenset({".git", ".jj"})

# A large lockfile produces thousands of rows. The lead section is never capped
# -- that is the report's argument -- but the bulk tiers are, with the elision
# stated so a short section can never be mistaken for a small one.
SECTION_TEXT_LIMIT = 25

# The same discipline per row. A minified lockfile line can be megabytes and a
# widely used component can be imported from hundreds of files, so the TEXT
# render is bounded -- but the record is not (ADR 0019: the operator's own data
# is never withheld), every cap states what it left out, and `--json` prints the
# whole thing. A cut with no marker is the shape that lies.
EVIDENCE_CHAR_LIMIT = 400
REFERENCE_SITE_LIMIT = 5
EVIDENCE_LIMIT = 3

# Trivy and Grype each name ecosystems their own way; map only the unambiguous
# ones and leave the rest blank so correlation falls back to matching on the
# coordinate. A type is mapped to the ecosystem VIGIL's readers call it, not to
# a normalized family -- `dependency_picture` owns the fact that Maven and
# Gradle share one coordinate space.
_SCAN_ECOSYSTEMS: dict[str, str] = {
    "pom": "maven",
    "jar": "maven",
    "java-archive": "maven",
    "maven": "maven",
    "gradle": "gradle",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "node-pkg": "npm",
    "gomod": "go",
    "golang": "go",
    "go": "go",
    "go-module": "go",
    "pip": "python",
    "poetry": "python",
    "pipenv": "python",
    "python": "python",
    "python-pkg": "python",
}


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "code-dependencies",
        help=(
            "Derive what a sealed repository actually ships and what the "
            "reviewed code reaches, from its own manifests, lockfiles, build "
            "configuration and build output."
        ),
        description=(
            "Reads the dependency-declaring files inside a source tree and reports, per "
            "component, what the build says about shipping it and what the import index "
            "says about reaching it. Only a component that is both is a lead.\n\n"
            "Every value is an `unverified_*` OBSERVATION, never a verdict: build files do "
            "not settle what a built artifact contains. `unverified_no_reference_observed` "
            "means the declaring module's own index was read and nothing matched; "
            "`unverified_reachability_unindexed` means there was nothing to read for that "
            "module. Confirm against the real artifact before acting on an exclusion."
        ),
    )
    p.add_argument("repo_path", help="Path to the sealed source tree (or a repository root)")
    p.add_argument(
        "--structural-index",
        default=None,
        help=(
            "Path to a `code-index build` manifest.json. Without it every "
            "component is reported unverified_reachability_unindexed — never as "
            "unreferenced."
        ),
    )
    p.add_argument(
        "--scan-report",
        default=None,
        help=(
            "Optional secondary input: a Trivy/Grype JSON report to correlate "
            "against the source-derived picture. Rows that match a derived "
            "component are marked; rows that match nothing are reported as "
            "unmatched, and neither changes a shipment observation."
        ),
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the full picture as JSON.",
    )
    p.set_defaults(func=run)


def _read_tree(
    repo: Path,
) -> tuple[list[manifests.ManifestParse], list[str], list[manifests.AnalysisGap]]:
    parses: list[manifests.ManifestParse] = []
    present: list[str] = []
    gaps: list[manifests.AnalysisGap] = []
    inventory_truncated = False
    manifest_budget_exhausted = False
    with RootedSourceTree(repo) as tree:
        for listing in tree.walk():
            listing.directories[:] = [
                name for name in listing.directories if name not in _SKIP_DIRS
            ]
            for filename in listing.regular_files:
                rel = (
                    f"{listing.relative_dir}/{filename}"
                    if listing.relative_dir
                    else filename
                )
                if len(present) < MAX_INVENTORY_PATHS:
                    present.append(rel)
                elif not inventory_truncated:
                    inventory_truncated = True
                    gaps.append(
                        manifests.AnalysisGap(
                            path="",
                            gap="inventory_truncated",
                            detail=(
                                f"stopped inventorying paths at {MAX_INVENTORY_PATHS}; "
                                "vendored and packaged output beyond that point is not "
                                "in this picture"
                            ),
                        )
                    )
                kind = manifests.manifest_kind_for_path(rel)
                if kind is None:
                    continue
                if _INSTALLED_MODULE_DIRS & set(PurePosixPath(rel).parts[:-1]):
                    continue
                if len(parses) >= MAX_MANIFESTS:
                    if not manifest_budget_exhausted:
                        manifest_budget_exhausted = True
                        gaps.append(
                            manifests.AnalysisGap(
                                path=rel,
                                gap="manifest_budget_exhausted",
                                detail=(
                                    f"stopped reading manifests at {MAX_MANIFESTS}; the "
                                    "remaining ones are unread, not empty"
                                ),
                            )
                        )
                    continue
                captured = tree.capture(
                    rel, retain_spool=False, materialize_limit=MAX_MANIFEST_BYTES
                )
                try:
                    if captured.materialized is None:
                        gaps.append(
                            manifests.AnalysisGap(
                                path=rel,
                                gap="manifest_too_large",
                                detail=f"{captured.size} bytes exceeds {MAX_MANIFEST_BYTES}",
                            )
                        )
                        continue
                    text = captured.materialized.decode("utf-8", errors="replace")
                finally:
                    captured.close()
                parses.append(manifests.parse_manifest(kind, rel, text))
        tree.verify_root_identity()
    return parses, present, gaps


# A file the index could not hand us imports for. Deliberately not `complete`:
# only `complete` files count as "looked at", so an unreadable artifact can never
# become an empty import list that reads as "nothing here uses it".
UNREADABLE_INDEX_STATUS = "unreadable_index_artifact"


def _artifact_imports(artifact: Path) -> tuple[tuple[str, ...], str, str]:
    """One artifact's import list, or the gap that explains why there is none.

    The reason is the whole point. An empty `imports` left behind by a shape
    this loader does not recognize is indistinguishable downstream from a file
    that genuinely imports nothing, and one of those is a negative result while
    the other is a hole. `code-index` writes `imports` as a list of strings for
    every status it emits, so anything else is a truncated, foreign or older
    artifact and is reported rather than read.
    """
    try:
        record = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return (), "structural_index_artifact_unparseable", f"did not read as JSON ({exc})"
    if not isinstance(record, dict):
        return (
            (),
            "structural_index_artifact_malformed",
            f"top-level value is {type(record).__name__}, not an object",
        )
    raw = record.get("imports")
    if not isinstance(raw, list):
        named = type(raw).__name__ if "imports" in record else "absent"
        return (
            (),
            "structural_index_artifact_malformed",
            f"`imports` is {named}, not a list",
        )
    for item in raw:
        if not isinstance(item, str):
            return (
                (),
                "structural_index_artifact_malformed",
                f"`imports` holds {type(item).__name__} entries, not strings",
            )
    return tuple(raw), "", ""


def _load_structural_index(
    path: str | None,
) -> tuple[list[IndexedFile], list[manifests.AnalysisGap]]:
    """Load per-file import evidence from a `code-index build` generation.

    `files/` always sits beside `manifest.json` inside a generation directory,
    so an entry's artifact resolves by name against the manifest's own parent.

    A manifest this loader cannot read raises, because an unreadable inventory
    means nothing is known about what was indexed. One unreadable artifact
    inside a readable inventory is a hole in that one file instead: it becomes a
    gap and an unindexed file, and the rest of the picture survives.
    """
    if not path:
        return [], []
    manifest_path = Path(path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("structural index manifest is not an object")
    entries = manifest.get("files")
    if not isinstance(entries, dict):
        raise ValueError("structural index manifest has no file inventory")
    indexed: list[IndexedFile] = []
    gaps: list[manifests.AnalysisGap] = []
    for file_path, binding in sorted(entries.items()):
        if not isinstance(binding, dict):
            raise ValueError(f"structural index binding is not an object: {file_path}")
        index_name = PurePosixPath(str(binding.get("index_path") or "")).name
        status = str(binding.get("analysis_status") or "")
        imports: tuple[str, ...] = ()
        artifact = manifest_path.parent / "files" / index_name if index_name else None
        if artifact is None or not artifact.is_file():
            status = UNREADABLE_INDEX_STATUS
            gaps.append(
                manifests.AnalysisGap(
                    path=str(file_path),
                    gap="structural_index_artifact_missing",
                    detail=(
                        f"{index_name or '(no index_path)'} is named by the index "
                        "manifest but is not readable; this file counts as unindexed"
                    ),
                )
            )
        else:
            imports, gap, detail = _artifact_imports(artifact)
            if gap:
                status = UNREADABLE_INDEX_STATUS
                gaps.append(
                    manifests.AnalysisGap(
                        path=str(file_path),
                        gap=gap,
                        detail=(
                            f"{index_name} is named by the index manifest but "
                            f"{detail}; this file counts as unindexed"
                        ),
                    )
                )
        indexed.append(
            IndexedFile(
                path=str(file_path),
                language=str(binding.get("language") or ""),
                analysis_status=status,
                imports=imports,
            )
        )
    return indexed, gaps


def _load_scan_report(path: str | None) -> list[dict[str, str]]:
    """Normalize a Trivy or Grype JSON report into correlation rows."""

    if not path:
        return []
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("scan report is not an object")
    if "Results" not in report and "matches" not in report:
        raise ValueError(
            "unrecognized scan report: expected a Trivy `Results` or Grype `matches` key"
        )
    rows: list[dict[str, str]] = []
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            continue
        ecosystem = _SCAN_ECOSYSTEMS.get(str(result.get("Type") or "").lower(), "")
        source = str(result.get("Target") or "")
        for finding in result.get("Vulnerabilities") or []:
            if isinstance(finding, dict):
                rows.append(
                    {
                        "ecosystem": ecosystem,
                        "component": str(finding.get("PkgName") or ""),
                        "version": str(finding.get("InstalledVersion") or ""),
                        "source": source,
                    }
                )
    scanned_source = report.get("source")
    target = (
        str(scanned_source.get("target") or "") if isinstance(scanned_source, dict) else ""
    )
    for match in report.get("matches") or []:
        if not isinstance(match, dict):
            continue
        artifact = match.get("artifact")
        if not isinstance(artifact, dict):
            continue
        rows.append(
            {
                "ecosystem": _SCAN_ECOSYSTEMS.get(str(artifact.get("type") or "").lower(), ""),
                "component": str(artifact.get("name") or ""),
                "version": str(artifact.get("version") or ""),
                "source": target,
            }
        )
    # A scan with no rows is a clean scan, not a malformed file, so an empty
    # report is honoured rather than refused.
    return rows


# Section order is the report's argument: the intersection first, then the
# shipped-but-unconfirmed tiers, then everything the build says is not in the
# artifact. Each title names the observation it groups rather than restating it
# as a conclusion. Assignment is FIRST MATCH, so every observation lands in
# exactly one section and none can be dropped from the report.
#
# `unverified_present_without_declaration` counts as shipping for the lead tier:
# a vendored copy the reviewed code imports is the strongest lead in the set,
# precisely because nothing declares it and so nothing updates it.
_SHIPPING_OBSERVATIONS: tuple[str, ...] = (
    "unverified_ships_by_default_scope",
    "unverified_relocated_into_shaded_artifact",
    "unverified_present_without_declaration",
)

_LEAD_SECTION = "shipped_and_reachable"
_SECTIONS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        _LEAD_SECTION,
        "shipped and reachable",
        _SHIPPING_OBSERVATIONS,
        ("unverified_import_site_observed",),
    ),
    (
        "present_without_declaration",
        "present in the tree with no declaration",
        ("unverified_present_without_declaration",),
        (),
    ),
    (
        "shipped_no_reference_observed",
        "shipped, no reference observed in the index",
        _SHIPPING_OBSERVATIONS,
        ("unverified_no_reference_observed",),
    ),
    (
        "shipped_unindexed",
        "shipped, reachability never indexed",
        _SHIPPING_OBSERVATIONS,
        ("unverified_reachability_unindexed",),
    ),
    (
        "excluded_by_declared_scope",
        "excluded by declared scope",
        ("unverified_excluded_by_declared_scope",),
        (),
    ),
    (
        "expected_from_runtime",
        "expected from the runtime",
        ("unverified_expected_from_runtime",),
        (),
    ),
    (
        "undetermined",
        "shipment undetermined",
        ("unverified_shipment_undetermined",),
        (),
    ),
)


def _grouped(picture) -> list[tuple[str, str, list]]:
    """Assign every observation to the first section that claims it."""

    grouped: list[tuple[str, str, list]] = [
        (key, title, []) for key, title, _shipments, _reachabilities in _SECTIONS
    ]
    for observation in picture.observations:
        for index, (_key, _title, shipments, reachabilities) in enumerate(_SECTIONS):
            if observation.shipment_observation in shipments and (
                not reachabilities
                or observation.reachability_observation in reachabilities
            ):
                grouped[index][2].append(observation)
                break
    return grouped


def _elide(text: str) -> str:
    """Bound one quoted line to the report's width, saying what it left out."""

    if len(text) <= EVIDENCE_CHAR_LIMIT:
        return text
    hidden = len(text) - EVIDENCE_CHAR_LIMIT
    return (
        f"{text[:EVIDENCE_CHAR_LIMIT]} ... {hidden} more character(s) in this "
        "line; re-run with --json for the whole quote"
    )


def _print_elision(hidden: int, noun: str) -> None:
    if hidden > 0:
        print(
            f"      ... {hidden} more {noun} on this component; "
            "re-run with --json for all of them"
        )


def _print_observation(observation) -> None:
    location = f"  [{observation.module_path}]" if observation.module_path else ""
    version = observation.version or "(version unresolved)"
    print(f"  {observation.ecosystem} {observation.coordinate} {version}{location}")
    print(
        f"      shipment={observation.shipment_observation} "
        f"reachability={observation.reachability_observation} "
        f"origin={observation.observation_origin} detection={observation.detection}"
    )
    if observation.declared_scope:
        scope = observation.declared_scope
        if observation.declared_range:
            scope += f"  declared range {observation.declared_range}"
        print(f"      declared as: {scope}")
    for site in observation.reference_sites[:REFERENCE_SITE_LIMIT]:
        print(f"      reference: {site.path}  {site.raw_import}")
    _print_elision(len(observation.reference_sites) - REFERENCE_SITE_LIMIT, "reference site(s)")
    for citation in observation.evidence[:EVIDENCE_LIMIT]:
        print(f"      evidence: {citation.path}:{citation.line}  {_elide(citation.text)}")
    _print_elision(len(observation.evidence) - EVIDENCE_LIMIT, "citation(s)")
    if observation.qualifiers:
        print(f"      qualifiers: {', '.join(observation.qualifiers)}")
    if observation.declaration_notes:
        print(f"      declared notes: {', '.join(observation.declaration_notes)}")


def _print_text(picture, repo: Path) -> None:
    print(f"code-dependencies: {repo}")
    print(
        f"{len(picture.observations)} component observation(s) across "
        f"{len(picture.modules)} module(s); "
        f"ecosystems read: {', '.join(picture.ecosystems) or '(none)'}"
    )
    print(
        "Every value below is an observation derived from build files and an import "
        "index. Neither settles what the built artifact contains, so confirm against "
        "the artifact before relying on an exclusion."
    )
    for key, title, observations in _grouped(picture):
        print(f"\n## {title} ({len(observations)})")
        if not observations:
            print("  (none)")
            continue
        limit = (
            len(observations) if key == _LEAD_SECTION else min(len(observations), SECTION_TEXT_LIMIT)
        )
        for observation in observations[:limit]:
            _print_observation(observation)
        if limit < len(observations):
            print(
                f"  ... {len(observations) - limit} more in this section; "
                "re-run with --json for the complete picture"
            )
    print(f"\n## gaps in this picture ({len(picture.gaps)})")
    if not picture.gaps:
        print("  (none)")
    for gap in picture.gaps:
        location = f"{gap.path}: " if gap.path else ""
        print(f"  {location}{gap.gap}  {gap.detail}")


def run(args) -> None:
    repo = Path(args.repo_path)
    if not repo.is_dir():
        print(f"code-dependencies: repository path not found: {repo}", file=sys.stderr)
        sys.exit(1)
    try:
        indexed_files, index_gaps = _load_structural_index(
            getattr(args, "structural_index", None)
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"code-dependencies: cannot read structural index: {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        scan_rows = _load_scan_report(getattr(args, "scan_report", None))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"code-dependencies: cannot read scan report: {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        parses, present_paths, walk_gaps = _read_tree(repo)
    except (OSError, ValueError, SourceSnapshotRaceError) as exc:
        print(f"code-dependencies: cannot read source tree: {exc}", file=sys.stderr)
        sys.exit(1)

    picture = build_dependency_picture(
        parses=parses,
        present_paths=present_paths,
        indexed_files=indexed_files,
        scan_rows=scan_rows,
    )
    picture = dataclasses.replace(
        picture,
        gaps=tuple(
            sorted(
                list(picture.gaps) + walk_gaps + index_gaps,
                key=lambda gap: (gap.path, gap.gap, gap.detail),
            )
        ),
    )

    if getattr(args, "as_json", False):
        payload = {
            "schema": PICTURE_SCHEMA,
            "repo_path": str(repo),
            "ecosystems": list(picture.ecosystems),
            "modules": list(picture.modules),
            "counts": {key: len(rows) for key, _title, rows in _grouped(picture)},
            "observations": [
                dataclasses.asdict(observation) for observation in picture.observations
            ],
            "gaps": [dataclasses.asdict(gap) for gap in picture.gaps],
        }
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        _print_text(picture, repo)
    sys.stdout.flush()
