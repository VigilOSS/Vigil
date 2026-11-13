"""vigil assess code-coverage — display code analysis coverage and gate status."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import sys
from pathlib import Path
from urllib.parse import urlencode

# `code-dispatch` owns the lease vocabulary these verbs share; importing its age
# renderer keeps one reading of "silent for" across the queue table, this report
# projection, and the resume brief.
from assess.commands.code_dispatch import _format_lease_age
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.phases import CODE_PHASES, TERMINAL_PHASE
from assess.lib.treesitter_index import FUNCTION_SCOPED_DIMENSIONS

EFFORT_THRESHOLDS = {
    "critical": 70,
    "high": 50,
    "medium": 30,
}

READINESS_TARGETS = (
    "classify-map",
    "hunt",
    "verify-variant",
    "fuzz",
    "complete",
)

_STRUCTURAL_DEBT_PREVIEW_LIMIT = 10
# Advisory rows the default view lists before pointing at `--cwe-matrix`, and
# the example files it names per tier x family group.
_ADVISORY_PREVIEW_LIMIT = 10
_ADVISORY_FILES_PER_GROUP = 3
_TIER_ORDER = ("critical", "high", "medium", "low")
# The share of claimed `functions_analyzed` that structurally bound callables
# must reach before the matrix stops flagging the claim as thinly receipted.
_CALLABLE_RATIO_FLOOR = 0.3


def _coerce_effort(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _format_effort(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:g}"


def _is_not_applicable_cwe_entry(entry: dict) -> bool:
    if entry.get("not_applicable") is True:
        return True
    disposition = str(entry.get("disposition", entry.get("status", ""))).strip().lower()
    return disposition in {"not_applicable", "not-applicable", "n/a", "na"}


def register(subparsers) -> None:
    p = subparsers.add_parser("code-coverage", help="Display code analysis coverage summary")
    p.add_argument("--repo-id", default=None, help="Filter by repository ID")
    p.add_argument(
        "--require-gate-pass",
        action="store_true",
        help=(
            "Exit non-zero when self-reported CWE effort or coverage-integrity "
            "warnings remain; structural transition readiness is separate"
        ),
    )
    p.add_argument(
        "--require-transition-ready",
        choices=READINESS_TARGETS,
        metavar="TARGET_PHASE",
        help=(
            "Fetch backend readiness for the target code phase and exit non-zero "
            "when structural or lifecycle blockers remain"
        ),
    )
    p.add_argument(
        "--cwe-matrix",
        action="store_true",
        help="Display per-file CWE effort coverage matrix",
    )
    p.add_argument(
        "--debt-paths", action="store_true",
        help="List every path behind the next structural review debt gate",
    )
    p.add_argument(
        "--by-path",
        action="store_true",
        help=(
            "Break coverage down by directory: files, LOC, analyzed critical/high, "
            "status buckets, unreviewed structural debt and accounted skips"
        ),
    )
    p.add_argument(
        "--inherited-from", type=_positive_int, default=None, metavar="GENERATION",
        help=(
            "Read each current unanalyzed file whose source hash is unchanged "
            "since GENERATION together with the terminal verdict recorded then, "
            "labelled inherited with its origin generation. A read only: an "
            "inherited verdict satisfies no gate and makes no currency claim"
        ),
    )
    p.add_argument(
        "--depth", type=_positive_int, default=None,
        help="With --by-path: directory segments below the repository root to group by (default 2)",
    )
    p.add_argument(
        "--path-prefix", action="append", default=None, metavar="PATH",
        help=(
            "With --by-path or --inherited-from: only files at or under PATH, "
            "matched by whole segments and case-sensitively; repeatable"
        ),
    )
    p.add_argument(
        "--limit", type=_positive_int, default=None,
        help=(
            "With --by-path: directories per page (default 50). With "
            "--inherited-from: files per page"
        ),
    )
    p.add_argument(
        "--offset", type=_non_negative_int, default=None,
        help="With --by-path or --inherited-from: rows to skip",
    )
    p.add_argument(
        "--json", dest="as_json", action="store_true",
        help="With --by-path or --inherited-from: emit the backend page as JSON",
    )
    p.set_defaults(func=run)


def _positive_int(value: str) -> int:
    number = _non_negative_int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be an integer >= 1")
    return number


def _non_negative_int(value: str) -> int:
    if not value.isdigit():
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return int(value)


# Flags that shape a row-listing view rather than the default summary, each with
# the views that honour it. One table, because the flag surface and the refusal
# that polices it are the same fact: a flag listed for a view the endpoint does
# not accept is an unreachable option, and one withheld from a view the endpoint
# DOES accept is a read an operator cannot narrow. `code/coverage/inherited`
# takes path_prefix, limit and offset exactly as `code/coverage/by-path` does;
# --depth groups directories, which only the by-path projection has rows for.
_VIEW_ONLY_OPTIONS = (
    ("depth", "--depth", ("--by-path",)),
    ("path_prefix", "--path-prefix", ("--by-path", "--inherited-from")),
    ("limit", "--limit", ("--by-path", "--inherited-from")),
    ("offset", "--offset", ("--by-path", "--inherited-from")),
    ("as_json", "--json", ("--by-path", "--inherited-from")),
)
_BY_PATH_EXCLUSIVE_OPTIONS = (
    ("cwe_matrix", "--cwe-matrix"),
    ("require_gate_pass", "--require-gate-pass"),
    ("require_transition_ready", "--require-transition-ready"),
    ("debt_paths", "--debt-paths"),
    ("inherited_from", "--inherited-from"),
)
# `--inherited-from` is its own read against a prior generation, so it cannot
# be combined with a view that reports the CURRENT one: one output carrying
# both would be exactly the currency claim this read must never make.
_INHERITED_EXCLUSIVE_OPTIONS = (
    ("by_path", "--by-path"),
    ("cwe_matrix", "--cwe-matrix"),
    ("require_gate_pass", "--require-gate-pass"),
    ("require_transition_ready", "--require-transition-ready"),
    ("debt_paths", "--debt-paths"),
)


def _refuse_misplaced_by_path_options(args) -> None:
    if getattr(args, "inherited_from", None) is not None:
        conflicts = [
            flag
            for field, flag in _INHERITED_EXCLUSIVE_OPTIONS
            if getattr(args, field, None)
        ]
        conflicts += [
            flag
            for field, flag, views in _VIEW_ONLY_OPTIONS
            if "--inherited-from" not in views
            and getattr(args, field, None) is not None
        ]
        if conflicts:
            print(
                "ERROR: --inherited-from is its own read of a prior generation and "
                f"cannot combine with {', '.join(conflicts)}",
                file=sys.stderr,
            )
            raise SystemExit(2)
        return
    if getattr(args, "by_path", False):
        conflicts = [flag for field, flag in _BY_PATH_EXCLUSIVE_OPTIONS if getattr(args, field, None)]
        if conflicts:
            print(
                f"ERROR: --by-path is its own view and cannot combine with {', '.join(conflicts)}",
                file=sys.stderr,
            )
            raise SystemExit(2)
        return
    misplaced = [
        f"{flag} requires {' or '.join(views)}"
        for field, flag, views in _VIEW_ONLY_OPTIONS
        if getattr(args, field, None) not in (None, False)
    ]
    if misplaced:
        print(f"ERROR: {'; '.join(misplaced)}", file=sys.stderr)
        raise SystemExit(2)


def _by_path_endpoint(args) -> str:
    query: list[tuple[str, object]] = []
    if getattr(args, "repo_id", None):
        query.append(("repo_id", args.repo_id))
    if getattr(args, "depth", None) is not None:
        query.append(("depth", args.depth))
    for prefix in sorted(set(getattr(args, "path_prefix", None) or [])):
        query.append(("path_prefix", prefix))
    if getattr(args, "limit", None) is not None:
        query.append(("limit", args.limit))
    if getattr(args, "offset", None) is not None:
        query.append(("offset", args.offset))
    return "code/coverage/by-path" + (f"?{urlencode(query)}" if query else "")


def _run_by_path(cfg, args) -> None:
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(_by_path_endpoint(args))
    if getattr(args, "as_json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    if not isinstance(result, dict):
        print("Backend returned a non-object coverage-by-path page", file=sys.stderr)
        raise SystemExit(1)
    _print_coverage_by_path(result)


def _inherited_endpoint(args) -> str:
    query: list[tuple[str, object]] = [("generation", args.inherited_from)]
    if getattr(args, "repo_id", None):
        query.append(("repo_id", args.repo_id))
    # Deduplicated and ordered exactly as `_by_path_endpoint` does it, so the
    # same scope spelled twice is one query the backend can cache-compare.
    for prefix in sorted(set(getattr(args, "path_prefix", None) or [])):
        query.append(("path_prefix", prefix))
    if getattr(args, "limit", None) is not None:
        query.append(("limit", args.limit))
    if getattr(args, "offset", None) is not None:
        query.append(("offset", args.offset))
    return "code/coverage/inherited?" + urlencode(query)


def _run_inherited(cfg, args) -> None:
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(_inherited_endpoint(args))
    if getattr(args, "as_json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    if not isinstance(result, dict):
        print("Backend returned a non-object inherited-coverage page", file=sys.stderr)
        raise SystemExit(1)
    _print_inherited_coverage(result, requested_generation=args.inherited_from)


def _print_inherited_coverage(result: dict, *, requested_generation: int) -> None:
    """Show the prior verdict each unchanged file already has, as a read only.

    A generation change supersedes every receipt repo-wide, so a re-ingest that
    touched one file reads as zero coverage for all of them. This names what
    was already reviewed and still byte-identical — the shortest honest route
    back to the work that matters. It deliberately does not carry that verdict
    forward: coverage, the gate and readiness all read the active generation,
    and a label that satisfied them would be a silent currency claim.
    """
    rows = [row for row in (result.get("files") or []) if isinstance(row, dict)]
    origin = result.get("origin_generation", requested_generation)
    active = result.get("active_generation", "?")
    offset = int(result.get("offset", 0) or 0)
    print(
        f"=== Inherited Coverage from generation {origin} "
        f"(active generation {active}; {len(rows)} of "
        f"{result.get('total', len(rows))} files, offset {offset}) ==="
    )
    print(
        "Each row is a file whose source hash is unchanged since that "
        "generation and whose most recent terminal result from it is shown as "
        "`inherited`. This is a read: an inherited verdict is NOT current, "
        "does not satisfy the coverage gate or phase readiness, and the file "
        "still owes a current attempt."
    )
    if not rows:
        print("No unchanged file carries a terminal result from that generation.")
        return
    print(
        f"{'FILE_ID':>8}  {'CLASS':<10}  {'INHERITED':<12}  {'FROM':>5}  "
        f"{'RECORDED':<22}  {'REPO':<16}  PATH"
    )
    for row in rows:
        # With several repositories in scope a path alone does not identify the
        # file, and re-queueing is a per-repository decision.
        repo = str(row.get("repo_key") or row.get("repo_id") or "")
        print(
            f"{row.get('file_id', '?')!s:>8}  "
            f"{str(row.get('classification', '')):<10}  "
            f"{str(row.get('disposition', '')):<12}  "
            f"{row.get('origin_generation', origin)!s:>5}  "
            f"{str(row.get('recorded_at') or ''):<22}  "
            f"{repo:<16}  {row.get('file_path', '')}"
        )
    if result.get("has_more"):
        print(f"\nMore files: re-run with --offset {offset + len(rows)}")
    print(
        "\nRe-review each file that still matters with `vigil assess "
        "code-dispatch queue` (or `reanalyze` where a current attempt exists); "
        "`code-coverage --by-path` shows where the uncovered ones are."
    )


def _tier_cell(row: dict, tier: str) -> str:
    counts = (row.get("by_classification") or {}).get(tier) or {}
    return f"{counts.get('analyzed', 0)}/{counts.get('count', 0)}"


def _print_coverage_by_path(result: dict) -> None:
    rows = [row for row in (result.get("directories") or []) if isinstance(row, dict)]
    offset = int(result.get("offset", 0) or 0)
    print(
        f"=== Coverage by Path (depth {result.get('depth', '?')}; "
        f"{len(rows)} of {result.get('total', len(rows))} directories, offset {offset}) ==="
    )
    if not rows:
        print("No admitted analysis-repository files matched.")
        return
    print(
        f"{'UNCOV':>5}  {'CRIT':>7}  {'HIGH':>7}  {'FILES':>6}  {'LOC':>8}  "
        f"{'DONE':>5}  {'QUEUED':>6}  {'ACTIVE':>6}  {'NCTX':>5}  {'CLSF':>5}  {'PEND':>5}  "
        f"{'DEBT':>5}  {'SKIPS':>5}  {'DEEP':>5}  {'CHWIDE':>6}  {'REPO':<16}  PATH"
    )
    for row in rows:
        statuses = row.get("by_status") or {}
        debt = row.get("structural_debt") or {}
        review_depth = row.get("by_review_depth") or {}
        print(
            f"{row.get('uncovered_critical_high', 0)!s:>5}  "
            f"{_tier_cell(row, 'critical'):>7}  {_tier_cell(row, 'high'):>7}  "
            f"{row.get('files', 0)!s:>6}  {row.get('loc', 0)!s:>8}  "
            f"{statuses.get('analyzed', 0)!s:>5}  {statuses.get('queued', 0)!s:>6}  "
            f"{statuses.get('in_progress', 0)!s:>6}  {statuses.get('needs_context', 0)!s:>5}  "
            f"{statuses.get('classified', 0)!s:>5}  {statuses.get('pending', 0)!s:>5}  "
            f"{debt.get('count', 0)!s:>5}  {row.get('accounted_skips', 0)!s:>5}  "
            f"{review_depth.get('deep', 0)!s:>5}  {row.get('critical_high_wide_only', 0)!s:>6}  "
            f"{str(row.get('repo_key', '')):<16}  {row.get('path', '')}"
        )
    print(
        "\nUNCOV = critical+high files without a successful review; CRIT/HIGH = analyzed/total. "
        "DONE..PEND are the summary's analysis-status buckets (analyzed, queued, in progress, "
        "needs context, classified, pending). DEBT = degraded/unsupported/truncated "
        "structural analysis with no successful review; SKIPS = accounted skips. "
        "DEEP = files with a deep pass (a reanalysis, a deep-manual dispatch, or a "
        "`hunt_scope: deep` packet); CHWIDE = critical+high files reviewed by wide "
        "passes only. Depth points at where to go deeper; it is not coverage."
    )
    _print_dispositions_by_path(rows)
    if result.get("has_more"):
        print(f"More directories: re-run with --offset {offset + len(rows)}")


def _print_dispositions_by_path(rows: list[dict]) -> None:
    """Report what the reviews in each directory actually concluded.

    The status census says a directory was reviewed; it does not say whether
    the reviews found anything. Without this, choosing where the next wave
    goes means reading two `code-dispatch list` dumps to recover information
    the coverage page already holds.
    """
    counted = [
        (row, row.get("by_disposition"))
        for row in rows
        if isinstance(row.get("by_disposition"), dict) and row["by_disposition"]
    ]
    if not counted:
        return
    print("\nBy Disposition (what the completed reviews concluded):")
    for row, dispositions in counted:
        census = ", ".join(
            f"{name}={dispositions[name]}" for name in sorted(dispositions)
        )
        print(f"  {row.get('path', '?')}: {census}")


def _next_code_gate(engagement_dir: str) -> str | None:
    scope_path = Path(engagement_dir) / "scope.json"
    if not scope_path.is_file():
        return None
    try:
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(scope, dict):
        return None
    from assess.lib.tracks import track_phases

    current = track_phases(scope).get("code")
    if current is None:
        return None
    if current == TERMINAL_PHASE:
        return None
    if current not in CODE_PHASES:
        return None
    index = CODE_PHASES.index(current)
    return (*CODE_PHASES, TERMINAL_PHASE)[index + 1]


def _debt_counts(readiness: dict) -> tuple[Counter, Counter, Counter]:
    classifications: Counter = Counter()
    statuses: Counter = Counter()
    truncated: Counter = Counter()
    for item in readiness.get("structural_debt", []):
        if not isinstance(item, dict):
            continue
        classifications[str(item.get("classification") or "unclassified")] += 1
        statuses[str(item.get("structural_analysis_status") or "unknown")] += 1
        if item.get("structural_artifact_truncated") is True:
            truncated["truncated"] += 1
    return classifications, statuses, truncated


def _print_debt_summary(readiness: dict, *, show_all: bool) -> None:
    debt = readiness.get("structural_debt")
    if not isinstance(debt, list):
        return
    count = readiness.get("structural_debt_count", len(debt))
    classifications, statuses, truncated = _debt_counts(readiness)
    class_text = ", ".join(
        f"{name}={classifications[name]}" for name in sorted(classifications)
    ) or "none"
    status_text = ", ".join(
        f"{name}={statuses[name]}" for name in sorted(statuses)
    ) or "none"
    print(f"  debt by classification: {class_text}")
    print(f"  debt by structural status: {status_text}; truncated={truncated['truncated']}")
    limit = len(debt) if show_all else _STRUCTURAL_DEBT_PREVIEW_LIMIT
    shown = debt[:limit]
    if shown:
        if len(debt) > len(shown):
            print(f"  debt files (showing {len(shown)} of {count}; use --debt-paths for all):")
        else:
            print("  debt files:")
        for item in shown:
            if not isinstance(item, dict):
                continue
            print(
                f"    repo {item.get('repo_id', '?')}: {item.get('file_path', '?')} "
                f"classification={item.get('classification') or 'unclassified'} "
                f"structural={item.get('structural_analysis_status') or 'unknown'}"
                f"{' truncated' if item.get('structural_artifact_truncated') is True else ''}"
            )


def _print_next_gate(target: str, readiness: dict, *, debt_paths: bool) -> None:
    ready = readiness.get("target_phase") == target and readiness.get("transition_ready") is True
    print(f"\nNext hard gate ({target}): {'READY' if ready else 'BLOCKED'}")
    blockers = readiness.get("blockers")
    if isinstance(blockers, list) and blockers:
        codes = [str(item.get("code")) for item in blockers if isinstance(item, dict)]
        print(f"  blockers: {', '.join(codes[:3])}" + (f" +{len(codes) - 3} more" if len(codes) > 3 else ""))
    debt_count = readiness.get("structural_debt_count")
    if isinstance(debt_count, int):
        print(f"  structural debt: {debt_count} file(s)")
    _print_debt_summary(readiness, show_all=debt_paths)
    print(f"  full gate: vigil assess code-coverage --require-transition-ready {target}")


def _readiness_endpoint(target: str, *, include_coverage: bool = False) -> str:
    endpoint = f"code/readiness?target_phase={target}&include_debt_paths=true"
    return endpoint + "&include_coverage=true" if include_coverage else endpoint


def _repo_scoped_debt(readiness: dict, repo_id: object) -> dict:
    """The readiness payload with `structural_debt` narrowed to one repository.

    Debt rows carry their `repo_id`; the count in the coverage table must
    describe the same repository as the rest of that table.
    """
    debt = readiness.get("structural_debt")
    if not isinstance(debt, list):
        return readiness
    return {
        **readiness,
        "structural_debt": [
            item for item in debt
            if isinstance(item, dict) and str(item.get("repo_id")) == str(repo_id)
        ],
    }


def _print_engagement_wide_readiness_note(repo_id: object) -> None:
    print(
        f"\nNOTE: --repo-id {repo_id} scopes the coverage table above. Phase "
        "readiness is engagement-wide by design — a phase advances for the whole "
        "engagement — so the gate, blockers and structural debt below cover every "
        "analysis repository."
    )


def run(args) -> None:
    _refuse_misplaced_by_path_options(args)
    cfg = load_config(args.engagement_dir)
    if getattr(args, "inherited_from", None) is not None:
        _run_inherited(cfg, args)
        return
    if getattr(args, "by_path", False):
        _run_by_path(cfg, args)
        return
    readiness_target = getattr(args, 'require_transition_ready', None)
    next_target = None if readiness_target else _next_code_gate(
        getattr(cfg, "engagement_dir", getattr(args, "engagement_dir", ""))
    )

    if getattr(args, 'cwe_matrix', False):
        quality_passed, reported_quality = _run_cwe_matrix(cfg, args)
        failed = bool(getattr(args, 'require_gate_pass', False) and not quality_passed)
        if readiness_target:
            with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
                readiness = client.get(_readiness_endpoint(readiness_target))
            if not isinstance(readiness, dict):
                print(
                    f"Transition Readiness ({readiness_target}): UNKNOWN\n"
                    "  - [invalid_code_readiness] Backend returned a non-object response"
                )
                failed = True
            else:
                if args.repo_id:
                    _print_engagement_wide_readiness_note(args.repo_id)
                _print_transition_readiness(
                    readiness_target, readiness,
                    debt_paths=bool(getattr(args, "debt_paths", False)),
                    reported_quality=reported_quality,
                )
                if (
                    readiness.get('target_phase') != readiness_target
                    or readiness.get('transition_ready') is not True
                ):
                    failed = True
        if failed:
            sys.exit(1)
        return

    repo_id = args.repo_id
    readiness_phase = readiness_target or next_target
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if readiness_phase and not repo_id:
            # Readiness gates on the engagement-wide summary, so one read
            # returns both instead of computing the summary twice.
            readiness = client.get(
                _readiness_endpoint(readiness_phase, include_coverage=True)
            )
            result = readiness.get("coverage") if isinstance(readiness, dict) else None
            if not isinstance(result, dict):
                print(
                    "Backend returned a readiness payload without its coverage summary",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            result = client.get(
                f'code/coverage?repo_id={repo_id}' if repo_id else 'code/coverage'
            )
            readiness = (
                client.get(_readiness_endpoint(readiness_phase))
                if readiness_phase
                else None
            )

    if not isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if getattr(args, 'require_gate_pass', False) or readiness_target:
            sys.exit(1)
        return

    table_debt = readiness if not repo_id or not isinstance(readiness, dict) else (
        _repo_scoped_debt(readiness, repo_id)
    )
    _print_coverage(
        result,
        structural_debt_by_classification=(
            _debt_counts(table_debt)[0] if isinstance(table_debt, dict) else Counter()
        ),
        include_review_quality=False,
    )
    _print_vuln_class_summary(result)
    if repo_id and readiness is not None:
        _print_engagement_wide_readiness_note(repo_id)
    if next_target:
        if isinstance(readiness, dict):
            _print_next_gate(
                next_target, readiness, debt_paths=bool(getattr(args, "debt_paths", False))
            )
        else:
            print(f"\nNext hard gate ({next_target}): UNKNOWN")

    failed = False
    if getattr(args, 'require_gate_pass', False):
        quality_passed, _ = _review_quality(result)
        if not quality_passed:
            failed = True

    if readiness_target:
        if not isinstance(readiness, dict):
            print(
                f"Transition Readiness ({readiness_target}): UNKNOWN\n"
                "  - [invalid_code_readiness] Backend returned a non-object response"
            )
            failed = True
        else:
            _print_transition_readiness(
                readiness_target, readiness,
                debt_paths=bool(getattr(args, "debt_paths", False)),
                reported_quality=_review_quality(result)[1],
            )
            if (
                readiness.get('target_phase') != readiness_target
                or readiness.get('transition_ready') is not True
            ):
                failed = True

    _print_review_quality(result, full=False)
    _print_depth_advisories(result, full=False)
    _print_context_tags_unrecorded(result)
    _print_client_bundle_advisories(result)
    _print_untriggered_depth_shortfalls(result)
    print()

    if failed:
        sys.exit(1)


def _repo_selector(repo_id: object) -> str:
    return f"--repo-id {repo_id}" if repo_id not in (None, '') else "--repo-id <repo-id>"


# The repair verb for each integrity blocker an operator can actually clear.
# Without these the blocker reads as "no repair path exists" and the operator
# reaches for a re-ingest, which advances the generation and invalidates every
# generation-bound review, index, and threat model.
_BLOCKER_REPAIRS = {
    'structural_index_stale': lambda repo_id: (
        f"vigil assess code-index build <snapshot-dir>/source {_repo_selector(repo_id)} "
        f"then vigil assess code-index sync {_repo_selector(repo_id)} "
        "(rebinds the existing generation; neither advances it)"
    ),
    'structural_index_metadata_incomplete': lambda repo_id: (
        f"vigil assess code-index build <snapshot-dir>/source {_repo_selector(repo_id)} "
        f"then vigil assess code-index sync {_repo_selector(repo_id)} "
        "(rebinds the existing generation; neither advances it)"
    ),
    'threat_model_stale': lambda repo_id: (
        "vigil assess code-record threat-model for the current generation"
    ),
    'admitted_files_unqueued': lambda repo_id: (
        "vigil assess code-dispatch queue <queue-items-json-file> — one row per "
        "admitted file, including skip-tier; "
        f"vigil assess code-dispatch list {_repo_selector(repo_id)} shows what is "
        "already loaded. If this repository is host/framework source nobody is "
        "reviewing, re-ingest it with --role reference instead: it stays indexed "
        "and citable and stops owing coverage"
    ),
    'source_snapshot_unverified': lambda repo_id: (
        "vigil assess code-ingest <repo-path> --repo-key <key> — a verified "
        "re-ingest, which advances the generation by design"
    ),
    'code_leads_unresolved': lambda repo_id: (
        # The blocker counts every binding whose note is open OR in_progress and
        # does not exclude stale ones, so a narrower read dead-ends the operator
        # on a gate that is still firing.
        f"`vigil assess code-lead list {_repo_selector(repo_id)} --include-superseded` "
        "shows each unanswered prior-art lead and where it points; "
        "`vigil assess code-lead queue` turns any bound file with no queue row "
        "into analysis work. Close each lead on the note itself: `vigil assess "
        "intel update note <lead-id> --inline '{\"lead_status\": \"ruled_out\"}'` "
        "(or resolved when it led to a finding)"
    ),
}


def _print_transition_readiness(
    target_phase: str,
    readiness: dict,
    *,
    debt_paths: bool = False,
    reported_quality: list[str] | None = None,
) -> None:
    """Render one readiness payload.

    *reported_quality* holds the review-quality warnings this invocation
    renders under "Review Quality"; readiness repeats them in
    `quality_gate.warnings`, so only the remainder is listed here.
    """
    bound_target = readiness.get('target_phase')
    ready = bound_target == target_phase and readiness.get('transition_ready') is True
    print(f"Transition Readiness ({target_phase}): {'READY' if ready else 'BLOCKED'}")

    blockers = readiness.get('blockers', [])
    if isinstance(blockers, list):
        for blocker in blockers:
            if not isinstance(blocker, dict):
                continue
            code = blocker.get('code', 'unknown')
            message = blocker.get('message', 'Unnamed readiness blocker')
            integrity = " [integrity; non-overrideable]" if blocker.get('overrideable') is False else ""
            # With several repos in scope, a blocker without its repo_id names
            # no repair target.
            repo_id = blocker.get('repo_id')
            scope = f" (repo {repo_id})" if repo_id not in (None, '') else ""
            print(f"  - [{code}]{scope} {message}{integrity}")
            sample = blocker.get('sample_paths')
            if isinstance(sample, list) and sample:
                omitted = blocker.get('omitted') or 0
                print(
                    "      files: " + ", ".join(str(path) for path in sample)
                    + (f" (+{omitted} more)" if omitted else "")
                )
                if blocker.get('full_list'):
                    print(f"      every file: {blocker['full_list']}")
            repair = _BLOCKER_REPAIRS.get(str(code))
            if repair:
                print(f"      repair: {repair(repo_id)}")

    quality = readiness.get('quality_gate')
    if isinstance(quality, dict):
        warnings = quality.get('warnings', [])
        quality_passed = quality.get('passed') is True
        already = set(reported_quality or [])
        # Review Quality has already shown the effort shortfalls (as groups, or
        # per file under --cwe-matrix), so readiness's copy of them, which
        # `quality_gate.effort_gap_warnings` names, is skipped in either wording.
        gap_lines = (
            {str(line) for line in quality.get('effort_gap_warnings') or []}
            if reported_quality is not None else set()
        )
        remaining = [
            str(warning) for warning in warnings
            if str(warning) not in already and str(warning) not in gap_lines
        ] if isinstance(warnings, list) else []
        if not quality_passed or remaining:
            print(
                "Readiness Advisories: "
                f"{'PASS' if quality_passed else 'NEEDS ATTENTION'}"
                + (
                    f" ({len(already)} review-quality advisory(ies) listed under Review Quality)"
                    if already and not quality_passed
                    else ""
                )
            )
            for warning in remaining[:_ADVISORY_PREVIEW_LIMIT]:
                print(f"  - {warning}")
            if len(remaining) > _ADVISORY_PREVIEW_LIMIT:
                print(
                    f"  ... +{len(remaining) - _ADVISORY_PREVIEW_LIMIT} more; "
                    "full list: vigil assess code-coverage --cwe-matrix"
                )
    _print_debt_summary(readiness, show_all=debt_paths)
    print()


def _run_cwe_matrix(cfg, args) -> tuple[bool, list[str]]:
    """Display the per-file CWE effort matrix; return its quality verdict and warnings."""
    endpoint = 'code/coverage?detail=cwe'
    if args.repo_id:
        endpoint = f'code/coverage?detail=cwe&repo_id={args.repo_id}'

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(endpoint)

    if not isinstance(result, dict):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return False, []

    files = result.get('files', [])
    if not files:
        print("NOTE: No CWE coverage data available from backend.\n")
        _print_coverage(result)
        return _review_quality(result)

    _print_cwe_matrix(files)
    _print_open_leases(result)
    _print_review_quality(result, full=True)
    _print_depth_advisories(result, full=True)
    _print_context_tags_unrecorded(result)
    _print_client_bundle_advisories(result)
    _print_untriggered_depth_shortfalls(result)
    return _review_quality(result)


def _print_cwe_matrix(files: list[dict]) -> None:
    """Print the per-file CWE effort matrix table."""
    all_families: list[str] = []
    seen: set[str] = set()
    for f in files:
        for fam in f.get('applicable_families', []):
            if fam and fam not in seen:
                all_families.append(fam)
                seen.add(fam)
    for f in files:
        for cwe in f.get('cwe_coverage', []):
            fam = cwe.get('family', '')
            if fam and fam not in seen:
                all_families.append(fam)
                seen.add(fam)

    if not all_families:
        print("NOTE: No CWE effort data found in coverage response.\n")
        return

    col_width = 11
    headers = [fam[:col_width] for fam in all_families]

    name_width = 28
    struct_width = 22
    print("=== CWE Coverage Matrix ===")
    header_line = f"{'File':<{name_width}} {'Funcs/EP/Sinks':^{struct_width}}"
    for h in headers:
        header_line += f" | {h:^{col_width}}"
    print(header_line)
    print("-" * len(header_line))

    for f in files:
        classification = f.get('classification', '')
        file_path = f.get('file_path', f.get('file_name', '?'))
        display_name = file_path.rsplit('/', 1)[-1] if '/' in file_path else file_path
        if classification:
            abbr = classification[:4]
            display_name = f"{display_name} ({abbr})"
        display_name = display_name[:name_width]

        effort_map: dict[str, float] = {}
        not_applicable: set[str] = set()
        for cwe in f.get('cwe_coverage', []):
            fam = cwe.get('family', '')
            if _is_not_applicable_cwe_entry(cwe):
                not_applicable.add(fam)
                continue
            effort_map[fam] = _coerce_effort(cwe.get('effort', 0))

        applicable = f.get('applicable_families', set())
        if isinstance(applicable, list):
            applicable = set(applicable)

        threshold = EFFORT_THRESHOLDS.get(classification, 0)

        total_funcs = f.get('total_functions', 0)
        total_ep = f.get('total_entry_points', 0)
        total_sinks = f.get('total_sinks', 0)
        has_structural = total_funcs or total_ep or total_sinks
        struct_cell = f"{total_funcs}/{total_ep}/{total_sinks}" if has_structural else "--"

        row = f"{display_name:<{name_width}} {struct_cell:^{struct_width}}"
        for fam in all_families:
            if applicable and fam not in applicable:
                cell = "--"
            elif fam in not_applicable:
                cell = "N/A"
            elif fam in effort_map:
                val = effort_map[fam]
                marker = "!" if threshold > 0 and val < threshold else ""
                cell = f"{_format_effort(val)}{marker}"
            else:
                cell = "0!" if threshold > 0 else "0"
            row += f" | {cell:^{col_width}}"
        print(row)

    _print_path_hints(files)
    _print_structural_verification(files)
    _print_review_depth(files)
    print()


def _print_review_depth(files: list[dict]) -> None:
    """Name each matrix file's review depth; deep files are only counted.

    Effort numbers say how hard a pass looked, not whether any pass went
    deep. The backend derives depth from the queue alone, so this is where a
    wide-only file with a full effort row shows as still wide.
    """
    depths = [
        (f, f.get('review_depth')) for f in files if isinstance(f.get('review_depth'), dict)
    ]
    if not depths:
        return
    census = Counter(str(depth.get('depth', 'none')) for _f, depth in depths)
    print(
        "\nReview Depth (pointer, not coverage): "
        + " ".join(f"{name}={census.get(name, 0)}" for name in ('deep', 'wide_only', 'none'))
    )
    for f, depth in depths:
        label = str(depth.get('depth', 'none'))
        if label == 'deep':
            continue
        print(
            f"  {f.get('file_path', '?')} ({f.get('classification', '?')}): {label} — "
            f"{depth.get('passes', 0)} pass(es), {depth.get('deep_passes', 0)} deep, "
            f"{depth.get('dispatches', 0)} dispatch(es), "
            f"{depth.get('signal_passes', 0)} with signal"
        )


def _print_path_hints(files: list[dict]) -> None:
    """List the families each file's path or unread markup suggests, and the
    ones its client-bundle tag makes optional, apart from the owed columns.

    A path word points at a family worth considering; only the architect's
    context tag makes it required. A markup file whose index fell back to a streaming read
    could not rule out code, so the code families point at it too. A
    `client-bundle` file owes no server-only family, and any effort recorded on
    one is shown. None carries a threshold flag.
    """
    _print_family_hints(
        files, "path_suggested_families",
        "Path Hints (advisory; a context tag makes them required)",
    )
    _print_family_hints(
        files, "unread_code_suggested_families",
        "Unread Code Hints (advisory; a streaming-fallback index could not rule them out)",
    )
    _print_family_hints(
        files, "optional_families",
        "Optional Families (server-only families a client-bundle tag makes optional)",
    )


def _print_family_hints(files: list[dict], key: str, title: str) -> None:
    rows: list[str] = []
    for f in files:
        hints = f.get(key) or []
        if not hints:
            continue
        efforts = {
            cwe.get('family', ''): cwe
            for cwe in f.get('cwe_coverage', [])
            if isinstance(cwe, dict)
        }
        cells = []
        for fam in hints:
            entry = efforts.get(fam)
            if entry is None:
                cells.append(fam)
            elif _is_not_applicable_cwe_entry(entry):
                cells.append(f"{fam} N/A")
            else:
                cells.append(f"{fam} {_format_effort(_coerce_effort(entry.get('effort', 0)))}")
        rows.append(
            f"  {f.get('file_path', '?')} ({f.get('classification', '')}): {', '.join(cells)}"
        )
    if not rows:
        return
    print(f"\n--- {title} ---")
    for row in rows:
        print(row)


def _unscanned_structural_scope(file_row: dict) -> bool:
    """Whether the index declares this file's function-scoped readers unmeasured.

    `FUNCTION_SCOPED_DIMENSIONS` is imported rather than restated: the indexer
    that publishes the list owns what belongs in it.
    """
    unavailable = file_row.get('structural_unavailable_dimensions') or []
    return bool(set(unavailable) & FUNCTION_SCOPED_DIMENSIONS)


def _print_structural_verification(files: list[dict]) -> None:
    """Cross-check analysed functions against the index, and name what it never read.

    The count check only means anything where there are functions to count, so
    a file whose scan scope covered no source is reported on its own terms
    instead of falling through the comparison into the all-clear.
    """
    unscanned = [f for f in files if _unscanned_structural_scope(f)]
    has_structural = any(f.get('total_functions', 0) > 0 for f in files)
    if not has_structural and not unscanned:
        return

    print("\n--- Structural Verification ---")
    gaps: list[str] = []
    for f in files:
        total_funcs = f.get('total_functions', 0)
        if total_funcs == 0:
            continue

        funcs_analyzed = 0
        for cwe in f.get('cwe_coverage', []):
            fa = cwe.get('functions_analyzed', 0)
            try:
                fa = int(fa)
            except (TypeError, ValueError):
                fa = 0
            funcs_analyzed = max(funcs_analyzed, fa)

        file_path = f.get('file_path', '?')
        display = file_path.rsplit('/', 1)[-1] if '/' in file_path else file_path
        classification = f.get('classification', '')

        if funcs_analyzed < total_funcs:
            pct = (funcs_analyzed / total_funcs * 100) if total_funcs > 0 else 0
            gaps.append(
                f"  {display} ({classification}): {funcs_analyzed}/{total_funcs} functions analyzed ({pct:.0f}%)"
            )

    if gaps:
        print(f"Files with unanalyzed functions: {len(gaps)}")
        for g in gaps:
            print(g)
    thin = _thinly_receipted_claims(files)
    if thin:
        print(f"Function claims with few structurally bound callables: {len(thin)}")
        for line in thin:
            print(line)
    if unscanned:
        # Zero functions means zero scanned spans, so the function-count check
        # above has nothing to compare and silently passed these files over.
        print(f"Files whose structural scan scope covered no source: {len(unscanned)}")
        for f in unscanned:
            file_path = f.get('file_path', '?')
            classification = f.get('classification', '')
            print(
                f"  {file_path} ({classification}): "
                f"{', '.join(f.get('structural_unavailable_dimensions') or [])} "
                "not measured — only whole-file source review can cover it"
            )
    if not gaps and not unscanned and not thin:
        # max(functions_analyzed) across CWE families matches total_functions,
        # but overlapping functions between families are not deduplicated —
        # this is count-based coverage, not identity-based.
        print("All indexed files report function-count coverage matching structural index.")


def _thinly_receipted_claims(files: list[dict]) -> list[str]:
    """Files whose claimed `functions_analyzed` far exceeds their bound callables.

    A ratio of distinct structurally bound callables to the largest claimed
    `functions_analyzed` below `_CALLABLE_RATIO_FLOOR` is worth a look, not a
    defect: a receipt can cover several functions through one call chain.
    """
    rows: list[str] = []
    for f in files:
        effort = f.get('analysis_effort') or {}
        bound = int(effort.get('distinct_structural_callables_reviewed', 0) or 0)
        claimed = 0
        for cwe in f.get('cwe_coverage', []):
            try:
                claimed = max(claimed, int(cwe.get('functions_analyzed', 0) or 0))
            except (TypeError, ValueError):
                continue
        if bound > 0 and claimed > 0 and bound / claimed < _CALLABLE_RATIO_FLOOR:
            rows.append(
                f"  {f.get('file_path', '?')} ({f.get('classification', '')}): "
                f"functions_analyzed={claimed} claimed, {bound} structurally bound "
                f"callable(s) recorded (ratio={bound / claimed:.2f})"
            )
    return rows


def _review_quality(data: dict) -> tuple[bool, list[str]]:
    """Derive the advisory quality verdict from its two canonical inputs only."""
    gate = data.get('gate')
    if not isinstance(gate, dict):
        return False, ["Review-quality metadata is unavailable"]

    effort_warnings = gate.get('effort_warnings')
    integrity = gate.get('coverage_integrity')
    if not isinstance(effort_warnings, list) or not isinstance(integrity, list):
        return False, ["Review-quality metadata is incomplete"]

    warnings = [str(warning) for warning in effort_warnings]
    for item in integrity:
        if not isinstance(item, dict):
            return False, ["Review-quality metadata is invalid"]
        item_warnings = item.get('warnings', [])
        if not isinstance(item_warnings, list):
            return False, ["Review-quality metadata is invalid"]
        for warning in item_warnings:
            warnings.append(f"{item.get('file_path', 'unknown file')}: {warning}")
    warnings = list(dict.fromkeys(warnings))
    return not warnings, warnings


def _print_review_quality(data: dict, *, full: bool) -> None:
    """Render the advisory review-quality verdict.

    These are self-attested numbers and receipt bookkeeping, so they never
    gate. ``full`` lists every warning (the `--cwe-matrix` view); otherwise
    effort shortfalls are grouped by tier x family and receipt warnings by
    tier, each with a few example files, and the full list is one flag away.
    """
    passed, warnings = _review_quality(data)
    print(f"\nReview Quality: {'PASS' if passed else 'NEEDS ATTENTION'} (advisory)")
    gate = data.get('gate')
    if full or passed or not isinstance(gate, dict):
        for warning in warnings:
            print(f"  - {warning}")
        return
    # The backend groups family shortfalls tier x family (`gate.effort_gaps`)
    # and names their lines in `effort_warnings` as `effort_gaps.warnings`;
    # those lines are shown through the groups, so only the other effort
    # warnings are listed below.
    gap_summary = gate.get('effort_gaps')
    groups = [
        group for group in (gap_summary.get('groups') or [] if isinstance(gap_summary, dict) else [])
        if isinstance(group, dict)
    ]
    grouped_messages: set[str] = set()
    if groups:
        print(
            f"  Effort below tier threshold: {gap_summary.get('total', 0)} family gap(s) across "
            f"{gap_summary.get('file_count', 0)} file(s)"
        )
        for group in groups:
            count = int(group.get('file_count', 0) or 0)
            shown = [str(path) for path in group.get('sample_file_paths') or []]
            more = f" +{count - len(shown)} more" if count > len(shown) else ""
            print(
                f"    {group.get('classification', '')} x {group.get('family', '')}: "
                f"{count} file(s) — {', '.join(shown)}{more}"
            )
        grouped_messages = {str(line) for line in gap_summary.get('warnings') or []}
    integrity = [
        item for item in gate.get('coverage_integrity') or []
        if isinstance(item, dict) and item.get('warnings')
    ]
    integrity_messages = {
        f"{item.get('file_path', 'unknown file')}: {warning}"
        for item in integrity
        for warning in item.get('warnings', [])
    }
    if integrity:
        by_tier: dict[str, list[str]] = {}
        for item in integrity:
            by_tier.setdefault(str(item.get('classification', '')), []).append(
                str(item.get('file_path', '?'))
            )
        print(f"  Receipt consistency warnings: {len(integrity)} file(s)")
        for tier in sorted(
            by_tier,
            key=lambda name: _TIER_ORDER.index(name) if name in _TIER_ORDER else len(_TIER_ORDER),
        ):
            paths = by_tier[tier]
            shown = paths[:_ADVISORY_FILES_PER_GROUP]
            more = f" +{len(paths) - len(shown)} more" if len(paths) > len(shown) else ""
            print(f"    {tier or 'unclassified'}: {len(paths)} file(s) — {', '.join(shown)}{more}")
    other = [
        warning for warning in warnings
        if warning not in grouped_messages and warning not in integrity_messages
    ]
    for warning in other[:_ADVISORY_PREVIEW_LIMIT]:
        print(f"  - {warning}")
    if len(other) > _ADVISORY_PREVIEW_LIMIT:
        print(f"  ... +{len(other) - _ADVISORY_PREVIEW_LIMIT} more")
    print("  Full per-file list: vigil assess code-coverage --cwe-matrix")


def _print_depth_advisories(data: dict, *, full: bool) -> None:
    """Name critical/high files whose signal came only from wide passes.

    A pointer for the next lane, never a gate: it is not part of
    `_review_quality`, readiness blockers, or `--require-gate-pass`.
    """
    gate = data.get('gate')
    advisories = [
        row for row in ((gate or {}).get('depth_advisories') or [] if isinstance(gate, dict) else [])
        if isinstance(row, dict)
    ]
    if not advisories:
        return
    print(
        f"\nDepth Advisories: {len(advisories)} critical/high file(s) produced signal "
        "on wide passes only (pointer; never gates)"
    )
    shown = advisories if full else advisories[:_ADVISORY_PREVIEW_LIMIT]
    for row in shown:
        print(
            f"  - {row.get('file_path', '?')} ({row.get('classification', '?')}): "
            f"{row.get('passes', 0)} wide pass(es), {row.get('signal_passes', 0)} with signal, "
            f"{row.get('findings', 0)} finding(s)"
        )
    if len(advisories) > len(shown):
        print(
            f"  ... +{len(advisories) - len(shown)} more; "
            "full list: vigil assess code-coverage --cwe-matrix"
        )
    print(
        "  Deeper read: a `hunt_scope: deep` lane over the file, or "
        "`vigil assess code-dispatch reanalyze <queue-items-json-file> <reason>`."
    )


def _print_context_tags_unrecorded(data: dict) -> None:
    """Name classified files whose classification recorded no context tags.

    A pointer for the architect, never a gate: those files owe only their slot
    and language families until their tags are recorded.
    """
    gate = data.get('gate')
    unrecorded = gate.get('context_tags_unrecorded') if isinstance(gate, dict) else None
    if not isinstance(unrecorded, dict) or not unrecorded.get('count'):
        return
    tiers = ", ".join(
        f"{tier} {count}" for tier, count in (unrecorded.get('by_classification') or {}).items()
    )
    print(
        f"\nContext Tags Unrecorded: {unrecorded['count']} classified file(s) ({tiers}) "
        "owe only their slot-type and language families (pointer; never gates)"
    )
    for path in unrecorded.get('sample_paths') or []:
        print(f"  - {path}")
    if unrecorded.get('omitted'):
        print(f"  ... +{unrecorded['omitted']} more")
    print(f"  Every file: {unrecorded.get('full_list')}")
    if unrecorded.get('paging'):
        print(f"  Paging: {unrecorded['paging']}")
    print(f"  Fix: {unrecorded.get('fix')}")


def _print_client_bundle_advisories(data: dict) -> None:
    """Name the families client-bundle tags make optional, and tags that look wrong.

    Pointers, never gates: an optional family is never measured, so it is named
    here rather than left silently absent from the gaps above.
    """
    gate = data.get('gate')
    if not isinstance(gate, dict):
        return
    optional = gate.get('optional_families')
    if isinstance(optional, dict) and optional.get('files'):
        families = ", ".join(
            f"{family} {count}" for family, count in (optional.get('by_family') or {}).items()
        )
        print(
            f"\nOptional Families: {optional['files']} client-bundle file(s) carry "
            f"server-only families nobody measures ({families}) (pointer; never gates)"
        )
        for path in optional.get('sample_paths') or []:
            print(f"  - {path}")
        if optional.get('omitted'):
            print(f"  ... +{optional['omitted']} more")
        print(f"  Every file: {optional.get('full_list')}")
    conflicts = gate.get('client_bundle_conflicts')
    if isinstance(conflicts, dict) and conflicts.get('count'):
        print(
            f"\nClient-Bundle Conflicts: {conflicts['count']} client-bundle file(s) whose "
            "language or other tags say server code (pointer; never gates)"
        )
        for entry in conflicts.get('sample') or []:
            print(f"  - {entry.get('file_path')}: {', '.join(entry.get('signals') or [])}")
        if conflicts.get('omitted'):
            print(f"  ... +{conflicts['omitted']} more")
        print(f"  Every file: {conflicts.get('full_list')}")
        print(f"  Fix: {conflicts.get('fix')}")


def _print_untriggered_depth_shortfalls(data: dict) -> None:
    """Name below-floor families no depth_floor trigger covers (a pointer, never a gate)."""
    gate = data.get('gate')
    shortfalls = gate.get('untriggered_depth_shortfalls') if isinstance(gate, dict) else None
    if not isinstance(shortfalls, dict) or not shortfalls.get('total'):
        return
    print(
        f"\nUntriggered Depth Shortfalls: {shortfalls['total']} critical/high famil(ies) on "
        f"{shortfalls.get('file_count', '?')} file(s) (pointer; never gates)"
    )
    for group in shortfalls.get('groups') or []:
        paths = ", ".join(group.get('sample_file_paths') or [])
        more = int(group.get('file_count') or 0) - len(group.get('sample_file_paths') or [])
        print(
            f"  - {group.get('classification')} {group.get('family')} (< {group.get('threshold')}): "
            f"{group.get('file_count')} file(s): {paths}" + (f" +{more} more" if more > 0 else "")
        )
    rows = shortfalls.get('rows')
    if isinstance(rows, list):
        print("  Every row:")
        for row in rows:
            if isinstance(row, dict):
                print(
                    f"    {row.get('file_path')}: {row.get('family')} "
                    f"{_format_effort(_coerce_effort(row.get('effort', 0)))} < {row.get('threshold')} "
                    f"({row.get('classification')})"
                )
    elif shortfalls.get('rows_omitted'):
        print(
            f"  {shortfalls['rows_omitted']} row(s) not listed; every row: "
            f"{shortfalls.get('full_list')}"
        )
    print(f"  {shortfalls.get('detail')}")


def _print_vuln_class_summary(data: dict) -> None:
    """Print a vulnerability class coverage summary from CWE effort data."""
    files = data.get('files', [])
    if not files:
        return

    total = 0
    full_coverage = 0
    shallow_gaps = 0
    zero_tested = 0

    for f in files:
        classification = f.get('classification', '')
        if classification == 'skip':
            continue
        total += 1

        cwe_coverage = f.get('cwe_coverage', [])
        applicable = f.get('applicable_families', [])

        if not cwe_coverage and not applicable:
            # No data for this file — treat as zero-tested if it has a classification
            if classification in ('critical', 'high', 'medium', 'low'):
                zero_tested += 1
            continue

        effort_map: dict[str, float] = {}
        not_applicable: set[str] = set()
        for cwe in cwe_coverage:
            fam = cwe.get('family', '')
            if _is_not_applicable_cwe_entry(cwe):
                not_applicable.add(fam)
                continue
            effort_map[fam] = _coerce_effort(cwe.get('effort', 0))

        threshold = EFFORT_THRESHOLDS.get(classification, 0)
        has_zero = False
        has_shallow = False

        families_to_check = set(applicable) if applicable else set(effort_map.keys())
        for fam in families_to_check:
            if fam in not_applicable:
                continue
            effort = effort_map.get(fam, 0)
            if effort == 0:
                has_zero = True
            elif threshold > 0 and effort < threshold:
                has_shallow = True

        if has_zero:
            zero_tested += 1
        elif has_shallow:
            shallow_gaps += 1
        else:
            full_coverage += 1

    if total > 0:
        print("Vulnerability Class Coverage:")
        print(f"  Files at full coverage: {full_coverage}/{total}")
        print(f"  Files with shallow gaps: {shallow_gaps}/{total}")
        print(f"  Files with zero-tested classes: {zero_tested}/{total}")
        print()


_ANALYSIS_STATUS_ORDER = (
    'analyzed', 'in_progress', 'needs_context', 'queued', 'classified', 'pending',
)


def _print_analysis_status(data: dict) -> None:
    """Render the per-file analysis-status census the backend already computes.

    Without it, a repo whose files were classified but never queued shows only
    "0 analyzed" against a full classification table — indistinguishable from
    lost work, when the real state is "the queue was never populated".
    """
    by_status = data.get('by_status')
    if not isinstance(by_status, dict) or not by_status:
        return
    print("\nBy Analysis Status:")
    for status in _ANALYSIS_STATUS_ORDER:
        if status in by_status:
            print(f"  {status:14s}: {by_status.get(status, 0):>5}")
    for status, count in sorted(by_status.items()):
        if status not in _ANALYSIS_STATUS_ORDER:
            print(f"  {str(status):14s}: {count:>5}")

    # `classified` holds every classified file without a successful review,
    # which includes files closed `skipped` with a reason: those are accounted
    # and owe no queue row, so they are named apart from the ones still owed.
    # The backend counts that share over the bucket's own files.
    classified = int(by_status.get('classified', 0) or 0)
    queued = int(by_status.get('queued', 0) or 0)
    confidence = data.get('confidence')
    skipped = int(
        (confidence.get('classified_accounted_skips') if isinstance(confidence, dict) else 0)
        or 0
    )
    unreviewed = classified - skipped
    if skipped:
        print(
            f"  NOTE: {skipped} classified file(s) are closed `skipped` with a "
            "reason — accounted, not reviewed."
        )
    if unreviewed > 0 and queued == 0:
        print(
            f"  NOTE: {unreviewed} classified file(s) have neither a successful "
            "review nor an accounted skip — queue them with "
            "`vigil assess code-dispatch queue <queue-items-json-file>`; "
            "`analyzed` counts require queue receipts."
        )
    # These are engagement-wide totals, so they say how much is left and
    # nothing about where. Composing the next wave from them otherwise means
    # paging `code-dispatch list` twice to recover a per-directory picture the
    # coverage page already computes.
    print(
        "  Next: `vigil assess code-coverage --by-path` breaks these buckets, "
        "the uncovered critical/high count and what the finished reviews "
        "concluded down by directory — the read a dispatch wave is planned from."
    )


def _print_source_identity(data: dict) -> None:
    """Surface per-repo binding state here, where it is cheap to discover.

    The structural-index binding is written by exactly one verb (`code-index
    sync`) and read as a hard gate by a much later one (`agent start`), so
    without this block the gap is only discovered at dispatch-composition time.
    """
    repos = data.get('repos')
    if not isinstance(repos, list) or not repos:
        return
    print("\nSource Identity:")
    for repo in repos:
        if not isinstance(repo, dict):
            continue
        repo_id = repo.get('repo_id', '?')
        generation = repo.get('active_generation', '?')
        quality = repo.get('source_snapshot_quality') or 'unknown'
        structural_bound = bool(repo.get('structural_index_bound'))
        threat_bound = bool(repo.get('threat_model_bound'))
        print(
            f"  repo {repo_id}: generation {generation} | snapshot {quality} | "
            f"structural index {'bound' if structural_bound else 'UNBOUND'} | "
            f"threat model {'bound' if threat_bound else 'unbound'}"
        )
        if not structural_bound:
            print(f"      {_BLOCKER_REPAIRS['structural_index_stale'](repo_id)}")


def _print_open_leases(data: dict) -> None:
    """Name the claimed attempts that never closed, oldest lease first.

    "Queue items still pending or processing" is a count; this is the item-level
    form of it, because a dispatch that died mid-file is indistinguishable from
    live work until you can see how long its lease has been silent and how many
    receipts would be thrown away by resetting it.
    """
    leases = data.get("open_leases")
    if not isinstance(leases, list) or not leases:
        return
    total = data.get("open_leases_count", len(leases))
    print(f"\nOpen Analysis Leases ({total}):")
    for lease in leases:
        if not isinstance(lease, dict):
            continue
        receipts = int(lease.get("current_result_count", 0) or 0)
        print(
            f"  item {lease.get('queue_item_id', '?')} "
            f"{lease.get('file_path', '?')} ({lease.get('classification', '?')}): "
            f"held by {lease.get('agent_name') or '-'} / "
            f"{lease.get('lease_token') or '-'}, silent for "
            f"{_format_lease_age(lease.get('heartbeat_age_seconds'))}, "
            f"{receipts} receipt(s) recorded"
        )
        for adopted in lease.get("adopted_leases") or []:
            if isinstance(adopted, dict):
                print(
                    f"      adopted from {adopted.get('agent_name', '?')} / "
                    f"{adopted.get('lease_token', '?')}"
                )
    if isinstance(total, int) and total > len(leases):
        # The backend already bounds the embedded list; the count is absolute.
        print(f"  ... showing {len(leases)} of {total}")
    print(
        "  Recover each with `vigil assess code-dispatch progress <item-id>` "
        "then `code-dispatch adopt-lease` (keeps the receipts) or "
        "`code-dispatch reset-stale <minutes>` (discards them)."
    )


def _print_coverage(
    data: dict,
    *,
    structural_debt_by_classification: Counter | None = None,
    include_review_quality: bool = True,
) -> None:
    total_files = data.get('total_files', 0)

    print("=== Code Analysis Coverage ===")
    print(
        "Coverage counts files with a receipt-backed review pass; it does not "
        "attest how deep that review went."
    )
    print(f"Total files: {total_files}")

    # A reference repository's files are deliberately absent from every count
    # above. Naming them keeps the smaller denominator explicit instead of
    # letting an operator read it as a shrinking inventory.
    reference_repos = data.get('reference_repos') or []
    if isinstance(reference_repos, list) and reference_repos:
        print("\nReference repositories (readable; no coverage obligation):")
        for repo in reference_repos:
            if not isinstance(repo, dict):
                continue
            name = repo.get('name') or repo.get('repo_key') or 'unknown'
            print(
                f"  {name} (repo {repo.get('repo_id', '?')}): "
                f"{repo.get('admitted_files', 0)} indexed file(s)"
            )

    by_class = data.get('by_classification', {})
    if by_class:
        print("\nBy Classification:")
        for tier in ('critical', 'high', 'medium', 'low', 'skip'):
            tier_data = by_class.get(tier, {})
            if isinstance(tier_data, dict):
                count = tier_data.get('count', 0)
                analyzed = tier_data.get('analyzed', 0)
                if tier == 'skip':
                    debt = (structural_debt_by_classification or Counter()).get(tier, 0)
                    print(
                        f"  {tier:10s}: {count:>4} files | {analyzed:>4} reviewed | "
                        f"structural debt: {debt}"
                    )
                elif count > 0:
                    pct = (analyzed / count) * 100.0
                    print(f"  {tier:10s}: {count:>4} files | {analyzed:>4} analyzed | {pct:5.1f}%")
                else:
                    print(f"  {tier:10s}: {count:>4} files |    0 analyzed |   0.0%")
            elif isinstance(tier_data, int):
                print(f"  {tier:10s}: {tier_data:>4} files")

    _print_analysis_status(data)
    _print_open_leases(data)
    _print_source_identity(data)

    func_level = data.get('function_level', {})
    if func_level:
        total_ctx = func_level.get('total_contexts', 0)
        analyzed_ctx = func_level.get('analyzed', 0)
        needs_ctx = func_level.get('needs_context', 0)
        pending_ctx = func_level.get('pending', 0)
        print("\nFunction-Level:")
        print(f"  Total contexts: {total_ctx}")
        print(f"  Analyzed: {analyzed_ctx} | Needs context: {needs_ctx} | Pending: {pending_ctx}")

    findings = data.get('findings_summary', {})
    if findings:
        total_findings = findings.get('total_code_findings', 0)
        by_severity = findings.get('by_severity', {})
        f_critical = by_severity.get('critical', 0)
        f_high = by_severity.get('high', 0)
        f_medium = by_severity.get('medium', 0)
        f_low = by_severity.get('low', 0)
        print(f"\nFindings: {total_findings} total ({f_critical} critical, {f_high} high, {f_medium} medium, {f_low} low)")
        variant_count = findings.get('variant_count', 0)
        if variant_count:
            print(f"Variants: {variant_count}")

    triggers = data.get('trigger_summary', {})
    if triggers:
        accepted = (
            triggers.get('external_context_unavailable', 0)
            + triggers.get('source_equivalent_analyzed', 0)
            + triggers.get('not_applicable', 0)
            + triggers.get('reviewed_at_sufficient_depth', 0)
        )
        print(
            "\nCross-File Triggers: "
            f"{triggers.get('pending', 0)} pending, "
            f"{triggers.get('queued', 0)} queued, "
            f"{triggers.get('resolved', 0)} resolved, "
            f"{accepted} accepted gap"
        )

    if include_review_quality:
        _print_review_quality(data, full=True)
    print()
