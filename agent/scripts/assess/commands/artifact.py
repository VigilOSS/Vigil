"""vigil assess artifact — indexed engagement artifact operations."""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from assess.lib.bulk_ingest import (
    bulk_endpoint_missing,
    DEFAULT_BULK_WRITE_SIZE,
    request_rejected_before_any_write,
)
from assess.lib.client import (
    DEFAULT_READ_TIMEOUT_SECONDS,
    AssessmentClient,
    AssessError,
    canonical_artifact_path,
    require_artifact_bulk_write_response,
    require_artifact_write_response,
    require_write_result,
)
from assess.lib.config import load_config
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.list_output import ListPage, lookahead_limit, page_from_backend, report_page


_MAX_SEARCH_LIMIT = 1000
# Response budget for one bulk registration chunk. The backend opens, reads and
# hashes every file in the chunk, so the work scales with the batch rather than
# sitting inside the client's flat 10 s default. A timeout here cannot be retried
# — the rows may already be durable — so the chunk is given time proportional to
# what it asked the backend to do.
_BULK_REGISTER_SECONDS_PER_PATH = 0.2


class _RemovedPositionalQueryAction(argparse.Action):
    """Reject the former positional query without advertising it in help."""

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        if values:
            parser.error(
                "artifact search: positional query was removed; "
                "use --q \"<free-text query>\""
            )


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "artifact",
        help="Search, get, register, and refresh indexed engagement artifacts.",
    )
    action_sub = p.add_subparsers(dest="action")
    action_sub.required = True

    # -- search ---------------------------------------------------------------
    sp_search = action_sub.add_parser(
        "search",
        help="Search indexed artifacts by free text and/or typed filters.",
        description=(
            "Search indexed artifacts. Use --q for free text; combine it with "
            "--finding or --kind to narrow the result."
        ),
    )
    sp_search.add_argument(
        "--q",
        dest="query",
        default="",
        metavar="QUERY",
        help="Free-text query. Quote multi-word values.",
    )
    sp_search.add_argument(
        "removed_positional_query",
        nargs="*",
        action=_RemovedPositionalQueryAction,
        help=argparse.SUPPRESS,
    )
    sp_search.add_argument("--finding", default="", help="Filter/rank by finding slug")
    sp_search.add_argument("--kind", default="", help="Filter by artifact kind")
    sp_search.add_argument("--limit", type=int, default=50)
    sp_search.add_argument("--offset", type=int, default=0)
    sp_search.add_argument(
        "--paginate",
        action="store_true",
        help="Fetch every matching artifact page from --offset.",
    )
    sp_search.add_argument("--json", dest="as_json", action="store_true")
    sp_search.set_defaults(func=_run_search)

    # -- get ------------------------------------------------------------------
    sp_get = action_sub.add_parser("get", help="Fetch a single artifact by id.")
    sp_get.add_argument("artifact_id", type=int, help="Artifact id (integer)")
    sp_get.add_argument("--json", dest="as_json", action="store_true")
    sp_get.set_defaults(func=_run_get)

    # -- register -------------------------------------------------------------
    sp_register = action_sub.add_parser(
        "register",
        help="Register one or more engagement-local files in the artifact index.",
        description=(
            "Register engagement-local files. One path registers exactly as it "
            "always has; two or more register in one bulk call that reports an "
            "outcome for every path, so a refused path costs only itself."
        ),
    )
    sp_register.add_argument(
        "paths",
        nargs="*",
        help="Relative or absolute paths to register (each must be inside the engagement dir)",
    )
    sp_register.add_argument(
        "--paths-file",
        dest="paths_file",
        default="",
        metavar="PATH",
        help="Newline-delimited file of paths to register ('-' reads stdin). Blank lines are "
             "skipped and the entries are appended after any positional paths.",
    )
    sp_register.add_argument("--kind", default="")
    sp_register.add_argument("--media-type", default="")
    sp_register.add_argument("--finding", default="", help="Link to finding slug")
    sp_register.add_argument("--agent-id", default="")
    sp_register.add_argument("--agent-role", default="")
    sp_register.add_argument("--command-run-id", type=int, default=None)
    sp_register.add_argument("--json", dest="as_json", action="store_true")
    sp_register.set_defaults(func=_run_register)

    # -- refresh --------------------------------------------------------------
    sp_refresh = action_sub.add_parser(
        "refresh",
        help="Refresh presence/hash metadata for already registered artifacts.",
    )
    sp_refresh.add_argument(
        "artifact_id",
        nargs="?",
        type=int,
        help="Optional artifact id; omit to refresh every registered artifact.",
    )
    sp_refresh.add_argument("--json", dest="as_json", action="store_true")
    sp_refresh.set_defaults(func=_run_refresh)

    sp_unlink = action_sub.add_parser(
        "unlink-finding",
        help="Clear one artifact's finding link without deleting the artifact or proof.",
    )
    sp_unlink.add_argument("artifact_id", type=int)
    sp_unlink.add_argument("--json", dest="as_json", action="store_true")
    sp_unlink.set_defaults(func=_run_unlink_finding)

    # -- mark-scratch ---------------------------------------------------------
    sp_scratch = action_sub.add_parser("mark-scratch", help="Mark an artifact as scratch (excluded from report-readiness).")
    sp_scratch.add_argument("target", nargs="?", default=None, help="Artifact id (numeric) or relative path")
    sp_scratch.add_argument(
        "--under",
        default="",
        help="Path prefix to scratch in bulk (e.g. notes/scratch/). Mutually exclusive with target.",
    )
    sp_scratch.add_argument("--json", dest="as_json", action="store_true")
    sp_scratch.set_defaults(func=_run_scratch, scratch=True)

    # -- unmark-scratch -------------------------------------------------------
    sp_unscratch = action_sub.add_parser("unmark-scratch", help="Remove scratch mark from an artifact.")
    sp_unscratch.add_argument("target", nargs="?", default=None, help="Artifact id (numeric) or relative path")
    sp_unscratch.add_argument(
        "--under",
        default="",
        help="Path prefix to unscratch in bulk (e.g. notes/scratch/). Mutually exclusive with target.",
    )
    sp_unscratch.add_argument("--json", dest="as_json", action="store_true")
    sp_unscratch.set_defaults(func=_run_scratch, scratch=False)


def _client_and_config(args) -> tuple[AssessmentClient, Any]:
    cfg = load_config(args.engagement_dir)
    return AssessmentClient(cfg.base_url, cfg.engagement_key), cfg


def _client(args) -> AssessmentClient:
    return _client_and_config(args)[0]


def _canonical_artifact_path(
    engagement_dir: str, path_value: str, *, operation: str
) -> str:
    """CLI form of `client.canonical_artifact_path`: report and exit, never raise."""
    try:
        return canonical_artifact_path(engagement_dir, path_value, operation=operation)
    except AssessError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)


def _render_rows(rows: list[dict]) -> str:
    if not rows:
        return "(no artifacts matched)"
    header = [
        "id",
        "present",
        "scratch",
        "kind",
        "finding",
        "bytes",
        "indexed_bytes",
        "index_status",
        "path",
        "preview",
    ]
    lines = ["\t".join(header)]
    for row in rows:
        preview = str(row.get("preview_text") or "").replace("\t", " ").replace("\n", " ")
        if len(preview) > 80:
            preview = preview[:77] + "..."
        lines.append(
            "\t".join(
                [
                    str(row.get("id", "")),
                    "yes" if row.get("present") else "no",
                    "yes" if row.get("scratch") else "no",
                    str(row.get("kind") or "-"),
                    str(row.get("related_finding_slug") or "-"),
                    str(row.get("size_bytes") or 0),
                    str(row.get("indexed_bytes") or 0),
                    str(row.get("index_status") or "unknown"),
                    str(row.get("relative_path") or ""),
                    preview or "-",
                ]
            )
        )
    return "\n".join(lines)


def _artifact_search_endpoint(args, *, limit: int, offset: int) -> str:
    query = str(args.query or "").strip()
    params: list[tuple[str, str]] = []
    if query:
        params.append(("q", query))
    if args.finding:
        params.append(("finding", args.finding))
    if args.kind:
        params.append(("kind", args.kind))
    params.extend((('limit', str(limit)), ('offset', str(offset))))
    return "artifacts/search?" + urlencode(params, quote_via=quote)


def _require_artifact_rows(value) -> list[dict]:
    if not isinstance(value, list) or any(
        not isinstance(row, dict)
        or not isinstance(row.get("id"), int)
        or isinstance(row.get("id"), bool)
        or row["id"] < 1
        or not isinstance(row.get("relative_path"), str)
        or not row["relative_path"].strip()
        or not isinstance(row.get("indexed_bytes"), int)
        or isinstance(row.get("indexed_bytes"), bool)
        or row["indexed_bytes"] < 0
        or row.get("index_status")
        not in {"complete", "missing", "not_text", "partial"}
        for row in value
    ):
        raise AssessError("artifact search: malformed artifact search response")
    return value


def _artifact_search_continuation(args, *, offset: int) -> str:
    parts = ["vigil", "assess", "artifact", "search"]
    for flag, value in (
        ("--q", str(args.query or "").strip()),
        ("--finding", args.finding),
        ("--kind", args.kind),
    ):
        if value:
            parts.extend((flag, str(value)))
    parts.extend(("--limit", str(args.limit), "--offset", str(offset)))
    return shlex.join(parts)


def _run_search(args) -> None:
    limit = int(args.limit)
    offset = int(args.offset)
    client = _client(args)
    try:
        if getattr(args, "paginate", False):
            rows: list[dict] = []
            next_offset = offset
            while True:
                page_rows = _require_artifact_rows(
                    client.get(
                        _artifact_search_endpoint(
                            args, limit=limit, offset=next_offset
                        )
                    )
                )
                rows.extend(page_rows)
                if len(page_rows) < limit:
                    break
                next_offset += len(page_rows)
        else:
            request_limit, used_lookahead = lookahead_limit(
                limit, maximum=_MAX_SEARCH_LIMIT
            )
            rows = _require_artifact_rows(
                client.get(
                    _artifact_search_endpoint(
                        args, limit=request_limit, offset=offset
                    )
                )
            )
    finally:
        client.close()

    if getattr(args, "paginate", False):
        exact_total = offset + len(rows) if rows or offset == 0 else None
        page = ListPage(
            rows=rows,
            offset=offset,
            total=exact_total,
            total_at_least=exact_total,
            has_more=False,
        )
    else:
        page = page_from_backend(
            rows,
            limit=limit,
            offset=offset,
            used_lookahead=used_lookahead,
        )
    report_page(
        page,
        noun="artifacts",
        continuation_command=_artifact_search_continuation(
            args, offset=page.offset + len(page.rows)
        ),
        point_read_hint="`vigil assess artifact get <id>`",
    )
    rows = page.rows
    if rows:
        warn_untrusted_data()
    print(json.dumps(rows, indent=2, ensure_ascii=False) if args.as_json else _render_rows(rows))


def _run_get(args) -> None:
    client = _client(args)
    try:
        row = client.get(f"artifacts/{args.artifact_id}")
        warn_untrusted_data()
        print(json.dumps(row, indent=2, ensure_ascii=False) if args.as_json else _artifact_text(row))
    finally:
        client.close()


def _register_paths(args) -> list[str]:
    """Every path to register: the positional ones first, then --paths-file order."""
    paths = [str(value) for value in (args.paths or [])]
    source = str(getattr(args, "paths_file", "") or "")
    if source:
        if source == "-":
            text = sys.stdin.read()
        else:
            try:
                text = Path(source).read_text(encoding="utf-8")
            except OSError as exc:
                print(f"register artifact: --paths-file {source}: {exc}", file=sys.stderr)
                sys.exit(1)
        paths.extend(entry for entry in (line.strip() for line in text.splitlines()) if entry)
    if not paths:
        print(
            "register artifact: at least one path is required — pass paths positionally "
            "or with --paths-file <PATH> ('-' reads stdin)",
            file=sys.stderr,
        )
        sys.exit(1)
    return paths


def _register_payload(args, canonical_path: str) -> dict[str, Any]:
    return {
        "path": canonical_path,
        "kind": args.kind,
        "media_type": args.media_type,
        "producer_agent_id": args.agent_id or None,
        "producer_agent_role": args.agent_role or None,
        "producer_command_run_id": args.command_run_id,
        "related_finding_slug": args.finding or None,
    }


def _register_outcome(
    index: int,
    path: str,
    outcome: str,
    *,
    detail: str,
    relative_path: str | None = None,
    artifact_id: int | None = None,
) -> dict[str, Any]:
    return {
        "index": index,
        "path": path,
        "relative_path": relative_path,
        "artifact_id": artifact_id,
        "outcome": outcome,
        "status_code": None,
        "detail": detail,
    }


def _register_accounting(result: dict[str, Any]) -> list[str]:
    """The accounting line plus one line per path that did not land, in full."""
    summary = (
        f"artifact register: requested={result['requested']} "
        f"registered={result['registered']} failed={result['failed']}"
    )
    for state in ("duplicate", "unknown", "not_attempted"):
        if result[state]:
            summary += f" {state}={result[state]}"
    lines = [summary]
    lines.extend(
        f"  {outcome['outcome']} {outcome['path']}: {outcome['detail']}"
        for outcome in result["outcomes"]
        if outcome["outcome"] != "registered"
    )
    return lines


def _run_register(args) -> None:
    paths = _register_paths(args)
    client, cfg = _client_and_config(args)
    try:
        if len(paths) == 1:
            _register_one(client, cfg, args, paths[0])
        else:
            _register_many(client, cfg, args, paths)
    finally:
        client.close()


def _register_one(client, cfg, args, path: str) -> None:
    canonical_path = _canonical_artifact_path(
        cfg.engagement_dir, path, operation="register artifact"
    )
    row = require_artifact_write_response(
        client.post("artifacts", _register_payload(args, canonical_path)),
        artifact_path=canonical_path,
        operation="register artifact",
    )
    print(json.dumps(row, indent=2, ensure_ascii=False) if args.as_json else _render_rows([row]))


def _register_many(client, cfg, args, paths: list[str]) -> None:
    """Register every path through the bulk endpoint, accounting for each one.

    A path this side cannot canonicalise fails alone and is never sent; a chunk
    whose POST or receipt fails STOPS the run, because its rows may already be
    durable — its paths are reported ``unknown`` and the untried remainder
    ``not_attempted`` rather than retried into duplicates.
    """
    outcomes: list[dict[str, Any]] = []
    # (submission index, path as the caller spelled it, canonical path) per path
    # that survived canonicalisation — the only ones the backend ever sees.
    pending: list[tuple[int, str, str]] = []
    canonical_seen: dict[str, int] = {}
    for index, path in enumerate(paths):
        try:
            canonical_path = canonical_artifact_path(
                cfg.engagement_dir, path, operation="register artifact"
            )
        except AssessError as exc:
            outcomes.append(_register_outcome(index, path, "failed", detail=str(exc)))
            continue
        first_seen = canonical_seen.get(canonical_path)
        if first_seen is not None:
            # One file named twice is one artifact, and counting it twice makes
            # `registered=` a number that does not describe the index. The
            # requeue-triggers precedent deduplicates for the same reason.
            outcomes.append(
                _register_outcome(
                    index,
                    path,
                    "duplicate",
                    relative_path=canonical_path,
                    detail=(
                        f"same canonical path as item {first_seen}; registered once"
                    ),
                )
            )
            continue
        canonical_seen[canonical_path] = index
        pending.append((index, path, canonical_path))

    artifacts: list[dict[str, Any]] = []
    unsent_from: int | None = None
    for start in range(0, len(pending), DEFAULT_BULK_WRITE_SIZE):
        chunk = pending[start:start + DEFAULT_BULK_WRITE_SIZE]
        canonical_paths = [canonical_path for _index, _path, canonical_path in chunk]
        try:
            receipt = require_artifact_bulk_write_response(
                client.post(
                    "artifacts/bulk",
                    {"items": [_register_payload(args, value) for value in canonical_paths]},
                    read_timeout=max(
                        DEFAULT_READ_TIMEOUT_SECONDS,
                        _BULK_REGISTER_SECONDS_PER_PATH * len(chunk),
                    ),
                ),
                artifact_paths=canonical_paths,
                operation="register artifact",
            )
        except AssessError as exc:
            if bulk_endpoint_missing(exc):
                # The CLI and the backend upgrade independently, and a backend
                # process that predates /artifacts/bulk answers 404/405 — the
                # stale-install case `vigil install` warns about every time it
                # syncs. Without this the new CLI registers NOTHING against an
                # old backend, which is strictly worse than the single-path form
                # it replaced. Same fallback both other bulk clients already use.
                print(
                    f"WARN register artifact: this backend has no bulk endpoint "
                    f"({exc}); registering {len(chunk)} path(s) individually. "
                    "Run `vigil orchestrator restart` to pick up the bulk route.",
                    file=sys.stderr,
                )
                for item_index, item_path, item_canonical in chunk:
                    try:
                        record = require_artifact_write_response(
                            client.post("artifacts", _register_payload(args, item_canonical)),
                            artifact_path=item_canonical,
                            operation="register artifact",
                        )
                    except AssessError as single_exc:
                        outcomes.append(
                            _register_outcome(
                                item_index, item_path, "failed", detail=str(single_exc)
                            )
                        )
                        continue
                    artifacts.append(record)
                    outcomes.append(
                        _register_outcome(
                            item_index,
                            item_path,
                            "registered",
                            detail="",
                            relative_path=str(record.get("relative_path") or ""),
                            artifact_id=record.get("id"),
                        )
                    )
                continue
            # A request the backend refused before its handler ran wrote nothing,
            # and calling that "may have committed" sends the caller to reconcile
            # state nothing touched. Anything else is genuinely unknown.
            if request_rejected_before_any_write(exc):
                state, detail = "failed", (
                    f"the bulk registration chunk carrying this path was refused "
                    f"before any write ({exc})"
                )
            else:
                state, detail = "unknown", (
                    f"the bulk registration chunk carrying this path did not return a "
                    f"usable receipt ({exc}); the write may have committed, so inspect "
                    "durable state and do not retry automatically"
                )
            outcomes.extend(
                _register_outcome(index, path, state, detail=detail)
                for index, path, _canonical_path in chunk
            )
            unsent_from = start + len(chunk)
            break
        outcomes.extend(
            {**outcome, "index": index, "path": path}
            for (index, path, _canonical_path), outcome in zip(
                chunk, receipt["outcomes"], strict=True
            )
        )
        artifacts.extend(receipt["artifacts"])
    if unsent_from is not None:
        outcomes.extend(
            _register_outcome(
                index,
                path,
                "not_attempted",
                detail="not sent: the run stopped at the chunk reported above",
            )
            for index, path, _canonical_path in pending[unsent_from:]
        )
    outcomes.sort(key=lambda outcome: outcome["index"])

    counts = dict.fromkeys(
        ("registered", "duplicate", "failed", "unknown", "not_attempted"), 0
    )
    for outcome in outcomes:
        counts[outcome["outcome"]] += 1
    result = {
        "requested": len(paths),
        **counts,
        "outcomes": outcomes,
        "artifacts": artifacts,
    }
    if args.as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        if artifacts:
            print(_render_rows(artifacts))
        # stderr, like the single-path refusal: `register ... > rows.txt` must
        # not swallow the reason a path did not land.
        print("\n".join(_register_accounting(result)), file=sys.stderr)
    if counts["registered"] + counts["duplicate"] != len(paths):
        sys.exit(1)


def _run_refresh(args) -> None:
    client = _client(args)
    try:
        artifact_id = getattr(args, "artifact_id", None)
        endpoint = (
            f"artifacts/{artifact_id}/refresh"
            if artifact_id is not None
            else "artifacts/refresh"
        )
        result = require_write_result(
            client.post(endpoint, {}),
            operation="refresh artifacts",
            nonnegative_counts=("refreshed", "present", "missing"),
        )
        print(json.dumps(result, indent=2, ensure_ascii=False) if args.as_json else _refresh_text(result))
    finally:
        client.close()


def _run_unlink_finding(args) -> None:
    client = _client(args)
    try:
        row = require_artifact_write_response(
            client.delete(f"artifacts/{args.artifact_id}/finding-link"),
            artifact_path=None,
            operation="clear artifact finding link",
        )
        if row.get("related_finding_slug") is not None:
            raise AssessError(
                "clear artifact finding link: backend did not confirm an empty link"
            )
        print(
            json.dumps(row, indent=2, ensure_ascii=False)
            if args.as_json
            else _render_rows([row])
        )
    finally:
        client.close()


def _run_scratch(args) -> None:
    scratch = args.scratch
    action_label = "mark-scratch" if scratch else "unmark-scratch"
    client, cfg = _client_and_config(args)
    try:
        under = (args.under or "").strip()
        if under:
            result = client.post(
                "artifacts/scratch-under",
                {"prefix": under, "scratch": scratch},
            )
            result = require_write_result(
                result,
                operation=f"artifact {action_label}",
                nonnegative_counts=("matched",),
            )
            updated = result.get("updated")
            if not isinstance(updated, list) or len(updated) != result["matched"]:
                raise AssessError(
                    f"artifact {action_label}: backend response paths do not match "
                    "its count; the write may have committed, so inspect durable "
                    "state and do not retry automatically"
                )
            if args.as_json:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                matched = result.get("matched", 0)
                prefix_display = result.get("prefix") or under
                print(f"matched={matched} prefix={prefix_display}")
                if matched == 0:
                    print(
                        f"  (no indexed artifacts under {prefix_display!r}; "
                        "check with `artifact search` or register them first)"
                    )
                for path in (result.get("updated") or [])[:20]:
                    print(f"  - {path}")
                if matched > 20:
                    print(f"  - … and {matched - 20} more")
            return
        if args.target is None:
            print(f"artifact {action_label}: artifact id or path is required (or pass --under <prefix>)", file=sys.stderr)
            sys.exit(1)
        target = args.target
        if target.isdigit():
            row = require_write_result(
                client.post(
                    f"artifacts/{int(target)}/scratch",
                    {"scratch": scratch},
                ),
                operation=f"artifact {action_label}",
                expected={"id": int(target), "scratch": scratch},
            )
        else:
            canonical_path = _canonical_artifact_path(
                cfg.engagement_dir, target, operation=f"artifact {action_label}"
            )
            row = require_artifact_write_response(
                client.post(
                    "artifacts/scratch-by-path",
                    {"path": canonical_path, "scratch": scratch},
                ),
                artifact_path=canonical_path,
                operation=f"artifact {action_label}",
            )
            if row.get("scratch") is not scratch:
                raise AssessError(
                    f"artifact {action_label}: backend response did not confirm the "
                    "requested state; the write may have committed, so inspect "
                    "durable state and do not retry automatically"
                )
        print(json.dumps(row, indent=2, ensure_ascii=False) if args.as_json else _render_rows([row]))
    finally:
        client.close()


def _artifact_text(row: dict) -> str:
    lines = [
        f"id: {row.get('id')}",
        f"path: {row.get('relative_path')}",
        f"kind: {row.get('kind')}",
        f"present: {'yes' if row.get('present') else 'no'}",
        f"bytes: {row.get('size_bytes')}",
        f"sha256: {row.get('sha256')}",
        f"indexed_bytes: {row.get('indexed_bytes')}",
        f"index_status: {row.get('index_status') or 'unknown'}",
        "content_truncated: "
        + (
            "yes"
            if row.get("content_truncated") is True
            else "no"
            if row.get("content_truncated") is False
            else "unknown"
        ),
    ]
    if row.get("content"):
        lines.extend(["", str(row.get("content"))])
    elif row.get("preview_text"):
        lines.extend(["", str(row.get("preview_text"))])
    if row.get("content_truncated"):
        lines.extend(
            [
                "",
                "content is truncated; use the engagement-local path for the remainder",
            ]
        )
    return "\n".join(lines)


def _refresh_text(result: dict) -> str:
    return (
        f"refreshed={result['refreshed']} "
        f"present={result['present']} "
        f"missing={result['missing']}"
    )
