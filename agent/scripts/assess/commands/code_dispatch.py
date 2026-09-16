"""vigil assess code-dispatch — analysis queue dispatch engine for the code analysis pipeline."""
from __future__ import annotations

import argparse
from fnmatch import fnmatch
import hashlib
import json
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlencode

from assess.lib.code_audit import write_json_snapshot
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.code_snapshot import MAX_JSON_ARTIFACT_BYTES, read_bounded_regular_file
from assess.lib.code_structural_identity import parse_code_file_page

_CODE_FILE_LOOKUP_PAGE_SIZE = 10000
_MAX_QUEUE_IDS_FILE_BYTES = 64 * 1024
_MAX_QUEUE_LOOKUP_MATCHES = 10000
_MAX_QUEUE_NORMALIZED_ITEMS = 10000
_MAX_QUEUE_INPUT_BYTES = MAX_JSON_ARTIFACT_BYTES
_QUEUE_SUBMISSION_BATCH_SIZE = 200
_MAX_QUEUE_REPORTED_OUTCOMES = 200
_PROCESS_DESCRIPTOR_PATH = re.compile(r"/(?:dev|proc/self)/fd/[0-9]+")
_DONE_DISPOSITIONS = ("clean", "finding", "suspicious", "skipped")
# C50: when disposition=skipped the operator must supply --skip-reason so
# code-coverage can attribute the skip. Common reasons:
_SKIP_REASONS_HINT = (
    "test-fixture",
    "generated-code",
    "minified",
    "out-of-scope-language",
    "vendored-dependency",
)

_ACTION_HELP: dict[str, str] = {
    "stats": (
        "Usage: vigil assess code-dispatch stats\n\n"
        "Print current and historical analysis-queue counts.\n"
    ),
    "list": (
        "Usage: vigil assess code-dispatch list [--status STATUS] [--repo-id ID] "
        "[--classification TIER] [--batch-theme THEME] [--queue-mode MODE] "
        "[--limit N] [--offset N] [--json|--ids-only]\n\n"
        "Page the current-generation analysis queue without claiming anything.\n"
        "Rows are ordered exactly as fetch claims them (priority desc, id asc).\n"
        "--json and --ids-only both emit a payload `fetch --ids-file` accepts, so "
        "explicit IDs stay recoverable after the queue-submission output scrolls.\n"
    ),
    "fetch": (
        "Usage: vigil assess code-dispatch fetch <limit> <agent-name> "
        "[--repo-id ID] [--classification TIER] [--batch-theme THEME] "
        "[--queue-mode MODE] [--ids-file PATH]\n\n"
        "Atomically claim matching current queue items for one analysis worker.\n"
    ),
    "heartbeat": (
        "Usage: vigil assess code-dispatch heartbeat "
        "<item-id> <agent-name> <lease-token>\n\n"
        "Renew the exact active lease for one claimed queue item.\n"
    ),
    "done": (
        "Usage: vigil assess code-dispatch done <item-id> <agent-name> "
        "<lease-token> <disposition> <cwe-coverage-json-file> [notes] "
        "[--dry-run] [--skip-reason <reason>]\n\n"
        f"Valid dispositions: {', '.join(_DONE_DISPOSITIONS)}.\n"
        "CWE coverage must be a JSON array such as "
        "[{\"family\":\"ssrf\",\"effort\":80}].\n"
        "--skip-reason is required when disposition=skipped. Suggested values: "
        f"{', '.join(_SKIP_REASONS_HINT)}.\n"
    ),
    "error": (
        "Usage: vigil assess code-dispatch error "
        "<item-id> <agent-name> <lease-token> [notes]\n\n"
        "Close the exact active lease as an analysis error.\n"
    ),
    "needs-context": (
        "Usage: vigil assess code-dispatch needs-context "
        "<item-id> <agent-name> <lease-token> [expansion-json-file]\n\n"
        "Close the exact active lease while recording the missing context.\n"
    ),
    "reset-stale": (
        "Usage: vigil assess code-dispatch reset-stale <minutes>\n\n"
        "Return processing leases older than the threshold to pending.\n"
    ),
    "retry-error": (
        "Usage: vigil assess code-dispatch retry-error <id1,id2,...> [reason]\n\n"
        "Create current retry attempts for errored queue items.\n"
    ),
    "retry-needs-context": (
        "Usage: vigil assess code-dispatch retry-needs-context "
        "<id1,id2,...> <reason>\n\n"
        "Create current retry attempts after supplying the missing context.\n"
    ),
    "queue": (
        "Usage: vigil assess code-dispatch queue <queue-items-json-file>\n\n"
        "Submit canonical initial analysis items.\n"
    ),
    "reanalyze": (
        "Usage: vigil assess code-dispatch reanalyze "
        "<queue-items-json-file> <reason>\n\n"
        "Create new current attempts that supersede prior analysis attempts.\n"
    ),
    "requeue-triggers": (
        "Usage: vigil assess code-dispatch requeue-triggers <triggers-json-file>\n\n"
        "Turn cross-file triggers into linked current analysis attempts.\n"
    ),
    "list-triggers": (
        "Usage: vigil assess code-dispatch list-triggers [status]\n\n"
        "List cross-file triggers, defaulting to pending.\n"
    ),
    "resolve-triggers": (
        "Usage: vigil assess code-dispatch resolve-triggers <triggers-json-file> "
        "<external_context_unavailable|source_equivalent_analyzed|not_applicable> "
        "<note>\n\n"
        "Resolve triggers that cannot or should not produce another queue attempt.\n"
    ),
}


def maybe_print_action_help(tokens: list[str]) -> None:
    """Render action help before argparse.REMAINDER consumes help flags as data."""
    if len(tokens) >= 2 and any(token in {"-h", "--help"} for token in tokens[1:]):
        help_text = _ACTION_HELP.get(tokens[0])
        if help_text:
            print(help_text)
            raise SystemExit(0)


def register(subparsers) -> None:
    p = subparsers.add_parser("code-dispatch", help="Code analysis queue dispatch engine")
    p.add_argument(
        "action",
        choices=tuple(_ACTION_HELP),
        help="stats|list|fetch|heartbeat|done|error|needs-context|reset-stale|retry-error|retry-needs-context|queue|reanalyze|requeue-triggers|list-triggers|resolve-triggers",
    )
    p.add_argument("extra", nargs=argparse.REMAINDER, help="Action-specific arguments")
    p.set_defaults(func=run)


def run(args) -> None:
    action = args.action
    extra = args.extra or []

    if action not in _ACTION_HELP:
        print(f"Unknown action: {action}", file=sys.stderr)
        print(f"Actions: {', '.join(_ACTION_HELP)}", file=sys.stderr)
        raise SystemExit(1)

    cfg = load_config(args.engagement_dir)

    if action == "stats":
        _stats(cfg)
    elif action == "list":
        filters, output = _parse_list_filters(extra)
        _list(cfg, filters, output)
    elif action == "fetch":
        if len(extra) < 2:
            print(
                "Usage: code-dispatch fetch <limit> <agent-name> "
                "[--repo-id ID] [--classification TIER] [--batch-theme THEME] "
                "[--queue-mode MODE] [--ids-file PATH]",
                file=sys.stderr,
            )
            sys.exit(1)
        _fetch(cfg, int(extra[0]), extra[1], _parse_fetch_filters(extra[2:]))
    elif action == "done":
        if len(extra) < 5:
            print(
                "Usage: code-dispatch done <item-id> <agent-name> <lease-token> <disposition> <cwe-coverage-json-file> [notes] [--dry-run] [--skip-reason <reason>]\n"
                f"Valid dispositions: {', '.join(_DONE_DISPOSITIONS)}\n"
                "CWE coverage must be a JSON array like "
                "[{\"family\":\"ssrf\",\"effort\":80}]\n"
                f"--skip-reason is required when disposition=skipped. "
                f"Suggested values: {', '.join(_SKIP_REASONS_HINT)}",
                file=sys.stderr,
            )
            sys.exit(1)
        notes_parts: list[str] = []
        dry_run = False
        dry_run_seen = False
        skip_reason = ""
        skip_reason_seen = False
        tokens = list(extra[5:])
        idx = 0
        while idx < len(tokens):
            token = tokens[idx]
            if token == "--dry-run":
                if dry_run_seen:
                    print("ERROR: --dry-run was specified more than once", file=sys.stderr)
                    sys.exit(1)
                dry_run_seen = True
                dry_run = True
                idx += 1
            elif token == "--skip-reason":
                if skip_reason_seen:
                    print("ERROR: --skip-reason was specified more than once", file=sys.stderr)
                    sys.exit(1)
                if (
                    idx + 1 >= len(tokens)
                    or not tokens[idx + 1].strip()
                    or tokens[idx + 1].startswith("-")
                ):
                    print("ERROR: --skip-reason requires a value", file=sys.stderr)
                    sys.exit(1)
                skip_reason_seen = True
                skip_reason = tokens[idx + 1]
                idx += 2
            elif token.startswith("-"):
                print(f"ERROR: unknown code-dispatch done option: {token}", file=sys.stderr)
                sys.exit(1)
            else:
                notes_parts.append(token)
                idx += 1
        notes = " ".join(notes_parts)
        _done(
            cfg, extra[0], extra[1], extra[2], extra[3], extra[4], notes,
            dry_run=dry_run, skip_reason=skip_reason,
        )
    elif action == "heartbeat":
        if len(extra) != 3:
            print("Usage: code-dispatch heartbeat <item-id> <agent-name> <lease-token>", file=sys.stderr)
            sys.exit(1)
        _heartbeat(cfg, extra[0], extra[1], extra[2])
    elif action == "error":
        if len(extra) < 3:
            print("Usage: code-dispatch error <item-id> <agent-name> <lease-token> [notes]", file=sys.stderr)
            sys.exit(1)
        _error(cfg, extra[0], extra[1], extra[2], " ".join(extra[3:]))
    elif action == "needs-context":
        if len(extra) < 3:
            print("Usage: code-dispatch needs-context <item-id> <agent-name> <lease-token> [expansion-json-file]", file=sys.stderr)
            sys.exit(1)
        expansion_file = extra[3] if len(extra) > 3 else None
        _needs_context(cfg, extra[0], extra[1], extra[2], expansion_file)
    elif action == "reset-stale":
        if not extra:
            print("Usage: code-dispatch reset-stale <minutes>", file=sys.stderr)
            sys.exit(1)
        minutes = int(extra[0])
        if minutes < 1:
            print("ERROR: code-dispatch reset-stale requires minutes >= 1", file=sys.stderr)
            sys.exit(1)
        _reset_stale(cfg, minutes)
    elif action == "retry-error":
        if not extra:
            print("Usage: code-dispatch retry-error <id1,id2,...> [reason]", file=sys.stderr)
            sys.exit(1)
        reason = " ".join(extra[1:])
        _retry_error(cfg, extra[0], reason)
    elif action == "retry-needs-context":
        if len(extra) < 2:
            print("Usage: code-dispatch retry-needs-context <id1,id2,...> <reason>", file=sys.stderr)
            sys.exit(1)
        _retry_needs_context(cfg, extra[0], " ".join(extra[1:]))
    elif action == "queue":
        if len(extra) != 1:
            print("Usage: code-dispatch queue <queue-items-json-file>", file=sys.stderr)
            sys.exit(1)
        _queue(cfg, extra[0], mode="initial")
    elif action == "reanalyze":
        if len(extra) < 2 or not " ".join(extra[1:]).strip():
            print(
                "Usage: code-dispatch reanalyze <queue-items-json-file> <reason>",
                file=sys.stderr,
            )
            sys.exit(1)
        _queue(cfg, extra[0], mode="reanalysis", reason=" ".join(extra[1:]))
    elif action == "requeue-triggers":
        if not extra:
            print("Usage: code-dispatch requeue-triggers <triggers-json-file>", file=sys.stderr)
            sys.exit(1)
        _requeue_triggers(cfg, extra[0])
    elif action == "list-triggers":
        status_filter = extra[0] if extra else "pending"
        _list_triggers(cfg, status_filter)
    elif action == "resolve-triggers":
        if len(extra) < 3:
            print(
                "Usage: code-dispatch resolve-triggers <triggers-json-file> "
                "<external_context_unavailable|source_equivalent_analyzed|not_applicable> <note>",
                file=sys.stderr,
            )
            sys.exit(1)
        _resolve_triggers(cfg, extra[0], extra[1], " ".join(extra[2:]))


def _validate_id_list(id_list: str) -> list[int]:
    """Validate and parse comma-separated ID list."""
    if re.fullmatch(r"[1-9][0-9]*(?:,[1-9][0-9]*)*", id_list) is None:
        print("ERROR: id-list must contain positive integer IDs separated by commas", file=sys.stderr)
        sys.exit(1)
    return [int(value) for value in id_list.split(",")]


def _validate_single_id(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        print("ERROR: item-id must be one positive integer", file=sys.stderr)
        raise SystemExit(1)
    return int(value)


def _stats(cfg) -> None:
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get('code/analysis-queue/stats')

    if isinstance(result, dict):
        print("=== Code Analysis Queue Stats ===")
        for key in ('pending', 'processing', 'done', 'error', 'needs_context'):
            val = result.get(key, 0)
            print(f"  {key}: {val}")
        total = result.get(
            'total',
            sum(result.get(k, 0) for k in ('pending', 'processing', 'done', 'error', 'needs_context')),
        )
        print(f"  total: {total}")
        # Print any extra fields
        for key, val in result.items():
            if key not in ('pending', 'processing', 'done', 'error', 'needs_context', 'total'):
                print(f"  {key}: {val}")
        if not total:
            # An all-zero queue reads like lost work. It is not: the queue has
            # exactly one writer, and classification is not it.
            print(
                "\nThe analysis queue is empty — classification does not populate it. "
                "Run `vigil assess code-dispatch queue <queue-items-json-file>` to "
                "queue classified files; `analyzed` counts require queue receipts."
            )
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _ids_from_file(path_value: str) -> list[int]:
    path = Path(path_value)
    is_process_descriptor = _PROCESS_DESCRIPTOR_PATH.fullmatch(path_value) is not None
    if not is_process_descriptor and not path.is_file():
        print(f"Queue ids file not found: {path_value}", file=sys.stderr)
        raise SystemExit(1)
    try:
        with path.open("rb") as handle:
            payload = handle.read(_MAX_QUEUE_IDS_FILE_BYTES + 1)
    except OSError as exc:
        print(f"Could not read queue ids file {path_value}: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    if len(payload) > _MAX_QUEUE_IDS_FILE_BYTES:
        print(
            f"Queue ids file exceeds {_MAX_QUEUE_IDS_FILE_BYTES} bytes",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        text = payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        print("Queue ids file must be valid UTF-8", file=sys.stderr)
        raise SystemExit(1) from None
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        tokens = [token for token in text.replace(",", " ").split() if token]
        if not tokens or any(re.fullmatch(r"[1-9][0-9]*", token) is None for token in tokens):
            print(
                "Queue ids file must contain a non-empty JSON array or positive id list",
                file=sys.stderr,
            )
            raise SystemExit(1)
        try:
            return sorted({int(token) for token in tokens})
        except ValueError:
            print("Queue ids file contains an invalid id", file=sys.stderr)
            raise SystemExit(1) from None
    except (ValueError, RecursionError):
        print("Queue ids file contains invalid or excessively complex JSON", file=sys.stderr)
        raise SystemExit(1) from None
    if isinstance(raw, dict):
        raw = raw.get("item_ids", raw.get("ids"))
    if not isinstance(raw, list) or not raw:
        print("Queue ids file must contain a non-empty JSON array or id list", file=sys.stderr)
        raise SystemExit(1)
    if any(type(value) is not int or value <= 0 for value in raw):
        print("Queue ids file contains a non-positive or non-integer id", file=sys.stderr)
        raise SystemExit(1)
    return sorted(set(raw))


def _parse_fetch_filters(tokens: list[str]) -> dict[str, object]:
    filters: dict[str, object] = {}
    index = 0
    options = {
        "--repo-id": "repo_id",
        "--classification": "classification",
        "--batch-theme": "batch_theme",
        "--queue-mode": "queue_mode",
        "--ids-file": "ids_file",
    }
    while index < len(tokens):
        option = tokens[index]
        field = options.get(option)
        if field is None or index + 1 >= len(tokens):
            print(f"Unknown or incomplete code-dispatch fetch option: {option}", file=sys.stderr)
            raise SystemExit(1)
        value = tokens[index + 1]
        if field == "repo_id":
            try:
                filters[field] = int(value)
            except ValueError:
                print("--repo-id must be an integer", file=sys.stderr)
                raise SystemExit(1) from None
        elif field == "ids_file":
            filters["item_ids"] = _ids_from_file(value)
        else:
            filters[field] = value
        index += 2
    return filters


# Flag -> query field, in the canonical order the query string is built, so the
# same filter set always produces the same endpoint regardless of typing order.
_LIST_FILTER_OPTIONS = (
    ("--status", "status"),
    ("--repo-id", "repo_id"),
    ("--classification", "classification"),
    ("--batch-theme", "batch_theme"),
    ("--queue-mode", "queue_mode"),
    ("--limit", "limit"),
    ("--offset", "offset"),
)
_LIST_INT_MINIMUMS = {"repo_id": 1, "limit": 1, "offset": 0}


def _parse_list_filters(tokens: list[str]) -> tuple[dict[str, str], str]:
    """Parse `code-dispatch list` flags into query fields plus an output mode."""
    fields = dict(_LIST_FILTER_OPTIONS)
    values: dict[str, str] = {}
    output = "table"
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"--json", "--ids-only"}:
            if output != "table":
                print(
                    "ERROR: choose either --json or --ids-only, not both",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            output = "json" if token == "--json" else "ids"
            index += 1
            continue
        field = fields.get(token)
        if field is None or index + 1 >= len(tokens):
            print(
                f"Unknown or incomplete code-dispatch list option: {token}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if field in values:
            print(f"ERROR: {token} was specified more than once", file=sys.stderr)
            raise SystemExit(1)
        value = tokens[index + 1]
        minimum = _LIST_INT_MINIMUMS.get(field)
        if minimum is None:
            if not value.strip():
                print(f"ERROR: {token} requires a value", file=sys.stderr)
                raise SystemExit(1)
        elif re.fullmatch(r"[0-9]+", value) is None or int(value) < minimum:
            print(
                f"ERROR: {token} requires an integer >= {minimum}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        values[field] = value
        index += 2
    return values, output


def _warn_if_page_is_partial(result: dict, output: str) -> None:
    """Say so on stderr when an ids file is only part of the queue.

    This verb exists because the insertion output truncates and its IDs become
    unrecoverable. A listing that silently stops at the page limit reproduces
    that failure one layer down, and `--ids-only` is where it would bite hardest:
    its whole purpose is to be redirected straight into a file that the operator
    then hands to `fetch --ids-file`, so a short page is a short claim set with
    nothing on stdout to reveal it. The table form already says "More rows".
    """
    if not result.get("has_more"):
        return
    listed = len(result.get("item_ids") or [])
    offset = int(result.get("offset", 0) or 0)
    total = result.get("total", "?")
    print(
        f"code-dispatch list: this page carries {listed} of {total} matching rows "
        f"(offset {offset}). Re-run with --offset {offset + listed} and concatenate, "
        f"or raise --limit, before using the output as an ids file.",
        file=sys.stderr,
    )


def _list(cfg, filters: dict[str, str], output: str) -> None:
    """Render one bounded page of the current-generation analysis queue."""
    query = urlencode(
        [(field, filters[field]) for _flag, field in _LIST_FILTER_OPTIONS if field in filters]
    )
    endpoint = "code/analysis-queue" + (f"?{query}" if query else "")
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(endpoint)

    if not isinstance(result, dict):
        print(
            "Backend returned a non-object analysis-queue listing", file=sys.stderr
        )
        raise SystemExit(1)
    if output in {"json", "ids"}:
        if output == "ids":
            print(json.dumps(result.get("item_ids") or []))
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        _warn_if_page_is_partial(result, output)
        return

    items = [item for item in (result.get("items") or []) if isinstance(item, dict)]
    total = result.get("total", len(items))
    offset = int(result.get("offset", 0) or 0)
    print(f"=== Code Analysis Queue ({len(items)} of {total}, offset {offset}) ===")
    if not items:
        print("No current-generation queue rows matched these filters.")
        return
    print(
        f"{'ID':>8}  {'STATUS':<13}{'MODE':<17}{'PRI':>4}  {'CLASS':<10}"
        f"{'THEME':<21}{'AGENT':<17}FILE"
    )
    for item in items:
        print(
            f"{item.get('id', '?')!s:>8}  {item.get('status', ''):<13}"
            f"{item.get('queue_mode', ''):<17}{item.get('priority', 0)!s:>4}  "
            f"{item.get('classification', ''):<10}{item.get('batch_theme', ''):<21}"
            f"{item.get('agent_name', ''):<17}{item.get('file_path', '')}"
        )
    if result.get("has_more"):
        print(f"\nMore rows: re-run with --offset {offset + len(items)}")
    print(
        "Add --ids-only (or --json) to write this page as an ids file for "
        "`code-dispatch fetch --ids-file`."
    )


def _prepare_dispatch_scratch_dir(
    engagement_dir: str | Path,
    *,
    queue_item_id: int,
    lease_token: str,
) -> Path:
    lease_key = hashlib.sha256(lease_token.encode("utf-8")).hexdigest()[:16]
    relative = Path(
        "tools",
        "analysis-state",
        "code-dispatch-scratch",
        str(queue_item_id),
        f"lease-{lease_key}",
    )
    root = Path(engagement_dir).resolve()
    current = root
    try:
        for component in relative.parts:
            current /= component
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ValueError
            current.resolve().relative_to(root)
        current.chmod(0o700)
    except (OSError, ValueError):
        print("Unsafe code-analysis scratch path", file=sys.stderr)
        raise SystemExit(1) from None
    return relative


def _fetch(cfg, limit: int, agent_name: str, filters: dict[str, object] | None = None) -> None:
    payload: dict[str, object] = {
        'limit': limit,
        'agent_name': agent_name,
        **(filters or {}),
    }
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/analysis-queue/fetch', payload)

    if isinstance(result, list):
        normalized_result: list[object] = []
        for raw_item in result:
            if not isinstance(raw_item, dict):
                normalized_result.append(raw_item)
                continue
            item = dict(raw_item)
            assigned_agent = item.pop("assigned_agent", None)
            if "agent_name" not in item and assigned_agent is not None:
                item["agent_name"] = assigned_agent
            queue_item_id = item.get("id")
            lease_token = item.get("lease_token")
            if type(queue_item_id) is not int or queue_item_id < 1 or not isinstance(lease_token, str) or not lease_token:
                print("Invalid code-analysis claim identity returned by backend", file=sys.stderr)
                raise SystemExit(1)
            scratch_relative = _prepare_dispatch_scratch_dir(
                cfg.engagement_dir,
                queue_item_id=queue_item_id,
                lease_token=lease_token,
            )
            item["scratch_dir"] = scratch_relative.as_posix()
            normalized_result.append(item)
        result = normalized_result

    if result == []:
        filter_text = ", ".join(
            f"{key}={value}" for key, value in sorted((filters or {}).items())
        ) or "none"
        print(
            "No current pending code-analysis queue items matched the claim filters "
            f"({filter_text}). Inspect `vigil assess code-dispatch stats` and the "
            "code-files queue join before retrying.",
            file=sys.stderr,
        )

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-fetch",
        label=agent_name,
        payload=result,
        metadata={
            "command": "code-dispatch fetch",
            "agent_name": agent_name,
            "limit": limit,
            "filters": filters or {},
        },
    )
    print(f"Saved audit snapshot: {snapshot.name}", file=sys.stderr)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def _done(
    cfg,
    id_list: str,
    agent_name: str,
    lease_token: str,
    disposition: str,
    cwe_file: str,
    notes: str = "",
    *,
    dry_run: bool = False,
    skip_reason: str = "",
) -> None:
    ids = [_validate_single_id(id_list)]
    normalized_disposition = disposition.strip().lower()
    if normalized_disposition not in _DONE_DISPOSITIONS:
        print(
            f"ERROR: invalid disposition {disposition!r}; expected one of: {', '.join(_DONE_DISPOSITIONS)}",
            file=sys.stderr,
        )
        sys.exit(1)
    # C50: client-side check (backend also enforces) for clearer operator
    # feedback before the round-trip.
    if normalized_disposition == "skipped" and not skip_reason.strip():
        print(
            "ERROR: --skip-reason is required when disposition=skipped; "
            f"suggested values: {', '.join(_SKIP_REASONS_HINT)}",
            file=sys.stderr,
        )
        sys.exit(1)

    cwe_path = Path(cwe_file)
    if not cwe_path.is_file():
        print(f"CWE coverage JSON file not found: {cwe_file}", file=sys.stderr)
        sys.exit(1)
    cwe_data = json.loads(cwe_path.read_text(encoding="utf-8"))
    if not isinstance(cwe_data, list):
        print("CWE coverage payload must be a JSON array", file=sys.stderr)
        sys.exit(1)
    for idx, entry in enumerate(cwe_data):
        if not isinstance(entry, dict):
            print(f"CWE coverage entry {idx} must be a JSON object", file=sys.stderr)
            sys.exit(1)
        family = str(entry.get("family", "")).strip()
        if not family:
            print(
                f"CWE coverage entry {idx} is missing family; expected entries like "
                "{\"family\":\"ssrf\",\"effort\":80}",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            float(entry.get("effort", 0))
        except (TypeError, ValueError):
            print(f"CWE coverage entry {idx} has a non-numeric effort", file=sys.stderr)
            sys.exit(1)

    payload: dict = {
        'item_ids': ids,
        'agent_name': agent_name,
        'lease_token': lease_token,
        'disposition': normalized_disposition,
    }
    if notes:
        payload['notes'] = notes
    payload['cwe_coverage'] = cwe_data
    if skip_reason:
        payload['skip_reason'] = skip_reason
    if dry_run:
        print("Dry run only; no queue state was changed.")
        print(json.dumps({"endpoint": "code/analysis-queue/done", "payload": payload}, indent=2, ensure_ascii=False))
        return
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/analysis-queue/done', payload)

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-done",
        label=normalized_disposition,
        payload=result,
        metadata={"command": "code-dispatch done", "item_ids": ids, "disposition": normalized_disposition},
    )
    updated = result.get('updated', 0) if isinstance(result, dict) else result
    print(f"Marked done ({normalized_disposition}): {updated} item(s)")
    print(f"Saved audit snapshot: {snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _heartbeat(cfg, item_id: str, agent_name: str, lease_token: str) -> None:
    item_id_value = _validate_single_id(item_id)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/analysis-queue/heartbeat', {
            'item_id': item_id_value, 'agent_name': agent_name, 'lease_token': lease_token,
        })
    print(json.dumps(result, indent=2, ensure_ascii=False))


def _error(cfg, id_list: str, agent_name: str, lease_token: str, notes: str = "") -> None:
    ids = [_validate_single_id(id_list)]
    payload: dict = {'item_ids': ids, 'agent_name': agent_name, 'lease_token': lease_token}
    if notes:
        payload['notes'] = notes
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/analysis-queue/error', payload)

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-error",
        label="items",
        payload=result,
        metadata={"command": "code-dispatch error", "item_ids": ids},
    )
    updated = result.get('updated', 0) if isinstance(result, dict) else result
    print(f"Marked error: {updated} item(s)")
    print(f"Saved audit snapshot: {snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _needs_context(
    cfg, id_list: str, agent_name: str, lease_token: str, expansion_file: str | None
) -> None:
    ids = [_validate_single_id(id_list)]

    payload: dict = {'item_ids': ids, 'agent_name': agent_name, 'lease_token': lease_token}
    if expansion_file:
        ep = Path(expansion_file)
        if not ep.is_file():
            print(f"Expansion JSON file not found: {expansion_file}", file=sys.stderr)
            sys.exit(1)
        expansion = json.loads(ep.read_text(encoding="utf-8"))
        payload['expansion_request'] = expansion

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/analysis-queue/needs-context', payload)

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-needs-context",
        label="items",
        payload={"request": payload, "response": result},
        source_path=expansion_file,
        metadata={"command": "code-dispatch needs-context", "item_ids": ids},
    )
    print(f"Marked needs-context: {id_list}")
    print(f"Saved audit snapshot: {snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _reset_stale(cfg, minutes: int) -> None:
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/analysis-queue/reset-stale', {'minutes': minutes})

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-reset-stale",
        label=f"{minutes}m",
        payload=result,
        metadata={"command": "code-dispatch reset-stale", "minutes": minutes},
    )
    reset_count = result.get('reset', 0) if isinstance(result, dict) else 0
    print(f"Reset {reset_count} stale item(s) (stuck > {minutes} min)")
    print(f"Saved audit snapshot: {snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _retry_error(cfg, id_list: str, reason: str = "") -> None:
    """C5.1: recover status='error' queue items back to 'pending' by id.

    Unlike `reset-stale` (time-windowed, 'processing' only), this is
    id-scoped and requires every id to currently be 'error' — the backend
    409s if any id has already moved (e.g. re-fetched, completed) since the
    operator listed it.
    """
    ids = _validate_id_list(id_list)
    payload: dict = {'item_ids': ids}
    if reason:
        payload['reason'] = reason
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/analysis-queue/retry-error', payload)

    snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-retry-error",
        label="items",
        payload=result,
        metadata={"command": "code-dispatch retry-error", "item_ids": ids, "reason": reason},
    )
    retried = result.get('retried', 0) if isinstance(result, dict) else 0
    print(f"Retried (error -> pending): {retried} item(s)")
    print(f"Saved audit snapshot: {snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def _retry_needs_context(cfg, id_list: str, reason: str) -> None:
    ids = _validate_id_list(id_list)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/analysis-queue/retry-needs-context', {
            'item_ids': ids, 'reason': reason,
        })
    print(f"Retried (needs_context -> pending): {result.get('retried', 0)} item(s)")
    print(json.dumps(result, indent=2, ensure_ascii=False))


def _queue_lookup_matches(row: dict, selectors: list[dict]) -> bool:
    return _compiled_queue_lookup_matches(row, _compile_queue_lookup(selectors))


def _compile_queue_lookup(
    selectors: list[dict],
) -> tuple[set[str], set[tuple[int, str]], list[dict]]:
    """Index exact selectors once while retaining glob matching semantics."""

    unscoped_paths: set[str] = set()
    repo_paths: set[tuple[int, str]] = set()
    glob_selectors: list[dict] = []
    for selector in selectors:
        requested = str(selector.get("file_path", "")).strip()
        if any(character in requested for character in "*?["):
            glob_selectors.append(selector)
            continue
        repo_id = selector.get("repo_id")
        if repo_id in (None, ""):
            unscoped_paths.add(requested)
        elif type(repo_id) is int:
            repo_paths.add((repo_id, requested))
    return unscoped_paths, repo_paths, glob_selectors


def _compiled_queue_lookup_matches(
    row: dict,
    lookup: tuple[set[str], set[tuple[int, str]], list[dict]],
) -> bool:
    unscoped_paths, repo_paths, glob_selectors = lookup
    candidate = str(row.get("file_path", ""))
    if candidate in unscoped_paths:
        return True
    row_repo_id = row.get("repo_id")
    if type(row_repo_id) is int and (row_repo_id, candidate) in repo_paths:
        return True
    for selector in glob_selectors:
        requested = str(selector.get("file_path", "")).strip()
        repo_id = selector.get("repo_id")
        if repo_id not in (None, "") and row.get("repo_id") != repo_id:
            continue
        if fnmatch(candidate, requested):
            return True
    return False


def _fetch_code_files(cfg, selectors: list[dict]) -> list[dict]:
    lookup = _compile_queue_lookup(selectors)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        matched_by_id: dict[int, dict] = {}
        offset = 0
        expected_total: int | None = None
        result: list[dict] | None = None
        while True:
            page = client.get(f'code/files?limit={_CODE_FILE_LOOKUP_PAGE_SIZE}&offset={offset}')
            try:
                items, total, has_more = parse_code_file_page(
                    page,
                    expected_offset=offset,
                    context="code queue file lookup response",
                )
            except ValueError:
                result = None
                break
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                result = None
                break
            invalid_row = False
            for row in items:
                if not _compiled_queue_lookup_matches(row, lookup):
                    continue
                file_id = row.get("id")
                if type(file_id) is not int or file_id <= 0:
                    invalid_row = True
                    break
                matched_by_id[file_id] = row
                if len(matched_by_id) > _MAX_QUEUE_LOOKUP_MATCHES:
                    print(
                        "Queue path lookup exceeds the bounded match cap of "
                        f"{_MAX_QUEUE_LOOKUP_MATCHES}; split broad globs into smaller "
                        "path or repository selections",
                        file=sys.stderr,
                    )
                    sys.exit(1)
            if invalid_row:
                break
            if not has_more:
                result = list(matched_by_id.values())
                break
            offset += len(items)
    if result is None:
        print("Could not fetch code files for queue normalization", file=sys.stderr)
        sys.exit(1)
    return result


def _normalize_string_list(value) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if item in (None, ""):
                continue
            if isinstance(item, str):
                result.append(item)
            else:
                result.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
        return result
    if isinstance(value, str):
        return [value]
    return [json.dumps(value, ensure_ascii=False, sort_keys=True)]


def _flatten_queue_specs(item, inherited: dict | None = None) -> list[dict]:
    if not isinstance(item, dict):
        print("Queue items must be JSON objects", file=sys.stderr)
        sys.exit(1)

    inherited_fields = dict(inherited or {})
    for key in ('priority', 'batch_theme', 'slot_types', 'guidance_hypotheses', 'repo_id'):
        if key in item and item[key] not in (None, ""):
            inherited_fields[key] = item[key]

    for collection_key in ('items', 'batches'):
        if collection_key in item:
            collection = item.get(collection_key)
            if not isinstance(collection, list):
                print(f"Queue field '{collection_key}' must be a JSON array", file=sys.stderr)
                sys.exit(1)
            flattened: list[dict] = []
            for child in collection:
                flattened.extend(_flatten_queue_specs(child, inherited_fields))
            return flattened

    if 'files' in item:
        collection = item.get('files')
        if not isinstance(collection, list):
            print("Queue field 'files' must be a JSON array", file=sys.stderr)
            sys.exit(1)
        flattened = []
        for child in collection:
            if isinstance(child, str):
                child_item = {'file_path': child}
            elif isinstance(child, dict):
                child_item = child
            else:
                print("Queue 'files' entries must be strings or JSON objects", file=sys.stderr)
                sys.exit(1)
            flattened.extend(_flatten_queue_specs(child_item, inherited_fields))
        return flattened

    if 'file_paths' in item:
        collection = item.get('file_paths')
        if not isinstance(collection, list):
            print("Queue field 'file_paths' must be a JSON array", file=sys.stderr)
            sys.exit(1)
        flattened = []
        for file_path in collection:
            flattened.extend(_flatten_queue_specs({'file_path': file_path}, inherited_fields))
        return flattened

    if 'path' in item and 'file_path' not in item:
        item = dict(item)
        item['file_path'] = item.pop('path')
    if 'glob' in item and 'file_path' not in item:
        item = dict(item)
        item['file_path'] = item.pop('glob')

    if 'file_id' in item or 'file_path' in item:
        leaf = dict(inherited_fields)
        leaf.update(item)
        return [leaf]

    print("Queue item is missing file_id/file_path or a supported batch wrapper", file=sys.stderr)
    sys.exit(1)


def _resolve_queue_file_ids(item: dict, code_files: list[dict]) -> list[int]:
    file_id = item.get('file_id')
    if file_id not in (None, ""):
        if type(file_id) is not int or file_id <= 0:
            print(f"Invalid queue file_id: {file_id!r}", file=sys.stderr)
            sys.exit(1)
        return [file_id]

    file_path = str(item.get('file_path', '')).strip()
    if not file_path:
        print("Queue item must include file_id or file_path", file=sys.stderr)
        sys.exit(1)

    repo_id = item.get('repo_id')
    if repo_id not in (None, ""):
        if type(repo_id) is not int or repo_id <= 0:
            print(f"Invalid queue repo_id: {repo_id!r}", file=sys.stderr)
            sys.exit(1)
    else:
        repo_id = None

    has_glob = any(ch in file_path for ch in "*?[")
    matches: list[dict] = []
    for row in code_files:
        candidate = str(row.get('file_path', ''))
        if has_glob:
            if fnmatch(candidate, file_path):
                matches.append(row)
        elif candidate == file_path:
            matches.append(row)

    if repo_id is not None:
        matches = [row for row in matches if int(row.get('repo_id', -1)) == repo_id]

    if not matches:
        print(f"No code file found for queue path: {file_path}", file=sys.stderr)
        sys.exit(1)

    if not has_glob and len(matches) > 1:
        print(
            f"Ambiguous queue path {file_path!r}; include file_id or repo_id to disambiguate",
            file=sys.stderr,
        )
        sys.exit(1)

    return [int(row['id']) for row in matches]


def _normalize_queue_items(cfg, raw_items: list[dict]) -> list[dict]:
    flattened: list[dict] = []
    for item in raw_items:
        flattened.extend(_flatten_queue_specs(item))
        if len(flattened) > _MAX_QUEUE_NORMALIZED_ITEMS:
            print(
                "Queue input exceeds the bounded item cap of "
                f"{_MAX_QUEUE_NORMALIZED_ITEMS}; split it into smaller submissions",
                file=sys.stderr,
            )
            sys.exit(1)

    needs_lookup = any(entry.get('file_id') in (None, "") for entry in flattened)
    lookup_selectors = [
        entry for entry in flattened if entry.get("file_id") in (None, "")
    ]
    code_files = _fetch_code_files(cfg, lookup_selectors) if needs_lookup else []

    normalized: list[dict] = []
    seen: set[str] = set()
    for entry in flattened:
        if entry.get('context_id') not in (None, ""):
            print(
                "Queue item includes obsolete field `context_id`. "
                "The hunt queue is file-level only and carries file_id plus metadata such as "
                "batch_theme, slot_types, guidance_hypotheses, and structural-index context.",
                file=sys.stderr,
            )
            sys.exit(1)

        file_ids = _resolve_queue_file_ids(entry, code_files)
        if entry.get('priority') in (None, ""):
            print("Queue item requires explicit priority", file=sys.stderr)
            sys.exit(1)
        priority = entry['priority']
        if type(priority) is not int:
            print("Queue priority must be an integer", file=sys.stderr)
            sys.exit(1)
        if not 0 <= priority <= 100:
            print("Queue priority must be between 0 and 100", file=sys.stderr)
            sys.exit(1)
        for file_id in file_ids:
            normalized_item: dict = {
                'file_id': file_id,
                'priority': priority,
                'batch_theme': str(entry.get('batch_theme', '')),
                'slot_types': _normalize_string_list(entry.get('slot_types')),
                'guidance_hypotheses': _normalize_string_list(entry.get('guidance_hypotheses')),
            }
            supersedes = entry.get("supersedes")
            if supersedes is not None:
                if type(supersedes) is not int or supersedes <= 0:
                    print("Queue supersedes must be a positive integer row ID", file=sys.stderr)
                    sys.exit(1)
                normalized_item["supersedes"] = supersedes

            dedupe_key = json.dumps(normalized_item, sort_keys=True, ensure_ascii=False)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            normalized.append(normalized_item)
            if len(normalized) > _MAX_QUEUE_NORMALIZED_ITEMS:
                print(
                    "Expanded queue selection exceeds the bounded item cap of "
                    f"{_MAX_QUEUE_NORMALIZED_ITEMS}; split globs or metadata variants "
                    "into smaller submissions",
                    file=sys.stderr,
                )
                sys.exit(1)

    return normalized


def _queue(
    cfg,
    queue_items_file: str,
    *,
    mode: str = "initial",
    reason: str = "",
) -> None:
    """Queue analysis items. Items can include batch_theme, slot_types, and
    guidance_hypotheses fields alongside the existing format — those are
    normalized (explicit priority validated, string lists flattened) before
    being posted to the backend."""
    fp = Path(queue_items_file)
    if not fp.is_file():
        print(f"Queue items JSON file not found: {queue_items_file}", file=sys.stderr)
        sys.exit(1)

    try:
        raw_items = read_bounded_regular_file(
            fp,
            max_bytes=_MAX_QUEUE_INPUT_BYTES,
            label="queue input",
        )
    except (OSError, ValueError) as exc:
        print(
            "Queue items file exceeds the bounded input cap or cannot be read "
            f"safely: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    items = json.loads(raw_items)
    if isinstance(items, dict):
        # Single item wrapped
        items = [items]
    if not isinstance(items, list):
        print("Queue items file must contain a JSON array or object", file=sys.stderr)
        sys.exit(1)

    normalized_items = _normalize_queue_items(cfg, items)
    if not normalized_items:
        print("Queue input does not contain any queue items", file=sys.stderr)
        sys.exit(1)

    normalized_mode = str(mode).strip().lower()
    normalized_reason = str(reason).strip()
    if normalized_mode not in {"initial", "reanalysis"}:
        print("Queue mode must be initial or reanalysis", file=sys.stderr)
        sys.exit(1)
    if normalized_mode == "reanalysis" and not normalized_reason:
        print("Reanalysis reason is required", file=sys.stderr)
        sys.exit(1)
    if normalized_mode == "reanalysis" and any(
        item.get("supersedes") is None for item in normalized_items
    ):
        print(
            "Every reanalysis item requires supersedes with the exact predecessor queue row ID",
            file=sys.stderr,
        )
        sys.exit(1)
    if normalized_mode == "initial" and any(
        item.get("supersedes") is not None for item in normalized_items
    ):
        print("Initial queue items must not set supersedes", file=sys.stderr)
        sys.exit(1)

    request_payload: dict[str, object] = {
        "mode": normalized_mode,
        "items": normalized_items,
    }
    if normalized_mode == "reanalysis":
        request_payload["reason"] = normalized_reason
    command_name = (
        "code-dispatch reanalyze"
        if normalized_mode == "reanalysis"
        else "code-dispatch queue"
    )

    submit_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-submit",
        label=fp.stem,
        payload={
            "input": items,
            "normalized": normalized_items,
            "mode": normalized_mode,
            "reason": normalized_reason,
        },
        source_path=str(fp),
        metadata={
            "command": command_name,
            "mode": normalized_mode,
            "count": len(normalized_items),
        },
    )
    totals = {
        "inserted": 0,
        "updated": 0,
        "already_active": 0,
        "conflicts": 0,
        "reanalysis": 0,
    }
    reported_outcomes: list[dict] = []
    response_snapshots: list[Path] = []
    batch_count = (
        len(normalized_items) + _QUEUE_SUBMISSION_BATCH_SIZE - 1
    ) // _QUEUE_SUBMISSION_BATCH_SIZE
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for batch_index, start in enumerate(
            range(0, len(normalized_items), _QUEUE_SUBMISSION_BATCH_SIZE),
            start=1,
        ):
            batch = normalized_items[start : start + _QUEUE_SUBMISSION_BATCH_SIZE]
            batch_payload = dict(request_payload)
            batch_payload["items"] = batch
            result = client.post("code/analysis-queue", batch_payload)
            response = result if isinstance(result, dict) else {}
            for key in totals:
                totals[key] += int(response.get(key, len(batch) if key == "inserted" else 0))
            outcomes = response.get("outcomes", [])
            if isinstance(outcomes, list) and len(reported_outcomes) < _MAX_QUEUE_REPORTED_OUTCOMES:
                remaining = _MAX_QUEUE_REPORTED_OUTCOMES - len(reported_outcomes)
                reported_outcomes.extend(
                    outcome for outcome in outcomes[:remaining] if isinstance(outcome, dict)
                )
            label = fp.stem if batch_count == 1 else f"{fp.stem}-batch-{batch_index:04d}"
            response_snapshots.append(
                write_json_snapshot(
                    cfg.engagement_dir,
                    category="code-queue-response",
                    label=label,
                    payload=result,
                    source_path=str(submit_snapshot),
                    metadata={
                        "command": command_name,
                        "mode": normalized_mode,
                        "count": len(batch),
                        "batch": batch_index,
                        "batches": batch_count,
                    },
                )
            )
            if totals["conflicts"]:
                break

    inserted_count = totals["inserted"]
    updated_count = totals["updated"]
    already_active_count = totals["already_active"]
    conflict_count = totals["conflicts"]
    reanalysis_count = totals["reanalysis"]
    print(
        "Queue outcomes: "
        f"inserted={inserted_count}, updated={updated_count}, "
        f"already-active={already_active_count}, conflicts={conflict_count}, "
        f"reanalysis={reanalysis_count}"
    )
    snapshot_names = ", ".join(path.name for path in response_snapshots)
    print(f"Audit snapshots: {submit_snapshot.name}, {snapshot_names}")
    print(
        json.dumps(
            {
                "batches_completed": len(response_snapshots),
                "batches_total": batch_count,
                "outcomes": reported_outcomes,
                "outcomes_truncated": sum(totals.values()) > len(reported_outcomes),
                **totals,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    if conflict_count:
        print(
            f"Queue submission reported {conflict_count} conflict(s)",
            file=sys.stderr,
        )
        sys.exit(1)


# One strict selector per input. `list-triggers` rows carry `id` AND
# `target_file_path`, so trigger_id wins over the path it already implies;
# file_id and trigger_id name different rows and are never both accepted.
_TRIGGER_ID_FIELDS = ("trigger_id", "id")
_TRIGGER_PATH_FIELDS = ("file_path", "target_file_path")
_TRIGGER_PAYLOAD_FIELDS = ("priority", "batch_theme", "slot_types", "guidance_hypotheses")
# Durable trigger-row columns. The backend rehydrates these onto the queue row
# from its own tables, so echoing them back as free context only duplicates
# state — `vuln_class` and `reason` are the specialist's words and stay.
_TRIGGER_ROW_FIELDS = frozenset({
    "id",
    "trigger_id",
    "engagement_id",
    "repo_id",
    "repo_generation",
    "source_queue_item_id",
    "source_file_id",
    "source_file_path",
    "target_file_id",
    "target_file_path",
    "resolved_target_file_path",
    "resolved_queue_item_id",
    "status",
    "resolution_note",
    "source_manifest_digest",
    "source_superseded_at",
    "source_supersession_reason",
    "replacement_repo_generation",
    "created_at",
    "updated_at",
})


_REQUEUE_RESPONSE_COUNTS = (
    "input_trigger_count",
    "target_count",
    "inserted",
    "already_queued",
    "already_completed",
    "blocked",
    "reopened_terminal_files",
)


def _require_positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        print(f"ERROR: {label} must be a positive integer", file=sys.stderr)
        raise SystemExit(1)
    return value


def _requeue_item(trigger: object, index: int) -> dict:
    """Normalize one trigger input into the backend's strict requeue item."""
    if not isinstance(trigger, dict):
        print(
            f"ERROR: trigger {index} must be a JSON object naming one target; "
            "a bare id is not a selector",
            file=sys.stderr,
        )
        raise SystemExit(1)

    item: dict = {}
    file_id = trigger.get("file_id")
    trigger_id = next(
        (trigger[field] for field in _TRIGGER_ID_FIELDS if trigger.get(field) is not None),
        None,
    )
    if file_id is not None and trigger_id is not None:
        print(
            f"ERROR: trigger {index} names both file_id and trigger_id; supply "
            "exactly one selector",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if file_id is not None:
        item["file_id"] = _require_positive_int(file_id, f"trigger {index} file_id")
    elif trigger_id is not None:
        item["trigger_id"] = _require_positive_int(
            trigger_id, f"trigger {index} trigger_id"
        )
    else:
        file_path = next(
            (
                str(trigger[field]).strip()
                for field in _TRIGGER_PATH_FIELDS
                if str(trigger.get(field) or "").strip()
            ),
            "",
        )
        if not file_path:
            print(
                f"ERROR: trigger {index} needs file_id, trigger_id/id, or "
                "file_path/target_file_path",
                file=sys.stderr,
            )
            raise SystemExit(1)
        item["file_path"] = file_path
        if trigger.get("repo_id") is not None:
            item["repo_id"] = _require_positive_int(
                trigger["repo_id"], f"trigger {index} repo_id"
            )

    if trigger.get("reason"):
        item["reason"] = str(trigger["reason"])
    for field in _TRIGGER_PAYLOAD_FIELDS:
        if trigger.get(field) is not None:
            item[field] = trigger[field]
    context = {
        key: value
        for key, value in trigger.items()
        if key not in _TRIGGER_ROW_FIELDS
        and key not in _TRIGGER_PAYLOAD_FIELDS
        and key not in {"file_id", "file_path", "reason"}
    }
    context["source"] = "cross_file_trigger"
    item["trigger_context"] = context
    return item


def _requeue_triggers(cfg, triggers_file: str) -> None:
    """Requeue cross-file triggers as new analysis queue items.

    Accepts a bare array or an object holding `cross_file_triggers`/`triggers`/
    `items`, so both an analysis result's trigger array and `list-triggers`
    output are consumable unchanged. Every input is reduced to exactly one
    selector before the write, and the response's per-target outcomes decide the
    exit status: a batch that left any target blocked or any selector
    unresolved is not a success.
    """
    fp = Path(triggers_file)
    if not fp.is_file():
        print(f"Triggers JSON file not found: {triggers_file}", file=sys.stderr)
        sys.exit(1)

    raw = json.loads(fp.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        triggers = raw.get(
            "cross_file_triggers", raw.get("triggers", raw.get("items", []))
        )
    elif isinstance(raw, list):
        triggers = raw
    else:
        print("Triggers file must contain a JSON array or object", file=sys.stderr)
        sys.exit(1)

    if not isinstance(triggers, list) or not triggers:
        print("Triggers file does not contain any triggers to requeue", file=sys.stderr)
        sys.exit(1)

    items = [_requeue_item(trigger, index) for index, trigger in enumerate(triggers)]

    submit_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-requeue-triggers",
        label=fp.stem,
        payload=items,
        source_path=str(fp),
        metadata={"command": "code-dispatch requeue-triggers", "count": len(items)},
    )
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/analysis-queue/requeue', {'items': items})

    response_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-queue-requeue-response",
        label=fp.stem,
        payload=result,
        source_path=str(submit_snapshot),
        metadata={"command": "code-dispatch requeue-triggers", "count": len(items)},
    )
    if not isinstance(result, dict):
        print("Backend returned a non-object requeue response", file=sys.stderr)
        sys.exit(1)

    counts: dict[str, int] = {}
    for field in _REQUEUE_RESPONSE_COUNTS:
        value = result.get(field)
        if type(value) is not int:
            # Exit status depends on these, so an absent count must fail closed
            # rather than read as zero blocked targets.
            print(f"Requeue response is missing the {field} count", file=sys.stderr)
            sys.exit(1)
        counts[field] = value
    blocked = counts["blocked"]
    not_found = result.get("not_found") or []
    ambiguous = result.get("ambiguous") or []
    print(
        f"Requeued {counts['input_trigger_count']} trigger input(s) across "
        f"{counts['target_count']} target(s): "
        f"inserted={counts['inserted']}, "
        f"already-queued={counts['already_queued']}, "
        f"already-completed={counts['already_completed']}, "
        f"blocked={blocked}"
    )
    reopened = counts["reopened_terminal_files"]
    if reopened:
        print(f"  reopened {reopened} terminal file(s) with a new trigger attempt")
    print(f"Audit snapshots: {submit_snapshot.name}, {response_snapshot.name}")
    print(json.dumps(result, indent=2, ensure_ascii=False))

    outcomes = result.get("outcomes")
    if isinstance(outcomes, list):
        for outcome in outcomes:
            if isinstance(outcome, dict) and outcome.get("outcome") == "blocked":
                print(
                    f"  blocked: {outcome.get('file_path', '?')} "
                    f"(file_id={outcome.get('file_id', '?')}) — "
                    f"{outcome.get('detail', 'no reason reported')}",
                    file=sys.stderr,
                )
    for label in not_found:
        print(f"  not found: {label}", file=sys.stderr)
    for label in ambiguous:
        print(f"  ambiguous without repo_id: {label}", file=sys.stderr)
    if blocked or not_found or ambiguous:
        print(
            f"code-dispatch requeue-triggers: {blocked} blocked target(s), "
            f"{len(not_found)} unresolved and {len(ambiguous)} ambiguous "
            "selector(s). Unblocked targets were committed; re-check each "
            "reported selector against `code-dispatch list-triggers` and "
            "`code-dispatch list` before retrying.",
            file=sys.stderr,
        )
        sys.exit(1)


def _list_triggers(cfg, status_filter: str) -> None:
    endpoint = "code/triggers"
    if status_filter:
        endpoint = f"{endpoint}?status={status_filter}"
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.get(endpoint)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def _resolve_triggers(cfg, triggers_file: str, resolution_status: str, note: str) -> None:
    fp = Path(triggers_file)
    if not fp.is_file():
        print(f"Triggers JSON file not found: {triggers_file}", file=sys.stderr)
        sys.exit(1)

    raw = json.loads(fp.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw_items = raw.get("items", raw.get("triggers", raw.get("cross_file_triggers", [])))
    elif isinstance(raw, list):
        raw_items = raw
    else:
        print("Triggers file must contain a JSON array or object", file=sys.stderr)
        sys.exit(1)

    if not isinstance(raw_items, list) or not raw_items:
        print("No triggers to resolve.", file=sys.stderr)
        sys.exit(1)

    items: list[dict] = []
    for idx, trigger in enumerate(raw_items):
        if not isinstance(trigger, dict):
            print(f"Trigger item {idx} must be a JSON object", file=sys.stderr)
            sys.exit(1)
        item: dict = {}
        for source_key, target_key in (
            ("trigger_id", "trigger_id"),
            ("id", "id"),
            ("file_path", "file_path"),
            ("target_file_path", "target_file_path"),
            ("repo_id", "repo_id"),
            ("vuln_class", "vuln_class"),
        ):
            if source_key in trigger and trigger[source_key] not in (None, ""):
                item[target_key] = trigger[source_key]
        if not any(key in item for key in ("trigger_id", "id", "file_path", "target_file_path")):
            print(
                f"Trigger item {idx} needs trigger_id/id or file_path/target_file_path",
                file=sys.stderr,
            )
            sys.exit(1)
        items.append(item)

    payload = {
        "items": items,
        "resolution_status": resolution_status,
        "resolution_note": note,
    }
    submit_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-trigger-resolve",
        label=fp.stem,
        payload=payload,
        source_path=str(fp),
        metadata={"command": "code-dispatch resolve-triggers", "count": len(items)},
    )
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post("code/triggers/resolve", payload)

    response_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-trigger-resolve-response",
        label=fp.stem,
        payload=result,
        source_path=str(submit_snapshot),
        metadata={"command": "code-dispatch resolve-triggers", "count": len(items)},
    )
    resolved_count = result.get("resolved", 0) if isinstance(result, dict) else 0
    not_resolved = result.get("not_resolved", []) if isinstance(result, dict) else []
    if not isinstance(not_resolved, list):
        not_resolved = [not_resolved]
    print(f"Resolved {resolved_count} of {len(items)} trigger(s)")
    print(f"Audit snapshots: {submit_snapshot.name}, {response_snapshot.name}")
    if isinstance(result, dict) and result:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    # `resolve` is a one-way pending -> terminal transition, so a request that
    # wrote nothing is not a no-op the caller can shrug off: it means the item
    # shapes never addressed a pending trigger. Exit loudly rather than 0.
    if not_resolved:
        for label in not_resolved:
            print(f"  unresolved: {label}", file=sys.stderr)
    if resolved_count == 0 or not_resolved:
        print(
            f"code-dispatch resolve-triggers: resolved {resolved_count} of "
            f"{len(items)} item(s); {len(not_resolved)} unresolved. Re-check each "
            "item's trigger_id/file_path against `code-dispatch list-triggers` — a "
            "trigger that already left `pending` can no longer be resolved.",
            file=sys.stderr,
        )
        sys.exit(1)
