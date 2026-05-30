"""aith assess anomaly-score — deterministic HTTP response anomaly oracle.

Scores a *population* of HTTP response records for anomalousness, surfacing
the odd-one-out(s) without any LLM or network call.  Specialist agents supply
the population as a JSON file or via stdin; the command returns a ranked list
of outliers annotated with the specific attributes that made them stand out.

Input format (auto-detected):
  - Top-level JSON array:  ``[{...}, {...}, ...]``
  - JSONL (one JSON object per line)

A record may contain any subset of:
  url, status (or response_status), content_length (or length / body_len),
  content_type, title, words, lines, headers (dict).

Missing fields are silently skipped — the oracle is tolerant of partial records.

Output (human-readable, default):
  Prints the top-N ranked outliers with score + anomalous attributes.

Output (``--json``):
  Emits a JSON array of the top-N annotated records, sorted descending by
  ``anomaly_score``.
"""
from __future__ import annotations

import json
import sys


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "anomaly-score",
        help=(
            "Score a population of HTTP response records and rank outliers "
            "(no LLM, no network, pure stdlib)."
        ),
    )
    p.add_argument(
        "records_file",
        nargs="?",
        default=None,
        help=(
            "Path to a JSON array or JSONL file of response records. "
            "Reads from stdin if omitted."
        ),
    )
    p.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top-ranked outliers to show (default: 10; 0 = all).",
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        default=False,
        help="Emit JSON output (machine-readable).",
    )
    p.set_defaults(func=run)


def _load_records(source: str) -> list[dict]:
    """Parse a JSON array or JSONL payload into a list of dicts."""
    text = source.strip()
    if not text:
        return []

    # A leading '[' means the caller intends a JSON array — parse it as one and
    # surface errors rather than silently degrading to JSONL, which would drop
    # records from a malformed multi-line array and skew the population stats.
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"input starts with '[' but is not valid JSON: {exc}") from exc
        if not isinstance(data, list):
            raise ValueError("input JSON must be an array of record objects")
        return [r for r in data if isinstance(r, dict)]

    # JSONL: one JSON object per non-empty line
    records: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            pass  # skip malformed lines

    return records


def _read_input(records_file: str | None) -> str:
    """Read raw text from a file path or stdin."""
    if records_file is not None:
        with open(records_file, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return sys.stdin.read()


def run(args) -> None:
    from assess.lib.anomaly import score_population

    raw = _read_input(getattr(args, "records_file", None))
    try:
        records = _load_records(raw)
    except ValueError as exc:
        print(f"anomaly-score: {exc}", file=sys.stderr)
        sys.exit(1)

    if not records:
        if getattr(args, "as_json", False):
            print(json.dumps([], ensure_ascii=False))
        else:
            print("No records to score.", file=sys.stderr)
        sys.stdout.flush()
        return

    ranked = score_population(records)

    top_n = getattr(args, "top", 10)
    if top_n and top_n > 0:
        output = ranked[:top_n]
    else:
        output = ranked

    as_json = getattr(args, "as_json", False)

    if as_json:
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        total = len(ranked)
        showing = len(output)
        print(
            f"anomaly-score: {total} record(s) scored, showing top {showing}"
            + (" (all)" if showing == total else "")
        )
        print()
        for rank, rec in enumerate(output, 1):
            score = rec.get("anomaly_score", 0.0)
            attrs = rec.get("anomalous_attributes") or []
            url = rec.get("url", rec.get("_url", "(no url)"))
            status = rec.get("status", rec.get("response_status", "?"))
            clen = next(
                (rec[k] for k in ("content_length", "length", "body_len") if rec.get(k) is not None),
                "?",
            )
            print(f"  #{rank:>3}  score={score:.4f}  status={status}  len={clen}  url={url}")
            if attrs:
                for attr in attrs:
                    print(f"          ^ {attr}")
            else:
                print("          ^ (no anomalous attributes)")
            print()

    sys.stdout.flush()
