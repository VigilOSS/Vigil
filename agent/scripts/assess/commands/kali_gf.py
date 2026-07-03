"""vigil assess kali gf — pattern-bucket a URL file with gf (maintenance verb).

gf is a grep wrapper: it reads a URL corpus and emits the URLs whose parameters
match a named vuln-pattern (ssrf, idor, sqli, lfi, redirect, xss, ...). It sends
NO traffic to any target — it is a pure local text filter — so, like
``sweep-orphans`` and ``tool-help``, it does NOT take the audit-flag set
(``--technique``/``--intent``/``--probe-kind``/``--phase``/``--timeout``) and
writes no command-run audit row.

This COMPLEMENTS, and does not replace, the inline classifier in
``assess.lib.classify_buckets`` (the source-of-truth applied automatically at
ingest). Reach for ``kali gf`` for ad-hoc one-off triage of a corpus on disk
(e.g. a gau dump you have not ingested) or to cross-check a single bucket against
the upstream gf pattern library.

The corpus is read HOST-side and piped over ``docker exec -i`` to gf inside the
runtime (where the ~/.gf pattern library lives); the matched URLs come back on
stdout. No container path translation is needed — the bytes flow through
stdin/stdout.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from assess.lib.client import AssessError, default_runtime_container
from assess.lib.kali_runtime_exec import _check_container_running

# A gf pattern name is a bare token (the JSON file stem under ~/.gf/). Reject
# anything with shell metacharacters/spaces so the exec target is unambiguous —
# argv is passed as a list (never through a shell), but this keeps it tight.
_PATTERN_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "gf",
        help="Pattern-bucket a URL file with gf (maintenance; no audit flags, sends no target traffic).",
    )
    p.add_argument("pattern", nargs="?", default="",
                   help="gf pattern name (ssrf, idor, sqli, lfi, redirect, xss, ...). Omit with --list.")
    p.add_argument("-i", "--input", dest="input_file", default="",
                   help="Path to the URL corpus to bucket (engagement-relative or absolute).")
    p.add_argument("-o", "--output", dest="output_file", default="",
                   help="Write matched URLs here (engagement-relative or absolute). Default: stdout.")
    p.add_argument("--list", dest="list_patterns", action="store_true",
                   help="List the gf patterns installed in the runtime and exit.")
    p.add_argument("--container-name", dest="container_name", default="",
                   help="Override the runtime container name (default: the configured runtime container).")
    p.set_defaults(func=run)


def _list_runtime_patterns(container: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 — argv list, no shell
        ["docker", "exec", container, "gf", "-list"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _run_gf(container: str, pattern: str, corpus_text: str) -> subprocess.CompletedProcess:
    """Pipe the host corpus to gf inside the container; return the CompletedProcess."""
    return subprocess.run(  # noqa: S603 — argv list, no shell; pattern is regex-validated
        ["docker", "exec", "-i", container, "gf", pattern],
        input=corpus_text,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _resolve_host_input(args) -> Path:
    """Best-effort anchor of the input path to the engagement dir; never raises."""
    raw = (args.input_file or "").strip()
    try:
        from assess.lib.config import anchor_engagement_relative, load_config
        cfg = load_config(getattr(args, "engagement_dir", None))
        return Path(anchor_engagement_relative(raw, cfg.engagement_dir))
    except (Exception, SystemExit):  # noqa: BLE001 — anchoring is best-effort
        return Path(raw).expanduser()


def _resolve_host_output(args) -> Path | None:
    raw = (args.output_file or "").strip()
    if not raw:
        return None
    try:
        from assess.lib.config import anchor_engagement_relative, load_config
        cfg = load_config(getattr(args, "engagement_dir", None))
        return Path(anchor_engagement_relative(raw, cfg.engagement_dir))
    except (Exception, SystemExit):  # noqa: BLE001 — anchoring is best-effort
        return Path(raw).expanduser()


def run(args) -> None:
    container = (args.container_name or "").strip() or default_runtime_container()
    _check_container_running(container)

    if args.list_patterns:
        try:
            proc = _list_runtime_patterns(container)
        except FileNotFoundError as exc:
            raise AssessError(f"docker not found: {exc}") from exc
        except subprocess.TimeoutExpired:
            raise AssessError("gf -list timed out")
        out = (proc.stdout or "").strip()
        if out:
            sys.stdout.write(out + "\n")
        else:
            print("gf: -list produced no patterns (is ~/.gf seeded?).", file=sys.stderr)
            raise AssessError("no gf patterns")
        return

    pattern = (args.pattern or "").strip()
    if not pattern:
        print("gf: pass a pattern name (e.g. ssrf), or --list to enumerate patterns.", file=sys.stderr)
        raise AssessError("missing pattern")
    if not _PATTERN_RE.match(pattern):
        print(
            f"gf: '{pattern}' is not a valid pattern name (allowed: letters, digits, '.', '_', '-').",
            file=sys.stderr,
        )
        raise AssessError("invalid pattern name")
    if not args.input_file:
        print("gf: pass -i <url-file> (the corpus to bucket).", file=sys.stderr)
        raise AssessError("missing -i input file")

    input_path = _resolve_host_input(args)
    if not input_path.is_file():
        print(f"gf: input corpus not found: {input_path}", file=sys.stderr)
        raise AssessError(f"input not found: {input_path}")
    corpus_text = input_path.read_text(encoding="utf-8", errors="replace")

    try:
        proc = _run_gf(container, pattern, corpus_text)
    except FileNotFoundError as exc:
        raise AssessError(f"docker not found: {exc}") from exc
    except subprocess.TimeoutExpired:
        raise AssessError("gf timed out after 120s")

    # gf exits 1 when grep finds no matches — that is an empty bucket, not an
    # error. Only a higher rc (or stderr with no stdout) is a real failure.
    matched = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if proc.returncode not in (0, 1):
        err = (proc.stderr or "").strip()
        print(f"gf: exited {proc.returncode}: {err}", file=sys.stderr)
        raise AssessError(f"gf exited {proc.returncode}")

    output_path = _resolve_host_output(args)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(matched) + ("\n" if matched else ""), encoding="utf-8")
    else:
        for line in matched:
            sys.stdout.write(line + "\n")

    print(
        json.dumps(
            {
                "verb": "gf",
                "pattern": pattern,
                "input": str(input_path),
                "matched_count": len(matched),
                "output": str(output_path) if output_path is not None else "(stdout)",
            },
            ensure_ascii=False,
        ),
        file=sys.stderr,
    )
