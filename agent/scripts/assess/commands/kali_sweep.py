"""vigil assess kali sweep — value-agnostic batch fan-out + response clustering.

A DUMB fan-out: take an operator-supplied value list/range and a request
template carrying a ``{}`` placeholder, run exactly one ``kali exec`` command
per value INSIDE the runtime (so every value gets its own ``command-runs`` audit
row), then summarize the results into a compact table grouped by distinct
response signature.

Deliberate non-features (it expands ONLY what the operator literally typed and
reports ONLY what was probed):
  * NO seed-ID lists, NO GlobalID/opaque-id auto-decode.
  * NO hostname / metadata-path generation or suggestion.
  * NO implicit value invention — ``--values`` is REQUIRED; absent template
    placeholder is an error (so it never silently runs N identical commands).

The clustering reuses the project's EXISTING reachability taxonomy
(``reachability`` + ``detect_transport_error``): LIVE / BLACKHOLED / TLS-reset /
UNKNOWN, and the dns-fail vs connection-refused vs reachable split — no new
"a filter/metadata service exists" hinting is introduced. ``filter-rejected`` is
derived PURELY by clustering identical reachable responses (a deny-shaped status
with an identical body marker repeated across values), never by any rule that
"knows" a filter exists.

Politeness (real-engagement safety): ``--max-values`` hard cap (default 200),
default ``--concurrency 1`` (serial), and the I-013 per-host "<=1 active
target-facing probe" rule is honored by refusing ``--concurrency > 1`` unless the
operator passes ``--allow-concurrent``.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from assess.lib.client import AssessError
from assess.lib.kali import (
    add_required_kali_flags,
    kali_args_to_kwargs,
    kali_exec,
)
from assess.lib import reachability
from assess.lib.kali_output import KaliResult, detect_transport_error


_DEFAULT_PLACEHOLDER = "{}"
_DEFAULT_MAX_VALUES = 200
_CONCURRENCY_CAP = 4
_SAMPLE_VALUES = 5

# Reachability buckets surfaced in the clustered table. These map onto the
# EXISTING reachability/transport vocabulary — they are a presentation grouping
# of those verdicts, not a new taxonomy.
_CLASS_DNS_FAILURE = "dns-failure"
_CLASS_CONNECTION_REFUSED = "connection-refused"
_CLASS_TLS_RESET = "tls-reset"
_CLASS_REACHABLE = "reachable"
_CLASS_UNKNOWN = "unknown"
_FILTER_REJECTED = "filter-rejected"

# Resolver-failure needles — the dns-failure subset of the canonical
# _TRANSPORT_FAIL_STDERR_NEEDLES. Reused verbatim, not reinvented.
_DNS_NEEDLES = (
    "could not resolve host",
    "couldn't resolve host",
    "name or service not known",
    "temporary failure in name resolution",
    "no address associated with hostname",
    "no such host",
    "lookup ",
)

# Deny-shaped HTTP status families. A reachable cluster whose status is one of
# these is ANNOTATED filter-rejected — but only because the clustering already
# proved an identical body repeated across distinct values; the status family
# alone never sets it.
_DENY_STATUS = frozenset({"401", "403", "406", "429", "451"})


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "sweep",
        help=(
            "Value-agnostic batch: run one audited `kali exec` per --values entry "
            "with {} substituted into the template, then cluster the responses."
        ),
    )
    add_required_kali_flags(p)
    values_group = p.add_mutually_exclusive_group(required=True)
    values_group.add_argument(
        "--values",
        default=None,
        help=(
            "Comma-separated literal values and/or inclusive integer ranges a-b "
            "(e.g. \"1,2,7-9\"). Value-agnostic: expanded EXACTLY as typed, no "
            "host/ID generation. Mutually exclusive with --values-file."
        ),
    )
    values_group.add_argument(
        "--values-file",
        dest="values_file",
        default=None,
        help="Path to a newline-delimited values file. Mutually exclusive with --values.",
    )
    p.add_argument(
        "--placeholder",
        default=_DEFAULT_PLACEHOLDER,
        help=f"Template token replaced by each value (default: {_DEFAULT_PLACEHOLDER!r}).",
    )
    p.add_argument(
        "--max-values",
        dest="max_values",
        type=int,
        default=_DEFAULT_MAX_VALUES,
        help=(
            f"Hard cap on expanded value count (default: {_DEFAULT_MAX_VALUES}). "
            "Refuses to expand beyond this — cost/politeness guard."
        ),
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help=(
            "In-runtime fan-out width (default: 1, serial). Capped at "
            f"{_CONCURRENCY_CAP}. >1 requires --allow-concurrent (I-013 per-host "
            "<=1 active probe politeness rule)."
        ),
    )
    p.add_argument(
        "--allow-concurrent",
        dest="allow_concurrent",
        action="store_true",
        help="Politeness override: permit --concurrency > 1 (I-013 per-host rule).",
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the clustered result as JSON (clusters carry per-value run_ids).",
    )
    p.add_argument(
        "command",
        nargs="+",
        help="Command template with the {} placeholder. Use `--` to separate from flags.",
    )
    p.set_defaults(func=run)


# --------------------------------------------------------------------------- #
# Value expansion (pure, value-agnostic)
# --------------------------------------------------------------------------- #

_RANGE_RE = re.compile(r"^(-?\d+)-(-?\d+)$")


def _expand_values(args) -> list[str]:
    """Expand --values / --values-file into the literal list of swept values.

    Accepts ONLY literal scalars and inclusive integer ranges ``a-b``. Never
    invents a value the operator did not supply. Enforces --max-values.
    """
    raw_items: list[str]
    if getattr(args, "values_file", None):
        try:
            with open(args.values_file, "r", encoding="utf-8") as fh:
                raw_items = [line.strip() for line in fh if line.strip()]
        except OSError as exc:
            raise AssessError(f"--values-file: cannot read {args.values_file}: {exc}") from exc
    else:
        raw_items = [tok.strip() for tok in (args.values or "").split(",") if tok.strip()]

    if not raw_items:
        raise AssessError("--values expanded to zero values; the sweep never invents values")

    expanded: list[str] = []
    for item in raw_items:
        match = _RANGE_RE.match(item)
        if match:
            lo, hi = int(match.group(1)), int(match.group(2))
            if hi < lo:
                raise AssessError(f"--values range '{item}' is descending (a-b needs a <= b)")
            step_count = hi - lo + 1
            if step_count > args.max_values:
                raise AssessError(
                    f"--values range '{item}' expands to {step_count} values, "
                    f"over the --max-values cap of {args.max_values}"
                )
            expanded.extend(str(n) for n in range(lo, hi + 1))
        else:
            expanded.append(item)
        if len(expanded) > args.max_values:
            raise AssessError(
                f"--values expands to more than the --max-values cap of {args.max_values}; "
                "raise --max-values explicitly or shrink the list"
            )
    return expanded


def _require_placeholder(template: list[str], placeholder: str) -> None:
    """Error unless the template contains the placeholder at least once.

    Guards against silently running the same command N times — the sweep is
    pointless (and misleading) without a per-value substitution site.
    """
    if not placeholder:
        raise AssessError("--placeholder cannot be empty")
    if not any(placeholder in str(tok) for tok in template):
        raise AssessError(
            f"command template does not contain the placeholder {placeholder!r}; "
            "the sweep would run the same command for every value. Add the "
            "placeholder (e.g. .../item/{}) or use `kali exec` for a single run."
        )


def _substitute(template: list[str], placeholder: str, value: str) -> list[str]:
    return [str(tok).replace(placeholder, str(value)) for tok in template]


# --------------------------------------------------------------------------- #
# Response classification + clustering (reuses the reachability taxonomy)
# --------------------------------------------------------------------------- #

_STATUS_RE = re.compile(r"^\s*(\d{3})\b")


def _extract_status(result: KaliResult) -> str:
    """Best-effort HTTP status for the signature.

    For the canonical ``curl -w '%{http_code}'`` shape the status is the leading
    3-digit token of stdout. When no HTTP status is recoverable, fall back to the
    process return code (rendered as ``rc=<n>``) so non-HTTP rows still cluster.
    """
    body = (result.stdout_preview or "").strip()
    if body:
        match = _STATUS_RE.match(body)
        if match and match.group(1) != "000":
            return match.group(1)
    if result.return_code is not None:
        return f"rc={result.return_code}"
    return "-"


def _classify_reachability(result: KaliResult) -> str:
    """Map one KaliResult onto a reachability bucket via the EXISTING detector.

    Reuses ``detect_transport_error`` (which itself delegates verdict semantics
    to ``reachability.classify_probe``). A synthetic result may carry an explicit
    ``transport_error``/``transport_error_detail`` (test inputs); we honor that,
    otherwise we recompute from the raw fields so production rows classify
    identically to the live false-negative guard.
    """
    tool_name = _result_tool_name(result)
    is_te = bool(getattr(result, "transport_error", False))
    detail = getattr(result, "transport_error_detail", "") or ""
    if not is_te:
        computed_te, computed_detail = detect_transport_error(
            tool_name=tool_name,
            return_code=result.return_code,
            stdout_preview=result.stdout_preview or "",
            stderr_preview=result.stderr_preview or "",
            timed_out=bool(result.timed_out),
        )
        is_te, detail = computed_te, computed_detail

    if not is_te:
        # No transport failure → a real answer came back (LIVE, any HTTP code
        # including 4xx walls). filter-rejected is decided later, by clustering.
        return _CLASS_REACHABLE

    haystack = f"{detail} {result.stderr_preview or ''}".lower()
    if any(needle in haystack for needle in _DNS_NEEDLES):
        return _CLASS_DNS_FAILURE
    # TLS reset is its own recoverable verdict in the reachability taxonomy.
    if "tls" in haystack and "reset" in haystack:
        return _CLASS_TLS_RESET
    # A blackholed verdict (clean connect failure) OR a connect-fail needle is
    # connection-refused; anything else transport-level stays unknown.
    if (
        f"reachability={reachability.BLACKHOLED}" in haystack
        or "connection refused" in haystack
        or "failed to connect" in haystack
        or "no route to host" in haystack
        or "connection timed out" in haystack
        or "network is unreachable" in haystack
    ):
        return _CLASS_CONNECTION_REFUSED
    return _CLASS_UNKNOWN


def _result_tool_name(result: KaliResult) -> str:
    """Tool name for the detector. KaliResult does not carry it, so the caller
    stamps it onto the synthetic/real result as ``tool_name`` when available."""
    return getattr(result, "tool_name", "") or "curl"


def _body_marker(result: KaliResult) -> str:
    """Stable short hash of the normalized stdout preview.

    Strips the leading status token and collapses whitespace so two responses
    that differ only by a volatile echo still cluster. An empty body hashes to a
    sentinel so transport failures with no body share a marker.
    """
    body = (result.stdout_preview or "").strip()
    # Drop a leading 3-digit status token (the curl -w write-out) so the marker
    # reflects the BODY, not the status (status is already a signature field).
    body = _STATUS_RE.sub("", body, count=1).strip()
    normalized = re.sub(r"\s+", " ", body)
    if not normalized:
        return "-"
    return hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:8]


def _signature(result: KaliResult) -> tuple[str, str, str]:
    """(reachability_class, status_or_rc, body_marker) — the clustering key."""
    return (_classify_reachability(result), _extract_status(result), _body_marker(result))


def cluster_results(results: list[tuple[str, KaliResult]]) -> list[dict[str, Any]]:
    """Group ``(value, KaliResult)`` pairs by distinct response signature.

    Returns a list of cluster dicts ordered by count DESC (mirroring
    list_clusters' priority-first ordering — the biggest cluster surfaces first),
    each carrying its class, status, marker, sample values, count, and the
    per-value run_ids for audit recovery.
    """
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    order: list[tuple[str, str, str]] = []
    for value, result in results:
        sig = _signature(result)
        if sig not in grouped:
            grouped[sig] = {
                "reachability_class": sig[0],
                "status": sig[1],
                "marker": sig[2],
                "values": [],
                "run_ids": [],
            }
            order.append(sig)
        grouped[sig]["values"].append(value)
        grouped[sig]["run_ids"].append(getattr(result, "run_id", None))

    clusters: list[dict[str, Any]] = []
    for sig in order:
        bucket = grouped[sig]
        count = len(bucket["values"])
        cls = bucket["reachability_class"]
        # filter-rejected is purely clustering-derived: a reachable cluster whose
        # status is a deny family AND whose identical body repeated across >1
        # distinct value. The status family alone never sets it.
        effective_class = cls
        if cls == _CLASS_REACHABLE and bucket["status"] in _DENY_STATUS and count > 1:
            effective_class = _FILTER_REJECTED
        clusters.append({
            "signature": f"{effective_class}:{bucket['status']}:{bucket['marker']}",
            "reachability_class": effective_class,
            "status": bucket["status"],
            "count": count,
            "sample_values": bucket["values"][:_SAMPLE_VALUES],
            "marker": bucket["marker"],
            "run_ids": bucket["run_ids"],
        })
    clusters.sort(key=lambda c: c["count"], reverse=True)
    return clusters


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _render_table(batch_id: str, total: int, clusters: list[dict[str, Any]]) -> str:
    lines = [
        f"# sweep {batch_id[:8]} — {total} value(s), {len(clusters)} cluster(s)",
        "",
        f"{'CLASS':<18} {'STATUS':<8} {'N':<4} {'EXAMPLE-VALUES':<22} MARKER",
    ]
    for c in clusters:
        samples = ",".join(str(v) for v in c["sample_values"])
        if c["count"] > len(c["sample_values"]):
            samples += ",…"
        lines.append(
            f"{c['reachability_class']:<18} {c['status']:<8} {c['count']:<4} "
            f"{samples:<22} {c['marker']}"
        )
    return "\n".join(lines)


def emit_sweep_result(
    batch_id: str,
    results: list[tuple[str, KaliResult]],
    *,
    as_json: bool = False,
) -> None:
    clusters = cluster_results(results)
    total = len(results)
    if as_json:
        print(json.dumps({
            "batch_id": batch_id,
            "total": total,
            "clusters": clusters,
        }, ensure_ascii=False))
    else:
        print(_render_table(batch_id, total, clusters))


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def _resolve_concurrency(args) -> int:
    concurrency = int(getattr(args, "concurrency", 1) or 1)
    if concurrency < 1:
        raise AssessError("--concurrency must be >= 1")
    if concurrency > 1 and not getattr(args, "allow_concurrent", False):
        raise AssessError(
            "--concurrency > 1 requires --allow-concurrent (I-013 per-host "
            "<=1 active target-facing probe politeness rule). Re-run with "
            "--allow-concurrent to override, or keep --concurrency 1."
        )
    if concurrency > _CONCURRENCY_CAP:
        raise AssessError(
            f"--concurrency {concurrency} exceeds the cap of {_CONCURRENCY_CAP}"
        )
    return concurrency


def run(args) -> None:
    values = _expand_values(args)
    template = list(args.command)
    placeholder = args.placeholder or _DEFAULT_PLACEHOLDER
    _require_placeholder(template, placeholder)
    concurrency = _resolve_concurrency(args)

    kwargs = kali_args_to_kwargs(args)
    base_intent = kwargs.pop("intent")
    batch_id = uuid.uuid4().hex

    def _run_one(value: str) -> tuple[str, KaliResult]:
        cmd_i = _substitute(template, placeholder, value)
        tool_name = cmd_i[0] if cmd_i else "command"
        # The batch id + value rides in the per-row intent so a later
        # `vigil assess list-command-runs --intent-q "sweep <id>"` recovers the
        # whole fan-out, and each row links back to ITS value.
        per_intent = f"{base_intent} [sweep {batch_id[:8]} value={value}]"
        result = kali_exec(cmd_i, tool_name=tool_name, intent=per_intent, **kwargs)
        # KaliResult has no tool_name field; stamp it so the clustering detector
        # classifies HTTP probers correctly without re-deriving from argv.
        try:
            setattr(result, "tool_name", tool_name)
        except (AttributeError, TypeError):
            pass
        return value, result

    results: list[tuple[str, KaliResult]]
    if concurrency == 1:
        results = [_run_one(v) for v in values]
    else:
        # Preserve input order in the output regardless of completion order.
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(_run_one, values))

    emit_sweep_result(batch_id, results, as_json=bool(getattr(args, "as_json", False)))
