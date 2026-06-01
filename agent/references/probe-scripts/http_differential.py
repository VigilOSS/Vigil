#!/usr/bin/env python3
"""Reusable probe: parametrized HTTP differential.

Many web checks are inconclusive from a single request because the app returns
the same status/shape for valid and invalid input. The fix is a *differential*:
send a control request and a test request, then decide on the delta (status,
length, marker presence, latency). That branching is bespoke logic no typed
`kali` verb expresses — hence a probe (see agent/skills/write-probe-script/SKILL.md).

Copy this into an engagement with `aith assess scaffold-probe`, or run it as-is.
Stdlib-only so it replays on any runtime tier.

Run (inside the runtime container, via kali exec):
  aith assess kali exec \\
    --technique IDOR --intent "differential: object id A vs B body delta" \\
    --probe-kind payload --phase consume-test --timeout 60 -- \\
    python3 /engagements/$ENGAGEMENT_KEY/scripts/http_differential.py \\
      --control "https://t/api/orders/1000" \\
      --test "https://t/api/orders/1001" \\
      --diff-on length \\
      --out /engagements/$ENGAGEMENT_KEY/scans/order_idor_diff.json

Output contract: the LAST stdout line is the JSON verdict
  {"finding": bool, "summary": str, "evidence": {...}}.

Validate before trusting it: point --control and --test at the SAME url and
confirm `finding` is false (a true differential must not fire on identity).
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def fetch(url: str, *, header: list[str], timeout: int) -> dict:
    """GET `url`; return status, body length, first 4 KiB of body, latency_ms.

    Non-2xx/3xx still return a result (status from the HTTPError) so the
    differential can compare error responses too.
    """
    req = urllib.request.Request(url, headers=_parse_headers(header))
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scoped target)
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:  # noqa: PERF203 — error body is signal
        raw = exc.read()
        status = exc.code
    latency_ms = int((time.monotonic() - started) * 1000)
    body = raw[:4096].decode("utf-8", "replace")
    return {"status": status, "length": len(raw), "body": body, "latency_ms": latency_ms}


def _parse_headers(pairs: list[str]) -> dict[str, str]:
    headers = {"User-Agent": "aith-probe"}
    for pair in pairs:
        if ":" in pair:
            key, _, value = pair.partition(":")
            headers[key.strip()] = value.strip()
    return headers


def decide(control: dict, test: dict, *, diff_on: str, marker: str, latency_delta_ms: int) -> tuple[bool, str]:
    """Return (finding, summary) for the chosen differential dimension."""
    if diff_on == "status":
        hit = control["status"] != test["status"]
        return hit, f"status differential: control={control['status']} test={test['status']}"
    if diff_on == "length":
        hit = control["length"] != test["length"]
        return hit, f"length differential: control={control['length']}B test={test['length']}B"
    if diff_on == "marker":
        c_has = marker in control["body"]
        t_has = marker in test["body"]
        hit = c_has != t_has
        return hit, f"marker {marker!r} presence differential: control={c_has} test={t_has}"
    if diff_on == "latency":
        delta = test["latency_ms"] - control["latency_ms"]
        hit = delta >= latency_delta_ms
        return hit, f"latency differential: control={control['latency_ms']}ms test={test['latency_ms']}ms (Δ{delta}ms)"
    raise ValueError(f"unknown --diff-on {diff_on!r}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Parametrized HTTP differential probe.")
    ap.add_argument("--control", required=True, help="Control (baseline) request URL.")
    ap.add_argument("--test", required=True, help="Test request URL.")
    ap.add_argument(
        "--diff-on",
        default="length",
        choices=["status", "length", "marker", "latency"],
        help="Which dimension decides the verdict.",
    )
    ap.add_argument("--marker", default="", help="Body marker for --diff-on marker.")
    ap.add_argument(
        "--latency-delta-ms",
        type=int,
        default=1000,
        help="Min test-minus-control latency (ms) to fire for --diff-on latency.",
    )
    ap.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra request header 'Name: value' (repeatable). E.g. an auth cookie.",
    )
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--out", default="", help="Optional path to write the JSON verdict to.")
    args = ap.parse_args()

    control = fetch(args.control, header=args.header, timeout=args.timeout)
    test = fetch(args.test, header=args.header, timeout=args.timeout)
    finding, summary = decide(
        control, test,
        diff_on=args.diff_on, marker=args.marker, latency_delta_ms=args.latency_delta_ms,
    )

    result = {
        "finding": finding,
        "summary": summary,
        "evidence": {
            "diff_on": args.diff_on,
            "control": {k: control[k] for k in ("status", "length", "latency_ms")},
            "test": {k: test[k] for k in ("status", "length", "latency_ms")},
        },
    }
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
    print(json.dumps(result, ensure_ascii=False))  # verdict is the LAST line
    return 0 if finding else 1


if __name__ == "__main__":
    sys.exit(main())
