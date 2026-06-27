#!/usr/bin/env python3
"""Maintainer tool — refresh the durable validated resolver list.

Run this OCCASIONALLY (a maintainer task, NOT during an engagement) to sync a
fresh, externally-validated resolver pool into the source repo, where it lives
durably and is committed. Engagement-time recon then consumes the committed
list — no live validation, no per-engagement network probing, nothing that can
go slow/dead mid-run (the I-001 / dead-resolver failure mode this addresses).

Why this model:
  * The brute fans out to PUBLIC RESOLVERS, and a list with slow/dead/lying
    resolvers tanks throughput and inflates REFUSED rates (engagement evidence).
  * `trickest/resolvers` is regenerated DAILY by running dnsvalidator against a
    trusted baseline, so SYNCING it == consuming a freshly-validated pool. We
    pin a snapshot into the repo (durable, reviewable, diffable) rather than
    fetching live every engagement.
  * `--validate` adds an optional local liveness+correctness re-prune (UDP probe
    of a control domain against a trusted baseline) for defense-in-depth.

Usage:
  python agent/scripts/refresh_resolvers.py                  # fetch -> filter -> write
  python agent/scripts/refresh_resolvers.py --validate       # + local liveness prune
  python agent/scripts/refresh_resolvers.py --out <path> --source-url <url>

Output: agent/scripts/assess/data/resolvers/validated-trickest.txt with a
provenance header (fetch date, source, raw/kept counts, validation note). The
curated premium-anycast.txt / trusted-anycast.txt two-tier lists are NOT touched
— this adds a wide, refreshable brute tier the operator points `--resolvers` at
for large brutes (`vigil assess dns-discovery --brute --resolvers <this file>`).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import random
import socket
import struct
import sys
import urllib.request
from pathlib import Path

_DEFAULT_SOURCE_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
_DEFAULT_OUT = Path(__file__).resolve().parent / "assess" / "data" / "resolvers" / "validated-trickest.txt"
# Control domains with stable, well-known A records; a healthy resolver returns
# at least one A answer for each within the latency budget.
_CONTROL_DOMAINS = ("one.one.one.one", "dns.google")
_TRUSTED_BASELINE = "1.1.1.1"


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested)
# --------------------------------------------------------------------------- #


def parse_resolver_ips(text: str) -> list[str]:
    """Extract unique, valid resolver IPs from a list file (one per line;
    `#` comments and blanks ignored), preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            ip = str(ipaddress.ip_address(line))
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def provenance_header(*, source: str, raw_count: int, kept_count: int,
                      validated: bool, now_iso: str) -> str:
    method = "fetched + IP-filtered" + (" + local dnsx-style liveness prune" if validated else "")
    return (
        f"# validated-trickest.txt — wide BRUTE-tier resolver pool (puredns `-r`)\n"
        f"#\n"
        f"# Provenance: synced by agent/scripts/refresh_resolvers.py — a MAINTAINER\n"
        f"# task, not engagement-time. Commit the result so engagements consume a\n"
        f"# durable, reviewed snapshot (no live per-engagement validation).\n"
        f"#   source:      {source}\n"
        f"#   synced_at:   {now_iso}\n"
        f"#   method:      {method}\n"
        f"#   resolvers:   {kept_count} kept / {raw_count} fetched\n"
        f"#\n"
        f"# Refresh occasionally (the upstream is regenerated daily). The curated\n"
        f"# premium-anycast.txt / trusted-anycast.txt tiers are separate and stay\n"
        f"# the safe defaults; point `--resolvers <this file>` for a wider brute.\n"
    )


def build_dns_query(qname: str, txid: int) -> bytes:
    """Minimal DNS A query packet (no EDNS) for a control-domain liveness probe."""
    header = struct.pack(">HHHHHH", txid & 0xFFFF, 0x0100, 1, 0, 0, 0)  # RD=1
    qparts = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in qname.split(".") if label
    )
    question = qparts + b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def response_has_answer(packet: bytes, txid: int) -> bool:
    """True when the DNS response matches our txid, is a response (QR=1), has a
    non-error RCODE, and carries at least one answer record."""
    if len(packet) < 12:
        return False
    r_txid, flags, _qd, ancount, _ns, _ar = struct.unpack(">HHHHHH", packet[:12])
    if r_txid != (txid & 0xFFFF):
        return False
    if not (flags & 0x8000):  # QR bit
        return False
    if (flags & 0x000F) != 0:  # RCODE != NOERROR
        return False
    return ancount > 0


# --------------------------------------------------------------------------- #
# Liveness probe (best-effort; --validate only)
# --------------------------------------------------------------------------- #


def resolver_answers(resolver_ip: str, qname: str, *, timeout: float, txid: int) -> bool:
    """Send one UDP A query for *qname* to *resolver_ip*; True iff a valid
    answer returns within *timeout*."""
    query = build_dns_query(qname, txid)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (resolver_ip, 53))
            data, _ = sock.recvfrom(4096)
    except (OSError, socket.timeout):
        return False
    return response_has_answer(data, txid)


def validate_resolvers(ips: list[str], *, timeout: float, sample: int | None) -> list[str]:
    """Keep resolvers that answer EVERY control domain within the latency budget.
    A trusted baseline must answer first (else the maintainer's own network is
    the problem, not the resolvers — abort rather than prune everything)."""
    for ctrl in _CONTROL_DOMAINS:
        if not resolver_answers(_TRUSTED_BASELINE, ctrl, timeout=max(timeout, 2.0),
                                txid=random.randint(0, 0xFFFF)):
            print(
                f"refresh-resolvers: trusted baseline {_TRUSTED_BASELINE} did not answer "
                f"{ctrl} — local network/UDP-53 looks blocked; skipping --validate prune.",
                file=sys.stderr,
            )
            return ips
    pool = ips[:sample] if sample else ips
    kept: list[str] = []
    for i, ip in enumerate(pool):
        ok = all(
            resolver_answers(ip, ctrl, timeout=timeout, txid=(i * 7 + j))
            for j, ctrl in enumerate(_CONTROL_DOMAINS)
        )
        if ok:
            kept.append(ip)
        if (i + 1) % 500 == 0:
            print(f"refresh-resolvers: validated {i + 1}/{len(pool)} ({len(kept)} kept)…",
                  file=sys.stderr)
    return kept


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def _fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 — maintainer-supplied URL
        return resp.read().decode("utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Refresh the durable validated resolver list.")
    ap.add_argument("--source-url", default=_DEFAULT_SOURCE_URL)
    ap.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    ap.add_argument("--validate", action="store_true",
                    help="Locally prune via a UDP control-domain liveness probe (slow on a large list).")
    ap.add_argument("--validate-timeout", type=float, default=2.0)
    ap.add_argument("--validate-sample", type=int, default=None,
                    help="Validate only the first N resolvers (smoke; default: all).")
    args = ap.parse_args(argv)

    print(f"refresh-resolvers: fetching {args.source_url}", file=sys.stderr)
    try:
        text = _fetch(args.source_url)
    except OSError as exc:
        print(f"refresh-resolvers: fetch failed: {exc}", file=sys.stderr)
        return 1

    ips = parse_resolver_ips(text)
    raw_count = len(ips)
    if raw_count == 0:
        print("refresh-resolvers: source produced 0 valid resolver IPs; aborting.", file=sys.stderr)
        return 1

    if args.validate:
        print(f"refresh-resolvers: validating {raw_count} resolvers (timeout {args.validate_timeout}s)…",
              file=sys.stderr)
        ips = validate_resolvers(ips, timeout=args.validate_timeout, sample=args.validate_sample)

    now_iso = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = provenance_header(
        source=args.source_url, raw_count=raw_count, kept_count=len(ips),
        validated=bool(args.validate), now_iso=now_iso,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(header + "\n".join(ips) + "\n", encoding="utf-8")
    print(f"refresh-resolvers: wrote {len(ips)} resolvers to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
