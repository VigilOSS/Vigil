"""Pure-helper tests for the resolver-refresh maintainer tool.

The script lives at agent/scripts/refresh_resolvers.py (outside the assess
package), so it is loaded by path. Network fetch + UDP liveness probing are the
script's runtime; here we pin the deterministic helpers: IP parsing/dedup, the
provenance header, the DNS query encoder, and the response validity check.
"""
from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "refresh_resolvers.py"
_spec = importlib.util.spec_from_file_location("refresh_resolvers", _SCRIPT)
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)


def test_parse_resolver_ips_filters_dedups_and_orders():
    text = "\n".join([
        "# comment",
        "8.8.8.8",
        "1.1.1.1   # inline comment",
        "",
        "not-an-ip",
        "8.8.8.8",          # dup
        "2606:4700:4700::1111",  # ipv6 ok
    ])
    assert rr.parse_resolver_ips(text) == ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]


def test_provenance_header_carries_source_counts_and_date():
    h = rr.provenance_header(
        source="https://example/resolvers.txt", raw_count=100, kept_count=87,
        validated=True, now_iso="2026-06-23T00:00:00Z",
    )
    assert "https://example/resolvers.txt" in h
    assert "87 kept / 100 fetched" in h
    assert "2026-06-23T00:00:00Z" in h
    assert "liveness prune" in h  # validated=True surfaced in the method line
    assert all(line.startswith("#") for line in h.splitlines() if line)


def test_build_dns_query_encodes_header_and_qname():
    q = rr.build_dns_query("a.com", 0x1234)
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", q[:12])
    assert txid == 0x1234
    assert flags == 0x0100  # RD set
    assert (qd, an, ns, ar) == (1, 0, 0, 0)
    # qname labels: 1 'a' 3 'c' 'o' 'm' 0  then QTYPE=A QCLASS=IN
    assert q[12:].startswith(b"\x01a\x03com\x00")
    assert q[-4:] == struct.pack(">HH", 1, 1)


def _resp(txid: int, flags: int, ancount: int) -> bytes:
    return struct.pack(">HHHHHH", txid, flags, 1, ancount, 0, 0)


def test_response_has_answer_accepts_valid_answer():
    # QR=1, RD=1, RA=1, RCODE=0 (0x8180), ancount=1
    assert rr.response_has_answer(_resp(0x1234, 0x8180, 1), 0x1234) is True


def test_response_has_answer_rejects_bad_cases():
    assert rr.response_has_answer(_resp(0x1234, 0x8180, 1), 0x9999) is False   # txid mismatch
    assert rr.response_has_answer(_resp(0x1234, 0x0100, 1), 0x1234) is False   # QR=0 (query, not response)
    assert rr.response_has_answer(_resp(0x1234, 0x8183, 1), 0x1234) is False   # RCODE=3 (NXDOMAIN)
    assert rr.response_has_answer(_resp(0x1234, 0x8180, 0), 0x1234) is False   # zero answers
    assert rr.response_has_answer(b"\x00\x01", 0x1234) is False                # truncated
