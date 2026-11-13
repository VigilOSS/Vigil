"""Decode httpx ``-store-response`` captures before anything mines them.

httpx writes each stored response as it was captured: the request block, the
response status line and headers, the body exactly as it arrived, then
``\\n\\n\\n`` and the full URL. The body is still content-encoded when the server
compressed it with an encoding the client did not transparently undo (a CDN
answering ``Accept-Encoding: gzip`` with brotli), and a chunked response is
written with chunk framing around it. jsluice, trufflehog and the regex
extractor read text, so they need the decoded body.

:func:`decode_stored_response` is the pure decoder; :func:`mirror_decoded_bodies`
writes a decoded mirror of a stored-response directory (same relative layout,
request and header block kept, body decoded and de-chunked, URL trailer kept)
and reports what it could not decode. The raw capture is never rewritten.
"""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path

try:  # The assess CLI pins brotli (agent/scripts/assess.py); keep a clear reason without it.
    import brotli
except ImportError:  # pragma: no cover - exercised only in an environment missing the pin
    brotli = None

try:  # Python 3.14+ ships zstd in the standard library.
    from compression import zstd
except ImportError:  # pragma: no cover - depends on the interpreter version
    zstd = None

# Cap on one decoded body. A stored body is itself capped (httpx
# -response-size-to-save), but a compressed stream can expand by orders of
# magnitude; past the cap the decoded prefix is kept and reported partial.
MAX_DECODED_BYTES = 64 * 1024 * 1024

_STATUS_LINE_RE = re.compile(rb"(?m)^HTTP/\d(?:\.\d)? \d{3}")
_TRAILER_RE = re.compile(rb"\n\n\nhttps?://[^\r\n]*\Z")
_IDENTITY_ENCODINGS = frozenset({"", "identity"})


@dataclass(frozen=True)
class DecodedResponse:
    """One stored response split into its parts, with the body decoded.

    ``status`` is ``identity`` (no content-encoding), ``decoded``, ``partial``
    (decoded prefix of a truncated or over-cap stream), ``undecodable`` (body
    kept as captured) or ``unparsed`` (no HTTP response block, e.g. httpx's
    index file; kept as captured).
    """

    head: bytes
    body: bytes
    trailer: bytes
    status: str
    encodings: tuple[str, ...] = ()
    reason: str = ""

    def rebuilt(self) -> bytes:
        return self.head + self.body + self.trailer


def _header_values(header_block: bytes, name: bytes) -> list[str]:
    values: list[str] = []
    for line in header_block.split(b"\n")[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.strip().lower() == name:
            values.extend(
                token.strip().lower()
                for token in value.decode("latin-1").split(",")
                if token.strip()
            )
    return values


def _dechunk(data: bytes) -> tuple[bytes, bool]:
    """Remove chunk framing; returns (payload, complete). Tolerates truncation."""
    out = bytearray()
    pos = 0
    while pos < len(data):
        line_end = data.find(b"\r\n", pos)
        if line_end < 0:
            return bytes(out), False
        size_token = data[pos:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_token, 16)
        except ValueError:
            return bytes(out), False
        if size == 0:
            return bytes(out), True
        start = line_end + 2
        chunk = data[start:start + size]
        out += chunk
        if len(chunk) < size:
            return bytes(out), False
        pos = start + size + 2
    return bytes(out), False


def _zlib_decode(data: bytes, wbits: int) -> tuple[bytes, str]:
    decompressor = zlib.decompressobj(wbits)
    out = decompressor.decompress(data, MAX_DECODED_BYTES)
    if decompressor.unconsumed_tail:
        return out, "decoded output exceeds the cap"
    if not decompressor.eof:
        return out, "stream truncated"
    return out, ""


def _decode_one(encoding: str, data: bytes) -> tuple[bytes, str]:
    """Decode one content-coding. Returns (output, partial_reason); raises on failure."""
    if encoding in {"gzip", "x-gzip"}:
        return _zlib_decode(data, 16 + zlib.MAX_WBITS)
    if encoding == "deflate":
        try:
            return _zlib_decode(data, zlib.MAX_WBITS)
        except zlib.error:
            return _zlib_decode(data, -zlib.MAX_WBITS)
    if encoding == "br":
        if brotli is None:
            raise ValueError("brotli module unavailable (the assess CLI pins it)")
        decompressor = brotli.Decompressor()
        out = decompressor.process(data, output_buffer_limit=MAX_DECODED_BYTES)
        if not decompressor.can_accept_more_data():
            return out, "decoded output exceeds the cap"
        if not decompressor.is_finished():
            return out, "stream truncated"
        return out, ""
    if encoding == "zstd":
        if zstd is None:
            raise ValueError("zstd needs Python 3.14 or newer")
        decompressor = zstd.ZstdDecompressor()
        out = decompressor.decompress(data, max_length=MAX_DECODED_BYTES)
        if not decompressor.eof:
            return out, (
                "stream truncated" if decompressor.needs_input else "decoded output exceeds the cap"
            )
        return out, ""
    raise ValueError(f"unsupported content-encoding {encoding!r}")


def decode_stored_response(raw: bytes) -> DecodedResponse:
    """Split one httpx stored response and decode its body."""
    status_match = _STATUS_LINE_RE.search(raw)
    if status_match is None:
        return DecodedResponse(head=raw, body=b"", trailer=b"", status="unparsed")
    header_end = raw.find(b"\r\n\r\n", status_match.start())
    separator = 4
    if header_end < 0:
        header_end = raw.find(b"\n\n", status_match.start())
        separator = 2
    if header_end < 0:
        return DecodedResponse(head=raw, body=b"", trailer=b"", status="unparsed")
    head = raw[:header_end + separator]
    rest = raw[header_end + separator:]
    trailer_match = _TRAILER_RE.search(rest)
    trailer = rest[trailer_match.start():] if trailer_match else b""
    wire_body = rest[:trailer_match.start()] if trailer_match else rest

    header_block = raw[status_match.start():header_end].replace(b"\r\n", b"\n")
    encodings = tuple(
        e for e in _header_values(header_block, b"content-encoding") if e not in _IDENTITY_ENCODINGS
    )
    chunked = "chunked" in _header_values(header_block, b"transfer-encoding")
    body = wire_body
    partial = ""
    if chunked:
        body, complete = _dechunk(wire_body)
        if not complete:
            partial = "stream truncated"
    if not encodings:
        if not chunked:
            return DecodedResponse(head=head, body=wire_body, trailer=trailer, status="identity")
        return DecodedResponse(head=head, body=body, trailer=trailer, status="identity")
    if not body:
        return DecodedResponse(
            head=head, body=wire_body, trailer=trailer, status="identity", encodings=encodings
        )
    try:
        for encoding in reversed(encodings):
            body, step_partial = _decode_one(encoding, body)
            partial = partial or step_partial
    except (ValueError, zlib.error, EOFError, *(_decoder_errors())) as exc:
        return DecodedResponse(
            head=head,
            body=wire_body,
            trailer=trailer,
            status="undecodable",
            encodings=encodings,
            reason=f"{','.join(encodings)}: {exc}",
        )
    if partial:
        return DecodedResponse(
            head=head, body=body, trailer=trailer, status="partial",
            encodings=encodings, reason=f"{','.join(encodings)}: {partial}; decoded prefix kept",
        )
    return DecodedResponse(head=head, body=body, trailer=trailer, status="decoded", encodings=encodings)


def _decoder_errors() -> tuple[type[BaseException], ...]:
    errors: list[type[BaseException]] = []
    if brotli is not None:
        errors.append(brotli.error)
    if zstd is not None:
        errors.append(zstd.ZstdError)
    return tuple(errors)


def decoded_body_text(path: Path) -> tuple[str, str]:
    """Return (decoded body text, status) for one stored response file."""
    decoded = decode_stored_response(path.read_bytes())
    payload = decoded.rebuilt() if decoded.status == "unparsed" else decoded.body
    return payload.decode("utf-8", errors="replace"), decoded.status


@dataclass
class MirrorReport:
    """What :func:`mirror_decoded_bodies` wrote and what it could not decode."""

    files: list[Path] = field(default_factory=list)
    decoded: dict[str, int] = field(default_factory=dict)
    partial: list[dict[str, str]] = field(default_factory=list)
    undecodable: list[dict[str, str]] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "decoded": dict(sorted(self.decoded.items())),
            "partial": list(self.partial),
            "undecodable": list(self.undecodable),
        }


def mirror_decoded_bodies(raw_root: Path, decoded_root: Path) -> MirrorReport:
    """Write a decoded mirror of every stored response under ``raw_root``.

    Each mirror file keeps the request and header block and the URL trailer
    byte for byte, with the body de-chunked and decoded. A body that cannot be
    decoded is mirrored as captured, so a miner sees no less than before, and
    is listed in the report with its reason.
    """
    report = MirrorReport()
    if not raw_root.is_dir():
        return report
    for source in sorted(entry for entry in raw_root.rglob("*") if entry.is_file()):
        target = decoded_root / source.relative_to(raw_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            decoded = decode_stored_response(source.read_bytes())
        except OSError:
            continue
        target.write_bytes(decoded.rebuilt())
        report.files.append(target)
        label = ",".join(decoded.encodings)
        if decoded.status in {"decoded", "partial"}:
            report.decoded[label] = report.decoded.get(label, 0) + 1
        if decoded.status == "partial":
            report.partial.append({"file": str(source), "reason": decoded.reason})
        elif decoded.status == "undecodable":
            report.undecodable.append({"file": str(source), "reason": decoded.reason})
    return report
