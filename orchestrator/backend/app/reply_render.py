"""Canonical exact-byte renderer for externally sent replies."""
from __future__ import annotations

from typing import Any, Mapping


REPLY_RENDERER_IDENTITY = "vigil/reply-markdown"
REPLY_RENDERER_VERSION = "1"


def _nonempty(value: object) -> str:
    return str(value or "").strip()


def outbound_reply_lines(entry: Mapping[str, Any], *, draft: bool) -> list[str]:
    """Return only the external copy/paste block, never internal thread history."""

    body = _nonempty(entry.get("body"))
    if not body and not draft:
        raise ValueError("a sent reply requires a nonempty authored body")
    lines = [body or "[NEEDS: reply body]", ""]
    new_evidence = _nonempty(entry.get("new_evidence"))
    if new_evidence:
        lines += ["**New evidence:**", "", new_evidence, ""]
    return lines


def render_outbound_reply_bytes(
    entry: Mapping[str, Any], *, draft: bool = False
) -> bytes:
    """Render the precise UTF-8 bytes represented as sent by Vigil."""

    text = "\n".join(outbound_reply_lines(entry, draft=draft)).rstrip() + "\n"
    return text.encode("utf-8")
