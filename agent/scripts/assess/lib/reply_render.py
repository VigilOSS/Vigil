"""Assess-side import bridge to the backend-owned exact reply renderer."""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND_ROOT = Path(__file__).resolve().parents[4] / "orchestrator" / "backend"
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.reply_render import (  # noqa: E402
    REPLY_RENDERER_IDENTITY,
    REPLY_RENDERER_VERSION,
    outbound_reply_lines,
    render_outbound_reply_bytes,
)

__all__ = [
    "REPLY_RENDERER_IDENTITY",
    "REPLY_RENDERER_VERSION",
    "outbound_reply_lines",
    "render_outbound_reply_bytes",
]
