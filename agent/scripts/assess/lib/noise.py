"""Katana noise detection — replaces lib/noise.sh."""
from __future__ import annotations

import re

_NOISE_TEMPLATE_RE = re.compile(r'(\{\{|\}\}|%7b%7b|%7d%7d|\'\+|\+\'|"\+|\+")', re.IGNORECASE)

_NOISE_MIME_PREFIXES = (
    "/application/vnd.",
    "/text/",
    "/audio/",
    "/video/",
    "/image/",
    "/font/",
)

_NOISE_EXACT_PATHS = {"/edge/", "/trident/", "/-"}


def is_katana_noise_path(path: str) -> bool:
    """Return True if the path looks like Katana crawl noise."""
    if not path:
        return True

    path_lower = path.lower()

    if _NOISE_TEMPLATE_RE.search(path_lower):
        return True

    for prefix in _NOISE_MIME_PREFIXES:
        if path_lower.startswith(prefix):
            return True

    if path_lower in _NOISE_EXACT_PATHS:
        return True

    return False
