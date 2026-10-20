"""Shared boundary between CLI options and opaque child-command arguments."""
from collections.abc import Sequence


def passthrough_boundary(argv: Sequence[str]) -> int:
    """Index of the first ``--``, or the end when no child payload is present."""
    try:
        return argv.index("--")
    except ValueError:
        return len(argv)
