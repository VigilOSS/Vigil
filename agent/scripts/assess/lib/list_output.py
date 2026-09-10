"""Shared pagination truth for bounded assessment list output."""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ListPage:
    rows: list[Any]
    offset: int
    total: int | None
    total_at_least: int | None
    has_more: bool


class RemovedOptionAction(argparse.Action):
    """Recognize a removed option only to return its actionable replacement."""

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        del namespace, values, option_string
        parser.error(str(self.const))


def page_from_complete(rows: list[Any], *, limit: int, offset: int) -> ListPage:
    """Slice a complete backend result while retaining its exact total."""

    _validate_window(limit, offset)
    total = len(rows)
    visible = rows[offset : offset + limit]
    return ListPage(
        rows=visible,
        offset=offset,
        total=total,
        total_at_least=total,
        has_more=offset + len(visible) < total,
    )


def page_from_backend(
    rows: list[Any],
    *,
    limit: int,
    offset: int,
    used_lookahead: bool,
) -> ListPage:
    """Bound one backend page and preserve honest exact/lower-bound totals."""

    _validate_window(limit, offset)
    visible = rows[:limit]
    if used_lookahead:
        has_more = len(rows) > limit
    else:
        # At the API's maximum page size there is no room for a lookahead row.
        # A full page is therefore conservatively reported as possibly truncated.
        has_more = len(rows) == limit
    if not visible and offset > 0:
        # An arbitrary offset may be beyond the end, so an empty page cannot
        # prove how many rows preceded it. Do not manufacture ``total=offset``.
        total_at_least = None
        total = None
    else:
        total_at_least = offset + len(rows)
        total = None if has_more else offset + len(visible)
    return ListPage(
        rows=visible,
        offset=offset,
        total=total,
        total_at_least=total_at_least,
        has_more=has_more,
    )


def lookahead_limit(limit: int, *, maximum: int) -> tuple[int, bool]:
    """Return a legal backend limit and whether it includes one lookahead row."""

    _validate_window(limit, 0)
    if limit < maximum:
        return limit + 1, True
    return limit, False


def report_page(
    page: ListPage,
    *,
    noun: str,
    continuation_command: str | None = None,
    point_read_hint: str | None = None,
) -> None:
    """Write pagination metadata to stderr, keeping JSON stdout parseable."""

    count = len(page.rows)
    if not count and page.total is None and page.total_at_least is None:
        print(
            f"showing no matching {noun} at offset {page.offset}; total unavailable",
            file=sys.stderr,
        )
        return
    first = page.offset + 1 if count else 0
    last = page.offset + count if count else 0
    if page.total is None and page.total_at_least is not None:
        total_text = f"at least {page.total_at_least}"
    else:
        total_text = str(page.total)
    message = f"showing {first}-{last} of {total_text} matching {noun}"
    if page.has_more and continuation_command:
        message += f"; continue with `{continuation_command}`"
    if point_read_hint:
        message += f"; complete rows: {point_read_hint}"
    print(message, file=sys.stderr)


def _validate_window(limit: int, offset: int) -> None:
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if offset < 0:
        raise ValueError("offset must be at least 0")
