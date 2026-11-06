"""`fetch`'s object-wrapped paging must terminate and must admit truncation.

Two failures hid in `_fetch_assessment_envelope`. The `--paginate` walk only
stopped on `has_more: false` or a short page, so a backend that keeps answering
full pages — one that drops `offset` and re-serves page one — kept the loop
running for ever with nothing on stderr. And the single-page branch printed its
bounded-page notice only when the caller supplied no `?limit=`, so an explicit
window was truncated in silence: the prompts were migrated onto `--paginate` on
the strength of a notice that never fired for them.

The runaway guard below is what keeps the first regression a bounded failure
instead of a hung suite.
"""
from __future__ import annotations

from urllib.parse import parse_qsl

import pytest

from assess.commands import fetch
from assess.lib.client import AssessError


# Far above any bound `fetch` could sanely carry, so a walk that trips this is
# a walk that was not going to stop at all.
_RUNAWAY_REQUESTS = 2000


class _Runaway(RuntimeError):
    """Raised instead of letting a non-terminating walk hang the suite."""


class _EnvelopeClient:
    """Answers one envelope route from a per-request page factory."""

    def __init__(self, page_factory) -> None:
        self._page_factory = page_factory
        self.calls: list[str] = []

    def get(self, endpoint: str):
        self.calls.append(endpoint)
        if len(self.calls) > _RUNAWAY_REQUESTS:
            raise _Runaway(
                f"{len(self.calls)} requests without terminating: {endpoint}"
            )
        query = dict(parse_qsl(endpoint.partition("?")[2]))
        # `offset` defaults to 0 server-side, and the array branch passes an
        # explicit `?limit=` through verbatim without adding one.
        return self._page_factory(int(query["limit"]), int(query.get("offset", 0)))


def _attempts_page(rows: list[dict]) -> dict:
    """The `attempts` envelope: a rows key and a count, no total, no has_more."""
    return {"attempts": rows, "count": len(rows)}


def _files_page(rows: list[dict], *, offset: int, total: int) -> dict:
    """The `code/files` envelope its shared validator requires."""
    return {
        "total": total,
        "offset": offset,
        "count": len(rows),
        "has_more": offset + len(rows) < total,
        "items": rows,
    }


def test_paginate_refuses_a_backend_that_never_reaches_the_end(capsys) -> None:
    """A full page every time is a backend that is not advancing.

    `attempts` carries no `has_more`, so the only stop condition is a short
    page. A backend that ignores `offset` never serves one, and the walk
    re-reads page one for ever while `combined` grows without bound.
    """
    client = _EnvelopeClient(
        lambda limit, _offset: _attempts_page(
            [{"id": index} for index in range(limit)]
        )
    )

    with pytest.raises(AssessError) as excinfo:
        fetch._fetch_assessment_endpoint(
            client, "attempts?limit=2", paginate=True
        )

    message = str(excinfo.value)
    assert "attempts" in message
    # The refusal has to be resumable: the page bound it stopped at, the rows
    # it did collect, and the exact window that continues the read.
    assert str(fetch._MAX_PAGE_WALK) in message
    assert len(client.calls) == fetch._MAX_PAGE_WALK
    assert f"?limit=2&offset={2 * fetch._MAX_PAGE_WALK}" in message
    assert str(2 * fetch._MAX_PAGE_WALK) in message
    capsys.readouterr()


def test_paginate_refuses_a_non_advancing_bare_array_route_too(capsys) -> None:
    """The array walk twenty lines up has the same shape and the same risk.

    `coverage-items` answers with a bare JSON array, so its only stop condition
    is a short page — identical to the `attempts` envelope above. One bound
    covers both walks; leaving one of them unbounded would make termination
    depend on which response shape a route happens to use.
    """
    client = _EnvelopeClient(
        lambda limit, _offset: [{"id": index} for index in range(limit)]
    )

    with pytest.raises(AssessError) as excinfo:
        fetch._fetch_assessment_endpoint(
            client, "coverage-items?limit=2", paginate=True
        )

    message = str(excinfo.value)
    assert "coverage-items" in message
    assert str(fetch._MAX_PAGE_WALK) in message
    assert len(client.calls) == fetch._MAX_PAGE_WALK
    assert f"?limit=2&offset={2 * fetch._MAX_PAGE_WALK}" in message
    capsys.readouterr()


class _EngagementListClient:
    """Answers the engagement-scoped list routes from a page factory."""

    def __init__(self, page_factory) -> None:
        self._page_factory = page_factory
        self.calls: list[str] = []

    def get_engagement(self, path: str, *, query: str = ""):
        self.calls.append(f"{path}?{query}")
        if len(self.calls) > _RUNAWAY_REQUESTS:
            raise _Runaway(
                f"{len(self.calls)} requests without terminating: {path}?{query}"
            )
        parsed = dict(parse_qsl(query))
        return self._page_factory(int(parsed["limit"]), int(parsed["offset"]))


def test_paginate_refuses_a_non_advancing_engagement_list_too(capsys) -> None:
    """The third walk in this module, with the same stop conditions.

    An intel list answers with a bare array and no total, so a backend that
    keeps serving full pages never ends the walk. One bound for all three.
    """
    client = _EngagementListClient(
        lambda limit, _offset: [{"id": index} for index in range(limit)]
    )

    with pytest.raises(AssessError) as excinfo:
        fetch._fetch_engagement_endpoint(
            client, "intel/credentials?limit=2", paginate=True
        )

    message = str(excinfo.value)
    assert "intel/credentials" in message
    assert str(fetch._MAX_PAGE_WALK) in message
    assert len(client.calls) == fetch._MAX_PAGE_WALK
    assert f"?limit=2&offset={2 * fetch._MAX_PAGE_WALK}" in message
    capsys.readouterr()


def test_an_explicit_limit_that_truncates_says_so(capsys) -> None:
    """`code/files?limit=2` over 12,000 rows exited 0 and said nothing."""
    client = _EnvelopeClient(
        lambda limit, offset: _files_page(
            [{"id": offset + index} for index in range(limit)],
            offset=offset,
            total=12000,
        )
    )

    page = fetch._fetch_assessment_endpoint(client, "code/files?limit=2")

    assert page["count"] == 2
    stderr = capsys.readouterr().err
    assert "TRUNCATED" in stderr
    assert "?limit=2" in stderr
    assert "?limit=2&offset=2" in stderr
    assert "--paginate" in stderr


def test_a_bare_array_window_that_truncates_says_so_too(capsys) -> None:
    """The array branch returned the caller's window with nothing on stderr.

    `_incomplete_envelope_notice` is the generic backstop and it reads
    envelopes only, so a bare-array route under an explicit `?limit=` was the
    one read with no truncation signal at all.
    """
    client = _EnvelopeClient(
        lambda limit, offset: [{"id": offset + index} for index in range(limit)]
    )

    rows = fetch._fetch_assessment_endpoint(client, "coverage-items?limit=2&offset=10")

    assert len(rows) == 2
    stderr = capsys.readouterr().err
    assert "TRUNCATED" in stderr
    assert "?limit=2&offset=12" in stderr
    assert "--paginate" in stderr


def test_a_short_bare_array_window_stays_quiet(capsys) -> None:
    """A page below the caller's window is the end of the list, not a loss."""
    client = _EnvelopeClient(lambda _limit, _offset: [{"id": 1}])

    rows = fetch._fetch_assessment_endpoint(client, "coverage-items?limit=50")

    assert len(rows) == 1
    assert "TRUNCATED" not in capsys.readouterr().err


def test_an_exactly_full_page_without_a_marker_is_reported_as_truncated(
    capsys,
) -> None:
    """`attempts` carries neither total nor has_more.

    A page that comes back exactly as large as the caller asked for cannot be
    told apart from more rows waiting, so the notice says that rather than
    claiming either way.
    """
    client = _EnvelopeClient(
        lambda limit, offset: _attempts_page(
            [{"id": offset + index} for index in range(limit)]
        )
    )

    page = fetch._fetch_assessment_endpoint(client, "attempts?limit=3&offset=10")

    assert page["count"] == 3
    stderr = capsys.readouterr().err
    assert "TRUNCATED" in stderr
    assert "?limit=3&offset=13" in stderr
    assert "--paginate" in stderr


def test_an_explicit_window_that_reached_the_end_stays_quiet(capsys) -> None:
    """The notice is evidence of truncation, not of an explicit `?limit=`."""
    client = _EnvelopeClient(
        lambda limit, offset: _files_page(
            [{"id": 1}], offset=offset, total=1
        )
    )

    page = fetch._fetch_assessment_endpoint(client, "code/files?limit=50")

    assert page["count"] == 1
    assert "TRUNCATED" not in capsys.readouterr().err


def test_a_caller_without_a_limit_keeps_the_bounded_page_notice(capsys) -> None:
    """The notice the prompts were migrated onto keeps its own wording."""
    client = _EnvelopeClient(
        lambda limit, offset: _files_page(
            [{"id": offset + index} for index in range(limit)],
            offset=offset,
            total=12000,
        )
    )

    fetch._fetch_assessment_endpoint(client, "code/files")

    stderr = capsys.readouterr().err
    assert "returned one bounded page of up to 100 code/files row(s)" in stderr
    assert "use --paginate to fetch every page" in stderr
