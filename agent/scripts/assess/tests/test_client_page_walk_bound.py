"""`get_all_pages` stops instead of walking for ever.

The walk advances by `page_size` and ends on a short page, so a backend that
serves a full page at every offset -- a route that drops `offset`, or one whose
window is wider than the page it returns -- never ends it. That is a hang with
no output, not a failure: the operator sees a command that never returns and has
nothing to report.

`fetch` already bounds its three walks at `_MAX_PAGE_WALK` and refuses with a
resumable window. This is the same shape in the shared client, so it gets the
same bound and the same resumability: a refusal names what it read and the
`?limit=N&offset=M` to continue from, because a read that stopped early must not
be mistaken for a complete one.
"""
from __future__ import annotations

import pytest

from assess.lib.client import MAX_PAGE_WALK, AssessError, AssessmentClient


class _NeverEnds(AssessmentClient):
    """A client whose backend always returns a full page."""

    def __init__(self, page_size: int) -> None:  # no network, no base URL
        self._page_size = page_size
        self.requests: list[str] = []

    def get(self, endpoint: str):  # type: ignore[override]
        self.requests.append(endpoint)
        return [{"id": n} for n in range(self._page_size)]


def test_a_backend_that_never_short_pages_is_refused_not_walked_for_ever() -> None:
    client = _NeverEnds(page_size=2)

    with pytest.raises(AssessError) as refused:
        client.get_all_pages("work-items", page_size=2)

    message = str(refused.value)
    assert "work-items" in message
    # Resumable: the operator can continue rather than start over.
    assert "offset=" in message
    # Bounded: it stopped at the bound rather than on a timeout or a hang.
    assert len(client.requests) == MAX_PAGE_WALK


def test_a_short_page_still_ends_the_walk_normally() -> None:
    class _Ends(_NeverEnds):
        def get(self, endpoint: str):  # type: ignore[override]
            self.requests.append(endpoint)
            return [{"id": 0}] if len(self.requests) == 1 else []

    client = _Ends(page_size=2)

    assert client.get_all_pages("work-items", page_size=2) == [{"id": 0}]


def test_agent_start_refuses_a_queue_listing_that_never_stops_advancing() -> None:
    """`agent start`'s queue manifest has the same shape and the same bound.

    Its existing guard catches a listing that returns an EMPTY page with
    `has_more`. A backend returning a FULL page with `has_more` at every offset
    advances for ever, and this walk runs inside `agent start`, so the failure
    is a dispatch that never launches and reports nothing.
    """
    import pytest as _pytest

    from assess.commands import agent as agent_cmd

    class _AlwaysMore:
        def __init__(self) -> None:
            self.calls = 0

        def get(self, endpoint: str):
            self.calls += 1
            # A full page, always more, and the requested id is never in it.
            return {"items": [{"id": 10_000 + self.calls}], "has_more": True}

    client = _AlwaysMore()
    with _pytest.raises(SystemExit) as exited:
        agent_cmd._backend_queue_manifest(
            client, [7], repo_id=1, repo_generation=1
        )

    assert exited.value.code == 1
    assert client.calls == MAX_PAGE_WALK
