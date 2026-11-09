"""The queue-row-by-id lookup must read the listing it claims, and must not
report a row it never reached as a row that is gone.

`_queue_rows_by_item_id` is the one read behind two operator-facing answers:
the per-id status report after a short `code-dispatch fetch`, and the
`queue_item_id` selector `code-dispatch reanalyze` resolves. Both rendered "the
walk stopped at its bound" as "no such row" — which sends an operator to
re-queue a file whose attempt is alive — and both have to keep reading the
recoverable listing rather than the narrower `analysis-queue/stats` lane, or an
id the claim refused reads as an id that does not exist.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl

import pytest
from _fake_client import StubClient

from assess.commands import code_dispatch


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://example.test",
        engagement_key="eng",
        engagement_dir=str(tmp_path),
    )


def _queue_rows(count: int) -> list[dict]:
    return [
        {
            "id": index,
            "file_id": 100 + index,
            "file_path": f"src/module_{index}.py",
            "status": "done",
        }
        for index in range(1, count + 1)
    ]


class _QueueListingClient(StubClient):
    """Pages the analysis-queue listing over a fixed row list.

    ``malformed_page`` makes one page answer with a non-object, the way a
    backend that broke mid-walk does: the walk stops there with the rest of the
    listing unread.

    ``lane_excluded`` holds the ids the backend's ``current_only=true`` lane
    filter would drop — an older active attempt, a demoted repository's row, an
    invalid active lane (``list_queue_items`` ->
    ``_queue_lane_sql``). Honouring that narrowing here is what lets a test say
    whether this read is the recoverable listing or the stats lane.
    """

    def __init__(
        self,
        rows: list[dict],
        *,
        malformed_page: int | None = None,
        lane_excluded: set[int] | None = None,
    ) -> None:
        self.rows = rows
        self.malformed_page = malformed_page
        self.lane_excluded = lane_excluded or set()
        self.reads: list[str] = []

    def get(self, endpoint: str):
        page_index = len(self.reads)
        self.reads.append(endpoint)
        if page_index == self.malformed_page:
            return ["not an object"]
        query = dict(parse_qsl(endpoint.partition("?")[2]))
        limit = int(query["limit"])
        offset = int(query["offset"])
        listed = (
            [row for row in self.rows if row["id"] not in self.lane_excluded]
            if query.get("current_only") == "true"
            else self.rows
        )
        page = listed[offset : offset + limit]
        return {
            "total": len(listed),
            "offset": offset,
            "count": len(page),
            "has_more": offset + len(page) < len(listed),
            "item_ids": [row["id"] for row in page],
            "items": page,
        }


def _install_client(monkeypatch, client: _QueueListingClient) -> None:
    monkeypatch.setattr(
        code_dispatch, "AssessmentClient", lambda *_args, **_kwargs: client
    )


def _bound_the_walk(monkeypatch, *, page_size: int, pages: int) -> None:
    """Shrink the bounded walk so a test can exceed it in a few rows."""
    monkeypatch.setattr(code_dispatch, "_QUEUE_LOOKUP_PAGE_SIZE", page_size)
    monkeypatch.setattr(code_dispatch, "_MAX_QUEUE_LOOKUP_PAGES", pages)


def _reanalyze_file(tmp_path: Path, queue_item_id: int) -> Path:
    path = tmp_path / "reanalyze.json"
    path.write_text(
        json.dumps([{"queue_item_id": queue_item_id, "batch_theme": "reread"}]),
        encoding="utf-8",
    )
    return path


def test_the_queue_row_lookup_reads_the_generation_it_claims(capsys) -> None:
    """Every message built from this read says "current-generation"."""
    client = _QueueListingClient(_queue_rows(3))

    code_dispatch._warn_if_claim_is_partial(
        client, [], [2], agent_name="code-vuln-hunter-1"
    )

    assert client.reads
    for read in client.reads:
        assert read.startswith("code/analysis-queue?"), read
    assert "2 (done): src/module_2.py" in capsys.readouterr().err


def test_the_lookup_reads_the_listing_that_keeps_the_unclaimable_rows(capsys) -> None:
    """The ids this report exists for are the ones the stats lane does not hold.

    Everything the headline names as a reason the claim dropped an id — not
    pending, already leased, superseded, a reference repository, an inactive
    generation — is a row the backend's listing deliberately KEEPS "so its row
    IDs stay recoverable" (``list_queue_items``: every current-generation,
    non-source-superseded attempt, including an older active row and a row in a
    repository demoted to `reference`, each carrying ``repo_role``). That
    listing is already current-generation — ``queue.repo_generation =
    repos.active_generation`` and ``queue.source_superseded_at IS NULL`` are
    unconditional — while ``current_only=true`` narrows it to each file's
    LATEST attempt in its status lane, the rows ``analysis-queue/stats``
    counts. Reading that lane instead would answer "no current-generation queue
    row found" for precisely the rows the claim had to refuse, which is the
    false absence this module exists to prevent.
    """
    rows = _queue_rows(3)
    rows[1] = {**rows[1], "status": "pending", "repo_role": "reference"}
    client = _QueueListingClient(rows, lane_excluded={2})

    code_dispatch._warn_if_claim_is_partial(
        client, [], [2], agent_name="code-vuln-hunter-1"
    )

    stderr = capsys.readouterr().err
    assert "2 (pending): src/module_2.py" in stderr
    assert "no current-generation queue row found" not in stderr


@pytest.mark.parametrize("malformed_page", [None, 0, 1])
def test_a_row_the_walk_never_reached_is_not_reported_as_absent(
    malformed_page, monkeypatch, capsys
) -> None:
    """`None` stops at the page bound; the integers stop on a broken page."""
    _bound_the_walk(monkeypatch, page_size=2, pages=2)
    client = _QueueListingClient(_queue_rows(6), malformed_page=malformed_page)

    code_dispatch._warn_if_claim_is_partial(
        client, [], [999], agent_name="code-vuln-hunter-1"
    )

    stderr = capsys.readouterr().err
    assert "999" in stderr
    assert "no current-generation queue row found" not in stderr
    assert "did not reach" in stderr or "not read" in stderr
    assert "code-dispatch progress 999" in stderr


def test_the_bound_it_stopped_at_is_named_in_rows_and_pages(
    monkeypatch, capsys
) -> None:
    """"We stopped looking" is only actionable if it says how far it looked."""
    _bound_the_walk(monkeypatch, page_size=2, pages=2)
    client = _QueueListingClient(_queue_rows(6))

    code_dispatch._warn_if_claim_is_partial(
        client, [], [999], agent_name="code-vuln-hunter-1"
    )

    assert "2 page(s) (4 row(s))" in capsys.readouterr().err


def test_an_exhausted_listing_still_reports_a_genuinely_absent_row(
    capsys,
) -> None:
    """A walk that reached the end of the listing does prove absence."""
    client = _QueueListingClient(_queue_rows(3))

    code_dispatch._warn_if_claim_is_partial(
        client, [], [999], agent_name="code-vuln-hunter-1"
    )

    assert "999: no current-generation queue row found" in capsys.readouterr().err


def test_reanalyze_refuses_an_unreached_queue_item_id_as_unproven(
    monkeypatch, tmp_path, capsys
) -> None:
    """A broken page cannot prove that the requested id is absent."""
    _bound_the_walk(monkeypatch, page_size=2, pages=2)
    _install_client(monkeypatch, _QueueListingClient(_queue_rows(6), malformed_page=1))

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._queue(
            _config(tmp_path),
            str(_reanalyze_file(tmp_path, 999)),
            mode="reanalysis",
            reason="Independent reread of the parser",
        )

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert "999" in stderr
    assert "No current-generation queue row found for queue_item_id" not in stderr
    assert "did not reach" in stderr
    assert "code-dispatch progress 999" in stderr


def test_reanalyze_still_refuses_a_genuinely_absent_queue_item_id(
    monkeypatch, tmp_path, capsys
) -> None:
    client = _QueueListingClient(_queue_rows(3))
    _install_client(monkeypatch, client)

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._queue(
            _config(tmp_path),
            str(_reanalyze_file(tmp_path, 999)),
            mode="reanalysis",
            reason="Independent reread of the parser",
        )

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert "No current-generation queue row found for queue_item_id 999" in stderr
    assert client.reads == ["code/analysis-queue?limit=1000&offset=0"]


def test_reanalysis_resolves_an_existing_id_past_the_diagnostic_walk_bound(
    monkeypatch, tmp_path
) -> None:
    _bound_the_walk(monkeypatch, page_size=2, pages=2)
    client = _QueueListingClient(_queue_rows(6))
    _install_client(monkeypatch, client)

    items = code_dispatch._normalize_queue_items(
        _config(tmp_path), [{"queue_item_id": 6, "batch_theme": "reread"}],
        mode="reanalysis",
    )

    assert items == [{
        "file_id": 106, "batch_theme": "reread", "slot_types": [],
        "guidance_hypotheses": [],
    }]
    assert len(client.reads) == 3


@pytest.mark.parametrize("with_offset", [True, False])
def test_reanalysis_stops_on_a_repeated_page_without_claiming_absence(with_offset):
    class Client:
        reads = 0

        def get(self, _endpoint):
            self.reads += 1
            assert self.reads <= 2, "lookup continued after the page stopped advancing"
            page = {"items": [{"id": 1, "file_id": 101}], "has_more": True}
            if with_offset:
                page["offset"] = 0
            return page

    client = Client()

    lookup = code_dispatch._queue_rows_by_item_id(client, {999}, read_to_end=True)

    assert not lookup.exhaustive
    assert lookup.rows == {}
    assert client.reads == 2
