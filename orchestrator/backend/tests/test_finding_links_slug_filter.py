"""``GET /finding-links?finding_slug=`` filters and windows the links in SQL.

``export submission`` needs one finding's command-run links, and read the whole
engagement's link ledger to find them. The route now filters by the owning
finding's slug and applies ``limit``/``offset`` in the query, so a reader gets
exactly the rows the unfiltered listing would have given it for that finding, in
the same order, without the service building every other row first.
"""
from __future__ import annotations

import pytest

from app import db as db_module
from app.services.state_manager import links as links_module
from tests.test_finding_links_paging import ENGAGEMENT_KEY, _base, linked  # noqa: F401


def _engagement_id() -> int:
    with db_module.get_connection() as connection:
        return int(connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()["id"])


@pytest.mark.parametrize("slug", ["VA-001", "VA-004", "VA-000"])
def test_slug_filter_returns_that_findings_rows_in_listing_order(linked, slug) -> None:  # noqa: F811
    whole = linked.get(f"{_base()}/finding-links").json()

    filtered = linked.get(f"{_base()}/finding-links", params={"finding_slug": slug}).json()

    assert filtered == [row for row in whole if row["finding_slug"] == slug]
    assert filtered


def test_slug_filter_naming_no_finding_is_an_empty_list(linked) -> None:  # noqa: F811
    assert linked.get(f"{_base()}/finding-links", params={"finding_slug": "VA-404"}).json() == []


@pytest.mark.parametrize(("limit", "offset"), [(2, 0), (2, 2), (3, 5), (5, 100)])
def test_window_is_the_same_slice_of_the_listing(linked, limit, offset) -> None:  # noqa: F811
    whole = linked.get(f"{_base()}/finding-links").json()

    page = linked.get(
        f"{_base()}/finding-links", params={"limit": limit, "offset": offset}
    ).json()

    assert page == whole[offset : offset + limit]


def test_window_and_filter_build_only_the_rows_they_return(linked, monkeypatch) -> None:  # noqa: F811
    built: list[int] = []
    project = links_module._finding_link_read_projection

    def _counting(row):
        built.append(int(row["id"]))
        return project(row)

    monkeypatch.setattr(links_module, "_finding_link_read_projection", _counting)
    engagement_id = _engagement_id()

    page = links_module.list_finding_links(engagement_id, limit=2, offset=1)
    assert [row["id"] for row in page] == built
    assert len(built) == 2

    built.clear()
    one = links_module.list_finding_links(engagement_id, finding_slug="VA-003")
    assert {row["finding_slug"] for row in one} == {"VA-003"}
    assert len(built) == len(one)


def test_export_submission_reads_only_the_exported_findings_links(linked) -> None:  # noqa: F811
    from assess.commands import export_submission

    whole = linked.get(f"{_base()}/finding-links")

    class _Bridge:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.bytes = 0

        def get_all_pages(self, endpoint: str, *, page_size: int = 5000) -> list:
            separator = "&" if "?" in endpoint else "?"
            paged = f"{endpoint}{separator}limit={page_size}&offset=0"
            self.calls.append(paged)
            response = linked.get(f"{_base()}/{paged}")
            assert response.status_code == 200, response.text
            self.bytes += len(response.content)
            return response.json()

    bridge = _Bridge()

    assert export_submission._linked_command_runs(bridge, "VA-003") == []
    assert bridge.calls == ["finding-links?finding_slug=VA-003&limit=5000&offset=0"]
    assert bridge.bytes * 3 < len(whole.content)
