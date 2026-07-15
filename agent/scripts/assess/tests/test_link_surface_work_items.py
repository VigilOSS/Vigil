"""Tests for `vigil assess work-buffer link-surface` (folded-in link-surface-work-items).

The sub-action selects work_items by --cluster/--queue-key and links each one's
durable backend ``request_variant_id`` to one or more surfaces.
``request_variant_id`` (not the local work_item row id) is the only identifier
the backend recognizes, so a work_item that never successfully posted to the
backend (NULL request_variant_id) must be skipped with a warning rather than
failing the whole run — and two work_items that share the same
request_variant_id must not produce duplicate link POSTs.

The pass logic lives in ``assess.commands.dispatch.work_items._link_surface`` and
is invoked directly with the backend-less fake client (the CLI wrapper builds the
client and hands it to ``dispatch.run``).
"""
from __future__ import annotations

import argparse

from assess.commands.dispatch import work_items as wi
from _fake_client import FakeAssessmentClient


def _seed_work_item(
    fake: FakeAssessmentClient,
    *,
    queue_key: str,
    url: str,
    url_path: str,
    case_type: str = "api_route",
    cluster_key: str | None = None,
    request_variant_id: int | None = None,
) -> dict:
    return fake.add_row(
        queue_key=queue_key,
        method="GET",
        url=url,
        url_path=url_path,
        type=case_type,
        cluster_key=cluster_key,
        request_variant_id=request_variant_id,
    )


def _inject_link_failures(fake: FakeAssessmentClient, fail_surface_ids: set[int]) -> None:
    """Make the fake's surface-link POST raise for the given surface_ids, then
    delegate to the original ``post``."""
    original_post = fake.post

    def post(endpoint: str, payload: dict) -> dict:
        if (
            endpoint == "surface-request-variant-links"
            and payload.get("surface_id") in fail_surface_ids
        ):
            raise RuntimeError(f"backend rejected surface_id={payload.get('surface_id')}")
        return original_post(endpoint, payload)

    fake.post = post  # type: ignore[method-assign]


def _ns(
    *,
    cluster: list[str] | None = None,
    queue_key: list[str] | None = None,
    surface_id: list[str] | None = None,
    relation: str = "",
    link_evidence_ref: str = "",
) -> argparse.Namespace:
    return argparse.Namespace(
        cluster=cluster or [],
        queue_key=queue_key or [],
        surface_id=surface_id or [],
        relation=relation,
        link_evidence_ref=link_evidence_ref,
    )


def test_link_by_cluster_creates_one_link_per_request_variant(tmp_path, capsys):
    fake = FakeAssessmentClient()
    _seed_work_item(fake, queue_key="variant:101:api_route", url="https://example.com/a",
                    url_path="/a", cluster_key="gf:cluster", request_variant_id=101)
    _seed_work_item(fake, queue_key="variant:102:api_route", url="https://example.com/b",
                    url_path="/b", cluster_key="gf:cluster", request_variant_id=102)

    wi._link_surface(fake, _ns(cluster=["gf:cluster"], surface_id=["5"]))
    out = capsys.readouterr().out

    assert len(fake.links) == 2
    assert {link["request_variant_id"] for link in fake.links} == {101, 102}
    assert all(link["surface_id"] == 5 for link in fake.links)
    assert "Created 2 surface link(s) across 2 request variant(s)" in out


def test_link_by_queue_key_selects_exact_row(tmp_path, capsys):
    fake = FakeAssessmentClient()
    _seed_work_item(fake, queue_key="variant:200:api_route", url="https://example.com/c",
                    url_path="/c", request_variant_id=200)
    _seed_work_item(fake, queue_key="variant:201:api_route", url="https://example.com/d",
                    url_path="/d", request_variant_id=201)

    wi._link_surface(fake, _ns(queue_key=["variant:200:api_route"], surface_id=["9"]))
    capsys.readouterr()

    assert len(fake.links) == 1
    assert fake.links[0]["request_variant_id"] == 200
    assert fake.links[0]["surface_id"] == 9


def test_skips_work_item_with_null_request_variant_id(tmp_path, capsys):
    fake = FakeAssessmentClient()
    _seed_work_item(fake, queue_key="skipped:none:api_route", url="https://example.com/never-posted",
                    url_path="/never-posted", cluster_key="gf:never-posted", request_variant_id=None)

    wi._link_surface(fake, _ns(cluster=["gf:never-posted"], surface_id=["5"]))
    out, err = capsys.readouterr()

    assert fake.links == []
    assert "has no request_variant_id" in err
    assert "skipped 1 work_item(s) with no request_variant_id" in out
    assert "Created 0 surface link(s)" in out


def test_dedup_when_multiple_work_items_share_request_variant_id(tmp_path, capsys):
    fake = FakeAssessmentClient()
    _seed_work_item(fake, queue_key="variant:300:api_route", url="https://example.com/e",
                    url_path="/e", cluster_key="gf:dup", request_variant_id=300)
    _seed_work_item(fake, queue_key="variant:300:event_feed", url="https://example.com/e?x=1",
                    url_path="/e", case_type="event_feed", cluster_key="gf:dup", request_variant_id=300)

    wi._link_surface(fake, _ns(cluster=["gf:dup"], surface_id=["1", "2"]))
    out = capsys.readouterr().out

    assert len(fake.links) == 2
    assert {link["request_variant_id"] for link in fake.links} == {300}
    assert {link["surface_id"] for link in fake.links} == {1, 2}
    assert "Created 2 surface link(s) across 1 request variant(s)" in out


def test_failed_link_does_not_abort_remaining_links(tmp_path, capsys):
    fake = FakeAssessmentClient()
    _seed_work_item(fake, queue_key="variant:400:api_route", url="https://example.com/f",
                    url_path="/f", cluster_key="gf:flaky", request_variant_id=400)
    _inject_link_failures(fake, {1})

    wi._link_surface(fake, _ns(cluster=["gf:flaky"], surface_id=["1", "2"]))
    out, err = capsys.readouterr()

    assert len(fake.links) == 1
    assert fake.links[0]["surface_id"] == 2
    assert "failed to link surface 1" in err
    assert "Created 1 surface link(s)" in out
    assert "1 link(s) failed" in out


def test_requires_at_least_one_surface_id(tmp_path, capsys):
    fake = FakeAssessmentClient()
    try:
        wi._link_surface(fake, _ns(cluster=["gf:x"], surface_id=[]))
        assert False, "expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 1
    assert "at least one --surface-id is required" in capsys.readouterr().err


def test_requires_cluster_or_queue_key(tmp_path, capsys):
    fake = FakeAssessmentClient()
    try:
        wi._link_surface(fake, _ns(surface_id=["1"]))
        assert False, "expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 1
    assert "select work_items with --cluster" in capsys.readouterr().err


def test_comma_separated_surface_ids(tmp_path, capsys):
    """--surface-id accepts a comma-separated value (repeatable too)."""
    fake = FakeAssessmentClient()
    _seed_work_item(fake, queue_key="variant:500:api_route", url="https://example.com/g",
                    url_path="/g", cluster_key="gf:c", request_variant_id=500)
    wi._link_surface(fake, _ns(cluster=["gf:c"], surface_id=["1,2", "3"]))
    capsys.readouterr()
    assert {link["surface_id"] for link in fake.links} == {1, 2, 3}
