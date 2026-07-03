"""Tests for `vigil assess link-surface-work-items`.

The command selects local cases.db work_items by --cluster/--queue-key and
links each one's durable backend ``request_variant_id`` to one or more
surfaces. ``request_variant_id`` (not the local work_item row id) is the only
identifier the backend recognizes, so a work_item that never successfully
posted to the backend (NULL request_variant_id) must be skipped with a
warning rather than failing the whole run — and two work_items that share the
same request_variant_id must not produce duplicate link POSTs.

The backend / runtime are stubbed (`load_config` and the context-managed
`AssessmentClient`), matching the pattern used by the ingest-candidates and
ingest-spec test suites.
"""
from __future__ import annotations

import argparse

from assess.commands import link_surface_work_items
from assess.lib.db import db_init, db_insert_work_item


class _Cfg:
    """Minimal stand-in for `assess.lib.config.Config`."""

    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Context-managed fake (the command uses `with AssessmentClient(...)`)."""

    def __init__(self) -> None:
        self.links: list[dict] = []
        self.fail_surface_ids: set[int] = set()

    def post(self, endpoint: str, payload: dict) -> dict:
        assert endpoint == "surface-request-variant-links"
        if payload.get("surface_id") in self.fail_surface_ids:
            raise RuntimeError(f"backend rejected surface_id={payload.get('surface_id')}")
        self.links.append(payload)
        return {"id": len(self.links), **payload}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _ns(
    db_path: str,
    engagement_dir: str,
    *,
    cluster: list[str] | None = None,
    queue_key: list[str] | None = None,
    surface_id: list[str] | None = None,
    relation: str = "",
    evidence_ref: str = "",
) -> argparse.Namespace:
    return argparse.Namespace(
        db_path=db_path,
        engagement_dir=engagement_dir,
        cluster=cluster or [],
        queue_key=queue_key or [],
        surface_id=surface_id or [],
        relation=relation,
        evidence_ref=evidence_ref,
    )


def _seed_db(tmp_path) -> str:
    db = tmp_path / "cases.db"
    db.write_bytes(b"")
    db_init(str(db))
    return str(db)


def _setup_client(monkeypatch, tmp_path, fake_client: _FakeClient) -> None:
    monkeypatch.setattr(link_surface_work_items, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(link_surface_work_items, "AssessmentClient", lambda *a, **k: fake_client)


def test_link_by_cluster_creates_one_link_per_request_variant(tmp_path, monkeypatch, capsys):
    db = _seed_db(tmp_path)
    db_insert_work_item(
        db,
        queue_key="variant:101:api_route",
        method="GET",
        url="https://example.com/a",
        url_path="/a",
        case_type="api_route",
        cluster_key="gf:cluster",
        request_variant_id=101,
    )
    db_insert_work_item(
        db,
        queue_key="variant:102:api_route",
        method="GET",
        url="https://example.com/b",
        url_path="/b",
        case_type="api_route",
        cluster_key="gf:cluster",
        request_variant_id=102,
    )

    fake_client = _FakeClient()
    _setup_client(monkeypatch, tmp_path, fake_client)

    link_surface_work_items.run(
        _ns(db, str(tmp_path), cluster=["gf:cluster"], surface_id=["5"])
    )
    out = capsys.readouterr().out

    assert len(fake_client.links) == 2
    variant_ids = {link["request_variant_id"] for link in fake_client.links}
    assert variant_ids == {101, 102}
    assert all(link["surface_id"] == 5 for link in fake_client.links)
    assert "Created 2 surface link(s) across 2 request variant(s)" in out


def test_link_by_queue_key_selects_exact_row(tmp_path, monkeypatch, capsys):
    db = _seed_db(tmp_path)
    db_insert_work_item(
        db,
        queue_key="variant:200:api_route",
        method="GET",
        url="https://example.com/c",
        url_path="/c",
        case_type="api_route",
        request_variant_id=200,
    )
    db_insert_work_item(
        db,
        queue_key="variant:201:api_route",
        method="GET",
        url="https://example.com/d",
        url_path="/d",
        case_type="api_route",
        request_variant_id=201,
    )

    fake_client = _FakeClient()
    _setup_client(monkeypatch, tmp_path, fake_client)

    link_surface_work_items.run(
        _ns(db, str(tmp_path), queue_key=["variant:200:api_route"], surface_id=["9"])
    )
    capsys.readouterr()

    assert len(fake_client.links) == 1
    assert fake_client.links[0]["request_variant_id"] == 200
    assert fake_client.links[0]["surface_id"] == 9


def test_skips_work_item_with_null_request_variant_id(tmp_path, monkeypatch, capsys):
    db = _seed_db(tmp_path)
    db_insert_work_item(
        db,
        queue_key="skipped:none:api_route",
        method="GET",
        url="https://example.com/never-posted",
        url_path="/never-posted",
        case_type="api_route",
        cluster_key="gf:never-posted",
        request_variant_id=None,
    )

    fake_client = _FakeClient()
    _setup_client(monkeypatch, tmp_path, fake_client)

    link_surface_work_items.run(
        _ns(db, str(tmp_path), cluster=["gf:never-posted"], surface_id=["5"])
    )
    out, err = capsys.readouterr()

    assert fake_client.links == []
    assert "has no request_variant_id" in err
    assert "skipped 1 work_item(s) with no request_variant_id" in out
    assert "Created 0 surface link(s)" in out


def test_dedup_when_multiple_work_items_share_request_variant_id(tmp_path, monkeypatch, capsys):
    db = _seed_db(tmp_path)
    db_insert_work_item(
        db,
        queue_key="variant:300:api_route",
        method="GET",
        url="https://example.com/e",
        url_path="/e",
        case_type="api_route",
        cluster_key="gf:dup",
        request_variant_id=300,
    )
    db_insert_work_item(
        db,
        queue_key="variant:300:event_feed",
        method="GET",
        url="https://example.com/e?x=1",
        url_path="/e",
        case_type="event_feed",
        cluster_key="gf:dup",
        request_variant_id=300,
    )

    fake_client = _FakeClient()
    _setup_client(monkeypatch, tmp_path, fake_client)

    link_surface_work_items.run(
        _ns(db, str(tmp_path), cluster=["gf:dup"], surface_id=["1", "2"])
    )
    out = capsys.readouterr().out

    # Only ONE link per surface should be created for the shared variant,
    # even though two work_items reference it.
    assert len(fake_client.links) == 2
    assert {link["request_variant_id"] for link in fake_client.links} == {300}
    assert {link["surface_id"] for link in fake_client.links} == {1, 2}
    assert "Created 2 surface link(s) across 1 request variant(s)" in out


def test_failed_link_does_not_abort_remaining_links(tmp_path, monkeypatch, capsys):
    db = _seed_db(tmp_path)
    db_insert_work_item(
        db,
        queue_key="variant:400:api_route",
        method="GET",
        url="https://example.com/f",
        url_path="/f",
        case_type="api_route",
        cluster_key="gf:flaky",
        request_variant_id=400,
    )

    fake_client = _FakeClient()
    fake_client.fail_surface_ids = {1}
    _setup_client(monkeypatch, tmp_path, fake_client)

    link_surface_work_items.run(
        _ns(db, str(tmp_path), cluster=["gf:flaky"], surface_id=["1", "2"])
    )
    out, err = capsys.readouterr()

    # surface_id=1 failed but surface_id=2 still got linked.
    assert len(fake_client.links) == 1
    assert fake_client.links[0]["surface_id"] == 2
    assert "failed to link surface 1" in err
    assert "Created 1 surface link(s)" in out
    assert "1 link(s) failed" in out


def test_requires_at_least_one_surface_id(tmp_path, monkeypatch, capsys):
    db = _seed_db(tmp_path)
    fake_client = _FakeClient()
    _setup_client(monkeypatch, tmp_path, fake_client)

    try:
        link_surface_work_items.run(_ns(db, str(tmp_path), cluster=["gf:x"], surface_id=[]))
        assert False, "expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 1
    err = capsys.readouterr().err
    assert "at least one --surface-id is required" in err


def test_requires_cluster_or_queue_key(tmp_path, monkeypatch, capsys):
    db = _seed_db(tmp_path)
    fake_client = _FakeClient()
    _setup_client(monkeypatch, tmp_path, fake_client)

    try:
        link_surface_work_items.run(_ns(db, str(tmp_path), surface_id=["1"]))
        assert False, "expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 1
    err = capsys.readouterr().err
    assert "select work_items with --cluster" in err
