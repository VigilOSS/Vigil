"""`finding list --json` names exactly the fields its rows carry, per mode.

The stderr notice is the reader's map of what each row holds and what it left
out. It listed ``root_cause_role`` for every listing, while only the
``--root-cause`` group rows carry it, so a reader of the ordinary ledger looked
for a field that was never there.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from _fake_client import StubClient

from assess.commands import list_findings


class _Client(StubClient):
    def __exit__(self, *exc):
        self.close()
        return False

    def get(self, endpoint: str):
        row = {"id": 1, "slug": "VA-001", "title": "Finding", "severity": "high"}
        if endpoint.startswith("finding-groups/"):
            return {"root": dict(row), "siblings": [{**row, "id": 2, "slug": "VA-002"}]}
        if endpoint.startswith("findings/count"):
            return {"total": 1, "by_severity": {"high": 1}}
        return [row]


def _run(monkeypatch, capsys, **over) -> tuple[list[dict], str]:
    monkeypatch.setattr(list_findings, "AssessmentClient", _Client)
    monkeypatch.setattr(
        list_findings, "load_config",
        lambda _path: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )
    args = dict(
        engagement_dir="/tmp/eng", severity=None, workflow_status=None,
        verification_status=None, source_name=None, slug=None, root_cause_slug=None,
        search=None, holding=False, limit=10, offset=0, json=True,
    )
    args.update(over)
    list_findings.run(SimpleNamespace(**args))
    captured = capsys.readouterr()
    notice = next(line for line in captured.err.splitlines() if "each row carries only" in line)
    return json.loads(captured.out), notice


def _carried(notice: str) -> set[str]:
    listed = notice.split("each row carries only ", 1)[1].split(" and _point_read", 1)[0]
    return {name.strip() for name in listed.split(",")}


def test_ledger_listing_notice_omits_the_group_only_role(monkeypatch, capsys):
    rows, notice = _run(monkeypatch, capsys)

    assert all("root_cause_role" not in row for row in rows)
    assert "root_cause_role" not in _carried(notice)
    assert {"slug", "severity", "row_version"} <= _carried(notice)


def test_root_cause_listing_notice_names_the_role_its_rows_carry(monkeypatch, capsys):
    rows, notice = _run(monkeypatch, capsys, root_cause_slug="VA-001")

    assert [row["root_cause_role"] for row in rows] == ["root", "sibling"]
    assert "root_cause_role" in _carried(notice)
