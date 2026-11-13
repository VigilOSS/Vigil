"""Work-buffer keys stay inside the backend bound, and relative paths are not hosts.

Two ingest defects pinned here:

* A skipped (out-of-scope) or deferred (egress-blocked) row's ``queue_key``
  embedded the raw URL, so a gau URL of a few thousand characters produced a key
  above the backend's 512-character ``queue_key`` bound. The whole
  ``work-items/bulk`` chunk was refused with a 422 and the process died, so every
  URL after it never reached the work buffer.
* A bare relative filename from a JS bundle (``app.css``, ``aura.js``) matched the
  host shape, was turned into ``https://app.css`` and recorded as an out-of-scope
  host, inviting a scope.json edit for a host that does not exist.
"""
from __future__ import annotations

import argparse
import json

from assess.commands import ingest_endpoints
from assess.lib.bulk_ingest import MAX_QUEUE_KEY_LENGTH, bounded_queue_key
from assess.lib.client import AssessError

from _fake_client import FakeAssessmentClient


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _BoundedBackend(FakeAssessmentClient):
    """Refuses a ``work-items/bulk`` request the way the backend model does."""

    def post(self, endpoint: str, payload: dict, **kwargs) -> dict:
        if endpoint == "work-items/bulk":
            for index, item in enumerate(payload.get("items", [])):
                if len(str(item.get("queue_key") or "")) > MAX_QUEUE_KEY_LENGTH:
                    raise AssessError(
                        f"HTTP 422: body.items.{index}.queue_key: String should have "
                        f"at most {MAX_QUEUE_KEY_LENGTH} characters"
                    )
                if len(str(item.get("host") or "")) > 512:
                    raise AssessError(
                        f"HTTP 422: body.items.{index}.host: String should have at "
                        "most 512 characters"
                    )
        return super().post(endpoint, payload)


def _install(monkeypatch, tmp_path, fake, scope: dict) -> None:
    (tmp_path / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    monkeypatch.setattr(ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_endpoints, "AssessmentClient", lambda *a, **k: fake)


def _run(tmp_path, lines: list[str], *, egress_blocked: str | None = None) -> None:
    input_file = tmp_path / "endpoints.txt"
    input_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ingest_endpoints.run(
        argparse.Namespace(
            source="gau",
            input_file=str(input_file),
            egress_blocked_hosts=egress_blocked,
            engagement_dir=str(tmp_path),
        )
    )


def test_long_out_of_scope_url_keeps_its_row_and_the_rest_of_the_batch(
    tmp_path, monkeypatch, capsys
):
    long_a = "https://cdn.other.example/assets/" + "a" * 3000 + "?v=1"
    long_b = "https://cdn.other.example/assets/" + "a" * 3000 + "?v=2"
    short = "https://cdn.other.example/x"
    in_scope = "https://app.example.com/api/v1/users"
    fake = _BoundedBackend()
    _install(monkeypatch, tmp_path, fake, {"hosts": ["*.example.com"]})

    _run(tmp_path, [long_a, long_b, short, in_scope])
    capsys.readouterr()

    items = fake.bulk_work_items()
    assert {item["url"] for item in items} == {long_a, long_b, short}
    assert all(len(item["queue_key"]) <= MAX_QUEUE_KEY_LENGTH for item in items)
    # Distinct long URLs keep distinct keys (no collision on a shared prefix).
    keys = {item["url"]: item["queue_key"] for item in items}
    assert keys[long_a] != keys[long_b]
    # A key that already fits keeps its readable shape.
    assert keys[short] == f"skipped:out-of-scope:cdn.other.example:{short}"
    assert keys[long_a].startswith("skipped:out-of-scope:cdn.other.example:")
    # The full URL stays on the row itself.
    assert fake.row_for_url(long_a)[0]["url"] == long_a
    # The in-scope URL after the long ones still reached the work buffer.
    assert {o["url"] for o in fake.observations} == {in_scope}


def test_long_egress_blocked_url_is_deferred_with_a_bounded_key(tmp_path, monkeypatch, capsys):
    blocked = tmp_path / "blocked.txt"
    blocked.write_text("edge.example.com\n", encoding="utf-8")
    long_url = "https://edge.example.com/" + "b" * 4000
    fake = _BoundedBackend()
    _install(monkeypatch, tmp_path, fake, {"hosts": ["*.example.com"]})

    _run(tmp_path, [long_url], egress_blocked=str(blocked))
    capsys.readouterr()

    rows = fake.row_for_url(long_url)
    assert len(rows) == 1
    assert rows[0]["status"] == "deferred"
    assert len(rows[0]["queue_key"]) <= MAX_QUEUE_KEY_LENGTH
    assert rows[0]["queue_key"].startswith("deferred:egress-blocked:edge.example.com:")


def test_bounded_queue_key_is_deterministic_and_bounded():
    short = "skipped:out-of-scope:h.example:https://h.example/a"
    assert bounded_queue_key(short) == short
    long_key = "skipped:out-of-scope:h.example:https://h.example/" + "z" * 2000
    bounded = bounded_queue_key(long_key)
    assert len(bounded) <= MAX_QUEUE_KEY_LENGTH
    assert bounded == bounded_queue_key(long_key)
    assert bounded != bounded_queue_key(long_key + "y")


def test_one_refused_direct_row_does_not_drop_its_chunk(tmp_path, monkeypatch, capsys):
    # A host longer than any DNS name: the backend refuses that row's host field.
    bad = "https://" + ".".join(["a" * 60] * 10) + ".other.example/x"
    good = "https://cdn.other.example/kept"
    fake = _BoundedBackend()
    _install(monkeypatch, tmp_path, fake, {"hosts": ["*.example.com"]})

    _run(tmp_path, [bad, good])
    err = capsys.readouterr().err

    assert fake.row_for_url(good), "the refused row took its whole chunk down"
    assert not fake.row_for_url(bad)
    assert "backend rejected" in err and bad[:60] in err


def test_bare_relative_filenames_are_not_recorded_as_hosts(tmp_path, monkeypatch, capsys):
    fake = _BoundedBackend()
    _install(monkeypatch, tmp_path, fake, {"hosts": ["*.example.com"]})

    _run(
        tmp_path,
        [
            "app.css",
            "aura.js",
            "static/syntax.html",
            "bundle.min.js?v=3",
            "data.json",
            "main.js.map",
            "/relative/only",
            "https://app.example.com/ok",
        ],
    )
    captured = capsys.readouterr()

    assert fake.bulk_work_items() == [], "relative paths were recorded as out-of-scope hosts"
    assert {o["url"] for o in fake.observations} == {"https://app.example.com/ok"}
    assert "out of scope" not in captured.err
    assert "7 relative-path" in captured.err


def test_hosts_whose_tld_resembles_a_file_type_stay_hosts(tmp_path, monkeypatch, capsys):
    # .zip, .mov and .app are delegated TLDs; .py and .sh are ccTLDs.
    hosts = ["downloads.zip", "trailer.mov", "portal.app", "docs.py", "tools.sh"]
    fake = _BoundedBackend()
    _install(monkeypatch, tmp_path, fake, {"scope_enforcement": "bypass"})

    _run(tmp_path, hosts)
    capsys.readouterr()

    assert {o["target_hostname"] for o in fake.observations} == set(hosts)


class _RefusingObservationBackend(_BoundedBackend):
    """Refuses observation rows on ``refused`` paths (422) and fails ``flaky`` ones (503)."""

    def post(self, endpoint: str, payload: dict, **kwargs) -> dict:
        if endpoint == "request-observations/bulk" and any(
            "/refused" in item["url"] or "/flaky" in item["url"]
            for item in payload.get("items", [])
        ):
            raise AssessError("HTTP 422: body.items.0.url: refused")
        if endpoint == "request-observations":
            if "/refused" in payload["url"]:
                raise AssessError("HTTP 422: body.url: refused")
            if "/flaky" in payload["url"]:
                raise AssessError("HTTP 503: backend unavailable")
        return super().post(endpoint, payload)


def test_rows_the_backend_refused_are_counted_as_refused_not_malformed(
    tmp_path, monkeypatch, capsys
):
    bad_direct = "https://" + ".".join(["a" * 60] * 10) + ".other.example/x"
    lines = [
        "https://app.example.com/refused",
        "https://app.example.com/flaky",
        "https://app.example.com/kept",
        bad_direct,
        "ftp://files.example.com/a",
    ]
    fake = _RefusingObservationBackend()
    _install(monkeypatch, tmp_path, fake, {"hosts": ["*.example.com"]})

    input_file = tmp_path / "endpoints.txt"
    input_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    summary = ingest_endpoints.run(
        argparse.Namespace(
            source="gau", input_file=str(input_file), egress_blocked_hosts=None,
            engagement_dir=str(tmp_path),
        )
    )
    err = capsys.readouterr().err

    assert summary["ingested"] == 1
    assert summary["backend_refused"] == 2  # the 422 observation and the 422 direct row
    assert summary["write_uncertain"] == 1  # a 503 may or may not have committed
    assert summary["skipped"]["malformed"] == 1  # only the line that was never an http(s) URL
    assert "2 row(s) the backend refused" in err
    assert "1 row(s) whose write failed with an unknown outcome" in err
    assert "1 malformed/unkeyable" in err
