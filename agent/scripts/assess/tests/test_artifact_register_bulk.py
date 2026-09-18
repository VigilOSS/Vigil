"""`artifact register` registers many paths in one call, and accounts for each.

Explicit registration was one POST per path — 14,351 of them across the recorded
engagements, one of which registered 3,503 artifacts by hand. The batch form
keeps the single-path call byte-for-byte unchanged (same endpoint, same output,
same audit row) and sends anything longer to `artifacts/bulk`, where one refused
path no longer costs the rest of the batch its work.

What these pin is the accounting: every submitted path leaves exactly one
outcome, a path the CLI cannot canonicalise fails on its own without reaching
the backend, and a chunk whose POST fails STOPS the run and reports its paths as
`unknown` (the write may have committed) with the untried remainder named rather
than dropped.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import artifact
from assess.lib.bulk_ingest import DEFAULT_BULK_WRITE_SIZE
from assess.lib.client import DEFAULT_READ_TIMEOUT_SECONDS, AssessError


class _RecordingClient:
    """Bulk-aware fake: registers whatever it is sent, in submission order."""

    def __init__(
        self,
        *,
        fail_chunks: set[int] | None = None,
        chunk_error: AssessError | None = None,
        refuse_paths: set[str] | None = None,
    ) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.read_timeouts: list[float | None] = []
        self._fail_chunks = fail_chunks or set()
        self._chunk_error = chunk_error or AssessError("HTTP 503\nbackend unavailable")
        self._refuse_paths = refuse_paths or set()
        self._bulk_calls = 0
        self._next_id = 1

    def _row(self, item: dict) -> dict:
        row = {
            "id": self._next_id,
            "relative_path": item["path"],
            "kind": item.get("kind") or "note",
            "present": True,
            "scratch": False,
            "size_bytes": 12,
            "sha256": "0" * 64,
            "indexed_bytes": 12,
            "index_status": "complete",
            "preview_text": "evidence",
            "related_finding_slug": item.get("related_finding_slug"),
        }
        self._next_id += 1
        return row

    def post(
        self, endpoint: str, payload: dict, *, read_timeout: float | None = None
    ) -> dict:
        if endpoint == "artifacts/bulk":
            self._bulk_calls += 1
            if self._bulk_calls in self._fail_chunks:
                raise self._chunk_error
        self.posts.append((endpoint, payload))
        self.read_timeouts.append(read_timeout)
        if endpoint == "artifacts":
            return self._row(payload)
        assert endpoint == "artifacts/bulk", endpoint
        outcomes: list[dict] = []
        artifacts: list[dict] = []
        for index, item in enumerate(payload["items"]):
            if item["path"] in self._refuse_paths:
                outcomes.append(
                    {
                        "index": index,
                        "path": item["path"],
                        "relative_path": None,
                        "artifact_id": None,
                        "outcome": "failed",
                        "status_code": 409,
                        "detail": "artifact path is reserved from indexing",
                    }
                )
                continue
            row = self._row(item)
            artifacts.append(row)
            outcomes.append(
                {
                    "index": index,
                    "path": item["path"],
                    "relative_path": row["relative_path"],
                    "artifact_id": row["id"],
                    "outcome": "registered",
                    "status_code": None,
                    "detail": "",
                }
            )
        return {
            "requested": len(payload["items"]),
            "registered": len(artifacts),
            "failed": len(payload["items"]) - len(artifacts),
            "outcomes": outcomes,
            "artifacts": artifacts,
        }

    def close(self) -> None:
        return None


@pytest.fixture()
def engagement(tmp_path: Path) -> Path:
    root = tmp_path / "engagements" / "e1"
    (root / "notes").mkdir(parents=True)
    for name in ("a.md", "b.md", "c.md"):
        (root / "notes" / name).write_text("evidence\n", encoding="utf-8")
    return root


def _install(monkeypatch, engagement_dir: Path, client: _RecordingClient) -> _RecordingClient:
    monkeypatch.setattr(artifact, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(
        artifact,
        "load_config",
        lambda _dir: SimpleNamespace(
            base_url="http://backend",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    return client


def _run(engagement_dir: Path, argv: list[str]) -> None:
    parser = argparse.ArgumentParser()
    artifact.register(parser.add_subparsers())
    args = parser.parse_args(["artifact", "register", *argv])
    args.engagement_dir = str(engagement_dir)
    args.func(args)


def test_one_path_still_uses_the_single_artifact_endpoint(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _install(monkeypatch, engagement, _RecordingClient())

    _run(engagement, ["notes/a.md", "--kind", "note", "--json"])

    assert [endpoint for endpoint, _payload in client.posts] == ["artifacts"]
    (_endpoint, payload) = client.posts[0]
    assert payload["path"] == "notes/a.md"
    # The single-path form answers with the artifact row itself, unwrapped.
    assert json.loads(capsys.readouterr().out)["relative_path"] == "notes/a.md"


def test_several_paths_use_the_bulk_endpoint_in_one_call(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _install(monkeypatch, engagement, _RecordingClient())

    _run(engagement, ["notes/a.md", "./notes/b.md", "notes/c.md", "--kind", "note"])

    assert [endpoint for endpoint, _payload in client.posts] == ["artifacts/bulk"]
    (_endpoint, payload) = client.posts[0]
    assert [item["path"] for item in payload["items"]] == [
        "notes/a.md",
        "notes/b.md",
        "notes/c.md",
    ]
    assert all(item["kind"] == "note" for item in payload["items"])
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert "notes/c.md" in out
    assert "requested=3 registered=3 failed=0" in out


def test_paths_file_entries_follow_the_positional_ones(
    monkeypatch, capsys, engagement: Path, tmp_path: Path
) -> None:
    listing = tmp_path / "paths.txt"
    listing.write_text("notes/b.md\n\n  notes/c.md  \n", encoding="utf-8")
    client = _install(monkeypatch, engagement, _RecordingClient())

    _run(engagement, ["notes/a.md", "--paths-file", str(listing)])

    (_endpoint, payload) = client.posts[0]
    assert [item["path"] for item in payload["items"]] == [
        "notes/a.md",
        "notes/b.md",
        "notes/c.md",
    ]
    assert "requested=3 registered=3 failed=0" in capsys.readouterr().err


def test_paths_file_dash_reads_the_list_from_stdin(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _install(monkeypatch, engagement, _RecordingClient())
    monkeypatch.setattr(
        "sys.stdin", SimpleNamespace(read=lambda: "notes/a.md\nnotes/b.md\n")
    )

    _run(engagement, ["--paths-file", "-"])

    (_endpoint, payload) = client.posts[0]
    assert [item["path"] for item in payload["items"]] == ["notes/a.md", "notes/b.md"]


def test_no_path_at_all_is_an_error(monkeypatch, capsys, engagement: Path) -> None:
    client = _install(monkeypatch, engagement, _RecordingClient())
    empty = engagement / "notes" / "empty-list.txt"
    empty.write_text("\n\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        _run(engagement, ["--paths-file", str(empty)])

    assert exc.value.code == 1
    assert client.posts == []
    assert "--paths-file" in capsys.readouterr().err


def test_more_paths_than_one_chunk_post_in_chunks_with_one_accounting(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _install(monkeypatch, engagement, _RecordingClient())
    paths = [f"notes/bulk-{index}.md" for index in range(DEFAULT_BULK_WRITE_SIZE + 2)]

    _run(engagement, paths)

    assert [endpoint for endpoint, _payload in client.posts] == [
        "artifacts/bulk",
        "artifacts/bulk",
    ]
    assert [len(payload["items"]) for _endpoint, payload in client.posts] == [
        DEFAULT_BULK_WRITE_SIZE,
        2,
    ]
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert (
        f"requested={len(paths)} registered={len(paths)} failed=0" in out
    ), out.splitlines()[-1]


def test_a_path_the_cli_cannot_canonicalise_fails_alone(
    monkeypatch, capsys, engagement: Path, tmp_path: Path
) -> None:
    client = _install(monkeypatch, engagement, _RecordingClient())
    outside = str(tmp_path / "outside.md")

    with pytest.raises(SystemExit) as exc:
        _run(engagement, ["notes/a.md", outside, "notes/b.md"])

    assert exc.value.code == 1
    (_endpoint, payload) = client.posts[0]
    assert [item["path"] for item in payload["items"]] == ["notes/a.md", "notes/b.md"]
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert "requested=3 registered=2 failed=1" in out
    # ADR 0019: the refused path and its whole reason, not a count.
    assert outside in out
    assert "inside the engagement directory" in out


def test_a_failed_chunk_stops_and_reports_unknown_and_not_attempted(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _install(monkeypatch, engagement, _RecordingClient(fail_chunks={2}))
    paths = [f"notes/bulk-{index}.md" for index in range(DEFAULT_BULK_WRITE_SIZE * 2 + 1)]

    with pytest.raises(SystemExit) as exc:
        _run(engagement, [*paths, "--json"])

    assert exc.value.code == 1
    # The third chunk is never sent: the second one's fate is unknown.
    assert len(client.posts) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["requested"] == len(paths)
    assert result["registered"] == DEFAULT_BULK_WRITE_SIZE
    assert result["unknown"] == DEFAULT_BULK_WRITE_SIZE
    assert result["not_attempted"] == 1
    assert (
        result["registered"] + result["failed"] + result["unknown"]
        + result["not_attempted"]
        == result["requested"]
    )
    assert [outcome["outcome"] for outcome in result["outcomes"][-2:]] == [
        "unknown",
        "not_attempted",
    ]
    assert "do not retry automatically" in result["outcomes"][-2]["detail"]
    assert "HTTP 503" in result["outcomes"][-2]["detail"]


def test_second_chunk_outcomes_carry_their_submission_index_and_spelling(
    monkeypatch, capsys, engagement: Path
) -> None:
    # The wire's `index` is chunk-relative and its `path` is the canonical form.
    # Both are re-based onto the submission before they reach the caller; without
    # that, the second chunk repeats indices 0..N and the --json outcomes sort
    # into an interleaved list that names the wrong path for every position.
    _install(monkeypatch, engagement, _RecordingClient())
    paths = [f"./notes/bulk-{index}.md" for index in range(DEFAULT_BULK_WRITE_SIZE + 2)]

    _run(engagement, [*paths, "--json"])

    result = json.loads(capsys.readouterr().out)
    assert [outcome["index"] for outcome in result["outcomes"]] == list(range(len(paths)))
    # The caller's own spelling survives, so a reported path is one they can find
    # in what they typed rather than a canonicalisation they never wrote.
    assert [outcome["path"] for outcome in result["outcomes"]] == paths
    last = result["outcomes"][-1]
    assert last["index"] == len(paths) - 1
    assert last["relative_path"] == f"notes/bulk-{len(paths) - 1}.md"


def test_a_path_the_backend_refuses_is_counted_and_reported_in_full(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _install(
        monkeypatch,
        engagement,
        _RecordingClient(refuse_paths={"notes/b.md"}),
    )

    with pytest.raises(SystemExit) as exc:
        _run(engagement, ["notes/a.md", "notes/b.md", "notes/c.md"])

    assert exc.value.code == 1
    # The refusal costs only itself: the other two still committed.
    assert len(client.posts) == 1
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert "requested=3 registered=2 failed=1" in out
    assert "failed notes/b.md: artifact path is reserved from indexing" in out


def test_a_chunk_refused_before_any_write_is_failed_not_unknown(
    monkeypatch, capsys, engagement: Path
) -> None:
    # A 422 is FastAPI rejecting the body ahead of the handler, so nothing in
    # that chunk can be durable. Reporting it as "may have committed" sends the
    # operator to reconcile state that was never touched.
    client = _install(
        monkeypatch,
        engagement,
        _RecordingClient(
            fail_chunks={1},
            chunk_error=AssessError("HTTP 422 validation error:\nitems: too many"),
        ),
    )

    with pytest.raises(SystemExit) as exc:
        _run(engagement, ["notes/a.md", "notes/b.md", "--json"])

    assert exc.value.code == 1
    assert client.posts == []
    result = json.loads(capsys.readouterr().out)
    assert result["failed"] == 2
    assert result["unknown"] == 0
    details = {outcome["detail"] for outcome in result["outcomes"]}
    assert all("may have committed" not in detail for detail in details)
    assert any("refused before any write" in detail for detail in details)


def test_a_bulk_chunk_gets_a_response_budget_that_scales_with_its_size(
    monkeypatch, capsys, engagement: Path
) -> None:
    # The backend hashes every file in the chunk, so a flat 10 s budget turns a
    # large but healthy batch into an `unknown` the caller cannot retry.
    client = _install(monkeypatch, engagement, _RecordingClient())
    paths = [f"notes/bulk-{index}.md" for index in range(DEFAULT_BULK_WRITE_SIZE + 2)]

    _run(engagement, paths)
    capsys.readouterr()

    assert client.read_timeouts == [
        artifact._BULK_REGISTER_SECONDS_PER_PATH * DEFAULT_BULK_WRITE_SIZE,
        DEFAULT_READ_TIMEOUT_SECONDS,
    ]


def test_a_bulk_receipt_that_registered_another_file_is_rejected(
    monkeypatch, capsys, engagement: Path
) -> None:
    # The bulk half of `test_a_response_for_another_file_is_still_rejected`.
    # Checking the returned row against the receipt's OWN `relative_path`
    # compares the response to itself: a backend that echoes the path it was
    # asked about and then names a different file as registered passes. The
    # canonical path we submitted is the only usable comparand.
    class _WrongFileClient(_RecordingClient):
        def post(self, endpoint: str, payload: dict, *, read_timeout=None) -> dict:
            self.posts.append((endpoint, payload))
            return {
                "requested": 2,
                "registered": 2,
                "failed": 0,
                "outcomes": [
                    {
                        "index": index,
                        "path": item["path"],
                        "relative_path": "notes/other.md",
                        "artifact_id": 7 + index,
                        "outcome": "registered",
                        "status_code": None,
                        "detail": "",
                    }
                    for index, item in enumerate(payload["items"])
                ],
                "artifacts": [
                    {"id": 7 + index, "relative_path": "notes/other.md", "present": True}
                    for index, _item in enumerate(payload["items"])
                ],
            }

    _install(monkeypatch, engagement, _WrongFileClient())

    with pytest.raises(SystemExit) as exc:
        _run(engagement, ["notes/a.md", "notes/b.md", "--json"])

    assert exc.value.code == 1
    result = json.loads(capsys.readouterr().out)
    # Nothing is claimed as registered on a receipt that cannot be trusted to say
    # which file it wrote, and the caller is told the rows may still be durable.
    assert result["registered"] == 0
    assert result["unknown"] == 2
    assert result["artifacts"] == []
    assert all(
        "do not retry automatically" in outcome["detail"]
        for outcome in result["outcomes"]
    )


def test_outcomes_come_back_in_submission_order(
    monkeypatch, capsys, engagement: Path, tmp_path: Path
) -> None:
    """``outcomes[i]`` is the outcome for the i-th path the caller supplied.

    A path the CLI cannot canonicalise is refused before the chunk loop runs, so
    it is recorded ahead of every path that reached the backend. Without the
    re-sort the array reads ``[1, 0, 2]`` and a caller zipping its own input list
    against ``outcomes`` positionally attributes each reason to the wrong file.
    """
    _install(monkeypatch, engagement, _RecordingClient())
    outside = str(tmp_path / "outside.md")

    with pytest.raises(SystemExit) as exc:
        _run(engagement, ["notes/a.md", outside, "notes/b.md", "--json"])

    assert exc.value.code == 1
    result = json.loads(capsys.readouterr().out)
    assert [outcome["index"] for outcome in result["outcomes"]] == [0, 1, 2]
    assert [outcome["path"] for outcome in result["outcomes"]] == [
        "notes/a.md",
        outside,
        "notes/b.md",
    ]
    assert [outcome["outcome"] for outcome in result["outcomes"]] == [
        "registered",
        "failed",
        "registered",
    ]


class _NoBulkRouteClient(_RecordingClient):
    """A backend process that predates /artifacts/bulk."""

    def post(self, endpoint: str, payload, **kwargs):
        if endpoint == "artifacts/bulk":
            self.posts.append((endpoint, payload))
            raise AssessError("HTTP 404: Not Found")
        return super().post(endpoint, payload, **kwargs)


def test_a_backend_without_the_bulk_route_still_registers_every_path(
    monkeypatch, capsys, engagement: Path
) -> None:
    """The CLI and the backend upgrade independently.

    A new CLI against a backend process that has not been restarted used to
    register NOTHING — strictly worse than the single-path form it replaced.
    Both other bulk clients already fall back per item on 404/405.
    """

    client = _install(monkeypatch, engagement, _NoBulkRouteClient())

    _run(engagement, ["notes/a.md", "notes/b.md", "notes/c.md"])

    endpoints = [endpoint for endpoint, _payload in client.posts]
    assert endpoints == ["artifacts/bulk", "artifacts", "artifacts", "artifacts"]
    captured = capsys.readouterr()
    assert "no bulk endpoint" in captured.err
    assert "vigil orchestrator restart" in captured.err
    assert "requested=3 registered=3 failed=0" in captured.err


def test_one_file_named_twice_is_registered_once(
    monkeypatch, capsys, engagement: Path
) -> None:
    """`registered=` has to describe the index, not the argv."""

    client = _install(monkeypatch, engagement, _RecordingClient())

    _run(engagement, ["notes/a.md", "./notes/a.md", "notes/b.md"])

    (_endpoint, payload) = client.posts[0]
    assert [item["path"] for item in payload["items"]] == ["notes/a.md", "notes/b.md"]
    captured = capsys.readouterr()
    assert "requested=3 registered=2 failed=0 duplicate=1" in captured.err
    assert "duplicate ./notes/a.md" in captured.err


def test_the_rows_go_to_stdout_and_the_reasons_to_stderr(
    monkeypatch, capsys, engagement: Path
) -> None:
    """`register ... > rows.txt` must not swallow why a path did not land."""

    _install(monkeypatch, engagement, _RecordingClient())

    # An absent file registers as a reference (same as the single-path form);
    # a path outside the engagement is the refusal worth pinning.
    with pytest.raises(SystemExit):
        _run(engagement, ["notes/a.md", "/etc/hosts"])

    captured = capsys.readouterr()
    assert "notes/a.md" in captured.out
    assert "requested=" not in captured.out
    assert "requested=2" in captured.err
    assert "/etc/hosts" in captured.err
