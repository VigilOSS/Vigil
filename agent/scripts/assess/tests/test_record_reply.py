"""CLI tests for `vigil assess record-reply`.

Drives the real argparse parser (`record_reply.register`) and `run` with a fake
client, pinning the array-safe write path the plan locks down:

  * read-modify-write — the FULL `details.replies` array is PATCHed back, so a new
    reply APPENDS without clobbering prior replies (the shallow backend details
    merge would otherwise replace the whole key);
  * `--seq N` on an existing entry updates it IN PLACE; a new reply defaults to
    max(seq)+1;
  * `--sent` operator-marks the reply (`sent_status`/`sent_at`) and NEVER writes
    `submission_status`; `--set-submission-status` is the one explicit opt-in that
    DOES; creating a reply requires `--in-response-to` + a body.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import record_reply
from assess.lib.client import AssessError

_NOW = "2026-07-17T12:00:00Z"


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    def __init__(self, finding: dict) -> None:
        self._finding = finding
        self.gets: list[str] = []
        self.patches: list[tuple[str, dict]] = []

    def get(self, endpoint: str):
        self.gets.append(endpoint)
        if endpoint.startswith("findings/"):
            slug = endpoint.split("/", 1)[1]
            if str(self._finding.get("slug") or "") != slug:
                raise AssessError(f"HTTP 404: finding {slug} not found")
            return self._finding
        raise AssessError(f"unexpected GET {endpoint}")

    def patch(self, endpoint: str, payload: dict, **kwargs) -> dict:
        self.patches.append((endpoint, payload))
        return {
            "finding": {
                "slug": endpoint.split("/", 1)[-1],
                **payload,
            }
        }

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _reply(seq, *, body="answered", ask="an ask", platform="hackerone", sent=False, sent_at=None, created="2026-07-16T00:00:00Z"):
    return {
        "seq": seq,
        "platform": platform,
        "in_response_to": ask,
        "reply_to_seq": None,
        "body": body,
        "new_evidence": "",
        "new_evidence_ref": "",
        "sent_status": "sent" if sent else "draft",
        "created_at": created,
        "sent_at": sent_at,
        "author": "report-writer",
    }


def _finding(slug: str = "VA-047", *, replies=None, submission_status: str = "needs_info") -> dict:
    details = {"evidence": "e", "impact": "i"}
    if replies is not None:
        details["replies"] = replies
    return {
        "id": 91,
        "slug": slug,
        "title": "IDOR",
        "severity": "high",
        "row_version": 7,
        "submission_status": submission_status,
        "details": details,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    record_reply.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(record_reply, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(record_reply, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(record_reply, "_utcnow_iso", lambda: _NOW)


def _patched_replies(fake: _FakeClient) -> list[dict]:
    assert len(fake.patches) == 1
    endpoint, payload = fake.patches[0]
    assert endpoint == "findings/VA-047"
    return payload["details"]["replies"]


# -- append preserves prior replies ------------------------------------------

def test_append_preserves_prior_replies(tmp_path, monkeypatch, capsys):
    r1 = _reply(1, body="first", ask="q1", sent=True, sent_at="2026-07-16T01:00:00Z")
    r2 = _reply(2, body="second", ask="q2")
    fake = _FakeClient(_finding(replies=[r1, r2]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-reply", "VA-047", "--seq", "3", "--in-response-to", "q3", "--body", "third answer", "--platform", "hackerone"],
        str(tmp_path),
    )
    record_reply.run(args)
    capsys.readouterr()

    replies = _patched_replies(fake)
    # Full array PATCHed: the two prior replies are preserved byte-for-byte, r3 appended.
    assert [r["seq"] for r in replies] == [1, 2, 3]
    assert replies[0] == r1 and replies[1] == r2
    assert replies[2]["body"] == "third answer"
    assert replies[2]["in_response_to"] == "q3"
    assert replies[2]["created_at"] == _NOW
    assert replies[2]["sent_status"] == "draft" and replies[2]["sent_at"] is None
    assert replies[2]["author"] == "report-writer"


def test_record_reply_rejects_response_without_canonical_finding(
    tmp_path, monkeypatch
):
    fake = _FakeClient(_finding(replies=[]))
    fake.patch = lambda _endpoint, _payload, **_kwargs: {"message": "accepted"}
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-reply", "VA-047",
            "--in-response-to", "triager question",
            "--body", "answer",
        ],
        str(tmp_path),
    )

    with pytest.raises(AssessError, match="record reply") as exc:
        record_reply.run(args)

    assert "do not retry automatically" in str(exc.value)


def test_patch_carries_fetched_row_version(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(replies=[_reply(1)]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-reply", "VA-047", "--in-response-to", "q2", "--body", "second"],
        str(tmp_path),
    )

    record_reply.run(args)
    capsys.readouterr()

    _endpoint, payload = fake.patches[0]
    assert payload["expected_row_version"] == 7


def test_missing_row_version_fails_closed_before_patch(tmp_path, monkeypatch):
    finding = _finding(replies=[_reply(1)])
    finding.pop("row_version")
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-reply", "VA-047", "--in-response-to", "q2", "--body", "second"],
        str(tmp_path),
    )

    with pytest.raises(AssessError, match="positive row_version"):
        record_reply.run(args)
    assert fake.patches == []


def test_auto_seq_appends_at_max_plus_one(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(replies=[_reply(1), _reply(2)]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["record-reply", "VA-047", "--in-response-to", "q3", "--body", "third"], str(tmp_path))
    record_reply.run(args)
    capsys.readouterr()
    replies = _patched_replies(fake)
    assert [r["seq"] for r in replies] == [1, 2, 3]
    # Platform inherited from the latest prior reply when --platform is omitted.
    assert replies[2]["platform"] == "hackerone"


def test_first_reply_seq_is_one(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding())  # no replies key at all
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["record-reply", "VA-047", "--in-response-to", "q1", "--body", "first", "--platform", "direct"], str(tmp_path))
    record_reply.run(args)
    capsys.readouterr()
    replies = _patched_replies(fake)
    assert [r["seq"] for r in replies] == [1]
    assert replies[0]["platform"] == "direct"


# -- in-place update ----------------------------------------------------------

def test_seq_updates_entry_in_place(tmp_path, monkeypatch, capsys):
    r1 = _reply(1, body="first", ask="q1", sent=True, sent_at="2026-07-16T01:00:00Z")
    r2 = _reply(2, body="draft body", ask="q2")
    fake = _FakeClient(_finding(replies=[r1, r2]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["record-reply", "VA-047", "--seq", "2", "--body", "revised body"], str(tmp_path))
    record_reply.run(args)
    capsys.readouterr()

    replies = _patched_replies(fake)
    assert len(replies) == 2
    assert replies[0] == r1  # untouched
    assert replies[1]["seq"] == 2
    assert replies[1]["body"] == "revised body"  # updated in place
    assert replies[1]["created_at"] == "2026-07-16T00:00:00Z"  # original stamp preserved


def test_sent_reply_cannot_be_edited_in_place(tmp_path, monkeypatch):
    sent = _reply(
        1,
        body="bytes actually sent",
        ask="q1",
        sent=True,
        sent_at="2026-07-16T01:00:00Z",
    )
    fake = _FakeClient(_finding(replies=[sent]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-reply", "VA-047", "--seq", "1", "--body", "rewritten"],
        str(tmp_path),
    )

    with pytest.raises(AssessError, match="immutable"):
        record_reply.run(args)

    assert fake.patches == []


def test_correction_appends_new_version_linked_to_sent_reply(
    tmp_path, monkeypatch, capsys
):
    sent = _reply(
        1,
        body="bytes actually sent",
        ask="q1",
        sent=True,
        sent_at="2026-07-16T01:00:00Z",
    )
    fake = _FakeClient(_finding(replies=[sent]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "record-reply",
            "VA-047",
            "--corrects",
            "1",
            "--in-response-to",
            "Correction to reply 1",
            "--body",
            "Corrected bytes",
        ],
        str(tmp_path),
    )

    record_reply.run(args)
    capsys.readouterr()

    replies = _patched_replies(fake)
    assert replies[0] == sent
    assert replies[1]["seq"] == 2
    assert replies[1]["corrects_seq"] == 1
    assert replies[1]["event_type"] == "correction"


# -- sent marking + submission_status coupling --------------------------------

def test_sent_marks_entry_and_never_writes_submission_status(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(replies=[_reply(1, body="answered", ask="q1")]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["record-reply", "VA-047", "--seq", "1", "--sent"], str(tmp_path))
    record_reply.run(args)
    capsys.readouterr()

    endpoint, payload = fake.patches[0]
    replies = payload["details"]["replies"]
    assert replies[0]["sent_status"] == "sent"
    assert replies[0]["sent_at"] == _NOW
    # HARD INVARIANT: --sent never touches submission_status.
    assert "submission_status" not in payload


def test_set_submission_status_opt_in_writes_it(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(replies=[_reply(1, body="answered", ask="q1")]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-reply", "VA-047", "--seq", "1", "--sent", "--set-submission-status", "submitted"],
        str(tmp_path),
    )
    record_reply.run(args)
    capsys.readouterr()

    _endpoint, payload = fake.patches[0]
    assert payload["submission_status"] == "submitted"
    assert payload["details"]["replies"][0]["sent_status"] == "sent"


def test_create_never_writes_submission_status_by_default(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(replies=[_reply(1)]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["record-reply", "VA-047", "--in-response-to", "q2", "--body", "second"], str(tmp_path))
    record_reply.run(args)
    capsys.readouterr()
    _endpoint, payload = fake.patches[0]
    assert "submission_status" not in payload


# -- create requires in_response_to + body ------------------------------------

def test_create_requires_in_response_to(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding())
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["record-reply", "VA-047", "--body", "orphan reply"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        record_reply.run(args)
    assert "--in-response-to" in str(exc.value)
    assert fake.patches == []


def test_create_requires_body(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding())
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["record-reply", "VA-047", "--in-response-to", "q1"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        record_reply.run(args)
    assert "--body" in str(exc.value)
    assert fake.patches == []


# -- reason audit passthrough / body-file -------------------------------------

def test_reason_is_passed_through(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(replies=[_reply(1)]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-reply", "VA-047", "--in-response-to", "q2", "--body", "second", "--reason", "answered triager"],
        str(tmp_path),
    )
    record_reply.run(args)
    capsys.readouterr()
    _endpoint, payload = fake.patches[0]
    assert payload["reason_text"] == "answered triager"


def test_body_file_is_read(tmp_path, monkeypatch, capsys):
    (tmp_path / "reply.txt").write_text("body from a file", encoding="utf-8")
    fake = _FakeClient(_finding())
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["record-reply", "VA-047", "--in-response-to", "q1", "--body-file", "reply.txt"], str(tmp_path))
    record_reply.run(args)
    capsys.readouterr()
    replies = _patched_replies(fake)
    assert replies[0]["body"] == "body from a file"


# -- new-evidence fields are clearable ----------------------------------------

@pytest.mark.parametrize("empty", ["", "   "])
def test_new_evidence_ref_is_cleared_by_an_explicit_empty_value(
    tmp_path, monkeypatch, capsys, empty
):
    """An empty --new-evidence-ref CLEARS the field instead of being a silent no-op.

    The field was truthiness-gated, so once a ref was recorded no value could unset
    it and every later `export reply` re-rendered a pointer to evidence that had been
    superseded. --body one flag above already uses the presence-gated (default=None)
    pattern; this follows it.
    """
    entry = _reply(1, body="answered", ask="q1")
    entry["new_evidence_ref"] = "scans/va-jolt-0725c/old-proof.txt"
    fake = _FakeClient(_finding(replies=[entry]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-reply", "VA-047", "--seq", "1", "--new-evidence-ref", empty],
        str(tmp_path),
    )

    record_reply.run(args)
    capsys.readouterr()

    assert _patched_replies(fake)[0]["new_evidence_ref"] == ""


def test_new_evidence_prose_is_cleared_by_an_explicit_empty_value(
    tmp_path, monkeypatch, capsys
):
    """Same defect, same fix, on the adjacent --new-evidence flag."""
    entry = _reply(1, body="answered", ask="q1")
    entry["new_evidence"] = "superseded proof narrative"
    fake = _FakeClient(_finding(replies=[entry]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-reply", "VA-047", "--seq", "1", "--new-evidence", ""], str(tmp_path)
    )

    record_reply.run(args)
    capsys.readouterr()

    assert _patched_replies(fake)[0]["new_evidence"] == ""


def test_omitting_the_new_evidence_flags_preserves_recorded_values(
    tmp_path, monkeypatch, capsys
):
    """Clearing must require the flag: an unrelated update never blanks the fields."""
    entry = _reply(1, body="answered", ask="q1")
    entry["new_evidence"] = "member B read order 1001"
    entry["new_evidence_ref"] = "scans/va-jolt-0725c/proof.txt"
    fake = _FakeClient(_finding(replies=[entry]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["record-reply", "VA-047", "--seq", "1", "--sent"], str(tmp_path))

    record_reply.run(args)
    capsys.readouterr()

    updated = _patched_replies(fake)[0]
    assert updated["new_evidence"] == "member B read order 1001"
    assert updated["new_evidence_ref"] == "scans/va-jolt-0725c/proof.txt"


def test_new_evidence_ref_is_stored_stripped(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(replies=[_reply(1, body="answered", ask="q1")]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["record-reply", "VA-047", "--seq", "1", "--new-evidence-ref", "  scans/proof.txt  "],
        str(tmp_path),
    )

    record_reply.run(args)
    capsys.readouterr()

    assert _patched_replies(fake)[0]["new_evidence_ref"] == "scans/proof.txt"
