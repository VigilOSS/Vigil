"""CLI tests for `vigil assess export-reply`.

Drives the real argparse parser (`export_reply.register`) and `run` with a fake
client, pinning the behaviour the plan locks down:

  * a reply is NOT a submission — no Title/VRT/CVSS/Summary; the layout is the
    pasteable body (leading with the new proof), then a SINGLE `---`, then the
    never-paste `## THREAD HISTORY` section (the ask, prior replies, the parent
    finding proof to author NEW evidence from, and FLAGGED hygiene warnings);
  * `--draft` always writes and marks an unauthored body with `[NEEDS: reply body]`;
  * the ask (`in_response_to`) and prior replies render ONLY below the `---` and
    never leak into the pasteable body;
  * next-seq selection: max(seq)+1 for a new reply; `--seq N` re-renders entry N;
  * the `new_evidence_ref` attachment pointer is an INTERNAL reference and renders
    only below the never-paste line (it always carries a dispatch id / finding slug);
  * internal-identifier hygiene FLAGS leaks in the body without mutating it, and a
    FINAL (non-`--draft`) render fails CLOSED while any flag stands;
  * the reply is registered as `kind="reply"` and NO payload carries
    `submission_status` — export-reply is a PURE render that never PATCHes.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import export_reply
from assess.lib.client import AssessError

# An INTERNAL engagement UUID (an id the backend assigns) that must be FLAGGED (not
# rewritten) when it leaks into the pasteable reply body.
_UUID = "550e8400-e29b-41d4-a716-446655440000"


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Routes GETs to canned payloads; records every GET/POST/PATCH endpoint."""

    def __init__(self, finding: dict, *, links=None, command_runs=None) -> None:
        self._finding = finding
        self._links = links or []
        self._command_runs = command_runs or {}
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict]] = []
        self.patches: list[tuple[str, dict]] = []

    def get(self, endpoint: str):
        self.gets.append(endpoint)
        if endpoint.startswith("findings/"):
            slug = endpoint.split("/", 1)[1]
            if str(self._finding.get("slug") or "") != slug:
                raise AssessError(f"HTTP 404: finding {slug} not found")
            return self._finding
        if endpoint == "finding-links":
            return self._links
        if endpoint.startswith("command-runs/"):
            run_id = int(endpoint.split("/", 1)[1])
            if run_id not in self._command_runs:
                raise AssessError(f"HTTP 404: command-run {run_id} not found")
            return self._command_runs[run_id]
        raise AssessError(f"unexpected GET {endpoint}")

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return {"id": len(self.posts), **payload}

    def patch(self, endpoint: str, payload: dict, **kwargs) -> dict:
        self.patches.append((endpoint, payload))
        return {"slug": endpoint.split("/", 1)[-1], **payload}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


# -- fixtures / builders ------------------------------------------------------

def _finding(slug: str = "VA-047", *, evidence_ref: str = "scans/idor.txt", replies=None, details: dict | None = None) -> dict:
    base_details = dict(details or {})
    base_details.setdefault("poc_request", {
        "method": "GET",
        "url": "https://app.example.com/orders/1001",
        "headers": {"Cookie": "session=member"},
        "body": "",
    })
    base_details.setdefault("poc_response", {
        "status": 200, "headers": {"Content-Type": "application/json"},
        "body_excerpt": '{"owner":"someone-else"}',
    })
    if replies is not None:
        base_details["replies"] = replies
    return {
        "id": 91,
        "slug": slug,
        "title": "IDOR exposes other users' orders on /orders/{id}",
        "severity": "high",
        "summary": "An anonymous member can read another member's order by id.",
        "auth_context": "member",
        "canonical_location": "/orders/1001",
        "evidence_ref": evidence_ref,
        "submission_status": "needs_info",
        "details_json": json.dumps(base_details),
    }


def _reply(seq, *, body="", ask="", platform="hackerone", sent=False, sent_at=None):
    return {
        "seq": seq,
        "platform": platform,
        "in_response_to": ask,
        "reply_to_seq": None,
        "body": body,
        "new_evidence": "",
        "new_evidence_ref": "",
        "sent_status": "sent" if sent else "draft",
        "created_at": "2026-07-16T00:00:00Z",
        "sent_at": sent_at,
        "author": "report-writer",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    export_reply.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(export_reply, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(export_reply, "AssessmentClient", lambda *a, **k: fake)


def _reply_path(tmp_path, seq, slug: str = "VA-047"):
    return tmp_path / "submissions" / slug / "replies" / f"reply-{seq}.md"


def _pasteable(body: str) -> str:
    """Everything above the single `---` line (the copy-paste block)."""
    return body.partition("\n---\n")[0]


def _thread_history(body: str) -> str:
    return body.partition("\n---\n")[2]


# -- draft scaffold -----------------------------------------------------------

def test_draft_scaffolds_reply_1_with_needs_marker_and_ask_below_line(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding())  # no replies yet
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["reply", "VA-047", "--in-response-to", "Can you show the raw response?", "--draft"],
        str(tmp_path),
    )
    export_reply.run(args)
    capsys.readouterr()

    body = _reply_path(tmp_path, 1).read_text()
    # Not a submission — none of the submission header fields appear.
    assert "**Title:**" not in body and "**VRT:**" not in body and "**CVSS:**" not in body
    # Unauthored body → NEEDS marker, in the pasteable block above the single `---`.
    assert "[NEEDS: reply body]" in _pasteable(body)
    # The ask renders ONLY in the never-paste THREAD HISTORY, never above the line.
    assert "## THREAD HISTORY" in body
    assert "Can you show the raw response?" in _thread_history(body)
    assert "Can you show the raw response?" not in _pasteable(body)
    # Exactly one never-paste divider.
    assert body.count("\n---\n") == 1
    # Registered as a reply artifact.
    reply_posts = [p for ep, p in fake.posts if ep == "artifacts"]
    assert len(reply_posts) == 1 and reply_posts[0]["kind"] == "reply"
    assert reply_posts[0]["related_finding_slug"] == "VA-047"
    assert reply_posts[0]["path"] == "submissions/VA-047/replies/reply-1.md"


def test_final_refuses_unauthored_reply_and_writes_nothing(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding())
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--in-response-to", "why?"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_reply.run(args)
    assert "reply body" in str(exc.value)
    assert not _reply_path(tmp_path, 1).exists()
    assert fake.posts == []


def test_new_reply_requires_in_response_to(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding())
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--draft"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_reply.run(args)
    assert "--in-response-to" in str(exc.value)


# -- next-seq selection -------------------------------------------------------

def test_next_seq_targets_max_plus_one(tmp_path, monkeypatch, capsys):
    replies = [
        _reply(1, body="first answer", ask="q1", sent=True, sent_at="2026-07-16T01:00:00Z"),
        _reply(2, body="second answer", ask="q2"),
    ]
    fake = _FakeClient(_finding(replies=replies))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--in-response-to", "q3", "--draft"], str(tmp_path))
    export_reply.run(args)
    out = capsys.readouterr().out

    # New reply lands at seq 3, platform inherited from the latest prior reply.
    assert _reply_path(tmp_path, 3).exists()
    assert "(seq 3)" in out
    assert "hackerone" in out


def test_seq_flag_rerenders_existing_entry(tmp_path, monkeypatch, capsys):
    replies = [
        _reply(1, body="first answer", ask="q1", sent=True, sent_at="2026-07-16T01:00:00Z"),
        _reply(2, body="second answer", ask="q2"),
    ]
    fake = _FakeClient(_finding(replies=replies))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--seq", "2"], str(tmp_path))
    export_reply.run(args)
    capsys.readouterr()

    body = _reply_path(tmp_path, 2).read_text()
    # Re-rendered from the stored entry: its authored body is the pasteable block.
    assert "second answer" in _pasteable(body)
    assert "[NEEDS: reply body]" not in body


def test_reply_output_renders_authored_body_verbatim(tmp_path, monkeypatch, capsys):
    """No masking pass runs on the way out — the authored body is what renders.

    Masking is the report-writer's decision, made once while authoring and stored
    in the reply entry. A render that rewrote it could not tell a credential we
    hold from one the target disclosed (which is often the proof), and silently
    corrupted the reply at the last step before sending.
    """
    token = "eyJhbGciOiJIUzI1NiJ9.session-under-test.signature"
    replies = [
        _reply(
            1,
            body=f"Re-run with Authorization: Bearer {token}",
            ask="Please retest",
        ),
    ]
    fake = _FakeClient(_finding(replies=replies))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--seq", "1"], str(tmp_path))

    export_reply.run(args)
    capsys.readouterr()

    rendered = _reply_path(tmp_path, 1).read_text()
    assert f"Bearer {token}" in rendered
    assert "<REDACTED_CREDENTIAL>" not in rendered


def test_new_reply_renders_cli_ask_verbatim(tmp_path, monkeypatch, capsys):
    token = "eyJhbGciOiJIUzI1NiJ9.session-under-test.signature"
    fake = _FakeClient(_finding())
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "reply",
            "VA-047",
            "--in-response-to",
            f"Retest with Bearer {token}",
            "--draft",
        ],
        str(tmp_path),
    )

    export_reply.run(args)
    capsys.readouterr()

    rendered = _reply_path(tmp_path, 1).read_text()
    assert f"Bearer {token}" in rendered
    assert "<REDACTED_CREDENTIAL>" not in rendered


# -- prior replies + ask stay below the never-paste line ----------------------

def test_prior_replies_and_ask_render_below_line_only(tmp_path, monkeypatch, capsys):
    replies = [
        _reply(1, body="Reply-one body text", ask="the first ask", sent=True, sent_at="2026-07-16T01:00:00Z"),
        _reply(2, body="Reply-two body text", ask="the second ask"),
    ]
    fake = _FakeClient(_finding(replies=replies))
    _install(monkeypatch, tmp_path, fake)
    # Render a fresh seq-3 draft so the pasteable block is just the NEEDS marker.
    args = _parse(["reply", "VA-047", "--in-response-to", "the third ask", "--draft"], str(tmp_path))
    export_reply.run(args)
    capsys.readouterr()

    body = _reply_path(tmp_path, 3).read_text()
    paste, hist = _pasteable(body), _thread_history(body)
    # Prior reply bodies + their asks + this reply's ask are all reference-only.
    for token in ("Reply-one body text", "Reply-two body text", "the first ask", "the second ask", "the third ask"):
        assert token in hist
        assert token not in paste
    # The prior-reply section header and the parent-proof block are present.
    assert "**Prior replies (most recent first):**" in hist
    assert "**Parent finding proof to author NEW evidence FROM" in hist
    # Most-recent-first ordering: reply 2 header precedes reply 1 header.
    assert hist.index("Reply 2") < hist.index("Reply 1")


# -- hygiene: FLAG, never mutate ---------------------------------------------

def test_hygiene_flags_body_leaks_without_mutating(tmp_path, monkeypatch, capsys):
    abs_path = f"{tmp_path}/scans/reply-proof.txt"
    leaky_body = (
        f"Confirmed again — see VA-047. Artifact saved to {abs_path} under engagement "
        f"{_UUID}; details in cases.db."
    )
    finding = _finding(replies=[_reply(1, body=leaky_body, ask="show proof")])
    # The UUID must be a KNOWN internal id (engagement_id) for the gate to flag it.
    finding["engagement_id"] = _UUID
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    # --draft is the DIAGNOSTIC render: it always writes and reports. A FINAL render
    # of the same content fails closed (see the gate test below).
    args = _parse(["reply", "VA-047", "--seq", "1", "--draft", "--json"], str(tmp_path))
    export_reply.run(args)
    captured = capsys.readouterr()
    out = json.loads(captured.out)

    body = _reply_path(tmp_path, 1).read_text()
    # FAITHFUL: nothing is rewritten — every leaked token survives verbatim.
    assert "VA-047" in body
    assert abs_path in body
    assert _UUID in body
    assert "cases.db" in body
    # ...but each leak is FLAGGED (advisory), surfaced in the --json summary.
    warnings = "\n".join(out["hygiene_warnings"])
    assert "finding slug" in warnings and "VA-047" in warnings
    assert "engagement path" in warnings
    assert _UUID in warnings
    assert "cases.db" in warnings
    # The warnings surface on stderr too.
    assert "WARN export-reply" in captured.err


# -- pure render: never PATCHes, never writes submission_status ---------------

def test_export_reply_never_patches_or_writes_submission_status(tmp_path, monkeypatch, capsys):
    replies = [_reply(1, body="answered", ask="q1")]
    fake = _FakeClient(_finding(replies=replies))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--seq", "1"], str(tmp_path))
    export_reply.run(args)
    capsys.readouterr()

    # HARD INVARIANT: export-reply is a pure render.
    assert fake.patches == []
    for _ep, payload in fake.posts:
        assert "submission_status" not in payload


# -- overwrite guard ----------------------------------------------------------

def test_overwrite_guard(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(_finding(replies=[_reply(1, body="answered", ask="q1")]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--seq", "1"], str(tmp_path))
    export_reply.run(args)
    capsys.readouterr()

    fake2 = _FakeClient(_finding(replies=[_reply(1, body="answered", ask="q1")]))
    _install(monkeypatch, tmp_path, fake2)
    args = _parse(["reply", "VA-047", "--seq", "1"], str(tmp_path))
    with pytest.raises(AssessError) as exc:
        export_reply.run(args)
    assert "already exists" in str(exc.value)
    assert fake2.posts == []  # nothing re-registered

    fake3 = _FakeClient(_finding(replies=[_reply(1, body="answered", ask="q1")]))
    _install(monkeypatch, tmp_path, fake3)
    args = _parse(["reply", "VA-047", "--seq", "1", "--overwrite"], str(tmp_path))
    export_reply.run(args)
    capsys.readouterr()
    assert any(ep == "artifacts" for ep, _ in fake3.posts)


# -- json shape ---------------------------------------------------------------

def test_json_summary_shape(tmp_path, monkeypatch, capsys):
    replies = [_reply(1, body="first", ask="q1", sent=True, sent_at="2026-07-16T01:00:00Z")]
    fake = _FakeClient(_finding(replies=replies))
    _install(monkeypatch, tmp_path, fake)
    # A fresh seq-2 draft (export-reply has no --body flag — body comes from the entry).
    args = _parse(["reply", "VA-047", "--in-response-to", "q2", "--draft", "--json"], str(tmp_path))
    export_reply.run(args)
    out = json.loads(capsys.readouterr().out)
    assert out["slug"] == "VA-047"
    assert out["platform"] == "hackerone"  # inherited from the latest prior reply
    assert out["seq"] == 2
    assert out["mode"] == "draft"
    assert out["path"] == "submissions/VA-047/replies/reply-2.md"
    assert out["in_response_to"] == "q2"
    assert out["has_body"] is False
    assert out["prior_replies"] == 1
    assert out["artifact_registered"] is True
    assert out["hygiene_warnings"] == []  # clean finding


def test_every_prior_reply_body_is_inlined_and_fenced(tmp_path, monkeypatch, capsys):
    """A long thread carries ALL prior bodies, not just the most recent few.

    Dropping the older bodies withholds the thread's own history from the section
    whose entire job is handing it to the report-writer. Bodies are fenced so a
    multi-line reply — or one whose lines start with `-`/`#`/`>` — cannot break out
    of the list and re-parse as new markdown structure.
    """
    replies = [
        _reply(seq, body=f"Reply-{seq} body text", ask=f"ask number {seq}")
        for seq in range(1, 7)
    ]
    # A multi-line body whose second line would otherwise become a list item.
    replies[0]["body"] = "First line of reply one\n- second line looks like a bullet"
    fake = _FakeClient(_finding(replies=replies))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["reply", "VA-047", "--in-response-to", "the seventh ask", "--draft"],
        str(tmp_path),
    )

    export_reply.run(args)
    capsys.readouterr()

    hist = _thread_history(_reply_path(tmp_path, 7).read_text())
    # Every prior body present, including the oldest of the six.
    assert "First line of reply one" in hist
    assert "- second line looks like a bullet" in hist
    for seq in range(2, 7):
        assert f"Reply-{seq} body text" in hist, f"prior reply {seq} body was dropped"
    # Fenced, so the multi-line body keeps its own structure.
    assert "```\nFirst line of reply one\n- second line looks like a bullet\n```" in hist


def test_thread_history_lists_a_linked_run_with_no_command(tmp_path, monkeypatch, capsys):
    """An explicitly linked run with no command string is NAMED, not hidden.

    The operator linked it deliberately, so silently dropping the row hides a link
    they made and leaves them hunting for a run the reply never mentions. Same
    treatment as ``export submission``'s OPERATOR DETAILS block, so one linked run
    reads the same in both renders.
    """
    links = [{"finding_slug": "VA-047", "target_kind": "command_run", "target_id": 5}]
    command_runs = {5: {"id": 5, "command": "", "intent": "retest as member B", "return_code": 0}}
    fake = _FakeClient(_finding(), links=links, command_runs=command_runs)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["reply", "VA-047", "--in-response-to", "Please retest", "--draft"],
        str(tmp_path),
    )

    export_reply.run(args)
    capsys.readouterr()

    hist = _thread_history(_reply_path(tmp_path, 1).read_text())
    assert "**Linked command runs**" in hist
    assert "retest as member B" in hist
    assert "(no command recorded on this run)" in hist


# -- new-evidence attachment: internal reference, never pasteable --------------

@pytest.mark.parametrize(
    "ref",
    [
        "scans/va-jolt-0725c/reply-proof.txt",   # carries a dispatch id
        "submissions/EX-006/attachments/poc.har",  # carries a finding slug
        "scans/proof.txt",                        # plain — still an internal path
    ],
)
def test_new_evidence_ref_renders_below_the_never_paste_line(
    tmp_path, monkeypatch, capsys, ref
):
    """The attachment pointer is an INTERNAL reference, so it must never be pasteable.

    Every engagement-relative evidence path names our own layout — a dispatch id, a
    finding slug, or at minimum the engagement's directory structure — and none of it
    means anything to a triager, who receives the file the operator attaches in the
    platform form. `export submission` documents exactly this for its (deliberately
    absent) POC line; the reply exporter emitted it ABOVE the separator, so ANY value
    for --new-evidence-ref put an internal identifier into the block the operator is
    told to paste to the program.
    """
    entry = _reply(1, body="Retested as member B; the foreign order still returns 200.", ask="proof?")
    entry["new_evidence"] = "Member B's session read order 1001, owned by member A."
    entry["new_evidence_ref"] = ref
    fake = _FakeClient(_finding(replies=[entry]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--seq", "1"], str(tmp_path))

    export_reply.run(args)
    capsys.readouterr()

    body = _reply_path(tmp_path, 1).read_text()
    assert ref not in _pasteable(body), "internal evidence path leaked into the paste block"
    assert ref in _thread_history(body), "the operator lost the pointer to the attachment"
    # The AUTHORED prose still leads the pasteable block — only the path moved.
    assert "Member B's session read order 1001" in _pasteable(body)


def test_new_evidence_header_is_omitted_when_only_a_ref_is_recorded(
    tmp_path, monkeypatch, capsys
):
    """A ref-only reply must not leave an empty `**New evidence:**` heading to paste."""
    entry = _reply(1, body="Retested; same result.", ask="proof?")
    entry["new_evidence_ref"] = "scans/va-jolt-0725c/reply-proof.txt"
    fake = _FakeClient(_finding(replies=[entry]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--seq", "1"], str(tmp_path))

    export_reply.run(args)
    capsys.readouterr()

    assert "**New evidence:**" not in _pasteable(_reply_path(tmp_path, 1).read_text())


# -- fail-closed hygiene gate (parity with export submission) ------------------

def test_final_reply_refuses_while_hygiene_warnings_remain(tmp_path, monkeypatch, capsys):
    """A FINAL reply is sent verbatim, so a flagged leak must fail closed.

    `export submission` already refuses a final render while any hygiene warning
    stands. export-reply only printed WARN to stderr, making it the softer of two
    doors onto the same external send.
    """
    finding = _finding(
        replies=[_reply(1, body="Confirmed again — see VA-047 for the full write-up.", ask="proof?")]
    )
    fake = _FakeClient(finding)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--seq", "1"], str(tmp_path))

    with pytest.raises(AssessError) as exc:
        export_reply.run(args)

    assert "hygiene warnings remain" in str(exc.value)
    assert "finding slug 'VA-047'" in str(exc.value)
    # Nothing written, nothing registered: a blocked render leaves no partial output.
    assert not _reply_path(tmp_path, 1).exists()
    assert fake.posts == []


def test_final_reply_renders_when_the_body_is_clean(tmp_path, monkeypatch, capsys):
    """The gate is a leak check, not a tax on every final render."""
    fake = _FakeClient(_finding(replies=[_reply(1, body="Retested; still reproduces.", ask="proof?")]))
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["reply", "VA-047", "--seq", "1", "--json"], str(tmp_path))

    export_reply.run(args)
    out = json.loads(capsys.readouterr().out)

    assert out["mode"] == "final"
    assert out["hygiene_warnings"] == []
    assert _reply_path(tmp_path, 1).exists()
