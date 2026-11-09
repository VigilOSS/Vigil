"""The finding total a dispatch dedupes against comes from the ledger, not typing.

Three consecutive waves shipped a brief quoting a finding total that was already
wrong when the packet was rendered (269 recorded, 265 stated). Specialists are
told to dedupe against "the N existing findings", so a stale N quietly
understates what they must check. The packet renderer therefore interpolates the
live total, and an authored count that disagrees with it is called out at the
keyboard.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from types import SimpleNamespace

from _fake_client import StubClient

from assess.commands import agent, resume_brief


class _LedgerClient(StubClient):
    """Only the finding ledger; every other read is an unexpected call."""

    def __init__(self, total: int) -> None:
        self.rows = [{"slug": f"VA-{index:03d}"} for index in range(total)]
        self.endpoints: list[str] = []

    def get(self, endpoint):
        self.endpoints.append(endpoint)
        if endpoint == "findings/count":
            return {"total": len(self.rows)}
        raise AssertionError(f"unexpected endpoint: {endpoint}")


def _context(**overrides):
    fields = {field: "none" for field in agent._PROMPT_CONTEXT_FIELDS}
    fields["authorized_phase"] = "hunt"
    fields.update(overrides)
    return fields


def _render(tmp_path: Path, client, **context):
    args = argparse.Namespace(prompt_context=_context(**context), prompt_context_json=None,
                              no_target_traffic=True, rate_budget=None)
    return agent._dispatch_prompt(
        {"agent_id": "hunter-1", "agent_role": "code-vuln-hunter", "task": "review auth"},
        engagement_dir=tmp_path, agent_root=tmp_path, source_identity=[],
        args=args, client=client, quote_finding_ledger=True,
    )


def test_packet_quotes_the_live_finding_total_from_the_backend(tmp_path: Path):
    client = _LedgerClient(269)
    prompt = _render(tmp_path, client)
    assert "269" in prompt
    assert client.endpoints == ["findings/count"]
    # The live count is backend-derived state, so it belongs inside the
    # persisted prior-state block with the rest of it.
    assert prompt.index("--- BEGIN PERSISTED PRIOR-STATE DATA ---") < prompt.index("269")
    assert prompt.index("269") < prompt.index("--- END PERSISTED PRIOR-STATE DATA ---")


def test_a_stale_authored_finding_count_is_flagged_against_the_live_total(capsys):
    agent._packet_advisories(
        {"agent_id": "hunter-1", "agent_role": "code-vuln-hunter", "task": "review auth"},
        _context(prior_state="Dedupe against the 265 existing findings before recording."),
        "rendered",
        finding_total=269,
    )
    err = capsys.readouterr().err
    assert "265" in err
    assert "269" in err


def test_a_current_authored_finding_count_is_not_flagged(capsys):
    agent._packet_advisories(
        {"agent_id": "hunter-1", "agent_role": "code-vuln-hunter", "task": "review auth"},
        _context(prior_state="Dedupe against the 269 existing findings before recording."),
        "rendered",
        finding_total=269,
    )
    assert "existing findings" not in capsys.readouterr().err


def test_resume_brief_states_the_live_finding_total(capsys):
    brief = {
        "finding_counts": {
            "workflow": {"active": 200, "draft": 69},
            "verification_status": {"unreviewed": 269},
            "severity": {"medium": 269},
            "source": {"code-vuln-hunter": 269},
        },
    }
    lines: list[str] = []
    resume_brief._render_finding_counts(lines, brief)
    rendered = "\n".join(lines)
    assert "- total: 269" in rendered
    assert "active=200, draft=69" in rendered


def test_the_dispatch_never_fails_when_the_ledger_cannot_be_counted(tmp_path, capsys):
    class _Broken:
        def get(self, _endpoint):
            raise RuntimeError("ledger unavailable")

    prompt = _render(tmp_path, _Broken())
    assert "## Runtime Identity" in prompt
    assert "finding ledger" in capsys.readouterr().err.lower()


def test_the_ledger_count_covers_more_than_one_listing_page(tmp_path):
    client = _LedgerClient(5200)
    prompt = _render(tmp_path, client)
    assert "5200" in prompt
    assert client.endpoints == ["findings/count"]


def test_the_rendered_count_is_the_one_the_advisory_compares_against(
    monkeypatch, tmp_path, capsys
):
    """One read, one number: the packet and the warning cannot disagree."""

    class _Recording(_LedgerClient):
        def __init__(self) -> None:
            super().__init__(269)
            self.writes: list[dict] = []

        def record_dispatch(self, payload):
            self.writes.append(payload)
            packet = dict(payload["prompt_packet"])
            packet["sha256"] = hashlib.sha256(packet["rendered_prompt"].encode()).hexdigest()
            return {"id": 3, **payload, "status": "in-progress",
                    "prompt_packet": packet, "launch_required": True}

    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    args = parser.parse_args(["agent", "start", "--agent-id", "acme-lane", "--role",
                              "code-vuln-hunter", "--task", "Review the batch",
                              "--no-target-traffic"])
    args.engagement_dir = str(tmp_path)
    args.allow_duplicate = True
    args.prompt_context = _context(
        prior_state="Dedupe against the 265 existing findings before recording.",
        queue_item_ids=[44],
    )
    recording = _Recording()
    cfg = SimpleNamespace(engagement_dir=str(tmp_path), agent_root=str(tmp_path))
    monkeypatch.setattr(agent.dispatch, "_build_register_payload", lambda _: {
        "agent_id": "acme-lane", "agent_role": "code-vuln-hunter",
        "task": args.task, "assessment_mode": "code",
    })
    monkeypatch.setattr(agent.dispatch, "_client_for", lambda _: (recording, cfg))
    monkeypatch.setattr(agent, "_attach_dispatch_provenance", lambda *_: [])
    monkeypatch.setattr(agent, "_code_source_identity_lines",
                        lambda *_, **__: ["repo_id: 7", "repo_generation: 3"])
    monkeypatch.setattr(agent, "_require_proof_variant_parent_set", lambda *_: None)
    monkeypatch.setattr(agent, "_backend_queue_manifest", lambda *_, **__: ["Queue manifest"])

    agent._start(args)

    err = capsys.readouterr().err
    assert "265" in err and "269" in err
    assert "269" in recording.writes[0]["prompt_packet"]["rendered_prompt"]
