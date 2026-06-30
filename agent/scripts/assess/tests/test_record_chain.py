"""Tests for `vigil assess record-chain`.

These pin I-18: the activity-feed event emitted after a chain is recorded must
not 422 (and silently vanish) when the chain title is long. The backend derives
``chain_key = _slugify(title)`` with no length cap and accepts titles up to 512
chars, so the returned ``chain_key`` can be ~500 chars — far over the event
field caps (``task_name`` max_length=128, ``summary`` max_length=512 at
``orchestrator/backend/app/api/events.py:20``). The chain row itself persists,
but the activity-feed event is dropped. The fix truncates the chain_key used in
the event so the emit succeeds while the full chain_key is still printed.

No FastAPI backend / runtime container: ``load_config`` and the
``AssessmentClient`` are stubbed so the test exercises only the host-side
record-chain path.
"""
from __future__ import annotations

import argparse
import json
import re

from assess.commands import record_chain


class _Cfg:
    """Minimal stand-in for `assess.lib.config.Config`."""

    def __init__(self) -> None:
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


def _slug(value: str) -> str:
    """Mirror the backend `_slugify` (state_manager/_common.py) closely enough
    that a long title yields a long chain_key, exactly as the real backend does."""
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-") or "finding"


# Backend event-field caps (orchestrator/backend/app/api/events.py CreateEventRequest).
_EVENT_FIELD_CAPS = {
    "event_type": 64,
    "phase": 64,
    "task_name": 128,
    "agent_name": 128,
    "summary": 512,
}


class _FakeClient:
    """Stand-in for `AssessmentClient` used as a context manager.

    Records the attack-chain POST and the emitted event, and mimics the backend
    Pydantic validation for the event so a field exceeding its cap is "rejected"
    (the real `post_event` swallows the 422 and returns None, dropping the
    event) — letting the test assert the emit actually succeeds.
    """

    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.events: list[dict] = []
        self.rejected_events: list[tuple[str, dict]] = []

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        if endpoint == "attack-chains":
            chain_key = payload.get("chain_key") or _slug(payload["title"])
            return {"chain": {"chain_key": chain_key}}
        return {}

    def post_event(self, payload: dict) -> dict | None:
        self.events.append(payload)
        for field, cap in _EVENT_FIELD_CAPS.items():
            value = payload.get(field, "")
            if not (1 <= len(value) <= cap):
                self.rejected_events.append((field, payload))
                return None
        return {"id": len(self.events)}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False


def _record_chain_ns(json_file: str, engagement_dir: str) -> argparse.Namespace:
    return argparse.Namespace(
        agent_name="exploit-specialist",
        json_file=json_file,
        engagement_dir=engagement_dir,
    )


def _write_chain(tmp_path, title: str) -> str:
    chain_file = tmp_path / "chain.json"
    chain_file.write_text(
        json.dumps({"title": title, "severity": "high"}), encoding="utf-8"
    )
    return str(chain_file)


def test_record_chain_long_title_event_emit_does_not_422(
    tmp_path, monkeypatch, capsys
):
    # A title at the backend's 512-char cap yields a ~512-char slugified
    # chain_key — far over the event task_name (128) and summary (512) caps.
    title = "Critical multi step exploit " + "a" * 480
    assert len(title) <= 512
    json_file = _write_chain(tmp_path, title)

    fake_client = _FakeClient()
    monkeypatch.setattr(record_chain, "load_config", lambda *a, **k: _Cfg())
    monkeypatch.setattr(record_chain, "AssessmentClient", lambda *a, **k: fake_client)

    record_chain.run(_record_chain_ns(json_file, str(tmp_path)))
    captured = capsys.readouterr()

    # The chain itself was recorded (POSTed), and the FULL chain_key is printed
    # for downstream consumers — truncation is confined to the activity event.
    chain_posts = [p for endpoint, p in fake_client.posts if endpoint == "attack-chains"]
    assert len(chain_posts) == 1
    full_chain_key = _slug(title)
    assert len(full_chain_key) > 128
    assert captured.out.strip() == full_chain_key

    # The activity-feed event was emitted AND accepted (no field over its cap) —
    # i.e. no silent 422 drop. Both task_name and summary are bounded.
    assert fake_client.rejected_events == []
    assert len(fake_client.events) == 1
    event = fake_client.events[0]
    assert len(event["task_name"]) <= 128
    assert event["task_name"] == full_chain_key[:128]
    assert len(event["summary"]) <= 512


def test_record_chain_short_title_event_unchanged(tmp_path, monkeypatch, capsys):
    # Regression guard: a normal short title is emitted verbatim (no truncation
    # side effects on the common path).
    title = "SQLi to RCE via order export"
    json_file = _write_chain(tmp_path, title)

    fake_client = _FakeClient()
    monkeypatch.setattr(record_chain, "load_config", lambda *a, **k: _Cfg())
    monkeypatch.setattr(record_chain, "AssessmentClient", lambda *a, **k: fake_client)

    record_chain.run(_record_chain_ns(json_file, str(tmp_path)))
    captured = capsys.readouterr()

    full_chain_key = _slug(title)
    assert captured.out.strip() == full_chain_key
    assert fake_client.rejected_events == []
    assert len(fake_client.events) == 1
    event = fake_client.events[0]
    assert event["task_name"] == full_chain_key
    assert event["summary"] == f"Attack chain recorded: {full_chain_key}"
