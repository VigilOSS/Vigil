"""`artifact register` compares canonical identity, not path spelling.

The backend canonicalises every submitted path to one engagement-relative POSIX
string. The CLI used to compare that answer against the caller's original
spelling, so `./tools/a.md` or an absolute alias of the same file was reported as
a failed write *after* the row had already been committed — the one outcome the
write-integrity rules exist to prevent, because the reasonable next move looks
like a retry. Canonicalise once, before the POST, and compare canonical to
canonical; when the response is still unusable, say whether the write landed.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import artifact
from assess.lib.client import AssessError


class _RecordingClient:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.posts: list[tuple[str, dict]] = []

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return self.response

    def close(self) -> None:
        return None


def _install(monkeypatch, engagement_dir: Path, response: dict) -> _RecordingClient:
    client = _RecordingClient(response)
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


def _register_args(engagement_dir: Path, path: str) -> SimpleNamespace:
    return SimpleNamespace(
        engagement_dir=str(engagement_dir),
        path=path,
        kind="note",
        media_type="text/markdown",
        agent_id="",
        agent_role="",
        command_run_id=None,
        finding="",
        as_json=True,
    )


@pytest.fixture()
def engagement(tmp_path: Path) -> Path:
    root = tmp_path / "engagements" / "e1"
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "a.md").write_text("evidence\n", encoding="utf-8")
    return root


@pytest.mark.parametrize(
    "spelling",
    ["tools/a.md", "./tools/a.md", "tools/./a.md", "<absolute>"],
)
def test_every_spelling_of_one_file_posts_and_accepts_the_canonical_path(
    monkeypatch, capsys, engagement: Path, spelling: str
) -> None:
    path = str(engagement / "tools" / "a.md") if spelling == "<absolute>" else spelling
    client = _install(
        monkeypatch,
        engagement,
        {"id": 7, "relative_path": "tools/a.md", "present": True},
    )

    artifact._run_register(_register_args(engagement, path))

    (_endpoint, payload) = client.posts[0]
    assert payload["path"] == "tools/a.md"
    assert json.loads(capsys.readouterr().out)["id"] == 7


def test_a_response_for_another_file_is_still_rejected(
    monkeypatch, engagement: Path
) -> None:
    _install(
        monkeypatch,
        engagement,
        {"id": 7, "relative_path": "notes/other.md", "present": True},
    )

    with pytest.raises(AssessError) as exc:
        artifact._run_register(_register_args(engagement, "./tools/a.md"))

    assert "do not retry automatically" in str(exc.value)


def test_an_unusable_id_on_our_own_path_reports_a_committed_write(
    monkeypatch, engagement: Path
) -> None:
    # The backend answered about the artifact we submitted, so the row exists;
    # the response simply cannot name it. "May have committed" understates that,
    # and understating it is what invites the duplicate retry.
    _install(
        monkeypatch,
        engagement,
        {"id": None, "relative_path": "tools/a.md", "present": True},
    )

    with pytest.raises(AssessError) as exc:
        artifact._run_register(_register_args(engagement, "tools/a.md"))

    message = str(exc.value)
    assert "committed but response invalid" in message
    assert "do not retry automatically" in message


def test_a_path_outside_the_engagement_never_reaches_the_backend(
    monkeypatch, engagement: Path, tmp_path: Path
) -> None:
    client = _install(
        monkeypatch, engagement, {"id": 7, "relative_path": "tools/a.md"}
    )

    with pytest.raises(SystemExit):
        artifact._run_register(
            _register_args(engagement, str(tmp_path / "outside.md"))
        )

    assert client.posts == []


def test_mark_scratch_by_path_uses_the_same_canonical_identity(
    monkeypatch, capsys, engagement: Path
) -> None:
    client = _install(
        monkeypatch,
        engagement,
        {"id": 7, "relative_path": "tools/a.md", "scratch": True},
    )

    artifact._run_scratch(
        SimpleNamespace(
            engagement_dir=str(engagement),
            target="./tools/a.md",
            under="",
            scratch=True,
            as_json=True,
        )
    )

    (_endpoint, payload) = client.posts[0]
    assert payload["path"] == "tools/a.md"
    assert json.loads(capsys.readouterr().out)["id"] == 7


def test_a_path_that_escapes_the_engagement_is_rejected_before_any_write(tmp_path):
    """Containment is checked after normalisation, not on the spelling.

    `../` and a symlink both name a file outside the engagement while looking
    engagement-relative, and the CLI must refuse them before a POST rather than
    spend a round trip discovering it. (The backend re-opens each component with
    O_NOFOLLOW regardless — this is early rejection, never the authorization.)
    """
    from assess.lib.client import AssessError, canonical_artifact_path

    engagement = tmp_path / "eng"
    (engagement / "tools").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.md").write_text("not yours\n", encoding="utf-8")
    (engagement / "tools" / "link.md").symlink_to(outside / "secret.md")

    for spelling in (
        "../outside/secret.md",
        "tools/../../outside/secret.md",
        str(outside / "secret.md"),
        "tools/link.md",
    ):
        with pytest.raises(AssessError, match="inside the engagement directory"):
            canonical_artifact_path(str(engagement), spelling, operation="register artifact")


def test_a_path_inside_the_engagement_survives_normalisation(tmp_path):
    from assess.lib.client import canonical_artifact_path

    engagement = tmp_path / "eng"
    (engagement / "tools").mkdir(parents=True)
    for spelling in ("tools/a.md", "./tools/a.md", "tools/./a.md", "tools/b/../a.md"):
        assert (
            canonical_artifact_path(str(engagement), spelling, operation="register artifact")
            == "tools/a.md"
        )
