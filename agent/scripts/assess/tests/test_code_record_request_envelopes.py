"""A code-record input file that holds the whole request envelope is unwrapped once.

`code-record threat-model` and `code-record modules` build the request
envelope themselves from their arguments: the file holds only the threat model
object or the module array. A file written as the full envelope would otherwise
be stored one level deep (`threat_model.threat_model`) or refused for its type.
The envelope is unwrapped when every identity key it carries matches the
arguments, the unwrap is named on stderr, and a contradicting identity key is
refused rather than silently overridden.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from _fake_client import StubClient
from assess.commands import code_record_modules, code_record_threat_model

_DIGEST = "a" * 64
_MODEL = {"assets": ["orders"], "trust_boundaries": ["public API"]}


class _RecordingClient(StubClient):
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict]] = []

    def get(self, _endpoint: str):
        return []

    def post(self, endpoint: str, payload: dict):
        self.posts.append((endpoint, payload))
        if endpoint == "code/threat-model":
            return {"id": payload["repo_id"], "active_generation": payload["repo_generation"],
                    "threat_model_generation": payload["repo_generation"],
                    "source_manifest_digest": payload["source_manifest_digest"],
                    "threat_model": payload["threat_model"]}
        return [{"id": index + 1, "repo_id": payload["repo_id"], **module}
                for index, module in enumerate(payload["modules"])]


def _install(monkeypatch, module) -> _RecordingClient:
    client = _RecordingClient()
    monkeypatch.setattr(module, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(module, "load_config", lambda _dir: SimpleNamespace(
        base_url="http://backend", engagement_key="eng", engagement_dir=str(_dir)))
    return client


def _threat_model_args(tmp_path, document) -> SimpleNamespace:
    source = tmp_path / "threat-model.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    return SimpleNamespace(repo_id="7", repo_generation=3, source_manifest_digest=_DIGEST,
                           threat_model_json=str(source), engagement_dir=str(tmp_path))


@pytest.mark.parametrize("envelope", [
    {"threat_model": _MODEL},
    {"repo_id": 7, "repo_generation": 3, "source_manifest_digest": _DIGEST,
     "threat_model": _MODEL},
])
def test_threat_model_envelope_is_unwrapped_when_its_identity_matches(
    monkeypatch, tmp_path, capsys, envelope
):
    client = _install(monkeypatch, code_record_threat_model)

    code_record_threat_model.run(_threat_model_args(tmp_path, envelope))

    [(_endpoint, payload)] = client.posts
    assert payload["threat_model"] == _MODEL
    assert "threat_model" in capsys.readouterr().err


def test_threat_model_envelope_with_a_contradicting_identity_is_refused(
    monkeypatch, tmp_path, capsys
):
    client = _install(monkeypatch, code_record_threat_model)
    envelope = {"repo_id": 7, "repo_generation": 2, "threat_model": _MODEL}

    with pytest.raises(SystemExit):
        code_record_threat_model.run(_threat_model_args(tmp_path, envelope))

    assert client.posts == []
    err = capsys.readouterr().err
    assert "repo_generation" in err and "--repo-generation 3" in err


def test_a_bare_threat_model_is_posted_unchanged(monkeypatch, tmp_path, capsys):
    client = _install(monkeypatch, code_record_threat_model)

    code_record_threat_model.run(_threat_model_args(tmp_path, _MODEL))

    assert client.posts[0][1]["threat_model"] == _MODEL
    assert capsys.readouterr().err == ""


def test_modules_envelope_is_unwrapped_when_its_repo_matches(monkeypatch, tmp_path, capsys):
    client = _install(monkeypatch, code_record_modules)
    source = tmp_path / "modules.json"
    modules = [{"module_key": "auth_login", "name": "Authentication"}]
    source.write_text(json.dumps({"repo_id": 7, "modules": modules}), encoding="utf-8")

    code_record_modules.run(SimpleNamespace(repo_id="7", modules_json=str(source),
                                            engagement_dir=str(tmp_path)))

    assert client.posts[0][1]["modules"] == modules
    assert "modules" in capsys.readouterr().err


def test_modules_envelope_for_another_repo_is_refused(monkeypatch, tmp_path, capsys):
    client = _install(monkeypatch, code_record_modules)
    source = tmp_path / "modules.json"
    source.write_text(json.dumps({"repo_id": 8, "modules": [{"module_key": "auth_login",
                                                             "name": "Authentication"}]}),
                      encoding="utf-8")

    with pytest.raises(SystemExit):
        code_record_modules.run(SimpleNamespace(repo_id="7", modules_json=str(source),
                                                engagement_dir=str(tmp_path)))

    assert client.posts == []
    assert "repo_id" in capsys.readouterr().err
