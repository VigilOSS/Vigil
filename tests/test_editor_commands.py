from __future__ import annotations

from pathlib import Path

import pytest

from vigil_cli import auth, config


def test_config_edit_splits_editor_command_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "config.json"
    calls: list[list[str]] = []
    monkeypatch.setattr(config, "config_path", lambda: target)
    monkeypatch.setenv("VISUAL", "code --wait")
    monkeypatch.setattr(config.subprocess, "call", lambda argv: calls.append(argv) or 0)

    with pytest.raises(SystemExit) as exc:
        config.edit_config()

    assert exc.value.code == 0
    assert calls == [["code", "--wait", str(target)]]


def test_auth_edit_splits_editor_command_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    writes: list[tuple[str, dict[str, object]]] = []

    def fake_api(
        _engagement_dir: Path,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        if method == "GET":
            assert path == "/resolve"
            return {
                "identity_name": "operator",
                "material": {"headers": {"Authorization": "Bearer old"}},
            }
        writes.append((path, payload or {}))
        return {}

    def edit(argv: list[str]) -> int:
        calls.append(argv)
        edit_path = Path(argv[-1])
        initial = edit_path.read_text(encoding="utf-8")
        assert '"Authorization": "Bearer old"' in initial
        edit_path.write_text(
            '{"headers": {"Authorization": "Bearer new"}}\n',
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(auth, "_api", fake_api)
    monkeypatch.setenv("VISUAL", "code --wait")
    monkeypatch.setattr(auth.subprocess, "call", edit)

    auth.edit_auth(tmp_path)

    assert calls[0][:2] == ["code", "--wait"]
    temp_path = Path(calls[0][-1])
    assert temp_path.suffix == ".json"
    assert not temp_path.exists()
    assert len(writes) == 1
    path, payload = writes[0]
    assert path == "/operator"
    assert payload["headers"] == {"Authorization": "Bearer new"}
    assert payload["make_active"] is True
    assert payload["updated_at"]


def test_config_edit_reports_editor_launch_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "config_path", lambda: tmp_path / "config.json")
    monkeypatch.setenv("VISUAL", "missing-editor --wait")

    def missing(_argv: list[str]) -> int:
        raise FileNotFoundError("missing-editor")

    monkeypatch.setattr(config.subprocess, "call", missing)

    with pytest.raises(SystemExit, match="could not launch editor 'missing-editor'"):
        config.edit_config()
