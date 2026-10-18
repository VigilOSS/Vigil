from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]


def _workflow() -> dict:
    return yaml.load(
        (REPO_ROOT / ".github/workflows/runtime-release.yml").read_text(),
        Loader=yaml.BaseLoader,
    )


def _release_module() -> ModuleType:
    path = REPO_ROOT / "tools/runtime_release.py"
    spec = importlib.util.spec_from_file_location("runtime_release", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_workflow_builds_each_platform_on_its_native_runner() -> None:
    jobs = _workflow()["jobs"]
    build = jobs["build-platform"]

    assert build["needs"] == "preflight"
    assert build["runs-on"] == "${{ matrix.runner }}"
    assert build["strategy"]["matrix"]["include"] == [
        {
            "platform": "linux/amd64",
            "runner": "ubuntu-24.04",
            "suffix": "amd64",
        },
        {
            "platform": "linux/arm64",
            "runner": "ubuntu-24.04-arm",
            "suffix": "arm64",
        },
    ]
    assert "setup-qemu-action" not in json.dumps(build)
    assert "tools/runtime_release.py build-platform" in json.dumps(build)

    release = jobs["release"]
    assert release["needs"] == ["preflight", "build-platform"]
    assert "tools/runtime_release.py publish-index" in json.dumps(release)


def test_platform_build_command_pushes_attested_repository_linked_image(tmp_path: Path) -> None:
    module = _release_module()
    context = tmp_path / "context"
    dockerfile = context / "agent/docker/runtime-full/Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM scratch\n")

    command = module.platform_build_command(
        context=context,
        release_tag="v2.0.0",
        platform="linux/arm64",
        suffix="arm64",
        inputs_digest="a" * 64,
        revision="b" * 40,
    )

    assert command[:3] == ["docker", "buildx", "build"]
    assert ["--platform", "linux/arm64"] == command[
        command.index("--platform") : command.index("--platform") + 2
    ]
    assert "--push" in command
    assert "--provenance=mode=max" in command
    assert "--sbom=true" in command
    assert "ghcr.io/vigiloss/vigil-runtime:v2.0.0-arm64" in command
    labels = {
        command[index + 1]
        for index, value in enumerate(command)
        if value == "--label"
    }
    assert labels == {
        "com.vigil.runtime-inputs-sha256=" + "a" * 64,
        "org.opencontainers.image.source=https://github.com/VigilOSS/Vigil",
        "org.opencontainers.image.revision=" + "b" * 40,
        "org.opencontainers.image.version=v2.0.0",
        "org.opencontainers.image.licenses=Apache-2.0",
    }


def test_platform_build_command_rejects_release_tag_that_docker_cannot_publish(
    tmp_path: Path,
) -> None:
    module = _release_module()

    with pytest.raises(SystemExit, match="Invalid release tag"):
        module.platform_build_command(
            context=tmp_path,
            release_tag="v2.0.0+local",
            platform="linux/amd64",
            suffix="amd64",
            inputs_digest="a" * 64,
            revision="b" * 40,
        )


def test_publish_index_writes_only_a_complete_immutable_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _release_module()
    pin = tmp_path / "agent/docker/runtime-full/release-image.json"
    pin.parent.mkdir(parents=True)
    pin.write_text('{"schema_version": 1}\n')
    monkeypatch.setattr(module, "PIN_PATH", pin.relative_to(tmp_path))
    monkeypatch.setattr(module, "runtime_inputs_digest", lambda _root: "c" * 64)
    monkeypatch.setattr(module, "release_image_pin", lambda root: json.loads((root / module.PIN_PATH).read_text()))
    calls: list[list[str]] = []

    class Result:
        stdout = json.dumps(
            {
                "digest": "sha256:" + "d" * 64,
                "manifests": [
                    {"platform": {"os": "linux", "architecture": "amd64"}},
                    {"platform": {"os": "linux", "architecture": "arm64"}},
                    {"platform": {"os": "unknown", "architecture": "unknown"}},
                ],
            }
        )

    def run(command: list[str], **_kwargs):
        calls.append(command)
        return Result()

    reference = module.publish_index(tmp_path, release_tag="v2.0.0", revision="e" * 40, runner=run)

    assert reference == "ghcr.io/vigiloss/vigil-runtime@sha256:" + "d" * 64
    assert calls[0][:4] == ["docker", "buildx", "imagetools", "create"]
    assert calls[1][-2:] == ["--format", "{{json .Manifest}}"]
    assert json.loads(pin.read_text()) == {
        "schema_version": 1,
        "reference": reference,
        "inputs_digest": "c" * 64,
        "platforms": ["linux/amd64", "linux/arm64"],
    }


def test_publish_index_refuses_an_incomplete_platform_set_before_writing_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _release_module()
    pin = tmp_path / "agent/docker/runtime-full/release-image.json"
    pin.parent.mkdir(parents=True)
    pin.write_text('{"schema_version": 1}\n')
    monkeypatch.setattr(module, "PIN_PATH", pin.relative_to(tmp_path))
    monkeypatch.setattr(module, "runtime_inputs_digest", lambda _root: "c" * 64)

    class Result:
        stdout = json.dumps(
            {
                "digest": "sha256:" + "d" * 64,
                "manifests": [
                    {"platform": {"os": "linux", "architecture": "amd64"}},
                ],
            }
        )

    with pytest.raises(SystemExit, match="missing required platforms"):
        module.publish_index(
            tmp_path,
            release_tag="v2.0.0",
            revision="e" * 40,
            runner=lambda *_args, **_kwargs: Result(),
        )

    assert json.loads(pin.read_text()) == {"schema_version": 1}
