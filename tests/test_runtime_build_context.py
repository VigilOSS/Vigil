from __future__ import annotations

from pathlib import Path

from vigil_cli import runtime
from vigil_cli.docker import DockerResult


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_distributable_compose_file_cannot_build_from_the_install_root() -> None:
    compose = (REPO_ROOT / "agent" / "docker" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    assert "build:" not in compose
    assert "context:" not in compose


def test_runtime_build_stages_only_declared_image_inputs(tmp_path: Path) -> None:
    install_root = tmp_path / "install"
    for source in runtime.runtime_image_inputs(install_root):
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"input:{source.relative_to(install_root)}\n", encoding="utf-8")

    (install_root / ".env").write_text("TOP_LEVEL_SECRET=present\n", encoding="utf-8")
    engagement = install_root / "agent" / "engagements" / "customer"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text('{"secret":"present"}\n', encoding="utf-8")
    database = install_root / "orchestrator" / "backend" / "data"
    database.mkdir(parents=True)
    (database / "orchestrator.sqlite3").write_bytes(b"private-state")

    observed_context: Path | None = None

    def runner(argv: list[str], **_: object) -> DockerResult:
        nonlocal observed_context
        observed_context = Path(argv[-1])
        assert observed_context != install_root
        for source in runtime.runtime_image_inputs(install_root):
            staged = observed_context / source.relative_to(install_root)
            assert staged.read_bytes() == source.read_bytes()
        assert not (observed_context / ".env").exists()
        assert not (observed_context / "agent" / "engagements").exists()
        assert not (observed_context / "orchestrator").exists()
        return DockerResult(0, "", "")

    runtime.build_runtime(
        install_root,
        runner=runner,
        daemon_runner=lambda *_args, **_kwargs: DockerResult(0, "", ""),
    )

    assert observed_context is not None
    assert not observed_context.exists()
