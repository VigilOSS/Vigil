"""Observable-behaviour pins for the S21 simplification packet.

Each test here snapshots the exact strings a consolidation is about to move —
consumer rows, rendered CLI blocks, argparse option surfaces, scope/manifest
payloads and the build backend's hook table. They are deliberately literal:
their only job is to fail the moment a mechanical rewrite changes a byte that
an operator or a front end can see.
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from vigil_cli import restart_manifest
from vigil_cli.docker import DockerResult


def _row(state: restart_manifest.ConsumerState) -> tuple[str, str, str, str, str]:
    return (state.key, state.label, state.state, state.remedy, state.detail)


def _runner(
    *,
    images: dict[str, str] | None = None,
    containers: dict[str, str] | None = None,
):
    """Answers only the metadata queries the container rows make."""
    images = images or {}
    containers = containers or {}

    def run(argv: list[str], **_: object) -> DockerResult:
        if argv[:2] == ["docker", "info"]:
            return DockerResult(0, "", "")
        if argv[:3] == ["docker", "image", "inspect"]:
            image = argv[-1]
            if image not in images:
                return DockerResult(1, "", "No such image")
            if "{{.Id}}" in argv:
                return DockerResult(0, f"{images[image]}\n", "")
            return DockerResult(0, f"{images[image]}\n", "")
        if argv[:2] == ["docker", "inspect"] and "--type" in argv:
            return DockerResult(0 if argv[-1] in images else 1, "", "")
        if argv[:2] == ["docker", "inspect"]:
            name = argv[-1]
            if name not in containers:
                return DockerResult(1, "", "No such object")
            return DockerResult(0, f"{containers[name]}\n", "")
        if argv[:2] == ["docker", "ps"]:
            return DockerResult(0, "\n".join(containers) + "\n", "")
        if argv[:3] == ["docker", "images", "-q"]:
            return DockerResult(0, "" if argv[-1] not in images else "abc123\n", "")
        return DockerResult(1, "", "unsupported")

    return run


def _unused_runner(argv: list[str], **_: object) -> DockerResult:
    raise AssertionError(f"docker must not be queried: {argv}")


# --- CLI-1: every consumer row's (key, label, state, remedy, detail) ----------


def test_pin_consumer_labels_are_one_per_key(tmp_path: Path) -> None:
    """Each key's label, exactly as every branch of that key spells it today."""
    assert restart_manifest.CONSUMER_KEYS == (
        "cli",
        "backend",
        "frontend",
        "report",
        "runtime-image",
        "proxy-image",
        "runtime-container",
        "proxy-container",
        "client-sessions",
        "agent-tree",
    )


def test_pin_docker_unavailable_rows(tmp_path: Path) -> None:
    assert _row(
        restart_manifest._runtime_image_state(tmp_path, runner=_unused_runner, docker_ok=False)
    ) == (
        "runtime-image",
        "Kali runtime image",
        "unknown",
        "",
        "the Docker daemon is not responding",
    )
    assert _row(
        restart_manifest._proxy_image_state(tmp_path, runner=_unused_runner, docker_ok=False)
    ) == (
        "proxy-image",
        "mitmproxy image",
        "unknown",
        "",
        "the Docker daemon is not responding",
    )
    assert _row(
        restart_manifest._runtime_container_state(runner=_unused_runner, docker_ok=False)
    ) == (
        "runtime-container",
        "Kali runtime container",
        "unknown",
        "",
        "the Docker daemon is not responding",
    )
    assert _row(
        restart_manifest._proxy_container_state(runner=_unused_runner, docker_ok=False)
    ) == (
        "proxy-container",
        "mitmproxy container",
        "unknown",
        "",
        "the Docker daemon is not responding",
    )


@pytest.mark.parametrize(
    ("build_state", "expected"),
    [
        ("current", ("frontend", "orchestrator frontend", "current", "", "")),
        ("missing", ("frontend", "orchestrator frontend", "missing", "", "")),
        (
            "stale",
            ("frontend", "orchestrator frontend", "stale", "vigil orchestrator build", ""),
        ),
        (
            "unknown",
            (
                "frontend",
                "orchestrator frontend",
                "unknown",
                "vigil orchestrator build",
                "built before input stamping",
            ),
        ),
    ],
)
def test_pin_frontend_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, build_state: str, expected: tuple[str, ...]
) -> None:
    monkeypatch.setattr(restart_manifest, "frontend_build_state", lambda _: build_state)
    assert _row(restart_manifest._frontend_state(tmp_path)) == expected


@pytest.mark.parametrize(
    ("build_state", "expected"),
    [
        ("current", ("report", "report template", "current", "", "")),
        ("missing", ("report", "report template", "missing", "", "")),
        ("stale", ("report", "report template", "stale", "vigil orchestrator build", "")),
        (
            "unknown",
            (
                "report",
                "report template",
                "unknown",
                "vigil orchestrator build",
                "built before input stamping",
            ),
        ),
        (
            "not-packaged",
            ("report", "report template", "missing", "", "this install has no report package"),
        ),
    ],
)
def test_pin_report_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, build_state: str, expected: tuple[str, ...]
) -> None:
    monkeypatch.setattr(restart_manifest, "report_build_state", lambda _: build_state)
    assert _row(restart_manifest._report_state(tmp_path)) == expected


def test_pin_runtime_container_rows() -> None:
    stopped = restart_manifest._runtime_container_state(
        runner=_runner(images={"vigil:latest": "sha256:a"}, containers={}), docker_ok=True
    )
    assert _row(stopped) == ("runtime-container", "Kali runtime container", "not-running", "", "")


def test_pin_proxy_container_rows() -> None:
    stopped = restart_manifest._proxy_container_state(
        runner=_runner(images={"vigil-proxy:latest": "sha256:a"}, containers={}), docker_ok=True
    )
    assert _row(stopped) == ("proxy-container", "mitmproxy container", "not-running", "", "")


@pytest.mark.parametrize(
    ("staleness", "expected"),
    [
        ({"state": "current"}, ("agent-tree", "working root", "current", "", "")),
        (
            {"state": "stale"},
            (
                "agent-tree",
                "working root",
                "stale",
                "vigil install",
                "installed content differs from the live source",
            ),
        ),
        (
            {"state": "no-stamp"},
            (
                "agent-tree",
                "working root",
                "unknown",
                "vigil install",
                "this install predates content stamping",
            ),
        ),
        (
            {"state": "whatever"},
            (
                "agent-tree",
                "working root",
                "unknown",
                "",
                "no local source checkout to compare against",
            ),
        ),
    ],
)
def test_pin_agent_tree_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, staleness: dict, expected: tuple[str, ...]
) -> None:
    from vigil_cli import status

    monkeypatch.setattr(status, "install_staleness", lambda *a, **k: staleness)
    assert _row(restart_manifest._agent_tree_state(tmp_path, source_root=None)) == expected


def test_pin_agent_tree_remedy_names_the_explicit_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from vigil_cli import status

    monkeypatch.setattr(status, "install_staleness", lambda *a, **k: {"state": "stale"})
    source = tmp_path / "a dir"
    row = restart_manifest._agent_tree_state(tmp_path, source_root=source)
    assert row.remedy == f"vigil --source '{source}' install"


def test_pin_cli_unknown_rows(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(restart_manifest, "_running_cli_package", lambda: None)
    assert _row(restart_manifest.cli_state(source_root=None)) == (
        "cli",
        "vigil CLI binary",
        "unknown",
        "",
        "the running CLI package has no resolvable location",
    )
    running = tmp_path / "pkg"
    running.mkdir()
    monkeypatch.setattr(restart_manifest, "_running_cli_package", lambda: running)
    monkeypatch.setattr(restart_manifest, "loaded_module_files", lambda **_: set())
    assert _row(restart_manifest.cli_state(source_root=None)) == (
        "cli",
        "vigil CLI binary",
        "unknown",
        "",
        "no local source checkout to compare against",
    )
    empty = tmp_path / "src-root"
    empty.mkdir()
    assert _row(restart_manifest.cli_state(source_root=empty)) == (
        "cli",
        "vigil CLI binary",
        "unknown",
        "",
        f"no CLI package at {empty / 'src' / 'vigil_cli'}",
    )


def test_pin_cli_current_from_the_source_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_root = tmp_path / "checkout"
    package = source_root / "src" / "vigil_cli"
    package.mkdir(parents=True)
    monkeypatch.setattr(restart_manifest, "_running_cli_package", lambda: package.resolve())
    monkeypatch.setattr(restart_manifest, "loaded_module_files", lambda **_: set())
    assert _row(restart_manifest.cli_state(source_root=source_root)) == (
        "cli",
        "vigil CLI binary",
        "current",
        "",
        f"running from the source tree ({package.resolve()})",
    )


def test_pin_cli_stray_module_row(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    running = tmp_path / "pkg"
    running.mkdir()
    monkeypatch.setattr(restart_manifest, "_running_cli_package", lambda: running)
    monkeypatch.setattr(
        restart_manifest, "loaded_module_files", lambda **_: {Path("/elsewhere/mod.py")}
    )
    assert _row(restart_manifest.cli_state(source_root=None)) == (
        "cli",
        "vigil CLI binary",
        "unknown",
        "",
        f"1 vigil_cli module(s) loaded from outside {running}",
    )


def test_pin_backend_unknown_and_stale_rows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from vigil_cli import application

    monkeypatch.setattr(application, "application_root_for_workspace", lambda _: tmp_path)
    assert _row(restart_manifest.backend_state_from_readiness(tmp_path, {"reachable": True})) == (
        "backend",
        "orchestrator backend",
        "unknown",
        "",
        "/readyz did not report a usable backend_runtime block",
    )
    assert _row(
        restart_manifest.backend_state_from_readiness(
            tmp_path, {"reachable": True, "backend_runtime": {}}
        )
    ) == (
        "backend",
        "orchestrator backend",
        "unknown",
        "",
        "/readyz did not report which install root it serves",
    )
    assert _row(
        restart_manifest.backend_state_from_readiness(
            tmp_path, {"reachable": True, "backend_runtime": {"install_root": "/nope"}}
        )
    ) == (
        "backend",
        "orchestrator backend",
        "unknown",
        "",
        "the backend on this port serves a different install root (/nope)",
    )
    assert _row(
        restart_manifest.backend_state_from_readiness(
            tmp_path, {"reachable": True, "backend_runtime": {"install_root": str(tmp_path)}}
        )
    ) == (
        "backend",
        "orchestrator backend",
        "stale",
        "vigil orchestrator restart",
        "running a legacy backend without a pinned application release",
    )
    other = tmp_path / "other"
    other.mkdir()
    assert _row(
        restart_manifest.backend_state_from_readiness(
            tmp_path,
            {
                "reachable": True,
                "backend_runtime": {
                    "install_root": str(tmp_path),
                    "application_root": str(other),
                },
            },
        )
    ) == (
        "backend",
        "orchestrator backend",
        "stale",
        "vigil orchestrator restart",
        f"running retained application release {other}; current release is {tmp_path}",
    )
    assert _row(
        restart_manifest.backend_state_from_readiness(
            tmp_path,
            {
                "reachable": True,
                "backend_runtime": {
                    "install_root": str(tmp_path),
                    "application_root": str(tmp_path),
                    "restart_required": False,
                },
            },
        )
    ) == ("backend", "orchestrator backend", "current", "", "")
    assert _row(
        restart_manifest.backend_state_from_readiness(
            tmp_path,
            {
                "reachable": True,
                "backend_runtime": {
                    "install_root": str(tmp_path),
                    "application_root": str(tmp_path),
                    "restart_required": True,
                    "changed_inputs": ["a.py", "b.py", "c.py", "d.py"],
                },
            },
        )
    ) == (
        "backend",
        "orchestrator backend",
        "stale",
        "vigil orchestrator restart",
        "a.py, b.py, c.py +1 more changed",
    )


def test_pin_client_sessions_rows(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import client_sessions

    monkeypatch.setattr(client_sessions, "active_client_sessions", lambda _: ())
    assert _row(restart_manifest.client_sessions_state(tmp_path)) == (
        "client-sessions",
        "client sessions",
        "not-running",
        "",
        "no registered live sessions",
    )

    sessions = (
        {
            "client": "codex",
            "mode": "web",
            "pid": 4242,
            "engagement": str(tmp_path / "engagements" / "acme"),
            "application": {"version": "2.6.0", "content_sha256": "old"},
        },
    )
    monkeypatch.setattr(client_sessions, "active_client_sessions", lambda _: sessions)
    from vigil_cli import application

    monkeypatch.setattr(application, "application_root_for_workspace", lambda w: w / "app")
    monkeypatch.setattr(
        application,
        "application_provenance",
        lambda _: {"version": "2.7.0", "content_sha256": "new"},
    )
    row = restart_manifest.client_sessions_state(tmp_path)
    assert (row.key, row.label, row.state) == ("client-sessions", "client sessions", "stale")
    assert row.detail == (
        "codex is still open for acme (current prompts and helpers retained; "
        "release=2.6.0 pid=4242)"
    )
    assert row.remedy == (
        "These sessions can continue. When ready to use the updated prompts and helpers, "
        "save a handoff, exit the listed clients, then start again: "
        f"vigil engagement start acme --client codex --mode web --root {tmp_path}"
    )

    monkeypatch.setattr(
        application, "application_provenance", lambda _: {"version": "2.6.0", "content_sha256": "old"}
    )
    assert _row(restart_manifest.client_sessions_state(tmp_path)) == (
        "client-sessions",
        "client sessions",
        "current",
        "",
        "1 live session(s) use the current application",
    )

    def _boom(_: Path) -> dict[str, str]:
        raise OSError("no provenance")

    monkeypatch.setattr(application, "application_provenance", _boom)
    assert _row(restart_manifest.client_sessions_state(tmp_path)) == (
        "client-sessions",
        "client sessions",
        "unknown",
        "",
        "no provenance",
    )


# --- CLI-11: the two Vite packages' declared inputs and states ----------------


def test_pin_web_package_declared_inputs(tmp_path: Path) -> None:
    assert [p.name for p in restart_manifest.frontend_build_inputs(tmp_path)] == [
        "package.json",
        "package-lock.json",
        "index.html",
        "vite.config.ts",
        "vite.config.js",
        "tsconfig.json",
        "tsconfig.app.json",
        "tsconfig.node.json",
        "src",
    ]
    assert [p.name for p in restart_manifest.report_build_inputs(tmp_path)] == [
        "package.json",
        "package-lock.json",
        "index.html",
        "vite.config.ts",
        "tsconfig.json",
        "scripts",
        "src",
    ]
    assert all(
        p.parent == tmp_path for p in restart_manifest.frontend_build_inputs(tmp_path)
    )
    assert all(p.parent == tmp_path for p in restart_manifest.report_build_inputs(tmp_path))
    assert restart_manifest.frontend_dir(tmp_path) == tmp_path / "orchestrator" / "frontend"
    assert restart_manifest.report_dir(tmp_path) == tmp_path / "orchestrator" / "report"


def test_pin_web_package_build_states_and_stamps(tmp_path: Path) -> None:
    assert restart_manifest.report_build_state(tmp_path) == "not-packaged"
    frontend = restart_manifest.frontend_dir(tmp_path)
    (frontend / "src").mkdir(parents=True)
    (frontend / "package.json").write_text("{}\n", encoding="utf-8")
    assert restart_manifest.frontend_build_state(tmp_path) == "missing"
    (frontend / "dist").mkdir()
    (frontend / "dist" / "index.html").write_text("x", encoding="utf-8")
    assert restart_manifest.frontend_build_state(tmp_path) == "unknown"
    restart_manifest.record_frontend_build(tmp_path)
    assert (
        frontend / "dist" / restart_manifest.BUILD_INPUTS_STAMP
    ).read_text(encoding="utf-8") == f"{restart_manifest.frontend_inputs_digest(tmp_path)}\n"
    assert restart_manifest.frontend_build_state(tmp_path) == "current"
    (frontend / "package.json").write_text("{\"a\": 1}\n", encoding="utf-8")
    assert restart_manifest.frontend_build_state(tmp_path) == "stale"

    report = restart_manifest.report_dir(tmp_path)
    (report / "src").mkdir(parents=True)
    (report / "package.json").write_text("{}\n", encoding="utf-8")
    assert restart_manifest.report_build_state(tmp_path) == "missing"
    (report / "dist").mkdir()
    (report / "dist" / "template.html").write_text("x", encoding="utf-8")
    assert restart_manifest.report_build_state(tmp_path) == "unknown"
    restart_manifest.record_report_build(tmp_path)
    assert (
        report / "dist" / restart_manifest.BUILD_INPUTS_STAMP
    ).read_text(encoding="utf-8") == f"{restart_manifest.report_inputs_digest(tmp_path)}\n"
    assert restart_manifest.report_build_state(tmp_path) == "current"
    (report / "package.json").write_text("{\"a\": 1}\n", encoding="utf-8")
    assert restart_manifest.report_build_state(tmp_path) == "stale"


# --- CLI-2: the two rendered CLI blocks, in both output forms ----------------


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def _captured_records(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, list[str]]]:
    """Record exactly what the TTY path hands ``term.print_records``."""
    from vigil_cli import term

    seen: list[tuple[str, list[str]]] = []

    def fake(title: str, records: Any, **_: object) -> None:
        seen.append((title, list(records)))

    monkeypatch.setattr(term, "print_records", fake)
    return seen


_MODE_STATE: dict[str, Any] = {
    "mode": None,
    "prompt": None,
    "client": "codex",
    "tracks": {
        "code": {
            "phase": "hunt",
            "prompt": "/agent/code.md",
            "start_command": "vigil engagement start acme --mode code",
        },
        "web": {"phase": "recon", "prompt": "/agent/web.md", "start_command": ""},
    },
    "source": {
        "path": "/src/acme",
        "state": "indexed",
        "file_count": 12,
        "entries": ["a.py", "b.py"],
        "detail": "one source root",
    },
}

_SELECTION_NOTE = (
    "Engagement found. This command has no session binding; choose a workflow and client. "
    "Inspect recovery commands with `vigil engagement mode --client <client>` "
    "(zcode, opencode, claude, codex, goose, kimi, or pi). "
    "Inside a generated client project, run this check from its Project folder."
)


def test_pin_engagement_mode_plain_output(capsys: pytest.CaptureFixture) -> None:
    from vigil_cli import main

    main._print_engagement_mode(_MODE_STATE)
    assert capsys.readouterr().out == (
        "mode: unselected\n"
        "prompt: unselected\n"
        "client: codex\n"
        f"{_SELECTION_NOTE}\n"
        "code: phase=hunt\n"
        "  prompt: /agent/code.md\n"
        "  start: vigil engagement start acme --mode code\n"
        "web: phase=recon\n"
        "  prompt: /agent/web.md\n"
        "source: /src/acme\n"
        "  state: indexed\n"
        "  files: 12\n"
        '  entries: ["a.py", "b.py"]\n'
        "  detail: one source root\n"
    )


def test_pin_engagement_mode_terminal_records(monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main

    seen = _captured_records(monkeypatch)
    monkeypatch.setattr(main.sys, "stdout", _TTY())
    main._print_engagement_mode(_MODE_STATE)
    assert seen == [
        (
            "Engagement mode",
            [
                "mode\tunselected",
                "prompt\tunselected",
                "client\tcodex",
                f"session\t{_SELECTION_NOTE}",
                "code\tphase=hunt",
                "code prompt\t/agent/code.md",
                "code start\tvigil engagement start acme --mode code",
                "web\tphase=recon",
                "web prompt\t/agent/web.md",
                "source\t/src/acme",
                "source state\tindexed",
                "source files\t12",
                'source entries\t["a.py", "b.py"]',
                "source detail\tone source root",
            ],
        )
    ]


def test_pin_engagement_mode_selected_mode_omits_note_and_source(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    from vigil_cli import main

    state: dict[str, Any] = {
        "mode": "code",
        "prompt": "/agent/code.md",
        "tracks": {},
        "source": None,
    }
    main._print_engagement_mode(state)
    assert capsys.readouterr().out == "mode: code\nprompt: /agent/code.md\n"

    seen = _captured_records(monkeypatch)
    monkeypatch.setattr(main.sys, "stdout", _TTY())
    main._print_engagement_mode(state)
    assert seen == [("Engagement mode", ["mode\tcode", "prompt\t/agent/code.md"])]


_SUMMARY_KWARGS: dict[str, Any] = {
    "target": "https://acme.example",
    "name": "Acme",
    "hosts": ["a.acme.example", "b.acme.example"],
    "repos": ["/src/acme"],
    "artifacts": ["app.apk"],
    "android_package": "com.acme.app",
    "required_headers": {"X-Acme": "1", "X-Trace": "2"},
    "out_of_scope": ["admin.acme.example"],
    "rate_limit": 2.5,
}


def test_pin_create_summary_plain_output(capsys: pytest.CaptureFixture) -> None:
    from vigil_cli import main

    main._print_create_summary("web", **_SUMMARY_KWARGS)
    assert capsys.readouterr().err == (
        "[vigil] engagement summary:\n"
        "[vigil]   type:      web\n"
        "[vigil]   target:    https://acme.example\n"
        "[vigil]   name:      Acme\n"
        "[vigil]   hosts:     a.acme.example, b.acme.example\n"
        "[vigil]   repos:     /src/acme\n"
        "[vigil]   artifacts: app.apk\n"
        "[vigil]   package:   com.acme.app\n"
        "[vigil]   headers:   X-Acme: 1, X-Trace: 2\n"
        "[vigil]   out-of-scope: admin.acme.example\n"
        "[vigil]   rate-limit: 2.5 req/s "
        "(global per-invocation; bounds per-host as a side effect)\n"
    )


def test_pin_create_summary_terminal_records(monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_cli import main

    seen = _captured_records(monkeypatch)
    monkeypatch.setattr(main.sys, "stderr", _TTY())
    main._print_create_summary("web", **_SUMMARY_KWARGS)
    assert seen == [
        (
            "Engagement summary",
            [
                "type\tweb",
                "target\thttps://acme.example",
                "name\tAcme",
                "hosts\ta.acme.example, b.acme.example",
                "repositories\t/src/acme",
                "artifacts\tapp.apk",
                "package\tcom.acme.app",
                "headers\tX-Acme: 1, X-Trace: 2",
                "out of scope\tadmin.acme.example",
                "rate limit\t2.5 req/s (global per invocation)",
            ],
        )
    ]


def test_pin_create_summary_minimal_forms(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    from vigil_cli import main

    minimal: dict[str, Any] = {
        "target": None,
        "name": None,
        "hosts": [],
        "repos": [],
        "artifacts": [],
        "android_package": None,
    }
    main._print_create_summary("code", **minimal)
    assert capsys.readouterr().err == (
        "[vigil] engagement summary:\n[vigil]   type:      code\n"
    )

    seen = _captured_records(monkeypatch)
    monkeypatch.setattr(main.sys, "stderr", _TTY())
    main._print_create_summary("code", **minimal)
    assert seen == [("Engagement summary", ["type\tcode"])]


def test_pin_create_summary_zero_rate_limit_is_still_reported(
    capsys: pytest.CaptureFixture,
) -> None:
    from vigil_cli import main

    main._print_create_summary(
        "web",
        target=None,
        name=None,
        hosts=[],
        repos=[],
        artifacts=[],
        android_package=None,
        rate_limit=0.0,
    )
    assert capsys.readouterr().err == (
        "[vigil] engagement summary:\n"
        "[vigil]   type:      web\n"
        "[vigil]   rate-limit: 0 req/s "
        "(global per-invocation; bounds per-host as a side effect)\n"
    )


# --- CLI-10 / CLI-9 / CLI-7: argparse option surfaces ------------------------


def _usage(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, *argv: str) -> str:
    """The usage block of one leaf verb's ``--help``, at a fixed width.

    The usage line is where argparse exposes registration order, so it is the
    part that moving an ``add_argument`` call can change.
    """
    from vigil_cli import main

    monkeypatch.setenv("COLUMNS", "100")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        main._main([*argv, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    return out.split("\n\n", 1)[0]


_ENGAGEMENT_SELECTOR_USAGES = {
    ("engagement", "path"): "usage: vigil engagement path [-h] [--select] [key]",
    ("engagement", "open"): "usage: vigil engagement open [-h] [--select] [key]",
    ("engagement", "archive"): "usage: vigil engagement archive [-h] [--select] [key]",
    ("engagement", "export-pdf"): (
        "usage: vigil engagement export-pdf [-h] [--select] [--output OUTPUT] [key]"
    ),
    ("engagement", "export"): (
        "usage: vigil engagement export [-h] [--select] [--format {tar.gz,markdown-tree}]"
        " [--output OUTPUT]\n                               [key]"
    ),
    ("auth", "alias"): (
        "usage: vigil auth alias [-h] [--select] --name NAME --principal PRINCIPAL"
        " [--scope SCOPE]\n                        [engagement]"
    ),
    ("auth", "env-check"): (
        "usage: vigil auth env-check [-h] [--select] --keys KEYS [KEYS ...] [engagement]"
    ),
    ("auth", "set-active"): (
        "usage: vigil auth set-active [-h] [--select] --identity IDENTITY [engagement]"
    ),
    ("auth", "import"): (
        "usage: vigil auth import [-h] [--source SOURCE] [--select] [--identity IDENTITY]"
        " [--factor FACTOR]\n                         [engagement]"
    ),
}


@pytest.mark.parametrize("verb", sorted(_ENGAGEMENT_SELECTOR_USAGES))
def test_pin_engagement_selector_usage(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    verb: tuple[str, str],
) -> None:
    assert _usage(monkeypatch, capsys, *verb) == _ENGAGEMENT_SELECTOR_USAGES[verb]


@pytest.mark.parametrize(
    "auth_name", ["status", "show", "edit", "clear", "export", "quarantine"]
)
def test_pin_auth_loop_verbs_keep_the_selector_first(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, auth_name: str
) -> None:
    usage = _usage(monkeypatch, capsys, "auth", auth_name)
    assert usage.startswith(f"usage: vigil auth {auth_name} [-h] [--select] ")
    assert "[engagement]" in usage


@pytest.mark.parametrize("verb", [("engagement", "start"), ("engagement", "prove")])
def test_pin_long_engagement_verbs_put_select_first(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, verb: tuple[str, str]
) -> None:
    usage = _usage(monkeypatch, capsys, *verb)
    assert usage.startswith(f"usage: vigil {verb[0]} {verb[1]} [-h] [--select]")
    assert usage.rstrip().endswith("[key]")


# --- CLI-9: every case-scoped remediation verb's usage block ------------------

# Each value is that verb's usage block exactly as argparse renders it at
# COLUMNS=100; the continuation indentation is part of the contract.
_REMEDIATION_USAGES: dict[str, str] = {
    "show": """\
usage: vigil remediation show [-h] case_id
""",
    "handoff": """\
usage: vigil remediation handoff [-h] case_id
""",
    "identity": """\
usage: vigil remediation identity [-h] --provider PROVIDER --key EXTERNAL_KEY case_id
""",
    "finalize-branch": """\
usage: vigil remediation finalize-branch [-h] --branch BRANCH case_id
""",
    "checks": """\
usage: vigil remediation checks [-h] --actor ACTOR [--name NAME]
                                [--shared-environment SHARED_ENVIRONMENT]
                                [--stage {verification,publication}]
                                case_id
""",
    "test": """\
usage: vigil remediation test [-h] --method METHOD --command TEST_COMMAND
                              --expected-failure EXPECTED_FAILURE [--fix-path FIX_PATH]
                              [--directory DIRECTORY] [--setup-command SETUP_COMMAND]
                              [--timeout-seconds TIMEOUT_SECONDS]
                              case_id
""",
    "environment": """\
usage: vigil remediation environment [-h] --name NAME --actor ACTOR [--token TOKEN]
                                     {acquire,release} case_id
""",
    "worktree": """\
usage: vigil remediation worktree [-h] [--base BASE] [--branch BRANCH] case_id
""",
    "sync-revision": """\
usage: vigil remediation sync-revision [-h] case_id
""",
    "runtime-identity": """\
usage: vigil remediation runtime-identity [-h] --compose-file COMPOSE_FILE --service SERVICE
                                          --container-path CONTAINER_PATH
                                          [--shared-environment SHARED_ENVIRONMENT]
                                          [--environment-token ENVIRONMENT_TOKEN] [--actor ACTOR]
                                          case_id
""",
    "evidence": """\
usage: vigil remediation evidence [-h] --kind KIND --method METHOD
                                  --environment {local,development,test,production}
                                  [--command EVIDENCE_COMMAND] --observed OBSERVED --proved PROVED
                                  [--artifact ARTIFACT] [--revision REVISION]
                                  [--outcome {failed_as_expected,passed,failed,blocked}]
                                  [--execution {executed,reasoned,unavailable}]
                                  [--executed-revision EXECUTED_REVISION]
                                  [--executed-directory EXECUTED_DIRECTORY]
                                  [--shared-environment SHARED_ENVIRONMENT]
                                  [--environment-token ENVIRONMENT_TOKEN]
                                  case_id
""",
    "baseline": """\
usage: vigil remediation baseline [-h]
                                  --outcome {runtime_reproduced,code_test_confirmed,unreproduced}
                                  --method METHOD --proved PROVED
                                  [--owner-decision {proceed,pause}] [--owner-actor OWNER_ACTOR]
                                  [--owner-reason OWNER_REASON]
                                  case_id
""",
    "plan": """\
usage: vigil remediation plan [-h] --file FILE [--requirements-file REQUIREMENTS_FILE]
                              [--alternatives-reason ALTERNATIVES_REASON]
                              case_id
""",
    "release-plan": """\
usage: vigil remediation release-plan [-h] --production-canary {required,not_required,defer}
                                      --rationale RATIONALE [--safe-procedure SAFE_PROCEDURE]
                                      --monitoring MONITORING
                                      case_id
""",
    "approve": """\
usage: vigil remediation approve [-h] --reviewer REVIEWER --owner-instruction OWNER_INSTRUCTION
                                 --review-digest REVIEW_DIGEST
                                 case_id
""",
    "transition": """\
usage: vigil remediation transition [-h] --actor ACTOR --reason REASON case_id status
""",
    "deployment": """\
usage: vigil remediation deployment [-h] --workflow WORKFLOW --run-id RUN_ID
                                    --expected-revision EXPECTED_REVISION
                                    --observed-revision OBSERVED_REVISION
                                    [--environment {development}] --actor ACTOR
                                    case_id
""",
    "human-verification": """\
usage: vigil remediation human-verification [-h] --actor ACTOR --result {passed,failed,blocked}
                                            --observed-revision OBSERVED_REVISION --notes NOTES
                                            case_id
""",
    "stagehand": """\
usage: vigil remediation stagehand [-h] --script SCRIPT --revision REVISION
                                   [--environment {local,development,test,production}]
                                   --purpose {happy-path,bad-path,other}
                                   [--production-decision PRODUCTION_DECISION]
                                   [--production-evidence-policy {retain-screenshots,no-screenshots}]
                                   [--shared-environment SHARED_ENVIRONMENT]
                                   [--environment-token ENVIRONMENT_TOKEN]
                                   case_id
""",
    "browser": """\
usage: vigil remediation browser [-h] [--driver {browse,stagehand}] --script SCRIPT
                                 --revision REVISION
                                 [--environment {local,development,test,production}]
                                 --purpose {happy-path,bad-path,other}
                                 [--production-decision PRODUCTION_DECISION]
                                 [--production-evidence-policy {retain-screenshots,no-screenshots}]
                                 [--shared-environment SHARED_ENVIRONMENT]
                                 [--environment-token ENVIRONMENT_TOKEN]
                                 case_id
""",
    "prepare-pr": """\
usage: vigil remediation prepare-pr [-h] --output OUTPUT --root-cause ROOT_CAUSE
                                    --fix-summary FIX_SUMMARY [--body-file BODY_FILE]
                                    case_id
""",
    "create-pr": """\
usage: vigil remediation create-pr [-h] --body-file BODY_FILE --actor ACTOR [--template-mapped]
                                   [--update] [--owner-instruction OWNER_INSTRUCTION]
                                   [--title TITLE]
                                   case_id
""",
    "deployment-run": """\
usage: vigil remediation deployment-run [-h] --actor ACTOR --owner-instruction OWNER_INSTRUCTION
                                        [--input INPUT] [--additional-tests-decision {run,skip}]
                                        [--new-request]
                                        case_id
""",
    "development-handoff": """\
usage: vigil remediation development-handoff [-h] --actor ACTOR case_id
""",
}


@pytest.mark.parametrize("verb", sorted(_REMEDIATION_USAGES))
def test_pin_remediation_case_verb_usage(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, verb: str
) -> None:
    expected = _REMEDIATION_USAGES[verb].rstrip("\n")
    assert _usage(monkeypatch, capsys, "remediation", verb) == expected
