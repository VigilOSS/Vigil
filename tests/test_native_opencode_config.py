"""Native OpenCode discovery contracts verified on 1.18.10 and 1.19.3.

The native config loader scans plugin(s)/*.{ts,js}; merely writing a valid
JavaScript module with another suffix does not register a lifecycle adapter.
"""
from pathlib import Path

from vigil_cli import assessment_clients


ROOT = Path(__file__).resolve().parents[1]


def test_prepared_assessment_hook_is_discoverable_by_native_opencode(tmp_path, monkeypatch):
    engagement = tmp_path / "private/engagements/acme"
    engagement.mkdir(parents=True)
    monkeypatch.setattr(assessment_clients, "agent_root", lambda _: ROOT / "agent")
    monkeypatch.setattr(assessment_clients, "application_provenance", lambda _: {
        "root": str(ROOT), "version": "1.0.0", "content_sha256": "a" * 64,
    })
    monkeypatch.setattr(assessment_clients, "session_cli_directory", lambda _: tmp_path / "helper")
    monkeypatch.setattr(assessment_clients, "_tools", lambda _: {
        name: "/bin/true" for name in ("uv", "bash", "jq", "node")
    })
    monkeypatch.setattr(assessment_clients, "resolve_orchestrator_base_url", lambda *_: "http://127.0.0.1:9")

    workspace, _ = assessment_clients.prepare_workspace(
        tmp_path / "private", engagement, "opencode", "code", native_version="1.18.10",
    )
    discovered = [
        path for directory in ("plugin", "plugins") for suffix in ("ts", "js")
        for path in (workspace / ".opencode" / directory).glob(f"*.{suffix}")
    ]
    assert len(discovered) == 1
    assert discovered[0].read_bytes() == (ROOT / "agent/.opencode/plugin/assessment-hooks.js").read_bytes()
