"""Required-header injection remains best-effort and never blocks execution."""
from __future__ import annotations

import json
from types import SimpleNamespace

from assess.lib import kali


def test_kali_exec_warns_and_runs_when_required_header_cannot_be_injected(
    tmp_path, monkeypatch, capsys
) -> None:
    eng_dir = tmp_path / "engagements" / "eng"
    eng_dir.mkdir(parents=True)
    (eng_dir / "scope.json").write_text(
        json.dumps(
            {
                "engagement_type": "web",
                "hosts": ["app.example.com"],
                "required_headers": {"X-Bug-Bounty": "vigiloss"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        kali,
        "load_config",
        lambda _flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(eng_dir),
            engagement_key=eng_dir.name,
            agent_root=str(eng_dir.parent.parent),
        ),
    )
    monkeypatch.setattr(kali, "_check_container_running", lambda _name: None)
    popen_seen: dict[str, list[str]] = {}

    class OkPopen:
        def __init__(self, argv, **_kwargs):
            popen_seen["argv"] = argv
            self.pid = 4321

        def wait(self, timeout=None):
            return 0

    class Client:
        def post(self, _endpoint, _payload):
            return {"id": 1, "superseded_by_id": None}

        def patch(self, _endpoint, payload, *, accept_409=False):
            return {"id": 1, "status": payload.get("status")}

        def close(self):
            pass

    monkeypatch.setattr(kali.subprocess, "Popen", OkPopen)
    monkeypatch.setattr(kali, "AssessmentClient", lambda *_a, **_k: Client())
    monkeypatch.setattr(kali, "_read_container_pid", lambda *_a, **_k: None)
    monkeypatch.setattr(kali, "_kill_in_container", lambda *_a, **_k: None)
    monkeypatch.setattr(kali, "_cleanup_container_pid_file", lambda *_a, **_k: None)

    result = kali.kali_exec(
        ["bash", "-c", "whatweb https://app.example.com"],
        technique="DISCOVERY",
        intent="fingerprint app",
        probe_kind="fingerprint",
        phase="recon",
        timeout=30,
        agent_name="recon-specialist",
        engagement_dir=eng_dir,
        tool_name="whatweb",
    )

    assert result.status != "refused"
    assert result.return_code == 0
    assert "argv" in popen_seen
    warning = capsys.readouterr().err
    assert "could not be injected" in warning
    assert "X-Bug-Bounty" in warning
