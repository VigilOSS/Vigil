from pathlib import Path

from vigil_cli import main as cli


def test_quickstart_routes_selected_code_client_and_source(tmp_path, monkeypatch):
    observed = []
    monkeypatch.setattr(cli, 'run_quickstart', lambda options: observed.append(options) or 0)
    try:
        cli.main(['--root', str(tmp_path), 'quickstart', '--type', 'code', '--client', 'codex', '--source-dir', str(tmp_path)])
    except SystemExit as exc:
        assert exc.code == 0, 'selected onboarding options must be accepted'
    assert observed
    assert observed[0].engagement_type == 'code'
    assert observed[0].client == 'codex'
    assert observed[0].source_dir == Path(tmp_path)


def test_create_routes_source_directory_without_copying(tmp_path, monkeypatch):
    observed = []
    monkeypatch.setattr(cli, 'plan_engagement', lambda options: observed.append(options) or type('Plan', (), {'engagement_type': 'code', 'label': 'acme', 'scope': {}, 'manifest': {}})())
    try:
        cli.main(['--root', str(tmp_path), 'engagement', 'create', '--type', 'code', '--name', 'acme', '--source-dir', str(tmp_path), '--dry-run', '--json', '--no-prompt'])
    except SystemExit as exc:
        assert exc.code == 0, 'source registration must be accepted'
    assert observed
    assert observed[0].source_dir == tmp_path


def test_quickstart_refuses_a_remediation_only_client(tmp_path, monkeypatch):
    import pytest
    observed = []
    monkeypatch.setattr(cli, 'run_quickstart', lambda options: observed.append(options) or 0)
    with pytest.raises(SystemExit) as failure:
        cli.main(['--root', str(tmp_path), 'quickstart', '--type', 'code', '--client', 'pi'])
    assert failure.value.code == 2
    assert observed == []
