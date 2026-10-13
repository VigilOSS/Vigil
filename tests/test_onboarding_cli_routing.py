from vigil_cli import main as cli


def test_doctor_plans_host_tools_without_installing(tmp_path, monkeypatch, capsys):
    import json

    monkeypatch.setattr(cli, 'collect_doctor_checks', lambda *a, **k: [])
    cli.main(['--root', str(tmp_path), 'doctor', '--install-host-tools', '--dry-run', '--json'])
    report = json.loads(capsys.readouterr().out)
    assert report['host_tools']['dry_run'] is True
    assert report['host_tools']['executed'] == []


def test_create_routes_source_directory_without_copying(tmp_path, monkeypatch):
    observed = []
    monkeypatch.setattr(cli, 'plan_engagement', lambda options: observed.append(options) or type('Plan', (), {'engagement_type': 'code', 'label': 'acme', 'scope': {}, 'manifest': {}})())
    try:
        cli.main(['--root', str(tmp_path), 'engagement', 'create', '--type', 'code', '--name', 'acme', '--source-dir', str(tmp_path), '--dry-run', '--json', '--no-prompt'])
    except SystemExit as exc:
        assert exc.code == 0, 'source registration must be accepted'
    assert observed
    assert observed[0].source_dir == tmp_path
