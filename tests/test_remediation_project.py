import json
import pytest
from vigil_cli import remediation
from vigil_cli.engagements import CreateEngagementOptions, _write_remediation_project_notes


def test_scaffold_has_one_repository_owned_project(tmp_path):
    repo = tmp_path / 'repo'
    repo.mkdir()
    eng = tmp_path / 'eng'
    (eng / 'cases').mkdir(parents=True)
    _write_remediation_project_notes(eng, CreateEngagementOptions(install_root=tmp_path, name='Example', repos=[str(repo)]))
    assert (repo / 'PROJECT.md').is_file()
    assert (eng / 'PROJECT.md').resolve() == repo / 'PROJECT.md'
    assert 'repository = "."' in (repo / 'PROJECT.md').read_text()
    assert 'development_url = ""' in (repo / 'PROJECT.md').read_text()


def test_project_loader_reloads_shared_source_and_local_override(tmp_path, monkeypatch):
    repo = tmp_path / 'repo'
    repo.mkdir()
    eng = tmp_path / 'eng'
    (eng / 'cases').mkdir(parents=True)
    _write_remediation_project_notes(eng, CreateEngagementOptions(install_root=tmp_path, name='Example', repos=[str(repo)]))
    (eng / 'scope.json').write_text(json.dumps({'engagement_type': 'remediation'}))
    monkeypatch.setattr(remediation, 'resolve_engagement_path', lambda *_: eng)
    source = repo / 'PROJECT.md'
    source.write_text('+++\nrepository = "."\ndevelopment_url = "https://shared.example"\n+++\n# Notes\n')
    monkeypatch.setenv('VIGIL_REMEDIATION_BROWSER_CDP_URL', 'http://127.0.0.1:9444')
    _, config = remediation._project(tmp_path, 'project')
    assert config['repository'] == str(repo)
    assert config['development_url'] == 'https://shared.example'
    assert config['browser_cdp_url'] == 'http://127.0.0.1:9444'
    source.write_text('+++\nrepository = "."\ndevelopment_url = "https://changed.example"\n+++\n')
    assert remediation._project(tmp_path, 'project')[1]['development_url'] == 'https://changed.example'


def test_project_loader_invalid_header_reports_clean_error(tmp_path, monkeypatch):
    repo = tmp_path / 'repo'
    repo.mkdir()
    eng = tmp_path / 'eng'
    (eng / 'cases').mkdir(parents=True)
    _write_remediation_project_notes(eng, CreateEngagementOptions(install_root=tmp_path, name='Example', repos=[str(repo)]))
    (eng / 'scope.json').write_text(json.dumps({'engagement_type': 'remediation'}))
    (repo / 'PROJECT.md').write_text('+++\nrepository = [\n+++\n')
    monkeypatch.setattr(remediation, 'resolve_engagement_path', lambda *_: eng)
    with pytest.raises(SystemExit, match='PROJECT.md'):
        remediation._project(tmp_path, 'project')


def test_create_accepts_project_frontmatter_without_writing_on_dry_run(tmp_path, capsys):
    import subprocess
    from vigil_cli import main
    repo = tmp_path / 'repo'
    subprocess.run(['git', 'init', str(repo)], check=True, capture_output=True)
    project = repo / 'PROJECT.md'
    project.write_text('+++\nrepository = "."\ndevelopment_url = "https://dev.example"\n+++\n# Shared notes\n')
    main.main(['--root', str(tmp_path / 'install'), 'engagement', 'create', '--type', 'remediation', '--name', 'Example', '--repo', str(repo), '--project-config', str(project), '--no-prompt', '--dry-run', '--json'])
    plan = json.loads(capsys.readouterr().out)
    assert plan['manifest']['remediation_project']['development_url'] == 'https://dev.example'
    assert not (tmp_path / 'install').exists()


def test_scaffold_preserves_existing_shared_project(tmp_path):
    repo = tmp_path / 'repo'
    repo.mkdir()
    project = repo / 'PROJECT.md'
    text = '+++\nrepository = "."\n+++\n# Existing notes\n'
    project.write_text(text)
    eng = tmp_path / 'eng'
    (eng / 'cases').mkdir(parents=True)
    _write_remediation_project_notes(eng, CreateEngagementOptions(install_root=tmp_path, name='Example', repos=[str(repo)]))
    assert project.read_text() == text


def test_plan_rejects_project_repository_mismatch_before_writes(tmp_path):
    import subprocess
    from vigil_cli.engagements import plan_engagement
    repo = tmp_path / 'repo'
    subprocess.run(['git', 'init', str(repo)], check=True, capture_output=True)
    source = repo / 'PROJECT.md'
    source.write_text('+++\nrepository = "../other"\n+++\n')
    with pytest.raises(SystemExit, match='selected remediation repository'):
        plan_engagement(CreateEngagementOptions(install_root=tmp_path / 'install', engagement_type='remediation', name='Example', repos=[str(repo)]))
    assert not (tmp_path / 'install').exists()


def test_plan_snapshot_records_existing_project_configuration(tmp_path):
    import subprocess
    from vigil_cli.engagements import plan_engagement
    repo = tmp_path / 'repo'
    subprocess.run(['git', 'init', str(repo)], check=True, capture_output=True)
    (repo / 'PROJECT.md').write_text('+++\nrepository = "."\ndevelopment_url = "https://dev.example"\n+++\n')
    plan = plan_engagement(CreateEngagementOptions(install_root=tmp_path / 'install', engagement_type='remediation', name='Example', repos=[str(repo)]))
    assert plan.manifest['remediation_project']['development_url'] == 'https://dev.example'
    assert 'remediation_project' not in plan.scope
