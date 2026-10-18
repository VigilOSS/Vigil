from app.services import remediation


def test_effective_configuration_but_not_project_notes_changes_review_digest(tmp_path, monkeypatch):
    monkeypatch.setattr(remediation, '_review_patch', lambda _: ('base', 'head', b'patch', False, 5))
    monkeypatch.setattr(remediation, '_actual_revision', lambda _: 'head')
    monkeypatch.setattr(remediation, '_worktree_digest', lambda _: 'contents')
    row = {'id': 1, 'title': 'Case', 'snapshot_json': '{}', 'worktree_path': 'unused', 'worktree_branch': None,
           'worktree_revision': 'head', 'verification_plan': 'Plan', 'baseline_json': '{}', 'release_plan_json': '{}'}
    source = tmp_path / 'PROJECT.md'
    source.write_text('+++\nrepository = "."\ndeployment_workflow = "develop.yml"\n+++\n# Notes\n')
    before = remediation._review_digest(row, [], tmp_path, [])
    source.write_text(source.read_text().replace('develop.yml', 'other.yml'))
    changed_workflow = remediation._review_digest(row, [], tmp_path, [])
    assert changed_workflow != before
    source.write_text(source.read_text() + '\nNew account prerequisites\n')
    changed_notes = remediation._review_digest(row, [], tmp_path, [])
    assert changed_notes == changed_workflow
    monkeypatch.setenv('VIGIL_REMEDIATION_BROWSER_CDP_URL', 'http://127.0.0.1:9555')
    assert remediation._review_digest(row, [], tmp_path, []) != changed_notes
