from pathlib import Path
import json
import shutil

import pytest

from vigil_cli import config, workspace

REPO = Path(__file__).resolve().parents[1]


def test_new_workspace_defaults_are_portable(tmp_path):
    original = tmp_path / 'original'
    data = workspace.initialize_workspace(original, REPO)
    assert data['paths']['engagements'] == 'engagements'
    copied = tmp_path / 'copied'
    shutil.copytree(original, copied)
    assert workspace.workspace_path(copied, 'data') == copied / 'state'


@pytest.mark.parametrize('legacy', [False, True])
def test_old_workspace_move_resolves_default_layout_before_writing(tmp_path, legacy):
    original = tmp_path / 'original'
    if legacy:
        (original / 'agent/engagements').mkdir(parents=True)
        (original / 'orchestrator/backend/data').mkdir(parents=True)
        (original / '.runtime-data/logs').mkdir(parents=True)
        (original / 'agent/references/tenants').mkdir(parents=True)
    workspace.initialize_workspace(original, REPO)
    metadata = json.loads((original / 'workspace.json').read_text())
    metadata['paths'] = {key: str(workspace.workspace_path(original, key)) for key in metadata['paths']}
    (original / 'workspace.json').write_text(json.dumps(metadata))
    moved = tmp_path / 'moved'
    original.rename(moved)
    relative = 'agent/engagements' if legacy else 'engagements'
    assert workspace.workspace_path(moved, 'engagements') == moved / relative
    workspace.initialize_workspace(moved, REPO)
    assert not original.exists()


def test_absolute_copy_refuses_ambiguous_adoption(tmp_path):
    original = tmp_path / 'original'
    workspace.initialize_workspace(original, REPO)
    metadata = json.loads((original / 'workspace.json').read_text())
    metadata['paths'] = {key: str(workspace.workspace_path(original, key)) for key in metadata['paths']}
    (original / 'workspace.json').write_text(json.dumps(metadata))
    copied = tmp_path / 'copied'
    shutil.copytree(original, copied)
    with pytest.raises(SystemExit, match='original workspace still exists'):
        workspace.initialize_workspace(copied, REPO)


def test_runtime_sizing_uses_selected_workspace_without_environment_mutation(tmp_path, monkeypatch):
    for key in ('MEMORY_GB', 'CPUS', 'PIDS_LIMIT', 'SHM_SIZE'):
        monkeypatch.delenv('VIGIL_RUNTIME_' + key, raising=False)
    (tmp_path / '.env').write_text('VIGIL_RUNTIME_MEMORY_GB=4\nVIGIL_RUNTIME_CPUS=2.5\nVIGIL_RUNTIME_PIDS_LIMIT=900\nVIGIL_RUNTIME_SHM_SIZE="2g"\n')
    assert config.runtime_resources(tmp_path) == config.RuntimeResources(4, 2.5, 900, '2g')
    monkeypatch.setenv('VIGIL_RUNTIME_CPUS', '3')
    assert config.runtime_resources(tmp_path).cpus == 3
    assert config.runtime_resources(tmp_path / 'other').memory_gb == 2


@pytest.mark.parametrize('value', ['nan', 'inf', '-1', '0'])
def test_runtime_sizing_rejects_invalid_workspace_cpu_value(tmp_path, monkeypatch, value):
    monkeypatch.delenv('VIGIL_RUNTIME_CPUS', raising=False)
    (tmp_path / '.env').write_text(f'VIGIL_RUNTIME_CPUS={value}\n')
    with pytest.raises(SystemExit, match='VIGIL_RUNTIME_CPUS'):
        config.runtime_resources(tmp_path)


def test_retained_sealed_source_remains_resumable_without_original(tmp_path):
    from vigil_cli.paths import add_assess_import_path
    from vigil_cli.engagements import engagement_source_state
    add_assess_import_path(tmp_path)
    from assess.lib.code_snapshot import SnapshotBuilder, RootedSourceTree
    original = tmp_path / 'original'
    original.mkdir()
    (original / 'acme.py').write_text('print("Acme")\n')
    engagement = tmp_path / 'engagement'
    builder = SnapshotBuilder(engagement / 'tools/analysis-state/code-snapshots', 'acme')
    with RootedSourceTree(original) as tree:
        builder.add('acme.py', tree.capture('acme.py'), language='python')
    snapshot = builder.finish(repo_key='acme', repo_name='Acme', source_origin_path=str(original), git={})
    shutil.rmtree(original)
    result = engagement_source_state(engagement)
    assert result['state'] == 'sealed'
    assert result['original_source_available'] is False
    assert result['sealed_sources'][0]['snapshot_digest'] == snapshot.snapshot_digest


def test_invalid_retained_snapshot_does_not_make_source_resumable(tmp_path):
    from vigil_cli.engagements import engagement_source_state
    snapshot = tmp_path / 'tools/analysis-state/code-snapshots/acme' / ('a' * 64)
    (snapshot / 'source').mkdir(parents=True)
    (snapshot / 'manifest.json').write_text('{}')
    result = engagement_source_state(tmp_path)
    assert result['state'] == 'waiting'
    assert result['sealed_source_errors']


@pytest.mark.parametrize('value', ['0', '-2g', 'unlimited', '1g extra'])
def test_runtime_shared_memory_rejects_invalid_size(tmp_path, monkeypatch, value):
    monkeypatch.delenv('VIGIL_RUNTIME_SHM_SIZE', raising=False)
    (tmp_path / '.env').write_text(f'VIGIL_RUNTIME_SHM_SIZE={value}\n')
    with pytest.raises(SystemExit, match='VIGIL_RUNTIME_SHM_SIZE'):
        config.runtime_resources(tmp_path)


def test_moved_workspace_start_rebinds_generated_launcher_without_rewriting_operator_env(tmp_path, monkeypatch):
    from vigil_cli import engagements
    original = tmp_path / 'original'
    workspace.initialize_workspace(original, REPO)
    monkeypatch.setattr(engagements, '_install_client_kind', lambda *a: 'both')
    created = engagements.create_engagement(engagements.CreateEngagementOptions(original, 'code', name='Acme'), contact_backend=False)
    operator_config = 'ACME_CUSTOM_VALUE=preserve-bytes\n'
    (created.path / '.orchestrator.env').write_text(operator_config)
    moved = tmp_path / 'moved'
    original.rename(moved)
    engagement = moved / 'engagements' / created.key
    monkeypatch.setattr(engagements.os, 'execv', lambda *a: None)
    monkeypatch.chdir(tmp_path)
    engagements.start_engagement(moved, engagement, 'codex', [], no_autoprompt=True)
    launcher = (engagement / 'start_codex.sh').read_text()
    assert str(moved) in launcher
    assert (engagement / '.orchestrator.env').read_text() == operator_config
    assert workspace.workspace_path(moved, 'runtime_state') == moved / 'state/runtime'


def test_moved_old_layout_preserves_explicit_external_data(tmp_path, monkeypatch):
    original, external = tmp_path / 'original', tmp_path / 'external-data'
    monkeypatch.setenv('VIGIL_DATA_DIR', str(external))
    workspace.initialize_workspace(original, REPO)
    metadata = json.loads((original / 'workspace.json').read_text())
    metadata['paths'] = {key: str(workspace.workspace_path(original, key)) for key in metadata['paths']}
    (original / 'workspace.json').write_text(json.dumps(metadata))
    moved = tmp_path / 'moved'
    original.rename(moved)
    workspace.initialize_workspace(moved, REPO)
    assert workspace.workspace_path(moved, 'data') == external
    assert workspace.workspace_path(moved, 'engagements') == moved / 'engagements'
