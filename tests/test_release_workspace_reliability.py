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


def test_source_state_does_not_reread_sealed_snapshot_bytes(tmp_path):
    """The source projection reports retained copies without re-reading them.

    ``engagement_source_state`` runs on ``vigil engagement start``, on every
    ``vigil engagement mode`` (which the code operator core runs at session
    start, on resume and after every compaction) and on the creation footer. A
    per-file content attestation there costs one full re-read of every sealed
    byte of every retained generation, on the critical path between the operator
    and the client exec, to render a path and a one-word state.

    The attestation belongs to the commands that read those bytes
    (``code-index``, ``code-index sync``, ``code-history``,
    ``code-dependencies``), and this pins the split: a sealed file rewritten to
    the same length and line count keeps every constant-time binding intact, so
    only a per-file content check can see the difference. The point-of-use
    attestation must still refuse it; the projection must not pay for it.
    """
    from vigil_cli.paths import add_assess_import_path
    from vigil_cli.engagements import engagement_source_state
    add_assess_import_path(tmp_path)
    from assess.lib.code_snapshot import RootedSourceTree, SnapshotBuilder, validate_snapshot
    original = tmp_path / 'original'
    original.mkdir()
    (original / 'acme.py').write_text('print("Acme")\n')
    engagement = tmp_path / 'engagement'
    builder = SnapshotBuilder(engagement / 'tools/analysis-state/code-snapshots', 'acme')
    with RootedSourceTree(original) as tree:
        builder.add('acme.py', tree.capture('acme.py'), language='python')
    snapshot = builder.finish(repo_key='acme', repo_name='Acme', source_origin_path=str(original), git={})
    shutil.rmtree(original)

    sealed = snapshot.source_path / 'acme.py'
    sealed.chmod(0o644)
    sealed.write_text('print("ACME")\n')  # same size, same loc, different bytes
    sealed.chmod(0o444)

    with pytest.raises(ValueError, match='file mismatch'):
        validate_snapshot(snapshot.manifest_path.parent)

    result = engagement_source_state(engagement)
    assert result['state'] == 'sealed'
    assert 'sealed_source_errors' not in result
    assert result['sealed_sources'] == [{
        'path': str(snapshot.source_path),
        'repo_key': 'acme',
        'snapshot_digest': snapshot.snapshot_digest,
        'file_count': 1,
    }]


def test_source_state_still_refuses_a_manifest_that_does_not_match_itself(tmp_path):
    """The shallow read keeps every check that does not cost a sealed byte.

    Skipping the per-file walk is only safe because the manifest's own content
    address is still recomputed. A manifest edited in place -- a file added to its
    inventory, its repo_name blanked -- keeps the snapshot digest and the directory
    name it is bound to, so nothing but that recomputation can see it. If the
    projection reported such a snapshot as ``sealed`` it would tell the operator the
    copy is intact at the moment they are deciding whether to resume or re-ingest,
    which is the one wrong answer this read must never give.
    """
    from vigil_cli.paths import add_assess_import_path
    from vigil_cli.engagements import engagement_source_state
    add_assess_import_path(tmp_path)
    from assess.lib.code_snapshot import RootedSourceTree, SnapshotBuilder, validate_snapshot
    original = tmp_path / 'original'
    original.mkdir()
    (original / 'acme.py').write_text('print("Acme")\n')
    engagement = tmp_path / 'engagement'
    builder = SnapshotBuilder(engagement / 'tools/analysis-state/code-snapshots', 'acme')
    with RootedSourceTree(original) as tree:
        builder.add('acme.py', tree.capture('acme.py'), language='python')
    snapshot = builder.finish(
        repo_key='acme', repo_name='Acme', source_origin_path=str(original), git={}
    )

    manifest_path = snapshot.manifest_path
    snapshot_root = manifest_path.parent
    payload = json.loads(manifest_path.read_text())
    payload['files'] = list(payload['files']) + [dict(payload['files'][0], path='ghost.py')]
    payload['repo_name'] = ''
    snapshot_root.chmod(0o755)
    manifest_path.chmod(0o644)
    manifest_path.write_text(json.dumps(payload))
    manifest_path.chmod(0o444)
    snapshot_root.chmod(0o555)

    with pytest.raises(ValueError):
        validate_snapshot(snapshot_root, deep=False)

    result = engagement_source_state(engagement)
    assert 'sealed_sources' not in result
    assert result['sealed_source_errors']
    assert result['state'] != 'sealed'


def test_install_digest_does_not_descend_into_engagement_source_or_snapshots(tmp_path):
    """Engagement data is private workspace state, never install-managed content.

    The install-managed content digest reads every byte of every declared input,
    so an engagement tree reachable from it would put the ingested source and
    every sealed snapshot on the critical path of every freshness comparison
    (``vigil status``, the engagement-start staleness warning, workspace
    adoption). The legacy ``agent/engagements`` location is preserved rather
    than copied, and this pins that the digest stops there.
    """
    from vigil_cli.install_manifest import install_source_content_sha256

    source = tmp_path / 'source'
    (source / 'src').mkdir(parents=True)
    (source / 'src' / 'feature.py').write_text('enabled = True\n', encoding='utf-8')
    sealed = (source / 'agent/engagements/acme/tools/analysis-state/code-snapshots'
              / 'acme' / ('a' * 64) / 'source')
    sealed.mkdir(parents=True)
    ingested = source / 'agent/engagements/acme/source'
    ingested.mkdir(parents=True)
    expected = install_source_content_sha256(source)

    (sealed / 'sealed.py').write_text('print("Acme sealed")\n', encoding='utf-8')
    (ingested / 'ingested.py').write_text('print("Acme ingested")\n', encoding='utf-8')
    assert install_source_content_sha256(source) == expected

    (source / 'src' / 'added.py').write_text('added = True\n', encoding='utf-8')
    assert install_source_content_sha256(source) != expected


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
