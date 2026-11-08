from __future__ import annotations

import importlib
import sqlite3
import os

import pytest
from tests.proof_fixtures import completed_confirm_check

from app import db
from app.services import artifact_index
from tests.test_artifact_resume_api import BASE, ENGAGEMENT_KEY, _register_note, _write_engagement

readiness = importlib.import_module('app.services.state_manager.report_readiness')


def _seed_notes(client, isolate_settings):
    root = _write_engagement(isolate_settings['engagements_dir'])
    for name in ('acme-one.md', 'acme-two.md'):
        (root / name).write_text('Acme résumé\n', encoding='utf-8')
        _register_note(client, name)
    with db.get_connection() as connection:
        eid = connection.execute('SELECT id FROM engagements WHERE key=?', (ENGAGEMENT_KEY,)).fetchone()['id']
    return root, int(eid)


def test_artifact_refresh_does_not_hold_a_writer_while_reading_the_next_file(
    client, isolate_settings, monkeypatch,
):
    _, eid = _seed_notes(client, isolate_settings)
    original = artifact_index._file_payload
    observed = []

    def read(*args, **kwargs):
        with db.get_connection() as connection:
            filename = connection.execute('PRAGMA database_list').fetchone()['file']
        other = sqlite3.connect(filename, timeout=0)
        try:
            other.execute('BEGIN IMMEDIATE')
            other.execute('UPDATE assessment_artifacts SET updated_at=updated_at WHERE id=-1')
            other.commit()
            observed.append(args[1])
        finally:
            other.close()
        return original(*args, **kwargs)

    monkeypatch.setattr(artifact_index, '_file_payload', read)
    result = artifact_index.refresh_artifacts(eid)
    assert result['refreshed'] == result['present'] == 2
    assert len(observed) == 2
    assert client.get(f'{BASE}/artifacts/search', params={'limit': 10}).status_code == 200


def test_compact_artifact_search_does_not_materialize_full_indexed_bodies(client, isolate_settings):
    _, eid = _seed_notes(client, isolate_settings)
    with db.get_connection() as connection:
        original = connection.row_factory
        selected_columns = []

        def observed(cursor, row):
            selected_columns.append(tuple(column[0] for column in cursor.description))
            return sqlite3.Row(cursor, row)

        connection.row_factory = observed
        try:
            rows = artifact_index.search_artifacts(eid, limit=10)
        finally:
            connection.row_factory = original
    assert len(rows) == 2
    assert all(row['indexed_bytes'] == len('Acme résumé\n'.encode()) for row in rows)
    assert all(row['index_status'] == 'complete' for row in rows)
    assert not any('indexed_text' in columns for columns in selected_columns), selected_columns


def test_missing_detail_citations_share_one_generation_roster_and_resolution():
    connection = sqlite3.connect(':memory:')
    connection.row_factory = sqlite3.Row
    connection.execute('CREATE TABLE code_source_generation_files(engagement_id INTEGER,repo_id INTEGER,repo_generation INTEGER,file_id INTEGER,file_path TEXT,file_hash TEXT,language TEXT,loc INTEGER)')
    connection.execute('CREATE TABLE code_analysis_triggers(engagement_id INTEGER,repo_id INTEGER,target_file_path TEXT,target_file_id INTEGER)')
    connection.executemany('INSERT INTO code_source_generation_files VALUES(1,1,1,?,?,?, ?,100)',
                           [(i, f'modules/Acme{i:04d}/Config.php', 'a'*64, 'php') for i in range(100)])
    candidates = [{'slug': f'VA-{i}', 'title': 'Acme config',
                   'provenance': {'code_snapshot': {'repo_id': 1, 'repo_generation': 1,
                                                   'source_manifest_digest': 'a'*64}},
                   'details': {'sink': 'modules/Unknown/Config.php:12'}} for i in range(1, 4)]
    statements = []
    connection.set_trace_callback(statements.append)
    blockers = readiness._details_citation_blockers(connection, 1, candidates)
    assert len(blockers) == 3
    assert {b['closest_admitted_path'] for b in blockers} == {'modules/Acme0099/Config.php'}
    roster_reads = [q for q in statements if 'SELECT file_path FROM code_source_generation_files' in q]
    assert len(roster_reads) <= 1, len(roster_reads)
    # Exact per-finding diagnostics remain lossless even though their path work is shared.
    assert {b['slug'] for b in blockers} == {'VA-1', 'VA-2', 'VA-3'}
    assert all(b['line'] == 12 and b['path'] == 'modules/Unknown/Config.php' for b in blockers)
    connection.close()


def test_verification_receipts_attest_shared_artifact_once_per_decision(client, isolate_settings, monkeypatch):
    from app.services.state_manager import proofs
    from tests.test_finding_list_batch_projection import _cloned_findings
    from tests.test_finding_code_snapshot_provenance import _verification_receipt

    eid = _cloned_findings(client, isolate_settings, count=1)
    receipt_id = _verification_receipt(client, 'cvv-va-501', 'VA-501')
    with db.get_connection() as connection:
        source = dict(connection.execute('SELECT * FROM assessment_proof_receipts WHERE id=?', (receipt_id,)).fetchone())
        columns = [name for name in source if name != 'id']
        second = connection.execute(
            'INSERT INTO assessment_proof_receipts (' + ','.join(columns) + ') VALUES ('
            + ','.join('?' for _ in columns) + ')', [source[name] for name in columns],
        ).lastrowid
    original = proofs.artifact_index.registered_snapshot_evidence_health
    checked = []

    def attest(*args, **kwargs):
        checked.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(proofs.artifact_index, 'registered_snapshot_evidence_health', attest)
    with db.get_connection() as connection:
        records, verifier = proofs._verification_receipts(connection, eid, [receipt_id, second])
    assert len(records) == 2 and verifier == source['producer_dispatch_id']
    assert all(r['evidence_health'] == 'healthy' for r in records)
    assert len(checked) == 1


def test_finding_verification_hashes_evidence_before_acquiring_the_writer(client, isolate_settings, monkeypatch):
    from tests.test_finding_list_batch_projection import _cloned_findings
    from tests.test_finding_code_snapshot_provenance import _verification_receipt, _verify, _info_severity_variance

    _cloned_findings(client, isolate_settings, count=1)
    receipt = _verification_receipt(client, 'cvv-va-501', 'VA-501')
    original = artifact_index._read_artifact_extent
    checked = []

    def read(*args, **kwargs):
        with db.get_connection() as connection:
            filename = connection.execute('PRAGMA database_list').fetchone()['file']
        other = sqlite3.connect(filename, timeout=0)
        try:
            other.execute('BEGIN IMMEDIATE')
            other.commit()
            checked.append(True)
        finally:
            other.close()
        yield from original(*args, **kwargs)

    monkeypatch.setattr(artifact_index, '_read_artifact_extent', read)
    result = _verify(client, 'VA-501', {
        'verification_status': 'confirmed', 'source_name': 'code-vuln-verifier',
        'reason_text': 'Independent Acme evidence confirms the recorded source issue.',
        'proof_receipt_ids': [receipt], 'severity_variance': _info_severity_variance(receipt),
        'confirm_check': completed_confirm_check(receipt),
    })
    assert result.status_code == 200, result.text
    assert checked


@pytest.mark.parametrize('change', ['rewrite', 'replace'])
def test_evidence_changed_after_validation_rolls_back_the_verdict(client, isolate_settings, monkeypatch, change):
    from pathlib import Path
    from tests.test_finding_list_batch_projection import _cloned_findings
    from tests.test_finding_code_snapshot_provenance import _verification_receipt, _verify, _info_severity_variance

    findings = importlib.import_module('app.services.state_manager.findings')
    eid = _cloned_findings(client, isolate_settings, count=1)
    receipt = _verification_receipt(client, 'cvv-va-501', 'VA-501')
    with db.get_connection() as connection:
        row = connection.execute('SELECT artifacts.relative_path, engagements.engagement_root FROM assessment_proof_receipts AS receipts JOIN assessment_artifacts AS artifacts ON artifacts.id=receipts.artifact_id JOIN engagements ON engagements.id=receipts.engagement_id WHERE receipts.id=?', (receipt,)).fetchone()
        before = dict(connection.execute('SELECT * FROM assessment_findings WHERE engagement_id=?', (eid,)).fetchone())
    path = Path(row['engagement_root']) / row['relative_path']
    original = findings.record_finding_verification_evidence

    def verify(*args, **kwargs):
        result = original(*args, **kwargs)
        metadata = path.stat()
        content = b'X' * metadata.st_size
        if change == 'rewrite':
            path.write_bytes(content)
            os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        else:
            replacement = path.with_suffix('.acme-replacement')
            replacement.write_bytes(content)
            replacement.replace(path)
        return result

    monkeypatch.setattr(findings, 'record_finding_verification_evidence', verify)
    result = _verify(client, 'VA-501', {
        'verification_status': 'confirmed', 'source_name': 'code-vuln-verifier',
        'reason_text': 'Independent Acme evidence confirms the recorded source issue.',
        'proof_receipt_ids': [receipt], 'severity_variance': _info_severity_variance(receipt),
        'confirm_check': completed_confirm_check(receipt),
    })
    assert result.status_code == 409, result.text
    with db.get_connection() as connection:
        after = dict(connection.execute('SELECT * FROM assessment_findings WHERE engagement_id=?', (eid,)).fetchone())
    assert after['verification_status'] == before['verification_status']
    assert after['row_version'] == before['row_version']


def test_refresh_enumeration_does_not_collect_every_indexed_body(client, isolate_settings):
    _, eid = _seed_notes(client, isolate_settings)
    with db.get_connection() as connection:
        original = connection.row_factory
        artifact_rows = []

        def observed(cursor, row):
            columns = tuple(column[0] for column in cursor.description)
            if 'relative_path' in columns:
                artifact_rows.append(columns)
            return sqlite3.Row(cursor, row)

        connection.row_factory = observed
    try:
        result = artifact_index.refresh_artifacts(eid)
    finally:
        connection.row_factory = original
    assert result['refreshed'] == 2
    assert len(artifact_rows) >= 2
    assert all('indexed_text' not in columns for columns in artifact_rows[:2])
