from __future__ import annotations

import hashlib
import os

import pytest
from fastapi import HTTPException

from app.services import artifact_index


@pytest.mark.parametrize("failure", [FileNotFoundError, PermissionError])
def test_prepared_root_open_failure_preserves_evidence_health(tmp_path, monkeypatch, failure):
    root = tmp_path / "acme"
    original = os.open
    def opened(path, *args, **kwargs):
        if path == root:
            raise failure("Acme root unavailable")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(artifact_index.os, "open", opened)
    args = dict(expected_size=4, expected_sha256=hashlib.sha256(b"Acme").hexdigest(),
                verified_device=None, verified_inode=None)
    ordinary = artifact_index.registered_snapshot_evidence_health(root, "proof.txt", **args)
    with artifact_index.prepared_artifact_health():
        assert artifact_index.registered_snapshot_evidence_health(root, "proof.txt", **args) == ordinary


def test_failed_root_pin_stat_does_not_leak_a_descriptor(tmp_path, monkeypatch):
    original_open, original_close = os.open, os.close
    active = set()
    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        active.add(fd)
        return fd
    def closed(fd):
        active.discard(fd)
        return original_close(fd)
    def failed(fd):
        raise OSError("Acme descriptor unavailable")
    monkeypatch.setattr(artifact_index.os, "open", opened)
    monkeypatch.setattr(artifact_index.os, "close", closed)
    monkeypatch.setattr(artifact_index.os, "fstat", failed)
    try:
        with artifact_index.prepared_artifact_health():
            try:
                artifact_index.registered_snapshot_evidence_health(
                    tmp_path, "proof.txt", expected_size=4, expected_sha256="a" * 64,
                    verified_device=None, verified_inode=None,
                )
            except OSError:
                pass
        assert not active
    finally:
        for fd in active:
            original_close(fd)


def _read(root, path, *, verified, size, digest):
    if verified:
        metadata = path.stat()
        return artifact_index.verified_snapshot_evidence_health(
            root, path.relative_to(root).as_posix(), expected_device=metadata.st_dev,
            expected_inode=metadata.st_ino, expected_size=size, expected_sha256=digest,
        )
    return artifact_index.registered_snapshot_evidence_health(
        root, path.relative_to(root).as_posix(), expected_size=size,
        expected_sha256=digest, verified_device=None, verified_inode=None,
    )


@pytest.mark.parametrize('verified', [False, True])
def test_size_drift_is_rejected_without_reading_the_changed_body(tmp_path, monkeypatch, verified):
    path = tmp_path / 'scans/command-runs/acme.stdout'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'changed Acme evidence' * 1000)
    observed = []
    original = os.read

    def read(fd, size):
        observed.append(size)
        return original(fd, size)

    monkeypatch.setattr(artifact_index.os, 'read', read)
    assert _read(tmp_path, path, verified=verified, size=4,
                 digest=hashlib.sha256(b'Acme').hexdigest()) == 'stale'
    assert not observed, 'A known size mismatch must not scan the changed body'


@pytest.mark.parametrize('verified', [False, True])
def test_growing_evidence_has_a_finite_read_budget_and_never_becomes_healthy(
    tmp_path, monkeypatch, verified,
):
    path = tmp_path / 'scans/command-runs/acme.stdout'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'Acme')
    original = os.read
    received = []

    def read(fd, size):
        # A producer that keeps extending a regular file must not hold a worker
        # until EOF. Stop the baseline after three reads to avoid hanging pytest.
        if len(received) >= 3:
            raise OSError('Acme producer is still appending')
        with path.open('ab') as output:
            output.write(b' more Acme evidence')
        chunk = original(fd, size)
        received.append(len(chunk))
        return chunk

    monkeypatch.setattr(artifact_index.os, 'read', read)
    assert _read(tmp_path, path, verified=verified, size=4,
                 digest=hashlib.sha256(b'Acme').hexdigest()) == 'stale'
    assert sum(received) <= 5, 'Attestation reads at most its expected extent plus an overflow byte'


def test_registered_content_reader_also_stops_at_the_indexed_extent(tmp_path, monkeypatch):
    path = tmp_path / 'acme.txt'
    path.write_bytes(b'Acme')
    original = os.read
    received = []

    def read(fd, size):
        with path.open('ab') as output:
            output.write(b' more Acme evidence')
        chunk = original(fd, size)
        received.append(len(chunk))
        return chunk

    monkeypatch.setattr(artifact_index.os, 'read', read)
    with pytest.raises(HTTPException):
        artifact_index.read_registered_artifact_bytes(
            tmp_path, 'acme.txt', expected_size=4,
            expected_sha256=hashlib.sha256(b'Acme').hexdigest(),
        )
    assert sum(received) <= 5


def test_artifact_registration_does_not_chase_a_growing_log(tmp_path, monkeypatch):
    path = tmp_path / 'acme.log'
    path.write_bytes(b'Acme')
    original = os.read
    received = []

    def read(fd, size):
        if len(received) >= 3:
            return b''
        with path.open('ab') as output:
            output.write(b' more Acme evidence')
        chunk = original(fd, size)
        received.append(len(chunk))
        return chunk

    monkeypatch.setattr(artifact_index.os, 'read', read)
    result = artifact_index._file_payload(tmp_path, 'acme.log', 'text/plain')
    assert not result['present']
    assert sum(received) <= 5


def test_prepared_evidence_retains_bounded_descriptors_for_many_files(tmp_path, monkeypatch):
    for i in range(50):
        (tmp_path / f'acme-{i}.txt').write_bytes(b'Acme')
    original_open, original_close = os.open, os.close
    active = set()
    peak = []

    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        active.add(fd)
        peak.append(len(active))
        return fd

    def closed(fd):
        active.discard(fd)
        return original_close(fd)

    monkeypatch.setattr(artifact_index.os, 'open', opened)
    monkeypatch.setattr(artifact_index.os, 'close', closed)
    with artifact_index.prepared_artifact_health() as observations:
        for i in range(50):
            assert _read(tmp_path, tmp_path / f'acme-{i}.txt', verified=False, size=4,
                         digest=hashlib.sha256(b'Acme').hexdigest()) == 'healthy'
        observations.sealed = True
        observations.verify_current()
    assert not active
    assert max(peak) < 10, 'Preparing proof must not retain one descriptor per evidence file'
