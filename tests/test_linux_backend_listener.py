"""Linux ownership discovery must identify a socket owner, never just a port."""
import socket

import pytest

from vigil_cli import orchestrator


def _address(address):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    raw = socket.inet_pton(family, address)
    return ''.join(raw[index:index + 4][::-1].hex().upper() for index in range(0, len(raw), 4))


def _listener(proc, address, port, inode, *, state='0A'):
    table = proc / 'net' / ('tcp6' if ':' in address else 'tcp')
    table.parent.mkdir(parents=True, exist_ok=True)
    with table.open('a') as handle:
        handle.write(f'0: {_address(address)}:{port:04X} {_address(address)}:0000 {state} 0:0 0:0 0 1000 0 {inode} 1\n')


def _owner(proc, pid, inode):
    fd = proc / str(pid) / 'fd'
    fd.mkdir(parents=True, exist_ok=True)
    (fd / str(inode)).symlink_to(f'socket:[{inode}]')


@pytest.fixture
def proc(tmp_path, monkeypatch):
    root = tmp_path / 'proc'
    root.mkdir()
    monkeypatch.setattr(orchestrator, '_PROC_ROOT', root, raising=False)
    def unavailable(*args, **kwargs):
        raise FileNotFoundError('lsof is not installed')
    monkeypatch.setattr(orchestrator.subprocess, 'run', unavailable)
    return root


@pytest.mark.parametrize(('bound', 'requested'), [
    ('127.0.0.1', '127.0.0.1'), ('0.0.0.0', '127.0.0.1'),
    ('::1', '::1'), ('::', '::1'), ('127.0.0.1', 'localhost'),
    ('::', '127.0.0.1'), ('::ffff:127.0.0.1', '127.0.0.1'),
])
def test_linux_finds_listener_socket_owner_without_lsof(proc, bound, requested):
    _listener(proc, bound, 18000, 500)
    _owner(proc, 4242, 500)
    assert orchestrator._port_listener_pid(requested, 18000) == 4242


@pytest.mark.parametrize(('address', 'port', 'state'), [
    ('127.0.0.2', 18000, '0A'), ('127.0.0.1', 18001, '0A'), ('127.0.0.1', 18000, '01'),
])
def test_linux_rejects_socket_that_does_not_own_requested_listener(proc, address, port, state):
    _listener(proc, address, port, 500, state=state)
    _owner(proc, 4242, 500)
    assert orchestrator._port_listener_pid('127.0.0.1', 18000) is None


def test_linux_ambiguous_socket_ownership_does_not_authorize_one_pid(proc):
    _listener(proc, '127.0.0.1', 18000, 500)
    _owner(proc, 4242, 500)
    _owner(proc, 4243, 500)
    assert orchestrator._port_listener_pid('127.0.0.1', 18000) is None


def test_linux_disappearing_process_does_not_break_discovery(proc):
    _listener(proc, '127.0.0.1', 18000, 500)
    (proc / '4243').mkdir()
    _owner(proc, 4242, 500)
    assert orchestrator._port_listener_pid('127.0.0.1', 18000) == 4242


def test_linux_dual_stack_candidate_does_not_hide_ambiguous_ipv4_owner(proc):
    _listener(proc, '::', 18000, 500)
    _owner(proc, 4242, 500)
    _listener(proc, '127.0.0.1', 18000, 501)
    _owner(proc, 4243, 501)
    assert orchestrator._port_listener_pid('127.0.0.1', 18000) is None
