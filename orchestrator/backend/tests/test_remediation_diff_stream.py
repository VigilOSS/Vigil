import fcntl
import os
import subprocess
import sys

import pytest

from app.services import remediation


@pytest.mark.parametrize("payload,limit,expected,truncated", [
    (b"Acme patch\n", 100, b"Acme patch\n", False),
    (b"Acme patch\n", 4, b"Acme", True),
    (b"", 100, b"", False),
])
def test_review_diff_reads_high_numbered_pipe(monkeypatch, payload, limit, expected, truncated):
    command = [sys.executable, "-c", f"import sys; sys.stdout.buffer.write({payload!r})"]
    monkeypatch.setattr(remediation._vcs, "diff_command", lambda *_: command)
    popen = subprocess.Popen

    def high_pipe(*args, **kwargs):
        process = popen(*args, **kwargs)
        descriptor = fcntl.fcntl(process.stdout.fileno(), fcntl.F_DUPFD, 1100)
        process.stdout.close()
        process.stdout = os.fdopen(descriptor, "rb")
        return process

    monkeypatch.setattr(remediation.subprocess, "Popen", high_pipe)
    assert remediation._bounded_vcs_diff(".", "HEAD", limit=limit) == (expected, truncated)
