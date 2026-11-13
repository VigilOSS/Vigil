"""Once-per-run stderr notices for advisories that would otherwise repeat.

A run is one top-level invocation that executes many tools (a recon job and
every stage in it). :func:`notice_scope` opens the run; :func:`emit_once`
prints a notice the first time its key is seen in that run and returns False
afterwards. What has been printed lives in one environment variable, so a child
process the run spawns inherits it and does not print the same notice again.

Outside a scope every :func:`emit_once` prints, so a single command, a direct
library call and the test suite keep the plain behaviour. A caller whose
notice is suppressed must have said so the first time: the text passed in is
expected to name what is not repeated and where the per-run detail lives.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import sys
import uuid
from collections.abc import Iterator

ENV_VAR = "VIGIL_ASSESS_RUN_NOTICES"


def _shown() -> tuple[str, set[str]] | None:
    raw = os.environ.get(ENV_VAR)
    if not raw:
        return None
    run_id, _, keys = raw.partition(":")
    return run_id, {key for key in keys.split(",") if key}


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def in_scope() -> bool:
    return _shown() is not None


@contextlib.contextmanager
def notice_scope() -> Iterator[None]:
    """Open a run scope unless one is already open (nested calls reuse it)."""
    if in_scope():
        yield
        return
    os.environ[ENV_VAR] = f"{uuid.uuid4().hex}:"
    try:
        yield
    finally:
        os.environ.pop(ENV_VAR, None)


def emit_once(key: str, message: str, *, stream=None) -> bool:
    """Print ``message`` unless ``key`` was already printed in this run.

    Returns True when the message was printed.
    """
    target = stream if stream is not None else sys.stderr
    state = _shown()
    if state is None:
        print(message, file=target)
        return True
    run_id, keys = state
    digest = _digest(key)
    if digest in keys:
        return False
    keys.add(digest)
    os.environ[ENV_VAR] = f"{run_id}:{','.join(sorted(keys))}"
    print(message, file=target)
    return True
