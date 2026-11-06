"""The assess CLI survives an output consumer that has already gone away.

`vigil assess` ``os.execvpe``s straight into ``assess.cli.main``
(``vigil_cli/main.py`` -> ``agent/scripts/assess.py``), so ``main`` is the
outermost Python frame for every assess verb. It only ever handled
``AssessError``, which left `foo | head` — and the `2>&1 | head` that turned a
committed `code-dispatch` claim into a lease with no local record — raising
``BrokenPipeError`` out of the first write and killing the process mid-work.

Two failures, both covered here:

  * the exit status was the interpreter's own unhandled-exception 1, not the
    shell's SIGPIPE convention, and
  * CPython's teardown flush hit the dead pipe a second time and printed
    ``Exception ignored in: <_io.TextIOWrapper name='<stdout>' ...>`` — noise on
    a stream whose reader is gone, which a caller cannot act on.

Both reach every exit path, not just the verbs that return: a verb ending in
``sys.exit(N)`` — 515 call sites across 78 modules under
``agent/scripts/assess`` end that way — and the ``print_help`` / action-help
paths in ``cli.main`` itself raise
``SystemExit`` straight past the in-guard flush, which left exactly the
``Exception ignored while flushing sys.stdout`` and status 120 the guard exists
to answer. The status those paths choose is a contract while the body is
DELIVERED, so the flush re-raises the same ``SystemExit``.

ONE rule decides the status when it was not: a proven dead pipe exits 141
whatever ending the command had — a refusal, any of the 515 ``sys.exit(N)``
sites, a documented kali status, a clean return — and the diagnostic that
reached stderr still stands beside it. A status that depended on which branch
of the guard the command left through would make the same lost pipeline report
``1`` or ``141`` according to nothing the caller can see.

A guard that cannot prove the output stream is a pipe with no reader re-raises,
so an ``EPIPE`` from anywhere else stays the loud failure it is — and an output
failure that is not ``EPIPE`` at all (``ENOSPC`` on a full disk, ``EIO``,
``EBADF``) is never relabelled as a departed reader: it keeps the command's own
status.
"""
from __future__ import annotations

import errno
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from assess import cli

_REPO_ROOT = str(Path(__file__).resolve().parents[4])

# A child that enters the real outermost frame, exactly as `assess.py` does.
_BOOTSTRAP = textwrap.dedent(
    f"""
    import sys
    sys.path.insert(0, {os.path.join(_REPO_ROOT, "agent", "scripts")!r})
    sys.path.insert(0, {os.path.join(_REPO_ROOT, "src")!r})
    from assess.cli import main
    main()
    """
)

# A child whose stdout holds undelivered bytes and whose fd 1 is open but
# unwritable — the read end of a pipe duplicated over it, so every write is
# `EBADF`, a full disk or a closed descriptor rather than a departed reader. fd
# 1 stays OPEN on purpose: `_silence_closed_output` opens /dev/null and would
# otherwise be handed fd 1 itself as the lowest free descriptor.
_BOOTSTRAP_UNWRITABLE_STDOUT_REFUSAL = textwrap.dedent(
    f"""
    import os, sys
    sys.path.insert(0, {os.path.join(_REPO_ROOT, "agent", "scripts")!r})
    sys.path.insert(0, {os.path.join(_REPO_ROOT, "src")!r})
    from assess.cli import main
    from assess.commands import contract
    from assess.lib.client import AssessError

    def refuse(_args):
        print("x" * 1000)  # buffered, under the 8KB block buffer: no write yet
        raise AssessError("the backend refused this write")

    contract.run = refuse
    read_fd, _write_fd = os.pipe()
    os.dup2(read_fd, 1)
    main(["contract", "finding", "record"])
    """
)

# A child that stages one verb of the test's choosing and runs it through the
# real outermost frame. Composed by join rather than dedent so the verb body
# keeps its own indentation.
_BOOTSTRAP_PRELUDE = "\n".join(
    [
        "import os, sys",
        f"sys.path.insert(0, {os.path.join(_REPO_ROOT, 'agent', 'scripts')!r})",
        f"sys.path.insert(0, {os.path.join(_REPO_ROOT, 'src')!r})",
        "from assess.cli import main",
        "from assess.commands import contract",
        "from assess.lib.client import AssessError",
    ]
)


def _bootstrap_with_verb(body: str) -> str:
    """A child whose `contract finding record` is ``body``."""
    return "\n".join(
        [
            _BOOTSTRAP_PRELUDE,
            body,
            "contract.run = _verb",
            'main(["contract", "finding", "record"])',
        ]
    )


# Each ending a verb can have, over a stdout consumer that has already gone
# away. The buffered body is under the 8KB block buffer, so it is still
# undelivered when the ending runs. ``sys.exit(3)`` is a documented kali status
# (`KALI_EXIT_CODES`), whose epilog says those statuses are "also reported as
# `.status` in the JSON on stdout" — the JSON that never arrived.
_VERB_ENDINGS = [
    pytest.param(
        'def _verb(_a):\n    print("x" * 1000)\n'
        '    raise AssessError("the backend refused this write")',
        "ERROR: the backend refused this write\n",
        id="AssessError",
    ),
    pytest.param(
        'def _verb(_a):\n    print("x" * 1000)\n    sys.exit(0)', "", id="sys.exit(0)"
    ),
    pytest.param(
        'def _verb(_a):\n    print("x" * 1000)\n    sys.exit(1)', "", id="sys.exit(1)"
    ),
    pytest.param(
        'def _verb(_a):\n    print("x" * 1000)\n    sys.exit(3)', "", id="kali-status-3"
    ),
    pytest.param('def _verb(_a):\n    print("x" * 1000)', "", id="clean-return"),
]

# The same endings over an fd 1 that is OPEN but UNWRITABLE — the read end of a
# pipe duplicated over it, so every write is `EBADF`: a closed descriptor or a
# full disk rather than a departed reader. Each keeps the status the command
# chose, because 141 would report a cause that is not the one to act on; a
# would-be 0 becomes 1, because output that never arrived is not success.
_BOOTSTRAP_UNWRITABLE_STAGE = "\n".join(
    [
        "contract.run = _verb",
        "read_fd, _write_fd = os.pipe()",
        "os.dup2(read_fd, 1)",
        'main(["contract", "finding", "record"])',
    ]
)
_UNWRITABLE_STDOUT_ENDINGS = [
    pytest.param(
        'def _verb(_a):\n    print("x" * 1000)\n'
        '    raise AssessError("the backend refused this write")',
        1,
        id="AssessError",
    ),
    pytest.param('def _verb(_a):\n    print("x" * 1000)\n    sys.exit(0)', 1, id="exit-0"),
    pytest.param('def _verb(_a):\n    print("x" * 1000)\n    sys.exit(3)', 3, id="kali-status-3"),
    pytest.param('def _verb(_a):\n    print("x" * 1000)', 1, id="clean-return"),
]

# `contract finding record` writes ~48KB to stdout, needs no engagement and no
# backend, so the only thing under test is what happens to the writes.
_STDOUT_VERB = ["contract", "finding", "record"]

# The same, for a verb that ends in `sys.exit`. The bare `kali` dispatcher is
# registered through `set_defaults(func=...)` like every other verb, writes its
# ~4.8KB help to stdout, and ends in `sys.exit(1)` — no engagement, no backend.
_STDOUT_VERB_THAT_EXITS = ["kali"]
_STDOUT_VERB_THAT_EXITS_STATUS = 1

# Help that `cli.main` writes BEFORE it dispatches a verb: `code-dispatch
# <action> --help` is rendered pre-parse (argparse.REMAINDER would otherwise
# swallow the flag as data) and raises SystemExit(0), and a bare `vigil assess`
# prints the root help and exits 1. Same stdout, same SystemExit, so the guard
# has to cover them too.
_PRE_DISPATCH_HELP = [
    (["code-dispatch", "stats", "--help"], 0),
    ([], 1),
]

_SIGPIPE_EXIT = 141


def _run_with_closed_stdout(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one verb with stdout pointed at a pipe whose reader is already gone.

    stderr is left on a live pipe on purpose: it is where CPython would print
    its teardown complaint, so the test can read the noise it is asserting the
    absence of.
    """
    return _run_script_with_closed_stdout(_BOOTSTRAP, argv)


def _run_script_with_closed_stdout(
    script: str, argv: list[str] | None = None
) -> subprocess.CompletedProcess[str]:
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        return subprocess.run(
            [sys.executable, "-c", script, *(argv or ())],
            stdout=write_fd,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    finally:
        os.close(write_fd)


def _run_with_live_stdout(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """The same child with a reader that is still there — the normal path."""
    return subprocess.run(
        [sys.executable, "-c", _BOOTSTRAP, *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )


def test_closed_stdout_consumer_exits_on_the_sigpipe_convention() -> None:
    result = _run_with_closed_stdout(_STDOUT_VERB)

    assert result.returncode == _SIGPIPE_EXIT, (
        f"expected {_SIGPIPE_EXIT} (128 + SIGPIPE); got {result.returncode} "
        f"with stderr:\n{result.stderr}"
    )


def test_closed_stdout_consumer_prints_no_interpreter_teardown_noise() -> None:
    result = _run_with_closed_stdout(_STDOUT_VERB)

    assert "Exception ignored" not in result.stderr
    assert "BrokenPipeError" not in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stderr == "", f"unexpected stderr:\n{result.stderr}"


def test_a_verb_that_ends_in_sys_exit_is_guarded_like_one_that_returns() -> None:
    """`sys.exit` raises past the in-guard flush; the buffered body is still lost.

    A real child process, because the failure under test only exists in one:
    the second flush is CPython's own finalization, which no in-process harness
    can stage.
    """
    result = _run_with_closed_stdout(_STDOUT_VERB_THAT_EXITS)

    assert result.returncode == _SIGPIPE_EXIT, (
        f"expected {_SIGPIPE_EXIT} (128 + SIGPIPE); got {result.returncode} "
        f"with stderr:\n{result.stderr}"
    )
    assert "Exception ignored" not in result.stderr
    assert result.stderr == "", f"unexpected stderr:\n{result.stderr}"


@pytest.mark.parametrize("argv,status", _PRE_DISPATCH_HELP)
def test_help_written_before_the_verb_dispatch_is_guarded_too(
    argv: list[str], status: int
) -> None:
    """`cli.main` writes to stdout before it dispatches, so the guard opens first."""
    result = _run_with_closed_stdout(list(argv))

    assert result.returncode == _SIGPIPE_EXIT, (
        f"{argv or ['<no command>']}: expected {_SIGPIPE_EXIT}; got "
        f"{result.returncode} with stderr:\n{result.stderr}"
    )
    assert result.stderr == "", f"unexpected stderr:\n{result.stderr}"
    # The status the path chooses is what a live consumer still sees.
    assert _run_with_live_stdout(list(argv)).returncode == status


def test_a_live_consumer_still_sees_the_status_the_verb_chose() -> None:
    """141 is the departed-reader answer ONLY; nothing else may acquire it.

    The flush the guard adds for the `sys.exit` path re-raises the same
    ``SystemExit``, so the status each of the 515 call sites chose is the
    status that exits.
    """
    result = _run_with_live_stdout(_STDOUT_VERB_THAT_EXITS)

    assert result.returncode == _STDOUT_VERB_THAT_EXITS_STATUS, (
        f"expected {_STDOUT_VERB_THAT_EXITS_STATUS}; got {result.returncode} "
        f"with stderr:\n{result.stderr}"
    )
    assert result.stdout, "the verb under test is supposed to write to stdout"
    assert _run_with_live_stdout(_STDOUT_VERB).returncode == 0


def test_the_added_flush_does_not_rewrite_an_arbitrary_verb_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any ``sys.exit(N)``, not just the statuses a real verb happens to use."""
    from assess.commands import contract

    def _print_then_exit(_args) -> None:
        print("x" * 4096)
        sys.exit(7)

    monkeypatch.setattr(contract, "run", _print_then_exit)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["contract", "finding", "record"])

    assert exc_info.value.code == 7


class _DeadStream:
    """A stream whose every write path reports the reader has gone."""

    def flush(self) -> None:
        raise BrokenPipeError(32, "Broken pipe")

    def write(self, _text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")

    def fileno(self) -> int:
        # A real descriptor number so the redirect is observable; `os.dup2` is
        # recorded rather than performed, so nothing is actually touched.
        return 1


def test_a_broken_output_stream_is_silenced_before_the_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The descriptors are redirected BEFORE exiting, or shutdown re-raises."""
    from assess.commands import contract

    redirected: list[int] = []

    def _boom(_args) -> None:
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(contract, "run", _boom)
    monkeypatch.setattr(sys, "stdout", _DeadStream())
    # Recorded rather than performed: a real dup2 here would point pytest's own
    # captured descriptors at /dev/null for the rest of the session.
    monkeypatch.setattr(os, "dup2", lambda _src, dst: redirected.append(dst))

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["contract", "finding", "record"])

    assert exc_info.value.code == _SIGPIPE_EXIT
    assert redirected, "output descriptors were not silenced before the exit"


def test_a_broken_pipe_that_is_not_the_output_stream_is_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A writable stdout/stderr means the EPIPE came from somewhere else.

    Reporting that as "the reader went away" would hide a real failure behind an
    exit status that says nothing happened, so it keeps propagating.
    """
    from assess.commands import contract

    def _boom(_args) -> None:
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(contract, "run", _boom)

    with pytest.raises(BrokenPipeError):
        cli.main(["contract", "finding", "record"])


# An output stream can fail for reasons that have nothing to do with a reader:
# a full disk (`ENOSPC`), a media error (`EIO`), a descriptor that was closed
# underneath the process (`EBADF`), a `ValueError` from a closed file object.
# 141 and the silent teardown would tell the operator "your reader went away"
# and bury the cause they have to act on, so only `EPIPE` counts as proof.
_NOT_A_DEAD_PIPE = [
    pytest.param(OSError(errno.ENOSPC, "No space left on device"), id="ENOSPC"),
    pytest.param(OSError(errno.EIO, "Input/output error"), id="EIO"),
    pytest.param(OSError(errno.EBADF, "Bad file descriptor"), id="EBADF"),
    pytest.param(ValueError("I/O operation on closed file"), id="closed-file"),
]


class _FailingStream:
    """A stream whose writes fail for a given, non-``EPIPE`` reason."""

    def __init__(self, failure: BaseException) -> None:
        self._failure = failure

    def flush(self) -> None:
        raise self._failure

    def write(self, _text: str) -> int:
        raise self._failure

    def fileno(self) -> int:
        return 1


@pytest.mark.parametrize("failure", _NOT_A_DEAD_PIPE)
def test_an_output_failure_that_is_not_epipe_is_not_called_a_departed_reader(
    failure: BaseException, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full disk plus an EPIPE from a socket is a full disk, not `| head`."""
    from assess.commands import contract

    redirected: list[int] = []

    def _socket_epipe(_args) -> None:
        # EPIPE from a socket or worker pipe — not from the output stream.
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    monkeypatch.setattr(contract, "run", _socket_epipe)
    monkeypatch.setattr(sys, "stdout", _FailingStream(failure))
    monkeypatch.setattr(os, "dup2", lambda _src, dst: redirected.append(dst))

    with pytest.raises(BrokenPipeError):
        cli.main(["contract", "finding", "record"])

    assert not redirected, (
        "a non-EPIPE output failure was silenced as if the reader had gone"
    )


@pytest.mark.parametrize("failure", _NOT_A_DEAD_PIPE)
def test_the_guard_answers_broken_only_for_a_pipe_with_no_reader(
    failure: BaseException, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The probe itself: positive proof is an ``EPIPE`` on the residue, nothing else."""
    monkeypatch.setattr(sys, "stdout", _FailingStream(failure))
    assert cli._output_stream_is_broken() is False
    # Still residue, though: the shutdown flush will fail on it either way, so
    # the two questions have to be answered separately.
    assert cli._failed_output_flush() is failure

    monkeypatch.setattr(sys, "stdout", _FailingStream(BrokenPipeError(errno.EPIPE, "Broken pipe")))
    assert cli._output_stream_is_broken() is True


def test_a_clean_output_stream_reports_no_residue() -> None:
    """Both streams flushing means nothing is left for shutdown to trip over."""
    assert cli._failed_output_flush() is None


def test_a_refusal_keeps_its_status_over_an_unwritable_stdout() -> None:
    """A delivered refusal must not lose status 1 to the interpreter's 120.

    An unwritable descriptor is NOT a departed reader, so the SIGPIPE status
    would misreport the cause: status 1 is the answer, and it depends on the
    undelivered stdout body being taken off shutdown's hands. Residue is
    residue whether a reader went away or the descriptor stopped accepting
    writes, so a real child proves it: in-process nothing can stage CPython's
    own finalization flush.
    """
    result = subprocess.run(
        [sys.executable, "-c", _BOOTSTRAP_UNWRITABLE_STDOUT_REFUSAL],
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )

    assert result.returncode == 1, (
        f"expected 1 (Vigil refused); got {result.returncode} with stderr:\n"
        f"{result.stderr}"
    )
    assert result.stderr == "ERROR: the backend refused this write\n", (
        f"unexpected stderr:\n{result.stderr}"
    )


def test_a_refusal_written_into_a_closed_consumer_is_also_guarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`except AssessError`'s own stderr write is the same failure one layer up."""
    from assess.commands import contract
    from assess.lib.client import AssessError

    redirected: list[int] = []

    def _refuse(_args) -> None:
        raise AssessError("the backend refused this write")

    monkeypatch.setattr(contract, "run", _refuse)
    monkeypatch.setattr(sys, "stderr", _DeadStream())
    monkeypatch.setattr(os, "dup2", lambda _src, dst: redirected.append(dst))

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["contract", "finding", "record"])

    # Nothing could be reported, so the departed reader IS the outcome here.
    assert exc_info.value.code == _SIGPIPE_EXIT
    assert redirected, "output descriptors were not silenced before the exit"


@pytest.mark.parametrize("verb_body,expected_stderr", _VERB_ENDINGS)
def test_one_departed_reader_rule_for_every_ending_a_verb_can_have(
    verb_body: str, expected_stderr: str
) -> None:
    """Undeliverable output is answered with 141 whatever the ending was.

    A refusal, a ``sys.exit(N)`` from any of the 515 call sites, a documented
    kali status and a clean return are all the same situation for the caller:
    the bytes they asked for never arrived because they stopped reading. One
    rule covers them, so the status cannot depend on which branch of the guard
    the command happened to leave through — and the diagnostic that did reach
    stderr still stands beside it.
    """
    result = _run_script_with_closed_stdout(_bootstrap_with_verb(verb_body))

    assert result.returncode == _SIGPIPE_EXIT, (
        f"expected {_SIGPIPE_EXIT} (128 + SIGPIPE); got {result.returncode} "
        f"with stderr:\n{result.stderr}"
    )
    assert result.stderr == expected_stderr, f"unexpected stderr:\n{result.stderr}"
    assert "Exception ignored" not in result.stderr


@pytest.mark.parametrize("verb_body,status", _UNWRITABLE_STDOUT_ENDINGS)
def test_an_unwritable_stdout_keeps_the_status_and_the_quiet(
    verb_body: str, status: int
) -> None:
    """The other half of the rule, over every ending a verb can have.

    A descriptor that stopped accepting writes is not a departed reader, so the
    status must not say it was — but the undelivered body still has to come off
    the interpreter's hands, or its finalization code answers for the command
    with 120 and a traceback over a stream the caller cannot act on.
    """
    result = _run_script_with_closed_stdout(
        "\n".join(
            [_BOOTSTRAP_PRELUDE, verb_body, _BOOTSTRAP_UNWRITABLE_STAGE]
        )
    )

    assert result.returncode == status, (
        f"expected {status}; got {result.returncode} with stderr:\n{result.stderr}"
    )
    assert "Traceback" not in result.stderr, f"unexpected stderr:\n{result.stderr}"
    assert "Exception ignored" not in result.stderr, (
        f"unexpected stderr:\n{result.stderr}"
    )


def test_a_delivered_refusal_over_a_dead_stdout_follows_the_same_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The in-process counterpart: the `AssessError` branch obeys the one rule.

    ``ERROR:`` on stderr is what tells the operator Vigil refused; the status
    tells the caller its output is missing. Both are true at once, so the
    refusal text is reported AND the departed reader sets the status.
    """
    from assess.commands import contract
    from assess.lib.client import AssessError

    redirected: list[int] = []

    def _refuse(_args) -> None:
        raise AssessError("the backend refused this write")

    monkeypatch.setattr(contract, "run", _refuse)
    monkeypatch.setattr(sys, "stdout", _DeadStream())
    monkeypatch.setattr(os, "dup2", lambda _src, dst: redirected.append(dst))

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["contract", "finding", "record"])

    assert exc_info.value.code == _SIGPIPE_EXIT
    assert redirected, "the dead stdout was not silenced before the exit"


# A child that stages the residue, closes fd 1 underneath itself and then asks
# the guard to take the dead stream off the interpreter's hands. `os.open`
# returns the LOWEST free descriptor, so with fd 1 closed it is handed fd 1
# itself — the one case the function exists for.
_BOOTSTRAP_SILENCE_A_CLOSED_DESCRIPTOR = "\n".join(
    [
        "import os, sys",
        f"sys.path.insert(0, {os.path.join(_REPO_ROOT, 'agent', 'scripts')!r})",
        f"sys.path.insert(0, {os.path.join(_REPO_ROOT, 'src')!r})",
        "from assess.cli import _silence_closed_output",
        'print("x" * 1000)',  # buffered, under the 8KB block buffer: no write yet
        "os.close(1)",  # the descriptor goes away with the body still in the buffer
        "_silence_closed_output()",
        'print("the diagnostic survives", file=sys.stderr)',
        "sys.exit(1)",
    ]
)


def test_silencing_a_closed_stdout_leaves_the_diagnostic_stream_alone() -> None:
    """`vigil assess ... >&-`: fd 1 is CLOSED, not a pipe with no reader.

    A real child, because the failure is CPython's own finalization flush,
    which no in-process harness can stage. Two things have to hold: stderr is
    still the operator's stderr afterwards, and the undelivered stdout body no
    longer costs the command its exit status.
    """
    result = subprocess.run(
        [sys.executable, "-c", _BOOTSTRAP_SILENCE_A_CLOSED_DESCRIPTOR],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )

    assert result.stderr == "the diagnostic survives\n", (
        f"the complaint did not survive the redirect; stderr:\n{result.stderr}"
    )
    assert result.returncode == 1, (
        f"expected the command's own status 1; got {result.returncode} "
        f"(120 is the interpreter's finalization failure) with stderr:\n"
        f"{result.stderr}"
    )


def test_the_sigpipe_exit_code_collides_with_no_other_assess_exit_code() -> None:
    """141 is 128 + SIGPIPE and must stay distinct from the verb statuses."""
    from assess.lib.kali_output import KALI_EXIT_CODES

    assert _SIGPIPE_EXIT not in set(KALI_EXIT_CODES.values()) | {0, 1, 2}
    assert cli._SIGPIPE_EXIT_CODE == _SIGPIPE_EXIT
