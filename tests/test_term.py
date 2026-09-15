"""Behavior tests for ``vigil_cli.term``.

The load-bearing invariant is the dual audience: every assertion about a
non-TTY stream is an assertion about what an LLM reader (``vigil assess``,
``vigil status``, the `agent/` operator prompts) will parse. A styled byte, a
soft-wrapped record, or a glyph in that path is a parser bug, not a cosmetic
one, so those cases are asserted as hard contracts (no ESC byte, one line, not
longer than the plain text).
"""
from __future__ import annotations

import inspect
import io
import sys

import pytest

from vigil_cli import term

ESC = "\x1b"


class FakeStream(io.StringIO):
    """A stream whose TTY-ness is ours to choose."""

    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class NoIsattyStream:
    """A file-like object that never grew an ``isatty`` (e.g. a test double)."""

    def write(self, text: str) -> int:
        return len(text)


class RaisingStream:
    """A closed/detached stream: ``isatty`` raises rather than answering."""

    def isatty(self) -> bool:
        raise ValueError("I/O operation on closed file")


@pytest.fixture(autouse=True)
def _styled_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """A baseline where styling is permitted, so each test opts out explicitly.

    The operator's own shell may export ``NO_COLOR`` or ``TERM=dumb``; without
    this the TTY assertions would silently pass for the wrong reason.
    """
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", "80")


def test_supports_style_true_for_a_tty() -> None:
    assert term.supports_style(FakeStream(tty=True)) is True


def test_supports_style_false_for_a_pipe() -> None:
    assert term.supports_style(FakeStream(tty=False)) is False


def test_no_color_disables_style_even_when_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """The NO_COLOR convention is presence-based: ``NO_COLOR=`` still means no color."""
    monkeypatch.setenv("NO_COLOR", "")
    assert term.supports_style(FakeStream(tty=True)) is False


def test_term_dumb_disables_style(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERM", "dumb")
    assert term.supports_style(FakeStream(tty=True)) is False


def test_no_color_withdraws_color_but_not_wrapping(monkeypatch: pytest.MonkeyPatch) -> None:
    """NO_COLOR is about color. It must not hand back the mid-word breaks.

    An operator who exports NO_COLOR still has an 80-column terminal, and the
    hard-wrap this module exists to prevent (``vigil insta``/``ll``) is not a
    color. Colour goes; layout stays.
    """
    monkeypatch.setenv("NO_COLOR", "1")
    stream = FakeStream(tty=True)
    assert term.supports_style(stream) is False
    assert term.is_terminal(stream) is True
    assert term.paint("text", "red", stream=stream) == "text"
    wrapped = term.wrap("word " * 40, stream=stream)
    assert "\n" in wrapped
    assert ESC not in wrapped
    assert all(len(line) <= 80 for line in wrapped.splitlines()), wrapped


def test_term_dumb_withdraws_wrapping_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """TERM=dumb says the terminal cannot be laid out, not merely uncolored."""
    monkeypatch.setenv("TERM", "dumb")
    stream = FakeStream(tty=True)
    assert term.is_terminal(stream) is False
    text = "word " * 40
    assert term.wrap(text, stream=stream) == text


def test_a_pipe_is_not_a_terminal() -> None:
    assert term.is_terminal(FakeStream(tty=False)) is False


def test_stream_without_isatty_is_not_styled() -> None:
    assert term.supports_style(NoIsattyStream()) is False  # type: ignore[arg-type]


def test_stream_whose_isatty_raises_is_not_styled() -> None:
    """Styling is decoration; it must never be the reason a command dies."""
    assert term.supports_style(RaisingStream()) is False  # type: ignore[arg-type]


@pytest.mark.parametrize("style", ["bold", "dim", "red", "yellow", "green", "cyan"])
def test_paint_emits_sgr_on_a_tty(style: str) -> None:
    painted = term.paint("hello", style, stream=FakeStream(tty=True))
    assert painted.startswith(ESC + "[")
    assert painted.endswith(ESC + "[0m")
    assert "hello" in painted


def test_paint_combines_styles_in_one_sequence() -> None:
    painted = term.paint("hello", "bold", "red", stream=FakeStream(tty=True))
    assert painted.count(ESC) == 2, painted
    assert painted == f"{ESC}[1;31mhello{ESC}[0m"


def test_paint_is_identity_when_piped() -> None:
    assert term.paint("hello", "bold", "red", stream=FakeStream(tty=False)) == "hello"


def test_paint_without_styles_is_identity_on_a_tty() -> None:
    assert term.paint("hello", stream=FakeStream(tty=True)) == "hello"


@pytest.mark.parametrize("tty", [True, False])
def test_paint_rejects_an_unknown_style_in_both_modes(tty: bool) -> None:
    """Validated before the TTY check on purpose: a style typo that only blew up
    on a real terminal would ship green through a piped CI run."""
    with pytest.raises(ValueError, match="unknown style"):
        term.paint("hello", "chartreuse", stream=FakeStream(tty=tty))


@pytest.mark.parametrize("tty", [True, False])
def test_row_rejects_an_unknown_state_in_both_modes(tty: bool) -> None:
    with pytest.raises(ValueError, match="unknown row state"):
        term.row("bogus", "docker", stream=FakeStream(tty=tty))


def test_wrap_fills_to_terminal_width_on_a_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "50")
    text = "word " * 40
    wrapped = term.wrap(text.strip(), stream=FakeStream(tty=True))
    assert "\n" in wrapped
    assert all(len(line) <= 50 for line in wrapped.splitlines()), wrapped


def test_wrap_honours_columns_over_a_wider_default(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "word " * 40
    monkeypatch.setenv("COLUMNS", "60")
    narrow = term.wrap(text.strip(), stream=FakeStream(tty=True))
    monkeypatch.setenv("COLUMNS", "100")
    wide = term.wrap(text.strip(), stream=FakeStream(tty=True))
    assert len(narrow.splitlines()) > len(wide.splitlines())


def test_wrap_clamps_an_absurdly_narrow_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "8")
    wrapped = term.wrap("word " * 40, stream=FakeStream(tty=True))
    widths = [len(line) for line in wrapped.splitlines()]
    assert max(widths) > 8, "a 8-column report must not shred output into one word per line"
    assert max(widths) <= term.MAX_WIDTH


def test_wrap_clamps_an_absurdly_wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "400")
    wrapped = term.wrap("word " * 200, stream=FakeStream(tty=True))
    assert max(len(line) for line in wrapped.splitlines()) <= term.MAX_WIDTH


def test_wrap_indents_continuation_lines_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "50")
    wrapped = term.wrap("word " * 40, indent="    ", stream=FakeStream(tty=True))
    lines = wrapped.splitlines()
    assert not lines[0].startswith(" ")
    assert all(line.startswith("    ") for line in lines[1:]), wrapped


def test_wrap_does_not_break_inside_a_command(monkeypatch: pytest.MonkeyPatch) -> None:
    """The defect this module exists to fix: a hard terminal wrap mid-token turned
    ``vigil install`` into ``vigil insta\\nll``, which cannot be copy-pasted."""
    monkeypatch.setenv("COLUMNS", "40")
    token = "vigil-config-set-oob.domain-<domain>-and-more"
    wrapped = term.wrap(f"prefix text here {token} suffix text", stream=FakeStream(tty=True))
    assert token in wrapped


def test_wrap_returns_one_unwrapped_record_when_piped() -> None:
    """A piped consumer greps line-by-line; a soft wrap would split one record."""
    text = "word " * 100
    wrapped = term.wrap(text.strip(), indent="    ", stream=FakeStream(tty=False))
    assert wrapped == text.strip()
    assert "\n" not in wrapped


@pytest.mark.parametrize(
    ("state", "word"),
    [("ok", "OK"), ("warn", "WARN"), ("fail", "FAIL"), ("info", "INFO")],
)
def test_row_is_tab_separated_plain_words_when_piped(state: str, word: str) -> None:
    """Matches the ``key\\tvalue`` house style of ``status.print_status``."""
    assert term.row(state, "oob.relay-route", "domain=x", stream=FakeStream(tty=False)) == (
        f"{word}\toob.relay-route\tdomain=x"
    )


def test_row_omits_the_empty_detail_field_when_piped() -> None:
    assert term.row("ok", "docker", stream=FakeStream(tty=False)) == "OK\tdocker"


@pytest.mark.parametrize("state", ["ok", "warn", "fail", "info"])
def test_row_is_styled_and_glyphed_on_a_tty(state: str) -> None:
    rendered = term.row(state, "docker", "running", stream=FakeStream(tty=True))
    assert ESC in rendered
    assert "docker" in rendered and "running" in rendered
    assert state.upper() not in rendered, "a TTY row shows a glyph, not the plain word"
    assert "\t" not in rendered, "tabs are the machine format; a TTY row is spaced prose"


def test_row_glyphs_are_distinct_per_state() -> None:
    stream = FakeStream(tty=True)
    rendered = {state: term.row(state, "x", stream=stream) for state in ("ok", "warn", "fail", "info")}
    assert len(set(rendered.values())) == 4, rendered


def test_piped_rendering_never_emits_an_escape_byte() -> None:
    """The hard contract for the LLM audience: zero style bytes off a TTY."""
    piped = FakeStream(tty=False)
    rendered = [
        term.paint("hello", "bold", "red", "green", stream=piped),
        term.wrap("word " * 100, indent="  ", stream=piped),
        term.row("ok", "docker", "running", stream=piped),
        term.row("fail", "oob.relay-route", "no route", stream=piped),
    ]
    assert not any(ESC in item for item in rendered), rendered


def test_piped_rendering_is_never_longer_than_the_plain_text() -> None:
    """Styling must cost zero bytes when piped — never one byte more than today's
    unstyled output for the same message."""
    piped = FakeStream(tty=False)
    message = "no OOB route allocated: `oob.domain` is not set"
    assert len(term.paint(message, "yellow", stream=piped)) == len(message)
    assert len(term.wrap(message, indent="        ", stream=piped)) == len(message)
    plain_row = "WARN\toob.relay-route\tno route"
    assert len(term.row("warn", "oob.relay-route", "no route", stream=piped)) == len(plain_row)


def test_piped_row_is_one_line_per_record() -> None:
    rendered = term.row("warn", "oob.relay-route", "a " * 200, stream=FakeStream(tty=False))
    assert "\n" not in rendered


def test_stream_defaults_to_stderr_where_the_diagnostics_go() -> None:
    """``paint``/``wrap``/``row`` default to stderr because that is where every
    ``[vigil] ...`` diagnostic and every doctor row is written. Callers that
    render for stdout must say so."""
    for function in (term.paint, term.wrap, term.row):
        default = inspect.signature(function).parameters["stream"].default
        assert default is sys.stderr, function.__name__
