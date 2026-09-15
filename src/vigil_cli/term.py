"""Terminal presentation for a CLI whose output has two audiences.

Vigil's stdout and stderr are read by an operator at a terminal **and** by
machines: `vigil assess`, `vigil status`/`doctor`, and the operator prompts
under `agent/` all consume CLI text. Those two readers want opposite things. A
human wants the 80-column terminal to stop breaking `vigil install` into
``vigil insta``/``ll`` mid-word, and wants severity visible at a glance. A model
(or a `grep`, or a redirected install log read back a week later) wants one
logical message per line, a stable ``key<TAB>value`` shape, and not one byte it
has to learn to discard.

The rule this module encodes is therefore asymmetric, and the asymmetry is the
whole point:

* **On a TTY** — escape codes, glyphs, and wrapping are free, because the only
  reader is the operator standing there.
* **Off a TTY** — the output is the same as, or shorter than, the unstyled line
  it replaced. No ESC byte, no soft wrap, no glyph. :func:`wrap` returns its
  input untouched precisely so a piped record stays one greppable line, and
  :func:`row` degrades to the ``OK``/``WARN``/``FAIL``/``INFO`` + tab shape
  that ``status.print_status`` already emits.

That is why styling lives behind functions rather than at the call sites: a
``print(f"\\033[31m...")`` sprinkled through the CLI cannot make this promise,
and the cost of breaking it is not ugly output — it is a prompt or a parser
that silently mis-reads Vigil's own state.

The two opt-outs are not interchangeable. ``NO_COLOR`` (any value, including
empty — the convention is presence-based) withdraws *colour* only, so a
terminal that set it still gets wrapped, legible output. ``TERM=dumb`` says the
terminal cannot be laid out at all and withdraws both. ``COLUMNS`` overrides the
detected width, via :func:`shutil.get_terminal_size`.

Style and state names are validated *before* the TTY check, so a typo fails
identically piped and interactive rather than lying dormant until someone runs
the command on a real terminal.
"""
from __future__ import annotations

import os
import shutil
import sys
import textwrap
from typing import TextIO

# Narrower than this and wrapping shreds prose into near-vertical text; wider
# and long lines stop being scannable. Both bounds exist because a terminal is
# free to report an absurd width (a 20-column pane, a 400-column ultrawide).
MIN_WIDTH = 40
MAX_WIDTH = 100

_RESET = "\x1b[0m"

# Select Graphic Rendition parameters. Deliberately the 8-color set: it renders
# correctly on every terminal Vigil is likely to meet, including a 16-color
# console and an ssh session with a minimal TERM.
_SGR_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "cyan": "36",
}

# Glyph + color per state for the human, plain word for the machine. The info
# bullet is deliberately uncolored-but-dim: it carries no severity, and giving
# it one would make a neutral row compete with a real WARN for attention.
_ROW_STATES = {
    "ok": ("✔", "green", "OK"),
    "warn": ("!", "yellow", "WARN"),
    "fail": ("✘", "red", "FAIL"),
    "info": ("•", "dim", "INFO"),
}


def is_terminal(stream: TextIO) -> bool:
    """True when `stream` is an interactive terminal that can render a layout.

    This is the *width* gate, and it is deliberately not the colour gate.
    ``NO_COLOR`` says the operator does not want escape codes; it does not say
    their terminal stopped being 80 columns wide, and answering it by also
    switching wrapping off would hand them back the mid-word breaks
    (``vigil insta``/``ll``) this module exists to prevent. ``TERM=dumb`` is
    different in kind — it says the terminal cannot be laid out at all — so it
    disables both.

    Never raises: a stream with no ``isatty`` (a test double, a captured
    buffer) or one whose ``isatty`` raises (a closed or detached file) is
    treated as not-a-terminal. Presentation is decoration, and decoration must
    never be the reason a command dies.
    """
    if os.environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except Exception:
        return False


def supports_style(stream: TextIO) -> bool:
    """True when `stream` is a terminal that wants escape codes.

    Everything :func:`is_terminal` requires, plus the operator not having opted
    out of colour via ``NO_COLOR`` (any value, including empty — the convention
    is presence-based).
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    return is_terminal(stream)


def paint(text: str, *styles: str, stream: TextIO = sys.stderr) -> str:
    """Wrap `text` in SGR codes for `stream`, or return it unchanged off a TTY.

    All styles collapse into one escape sequence so the result costs exactly two
    escape sequences however many styles are named.
    """
    codes = [_style_code(style) for style in styles]
    if not codes or not supports_style(stream):
        return text
    return f"\x1b[{';'.join(codes)}m{text}{_RESET}"


def wrap(text: str, *, indent: str = "", stream: TextIO = sys.stderr) -> str:
    """Fill `text` to the terminal width, or return the single line off a TTY.

    `indent` prefixes continuation lines only, so a wrapped diagnostic stays
    visually hung under its ``[vigil] `` marker. Words are never broken and
    hyphens are never split points: the tokens being wrapped here are commands
    and config keys an operator has to copy verbatim.

    Off a TTY the text is returned exactly as given — one record, one line —
    because that is what a pipe, a redirected log, and a model reading `vigil`
    output all parse against. Gated on :func:`is_terminal`, not
    :func:`supports_style`: an operator who set ``NO_COLOR`` asked for no
    colour, not for their 80-column terminal to break commands mid-word.
    """
    if not is_terminal(stream):
        return text
    return textwrap.fill(
        text,
        width=_width(),
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def row(state: str, label: str, detail: str = "", *, stream: TextIO = sys.stderr) -> str:
    """One status row, in the reader's own vocabulary.

    On a TTY: a colored glyph, the label, and a dim detail. Off a TTY: the plain
    state word, the label, and the detail, tab-separated — the ``key<TAB>value``
    shape ``status.print_status`` already emits, so a machine reader parses
    doctor rows and these rows the same way. An empty `detail` emits no trailing
    separator, so the field count matches the fields present.
    """
    try:
        glyph, color, word = _ROW_STATES[state]
    except KeyError:
        raise ValueError(
            f"unknown row state {state!r}; expected one of {', '.join(sorted(_ROW_STATES))}"
        ) from None
    if not is_terminal(stream):
        # `is_terminal`, not `supports_style`: this chooses a LAYOUT — a glyph
        # row versus the machine `key<TAB>value` record. NO_COLOR asks for no
        # colour, not for the machine shape, and the `paint` calls below already
        # self-gate, so a NO_COLOR terminal gets an uncoloured glyph row while a
        # pipe still gets bytes identical to before.
        return f"{word}\t{label}\t{detail}" if detail else f"{word}\t{label}"
    rendered = f"{paint(glyph, color, stream=stream)} {label}"
    if detail:
        rendered = f"{rendered}  {paint(detail, 'dim', stream=stream)}"
    return rendered


def _style_code(style: str) -> str:
    try:
        return _SGR_CODES[style]
    except KeyError:
        raise ValueError(
            f"unknown style {style!r}; expected one of {', '.join(sorted(_SGR_CODES))}"
        ) from None


def _width() -> int:
    """The wrap width, clamped. ``get_terminal_size`` reads ``COLUMNS`` first and
    falls back to 80 when no terminal answers, which is the behavior we want."""
    return max(MIN_WIDTH, min(MAX_WIDTH, shutil.get_terminal_size().columns))
