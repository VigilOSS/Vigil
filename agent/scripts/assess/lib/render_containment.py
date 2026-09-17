"""Lossless containment for persisted text rendered into agent-read markdown.

Two commands render the operator's durable state back to an agent that reads it
as its operating picture: `vigil assess resume-brief` and
`vigil assess operator-checkpoint show` (which the brief also embeds). Every
string column the backend stores is bounded by `max_length` and nothing else —
`DispatchCreate.agent_id`, `DecisionCreate.kind`, an artifact path — so stored
bytes reach those documents carrying whatever line separators the writer put in
them, and a continuation that starts at column zero impersonates one of the
document's own section boundaries.

Containment lives here, in one place, because both renderers need it and
`resume_brief` already imports the checkpoint renderers from
`operator_checkpoint` (so the reverse import would close a cycle). It is
containment, not masking: ADR 0019 forbids hiding the operator's own data from
the operator, so nothing here trims, collapses, escapes, or drops a character —
the only edit is the rendering indent inserted after a separator.
"""
from __future__ import annotations

import re

_CONTAINED_VALUE_INDENT = "    "
# Every boundary `str.splitlines()` recognises, CRLF first so it is contained as
# one separator rather than two. The set is chosen by the reader, not by
# aesthetics: "nothing reaches column zero" is only true for separators the
# reader splits on, and a Python consumer of this stdout splits on all eleven.
# A pattern covering only CR/LF/U+2028/U+2029 left VT, FF, FS, GS, RS and NEL
# able to start a line in a document an agent reads as its operating picture.
_RENDER_LINE_SEPARATOR = re.compile(
    r"\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]"
)


def contain_separators(text: str, *, indent: str = _CONTAINED_VALUE_INDENT) -> str:
    """Indent whatever follows every line separator, so nothing reaches column zero.

    `indent` exists because the checkpoint's intent note sits one list level
    deeper than the reference rows; the separator SET is deliberately not a
    parameter, so every renderer contains the same characters.
    """
    return _RENDER_LINE_SEPARATOR.sub(lambda match: f"{match.group(0)}{indent}", text)


def append_contained_value(lines: list, label: str, value: object) -> None:
    """Append untrusted persisted text losslessly inside a fixed-indent block.

    Decision payloads, dispatch tasks, and handoff summaries are operator-facing
    records, so ADR 0019 forbids truncating, collapsing, or masking them. They can
    also contain target-controlled line separators; emitted inline, a continuation
    beginning ``##`` could impersonate a resume-brief heading. Preserve every
    original character and insert only the rendering indent after every separator,
    including bare CR, VT/FF, the C0 separator controls, NEL, and the Unicode
    line/paragraph separators.

    BOTH halves are contained, not just the payload. Every caller builds `label`
    by interpolating persisted columns — `kind`, `agent_id`, `agent_role`,
    `status` — and `DecisionCreate.kind` is deliberately an unconstrained string
    ("the table just stores the bytes"), so a newline in one of those escaped the
    block through the label and forged a heading in a brief an agent reads as
    instructions.
    """
    lines.extend(
        [
            contain_separators(label),
            f"{_CONTAINED_VALUE_INDENT}{contain_separators(str(value))}",
        ]
    )
