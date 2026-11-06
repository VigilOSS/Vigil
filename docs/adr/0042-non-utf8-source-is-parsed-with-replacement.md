# ADR 0042 — Non-UTF-8 source is parsed with replacement

- Status: Accepted — implemented
- Date: 2026-11-05
- Amends: [ADR 0029](0029-structural-parsers-are-contained-with-honest-fallback.md), which
  listed invalid UTF-8 among the degraded outcomes.

## Context

Legacy repositories carry Latin-1 and Windows-1252 bytes in comments, strings and
templates. Treating one such byte as a reason to degrade the whole file sent it to
the streaming fallback, which records no callables, no call sites and only the
sinks its line patterns match. A PHP file with a `// Café` comment in Latin-1 lost
its functions and its dynamic-invocation sink.

The exact parser already reads bytes, and every text value it derives from them is
decoded with replacement. Its result for such a file passes the structural
validators, and its line counts and callable spans equal those of the UTF-8 twin,
because a replacement character never adds or removes a line break.

## Decision

The parser boundary no longer rejects source that is not valid UTF-8. The worker
parses the unchanged bytes, and a derived name, snippet or path shows U+FFFD where
a byte did not decode. A byte the grammar cannot accept in an identifier still
produces a syntax error and the existing degraded fallback.

Source that starts with a UTF-16 or UTF-32 byte order mark still takes the
streaming fallback, as `utf16_or_utf32_source`. The sealed snapshot counts its
lines in that encoding, so a byte-level parse would disagree with the snapshot's
line numbers.

## Consequences

- Single-byte legacy encodings keep their structural index and hints.
- Multi-byte legacy encodings (Shift-JIS, Big5, GBK) rely on the grammar's error
  recovery: a trailing byte of 0x5C can escape a quote and hide code inside a
  string, so their sinks and segments still owe review.
- A callable named by a string key can carry U+FFFD; that name is what the index
  publishes and what a receipt cites.
- The sealed raw source stays unchanged, as ADR 0029 requires.

## Alternatives considered

- **Keep degrading.** Rejected because it drops most hints for a byte that rarely
  matters to the code's behaviour.
- **Guess a legacy encoding and transcode.** Rejected because a wrong guess changes
  byte offsets and the parser would no longer read the sealed bytes.
