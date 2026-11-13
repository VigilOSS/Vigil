---
description: Deep-read question sets behind code-vulnerability-analysis Steps 2, 5 and 6 and its SAST-surviving bug classes (composition, sibling paths, state, protocol semantics, macros, conditional builds), for deep-manual dispatches, complex critical/high files, and any function where one of those classes appears
skill: code-vulnerability-analysis
---

# Code Hunt Deep-Audit Question Sets

Load this from `agent/skills/code-vulnerability-analysis/SKILL.md` on a `deep-manual` dispatch;
when a critical or high file that parses untrusted input, decides access, runs a protocol state
machine, mutates shared state, or allocates and frees heavily needs more than the core step text;
or when one of the skill's SAST-surviving bug classes appears. The skill's steps stay
authoritative. These questions are a floor for a line-by-line read, never a list of what to report
or a bound on what you look for.

## Step 2: Taint transformations

Carry taint through arithmetic and casts (wrap, truncation, sign change), accumulation against a
fixed capacity, a callee that writes a buffer with an untrusted size, struct fields (every later
read of the field is tainted), array indexes (propagation and sink at once), return values, and
globals or statics written by another thread or an earlier call.

## Step 5: Error paths

Enumerate every exit: early returns, `goto cleanup` labels, default cases, catch and finally
blocks, destructor side effects, signal handlers. At each one ask which fields were set and whether
the caller can tell this failure from another; which resources were acquired, which leak, and which
the caller releases again; whether the caller checks, propagates, or swallows the error and
continues as if it succeeded; whether the attacker can force the path with input, resource
exhaustion, a timeout, or an allocation failure; and what state a function two or three callers up
sees. Check each exit against the weaponizable error shapes in skill Step 5.

## Step 6: Escalation

- Caller assumptions about callees (always succeeds, already validated, return value in range):
  read the callee to check each one.
- Concurrent or nested failures, and cleanup that itself fails.
- Timing as an attacker input: arrival relative to a timeout, a delayed response widening a race
  window, a forced garbage collection at a chosen point.
- Valid but unexpected input: zero-length and maximum-length fields, NaN, Infinity, negative zero,
  empty arrays, NUL bytes mid-string, Unicode normalization differences.
- Defensive code that cannot fire from its callers: work out what the author feared and whether it
  is reachable somewhere the guard does not run.

## SAST-surviving classes

- **Composition.** Each function is correct alone and the chain is not: A validates a length, B
  adds a header, C copies the result. At every boundary compare the caller's postcondition with the
  callee's precondition, including arithmetic bounded per operand that overflows in combination
  (`validated_a + validated_b`, a validated size plus a header times an element count).
- **Incomplete patches and sibling paths.** A guard found on one path is a question for every
  sibling: other callers of the same function, other switch arms, protocol-variant handlers,
  copy-pasted code, platform-specific branches.
- **State and concurrency.** Trace every reader and writer of shared mutable state: freed memory a
  pending callback still references, a window between check and use, a multi-step transition that
  is not atomic.
- **Protocol semantics.** Compare behavior with the specification or documented business rule,
  especially where two parsers can disagree about where a message ends (proxy versus server), and
  at empty, maximum-length, nested, recursive, or conflicting fields.
- **Macro-hidden operations (C/C++).** Expand a macro before reasoning past it: a wrapper such as
  `COPY(dst, src, len)` or `SAFE_FREE(p)` hides `memcpy` or `free` from a name search, a
  `CHECK(x)` that contains `return` or `goto` changes control flow invisibly, and a variadic macro
  that forwards a format string is a format-string sink.
- **Conditional compilation.** A security guard has to exist in every `#if`/`#ifdef` branch that
  reaches the sink, not only the one you are reading. Check platform branches (`WIN32`,
  `__linux__`), where a bug can be platform-specific, and feature-flag branches, since a feature
  disabled by default may still be compiled and reachable.
