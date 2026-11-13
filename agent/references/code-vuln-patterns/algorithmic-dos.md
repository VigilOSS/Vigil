---
description: Hash collision, ReDoS, parser bombs, unbounded allocation, zip bombs
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Algorithmic Denial of Service — Complexity Attacks

CWE-400, CWE-1333, CWE-776. Worst-case algorithmic behavior under adversarial input, not merely a
missing limit.

## What You're Hunting (LLM-Advantage Patterns)

### 1. Hash Collision DoS

C/C++ tables keyed by DJB2, FNV, or modular hashing without a per-process seed let an attacker
precompute colliding keys, turning n insertions into O(n²): HTTP header tables, cookie jars, DNS
caches, symbol tables. Python randomizes `str`/`bytes` hashes (since 3.3, SipHash since 3.4 via PEP
456), but `int` hashes are not randomized, so dicts keyed by attacker-chosen integers still collide;
a custom `__hash__` that delegates to `hash(str)` inherits the protection.

### 2. ReDoS

Backtracking engines (Python `re`, JavaScript `RegExp`, PCRE, Java, .NET) explode on near-matching
input when a quantified group can match the same text in more than one way: `(a+)+`, `(a|aa)+`,
`(\w+\s?)+$`, or two adjacent quantified groups with overlapping character classes. A required
literal separator between repetitions (`([a-z]+\.)+`) makes the split deterministic and is usually
not catastrophic; ambiguity is what to look for. Overlapping adjacent groups are often polynomial
rather than exponential, which still matters at large input sizes. Go `regexp` and Rust `regex` are
linear-time by construction, so the same pattern there is not a finding.

### 3. Recursive Parsers

Recursive-descent JSON, XML, or custom parsers without a depth counter overflow the stack on
`[[[[...` (C has no stack protection by default; checks must run before recursing). XML namespace
processing multiplies per-level work. protobuf C++ and Java enforce a default recursion limit of
100, but paths outside it can still recurse: CVE-2024-7254 (protobuf-java unknown-group parsing).

### 4. Unbounded Allocation

An attacker integer (Content-Length, array count, string length) sizes an allocation with only a
NULL check after it. Linux overcommit means the `malloc` may succeed and the damage arrives later as
memory pressure or the OOM killer. Cap the value in the parsing layer, where it can still become a
413, not in the allocator.

### 5. Quadratic String Building

`strcat` into a growing buffer rescans from the start each iteration; track the write offset and
`memcpy`. In Python, CPython often optimizes `s += t` in place when the string has a single
reference, so quadratic behavior depends on the implementation and on other references (PyPy, a
second reference); `"".join(parts)` is reliably linear.

### 6. Decompression Bombs

A small compressed input that inflates enormously: nested or overlapping zip entries
(`zipfile` `ZipInfo.file_size` is attacker-declared, so check the bytes actually produced while
streaming), gzip request bodies decompressed for `Content-Encoding: gzip` with no output cap, and
image headers declaring 100000x100000 pixels (PIL's `Image.MAX_IMAGE_PIXELS` raises
`DecompressionBombError` only beyond twice the limit and only warns between).

**Severity guardrail.** "Compressed input bypasses a named request limit" is not the finding. Prove
what the inflated bytes do downstream. If they stream through bounded buffers into linear parsing
that is equally reachable over another default transport, it is a resource-limit consistency or
hardening issue. High needs at least one second-order impact: superlinear CPU or worker exhaustion
under realistic concurrency; unbounded retained memory or disk after parsing; duplicate state that
escapes deduplication before expensive work; output amplification well beyond the inflated input;
a crash, memory corruption, or command execution in the downstream parser; or a bypass of an
independent default deployment boundary rather than a local spool cap. When the same logical stream
is accepted over SSH, raw TCP, or another default mode without the named limit, grade on the
downstream behavior, not the option name.

### 7. Loops That Do Not Advance

Each loop iteration should consume input or move state toward completion. The DoS shape is an
iteration that does neither: a zero-length record or TLV whose length field is 0, a `continue` that
skips the offset increment, or a reset transition that re-processes the same buffered message.
Endless HELLO/RESET cycles that each consume attacker bytes cost linear work per byte sent and are
not, by themselves, a finding.

## Language Notes

- **C/C++:** glibc `qsort` with a non-transitive comparator corrupted memory (Qualys, fixed in glibc
  2.39); custom sorts with naive pivots are O(n²) on crafted input.
- **Python:** `re` backtracks; Python 3.11 added atomic groups and possessive quantifiers, and
  `google-re2` gives linear time. Deep `json.loads` nesting raises `RecursionError`, not a crash.
  The stdlib XML parsers use Expat, which does not open local files or network connections by
  default (the SAX parser stopped processing external general entities in 3.7.1). Expat below 2.7.2
  may be vulnerable to billion laughs, quadratic blowup, and large-token reparsing, and Python may
  use its bundled or the system Expat, so check `pyexpat.EXPAT_VERSION` before reporting entity
  expansion; `defusedxml` remains the safe default for untrusted XML.
- **JavaScript:** a ReDoS blocks the single event loop for every concurrent request, and `RegExp` has
  no timeout. V8 has an experimental non-backtracking engine (`--enable-experimental-regexp-engine`,
  the `/l` flag), off by default.

## Detection Questions

- Can valid-looking input keep this loop running without consuming input or advancing state? A
  reset-to-start transition with no retry counter is a candidate.
- Is the decompressed or decoded size checked against a policy limit while producing output, or only
  after the whole result exists?

## Real CVE Examples

- **CVE-2023-44487 (HTTP/2 Rapid Reset).** HEADERS + RST_STREAM pairs cost the client a few bytes
  and the server stream setup and teardown each time; no single code path was buggy, the
  vulnerability was the protocol's cost asymmetry.
- **CVE-2024-22019 (Node.js chunk extensions).** llhttp accepted unbounded chunk-extension bytes, so
  one request kept the parser reading extension data and exhausted CPU and bandwidth for the whole
  single-threaded server — resource exhaustion inside the runtime's parser, not user code.
