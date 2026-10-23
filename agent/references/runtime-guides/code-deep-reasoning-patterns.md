---
description: Detailed source audit examples for sibling guards, state, arithmetic, macros and build variants
skill: code-vulnerability-analysis
---

## SAST-Surviving Bug Classes

These are the specific classes of vulnerabilities that survive automated static analysis and
require human-level reasoning to detect:

### Multi-Function Reasoning Chains
Each function is correct when analyzed in isolation. The vulnerability only manifests when
functions are composed. Example: function A validates input length, function B adds a header,
function C copies the result -- but A's length check does not account for B's added header,
so C overflows.

**Detection approach**: Follow untrusted data across function boundaries. At each function
boundary, check: does the callee's precondition match the caller's postcondition? Are
size/length values adjusted correctly across calls?

### Incomplete Patches
A vulnerability was fixed in one code path, but a sibling code path performing the same
operation was not patched. Common in copy-paste code, protocol variant handlers, and
platform-specific branches.

**Detection approach**: When you find a guard in one code path, search for sibling paths
(same function called from different callers, same operation in switch cases, same pattern
in platform-specific `#ifdef` branches). Verify each sibling has equivalent guards.

### State Machine Bugs
Asynchronous or concurrent code where state transitions create windows for exploitation.
Use-after-free in event-driven code, TOCTOU in file operations, race conditions in
lock-free data structures.

**Detection approach**: Identify shared mutable state. Trace all paths that read and write
it. Look for: freed memory still referenced by pending callbacks, unlocked windows between
check and use, missing atomicity in multi-step state transitions.

### Combinatorial Integer Arithmetic
Individual arithmetic operations have bounds checks, but the combination overflows. Example:
`validated_a + validated_b` overflows even though `validated_a < MAX` and `validated_b < MAX`.

**Detection approach**: At every arithmetic operation on untrusted-derived integers, check:
can the RESULT overflow even if each operand is individually bounded? Track through chains
of arithmetic operations.

### Semantic/Protocol Bugs
Bugs that require understanding the protocol specification or business logic. Example: HTTP
request smuggling from disagreement between parser and proxy about where a request ends, or
authentication bypass from incorrect handling of a protocol edge case.

**Detection approach**: Compare the code's behavior against the protocol specification or
documented business rules. Look for edge cases: empty fields, maximum-length fields, nested
structures, recursive definitions, conflicting headers.

### Error Path Vulnerabilities (CRITICAL -- Most CVEs Live Here)
Most real-world CVEs are in error handling code, not the happy path. Error paths are less
tested, less reviewed, and often violate assumptions the happy path establishes.

**Detection approach**:
- For every function, identify ALL error return paths (early returns, goto cleanup, exception
  handlers, default switch cases)
- At each error path: what state has been partially initialized? What resources have been
  acquired but not released?
- Check for: double-free (both error handler and caller free), use of partially initialized
  structs, resource leaks (open handles not closed), fail-open (error acknowledged but
  execution continues)
- Ask: "If this function fails at line N, what state does the caller see?"

### Macro-Hidden Operations (C/C++ Critical)
C/C++ macros can hide dangerous operations. A macro wrapping `memcpy`, `free`, or `printf`
won't appear as those function names in source code.

**Detection approach**:
- When analyzed code contains macro calls, expand them via grep for the macro definition
- Common patterns: `COPY(dst, src, len)` hiding memcpy, `SAFE_FREE(p)` hiding free+NULL,
  `LOG(fmt, ...)` hiding printf-family
- Macros with control flow (`CHECK(x)` containing return/goto) change function semantics
  invisibly
- Variadic macros with format strings are injection vectors

### Conditional Compilation Variants (#ifdef)
A function may behave completely differently depending on build flags. A vulnerability fixed
in one `#ifdef` branch may still exist in another.

**Detection approach**:
- Identify all `#ifdef` / `#if` / `#ifndef` blocks in analyzed code
- For security-critical guards: verify the guard exists in ALL conditional branches, not just
  the one you're reading
- Check platform-specific branches (`#ifdef WIN32`, `#ifdef __linux__`) -- vulnerability may
  be platform-specific
- Check feature-flag branches -- a feature disabled by default may still be compiled and
  reachable

