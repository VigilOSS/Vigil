---
description: Conditional initialization, cross-function partial init, stack/heap info leaks
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Uninitialized Memory — Cross-Function Initialization Gaps

CWE-457, CWE-908. Initialization and use sit in different functions, branches, or lifecycle phases.

## What You're Hunting (LLM-Advantage Patterns)

1. **Assigned in one branch, used on all.** `int status; if (input && *input) status = parse(...);
   return status;` — the attacker picks the empty input, and garbage may equal `SUCCESS` for a
   caller deciding trust on it.
2. **Struct filled across functions.** A mallocs, B sets four of six fields, C reads a field B never
   wrote (`if (!cfg->auth_required) allow_anonymous(conn);`). List every field and its writer; a
   field with no writer is the bug, and SAST cannot do that completeness check.
3. **Partial memset of a trailing payload.** `malloc(sizeof(hdr) + payload_len)` then
   `memset(pkt, 0, sizeof(hdr))` zeros only the header; a short copy into the payload sends prior
   heap contents over the wire.
4. **Fixed buffer, ignored fill length.** `read()`/`recv()`/`fread()` returns `n`, but the code
   parses or forwards `sizeof(buf)` bytes.
5. **Reused stack slots.** A formats a secret into a 256-byte local; B, called next on the same
   path, `snprintf(buf, 128, ...)` into its own 256-byte local and sends `sizeof buf`, leaking A's
   bytes 128-255. Each function is valid alone; the leak is in the call sequence.

Uninitialized data becomes a vulnerability when it crosses a trust boundary (network, userspace,
another process) or steers a security decision; otherwise it is a reliability bug.

## C/C++ Specifics

- **Struct padding.** In `struct msg { uint8_t type; uint32_t value; }` the three bytes between the
  members are never written; copying the struct out field-by-field leaks them. A `memset` before
  the assignments is the remedy (`packed` removes the padding but changes the layout).
- **Unions:** writing a smaller member and reading a larger one exposes the difference.
- **`alloca()` and VLAs** are never zeroed.
- **C++:** constructor initializer lists that miss members, derived constructors that skip the
  base's full initialization, and `new int` (indeterminate) versus `new int()` (value-initialized).
  `malloc` does not zero; `calloc` does.

## Python Specifics

- `ctypes.create_string_buffer` zeros, but views from `from_address()` or shared-memory pointers
  are whatever the memory held.
- C extensions calling `PyBytes_FromStringAndSize(NULL, n)` and filling fewer than `n` bytes
  return the unfilled heap tail to Python.

## JavaScript Specifics

- `Buffer.allocUnsafe(n)` (and `allocUnsafeSlow`) is not zeroed; `buf.write(userInput)` followed by
  sending the whole buffer leaks heap data. This is the most common Node.js instance; the fix is
  `Buffer.alloc` or slicing to the written length.
- WebAssembly linear memory is zeroed at instantiation and on `memory.grow`, but an in-module
  allocator that reuses freed regions without zeroing behaves like C heap reuse.

## Real CVE Examples

- **CVE-2016-4569 (Linux ALSA timer).** `snd_timer_user_params()` assigned a stack
  `struct snd_timer_tread` field by field and handed it to userspace from another function; eight
  padding bytes after `event` and `val` leaked kernel stack per event. Every assignment was correct;
  only the layout shows the bug.
- **CVE-2022-1016 (Linux nf_tables).** `nft_do_chain` did not initialize its register array, and a
  rule could read a register no earlier expression wrote, leaking kernel stack. Each expression
  handler is correct alone; the rule composition is what reads before writing.
- **CVE-2016-0777 (OpenSSH client roaming).** `resend_bytes()` could send the whole roaming
  `out_buf`, allocated with `malloc()` at a server-chosen size, to a malicious server, leaking
  private keys left in the heap by stdio buffers, `realloc()` growth, and clearing `memset()`s the
  compiler removed. Secrets left in a buffer that is reused or resent travel with it: check what a
  send-whole-buffer path can contain, and that wipes use `explicit_bzero`/`OPENSSL_cleanse`.
