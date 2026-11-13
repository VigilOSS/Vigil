---
description: Cross-function size propagation, incomplete bounds checks, realloc chains
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Buffer Overflow — Cross-Function Size Propagation

## What You're Hunting (LLM-Advantage Patterns)

1. **Size computed in one function, data transformed in another.** A length is computed in A,
   passed to B, which prepends a header, encodes, or appends a suffix, and C copies with the
   original length. At every call boundary ask: did the data grow while the size stayed the same?
2. **The check names a different variable than the copy.** The guard tests `len`, the copy writes
   `data_len + header_len`; or the guard uses the capacity from before a realloc. Trace both
   expressions to their definitions.
3. **Signed check, unsigned use, in different functions.** `int len <= max` passes a negative value
   that `memcpy` then reads as a huge `size_t`. SAST catches it when both sit in one function and
   misses it across layers.
4. **Untrusted metadata validated for the wrong consumer.** A parsed length is checked against
   `MAX_HEADER` at the parser, stored in a struct, and used three calls later against a smaller
   buffer. Project-specific carriers: cURL chunked-encoding sizes, multipart Content-Length, FTP
   response lengths; git pack object sizes, tree entry name lengths, commit header fields; wget
   header field lengths, HTML tokenizer sizes, IRI encoding lengths.
5. **Stale capacity after realloc.** The realloc is right, but a caller keeps a cached capacity in a
   local or struct field, or assumes a growth strategy the callee does not use.
6. **Off-by-one split across functions.** A excludes the terminator assuming B adds it, B assumes A
   included it, and the allocation lacks the byte both write.

## C/C++ Specifics

- **Struct member overflow.** Writing 65 bytes into `char name[64]` of `{char name[64]; int flags;}`
  corrupts `flags` without leaving the allocation, so allocation-bounds tools stay silent.
- **Flexible and legacy trailing arrays.** A length field from untrusted input sizes the trailing
  array. Pre-C99 `data[1]`/`data[0]` idioms are treated as fixed-size by `-fstrict-flex-arrays` and
  `_FORTIFY_SOURCE`, so mixing the idioms changes which accesses are caught, and an allocation that
  subtracts the placeholder element can be one element short.
- **Heap overflows stay exploitable with stack canaries**: note heap versus stack when reporting.

## Python Specifics

- `ctypes`: `libc.strcpy(ctypes.create_string_buffer(64), user_bytes)` has no Python-level bound.
- C extensions taking `Py_buffer` and writing past its `len`; the runtime trusts the extension.
- `bytearray` resize with a live `memoryview` export raises `BufferError` in CPython, so the stale
  pointer risk lives in C code that keeps a pointer after `PyBuffer_Release`, or in a callback
  (`__index__`, `__len__`) that mutates the buffer mid-operation.

## JavaScript Specifics

- Native addons (N-API, nan) that use the raw `Buffer` pointer without checking
  `Buffer::Length()`: the JS side can pass a shorter buffer than C++ expects.
- `Buffer.allocUnsafe` exposure is covered in `uninitialized-memory.md`.

## Detection Questions

- What is the length's type at each function boundary (signed/unsigned, 64/32-bit,
  `int`/`size_t`/`ssize_t`)?
- After every realloc or capacity change, is every cached copy of the capacity updated?

## Real CVE Examples

- **CVE-2023-38545 (cURL SOCKS5 heap overflow).** For hostnames over 255 bytes cURL decided to
  resolve locally, but that decision lived in a local variable lost when the non-blocking state
  machine re-entered on a slow handshake; the re-entered path then copied the over-long hostname
  into the heap download buffer reused for SOCKS negotiation (16 kB by default, overflowable when
  smaller than 65,541 bytes). The check and the copy sat on opposite sides of a state
  transition, which is the shape to look for.
- **CVE-2023-4863 (libwebp Huffman tables).** Image-declared code lengths drove table construction
  past a table sized from a compile-time constant; parsing, table building, and the out-of-bounds
  write were three functions apart. Exploited in the wild through a crafted WebP image.
- **CVE-2022-41903 (git `format_commit_message`)** is an accumulated-`int` size overflow; see
  `integer-overflow.md`.
