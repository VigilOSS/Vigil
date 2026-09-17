---
description: Cross-function size propagation, incomplete bounds checks, realloc chains
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Buffer Overflow — Cross-Function Size Propagation

> Target: Bugs that survive CodeQL, Semgrep, and OSS-Fuzz in heavily-audited C projects (cURL, git, wget).
> These require multi-function reasoning and semantic understanding of size propagation.

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Cross-Function Size Propagation

The size of a buffer is computed in function A, passed to function B as a parameter, and
used in function C for a copy operation. The problem: function B transforms the data
(adds a header, applies encoding, appends a suffix) but the size value is not updated
to reflect the transformation.

**Pattern to trace**: Follow every path where a `size` or `len` variable is computed,
then passed to another function. At each call boundary, ask: "Did the data grow but the
size stay the same?"

```
// Function A: computes size
size_t len = strlen(input);  // correct here

// Function B: transforms data, adds header
void add_header(char *buf, const char *input, size_t len) {
    memcpy(buf, HEADER, HEADER_LEN);
    memcpy(buf + HEADER_LEN, input, len);  // total write is HEADER_LEN + len
}

// Function C: allocated buffer using original len
char *buf = malloc(len);  // should be len + HEADER_LEN
add_header(buf, input, len);
```

### 2. Incomplete Bounds Checks (Wrong Variable)

A bounds check exists — it just checks the wrong thing. The developer checked `len`
but the actual copy uses `data_len + header_len`. Or the check uses the old size
before a realloc that changed the capacity.

**Pattern**: Look for functions with bounds checks where the checked variable and
the variable used in the memory operation are different names. Trace both back to
their definitions.

### 3. Signed/Unsigned Mismatch in Bounds Check

```c
int validate_length(int len, int max) {
    return len <= max;  // negative len passes this check
}

void copy_data(char *dst, const char *src, size_t len) {
    memcpy(dst, src, len);  // negative int cast to huge size_t
}
```

The bounds check uses `int`, the copy uses `size_t`. A negative value passes the
check then becomes an enormous unsigned value. SAST tools flag simple cases but miss
it when the types are in different functions or separated by layers of indirection.

### 4. Untrusted Metadata Flowing Across Call Chains

Content-Length headers, chunk sizes, array counts from parsed protocols. The value
enters at a parsing layer, gets stored in a struct, then used three function calls
later for allocation. The validation happens at the parsing layer but may be
insufficient for the eventual use (e.g., validates < MAX_HEADER but the buffer is
smaller than MAX_HEADER).

**In cURL**: HTTP chunked transfer encoding sizes, Content-Length for multi-part
boundaries, FTP response lengths.

**In git**: Pack file object sizes, tree entry name lengths, commit header field sizes.

**In wget**: HTTP header field lengths, HTML parser token sizes, IRI encoding lengths.

### 5. Realloc Growth Factor Miscalculation

```c
// In function A: grow buffer
new_size = old_size + chunk_size;
buf = realloc(buf, new_size);

// In function B: assumes buffer doubled
available = old_size;  // wrong: should be new_size - used
memcpy(buf + used, data, available);
```

The realloc call is correct, but the calling function miscalculates available space
because it uses a stale capacity value or assumes a different growth strategy.

### 6. Off-by-One Spanning Multiple Functions

Each function in the chain adds 1 for a null terminator. The allocation only includes
one +1, but two functions each write a null byte one past their segment. Or: function A
calculates `len` excluding the null terminator, function B adds 1 for it, then function
C also adds 1 — the allocation is 1 byte too large (wasteful but safe) or, more
dangerously, function B does NOT add 1 assuming A included it, and A did NOT include it
assuming B would.

---

## C/C++ Specific Patterns

### Heap vs Stack Implications
Stack overflows corrupt return addresses (classic RCE). Heap overflows corrupt allocator
metadata or adjacent objects (use-after-free chain). The hunter should note which type
of buffer is involved — heap overflows in malloc'd buffers are often exploitable even
with stack canaries enabled.

### Struct Member Overflow
Writing past one struct member into an adjacent member. SAST tools check bounds of the
buffer, not of the struct member. If a struct has `char name[64]; int flags;`, writing
65 bytes to `name` corrupts `flags` without overflowing the struct's allocation.

### Flexible Array Member Sizing
```c
struct packet {
    uint32_t length;
    char data[];  // flexible array member
};
// Allocation: sizeof(struct packet) + data_length
// Bug: using sizeof(*pkt) instead of sizeof(struct packet) on some compilers
// Or: data_length from untrusted source without validation
```

---

## Python Specific Patterns

### ctypes Buffer Overflow
```python
buf = ctypes.create_string_buffer(64)
libc.strcpy(buf, user_bytes)  # no length enforcement at Python level
```

### C Extension Module Buffer Issues
C extensions that accept `Py_buffer` and write beyond the buffer's `len` field.
The Python runtime trusts the C extension's bounds checking.

### memoryview Bounds
`memoryview` objects can be sliced, but if the underlying buffer is released or
resized (via `bytearray`), the memoryview may reference stale memory. Not a classic
buffer overflow but achieves the same effect.

---

## JavaScript Specific Patterns

### Buffer.allocUnsafe
`Buffer.allocUnsafe(n)` does not zero memory. If `n` is derived from user input and
the buffer is returned partially filled, it leaks heap contents. Not an overflow per se
but a buffer safety issue.

### TypedArray via Prototype Pollution
If `Array.prototype` or `Object.prototype` is polluted with a `length` property,
TypedArray constructors or manual iteration may use the wrong bounds.

### Native Addon Buffer Issues
Node.js native addons (N-API / nan) that accept `Buffer` objects and read/write
using the raw pointer without checking `Buffer::Length()`. The JS side can pass a
smaller buffer than the C++ side expects.

---

## Detection Questions

1. **"Where was this size value born, and how many functions has it passed through?"**
   Trace the allocation size back to its origin. Every function boundary is a chance
   for the size to become stale.

2. **"Does the bounds check variable match the variable used in the copy/write?"**
   Literally compare the variable names or expressions. If they differ, trace both.

3. **"What is the type of the length at each function boundary?"**
   Look for signed ↔ unsigned transitions, 64-bit ↔ 32-bit narrowing, or
   int ↔ size_t ↔ ssize_t changes.

4. **"Does any function in the chain transform the data without updating the length?"**
   Encoding, escaping, prepending headers, appending trailers — all change data
   size. The length variable must be updated at each transformation.

5. **"Is the bounds check using a stale capacity value?"**
   After realloc, buffer resize, or capacity change — are all references to the
   capacity updated? Look for cached copies in local variables or struct fields.

---

## Real CVE Examples

### CVE-2023-38545 (cURL SOCKS5 heap buffer overflow)
The hostname for SOCKS5 proxy negotiation was copied into a heap buffer. The size
check validated the hostname length at input time, but a slow SOCKS5 handshake
triggered a fallback path that resolved the hostname locally, then copied the
resolved address into the same buffer — which could be longer than the original
hostname that was bounds-checked. The size was validated in one code path but used
in a different code path after a state machine transition. No single-function analysis
could find this; it required understanding the SOCKS5 state machine across multiple
functions and timeout-triggered state transitions.

### CVE-2021-22947 (cURL STARTTLS injection)
During STARTTLS negotiation, response data from the server was buffered. The buffer
handling assumed that data received before TLS was complete would be discarded, but
a response injection could place data in the pre-TLS buffer that survived into the
post-TLS context. The buffer size assumptions were correct for the TLS data path
but not for the pre-TLS injection path.

### CVE-2022-41903 (git integer overflow in pretty-print)
The `format_commit_message` function used `int` for tracking output buffer size.
When formatting a commit with an extremely long message combined with padding
directives, the size calculation overflowed `int`, leading to a heap buffer overflow.
The individual size calculations were locally reasonable — the overflow emerged from
their accumulation across multiple formatting function calls.
