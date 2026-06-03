---
description: Combinatorial arithmetic, signed/unsigned confusion across boundaries, encoding expansion
skill: code-vulnerability-analysis
languages: C/C++, Python, JS
---

# Integer Overflow — Combinatorial Arithmetic

> Target: Arithmetic bugs that survive SAST because each individual operation looks correct.
> The overflow emerges only when values from multiple functions combine, or when type
> transitions at function boundaries cause silent truncation or sign extension.

---

## Baseline Patterns (Single-Function / Single-Scope)

Toolchain-catchable patterns. Record as findings if encountered during orientation —
on unaudited codebases these are real, exploitable bugs that no prior tool run has caught.
Invest primary analysis time in the LLM-advantage patterns below.

- Single-expression overflow: `a + b` without prior check when both are user-controlled
- Obvious truncation: `int x = (int)large_uint64_value;` in the same scope
- `malloc(n * sizeof(T))` where `n` is directly from user input without validation
- Compiler-warned implicit narrowing conversions (same function scope)

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Type Transition Chains Across Functions

A value starts as `size_t` in function A, is passed as `int` to function B (truncation),
then cast back to `size_t` in function C (sign extension). If the original value was
larger than INT_MAX, it becomes negative in B, then becomes a very large positive value
in C.

```c
// Function A (parser)
size_t content_length = parse_header_value(hdr);  // returns 3GB

// Function B (validator) — takes int for historical reasons
int validate_size(int size, int max) {
    return size > 0 && size <= max;
}
// 3GB as int = negative → fails > 0 check (safe by accident)
// But what if content_length is 2GB + 1? As int: negative. Depends on max.

// Function C (allocator)
void *alloc_response(size_t len) { return malloc(len); }
```

The danger: some values in the range [INT_MAX+1, UINT_MAX] may pass validation
in B (depends on the exact check) and then cause havoc in C.

### 2. Length + Offset Validated Independently But Sum Wraps

```c
if (offset < buf_size && len < buf_size) {
    memcpy(buf + offset, src, len);
}
```

Both `offset` and `len` are individually less than `buf_size`, but `offset + len` can
exceed `buf_size` — or worse, wrap around to a small value on 32-bit or with 32-bit
types. SAST tools look for missing bounds checks, not semantically wrong bounds checks.

**The fix they should have written**: `if (offset <= buf_size && len <= buf_size - offset)`

### 3. Encoding Expansion Not Reflected in Allocation

Input is N bytes, but the encoded form is larger:
- Base64: N bytes → ceil(N/3)*4 bytes + padding
- URL encoding: N bytes → up to N*3 bytes (each byte becomes %XX)
- UTF-8 encoding: N codepoints → up to N*4 bytes
- HTML entity encoding: N bytes → up to N*6 bytes (&#NNN;)

The allocation uses the input length, but the write uses the encoded length. Each
encoding function correctly computes its output size, but the caller allocates based
on the pre-encoding size.

**Real pattern in git**: Encoding filenames for transport — the filename length is
validated against a limit, but the encoded form exceeds the buffer allocated for the
encoded result.

### 4. Multiplication Overflow in Allocation

```c
size_t n_items = read_uint32(stream);    // validated: < MAX_ITEMS (e.g., 1M)
size_t item_size = read_uint32(stream);  // validated: < MAX_ITEM_SIZE (e.g., 64K)
// Both pass validation, but n_items * item_size = 64GB, wraps on 32-bit
void *buf = malloc(n_items * item_size);
```

Each value is individually validated against a reasonable maximum, but the product
overflows. On 64-bit systems this allocates 64GB (DoS). On 32-bit systems the product
wraps to a small allocation (heap overflow).

### 5. Signed Return Values Misinterpreted as Unsigned

```c
// Function returns ssize_t: -1 on error, positive on success
ssize_t read_data(int fd, void *buf, size_t len);

// Caller
size_t bytes = read_data(fd, buf, sizeof(buf));
if (bytes > MAX_SIZE) return ERROR;  // -1 cast to size_t is huge, passes check? No.
// Actually, (size_t)-1 is SIZE_MAX which IS > MAX_SIZE, so this specific check works.
// But what about:
size_t remaining = total - bytes;  // total - SIZE_MAX wraps
```

The subtle version: the error return is not -1 but some other negative value that,
when cast to unsigned, happens to be in a "valid" range.

### 6. 64-bit to 32-bit Narrowing at Storage Boundaries

A value computed as 64-bit is stored in a struct field that's 32-bit (for protocol
compatibility or historical reasons). The stored value is later used for allocation.

```c
struct index_entry {
    uint32_t offset;   // from 64-bit computation, truncated on store
    uint32_t size;     // same issue
};
// If file > 4GB, offset wraps. Later code reads entry.offset and seeks to wrong position.
```

**In git**: Pack index v2 uses 32-bit offsets with a special marker for large offsets,
but code paths that don't check the marker use the 32-bit value directly.

---

## C/C++ Specific Patterns

### Implicit Integer Promotion Rules
In C, arithmetic on types smaller than `int` promotes to `int` first. Two `uint16_t`
values multiplied produce an `int` result, not `uint16_t`. This is usually safe but
becomes dangerous when the `int` result overflows (undefined behavior in C).

### Undefined Behavior Exploitation
Signed integer overflow is undefined behavior in C/C++. Compilers may optimize away
overflow checks:
```c
if (x + 100 < x) { /* overflow check */ }
// Compiler may remove this: signed overflow is UB, so x + 100 is always >= x
```

### Platform-Dependent size_t Width
Code tested on 64-bit (size_t = 8 bytes) may overflow on 32-bit (size_t = 4 bytes).
Cross-platform projects like cURL, git, and wget must handle both. An allocation of
`n * m` that's safe on 64-bit wraps on 32-bit.

---

## Python Specific Patterns

### Arbitrary Precision Is NOT a Complete Shield
Python integers don't overflow, but:

- **ctypes**: `ctypes.c_int(2**31)` wraps silently
- **struct.pack**: `struct.pack('i', 2**31)` raises OverflowError, but `struct.pack('I', -1)`
  does not — it becomes 4294967295
- **numpy**: `np.int32(2**31)` wraps silently, and array operations inherit the dtype
- **C extensions**: Any value passed to a C extension through `PyArg_ParseTuple` with `i`
  format truncates to C int

### Size Calculations for C Interop
When Python code calculates sizes to pass to C functions (via ctypes, cffi, or C extensions),
the Python integer won't overflow, but the C side will truncate the value.

---

## JavaScript Specific Patterns

### Number.MAX_SAFE_INTEGER Boundaries
JavaScript numbers are IEEE 754 doubles. Integers above 2^53 lose precision:
```javascript
Number.MAX_SAFE_INTEGER + 1 === Number.MAX_SAFE_INTEGER + 2  // true!
```
Any size calculation that might exceed 2^53 silently produces wrong results.

### BigInt and Number Coercion
```javascript
let size = BigInt(userInput);
let buf = Buffer.alloc(Number(size));  // Number(BigInt) can lose precision or produce Infinity
```
`Number(very_large_bigint)` returns `Infinity`, and `Buffer.alloc(Infinity)` throws.
But `Number(2n**53n + 1n)` silently loses the +1.

### Bitwise Operators Force 32-bit
All bitwise operators in JavaScript coerce operands to 32-bit signed integers:
```javascript
let x = 0x1_0000_0000;  // 4294967296 (fits in Number)
x | 0;  // 0 — silently truncated to 32-bit
x >>> 0; // 0 — unsigned right shift also truncates
```
Any size calculation that uses `| 0` or `>>> 0` for "integer conversion" will wrap.

---

## Detection Questions

1. **"What is the type of this value at each function boundary it crosses?"**
   Draw the type chain: `size_t → int → size_t`. Every type transition is a potential
   truncation or sign-extension point.

2. **"Are two values validated independently but used together in arithmetic?"**
   If `offset < max` and `len < max`, does the code also check `offset + len ≤ max`?
   Or more correctly, `len ≤ max - offset`?

3. **"Does an encoding/transformation step change the data size?"**
   If data is encoded, escaped, compressed, or otherwise transformed between size
   calculation and buffer use, does the allocation reflect the output size?

4. **"Can a product of two validated values overflow?"**
   If `n < 1000000` and `m < 65536`, their product can be up to ~65 billion —
   overflows 32-bit, safe in 64-bit. Check the type of the product.

5. **"Does this function return a negative error value to a caller that uses unsigned?"**
   Map error-return conventions across module boundaries. Every `-1` return that gets
   cast to `size_t` is a potential SIZE_MAX.

---

## Real CVE Examples

### CVE-2022-41903 (git format-commit integer overflow)
The `--format` option for `git log` and `git archive` used `int` to track padding
widths. User-controlled padding specifiers like `%>(2147483647)` could overflow the
`int` used for buffer size calculation. The individual parsing of the padding value
was correct (it read a number), and the individual buffer operations were correct
(they wrote `len` bytes), but the combination of a large padding value with actual
content caused the total to overflow `int`, resulting in a heap buffer overflow.
The bug spanned the format-parsing module and the buffer-management module.

### CVE-2023-29007 (git config parsing integer overflow)
When parsing `.gitconfig` files, extremely long values could cause the string length
tracking to overflow. The config parser used `int` for line lengths. Values close to
INT_MAX would wrap when combined with other header bytes. The validation checked the
value length in isolation, but didn't account for the additional bytes added during
config entry construction.

### CVE-2016-7167 (cURL integer overflow in URL glob)
The URL globbing feature (`[1-1000000000]`) computed allocation sizes by multiplying
the number of generated URLs by the URL template length. Both values were individually
reasonable, but their product overflowed. The range validation and the URL template
length validation were in different functions, so no single-function analysis saw the
dangerous multiplication.
