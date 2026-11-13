---
description: Combinatorial arithmetic, signed/unsigned confusion across boundaries, encoding expansion
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Integer Overflow — Combinatorial Arithmetic

Each operation looks correct; the overflow appears only when values from several functions combine
or a type changes at a call boundary.

## What You're Hunting (LLM-Advantage Patterns)

1. **Type transition chains.** `size_t` in the parser, `int` in a legacy validator, `size_t` again
   in the allocator: values in `[INT_MAX+1, UINT_MAX]` turn negative in the middle and may pass a
   check written for positive ints. Draw the type at every boundary.
2. **Offset and length validated separately.** `offset < size && len < size` lets `offset + len`
   exceed or wrap. The correct form is `offset <= size && len <= size - offset`.
3. **Encoding expansion missing from the allocation.** Base64 grows to `ceil(N/3)*4`, `%XX` URL
   encoding to `3N`, UTF-8 to `4N` per codepoint, numeric HTML entities to about `6N`. Each encoder
   sizes its own output correctly while the caller allocates from the pre-encoding length (git
   filename encoding for transport is this shape).
4. **Product of two validated values.** `n < 1M` and `size < 64K` each pass, and the product is
   64 GB: a DoS on 64-bit, a wrap to a small allocation on 32-bit.
5. **Signed error returns used as unsigned.** `(size_t)-1` fails `> MAX` checks, but
   `remaining = total - bytes` wraps; other negative error codes can land in a valid-looking range.
6. **Narrowing at storage.** A 64-bit result stored in a `uint32_t` struct field for protocol
   compatibility. git's pack index v2 stores 32-bit offsets with a marker bit for large offsets;
   paths that skip the marker check use the truncated value.

## C/C++ Specifics

- **Promotion:** `uint16_t * uint16_t` is computed in `int` and can overflow, which is undefined.
- **UB-based check removal:** `if (x + 100 < x)` on a signed `x` may be deleted by the optimizer;
  overflow checks must be written before the operation or with `__builtin_*_overflow`.
- **`size_t` width:** an `n * m` safe on 64-bit wraps on 32-bit builds that cURL, git, and wget
  still ship.

## Python Specifics

Python ints do not overflow, but the boundaries do:
- `ctypes.c_int(2**31)` wraps silently.
- NumPy array arithmetic wraps silently in the array's dtype; scalar construction such as
  `np.int32(2**31)` raises `OverflowError` on NumPy 2.x.
- `PyArg_ParseTuple` format `i` range-checks and raises, while `I`, `k`, `K`, `B`, and `H` convert
  without overflow checking.
- Sizes computed in Python and passed through ctypes or cffi truncate on the C side.
- `struct.pack` raises `struct.error` for out-of-range values in both signed and unsigned formats,
  so it is not a wrap source.

## JavaScript Specifics

- Integers above `Number.MAX_SAFE_INTEGER` (2^53) lose precision silently.
- `Number(bigint)` loses low bits above 2^53 and returns `Infinity` past the double range.
- Bitwise operators coerce to 32 bits: `0x1_0000_0000 | 0` and `>>> 0` are both 0, so `| 0` used as
  "integer conversion" wraps sizes.

## Real CVE Examples

- **CVE-2022-41903 (git `--format` padding).** Padding specifiers such as `%>(2147483647)` were
  parsed correctly and each buffer write was correct, but the accumulated `int` size across the
  format-parsing and buffer modules overflowed into a heap overflow (`git log`, `git archive`).
- **CVE-2016-7167 (libcurl escape/unescape).** `curl_easy_escape()` and siblings never validated the
  caller-supplied length; `0xffffffff` (or `-1` arriving signed) wrapped the output-size arithmetic
  to a zero-byte allocation that was then written. The length comes from the application and the
  allocation happens inside the library, so neither side sees the wrap: audit the API boundary,
  not only module boundaries. Fixed in 7.50.3.
- **CVE-2022-35737 (SQLite `sqlite3_str_vappendf`).** The `%q`/`%Q`/`%w` paths computed escaped
  output size in a signed `int`, so string arguments over 2 GB overflowed it; reachable only when an
  application passes such a string to the printf-style API.
