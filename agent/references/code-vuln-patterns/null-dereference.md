---
description: Cross-function NULL propagation, optional field assumptions, race-to-NULL
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Null Dereference — Cross-Function NULL Propagation

CWE-476. A NULL is produced in one function and dereferenced in another that assumes it cannot be.

## What You're Hunting (LLM-Advantage Patterns)

1. **NULL stored, dereferenced later.** B stores a failed lookup's NULL in a struct; C, reached by
   another path, dereferences the field. Also: the pointer is checked but a member pointer it holds
   is not, and an init function's NULL or error return is ignored by its caller.
2. **Optional fields by init path.** TLS connections set `conn->tls`, plaintext ones leave it NULL,
   and `send_data()` calls `SSL_write(conn->tls->ssl, ...)`. For each struct, list every
   initialization path; a field any path leaves NULL needs a check in every consumer.
3. **Compiler-deleted checks.** A dereference before the NULL check lets the optimizer delete the
   check as dead (`-fno-delete-null-pointer-checks` exists because of this; the Linux tun driver
   case). Look for `x->field` reads that precede `if (!x)`.

Check-then-use races to NULL are covered in `race-condition.md`, and stale non-NULL pointers after
free in `use-after-free.md`.

## C/C++ Specifics

- `buf = realloc(buf, n)` loses the original on failure and leaves `buf` NULL for the next copy.
- `std::unique_ptr` after `std::move`: the moved-from pointer's `.get()` is null; a raw pointer saved
  before the move stays valid only while the new owner lives.

## Python Specifics

- Lookups that return `None` for an attacker-chosen missing id, chained without a guard: a 500 at
  best, a fail-open when the exception handler or a falsy check treats "no object" as "no
  restriction".
- mypy enforces `Optional` by default, but unannotated functions are not checked unless
  `--check-untyped-defs` is on, so `None` flows through them freely.

## JavaScript Specifics

`Array.find()`, `Map.get()`, and most lookups return `undefined`, not `null`: `if (user !== null)`
passes for a missing user. Server-side, the same applies to cache and query results.

## Real CVE Examples

- **CVE-2019-9213 (Linux `expand_downwards`).** The stack-expansion path missed the `mmap_min_addr`
  check, letting an unprivileged user map page zero; kernel NULL dereferences then read
  attacker-controlled memory. What makes a NULL dereference exploitable is whether page zero can be
  mapped.
- **CVE-2023-6622 (Linux nf_tables `nft_dynset_init`).** A crafted expression reached a pointer that
  rule construction never set; the field is established and consumed through different entry
  points into the subsystem. Local with `CAP_NET_ADMIN` (reachable from an unprivileged user
  namespace), and denial of service only — the contrast with the same subsystem's use-after-free
  bugs is null versus stale.
