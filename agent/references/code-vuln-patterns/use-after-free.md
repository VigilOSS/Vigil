---
description: Cross-module lifetime reasoning, refcount errors, async cleanup races
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Use-After-Free — Lifetime Reasoning Across Modules

CWE-416, CWE-415. The free and the use sit in different modules, threads, or state-machine phases.

## What You're Hunting (LLM-Advantage Patterns)

1. **Callback after free.** `close_connection()` unregisters the fd and frees `conn`, but an event
   queued before the unregister still dispatches `ev->data`. For every callback registration, find
   where its context is freed and whether deregistration can race dispatch. cURL: easy handles freed
   while the multi handle has queued work.
2. **Refcount imbalance across modules.** `cache_get()` returns a stored pointer without
   incrementing; a later `release_obj()` drops the count to zero while the getter's caller still
   holds it. Pair every increment and decrement across files, especially on error paths.
3. **Teardown racing in-flight work.** Thread 1 runs `SSL_shutdown`/`SSL_free`/`free(ctx)` while a
   read callback on thread 2 calls `SSL_read(ctx->ssl, ...)`. cURL: closing one transfer can free a
   shared connection another transfer's callback is pending on.
4. **State transitions that free.** Moving to IDLE frees `active_request` while a handler for the
   previous state checked it non-NULL and is about to write through it.
5. **Iterator invalidation.** The loop body calls something that removes and frees the current node,
   then the loop reads `n->next`; git ref-list iteration with callbacks that modify the list.
6. **Error-path ownership confusion.** The callee frees its argument on failure and the caller frees
   it too; on success ownership moved to a queue. Each side is correct against a contract that
   exists only in someone's head. This file owns the double-free-on-error shape.
7. **Freed but not cleared.** `cleanup()` frees `ctx->cache` without setting it to NULL; a later
   `process()` tests `if (!ctx->cache)` to decide whether to create one, sees the dangling non-NULL
   pointer, skips creation, and uses freed memory. The root cause is the missing NULL assignment.
   After every free, release, or close of a struct field or global, check that the pointer is
   cleared, and find later code that treats non-NULL as "still live".

## C/C++ Specifics

- **Pool, slab, and arena allocators** reuse memory immediately, so a UAF touches a different live
  object: harder to detect and often a type confusion.
- **`goto cleanup` with an uninitialized pointer.** A `goto` that jumps over `r = acquire()` when `r`
  was never initialized to `NULL` makes `cleanup: free(r)` free a garbage pointer; an early `return`
  that skips cleanup is the leak counterpart.
- **Callback and context registered separately:** the context is freed while the registration
  stays live, so the next event calls a valid function with a dangling context.

## Python Specifics

- C extensions holding **borrowed references** (`PyList_GetItem`, `PyDict_GetItem`) across anything
  that can run Python code: a GC pass, a callback, or an `__eq__`/`__hash__` that mutates the
  container can free the item before its use. `Py_INCREF` before the call, or use the
  new-reference APIs.
- `__del__` and weakref callbacks in reference cycles run in an unspecified order (PEP 442,
  Python 3.4+); touching another member of the cycle is a logic bug in pure Python and a UAF only
  through C extension state.

## JavaScript Specifics

Native addons must keep JS objects alive while C++ holds them. A `Nan::Persistent` made weak with
`SetWeak(...)` lets V8 collect the object; if the weak callback does not clean up the C++ side, the
next access is a UAF.

## Real CVE Examples

- **CVE-2021-22901 (cURL TLS session cache).** The OpenSSL backend stored easy-handle pointers in
  the session-ID cache; `curl_easy_cleanup()` freed the handle without evicting them, and a later
  transfer reusing the connection read (and could call a function pointer in) the freed object.
  Teardown frees, the cache still holds, connection reuse dereferences.
- **CVE-2019-5481 (cURL krb5 FTP).** A server-declared 32-bit block size went to `realloc()`; on
  32-bit builds a size near 4 GB made `realloc()` fail and the error handling freed the buffer
  twice. The bug lives entirely in the failure path.
