---
description: Fail-open, unchecked returns, exception swallowing, partial construction, error-code collapse
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Error Handling — Fail-Open and Recovery Bugs

CWE-755, CWE-252, CWE-754. The check exists; what happens after it is the bug. Double-free on error
paths is owned by `use-after-free.md` "What You're Hunting" item 6 ("Error-path ownership confusion"); the full error-path question set for deep dispatches is in
`agent/references/runtime-guides/code-hunt-deep-audit.md`.

## What You're Hunting (LLM-Advantage Patterns)

1. **Logged, not stopped.**
   ```c
   if (verify_token(token) != AUTH_SUCCESS) {
       log_warning("Authentication failed");
       /* no return */
   }
   conn->authenticated = true;
   ```
   SAST sees the `if` and calls the error handled.
2. **Tri-state returns read as booleans.** `SSL_read`/`SSL_write` return >0 on success, and for any
   return ≤0 the caller must ask `SSL_get_error()`: 0 is not necessarily a clean shutdown, and code that
   handles `n == 0` and `n > 0` but not `n < 0` falls through on real errors. Call `ERR_clear_error()`
   before the I/O call so `SSL_get_error()` is not reading a stale queue.
3. **`close()` retried on `EINTR`.** On Linux the descriptor is released even when `close()` returns
   `EINTR`, so a retry can close a descriptor another thread just opened.
4. **Broad catch around security checks.**
   ```python
   try:
       verify_signature(body, headers["X-Signature"])
       check_timestamp(headers["X-Timestamp"])
       validate_permissions(user, resource)
   except Exception:
       logger.warning("Validation issue, continuing with defaults")
   return process_request(request)
   ```
   Meant for transient errors, it swallows the signature, expiry, and permission failures. The same
   shape is `except Exception: result = None` around `verify()`, and a JavaScript `catch` that answers
   every failure, including "permission denied", with a retryable 500.
5. **Partially constructed C++ objects.** When a constructor throws after acquiring raw handles
   (`socket_`, `tls_`), the class destructor does not run, so the handles leak; members that are RAII
   wrappers are released. Use RAII per resource or two-phase init.
6. **Error codes collapsed to booleans.** `read_config()` returns `EACCES` or `ENOENT`, `load_config()`
   reduces it to `false`, and the caller falls back to the default config for both: "missing" makes
   defaults reasonable, "permission denied" makes them a security downgrade.
7. **Unchecked security-library results.** `RAND_bytes()` returning 0 or -1 unchecked leaves an
   uninitialized buffer used as a key or IV. (In OpenSSL 1.1.1+ an unseeded PRNG makes `RAND_bytes`
   fail rather than return predictable bytes, so the unchecked return is the bug.)

## C/C++ Specifics

- `errno` read after an intervening call (a logging helper that calls `write()`) reports the wrong
  error.
- `setjmp`/`longjmp` error handling (libpng and libjpeg use it) skips cleanup in every frame between,
  and skips C++ destructors in mixed code.

## Python Specifics

- `except Exception` does not catch `KeyboardInterrupt` or `SystemExit`; bare `except:` and
  `except BaseException` do, and since 3.8 so would `asyncio.CancelledError`, which is a
  `BaseException`. An explicit `except CancelledError: pass` swallows cancellation and leaves cleanup
  undone.
- A `@contextmanager` that raises privileges (`os.seteuid(0)`) and restores them in `finally`: if the
  restore raises, the process stays elevated.

## JavaScript Specifics

- A missing `await` on a payment or permission call (`stripe.charges.create(order)`) returns success
  before the operation settles; Node 15+ terminates on the unhandled rejection, older versions printed
  `UnhandledPromiseRejectionWarning` and continued.
- Ignoring a callback's `err` argument turns a read failure into an unrelated parse error on
  `undefined`.

## Detection Questions

- After each error check, does control actually leave (`return`, `throw`, `goto`, `break`)?
- Which exception types does each `catch` really catch, and which of them are security failures?
- Is the specific error preserved across each boundary, or collapsed until fatal and recoverable look
  the same?

## Real CVE Examples

- **CVE-2014-0224 (OpenSSL CCS injection).** A ChangeCipherSpec accepted before key exchange should
  have been fatal; the state machine processed it, keying the connection with predictable material.
- **CVE-2020-0601 (Windows CryptoAPI).** ECC certificate validation checked the named curve but not
  that the supplied generator matched it, so a crafted generator made an attacker key validate as a
  trusted CA's: partial validation that fell through to acceptance.
- **CVE-2019-1559 (OpenSSL 0-byte record oracle).** When an application called `SSL_shutdown()` twice
  after a fatal protocol error, OpenSSL responded differently to a 0-byte record with invalid padding
  than to one with an invalid MAC, giving a padding oracle. The error paths each rejected the record;
  their observable difference leaked.
