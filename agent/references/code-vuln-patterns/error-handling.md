# Error Handling — Fail-Open and Recovery Bugs

> Target: Error handling bugs (CWE-755, CWE-252, CWE-754) that survive SAST because the
> error check exists but takes the wrong action, because error paths create new
> vulnerabilities (double-free, resource leak, partial state), or because exception
> handling swallows security-critical failures. These require reasoning about what
> happens AFTER the error is detected, not just whether it is detected.

---

## What SAST Already Catches (Skip These)

- Empty catch blocks with no logic (`catch (Exception e) {}`)
- Unchecked `malloc` return value in the same function
- Missing error check on `fopen` immediately followed by `fread`
- Basic unchecked return value from well-known functions in same scope
- `except: pass` in Python (bare except with no body)

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Fail-Open — Error Detected But Execution Continues

The error check exists. The developer logs or records the error. But the function
does not return, abort, or branch to safe handling — execution falls through to
code that assumes the operation succeeded.

```c
int authenticate(conn_t *conn, const char *token) {
    int result = verify_token(token);
    if (result != AUTH_SUCCESS) {
        log_warning("Authentication failed: %d", result);
        // BUG: no return statement — falls through to authorized path
    }
    conn->authenticated = true;
    return 0;
}
```

SAST sees the `if` block and considers the error "handled." The missing `return -1`
inside the block is a logic error that requires understanding the function's security
contract: authentication failure must prevent the authenticated=true assignment.

### 2. Checked But Wrong Error Code — Inverted Logic

The return value is checked, but the comparison tests for the wrong value. A common
variant: POSIX functions return -1 on error, but the developer checks `!= 0`
(treating any non-zero as error) or `== 0` (treating zero as error when zero is
actually success).

```c
// OpenSSL: SSL_read returns >0 on success, 0 on clean shutdown, <0 on error
int n = SSL_read(ssl, buf, sizeof(buf));
if (n == 0) {
    // Developer thinks 0 = error, but 0 = clean shutdown
    handle_error();  // calls SSL_get_error, but the session is actually closing
}
if (n > 0) {
    process_data(buf, n);
}
// BUG: n < 0 (actual error) is not checked — falls through silently
```

```c
// POSIX: close() returns 0 on success, -1 on error
if (close(fd)) {  // correct for -1 error case
    // But EINTR means the fd is still open — retrying close() may close
    // a DIFFERENT fd that another thread opened in the meantime
}
```

### 3. Error Handler Creates New Vulnerability — Double-Free

The error path frees resources that the caller also frees, resulting in a
double-free. Each side's cleanup code is locally correct — the bug is in the
ownership contract during error recovery.

```c
int send_message(conn_t *conn, msg_t *msg) {
    if (serialize(msg) < 0) {
        free(msg->payload);  // error cleanup in callee
        return -1;
    }
    queue_send(conn, msg);
    return 0;
}

// Caller
msg_t *msg = create_message(data);
if (send_message(conn, msg) < 0) {
    free(msg->payload);  // caller also frees — double-free!
    free(msg);
}
```

The ownership of `msg->payload` is ambiguous on the error path. The callee frees
it during error cleanup, then returns an error code that tells the caller "it
failed" — and the caller also cleans up.

### 4. Exception Swallowing Hides Security Failure

A try/catch block around security-critical code catches all exceptions, including
those that indicate a security violation. Execution continues with an unvalidated
or partially validated state.

```python
def validate_request(request):
    try:
        verify_signature(request.body, request.headers['X-Signature'])
        check_timestamp(request.headers['X-Timestamp'])
        validate_permissions(request.user, request.resource)
    except Exception:
        # "Log and continue" pattern — swallows crypto verification failures
        logger.warning("Validation issue, continuing with defaults")
    # Execution reaches here whether validation passed or failed
    return process_request(request)
```

The developer intended to catch transient errors (network timeouts, missing
optional headers). Instead, the broad catch swallows `InvalidSignatureError`,
`ExpiredTimestampError`, and `PermissionDeniedError` — all security-critical.

### 5. Resource Leak on Error Path — DoS via Exhaustion

A file handle, socket, or lock is acquired. An error occurs before the cleanup
code runs. The resource is never released, and after enough errors, the system
runs out of that resource type.

```c
int process_upload(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    char *buf = malloc(MAX_SIZE);
    if (!buf) return -1;  // BUG: fd leaked — not closed before return

    ssize_t n = read(fd, buf, MAX_SIZE);
    if (n < 0) {
        free(buf);
        return -1;  // BUG: fd still leaked
    }

    process(buf, n);
    free(buf);
    close(fd);
    return 0;
}
```

Each error path leaks the file descriptor. An attacker triggering repeated OOM
conditions (via large allocations elsewhere) causes fd exhaustion, denying service
to all file operations system-wide.

### 6. Partial Initialization on Error — Half-Constructed Object

A constructor or init function initializes several fields. An error occurs midway.
The partially initialized object is returned or used, with some fields valid and
others holding garbage or NULL.

```c++
class Session {
public:
    Session(const Config& cfg) {
        socket_ = connect(cfg.host, cfg.port);      // field 1: set
        tls_ = setup_tls(socket_, cfg.cert);         // field 2: set
        auth_ = authenticate(tls_, cfg.credentials); // field 3: may fail
        if (!auth_) throw AuthError();  // throws AFTER socket_ and tls_ are set
        cache_ = init_cache(cfg.cache_size);          // field 4: never reached
    }
    ~Session() {
        delete cache_;
        cleanup_auth(auth_);
        SSL_free(tls_);
        close(socket_);
    }
};
```

If the constructor throws on field 3, the destructor for `Session` does NOT run
(C++ rule: destructors only run for fully constructed objects). `socket_` and
`tls_` are raw handles — not RAII wrappers — so they leak silently. Member
sub-object destructors run for fully constructed members, but raw ints and
pointers have trivial destructors that release nothing. The fix is either RAII
wrappers for each resource (`unique_ptr`, socket guard) or two-phase init where
the constructor cannot throw and a separate `init()` returns an error code.

### 7. Error Code Propagation Loss

Function A returns a detailed error code (EACCES, ENOMEM, ENOENT). Function B
converts it to a boolean (success/failure), losing the specific error type.
Function C receives the boolean and cannot distinguish recoverable from fatal.

```c
// Function A: detailed error
int read_config(const char *path, config_t *cfg) {
    if (access(path, R_OK) != 0) return errno;  // EACCES, ENOENT, etc.
    // ...
    return 0;
}

// Function B: converts to bool
bool load_config(config_t *cfg) {
    return read_config("/etc/app.conf", cfg) == 0;  // loses error type
}

// Function C: can't distinguish "file not found" from "permission denied"
void init_app() {
    config_t cfg = DEFAULT_CONFIG;
    if (!load_config(&cfg)) {
        // Uses default config for ALL errors — including EACCES
        // "File not found" → default config is reasonable
        // "Permission denied" → default config is a security downgrade
        log_info("Using default configuration");
    }
}
```

### 8. Library Initialization Failure Ignored

A security library's init function returns an error, but the caller proceeds.
All subsequent operations from that library silently produce insecure results.

```c
int main() {
    SSL_library_init();  // old OpenSSL — returns 1 on success
    // Return value not checked. If it fails (out of memory, missing
    // entropy source), all subsequent SSL operations use uninitialized
    // crypto state — connections are not actually encrypted.

    RAND_status();  // returns 1 if PRNG is seeded, 0 if not
    // Not checked — if PRNG is unseeded, SSL_connect will use
    // predictable keys. The connection "works" but is breakable.
}
```

---

## C/C++ Specific Patterns

### errno Misuse
`errno` is a thread-local global set by the last failed syscall. Reading it after
an intervening call (even a successful one) gives stale data:
```c
fd = open(path, O_RDONLY);
log_debug("opened %s", path);  // log_debug may call write(), resetting errno
if (fd < 0) {
    log_error("open failed: %s", strerror(errno));  // errno is from write(), not open()
}
```

### OpenSSL Error Queue
OpenSSL pushes errors onto a per-thread error queue. If the queue is not cleared
after handling an error, the next call that checks the queue may see stale errors
from a prior operation — leading to false error detection or missed real errors.

### setjmp/longjmp Cleanup Bypass
C code using `setjmp`/`longjmp` for error handling (common in parsers, image decoders)
skips all stack frames between the `longjmp` call and the `setjmp` target. Cleanup
code in those skipped frames never runs — resources are leaked and destructors (in
C++ code mixed with C) are not called.

---

## Python Specific Patterns

### Bare except / except Exception
```python
try:
    result = crypto.verify(signature, data)
except Exception as e:
    # Catches VerificationError (security failure) AND
    # ConnectionError (transient) AND KeyboardInterrupt (user abort)
    result = None  # fail-open: treats all errors as "no result"
```

The fix is to catch only the specific expected exceptions and let security-
critical exceptions propagate.

### contextmanager Cleanup Failures
```python
@contextmanager
def temp_elevated_privileges():
    os.seteuid(0)
    try:
        yield
    finally:
        os.seteuid(original_uid)  # if this raises, privileges remain elevated
```

### asyncio Exception Swallowing
```python
async def handle_connection(reader, writer):
    try:
        data = await reader.read(1024)
        await process(data)
    except asyncio.CancelledError:
        pass  # swallows cancellation — cleanup may not complete
    except Exception:
        pass  # swallows ALL errors — connection in unknown state
```

Unhandled exceptions in asyncio tasks are logged but do not crash the program.
In Python 3.8+, they generate a warning, but the program continues with the
failed task silently abandoned and its resources potentially leaked.

---

## JavaScript Specific Patterns

### Unhandled Promise Rejection
```javascript
async function processPayment(order) {
    const charge = stripe.charges.create(order);  // missing await
    // charge is a Promise, not a result — no error handling
    return { status: 'success' };  // returns before charge completes
}
// If stripe.charges.create rejects, the rejection is unhandled
// Node.js >= 15 terminates on unhandled rejection; older versions silently ignore
```

### try/catch Too Broad Around Async Operations
```javascript
try {
    const user = await getUser(id);
    const perms = await checkPermissions(user);
    const result = await executeAction(user, perms);
} catch (err) {
    // Which operation failed? All three errors land here.
    // Developer returns a generic "try again" response for ALL failures,
    // including "permission denied" — which should not be retried.
    res.status(500).json({ error: 'Internal error, please retry' });
}
```

### Callback Error Parameter Ignored
```javascript
fs.readFile(configPath, (err, data) => {
    // err parameter ignored — no check
    const config = JSON.parse(data);  // data is undefined if err occurred
    // JSON.parse(undefined) throws — but this is a different error than the original
    applyConfig(config);
});
```

The Node.js callback convention passes errors as the first argument. Ignoring
it does not suppress the error — it transforms a file-read error into a JSON
parse error, losing all diagnostic information.

---

## Detection Questions

1. **"After this error is detected, does execution actually stop or diverge?"**
   Follow the control flow after every error check. If there is no `return`,
   `throw`, `goto cleanup`, or `break` — the error is logged but ignored.

2. **"Does this error handler free/release resources that the caller also frees?"**
   On every error return path, trace which resources are freed by the callee
   and which the caller expects to free. Overlapping ownership is a double-free.

3. **"Does this catch/except block catch more exception types than intended?"**
   List the exceptions the developer expects. List the exceptions the catch
   actually catches. Any security-critical exception in the latter but not
   the former is swallowed.

4. **"Is the specific error type preserved through the call chain, or is it reduced to bool?"**
   At each function boundary, compare the error type/code going in with what
   comes out. Any reduction (detailed code to bool, multiple errors to single
   code) may collapse security-fatal errors into recoverable ones.

5. **"On every error return path, are ALL acquired resources released?"**
   For each resource acquired before the error point (fd, lock, malloc, handle),
   verify it is released on the error path. A missing release is a leak; enough
   leaks are a DoS.

---

## Real CVE Examples

### CVE-2014-0224 (OpenSSL — CCS injection / error handling bypass)
The OpenSSL ChangeCipherSpec message was accepted at unexpected points in the TLS
handshake. The state machine checked for the message type but did not verify the
handshake state before processing it. The error was that receiving CCS before the
key exchange was complete should have been a fatal error — instead, the code
processed it, causing the connection to use weak or predictable keys. The error
condition was detectable but the handler took the wrong action: it processed the
CCS rather than aborting the handshake.

### CVE-2020-0601 (Windows CryptoAPI — ECC curve parameter validation fail-open)
Windows CryptoAPI (crypt32.dll) failed to fully validate ECC certificate curve
parameters. When verifying a certificate's ECC public key, the API checked that
the key was on a named curve but did not verify that the curve's generator point
matched the standard definition. An attacker could craft a certificate with a
custom generator that made their key appear to belong to a trusted CA's curve.
The validation existed but was incomplete — the missing generator check caused
the verifier to fall through to acceptance, treating a forged certificate chain
as valid. The error was a classic fail-open: partial validation that looked
correct but silently accepted malformed inputs.

### CVE-2019-1559 (OpenSSL — padding oracle via error differentiation)
OpenSSL's TLS record processing returned different error types for padding errors
vs. MAC errors in CBC mode. The error handling paths had different timing
characteristics — a padding error returned faster than a MAC error. An attacker
could distinguish the two errors by measuring response time, building a padding
oracle that decrypted TLS traffic. The error handling was "correct" in isolation
(both errors rejected the record), but the differential behavior between error
paths leaked information.
