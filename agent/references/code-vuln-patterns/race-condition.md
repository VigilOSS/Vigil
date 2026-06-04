---
description: State machine bugs, async refactoring artifacts, signal handler races
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Race Conditions — State Machine & Async Bugs

> Target: Race conditions that survive SAST because they involve state machine transitions,
> async execution ordering, or time-of-check-to-time-of-use gaps that span multiple functions,
> modules, or threads. These require understanding execution ordering semantics, not just
> lock presence.

---

## Baseline Patterns (Single-Function / Single-Scope)

Toolchain-catchable patterns. Record as findings if encountered during orientation —
on unaudited codebases these are real, exploitable bugs that no prior tool run has caught.
Invest primary analysis time in the LLM-advantage patterns below.

- Basic TOCTOU on file open: `access()` then `open()` in the same function
- Missing lock around shared variable access (simple data-race detectors)
- Obvious thread-safety violations in single-function scope
- `stat()` then `open()` without `O_NOFOLLOW` in the same function

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. State Machine Transitions With Out-of-Order Events

A state machine expects events in order (INIT → AUTH → READY → DATA). When concurrent
events arrive out of order (DATA arrives before AUTH completes), the transition handler
may skip validation that only happens in the AUTH state.

```c
void handle_event(session_t *sess, event_t *ev) {
    switch (sess->state) {
    case STATE_AUTH:
        if (ev->type == AUTH_SUCCESS) {
            sess->authenticated = true;
            sess->state = STATE_READY;
        }
        break;
    case STATE_READY:
        if (ev->type == DATA_REQUEST) {
            // No check for sess->authenticated here — assumed true
            // because we "must have" passed through STATE_AUTH
            process_data(sess, ev);
        }
        break;
    }
}

// Race: concurrent thread sets sess->state = STATE_READY directly
// (via a different code path), bypassing STATE_AUTH entirely
```

**In cURL**: TLS handshake states, HTTP/2 stream states, FTP control channel states.
**In git**: Pack negotiation states, fetch/push protocol states.

### 2. TOCTOU Spanning Multiple Function Calls

The time-of-check and time-of-use are not just `stat()` then `open()` — they span
multiple function calls across different modules.

```c
// Module A: validation (time-of-check)
int validate_path(const char *path) {
    struct stat st;
    if (lstat(path, &st) < 0) return -1;
    if (!S_ISREG(st.st_mode)) return -1;  // must be regular file
    if (st.st_uid != expected_uid) return -1;  // must be owned by expected user
    return 0;
}

// Module B: processing (time-of-use, called later, possibly much later)
int process_file(const char *path) {
    int fd = open(path, O_RDONLY);  // path could now be a symlink to /etc/shadow
    // ... read and process
}

// Caller: check then use
if (validate_path(user_path) == 0) {
    // WINDOW: attacker replaces file with symlink here
    process_file(user_path);
}
```

The TOCTOU window is between `validate_path` returning and `process_file` running.
SAST catches `stat(); open()` in the same function but not across module boundaries.

**In git**: Worktree file access — git checks file properties, then later reads/writes
the file. If the file is on a shared filesystem or the attacker has local access, the
file can be swapped between check and use.

### 3. Async Refactoring Artifacts

Code originally written as synchronous (with implicit ordering from the call stack)
is refactored to async. Lock ordering that was guaranteed by the call stack is no longer
guaranteed between await points.

```c
// Original synchronous code (safe):
void process_request(ctx_t *ctx) {
    lock(ctx->mutex);
    data = read_data(ctx);       // blocking — lock held throughout
    validate(data);
    write_response(ctx, data);
    unlock(ctx->mutex);
}

// Refactored to async (unsafe):
async void process_request(ctx_t *ctx) {
    lock(ctx->mutex);
    data = await read_data(ctx);  // await releases execution
    // ANOTHER TASK CAN RUN HERE — but lock is still held (deadlock)
    // Or: developer "fixes" by unlocking before await:
    unlock(ctx->mutex);
    data = await read_data(ctx);
    lock(ctx->mutex);             // ctx state may have changed
    validate(data);               // validation based on stale assumption
    write_response(ctx, data);
    unlock(ctx->mutex);
}
```

### 4. Connection State Shared Between Handler and Cleanup Thread

A TLS connection is being used by a request handler while a timeout thread or
cleanup thread tears down the connection.

```c
// Request handler thread
void handle_request(conn_t *conn) {
    SSL_read(conn->ssl, buf, len);  // reading data
    // ... processing ...
    SSL_write(conn->ssl, resp, resp_len);  // writing response
}

// Timeout thread
void check_timeouts() {
    for (conn_t *c = conn_list; c; c = c->next) {
        if (now - c->last_activity > TIMEOUT) {
            SSL_shutdown(c->ssl);  // races with SSL_read/SSL_write above
            close_conn(c);
        }
    }
}
```

**In cURL**: The multi-interface timeout handling runs in a different context than
the transfer callbacks, and both access connection state.

### 5. Signal Handler Accessing Mainline Data

Signal handlers that access data structures being modified by the main thread.
Only async-signal-safe functions may be called from signal handlers, but in
practice, many programs violate this.

```c
// Global state
static transfer_t *current_transfer;

// Main thread
void do_transfer(transfer_t *t) {
    current_transfer = t;
    // ... long operation ...
    current_transfer = NULL;
}

// Signal handler (e.g., SIGINT for progress display or cleanup)
void signal_handler(int sig) {
    if (current_transfer) {
        printf("Transfer: %s at %d%%\n",   // printf is not async-signal-safe
               current_transfer->url,        // may be partially written
               current_transfer->progress);
    }
}
```

**In cURL**: Progress callbacks and signal handling during transfers.
**In wget**: Signal handlers for progress display and graceful shutdown.

### 6. Mutex Ordering Violations

Module A locks mutex M1 then M2. Module B locks M2 then M1. This causes deadlock
with certainty under specific timing, or — if the mutexes protect overlapping state —
a race condition where each module sees inconsistent state.

```c
// Module A
void update_cache(cache_t *c, conn_t *conn) {
    lock(c->mutex);       // lock 1
    lock(conn->mutex);    // lock 2
    c->entries[conn->id] = conn->data;
    unlock(conn->mutex);
    unlock(c->mutex);
}

// Module B
void close_connection(conn_t *conn, cache_t *c) {
    lock(conn->mutex);    // lock 2
    lock(c->mutex);       // lock 1 — DEADLOCK with update_cache
    remove_cache_entry(c, conn->id);
    unlock(c->mutex);
    unlock(conn->mutex);
}
```

---

## C/C++ Specific Patterns

### pthread Races
- `pthread_mutex_lock`/`unlock` pairs that don't cover the full critical section
- `pthread_cond_wait` without re-checking the condition in a loop (spurious wakeup)
- Missing memory barriers: reads/writes to shared state without locks or atomics
  may be reordered by the CPU or compiler

### Signal Safety
Only functions listed in POSIX as async-signal-safe may be called from signal handlers.
Common violations: `malloc`, `free`, `printf`, `syslog`, mutex operations, and any
function that's not explicitly listed. In practice, most signal handler bugs are latent
and only manifest under heavy load or specific timing.

### volatile Misuse
`volatile` prevents compiler optimization of reads/writes but does NOT provide atomicity
or memory ordering. Code that uses `volatile` instead of atomics or mutexes has data
races that may appear to work on x86 (strong memory model) but fail on ARM/RISC-V
(weak memory model).

### Lock-Free Data Structure Bugs
Custom lock-free queues, stacks, and lists are notoriously difficult to get right.
ABA problems (a pointer is freed and a new allocation returns the same address, fooling
a CAS operation) are the classic lock-free data structure bug.

---

## Python Specific Patterns

### GIL Does Not Protect Against All Races
The GIL prevents concurrent execution of Python bytecode but is released during I/O
operations and C extension calls. Code that assumes atomicity of Python operations
can race when those operations release the GIL.

```python
# Unsafe under concurrent access:
if key in shared_dict:       # GIL held, but...
    # another thread could delete key here if a C extension call happens
    value = shared_dict[key]  # KeyError
```

### asyncio Task Cancellation
```python
async def process(resource):
    await resource.acquire()
    try:
        await do_work()  # CancelledError can be raised here
    finally:
        resource.release()  # may not run if task is cancelled and not awaited
```

`asyncio.Task.cancel()` raises `CancelledError` at the next await point. If the
task holds resources, the cancellation may leave them in an inconsistent state.
The `finally` block runs, but if `resource.release()` is also async and the
cancellation is aggressive, even the cleanup may not complete.

### threading.Event Races
```python
event = threading.Event()
result = None

def worker():
    global result
    result = compute()  # may not be visible to main thread immediately
    event.set()

threading.Thread(target=worker).start()
event.wait()
use(result)  # result may still be None due to memory ordering
```

In CPython this usually works due to the GIL, but it's technically a data race and
may fail with future Python implementations or JIT compilers.

---

## JavaScript Specific Patterns

### Microtask vs Macrotask Ordering
```javascript
// Developer assumes this order: A, B, C
console.log('A');
setTimeout(() => console.log('C'), 0);  // macrotask
Promise.resolve().then(() => console.log('B'));  // microtask

// Actual order: A, B, C — microtasks run before macrotasks
// Race condition if code depends on setTimeout running before Promise
```

### SharedArrayBuffer Atomics
SharedArrayBuffer allows shared memory between workers. Without `Atomics` operations,
reads and writes may be reordered and torn.

```javascript
// Worker A
const view = new Int32Array(sab);
view[0] = 1;  // non-atomic write
view[1] = 2;  // non-atomic write

// Worker B
if (view[1] === 2) {
    // view[0] might not be 1 yet — no ordering guarantee without Atomics
    console.log(view[0]);  // could print 0
}
```

### Worker Thread Message Ordering
Node.js worker threads communicate via `postMessage`. Messages are ordered per-channel,
but if a worker communicates with multiple workers, there's no global ordering guarantee.

---

## Detection Questions

1. **"Can these two code paths execute concurrently, and do they share mutable state?"**
   Map all threads, async tasks, signal handlers, and event callbacks. For each pair
   that shares state, identify the synchronization mechanism.

2. **"Between this check and this use, what else can execute?"**
   For every validation → use pair, enumerate all possible interleaving points:
   await/yield points, signal delivery, lock release, context switches.

3. **"Was this code originally synchronous and later made async?"**
   Look for async refactoring artifacts: locks acquired before await points,
   shared state accessed across await boundaries without re-validation.

4. **"Do all code paths that acquire multiple locks use the same ordering?"**
   Build a lock-ordering graph. Any cycle is a potential deadlock. Any partial
   ordering difference is a potential race.

5. **"Does any signal handler or interrupt handler access non-atomic shared state?"**
   Signal handlers may interrupt at any point. If they access global state that's
   being modified, the state may be inconsistent.

---

## Real CVE Examples

### CVE-2016-5195 (Linux kernel — Dirty COW page table race)
The copy-on-write mechanism in the Linux kernel memory manager had a race condition
between the page fault handler and the `madvise(MADV_DONTNEED)` system call. Thread 1
triggered a write fault on a COW-mapped read-only page, causing the kernel to allocate
a writable copy. Thread 2 simultaneously called `madvise(MADV_DONTNEED)` on the same
range, discarding the private copy and reverting the mapping to the original read-only
file page. The page table update in the fault handler then wrote to the original page
instead of the copy. The check (page is COW) and the use (write to the resolved page)
were in different kernel functions with no lock spanning both.

### CVE-2022-24765 (git — unsafe directory ownership check)
Git checked directory ownership to prevent running in directories owned by other users
(a security boundary). The ownership check used `stat()` on the directory, but the
actual git operations happened later. On a shared system, an attacker could swap the
directory (or its parent) between the ownership check and git's use of the directory.
The TOCTOU window spanned multiple function calls across the initialization code.

### CVE-2023-0386 (Linux kernel — OverlayFS TOCTOU privilege escalation)
The OverlayFS filesystem had a TOCTOU race in its file copy-up mechanism. When a file
was modified on an overlay mount, the kernel checked the file's permissions and
ownership in the lower layer, then performed the copy-up to the upper layer. An
attacker could exploit the race by swapping a SUID binary into the lower layer between
the permission check and the copy-up operation. The security check in `ovl_copy_up_one`
and the actual file copy in `ovl_do_copy_up` were separate functions with no atomic
guarantee, allowing a crafted setuid executable to be copied to the upper layer with
elevated privileges intact.
