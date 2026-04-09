# Use-After-Free — Lifetime Reasoning Across Modules

> Target: UAF bugs that survive SAST because the free and the use happen in different
> modules, different threads, or different phases of a state machine. These require
> understanding object lifetime semantics, ownership transfer, and async execution models.

---

## Baseline Patterns (Single-Function / Single-Scope)

Toolchain-catchable patterns. Record as findings if encountered during orientation —
on unaudited codebases these are real, exploitable bugs that no prior tool run has caught.
Invest primary analysis time in the LLM-advantage patterns below.

- `free(p); *p = 0;` — direct free-then-use in the same function
- `free(p); free(p);` — double-free in the same function
- Simple null-after-free violations where the use is in the same basic block
- Return-after-free within a single function scope

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Object Freed in Module A, Referenced in Module B via Callback

Module A owns an object and frees it during cleanup. Module B registered a callback
that holds a pointer to the object. When the callback fires (possibly triggered by
the cleanup itself), it dereferences the freed pointer.

```c
// Module A: connection manager
void close_connection(conn_t *conn) {
    unregister_from_event_loop(conn->fd);  // removes fd, but pending callbacks?
    free(conn->read_buffer);
    free(conn);
}

// Module B: event loop (runs callbacks from queue)
void process_event(event_t *ev) {
    conn_t *conn = ev->data;     // conn was freed by close_connection!
    conn->handler(conn, ev);     // UAF
}
```

The race: if `close_connection` and `process_event` can run concurrently (threads)
or if the event was already queued before `unregister_from_event_loop` runs, the
callback executes against freed memory.

**In cURL**: Transfer handles freed while multi-handle has queued operations.
**In git**: Packed refs freed while another thread holds a reference for reading.

### 2. Reference Counting Errors Across Modules

Module A increments refcount on acquisition, module B also acquires but forgets to
increment (or decrements twice on its error path). The object is freed when refcount
reaches zero, but outstanding references remain.

```c
// Module A: adds object to cache (increments refcount)
void cache_add(cache_t *c, obj_t *obj) {
    obj->refcount++;
    c->entries[c->count++] = obj;
}

// Module B: takes object from cache but doesn't increment refcount
obj_t *cache_get(cache_t *c, int idx) {
    return c->entries[idx];  // BUG: should increment refcount
}

// Module C: done with object, decrements refcount
void release_obj(obj_t *obj) {
    if (--obj->refcount == 0) free(obj);
}
// After A calls release_obj, refcount hits 0 and obj is freed.
// But B's caller still holds a pointer.
```

The bug is in B, but it manifests in whatever code uses B's return value after A
releases. SAST can't reason about reference counting semantics.

### 3. Async Cleanup Racing With In-Flight Operations

Teardown code frees a resource while an async operation (network I/O, timer, signal
handler) is still in progress using that resource.

```c
// Thread 1: teardown
void shutdown_tls(tls_ctx *ctx) {
    SSL_shutdown(ctx->ssl);
    SSL_free(ctx->ssl);    // frees the SSL object
    free(ctx);
}

// Thread 2: read callback (may be in-flight during shutdown)
void on_data_ready(tls_ctx *ctx) {
    int n = SSL_read(ctx->ssl, buf, sizeof(buf));  // UAF if shutdown ran first
}
```

**In cURL**: The multi-interface allows multiple transfers to share connections.
Closing one transfer may free a connection while another transfer's callback is
pending on the same connection.

### 4. State Machine Transitions Freeing Resources

A state machine transitions from state S1 to S2, freeing S1's resources. But an
event handler still processing an S1 event holds pointers to S1's resources.

```c
// State machine transition
void transition_to_idle(session_t *sess) {
    free(sess->active_request);
    sess->active_request = NULL;
    sess->state = IDLE;
}

// Event handler — may be called during transition
void handle_response(session_t *sess, response_t *resp) {
    if (sess->active_request) {
        // Race: active_request freed between the NULL check and the dereference
        sess->active_request->status = resp->code;  // UAF
    }
}
```

### 5. Iterator Invalidation Across Function Calls

A container is modified (element removed, container resized) while an iteration is
in progress. The iterator holds pointers to container internals that become invalid.

```c
// Iterating over a linked list
for (node_t *n = list->head; n; n = n->next) {
    process_node(n);  // process_node may remove n from the list and free it!
    // n->next is now accessing freed memory
}
```

**In git**: Iterating over ref lists while a callback triggered by processing one
ref modifies the ref list.

### 6. Double-Free via Error Path Ownership Confusion

Both caller and callee believe they own a resource. On the success path, ownership
is implicitly transferred. On the error path, both try to free it.

```c
// Callee: takes ownership on success, caller retains on failure
int send_data(conn_t *conn, buffer_t *buf) {
    if (conn->state != CONNECTED) {
        free(buf);  // callee frees on error
        return -1;
    }
    queue_write(conn, buf);  // ownership transferred to write queue
    return 0;
}

// Caller
buffer_t *buf = create_buffer(data, len);
if (send_data(conn, buf) < 0) {
    free(buf);  // double-free! callee already freed it
    return ERROR;
}
```

The error-path ownership contract is ambiguous and exists only in documentation
(or not at all). Each side's code looks correct in isolation.

---

## C/C++ Specific Patterns

### Custom Allocator Tracking
Projects with custom allocators (slab allocators, pool allocators, arena allocators)
may reuse memory immediately after "free." A UAF against a pool allocator accesses
a different live object rather than freed heap memory, making it both harder to
detect and potentially more dangerous (type confusion).

### RAII Bypass in C
C projects simulate RAII with cleanup labels and goto. If a new code path is added
that returns before the cleanup label, or if a goto jumps over the initialization
of a resource but the cleanup frees it, the result is either a leak or a UAF.

```c
int process(ctx_t *ctx) {
    resource_t *r = NULL;
    if (condition_a) goto cleanup;  // r is NULL — free(NULL) is safe
    r = acquire_resource();
    if (condition_b) return -1;     // BUG: r is leaked (bypass cleanup)
    use(r);
cleanup:
    free(r);
    return 0;
}
```

### Callback Registration Lifetime
If a callback function pointer and its context data are registered separately,
the context data may be freed while the callback registration is still active.
The next event dispatches to a valid function with a dangling context pointer.

---

## Python Specific Patterns

### C Extension Reference Counting Bugs
The most common source of UAF in Python is C extension modules that mismanage
reference counts.

```c
// C extension function
static PyObject* process(PyObject *self, PyObject *args) {
    PyObject *list = PyList_New(0);
    PyObject *item = PyList_GetItem(some_list, 0);  // borrowed reference!
    // ... code that might trigger GC or modify some_list ...
    PyList_Append(list, item);  // item may have been freed if some_list was modified
    return list;
}
```

`PyList_GetItem` returns a borrowed reference. If anything between the GetItem and
the subsequent use could modify the list (even indirectly via Python code execution),
the borrowed reference may be invalid.

### weakref Callback Timing
```python
import weakref
obj = SomeClass()
ref = weakref.ref(obj, callback_function)
del obj  # callback_function is called; if it accesses other objects
         # that were in the same reference cycle, they may already be finalized
```

### __del__ Ordering in Reference Cycles
When a reference cycle is collected, the order of `__del__` calls is undefined.
If one object's `__del__` accesses another object in the same cycle, that object
may already be in a partially finalized state.

---

## JavaScript Specific Patterns

### Event Listener on Garbage-Collected Object
In browser environments, if a DOM node is removed from the document and garbage
collected, event listeners attached to it may still be in the event queue. This
rarely causes memory corruption (JS is memory-safe) but can cause logic bugs where
handlers operate on stale state.

### SharedArrayBuffer Race
```javascript
// Worker A
const view = new Int32Array(sharedBuffer);
view[0] = 42;

// Worker B — no synchronization
if (view[0] !== 0) {
    let val = view[0];  // may read a different value than the check saw
}
```
Not a traditional UAF, but SharedArrayBuffer allows workers to observe partially
constructed objects or torn reads — the JS equivalent of accessing freed memory.

### Native Addon prevent_gc Patterns
Node.js native addons must prevent garbage collection of JS objects that C++ code
holds references to. If the prevent-gc mechanism fails (wrong weak reference setup,
missing persistent handle), the V8 GC frees the JS object while C++ still references it.

```cpp
// Correct: persistent handle prevents GC
Nan::Persistent<v8::Object> persistent(jsObject);

// Bug: weak persistent allows GC, callback tries to use the C++ side
persistent.SetWeak(pointerToCppObj, weakCallback, Nan::WeakCallbackType::kParameter);
// If weakCallback doesn't clean up the C++ side, subsequent access is UAF
```

---

## Detection Questions

1. **"Who owns this object — and does ownership transfer on error paths?"**
   Trace the lifecycle: creation, every function that stores a pointer to it, every
   function that frees it. On every error path, who is responsible for cleanup?

2. **"Can this callback fire after the object it references has been freed?"**
   Find all callback registrations. For each, find where the callback's context/data
   pointer is freed. Is the callback always deregistered before the free? Can
   deregistration race with callback dispatch?

3. **"Are reference counts incremented and decremented in matched pairs across all modules?"**
   For refcounted objects, trace every inc and every dec across all files. A missing
   inc on an acquisition path or an extra dec on an error path causes UAF.

4. **"Can a state machine transition free resources while event handlers are in-flight?"**
   Map all state transitions and all event handlers. For each transition that frees
   resources, identify which event handlers reference those resources and whether
   they can be running concurrently.

5. **"Does any function modify a container while another function iterates over it?"**
   Find all iteration loops. For each, trace every function called within the loop
   body. Does any of them insert, remove, or reallocate the container?

---

## Real CVE Examples

### CVE-2023-27535 (cURL — connection reuse UAF)
The cURL multi-interface reused connections across transfers. When one transfer
completed and freed its connection data, a queued transfer that had been assigned
the same connection could dereference the freed connection state. The free happened
in the transfer-completion cleanup code, and the use happened in the connection-reuse
matching code — two separate modules with different assumptions about connection
lifetime.

### CVE-2024-32002 (git — recursive clone UAF)
During recursive cloning with submodules, git could be tricked into freeing a
repository object while submodule operations still held references to it. The
parent repository's cleanup logic ran when the parent clone completed, but
submodule processing (which happened in a different phase) still accessed the
parent's repository structure. The free and use were in different subsystems
(clone vs. submodule) with no explicit ownership tracking.

### CVE-2019-5481 (cURL — FTP double-free)
During FTP wildcard matching, a `conn` structure's path data was freed in the
wildcard cleanup function and again in the connection close function. Both functions
believed they owned the path data. On the success path, only one ran. On certain
error paths (particularly timeout-related), both ran, causing a double-free.
