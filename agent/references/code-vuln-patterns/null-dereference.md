# Null Dereference — Cross-Function Null Propagation

> Target: Null pointer dereference bugs (CWE-476) that survive SAST because the null
> return and the dereference happen in different functions, different error paths, or
> across ownership boundaries. These require reasoning about how null values propagate
> through call chains, optional fields, and error-recovery paths.

---

## What SAST Already Catches (Skip These)

- `malloc()` return used without NULL check in the same function
- Direct `*ptr` where `ptr` is visibly NULL from a literal assignment
- Simple `fopen()` without NULL check followed by `fread()` in same scope
- Obvious null dereference after failed allocation in a single basic block

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Cross-Function Null Propagation

Function A returns NULL on error. Function B stores the result in a struct field.
Function C retrieves the field and dereferences it. Each function individually
handles its own contract — but the NULL slips through the cracks between them.

```c
// Function A: returns NULL on error
user_t *lookup_user(const char *name) {
    user_t *u = db_query(name);
    if (!u) return NULL;  // clearly documented
    return u;
}

// Function B: stores result, does not check NULL
void init_session(session_t *sess, const char *username) {
    sess->user = lookup_user(username);  // may be NULL
    sess->created = time(NULL);
    sess->active = true;
}

// Function C: assumes user is always set
void check_permissions(session_t *sess) {
    if (sess->user->role == ADMIN) {  // NULL dereference
        grant_admin_access(sess);
    }
}
```

The bug spans three functions across potentially three files. Function B is the
real culprit — it stores NULL without checking — but the crash happens in C.

### 2. Partial Null Checks — Checked Pointer, Unchecked Member

The pointer itself is checked for NULL, but a member of the pointed-to struct
could independently be NULL and is not checked.

```c
void process_response(response_t *resp) {
    if (!resp) return;  // checks resp itself
    // resp->headers could be NULL if the response had no headers
    int content_length = find_header(resp->headers, "Content-Length");
    // find_header crashes if resp->headers is NULL
}

header_t *find_header(header_list_t *headers, const char *name) {
    for (int i = 0; i < headers->count; i++) {  // NULL deref on headers
        if (strcmp(headers->entries[i].name, name) == 0)
            return &headers->entries[i];
    }
    return NULL;
}
```

The developer checked `resp` but assumed `resp->headers` is always populated.
SAST flags the missing check on `resp` but not on `resp->headers` because the
member's nullability depends on semantic context (a valid response with no headers).

### 3. Error-Path Silent Failure

An object is initialized to NULL. An initialization function is called but may
fail silently (return without error, or return an error code that the caller
ignores). The object is then used as if initialization succeeded.

```c
ssl_ctx_t *ctx = NULL;

int init_ssl(ssl_ctx_t **out) {
    *out = SSL_CTX_new(TLS_method());
    if (!*out) return -1;
    if (SSL_CTX_set_cipher_list(*out, CIPHERS) != 1) {
        SSL_CTX_free(*out);
        *out = NULL;
        return -1;  // returns error, but caller may ignore
    }
    return 0;
}

// Caller
init_ssl(&ctx);  // return value ignored!
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  // ctx is NULL → crash
```

The init function properly returns an error code. The caller ignores it. This
is a cross-function contract violation that SAST rarely catches because the
init function does its job correctly.

### 4. Race Between Check and Use (TOCTOU Null)

Thread 1 checks that a pointer is non-NULL. Thread 2 sets the pointer to NULL
(during cleanup or error handling). Thread 1 dereferences the now-NULL pointer.

```c
// Thread 1: request handler
void handle_request(server_t *srv) {
    if (srv->config) {  // check
        // Thread 2 may call shutdown() here, setting config = NULL
        int timeout = srv->config->timeout;  // use — potential NULL deref
        process_with_timeout(timeout);
    }
}

// Thread 2: shutdown
void shutdown_server(server_t *srv) {
    config_t *cfg = srv->config;
    srv->config = NULL;  // clears pointer
    free(cfg);           // frees the object
}
```

The check and use are in the same function, but the interleaving between threads
makes the check meaningless without a lock or atomic snapshot.

### 5. Optional Struct Fields — Caller Assumes Always Set

Some operations populate a struct field; others do not. Callers that assume the
field is always non-NULL crash when they encounter an object that went through
a different initialization path.

```c
// Path A: full initialization
void init_connection_with_tls(conn_t *conn) {
    conn->socket = create_socket();
    conn->tls = create_tls_context();  // sets tls field
    conn->buffer = create_buffer();
}

// Path B: plaintext initialization — no TLS
void init_connection_plain(conn_t *conn) {
    conn->socket = create_socket();
    conn->tls = NULL;                  // explicitly NULL
    conn->buffer = create_buffer();
}

// Consumer: assumes TLS is always present
void send_data(conn_t *conn, const char *data, size_t len) {
    SSL_write(conn->tls->ssl, data, len);  // NULL deref if plaintext conn
}
```

The code works for all TLS connections. The first plaintext connection crashes.
The optional nature of the `tls` field is not visible from `send_data` alone.

### 6. Null After Free — Pointer Not Cleared

A pointer is freed but not set to NULL. A later code path re-enters the function
and sees the stale non-NULL pointer, assumes the object is live, and dereferences
it. This is a UAF variant, but the root cause is the missing NULL assignment.

```c
void cleanup(ctx_t *ctx) {
    if (ctx->cache) {
        free_cache(ctx->cache);
        // BUG: ctx->cache not set to NULL
    }
}

void process(ctx_t *ctx) {
    if (!ctx->cache) {
        ctx->cache = create_cache();
    }
    // If cleanup() was called but process() re-enters:
    // ctx->cache is non-NULL (dangling pointer), so create_cache is skipped
    use_cache(ctx->cache);  // UAF — cache was freed
}
```

---

## C/C++ Specific Patterns

### realloc Returning NULL
`realloc(ptr, new_size)` returns NULL on failure but does NOT free the original
pointer. If the caller assigns `ptr = realloc(ptr, new_size)`, the original pointer
is lost on failure (memory leak) AND ptr is now NULL (null deref on next use).

```c
buf = realloc(buf, new_size);  // if this fails, buf is NULL and old memory is leaked
memcpy(buf, data, len);         // NULL dereference
```

### strdup / strndup Return NULL
String duplication functions allocate memory and can return NULL. They are often
used in chains where the result is immediately passed to another function:
```c
config->hostname = strdup(input);  // NULL if OOM
connect_to(config->hostname);       // NULL dereference
```

### C++ Smart Pointer Edge Cases
`std::unique_ptr::get()` returns nullptr after move. Code that saves the raw pointer
before a move, then accesses via the saved pointer, dereferences freed memory. Code
that calls `.get()` after a move dereferences null.

---

## Python Specific Patterns

### None Propagation (NoneType has no attribute X)
```python
def get_user(user_id):
    return db.query(User, user_id)  # returns None if not found

def get_user_email(user_id):
    user = get_user(user_id)
    return user.email  # AttributeError: 'NoneType' has no attribute 'email'
```

The `Optional[User]` return type is often undeclared. Callers chain method calls
without None guards. In web frameworks, this manifests as 500 errors when an
attacker provides an invalid ID.

### Dictionary .get() Default Confusion
```python
config = load_config()
timeout = config.get('timeout')  # returns None if key missing (not KeyError)
connection = connect(timeout=timeout)  # library may not handle None timeout
```

### Optional Type Without Guard in Type-Checked Code
Even with mypy, `Optional[X]` is only enforced in strict mode. In non-strict mode,
`None` flows freely through typed interfaces, and runtime null dereferences occur.

---

## JavaScript Specific Patterns

### null vs undefined Confusion
```javascript
function getUser(id) {
    const user = users.find(u => u.id === id);
    // find() returns undefined if not found, not null
    if (user !== null) {  // WRONG CHECK — undefined !== null is true
        return user.name;  // TypeError: Cannot read property 'name' of undefined
    }
}
```

### Optional Chaining Missed in One Path
```javascript
// Safe path uses optional chaining:
const name = user?.profile?.name;

// Unsafe path forgets it:
function updateProfile(user) {
    user.profile.name = newName;  // TypeError if profile is null/undefined
}
```

### Property Access on Null Return From DOM/API
```javascript
const el = document.querySelector('.admin-panel');
// querySelector returns null if no match
el.style.display = 'none';  // TypeError if element doesn't exist
```

In server-side code, the same pattern occurs with database query results, cache
lookups, and Map.get() calls.

---

## Detection Questions

1. **"Can this function return NULL/None/undefined, and does every caller check for it?"**
   For each function that can return a null value, trace every call site. Any call
   site that uses the return value without a null check is a potential dereference.

2. **"Is this struct field always populated, or is it optional depending on the init path?"**
   Find all initialization paths for the struct. If any path leaves a field as NULL,
   every consumer of that field needs a null check.

3. **"Does any concurrent code path set this pointer to NULL while it is being used?"**
   For shared pointers, identify all writers (especially cleanup/shutdown code) and
   all readers. Without synchronization, check-then-use is a TOCTOU null dereference.

4. **"Is this function's error return value actually checked at the call site?"**
   Functions that return error codes or NULL on failure are only safe if the caller
   inspects the result. Grep for call sites that discard the return value.

5. **"After free/release/close, is the pointer set to NULL to prevent re-use?"**
   Freed pointers that remain non-NULL are traps for subsequent code that checks
   nullity as a proxy for validity.

---

## Real CVE Examples

### CVE-2023-2163 (Linux kernel — BPF verifier null pointer dereference)
The BPF verifier tracked register states across branches. When a conditional branch
checked whether a pointer register was NULL and took the non-NULL path, the verifier
recorded that the register was non-NULL. However, a subsequent operation could
invalidate this assumption (register spill and reload across a function call), and
the verifier's state tracking did not account for the invalidation. The generated
BPF program then dereferenced a potentially NULL pointer that the verifier had
incorrectly proven non-NULL. The null check was in the verifier's abstract
interpretation, not in the generated code — a cross-system type-state reasoning gap.

### CVE-2022-32250 (Linux kernel — Netfilter null deref via use-after-free)
In the Netfilter subsystem, an expression object was freed during error handling but
its pointer in the parent rule structure was not set to NULL. A subsequent operation
on the rule iterated over its expressions and dereferenced the stale pointer. The
free happened in the error path of one function; the dereference happened during
rule evaluation in a completely different code path triggered by incoming packets.

### CVE-2020-1938 (Apache Tomcat Ghostcat — null processing in AJP)
The AJP (Apache JServ Protocol) connector could receive requests with null attribute
values. The request processing code accessed these attributes without null checks in
several handler functions. An attacker sending a crafted AJP request with null
attributes could trigger null pointer dereferences in request attribute processing,
leading to denial of service. The AJP parsing set fields to null in one module;
the servlet processing read them without guards in another.
