# Uninitialized Memory — Cross-Function Initialization Gaps

> Target: Uninitialized memory bugs (CWE-457, CWE-908) that survive SAST because the
> initialization and use happen in different functions, different branches, or different
> lifecycle phases. These require reasoning about conditional control flow, allocation
> patterns, and partial initialization across call boundaries.

---

## What SAST Already Catches (Skip These)

- Simple `int x; use(x);` in the same function without any intervening assignment
- Obvious uninitialized local variable used immediately in next statement
- Compiler `-Wuninitialized` catches: single-function, single-branch reads of unset locals
- `memcpy` from a clearly uninitialized stack buffer in the same scope

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Conditional Initialization — Else-Branch Gap

Variable initialized inside an if-branch but used unconditionally after the branch.
The else-branch (or missing else) leaves it holding stack garbage.

```c
int validate_token(const char *input, token_t *out) {
    int status;
    if (input && strlen(input) > 0) {
        status = parse_token(input, out);
    }
    // Missing else: status is uninitialized when input is NULL or empty
    return status;  // caller checks status to decide trust level
}
```

SAST sees the assignment inside the if-block and often assumes all paths assign. The
attacker controls whether the if-branch is taken — an empty input yields a garbage
return value, which may happen to equal SUCCESS.

### 2. Cross-Function Struct Initialization

Struct allocated in function A, fields populated in function B, but B does not set
all fields. Function C reads a field that B never touched.

```c
// Function A: allocates
config_t *cfg = malloc(sizeof(config_t));

// Function B: partial init — sets 4 of 6 fields
void init_config_defaults(config_t *cfg) {
    cfg->timeout = 30;
    cfg->retries = 3;
    cfg->port = 8080;
    cfg->use_tls = 1;
    // cfg->auth_required NOT SET
    // cfg->max_request_size NOT SET
}

// Function C: reads all fields
if (!cfg->auth_required) {   // reads uninitialized heap memory
    allow_anonymous(conn);   // attacker bypasses auth if heap byte is 0x00
}
```

Each function in isolation looks reasonable. The bug lives in the gap between B's
writes and C's reads — a cross-function completeness problem.

### 3. Error-Path Partial Initialization

The happy path initializes all fields. An error path bails early but does not
return — it falls through to code that reads partially initialized state.

```c
int setup_session(session_t *sess) {
    sess->user = lookup_user(sess->user_id);
    if (!sess->user) {
        log_error("user not found");
        // BUG: does not return -1 here — falls through
    }
    sess->permissions = load_permissions(sess->user);  // NULL deref if user missing
    sess->token = generate_token(sess);
    return 0;
}
```

The error is not that initialization is skipped — it is that the error path does not
terminate execution, so subsequent fields are initialized with garbage inputs.

### 4. malloc Without Zeroing + Partial memset

Heap allocation via `malloc` (which does not zero memory) followed by a `memset`
that covers only part of the allocation.

```c
packet_t *pkt = malloc(sizeof(packet_t) + payload_len);
memset(pkt, 0, sizeof(packet_t));  // zeros the header, NOT the payload area
// pkt->payload contains whatever was in that heap region before
memcpy(pkt->payload, user_data, user_data_len);
// If user_data_len < payload_len, trailing bytes leak prior heap contents
send(sock, pkt, sizeof(packet_t) + payload_len, 0);
```

The memset looks correct at a glance — it zeros the struct. But the flexible payload
area past the struct is uninitialized, and if the copy does not fill it completely,
stale heap data is transmitted over the network (info leak).

### 5. Stack Buffer Partially Filled — Short Read

`read()` or `recv()` returns fewer bytes than the buffer size. The remaining bytes
hold whatever was on the stack from the prior call frame.

```c
void process_request(int fd) {
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n <= 0) return;
    // n might be 100, but we process all 4096 bytes:
    parse_headers(buf, sizeof(buf));  // reads 3996 bytes of stack garbage
}
```

The fix is to use `n` as the length, but the pattern of allocating a fixed buffer
and then not tracking the actual fill length is common in network code.

### 6. Reused Stack Slots — Information Leak Across Calls

Function A stores sensitive data in a local variable, returns. Function B is called
next — its locals may occupy the same stack addresses. If B does not initialize its
locals, it reads A's leftover data.

```c
void handle_admin_request(conn_t *conn) {
    char admin_token[256];
    snprintf(admin_token, sizeof(admin_token), "Bearer %s", get_admin_token());
    send_api_request(conn, admin_token);
}

void handle_user_request(conn_t *conn) {
    char response_buf[256];  // same stack slot as admin_token above
    // BUG: response_buf not initialized before partial write
    int len = snprintf(response_buf, 128, "Hello %s", conn->username);
    // Bytes 128-255 contain the admin token from the previous call
    send(conn->fd, response_buf, sizeof(response_buf), 0);  // leaks admin token
}
```

Compiler-level analysis cannot see this because each function's locals are
independently valid. The leak requires reasoning about call sequence and stack layout.

---

## C/C++ Specific Patterns

### Struct Padding Leaks
Compiler-inserted padding bytes between struct members are never explicitly written.
When structs are copied to userspace or sent over the network, padding bytes leak
kernel or heap memory.

```c
struct __attribute__((packed)) msg { uint8_t type; /* 3 pad bytes */ uint32_t value; };
// Without packed: 3 padding bytes between type and value are uninitialized
```

### Union Reinterpretation
Writing a smaller union member then reading a larger one exposes uninitialized bytes
in the size difference.

### alloca / VLA Dangers
Stack-allocated dynamic buffers via `alloca()` or VLAs are never zeroed. Combined
with partial writes, they leak stack contents from prior frames.

### C++ Member Initializer Gaps
A class with 8 member variables where the constructor initializer list only covers 5.
The remaining 3 hold indeterminate values. Particularly dangerous when a derived class
constructor does not call the base constructor's full initializer.

---

## Python Specific Patterns

### ctypes.create_string_buffer
```python
buf = ctypes.create_string_buffer(1024)
lib.partial_fill(buf, 100)  # fills first 100 bytes
data = buf.raw  # all 1024 bytes — last 924 are zero (create_string_buffer zeros)
```
`create_string_buffer` zeros memory, but `ctypes.c_char * 1024` via `from_address()`
or shared-memory pointers may not be zeroed.

### C Extension PyBytes Internals
C extensions that build `PyBytes` objects by writing partial data into the internal
buffer and returning it. The unfilled portion of the buffer may contain heap data.

---

## JavaScript Specific Patterns

### Buffer.allocUnsafe
```javascript
const buf = Buffer.allocUnsafe(1024);  // NOT zeroed
buf.write(userInput);  // writes userInput.length bytes
res.send(buf);  // sends full 1024 bytes — leaks heap data in trailing bytes
```
This is the single most common uninitialized memory pattern in Node.js. The fix is
`Buffer.alloc(1024)` (zeroed) or truncating to actual written length.

### TypedArray Over SharedArrayBuffer
SharedArrayBuffer memory is zeroed on creation, but if workers write partial data and
other workers read the full extent, the read races with incomplete writes (not truly
uninitialized, but observes intermediate states).

### WebAssembly Linear Memory
Wasm memory is zeroed on instantiation, but `memory.grow()` adds pages whose initial
content is zero. However, if Wasm code reuses freed regions without zeroing, the
pattern mirrors C heap reuse — stale data from prior allocations.

---

## Detection Questions

1. **"Is this variable initialized on ALL control flow paths, or only some?"**
   Trace every branch (if/else, switch/case, early return, goto). If any path
   reaches the use without an assignment, the variable holds garbage.

2. **"Does the allocator zero memory, or is a separate memset/bzero required?"**
   `malloc` does not zero. `calloc` does. `new` in C++ calls constructors but
   POD types are not zeroed by `new` unless value-initialized: `new int()` vs `new int`.

3. **"Does the copy/read fill the entire buffer, or could it be a short operation?"**
   `read()`, `recv()`, `fread()` may return fewer bytes. If subsequent code uses
   the buffer size rather than the return value, trailing bytes are uninitialized.

4. **"When this struct is populated across multiple functions, does every field get set?"**
   List all fields. For each field, find which function writes it. Any field with
   no writer is uninitialized — a cross-function completeness check SAST cannot do.

5. **"Is this buffer sent over the network or copied to another trust domain?"**
   Uninitialized memory is only a vulnerability when it crosses a security boundary.
   Internal use is a reliability bug; network transmission or cross-process copy is
   an information disclosure vulnerability.

---

## Real CVE Examples

### CVE-2017-7184 (Linux kernel — xfrm uninitialized kernel stack leak)
The XFRM (IPsec) subsystem's netlink handler allocated a response structure on the
kernel stack and partially populated it from the request. The `xfrm_replay_verify_len`
function set most fields, but padding bytes and one trailing field were left
uninitialized when the replay window size was smaller than the maximum. The response
was then copied to userspace via `nla_put` in a separate function, transmitting the
full structure including the uninitialized stack bytes. An unprivileged user could
send crafted XFRM netlink messages to read kernel stack memory, potentially leaking
KASLR addresses and other sensitive data from prior kernel function frames.

### CVE-2021-3501 (Linux kernel — KVM uninitialized stack variable)
In KVM's handling of VMX instructions, a local variable was conditionally initialized
inside a switch statement. One case arm did not assign the variable, but the code after
the switch used it unconditionally. The variable held a stack value from a prior kernel
function, potentially leaking kernel ASLR addresses to the guest VM. The switch had
dozens of cases, making it easy for a reviewer (and SAST) to miss the one uninitializing
path.

### CVE-2019-11091 (Intel CPU — Microarchitectural Data Sampling / MDSUM)
The Microarchitectural Data Sampling (MDS) class of vulnerabilities allowed processes
to read stale data from CPU-internal buffers (fill buffers, load ports, store buffers)
that had not been cleared between context switches. When a load encountered a fault or
assist condition, the CPU's speculative execution could forward uninitialized data from
these microarchitectural buffers to dependent instructions. The "initialization" (buffer
clearing) was expected to happen during context switch in one kernel function, but the
speculative read in the CPU pipeline operated before the architectural state was
committed — a hardware-level cross-domain uninitialized data exposure that leaked
memory across process, VM, and privilege boundaries.
