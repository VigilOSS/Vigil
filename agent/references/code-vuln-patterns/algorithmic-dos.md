# Algorithmic Denial of Service — Complexity Attacks

> Target: Algorithmic DoS bugs (CWE-400, CWE-1333, CWE-776) that survive SAST because
> the complexity explosion requires reasoning about data structure behavior under
> adversarial input, regex engine backtracking semantics, or recursive parsing depth
> across multiple parser layers. These are not resource exhaustion from missing limits
> alone — they exploit algorithmic worst-case behavior.

---

## What SAST Already Catches (Skip These)

- Basic XML External Entity (XXE) expansion (billion laughs with known entity pattern)
- Obvious `while(true)` infinite loops with no break condition
- Simple missing `Content-Length` / upload size limits in framework config
- `eval()` on user input (more injection than DoS, but tools flag it)
- Direct recursion without a base case in a single function

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Hash Collision DoS (HashDoS)

Hash tables with predictable hash functions process attacker-crafted inputs that all
hash to the same bucket. Lookups degrade from O(1) to O(n) per operation, making n
insertions O(n^2) total.

```python
# Python dicts are randomized (SipHash) since 3.3, but custom hash functions are not:
class CaseInsensitiveKey:
    def __init__(self, key):
        self.key = key
    def __hash__(self):
        return hash(self.key.lower())  # safe — delegates to SipHash
    def __eq__(self, other):
        return self.key.lower() == other.key.lower()

# Dangerous: C/C++ hash tables with DJB2, FNV, or simple modular hashing
# without randomization. The attacker precomputes colliding keys offline.
```

**In web servers**: HTTP header parsing uses hash tables. If the header name hash is
predictable, an attacker sends thousands of headers with colliding names. Each lookup
in the header table scans the entire collision chain.

**In cURL**: Cookie jars, header storage, and hostname resolution caches use hash tables.
The hash function and table size determine collision vulnerability.

### 2. Regular Expression Denial of Service (ReDoS)

Regex engines with backtracking (NFA-based, as in Python `re`, JavaScript `RegExp`,
PCRE) exhibit catastrophic backtracking on certain patterns with adversarial input.

```javascript
// Nested quantifiers — classic ReDoS pattern
const emailRegex = /^([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/;
// Input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" — exponential backtracking
// The engine tries every way to split the 'a's into groups followed by '.'

// Alternation with overlap
const pathRegex = /^(\/[a-z]+)*(\/[a-z0-9]+)*$/;
// Input: "/aaa/bbb/ccc/ddd/eee/fff/ggg/!!!" — exponential on the failing suffix
```

The pattern compiles without error. It works correctly on valid input. It only
explodes on adversarial input that is designed to be almost-but-not-quite matching,
forcing the engine to explore exponentially many backtracking paths.

**Detection heuristic**: Look for `(a+)+`, `(a|a)+`, `(a+b?)+`, or any pattern
where a quantified group contains elements that can match zero-length or overlap
with adjacent elements.

### 3. Recursive Parser Stack Overflow / Exponential Parsing

Deeply nested JSON, XML, protobuf, or custom protocol structures cause recursive
descent parsers to overflow the stack or exhibit exponential behavior.

```c
// JSON parser — each nested object/array adds a stack frame
json_value_t *parse_value(parser_t *p) {
    if (peek(p) == '{') return parse_object(p);   // calls parse_value recursively
    if (peek(p) == '[') return parse_array(p);     // calls parse_value recursively
    return parse_primitive(p);
}

// Attacker input: [[[[[[[[[[[[... 10000 levels deep ...]]]]]]]]]]]]
// Each level is one stack frame. At ~8KB per frame, 10000 levels = 80MB stack.
// Default thread stack is typically 1-8MB → stack overflow → crash.
```

**In protobuf**: Nested message fields with repeated sub-messages. The schema allows
arbitrary nesting depth, and the generated parser uses recursion.

**In XML**: Not just entity expansion — deeply nested elements cause recursive
SAX/DOM parser calls. Combined with namespace processing, each level multiplies work.

### 4. Unbounded Allocation via Attacker-Controlled Size

An attacker-controlled integer (Content-Length, array count, string length) is used
directly as an allocation size without an upper bound check.

```c
// HTTP request parsing
uint64_t content_length = parse_header_uint64("Content-Length");
char *body = malloc(content_length);  // attacker says Content-Length: 9999999999
if (!body) return -1;  // OOM check exists, but the allocation itself may
                        // cause memory pressure, swap thrashing, or OOM killer
```

The fix is not just checking the return — it is capping the maximum at a
policy-defined limit before attempting the allocation. The cap must be in the
parsing layer, not the allocation layer, so it can return a proper 413 error.

### 5. Quadratic String Operations

Repeated string concatenation in a loop where the string grows linearly per
iteration, but each concatenation copies the entire accumulated string.

```python
def build_response(items):
    result = ""
    for item in items:  # attacker controls len(items)
        result += format_item(item)  # O(len(result)) copy each iteration
    return result
    # Total: O(n^2) where n = total output length
```

```c
// C equivalent: repeated strcat into a buffer with realloc
for (int i = 0; i < n; i++) {
    size_t new_len = strlen(buf) + strlen(items[i]) + 1;
    buf = realloc(buf, new_len);
    strcat(buf, items[i]);  // strcat scans from the beginning each time: O(n^2)
}
```

In Python, the idiomatic fix is `"".join(parts)`. In C, track the current write
position and use `memcpy` at the offset.

### 6. Decompression Bombs (Zip Bombs)

A small compressed payload that expands to an enormous size. Classic zip bombs use
nested compression layers or overlapping file entries.

```python
import zipfile
with zipfile.ZipFile(uploaded_file) as zf:
    for entry in zf.namelist():
        data = zf.read(entry)  # entry is 10 bytes compressed, 4GB uncompressed
        process(data)          # OOM or disk exhaustion
```

**Gzip variant**: A 50KB gzip file that decompresses to 1TB. Servers that decompress
`Content-Encoding: gzip` request bodies without checking the decompressed size are
vulnerable.

**Image variant**: A 100x100 PNG with a declared dimension of 100000x100000 pixels.
Decoders that allocate based on the header dimensions without checking plausibility
allocate terabytes.

### 7. State Machine Infinite Loop via Crafted Protocol Messages

An attacker crafts protocol messages that keep a state machine cycling between states
without making progress. The loop does not appear infinite to static analysis because
each iteration processes valid input.

```c
void protocol_loop(conn_t *conn) {
    while (conn->state != STATE_DONE) {
        msg_t *msg = read_message(conn);
        switch (conn->state) {
        case STATE_HANDSHAKE:
            if (msg->type == HELLO) conn->state = STATE_AUTH;
            else if (msg->type == RESET) conn->state = STATE_HANDSHAKE; // loop!
            break;
        case STATE_AUTH:
            if (msg->type == RESET) conn->state = STATE_HANDSHAKE; // back to start
            break;
        }
    }
}
// Attacker sends: HELLO, RESET, HELLO, RESET, ... forever
// Each iteration is valid, but the session never reaches STATE_DONE
```

---

## C/C++ Specific Patterns

### Recursion Without Depth Limit
C has no stack overflow protection by default. Recursive functions processing
attacker-controlled data must enforce a depth counter. Common vulnerable patterns:
recursive tree/graph traversal of deserialized data, recursive regular expression
matching in custom regex engines, and recursive descent parsers.

### realloc Growth Without Upper Bound
```c
while (has_more_data(stream)) {
    needed = current_size * 2;  // exponential growth — 30 doublings = 1GB
    buf = realloc(buf, needed);
    read_data(stream, buf + current_size, current_size);
    current_size = needed;
}
```

### CPU-Intensive Operations Without Timeout
`qsort` on attacker-controlled data with O(n^2) worst case (non-randomized pivot).
Sorting algorithms with adversarial worst cases should use intro-sort or similar.

---

## Python Specific Patterns

### regex Module Catastrophic Backtracking
```python
import re
pattern = re.compile(r'^(a+)+$')  # catastrophic on "aaa...!" input
# The re module uses NFA backtracking, NOT Thompson NFA
# Use re2 (google-re2) for linear-time guaranteed matching
```

### json.loads With Extreme Nesting
CPython's `json.loads` uses C recursion. Default recursion limit is 1000, but deeply
nested JSON can crash before that limit if the C stack is smaller than Python's
sys.getrecursionlimit suggests.

### xml.etree and Billion Laughs
```python
import xml.etree.ElementTree as ET
ET.fromstring(malicious_xml)  # defusedxml not used → entity expansion attack
```
Always use `defusedxml` for untrusted XML. The stdlib XML parsers do not defend
against entity expansion, external entity inclusion, or DTD retrieval by default.

---

## JavaScript Specific Patterns

### Regex Catastrophic Backtracking
JavaScript's RegExp is NFA-based with backtracking. All the same ReDoS patterns
apply. No built-in timeout mechanism — a ReDoS in server-side JS blocks the
event loop, denying service to all concurrent requests.

```javascript
// Express.js route with ReDoS-vulnerable validation
app.get('/search', (req, res) => {
    if (/^([a-z]+\.)*[a-z]+$/.test(req.query.q)) {  // ReDoS on "aaa.bbb.ccc...!"
        // Event loop blocked for minutes on adversarial input
    }
});
```

### JSON.parse Stack Overflow
V8's JSON.parse is iterative for arrays/objects but recursive for nested structures
in some edge cases. Extremely deep nesting (10000+ levels) can cause stack overflow.

### Prototype Pollution Causing Infinite Iteration
If `Object.prototype` is polluted with enumerable properties, `for...in` loops may
iterate over unexpected properties. If those properties reference objects that also
have polluted prototypes, the iteration can become unbounded:
```javascript
Object.prototype.evil = { evil: { evil: {} } };  // recursive structure
for (let key in userObj) {
    deepProcess(userObj[key]);  // infinite recursion via prototype chain
}
```

---

## Detection Questions

1. **"Is this data structure's performance guaranteed under adversarial input?"**
   Hash tables need randomized hashing. Sorting needs worst-case O(n log n).
   Regular expressions need linear-time guarantees or input length limits.

2. **"Is there a hard upper bound on recursion depth / nesting level?"**
   Every recursive parser needs a depth counter. Every nested data format needs
   a maximum nesting limit. Both must be checked before recursing, not after.

3. **"Does any allocation size come from untrusted input without a ceiling?"**
   Trace every `malloc`, `new`, `Buffer.alloc` back to its size argument. If that
   argument is derived from network input, verify there is a maximum enforced
   before the allocation, not just an OOM check after.

4. **"Can an attacker keep this loop running indefinitely with valid-looking input?"**
   For protocol state machines and parser loops, verify that each iteration
   makes provable forward progress. A reset-to-start transition without a
   retry counter is a DoS vector.

5. **"Is decompressed / decoded size checked before the operation, or only after?"**
   Zip, gzip, brotli, image decoders — all need to check the declared output
   size against a policy limit before beginning decompression.

---

## Real CVE Examples

### CVE-2023-44487 (HTTP/2 Rapid Reset — protocol-level DoS)
The HTTP/2 protocol allows clients to open streams and immediately reset them.
Each stream open/reset cycle costs the server CPU and memory for stream setup and
teardown, but costs the client almost nothing (a few bytes per frame). An attacker
sending rapid HEADERS + RST_STREAM pairs could exhaust server resources without
ever completing a request. The attack exploited the asymmetry between client cost
(O(1) per stream) and server cost (O(n) for n streams with setup/teardown overhead).
No single code path was buggy — the vulnerability was in the protocol's cost model.

### CVE-2022-35737 (SQLite — oversized string causing array index DoS)
SQLite's `printf`-like formatting function used an array indexed by format specifier
characters. An extremely long string argument (2GB+) caused integer overflow in the
length calculation, which led to either a massive allocation attempt (DoS via OOM)
or an out-of-bounds access in the formatting buffer. The size came from user input
via SQL query parameters, propagated through multiple internal functions before
reaching the vulnerable allocation.

### CVE-2024-22019 (Node.js — HTTP chunk extension ReDoS)
Node.js's HTTP parser accepted unbounded chunk extension bytes in
Transfer-Encoding: chunked requests. An attacker could send a single request
with an extremely long chunk extension line, causing the parser to spend seconds
in a tight read loop processing the extension data. Since Node.js is
single-threaded, one malicious request blocked the event loop and denied service
to all concurrent connections. The vulnerability was in the llhttp parser's
chunk-extension handling, not in user code, requiring a Node.js patch to fix.
