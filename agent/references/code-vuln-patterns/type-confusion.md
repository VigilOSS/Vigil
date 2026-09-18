---
description: void* casts, union abuse, tagged union errors, inheritance downcasts
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS, Go
---

# Type Confusion — Cross-Boundary Type Misinterpretation

> Target: Type confusion bugs (CWE-843) that survive SAST because the type cast and the
> data access happen in different functions, different modules, or across serialization
> boundaries. These require reasoning about how type information is lost, reinterpreted,
> or assumed across call chains and data formats.

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. void* Casts Across Function Boundaries

Function A stores a pointer to `struct_small` into a `void*` context parameter.
Function B retrieves the `void*` and casts it to `struct_large`. The access to
fields beyond `struct_small`'s size is an out-of-bounds read/write on A's object.

```c
// Module A: stores a small struct as callback context
void register_handler(event_loop_t *loop, int fd) {
    small_ctx_t *ctx = malloc(sizeof(small_ctx_t));  // 16 bytes
    ctx->fd = fd;
    ctx->flags = 0;
    event_add(loop, fd, on_event, (void *)ctx);
}

// Module B: retrieves as wrong type
void on_event(void *data) {
    large_ctx_t *ctx = (large_ctx_t *)data;  // large_ctx_t is 64 bytes
    ctx->session_id = new_session();  // writes past small_ctx_t allocation
    process_request(ctx);             // reads unallocated fields
}
```

SAST cannot trace types through `void*` across compilation units. The attacker
triggers the event to corrupt heap metadata adjacent to the small allocation.

### 2. Union Member Confusion

A tagged union where the tag and the data can fall out of sync — writing one
union member then reading a different member with a larger size or different
alignment.

```c
typedef union {
    int32_t  as_int;      // 4 bytes
    double   as_double;   // 8 bytes
    char    *as_string;   // 8 bytes (pointer)
} value_t;

typedef struct {
    int type;   // TAG: 0=int, 1=double, 2=string
    value_t val;
} tagged_value_t;

void process_value(tagged_value_t *v) {
    if (v->type == 0) {
        // Attacker controls the raw bytes and sets type=0
        // but the bytes actually encode a pointer value
        printf("Integer: %d\n", v->val.as_int);
        // Safe so far — but the truncation to 32 bits hides the attack
    }
    // Later code path re-reads as string based on a different check:
    if (needs_string_representation(v)) {
        use_string(v->val.as_string);  // interprets 4 bytes of int + 4 garbage as ptr
    }
}
```

### 3. C++ Inheritance — Unsafe Downcast

A base class pointer is used to access derived-class members without verifying
the actual dynamic type. When the object is actually a different derived class
(or just the base), the member access reads memory outside the object.

```c++
class Shape { public: int type; double area; };
class Circle : public Shape { public: double radius; };
class Polygon : public Shape { public: int num_sides; Point *vertices; };

void process_shape(Shape *s) {
    if (s->type == CIRCLE) {
        Circle *c = static_cast<Circle *>(s);  // no runtime check
        draw_circle(c->radius);
    } else {
        Polygon *p = static_cast<Polygon *>(s);
        // If s is actually a Circle, p->vertices reads Circle's radius as a pointer
        for (int i = 0; i < p->num_sides; i++)
            draw_line(p->vertices[i]);  // controlled pointer dereference
    }
}
```

The `static_cast` compiles to nothing — it is a promise to the compiler. If the
type field is attacker-controlled (deserialized from a file or protocol), the
promise is violated.

### 4. Deserialization Type Confusion

A protocol or file format declares a type tag, but the parsing code does not
validate that the payload matches the declared type. The attacker sets type=X
but provides data for type=Y, reaching a code path that interprets the bytes
differently.

```python
def process_message(msg):
    if msg['type'] == 'config':
        # Expects msg['data'] to be a dict with known keys
        apply_config(msg['data'])
    elif msg['type'] == 'command':
        # Expects msg['data'] to be a string
        execute_command(msg['data'])

def apply_config(config):
    # If attacker sends type='config' with data='__import__("os").system("id")'
    # and apply_config eventually calls eval() on a config value...
    for key, value in config.items():  # TypeError if data is actually a string
        # Or worse: if data is a list, .items() fails but data[0] works elsewhere
```

The confusion is between the declared type and the actual runtime type of the
deserialized payload. Each handler assumes its expected type without validation.

### 5. Enum/Integer as Array Index Without Range Check

An enum value received from an untrusted source is used directly as an array index.
The attacker provides a value outside the enum's defined range but within the
integer's representable range.

```c
enum msg_type { MSG_HELLO = 0, MSG_AUTH = 1, MSG_DATA = 2, MSG_MAX = 3 };

typedef void (*handler_fn)(conn_t *, msg_t *);
handler_fn handlers[] = { handle_hello, handle_auth, handle_data };

void dispatch(conn_t *conn, msg_t *msg) {
    // msg->type comes from the network — attacker controls it
    // No range check: what if msg->type == 50?
    handlers[msg->type](conn, msg);  // OOB read of function pointer → RCE
}
```

SAST tools may flag the missing bounds check in trivial cases, but when the enum
is parsed in module A, stored in a struct, and used as an index in module C via
a function pointer table in module B, the three-module chain escapes analysis.

### 6. Tagged Union With Corrupted Discriminant

A tagged union's discriminant field is set correctly at creation, but a subsequent
operation (serialization roundtrip, partial overwrite via buffer overflow, race
condition) corrupts the tag without changing the payload.

```c
// Tag says "integer" but payload is actually a pointer
tagged_value_t val;
val.type = TYPE_INT;
val.val.as_pointer = attacker_controlled_address;
// If val is later read and the reader trusts type==INT:
int result = val.val.as_int;  // truncation, but safe
// But if val is serialized and the receiver reconstructs:
if (received.type == TYPE_INT) {
    // received.val contains the full 8 bytes — reinterpreted as int
    // On a different code path that handles integers specially:
    store_result(received.val.as_int);  // or as_pointer if code branches wrong
}
```

---

## C/C++ Specific Patterns

### Flexible Array Member With Wrong Size Calculation
```c
struct msg { uint32_t type; uint32_t len; char data[]; };
// If type indicates "list of uint64_t" but len is in bytes:
uint64_t *items = (uint64_t *)msg->data;
int count = msg->len / sizeof(uint64_t);  // correct only if data IS uint64_t
// If data is actually strings, count is wrong and items[i] reads garbage
```

### std::variant / std::any Misuse
`std::get<T>(variant)` throws on type mismatch, but `std::get_if<T>()` returns
nullptr. Code that uses `get_if` and forgets the null check, or code that catches
the `bad_variant_access` and continues with a default, may process wrong-type data.

### C Macro Type Erasure
Macros that cast to `void*` or use `typeof` tricks can silently change types:
```c
#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))
// If ptr is not actually embedded in `type`, this computes a garbage pointer
```

---

## Python Specific Patterns

### Missing isinstance Before Attribute Access
```python
def process(obj):
    # Duck typing — assumes obj has .execute() method
    result = obj.execute()
    # If obj is a string (from deserialization), this calls str.execute() — AttributeError
    # Worse: if obj is a class with an execute() that does something dangerous
```

### C Extension Type Slot Confusion
CPython C extensions define type objects with `tp_` slots. If a C extension checks
`Py_TYPE(obj) == &MyType` but the object was created by a subclass or a different
extension that reuses the same slot layout, method dispatch goes to the wrong
implementation, potentially with incompatible internal data layout.

### pickle / marshal Type Confusion
`pickle.loads` can instantiate arbitrary classes. The deserialized object's type
depends entirely on the pickle stream — attacker controls which class is
instantiated and which `__reduce__` method executes.

---

## JavaScript Specific Patterns

### typeof null === "object"
```javascript
function process(input) {
    if (typeof input === 'object') {
        return input.key;  // TypeError if input is null
    }
}
```
This is JavaScript's oldest type confusion. `null` passes the object check but
has no properties. In security-relevant code (auth token parsing, permission
objects), this can cause fail-open behavior.

### Prototype Chain Confusion
```javascript
const obj = JSON.parse(untrustedInput);
if (obj.isAdmin) {
    grantAdmin();
}
// Attacker sends: {"__proto__": {"isAdmin": true}}
// With prototype pollution, ALL objects inherit isAdmin=true
```

### Symbol.toPrimitive / valueOf Abuse
Objects with custom `Symbol.toPrimitive` or `valueOf` methods can return unexpected
types during implicit conversion, causing type confusion in comparison operations:
```javascript
const evil = { [Symbol.toPrimitive](hint) {
    if (hint === 'number') return 0;  // passes == 0 check
    if (hint === 'string') return 'admin';  // but stringifies as admin
}};
```

---

## Go Specific Patterns

### unsafe.Pointer Conversions
`unsafe.Pointer` is Go's `void*`: the one construct that suspends the type and memory
safety the rest of the language guarantees. A round trip through it — or through
`reflect.SliceHeader`/`reflect.StringHeader` — reinterprets one type's bytes as another,
so a length or element size that no longer matches is an out-of-bounds access with no
runtime check to catch it. Treat every `unsafe.Pointer` as a cast whose destination type
must be justified at the use site, not at the conversion.

---

## Detection Questions

1. **"What type was this data when it was created, and what type is it treated as here?"**
   Trace the data from creation/allocation through every cast, store, and retrieval.
   Any point where the type changes without validation is a confusion candidate.

2. **"Is this void*/Object/any cast validated at the destination?"**
   Every `void*` retrieval, JSON property access, or `any` cast should have a type
   check. If the cast target is just assumed, the confusion is exploitable.

3. **"Can an attacker control the type discriminant independently of the payload?"**
   Tagged unions, protocol type fields, and serialized type markers are all
   attacker-controlled if they come from untrusted input. The tag must be validated
   against the actual payload structure.

4. **"Does this downcast have a runtime type check, or is it a static/reinterpret cast?"**
   `dynamic_cast` checks at runtime (with RTTI). `static_cast` and `reinterpret_cast`
   are compile-time-only — they trust the programmer. Untrusted type sources require
   runtime checks.

5. **"Are deserialized objects validated for expected structure before use?"**
   After JSON.parse, pickle.loads, protobuf decode, or any deserialization — is the
   result checked for expected keys, types, and ranges before being passed to
   type-specific handlers?

---

## Real CVE Examples

### CVE-2023-4863 (libwebp — Huffman table type confusion)
The WebP image decoder's Huffman table construction used a lookup table indexed by
code length. A malformed WebP image could provide code lengths that exceeded the
table's allocated size, causing an out-of-bounds write. The core confusion was
between the image-declared code length (attacker-controlled integer) and the
decoder's internal table size (compile-time constant). The parsing happened in
one function, table construction in another, and the OOB access in a third.
This was exploited in the wild via a crafted WebP image.

### CVE-2022-1096 (V8 — JavaScript engine type confusion)
Chrome's V8 JavaScript engine had a type confusion vulnerability in its optimizing
compiler (TurboFan). The JIT compiler made an incorrect assumption about an object's
type during optimization, generating machine code that accessed object fields at
offsets corresponding to the wrong type. When the actual runtime type differed from
the JIT's assumption, the generated code read/wrote to incorrect memory locations.
The confusion spanned the type inference phase, the optimization phase, and the
generated code execution — three distinct subsystems with different type representations.

### CVE-2021-30551 (V8 — type confusion in Map transitions)
V8's hidden class (Map) transition system allowed an object's shape to change during
certain operations. If the JIT compiler cached a Map transition but the object's
actual Map changed via a different code path, subsequent property accesses used
offsets from the cached (wrong) Map. The attacker crafted JavaScript that forced a
Map transition between the JIT's type check and the property access, achieving
controlled out-of-bounds read/write in the V8 heap.
