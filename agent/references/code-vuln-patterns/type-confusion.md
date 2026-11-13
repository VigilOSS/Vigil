---
description: void* casts, union abuse, tagged union errors, inheritance downcasts
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS, Go
---

# Type Confusion — Cross-Boundary Type Misinterpretation

CWE-843. The cast and the access sit in different functions, modules, or sides of a serialization
boundary, so the type information that would expose the mismatch is gone.

## What You're Hunting (LLM-Advantage Patterns)

1. **`void*` context retrieved as a larger type.** Module A registers a 16-byte `small_ctx_t` as
   callback data; module B casts it to a 64-byte `large_ctx_t` and writes past the allocation. SAST
   does not follow types through `void*` across compilation units.
2. **Tag and payload out of sync.** A tagged union whose discriminant the attacker sets independently
   of the payload (deserialized, overwritten by an adjacent overflow, raced), so one path reads
   `as_int` while another later reads the same bytes `as_string` as a pointer. The tag must be
   validated against the payload, not trusted.
3. **`static_cast` downcasts on an attacker-controlled type field.** `static_cast<Polygon*>(s)` when
   `s` is really a `Circle` reads `radius` as `vertices`: a controlled pointer. `static_cast` and
   `reinterpret_cast` compile to nothing; untrusted type sources need `dynamic_cast` (RTTI) or a
   checked tag.
4. **Declared message type versus runtime payload type.** A handler for `type == "config"` assumes a
   dict and another for `"command"` a string; nothing checks that `data` matches the declared type
   before the type-specific handler runs.
5. **Enum used as an index.** `handlers[msg->type](conn, msg)` with `type` from the network and no
   range check is an out-of-bounds function-pointer read. A C enum's underlying type is
   implementation-defined, so `type < MSG_MAX` can pass a negative value when the field is signed;
   the three-module version (parsed in A, stored in B's struct, indexed in C) escapes SAST.

## C/C++ Specifics

- `std::get_if<T>()` returns `nullptr` on mismatch; code that skips the check, or catches
  `bad_variant_access` and continues with a default, processes the wrong alternative.
- `container_of(ptr, type, member)` on a pointer that is not actually embedded in `type` computes a
  garbage object address.

## Python Specifics

CPython C extensions that cast a `METH_O` argument straight to their object struct, or accept
subclasses with an incompatible layout through `PyObject_TypeCheck`, dispatch on the wrong memory
layout; the exact `Py_TYPE(obj) == &MyType` check is the safe form. pickle instantiates whatever
class the stream names; see `web-app-injection.md`.

## JavaScript Specifics

- `typeof null === "object"`: an object check passes `null`, which in auth-token or permission
  parsing can fail open.
- `Symbol.toPrimitive`/`valueOf` let one object compare as `0` and stringify as `"admin"`.
- Query parsers turn `?role[]=admin` into an array where the code expects a string, so
  `role === "admin"` and `.includes()`/`.indexOf()` checks diverge.

## Go Specifics

`unsafe.Pointer` suspends Go's type and memory safety; a conversion reinterprets one type's bytes as
another, and a length or element size that no longer matches is an unchecked out-of-bounds access.
`reflect.SliceHeader`/`StringHeader` were deprecated in Go 1.21 for `unsafe.Slice`/`unsafe.SliceData`/
`unsafe.String`/`unsafe.StringData`, and code still building headers by hand is a place to look. Justify each conversion's destination
type at the use site.

## Real CVE Examples

- **CVE-2021-30551 and CVE-2022-1096 (V8).** A property interceptor runs user JavaScript in the
  middle of a store (`SetPropertyInternal`); the script adds the property the store had found
  absent, the engine does not re-check, and the property is added a second time, leaving a
  corrupted object. The 30551 patch covered only the prototype-chain path, so 1096 reached the same
  root cause through an own property, and its fix in turn missed the `Object.defineProperty` path
  (CVE-2022-1232). Any callout to user code between a lookup and the write that relies on it needs
  the lookup redone; check every path into the same write, not just the one a patch names.
