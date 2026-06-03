---
description: Trust-boundary object materialization, type-tag abuse, post-decode gadget reachability
languages: C/C++, Python, JS, Java
---

# Deserialization — Trust-Boundary Object Materialization and Gadget Reachability

> Target: Decode paths where attacker-controlled structured data becomes objects, executable
> behavior, privileged types, or security decisions across a trust boundary.

---

## Baseline Patterns

- Native language object deserialization on untrusted input
- Unsafe YAML/pickle/XMLDecoder-style loaders
- Framework/session/cache decode paths that materialize attacker-influenced objects

---

## What You're Hunting

### 1. “Only Internal Format” Assumptions

The code treats a format as trusted because the producer is “supposed” to be internal.

- Signed/encrypted envelope optional or inconsistently enforced
- Internal queue/cache/session data later attacker-controlled via another path
- Compatibility mode accepting older unsafe formats

### 2. Type Selection by Attacker Input

The decode path chooses a class or handler based on a type tag, discriminator, or registry lookup.

- Polymorphic decode by user-controlled type field
- Reflection-based object construction
- Variant dispatch to privileged handlers

### 3. Decode-Then-Trust Chains

The dangerous action happens after deserialization, not during it.

- Deserialized object later controls filesystem path, command, template, or URL
- Validation happens on pre-decoded bytes, not post-decoded object graph
- Security decisions trust decoded fields that were never canonicalized

### 4. Gadget Reachability and Partial Hardening

- Allowlist covers top-level type but not nested types
- Dangerous callbacks fire during object rehydration
- Custom read hooks / post-load hooks run before validation

---

## Audit Questions

- What data formats cross trust boundaries and become objects or privileged structs?
- Who chooses the decoded type, handler, or variant tag?
- Are authenticity/integrity checks enforced before any decode side effects?
- After decode, which fields immediately influence commands, files, URLs, auth, or policy?
