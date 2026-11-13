---
name: mobile-fuzzing
description: Authorized mobile fuzzing for app APIs, file parsers, IPC surfaces, WebView/browser-adjacent inputs, native libraries, Android Binder/AIDL, iOS XPC/Mach, crash triage, and Docker/Mac ARM fuzzing workflows
origin: Vigil
---

# Mobile Fuzzing

## When to Activate

- A mobile lead (parser, imported file, intent/URL scheme, WebView input, native/JNI library,
  Binder/AIDL, XPC/Mach, app extension, API schema) warrants a coverage-guided campaign or
  reproducible crash triage.

## Scope Gate

Fuzz only owned apps, lab devices, local services, bug-bounty targets or explicitly authorized
client assets. System services, Binder, XPC, Mach, WebKit and kernel fuzzing stay inside owned
research builds (AOSP/Cuttlefish/Pixel with recovery paths; owned iOS research devices) or
approved programs, because they destabilize devices and cross process boundaries.

Harness rules, engine choice, seeds and dictionaries, sanitizers, Docker and Mac ARM notes:
`agent/references/mobile/mobile-fuzzing.md` and
`agent/references/code-vuln-patterns/fuzz-harness-patterns.md`. Campaign registration, crash
recording (`details.campaign_id`, `crash_input`, `asan_report`) and the fuzz evidence ladder are
owned by `agent/skills/code-fuzz-campaign/SKILL.md`; follow it for the Vigil mechanics.

## Campaign decisions

- **Targets:** attacker-controlled bytes (files, media, archives, QR codes, imports, SDK
  callbacks, WebView bridges, IPC messages, backend bodies), complex state machines, native code,
  size arithmetic, decompression, serialization, prior static suspicion. App-specific IPC before
  platform services unless platform research is authorized. Source-level harnesses when source
  exists; Frida-driven stimulation only when closed-source boundaries block rebuilds.
- **Boundary first:** name the entrypoint, input format, caller preconditions, authorization
  scope, device/build, expected crash signals and reset plan. Without it the crashes are noisy
  and unreportable. The harness calls the same parser or receiver production calls, with real
  caller preconditions.
- **Triage:** minimise, reproduce on a clean build, symbolise, deduplicate by crash state, and
  separate harness bugs from product bugs.

## Evidence

A crash is a finding when it is **reachable** through a path the attacker controls under the
threat model, **impactful** beyond lab instability (memory corruption, other-user DoS, disclosure
via crash report or error, a step towards code execution) and **reproducible** on a clean build.
Classification (severity is set by `agent/references/finding-fp-and-severity-gate.md`):

| Signal | Classification |
|---|---|
| Crash only in the harness, not reachable from a production input path | harness bug, fix the harness |
| ASan/MTE crash on attacker input, no write primitive | denial of service |
| ASan/MTE crash with a heap/stack write primitive | memory corruption |
| Controlled write to a chosen address | arbitrary write |
| Platform service (Binder/XPC) crash from app-delivered input | cross-boundary DoS |

Record build hash, OS/device version, sanitizer flags, corpus source, fuzzer version, command,
timeout and reset behaviour, and the MASVS mapping.

## Kill and escalate

- Stop when: a parser target ran 10M+ iterations with no new edges or crashes past warm-up and
  coverage plateaued for 2+ hours; every IPC method returns permission or validation errors; a
  memory-safe library stays clean under sustained sanitised fuzzing; every mutated API request
  returns 400/422 with no divergence in timing, error structure or behaviour.
- Extend when: a new edge appears after a plateau (seed it back); a non-deterministic ASan/MTE
  report (switch to TSan, add thread stress); a crash in a third-party SDK or system library
  reachable from app input (the app inherits it); a hang without a crash (algorithmic complexity;
  grow inputs with timeout instrumentation); a UBSan-only crash (check exploitability on
  production builds without the sanitizer).
