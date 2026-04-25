---
name: mobile-fuzzing
description: Authorized mobile fuzzing for app APIs, file parsers, IPC surfaces, WebView/browser-adjacent inputs, native libraries, Android Binder/AIDL, iOS XPC/Mach, crash triage, and reproducible campaigns
origin: AI Threat Hunting
---

# Mobile Fuzzing

## When to Activate

- Fuzzing Android or iOS app APIs, imported files, parsers, serialization formats, deep links, intents, URL schemes, WebView inputs, native libraries, Binder/AIDL, XPC/Mach, or app extensions.
- Turning a static mobile security lead into a coverage-guided campaign or reproducible crash triage workflow.
- Choosing between libFuzzer, AFL++, honggfuzz, Frida-driven stimulation, API fuzzing, or device-level fuzzing.

## Scope Gate

Fuzz only owned apps, lab devices, local services, bug-bounty targets, or explicitly authorized client assets. Keep system-service, Binder, XPC, Mach, WebKit, and kernel fuzzing inside owned research builds or approved programs because those surfaces can destabilize devices and cross process boundaries.

## Target Selection

- Prioritize parsers reachable from files, media, archives, QR codes, imports, SDK callbacks, WebView bridges, IPC messages, and backend request bodies.
- Prefer targets with attacker-controlled bytes, complex state machines, native code, size arithmetic, custom crypto, decompression, serialization, or prior static-analysis suspicion.
- Use source-level harnessing when source is available; use Frida-based runtime stimulation only when closed-source boundaries block rebuilds.
- Fuzz app-specific IPC before platform-wide services unless the engagement explicitly authorizes device/platform research.

## Campaign Workflow

### 1. Define The Boundary

Name the entrypoint, input format, caller preconditions, authorization scope, target device/build, expected crash signals, and reset plan. A fuzzer without a precise boundary produces noisy crashes that cannot be reported.

### 2. Build The Harness

- Call the same parser, dispatcher, API handler, or IPC receiver that production code calls.
- Preserve real caller preconditions so harness crashes represent reachable behavior.
- Reset global state, avoid sleeps and network dependencies, cap input size, and compile with debug symbols.
- Use libFuzzer for in-process C/C++ parser APIs, AFL++ for forkserver or binary-oriented workflows, honggfuzz for multiprocessing or attach-style workflows, and Frida for targeted runtime calls.

### 3. Seed And Instrument

- Start with small valid inputs from tests, fixtures, captured traffic, exported files, and minimal generated samples.
- Add dictionaries for magic bytes, field names, MIME types, URL parameters, intent extras, AIDL fields, plist keys, JSON keys, and protocol tokens.
- Use ASan/UBSan first, add HWASan/MSan/TSan only when platform and build support make them meaningful.
- Track coverage with SanitizerCoverage, AFL++ instrumentation, or engine-native feedback; measure corpus quality by new reachable code.

### 4. Run And Triage

- Record build hash, OS/device version, sanitizer flags, corpus source, fuzzer version, command line, timeout, and reset behavior.
- Minimize crashing inputs, reproduce them on a clean build, collect symbolized traces, deduplicate by crash state, and separate harness bugs from product bugs.
- Convert confirmed crashes into findings only when the input is reachable under the engagement threat model and the crash demonstrates memory corruption, information disclosure, privilege boundary crossing, or reliable denial of service affecting other users.

## Mobile-Specific Notes

- Android app fuzzing commonly targets parsers, intents, content providers, exported services, JNI libraries, and mobile API schemas.
- Android platform fuzzing can target Binder/AIDL and native services only in owned AOSP/Cuttlefish/Pixel labs with recovery paths.
- iOS app fuzzing commonly targets imported files, URL schemes, universal links, pasteboard-driven parsing, WebView bridges, app extensions, and native libraries.
- iOS platform fuzzing requires owned research devices, source builds, public research harnesses, or approved virtual platforms for meaningful crash visibility.
- Docker helps Linux fuzzing toolchains, OSS-Fuzz-style layouts, and CI replay; Mac ARM hosts should prefer native arm64 builds or remote Linux/x86 workers for throughput-sensitive campaigns.

## Evidence Standard

Map each crash to OWASP MASVS, affected app version, device/OS version, build hash, sanitizer flags, input reachability, and security impact. A crash becomes a finding when:

- **Reachable:** the crashing input can be delivered through a path an attacker controls under the engagement threat model (file import, API request, IPC message, deep link parameter, WebView bridge call).
- **Impactful:** the crash produces a security consequence beyond local lab instability — memory corruption with write primitive, denial of service against other users, information disclosure via crash report or error response, or a stepping stone to code execution.
- **Reproducible:** the minimized input reproduces on a clean build with symbolized traces, and the crash state is distinct from harness artifacts.

Evidence tiers for severity differentiation:

| Signal | Classification | Severity Guidance |
|---|---|---|
| Crash in harness only, not reachable from production input path | Harness bug | Not reportable — fix the harness |
| Crash on attacker-controlled input, caught by parser rejection | Expected rejection | Not reportable — defense working |
| ASan/MTE crash on attacker-controlled input, no write primitive | Denial of service | Low-Medium depending on multi-user impact |
| ASan/MTE crash with heap/stack write primitive | Memory corruption | High — write primitive enables code execution |
| Controlled write to specific address via crafted input | Arbitrary write | Critical — code execution path |
| Crash in platform service (Binder/XPC) from app-delivered input | Cross-boundary DoS | Medium-High depending on service criticality |

## Kill Signals and Escalation Triggers

### Kill Signals — stop the campaign when these hold

- **Parser target:** fuzzer has run 10M+ iterations with no new coverage edges and no crashes beyond the initial corpus warm-up; coverage has plateaued for 2+ hours.
- **IPC target:** all exported service methods return permission errors or input validation rejections; no Binder/XPC transaction code accepts the fuzzed parcel shape.
- **Native library:** library uses safe wrappers (Rust, bounds-checked C++) and sanitizers confirm no memory safety violations after sustained fuzzing.
- **API target:** all mutated requests return 400/422 validation errors with no divergence in timing, error structure, or server behavior.

### Escalation Triggers — extend the campaign when these appear

- **New coverage edge discovered after plateau** — the fuzzer found a new code path; extend the campaign and seed the corpus with the triggering input.
- **ASan/MTE report but crash is non-deterministic** — race condition or timing-dependent bug; switch to TSan or add thread-stress to the harness.
- **Crash in third-party SDK or system library** — verify reachability from the app's input surface; if reachable, the app inherits the vulnerability.
- **Partial signal: timeout or hang without crash** — the parser hit an algorithmic complexity or infinite loop; add timeout instrumentation and test with progressively larger inputs.
- **Crash only under specific sanitizer** (UBSan but not ASan) — the bug is real but does not produce visible corruption without sanitizer; check whether it's exploitable without sanitizer on production builds.

## Extended Resources

- `agent/references/mobile/mobile-fuzzing.md` - campaign design, tool choice, OS-specific targets, Docker, Mac ARM, and sources.
- `agent/references/code-vuln-patterns/fuzz-harness-patterns.md` - libFuzzer/AFL++ harness patterns and sanitizer flags for C/C++.
- `agent/references/mobile/android-app-security.md` - Android app target selection context.
- `agent/references/mobile/ios-app-security.md` - iOS app target selection context.
