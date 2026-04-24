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
- Convert confirmed crashes into findings only when the input is reachable under the engagement threat model and the crash has security impact or reliable denial-of-service impact.

## Mobile-Specific Notes

- Android app fuzzing commonly targets parsers, intents, content providers, exported services, JNI libraries, and mobile API schemas.
- Android platform fuzzing can target Binder/AIDL and native services only in owned AOSP/Cuttlefish/Pixel labs with recovery paths.
- iOS app fuzzing commonly targets imported files, URL schemes, universal links, pasteboard-driven parsing, WebView bridges, app extensions, and native libraries.
- iOS platform fuzzing requires owned research devices, source builds, public research harnesses, or approved virtual platforms for meaningful crash visibility.
- Docker helps Linux fuzzing toolchains, OSS-Fuzz-style layouts, and CI replay; Mac ARM hosts should prefer native arm64 builds or remote Linux/x86 workers for throughput-sensitive campaigns.

## Extended Resources

- `agent/references/mobile/mobile-fuzzing.md` - campaign design, tool choice, OS-specific targets, Docker, Mac ARM, and sources.
- `agent/references/code-vuln-patterns/fuzz-harness-patterns.md` - libFuzzer/AFL++ harness patterns and sanitizer flags for C/C++.
- `agent/references/mobile/android-app-security.md` - Android app target selection context.
- `agent/references/mobile/ios-app-security.md` - iOS app target selection context.
