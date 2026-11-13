---
description: Mobile fuzzing specifics — target classes (app/API, file formats, IPC, Binder/AIDL service_fuzzer, XPC/Mach, WebView, native/JNI), mobile seeds and dictionaries, HWASan/MTE, iOS and Mac ARM/Docker limits, crash-to-finding rule
skill: mobile-fuzzing
---

# Mobile Fuzzing Reference

Engine templates, sanitizer flags and generic harness shapes are in
`agent/references/code-vuln-patterns/fuzz-harness-patterns.md`; campaign registration and crash
recording are `agent/skills/code-fuzz-campaign/SKILL.md`. This file holds what is mobile-specific.

## Target Classes

- App/API fuzzing mutates authorized REST, GraphQL, WebSocket, MQTT and local backend request sequences while preserving authentication boundaries and account separation.
- File-format fuzzing targets app import paths, media handlers, document readers, archives, protobuf/JSON/plist/SQLite parsers, QR codes and SDK callbacks.
- IPC fuzzing targets exported Android components, AIDL/Binder services, intents, content providers, URL schemes, universal links, app extensions, XPC services and Mach services under explicit scope. For Android Binder/AIDL services in AOSP builds, use the `service_fuzzer` framework: it generates libFuzzer harnesses from AIDL interface definitions via `fuzzService()` and the `service_fuzzer_defaults` build module. For closed-source services, use Frida to call `IBinder.transact()` with mutated parcels.
- WebView/browser-adjacent fuzzing targets app-owned JavaScript bridges, URL routing, content loading and HTML/JS inputs. Full WebKit fuzzing targets engine internals that need source builds, custom toolchains and approved platform labs for meaningful crash visibility; treat it as a separate engine-level campaign (Fuzzilli for JavaScript engines).
- Native fuzzing targets C/C++ parser APIs, JNI boundaries, compression/media libraries, crypto adapters and SDK native code.
- iOS app fuzzing commonly targets imported files, URL schemes, universal links, pasteboard-driven parsing, WebView bridges, app extensions and native libraries.

## Harness Choice

Prefer source-level harnesses on the real production entrypoint when source and rebuilds exist: runtime-hook fuzzing through Frida usually has lower throughput, weaker coverage feedback and more false positives, so keep it for closed-source runtime stimulation. Engines: libFuzzer for in-process parser APIs,
AFL++ for forkserver or binary-oriented workflows, honggfuzz for multiprocessing or attach-style
workflows.

## Corpus And Dictionaries

Mobile seed sources beyond test fixtures: exported files, captured traffic, app backups, public format examples and crash regressions. Dictionary entries specific to mobile surfaces: intent actions and extra keys, AIDL fields, plist keys, MIME types, URL parameters, file extensions and GraphQL names, alongside magic bytes and protocol tokens.

## Sanitizers And Platforms

- HWASan or Android MTE when the target hardware or build supports it; MSan only when the full dependency graph rebuilds cleanly with MSan instrumentation; TSan for race-focused harnesses after deterministic single-threaded parsing is ruled out.
- MTE (Pixel 8+ / Tensor G3, Pixel 9+ / Tensor G4): enable per app with `adb shell am compat enable NATIVE_MEMTAG_SYNC com.target.app` for precise diagnostics during fuzzing, or `NATIVE_MEMTAG_ASYNC` for low-overhead production-like detection. It catches heap-buffer-overflow, use-after-free and double-free with 15/16 detection probability per tag mismatch without recompiling heap allocations; add `-fsanitize=memtag -march=armv8-a+memtag` for stack and global coverage.
- 16KB page devices (Android 15+): native code behaves differently between 4KB and 16KB pages; alignment check in `agent/references/mobile/android-app-security.md` "API-Level Coverage".
- iOS: sanitizer and symbolization quality are strongest with source builds, debug symbols and owned devices provisioned for development.

## Crash Triage

Record device, OS, build and fuzzer versions with each crash, and classify it (harness bug, expected parser rejection, denial of service, memory safety, logic assertion, platform bug) before reporting. A crash becomes a finding only when the crashing input is reachable under the engagement threat model and the impact is memory corruption, information disclosure, privilege crossing, or denial of service affecting other users; the classification table is in the skill's "Evidence".

## Docker And Mac ARM

Docker suits Linux fuzzing toolchains, OSS-Fuzz-style build layouts, reproducible CI replay and isolating crash artifacts.

Mac ARM hosts run native arm64 builds at full speed. QEMU emulation of amd64 introduces timing variation that masks race conditions and slows iteration, so move long amd64 campaigns to native x86_64 hosts or cloud workers.

Docker cannot emulate iOS devices and is no substitute for owned iPhones, Apple Security Research Devices or approved virtual iOS platforms.

## Source Anchors

- Android AIDL fuzzing: https://source.android.com/docs/core/architecture/aidl/aidl-fuzzing
- Google Android Offensive Security — Binder fuzzing: https://androidoffsec.withgoogle.com/posts/binder-fuzzing/
- Android HWASan: https://developer.android.com/ndk/guides/hwasan
- Android MTE for NDK: https://developer.android.com/ndk/guides/arm-mte
- Fuzzilli: https://github.com/googleprojectzero/fuzzilli
