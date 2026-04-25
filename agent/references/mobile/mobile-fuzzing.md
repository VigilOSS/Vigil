# Mobile Fuzzing Reference

## Target Classes

- App/API fuzzing mutates authorized REST, GraphQL, WebSocket, MQTT, and local backend request sequences while preserving authentication boundaries and account separation.
- File-format fuzzing targets app import paths, media handlers, document readers, archives, protobuf/JSON/plist/SQLite parsers, QR codes, and SDK callbacks.
- IPC fuzzing targets exported Android components, AIDL/Binder services, intents, content providers, URL schemes, universal links, app extensions, XPC services, and Mach services under explicit scope. For Android Binder/AIDL services in AOSP builds, use the `service_fuzzer` framework — it generates libFuzzer harnesses from AIDL interface definitions via `fuzzService()` and the `service_fuzzer_defaults` build module. For closed-source services, use Frida to call `IBinder.transact()` with mutated parcels.
- WebView/browser-adjacent fuzzing targets app-owned JavaScript bridges, URL routing, content loading, and HTML/JS inputs. Full WebKit fuzzing targets engine internals that require source builds, custom toolchains, and approved platform labs for meaningful crash visibility — treat it as a separate campaign scoped to engine-level research.
- Native fuzzing targets C/C++ parser APIs, JNI boundaries, compression/media libraries, crypto adapters, and SDK native code.

## Harness Rules

Use the real production entrypoint, preserve caller preconditions, initialize real context, reset state between iterations, cap input sizes, avoid sleeps/network, compile with debug symbols, and crash only on security-relevant invariants.

Prefer libFuzzer for in-process parser APIs, AFL++ for forkserver or binary-oriented workflows, honggfuzz for multiprocessing or attach-style workflows, and Frida for closed-source runtime stimulation.

Use source-level harnesses when source and rebuilds are available because runtime hook fuzzing usually has lower throughput, weaker coverage feedback, and more false positives.

## Corpus And Coverage

Seed from valid test fixtures, exported files, captured traffic, minimal generated samples, app backups, public format examples, and crash regression cases.

Add dictionaries for magic bytes, MIME types, intent actions, extra keys, AIDL fields, plist keys, JSON keys, GraphQL names, URL parameters, file extensions, and protocol tokens.

Track coverage with SanitizerCoverage, AFL++ instrumentation, engine feedback, or platform-specific coverage where available.

Judge corpus quality by new reachable code, unique edges, and stable parser states, not by raw file count.

## Sanitizers And Platforms

Use ASan and UBSan first because memory corruption and undefined behavior dominate native parser triage.

Use HWASan or Android MTE when supported by target hardware/builds; use MSan only when the full dependency graph rebuilds cleanly with MSan instrumentation.

Use TSan for race-focused harnesses only after deterministic single-threaded parsing has been ruled out.

MTE (Memory Tagging Extension) provides hardware-accelerated memory safety checking on Pixel 8+ (Tensor G3) and Pixel 9+ (Tensor G4). Enable per-app via `adb shell am compat enable NATIVE_MEMTAG_SYNC com.target.app` for precise diagnostics during fuzzing, or use `NATIVE_MEMTAG_ASYNC` for low-overhead production-like detection. MTE catches heap-buffer-overflow, use-after-free, and double-free at 15/16 detection probability per tag mismatch without recompilation for heap allocations — add `-fsanitize=memtag -march=armv8-a+memtag` for stack and global coverage.

On iOS, sanitizer and symbolization quality are strongest with source builds, debug symbols, and owned devices provisioned for development.

## Crash Triage

Minimize the input, reproduce on a clean build, collect symbolized stack traces, record device/OS/build/fuzzer versions, and deduplicate by crash state.

Classify crashes as harness bug, expected parser rejection, denial of service, memory safety issue, logic assertion, or platform bug before reporting.

Convert a crash into a finding only when the crashing input is reachable under the engagement threat model and impact demonstrates memory corruption, information disclosure, privilege crossing, or denial of service affecting other users.

Add a regression test or minimized corpus seed after remediation so the bug stays fixed.

## Docker And Mac ARM

Docker is useful for Linux fuzzing toolchains, OSS-Fuzz-style build layouts, reproducible CI replay, and isolating crash artifacts.

Mac ARM hosts run native arm64 builds for full-speed coverage feedback — QEMU emulation of amd64 introduces timing variation that masks race conditions and slows iteration. Move long amd64 campaigns to native x86_64 hosts or cloud workers.

Docker cannot emulate iOS devices and should not be used as a substitute for owned iPhones, Apple Security Research Devices, or approved virtual iOS platforms.

## Source Anchors

- LLVM libFuzzer: https://llvm.org/docs/LibFuzzer.html
- SanitizerCoverage: https://clang.llvm.org/docs/SanitizerCoverage.html
- AddressSanitizer: https://clang.llvm.org/docs/AddressSanitizer.html
- Android HWASan: https://developer.android.com/ndk/guides/hwasan
- AFL++ fuzzing in depth: https://aflplus.plus/docs/fuzzing_in_depth/
- honggfuzz: https://github.com/google/honggfuzz
- OSS-Fuzz ideal integration: https://google.github.io/oss-fuzz/advanced-topics/ideal-integration/
- Android libFuzzer: https://source.android.com/docs/security/test/libfuzzer
- Android AIDL fuzzing: https://source.android.com/docs/core/architecture/aidl/aidl-fuzzing
- Frida JavaScript API: https://frida.re/docs/javascript-api/
- Fuzzilli: https://github.com/googleprojectzero/fuzzilli
- Docker multi-platform builds: https://docs.docker.com/build/building/multi-platform/
- Android MTE for NDK: https://developer.android.com/ndk/guides/arm-mte
- Android MTE system testing: https://source.android.com/docs/security/test/memory-safety/arm-mte
- Google Android Offensive Security — Binder fuzzing: https://androidoffsec.withgoogle.com/posts/binder-fuzzing/
- Android 16KB page size: https://developer.android.com/guide/practices/page-sizes
