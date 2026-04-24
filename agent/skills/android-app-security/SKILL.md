---
name: android-app-security
description: Authorized Android app security assessment for APK/AAB artifacts, app APIs, storage, crypto, IPC, WebView, native libraries, and runtime instrumentation
origin: AI Threat Hunting
---

# Android App Security

## When to Activate

- Assessing an Android APK, AAB, source tree, or client-provided app build.
- Testing Android app APIs, local storage, Keystore usage, TLS behavior, exported components, deep links, WebView bridges, native libraries, or anti-tamper controls.
- Deciding whether an emulator is enough or an owned physical Android device is required.

## Scope Gate

Confirm authorization covers the app package, backend APIs, test accounts, lab devices, proxy interception, repackaging, hooks, and companion test apps. Keep bypasses and malicious companion apps inside owned labs or explicit client scope because they can affect third-party apps and real user data if misdirected.

## Core Workflow

### 1. Collect Inputs

- Final APK/AAB or release-equivalent build, because merged manifests and third-party SDKs can change the attack surface.
- Debug or instrumentable build when available, because it preserves visibility into pinning, RASP, and storage behavior.
- Package name, version, signing state, target SDK, minimum SDK, API hosts, test accounts, backend scope, and expected app roles.
- Device matrix: emulator for fast loops, rooted owned Pixel for privileged runtime visibility, stock owned Pixel for Play Integrity and hardware-backed behavior.

### 2. Model Attackers

Use four app-level attackers: network observer with proxy control, co-installed malicious app, owner of a rooted lab device, and backend/API caller replaying mobile flows outside the client.

### 3. Static Triage

- Decode resources and manifest with `apktool`; decompile Java/Kotlin with `jadx`.
- Inspect `AndroidManifest.xml`, exported activities/services/receivers/providers, permissions, app links, deep links, pending intents, backup settings, debuggability, network security config, and SDK-added components.
- Search decompiled code for API bases, auth logic, WebView setup, crypto primitives, Keystore calls, root/emulator checks, JNI registration, native library loading, logging, and feature flags.
- Inventory `.so` libraries by ABI and send parser, crypto, compression, media, and RASP libraries to native analysis.

### 4. Dynamic Triage

- Run the app through login, logout, enrollment, payment, sharing, import/export, and account-switching flows while capturing proxy traffic and `adb logcat`.
- Use Frida or Objection only on owned devices or authorized builds; prefer custom Frida hooks when Java/Kotlin, Swift-style obfuscation, JNI, or app-specific trust logic defeats canned checks.
- Inspect app-private files, SharedPreferences, SQLite/Room, caches, WebView stores, logs, screenshots, backup artifacts, and process memory before and after sensitive flows.
- Replay captured API calls with altered object IDs, roles, tenant IDs, device IDs, headers, and flow order to prove whether client-side controls hide server-side authorization defects.

### 5. Test High-Value Boundaries

- **Storage and crypto:** distinguish encryption from safe key management; check Keystore attributes, IV reuse, hardcoded keys, biometric gates, backup eligibility, and logout cleanup.
- **Network:** test cleartext policy, trust managers, pinning implementation, token refresh, WebSocket/MQTT channels, GraphQL/REST authorization, retries, and error leakage.
- **IPC and links:** fuzz exported components, deep links, app links, content providers, URI grants, pending intents, custom permissions, and caller validation.
- **WebView:** review every loaded URL, navigation override, JavaScript bridge, file access setting, mixed-content policy, injected script, and origin check.
- **Native/JNI:** map Java-to-native entrypoints, hook JNI boundaries, inspect parser and crypto code, and triage sanitizer-suitable targets through `mobile-fuzzing`.
- **Resilience:** evaluate root/emulator/debugger/pinning checks only to preserve authorized test visibility and to measure client-side resistance.

### 6. Evidence Standard

Map each result to OWASP MASVS, affected app version, device/API level, artifact hash, account role, reproducible steps, security impact, and server-side validation. A mobile finding is reportable when it shows harm beyond local observation, such as token reuse, unauthorized data access, unintended state change, sensitive-data exposure, or a WebView-to-native privilege crossing.

## Extended Resources

- `agent/references/mobile/android-app-security.md` - Android app testing details, API-level notes, and source links.
- `agent/references/mobile/mobile-lab-setup.md` - emulator, physical device, Mac ARM, Docker, proxy, and device-farm decisions.
- `agent/references/mobile/android-platform-device-lab.md` - Pixel, bootloader, AVB, Cuttlefish, Binder, SELinux, HAL, and kernel research boundaries.
- `agent/references/mobile/mobile-fuzzing.md` - mobile fuzzing target selection, harnessing, corpus design, and crash triage.
