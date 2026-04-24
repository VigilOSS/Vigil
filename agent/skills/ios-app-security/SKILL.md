---
name: ios-app-security
description: Authorized iOS app security assessment for IPA/Xcode/TestFlight builds, app APIs, Keychain, local storage, ATS/TLS, links, pasteboard, WebView, native code, and runtime instrumentation
origin: AI Threat Hunting
---

# iOS App Security

## When to Activate

- Assessing an iOS app from source, `.ipa`, `.xcarchive`, TestFlight, enterprise distribution, or client-provided builds.
- Testing Keychain, Data Protection, ATS/TLS, URL schemes, universal links, pasteboard, WebView bridges, local storage, app extensions, or mobile APIs.
- Deciding whether Simulator testing is sufficient or owned iPhone/iPad hardware is required.

## Scope Gate

Confirm authorization covers the app bundle, Apple IDs, test accounts, backend APIs, device UDIDs, proxy interception, repackaging, jailbreak use, Frida Gadget, LLDB attachment, and decrypted IPA workflows. Treat App Store binaries, jailbroken devices, and virtual iOS platforms as lab assets that require explicit permission and clean data separation.

## Core Workflow

### 1. Collect Inputs

- Release-equivalent build for shipped behavior and debug/instrumentable build for visibility.
- Bundle ID, version, Team ID, provisioning profile, entitlements, minimum iOS version, supported devices, API hosts, test roles, and backend scope.
- Real-device plan for App Store/TestFlight behavior, Keychain edges, biometrics, push, Secure Enclave-adjacent flows, and anti-tamper checks.

### 2. Static Triage

- Unpack the IPA and inspect `Info.plist`, entitlements, `embedded.mobileprovision`, ATS settings, URL schemes, associated domains, app groups, extensions, document types, libraries, symbols, strings, bundled certificates, and bundled configs.
- Use `otool`, `nm`, `rabin2`, Ghidra/IDA, MobSF, Swift metadata tools, and Objective-C metadata only when the binary exposes the relevant symbol model.
- Search for Keychain wrappers, local database paths, logging, certificate pinning, custom trust evaluation, WebView setup, JavaScript bridges, URL handling, pasteboard access, jailbreak/debugger checks, and native parsers.

### 3. Dynamic Triage

- Exercise login, logout, enrollment, payment, sharing, deep-link, push, import/export, and account-switch flows while capturing proxy traffic and device logs.
- Use Simulator for source-built debug loops, UI automation, and quick storage checks; validate security conclusions on owned hardware when hardware-backed services or distribution behavior matter.
- Use Frida server on authorized jailbroken devices and Frida Gadget only for owned or explicitly authorized repackaged apps; use LLDB primarily with debuggable builds or source-level access.
- Inspect app containers, group containers, cookies, WebView stores, caches, logs, snapshots, and Keychain items before and after sensitive flows.

### 4. Test High-Value Boundaries

- **Keychain and Data Protection:** check `SecItem*` usage, access groups, synchronizable items, `kSecAttrAccessible`, biometric access controls, token lifetime, migration behavior, and lock-state assumptions.
- **Local storage:** review `UserDefaults`, SQLite/Core Data/Realm, plist/json files, cookies, caches, logs, snapshots, backups, WebView storage, and logout cleanup.
- **Network:** map hosts, ATS exceptions, TLS versions, custom trust evaluation, pinning, mTLS storage, WebSocket traffic, GraphQL/REST authorization, replay resistance, and error leakage.
- **Links and pasteboard:** test custom URL schemes, universal links, pasteboard reads/writes, token leakage, malformed parameters, cross-account actions, and destructive actions without fresh authorization.
- **WebView:** prefer `WKWebView`, enumerate script message handlers, validate loaded origins, block unsafe file/content loading, and clear web data after sensitive sessions.
- **Native code:** review Swift/ObjC/native boundaries, C/C++ parsers, crypto code, and app extensions that process attacker-controlled files or IPC messages.

### 5. Evidence Standard

Map each result to OWASP MASVS, affected version, device/iOS version, distribution path, entitlement context, account role, reproducible steps, and server-side impact. A client-side observation becomes a finding when it enables account compromise, unauthorized data access, unintended state change, sensitive-data exposure, privacy violation, or native/WebView boundary crossing.

## Extended Resources

- `agent/references/mobile/ios-app-security.md` - iOS app testing details and source links.
- `agent/references/mobile/mobile-lab-setup.md` - Simulator, real-device, jailbreak, Mac ARM, Docker, proxy, and device-farm decisions.
- `agent/references/mobile/ios-platform-device-lab.md` - secure boot, SEP, Data Protection, sandboxing, XPC/Mach, dyld, XNU, jailbreak, and SRD boundaries.
- `agent/references/mobile/mobile-fuzzing.md` - iOS-relevant fuzzing workflow for APIs, parsers, IPC, WebView, and native libraries.
