---
name: ios-app-security
description: Authorized iOS app security assessment for IPA/Xcode/TestFlight builds, app APIs, Keychain, local storage, ATS/TLS, links, pasteboard, WebView, native code, and runtime instrumentation
origin: Vigil
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

### 2. Model Attackers

Use four app-level attackers: network observer with proxy control on shared Wi-Fi, co-installed malicious app on the same device, owner of a jailbroken lab device with filesystem and process access, and backend/API caller replaying mobile flows outside the client. Add MDM-enrolled adversary when the app targets managed enterprise devices.

### 3. Static Triage

- Unpack the IPA and inspect `Info.plist`, entitlements, `embedded.mobileprovision`, ATS settings, URL schemes, associated domains, app groups, extensions, document types, libraries, symbols, strings, bundled certificates, and bundled configs.
- Use `otool`, `nm`, `rabin2`, Ghidra/IDA, MobSF, Swift metadata tools, and Objective-C metadata tools matched to the binary's symbol model — stripped binaries need different tooling than debug builds with full symbols.
- Search for Keychain wrappers, local database paths, logging, certificate pinning, custom trust evaluation, WebView setup, JavaScript bridges, URL handling, pasteboard access, jailbreak/debugger checks, and native parsers.

### 4. Dynamic Triage

- Exercise login, logout, enrollment, payment, sharing, deep-link, push, import/export, and account-switch flows while capturing proxy traffic and device logs.
- Use Simulator for source-built debug loops, UI automation, and quick storage checks; validate security conclusions on owned hardware when hardware-backed services or distribution behavior matter.
- Use Frida server on authorized jailbroken devices and Frida Gadget in owned or explicitly authorized repackaged apps — Gadget injection modifies the binary, so repackaging authorization is required; use LLDB primarily with debuggable builds or source-level access.
- Inspect app containers, group containers, cookies, WebView stores, caches, logs, snapshots, and Keychain items before and after sensitive flows.

### 5. Test High-Value Boundaries

- **Keychain and Data Protection:** check `SecItem*` usage, access groups, synchronizable items, `kSecAttrAccessible`, biometric access controls, token lifetime, migration behavior, and lock-state assumptions.
- **Local storage:** review `UserDefaults`, SQLite/Core Data/Realm, plist/json files, cookies, caches, logs, snapshots, backups, WebView storage, and logout cleanup.
- **Network:** map hosts, ATS exceptions, TLS versions, custom trust evaluation, pinning, mTLS storage, WebSocket traffic, GraphQL/REST authorization, replay resistance, and error leakage.
- **Links and pasteboard:** test custom URL schemes, universal links, pasteboard reads/writes, token leakage, malformed parameters, cross-account actions, and destructive actions without fresh authorization.
- **WebView:** require `WKWebView` over deprecated UIWebView — WKWebView runs in a separate process with stricter sandboxing; enumerate script message handlers, validate loaded origins, block unsafe file/content loading, and clear web data after sensitive sessions.
- **Native code:** review Swift/ObjC/native boundaries, C/C++ parsers, crypto code, and app extensions that process attacker-controlled files or IPC messages.

### 6. Evidence Standard

Map each result to OWASP MASVS, affected version, device/iOS version, distribution path, entitlement context, account role, reproducible steps, and server-side impact. A client-side observation becomes a finding when it enables account compromise, unauthorized data access, unintended state change, sensitive-data exposure, privacy violation, or native/WebView boundary crossing.

## Adjacent Mobile Skills

Static/dynamic triage above routinely surfaces leads outside this skill's own scope — dispatch
the matching skill directly instead of forcing the lead into this workflow:

- **Third-party SDK surface** — Step 3's binary/symbol inspection inventories ad, analytics,
  crash, or attribution SDKs → `agent/skills/sdk-supply-chain-security/SKILL.md` for SDK BOM, CVE
  checking, malicious-SDK detection, and over-collection auditing.
- **On-device AI/ML** — the app bundles Core ML models or integrates Apple Intelligence / an
  on-device LLM → `agent/skills/ai-ml-on-device-security/SKILL.md` for model extraction,
  inference-leakage, and prompt-injection testing.
- **Privacy/tracking compliance** — the app collects device identifiers, implements App Tracking
  Transparency, or its App Store Privacy Label needs verification against observed behavior →
  `agent/skills/masvs-privacy-testing/SKILL.md`.
- **Coverage-guided fuzzing** — a native-code or parser target from Step 5 warrants a campaign
  rather than manual review → `agent/skills/mobile-fuzzing/SKILL.md`.

## A→B Chain Table

When an iOS vulnerability is confirmed, check B candidates before closing the finding — chaining raises a Medium to Critical.

| Found A | Check B | Combined Impact |
|---|---|---|
| Universal link handler accepts unvalidated parameters | Inject redirect parameter to steal OAuth code/token during auth flow | Steal OAuth authorization code, gain authenticated API access as victim |
| WKWebView registers script message handlers with sensitive native methods | Navigate WebView to attacker page via deep link or redirect; call `window.webkit.messageHandlers.<name>.postMessage()` | Execute native methods: read Keychain items, access files, invoke APIs with stored credentials |
| Keychain items stored with weak protection class (no biometric gate) | Extract from backup or jailbroken device filesystem | Recover auth tokens, API keys, certificates; replay for account access |
| Custom URL scheme handles auth callback without AASA validation | Register competing app with same scheme to intercept OAuth code | Steal authorization code, exchange for access token, account takeover |
| App writes sensitive data to UIPasteboard without expiration | Background app reads general pasteboard content | Capture auth tokens, passwords, OTP codes; replay for account access |
| App Extension shares data via App Group with broad access | Read shared UserDefaults, SQLite, files from compromised extension | Cross-app data leakage: tokens, user data, cached credentials |
| Backup includes sensitive files without NSFileProtectionComplete | Create unencrypted backup, extract app container | Recover stored passwords, session tokens, encryption keys, chat databases |
| ATS disabled or custom trust evaluation weakened | MITM via proxy on shared network, capture login/API traffic | Full credential interception, session hijack, API replay |
| SFSafariViewController with open redirect in OAuth flow | Chain redirect with authorization endpoint to redirect code to attacker URI | Steal OAuth authorization code, access user account |
| Deep link triggers state-changing action without re-authentication | Send victim a link that triggers account deletion, payment, or settings change | State changes without user confirmation — CSRF-equivalent for mobile |
| Jailbreak detection bypass succeeds | Inspect Keychain, filesystem, runtime memory without app restrictions | Full runtime visibility: extract all credentials, hook all crypto, bypass client controls |
| Snapshot/screenshot cache not cleared on background | Extract snapshots from backup or jailbroken device | Recover screenshots of sensitive screens: balances, personal data, auth codes |

## Kill Signals and Escalation Triggers

Use these to decide when to stop or push harder on each surface — grinding dead leads wastes tokens, abandoning live signals misses findings.

### Kill Signals — rotate when these hold

- **URL schemes and links:** deep link handlers validate all parameters server-side; AASA file is correctly hosted with single-path patterns (no wildcards, no prefix-only matches) verified dynamically via universal link test; URL scheme does not handle auth callbacks.
- **WebView:** loads only first-party HTTPS URLs from an allowlist enforced in `decidePolicyFor:navigationAction:`; no `WKScriptMessageHandler` registered; JavaScript disabled in configuration.
- **Keychain:** all items use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or stricter with biometric binding; no `kSecAttrSynchronizable=true` on sensitive items; backup extraction yields no readable credentials.
- **Storage:** `NSFileProtectionComplete` applied to sensitive files; `UserDefaults` contains no credentials or tokens; logout clears all Keychain items, cookies, WebView storage, and caches.
- **Network:** ATS enforced with no exceptions; certificate pinning implemented correctly; pinning bypass via Frida fails or reveals only device-bound tokens that cannot be replayed.

### Escalation Triggers — push harder when these appear

- **AASA file exists but misconfigured** — served with wrong content type, expired, or uses overly broad path patterns; verify whether the OS actually enforces the association.
- **WebView loads first-party URL that has XSS or open redirect** — chain to load attacker JS in the WebView context; if a script message handler exists, the XSS becomes native method invocation.
- **Script message handlers appear read-only** — hook with Frida to see actual parameters; "UI-only" handlers sometimes accept file paths, URLs, or serialized objects.
- **Keychain item requires user auth but has long validity duration** (300+ seconds) — after one biometric unlock the key stays usable for the entire window without re-auth, giving a co-installed malicious app time to extract it; demonstrate extraction during the window.
- **Keychain item is `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (good) but `kSecAttrSynchronizable=true` (bad)** — synchronizable items go to iCloud Keychain, expanding the attack surface to iCloud account compromise.
- **Credentials cleared on logout but WebView cookies/localStorage are not** — check whether WebView storage contains session tokens that survive the logout flow.
- **App uses both WKWebView and SFSafariViewController** — test whether URL routing sends sensitive flows to the wrong renderer; security boundaries differ between in-app WebView (bridge access) and SafariVC (Chrome process).
- **SSL pinning bypass triggers session termination** — captured credentials from before termination may still be valid; test immediate token replay from a separate client.

## Extended Resources

- `agent/references/mobile/ios-app-security.md` - iOS app testing details and source links.
- `agent/references/mobile/mobile-lab-setup.md` - Simulator, real-device, jailbreak, Mac ARM, Docker, proxy, and device-farm decisions.
- `agent/references/mobile/ios-platform-device-lab.md` - secure boot, SEP, Data Protection, sandboxing, XPC/Mach, dyld, XNU, jailbreak, and SRD boundaries.
- `agent/references/mobile/mobile-fuzzing.md` - iOS-relevant fuzzing workflow for APIs, parsers, IPC, WebView, and native libraries.
