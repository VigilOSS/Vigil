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

- Preflight runtime tooling with the generic audited route: `aith assess kali exec --technique HEALTH --intent "Android APK tooling inventory" --probe-kind fingerprint --phase code-ingest --timeout 60 -- which apktool jadx adb bundletool apksigner`. Use `HEALTH` for tool inventory — unknown technique tags are rejected before an audit row is written, so invented tags like `TOOL-INVENTORY` create no records and leave coverage gaps.
- Decode resources and manifest with `apktool`; decompile Java/Kotlin with `jadx`.
- Inspect `AndroidManifest.xml`, exported activities/services/receivers/providers, permissions, app links, deep links, pending intents, backup settings, debuggability, network security config, and SDK-added components.
- Search decompiled code for API bases, auth logic, WebView setup, crypto primitives, Keystore calls, root/emulator checks, JNI registration, native library loading, logging, and feature flags.
- Inventory `.so` libraries by ABI and send parser, crypto, compression, media, and RASP libraries to native analysis.

### 4. Dynamic Triage

- Run the app through login, logout, enrollment, payment, sharing, import/export, and account-switching flows while capturing proxy traffic and `adb logcat`.
- Use Frida or Objection on owned devices or authorized builds; prefer custom Frida hooks when ProGuard/R8 obfuscation, JNI boundaries, or app-specific trust logic defeats canned checks.
- Inspect app-private files, SharedPreferences, SQLite/Room, caches, WebView stores, logs, screenshots, backup artifacts, and process memory before and after sensitive flows.
- Replay captured API calls with altered object IDs, roles, tenant IDs, device IDs, headers, and flow order to prove whether client-side controls hide server-side authorization defects.

### 5. Test High-Value Boundaries

- **Storage and crypto:** distinguish encryption from safe key management; check Keystore attributes, IV reuse, hardcoded keys, biometric gates, backup eligibility, and logout cleanup.
- **Network:** test cleartext policy, trust managers, pinning implementation, token refresh, WebSocket/MQTT channels, GraphQL/REST authorization, retries, and error leakage.
- **IPC and links:** fuzz exported components, deep links, app links, content providers, URI grants, pending intents, custom permissions, and caller validation.
- **WebView:** review every loaded URL, navigation override, JavaScript bridge, file access setting, mixed-content policy, injected script, and origin check.
- **Native/JNI:** map Java-to-native entrypoints, hook JNI boundaries, inspect parser and crypto code, and triage sanitizer-suitable targets through `mobile-fuzzing`.
- **Resilience:** Evaluate root/emulator/debugger/pinning checks to confirm authorized test tooling remains functional and to measure the strength of client-side resistance controls.

### 6. Evidence Standard

Map each result to OWASP MASVS, affected app version, device/API level, artifact hash, account role, reproducible steps, security impact, and server-side validation. A mobile finding is reportable when it shows harm beyond local observation, such as token reuse, unauthorized data access, unintended state change, sensitive-data exposure, or a WebView-to-native privilege crossing.

## A→B Chain Table

When a mobile vulnerability is confirmed, check B candidates before closing the finding — chaining raises a Medium to Critical.

| Found A | Check B | Combined Impact |
|---|---|---|
| Exported Activity with intent redirection | Craft Intent targeting internal Activity/ContentProvider that returns data | Access internal screens, read tokens, trigger state changes from zero-permission app |
| WebView with JS bridge and lax URL loading | Load attacker page in WebView via deep link or redirect that calls bridge methods | JS calls native methods to read files, exfiltrate tokens, or invoke content providers |
| Deep link handler accepts unvalidated parameters | Inject parameters to redirect OAuth flow or trigger authenticated API calls | Trigger authenticated actions (transfer, password reset) via crafted link |
| Content Provider exported without permission | Query with path traversal or SQL injection in selection args | Read app-private files, databases, tokens, keys from any installed app |
| Keystore key without user-auth requirement | Extract via Frida hook or backup, then forge JWTs/HMACs offline | Forge authentication tokens, impersonate device to backend |
| Broadcast Receiver leaks sensitive extras | Register matching receiver from malicious app to capture data | Capture OTPs or session tokens in real-time, replay for account takeover |
| `allowBackup="true"` with sensitive data in storage | Run `adb backup`, extract credentials from SharedPreferences/SQLite | Recover stored passwords, tokens, API keys; replay for account access |
| SSL pinning bypass succeeds | Intercept login/refresh flow, capture credentials or tokens in transit | Full credential interception, session hijack, API replay |
| URL scheme processes state-changing actions without CSRF check | Craft page with `<iframe src="myapp://account/delete">` | Trigger account deletion, settings change, payment without user consent |
| Mutable PendingIntent with empty base Intent | Intercept and fill missing fields to redirect to attacker target | Hijack notification actions, redirect auth callbacks with app's identity |
| Firebase/cloud config misconfiguration | Enumerate Firebase project, query open database or storage | Read/write user data, PII, uploaded documents |
| Notification/log leaks OTP or session token | Read logcat or notification content via listener | Capture OTPs, password reset links, session identifiers in real-time |

## Kill Signals and Escalation Triggers

Use these to decide when to stop or push harder on each surface — grinding dead leads wastes tokens, abandoning live signals misses findings.

### Kill Signals — rotate when these hold

- **Exported components:** all require signature-level or dangerous-level permissions that a co-installed app cannot obtain, and no intent redirection pattern exists in decompiled code.
- **WebView:** loads only first-party HTTPS URLs from a hardcoded allowlist confirmed both statically and dynamically, and no JS bridge is registered.
- **IPC:** all broadcasts use `LocalBroadcastManager` or signature-level permissions; services are unexported or signature-protected; content providers have signature-level read/write permissions with `grantUriPermissions=false`.
- **Storage:** all sensitive data at rest uses hardware-backed Keystore keys with user-auth requirement; no plaintext credentials in SharedPreferences, SQLite, logs, caches, screenshots, or clipboard after exercising all sensitive flows; `allowBackup=false`.
- **Network/TLS:** restrictive `network_security_config` with no cleartext and no user-CA trust; certificate pinning bypass fails; server rejects replayed tokens from non-app clients.

### Escalation Triggers — push harder when these appear

- **Exported Activity crashes on empty extras** — decompile and read which extras it expects; the crash confirms the component processes external input.
- **Deep link handler redirects to WebView but URL parameter is partially validated** — test path-based bypasses (`https://trusted.example@evil.example`, `https://trusted.example.evil.example`).
- **WebView loads first-party URL that has a reflected XSS or open redirect** — chain the XSS to load attacker JS; if a bridge exists, the XSS becomes native code execution.
- **Bridge methods appear UI-only** — hook with Frida to see actual parameters processed; "UI-only" methods sometimes accept file paths or serialized objects.
- **Sensitive data in logs during startup but not normal operation** — test error paths, session expiration, backgrounding, account switching; error paths often log data that happy paths hide.
- **Database encrypted but key derived from device identifier** — derive the key from the known identifier and attempt decryption; device-based keys are not secrets.
- **Pinning bypass works but tokens contain device-bound claims** — test whether the server actually validates binding claims; many apps include device ID but the server never checks.
- **Broadcast uses `protectionLevel="normal"` permission** — any installed app can request normal permissions; demonstrate cross-app interception.

## Extended Resources

- `agent/references/mobile/android-app-security.md` - Android app testing details, API-level notes, and source links.
- `agent/references/mobile/mobile-lab-setup.md` - emulator, physical device, Mac ARM, Docker, proxy, and device-farm decisions.
- `agent/references/mobile/android-platform-device-lab.md` - Pixel, bootloader, AVB, Cuttlefish, Binder, SELinux, HAL, and kernel research boundaries.
- `agent/references/mobile/mobile-fuzzing.md` - mobile fuzzing target selection, harnessing, corpus design, and crash triage.
