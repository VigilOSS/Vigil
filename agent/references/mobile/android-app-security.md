# Android App Security Reference

## Assessment Spine

Use OWASP MASVS to keep the assessment organized by storage, crypto, auth, network, platform interaction, code quality, resilience, and privacy: https://mas.owasp.org/MASVS/03-Using_the_MASVS/

Start from the final APK/AAB because Gradle manifests, product flavors, dependency manifests, and SDK code can create components that are absent from source-only review.

Request a debug or instrumentation build when possible, but validate findings on release-equivalent behavior because R8, obfuscation, signing, pinning, Play Integrity, and SDK configuration can differ.

## Static Review Targets

- Manifest: package, `targetSdkVersion`, permissions, exported components, intent filters, app links, custom permissions, `allowBackup`, debuggability, providers, services, receivers, and SDK-added components.
- Resources: `network_security_config`, XML preferences, raw assets, bundled certs, API config, Firebase files, feature flags, and localization strings that reveal hidden flows.
- Code: auth/session logic, WebView settings, deep-link handlers, intent forwarding, `PendingIntent` creation, provider access checks, crypto primitives, Keystore use, logging, emulator/root checks, and JNI registration.
- Native libraries: ABI coverage, exported JNI symbols, dynamic registration, parsers, crypto/compression/media code, RASP/pinning libraries, and memory-unsafe dependencies.

Primary tools: `apktool` for resources/smali, `jadx` for Java/Kotlin cross-reference, MobSF for first-pass triage, Ghidra/IDA/radare2 for native code, and `apksigner`/`bundletool` for signing and bundle details.

## Dynamic Review Targets

- Proxy login, logout, enrollment, payment, import/export, sharing, push, deep-link, and account-switching flows through Burp or mitmproxy.
- Capture `adb logcat`, screenshots, local files, databases, WebView stores, cookies, and process memory around sensitive transitions.
- Use Frida server on rooted owned devices or Frida Gadget in authorized repackaged builds; use Objection for quick storage, Keystore-related, SSL-pinning, class, and heap exploration.
- Replay mobile API calls outside the app with changed role, tenant, object ID, device ID, request order, and stale tokens.

## High-Value Bug Classes

- Storage bugs expose credentials, tokens, keys, PII, documents, or payment data through SharedPreferences, SQLite/Room, files, logs, caches, backups, screenshots, clipboard, or WebView stores.
- Crypto bugs use static keys, static IVs, unauthenticated modes, hardcoded wrapping keys, predictable randomness, weak derivation, or Keystore keys without the required user-auth constraints.
- Network bugs weaken cleartext policy, custom trust managers, certificate pinning, token refresh, WebSockets, GraphQL/REST authorization, mTLS storage, or retry/error behavior.
- IPC bugs expose activities, services, receivers, providers, deep links, app links, URI grants, mutable pending intents, intent forwarding, or custom permissions without caller validation.
- WebView bugs join attacker-controlled URLs or JavaScript with native bridges, file access, mixed content, permissive navigation, or missing origin checks.
- Native bugs sit in JNI parsers, compression/media handlers, crypto adapters, SDK libraries, and RASP code that Java-layer hooks do not see.

## API-Level Coverage

- API 31 matters because Android 12 requires explicit `android:exported` for components with intent filters and introduced `PendingIntent` mutability expectations.
- API 34 matters because Android 14 adds restrictions around implicit intents, mutable pending intents, dynamic code loading, and ZIP path traversal handling: https://developer.android.com/about/versions/14/behavior-changes-14
- API 35 matters because Google Play requires new apps and app updates to target Android 15 or higher as of August 31, 2025: https://developer.android.com/google/play/requirements/target-sdk
- API 36 matters because Android 16 hardens default behavior against general intent-redirection attacks: https://developer.android.com/about/versions/16/behavior-changes-all
- API 37 matters in 2026 because Android 17 beta images are available for Pixel devices and emulators, but preview APIs can change until Platform Stability: https://developer.android.com/about/versions/17/overview

## Source Anchors

- Android security best practices: https://developer.android.com/privacy-and-security/security-best-practices
- Network Security Config: https://developer.android.com/privacy-and-security/security-config
- Android Keystore: https://developer.android.com/privacy-and-security/keystore
- Intents and intent filters: https://developer.android.com/guide/components/intents-filters
- PendingIntent risks: https://developer.android.com/privacy-and-security/risks/pending-intent
- WebView JavaScript bridge risks: https://developer.android.com/develop/ui/views/layout/webapps/native-api-access-jsbridge
- JNI tips: https://developer.android.com/ndk/guides/jni-tips
- Frida Android: https://frida.re/docs/android/
- Objection: https://github.com/sensepost/objection
- apktool: https://apktool.org/
- jadx: https://github.com/skylot/jadx
