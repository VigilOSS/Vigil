# iOS App Security Reference

## Assessment Spine

Use OWASP MASVS and MASTG to organize findings by storage, crypto, auth, network, platform interaction, code quality, resilience, and privacy: https://mas.owasp.org/MASVS/03-Using_the_MASVS/

Start with authorized source, `.ipa`, `.xcarchive`, TestFlight/internal access, or a client-owned App Store install because App Store binaries are FairPlay-encrypted and decrypted static analysis requires an authorized lab path.

Request both release-equivalent and debug/instrumentable builds because iOS signing, entitlements, anti-tamper checks, and pinning can block analysis while shipped behavior still needs validation.

## Static Review Targets

- IPA metadata: `Info.plist`, entitlements, `embedded.mobileprovision`, Team ID, ATS settings, URL schemes, associated domains, app groups, app extensions, document types, privacy purpose strings, and background modes.
- Binary metadata: linked frameworks, symbols, Swift metadata, Objective-C classes, strings, bundled certificates, bundled configs, and native libraries.
- Code patterns: Keychain wrappers, file protection classes, local databases, logging, custom trust evaluation, pinning, WebView setup, script message handlers, URL handlers, pasteboard use, jailbreak checks, debugger checks, and native parsers.

Primary tools: Xcode tooling, `otool`, `nm`, `strings`, `rabin2`, Ghidra/IDA/radare2, MobSF, Swift metadata tooling, and Objective-C metadata tools when symbols are available.

## Dynamic Review Targets

- Exercise login, logout, enrollment, payment, sharing, import/export, push, deep-link, universal-link, app-extension, and account-switch flows while capturing proxy traffic and device logs.
- Inspect app containers, group containers, Keychain items, cookies, WebView stores, caches, snapshots, logs, and backup behavior before and after sensitive flows.
- Use Simulator for source-built debug loops and UI automation; validate Keychain, biometrics, APNs, Secure Enclave-adjacent behavior, TestFlight/App Store behavior, and anti-tamper results on owned hardware.
- Use Frida server on authorized jailbroken devices, Frida Gadget in authorized repackaged apps, and LLDB mainly for source/debug builds.

## High-Value Bug Classes

- Keychain bugs misuse access groups, `kSecAttrAccessible`, synchronizable items, biometric access controls, migration, logout cleanup, or token lifetime.
- Local storage bugs expose sensitive data through `UserDefaults`, SQLite/Core Data/Realm, plist/json files, cookies, logs, snapshots, caches, backups, WebView storage, or group containers.
- Network bugs weaken ATS, TLS validation, pinning, mTLS storage, WebSocket traffic, token refresh, replay protection, GraphQL/REST authorization, or error behavior.
- Link bugs abuse URL schemes, universal links, OAuth redirects, malformed parameters, cross-account actions, token leakage, open redirects, or destructive actions without fresh authorization.
- Pasteboard bugs leak sensitive data, persist data too long, miss local-only/expiration controls, or read external pasteboard content without user intent.
- WebView bugs expose JavaScript bridges, unsafe origin checks, attacker-controlled navigation, file/content loading, mixed web-native trust, or uncleared web data.

## Source Anchors

- Apple app security overview: https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/web
- Apple app code signing: https://support.apple.com/guide/security/app-code-signing-process-sec7c917bf14/web
- Xcode Simulator and device testing: https://developer.apple.com/documentation/xcode/running-your-app-in-simulator-or-on-a-device/
- Testing in Simulator versus hardware: https://developer.apple.com/documentation/xcode/testing-in-simulator-versus-testing-on-hardware-devices
- App Transport Security: https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity
- WKWebView: https://developer.apple.com/documentation/webkit/wkwebview
- Keychain Services: https://developer.apple.com/documentation/security/keychain_services
- OWASP iOS platform overview: https://mas.owasp.org/MASTG/0x06a-Platform-Overview/
- OWASP iOS app extraction: https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0054/
- Frida iOS: https://frida.re/docs/ios/
- Frida Gadget: https://frida.re/docs/gadget/
- Objection: https://github.com/sensepost/objection
