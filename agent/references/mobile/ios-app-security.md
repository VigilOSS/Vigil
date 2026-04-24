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

## Privacy Testing (MASVS-PRIVACY)

- **Identifier audit:** check for IDFA usage via `ASIdentifierManager`, `advertisingIdentifier`; check `identifierForVendor` scope; check for fingerprinting signals (screen metrics, timezone, language, installed fonts, device model, carrier). Frida hook: `Interceptor.attach(ObjC.classes.ASIdentifierManager['- advertisingIdentifier'].implementation, { onLeave: function(retval) { console.log('[IDFA] ' + new ObjC.Object(retval)); } });`
- **App Tracking Transparency (ATT):** verify the app calls `ATTrackingManager.requestTrackingAuthorization` before accessing IDFA; check whether tracking occurs when ATT consent is denied (fingerprinting workaround, server-side attribution, probabilistic matching). Capture outbound traffic with ATT denied and compare against ATT-granted traffic.
- **Data deletion:** after account deletion request, verify that Keychain items, UserDefaults, SQLite/Core Data, cached files, WebView storage, cookies, app group containers, and iCloud-synced data are actually removed. Re-login and check whether any prior state persists.
- **Privacy Nutrition Label vs behavior:** compare App Store privacy label declarations against actual network traffic and local storage. Use proxy captures to identify analytics/ad SDKs sending data types (location, contacts, identifiers) not declared in the privacy label.
- **Analytics/telemetry audit:** identify Firebase Analytics, Amplitude, Mixpanel, Adjust, AppsFlyer, and ad SDKs in binary symbols and framework bundles; capture their outbound requests; assess whether data collection scope exceeds what the app's stated purpose requires.

## AI/ML On-Device Features

- **Model file extraction:** search IPA for Core ML models (`.mlmodel`, `.mlmodelc` in `Payload/App.app/`), TFLite models, and ONNX models. Extract and inspect model architecture, input/output shapes, and embedded metadata. Core ML compiled models are in `App.app/*.mlmodelc/` directories.
- **Inference data leakage:** after exercising AI features (Apple Intelligence integration, smart compose, image classification, summarization), check UserDefaults, SQLite, logs, crash reports, and Keychain for model input/output data persisting in cleartext.
- **Prompt injection:** if the app integrates Apple Intelligence, on-device LLM, or cloud LLM features, test whether user input fields that feed the model accept prompt injection payloads that change model behavior, bypass content filters, or extract system prompts.
- **On-device processing audit:** verify on-device AI processing claims by capturing network traffic during AI feature usage — any outbound connections to inference endpoints contradict on-device claims and indicate server-side data processing.

## SDK Supply Chain

- **SDK bill of materials:** enumerate third-party frameworks from `Payload/App.app/Frameworks/`, CocoaPods `Podfile.lock` (if source available), SPM `Package.resolved`, and binary symbol patterns (`nm`, `strings`, class-dump). Record framework name, version, and purpose.
- **SDK CVE checking:** check bundled framework versions against NVD, Snyk, and vendor advisories. Focus on high-value frameworks: Alamofire, AFNetworking, Firebase, React Native, Flutter engine, WebKit extensions.
- **SDK data exfiltration:** capture outbound traffic from analytics/ad SDKs and compare against the app's privacy label declarations. SDKs that collect IDFA, location, contacts, or device data beyond the app's declared purposes indicate supply chain risk.
- **SDK permission scope:** check entitlements and Info.plist privacy purpose strings against actual SDK usage. SDKs that request location (`NSLocationWhenInUseUsageDescription`), contacts, camera, or microphone access beyond the app's core features indicate over-scoped permissions.

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
