# iOS Platform And Device Lab Reference

## Authorization Gate

Confirm owned hardware or explicit client authorization, Apple ID separation, device UDID/provisioning approval, jailbreak/SRD/virtual-device permission, backup/wipe acceptance, log-handling rules, and disclosure path before advising invasive iOS research.

## Platform Security Map

- Secure boot verifies each stage from Boot ROM through iBoot, kernel, kernel extensions, baseband firmware, and Secure Enclave firmware.
- Secure Enclave, keybags, Data Protection classes, APFS encryption, and Keychain access classes shape lock-state and credential-storage behavior.
- Mandatory code signing, Team ID checks, provisioning, entitlements, sandboxing, ASLR, and runtime protections constrain what third-party apps can load or access.
- App groups, extensions, URL schemes, universal links, pasteboard, Keychain access groups, and WebKit bridges are common app-level boundary surfaces.
- XPC, Mach services, launchd, dyld shared cache, XNU, IOKit, AMFI, PAC, and sandbox profiles are platform-research topics that require stronger lab controls than app testing.

## Simulator, Device, Jailbreak, And SRD Split

Use iOS Simulator for source-built app loops, UI automation, and quick proxy or storage checks.

Use current physical iPhones/iPads for TestFlight/App Store behavior, APNs, Keychain edge cases, Face ID/Touch ID, Secure Enclave-adjacent flows, modem/SIM, camera/NFC, and performance realism.

Use jailbreakable legacy devices only when authorized runtime visibility, Frida server, filesystem inspection, or jailbreak-only tooling is required.

Use Apple Security Research Device or approved virtual iOS platforms for deeper platform research that needs shell access, custom entitlements, or kernel-level observability.

Do not assume modern A12+ devices on current iOS are jailbreakable because public jailbreak support is version- and chipset-dependent.

## Observability

Collect crash logs, sysdiagnose, device logs, Console output, stackshots, profiles, and network traces with Apple-supported tooling when possible.

Symbolicate crashes with the exact dSYM, build, device architecture, and OS version because iOS mitigations and dyld shared cache differences affect crash interpretation.

Treat platform crashes as reliability evidence until reachability, trust boundary, and security impact are established.

## Source Anchors

- iPhone/iPad boot process: https://support.apple.com/guide/security/boot-process-for-ipad-and-iphone-devices-secb3000f149/web
- Secure Enclave: https://support.apple.com/guide/security/the-secure-enclave-sec59b0b31ff/web
- Data Protection: https://support.apple.com/guide/security/data-protection-sece8608431d/web
- Data Protection classes: https://support.apple.com/guide/security/data-protection-classes-secb010e978a/web
- Keychain data protection: https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web
- Runtime process security: https://support.apple.com/guide/security/security-of-runtime-process-sec15bfe098e/web
- App access to user data: https://support.apple.com/guide/security/protecting-app-access-to-user-data-secc01781f46/web
- Code signing process: https://support.apple.com/guide/security/app-code-signing-process-sec7c917bf14/web
- XPC: https://developer.apple.com/documentation/xpc
- XNU source: https://github.com/apple-oss-distributions/xnu
- dyld source: https://github.com/apple-oss-distributions/dyld
- Profiles and Logs: https://developer.apple.com/feedback-assistant/profiles-and-logs/?platform=ios
- Apple Security Research Device: https://security.apple.com/research-device
- Apple bounty terms: https://security.apple.com/terms-and-conditions/
- Theos rootless notes: https://theos.dev/docs/rootless
