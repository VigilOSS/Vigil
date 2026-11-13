---
description: iOS secure boot, SEP, Data Protection, sandboxing, XPC/Mach, dyld/XNU, observability, jailbreak, SRD boundaries
skill: mobile-lab-setup
---

# iOS Platform And Device Lab Reference

## Authorization Gate

Confirm owned hardware or explicit client authorization, Apple ID separation, device UDID/provisioning approval, jailbreak/SRD/virtual-device permission, backup/wipe acceptance, log-handling rules, and disclosure path before advising invasive iOS research.

## Platform Security Map

- Boundaries a finding is placed against: secure boot (Boot ROM, iBoot, kernel, baseband and Secure Enclave firmware); Secure Enclave, keybags, Data Protection classes, APFS encryption and Keychain access classes (lock-state and credential storage); code signing, Team ID, provisioning, entitlements and the sandbox.
- App-level boundary surfaces: app groups, extensions, URL schemes, universal links, pasteboard, Keychain access groups and WebKit bridges.
- XPC, Mach services, launchd, the dyld shared cache, XNU, IOKit, AMFI, PAC and sandbox profiles are platform-research topics that need stronger lab controls than app testing.

## Simulator, Device, Jailbreak, And SRD Split

Use iOS Simulator for source-built app loops, UI automation, and quick proxy or storage checks.

Use current physical iPhones/iPads for TestFlight/App Store behavior, APNs, Keychain edge cases, Face ID/Touch ID, Secure Enclave-adjacent flows, modem/SIM, camera/NFC, and performance realism.

Use jailbreakable legacy devices only when authorized runtime visibility, Frida server, filesystem inspection, or jailbreak-only tooling is required.

Use Apple Security Research Device or approved virtual iOS platforms for deeper platform research that needs shell access, custom entitlements, or kernel-level observability.

Verify jailbreak availability before planning invasive iOS research — public jailbreak support is version- and chipset-dependent, and A12+ devices on current iOS releases are frequently not jailbreakable.

## Observability

Collect crash logs, sysdiagnose, device logs, Console output, stackshots, profiles, and network traces with Apple-supported tooling when possible.

Symbolicate crashes with the exact dSYM, build, device architecture, and OS version because iOS mitigations and dyld shared cache differences affect crash interpretation.

Treat platform crashes as reliability evidence until reachability, trust boundary, and security impact are established.

## Source Anchors

- Data Protection classes: https://support.apple.com/guide/security/data-protection-classes-secb010e978a/web
- Profiles and Logs: https://developer.apple.com/feedback-assistant/profiles-and-logs/?platform=ios
- Apple Security Research Device: https://security.apple.com/research-device
- Apple bounty terms: https://security.apple.com/terms-and-conditions/
- Theos rootless notes: https://theos.dev/docs/rootless
