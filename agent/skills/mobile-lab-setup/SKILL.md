---
name: mobile-lab-setup
description: Build and choose Android/iOS mobile security labs with emulators, simulators, owned devices, Mac ARM hosts, Docker, proxies, Frida, device farms, and authorization boundaries
origin: Vigil
---

# Mobile Lab Setup

## When to Activate

- Deciding which devices, emulators, simulators, cloud devices or hosts a mobile test needs, or
  whether it needs owned, rooted or jailbroken hardware.

## Scope Gate

Lab workflows only for apps, devices, accounts, networks and APIs under written authorization.
Keep lab Apple IDs, Google accounts, SIMs/eSIMs, payment cards, Wi-Fi, email, password managers
and push projects separate from personal and production identities.

Baseline and advanced lab inventories, Mac ARM and device-farm detail:
`agent/references/mobile/mobile-lab-setup.md`; platform research boundaries:
`agent/references/mobile/android-platform-device-lab.md`, `ios-platform-device-lab.md`.

## Device decision rules

- **Emulator:** fast behaviour loops, storage inspection, proxy setup, rooted checks, snapshots,
  CI regression.
- **Physical Android:** bootloader state, firmware, Play Integrity, StrongBox, biometrics, NFC,
  Bluetooth, UWB, camera, sensors, OEM services, anti-emulator checks, Pixel-specific behaviour.
- **iOS Simulator** for source-built debug builds and UI automation; **physical iPhone/iPad** for
  TestFlight/App Store, Keychain, APNs, biometrics, Secure Enclave-adjacent behaviour, modem/SIM
  and performance realism.
- **Jailbreakable iOS hardware, an Apple Security Research Device or approved virtual iOS** when
  the test needs filesystem, process or kernel visibility.
- **Docker** for repeatable toolchains (MobSF, jadx, apktool, Appium, Linux fuzzing). Docker
  Desktop on macOS runs a VM, so USB passthrough and iOS virtualization need native host access
  or a Linux KVM host.
- **Interception:** point devices at Vigil's shared mitmproxy (`vigil mitmproxy start`;
  `agent/references/tools/proxy/mitmproxy.md`) so captures are attributed to the engagement; the
  lab CA goes on test devices only.

## Output checklist

- Authorized targets, devices, accounts, APIs and interception path named.
- Device matrix: emulator, simulator, stock, rooted/jailbroken and cloud-device coverage.
- Host architecture, Docker constraints, USB/proxy path and reset strategy documented.
- Synthetic test accounts, certificates, captures and logs.
- A tested recovery-to-stock path before flashing, rooting, jailbreaking or installing profiles.
