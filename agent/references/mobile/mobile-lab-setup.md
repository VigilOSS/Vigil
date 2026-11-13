---
description: Mac ARM, emulators, simulators, owned devices, Docker, proxies, Frida, device farms, reset/data hygiene
skill: mobile-lab-setup
---

# Mobile Lab Setup Reference

## Baseline Lab

- Mac ARM host: Android Studio, Android SDK platform-tools, Xcode, Burp Suite or mitmproxy, Frida tools, Docker Desktop, `libimobiledevice`, Appium optional, and isolated test accounts.
- Android device: factory-unlocked current Pixel for current OS behavior, bootloader workflows, published images, and hardware-backed features.
- iOS device: current non-jailbroken iPhone for App Store/TestFlight, Keychain, biometrics, APNs, Secure Enclave-adjacent flows, and production behavior.
- Virtual devices: Android Emulator for app loops and API coverage; iOS Simulator for source-built app loops and UI automation.
- Proxy path: host proxy over Wi-Fi or emulator networking, lab CA installed only on test devices, and pinned apps handled through authorized test builds or lab instrumentation.

## Advanced Lab

- Older jailbreakable iPhone or iPad for authorized iOS filesystem, process, and Frida server work.
- Older root-friendly Pixel or secondary OEM Android device for root workflows and OEM comparison.
- Linux KVM host for Cuttlefish, Android emulator containers, high-parallel automation, and fuzzing throughput.
- Device shelf with powered USB hub, labeled cables, dedicated access point, managed VLAN, Appium/WebDriverAgent runners, and scripted reset.
- Device farms for compatibility and UI coverage; for security conclusions, confirm the provider grants rooted/jailbroken access, isolated network tenancy, and API-level tool availability.

## What Requires Physical Devices

- Android: bootloader, firmware, AVB, rollback, StrongBox, Play Integrity, biometrics, NFC, Bluetooth, UWB, camera, sensors, OEM services, radios, thermal behavior, and anti-emulator checks.
- iOS: App Store encrypted apps, TestFlight distribution, APNs, Keychain access groups, Face ID/Touch ID, Secure Enclave-adjacent flows, Apple Pay-style flows, modem/SIM, camera/NFC, and production performance.
- Both: MDM enrollment, captive portals, carrier provisioning, Bluetooth peripherals, real payment test rails, and hardware-specific regressions.

## Mac ARM And Docker

Apple Silicon works well for Android Studio, arm64 Android emulator images, Xcode, iOS Simulator, `adb`, `fastboot`, Frida clients, proxy tools, and browser-based flashing.

Prefer arm64 containers and native builds on Mac ARM; use `buildx`/QEMU for compatibility only when throughput is not critical.

Docker is useful for repeatable tooling such as MobSF, jadx, apktool, mitmproxy, Appium services, report pipelines, Linux fuzzing, and CI replay.

Docker Desktop on macOS runs Linux containers inside a VM, so USB passthrough and KVM-backed Android virtualization are not equivalent to a Linux host.

## Vigil Runtime And The Lab Host

The Kali runtime carries the Android static toolchain: apktool, jadx, aapt, apksigner, adb, apkeep
and bundletool (confirm with `vigil assess kali exec --technique HEALTH --intent "mobile tooling
inventory" --probe-kind fingerprint --phase code-ingest --timeout 60 -- which apktool jadx aapt
apksigner adb apkeep bundletool`). Frida, objection, MobSF, APKiD, Xcode/`simctl`,
`libimobiledevice` and other iOS tooling are not in the image. Run them, and anything that needs a
USB-attached device (Docker Desktop on macOS has no native USB passthrough), on the lab host
through host-exec so the run is audited:
`vigil assess host-exec --tool <tool> --intent "<why>" --technique <technique> --phase <phase> -- <command>`
(`vigil assess contract host-exec`; full output lands under `scans/host-exec/`). App API traffic replays through `vigil assess kali exec`. Files the runtime
reads or writes live under `/engagements/$ENGAGEMENT_KEY/...` (`agent/shared-constraints.md` §11).

## Reset And Data Hygiene

Use emulator snapshots, Cuttlefish powerwash, `simctl erase`, device-farm cleanup, scripted app uninstall, and account teardown to avoid state drift.

Use synthetic PII, test payment instruments, lab push projects, dedicated email/SMS inboxes, and separated Apple/Google accounts.

Export proxy logs, device logs, crash reports, and screenshots into engagement storage.

## Source Anchors

- Android Cuttlefish multi-tenancy: https://source.android.com/docs/devices/cuttlefish/multi-tenancy
- Xcode Developer Mode: https://developer.apple.com/documentation/xcode/enabling-developer-mode-on-a-device
- Frida Gadget: https://frida.re/docs/gadget/
- Docker Desktop USB/IP: https://docs.docker.com/desktop/features/usbip/
- Corellium devices: https://support.corellium.com/devices/ios
