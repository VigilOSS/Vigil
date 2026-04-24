---
name: mobile-lab-setup
description: Build and choose Android/iOS mobile security labs with emulators, simulators, owned devices, Mac ARM hosts, Docker, proxies, Frida, device farms, and safe account separation
origin: AI Threat Hunting
---

# Mobile Lab Setup

## When to Activate

- Deciding what Android or iOS devices, emulators, simulators, cloud devices, or host machines are needed.
- Planning a Mac ARM mobile testing lab, Docker usage, proxy setup, Frida deployment, CI automation, or device-farm strategy.
- Answering whether a test requires owned physical hardware, a rooted/jailbroken device, an emulator, a simulator, or a virtual research platform.

## Scope Gate

Use lab workflows only for apps, devices, accounts, networks, and APIs under written authorization. Keep lab Apple IDs, Google accounts, SIMs/eSIMs, payment cards, Wi-Fi, email, password managers, and push projects separate from personal and production identities.

## Baseline Lab

- Mac ARM host with Android Studio, Android SDK platform-tools, Xcode, Burp Suite or mitmproxy, Frida tools, Docker Desktop, `libimobiledevice`, and isolated test accounts.
- Factory-unlocked modern Pixel, preferably Pixel 8-class or newer, for stock Android behavior, unlockable bootloader workflows, current security updates, and hardware-backed features.
- Current non-jailbroken iPhone for real iOS distribution, Keychain, biometrics, APNs, Secure Enclave-adjacent flows, and production app behavior.
- Android Emulator for fast APK triage, rooted AVDs, snapshots, proxy checks, Frida smoke tests, and API-version coverage.
- iOS Simulator for source-built app loops, UI automation, and quick network or storage checks, not for final security conclusions that depend on hardware.
- Burp or mitmproxy on the host, proxy configured through Wi-Fi or emulator networking, and lab CA installed only on test devices.

## Advanced Lab

- Older jailbreakable iPhone or iPad for authorized filesystem and process instrumentation that stock iOS blocks.
- Older root-friendly Pixel or secondary OEM Android device for version/OEM differences and invasive root workflows.
- Linux KVM host for Cuttlefish, high-parallel Android virtual devices, emulator containers, and long fuzzing campaigns.
- Physical device shelf with powered USB hub, labeled cables, dedicated access point, managed VLAN, Appium/WebDriverAgent runners, and scripted cleanup.
- Corellium, Genymotion, Firebase Test Lab, AWS Device Farm, BrowserStack, or similar services only when their access model matches the research question and program rules.

## Device Decision Rules

- Use emulators for fast app behavior loops, storage inspection, proxy setup, rooted Android checks, clean snapshots, and CI regression.
- Use physical Android for bootloader state, firmware, Play Integrity, StrongBox, biometrics, NFC, Bluetooth, UWB, camera, sensors, OEM services, anti-emulator checks, and Pixel-specific behavior.
- Use iOS Simulator for source-built debug builds and UI automation; use physical iPhone/iPad for TestFlight/App Store, Keychain, APNs, biometrics, Secure Enclave-adjacent behavior, modem/SIM, and performance realism.
- Use jailbreakable iOS hardware, Apple Security Research Device, or approved virtual iOS when testing requires broad filesystem, process, or kernel-level visibility.
- Use Docker for repeatable toolchains, MobSF, jadx, apktool, mitmproxy, Appium services, report pipelines, and Linux fuzzing; do not expect Docker Desktop on macOS to replace USB-connected devices or iOS virtualization.

## Output Checklist

- [ ] Authorized targets, devices, accounts, APIs, and interception paths are named.
- [ ] Device matrix states emulator, simulator, stock device, rooted/jailbroken device, and cloud-device coverage.
- [ ] Host architecture, Docker constraints, USB/proxy path, and reset strategy are documented.
- [ ] Test accounts, certificates, captures, and logs use synthetic data.
- [ ] Recovery-to-stock path exists before flashing, rooting, jailbreaking, or installing profiles.

## Extended Resources

- `agent/references/mobile/mobile-lab-setup.md` - baseline, advanced, Mac ARM, Docker, proxy, jailbreak, and device-farm details.
- `agent/references/mobile/android-platform-device-lab.md` - Android/Pixel platform setup and device research boundaries.
- `agent/references/mobile/ios-platform-device-lab.md` - iOS device, Simulator, jailbreak, SRD, and observability boundaries.
