---
description: Pixel/reference-device setup, bootloader/AVB/rollback and root caveats, MTE, Cuttlefish vs emulator vs real device, Binder/AIDL/SELinux/HAL boundaries, AIDL fuzzing, specialist-domain limits
skill: mobile-lab-setup
---

# Android Platform And Device Lab Reference

## Authorization Gate

Confirm owned hardware or explicit client authorization, lab network isolation, backup/wipe acceptance, firmware provenance, root/bootloader plan, recovery-to-stock plan, and disclosure channel before advising invasive device work.

## Device And Firmware Basics

Pixel-class devices are the reference research targets because Google publishes factory images, full OTA images, Pixel security bulletins and long update windows.

Factory flashing and bootloader unlocking erase data, change security posture, trip app integrity checks, and constrain downgrade once rollback indexes advance: document the recovery plan first. Use factory images for complete restoration or partition extraction; full OTA images when stock restoration without unlocking is enough.

Rooting stays lab-only: Magisk-style workflows need an unlocked bootloader and a boot/init_boot/recovery image matching the exact device build.

## Platform Security Notes

- Boundaries to place a finding against: Verified Boot and rollback protection; app sandbox (Linux UID), SELinux, scoped storage, runtime permissions and package visibility; Binder/AIDL IPC across framework, app, HAL and vendor processes; Treble, VINTF, HALs and GKI separating framework from vendor code.
- StrongBox, Titan M2-class hardware, Trusty and hardware-backed Keystore behaviour need real devices for meaningful validation.
- MTE on Pixel 8+ (Tensor G3) and Pixel 9+ (Tensor G4) gives hardware heap tagging for use-after-free and overflow detection, a reason to choose those devices for native work; per-app enablement and coverage limits are in `agent/references/mobile/mobile-fuzzing.md` "Sanitizers And Platforms".
- 16KB page sizes (Android 15+): native-library alignment and the `llvm-objdump` check are in `agent/references/mobile/android-app-security.md` "API-Level Coverage".

## Emulator, Cuttlefish, And Real Device Split

- Android Emulator: app triage, rooted AVDs, snapshots, proxy checks, Frida smoke tests, API-version compatibility.
- Cuttlefish: AOSP framework behaviour, repeatable virtual devices, multi-tenancy, high-fidelity framework testing; needs a native Linux KVM host (Docker Desktop on macOS has no native KVM or straightforward USB passthrough).
- Real Pixels: bootloader state, AVB, rollback, sensors, radios, HALs, vendor drivers, StrongBox, Play Integrity, OEM services, thermal behaviour, kernel/device-driver observations.

## Research Target Selection

Start with app and framework behaviour before HAL, kernel or firmware work: app-level defects are easier to reproduce, safer to disclose and closer to most engagements.

Study Binder/AIDL, content providers, permission checks and native services before baseband or RF topics. For AIDL service fuzzing, the AOSP `service_fuzzer` framework generates libFuzzer harnesses from interface definitions; use it in owned AOSP/Cuttlefish builds.

Treat modem/baseband, boot ROM, secure element and carrier-facing research as specialist domains needing separate authorization, safety planning and disclosure handling.

## Source Anchors

- Pixel security bulletins: https://source.android.com/docs/security/bulletin/pixel
- AIDL fuzzing: https://source.android.com/docs/core/architecture/aidl/aidl-fuzzing
- Android MTE: https://developer.android.com/ndk/guides/arm-mte
- Android MTE system testing: https://source.android.com/docs/security/test/memory-safety/arm-mte
- Google Android Offensive Security — Binder fuzzing: https://androidoffsec.withgoogle.com/posts/binder-fuzzing/
