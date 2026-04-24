# Android Platform And Device Lab Reference

## Authorization Gate

Confirm owned hardware or explicit client authorization, lab network isolation, backup/wipe acceptance, firmware provenance, root/bootloader plan, recovery-to-stock plan, and disclosure channel before advising invasive device work.

## Device And Firmware Basics

Pixel-class devices are useful research targets because Google publishes factory images, full OTA images, security bulletins, and long update windows for recent devices.

Factory flashing and bootloader unlocking can erase data, change security posture, trip app integrity checks, and constrain downgrade workflows when rollback indexes advance.

Use factory images for complete restoration or partition extraction; use full OTA images when stock restoration without bootloader unlocking is sufficient.

Rooting should stay lab-only because Magisk-style workflows require an unlocked bootloader and a boot/init_boot/recovery image that matches the exact device build.

## Platform Security Map

- Verified Boot establishes a chain of trust from hardware root through boot and verified partitions.
- Rollback protection blocks returning to older vulnerable firmware when rollback indexes have advanced.
- Android's app sandbox, Linux UID isolation, SELinux, scoped storage, runtime permissions, and package visibility define normal app boundaries.
- Binder and AIDL carry framework, app, HAL, and vendor IPC across process boundaries.
- Treble, VINTF, HALs, vendor services, and GKI separate framework code from device/vendor implementation details.
- StrongBox, Titan M2-class hardware, Trusty, and hardware-backed Keystore behavior require real devices for meaningful validation.

## Emulator, Cuttlefish, And Real Device Split

Use Android Emulator for app triage, rooted AVDs, snapshots, proxy checks, Frida smoke tests, and API-version compatibility.

Use Cuttlefish for AOSP framework behavior, repeatable virtual devices, multi-tenancy, and high-fidelity Android framework testing on Linux KVM hosts.

Use real Pixels for bootloader state, AVB, rollback, sensors, radios, HALs, vendor drivers, StrongBox, Play Integrity, OEM services, thermal behavior, and kernel/device-driver observations.

Use a native Linux KVM host for Cuttlefish and direct host/device workflows for USB-heavy testing because Docker Desktop on macOS runs containers inside a VM without native KVM or straightforward USB passthrough.

## Research Target Selection

Start with app and framework behavior before HAL, kernel, or firmware work because app-level defects are easier to reproduce, safer to disclose, and closer to most engagements.

Study Binder/AIDL, content providers, permission checks, and native services before baseband or RF topics because they expose meaningful device boundaries without radio exploitation.

Treat modem/baseband, boot ROM, secure element, and carrier-facing research as specialist domains that need separate authorization, safety planning, and disclosure handling.

## Source Anchors

- Bootloader lock/unlock: https://source.android.com/docs/core/architecture/bootloader/locking_unlocking
- Android Verified Boot: https://source.android.com/docs/security/features/verifiedboot
- Pixel factory images: https://developers.google.com/android/images
- Pixel full OTA images: https://developers.google.com/android/ota
- Pixel security bulletins: https://source.android.com/docs/security/bulletin/pixel
- Cuttlefish overview: https://source.android.com/docs/devices/cuttlefish
- Cuttlefish get started: https://source.android.com/docs/devices/cuttlefish/get-started
- Binder overview: https://source.android.com/docs/core/architecture/ipc/binder-overview
- AIDL fuzzing: https://source.android.com/docs/core/architecture/aidl/aidl-fuzzing
- AIDL HALs: https://source.android.com/docs/core/architecture/aidl/aidl-hals
- Pixel update policy: https://support.google.com/pixelphone/answer/4457705
- Pixel 8 Pro specs: https://store.google.com/us/product/pixel_8_pro_specs
- Android MTE: https://developer.android.com/ndk/guides/arm-mte
- Magisk install docs: https://topjohnwu.github.io/Magisk/install.html
