---
name: sdk-supply-chain-security
description: Third-party SDK supply chain security testing for mobile apps including SDK inventory, CVE checking, malicious SDK detection, data exfiltration auditing, and permission scope analysis
origin: Vigil
---

# SDK Supply Chain Security

## When to Activate

- An Android or iOS app's third-party SDKs need an inventory, a CVE check, malicious-SDK
  screening, an over-collection audit (this skill owns analytics, ad, crash and attribution SDK
  collection) or a permission-to-SDK mapping.

## Scope Gate

Authorized builds on owned devices; proxy interception and Frida instrumentation only where
authorized. No reverse engineering of SDK licensing/DRM beyond what the assessment needs.

Identification signals, CVE handling, campaign indicators, the SDK domain map and traffic
heuristics, and permission hook targets: `agent/references/mobile/sdk-supply-chain-security.md`;
load it before the BOM pass.

## Method

1. **SDK bill of materials.** Preflight: `vigil assess kali exec --technique HEALTH --intent
   "Android SDK inventory tooling preflight" --probe-kind fingerprint --phase code-ingest
   --timeout 60 -- which apktool jadx apkid`. Android: package namespaces in smali/dex (minus
   Android/AndroidX/Material), `.so` naming patterns, SDK config assets (`google-services.json`,
   AppsFlyer/Branch/Adjust configs), `BuildConfig.VERSION_NAME`/`SDK_VERSION` strings. iOS:
   embedded frameworks, `otool -L`, `nm` class prefixes (FB, GA, FIR, AF, ADJ, BRN, SEN, AMP, MP),
   version strings, framework `Info.plist`. With source, parse the lockfiles
   (`agent/skills/dependency-analysis/SKILL.md`, `vigil assess code-dependencies`). MobSF and
   APKiD as triage. Record name, vendor, version, integration, category and evidence per SDK; flag
   debug/development SDKs in production builds.
2. **CVEs:** OSV/NVD/vendor advisories for each versioned SDK. A match is intel
   (`vigil assess intel record cve`) until the vulnerable code path is shown to be exercised by the
   app; only then a finding.
3. **Malicious SDKs:** namespaces and endpoints of documented campaigns (SpinOK, Goldoson class);
   behaviour indicators — clipboard reads by non-clipboard SDKs, SMS reads, installed-package
   enumeration, sensor harvesting, DGA-like or direct-IP endpoints, large base64 uploads. Frida
   hooks with backtraces attribute the call to the SDK's code path, not just the API.
4. **Data exfiltration:** attribute each request to its SDK and judge proportionality. Expected:
   analytics screen views and session length; crash stack traces with OS and model. Excessive:
   contacts, SMS or installed apps from analytics; request bodies, auth tokens or messages in crash
   reports; precise location from an ad SDK in an app without location features. Also check
   collection after opt-out.
5. **Permissions:** map each dangerous permission (Android manifest; iOS `NS*UsageDescription`)
   to the SDK code that uses it (static search filtered to SDK packages, runtime hooks with
   backtraces) and the user-facing feature that justifies it.

## Evidence

SDK identity (name, version, classes), hook output with backtrace, the request carrying the data,
permission-check output naming the SDK caller, the CVE entry, and the privacy policy or label text
compared with observed behaviour. Severity: `agent/references/finding-fp-and-severity-gate.md`;
format: `agent/references/runtime-guides/web-finding-recording.md`.
