---
name: sdk-supply-chain-security
description: Third-party SDK supply chain security testing for mobile apps including SDK inventory, CVE checking, malicious SDK detection, data exfiltration auditing, and permission scope analysis
origin: AI Threat Hunting
---

# SDK Supply Chain Security

## When to Activate

- Assessing the third-party SDK surface of an Android or iOS app for supply chain risk.
- Building an SDK Bill of Materials to understand what code runs inside the app beyond the developer's own code.
- Checking bundled SDK versions against known CVEs and security advisories.
- Detecting known malicious SDKs (SpinOK, Goldoson-class patterns) or behavioral indicators of trojaned SDK distributions.
- Auditing whether analytics, ad, crash, or attribution SDKs collect more data than the app developer intends or discloses.
- Mapping which permissions each SDK accesses and whether those exceed the app's stated needs.

## Scope Gate

Test only authorized app builds on owned devices. SDK traffic analysis requires proxy interception authorization. CVE checking uses public vulnerability databases. Behavioral analysis through Frida hooks requires authorized instrumentation. Do not reverse-engineer SDK licensing or DRM protections beyond what is needed for security assessment.

## Core Workflow

### 1. SDK Bill of Materials

Preflight Android tooling through the generic audited route before APK work:
`aith assess kali exec --technique HEALTH --intent "Android SDK inventory tooling preflight" --probe-kind fingerprint --phase code-ingest --timeout 60 -- which apktool jadx apkid`. Use `HEALTH` for tool inventory — unknown technique tags are rejected before an audit row is written, so coverage filters and command-history queries stay clean.

**Android:** Decode the APK with `apktool`. Identify SDKs through four methods: (1) enumerate package namespaces in smali/dex directories, filtering out Android/AndroidX/Material; (2) identify native libraries (`.so` files) by known naming patterns; (3) check assets for SDK configuration files (`google-services.json`, AppsFlyer/Branch/Adjust configs); (4) decompile with `jadx` and search for `BuildConfig.VERSION_NAME` and `SDK_VERSION` strings. If source is available, parse Gradle dependencies for exact versions.

**iOS:** Unpack the IPA. Identify SDKs through: (1) list embedded frameworks; (2) check `otool -L` for non-system dynamic libraries; (3) search symbols with `nm` for common SDK class prefixes (FB, GA, FIR, AF, ADJ, BRN, SEN, AMP, MP); (4) search binary strings for SDK version identifiers; (5) check framework `Info.plist` files for bundle identifiers and versions. If source is available, parse Podfile.lock, Package.resolved, or Cartfile.resolved.

Use MobSF for automated SDK identification as a triage pass. Use APKiD to identify compilers, packers, and obfuscators.

For each SDK, record: name, vendor, version, integration method, category (analytics/ads/crash/auth/payments/social/mapping/push/deep-linking), and identification evidence.

### 2. CVE Checking

For each SDK with a known version:
- Query OSV API with the package name and version (Maven ecosystem for Android Gradle dependencies).
- Query NVD API by keyword for the SDK name and version.
- Check SDK vendor advisory pages (GitHub Security Advisories for open-source SDKs).

For SDKs without clean version identification:
- Use OWASP Dependency-Check on Gradle project files.
- Use retire.js for JavaScript dependencies in React Native, Cordova, or WebView bundles.
- Use Trivy filesystem scan on the decoded APK/IPA.

Record each CVE match with: SDK name, version, CVE ID, CVSS score, description, and whether the vulnerable code path is reachable through the app's usage of the SDK. CVE matches are intelligence until validated; only record as findings after confirming the vulnerable code path is exercised.

### 3. Malicious SDK Detection

**Known campaigns:** Search decoded app for package namespaces and network endpoints associated with SpinOK, Goldoson, and other documented malicious SDK campaigns (2023-2025). Check for behavioral indicators: clipboard access by non-clipboard SDKs, SMS reading, installed package enumeration, device sensor harvesting beyond app needs, and communication with DGA-like domains.

**Runtime behavioral monitoring:** Deploy Frida hooks to detect suspicious SDK behaviors at runtime: clipboard reads (with backtrace to identify calling SDK), installed package enumeration, contact list access by non-contact SDKs, and file system scanning of external storage. These hooks produce backtraces that pinpoint the SDK code path, not just the API call.

**Network monitoring:** Use the SDK exfiltration monitor mitmproxy script from the reference to flag DGA-like domains, direct IP communication, large base64-encoded payloads, and bulk data uploads.

### 4. Data Exfiltration Audit

Map each SDK to its known network domains from static analysis. Capture a full usage session through the proxy. Use the SDK traffic categorizer mitmproxy script to attribute each request to its originating SDK.

For each SDK, assess whether transmitted data is proportionate to the SDK's stated purpose:
- **Expected:** Analytics SDK sends screen views and session duration. Crash reporter sends stack traces with OS version and device model.
- **Excessive (finding):** Analytics SDK sends contact lists, SMS, or installed apps. Crash reporter sends full request bodies, auth tokens, or user messages. Ad SDK sends precise location when the app has no location feature. Attribution SDK sends browsing history or contact list.

Check whether SDKs continue data collection after the user opts out of the relevant category. Check whether SDKs use certificate pinning that prevents the app developer from auditing their traffic.

### 5. Permission Scope Analysis

**Android:** Extract all permissions from the manifest. For each dangerous permission (FINE_LOCATION, CAMERA, CONTACTS, PHONE_STATE, EXTERNAL_STORAGE), search smali/dex code for the permission-guarded APIs, filtering for calls originating from SDK packages rather than the app's own code. Deploy Frida hooks on `ContextCompat.checkSelfPermission` and `ActivityCompat.requestPermissions` to monitor runtime permission checks with backtraces.

**iOS:** Extract permission purpose strings from Info.plist (each `NS*UsageDescription` key). Deploy Frida hooks on permission request APIs (`CLLocationManager.requestWhenInUseAuthorization`, `CNContactStore.requestAccessForEntityType:`, `AVCaptureDevice.requestAccessForMediaType:`) to capture which SDK code requests each permission at runtime.

Build a permission-to-SDK matrix mapping each permission to the SDK(s) that access it, the app feature that justifies it, and whether each SDK's access is justified by the app's user-facing functionality.

### 6. Evidence Collection

For each finding, capture:
- SDK identity: name, version, package/framework name, specific class names involved.
- Behavioral evidence: Frida hook output with backtrace showing SDK code path.
- Network evidence: full request/response from proxy showing data transmitted.
- Permission evidence: runtime permission check output showing SDK as caller.
- CVE evidence: vulnerability database entry with affected version range and CVSS score.
- App context: privacy policy statement, privacy label declaration, and how it compares to observed behavior.

## Output Checklist

- [ ] SDK BOM complete: every third-party SDK identified with name, version, category, and evidence.
- [ ] CVE check complete: each versioned SDK queried against OSV, NVD, and vendor advisories.
- [ ] Malicious SDK scan complete: known campaign indicators and behavioral anomalies checked.
- [ ] Data exfiltration audit complete: each SDK's traffic assessed for proportionality to stated purpose.
- [ ] Permission scope analysis complete: permission-to-SDK matrix built with justification assessment.
- [ ] Debug/development SDKs flagged if present in production builds.
- [ ] Findings recorded with SDK identity, behavioral evidence, and privacy policy comparison.

## Extended Resources

- `agent/references/mobile/sdk-supply-chain-security.md` - SDK enumeration commands, CVE checking tools, malicious SDK indicators, exfiltration detection scripts, permission analysis hooks, and evidence standards.
- `agent/references/mobile/android-app-security.md` - Android static/dynamic analysis context.
- `agent/references/mobile/ios-app-security.md` - iOS static/dynamic analysis context.
- `agent/references/mobile/mobile-lab-setup.md` - device and proxy setup.
- `agent/references/mobile/masvs-privacy-testing.md` - privacy label and analytics audit overlap.
