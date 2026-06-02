---
name: masvs-privacy-testing
description: OWASP MASVS-PRIVACY testing for identifier auditing, tracking transparency (ATT/Privacy Sandbox), data deletion verification, privacy label compliance, and analytics/telemetry over-collection assessment
origin: Vigil
---

# MASVS-PRIVACY Testing

## When to Activate

- Testing whether an app collects, stores, or transmits device identifiers (IDFA, GAID, IMEI, MAC, ANDROID_ID) in ways that violate privacy policies or regulations.
- Verifying App Tracking Transparency (iOS) or Privacy Sandbox (Android) compliance: consent state, fingerprinting workarounds, server-side attribution bypass.
- Validating that account deletion removes all user data from local storage, Keychain/Keystore, backups, and server-side state.
- Comparing App Store Privacy Labels (iOS) or Data Safety declarations (Android) against actual app behavior observed through traffic analysis.
- Auditing analytics SDKs, ad SDKs, and crash reporters for over-collection of PII, location, user content, or sensitive screen names.

## Scope Gate

Test only apps, accounts, devices, APIs, and analytics endpoints under written authorization. Use synthetic test accounts and test data. Avoid capturing real user traffic or PII from production analytics pipelines. Coordinate with app developers when testing server-side deletion to avoid disrupting production data.

## Core Workflow

### 1. Identifier Audit

Deploy Frida hooks on the target device to intercept identifier access APIs. On iOS, hook `ASIdentifierManager` (IDFA), `UIDevice.identifierForVendor` (IDFV), and fingerprinting signals (screen, locale, timezone, model, fonts, sensors). On Android, hook `AdvertisingIdClient.getAdvertisingIdInfo` (GAID), `TelephonyManager.getDeviceId`/`getImei` (IMEI), `Settings.Secure.getString` (ANDROID_ID), and `NetworkInterface.getHardwareAddress` (MAC).

Run mitmproxy with the identifier filter script from the reference to flag outbound requests containing UUID patterns (IDFA/GAID format), IMEI patterns, MAC address patterns, and ANDROID_ID hex strings.

Cross-reference: each identifier access must have a corresponding consent gate or legitimate purpose. Any identifier transmitted to a third-party domain without user awareness is a candidate finding.

### 2. Tracking Transparency Testing

**iOS ATT:** Hook `ATTrackingManager.trackingAuthorizationStatus` and `requestTrackingAuthorizationWithCompletionHandler:`. Fresh-install the app, deny ATT when prompted (or do not trigger the prompt), then capture all traffic for a full usage session. Analyze captured traffic for:
- IDFA or IDFV sent to third-party tracking domains before ATT is `.authorized`.
- Probabilistic fingerprints (four or more device signals in a single payload) sent to attribution/analytics domains.
- Hidden WebView creation (zero-size or 1x1 frames) that serves as a fingerprinting surface.
- Server-side attribution attempts that send raw device signals to first-party domains for server-side joining.

**Android Privacy Sandbox:** Hook `TopicsManager.getTopics`, `MeasurementManager.registerSource`/`registerTrigger`, and check whether the app still uses GAID directly alongside Privacy Sandbox APIs. Verify that Attribution Reporting registration URIs do not contain PII or precise identifiers in query parameters. Check whether ad SDKs have migrated to SDK Runtime or still run in the main app process.

### 3. Data Deletion Verification

Before deletion: snapshot all local storage (SharedPreferences/UserDefaults, databases, files, Keychain/Keystore entries, caches). Execute account deletion through the app's UI. After deletion:
- Re-scan local storage for residual PII, tokens, session data, and cached content.
- Check Keychain/Keystore for orphaned entries.
- Create a backup and search for pre-deletion data.
- Attempt server-side access with cached auth tokens.
- Attempt re-registration with the same email and check if old data reappears.

### 4. Privacy Label Audit

Collect the declared Privacy Labels (iOS) or Data Safety section (Android) from the store listing. Run a comprehensive traffic capture during a full app usage session covering all major features. Use the privacy label audit mitmproxy script from the reference to categorize observed data types (location, contact info, identifiers, usage data, financial, health, browsing history, search history, user content, diagnostics, purchases). Inspect local storage for additional data types not visible in network traffic.

Build a comparison matrix: declared data types versus observed data types. Any data type observed but not declared is a candidate finding.

### 5. Analytics/Telemetry Audit

Identify all analytics, crash reporting, and ad SDKs through static analysis (jadx/strings/framework inspection). Map each SDK to its known network domains. Capture traffic and categorize by SDK using the analytics audit mitmproxy script from the reference.

For each SDK, assess whether its data collection is proportionate:
- Does the analytics payload contain PII (email, phone, name) in standard events?
- Does the crash reporter capture auth tokens, request bodies, or session cookies?
- Do ad SDKs collect precise location when the app has no location features?
- Do analytics events capture sensitive screen names or user-generated content?
- Are multiple analytics SDKs collecting redundant device identifiers?

### 6. Evidence Capture

For each finding, capture:
- Frida hook output showing the API call, backtrace, and return value.
- Network request/response showing the data transmitted (via Burp or mitmproxy).
- Destination domain and its ownership/purpose.
- Consent state at time of data collection (ATT status, opt-out flag, Privacy Sandbox state).
- Privacy Label/Data Safety declaration text for comparison.
- OWASP MASVS-PRIVACY control mapping.

## Output Checklist

- [ ] Identifier inventory complete: all accessed identifiers listed with purpose and consent gate status.
- [ ] Tracking transparency verified: ATT/Privacy Sandbox compliance tested with consent denied.
- [ ] Data deletion verified: local storage, Keychain/Keystore, backups, and server-side state checked post-deletion.
- [ ] Privacy label comparison complete: declared versus observed data types matrix built.
- [ ] Analytics SDK audit complete: each SDK's data collection assessed for proportionality.
- [ ] Findings mapped to OWASP MASVS-PRIVACY controls with reproducible evidence.

## Extended Resources

- `agent/references/mobile/masvs-privacy-testing.md` - identifier hooks, ATT testing, Privacy Sandbox, deletion verification, privacy label audit scripts, analytics audit scripts, and evidence standards.
- `agent/references/mobile/android-app-security.md` - Android storage, crypto, network, and IPC context.
- `agent/references/mobile/ios-app-security.md` - iOS Keychain, storage, ATS, and link context.
- `agent/references/mobile/mobile-lab-setup.md` - device, proxy, and Frida setup.
