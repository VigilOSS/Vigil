---
description: "MASVS-PRIVACY: identifier and fingerprinting hook targets (IDFA/IDFV/GAID/IMEI/MAC/ANDROID_ID), ATT state and pre-consent signals, Privacy Sandbox APIs, deletion residue locations, privacy-label category mapping, finding criteria and evidence standards"
skill: masvs-privacy-testing
---

# MASVS-PRIVACY Testing Reference

Hook targets, traffic signals and finding criteria for each check in
`agent/skills/masvs-privacy-testing/SKILL.md`. Frida hooks and mitmproxy addons are written on
demand against the targets named here; hook output needs a backtrace so the caller (app code or a
named SDK) is attributable. Analytics, crash and ad SDK over-collection, and the per-SDK domain map,
live in `agent/references/mobile/sdk-supply-chain-security.md` "SDK Data Exfiltration Audit".

## Identifier Audit

**iOS hook targets:** `ASIdentifierManager +sharedManager` and `-advertisingIdentifier` (IDFA,
read `UUIDString` on return); `UIDevice -identifierForVendor` (IDFV); custom persistent identifiers
written to the Keychain before ATT (`objection … ios keychain dump`, look for UUID-shaped values).

**Android hook targets:** `com.google.android.gms.ads.identifier.AdvertisingIdClient.getAdvertisingIdInfo(Context)`
(GAID via `getId()`, opt-out via `isLimitAdTrackingEnabled()`); `TelephonyManager.getDeviceId()`
and `getImei()`; `Settings$Secure.getString(resolver, "android_id")`;
`java.net.NetworkInterface.getHardwareAddress()` (MAC).

**Fingerprinting signals:** iOS `UIScreen -bounds`, `NSLocale +currentLocale`,
`NSTimeZone +localTimeZone`, `UIDevice -model`, `UIFont +familyNames` (font enumeration). Android
`Build.MODEL` / `MANUFACTURER` / `FINGERPRINT`, `WebSettings.getUserAgentString()`,
`SensorManager.getSensorList()`, installed-package queries.

**Traffic patterns:** IDFA/GAID are UUIDs, IMEI 15 digits, MAC `xx:xx:xx:xx:xx:xx`, ANDROID_ID
16 hex. Pattern hits over-match (any UUID, any 15-digit number); a candidate is the hooked value
itself appearing in the request.

### What Constitutes a Finding

- IDFA/GAID accessed without ATT consent (iOS) or ignoring the ad-tracking opt-out (Android).
- Hardware identifiers (IMEI, MAC, serial) read for analytics, attribution or cross-app tracking.
- Several device-identifying signals (screen, locale, timezone, model, fonts, sensors) sent in one
  analytics payload beyond what core functionality needs.
- Identifiers in plaintext in traffic, local storage or logs.

### Evidence Standard

The hook output with backtrace, the request carrying the identifier, and the destination domain,
with the value marked in the proxy capture.

## App Tracking Transparency (iOS)

ATT (iOS 14.5+) gates tracking across other companies' apps and sites. Consent state:
`ATTrackingManager +trackingAuthorizationStatus` (0 `notDetermined`, 1 `restricted`, 2 `denied`,
3 `authorized`) and `+requestTrackingAuthorizationWithCompletionHandler:`. Pre-consent run: fresh
install, proxy capturing before first launch, the prompt denied or never triggered, core features
used for a few minutes; repeat with ATT granted and diff the two captures. Tracking domains are
the sdk-supply-chain reference's domain map; tracking parameter names to flag: `idfa`, `idfv`, `att_status`, `advertising_id`, `gaid`, `device_id`,
`fingerprint`, `device_fingerprint`.

Workarounds after denial:
- **Probabilistic fingerprint:** a payload to an attribution or analytics domain carrying four or
  more device signals (model, screen, locale, timezone, carrier).
- **Hidden WebView fingerprinting:** `WKWebView -initWithFrame:configuration:` with a zero or 1x1
  frame, then JavaScript drawing whose hash goes to analytics; DeviceCheck or other fingerprinting
  services receiving signals after denial.
- **Server-side attribution:** first-party POSTs carrying install timestamp, IP, user agent, app
  version and model that the server joins to campaign IDs. SKAdNetwork and AdServices without ATT
  are legitimate; note their data granularity.

### What Constitutes a Finding

- IDFA sent to any third-party domain before the status is `authorized`.
- A probabilistic fingerprint (four or more device signals in one payload) sent to a tracking
  domain after denial.
- Hidden WebViews or JavaScript run for fingerprinting after denial.
- A Privacy Nutrition Label claiming "Data Not Collected" for tracking while pre-consent traffic
  carries tracking payloads: record the label text, the request URL and the payload fields.

### Evidence Standard

The full request/response annotated with the ATT state at capture time, hook output showing
`denied` or `notDetermined`, and the timeline of denial versus tracking request.

## Android Privacy Sandbox

Hook targets: `android.adservices.topics.TopicsManager.getTopics` (Android 13+ with Privacy
Sandbox enabled; log request and returned topics), and
`android.adservices.measurement.MeasurementManager.registerSource` / `registerTrigger` (the
registration URI and input event). SDK Runtime (Android 14+): `<uses-sdk-library>` in the manifest,
`SandboxedSdkProvider` / `SdkSandboxManager` in code, and on device `ps -A | grep sdk_sandbox` and
`dumpsys activity services | grep SdkSandbox`.

Questions: GAID still used alongside or instead of the Sandbox APIs; attribution registrations
carrying extra query parameters or custom headers beyond the API design; ad SDKs still in the app
process with full data access; Topics responses reaching unauthorized callers.

### What Constitutes a Finding

- GAID read and sent to third parties while Privacy Sandbox APIs are available and the device has
  GAID deprecation flags enabled.
- Source/trigger registration URIs carrying PII, user identifiers or precise location.
- SDK Runtime available but ad SDKs in the main process reading contacts, location or other
  protected data.

## Data Deletion Testing

Account deletion (GDPR Art. 17, App Store and Google Play account-deletion requirements) must remove
local, Keychain/Keystore, backup, cloud-sync and server-side state. Snapshot before and after:
Android `/data/data/<pkg>/` file list, `shared_prefs/*.xml`, `databases/*.db` (table list and row
counts), `AndroidKeyStore` aliases (`KeyStore.getInstance("AndroidKeyStore").aliases()`); iOS the
data container's Documents, Library and tmp (path via `objection … env`), app group containers,
cookies and WebView storage, iCloud-synced data, and a Keychain dump. After deletion, log in again
and check whether prior state comes back.
Record the deletion flow, confirmation steps and any grace-period wording. Backups: `adb backup`
(only for debuggable or targetSdk ≤ 30 apps) unpacked with android-backup-extractor (`abe.jar
unpack`), or an unencrypted Finder backup read with libimobiledevice or iMazing. Server side:
login with the deleted credentials, a cached token against user endpoints, the deleted user's
profile from another account's view, and re-registration with the same email.

### What Constitutes a Finding

- Auth, session or refresh tokens left in the Keychain/Keystore.
- PII left in local databases, SharedPreferences or UserDefaults.
- Cached user content (photos, messages, documents) left in the container.
- The API still serving the profile to a cached token.
- Re-registration with the same email restoring deleted data.
- A backup made after deletion still holding pre-deletion PII.

### Evidence Standard

Timestamped before/after file listings, database and Keychain/Keystore dumps, the deletion request
time, the post-deletion capture time, and the specific fields that survived.

## Privacy Label vs Behavior Audit

Declared: iOS App Privacy label (each type, purpose, linked-to-identity) in Apple's categories
(Contact Info, Health & Fitness, Financial Info, Location, Sensitive Info, Contacts, User Content,
Browsing History, Search History, Identifiers, Purchases, Usage Data, Diagnostics, Other Data);
Android Data Safety (type, purpose, sharing disclosure, deletion availability). Observed: a full
session exercising registration, profile edit, messaging, media upload, search, settings, payment,
sharing and export/import, plus local database schemas.

Payload keys (substring matches on the lowercased body and URL) that map to categories:

- location: `latitude`, `longitude`, `lat`, `lng`, `geo`, `location`, `place_id`, `coordinates`
- contact_info: `email`, `phone`, `address`, `first_name`, `last_name`, `full_name`, `contact`
- identifiers: `idfa`, `idfv`, `gaid`, `advertising_id`, `device_id`, `android_id`, `imei`, `serial`
- usage_data: `screen_view`, `page_view`, `event`, `action`, `session_id`, `app_version`,
  `os_version`, `screen_name`
- financial: `card_number`, `cvv`, `expir`, `bank`, `payment`, `billing`, `transaction`
- health_fitness: `heart_rate`, `steps`, `calories`, `weight`, `height`, `health`, `workout`, `sleep`
- browsing_history: `referrer`, `visited_url`, `browsing`, `history`
- search_history: `search_query`, `search_term`, `query`, `keyword`
- user_content: `message`, `comment`, `post`, `photo`, `video`, `file_name`
- diagnostics: `crash`, `error`, `stack_trace`, `exception`, `diagnostic`, `performance`
- purchases: `purchase`, `order`, `product_id`, `sku`, `receipt`, `subscription`

Build the matrix: declared type; observed in traffic (with destination); observed in storage; gap
(collected but undeclared, or declared but unobserved).

### What Constitutes a Finding

- A collected type (location, contacts, identifiers, health) absent from the label or Data Safety.
- Third-party sharing (analytics, ad networks) not disclosed in "shared with third parties".
- "Data Not Collected" for a category that traffic shows collected.
- "Data Not Linked to You" for identifiers sent alongside account tokens.

### Evidence Standard

The exact declaration text, the request showing undeclared collection (timestamp, destination,
payload), and the declared-versus-observed table.

## Analytics and Telemetry Audit

Owned by `agent/references/mobile/sdk-supply-chain-security.md` "SDK Data Exfiltration Audit"
(SDK identification, domain map, over-collection indicators, opt-out test, finding criteria).

## Source Anchors

- OWASP MASTG privacy tests: https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/ and https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/
- Apple required-reason APIs (iOS 17+): https://developer.apple.com/documentation/bundleresources/privacy-manifest-files/describing-use-of-required-reason-api
- Google Play Data Safety: https://support.google.com/googleplay/android-developer/answer/10787469
- Google Play account deletion requirement: https://support.google.com/googleplay/android-developer/answer/13327111
- Android Attribution Reporting: https://developer.android.com/design-for-safety/privacy-sandbox/attribution
