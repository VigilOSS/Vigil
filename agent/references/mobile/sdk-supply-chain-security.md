---
description: "SDK supply chain: BOM identification signals (namespaces, .so names, config assets, iOS symbol prefixes), CVE handling, malicious SDK indicators (SpinOK/Goldoson), SDK domain map and over-collection audit, permission-to-SDK mapping, finding criteria and evidence"
skill: sdk-supply-chain-security
---

# SDK Supply Chain Security Testing Reference

Identification signals, hook targets, traffic heuristics and finding criteria for each step in
`agent/skills/sdk-supply-chain-security/SKILL.md`. Frida hooks and mitmproxy addons are written on
demand against the targets named here; every hook records a backtrace so the call is attributed to
the SDK's code path, not just the API.

Runtime image facts: apktool, jadx, aapt, apksigner and bundletool are installed; MobSF, APKiD,
OWASP dependency-check, retire.js, Trivy and Snyk are not, so run them from the lab host when
needed (`agent/references/mobile/mobile-lab-setup.md` "Vigil Runtime And The Lab Host").

## SDK Bill of Materials

**Android signals.**
- Package namespaces from the smali/dex tree, minus `android.`, `androidx.`,
  `com.google.android.material`. Analytics, crash and attribution namespaces to search for:
  firebase, amplitude, mixpanel, segment, flurry, appsflyer, adjust, branch, kochava, mparticle,
  braze, clevertap, crashlytics, sentry, bugsnag, instabug, datadog, newrelic.
- Native library names under `lib/<abi>/`: `libfb*.so` (Facebook), `libhermes*.so` (React
  Native/Hermes), `libflutter*.so` (Flutter engine), `libsentry*.so`, `lib*unity*.so`, and
  `libfrida-gadget.so` (never legitimate in production).
- Config assets: `assets/google-services.json`, `appsflyer*.properties`, `branch*.json`, and other
  `.json` / `.xml` / `.properties` under `assets/`.
- Version strings: `BuildConfig.VERSION_NAME`, `SDK_VERSION`, `sdkVersion`, `LIBRARY_VERSION`.
- Source builds: `build.gradle(.kts)` `implementation` / `api` / `compileOnly` / `runtimeOnly`.

**iOS signals.**
- `Payload/<App>.app/Frameworks/` (each `.framework` is an SDK) and their `Info.plist`
  (`CFBundleIdentifier`, `CFBundleShortVersionString`).
- `otool -L` on the main binary minus `/usr/lib` and `/System`.
- Static-linked SDKs by `nm` class prefix: `FB` (Facebook), `GA` (Google Analytics), `FIR`
  (Firebase), `AF` (AppsFlyer), `ADJ` (Adjust), `BRN` (Branch), `SEN` (Sentry), `AMP`
  (Amplitude), `MP` (Mixpanel).
- `embedded.mobileprovision` (`security cms -D -i`) entitlements tied to SDKs: `app-group`,
  `aps-environment`, `associated-domains`.
- Source builds: `Podfile.lock`, `Package.resolved`, `Cartfile.resolved`; with source,
  `vigil assess code-dependencies` (`agent/skills/dependency-analysis/SKILL.md`).

Per SDK record name, vendor, version (exact, or estimated from symbols and strings), integration
method (framework, static lib, source, CocoaPods, Gradle, SPM), category (analytics, ads, crash,
auth, payments, social, mapping, push, A/B testing, deep linking), permissions used and endpoints
contacted (the sections below), and the file path or symbol that identified it.

### What Constitutes a Finding

- SDKs embedded but absent from the developer's dependency manifest.
- Frida Gadget, Flipper, Stetho or LeakCanary in a production build (incomplete build stripping).
- SDK versions more than two major releases behind the current one.
- Several competing SDKs for one purpose (three analytics SDKs, two crash reporters) without
  business justification.

## SDK CVE Checking

Query OSV with the package coordinate and ecosystem (`com.squareup.okhttp3:okhttp`, `Maven`), NVD
and the vendor's GitHub security advisories; for JavaScript inside React Native, Cordova or
WebView bundles, check the bundled library versions under `assets/`. Prioritise the high-value
SDKs: OkHttp, Retrofit, Google Play Services, Firebase, React Native, Flutter engine, WebView,
Conscrypt and Sentry on Android; AFNetworking, Alamofire, SDWebImage and WebKit extensions on
iOS. A version match is intel (`vigil assess intel record cve`) until the vulnerable code path is shown reachable through the
app's use of the SDK; a HIGH/CRITICAL with a public exploit reachable that way is a finding, as is a
vulnerable transitive dependency shared by several SDKs once reachable.

Evidence: SDK name and exact version (or range), CVE ID, CVSS, description, and the reachable
path through the app.

## Known Malicious SDK Detection

- **SpinOK class** (data-harvesting ad SDK, 2023–2025 campaigns): namespaces `com.spin`,
  `spin.sdk`, `spinok`; endpoint strings `spin-sdk`, `spinok`, `deneyapps`, `lfrfrn`, `spcliix`;
  behaviour: clipboard reads, SMS reads, installed-package enumeration, sensor harvesting, DGA-like
  domains.
- **Goldoson class** (ad library collection and click fraud, 2023): `goldoson` / `GoldoSon`,
  `com.lottecorp`, `com.cupang`, dynamic code loading; behaviour: installed-app list, Wi-Fi and
  Bluetooth device harvesting, GPS without a user-facing feature, ad clicks in background WebViews.

**Behaviour hook targets (Android):** `ClipboardManager.getPrimaryClip`, `PackageManager`
installed-package queries (`getInstalledPackages`, `getInstalledApplications`),
`ContentResolver.query(Uri, String[], String, String[], String)` on contacts, phone or SMS URIs,
`File.listFiles()` on `/sdcard`, `/storage`, `DCIM`, `Download`.

**Network heuristics:** hostnames of 12+ lowercase letters on `.com/.net/.io/.xyz/.top`
(DGA-like), direct-IP hosts, base64 runs of 50+ characters in bodies, bodies over ~10 KB or JSON
arrays of 20+ items (bulk upload).

### What Constitutes a Finding

- An SDK with documented malicious behaviour (SpinOK, Goldoson or advisory-identified variants).
- An SDK acting outside its stated purpose: an ad SDK reading contacts, analytics enumerating
  installed apps, a crash reporter reading the clipboard.
- DGA-like, direct-IP or known C2 destinations.
- Bulk uploads of device data, contact lists or installed-app inventories.

Evidence: package name, version and classes; the backtrace showing the SDK code path; the network
destination; the advisory or research report for a known campaign.

## SDK Data Exfiltration Audit

Seed the domain list from URL strings in the decoded app, capture a full session through the
shared proxy, and attribute each request to its SDK.

| SDK | Hosts |
|---|---|
| Firebase / Crashlytics | `app-measurement.com`, `firebaseinstallations.googleapis.com`, `fcm.googleapis.com`, `firebase-settings.crashlytics.com`, `settings.crashlytics.com`, `reports.crashlytics.com` |
| Google Analytics / Ads / AdMob | `analytics.google.com`, `googleads.g.doubleclick.net`, `pagead2.googlesyndication.com`, `adservice.google.com`, `admob-sdk-config.googleapis.com` |
| Facebook | `graph.facebook.com`, `an.facebook.com`, `connect.facebook.net` |
| Amplitude | `api.amplitude.com`, `api2.amplitude.com` |
| Mixpanel | `api.mixpanel.com`, `decide.mixpanel.com` |
| Segment | `api.segment.io`, `cdn.segment.com` |
| AppsFlyer | `app.`, `launches.`, `events.`, `conversions.`, `register.appsflyer.com` |
| Adjust | `app.adjust.com`, `app.adjust.io`, `s2s.adjust.com` |
| Branch | `api.branch.io`, `api2.branch.io`, `branch.io`, `bnc.lt` |
| Sentry | `sentry.io`, `o<org>.ingest.sentry.io` |
| Braze | `sdk.iad-01.braze.com`, `rest.iad-01.braze.com` |
| Unity Ads | `unityads.unity3d.com`, `ads-game-configuration.unityads.unity3d.com` |
| Kochava, Singular, Tenjin, Flurry | `kochava.com`, `singular.net`, `tenjin.com`, `data.flurry.com` |

| SDK category | Expected | Excessive (finding) |
|---|---|---|
| Analytics | Screen views, taps, session duration | Contacts, SMS, photos, clipboard, installed apps |
| Crash reporting | Stack trace, OS version, model | Full request bodies, auth tokens, user messages |
| Ads | Impression, click, model, GAID/IDFA | Precise location in an app with no location feature, Wi-Fi SSID list, Bluetooth devices |
| Attribution | Install source, campaign ID, device fingerprint | Browsing history, contacts, SMS content |
| Push | Push token, device ID | Installed apps, battery level, storage capacity |

Other over-collection indicators: PII in event properties unrelated to the event; a full device
fingerprint (model, OS, screen, carrier, timezone, locale) where analytics works without it;
user-generated content (message text, search queries, file names) in events; sensitive screen names
("HIV Test Results", "Bankruptcy Filing", "Pregnancy Tracker"). Opt-out test: opt out in app
settings, capture for five minutes, and compare pre- and post-opt-out payloads.

### What Constitutes a Finding

- Data beyond the SDK's function (an ad SDK sending contacts or precise location the app's
  features do not need, a crash reporter capturing request bodies, auth tokens or session cookies).
- Events carrying sensitive screen names or user content that reveal health, financial or personal
  information.
- Collection undisclosed in the privacy policy or label.
- User-identifiable data (email, phone, name) to third parties without consent for that sharing.
- Transmission continuing, or sensitive fields still present, after opt-out.
- Transmission over HTTP, or SDK-level pinning that prevents the developer auditing its traffic.
- Several SDKs collecting overlapping identifiers without proportionate benefit.

Evidence: SDK name and version, the request (URL, headers, body), the fields sent, the SDK's
stated purpose and why the data exceeds it, the privacy-policy or label statement, and per-session
volume (requests, bytes, distinct data types).

## SDK Permission Scope

**Android.** Declared: `aapt dump permissions` or the decoded manifest. Guarded-API search in
smali, filtered to SDK packages (exclude the app's own namespace): location
(`getLastKnownLocation`, `requestLocationUpdates`, `FusedLocationProviderClient`,
`getCurrentLocation`), camera (`Camera.open`, `CameraManager`, `CameraDevice`), contacts
(`ContactsContract`), phone state (`TelephonyManager`, `getDeviceId`, `getLine1Number`,
`getSimSerialNumber`), storage (`READ_`/`WRITE_`/`MANAGE_EXTERNAL_STORAGE`). Runtime:
`androidx.core.content.ContextCompat.checkSelfPermission` and
`androidx.core.app.ActivityCompat.requestPermissions`, with backtraces.

**iOS.** `Info.plist` `NS*UsageDescription` keys (Camera, PhotoLibrary, LocationWhenInUse,
LocationAlways, Contacts, Microphone, Calendars, Motion, BluetoothAlways, LocalNetwork,
UserTracking); entitlements via `codesign -d --entitlements -`; `nm` on each framework binary for
`CLLocationManager`, `CNContactStore`, `PHPhotoLibrary`, `AVCaptureDevice`, `ATTrackingManager`.
Runtime: `CLLocationManager -requestWhenInUseAuthorization`,
`CNContactStore -requestAccessForEntityType:completionHandler:`,
`AVCaptureDevice +requestAccessForMediaType:completionHandler:`.

Build the matrix permission × app feature × SDK(s) using it × justified. Example rows: fine
location for a map view used by the Maps SDK (justified) and by Adjust (not, unless location-based
attribution is disclosed); `READ_PHONE_STATE` with no visible feature, used by AppsFlyer (finding).

### What Constitutes a Finding

- An SDK using a permission no user-facing feature needs.
- An SDK requesting dangerous permissions at runtime (backtrace shows SDK code as caller).
- A manifest permission present only because an SDK needs it.
- An SDK reusing a permission granted for a core feature for its own purpose (map location used for
  ad targeting).

Evidence: the permission, the SDK caller (backtrace or static hit), the app's stated need (purpose
string or store listing), and why the SDK's use exceeds it.

## Source Anchors

- SpinOK research (Dr.Web, 2023): https://news.drweb.com/show/?i=14705
- Goldoson research (McAfee, 2023): https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-policy-violating-apps/
- Google Play SDK Index: https://play.google.com/sdks
- Apple Privacy Manifest (iOS 17+): https://developer.apple.com/documentation/bundleresources/privacy-manifest-files
- OSV: https://osv.dev/
