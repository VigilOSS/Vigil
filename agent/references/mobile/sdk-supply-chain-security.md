---
description: "SDK supply chain: BOM enumeration, CVE checking, malicious SDK detection (SpinOK/Goldoson), data exfiltration audit, permission scope analysis"
skill: sdk-supply-chain-security
---

# SDK Supply Chain Security Testing Reference

Third-party SDKs embedded in mobile apps create supply chain risk. This reference provides concrete test procedures for SDK inventory, CVE checking, malicious SDK detection, data exfiltration auditing, and permission scope analysis.

## SDK Bill of Materials

### What to Test

Enumerate every third-party SDK bundled in the app. The SDK inventory is the foundation for CVE checking, behavioral analysis, and data flow auditing.

### Android SDK Enumeration

**From APK/AAB (binary-level):**

```bash
# Decode APK
apktool d target.apk -o target_decoded

# Method 1: Identify SDKs by package namespaces in smali/dex
find target_decoded/smali* -type d -maxdepth 4 | \
    sed 's|target_decoded/smali[^/]*/||' | \
    sed 's|/|.|g' | \
    sort -u | \
    grep -vE "^(android\.|androidx\.|com\.google\.android\.material)" | \
    head -100

# Method 2: Identify SDKs from native libraries
ls -la target_decoded/lib/*/
# Common patterns:
# libfb*.so          — Facebook SDK
# libhermes*.so      — React Native / Hermes
# libflutter*.so     — Flutter engine
# libsentry*.so      — Sentry crash reporting
# libfrida-gadget.so — Frida (should not be in production)
# lib*unity*.so      — Unity game engine

# Method 3: Check assets for SDK configuration files
find target_decoded/assets -type f -name "*.json" -o -name "*.xml" -o -name "*.properties" | head -50
cat target_decoded/assets/google-services.json 2>/dev/null
cat target_decoded/assets/appsflyer*.properties 2>/dev/null
cat target_decoded/assets/branch*.json 2>/dev/null

# Method 4: Use jadx for detailed SDK identification
jadx -d decompiled target.apk
grep -rn "BuildConfig.VERSION_NAME\|SDK_VERSION\|sdkVersion\|LIBRARY_VERSION" decompiled/ | head -50
```

**From Gradle dependencies (source-level):**

```bash
# If source or build files are available
cat app/build.gradle app/build.gradle.kts 2>/dev/null | \
    grep -E "implementation|api|compileOnly|runtimeOnly" | \
    grep -v "//\|^\s*$" | \
    sed 's/.*["'"'"']\(.*\)["'"'"'].*/\1/' | \
    sort -u
```

**Automated SDK fingerprinting:**

```bash
# MobSF provides SDK identification
# Upload APK to local MobSF instance
curl -F "file=@target.apk" http://localhost:8000/api/v1/upload \
    -H "Authorization: <api_key>"
# Then analyze and check the "Libraries" section

# APKiD for compiler/packer/obfuscator identification
apkid target.apk
```

### iOS SDK Enumeration

**From IPA (binary-level):**

```bash
# Extract IPA
unzip -o target.ipa -d target_extracted

# Method 1: List embedded frameworks
ls target_extracted/Payload/*.app/Frameworks/
# Each .framework directory is a third-party SDK

# Method 2: Check linked dynamic libraries
otool -L target_extracted/Payload/*.app/<binary_name> | grep -v "/usr/lib\|/System"

# Method 3: Identify static libraries from symbols
nm target_extracted/Payload/*.app/<binary_name> 2>/dev/null | \
    grep -oE "[A-Z][A-Za-z]+\." | sort -u | head -50
# Common prefixes:
# FB*      — Facebook SDK
# GA*      — Google Analytics
# FIR*     — Firebase
# AF*      — AppsFlyer
# ADJ*     — Adjust
# BRN*     — Branch
# SEN*     — Sentry
# AMP*     — Amplitude
# MP*      — Mixpanel

# Method 4: Search for SDK version strings
strings target_extracted/Payload/*.app/<binary_name> | \
    grep -iE "sdk.*version\|library.*version\|^[0-9]+\.[0-9]+\.[0-9]+" | head -50

# Method 5: Check for Swift package or CocoaPods metadata
cat target_extracted/Payload/*.app/Frameworks/*/Info.plist 2>/dev/null | \
    grep -A1 "CFBundleIdentifier\|CFBundleShortVersionString"

# Method 6: Check embedded mobileprovision and entitlements for SDK-related entries
security cms -D -i target_extracted/Payload/*.app/embedded.mobileprovision 2>/dev/null | \
    grep -iE "app-group\|aps-environment\|associated-domains"
```

**From Podfile/SPM (source-level):**

```bash
# CocoaPods
cat Podfile Podfile.lock 2>/dev/null
# SPM
cat Package.resolved 2>/dev/null
# Carthage
cat Cartfile Cartfile.resolved 2>/dev/null
```

### Build the SDK BOM

For each identified SDK, record:
- SDK name and vendor
- Version (exact if available, estimated from symbols/strings otherwise)
- Integration method (framework, static lib, source, CocoaPods, Gradle, SPM)
- Category (analytics, ads, crash reporting, auth, payments, social, mapping, push, A/B testing, deep linking)
- Permissions accessed (determined in the Permission Scope section below)
- Network endpoints contacted (determined in the Data Exfiltration section below)

### What Constitutes a Finding

- App contains SDKs that are not listed in the developer's dependency manifest (embedded but not tracked).
- SDK versions are significantly outdated (more than two major versions behind current release).
- Frida Gadget, Flipper, Stetho, or LeakCanary frameworks present in production builds indicate incomplete build stripping.
- App bundles multiple competing SDKs serving the same purpose (three analytics SDKs, two crash reporters) without business justification.

### Evidence Standard

Provide the complete SDK inventory table with name, version, category, and identification method for each SDK. Include the specific file path or symbol that identifies each SDK.

## SDK CVE Checking

### What to Test

Check each SDK in the BOM against known vulnerability databases.

### CVE Database Queries

```bash
# OSV (Open Source Vulnerabilities) — covers Maven, npm, PyPI, and more
# For each Gradle dependency:
curl -s "https://api.osv.dev/v1/query" \
    -H "Content-Type: application/json" \
    -d '{"package":{"name":"com.squareup.okhttp3:okhttp","ecosystem":"Maven"},"version":"4.9.0"}' | \
    python3 -m json.tool

# NVD (National Vulnerability Database)
# Search by CPE or keyword
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=okhttp+4.9" | \
    python3 -c "import sys,json; data=json.load(sys.stdin); [print(v['cve']['id'],v['cve']['descriptions'][0]['value'][:120]) for v in data.get('vulnerabilities',[])]"
```

**Automated scanning:**

```bash
# dependency-check (OWASP) for Android Gradle projects
dependency-check --project "target-app" --scan ./app/build.gradle --format JSON --out report/

# retire.js for JavaScript dependencies (React Native, Cordova, WebView bundles)
retire --path target_decoded/assets/ --outputformat json --outputpath retire_report.json

# Trivy for container and filesystem scanning
trivy fs --scanners vuln target_decoded/

# Snyk (if available)
snyk test --all-projects --json > snyk_report.json
```

**Manual version-to-CVE mapping for common mobile SDKs:**

```bash
# Check specific SDK advisory pages
# OkHttp: https://github.com/square/okhttp/security/advisories
# Retrofit: https://github.com/square/retrofit/security/advisories
# React Native: https://github.com/facebook/react-native/security/advisories
# Flutter: https://github.com/flutter/flutter/security/advisories
# Firebase: https://firebase.google.com/support/release-notes/android
# Sentry: https://github.com/getsentry/sentry-java/security/advisories

# For iOS:
# AFNetworking: https://github.com/AFNetworking/AFNetworking/security/advisories
# Alamofire: https://github.com/Alamofire/Alamofire/security/advisories
# SDWebImage: https://github.com/SDWebImage/SDWebImage/security/advisories
```

### What Constitutes a Finding

- SDK has a known HIGH or CRITICAL CVE with a public exploit that is reachable through the app's usage of the SDK.
- SDK has a known vulnerability affecting the specific version bundled, even if exploitability through the app is not immediately confirmed (record as intelligence, not finding, until validated).
- Multiple SDKs depend on the same transitive dependency with a known vulnerability.

### Evidence Standard

Provide the SDK name, exact version (or version range), CVE ID, CVSS score, vulnerability description, and whether the vulnerable code path is reachable through the app's SDK usage. For HIGH/CRITICAL CVEs, demonstrate or describe the attack path through the app.

## Known Malicious SDK Detection

### What to Test

Detect SDKs with known malicious behavior patterns, including data harvesting SDKs (SpinOK, Goldoson), ad fraud SDKs, and trojaned SDK distributions.

### SpinOK-Class Detection (Data Harvesting Ad SDK)

```bash
# SpinOK indicators (2023-2025 campaigns)
# Package namespaces
grep -rn "com.spin\|spin\.sdk\|spinok" target_decoded/smali*/
# Network endpoints
grep -rn "spin-sdk\|spinok\|deneyapps\|lfrfrn\|spcliix" target_decoded/

# Behavioral indicators:
# - Requests clipboard contents
# - Reads SMS messages
# - Enumerates installed packages
# - Reads device sensor data beyond app needs
# - Contacts domains with random/DGA-like names
```

### Goldoson-Class Detection (Ad Library Data Collection)

```bash
# Goldoson indicators (2023 campaigns)
grep -rn "goldoson\|GoldoSon\|com\.lottecorp\|com\.cupang" target_decoded/smali*/

# Detect via static or runtime analysis: class names, package namespaces, or network
# endpoints matching documented malicious SDK indicators (SpinOK com.spin.*, Goldoson
# dynamic loading patterns). Behavioral indicators:
# - Collects installed app list
# - Harvests Wi-Fi and Bluetooth device information
# - Collects GPS location without user-facing feature
# - Performs ad click fraud in background WebViews
```

### General Malicious SDK Behavioral Indicators

```javascript
// Frida: detect suspicious SDK behaviors at runtime
Java.perform(function() {
    // Clipboard access by SDKs
    var ClipboardManager = Java.use('android.content.ClipboardManager');
    ClipboardManager.getPrimaryClip.implementation = function() {
        console.log('[SDK-SUSPICION] Clipboard read');
        console.log(Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new()));
        return this.getPrimaryClip();
    };

    // Installed package enumeration
    var PackageManager = Java.use('android.app.ApplicationContext');
    try {
        var PM = Java.use('android.content.pm.PackageManager');
        // Hook getInstalledPackages
        Java.use('android.app.ContextImpl').getPackageManager.implementation = function() {
            var pm = this.getPackageManager();
            console.log('[SDK-SUSPICION] getPackageManager called');
            return pm;
        };
    } catch(e) {}

    // Contact list access
    var ContentResolver = Java.use('android.content.ContentResolver');
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;',
        'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, proj, sel, selArgs, sort) {
        var uriStr = uri.toString();
        if (uriStr.includes('contacts') || uriStr.includes('phone') || uriStr.includes('sms')) {
            console.log('[SDK-SUSPICION] Sensitive content query: ' + uriStr);
            console.log(Java.use('android.util.Log').getStackTraceString(
                Java.use('java.lang.Exception').$new()));
        }
        return this.query(uri, proj, sel, selArgs, sort);
    };

    // File system scanning
    var File = Java.use('java.io.File');
    File.listFiles.overload().implementation = function() {
        var path = this.getAbsolutePath();
        if (path.includes('/sdcard') || path.includes('/storage') ||
            path.includes('/DCIM') || path.includes('/Download')) {
            console.log('[SDK-SUSPICION] Directory listing: ' + path);
            console.log(Java.use('android.util.Log').getStackTraceString(
                Java.use('java.lang.Exception').$new()));
        }
        return this.listFiles();
    };
});
```

### Network-Based Detection

```python
# sdk_exfil_monitor.py — detect suspicious SDK network behavior
from mitmproxy import http
import re, json

SUSPICIOUS_INDICATORS = {
    'dga_domain': re.compile(r'^[a-z]{12,}\.(com|net|io|xyz|top)$'),
    'ip_direct': re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
    'base64_payload': re.compile(r'[A-Za-z0-9+/]{50,}={0,2}'),
    'large_json_array': re.compile(r'^\s*\[.{1000,}'),
}

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host
    body = flow.request.get_text() or ''

    # DGA-like domain
    if SUSPICIOUS_INDICATORS['dga_domain'].match(host):
        print(f'[MALICIOUS-SDK] DGA-like domain: {host}')

    # Direct IP communication
    if SUSPICIOUS_INDICATORS['ip_direct'].match(host):
        print(f'[MALICIOUS-SDK] Direct IP request: {host}{flow.request.path}')

    # Large encoded payload
    if SUSPICIOUS_INDICATORS['base64_payload'].search(body):
        print(f'[MALICIOUS-SDK] Large base64 payload to {host} ({len(body)} bytes)')

    # Bulk data upload
    if len(body) > 10000:
        print(f'[MALICIOUS-SDK] Large payload ({len(body)} bytes) to {host}{flow.request.path}')
        try:
            data = json.loads(body)
            if isinstance(data, list) and len(data) > 20:
                print(f'  Array with {len(data)} items — possible bulk exfiltration')
        except (json.JSONDecodeError, TypeError):
            pass
```

### What Constitutes a Finding

- App contains an SDK with known malicious behavior (SpinOK, Goldoson, or variants identified in security advisories).
- An SDK performs actions inconsistent with its stated purpose: an ad SDK reading contacts, an analytics SDK enumerating installed apps, a crash reporter accessing the clipboard.
- An SDK communicates with domains matching DGA patterns, direct IP addresses, or known C2 infrastructure.
- An SDK uploads large bulk payloads containing device data, contact lists, or installed app inventories.

### Evidence Standard

Identify the specific SDK (package name, version, class names), the suspicious behavior observed (Frida backtrace showing the SDK code path), and the network destination. For known malicious SDKs, reference the security advisory or research report.

## SDK Data Exfiltration Audit

### What to Test

Determine what data each SDK actually collects and transmits, versus what the app developer likely intended the SDK to collect.

### Per-SDK Traffic Isolation

```bash
# Step 1: Map SDK domains from static analysis
grep -rn "https\?://\|\.com\|\.io\|\.net" target_decoded/smali*/ | \
    grep -oE 'https?://[a-zA-Z0-9._/-]+' | sort -u > sdk_domains.txt

# Step 2: Capture full session traffic
mitmproxy --mode regular --listen-port 8080 -w sdk_audit.flow

# Step 3: Categorize traffic by SDK
mitmdump -r sdk_audit.flow -s sdk_traffic_categorizer.py
```

```python
# sdk_traffic_categorizer.py — map network requests to SDKs
from mitmproxy import http
import json
from collections import defaultdict

SDK_DOMAIN_MAP = {
    'Firebase': ['app-measurement.com', 'firebaseinstallations.googleapis.com',
                 'firebase-settings.crashlytics.com', 'fcm.googleapis.com'],
    'Facebook': ['graph.facebook.com', 'an.facebook.com', 'connect.facebook.net'],
    'Amplitude': ['api2.amplitude.com', 'api.amplitude.com'],
    'Mixpanel': ['api.mixpanel.com', 'decide.mixpanel.com'],
    'Segment': ['api.segment.io', 'cdn.segment.com'],
    'AppsFlyer': ['launches.appsflyer.com', 'events.appsflyer.com',
                  'conversions.appsflyer.com', 'register.appsflyer.com'],
    'Adjust': ['app.adjust.com', 'app.adjust.io', 's2s.adjust.com'],
    'Branch': ['api.branch.io', 'api2.branch.io', 'bnc.lt'],
    'Sentry': ['sentry.io'],
    'Braze': ['sdk.iad-01.braze.com'],
    'Crashlytics': ['reports.crashlytics.com', 'settings.crashlytics.com'],
    'Google Ads': ['googleads.g.doubleclick.net', 'pagead2.googlesyndication.com',
                   'adservice.google.com'],
    'Unity Ads': ['unityads.unity3d.com', 'ads-game-configuration.unityads.unity3d.com'],
    'AdMob': ['admob-sdk-config.googleapis.com'],
}

sdk_data = defaultdict(list)

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host.lower()
    body = flow.request.get_text() or ''
    matched_sdk = 'Unknown'
    for sdk, domains in SDK_DOMAIN_MAP.items():
        if any(d in host for d in domains):
            matched_sdk = sdk
            break
    entry = {
        'url': flow.request.pretty_url[:200],
        'method': flow.request.method,
        'body_size': len(body),
        'content_type': flow.request.headers.get('content-type', ''),
    }
    # Extract data types from payload
    try:
        data = json.loads(body)
        entry['payload_keys'] = list(data.keys()) if isinstance(data, dict) else 'array'
    except (json.JSONDecodeError, TypeError):
        pass
    sdk_data[matched_sdk].append(entry)
    print(f'[SDK-TRAFFIC] {matched_sdk}: {flow.request.method} {host}{flow.request.path} ({len(body)}b)')

def done():
    print('\n=== SDK Traffic Summary ===')
    for sdk, entries in sorted(sdk_data.items()):
        total_bytes = sum(e['body_size'] for e in entries)
        print(f'{sdk}: {len(entries)} requests, {total_bytes} bytes total')
```

### Data Field Analysis

For each SDK's traffic, categorize the data fields into:

1. **Expected for SDK purpose:** Analytics SDK sending screen views, crash reporter sending stack traces.
2. **Excessive for SDK purpose:** Analytics SDK sending full contact list, crash reporter sending GPS coordinates.
3. **Undisclosed by developer:** Data types collected by the SDK that are not mentioned in the app's privacy policy.

```bash
# Deep inspect specific SDK payloads
mitmdump -r sdk_audit.flow --set flow_detail=3 | \
    grep -A 50 "app-measurement.com\|api2.amplitude.com\|api.mixpanel.com"
```

### Common Exfiltration Patterns

| SDK Category | Expected Data | Excessive Data (Finding) |
|---|---|---|
| Analytics | Screen views, tap events, session duration | Contact list, SMS, photos, clipboard, installed apps |
| Crash Reporting | Stack trace, OS version, device model | Full request body, auth tokens, user messages |
| Ad SDK | Ad impression, click, device model, GAID/IDFA | Precise location (when app has no location feature), Wi-Fi SSID list, Bluetooth devices |
| Attribution | Install source, campaign ID, device fingerprint | Full browsing history, contact list, SMS content |
| Push | Push token, device ID | Installed apps, battery level, storage capacity |

### What Constitutes a Finding

- An SDK transmits data types that exceed its functional requirements (an ad SDK sending contact lists, a crash reporter sending auth tokens).
- An SDK collects data not disclosed in the app's privacy policy or privacy label.
- An SDK transmits user-identifiable data (email, phone, name) to third-party domains without explicit user consent for that specific sharing.
- An SDK continues to transmit data after the user opts out: opt out via app settings, capture traffic for 5 minutes, verify SDK requests to analytics domains cease or sensitive fields are removed — compare pre-opt-out vs post-opt-out payloads to quantify the gap.
- An SDK transmits data over HTTP instead of HTTPS, or uses certificate pinning that prevents the app developer from auditing its traffic.

### Evidence Standard

For each finding, provide the SDK name and version, the specific network request (URL, headers, body), the data fields transmitted, the SDK's stated purpose, and why the observed data exceeds that purpose. Reference the app's privacy policy statement about the relevant data type.

## SDK Permission Scope

### What to Test

Determine what Android permissions or iOS entitlements/capabilities each SDK declares or uses at runtime, and whether those exceed the app's stated needs.

### Android Permission Analysis

```bash
# Extract all permissions from manifest
aapt dump permissions target.apk

# Or from decoded manifest:
grep -oE 'android:name="android.permission\.[A-Z_]+"' target_decoded/AndroidManifest.xml | sort -u

# Map permissions to SDKs by checking which SDK code accesses each permission
# For each permission, find the SDK code that uses the guarded API:

# Location
grep -rn "getLastKnownLocation\|requestLocationUpdates\|FusedLocationProviderClient\|getCurrentLocation" \
    target_decoded/smali*/ | grep -v "com/target/app" | head -20

# Camera
grep -rn "Camera\.open\|CameraManager\|CameraDevice" \
    target_decoded/smali*/ | grep -v "com/target/app" | head -20

# Contacts
grep -rn "ContactsContract\|READ_CONTACTS\|WRITE_CONTACTS" \
    target_decoded/smali*/ | grep -v "com/target/app" | head -20

# Phone state
grep -rn "TelephonyManager\|getDeviceId\|getLine1Number\|getSimSerialNumber" \
    target_decoded/smali*/ | grep -v "com/target/app" | head -20

# Storage
grep -rn "READ_EXTERNAL_STORAGE\|WRITE_EXTERNAL_STORAGE\|MANAGE_EXTERNAL_STORAGE" \
    target_decoded/smali*/ | grep -v "com/target/app" | head -20
```

**iOS equivalent — map SDK permission usage via Info.plist and binary symbols:**

```bash
# Check Info.plist for permission usage descriptions that SDK code triggers
/usr/libexec/PlistBuddy -c "Print :NSPhotoLibraryUsageDescription" target_extracted/Payload/*.app/Info.plist 2>/dev/null
/usr/libexec/PlistBuddy -c "Print :NSCameraUsageDescription" target_extracted/Payload/*.app/Info.plist 2>/dev/null
/usr/libexec/PlistBuddy -c "Print :NSLocationWhenInUseUsageDescription" target_extracted/Payload/*.app/Info.plist 2>/dev/null
/usr/libexec/PlistBuddy -c "Print :NSContactsUsageDescription" target_extracted/Payload/*.app/Info.plist 2>/dev/null
/usr/libexec/PlistBuddy -c "Print :NSMicrophoneUsageDescription" target_extracted/Payload/*.app/Info.plist 2>/dev/null
/usr/libexec/PlistBuddy -c "Print :NSBluetoothAlwaysUsageDescription" target_extracted/Payload/*.app/Info.plist 2>/dev/null
/usr/libexec/PlistBuddy -c "Print :NSUserTrackingUsageDescription" target_extracted/Payload/*.app/Info.plist 2>/dev/null

# Search SDK framework binaries for permission-guarded API calls
for fw in target_extracted/Payload/*.app/Frameworks/*.framework/*; do
    [ -f "$fw" ] || continue
    nm "$fw" 2>/dev/null | grep -iE "CLLocationManager|CNContactStore|PHPhotoLibrary|AVCaptureDevice|ATTrackingManager" && \
        echo "  ^^^ from: $fw"
done
```

**Runtime permission monitoring:**

```javascript
// Android: hook permission checks at runtime
Java.perform(function() {
    var ContextCompat = Java.use('androidx.core.content.ContextCompat');
    ContextCompat.checkSelfPermission.implementation = function(context, permission) {
        var result = this.checkSelfPermission(context, permission);
        console.log('[PERM] checkSelfPermission: ' + permission + ' = ' +
            (result === 0 ? 'GRANTED' : 'DENIED'));
        if (result === 0) {
            console.log(Java.use('android.util.Log').getStackTraceString(
                Java.use('java.lang.Exception').$new()).split('\n').slice(0, 8).join('\n'));
        }
        return result;
    };

    // Hook ActivityCompat.requestPermissions
    var ActivityCompat = Java.use('androidx.core.app.ActivityCompat');
    ActivityCompat.requestPermissions.implementation = function(activity, permissions, requestCode) {
        console.log('[PERM] requestPermissions: ' + permissions.join(', '));
        return this.requestPermissions(activity, permissions, requestCode);
    };
});
```

### iOS Permission Analysis

```bash
# Check Info.plist for permission purpose strings
# Each NS*UsageDescription indicates a permission the app requests
/usr/libexec/PlistBuddy -c "Print" target_extracted/Payload/*.app/Info.plist 2>/dev/null | \
    grep -i "UsageDescription"

# Common iOS permission keys:
# NSCameraUsageDescription, NSPhotoLibraryUsageDescription,
# NSLocationWhenInUseUsageDescription, NSLocationAlwaysUsageDescription,
# NSContactsUsageDescription, NSMicrophoneUsageDescription,
# NSCalendarsUsageDescription, NSMotionUsageDescription,
# NSBluetoothAlwaysUsageDescription, NSLocalNetworkUsageDescription,
# NSUserTrackingUsageDescription (ATT)

# Check entitlements for capability-level permissions
codesign -d --entitlements - target_extracted/Payload/*.app/ 2>/dev/null
```

**Runtime permission monitoring (iOS):**

```javascript
// iOS: hook permission request APIs
if (ObjC.available) {
    // Location
    var CLLocationManager = ObjC.classes.CLLocationManager;
    if (CLLocationManager) {
        Interceptor.attach(CLLocationManager['- requestWhenInUseAuthorization'].implementation, {
            onEnter: function() {
                console.log('[PERM-iOS] Location WhenInUse requested');
                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n'));
            }
        });
    }

    // Contacts
    var CNContactStore = ObjC.classes.CNContactStore;
    if (CNContactStore) {
        Interceptor.attach(CNContactStore['- requestAccessForEntityType:completionHandler:'].implementation, {
            onEnter: function(args) {
                console.log('[PERM-iOS] Contacts access requested, type: ' + args[2]);
            }
        });
    }

    // Camera
    var AVCaptureDevice = ObjC.classes.AVCaptureDevice;
    if (AVCaptureDevice) {
        Interceptor.attach(AVCaptureDevice['+ requestAccessForMediaType:completionHandler:'].implementation, {
            onEnter: function(args) {
                var mediaType = new ObjC.Object(args[2]);
                console.log('[PERM-iOS] Camera/Mic access requested: ' + mediaType);
            }
        });
    }
}
```

### Permission-to-SDK Mapping

Build a matrix crossing each permission with the SDK(s) that access it:

| Permission | App Feature | SDK(s) Using It | Justified? |
|---|---|---|---|
| ACCESS_FINE_LOCATION | Map view | Google Maps SDK, Adjust SDK | Maps: Yes. Adjust: No unless location-based attribution is disclosed |
| CAMERA | Photo upload | App core code, Facebook SDK | Core: Yes. Facebook: Only if camera-based features are used via FB |
| READ_CONTACTS | Contact invite | App core code, Branch SDK | Core: Yes if invite feature exists. Branch: No |
| READ_PHONE_STATE | (none visible) | AppsFlyer SDK | Finding: no user-facing feature justifies this |

### What Constitutes a Finding

- An SDK accesses a permission (location, contacts, camera, microphone) that is not required for the app's user-facing features.
- An SDK requests dangerous permissions at runtime without the app developer's awareness (identified through backtrace analysis showing SDK code, not app code, as the caller).
- The app declares permissions in the manifest solely because an SDK requires them, even though the app's features do not need them.
- An SDK uses a permission granted for the app's core feature (e.g., location for a map) to collect data for the SDK's own purposes (e.g., location-based ad targeting).

### Evidence Standard

For each finding, show the permission, the SDK that accesses it (with Frida backtrace or static analysis evidence), the app's stated need for the permission (from Info.plist purpose string or Play Store listing), and why the SDK's access exceeds that stated need. Include the runtime hook output showing the SDK code path in the call stack.

## Source Anchors

- OWASP Mobile Supply Chain: https://mas.owasp.org/MASVS/06-MASVS-CODE/
- OWASP Dependency-Check: https://owasp.org/www-project-dependency-check/
- OSV (Open Source Vulnerabilities): https://osv.dev/
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- retire.js: https://retirejs.github.io/retire.js/
- Trivy: https://aquasecurity.github.io/trivy/
- MobSF: https://mobsf.github.io/docs/
- APKiD: https://github.com/rednaga/APKiD
- SpinOK research (Dr.Web, 2023): https://news.drweb.com/show/?i=14705
- Goldoson research (McAfee, 2023): https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-policy-violating-apps/
- Google Play SDK Index: https://play.google.com/sdks
- Apple Privacy Manifest (iOS 17+): https://developer.apple.com/documentation/bundleresources/privacy-manifest-files
- Android permissions reference: https://developer.android.com/reference/android/Manifest.permission
- Frida JavaScript API: https://frida.re/docs/javascript-api/
- jadx: https://github.com/skylot/jadx
- apktool: https://apktool.org/
