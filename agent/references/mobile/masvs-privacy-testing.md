# MASVS-PRIVACY Testing Reference

OWASP MASVS v2 added MASVS-PRIVACY as a top-level category. This reference provides concrete test procedures for identifier auditing, tracking transparency, privacy sandbox, data deletion, privacy label verification, and analytics/telemetry assessment.

## Identifier Audit

### What to Test

Apps collect device and user identifiers for analytics, attribution, fraud detection, and fingerprinting. Test whether the app accesses advertising identifiers, hardware identifiers, or fingerprinting signals and whether usage aligns with stated purposes.

### iOS Identifiers

**IDFA (Identifier for Advertisers):**

```bash
# Frida hook to detect IDFA access
frida -U -n <app_name> -l idfa_hook.js
```

```javascript
// idfa_hook.js — detect ASIdentifierManager usage
if (ObjC.available) {
    var ASIdentifierManager = ObjC.classes.ASIdentifierManager;
    Interceptor.attach(ASIdentifierManager['+ sharedManager'].implementation, {
        onEnter: function(args) {
            console.log('[IDFA] ASIdentifierManager.sharedManager called');
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n'));
        }
    });
    Interceptor.attach(ASIdentifierManager['- advertisingIdentifier'].implementation, {
        onEnter: function(args) {
            console.log('[IDFA] advertisingIdentifier accessed');
        },
        onLeave: function(retval) {
            var nsuuid = new ObjC.Object(retval);
            console.log('[IDFA] Value: ' + nsuuid.UUIDString());
        }
    });
}
```

**identifierForVendor:**

```javascript
// Hook UIDevice.identifierForVendor
if (ObjC.available) {
    Interceptor.attach(ObjC.classes.UIDevice['- identifierForVendor'].implementation, {
        onLeave: function(retval) {
            var uuid = new ObjC.Object(retval);
            console.log('[IDFV] identifierForVendor: ' + uuid.UUIDString());
        }
    });
}
```

**Keychain-persisted identifiers:**

```bash
# Objection: dump Keychain items and grep for UUID patterns
objection -g <bundle_id> explore -c "ios keychain dump"
# Look for custom persistent identifiers stored pre-ATT
```

### Android Identifiers

**Google Advertising ID (GAID):**

```javascript
// Frida hook for GAID access
Java.perform(function() {
    var AdvertisingIdClient = Java.use('com.google.android.gms.ads.identifier.AdvertisingIdClient');
    AdvertisingIdClient.getAdvertisingIdInfo.overload('android.content.Context').implementation = function(ctx) {
        console.log('[GAID] getAdvertisingIdInfo called');
        console.log(Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new()));
        var info = this.getAdvertisingIdInfo(ctx);
        console.log('[GAID] ID: ' + info.getId());
        console.log('[GAID] Limit Ad Tracking: ' + info.isLimitAdTrackingEnabled());
        return info;
    };
});
```

**Hardware identifiers (IMEI, serial, MAC):**

```javascript
// Hook TelephonyManager for IMEI/device ID
Java.perform(function() {
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getDeviceId.overload().implementation = function() {
        console.log('[IMEI] getDeviceId called');
        var result = this.getDeviceId();
        console.log('[IMEI] Value: ' + result);
        return result;
    };
    TelephonyManager.getImei.overload().implementation = function() {
        console.log('[IMEI] getImei called');
        var result = this.getImei();
        console.log('[IMEI] Value: ' + result);
        return result;
    };

    // ANDROID_ID
    var Settings = Java.use('android.provider.Settings$Secure');
    Settings.getString.implementation = function(resolver, name) {
        var result = this.getString(resolver, name);
        if (name === 'android_id') {
            console.log('[ANDROID_ID] Value: ' + result);
        }
        return result;
    };

    // MAC address
    var NetworkInterface = Java.use('java.net.NetworkInterface');
    NetworkInterface.getHardwareAddress.implementation = function() {
        console.log('[MAC] getHardwareAddress called');
        return this.getHardwareAddress();
    };
});
```

### Fingerprinting Signals

```javascript
// iOS — detect fingerprinting signal collection
if (ObjC.available) {
    // Screen dimensions
    Interceptor.attach(ObjC.classes.UIScreen['- bounds'].implementation, {
        onEnter: function() { console.log('[FP] UIScreen.bounds accessed'); }
    });
    // Locale/timezone
    Interceptor.attach(ObjC.classes.NSLocale['+ currentLocale'].implementation, {
        onEnter: function() { console.log('[FP] NSLocale.currentLocale accessed'); }
    });
    Interceptor.attach(ObjC.classes.NSTimeZone['+ localTimeZone'].implementation, {
        onEnter: function() { console.log('[FP] NSTimeZone.localTimeZone accessed'); }
    });
    // Device model
    Interceptor.attach(ObjC.classes.UIDevice['- model'].implementation, {
        onEnter: function() { console.log('[FP] UIDevice.model accessed'); }
    });
    // Font enumeration
    Interceptor.attach(ObjC.classes.UIFont['+ familyNames'].implementation, {
        onEnter: function() { console.log('[FP] UIFont.familyNames — possible font fingerprinting'); }
    });
}
```

```javascript
// Android — detect fingerprinting signal collection
Java.perform(function() {
    var Build = Java.use('android.os.Build');
    console.log('[FP-STATIC] Build fields accessible: MODEL=' + Build.MODEL.value +
        ' MANUFACTURER=' + Build.MANUFACTURER.value + ' FINGERPRINT=' + Build.FINGERPRINT.value);

    // WebView user agent extraction
    var WebSettings = Java.use('android.webkit.WebSettings');
    WebSettings.getUserAgentString.implementation = function() {
        console.log('[FP] getUserAgentString called');
        return this.getUserAgentString();
    };

    // Sensor enumeration
    var SensorManager = Java.use('android.hardware.SensorManager');
    SensorManager.getSensorList.implementation = function(type) {
        console.log('[FP] getSensorList type=' + type);
        return this.getSensorList(type);
    };
});
```

### Traffic Analysis for Identifiers

```bash
# mitmproxy: filter for known identifier patterns in outbound requests
mitmdump -s identifier_filter.py -w identifier_traffic.flow
```

```python
# identifier_filter.py — flag requests containing device identifiers
import re
from mitmproxy import http

PATTERNS = {
    'IDFA/GAID': re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
    'IMEI': re.compile(r'\b\d{15}\b'),
    'MAC': re.compile(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}'),
    'ANDROID_ID': re.compile(r'\b[0-9a-f]{16}\b'),
}

def request(flow: http.HTTPFlow):
    body = flow.request.get_text() or ''
    url = flow.request.pretty_url
    for name, pattern in PATTERNS.items():
        if pattern.search(url) or pattern.search(body):
            print(f'[ID-LEAK] {name} found in request to {flow.request.pretty_host}{flow.request.path}')
```

### What Constitutes a Finding

- App accesses IDFA/GAID without ATT consent (iOS) or without respecting ad tracking opt-out (Android).
- App reads hardware identifiers (IMEI, MAC, serial) for analytics, attribution, or cross-app tracking.
- App transmits multiple device-identifying signals (screen dimensions, locale, timezone, device model, font list, sensor data) in a single analytics payload beyond what core functionality requires.
- Identifiers appear in plaintext in network traffic, local storage, or logs.

### Evidence Standard

Capture the Frida hook output showing the API call and backtrace, the corresponding network request showing the identifier transmitted, and the destination domain. Screenshot the traffic in Burp/mitmproxy with the identifier value highlighted.

## App Tracking Transparency (iOS)

### What to Test

iOS 14.5+ requires apps to request permission through ATT before tracking users across apps and websites owned by other companies. Test whether the app tracks without consent, uses fingerprinting as a workaround, or bypasses ATT via server-side attribution.

### ATT Consent State Testing

```javascript
// Hook ATTrackingManager to observe consent flow
if (ObjC.available) {
    var ATTrackingManager = ObjC.classes.ATTrackingManager;
    if (ATTrackingManager) {
        Interceptor.attach(ATTrackingManager['+ trackingAuthorizationStatus'].implementation, {
            onLeave: function(retval) {
                var status = retval.toInt32();
                var statusMap = {0: 'notDetermined', 1: 'restricted', 2: 'denied', 3: 'authorized'};
                console.log('[ATT] trackingAuthorizationStatus: ' + statusMap[status]);
            }
        });
        Interceptor.attach(ATTrackingManager['+ requestTrackingAuthorizationWithCompletionHandler:'].implementation, {
            onEnter: function(args) {
                console.log('[ATT] requestTrackingAuthorization called');
            }
        });
    }
}
```

### Pre-Consent Tracking Detection

```bash
# Step 1: Fresh install the app on test device, do NOT grant ATT permission
# Step 2: Start proxy capture before first launch
mitmproxy --mode regular --listen-port 8080 --set stream_large_bodies=0

# Step 3: Launch app, use core features for 2-3 minutes
# Step 4: Export captured traffic
mitmdump -r captured.flow -w preconsent_traffic.flow

# Step 5: Analyze for tracking indicators
mitmdump -r preconsent_traffic.flow -s att_preconsent_check.py
```

```python
# att_preconsent_check.py — detect pre-consent tracking behavior
from mitmproxy import http
import json

TRACKING_DOMAINS = [
    'graph.facebook.com', 'app-measurement.com', 'analytics.google.com',
    'app.adjust.com', 'app.appsflyer.com', 'branch.io', 'api.branch.io',
    'kochava.com', 'singular.net', 'tenjin.com', 'api2.amplitude.com',
    'api.mixpanel.com', 'data.flurry.com', 'api.segment.io',
]

TRACKING_PARAMS = ['idfa', 'idfv', 'att_status', 'advertising_id', 'gaid',
                   'device_id', 'fingerprint', 'device_fingerprint']

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host.lower()
    if any(td in host for td in TRACKING_DOMAINS):
        body = flow.request.get_text() or ''
        print(f'[ATT-PRE] Request to tracking domain: {host}{flow.request.path}')
        for param in TRACKING_PARAMS:
            if param in body.lower() or param in flow.request.pretty_url.lower():
                print(f'  [ATT-PRE] Contains tracking param: {param}')
        try:
            data = json.loads(body)
            print(f'  [ATT-PRE] Payload keys: {list(data.keys()) if isinstance(data, dict) else "array"}')
        except (json.JSONDecodeError, TypeError):
            pass
```

### Fingerprinting Workaround Detection

Deny ATT permission, then monitor outbound traffic for requests aggregating device signals (model + screen dimensions + locale + timezone + carrier) — this combination indicates probabilistic fingerprinting despite consent denial. Test each workaround vector:
- Capture POST bodies to analytics and attribution domains; flag any payload containing four or more device-identifying fields.
- Query DNS and HTTP traffic for known fingerprinting services (DeviceCheck, server-side attribution endpoints that aggregate signals) and verify they receive device signals after ATT denial.
- Detect canvas/WebView-based fingerprinting: hook WKWebView creation, flag offscreen or zero-frame instances, and trace JavaScript drawing operations whose output hash is transmitted to analytics endpoints.

```javascript
// Detect off-screen WebView creation (fingerprinting workaround)
if (ObjC.available) {
    Interceptor.attach(ObjC.classes.WKWebView['- initWithFrame:configuration:'].implementation, {
        onEnter: function(args) {
            var frame = ObjC.Object(args[2]);
            console.log('[ATT-FP] WKWebView created, frame: ' + frame.toString());
            if (frame.toString().includes('0, 0') || frame.toString().includes('1, 1')) {
                console.log('[ATT-FP] WARNING: Zero/tiny frame WebView — possible fingerprinting');
            }
        }
    });
}
```

### Server-Side Attribution Bypass Detection

Apps may send raw event data plus device signals to their server, which then performs attribution without client-side SDK tracking. Look for:
- POST requests to first-party domains containing install timestamps, IP address, user agent, app version, and device model.
- SKAdNetwork or AdServices framework usage without ATT (legitimate, but note the data granularity).
- Requests that correlate device-level signals to advertising campaign IDs through server-side joins.

### What Constitutes a Finding

- App sends IDFA to any third-party domain before ATT authorization is `.authorized`.
- App transmits a probabilistic device fingerprint (four or more device signals in a single payload) to a tracking domain after ATT is denied.
- App creates hidden WebViews or runs JavaScript solely for fingerprinting purposes after ATT denial.
- Compare the Privacy Nutrition Label declaration against captured traffic: if the label claims "Data Not Collected" for tracking but traffic analysis shows tracking payloads sent pre-consent, record the discrepancy with the exact label text, the request URL, and the payload fields.

### Evidence Standard

Capture the full request/response showing the tracking payload, annotated with ATT state at time of capture. Include Frida output showing ATT status was `.denied` or `.notDetermined`. Show the timeline: ATT denial timestamp versus tracking request timestamp.

## Android Privacy Sandbox

### What to Test

Android Privacy Sandbox replaces GAID with privacy-preserving APIs. Test current app behavior against the transition state: Topics API, Attribution Reporting API, Protected Audiences, and SDK Runtime.

### Topics API Testing

```javascript
// Hook Topics API (Android 13+ with Privacy Sandbox enabled)
Java.perform(function() {
    try {
        var TopicsManager = Java.use('android.adservices.topics.TopicsManager');
        TopicsManager.getTopics.implementation = function(request, executor, callback) {
            console.log('[TOPICS] getTopics called');
            console.log('[TOPICS] Request: ' + request.toString());
            this.getTopics(request, executor, {
                accept: function(response) {
                    console.log('[TOPICS] Response topics: ' + response.getTopics().toString());
                    callback.accept(response);
                }
            });
        };
    } catch(e) {
        console.log('[TOPICS] TopicsManager not available: ' + e);
    }
});
```

### Attribution Reporting API

```javascript
// Hook Attribution Reporting registration
Java.perform(function() {
    try {
        var MeasurementManager = Java.use('android.adservices.measurement.MeasurementManager');
        MeasurementManager.registerSource.implementation = function(uri, event, executor, callback) {
            console.log('[ATTRIB] registerSource URI: ' + uri.toString());
            console.log('[ATTRIB] InputEvent: ' + (event ? event.toString() : 'null'));
            return this.registerSource(uri, event, executor, callback);
        };
        MeasurementManager.registerTrigger.implementation = function(uri, executor, callback) {
            console.log('[ATTRIB] registerTrigger URI: ' + uri.toString());
            return this.registerTrigger(uri, executor, callback);
        };
    } catch(e) {
        console.log('[ATTRIB] MeasurementManager not available: ' + e);
    }
});
```

### SDK Runtime Isolation

```bash
# Check if app uses SDK Runtime (Android 14+)
# In AndroidManifest.xml, look for:
#   <uses-sdk-library android:name="..." android:versionMajor="..." android:certDigest="..." />
apktool d target.apk -o target_decoded
grep -r "uses-sdk-library\|SandboxedSdkProvider\|SdkSandboxManager" target_decoded/
```

```bash
# On device, check SDK sandbox processes
adb shell ps -A | grep sdk_sandbox
adb shell dumpsys activity services | grep SdkSandbox
```

### What to Test in Practice (2025-2026)

- Whether the app still uses GAID directly alongside or instead of Privacy Sandbox APIs.
- Whether attribution reporting registrations leak more data than the API design intends (extra query params, custom headers).
- Whether the app's ad SDKs have migrated to SDK Runtime or still run in the app process with full data access.
- Whether Topics API responses leak sensitive interest categories to unauthorized callers.

### What Constitutes a Finding

- App reads GAID and transmits it to third parties while Privacy Sandbox APIs are available and the device has GAID deprecation flags enabled.
- Attribution Reporting source/trigger registration URIs contain PII, user identifiers, or precise location data in query parameters.
- SDK Runtime is available but ad SDKs still run in the main app process, accessing contacts, location, or other protected data.

## Data Deletion Testing

### What to Test

Verify that account deletion (GDPR Article 17, Apple App Store requirement, Google Play Data Deletion requirement) actually removes user data from local storage, Keychain/Keystore, backups, cloud sync, and server-side state.

### Pre-Deletion Baseline

```bash
# Android: snapshot app data before deletion
adb shell run-as <package_name> find /data/data/<package_name> -type f > pre_delete_files.txt
adb shell run-as <package_name> cat /data/data/<package_name>/shared_prefs/*.xml > pre_delete_prefs.txt
adb shell run-as <package_name> sqlite3 /data/data/<package_name>/databases/*.db ".dump" > pre_delete_db.txt

# iOS: snapshot app container before deletion
# On jailbroken device or via Frida:
objection -g <bundle_id> explore -c "env"
# Note the Documents, Library, and tmp paths, then:
# frida-pull or scp the full container directory
```

### Execute Account Deletion

Trigger account deletion through the app's UI. Record the exact flow, confirmation steps, and any "grace period" messaging.

### Post-Deletion Local Storage Check

```bash
# Android: check what remains after deletion
adb shell run-as <package_name> find /data/data/<package_name> -type f > post_delete_files.txt
diff pre_delete_files.txt post_delete_files.txt

# Check SharedPreferences for residual tokens/PII
adb shell run-as <package_name> cat /data/data/<package_name>/shared_prefs/*.xml

# Check databases for residual data
adb shell run-as <package_name> sqlite3 /data/data/<package_name>/databases/*.db \
    "SELECT name FROM sqlite_master WHERE type='table';"
# For each table:
adb shell run-as <package_name> sqlite3 /data/data/<package_name>/databases/*.db \
    "SELECT COUNT(*) FROM <table_name>;"
```

### Keychain/Keystore Check

```javascript
// iOS: check Keychain items after deletion
// Run via Objection on jailbroken device
// objection -g <bundle_id> explore -c "ios keychain dump"
// Compare pre and post deletion dumps
```

```javascript
// Android: check Keystore entries after deletion
Java.perform(function() {
    var KeyStore = Java.use('java.security.KeyStore');
    var ks = KeyStore.getInstance('AndroidKeyStore');
    ks.load(null);
    var aliases = ks.aliases();
    while (aliases.hasMoreElements()) {
        console.log('[KEYSTORE-POST-DELETE] Alias: ' + aliases.nextElement());
    }
});
```

### Backup Residual Check

```bash
# Android: create ADB backup, extract, and search for user data
adb backup -f post_delete_backup.ab <package_name>
# Convert with android-backup-extractor:
java -jar abe.jar unpack post_delete_backup.ab post_delete_backup.tar
tar xf post_delete_backup.tar
# Search extracted files for PII patterns:
grep -rn "email\|@.*\.com\|phone\|token\|session\|password\|user" apps/<package_name>/

# iOS: create iTunes/Finder backup (unencrypted for testing)
# Use iMazing or libimobiledevice to extract and search app backup domain
```

### Server-Side Deletion Verification

```bash
# Re-authenticate with deleted account credentials (should fail)
curl -X POST https://api.target.example/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"deleted_user@test.com","password":"testpass"}'

# Attempt to access user-specific API endpoints with cached token
curl -H "Authorization: Bearer <cached_token>" \
    https://api.target.example/api/v1/user/profile

# Check if user data appears in other users' views (shared content, comments, etc.)
curl -H "Authorization: Bearer <other_user_token>" \
    https://api.target.example/api/v1/users/<deleted_user_id>/profile

# Test account re-registration with same email
curl -X POST https://api.target.example/auth/register \
    -d '{"email":"deleted_user@test.com","password":"newpass"}'
# If re-registration succeeds, check if old data reappears
```

### What Constitutes a Finding

- Auth tokens, session data, or refresh tokens remain in Keychain/Keystore after account deletion.
- PII (email, name, phone, payment info) remains in local databases or SharedPreferences/UserDefaults.
- Cached user content (photos, messages, documents) remains in app container after deletion.
- Server-side API still returns user profile data using a cached auth token after deletion.
- Re-registering with the same email address restores previously deleted data.
- Backup created after deletion still contains pre-deletion PII.

### Evidence Standard

Provide timestamped before/after file listings, database dumps, and Keychain/Keystore dumps. Show the deletion request timestamp, the post-deletion data capture timestamp, and the specific data fields that survived deletion.

## Privacy Label vs Behavior Audit

### What to Test

Compare the app's declared privacy practices (iOS App Privacy labels, Android Data Safety section) against actual data collection observed through traffic analysis, local storage inspection, and runtime hooks.

### Collect Declared Privacy Practices

**iOS App Privacy labels:** Fetch from the App Store page or App Store Connect. Record each declared data type, collection purpose, and whether it is linked to identity. Apple's categories: Contact Info, Health & Fitness, Financial Info, Location, Sensitive Info, Contacts, User Content, Browsing History, Search History, Identifiers, Purchases, Usage Data, Diagnostics, Other Data.

**Android Data Safety section:** Fetch from the Google Play listing. Record each declared data type, purpose, sharing disclosure, and deletion availability.

### Map Actual Behavior

```bash
# Comprehensive traffic capture during full app usage session
mitmproxy --mode regular --listen-port 8080 -w full_session.flow

# Exercise every major feature: registration, profile edit, messaging,
# media upload, search, settings, payment, sharing, export/import

# Export flows for analysis
mitmdump -r full_session.flow -s privacy_label_audit.py
```

```python
# privacy_label_audit.py — categorize data types observed in traffic
from mitmproxy import http
import json, re

DATA_CATEGORIES = {
    'location': [r'latitude', r'longitude', r'lat', r'lng', r'geo', r'location',
                 r'place_id', r'coordinates'],
    'contact_info': [r'email', r'phone', r'address', r'first_name', r'last_name',
                     r'full_name', r'contact'],
    'identifiers': [r'idfa', r'idfv', r'gaid', r'advertising_id', r'device_id',
                    r'android_id', r'imei', r'serial'],
    'usage_data': [r'screen_view', r'page_view', r'event', r'action', r'session_id',
                   r'app_version', r'os_version', r'screen_name'],
    'financial': [r'card_number', r'cvv', r'expir', r'bank', r'payment', r'billing',
                  r'transaction'],
    'health_fitness': [r'heart_rate', r'steps', r'calories', r'weight', r'height',
                       r'health', r'workout', r'sleep'],
    'browsing_history': [r'referrer', r'visited_url', r'browsing', r'history'],
    'search_history': [r'search_query', r'search_term', r'query', r'keyword'],
    'user_content': [r'message', r'comment', r'post', r'photo', r'video', r'file_name'],
    'diagnostics': [r'crash', r'error', r'stack_trace', r'exception', r'diagnostic',
                    r'performance'],
    'purchases': [r'purchase', r'order', r'product_id', r'sku', r'receipt',
                  r'subscription'],
}

def request(flow: http.HTTPFlow):
    body = (flow.request.get_text() or '').lower()
    url = flow.request.pretty_url.lower()
    combined = body + ' ' + url
    host = flow.request.pretty_host
    found = {}
    for category, patterns in DATA_CATEGORIES.items():
        matches = [p for p in patterns if re.search(p, combined)]
        if matches:
            found[category] = matches
    if found:
        print(f'[LABEL-AUDIT] {host}{flow.request.path}')
        for cat, matches in found.items():
            print(f'  Category: {cat} — matched: {matches}')
```

### Local Storage Cross-Reference

```bash
# Android: dump all local data and categorize
adb shell run-as <package_name> find /data/data/<package_name> -type f -name "*.db" \
    -exec sqlite3 {} ".schema" \;

# Look for tables/columns containing PII not declared in Data Safety
adb shell run-as <package_name> sqlite3 /data/data/<package_name>/databases/analytics.db \
    "SELECT * FROM events LIMIT 20;"
```

```bash
# iOS: inspect local databases via Objection or Frida
objection -g <bundle_id> explore -c "sqlite connect Library/Application Support/app.db"
# Then: .tables, .schema <table>, SELECT * FROM <table> LIMIT 20
```

### Comparison Matrix

Build a matrix of:
1. Data type declared in Privacy Label / Data Safety.
2. Data type observed in network traffic (with destination domain).
3. Data type observed in local storage.
4. Gap: collected but not declared, or declared but not observed.

### What Constitutes a Finding

- App collects a data type (location, contacts, identifiers, health data) that is not declared in the Privacy Label or Data Safety section.
- App shares data with third parties (analytics, ad networks) not disclosed in the "shared with third parties" section.
- App declares "Data Not Collected" for a category but traffic analysis proves otherwise.
- App declares "Data Not Linked to You" for identifiers but traffic shows identifiers sent alongside user account tokens.

### Evidence Standard

Provide the exact Privacy Label/Data Safety declaration text, the network request showing undeclared data collection (with timestamp, destination, and payload), and a comparison table mapping declared versus observed categories.

## Analytics and Telemetry Audit

### What to Test

Identify all analytics, crash reporting, and ad SDKs. Assess whether data collection is proportionate to stated purposes and whether the app developer is aware of what each SDK collects.

### SDK Identification

```bash
# Android: identify analytics SDKs from the APK
jadx -d decompiled target.apk
grep -rn "firebase\|amplitude\|mixpanel\|segment\|flurry\|appsflyer\|adjust\|branch\|kochava\|mparticle\|braze\|clevertap\|crashlytics\|sentry\|bugsnag\|instabug\|datadog\|newrelic" decompiled/

# Check Gradle dependencies
grep -rn "implementation\|api\|compile" decompiled/resources/assets/ decompiled/resources/res/ 2>/dev/null
```

```bash
# iOS: identify analytics frameworks in IPA
unzip -o target.ipa -d target_extracted
# List embedded frameworks
ls target_extracted/Payload/*.app/Frameworks/
# Search binary for SDK class names
strings target_extracted/Payload/*.app/<binary_name> | \
    grep -iE "Firebase|Amplitude|Mixpanel|Segment|AppsFlyer|Adjust|Branch|Crashlytics|Sentry|Bugsnag|DataDog|NewRelic|Braze|CleverTap"
```

### Traffic Analysis by SDK

```python
# analytics_audit.py — categorize analytics traffic by SDK
from mitmproxy import http
import json

SDK_DOMAINS = {
    'Firebase Analytics': ['app-measurement.com', 'firebase-settings.crashlytics.com',
                           'firebaseinstallations.googleapis.com'],
    'Amplitude': ['api2.amplitude.com', 'api.amplitude.com'],
    'Mixpanel': ['api.mixpanel.com', 'decide.mixpanel.com'],
    'Segment': ['api.segment.io', 'cdn.segment.com'],
    'AppsFlyer': ['launches.appsflyer.com', 'events.appsflyer.com',
                  'conversions.appsflyer.com'],
    'Adjust': ['app.adjust.com', 'app.adjust.io'],
    'Branch': ['api.branch.io', 'api2.branch.io'],
    'Crashlytics': ['firebase-settings.crashlytics.com',
                    'reports.crashlytics.com'],
    'Sentry': ['sentry.io', 'o0.ingest.sentry.io'],
    'Braze': ['sdk.iad-01.braze.com', 'rest.iad-01.braze.com'],
    'Facebook': ['graph.facebook.com', 'an.facebook.com'],
    'Google Ads': ['googleads.g.doubleclick.net', 'pagead2.googlesyndication.com'],
}

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host.lower()
    for sdk_name, domains in SDK_DOMAINS.items():
        if any(d in host for d in domains):
            body = flow.request.get_text() or ''
            print(f'\n[ANALYTICS] {sdk_name} -> {host}{flow.request.path}')
            print(f'  Method: {flow.request.method}')
            print(f'  Size: {len(body)} bytes')
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    print(f'  Top-level keys: {list(data.keys())}')
                    # Check for PII in analytics payloads
                    flat = json.dumps(data).lower()
                    pii_signals = ['email', 'phone', 'name', 'address', 'ssn',
                                   'credit_card', 'password', 'location']
                    for signal in pii_signals:
                        if signal in flat:
                            print(f'  [PII-RISK] Contains: {signal}')
            except (json.JSONDecodeError, TypeError):
                pass
            break
```

### Over-Collection Indicators

Check each analytics payload for:
- PII fields (email, phone, name, address) in event properties that are not related to the tracked event.
- Precise location (lat/lng) when the feature being tracked does not need location.
- Full device fingerprint (model + OS + screen + carrier + timezone + locale) when analytics functions without those signals.
- User-generated content (message text, search queries, file names) captured in analytics events.
- Sensitive UI state (screen names like "HIV Test Results", "Bankruptcy Filing", "Pregnancy Tracker") without user awareness.

### What Constitutes a Finding

- Analytics SDK collects PII (email, phone, full name) in standard event payloads without explicit user consent for that specific collection.
- Crash reporting SDK captures full request bodies, auth tokens, or session cookies in crash reports.
- Ad SDK collects precise location when the app's core features do not require location.
- Analytics events capture sensitive screen names or user-generated content that reveals protected health, financial, or personal information.
- Multiple analytics SDKs collect overlapping device identifiers, creating redundant tracking surface without proportionate benefit.

### Evidence Standard

Capture the full analytics request with payload, annotate which fields constitute over-collection, name the SDK and version, and reference the app's privacy policy or privacy label for the stated collection purpose. Quantify the volume: number of analytics requests per session, total payload bytes per session, and unique data types collected.

## Source Anchors

- OWASP MASVS-PRIVACY: https://mas.owasp.org/MASVS/07-MASVS-PRIVACY/
- OWASP MASTG Privacy testing: https://mas.owasp.org/MASTG/tests/ios/MASVS-PRIVACY/ and https://mas.owasp.org/MASTG/tests/android/MASVS-PRIVACY/
- Apple App Tracking Transparency: https://developer.apple.com/documentation/apptrackingtransparency
- Apple Privacy Nutrition Labels: https://developer.apple.com/app-store/app-privacy-details/
- Apple required reason APIs (iOS 17+): https://developer.apple.com/documentation/bundleresources/privacy-manifest-files/describing-use-of-required-reason-api
- Google Play Data Safety: https://support.google.com/googleplay/android-developer/answer/10787469
- Android Privacy Sandbox: https://developer.android.com/design-for-safety/privacy-sandbox
- Android Topics API: https://developer.android.com/design-for-safety/privacy-sandbox/topics
- Android Attribution Reporting: https://developer.android.com/design-for-safety/privacy-sandbox/attribution
- Apple SKAdNetwork: https://developer.apple.com/documentation/storekit/skadnetwork
- Google Play Account Deletion requirement: https://support.google.com/googleplay/android-developer/answer/13327111
- GDPR Right to Erasure: https://gdpr-info.eu/art-17-gdpr/
- Frida JavaScript API: https://frida.re/docs/javascript-api/
- mitmproxy scripting: https://docs.mitmproxy.org/stable/addons-scripting/
