---
description: kali browser (audited Playwright/system-Chromium) as the recovery path for a waf_challenge result — when it applies, the --identity refusal states, the steps-file shape, and pointers to the contract for attribution scope, waiting and timeout budgeting
skill: web-recon
---

# kali browser

`vigil assess kali browser` drives Playwright against the runtime's system Chromium (no Selenium or
chromedriver) and returns the origin HTTP status, final DOM, screenshot, bounded console/network
metadata, route candidates and typed-step results. Attribution routing by scope, the
waiting flags, the `--timeout` budget WARN, HAR/body capture and storage-state rules are in
`vigil assess contract kali browser`; examples there too, flags in `--help`.

## When to reach for it

`kali_exec` runs a WAF/bot-challenge detector (`kali_output.detect_waf_challenge`) on every HTTP
prober run. A Cloudflare "Just a moment", Akamai "Access Denied", Imperva "Pardon Our
Interruption" or generic JS-only challenge shell surfaces as `status='waf_challenge'`: that body is
the WAF's, so it is no target verdict (`agent/rules/hunting.md` "A non-conclusive response is a
lead, not a verdict"). A headless render executes the challenge JS, which clears most JS
challenges, so the DOM and captured origin status reflect the application. Use it only for a
JS/bot interstitial: a hard signature or edge block usually survives the same browser egress and
needs a route, request-shape or egress correction instead.

## Identity and state

`--identity <name>` resolves that identity's cookies/headers and stamps the run. The run is
refused rather than downgraded to anonymous when the identity is missing, `dead` or quarantined
(`use_for_requests: false`), or carries nothing injectable for the host, because an `auth_context`
stamp without credentials destroys cross-identity evidence. A `stale` (8-hour flag) identity is
still replayed with a warning. Identity headers follow the hosts the run was told to visit (the
initial URL and each `navigate` step); cookies follow Chromium's domain/path scoping.

## Steps file

`--steps-file` takes up to 50 typed actions; unknown actions or fields, non-HTTP navigation and
excessive timeouts fail before launch. A failed step still writes the screenshot/DOM and exits
non-zero rather than reading as completed coverage.

```json
[
  {"action": "fill", "selector": "#search", "value": "invoice"},
  {"action": "click", "selector": "button[type=submit]"},
  {"action": "wait", "selector": "#results", "state": "visible", "timeout_ms": 10000},
  {"action": "assert", "selector": "#results", "contains": "invoice"}
]
```

Pass `--destructive` whenever the URL or any step can change target state.
