---
name: user-enumeration
description: Discover any interface (HTTP, WebSocket, GraphQL, gRPC, or other) that distinguishes between existing and non-existing users through any observable difference
origin: Vigil
vuln_class: user-enumeration
---

# User Enumeration Testing

Any interface that accepts a user identifier (username, email, phone, ID) and answers differently
for existing and non-existing users is a vector, not only HTTP login forms: REST/AJAX/HTML forms,
WebSocket messages, GraphQL (error code, `null` vs object), gRPC (`NOT_FOUND` vs
`PERMISSION_DENIED`), SMTP `VRFY`/`RCPT TO`, LDAP bind, SSO home-realm discovery (the redirect
target differs per user), and mobile APIs (often less protected than web).

`--technique USER-ENUMERATION` (credits this skill's class). Run probes inside
`vigil assess kali exec … --intent … --phase consume-test --timeout <N>` or a typed verb.

## Observable differences

Error message, status code, body size, JSON structure, redirect target, `Set-Cookie` for valid
users only, different rate-limit headers, WebSocket frame type, GraphQL `errors`, gRPC status, and
**timing**: with identical messages, the valid-user path is often 50-200 ms slower because the
password hash is computed. Take at least 5 samples for each identifier and compare averages.

## Method

1. Surfaces: login, registration, password reset, `check-email`/`check-username`/`check-phone`
   style endpoints, OTP send, profile lookups, plus the non-HTTP interfaces above.
2. Send a definitely-invalid identifier and a likely-valid one (`admin`, `test`, a known
   account); any consistent difference is the oracle. OTP-send endpoints often leak existence, and
   an unthrottled one also costs the owner SMS money.
3. For more than a couple of probes, rank the population instead of diffing pairs: one
   `{url,status,content_length,title|words|lines}` record per identifier, then
   `vigil assess anomaly-score <file> --top 10`; identifiers at the top broke from the not-found
   cluster. A flat ranking means not enumerable *on the attributes captured*; it does not model
   timing, so check that separately.
4. Wordlist sweep with the typed verb; POST bodies go through `--extra-args`:

   ```bash
   vigil assess kali ffuf --technique USER-ENUMERATION --intent "username enumeration on login" \
     --probe-kind payload --phase consume-test --timeout 600 \
     -u "https://target.example/api/login" -w /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt \
     -H "Content-Type: application/json" \
     -o /engagements/$ENGAGEMENT_KEY/scans/user_enum.json -of json \
     --extra-args "-X POST -d '{\"username\":\"FUZZ\",\"password\":\"invalid\"}'"
   # rank without guessing a filter (anomaly-score expects content_type with an underscore):
   jq '[.results[] | {url, status, length, words, lines, content_type: .["content-type"]}]' \
     "$ENGAGEMENT_DIR/scans/user_enum.json" > "$ENGAGEMENT_DIR/scans/enum_pop.json"
   vigil assess anomaly-score "$ENGAGEMENT_DIR/scans/enum_pop.json" --top 10
   ```

## What to Record

The interface, parameter and the exact observable difference (valid vs invalid response), a
small confirmed sample, and whether the interface is rate-limited. Severity follows
`agent/references/finding-fp-and-severity-gate.md`: an existence oracle alone is usually a
downgrade; it rises with what it enables (an unthrottled login on an enumerated account, a
documented chain). Credential stuffing with breach data needs explicit ROE. Format:
`agent/references/runtime-guides/web-finding-recording.md`. Related: `rate-limit-bypass`
(throttling on the oracle), `auth-bypass` (what the enumerated accounts unlock).
