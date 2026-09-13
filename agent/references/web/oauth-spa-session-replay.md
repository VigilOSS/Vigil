---
description: Replaying a live SPA session with silent authorization-code plus PKCE, per-host issuer checks, complete gateway envelopes, and a same-batch liveness control; examples use configurable fictional endpoints rather than target-specific credentials.
skill: oauth-oidc-testing
---

# OAuth / OIDC SPA Session Replay

Use this pattern when an authorized browser session remains valid longer than the
SPA's access token. Replaying an expired captured token creates false “unreachable”
results. Reproduce the application's own silent authorization-code plus PKCE flow,
mint immediately before a test batch, and prove liveness against a known own-object
endpoint before interpreting any other response.

This is a replay method, not a universal OAuth recipe. Derive every endpoint,
client ID, redirect URI, scope, and envelope header from the target's own working
SPA flow. The example hostnames are fictional.

## Inputs from the authorized session

Set these from captured browser traffic or the SPA bundle:

```bash
JAR=/engagements/ENGAGEMENT_KEY/auth/user_a.cookies
AUTHORIZE_URL=https://login.acme-bank.example/oauth2/authorize
TOKEN_URL=https://login.acme-bank.example/oauth2/token
CLIENT_ID=spa-client-from-target
REDIRECT_URI=https://app.acme-bank.example/auth/silent-callback
SCOPE='openid profile accounts.read'
LIVE_URL=https://api.acme-bank.example/v1/me
```

Keep the exact values in ordinary engagement evidence. Vigil does not mask the
operator's credentials or tokens.

## 1. Generate PKCE material

```bash
VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" \
  | openssl dgst -binary -sha256 \
  | openssl base64 -A \
  | tr '+/' '-_' \
  | tr -d '=')
STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)
```

## 2. Run the silent authorization request

Use a URL builder rather than hand-concatenating unescaped values:

```bash
AUTH_REQUEST=$(python3 - "$AUTHORIZE_URL" "$CLIENT_ID" "$REDIRECT_URI" \
  "$SCOPE" "$CHALLENGE" "$STATE" "$NONCE" <<'PY'
import sys
from urllib.parse import urlencode

base, client_id, redirect_uri, scope, challenge, state, nonce = sys.argv[1:]
print(base + "?" + urlencode({
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "response_type": "code",
    "code_challenge": challenge,
    "code_challenge_method": "S256",
    "scope": scope,
    "state": state,
    "nonce": nonce,
    "prompt": "none",
    "response_mode": "query",
}))
PY
)

FINAL_URL=$(curl_chrome116 -sSL --max-redirs 5 --max-time 25 \
  -b "$JAR" -c "$JAR" -o /dev/null -w '%{url_effective}' "$AUTH_REQUEST")
CODE=$(python3 - "$FINAL_URL" "$STATE" <<'PY'
import sys
from urllib.parse import parse_qs, urlsplit

values = parse_qs(urlsplit(sys.argv[1]).query)
if values.get("state", [None])[0] != sys.argv[2]:
    raise SystemExit("OAuth state mismatch")
code = values.get("code", [None])[0]
if not code:
    raise SystemExit("silent authorization returned no code")
print(code)
PY
)
```

A bounded CDN interstitial may add one redirect before the callback. Inspect and
retain the chain. Do not treat any redirect as session expiry, and do not follow an
unbounded or off-scope chain.

## 3. Exchange the code

```bash
TOKEN_JSON=$(curl_chrome116 -sS --max-time 25 -b "$JAR" -c "$JAR" \
  -X POST "$TOKEN_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER")
TOKEN=$(printf '%s' "$TOKEN_JSON" | jq -r '.access_token // empty')
[ -n "$TOKEN" ] || { printf '%s\n' "$TOKEN_JSON" >&2; exit 1; }
```

## 4. Present the complete gateway envelope

```bash
CSRF_VALUE=$(awk '$6 == "SessionCsrf" {print $7}' "$JAR" | tail -1)
curl_chrome116 -sS -b "$JAR" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CSRF-Token: $CSRF_VALUE" \
  -H 'Accept: application/json' \
  "$LIVE_URL"
```

The cookie and header names are examples. The real gateway multiline request may
also require device proof, a channel header, or another cookie/header equality
check. If no token, a known-good token, and a different token all produce the same
validation error, diff the SPA's working request header-by-header before declaring
authentication broken.

## 5. Gate every batch on liveness

When the identity is in Vigil's credential store, prefer the shared probe:

```bash
vigil assess auth status \
  --probe \
  --identity user_a \
  --probe-url "$LIVE_URL"
```

Otherwise, run the known own-object request immediately before the batch and assert
its expected status and response signature. If it fails, refresh the identity and
discard path-level conclusions from that batch. A dead-token `401` or `403` is not
evidence that a candidate endpoint is absent.

## Cross-issuer checks

Sibling hosts can use different OAuth issuers. Read
`/.well-known/openid-configuration` on each trust domain and compare
`issuer`, authorization endpoint, audience, and supported scopes. A token working
on `app.acme-bank.example` does not prove that `api.acme-bank.example` accepts it.
Likewise, a BFF accepting a browser token does not prove its internal service uses
the same issuer.

## Common dead ends

- Reusing one captured token long after its expiry.
- Guessing OAuth client metadata instead of deriving it from the target.
- Treating any redirect as session expiry without inspecting its destination.
- Trying more bearer tokens when the unchanged error is from a pre-auth envelope check.
- Calling a response-embedded BFF path directly and assuming it was browser-routable.
- Treating sibling hosts as one trust domain without comparing issuer and audience.
- Recording “unreachable” without a same-batch live control.

## Completion checklist

- OAuth metadata came from the target's own bundle, discovery, or captured request.
- PKCE state was checked and the redirect chain retained.
- The token response and exact scopes were preserved.
- The API request reproduced the working cookies and envelope headers.
- A known own-object control was live in the same batch.
- Issuer and audience were checked per host.
- Failed liveness invalidated the batch rather than becoming endpoint evidence.

## Cross-references

- `agent/skills/browser-automation/SKILL.md`
- `agent/references/recon/cdn-edge-and-bff-reachability.md`
- `agent/references/gf-patterns/oauth-oidc.md`
- `agent/skills/oauth-oidc-testing/SKILL.md`
