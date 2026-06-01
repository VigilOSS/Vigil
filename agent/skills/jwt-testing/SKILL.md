---
name: jwt-testing
description: JWT token attack techniques — alg bypass, key confusion, claim tampering
origin: AI Threat Hunting
---

# JWT Testing (JSON Web Token Attacks)

## When to Activate

- **Scope note:** Use this skill when JWT is the primary auth mechanism. If testing general login bypass where JWT is one component, load `auth-bypass` skill instead — it covers JWT briefly alongside other auth mechanisms. Do not load both skills for the same endpoint.
- Application uses JWT for authentication or authorization
- Tokens visible in cookies, Authorization header, or URL params
- Token structure: `xxxxx.yyyyy.zzzzz` (three base64url segments)

## Tools

- jwt_tool (comprehensive JWT testing)
- jwt.io (decode and inspect)
- hashcat (`-m 16500` for JWT cracking)
- john (jwt2john + wordlist)
- Custom scripts for key confusion

## Methodology

### 1. Decode and Analyze

- [ ] Split token: header.payload.signature
- [ ] Base64url-decode header → check `alg`, `typ`, `kid`, `jku`, `jwk`
- [ ] Base64url-decode payload → check `sub`, `role`, `admin`, `exp`, `iat`, `iss`
- [ ] Note expiration time — is it enforced?
- [ ] Collect multiple tokens — compare structure, observe changing fields
- [ ] Confirm the token is recognised as a JWT and pull a deterministic first-pass variant set
      (the `alg:none` forgery, empty/malformed signatures) before reaching for jwt_tool:
      ```bash
      aith assess classify-payload "$TOKEN" --mutations
      #   type: jwt
      #   escalation: 'eyJhbGciOiJub25l..."role":"admin","sub":"1"}.'   ← ready-to-send alg:none token
      #               '<header>.<payload>.AAAA'                          ← bogus signature
      #   boundary:   '' 'a' (255×a)                                     ← empty / junk-signature variants
      #   empty:      '' 'null' 'undefined' ' ' '\x00'
      ```
      These are starting probes; for full claim editing, secret cracking, and key confusion use
      jwt_tool (the variants below).

### 2. Algorithm None Attack

- [ ] Set header `"alg": "none"` — remove signature
- [ ] Variations: `"alg": "None"`, `"alg": "NONE"`, `"alg": "nOnE"`
- [ ] Empty signature: `header.payload.`
- [ ] Test if server accepts unsigned token

### 3. Weak Secret (HMAC)

- [ ] If `alg: HS256`, brute-force secret:
      `hashcat -m 16500 jwt.txt rockyou.txt`
- [ ] Common secrets: `secret`, `password`, application name, blank string
- [ ] jwt_tool: `python3 jwt_tool.py TOKEN -C -d wordlist.txt`
- [ ] Once secret found, forge arbitrary tokens

### 4. Key Confusion (RS256 → HS256)

- [ ] Obtain public key (JWKS endpoint, TLS cert, `/.well-known/jwks.json`)
- [ ] Change `alg` from `RS256` to `HS256`
- [ ] Sign token with public key as HMAC secret
- [ ] Server may verify HMAC using the public key it already has
- [ ] Try multiple public key formats — server may expect different encoding:
      Raw PEM | PEM with stripped headers | No newlines | Base64-only (no PEM wrapper)
- [ ] Obtain key from: `/.well-known/jwks.json`, `/.well-known/openid-configuration` → jwks_uri, TLS certificate public key

### 5. Claim Tampering

- [ ] Change `sub` to another user ID
- [ ] Change `role` from `user` to `admin`
- [ ] Set `admin: true` or `is_admin: 1`
- [ ] Extend `exp` far into the future
- [ ] Change `iss` to see if validated
- [ ] Add unexpected claims the server may process

### 6. Header Injection Attacks

- [ ] `kid` injection: `"kid": "../../dev/null"` (empty key → trivial signature)
- [ ] `kid` SQL injection: `"kid": "key' UNION SELECT 'secret'--"`
- [ ] `jku` spoofing: point to attacker-controlled JWKS
- [ ] `jwk` embedding: include attacker's key in header
- [ ] `x5u` / `x5c`: point to attacker certificate
- [ ] `kid` path traversal to `/dev/null`: empty key → sign with empty string → valid HMAC
- [ ] `jku` with attacker JWKS: host `{"keys":[{"kty":"RSA","n":"...","e":"AQAB"}]}` at attacker URL
      Change token `jku` header to point to attacker URL → server fetches attacker's key to verify
- [ ] `kid` with SSRF: `"kid": "http://internal-server/key"` — may trigger server-side request

### 7. Token Lifecycle

- [ ] Use expired token — is expiration enforced?
- [ ] Replay token after logout — is it invalidated?
- [ ] Use token after password change
- [ ] Test token refresh mechanism for flaws
- [ ] Check if tokens are stored and revocable server-side

### 8. Cross-Service Attacks

- [ ] Use token from service A on service B (shared key?)
- [ ] Check audience (`aud`) claim validation
- [ ] Test tokens across environments (staging key on production)

## What to Record

- Token algorithm and claims structure
- Attack type that succeeded (none, weak key, confusion, injection)
- Forged token and the access it granted
- Secret recovered (if HMAC brute-force)
- Severity: Critical (forge any user/admin token) or High (privilege escalation)
- Remediation: strong secrets, enforce algorithm allowlist, validate all claims

## Triage a Batch of Token Variants

When you spray many forged tokens at one endpoint (alg-casing set, the `kid`/`jku` injection
matrix in §6, a claim-rewrite sweep), the kill-signal is a response that *breaks from the
rejection cluster* — a `200`, a different status, a different error body. Capture one record per
variant (`url`, `status`, `content_length`, and `title` or `words` if the body carries the error
text) and rank the odd-one-out instead of eyeballing every reply:

```bash
# one {url,status,content_length,title} object per token variant → jwt_variants.jsonl
aith assess anomaly-score jwt_variants.jsonl --top 5
#   #1  score=4.17  status=200  len=842  url=.../api/me   ← the accepted forgery
#       ^ status='200'  ^ title='dashboard'              the rest 401'd with identical bodies
```

The top-ranked record is the variant the verifier treated differently — the accepted `alg:none`,
the `kid` that resolved to an empty key, the claim edit that passed. The oracle surfaces
category-level breaks (status flip, size-class jump, changed error title), so it is the fast path
from "100 variants fired" to "this one validated"; confirm by replaying that single token.

## Kill Signals — Stop Testing When
- alg:none accepted → CRITICAL, record immediately, stop testing other JWT vectors
- HMAC secret cracked → CRITICAL, record and stop
- Key confusion (RS256→HS256) succeeds → CRITICAL, record and stop
- All three above fail AND kid/jku injection returns errors → JWT implementation is robust, test only claim tampering and lifecycle
- Server validates all claims strictly (exp enforced, iss checked, aud validated) → move on

## Escalate When
- The header contains `kid`, `jku`, `jwk`, or `x5u` — each is a distinct injection surface (path traversal in kid, attacker-controlled JWKS URL in jku/x5u, embedded attacker key in jwk), walk all four before moving on
- Changing `alg` casing (`None`, `NONE`, `nOnE`) or trimming the signature produces a different error than an outright-invalid token — the verifier has a normalization gap, push alg-confusion variants and empty-signature acceptance
- Two tokens with different claims but identical signatures are both accepted, or a token signed with a different key validates — signature verification is partial or cached, forge further
- `exp`, `nbf`, `iat` tampering (expired token, future `nbf`, negative `iat`) is not rejected on at least one endpoint — claim validation is applied inconsistently across services, test each authenticated route
- The token carries a `role`, `is_admin`, `tenant_id`, `sub`, `scope`, or similar authorization claim and the signature model allows any of the above — privilege escalation via claim rewrite is the real impact, tamper the claim and replay

## Extended Resources

- `agent/references/payloads/jwt-payloads.md` — alg:none, key confusion (RS256→HS256), JWK/kid injection, weak secret brute-force
