---
name: jwt-testing
description: JWT token attack techniques — alg bypass, key confusion, claim tampering
origin: Vigil
vuln_class: jwt
---

# JWT Testing (JSON Web Token Attacks)

## When to Activate

- A JWT is the auth or authorization carrier for the endpoint under test. `auth-bypass` routes
  token attacks here; use one skill per endpoint so the token work has one owner.

`--technique JWT`. `jwt_tool` and `hashcat -m 16500` are in the runtime. Payload recipes (alg:none,
RS256→HS256, JWK/JKU/kid injection, weak-secret cracking, null signature CVE-2020-28042, JWKS
endpoints to probe) are in `agent/references/payloads/jwt-payloads.md`; load it when you start
forging.

## Methodology

1. **First pass:** `vigil assess classify-payload "$TOKEN" --mutations` confirms the type and emits
   a ready alg:none forgery plus bogus/empty-signature variants; then jwt_tool for claim edits,
   cracking and key confusion.
2. **Standard attack families** (recipes in the reference): alg:none including casing variants
   and an empty signature; weak HMAC secret; RS→HS key confusion; JWK/JKU/x5u/x5c/kid header
   injection; claim tampering (`sub`, `role`, `is_admin`, `tenant_id`, `scope`, `exp`/`nbf`/`iat`,
   `iss`, unexpected claims).
3. **Key-confusion encodings:** servers expect different encodings of the public key used as the
   HMAC secret; try raw PEM, PEM with headers stripped, no newlines, base64 without the wrapper.
   Keys come from `/.well-known/jwks.json`, `openid-configuration` → `jwks_uri`, or the TLS cert.
4. **URL-bearing headers** (`jku`, `x5u`, a URL in `kid`) make the verifier fetch. The OOB server only records
   the fetch and serves no content (`agent/references/offensive-tactics/frp-tunneling.md` "What a
   callback proves, and hosted payloads"), so a JWKS must be served from the operator-provisioned
   listener (`$DIR/.listener_url`, `agent/shared-constraints.md` §12); without one, record the
   technique as blocked. A fetch proves egress/SSRF, not that the forged key was
   accepted; acceptance is the forged token reaching an authorized response.
5. **Lifecycle:** expiry, logout, password change, refresh and revocation
   (`agent/references/api-security/API02-broken-authentication.md`).
6. **Cross-service and environment:** a token from service A on service B (shared key), `aud`
   validation, a staging key accepted on production.

**Batch triage.** When spraying variants (alg-casing set, header-injection matrix, claim sweep),
write one `{url,status,content_length,title}` record per variant and rank with
`vigil assess anomaly-score <file.jsonl> --top 5`; the accepted forgery breaks from the rejection
cluster. Confirm by replaying that single token.

## Kill and escalate

- An accepted forgery (alg:none, cracked secret, key confusion) is a candidate whose severity is
  what the forged token can reach (`agent/references/finding-fp-and-severity-gate.md`): prove the
  authorized action, then check sibling services and endpoints, which may verify differently
  (`agent/rules/hunting.md` §6).
- All three fail and header injection errors out → test only claim tampering and lifecycle; strict
  claim validation everywhere → move on.
- Escalate when: alg casing or a trimmed signature yields a *different* error than an invalid token
  (a normalisation gap); different claims with the same signature, or a foreign key, validate
  (partial or cached verification); time-claim tampering passes on at least one endpoint; the token
  carries an authorization claim and any forgery path exists (claim rewrite is the real impact).

## What to Record

Algorithm and claim structure, the attack that worked, the forged token and the access it granted,
any recovered secret. Format: `agent/references/runtime-guides/web-finding-recording.md`.
