---
name: gf-patterns:secret_vault
description: Credential-store and secrets-manager API path patterns (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, credential-proxy endpoints)
origin: local overlay (no upstream gf equivalent)
bucket: secret_vault
weight: 45
---

# gf: secret_vault

## What this bucket classifies

Credential-store / secrets-manager API endpoints where an attacker can read, enumerate, or
mint secrets when the store is exposed without (or with a weak) token policy. Covers HashiCorp
Vault secret and token-auth backends, AWS Secrets Manager and Azure Key Vault proxy routes, and
generic credential-proxy APIs that retrieve stored secrets by reference. An exposed credential
store is treated as a P1-class finding — hence the highest non-RCE weight in the table.

## Load this reference when

- The corpus contains `/v1/secret`, `/v1/secrets`, `/v1/auth/token`, or `/vault/` paths
  (HashiCorp Vault), `/secretsmanager` (AWS), `/keyvault` (Azure), or generic credential-proxy
  routes (`/credential-stores`, `/credentials/retrieve`, `/values/retrieve`, `/api/secrets`)
- Operator is checking for an unauthenticated or over-permissioned secrets store, a
  credential-proxy that fetches another principal's secret by reference, or token-mint /
  privilege-escalation surfaces on a Vault token backend

## Parameter keys that match

(none)

This bucket is **path-only**: the matching credential-store surfaces have no single canonical
parameter name, so the key set is empty and every match comes from a path fragment. A
secret-bearing query parameter (`?secret=`, `?api_key=`, `?token=`, `?password=`) is captured by
`interestingparams` (weight 15), not here — secret_vault deliberately does not claim those
generic keys, which would flood the bucket with cross-bucket false positives.

## Path patterns that match

HashiCorp Vault (secret engines + token auth):
`/v1/secret`, `/v1/secrets`, `/v1/auth/token`, `/vault/`

AWS Secrets Manager:
`/secretsmanager`

Azure Key Vault:
`/keyvault`

Generic credential-proxy APIs:
`/credential-stores`, `/credentials/retrieve`, `/values/retrieve`, `/api/secrets`

All fragments are boundary-anchored by `fragment_in_path` (the same `re.escape()` + boundary
semantics as `interestingext`'s `.env`/`.bak`). `/v1/secret` resolves to its core `/v1/secret`
plus a boundary, so it matches `/v1/secret` and `/v1/secret/data/...` but does **not** match
`/v1/secretstore`; that is precisely why `/v1/secrets` is listed as a separate fragment rather
than relying on `/v1/secret` to cover it. Likewise `/vault/` requires the trailing slash
boundary so a content slug like `/vault-of-records` does not fire.

## Weight and priority interpretation

- Baseline priority score: 45
- Highest **non-RCE** weight in `_BUCKETS` — tied with `graphql` (45) and below only `rce`
  (50), because an exposed credential store yields immediate, P1-class compromise
- Declared **after** `graphql` in `_BUCKETS`, so if a row ever co-fired both weight-45 buckets,
  `graphql` would keep `cluster_key` by the first-at-max-weight tie-break while `secret_vault`
  is still recorded additively in the `priority_reason` chain
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

HashiCorp Vault:

- `https://target.example/v1/secret/data/prod/db` — KV v2 secret read
- `https://target.example/v1/secrets/myapp/config` — KV secret path
- `https://target.example/v1/auth/token/create` — token backend (mint/escalate)
- `https://target.example/vault/v1/sys/mounts` — Vault behind a `/vault/` proxy prefix

Cloud secrets managers:

- `https://target.example/secretsmanager/getSecretValue?SecretId=prod/api` — AWS Secrets Manager proxy
- `https://target.example/keyvault/secrets/api-key` — Azure Key Vault secret

Credential-proxy APIs:

- `https://target.example/api/credential-stores/1/credentials/retrieve` — credential-store fetch
- `https://target.example/values/retrieve?name=db-password` — generic value-store retrieve
- `https://target.example/api/secrets` — generic secrets API root

## What it does NOT classify

- `/v1/secretstore` (and any `/v1/secret`-prefixed word with no boundary) — excluded by the
  `fragment_in_path` boundary anchor; `/v1/secrets` is listed separately to capture the plural
- A secret-bearing query parameter (`?secret=`, `?api_key=`, `?password=`) — owned by
  `interestingparams` (weight 15); secret_vault carries no parameter keys by design
- A credential FILE on disk (`.pem`, `.key`, `.env`, `.config`) — owned by `interestingext` /
  `debug_logic`, not this bucket
- A bare `/secret`/`/secrets` content slug with no `/v1` or `/api` prefix — deliberately not a
  fragment (it would match marketing/blog paths like `/secrets-of-success`)

## Attack classes

- **Unauthenticated secret read / KV enumeration:** Vault `/v1/secret/data/*` (or a cloud
  proxy) returns plaintext secrets when the store is exposed or the token policy is missing/weak
- **Token mint / privilege escalation:** `/v1/auth/token/create` can issue tokens with broader
  policies than the caller should hold, escalating access across the secrets backend
- **Credential-proxy IDOR / SSRF:** `/credentials/retrieve?id=` or `/values/retrieve?name=`
  returns another principal's credential when the object reference is not authorization-scoped,
  or fetches an internal store via an attacker-controlled reference
- **Cloud secret-store exposure:** an `/secretsmanager` or `/keyvault` proxy that forwards to
  the cloud control plane without re-authenticating leaks managed secrets
- **Vault config / policy disclosure:** `/vault/v1/sys/*` system endpoints reveal mounts,
  policies, and audit configuration that map the secret topology for a follow-on read

## Corpus grounding

Forward-looking coverage. Per the plan's stated goal, the zero-hit buckets (jenkins,
phpmyadmin, wsdl, cloud-metadata, **vault**) size no immediate win against the validated corpus
but provide coverage for future engagements where a credential store is exposed. No DB hits are
recorded for this bucket; its weight (45) ensures that when a Vault / Secrets Manager / Key
Vault surface does appear it is dispatched to a specialist ahead of every
non-RCE bucket. See ADR 0008 and `DRIFT.md` for the accepted rationale.

## Sources

- [HashiCorp Vault — KV secrets engine API](https://developer.hashicorp.com/vault/api-docs/secret/kv)
- [HashiCorp Vault — Token auth method API](https://developer.hashicorp.com/vault/api-docs/auth/token)
- [AWS Secrets Manager — GetSecretValue API reference](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)
- [Azure Key Vault — Secrets REST API (Get Secret)](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret)
- [OWASP API Security Top 10 — API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)

## Related

- `agent/references/gf-patterns/interestingparams.md` — secret-bearing query params (`secret`, `api_key`, `token`, `password`); the parameter-side of the same `secrets-exposure` class
- `agent/references/gf-patterns/interestingEXT.md` — credential FILES (`.pem`, `.key`, `.env`); the file-side of `secrets-exposure`
- `agent/references/gf-patterns/idp_admin.md` — identity-provider token/realm admin surface; `/v1/auth/token` overlaps a Vault token backend vs an IdP token endpoint
- `agent/references/gf-patterns/ssrf.md` — credential stores are frequent SSRF targets (fetch an internal vault via a server-side proxy)
