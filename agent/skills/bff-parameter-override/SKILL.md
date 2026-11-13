---
name: bff-parameter-override
description: Test for hidden middleware/BFF parameters that override backend identity, authorization, or object resolution when supplied by the client
origin: Vigil
vuln_class: mass-assignment, bola
---

# BFF Parameter Override Testing

A BFF, gateway or middleware enriches each request with internal parameters (user identity,
tenant, permissions) before forwarding it. The flaw: (1) the middleware sets parameter X from the
session, (2) it does not strip a client-supplied X, and (3) the backend trusts X because "it comes
from the BFF". The attacker supplies X directly.

## When to Activate

- A BFF/API gateway/Express or Next.js middleware proxies to internal services.
- Source analysis or recon shows parameters used in backend calls but absent from client code.
- The middleware sets identity-bearing parameters (`userId`, `tenantId`, `accountId`) before
  forwarding, or a response echoes a session-derived value (the **mirror parameter**: you are
  `abc123` and the response says `"userId":"abc123"`, so try supplying `userId=xyz789`).

## Mechanics

- `--technique AUTH` for identity override, `IDOR` for object override; `--probe-kind payload`
  for injection, `exploit` for a demonstrated override. `kali exec` also needs `--intent`,
  `--phase`, `--timeout`; run probes as named identities (idor-testing "Vigil mechanics").
- Candidate names come from source-analyzer output, JS API-client wrappers, validation errors,
  OpenAPI specs and echoed responses, then the framework wordlist in
  `agent/references/payloads/bff-override-params.md` (Express, Next.js, Nuxt, DRF, Rails, Spring,
  Kong, Apollo; its "Parameter Location Matrix" gives query/body/header/cookie placement).
  Load it once a BFF/middleware layer is identified.
- Quick-start, highest-yield first regardless of framework: `userId`, `$id$`, `notAuthUserId`,
  `tenantId`, `isAdmin`, `X-User-Id`, `X-Forwarded-User`, `X-Tenant-Id`, `checkPassword`,
  `skipValidation`.
- Inject the wordlist one parameter per request, write one `{url,status,content_length,title}`
  record per parameter (put the parameter name in `url`), and rank with
  `vigil assess anomaly-score <file.jsonl> --top 5`: the honoured override breaks from the
  identical-to-baseline cluster. Confirm the winner with the protocol below.
- No second account: `vigil assess classify-payload "$MY_USER_ID" --mutations` and use its
  escalation/neighbor/boundary variants as override values.

## Override families

- **Identity** — `userId`/`X-User-Id`-style values in any location.
- **Tenant/org** — including sigil-wrapped names (`$agencyId$`, `$originId$`) that some
  middleware use for injected context.
- **Role and bypass flags** — `checkPassword:false`, `nonAuthorizedUpdate`, `skipValidation`,
  `isAdmin`.
- **Object resolution** — `$ownerId$`-style overrides, often on export endpoints.
- Also vary Content-Type and location for each candidate.

## Confirm override vs ignore

1. Baseline as user A. 2. Add the parameter pointing at user B. 3. The response shows B's data.
4. Remove it; the response reverts. 5. Repeat with a third identity to rule out coincidence.
Impact and severity follow `agent/references/finding-fp-and-severity-gate.md` and
`agent/rules/hunting.md` §2: show what the attacker gains (victim data, write to victim account,
cross-tenant read, admin action), not that the parameter is accepted.

## What to Record

The parameter name and the location that achieved the override, whose session ran it and whose
data came back, baseline vs override vs revert evidence. Format:
`agent/references/runtime-guides/web-finding-recording.md`.

## Kill Signals

- Every candidate is rejected with a validation error, or responses are identical regardless of
  value (stripped or ignored).
- The override works only with an admin session: an admin feature, not a vulnerability.
- Content-Type and location variants all produce the same result.

## Escalate When

- One override shows another user's data → test every endpoint with it (account-takeover path).
- It works on writes → demonstrate impact with approval.
- It works unauthenticated → any user's data via the parameter alone.
- Several overrides are accepted together → combine identity + tenant + role.
