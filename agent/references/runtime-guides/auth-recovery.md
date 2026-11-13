# Credentials, named identities, and auth-expiry recovery

The operator core's "Credential Auto-Use" section states the rule in brief and points here; this guide
holds the procedure. Credentials, `command-run` rows, intel and handoffs are the operator's own working
state (ADR 0019): use them verbatim, never redact them, and never treat the engagement's own test
credentials as a finding. Specialists carry the same statement in `agent/shared-constraints.md`
("Credentials and Local State Are Self-Owned").

## Credential Auto-Use procedure

When any agent discovers a credential, the operator coordinates these steps.

1. **Test it with one login request.** This is mechanical pipeline work, so run it yourself:
   `vigil assess kali exec --technique AUTH --intent "credential validation" --probe-kind baseline --phase <current> --timeout 60 -- <login request>`
   (or a typed verb where one fits), so the audit row records the test.
   - **One identity-reflecting endpoint is the acceptance oracle.** Pick a single route that echoes who
     you are when the credential is good (a session, whoami or profile route, or any response that
     changes with identity) and treat its verdict as authoritative. Another endpoint rejecting the
     credential does not prove it invalid: one surface can refuse what another accepts. "Accepted" means
     the request reached an authenticated, identity-bearing state, not merely that some endpoint
     returned 200. Apply the oracle once per named identity; cross-identity depth needs each identity
     confirmed independently.
   - On failure, record it with `vigil assess log operator "Login test failed" "<command>" "<response>"`
     and continue anonymously. Do not dispatch a specialist for a failed login.
2. **Store a working credential** in the backend credential store:
   `vigil auth import <key> --source - --identity <name>` (or `vigil auth edit <key>`), with
   `use_for_requests` set to `true`.
3. **Re-collect authenticated surface.** Re-dispatch surface-collector so it crawls with the new
   identity and ingests authenticated-only endpoints into the work buffer.
4. **Dispatch `vulnerability-analyst` lanes** over the authenticated surfaces (`hunt_scope: deep`;
   `idor-bac.md` when two identities exist) to test privilege escalation, IDOR and auth-boundary
   weaknesses. What they confirm reaches exploitation through Verify and `exploit_policy` like any other
   finding.

A credential recorded with `status=discovered` through `vigil assess post credentials` flags a candidate
finding automatically and, for a session-artifact secret, mints a usable identity;
`agent/shared-constraints.md` §10 states which secret types mint. One that did not mint still needs
steps 1-2 to become a replayable identity. A leaked cloud key goes to the matching skill after step 1
confirms it is live (operator core "Beyond-Web Surfaces").

## Auth handling rules

- Engagement credentials live in the orchestrator backend credential store, one record per
  `(engagement, identity)`, managed with the `vigil auth` CLI. There is no `auth.json`.
- Proxy-captured logins append one identity per distinct login and never overwrite another identity;
  IDOR/BOLA testing depends on that.
- Age alone never marks a session `dead`; only a proven-dead liveness probe does.
- Missing material or an expired/dead credential: warn and continue anonymously rather than halting.
- That anonymous fallback does not satisfy an authenticated-only objective. When the missing identity
  makes the named surface or cross-identity lane impossible, record a `dispatch_blocked` decision naming
  the identity and surface, return a blocked handoff with the exact refresh or provisioning need, and
  surface it to the human. Continue anonymously only on work that has a real anonymous coverage lane.

## Named identities and cross-identity depth

Access-control depth (IDOR/BOLA/BFLA) is real only across two or more identities. The depth ledger's
`access-control` family on a decisive or high-confidence app unit is satisfied only by a covering probe
recorded under a genuine second identity's `auth_context`. The credential store holds one row per
distinct identity, with one marked active.

```bash
vigil assess auth list --host <host> [--include-dead] [--json]
```

Each row shows the identity name, `auth_context`, `state`, liveness verdict, age, the cookie names it
holds (never raw values) and the hosts it covers; `*` marks the active identity. `stale` rows always
show; `dead` rows only with `--include-dead`.

- A credential imported without `--identity` lands under `default` and is marked active for
  credential-store management, but ordinary `vigil assess kali ...` commands run anonymous unless a
  dispatch passes `--identity`. That keeps audit labels honest and avoids a credential lookup on every
  unauthenticated recon probe.
- Specialists select an identity per request with `vigil assess kali <verb> --identity <name>`. The flag
  stamps the identity as the probe's `auth_context` only when Vigil can inject that material into the
  invocation. Cross-identity depth counts only probes whose recorded `auth_context` names the identity
  that actually ran; a shell wrapper or hand-pasted token may be useful evidence but does not satisfy it.
- Store each hand-captured test account under its own name with `vigil auth import <key> --identity <name>`
  so "which identity ran which probe" stays recordable.
- For two-user replay, point specialists at `agent/skills/idor-testing/SKILL.md` and
  `agent/skills/split-brain-idor/SKILL.md`.

**Per-session liveness.** A populated identity is not proof it is live. `agent/shared-constraints.md` §1
owns the "whoever takes it owns proving it" rule and the `material.liveness` oracle setup. Probe it:

```bash
vigil assess auth status --probe --identity <name> --probe-url <authed-url>   # agent side
vigil auth status --probe --identity <name> --probe-url <authed-url>         # operator side
```

`live` clears a `stale` mark; `dead` is written only by a proven-dead probe, never by hand or by age; a
transport error or missing liveness signature returns `unknown`, never a false verdict. A `dead` verdict
feeds the recovery branch below.

## Auth-expiry recovery

Authenticated dispatches fail in a recognizable shape: 401/403 on routes that were 200 before,
redirect-to-login, a session-expired JSON body, or `WWW-Authenticate: Bearer error="invalid_token"`.
Specialists surface these in handoff `runtime_issues`; a `dead` liveness verdict is the same signal
proven directly. On either signal, recover the auth before re-dispatching; re-dispatching with the same
expired material fails deterministically and burns a context window.

1. **Detect.** Scan recent handoffs and command-run output for the failure shape, and check the identity's
   liveness directly:
   ```bash
   vigil assess agent list --limit 5 \
     | jq -r 'select(.handoff.runtime_issues // [] | tostring | test("401|403|expired|invalid_token|redirect.*login"; "i")) | .agent_id'
   vigil assess command-run list --q "401\|403\|session\|expired" --show-matches --limit 10
   vigil assess auth list --host <host> --include-dead --json
   ```
2. **Decide the refresh path.**
   - **Bearer / API token** in the record's `headers.Authorization`: refresh through the program's
     refresh endpoint if it offers one, or re-run the login flow, then store it with `vigil auth import`
     or `vigil auth edit`. This is a one-shot operator action; do not dispatch a specialist for it.
   - **Session cookie** in `cookies` / `host_cookies[]`: re-capture through mitmproxy-assisted login. The
     proxy addon posts the refreshed cookies to the matching engagement's store by scope and mints a
     fresh identity from the new login; the dead identity stays visible with `--include-dead` until its
     purge.
   - **OAuth/OIDC**: re-run the authorization-code grant against the discovery endpoint; check the record's
     `tokens.refresh_token` first.
3. **Validate.** Re-run the step-1 login check (`vigil assess kali exec --technique AUTH --intent "post-refresh validation" ...`),
   then confirm liveness on the new identity with `vigil assess auth status --probe --identity <name> --probe-url <authed-url>`.
   The audit rows record both the failed and the successful probe.
4. **Re-dispatch only on success**, with a context note: "Auth refreshed at <iso> (new identity `<name>`);
   the previous handoff's 401/403 runtime_issues are stale — re-run the same objective with the refreshed
   credential."
5. **Fall back to anonymous** when the auth cannot be refreshed in-session (MFA challenge, a human needed,
   credentials genuinely expired by the program): record
   `vigil assess agent decision --kind dispatch_blocked --reason "auth expired; awaiting human refresh" --surfaced-to-user`
   and continue against anonymous scope.

Cap recovery at two attempts. When the refreshed auth fails validation twice, treat it as a genuine
credential problem rather than an in-session expiry and take step 5.

## Credential store reference

Each record may hold cookies, headers, `auth_context`, `use_for_requests`, `state`
(`available` / `stale` / `dead` / `expired`), and freshness fields (`created_at`, `last_seen_at`,
`liveness_verdict`, `last_probed_at`).

**Proxy capture.** The shared mitmproxy, when running, posts captures to the matching engagement's store
by scope. Capture is append-only and multi-identity: the identity name is derived server-side from the
capture's session-anchor cookies (or a JWT `sub` / `uid` / `user_id` / `email` claim), so two logins on
one site land as two identities. Reloading an already-captured login refreshes that identity in place;
anonymous pre-login traffic carries no anchor and is not captured.

**Freshness.** A session with no fresh capture for 8h is flagged `stale` (advisory: re-probe before
trusting it); one with no fresh capture for 5 days is purged. A dead identity stays visible with
`vigil assess auth list --include-dead` until its purge, so evidence tied to it stays attributable.

**Manually managed records.** `vigil auth show <key>` dumps the full identity map, e.g.:

```json
{
  "identities": {
    "user_a": { "cookies": {"session": "..."} },
    "user_b": { "cookies": {"session": "..."} },
    "admin":  { "headers": {"Authorization": "Bearer ..."} }
  },
  "active_identity": "user_a"
}
```
