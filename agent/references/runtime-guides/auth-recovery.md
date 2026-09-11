# Auth-expiry recovery loop — the full procedure

Authenticated dispatches fail in a recognizable shape: 401/403 on routes that were 200 yesterday, redirect-to-login, session expired JSON, or a `WWW-Authenticate: Bearer error="invalid_token"` header. Specialists surface these in their handoff `runtime_issues` with auth-expiry keywords. A `vigil assess auth status --probe --identity <name> --probe-url <authed-url>` verdict of `dead` is the same signal, proven directly rather than inferred from a dispatch failure. On either signal, do not blame the specialist or re-dispatch with the same expired material — recover the auth first, then re-dispatch. The operator cue lives inline in `agent/operator-core.md` "Auth-expiry recovery loop"; this guide holds the full recovery branch.

Recovery branch:

1. **Detect.** Scan recent dispatch handoffs and command-run output for the failure shape, and check the identity's own liveness state directly:
   ```bash
   vigil assess agent list --limit 5 \
     | jq -r 'select(.handoff.runtime_issues // [] | tostring | test("401|403|expired|invalid_token|redirect.*login"; "i")) | .agent_id'
   vigil assess command-run list --q "401\|403\|session\|expired" --show-matches --limit 10
   vigil assess auth list --host <host> --include-dead --json
   ```
2. **Decide refresh path.**
   - **Bearer / API token** in the credential record's `headers.Authorization`: refresh via the documented refresh endpoint (if the program offers one) or re-run the login flow, then store it with `vigil auth import`/`vigil auth edit`. Operator action; do NOT dispatch a specialist for a token refresh — the refresh request itself is one-shot mechanical work.
   - **Session cookie** in the credential record's `cookies` / `host_cookies[]`: re-capture via mitmproxy-assisted login. Restart browser flow through the proxy; `proxy_addon.py` POSTs the refreshed cookie set to the matching engagement's credential store automatically (per-engagement routing by scope), which mints a fresh identity from the new login rather than overwriting the dead row — the dead identity stays visible via `--include-dead` until its 5-day purge.
   - **OAuth/OIDC**: re-run the authorization code grant against the discovery endpoint; check the credential record's `tokens.refresh_token` first.
3. **Validate the refresh.** Re-run the same login check from Credential Auto-Use step 1 via `vigil assess kali exec --technique AUTH --intent "post-refresh validation" ...`, then confirm liveness on the new identity by name with `vigil assess auth status --probe --identity <name> --probe-url <authed-url>`. The audit row records both the failed pre-refresh probe and the successful post-refresh probe so the timeline is unambiguous.
4. **Re-dispatch only on success.** Re-dispatch the affected specialist (typically `vulnerability-analyst` or `exploit-developer`) with a dispatch-context note: "Auth refreshed at <iso> (new identity `<name>`); the previous handoff's runtime_issues about 401/403 are stale — re-run from the same task objective with fresh credentials in the engagement's credential store."
5. **Fallback to anonymous.** When the auth cannot be refreshed in-session (MFA challenge, human-in-the-loop required, credentials genuinely expired by the program), record the gap with `vigil assess agent decision --kind dispatch_blocked --reason "auth expired; awaiting human refresh" --surfaced-to-user` and let the dispatch continue against anonymous scope. Do not silently retry against expired material — every retry burns a context window and the failure is deterministic.

Limit step 4 to two attempts. If the refreshed auth fails validation in step 3 twice, treat it as a genuine credential issue (not an in-session expiry) and switch to the fallback branch in step 5.
