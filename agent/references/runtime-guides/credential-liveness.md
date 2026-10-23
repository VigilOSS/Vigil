---
description: Named identity liveness setup and result interpretation before authenticated probing
skill: kali-exec
---

# Credential liveness

Whoever takes an identity for a task owns proving it live: there is NO auto-detection of
where a site handles auth. First declare `material.liveness = {expect_status, authed_marker,
dead_marker}` on that identity (via `vigil auth import`/`edit`), then probe it BY NAME with
`vigil assess auth status --probe --identity <name> --probe-url <authed-endpoint>` before
trusting any result or recording a "dead"/"unreachable" verdict. Pick an `authed_marker` that
appears ONLY when logged in (the logged-in username, an account/settings link, a per-user
CSRF token field) and a `dead_marker` from the login page — the same logged-in/logged-out
markers a DAST scanner (InsightAppSec/Burp) uses to validate a session. Redirects are never
followed.

| Probe result | Resulting state | Meaning |
|---|---|---|
| `authed_marker` matched | `live` | Clears any prior `stale` mark |
| `dead_marker` matched | `dead` | Set only by a proven-dead probe |
| No signature match, or a transport error | `unknown` | Never a false verdict — stays `unknown` rather than guessing |

