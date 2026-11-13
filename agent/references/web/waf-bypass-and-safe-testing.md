---
description: Detecting a WAF/edge block before it burns the engagement — per-request denial vs estate-wide rate or reputation blocks, fail-visible pending verdicts, aggregate egress budgeting, alternate clean routes, and request-mutation classes. Examples use fictional targets.
skill: web-recon
---

# WAF Bypass & Safe Testing

Recognizing a WAF/edge block, not misreading it as a target verdict, and staying under the trigger
threshold on a shared egress IP. WAF identification is `agent/references/tools/recon/wafw00f.md`
(run it first: the tier it names sets every later tool's rate); the sqlmap tamper map is
`agent/references/tools/exploitation/sqlmap.md` "Tamper Scripts".

## A. Detecting a WAF / edge block

**CloudFront/S3 edge-block envelope.** A `403` with a CloudFront/AmazonS3 server banner,
`x-cache: Error from cloudfront`, and no application `x-request-id` is evidence that the edge, not
the application, generated the response. That full conjunction is deployment-specific evidence,
not a universal AWS-WAF signature; CloudFront/S3 headers alone identify infrastructure only. A
CloudFront-fronted estate that runs AWS WAF commonly enforces a rate-based rule that trips on
request volume from one source IP within a rolling window, independent of payload content (§C),
before you conclude a host is "protected everywhere."

**Distinguish a per-request deny from an estate-wide IP/rate block.** Immediately after any `403`,
send a known-good control request (apex `/`, `/robots.txt`) over the same egress:

| Shape | Control request result | What it means |
|---|---|---|
| Payload-403 (WAF signature match) | Control returns `200` | The edge denied *this* request only — no reputation penalty, host is live, keep testing (re-encode or pivot the probe) |
| Possible rate/IP/egress block | Control also `403`/`429`/`000` | Inconclusive from one control: stop hammering, retain both responses, then repeat across another known-good control/route before assigning the cause |
| Per-path authorization `403` | Control returns `200`, other paths differ consistently | A real access-control answer, not the WAF — this is signal |

The full disambiguation triad, the WAF trigger matrix (which probe classes get inspected and which
pass straight through) and Bot-Manager scanner-UA blocks are in
`agent/references/runtime-guides/cdn-edge-behavior.md`; reading an edge error envelope to classify
a path as unrouted, edge-denied or origin-answered is
`agent/references/recon/cdn-edge-and-bff-reachability.md`.

## B. Safe-testing discipline (LOAD-BEARING)

**A fingerprint-based edge 403 (the §A AWS-WAF + CloudFront signature) is PENDING, never a clean
negative** (`agent/rules/hunting.md` §12). The response belongs to the edge, so it proves neither
presence nor absence of a finding; do not record a WAF-blocked lane as clean, ruled out, patched or
not-present. A browser re-render does not help here: a signature block matches the request bytes and
returns the same `403` to headless Chromium, with no challenge JS to execute. Get past it by
re-encoding or pivoting the probe past the signature (§E) or by finding a WAF-clean sibling route
(§D).

A true JS / bot-challenge interstitial is the distinct case: Imperva `reese84` / "Pardon Our
Interruption", Akamai `_abck` / "Access Denied", Cloudflare `cf-chl` / "Just a moment". There the
bytes are a challenge page, and `agent/rules/hunting.md` §12(d) prescribes
`vigil assess kali browser <url>` so the headless browser runs the JS and reaches the origin. The
hard signature block in §A is not a solvable challenge, so that remedy does not apply to it.

**Back off on a possible estate-wide IP block instead of pushing through it.** A failed control
makes the check inconclusive; it does not prove every route is unreachable or that egress reputation
is the cause. Uniform `403`/`429`/`000` across repeated, independent controls supports it, and
route-specific variation disproves it. Continuing at volume only adds noise that looks like target
behavior. The mitigation ladder (program allowlist, browser-based tool, residential proxy,
accept-and-document-gap) is `agent/references/runtime-guides/cdn-ip-blocking.md`.

## C. Aggregate-rate avoidance

The WAF sees the sum of every concurrent dispatch against the estate over the shared runtime egress
IP: four lanes at a "safe" 5 r/s look like one client at 20 r/s, which is what trips a rate-based
rule like the one in §A. Sum the rates in flight against the tier's ceiling
(`agent/references/recon/rate-calibration.md`) before adding a lane, and serialize high-volume tools
(`arjun`, `ffuf`, a large `nuclei` sweep) rather than running them beside deep specialist lanes on
the same edge (`agent/rules/hunting-operator.md` §2, which also covers `kali job` versus an orphaned
`kali exec`).

The aggregate budget is operator-authored coordination, not a backend reservation: pass the exact
instruction through each dispatch's `--rate-budget`. The CLI's pre-run advisory reports recorded
target-facing commands and their latest timing, not request totals, and never blocks or claims
enforcement.

## D. WAF-clean routing intel

WAF rules are often scoped to a path or host rather than the whole estate, so a blocked route often
has a sibling that reaches the same data cleanly. Finding it is worth the recon time before accepting
a WAF as a hard wall.

**Synthetic routing example.** On `*.acme-planner.example`, the SPA's
`<app>.acme-planner.example/gateway/...` route may remain stable while a direct
`api.acme-planner.example/v2/...` route triggers a rate-based edge policy. Confirm both routes from
captured application behavior, use the route the authorized client actually uses, and preserve the
differential rather than assuming the alternate route is a bypass.

When one route on a CDN-fronted estate is WAF-hostile, check whether a BFF proxy path, an internal
API gateway alias or a differently versioned route reaches the same resource without the same rule,
and confirm it with the §A control probe before relying on it for volume.

## E. Request-mutation bypasses (brief)

Only where authorized and safe for the target. These slip a payload past a signature match; they do
nothing for a rate or IP block (§B, §C). The standard classes apply (inspection-limit body padding,
encoding and case variation, parameter pollution, chunked bodies, direct-to-origin when the origin is
reachable and the ROE permits it).

SQLi-specific shapes that still slip past common WAFs: parameter pollution where the origin uses
the last value and the WAF inspects the first (seen against AWS ALB + WAF); weaker inspection of
nested `application/json` bodies; chunked bodies split across the keyword; fullwidth characters
(`%EF%BC%87`) that `utf8mb4` backends normalise to a quote; double URL-encoding only where the
app decodes twice; the same request as GET (clean) and POST (payload); numeric-context payloads
(`1 AND 1=1`) that contain none of the quote characters string-oriented rules key on. Identify
the WAF vendor first and pick targeted shapes rather than spraying tamper scripts.
