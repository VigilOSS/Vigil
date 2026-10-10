---
description: Detecting a WAF/edge block before it burns the engagement — per-request denial vs estate-wide rate or reputation blocks, fail-visible pending verdicts, aggregate egress budgeting, alternate clean routes, and request-mutation classes. Examples use fictional targets.
skill: web-recon
---

# WAF Bypass & Safe Testing

Field reference for recognizing a WAF/edge block, not misreading it as a target verdict, and
staying under the trigger threshold on a shared egress IP. This file does not re-teach WAF
*identification* (`wafw00f.md`) or the sqlmap tamper-script catalog (`sqlmap.md`) — it
consolidates the safe-testing discipline around them and cross-references both.

## A. Detecting a WAF / edge block

**CloudFront/S3 edge-block envelope.** A `403` with a CloudFront/AmazonS3 server
banner, `x-cache: Error from cloudfront`, and no application `x-request-id` is
evidence that this response was generated at the edge rather than by the application.
That full conjunction is deployment-specific evidence, not a universal AWS-WAF signature;
CloudFront/S3 headers by themselves identify infrastructure only. A CloudFront-fronted estate that runs AWS WAF commonly
enforces a **rate-based rule**
that trips on request volume from a single source IP within a rolling window, independent of
payload content — see §C before you conclude a host is "protected everywhere."

**Run `wafw00f` first.** `agent/references/tools/recon/wafw00f.md` is the first tool in the
mandatory recon order specifically because the WAF tier it identifies drives every later
tool's rate profile. Do not fingerprint a WAF ad hoc with raw curl — the resulting rate
profile is guesswork instead of evidence.

**Distinguish a per-request deny from an estate-wide IP/rate block.** These are different
failures with different fixes. Immediately after any `403`, send a known-good control request
(apex `/`, `/robots.txt`) over the same connection/egress:

| Shape | Control request result | What it means |
|---|---|---|
| Payload-403 (WAF signature match) | Control returns `200` | The edge denied *this* request only — no reputation penalty, host is live, keep testing (re-encode or pivot the probe) |
| Possible rate/IP/egress block | Control also `403`/`429`/`000` | Inconclusive from one control: stop hammering, retain both responses, then repeat across another known-good control/route before assigning the cause |
| Per-path authorization `403` | Control returns `200`, other paths differ consistently | A real access-control answer, not the WAF — this is signal |

Full disambiguation table, the WAF trigger matrix (which probe classes get inspected vs pass
straight through), and Bot-Manager scanner-UA blocks:
`agent/references/runtime-guides/cdn-edge-behavior.md`.

## B. Safe-testing discipline (LOAD-BEARING)

**A fingerprint-based edge 403 (the §A AWS-WAF + CloudFront signature) is PENDING, never a
clean negative.** The response belongs to the edge, not the application behind it, so it proves
neither presence nor absence of a finding and decides nothing about the surface. This is
`agent/rules/hunting.md` rule 23 in its general form — a non-conclusive response is a LEAD, not
a verdict. Do not record a WAF-blocked lane as "clean," "ruled out," "patched," or
"not-present." **The remedy is NOT a browser re-render.** A signature/fingerprint block matches
on the request bytes and returns the same `403` to headless Chromium — there is no challenge JS
for the browser to execute, so `kali browser` changes nothing here. Get past a fingerprint block
by re-encoding / pivoting the probe past the signature (§E) or by finding a WAF-clean sibling
route (§D).

*(Distinct case — do not conflate.)* A true **JS / bot-challenge interstitial** — Imperva
`reese84` / *"Pardon Our Interruption,"* Akamai `_abck` / *"Access Denied,"* Cloudflare
`cf-chl` / *"Just a moment"* — is the one place `agent/rules/hunting.md` rule 23(d) prescribes
`vigil assess kali browser <url>`: there the bytes ARE a challenge page whose JS the headless
browser executes to reach the real origin. The AWS-WAF + CloudFront deny in §A is a hard
signature block, not a solvable challenge, so 23(d)'s browser-re-render remedy does not apply to
it.

**Back off on a possible estate-wide IP block instead of pushing through it.** A failed
control makes the check inconclusive; it does not prove that every host/route is unreachable or
that egress reputation is the cause. Uniform `403`/`429`/`000` across repeated, independent
controls is supporting evidence, while route-specific variation disproves an estate-wide claim.
Continuing at volume just accumulates noise that looks like target behavior but isn't.
Cross to `agent/references/runtime-guides/cdn-ip-blocking.md` for the mitigation ladder
(program allowlist → browser-based tool → residential proxy → accept-and-document-gap).

## C. Aggregate-rate avoidance

The WAF sees the **sum** of every concurrent dispatch against the same estate over the shared
runtime egress IP, not any one dispatch in isolation. Four agents each issuing a "safe" 5 r/s
look like one client doing 20 r/s at the edge — the aggregate, not the per-dispatch rate, is
what trips a rate-based rule like the one in §A.

- **Budget the AGGREGATE request rate across ALL concurrent dispatches**, not per-dispatch.
  Before adding another concurrent agent against a WAF-fronted estate, sum the rates already
  in flight and confirm the total still sits under the tier's ceiling
  (`agent/references/recon/rate-calibration.md`).
- This is an operator-authored coordination budget, not a backend reservation.
  Pass the exact instruction through each dispatch's `--rate-budget`; the CLI's
  pre-run advisory reports recorded target-facing **commands** and latest timing,
  not request totals, and never blocks or claims enforcement.
- **Serialize inherently high-volume tools** — `arjun`, `ffuf`, a large `nuclei` sweep —
  instead of running them alongside multiple deep specialist agents on the same estate. Run
  the high-volume tool alone, or scope it to a handful of endpoints at a low rate, while other
  agents are live against the same edge.
- The full guardrail, including the `kali job`-vs-orphaned-`kali exec` failure mode, is
  `agent/rules/hunting.md` rule 23a.

## D. WAF-clean routing intel

WAF rules are frequently scoped to a **path or host**, not the whole estate — a blocked route
often has a sibling that reaches the same data cleanly. Finding that sibling is worth the
recon time before accepting a WAF as a hard wall.

**Synthetic routing example.** On `*.acme-planner.example`, the SPA's
`<app>.acme-planner.example/gateway/...` route may remain stable while a direct
`api.acme-planner.example/v2/...` route triggers a rate-based edge policy. Confirm both
routes from captured application behavior; use the route the authorized client actually
uses, and preserve the differential rather than assuming the alternate route is a bypass.

Generalize this: when one route on a CDN-fronted estate is WAF-hostile, check whether a BFF
proxy path, an internal API gateway alias, or a differently-versioned route reaches the same
resource without tripping the same rule — confirm with the disambiguation probe in §A before
relying on it for volume.

## E. Request-mutation bypasses (brief)

Only where authorized and safe for the target — these mutate the request to slip past a
signature match, not to defeat a rate/IP block (§B/§C are the answer there):

- **Body-inspection padding** — oversized or junk body content that pushes the payload past
  the WAF's inspection byte limit.
- **Encoding / case variation** — mixed case, URL-encoding, double-encoding, Unicode
  normalization tricks on the payload.
- **HTTP parameter pollution** — duplicate parameter names/values that the WAF and the origin
  parse differently.
- **Chunked transfer encoding** — some WAFs inspect the un-chunked body incompletely or not
  at all.
- **Origin-IP direct-to-origin** — bypassing the edge entirely by resolving and hitting the
  origin IP directly, when the origin is reachable and the ROE permits it.

For the concrete sqlmap `--tamper` script map (space/case/quote/encoding evasions), see
`agent/references/tools/exploitation/sqlmap.md` "Tamper Scripts" — this file does not
reproduce it.

## Cross-references

- `agent/references/tools/recon/wafw00f.md` — WAF identification/fingerprinting, run FIRST in
  the recon sequence, WAF-tier → rate-profile table.
- `agent/references/tools/exploitation/sqlmap.md` "Tamper Scripts" — the canonical
  `--tamper` script map for signature evasion.
- `agent/references/runtime-guides/cdn-edge-behavior.md` — full 403 disambiguation triad, WAF
  trigger matrix, Bot-Manager UA blocks, safe crawl rates and cooldown behavior.
- `agent/references/runtime-guides/cdn-ip-blocking.md` — detecting and mitigating an
  estate-wide egress IP reputation block (the failure mode in §B).
- `agent/references/recon/cdn-edge-and-bff-reachability.md` — reading the edge error envelope
  to classify a path as not-exposed vs edge-authz-denied vs origin-answered.
- `agent/references/recon/rate-calibration.md` — per-target-trait rate table for nmap/dir-fuzz/
  nuclei/DNS; this file adds the operator-authored lane budget and observed-command advisory.
- `agent/rules/hunting.md` rule 23 (general — a non-conclusive/edge response is a LEAD, not a
  verdict; the frame for a fingerprint 403 in §B), rule 23(d) (the JS/bot-challenge interstitial
  special case where a browser re-render IS the fix), and rule 23a (authored-budget discipline /
  `kali job` vs orphaned `kali exec`).
