---
description: Detecting a WAF/edge block before it burns the engagement — AWS-WAF+CloudFront signatures (403 + `server: CloudFront` + `x-cache: Error from cloudfront`, the example-rate-rule rate-based rule) vs a per-request WAF deny vs an estate-wide IP/rate block; the load-bearing rule that a WAF challenge is PENDING, never a clean negative (hunting.md rule 23d); aggregate request-rate budgeting across ALL concurrent dispatches sharing one egress IP; finding a WAF-clean routing path (worked example: `*.acme-portal.example/~api/...` vs bare `/people/v2/`); and a brief pointer to request-mutation bypass classes. Consolidates wafw00f.md detection + sqlmap.md's tamper-script map into one field reference instead of duplicating them.
skill: web-recon
---

# WAF Bypass & Safe Testing

Field reference for recognizing a WAF/edge block, not misreading it as a target verdict, and
staying under the trigger threshold on a shared egress IP. This file does not re-teach WAF
*identification* (`wafw00f.md`) or the sqlmap tamper-script catalog (`sqlmap.md`) — it
consolidates the safe-testing discipline around them and cross-references both.

## A. Detecting a WAF / edge block

**AWS WAF + CloudFront signature.** A `403` with `server: CloudFront` and
`x-cache: Error from cloudfront` is the edge rejecting the request before it reaches the
origin — not an application-level `403`. Treat any response carrying this header pair as an
edge artifact, not app behavior. A CloudFront-fronted estate that runs AWS WAF commonly
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
| Rate-429 / rate-based IP block | Control also `403`/`429`/`000` | The egress IP/session is blocked — stop hammering, step down to serial |
| Per-path authorization `403` | Control returns `200`, other paths differ consistently | A real access-control answer, not the WAF — this is signal |

Full disambiguation table, the WAF trigger matrix (which probe classes get inspected vs pass
straight through), and Bot-Manager scanner-UA blocks:
`agent/references/runtime-guides/cdn-edge-behavior.md`.

## B. Safe-testing discipline (LOAD-BEARING)

**A WAF challenge / CloudFront 403 block is PENDING, never a clean negative.** This is
`agent/rules/hunting.md` rule 23(d): the response belongs to the edge, not the application
behind it. It proves neither presence nor absence of a finding and decides nothing about the
surface. Do not record a WAF-blocked lane as "clean," "ruled out," "patched," or
"not-present" — re-render with `vigil assess kali browser <url>` (headless Chromium executes
the challenge JS and returns the real origin response) before closing the lead.

**Back off on an estate-wide IP block instead of pushing through it.** Once the control
request in §A also fails, every subsequent response from that egress is a **false-403
"verdict"** — a blocked egress produces uniform `403`/`429`/`000` regardless of what you send,
and continuing to probe just accumulates noise that looks like target behavior but isn't.
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
  nuclei/DNS; this file adds the aggregate-across-dispatches budget on top of it.
- `agent/rules/hunting.md` rule 23(d) (WAF challenge is PENDING) and rule 23a (aggregate-rate
  discipline / `kali job` vs orphaned `kali exec`).
