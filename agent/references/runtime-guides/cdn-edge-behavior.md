---
description: Target-edge defensive behavior — disambiguating a per-request payload-403 WAF deny (no reputation penalty; do NOT abandon the host) from a rate-429/IP block (session/egress killer); the WAF trigger matrix; Bot-Manager scanner-UA blocks (use a realistic browser UA); safe sustained crawl rates and per-host katana settings; preview/nonprod edge reputation cooldown. Vendor-trait-keyed with Akamai as the worked example. Distinct from cdn-ip-blocking.md (our egress-IP reputation).
skill: web-recon
---

# CDN / Edge Defensive Behavior — reading the target edge's reactions

This reference is about **the target edge defending itself against your probe** —
which probes it denies, how it denies them, and how to tell a per-request denial
apart from a block that has killed your session. It is **distinct** from
`agent/references/runtime-guides/cdn-ip-blocking.md`, which covers the opposite
concern: when **our own runtime egress IP** is on a CDN reputation list and all
of our recon collapses into uninformative 403s. Read that one when *every* host
goes dark from our side; read *this* one when a *specific probe* is denied but the
host is otherwise responsive.

Vendor names below are **trait-match examples**, not canonical categories. The
worked example is **Akamai** (App & API Protector WAF + Bot Manager, observed
against an edge-protected CMS), but the same shapes appear on
Cloudflare WAF + Bot Management, Fastly/Signal Sciences, AWS WAF + CloudFront,
and Imperva. Match the row on the behavior, not the brand.

## Why this matters

The single most expensive mistake against a CDN-fronted target is **reading a
per-request WAF deny as a dead host or a global block** and abandoning the host
(or the whole engagement). A `403` to a `../` or SQLi probe almost always means
the **edge denied that one request** — the next clean request to the same host
returns `200`. Treating it as "host down / patched / blocked" produces a false
negative and burns a coverage lane. The disambiguation below is the load-bearing
skill; everything else is supporting detail.

## A. 403 disambiguation — three different 403s

A `403` is not one signal. Classify which of these you are looking at **before**
recording any verdict:

| Shape | Cause | Reputation penalty? | What it means for you |
|---|---|---|---|
| **Payload-403 (WAF deny)** | The request path/body matched a WAF signature (traversal, SQLi, XSS, cmd-injection, `/etc/passwd`) | **None** on production edge — clean requests immediately before/after return normal | The edge denied *this request*. Do **not** abandon the host. Re-encode/obfuscate the payload or pivot to a non-signatured probe. |
| **Rate-429 / rate-based IP block** | Too many requests from your egress IP in a window | **Yes** — the IP/session is blocked, often kills the user's shared-egress session | Go low-and-slow / serial; this is the session killer. Pair with the egress mitigations in `cdn-ip-blocking.md`. |
| **Per-path authorization 403** | The app (or edge ACL) genuinely forbids this path for this identity | N/A | A real access-control answer — varies by path, consistent across rate/UA. This is signal, not noise. |

**The disambiguation probe (do this every time).** Immediately after a `403`,
send a **known-good control request** (the apex `/`, `/robots.txt`, a public
asset) over the same connection/egress:

- Control returns **200** → the `403` was **per-request** (payload-403 or
  per-path authz). The host is live. Keep testing it; just change the probe.
- Control also returns **403 / 429 / 000** → the check is **inconclusive**, with a
  possible rate/IP/egress block. Stop hammering, retain both response shapes, and
  repeat against an independent known-good control/route before assigning the
  cause (cross to `cdn-ip-blocking.md`). One control cannot prove an estate-wide,
  per-host, or per-route reachability claim.

On the Akamai CMS, a request with a literal `..`, `%2e%2e`, `/etc/passwd`, SQLi
metacharacters, `<script>`/`<img onerror>`, or a command-injection pattern
returned a **per-request HTTP 403 Akamai WAF deny — not a 429, not a global
block**. A clean request one line later returned `200`. **Production edge applied
no reputation penalty after a WAF deny.**

## B. WAF trigger matrix — which probe classes the edge inspects

Not every malicious-looking probe is edge-inspected. Knowing what the edge
*normalizes*, what it *denies*, and what it *passes straight through* tells you
where the edge is the obstacle vs. where you are actually reaching the origin.
Observed Akamai behavior (use as the starting hypothesis; re-confirm per target):

| Probe class | Edge behavior | Status |
|---|---|---|
| Literal traversal (`/../../`) | Path-normalized by the edge before routing | `404` (normalized away — **not** a WAF deny) |
| `/etc/passwd` in path | WAF signature match | `403` |
| Encoded traversal (`%2e%2e`, double-encoded) | WAF signature match | `403` |
| SQLi metacharacters | WAF signature match | `403` |
| XSS (`<script>`, `<img onerror=>`) | WAF signature match | `403` |
| Command-injection patterns | WAF signature match | `403` |
| Null byte (`%00`) | Not WAF-inspected | passes to origin |
| RFI / URL-in-param (`?u=http://…`) | Not WAF-inspected | passes to origin |
| Long path / oversized URL | Not WAF-inspected | passes to origin |

**Operational reads:** (1) A literal-traversal `404` is the edge *normalizing*,
not the app handling it — re-test with encoded forms to learn whether the app is
actually vulnerable behind the edge, knowing the encoded form will hit the WAF.
(2) The "not WAF-inspected" classes (null byte, RFI param, long path) reach the
origin, so a clean `403`/`500`/`200` on those is the **application's** answer and
is a real verdict. (3) "Every payload returns 403" is the WAF talking, not a
vulnerability signal — see `agent/skills/sqli-testing/SKILL.md`.

## C. Bot-Manager scanner-UA blocks — use a realistic browser UA

This **inverts** the usual "rotate to an obvious tool UA" instinct. A Bot Manager
tier blocks **scanner User-Agents at the edge, before the request reaches the
app**, while leaving generic clients through:

| User-Agent | Edge behavior (observed Akamai Bot Manager) |
|---|---|
| `sqlmap`, `nikto`, tool-default scanner UAs | `403` (Bot Manager deny — never reaches origin) |
| `python-requests`, `curl`, empty UA | `200` (passes to origin) |
| Realistic browser UA (current Chrome/Firefox string) | `200` (passes; the safest default) |

Two consequences:

1. **Use a realistic browser UA by default** for crawling and probing CDN-fronted
   targets (`katana`/`httpx`/`curl` all accept `-H "User-Agent: …"`). A
   scanner-default UA produces a `403` that you will mistake for a dead host or a
   patched endpoint — a **false negative**. (Note `python-requests`/`curl`/empty
   UA passed in this case, but a current-browser UA is the robust choice and also
   survives stricter Bot-Manager policies.)
2. **The UA-403 boundary is itself a recon signal.** If `sqlmap`-UA gets `403` but
   a browser UA gets `200` on the same path, you have positively fingerprinted a
   Bot Manager tier in front of the origin — record it as edge intel.

## D. Safe crawl rates + edge cooldown

The real `429`/rate-block risk on a CDN-fronted target is **not** GET-crawling the
edge cache — it is **application-layer dynamic POST API endpoints** (chat,
eligibility, role-flip, search-as-you-type). Calibrate accordingly.

**Observed-safe starting points (Akamai production edge — treat as a starting
point and probe-and-measure per target, not fixed law):**

- **Production GET-crawl:** safe sustained at **~5 req/s, concurrency C=8**. The
  edge cache absorbs this; it is *not* where the rate block lives.
- **Dynamic POST API endpoints:** the genuine `429` surface. Do **not** burst
  these — serialize and pace them well below the crawl rate.

**Per-host crawl settings (katana):**

| Host class | katana settings | UA |
|---|---|---|
| Production edge | `-rl 4 -c 5` | realistic browser UA |
| Nonprod / preview edge | `-rl 2 -c 3` | realistic browser UA |

In all cases: no `..` / `<` / SQLi / `/etc/passwd` path payloads in the crawl
seed (they trip the WAF and pollute the crawl with `403`s), and avoid dynamic API
POST bursts.

**Preview / nonprod edge reputation cooldown.** Nonprod edges can carry a
**per-host reputation cooldown** that production does not. On a synthetic
`preview.acme-agency.example` deployment,
after a WAF deny the edge **briefly `403`s even clean requests for a few seconds**
(a per-host reputation cooldown), then **self-clears in ~8s**. So on a nonprod
edge, a clean-request `403` *right after* a payload deny can be the cooldown, not
a real block — wait ~8–10s and re-send the control before concluding anything.
Crawl nonprod edges more gently (`-rl 2 -c 3`) precisely to avoid tripping this.

## Calibration procedure (when the numbers above may not generalize)

The defaults in §D were observed against one Akamai configuration. To recalibrate
against an unknown CDN-fronted target:

1. **Fingerprint the edge** (`wafw00f`, response headers, the §A/§B/§C shapes) and
   pick the trait row from `agent/references/recon/rate-calibration.md`.
2. **Map the WAF trigger matrix** (§B): send one of each probe class with a clean
   control after it; record which classes are denied vs. pass-through.
3. **Confirm the UA boundary** (§C): one scanner-UA request and one browser-UA
   request to the same clean path; if they differ, a Bot Manager is in front.
4. **Find the crawl ceiling:** start at the production GET-crawl default and step
   the rate up until clean control requests start returning `429`; back off one
   step. Keep dynamic POST APIs well under that.
5. **Probe the cooldown** on any nonprod/preview edge: after a deliberate WAF
   deny, time how long clean control requests keep returning `403`; use that as
   the nonprod re-probe wait.

## Cross-references

- `agent/references/runtime-guides/cdn-ip-blocking.md` — the **distinct** concern:
  our own egress IP is on a CDN reputation list (our recon collapses globally).
  Reach for it when the §A control request *also* fails; this file is for when the
  control returns `200` and only the specific probe was denied.
- `agent/references/recon/cdn-edge-and-bff-reachability.md` — the **third** member
  of this triad: reading the edge **error envelope** to decide whether a path is
  architecturally not-exposed (Akamai `27368`), edge-authz-denied (`2736803`), or
  origin-answered — plus the BFF-capture trap and the confirmed-live-token rule.
  This file is about the edge denying *your probe*; that file is about deciding
  whether a *clean* path is even routable.
- `agent/references/recon/rate-calibration.md` — the per-target rate trait table
  (nmap/dir-fuzz/nuclei/DNS); use it to pick the trait row, then this file for the
  katana crawl rate + edge-behavior reads it does not carry.
- `agent/references/tools/recon/katana.md` — live crawl doctrine, JS-aware
  defaults, headless escalation, and ingestion handoff.
- `agent/skills/web-recon/SKILL.md` — wafw00f→tier mapping; this file is the
  edge-behavior detail behind that step.
- `agent/skills/rate-limit-bypass/SKILL.md` and
  `agent/references/payloads/rate-limit-bypass-payloads.md` — *offensive* edge
  manipulation (IP-spoofing headers); this file is the *defensive*
  behavior-reading counterpart.
- `agent/skills/sqli-testing/SKILL.md` — "every payload returns 403 is the WAF,
  not injection"; consistent with §B.
