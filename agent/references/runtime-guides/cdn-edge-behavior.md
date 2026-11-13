---
description: Target-edge defensive behavior — disambiguating a per-request payload-403 WAF deny (no reputation penalty; do NOT abandon the host) from a rate-429/IP block (session/egress killer); the WAF trigger matrix; Bot-Manager scanner-UA blocks (use a realistic browser UA); safe sustained crawl rates and per-host katana settings; preview/nonprod edge reputation cooldown. Vendor-trait-keyed with Akamai as the worked example. Distinct from cdn-ip-blocking.md (our egress-IP reputation).
skill: web-recon
---

# CDN / Edge Defensive Behavior — reading the target edge's reactions

This file is about the target edge defending itself against your probe: which probes it denies,
how, and how to tell a per-request deny from a block that has killed your session. If every host
goes dark from our side, the runtime's own egress IP is the problem; read
`agent/references/runtime-guides/cdn-ip-blocking.md` instead. Vendor names here are trait
examples. The worked example is Akamai (App & API Protector + Bot Manager on an edge-protected
CMS), and the same shapes show up on Cloudflare, Fastly/Signal Sciences, AWS WAF + CloudFront and
Imperva, so match the row on behaviour rather than brand.

The costly mistake is reading a per-request WAF deny as a dead, patched or globally blocked host
and abandoning it. That produces a false negative and wastes a coverage lane.

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

The §D numbers come from one Akamai configuration. On an unknown edge:

1. Fingerprint it (wafw00f, headers, the §A–§C shapes) and pick the trait row in
   `agent/references/recon/rate-calibration.md`.
2. Map the §B matrix with one probe per class, each followed by a clean control.
3. Check the §C UA boundary with one scanner-UA and one browser-UA request.
4. Step the GET-crawl rate up from the production default until controls return `429`, then back
   off one step. Keep dynamic POST APIs well below that.
5. On a nonprod edge, time how long controls keep returning `403` after a deliberate deny, and use
   that as the re-probe wait.

## Cross-references

- `agent/references/recon/cdn-edge-and-bff-reachability.md`: reading the edge error envelope to
  decide whether a clean path is not exposed (Akamai `27368`), edge-authz-denied (`2736803`) or
  answered by the origin, plus the BFF-capture trap.
- `agent/references/tools/recon/katana.md`: crawl doctrine and headless escalation.
- `agent/skills/sqli-testing/SKILL.md` "Kill and escalate": a WAF that blocks every payload is a
  blocked surface to report, not a negative.
