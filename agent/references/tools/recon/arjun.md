---
description: Hidden HTTP parameter discovery (GET/POST/JSON/XML), passive OSINT param mining, auth-aware
---

# arjun

**Purpose:** Discover *hidden* HTTP parameters an endpoint silently accepts but never advertises — the inputs no crawler or archive surfaces. Arjun fires batches from a ~25k parameter-name wordlist, diffs each response against a baseline (reflection / status / length / content factors), and binary-splits to isolate the params that actually change behavior.

Run all target-facing Arjun via `vigil assess kali arjun` (typed verb, audit-flag-aware, runs inside the isolated runtime). Pass the required audit flags (`--technique`, `--intent`, `--probe-kind`, `--phase`, `--timeout`) per `shared-constraints.md §2`. Use `--technique PARAM-DISCOVERY` for active runs, `--technique OSINT` for `--passive` runs. Pull `--rate-limit`/`-d`/`-T` values from the matching trait row in `agent/operator-core.md` "Recon Dispatch Resource Policy" before running in volume.

## Full capability — use all of it (nothing is narrowed)
- **Methods** (`-m GET|POST|XML|JSON`): JSON/XML matter for modern APIs — discover hidden *body* fields on JSON endpoints, not just query params.
- **Passive OSINT mode** (`--passive [sources]`): mines parameter names from wayback / commoncrawl / otx with little/no target traffic. Use on rate-sensitive or low-and-slow engagements, or to seed a wordlist before an active pass.
- **Auth-aware** (`--headers $'Authorization: Bearer …\nCookie: …'`): runs discovery as an authenticated user — finds params gated behind auth.
- **Tuning / politeness** (`--stable`, `--rate-limit`, `-d` delay, `-T` timeout, `-t` threads, `-c` chunk size): essential on content-heavy targets.
- **Output:** JSON is ALWAYS written under `scans/arjun/<target>/<hash>.json` for `ingest-arjun`; `-oT` text and `-oB` Burp are also available.
- **Misc:** `--include` (data in every request), `--casing` (`like_this`/`likeThis`/`likethis`), `--disable-redirects`, `-w` custom wordlist (default = Arjun's full `db/large.txt`).

## Workflow — discover → enrich → route → test
1. **Gate the target list.** NEVER aim Arjun at a raw URL dump or inert assets — on a content-heavy target that's thousands of requests for nothing. Build a disciplined list first:
   `vigil assess arjun-select <cases.db> -o <list> [--param-poor-only] [--max-per-host N]`
   (live + dynamic + path-template-deduped + param-poor — collapses id-varied URLs to one route).
2. **Run — bounded first, escalate for depth.** Start with a focused `-w` list and `--stable --rate-limit` so the run stays gentle; Arjun's default wordlist expands to ~100+ request chunks per host, enough to overload a rate-sensitive or production target if left unbounded:
   `vigil assess kali arjun -i <list> -m GET -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt --stable --rate-limit 10 --technique PARAM-DISCOVERY …`
   Escalate for depth by dropping `-w` (Arjun's full ~25k default list) and/or adding `--passive`.
   - **Reach for `--passive` to deepen coverage on a single `-u` endpoint** — it folds wayback/commoncrawl/otx parameter names into the wordlist and then scans actively, so it raises request volume rather than lowering it. Keep `--stable --rate-limit` set, and give it a `-u` target (an `-i` list leaves it no domain to harvest from).
   - **Run high-value endpoints with `-u`, or keep `-i` batches small via `arjun-select --max-per-host`** — Arjun 2.2.7 aborts the whole batch when a single endpoint returns an unexpected status (an upstream bug in its error path), so a small blast radius keeps one bad URL from ending the run. The verb writes an empty `{}` artifact even on a failed or partial run, so `ingest-arjun` always has a file to read.
3. **Enrich:** `vigil assess ingest-arjun <cases.db> <arjun.json>` folds the discovered params onto the matching work-buffer row (GET→`query_params`, POST/JSON/XML→`body_params`; header-mode params recorded as a signal) and re-runs the EXISTING classifier. The now-parameterized endpoint **auto-routes** — `url=`→`gf:ssrf`, `file=`→`gf:lfi`, `id=`→`gf:idor`/`gf:sqli` — with no new classification logic. Rows are stamped `selected_by=arjun`, the discovered params land in `signals`, and an LLM instruction in `triage_rationale`.

## SQLMAP doctrine
When an enriched row routes to a DB-backed surface (`gf:sqli`, or an `id=`/numeric param on a DB-ish route), `ingest-arjun` names **`vigil assess kali sqlmap`** in the `triage_rationale` as the next step. Division of labor: **Arjun + the classifier ISOLATE the injectable parameter; sqlmap CONFIRMS and does the high-volume blind/time-based extraction** across DBMS variants. A capable LLM can spot error-based/obvious SQLi, but blind/time-based extraction is hundreds-to-thousands of timed inference requests — mechanical work sqlmap does deterministically. sqlmap is **suggested and operator-invoked, never auto-fired.**

Canonical annotated invocations: `vigil assess contract kali arjun`.
