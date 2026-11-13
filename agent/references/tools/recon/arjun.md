---
description: Hidden HTTP parameter discovery with Arjun — arjun-sweep vs manual kali arjun, per-method lists, bounded-first sizing ("size to finish"; a timed-out run is not a negative), --passive and --identity, the patched batch-abort bug, ingest-and-route, and the sqlmap doctrine
skill: parameter-fuzzing
---

# arjun

Arjun finds parameters an endpoint accepts but never advertises, which no crawler or archive
surfaces: it fires batches from a ~25k-name list, diffs each response against a baseline, and
binary-splits to the parameters that change behaviour. Run it as `vigil assess arjun-sweep` or
`vigil assess kali arjun`; flags, the always-written JSON path, method semantics and politeness
knobs are in `vigil assess contract kali arjun`. Use `--technique PARAM-DISCOVERY` for every run,
`--passive` included: Arjun 2.2.7 adds the harvested names to the wordlist and then scans the target
actively. Take `--rate-limit`/`-d`/`-T` from the matching row of
`agent/references/recon/rate-calibration.md` before running in volume.

## One-shot: `vigil assess arjun-sweep`

The verb gates the work buffer, scans each method list under its own `-m` (so POST/JSON/XML body
surfaces are not scanned as GET) and always ingests. It is sized to finish: `--stable` is off,
`-T 7` fails dead targets fast, and `--max-targets 100` per method caps the list; deferred targets
are reported, not dropped. `--timeout` bounds the whole sweep: each method gets the smaller of
`--stage-timeout` (default 600) and the time left, and a method left without time is listed in
`deferred_methods`. Its exit code follows the kali worst-arm-when-all-failed rule, so a partial
failure exits 0 and names the dead arms in `failed_methods`. When every arm failed it exits with
their shared status's code (4 all timed out, 6 all transport errors), or 3 (`failed`) when the arms
failed in different ways. A deferred or failed arm is a hole to re-run, not a negative. Use the
manual steps below for a `--passive` single-`-u` harvest or per-call control.

**Size to finish.** A slow configuration (low `--rate-limit` × `--stable` × high `-T`) over a large
or junk list (`--include-unknown`, Wayback URLs) is SIGTERM-killed after a couple of targets, and
its empty output reads like a clean result. On a timed-out or killed list run the wrapper prints
`INCOMPLETE: arjun ... ~K of N targets`; re-run on a smaller curated live list. A completed run over
16 confirmed-live API endpoints is worth more than a killed run over 134 historic URLs.

## Manual workflow — gate, run per method, ingest

1. **Gate the list.** Never aim Arjun at a raw URL dump or inert assets.
   `vigil assess arjun-select -o <list> [--param-poor-only] [--max-per-host N]` keeps live,
   dynamic, template-deduped, param-poor routes and keeps method variants separate. Besides the
   union `<list>` it writes `<list>.GET` / `.POST` / `.JSON` / `.XML` for each verb present
   (`summary.method_outputs` names them).
2. **Run each method list under its own `-m`**, bounded first: Arjun's default list expands to
   100+ request chunks per host, enough to overload a rate-sensitive target.
   `for M in GET POST JSON XML; do [ -s <list>.$M ] && vigil assess kali arjun -i <list>.$M -m "$M" -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt --stable --rate-limit 10 --technique PARAM-DISCOVERY …; done`
   Escalate for depth by dropping `-w` (the full default list) and/or adding `--passive`.
   - `--passive` folds wayback/commoncrawl/otx parameter names into the list and then scans
     actively, so it raises request volume. Bare `--passive` derives the harvest domain from the
     URL, so give it one `-u`; keep `--stable --rate-limit` set.
   - Prefer `--identity <name>` for authenticated discovery: it folds the identity's session into
     Arjun's `--headers` and stamps `auth_context`, so no raw token lands in the audit argv.
     Hand-written `--headers $'Authorization: ...\nCookie: ...'` is for material outside the
     credential store.
   - Keep `-i` batches small (`arjun-select --max-per-host`) or use `-u` for high-value endpoints.
     Upstream Arjun 2.2.7 aborts the whole `-i` batch when one endpoint returns a 4xx/5xx (a 429
     trips it); the runtime ships a patched Arjun that skips the endpoint instead
     (`agent/docker/patches/arjun-batch-resilience.py`). The verb writes an empty `{}` artifact even
     on a failed run, so ingest always has a file.
3. **Ingest:** `vigil assess ingest arjun <arjun.json>` folds the parameters onto the matching
   work-buffer row (GET → `query_params`, POST/JSON/XML → `body_params`, header-mode params as a
   signal) and re-runs the classifier, so the endpoint auto-routes (`url=` → `gf:ssrf`, `file=` →
   `gf:lfi`, `id=` → `gf:idor`/`gf:sqli`). Rows carry `selected_by=arjun`, the parameters in
   `signals`, and an instruction in `triage_rationale`.

## SQLMAP doctrine

When an enriched row routes to a DB-backed surface (`gf:sqli`, or an `id=`/numeric parameter on a
DB-ish route), `ingest arjun` names `vigil assess kali sqlmap` in `triage_rationale` as the next
step. Arjun and the classifier isolate the injectable parameter; sqlmap confirms it and does the
blind/time-based extraction, which is hundreds to thousands of timed inference requests across
DBMS variants and mechanical work sqlmap does deterministically. sqlmap is suggested and
operator-invoked, never auto-fired.
