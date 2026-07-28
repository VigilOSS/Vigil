---
name: kali-exec
description: Foundational discovery skill for the `vigil assess kali` CLI surface — sync-vs-async decision, attribution/scope semantics, and pointers to `list-commands`/`contract` for the verb catalog and per-verb schemas
origin: Vigil
---

# Kali Execution via `vigil assess kali`

> **Use when:** Always — every target-facing call uses `vigil assess kali ...`. This skill is foundational and is paired with `agent/shared-constraints.md`. Load it before any other skill that runs probes against scoped targets — the sync-vs-async, attribution-header, and out-of-scope rules below are what keep the runtime auditable and the orchestrator backend in sync; `vigil assess list-commands` and `vigil assess contract kali <verb>` are how you find and shape the actual call.

`vigil assess kali` is the host-side CLI that runs Kali tools inside the runtime container with audit recording. It writes a queued audit row to the orchestrator backend before exec, streams stdout/stderr to `${ENGAGEMENT_DIR}/scans/kali/<run-id>.{out,err}` from line one, and finalizes the row on exit. The CLI is the only sanctioned path for target-facing work — host Bash, `docker run`, `docker exec`, and ad-hoc curl/nmap from the host bypass the audit pipeline and the runtime's network isolation.

## Discovery layers

The CLI surface is intentionally large. Four discovery layers keep per-turn context cost bounded while still letting you find the right invocation fast:

1. **This skill (methodology layer)** — sync-vs-async decision, the required-attribution-header three-way split, out-of-scope carve-out semantics, common invocation patterns, and troubleshooting. Load for the judgment calls the mechanical layers below cannot give you.
2. **`vigil assess list-commands [--phase <N>] [--kali-only] [--grep <s>]`** — grouped-by-phase catalog of every command (typed verbs, fallbacks, batch, maintenance) with a one-line summary and a pointer to its contract. Use to find the right verb for a phase or keyword.
3. **`vigil assess kali --help` and `vigil assess kali <verb> --help`** — live argparse output. Use when you are composing an invocation and need the exact flag spelling or default for a verb you have already chosen.
4. **`vigil assess contract kali <verb>`** — canonical schema introspection: preferred invocations, helper-supplied defaults, common mistakes, and a JSON example payload. Use when you are authoring a complex invocation and want the canonical field list — same purpose `contract intel record <type>` serves for intel writes. The schema is derived from `agent/scripts/assess/lib/contracts.py`, so it stays current with the implementation.

Skills should point you at `vigil assess list-commands` for the verb catalog and `vigil assess contract kali <verb>` for field tables instead of duplicating them, because both are generated from the same source as the CLI's argparse. When this skill omits a verb or flag detail, that is intentional — go to layer 2, 3, or 4.

## Verb menu

28 verbs total: 22 typed, 1 local filter (`gf`, no audit flags), 2 fallback (`exec`, `job`), 1 batch fan-out (`sweep`), and 2 host-side maintenance commands (`sweep-orphans`, `tool-help`). Each typed verb wraps a tool with argparse-validated flags and the audit recording path; the fallback verbs cover unmodeled tools and async lifecycles; the batch verb fans one audited command out across an operator-supplied value list; the maintenance commands reconcile stuck audit rows and print a tool's live help.

Every typed verb's result JSON includes a `resolved_argv` — the argv that ACTUALLY ran inside the container AFTER the transparent injections (program attribution `-H` headers, the `--resolve` IP-pin, nuclei's default `-exclude-tags`). Read it to see what executed, not just what you typed.

Full catalog (every verb, its use, and its paired reference doc): `vigil assess list-commands --kali-only` — add `--phase <N>` to scope one phase, `--grep <tool>` to jump straight to one verb. Per-verb schema (flags, defaults, common mistakes, JSON example payload): `vigil assess contract kali <verb>`.

`kali exec` is the escape hatch — use it for tools the typed surface does not yet model (dirb, gobuster, hydra, john, hashcat, custom scripts, etc.) and pass the same audit-metadata flags as a typed verb. `kali job` is the supervisor — see the sync-vs-async decision below.

## Long-tail flags via `--extra-args`

Every typed verb accepts an optional `--extra-args "<shell-quoted string>"` to bridge the typed-flag gap without dropping to `kali exec`. The string is shlex-split and appended to the underlying tool argv after the typed-flag-derived arguments — verb identity is preserved in the audit trail (`command-run list --tool-bin httpx` still finds these calls), so reach for raw `kali exec` only when no typed verb fits at all. Audit truth is preserved because the audit row records the full final argv, including the splatted extra args.

Critical: `--destructive` still applies. If the extra args include a write/delete (`--os-shell` for sqlmap, `--script vuln` for nmap, etc.), you must also pass `--destructive` so the audit row reflects the actual blast radius.

```bash
# Headers (-H) and match-codes (-mc) are now TYPED flags — pass them directly.
# Reserve --extra-args for genuinely unmodeled flags.
vigil assess kali httpx -u https://x -tech-detect \
  -H 'X-Forwarded-For: 127.0.0.1' -mc 200,302 \
  --extra-args "-sr -include-response" \
  --technique DISCOVERY --intent "tech detect with custom headers" \
  --probe-kind fingerprint --phase recon --timeout 60
```

**Quoting gotcha:** an `--extra-args` VALUE that begins with a now-typed short flag
(e.g. `-H`, `-t`) is greedily claimed by argparse as that flag and rejected
("expected one argument"). Use the typed flag instead, or — for an unmodeled flag
whose value must lead with a dash — the equals form `--extra-args=-X ...`.

## Synchronous vs. async decision

**Specialists run synchronously — always.** Each `vigil assess kali
<verb> ... --timeout N` call is awaited in-band — no `run_in_background`, no `kali job start`,
no dtach, no watcher/poll loop. "Synchronous" means awaited-in-band, NOT one-call-at-a-time:
issuing several blocking calls in parallel, each awaited in-band, is fine (see `agent/shared-constraints.md` §2). Even heavy probes (nmap+scripts, full-tree
nuclei sweeps, `sqlmap --level 5 --risk 3`, dirb/gobuster on raft-large
wordlists, ffuf on `directory-list-2.3-big.txt`) run as a single blocking call
with a generous `--timeout`. A long synchronous call is killed cleanly on
`--timeout` expiry — the CLI sends SIGTERM to the process group, then SIGKILL
after 5 seconds, and the audit row records `timed_out=true`, so the row never
disappears and nothing is orphaned.

| Mode | Who | When | Mechanism |
|------|-----|------|-----------|
| Synchronous (the rule for specialists) | every dispatched specialist | all target-facing work, light or heavy | The CLI runs as a single process, blocks the calling shell, and finalizes the audit row on exit. |
| Async (`kali job start ...`) | **operator only** | a single authorized sweep that must outlive its dispatch; never a per-step loop and never to fan out parallel probes | `vigil assess kali job start ...` returns a job-id immediately; the worker runs under `dtach` inside the container and survives calling-shell exit. Poll with `kali job status <id>`, read with `kali job tail <id>`, stop with `kali job stop <id>`. |

**Why specialists never background:** a subagent that launches a detached job
and halts "waiting for a completion notification" gets auto-resumed by the
harness, launches the *next* detached job, and halts again — unbounded relaunch
thrash that produced duplicate httpx passes and zero net progress in past
engagements. The fix is structural: keep target traffic synchronous and
in-band. `--timeout` extends the wall-clock budget; it is **not** a reason to
reach for `kali job start`. If a probe genuinely must outlive the dispatch, the
specialist says so in its handoff and the operator owns the job.

## Audit-flag mapping (REQUIRED on every typed verb and `kali exec`)

The CLI fails closed when `--technique`, `--intent`, `--probe-kind`, `--phase`, and `--timeout` are missing — pass them explicitly, because there is no env-var fallback for the agent-supplied fields (a stale env-var would silently mislabel the audit row). `--destructive` flags writes/deletes; `--force` only suppresses the dedup-warning log for an intentional retry — a fresh audit row is written regardless.

Full flag-by-flag purpose, the `--technique` enum, and the `--probe-kind` vocabulary: `vigil assess contract kali <verb>` (per-verb) or `vigil assess kali <verb> --help` (live argparse). Phase values: see "Phase tags" below.

The engagement key is derived from the single assessment binding documented by
`vigil assess contract kali <verb>`; there is no second key override. `--agent-name` resolves from
the explicit flag, `$AGENT_NAME`, `$VIGIL_AGENT_NAME`, then `operator`. Specialists should normally
inherit `AGENT_NAME=<role>` from their dispatch wrapper; if that context is absent or suspicious,
pass `--agent-name <role>` explicitly so the audit row is not misattributed to `operator`.

## Required attribution headers (program-mandated, e.g. BugCrowd)

When `scope.json` carries a `required_headers` map (set at create time with `vigil engagement create … --program bugcrowd --researcher <handle>` or `--header "Name: Value"`, or after the fact with `vigil engagement set-header <key> "Name: Value"`), `kali_exec` injects those headers into every in-scope HTTP probe automatically. You do **not** add them by hand. The injection is three-way by tool:

- **Injected** (`curl`, `httpx`, `nuclei`, `ffuf`, `sqlmap`, `katana`, `arjun`): the `-H "Name: Value"` is appended and lands in the recorded audit argv, so `command-run list` proves the program got tagged traffic.
- **Silently skipped** (`gau`, `waybackurls`, `subfinder`, `amass`, `dnsx`, `nmap`, `naabu`, `masscan`, …): these query third-party archives / DNS / L3-L4, not the in-scope target — injecting would leak the researcher handle to web.archive.org/CommonCrawl, so it is intentionally NOT added.
- **Warned, runs untagged** (`nikto`, `whatweb`, `wafw00f`, any tool with no known `-H` flag): a stderr warning fires; if that tool reaches the in-scope target you must carry the header another way.

A non-HTTP raw tool that the program still requires tagging on is the operator's responsibility to handle out-of-band — the warning is the cue.

## Out-of-scope carve-outs (`out_of_scope` denylist)

`scope.json` `hosts` wildcards (`*.example.com`) match the apex and **every** subdomain, which
over-includes a program's specific OOS carve-outs. The `out_of_scope` list expresses exceptions: a
host is admitted to collected coverage IFF it matches an original root AND matches **no**
`out_of_scope` entry (the denylist wins). Recon, `scope filter`, spec/endpoint ingestion, the work
buffer, and proxy capture attribution use that admission result to keep unrelated data out of the
engagement. Add carve-outs at create (`--out-of-scope appointments.acme-regional.example --out-of-scope
"*.mobile.acme-net.example"`) or later (`vigil engagement add-oos <key> <host…>` / `remove-oos`). Execution
and dispatch admission are not destination filters; the shared boundary rule remains
`agent/shared-constraints.md` §1.

## Phase tags (including half-phase tags)

`--phase` accepts the canonical engagement phases plus two half-phase tags, `recon-pivot` and `exploit-recon` (explained below). The authoritative, drift-free enumeration is generated from `kali_audit.ALLOWED_PHASES` — list it with `vigil assess list-commands --phase <N>` (which also validates that a given phase token is canonical) or `vigil assess contract kali <verb>`. Do not restate the full phase list here.

Pass the phase the dispatch was authorized for — `scope.json.current_phase` is operator state and updates only on phase transitions, but engagements regularly operate **between phases**. The half-phase tags exist because the audit row must reflect what the dispatch was for, not what `scope.json` happened to say at the time. Source-analyzer mid-engagement looking up version intel uses `recon-pivot`. An exploit-developer fingerprinting a binary before exploitation uses `exploit-recon`. The CLI rejects calls without `--phase` so agents cannot silently rely on a stale env-var default.

## Cross-reference: rate-limit calibration

Per-target rate guidance (Cloud-fronted, Origin, WAF-protected, vendor-SaaS, high-friction) lives in `agent/references/recon/rate-calibration.md` (loaded by recon-class roles on first use). Tier-pick prose stays in `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy".

## Examples per verb

Per-verb worked examples — the full audit-flag set, typed-flag shapes, and copy-paste-ready commands — live in each verb's contract, not here: `vigil assess contract kali <verb>` (a JSON `examples` payload per verb) or `vigil assess kali <verb> --help` for live flag spelling. To find a verb by phase or keyword instead of scanning a table, use `vigil assess list-commands --kali-only --phase <N>` / `--grep <keyword>`.

Two cross-verb pointers worth restating because a single verb's contract doesn't carry them:

- **Subdomain enumeration (Phase 0/1/2/3 staged workflow)** is owned by [`agent/skills/subdomain-enumeration/SKILL.md`](../subdomain-enumeration/SKILL.md) — load that skill rather than composing `subfinder`/`cero`/`alterx`/`puredns`/`dnsx` calls from first principles. It carries the tool-tier rationale, the quantified bound rules (>5000 subs skip Phase 2, >30% wildcard ratio switch to TLS SAN, >500k permutation estimate abort), and the host-CPU gate on the bruteforce profile. Pair it with `agent/references/tools/recon/subdomain-enumeration-tools.md` for the full tool-tier table.
- **Historical-URL collection:** prefer `vigil assess gau endpoints` over the raw `kali gau` typed verb — it wraps `kali gau` with cache reuse and inline work-buffer ingestion in one call. Reach for raw `kali gau` only for a one-off archive sweep that does not need to feed the work buffer.

## Common Patterns

These are the high-frequency invocation shapes specialists reach for. They are
written as templates so the operator/specialist substitutes the engagement
key, target, and audit metadata without re-deriving the path conventions.

### Run a custom Python helper inside the runtime

Authoring path on the host: `$DIR/scripts/<name>.py` (or
`$ENGAGEMENT_DIR/scripts/<name>.py`). Container path the script sees at
execution time: `/engagements/$ENGAGEMENT_KEY/scripts/<name>.py`. Both names
point at the same bind-mounted bytes — the dual naming exists because the
container and host share one filesystem at one mount point. See
`agent/shared-constraints.md §11a` for the path-aliasing rule.

```bash
vigil assess kali exec \
    --technique EXPLOIT --intent "PoC: chained SSRF -> metadata creds" \
    --probe-kind exploit --phase exploit --timeout 600 \
    -- python3 /engagements/$ENGAGEMENT_KEY/scripts/exploit.py \
       --target https://target.example --out /engagements/$ENGAGEMENT_KEY/scans/exploit.log
```

The `--` separator is what makes everything after it raw argv to the
in-container command, which is how arbitrary scripts stay auditable through
the same wrapper that records typed verbs.

### Capture stdout/stderr to engagement-scoped paths

Always write outputs under `/engagements/$ENGAGEMENT_KEY/...` so artifacts
survive container restarts and stay attached to the engagement. `/tmp` and
`/data` inside the container are non-engagement paths and outputs there are
invisible from the host.

```bash
vigil assess kali exec \
    --technique RECON --intent "harvest body of /api/health" \
    --probe-kind fingerprint --phase recon --timeout 60 \
    -- bash -lc "curl -sS https://target.example/api/health \
                   > /engagements/$ENGAGEMENT_KEY/scans/health.json \
                   2> /engagements/$ENGAGEMENT_KEY/scans/health.err"
```

The same files are visible from the host at `$DIR/scans/health.json` and
`$DIR/scans/health.err` for review and for `vigil assess record-*` references.

### Batch one command across a value list and cluster the responses

When you want to probe the SAME command across many literal values you already
have (e.g. an enumerated set of object ids you captured from recon), use
`vigil assess kali sweep` instead of hand-looping `kali exec`. It fans one
audited `kali exec` out per value — `{}` is substituted into the template — so
every value gets its own `command-runs` row, then it prints a compact table
clustered by distinct response signature (reachability class + status + body
marker). The clustering reuses the shared reachability taxonomy, so a
reachable-but-blocked cluster reads differently from a `dns-failure` /
`connection-refused` cluster. It is value-agnostic: it expands ONLY the values
you supply (a literal list and/or inclusive integer ranges `a-b`) and never
generates ids or hosts. Politeness guards: `--max-values 200` cap, default
`--concurrency 1` (`>1` requires `--allow-concurrent`, the I-013 per-host rule).

```bash
vigil assess kali sweep \
    --technique RECON --intent "object-id reachability sweep" \
    --probe-kind baseline --phase recon --timeout 30 \
    --values "1,2,7-9,42" \
    -- curl -s -o /dev/null -w '%{http_code}' https://target.example/item/{}
```

Recover the whole fan-out afterward with
`vigil assess command-run list --intent-q "sweep"`; add `--json` to the sweep
to get cluster objects that carry each value's `run_id` for audit linkage.

### Wrap a long-running custom command as a job (operator-only)

This path belongs to the **operator** — `kali job start` backgrounds a probe past the
synchronous window, and only the operator owns long supervised jobs, because a
dispatched specialist that backgrounds-and-polls is SIGUSR1-killed mid-wait (see
`agent/shared-constraints.md` §2). As a specialist, when a probe won't fit the
synchronous `--timeout`, hand it to the operator in your `next_steps` rather than
starting a job yourself. The dtach session is parented by tini so it survives the
calling agent's exit; recover with `kali job status <id>` and `kali job tail <id>`.

```bash
vigil assess kali job start \
    --technique FUZZ --intent "long ffuf sweep on /api/v1/{id}" \
    --probe-kind payload --phase consume-test --timeout 21600 \
    -- ffuf -u https://target.example/api/v1/FUZZ \
            -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
            -mc 200,401,403 -o /engagements/$ENGAGEMENT_KEY/scans/ffuf-api.json -of json
```

Job output writes through the wrapper so the audit row stays accurate even
when the agent that started the job has long since exited.

## Coverage check before probing

Every typed verb and `kali exec` writes an audit row with `command`, `argv`, `tool`, `agent`, `phase`, `technique`, `intent`, `probe_kind`, `destructive`, exit code, timings, and an output preview. Treat that history as a coverage map — search for prior work on this surface before dispatching, with `vigil assess command-run list --q <keyword> --show-matches`. The full coverage-vs-duplicate decision table lives in `agent/references/runtime-guides/command-history-auditing.md`. The shared `agent/shared-constraints.md §2b` has the agent-side rule.

## Process cleanup discipline

Use PID-targeted cleanup, not binary-name signals — `pkill -f nmap` or `pkill -f ffuf` kills sibling specialists' parallel scans in the shared runtime, losing potentially hours of recon. For async jobs, use `vigil assess kali job stop <id>` (signals only the job-owned in-container PID); for synchronous calls, the CLI already handles the SIGTERM/SIGKILL escalation on `--timeout` expiry so no manual cleanup is needed.

## Wire-Byte Verification Before Trusting a 406 / Content-Negotiation Verdict

A 406 Not Acceptable response (or any content-negotiation-derived verdict) can be fabricated by a **malformed request**, not by the real target behavior. The most common source is an unquoted header value in shell argv that splits at whitespace into two separate tokens before it reaches the HTTP request:

```bash
# WRONG — the Accept header splits; the request goes out without a valid Accept
curl https://TARGET/api/endpoint -H Content-Type: application/json

# CORRECT — quote the entire header value so it reaches the wire intact
curl https://TARGET/api/endpoint -H "Content-Type: application/json"
```

Before treating a 406 (or a content-negotiation-driven "handler not reached" result) as target behavior:

1. **Inspect the recorded argv.** The audit row's `resolved_argv` field shows what ACTUALLY ran inside the container. Read it with `vigil assess command-run get <id>` and confirm every `-H` value is quoted and complete.
2. **Capture the raw wire bytes.** Re-run with `-v` (curl) or `-debug` (httpx) to see the literal request headers sent. A missing or truncated header explains the 406 without any target-side enforcement.
3. **Send a canonical request.** Construct the request with explicit, fully-quoted headers and confirm the 406 persists before recording "content-negotiation blocked" as a verdict.

An unquoted-header 406 is a **tooling artifact**, not a target signal — it fabricates a "handler not reached" lead that closes coverage prematurely. See `agent/rules/hunting.md §23` ("A non-conclusive response is a LEAD, not a verdict") for the doctrine.

## Troubleshooting and runtime errors

When `vigil assess kali --help` errors or a verb fails unexpectedly, see `agent/references/runtime-guides/kali-cli.md` for diagnosis steps (runtime status, dtach reachability, dedup-window, common error messages).

When you see audit rows stuck in `status=running` long after their tool would have finished — typical after a backend restart, host crash mid-run, or a network blip during the finalize PATCH — run `vigil assess kali sweep-orphans --dry-run` to inspect candidates, then re-run without `--dry-run` to finalize dead rows to `status=lost`. The sweep is non-destructive for live processes (it leaves still-running rows untouched), so a periodic sweep is safe even when nothing looks broken.
