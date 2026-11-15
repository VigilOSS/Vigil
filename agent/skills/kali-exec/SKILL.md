---
name: kali-exec
description: Foundational discovery skill for the `vigil assess kali` CLI surface — sync-vs-async decision, attribution/scope semantics, and pointers to `list-commands`/`contract` for the verb catalog and per-verb schemas
origin: Vigil
---

# Kali Execution via `vigil assess kali`

> **Use when:** every target-facing call, because all of them go through `vigil assess kali ...`.
> Pair it with `agent/shared-constraints.md` §2, which owns the execution rules: synchronous calls
> only for specialists, the `--timeout` ceiling, signalling only your own run, and no host-side
> probes. This skill covers what the per-verb mechanical layers don't tell you.

`vigil assess kali` runs Kali tools inside the runtime container. It writes a queued audit row
before exec, streams stdout/stderr to `${ENGAGEMENT_DIR}/scans/kali/<run-id>.{out,err}` from line
one, and finalizes the row on exit.

## Finding the right call

- `vigil assess list-commands --kali-only [--phase <tag>] [--grep <tool>]` is the catalog of every
  verb (typed wrappers, the `exec`/`job` fallbacks, the `sweep` fan-out, and the
  `sweep-orphans`/`tool-help` maintenance verbs), each with a one-line use.
- `vigil assess kali <verb> --help` gives live flag spellings and defaults.
- `vigil assess contract kali <verb>` gives the schema, helper defaults, common mistakes and an
  example. It is generated from the same source as argparse, so it is always current.

`kali exec` runs tools the typed surface does not model (dirb, gobuster, hydra, john, hashcat,
custom scripts) and takes the same audit flags.

## Reading a result

Every typed verb's result JSON has `resolved_argv`: the argv that actually ran after the
transparent injections (attribution `-H` headers, the `--resolve` IP pin, nuclei's default
`-exclude-tags`). Read it to see what was sent.

The exit code carries the run's verdict:

| Exit | Meaning |
|---|---|
| `0` | completed, or `waf_challenge`. A WAF or edge block is a complete exchange but not a target verdict. Use `kali browser` only for a JS interstitial; hard blocks need a route, request or egress correction. |
| `3` / `4` / `5` / `6` | failed / timed_out / killed / transport_error. No complete output exists to interpret. |
| `1` / `2` | Vigil refusal (scope, policy, audit) / argparse rejection. |
| `7` | The target response is in the JSON, but the terminal audit row never became durable. Reconcile with `kali sweep-orphans` instead of re-probing the target. |
| `141` | The reader of stdout went away, so the JSON never arrived. It overrides every status above, but a refusal that reached stderr still stands. |

The fan-out verbs (`kali sweep`, `arjun-sweep`) exit non-zero only when every arm failed (with the
shared status's code, or `3` for a mixed set). A few dead arms still exit `0`, with
`failed`/`failed_by_status`/`failed_methods` in the JSON and a stderr line. Those arms are holes,
not negatives, so re-run them before you read their absence as a result.

## Long-tail flags via `--extra-args`

Every typed verb accepts `--extra-args "<shell-quoted string>"`, which is shlex-split and appended
after the typed arguments. The audit row records the full final argv and keeps the verb identity
(`command-run list --tool-bin httpx` still finds the call), so prefer this to dropping into
`kali exec`. Headers (`-H`) and match codes (`-mc`) are typed flags, so pass those directly. If the
extra args write or delete (`--os-shell` for sqlmap, `--script vuln` for nmap), also pass
`--destructive` so the audit row records the real blast radius.

Quoting gotcha: argparse claims an `--extra-args` value that starts with a typed short flag (`-H`,
`-t`) and rejects it with "expected one argument". Use the typed flag, or the equals form
`--extra-args=-X ...` for an unmodeled dash-leading value.

## Synchronous vs. async decision

| Mode | Who | When |
|------|-----|------|
| Synchronous | every dispatched specialist | all target-facing work, light or heavy. The call blocks and finalizes its audit row on exit. On `--timeout` the CLI sends SIGTERM, then SIGKILL after 5 s, and records `timed_out=true`. |
| `kali job start` | operator only | one authorized sweep that must outlive a dispatch, never a per-step loop or a parallel fan-out. It returns a job id, runs under `dtach` in the container, and is managed with `kali job status` / `tail` / `stop <id>`. |

If a probe has to outlive your dispatch, say so in the handoff's `next_steps` and the operator
will run it as a job.

## Audit-flag mapping

`--technique`, `--intent`, `--probe-kind`, `--phase` and `--timeout` are required on every typed
verb and `kali exec`. The CLI fails closed without them, because an env-var fallback could
mislabel the row. `--destructive` marks writes and deletes. `--force` only silences the
dedup-window warning for an intentional retry. The enums are in `vigil assess contract kali <verb>`.

Attribution resolves from `--agent-name`, then `--agent-id`, `$AGENT_NAME`, `$VIGIL_AGENT_NAME`,
then `operator`. A dispatched specialist passes `--agent-id <your dispatch agent_id>` and no
`--agent-name`, so the run belongs to the dispatch. A command run that backs verifier evidence
needs that dispatch id. A helper script that calls `kali exec` itself inherits attribution only
through env: run it as `VIGIL_AGENT_NAME=<your dispatch agent_id> ./tools/<helper>`, or through
`vigil assess host-exec --agent-name <your dispatch agent_id>`, which exports it to the child. The engagement key comes from the single assessment binding; there is no
second override.

## Required attribution headers (program-mandated, e.g. Bugcrowd)

When `scope.json` has a `required_headers` map (set with `vigil engagement create … --program
bugcrowd --researcher <handle>`, `--header "Name: Value"`, or later `vigil engagement set-header
<key> "Name: Value"`), the CLI adds those headers to in-scope HTTP probes for you. How it applies
them depends on the tool:

- **Injected** (`curl`, `httpx`, `nuclei`, `ffuf`, `sqlmap`, `katana`, `dalfox` via `-H`;
  `whatweb` via `--header`, `nikto` via `-Add-header`, `arjun` via `--headers`; `wafw00f` via a
  headers file under `scans/kali/required-headers/` that keeps its default header set and any
  `-H` file you pass): the header lands in the recorded argv, so `command-run list` proves the
  traffic was tagged. `kali browser` hands the headers to the Playwright driver instead of the
  argv. A shell script FILE (`sh scripts/x.sh`) that reaches a declared host, or builds its
  targets at run time, runs as an attributed copy beside it (`scripts/.x.attributed-<digest>.sh`)
  whose curl/wget carry the headers.
- **Skipped on purpose** (`gau`, `waybackurls`, `subfinder`, `amass`, `dnsx`, `puredns`, `nmap`,
  `naabu`, `masscan`, `tlsx`): these hit third-party archives, DNS, or L3-L6 without HTTP, and
  injecting would leak the researcher handle to web.archive.org or CommonCrawl.
- **Not applicable, offline** (`which`, `find` without `-exec`, `jsluice`, `uro`, `trufflehog
  filesystem`, and text tools such as `grep` or `jq`): a run whose every command reads only local
  files makes no target traffic, so it needs no header and records `not_applicable_offline`.
- **Read from the program** (a python/node/ruby/perl/php script or inline `-c`/`-e` program, and
  shell scripts with no curl/wget to rewrite): one that names the headers (or
  `$VIGIL_REQUIRED_HEADERS` / `$VIGIL_REQUIRED_HEADER_<NAME>`, exported for every run) proceeds;
  one whose literal requests all name hosts outside scope proceeds untagged.
- **Refused before it starts**: a literal request to a declared host without the headers, a
  program that builds its targets at run time without naming them, a script Vigil cannot read
  beneath the engagement, and any tool with no header flag Vigil can fill. Send the requests with
  a tool Vigil injects into, or reference the env carrier in the script. A run that sends no
  request to a declared target (it parses stored output, talks to a local mock) passes
  `--no-target-requests '<why>'`; the audit row records the statement, and a run whose argv names
  a target is refused anyway.

## Out-of-scope carve-outs

A `scope.json` wildcard (`*.example.com`) matches the apex and every subdomain. `out_of_scope`
entries are exceptions, and the denylist wins: a host is admitted only if it matches a root and
no `out_of_scope` entry. Recon, `scope filter`, spec and endpoint ingestion, the work buffer and
proxy capture attribution all use this admission. Add carve-outs at create time
(`--out-of-scope appointments.acme-telco.example --out-of-scope "*.mobile.acme-telco.example"`)
or later (`vigil engagement add-oos <key> <host…>` / `remove-oos`). Execution and dispatch
admission are not destination filters; the boundary rule is `agent/shared-constraints.md` §1.

## Phase tags (including half-phase tags)

`--phase` takes an audit tag: a web phase, a code audit tag, or a half-phase tag. The list is in
`vigil assess contract kali <verb>`. Pass the phase your dispatch was authorized for, not
`scope.json.current_phase`, because engagements regularly work between phases and the row should
say what the run was for. The half-phase tags:

- `recon-pivot`: recon done mid-engagement, such as source-analyzer looking up version intel.
- `exploit-recon`: fingerprinting before exploitation.

Code dispatches can carry the track phase as `authorized_phase`, but `--phase` takes only the
audit tag: `ingest` → `code-ingest`, `classify-map` → `code-classify`, `hunt` → `code-hunt`,
`verify-variant` → `code-verify`, `fuzz` → `code-fuzz`. A packet that already names the tag
(claimed code proof work carries `code-verify`) passes it unchanged.

## Examples per verb

Each verb's contract carries copy-paste examples (`vigil assess contract kali <verb>`). Two
cross-verb pointers that no single contract carries:

- **Subdomain enumeration** belongs to `agent/skills/subdomain-enumeration/SKILL.md`. Load it
  rather than composing `subfinder`/`cero`/`alterx`/`puredns`/`dnsx` calls yourself, because it
  carries the brute gating, wildcard and permutation bounds, and the host-CPU gate. Stage commands
  are in `agent/references/recon/subdomain-enum-manual-stages.md`.
- **Historical URLs:** prefer `vigil assess gau endpoints`, which wraps `kali gau` with cache reuse
  and work-buffer ingestion. Use raw `kali gau` only for a one-off sweep that won't feed the
  buffer.

Per-target rate guidance is in `agent/references/recon/rate-calibration.md`.

## Common patterns

### Run a custom Python helper inside the runtime

Author the script on the host at `$ENGAGEMENT_DIR/scripts/<name>.py`, and run it at
`/engagements/$ENGAGEMENT_KEY/scripts/<name>.py`. Both paths name the same bind-mounted bytes
(`agent/shared-constraints.md` §11a). Everything after `--` is raw argv, so the script is audited
like a typed verb. The container has no `vigil` executable, so a script run there must be
self-contained (`agent/skills/write-probe-script/SKILL.md`).

```bash
vigil assess kali exec \
    --technique SSRF --intent "PoC: chained SSRF -> metadata creds" \
    --probe-kind exploit --phase exploit --timeout 600 \
    -- python3 /engagements/$ENGAGEMENT_KEY/scripts/exploit.py \
       --target https://target.example --out /engagements/$ENGAGEMENT_KEY/scans/exploit.log
```

### Capture stdout/stderr to engagement-scoped paths

Write outputs under `/engagements/$ENGAGEMENT_KEY/...`. Container `/tmp` and `/data` are invisible
from the host and are lost on restart. A single request looks like this:

```bash
vigil assess kali exec \
    --technique RECON --intent "harvest body of /api/health" \
    --probe-kind fingerprint --phase recon --timeout 60 \
    -- bash -lc "curl -sS https://target.example/api/health \
                   > /engagements/$ENGAGEMENT_KEY/scans/health.json"
```

### Batch one command across a value list

To run the same command across values you already have (object ids captured in recon, for
example), use `vigil assess kali sweep` rather than looping `kali exec`. It runs one audited exec
per value, substituting `{}`, and prints responses clustered by reachability class, status and
body marker. It expands only the values you supply (a literal list or inclusive `a-b` ranges) and
never generates ids or hosts. The limits are `--max-values 200` and `--concurrency 1` by default;
going above 1 needs `--allow-concurrent`, because parallel arms multiply the per-host rate. Add
`--json` to get each value's `run_id`.

```bash
vigil assess kali sweep \
    --technique IDOR --intent "object-id reachability sweep" \
    --probe-kind baseline --phase consume-test --timeout 30 \
    --values "1,2,7-9,42" \
    -- curl -s -o /dev/null -w '%{http_code}' https://target.example/item/{}
```

## Before and after probing

- Search prior runs on the surface first: `vigil assess command-run list --q <keyword>
  --show-matches` (`agent/shared-constraints.md` §2b; decision table in
  `agent/references/runtime-guides/command-history-auditing.md`).
- A 406 or other content-negotiation verdict often comes from an unquoted header that split
  before reaching the wire. Before treating it as target behaviour, check `resolved_argv` with
  `vigil assess command-run get <id>`, replay with `-v` (curl) or `-debug` (httpx), and confirm the
  verdict holds with fully quoted headers (`agent/rules/hunting.md` §12(f)).
- When a verb errors, a documented verb, flag or skill is missing, or audit rows sit at
  `status=running` long after the tool finished, see
  `agent/references/runtime-guides/kali-cli.md`.
