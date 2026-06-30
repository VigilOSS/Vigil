---
name: kali-exec
description: Foundational discovery skill for the `vigil assess kali` CLI surface — verb menu, audit flags, sync-vs-async decision, and per-verb invocation profiles
origin: Vigil
---

# Kali Execution via `vigil assess kali`

> **Use when:** Always — every target-facing call uses `vigil assess kali ...`. This skill is foundational and is paired with `agent/shared-constraints.md`. Load it before any other skill that runs probes against scoped targets, because the verb menu and audit-flag mapping below are how the runtime stays auditable and the orchestrator backend stays in sync.

`vigil assess kali` is the host-side CLI that runs Kali tools inside the runtime container with audit recording. It writes a queued audit row to the orchestrator backend before exec, streams stdout/stderr to `${ENGAGEMENT_DIR}/scans/kali/<run-id>.{out,err}` from line one, and finalizes the row on exit. The CLI is the only sanctioned path for target-facing work — host Bash, `docker run`, `docker exec`, and ad-hoc curl/nmap from the host bypass the audit pipeline and the runtime's network isolation.

## Discovery layers

The CLI surface is intentionally large. Three discovery layers keep per-turn context cost bounded while still letting you find the right invocation fast:

1. **This skill (methodology layer)** — verb menu, sync-vs-async decision, audit-flag mapping, half-phase tags, and example flag profiles per verb. Load when you need to pick a verb or remind yourself of the audit-flag set.
2. **`vigil assess kali --help` and `vigil assess kali <verb> --help`** — live argparse output. Use when you are composing an invocation and need the exact flag spelling or default for a verb you have already chosen.
3. **`vigil assess contract kali <verb>`** — canonical schema introspection: preferred invocations, helper-supplied defaults, common mistakes, and a JSON example payload. Use when you are authoring a complex invocation and want the canonical field list — same purpose `contract record-intel <type>` serves for intel writes. The schema is derived from `agent/scripts/assess/lib/contracts.py`, so it stays current with the implementation.

Skills should point you at `vigil assess contract kali <verb>` for field tables instead of duplicating them, because the contract is generated from the same source as the CLI's argparse. When this skill omits a flag detail, that is intentional — go to layer 2 or 3.

## Verb menu

24 verbs total: 19 typed, 2 fallback, 1 batch fan-out, and 2 host-side maintenance commands. Each typed verb wraps a tool with argparse-validated flags and the audit recording path; the fallback verbs cover unmodeled tools and async lifecycles; the batch verb fans one audited command out across an operator-supplied value list; the maintenance commands reconcile stuck audit rows (`sweep-orphans`) and print a tool's live help (`tool-help`).

Every typed verb's result JSON includes a `resolved_argv` — the argv that ACTUALLY ran inside the container AFTER the transparent injections (program attribution `-H` headers, the `--resolve` IP-pin, nuclei's default `-exclude-tags`). Read it to see what executed, not just what you typed.

| Verb | Use | Paired reference |
|------|-----|------------------|
| `kali nmap-scan` | Port + service scan with optional NSE scripts. TLS SAN extraction and rDNS via `-sV`. | `references/tools/recon/nmap.md` |
| `kali nuclei` | Template-based vulnerability scanner. Curated template set is the mandatory web-vuln pass — `nuclei` is the primary, `nikto` is the conditional fallback. WAF-resilient: injects `-mhe 50` by default so a 403 storm doesn't make nuclei abandon the host; lead with explicit `-t`, add `-random-agent`/`-H` past UA blocks. | `references/tools/recon/nuclei.md` |
| `kali httpx` | Fast HTTP probing: status, title, tech-detect, TLS-grab. Drives WAF-tier and CDN decisions. | `references/tools/recon/httpx.md` |
| `kali wafw00f` | WAF identification. Run FIRST, before nmap/nikto/dir-fuzz, because WAF tier dictates rate limits for every later tool. | `references/tools/recon/wafw00f.md` |
| `kali ffuf` | Directory and parameter fuzzing with fast filtering. | `references/tools/fuzzing/ffuf.md` |
| `kali sqlmap` | SQL injection detection and exploitation. Native sqlmap `--technique` flag (BEUSTQ) is distinct from the audit `--technique` enum. | `references/tools/exploitation/sqlmap.md` |
| `kali subfinder` | Passive subdomain enumeration (Tier A). | `references/tools/recon/subdomain-enumeration-tools.md` |
| `kali bbot` | Deep passive recon (Tier A+). `bbot -p subdomain-enum -rf passive -t <target>`. `--allow-deadly` requires `--destructive`. | `references/tools/recon/subdomain-enumeration-tools.md` |
| `kali cero` | TLS-handshake SAN scraper (Tier B). CIDR-fed; complements CT logs. | `references/tools/recon/subdomain-enumeration-tools.md` |
| `kali alterx` | Subdomain permutation generator (Tier C). Feed into `puredns resolve`. Run `-enrich -estimate` first to bound output before `-limit N`. | `references/tools/recon/subdomain-enumeration-tools.md` |
| `kali asnmap` | ASN → CIDR mapper. Resolves a domain or org name to its announced IP ranges; the cero feed for the Phase 3 TLS SAN sweep. | `references/tools/recon/asnmap.md` |
| `kali puredns` | Active DNS brute-force with massdns + wildcard filter (Tier C). | `references/tools/recon/puredns.md` |
| `kali dnsx` | Bulk DNS resolution and record enrichment (Tier D). | `references/tools/recon/dnsx.md` |
| `kali nikto` (CONDITIONAL — see triggers in `references/tools/recon/nikto.md`) | Web vuln scanner; legacy/odd-stack only. CLI flag is `--host <h>` (not `-h`, which argparse reserves for help) — the underlying nikto invocation builds `nikto -h <host>` correctly. | `references/tools/recon/nikto.md` |
| `kali katana` | JS-aware crawler. Deep + scope-safe + disk-bounded by DEFAULT: `-d 5`, `-fs fqdn`, `-or -ob`, `-ef <static>`, `-jc -jsl`, and a SAFE `-rl 10` (hard-capped 20; `--allow-fast-crawl` to exceed). Depth is decoupled from rate — go deep without going fast. `--keep-bodies` / `--include-static` undo the disk/asset defaults; `-headless` for browser-semantic deltas. | `agent/references/tools/recon/katana.md` |
| `kali gau` | Historical URL collection (Wayback / OTX / Common Crawl / URLScan). | `references/tools/recon/gau.md` |
| `kali arjun` | Hidden HTTP-parameter discovery (GET/POST/JSON/XML), `--passive` OSINT mode, auth via `--headers`. Aim it at a GATED list (`vigil assess arjun-select`), then fold results back with `vigil assess ingest-arjun` so the classifier re-routes the now-parameterized endpoint. | `references/tools/recon/arjun.md` |
| `kali whatweb` | Deep web technology fingerprinting. | `references/tools/recon/whatweb.md` |
| `kali browser` | Headless-chromium (selenium) render of one URL: origin status + final DOM + screenshot as one JSON. The trustworthy-signal recovery for a curl/httpx run flagged `status='waf_challenge'` (real browser clears JS bot-challenges). | `references/tools/recon/kali-browser.md` |
| `kali exec <cmd>` | Raw passthrough for tools not yet typed. Same audit metadata flags. | `references/runtime-guides/kali-cli.md` |
| `kali job <start\|status\|tail\|stop\|list>` | **Operator-only** async-job lifecycle for a single authorized long sweep that must outlive its dispatch. Specialists run synchronously instead — see the sync-vs-async decision below. | `references/runtime-guides/kali-cli.md` |
| `kali sweep` | Value-agnostic batch: runs one audited `kali exec` per `--values` entry (a literal list and/or inclusive integer ranges `a-b`) with `{}` substituted into the command template, then clusters the responses by distinct signature (reachability class + status + body marker) — distinguishing reachable vs. dns-failure vs. connection-refused via the shared reachability taxonomy. One `command-runs` audit row per value. Politeness: `--max-values 200` cap, default `--concurrency 1` (>1 needs `--allow-concurrent`, I-013 per-host rule). It expands ONLY the values you supply — no ID/host generation. | `references/runtime-guides/kali-cli.md` |
| `kali sweep-orphans` | Host-side reconciler for `assessment_command_runs` rows stuck in `status=running` past `--max-age-seconds` (default 3600s). Probes the in-container PID via `kill -0`; finalizes dead rows to `status=lost`. No audit flags — it is maintenance, not a probe. | `references/runtime-guides/kali-cli.md` |
| `kali tool-help <tool>` | Print a runtime tool's live `-h`/`--help` from inside the container, so you read the EXACT flags the installed version supports instead of guessing into `--extra-args`. No audit flags — maintenance, not a probe. e.g. `vigil assess kali tool-help katana`. | `references/runtime-guides/kali-cli.md` |

`kali exec` is the escape hatch — use it for tools the typed surface does not yet model (dirb, gobuster, hydra, john, hashcat, custom scripts, etc.) and pass the same audit-metadata flags as a typed verb. `kali job` is the supervisor — see the sync-vs-async decision below.

## Long-tail flags via `--extra-args`

Every typed verb accepts an optional `--extra-args "<shell-quoted string>"` to bridge the typed-flag gap without dropping to `kali exec`. The string is shlex-split and appended to the underlying tool argv after the typed-flag-derived arguments — verb identity is preserved in the audit trail (`list-command-runs --tool-bin httpx` still finds these calls), so reach for raw `kali exec` only when no typed verb fits at all. Audit truth is preserved because the audit row records the full final argv, including the splatted extra args.

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

**Specialists run synchronously — always.** One blocking `vigil assess kali
<verb> ... --timeout N` at a time. No `run_in_background`, no `kali job start`,
no dtach, no watcher/poll loop. Even heavy probes (nmap+scripts, full-tree
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

The CLI fails closed when these are missing. Pass them explicitly — there is no env-var fallback for the agent-supplied fields, because a stale env-var would silently mislabel the audit row.

| Flag | Purpose | Notes |
|------|---------|-------|
| `--technique <enum>` | Vulnerability class this command tests, OR the operator-side category for non-attack runs. | Allowed values: `SSRF`, `XSS`, `XXE`, `SQLI`, `NOSQLI`, `SSTI`, `RCE`, `CMDI`, `IDOR`, `LFI`, `RFI`, `OPEN-REDIRECT`, `AUTH`, `JWT`, `CSRF`, `CORS`, `REQUEST-SMUGGLING`, `RATE-LIMIT`, `INFO-DISCLOSURE`, `RECON`, `DISCOVERY`, `FUZZ`, `OSINT`, `CVE-VALIDATION`, `EXPLOIT-CHAIN`, `META`, `HEALTH`, `LOG-READ`, `OTHER`. Pick the enum the skill maps to (`sqli-testing` → `SQLI`); use `META` for operator-side dispatch metadata, registry writes, and scope decisions; `HEALTH` for runtime health checks and tool inventory (`which jadx apktool`, version probes, container-status); `LOG-READ` for reading existing artifacts/log files (no new probes); `OTHER` only when no specific class fits. Unknown tags are rejected before an audit row is written. |
| `--intent "<text>"` | ≤200-char one-liner of purpose. | Replaces the old `echo "=== label ==="` pattern. The intent is what makes `list-command-runs --q <keyword> --show-matches` searchable across an engagement. |
| `--probe-kind <kind>` | What the command represents. | One of `fingerprint` (learning the target, no payload) / `baseline` (vanilla control request, for diff) / `payload` (crafted attack payload testing a hypothesis) / `exploit` (attacker-outcome proof) / `replay` (captured primitive on a new surface) / `cleanup` (undoing target-side changes). |
| `--phase <enum>` | The phase the dispatch was authorized for. | REQUIRED. See "Phase tags" below — pass the dispatch phase, not `scope.json.current_phase`. |
| `--timeout <seconds>` | Wall-clock budget. | Required. Default suggestion: 1800 for typical probes; raise it for a heavy single probe (the call still runs synchronously and is killed cleanly on expiry). A long budget is not a reason to use `kali job start` — that is operator-only (see the sync-vs-async decision). |
| `--destructive` | Flag for writes/deletes. | Off by default. Set when the command does POST/PUT/PATCH/DELETE, file upload, account creation, config change, or any state-modifying shell exec on the target. |
| `--force` | Suppress the dedup-warning log for an intentional retry. | The CLI hashes `(command, argv_json)` and warns when an identical command ran within `KALI_AUDIT_DEDUP_WINDOW_SECONDS` (default 30s), but the new command always executes — the backend records a fresh audit row regardless, with `superseded_by_id` linking it to the predecessor when applicable. `--force` suppresses only the warning text; it does not change run behavior or backend state. |

`--engagement-key` is derived from `${ENGAGEMENT_DIR}/engagement.json`. `--agent-name` resolves from the explicit flag, `$AGENT_NAME`, `$VIGIL_AGENT_NAME`, then `operator`. Specialists should normally inherit `AGENT_NAME=<role>` from their dispatch wrapper; if that context is absent or suspicious, pass `--agent-name <role>` explicitly so the audit row is not misattributed to `operator`.

## Required attribution headers (program-mandated, e.g. BugCrowd)

When `scope.json` carries a `required_headers` map (set at create time with `vigil engagement create … --program bugcrowd --researcher <handle>` or `--header "Name: Value"`, or after the fact with `vigil engagement set-header <key> "Name: Value"`), `kali_exec` injects those headers into every in-scope HTTP probe automatically. You do **not** add them by hand. The injection is three-way by tool:

- **Injected** (`curl`, `httpx`, `nuclei`, `ffuf`, `sqlmap`, `katana`, `arjun`): the `-H "Name: Value"` is appended and lands in the recorded audit argv, so `list-command-runs` proves the program got tagged traffic.
- **Silently skipped** (`gau`, `waybackurls`, `subfinder`, `amass`, `dnsx`, `nmap`, `naabu`, `masscan`, …): these query third-party archives / DNS / L3-L4, not the in-scope target — injecting would leak the researcher handle to web.archive.org/CommonCrawl, so it is intentionally NOT added.
- **Warned, runs untagged** (`nikto`, `whatweb`, `wafw00f`, any tool with no known `-H` flag): a stderr warning fires; if that tool reaches the in-scope target you must carry the header another way.

A non-HTTP raw tool that the program still requires tagging on is the operator's responsibility to handle out-of-band — the warning is the cue.

## Out-of-scope carve-outs (`out_of_scope` denylist)

`scope.json` `hosts` wildcards (`*.example.com`) match the apex and **every** subdomain, which over-includes a program's specific OOS carve-outs. The `out_of_scope` list expresses exceptions: a host is admitted IFF it matches an in-scope entry AND matches **no** `out_of_scope` entry (the denylist wins). It is enforced at `filter-scope`, the dispatch scope_host gate, spec ingestion, and proxy routing/capture. Add carve-outs at create (`--out-of-scope mobile.acme.example --out-of-scope "*.mobile.acme.example"`) or later (`vigil engagement add-oos <key> <host…>` / `remove-oos`). A dispatch whose `scope_host` matches a carve-out is rejected with a distinct "out_of_scope carve-out" error — reframe as recon or remove the carve-out, never probe it.

## Phase tags (including half-phase tags)

`--phase` accepts the canonical phases plus two half-phase tags. Pass the phase the dispatch was authorized for — `scope.json.current_phase` is operator state and updates only on phase transitions, but engagements regularly operate **between phases**.

| Tag | When |
|-----|------|
| `recon` | Phase 1 reconnaissance work. |
| `collect` | Phase 2 surface collection. |
| `consume-test` | Phase 3 work-buffer consumption and targeted testing. |
| `verify` | Phase 4 finding verification. |
| `exploit` | Phase 5 exploitation. |
| `report` | Phase 7 reporting. |
| `code-ingest` / `code-classify` / `code-hunt` / `code-verify` | Code-analysis mode phases. |
| `recon-pivot` | Mid-engagement recon on a newly-surfaced host (e.g. Phase-3 vulnerability-analyst found a new vendor SaaS host and needs to fingerprint it before deciding scope). The audit row reflects "this was recon, even though the engagement was in Phase 3." |
| `exploit-recon` | Phase-5 exploit-developer running additional fingerprinting (e.g. version triangulation via npm registry, or per-CVE pre-exploit checks). |

The half-phase tags exist because the audit row must reflect what the dispatch was for, not what `scope.json` happened to say at the time. Source-analyzer mid-engagement looking up version intel uses `recon-pivot`. An exploit-developer fingerprinting a binary before exploitation uses `exploit-recon`. The CLI rejects calls without `--phase` so agents cannot silently rely on a stale env-var default.

## Cross-reference: rate-limit calibration

Per-target rate guidance (Cloud-fronted, Origin, WAF-protected, vendor-SaaS, high-friction) lives in `agent/references/recon/rate-calibration.md` (loaded by recon-class roles on first use). Tier-pick prose stays in `agent/operator-core.md` "Recon Dispatch Resource Policy".

## Examples per verb

Examples show the audit-flag set explicit so you can copy-paste and edit. All paths use `/engagements/$ENGAGEMENT_KEY/...` because that is what the runtime sees through the bind mount.

### `kali nmap-scan`

```bash
# Cautious-tier profile (CDN-fronted / WAF-protected / regulated) — top-1000 + service detection.
vigil assess kali nmap-scan \
  --target www.example.gov \
  --ports top-1000 --service-detection \
  --max-rate 200 --max-retries 2 --host-timeout 300s \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_example_gov \
  --technique RECON --intent "top-1000 + -sV vs example.gov" \
  --probe-kind fingerprint --phase recon --timeout 1800

# TLS SAN extraction (ssl-cert + ssl-enum-ciphers on 443 only).
vigil assess kali nmap-scan \
  --target api.example.com --ports 443 \
  --scripts ssl-cert,ssl-enum-ciphers \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_san_api \
  --technique RECON --intent "TLS SAN + cipher enum on api.example.com:443" \
  --probe-kind fingerprint --phase recon --timeout 600

# Multi-host batch from -iL list (recon-pivot when discovered mid-Phase-3).
vigil assess kali nmap-scan \
  --target placeholder \
  -iL /engagements/$ENGAGEMENT_KEY/scans/new_hosts.txt \
  --ports top-100 --service-detection \
  --technique RECON --intent "fingerprint newly-discovered vendor SaaS hosts" \
  --probe-kind fingerprint --phase recon-pivot --timeout 1800
```

### `kali nuclei`

```bash
# Reactive sweep against a delta file (Phase 1-2 in-phase pattern).
vigil assess kali nuclei \
  -l /engagements/$ENGAGEMENT_KEY/scans/nuclei_reactive_$RID.txt \
  -t http/cves/,http/misconfiguration/,http/exposures/,http/default-logins/,http/technologies/,http/exposed-panels/ \
  -severity medium,high,critical \
  -as -stream -jsonl \
  -rate-limit 150 -c 25 -bs 25 \
  -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_reactive_$RID.jsonl \
  --technique CVE-VALIDATION --intent "reactive sweep on Phase-1 URL delta" \
  --probe-kind fingerprint --phase recon --timeout 1800

# CDN-fronted target — cap rate and concurrency lower so the edge doesn't 429.
vigil assess kali nuclei \
  -u https://www.example.com \
  -tags cve -severity critical,high -as -jsonl \
  -rate-limit 50 -c 10 -bs 10 \
  -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_cdn.jsonl \
  --technique CVE-VALIDATION --intent "CVE templates against CDN-fronted host" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

### `kali httpx`

```bash
# Live-host confirmation + tech-detect + TLS-grab over a candidate list.
vigil assess kali httpx \
  -l /engagements/$ENGAGEMENT_KEY/scans/candidate_hosts.txt \
  -status-code -title -tech-detect -tls-grab -json \
  -o /engagements/$ENGAGEMENT_KEY/scans/httpx_live.jsonl \
  --technique DISCOVERY --intent "live-host + tech + TLS over candidate hosts" \
  --probe-kind fingerprint --phase recon --timeout 1200
```

### `kali wafw00f`

```bash
# Run FIRST so the WAF tier is known before nmap/nuclei/ffuf calibrate.
vigil assess kali wafw00f https://www.example.com \
  -o /engagements/$ENGAGEMENT_KEY/scans/wafw00f_www.csv \
  --technique DISCOVERY --intent "WAF identification on www.example.com" \
  --probe-kind fingerprint --phase recon --timeout 300
```

### `kali ffuf`

```bash
# Standard L1 directory fuzz with a tech-aware extension list.
vigil assess kali ffuf \
  -u https://www.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,401,403 \
  -rate 50 \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_www.json -of json \
  --technique FUZZ --intent "L1 dir fuzz on www root" \
  --probe-kind payload --phase consume-test --timeout 1800
```

### `kali sqlmap`

```bash
# Targeted SQLi pass — sqlmap's --technique flag is the SQLi technique set
# (BEUSTQ); the audit --technique enum is SQLI.
vigil assess kali sqlmap \
  -u "https://www.example.com/search?q=test" \
  --technique=BEUS --level 3 --risk 2 --batch \
  --threads 4 \
  --technique SQLI --intent "boolean+error+union+stacked SQLi on /search?q" \
  --probe-kind payload --phase consume-test --timeout 1800

# Long sqlmap dump — a specialist runs this SYNCHRONOUSLY with a generous --timeout.
# `kali job start` (shown) is OPERATOR-ONLY (see the sync-vs-async decision above);
# a dispatched specialist uses `vigil assess kali sqlmap ... --timeout 3600` instead.
vigil assess kali job start \
  --technique SQLI --intent "deep sqlmap dump on /api/users?id" \
  --probe-kind exploit --phase exploit --timeout 28800 --destructive \
  --container-name vigil -- \
  sqlmap -u "https://www.example.com/api/users?id=1" \
  --technique=BEUSTQ --level 5 --risk 3 --batch --dump
```

### `kali subfinder` / `kali puredns` / `kali dnsx`

```bash
# Passive subdomain enum (subfinder) → active resolution (puredns/dnsx).
vigil assess kali subfinder -d example.com -all -recursive -t 30 \
  -o /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  --technique RECON --intent "passive subdomain enum for example.com" \
  --probe-kind fingerprint --phase recon --timeout 1800

vigil assess kali puredns resolve /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  -r /engagements/$ENGAGEMENT_KEY/wordlists/resolvers.txt \
  --rate-limit 800 \
  -w /engagements/$ENGAGEMENT_KEY/scans/subs_resolved.txt \
  --technique RECON --intent "active wildcard-aware resolution @ polite-CDN-fronted-target rate" \
  --probe-kind fingerprint --phase recon --timeout 1800

vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/subs_resolved.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_live.txt \
  --technique RECON --intent "lean dnsx confirmation for resolved subs" \
  --probe-kind baseline --phase recon --timeout 1200

vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/dnsx_live.txt \
  --dnsx-profile polite-cdn --resolver-profile public-tcp \
  -a -cname -resp -json --allow-bulk-json \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx.jsonl \
  --technique RECON --intent "A+CNAME enrichment for live dnsx survivors" \
  --probe-kind fingerprint --phase recon --timeout 1200
```

### Subdomain enumeration: Phase 0/1/2/3 staged workflow

The staged subdomain-enumeration workflow is owned by
[`agent/skills/subdomain-enumeration/SKILL.md`](../subdomain-enumeration/SKILL.md). Load
that skill when running subdomain workflows; this section is intentionally a stub. The
skill carries the Phase 0/1/2/3 composition (passive enum, deep passive, TLS SAN
scraping, gated bruteforce, active probe), the tool-tier rationale, the bound rules
with quantified thresholds (>5000 subs skip Phase 2, >30% wildcard ratio switch to TLS
SAN, >500k permutation estimate abort), and the host-CPU note that gates the
DNS-bruteforce profile against the runtime tier. Pair it with
`agent/references/tools/recon/subdomain-enumeration-tools.md` for the full tool-tier table.

### `kali nikto` (CONDITIONAL)

```bash
# Only run when httpx fingerprint matches a trigger (legacy stack, intranet,
# basic-auth realm, WebDAV indicator) — see references/tools/recon/nikto.md.
# Note: --host (not -h) because argparse reserves -h for help; the underlying
# nikto invocation builds `nikto -h <host>` correctly inside the helper.
vigil assess kali nikto \
  --host www.example.gov --ssl \
  -Tuning x60 -Pause 2 -maxtime 300 \
  -Format json -output /engagements/$ENGAGEMENT_KEY/scans/nikto_www_gov.json \
  --technique INFO-DISCLOSURE --intent "nikto on legacy IIS/7.5 fingerprint" \
  --probe-kind payload --phase recon --timeout 600
```

### `kali katana`

Use `agent/references/tools/recon/katana.md` for crawl depth, rate, exclusion,
headless escalation, and ingestion rules.

```bash
# JS-aware authenticated crawl with rate cap.
vigil assess kali katana \
  -u https://app.example.com -jc -jsl -d 4 -c 10 -rl 20 \
  -jsonl -o /engagements/$ENGAGEMENT_KEY/scans/katana_app.jsonl \
  --technique DISCOVERY --intent "JS-aware crawl of app.example.com" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

### `kali gau`

For the standard historical-URL collection flow, prefer `vigil assess gau-endpoints` —
it wraps `kali gau` with cache reuse and inline ingestion in one verb. The raw `kali gau`
typed verb is for one-off archive sweeps that do not need to feed the work buffer.

```bash
# Historical URLs from passive archives — no traffic to the target.
vigil assess kali gau example.com --subs --threads 5 \
  --providers wayback,otx,commoncrawl,urlscan \
  -o /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt \
  --technique DISCOVERY --intent "historical URL harvest for example.com (passive)" \
  --probe-kind fingerprint --phase collect --timeout 1800
```

### `kali whatweb`

```bash
# Deep tech fingerprint — aggression 3 balances depth vs request volume.
vigil assess kali whatweb https://www.example.com -a 3 \
  --log-json /engagements/$ENGAGEMENT_KEY/scans/whatweb_www.json \
  --technique DISCOVERY --intent "deep tech fingerprint on www.example.com" \
  --probe-kind fingerprint --phase recon --timeout 600
```

### `kali exec`

```bash
# Escape hatch — same audit-metadata flags as a typed verb.
vigil assess kali exec --technique AUTH \
  --intent "hydra ssh brute, small wordlist, throttled" \
  --probe-kind payload --phase exploit --timeout 3600 --destructive -- \
  hydra -L /engagements/$ENGAGEMENT_KEY/wordlists/users.txt \
        -P /engagements/$ENGAGEMENT_KEY/wordlists/passes-small.txt \
        -t 4 -f -o /engagements/$ENGAGEMENT_KEY/scans/hydra_ssh.txt \
        ssh://target.example.com
```

### `kali job`

```bash
# Start a long async run.
vigil assess kali job start \
  --technique CVE-VALIDATION --intent "full http/ nuclei sweep across engagement" \
  --probe-kind fingerprint --phase recon --timeout 21600 \
  --container-name vigil -- \
  nuclei -l /engagements/$ENGAGEMENT_KEY/scans/all_live.txt \
         -t http/ -severity medium,high,critical \
         -rate-limit 100 -c 25 -bs 25 -jsonl \
         -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_full.jsonl

# Poll status and tail output. NOTE: <id> is the INTEGER job id from the
# `start`/`list` JSON (`"id": 42`), NOT the dtach socket-hash filename — `status`,
# `tail`, and `stop` reject the hash with "invalid int value".
vigil assess kali job status 42
vigil assess kali job tail 42
vigil assess kali job tail 42 --follow

# Stop a runaway job (after `stop`, confirm the binary is actually gone with
# `pgrep -x <tool>` in-container — if you unlinked the open -o file, the disk is
# reclaimed only once the process exits).
vigil assess kali job stop 42 --container-name vigil

# List recent jobs (filter by status).
vigil assess kali job list --status running
```

## Quick "which verb?" recipes

When you know what you want to learn, this lookup gets you to the right verb without re-reading the menu:

- "Scan a host's TLS for SAN expansion?" → `kali nmap-scan --target <host> --ports 443 --scripts ssl-cert,ssl-enum-ciphers`.
- "Identify the WAF before scanning?" → `kali wafw00f <url>`.
- "Confirm hosts are live and grab tech?" → `kali httpx -l <list> -status-code -title -tech-detect -tls-grab`.
- "Find directories on a target?" → `kali ffuf -u <url>/FUZZ -w <wordlist>`.
- "Sweep for CVEs/misconfigs/exposures?" → `kali nuclei -l <list> -t http/cves/,http/misconfiguration/,http/exposures/`.
- "Probe a SQLi candidate?" → `kali sqlmap -u <url> --technique=<BEUSTQ subset> --batch`.
- "Crawl a JS-heavy SPA?" → `kali katana -u <url> -jc -jsl` and apply `agent/references/tools/recon/katana.md`.
- "Harvest historical URLs without touching the target?" → `kali gau <domain> --subs`.
- "Enumerate subdomains?" → `kali subfinder -d <domain> -all` then `kali puredns resolve` then `kali dnsx`.
- "Inventory runtime tools or versions?" → `kali exec --technique HEALTH --intent "tooling inventory" --probe-kind fingerprint --phase <phase> --timeout 60 -- which <tool...>`.
- "Run a tool not in the typed surface?" → `kali exec --technique <enum> --intent "<why>" --probe-kind <kind> --phase <phase> --timeout <seconds> -- <command...>`.
- "Run a long probe?" → SYNCHRONOUSLY with a generous `--timeout` (specialists do not background). Only the **operator** uses `kali job start` for a single authorized sweep that must outlive a shell.

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
`vigil assess list-command-runs --intent-q "sweep"`; add `--json` to the sweep
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

Every typed verb and `kali exec` writes an audit row with `command`, `argv`, `tool`, `agent`, `phase`, `technique`, `intent`, `probe_kind`, `destructive`, exit code, timings, and an output preview. Treat that history as a coverage map — search for prior work on this surface before dispatching, with `vigil assess list-command-runs --q <keyword> --show-matches`. The full coverage-vs-duplicate decision table lives in `agent/references/runtime-guides/command-history-auditing.md`. The shared `agent/shared-constraints.md §2b` has the agent-side rule.

## Process cleanup discipline

Use PID-targeted cleanup, not binary-name signals — `pkill -f nmap` or `pkill -f ffuf` kills sibling specialists' parallel scans in the shared runtime, losing potentially hours of recon. For async jobs, use `vigil assess kali job stop <id>` (signals only the job-owned in-container PID); for synchronous calls, the CLI already handles the SIGTERM/SIGKILL escalation on `--timeout` expiry so no manual cleanup is needed.

## Troubleshooting and runtime errors

When `vigil assess kali --help` errors or a verb fails unexpectedly, see `agent/references/runtime-guides/kali-cli.md` for diagnosis steps (runtime status, dtach reachability, dedup-window, common error messages).

When you see audit rows stuck in `status=running` long after their tool would have finished — typical after a backend restart, host crash mid-run, or a network blip during the finalize PATCH — run `vigil assess kali sweep-orphans --dry-run` to inspect candidates, then re-run without `--dry-run` to finalize dead rows to `status=lost`. The sweep is non-destructive for live processes (it leaves still-running rows untouched), so a periodic sweep is safe even when nothing looks broken.
