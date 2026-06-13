---
description: Subdomain permutation generator (Phase 2); always `-enrich -estimate` first, chains into puredns resolve
skill: subdomain-enumeration
---

# alterx

**Purpose:** Subdomain permutation generator — takes known subs and emits permutations using built-in `{{sub}}`, `{{word}}`, `{{suffix}}` patterns or custom DSL templates. Phase 2 candidate generator that always feeds puredns resolve (never a raw resolver — permutations are high-FP and need wildcard filtering).

For live engagement targets, run alterx via `vigil assess kali alterx` (typed verb, audit-flag-aware).

**Where it lives:** `/usr/local/bin/alterx` in `runtime-full` (`go install github.com/projectdiscovery/alterx/cmd/alterx@latest` — see `agent/docker/runtime-full/Dockerfile`).

## Resource-safe invocation (always estimate first)

`-enrich -estimate` prints the candidate count without generating output. Always run it first — a 5000-sub input with default patterns can produce 500k+ candidates, and the bound rule says abort at 500k.

```bash
# Step 1: estimate
vigil assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  -enrich -estimate \
  --technique RECON --intent "alterx permutation estimate" \
  --probe-kind fingerprint --phase recon --timeout 120

# Step 2: generate, capped at 100k
vigil assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt \
  -enrich -limit 100000 \
  -o /engagements/$ENGAGEMENT_KEY/scans/perms.txt \
  --technique RECON --intent "alterx permutation generation, capped at 100k" \
  --probe-kind fingerprint --phase recon --timeout 600
```

The output then feeds `puredns resolve` (Phase 2 step 2c in the SKILL).

## Operational notes

- **stdin-hang failure mode (raw runs only).** alterx (v0.1.0) blocks forever when
  given `-l <file>` with stdin still attached — it tries to read stdin for input
  even though `-l` already supplies the seed list, so it waits on an EOF that never
  arrives. Symptom: the alterx process is alive, ~0% CPU, produces 0 output, and
  `ps` shows `STAT=S`. **This cannot occur through the `vigil assess kali alterx`
  wrapper:** vigil closes stdin centrally (`kali.py` runs the foreground probe with
  `stdin=subprocess.DEVNULL`, and the background job path wraps the command with
  `</dev/null`), so alterx always sees an immediate EOF. If you run alterx *raw*
  (outside the wrapper), redirect `< /dev/null` yourself, or you will hit this hang.
- **`-disable-update-check` is injected by default.** The wrapper appends
  `-disable-update-check` to every alterx invocation (the v0.1.0 startup update
  check is pure noise/latency in an egress-restricted container). It is idempotent —
  if you pass `-disable-update-check` yourself via `--extra-args` the wrapper does
  not double-add it.

## DSL patterns

- `-p '{{sub}}-{{word}}.{{suffix}}'` — fixed-pattern expansion against a payload list.
- `-pf custom-patterns.txt` — pattern file with one DSL template per line.

Reach for `-p` only when the engagement has obvious naming-convention signals (e.g. company internal naming pattern leaked via JS or breach data). Default patterns cover `{sub}-staging`, `{sub}-dev`, `{sub}.{suffix}`, etc.

## When to use vs. alternatives

- **vs. raw wordlist brute through puredns:** alterx uses known subs as the seed, so it catches `staging-api.target.example` when `api.target.example` is in the seed. Wordlist brute would only find it if `staging-api` is in the wordlist.
- **vs. dnsgen (similar tool):** alterx's DSL is more expressive and the binary is in the runtime image; dnsgen is not.

## Cross-reference

- Permutation chain pattern (alterx → puredns): `agent/references/tools/recon/subdomain-enumeration-tools.md` "alterx — permutation expansion".
- Phase 2 in the staged composition: `agent/skills/subdomain-enumeration/SKILL.md`.
