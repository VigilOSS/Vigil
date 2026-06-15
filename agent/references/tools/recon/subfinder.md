---
description: subfinder passive enumeration — how keyed sources are configured (provider-config.yaml generated at runtime start from SUBFINDER_* env), free-key minimum (Chaos + GitHub), per-domain -timeout, fail-open keyless behaviour
skill: subdomain-enumeration
---

# subfinder

**Purpose:** Passive subdomain aggregator (Phase A) over 30+ public sources.
Run it for live engagement targets via `vigil assess kali subfinder` (typed verb,
audit-flag-aware).

subfinder is **fail-open**: it queries every source, drops the ones that fail or
are unkeyed, and aggregates whatever the free sources return. Coverage without
keys is roughly **60-70%** of the full-key set — useful, but you leave real
subdomains on the table. Configuring even the two free keys closes most of that
gap.

## How keyed sources are configured (read first)

subfinder does **NOT** read API keys from arbitrary `SUBFINDER_*` environment
variables. It reads them only from an on-disk file in its native schema:

```
~/.config/subfinder/provider-config.yaml
```

Vigil bridges the two automatically:

1. You put keys in `<install>/.env` using the `SUBFINDER_*` names from
   `agent/.env.example` (e.g. `SUBFINDER_CHAOS_API_KEY=...`).
2. `vigil runtime start` passes `.env` to the container (`docker run --env-file`)
   and then **generates** `~/.config/subfinder/provider-config.yaml` inside the
   container from the non-empty `SUBFINDER_*` vars
   (`src/vigil_cli/runtime.py :: generate_subfinder_provider_config`).
3. subfinder finds that file on its default lookup path — no `-provider-config`
   flag is needed and the wrapper does not pass one.

So **setting the env vars is enough**, but only because the generator translates
them at runtime start. The config is **regenerated on every
`vigil runtime start`**: edit `.env`, run `vigil runtime start` (or `vigil up`),
and the new keys take effect — no rebuild, no recreate.

A committed template documenting the exact schema and the env→source mapping
lives at `agent/docker/subfinder-provider-config.example.yaml`. You do not copy
it by hand; it is reference for what the generator emits.

### Free-key minimum: Chaos + GitHub

If you configure nothing else, configure these two free keys first — they are the
highest signal-per-cost and cost nothing:

| Source | env var | Key URL |
|--------|---------|---------|
| **Chaos** (ProjectDiscovery) | `SUBFINDER_CHAOS_API_KEY` | https://chaos.projectdiscovery.io/ |
| **GitHub** | `SUBFINDER_GITHUB_TOKEN` | https://github.com/settings/tokens |

Chaos is a free, high-signal passive dataset; the GitHub token mines code search
for subdomains leaked in source and configs. A classic or fine-grained PAT with
no scopes works.

### Paid / rate-limited keys (add when budget supports)

Ranked by unique-coverage delta — see
`agent/references/tools/recon/subdomain-enumeration-tools.md` "subfinder — API key
value-for-cost" for the full cost discussion:

1. **SecurityTrails** — `SUBFINDER_SECURITYTRAILS_API_KEY` (free tier ~50 req/month).
2. **Censys** — `SUBFINDER_CENSYS_API_ID` + `SUBFINDER_CENSYS_API_SECRET`
   (emitted as `id:secret`; newer subfinder builds accept a Personal Access Token
   as `PAT:ORG_ID`, ORG_ID optional for free accounts).
3. **VirusTotal** — `SUBFINDER_VIRUSTOTAL_API_KEY` (free tier rate-limited 4/min).
4. **Shodan** — `SUBFINDER_SHODAN_API_KEY`.

`SUBFINDER_INTELX_API_KEY`, `SUBFINDER_URLSCAN_API_KEY`, and PassiveTotal
(`SUBFINDER_PASSIVETOTAL_USERNAME` + `SUBFINDER_PASSIVETOTAL_API_KEY`) are also
wired and emitted when set.

### Keys are fail-open, not required

Unlike asnmap's PDCP key (which is a hard gate because asnmap returns empty output
without it), subfinder genuinely works keyless, so missing keys are **never a hard
failure**:

- At `vigil runtime start`, the generator prints a one-line WARN if zero
  `SUBFINDER_*` keys are configured.
- `vigil assess kali subfinder` prints a one-line WARN at run time when it detects
  no provider config / no key env vars, then runs anyway.

If you intend to run keyless, ignore the WARN — it is advisory.

### Key-leak / multi-engagement note

The generated `provider-config.yaml` lives under the runtime user's HOME inside
the **shared** runtime container. If you reuse one container across engagements
with different scopes, the same keys are visible to every engagement that execs
subfinder there — which is already true of the `--env-file` env vars themselves,
so this is not a new exposure. To isolate keys per scope, run a dedicated runtime
(distinct `VIGIL_RUNTIME_CONTAINER`) per engagement; swapping `.env` and
restarting fully replaces the file (it is rewritten, not merged). The file is
written `0600` and keys never bake into the image or appear in host-side
process argv.

## Per-domain runs and `-timeout`

Prefer running subfinder **per apex** with a bounded `-timeout` rather than one
`-dL <list> -all` mega-run. subfinder's `-timeout` is the per-source response
ceiling (seconds; subfinder's own default is 30). A single slow or unkeyed source
can stall a run near that ceiling, and in a `-dL` batch that stall blocks the
whole list.

The typed verb defaults `-timeout` to **20s** and you can override it:

```bash
# Per apex (preferred) — bounded, one domain cannot stall the batch:
vigil assess kali subfinder -d example.com -all -silent -o /engagements/$KEY/scans/subs_example.txt \
  --technique OSINT --intent "passive subdomain enum example.com" --phase recon

# Override the per-source timeout:
vigil assess kali subfinder -d example.com -timeout 30 -silent ...

# Batch form (throughput) — still timeout-bounded; the composed dns-discovery
# verb uses this form:
vigil assess kali subfinder -dL /engagements/$KEY/scans/apexes.txt -all -silent -t 10 \
  -o /engagements/$KEY/scans/subs_passive.txt --technique OSINT \
  --intent "passive subdomain enum" --phase recon
```

`-timeout 0` (or `-timeout ''`) falls back to subfinder's own default. If you pass
`-timeout` via `--args` passthrough, the wrapper does not double-add its typed
default (idempotent).

## Cross-references

- API-key value-for-cost ranking: `agent/references/tools/recon/subdomain-enumeration-tools.md`
- Provider-config schema template: `agent/docker/subfinder-provider-config.example.yaml`
- Env-var names: `agent/.env.example` ("Passive recon / ProjectDiscovery tooling")
- Phase A→D workflow: `agent/skills/kali-exec/SKILL.md` "Subdomain enumeration: Phase A→D workflow"
- subdomain-enumeration skill: `agent/skills/subdomain-enumeration/SKILL.md`
