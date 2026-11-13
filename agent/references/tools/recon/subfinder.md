---
description: subfinder passive enumeration — how keyed sources reach subfinder (provider-config.yaml generated at runtime start from SUBFINDER_* env), which keys pay first (Chaos + GitHub free, then SecurityTrails/Censys/VirusTotal/Shodan), fail-open keyless behaviour, per-domain -timeout
skill: subdomain-enumeration
---

# subfinder

Phase 0 passive aggregator, run as `vigil assess kali subfinder` (stage command in
`agent/references/recon/subdomain-enum-manual-stages.md` "Phase 0"). It is fail-open: unkeyed or
failing sources are dropped and the free sources still return roughly 60-70% of the full-key set.
The two free keys close most of that gap.

## How keyed sources are configured

subfinder reads keys only from `~/.config/subfinder/provider-config.yaml`, not from
`SUBFINDER_*` environment variables. Vigil bridges the two:

1. Put keys in `<install>/.env` under the `SUBFINDER_*` names from `agent/.env.example`.
2. `vigil runtime start` passes `.env` to the container (`--env-file`) and generates the
   provider config from the non-empty `SUBFINDER_*` vars
   (`src/vigil_cli/runtime.py :: generate_subfinder_provider_config`). It regenerates the file on
   every start, so edit `.env` and re-run `vigil runtime start` (or `vigil up`); no rebuild.
3. subfinder finds the file on its default path; the wrapper passes no `-provider-config`.

`agent/docker/subfinder-provider-config.example.yaml` documents the schema the generator emits;
it is reference, not something to copy by hand.

## Which keys to configure

Free minimum, configure first:

| Source | env var | Key URL |
|--------|---------|---------|
| Chaos (ProjectDiscovery) | `SUBFINDER_CHAOS_API_KEY` | https://chaos.projectdiscovery.io/ |
| GitHub code search | `SUBFINDER_GITHUB_TOKEN` | https://github.com/settings/tokens (a PAT with no scopes works) |

Paid or rate-limited, ranked by unique-coverage delta:

1. **SecurityTrails** — `SUBFINDER_SECURITYTRAILS_API_KEY`. Largest delta; the ~50 requests/month
   free tier covers about 50 wildcard scope entries per engagement.
2. **Censys** — `SUBFINDER_CENSYS_API_ID` + `SUBFINDER_CENSYS_API_SECRET`, emitted as `id:secret`
   (newer subfinder builds accept a Personal Access Token as `PAT:ORG_ID`, ORG_ID optional on free
   accounts). The free tier covers most engagement-scale work.
3. **VirusTotal** — `SUBFINDER_VIRUSTOTAL_API_KEY`. Large history; free tier is 4 requests/min.
4. **Shodan** — `SUBFINDER_SHODAN_API_KEY`. Pays mainly when the target exposes many services.

`SUBFINDER_INTELX_API_KEY`, `SUBFINDER_URLSCAN_API_KEY` and PassiveTotal
(`SUBFINDER_PASSIVETOTAL_USERNAME` + `SUBFINDER_PASSIVETOTAL_API_KEY`) are wired too.
The separate `github-subdomains` binary reads `GITHUB_TOKEN` from the container environment at
probe time; without it that source is a no-op, which is a configuration gap.

Missing keys never fail a run: `vigil runtime start` WARNs when no `SUBFINDER_*` key is set, and
`vigil assess kali subfinder` WARNs at run time and runs keyless. Under 10 passive subs, check the
keys before trusting the count (the skill's "Decisions").

**Shared runtime.** The generated file sits in the runtime user's HOME inside the shared
container, so every engagement that execs subfinder there sees the same keys (as it already sees
the `--env-file` vars). Isolate keys per scope with a dedicated runtime (distinct
`VIGIL_RUNTIME_CONTAINER`); swapping `.env` and restarting rewrites the file rather than merging.
The file is written `0600` and keys never enter the image or host-side argv.

## Per-domain runs and `-timeout`

subfinder's `-timeout` is the per-source response ceiling (its own default is 30 s). One slow or
unkeyed source can stall a run near that ceiling, and in a `-dL` batch the stall holds the whole
list, so prefer one call per apex. The typed verb defaults `-timeout` to 20; pass `-timeout <n>`
to change it, or `-timeout 0` for subfinder's own default. A `-timeout` inside `--extra-args`
replaces the typed default rather than doubling it. The composed `dns-discovery` keeps the `-dL`
form for throughput with the same 20 s cap (`--subfinder-timeout`).

```bash
vigil assess kali subfinder -d example.com -all -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subs_example.txt \
  --technique OSINT --intent "passive subdomain enum example.com" \
  --probe-kind fingerprint --phase recon --timeout 600
```
