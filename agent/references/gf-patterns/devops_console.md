---
name: gf-patterns:devops_console
description: Ops dashboards, metrics planes, and registry/CI APIs routinely deployed unauthenticated (Grafana, Jenkins, Jolokia, Kibana, Solr, Druid, pprof, Docker registry, GitLab API)
origin: local overlay (no upstream gf equivalent)
bucket: devops_console
weight: 30
---

# gf: devops_console

## What this bucket classifies

Operations dashboards, metrics/observability planes, and registry/CI control APIs that
are routinely deployed without authentication or behind a single weak proxy. These are
the "internal tooling accidentally on the edge" surfaces: Grafana, Jenkins, Jolokia
(JMX-over-HTTP), Hystrix, the ELK/Solr/Druid query stack, Go `pprof` profiling, the
Docker registry catalog, and the GitLab projects API. Exposure typically yields
information disclosure, data-source SSRF, credential/config leakage, or direct RCE — so
the bucket maps to the canonical `debug-exposure` class (same class as `debug_logic`).

## Load this reference when

- The corpus contains `/grafana`, `/jenkins`, `/jolokia`, `/kibana`, `/solr/`, `/druid`,
  `/debug/pprof`, `/v2/_catalog`, or `/api/v4/projects` paths
- A non-standard / management port (`:3000` Grafana, `:8080` Jenkins, `:5601` Kibana,
  `:8983` Solr) surfaced an ops dashboard during liveness/port revalidation
- Operator is sweeping for unauthenticated ops planes, exposed metrics/registries, or
  data-source SSRF pivots before sending nuclei/info-disclosure templates

## Parameter keys that match

None — `devops_console` matches on path fragments only. These products are identified by
their route prefixes, not by a single canonical query parameter.

## Path patterns that match

`/grafana`, `/api/datasources`, `/jenkins`, `/jolokia`, `/hystrix`, `/kibana`, `/_cat/`,
`/solr/`, `/druid`, `/debug/pprof`, `/v2/_catalog` (Docker registry catalog),
`/api/v4/projects` (GitLab projects API)

All fragments are boundary-anchored by `fragment_in_path`, so `/solr/admin` matches but a
content slug such as `/solrful-guide` does not.

## Weight and priority interpretation

- Baseline priority score: 30
- Declared **after** `debug_logic` (also weight 30) in `_BUCKETS`. A URL such as
  `/debug/pprof` matches both this bucket's `/debug/pprof` fragment and `debug_logic`'s
  `/debug` fragment; the first-at-max-weight tie-break keeps the cluster as
  `gf:debug_logic`, while `devops_console` is additively recorded in the `+`-joined
  `priority_reason` chain. The bucket is boost-only and never lowers a co-firing
  bucket's score.
- Below specific vulnerability buckets (ssrf=40, auth=40, deserialization=40,
  secret_vault=45) — those dominate `cluster_key`/`priority_score` when they co-fire,
  with `devops_console` still recorded in the reason chain.
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/grafana/api/datasources` — Grafana data-source list (data-source SSRF / config leak)
- `https://target.example/jenkins/script` — Jenkins script console (RCE if reachable)
- `https://target.example/jolokia/read/java.lang:type=Memory` — Jolokia JMX read endpoint
- `https://target.example/hystrix/monitor` — Hystrix dashboard / stream proxy
- `https://target.example/_cat/indices` — Elasticsearch `_cat` index listing
- `https://target.example/solr/admin/cores` — Solr admin core enumeration
- `https://target.example/debug/pprof/heap` — Go `pprof` heap profile (also recorded under `gf:debug_logic`)
- `https://target.example/v2/_catalog` — open Docker registry image catalog
- `https://target.example/api/v4/projects` — GitLab unauthenticated project enumeration

## What it does NOT classify

- Bare `/api/` or `/api/v<n>/` routes — owned by the `api` type floor and the
  `api-versioning` regex bucket; only the specific `/api/datasources`,
  `/api/v4/projects` ops endpoints fire here
- Generic `/dashboard`, `/console`, `/internal`, `/mgmt` paths — those are `debug_logic`
  fragments; this bucket is scoped to the named product surfaces, not every management
  word
- Documentation or marketing pages that merely mention "Grafana" or "Jenkins" without a
  live endpoint — verify live status before prioritizing
- CDN-served static copies of an ops UI shell that resolve to inert HTML — these fire but
  usually clear once liveness/source demotion runs

## Attack classes

- **Unauthenticated ops dashboard / data-source abuse:** Grafana data sources
  (`/api/datasources`) can be queried or used to pivot; the proxy can be steered at
  internal hosts. Tracks the Grafana CVE-2026-27876 family cited by the plan.
- **Data-source / proxy SSRF:** Grafana, Hystrix, and Jolokia all proxy outbound fetches
  that an attacker can redirect at internal services or cloud metadata.
- **Jolokia JMX-over-HTTP RCE:** an exposed `/jolokia` agent allows MBean reads/writes
  that escalate to remote code execution.
- **Go `pprof` exposure:** `/debug/pprof` leaks memory/goroutine profiles (source paths,
  secrets in heap) and enables resource-exhaustion DoS.
- **Open Docker registry enumeration:** `/v2/_catalog` lists every image; unauthenticated
  pulls can leak source, build secrets, and credentials baked into layers.
- **GitLab project enumeration:** an unauthenticated `/api/v4/projects` returns project
  metadata and can expose internal repos / tokens.
- **Search-engine data exfiltration:** open Kibana `_cat`, Solr, and Druid endpoints
  allow arbitrary index/query reads.

## Corpus grounding

50 `grafana` rows observed in the validation `cases.db` (the only `devops_console`
fragment with a non-zero hit count today; these scored 0 before this bucket existed). The
remaining fragments (`/jenkins`, `/jolokia`, `/hystrix`, `/kibana`, `/solr/`, `/druid`,
`/debug/pprof`, `/v2/_catalog`, `/api/v4/projects`) are **forward-looking coverage** for
future engagements — ops/registry/CI planes recur across enterprise targets even when the
current corpus has none. See `docs/plans/classify-context-and-surface-buckets-2026-06.md`
Part 3 §A.7.

## Sources

- [Grafana security advisories — CVE-2026-27876 family](https://grafana.com/security/security-advisories/) — unauthenticated data-source / dashboard exposure (cited by the plan)
- [Jolokia security — JMX-over-HTTP RCE](https://jolokia.org/reference/html/security.html) — exposed agent escalation
- [Go `net/http/pprof` — profiling endpoint exposure](https://pkg.go.dev/net/http/pprof) — `/debug/pprof` disclosure / DoS
- [Docker Registry HTTP API V2 — `/v2/_catalog`](https://distribution.github.io/distribution/spec/api/) — open catalog enumeration
- [GitLab REST API — projects (`/api/v4/projects`)](https://docs.gitlab.com/ee/api/projects.html) — unauthenticated project enumeration
- [HackTricks — pentesting exposed services (Grafana / Jenkins / Solr / Kibana)](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web) — exploitation playbooks

## Related

- `agent/references/gf-patterns/debug_logic.md` — sibling `debug-exposure` bucket; `/debug/pprof` co-fires and keeps the `gf:debug_logic` cluster by the first-at-max-weight tie-break
- `agent/references/gf-patterns/ssrf.md` — Grafana data-source, Hystrix, and Jolokia proxies are SSRF vectors (and pivot to `cloud_metadata`)
- `agent/references/gf-patterns/rce.md` — Jolokia JMX, Jenkins script console, and Hystrix can escalate ops exposure to RCE
- `agent/references/gf-patterns/interestingparams.md` — ops consoles frequently combine with exposed `token=`/`api_key=` credentials
