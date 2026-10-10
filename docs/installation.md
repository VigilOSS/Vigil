# Installation

Install detail behind the README [Quick start](../README.md#quick-start): what
`vigil quickstart` checks, application releases and private workspaces, host-side recon tools on Docker Desktop,
and the code-track search dependency.

## Before the first engagement

`vigil quickstart` mutates nothing unless you pass `--install-host-tools`, so it is safe to run
first; `--json` gives a machine-readable readiness report. The orchestrator UI is at
`http://127.0.0.1:18000` once the stack is up. Install the versioned wheel from the
[GitHub release](https://github.com/VigilOSS/Vigil/releases/tag/v1.1.0):

```bash
uv tool install --from https://github.com/VigilOSS/Vigil/releases/download/v1.1.0/vigil-1.1.0-py3-none-any.whl vigil
vigil up
```

The release includes the CLI, backend, prompts, schemas, Docker definitions, documentation,
legal files, and prebuilt frontend/report. Consumer installation needs neither Git nor Node
and does not fetch a source checkout. Docker must be running to bring up the local stack.
For development, use `uv tool install --editable .` in the source checkout; the imported
CLI's checkout supplies application assets.

**Install ripgrep (`rg`) before running a code engagement.** It is the code track's primary search
tool after the ctags index, and it is in no dependency manifest — it ships only in the runtime
image, which code analysis does not use. Claude and opencode bundle their own search tool, but
Codex and goose specialists have shell only: without `rg` their searches exit 127 and the operator
reads that as "no results" rather than "tool missing". `vigil doctor` reports it and
`vigil engagement start` warns on stderr; neither blocks.

## Application release and private workspace

One application release supplies matched CLI, backend, prompts, schemas, docs, and UI assets.
Application assets are materialized in a persistent cache identified by version and content
digest. Changing directory does not select another application tree.

Your private workspace defaults to `~/vigil`. Select another with `vigil --root <path>` or
`vigil install <path>`. `vigil up` initializes it automatically; `vigil install` is the
explicit initialize/adopt command. Fresh workspaces contain:

```text
workspace.json       # registered private paths and application provenance
.env                 # operator configuration
engagements/         # engagement files and evidence
state/               # orchestrator database and backups
tenant-references/   # private tenant references
logs/                # service logs
cache/               # dependency environments and disposable build inputs
```

Application source and prompt trees are not copied into fresh workspaces. Documentation and
legal files live together in the application bundle so relative links work there.

Existing workspaces are adopted in place. `workspace.json` registers the existing engagement,
database, and tenant-reference locations, including legacy `agent/engagements/` and backend
data directories. Evidence paths, `.env`, custom client files, and all operator data stay at
their original locations. Old copied application source remains on disk but is no longer used.

To upgrade, install the next release wheel with `uv tool install --force --from <wheel-url>
vigil`, then run `vigil install` to reconcile workspace metadata. Routine adoption preserves
existing generated client files; explicit maintenance flags request their repair.
Running services and sessions retain their original release assets until restarted; new
sessions use the current release. Starting a session refreshes that engagement's generated
entrypoints. If it still has an official client process from another release, end that process
first: shared client files cannot be rebound while the original session is alive. Sessions on
other engagements can start with the new release. `vigil status` and `vigil doctor` report application identity
and affected consumers that require restart. Freshness compares content digests, never file
timestamps. See [`install-integrity.md`](install-integrity.md).

The frontend and report ship prebuilt. `vigil orchestrator build` reports their installed
state for packaged releases; rebuilding with Node is a source-development operation. To
replace packaged UI assets, upgrade or reinstall the release.

## Recon runtime: host vs container

Most target-facing tools run **inside** the shared `vigil` container. The exception is the
DNS-heavy and bulk-liveness recon stages, which on **macOS/Windows Docker Desktop** must run on
the **host**: Docker Desktop proxies every container packet through a userspace proxy
(`com.docker.backend`) that NAT-tracks state *per distinct destination IP*, so a DNS brute or a
bulk `httpx` liveness pass over thousands of hosts saturates that table and wedges the whole VM.

| Stage / tool | Runs | Why |
|---|---|---|
| `subfinder`, `dnsx`, `puredns` (+`massdns`), `shuffledns`, `alterx`, bulk `httpx` liveness | **Host** on Docker Desktop | DNS-heavy / bulk — would wedge the userspace proxy in-container |
| `katana` crawl, `nuclei`, `ffuf`, exploit / authenticated HTTP | **Container** (always) | Isolation: auth'd and exploit traffic must not leave the sandbox |

On native Linux or a remote Docker host there is no userspace proxy, so everything runs
in-container and the host tools are optional — the split is a transparent no-op. On Docker
Desktop, `vigil assess recon` and `--runtime host` **enforce** it: a missing host binary fails
the preflight rather than silently degrading. `vigil quickstart --install-host-tools` runs these
installs for you; `vigil doctor`'s `host-recon-tools` row reports what is missing, and
`$(go env GOPATH)/bin` must be on your `PATH`.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0
go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3
go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0
go install github.com/d3mondev/puredns/v2@v2.1.1
brew install massdns      # macOS; Linux: build from github.com/blechschmidt/massdns

# Optional: wider brute and permutations
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.1.0
go install github.com/projectdiscovery/alterx/cmd/alterx@v0.1.0
```

Runtime sizing, kernel limits, and orchestrator backups: [`operations.md`](operations.md).
