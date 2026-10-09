# Installation

Install detail behind the README [Quick start](../README.md#quick-start): what
`vigil quickstart` checks, the two installed layers, host-side recon tools on Docker Desktop,
and the code-track search dependency.

## Before the first engagement

`vigil quickstart` mutates nothing unless you pass `--install-host-tools`, so it is safe to run
first; `--json` gives a machine-readable readiness report. The orchestrator UI is at
`http://127.0.0.1:18000` once the stack is up. Vigil is distributed from source — pin a Git
revision for reproducible installs, or use `uv tool install --editable .` for development.

**Install ripgrep (`rg`) before running a code engagement.** It is the code track's primary search
tool after the ctags index, and it is in no dependency manifest — it ships only in the runtime
image, which code analysis does not use. Claude and opencode bundle their own search tool, but
Codex and goose specialists have shell only: without `rg` their searches exit 127 and the operator
reads that as "no results" rather than "tool missing". `vigil doctor` reports it and
`vigil engagement start` warns on stderr; neither blocks.

## The two layers: CLI binary vs working root

The **CLI binary** (`vigil` itself) is installed and upgraded with `uv tool install` /
`uv tool upgrade vigil`. The **working root** (`~/vigil` — the `agent/` tree of code, prompts,
skills, and scripts, plus the orchestrator) is installed and upgraded with `vigil install`
or with `vigil up`, which syncs first.

`vigil --version` reports the CLI binary's version; `vigil status` reports the working root's.

Upgrading one does not upgrade the other, and a newer CLI against a stale working root leaves
the affected features silently inert. Every sync path stamps a SHA-256 manifest of what it
copied and compares it against the live source, so the drift is detectable. Three surfaces warn
without blocking: a `warn` line in `vigil status`, an `install_staleness` check in
`vigil doctor`, and a `[vigil] WARN: install root <path> is stale ...` line on stderr before a
`vigil assess` passthrough execs. Run `vigil install` when you see one — it upgrades in place,
never moving or deleting engagements, the database, or `.env`. Mechanism:
[`install-integrity.md`](install-integrity.md).

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
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/d3mondev/puredns/v2@latest
brew install massdns      # macOS; Linux: build from github.com/blechschmidt/massdns

# Optional: wider brute and permutations
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
```

Runtime sizing, kernel limits, and orchestrator backups: [`operations.md`](operations.md).
