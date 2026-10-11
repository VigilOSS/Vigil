# Installation

Install detail behind the README [Quick start](../README.md#quick-start).

## Install

Install the versioned wheel from the
[GitHub release](https://github.com/VigilOSS/Vigil/releases/tag/v1.2.2), check the host, and
bring the stack up:

```bash
uv tool install --from https://github.com/VigilOSS/Vigil/releases/download/v1.2.2/vigil-1.2.2-py3-none-any.whl vigil
vigil quickstart
vigil up
```

The release includes the CLI, backend, prompts, schemas, Docker definitions, documentation,
legal files, and prebuilt frontend and report. It needs neither Git nor Node. Docker must be
running for `vigil up`, and the orchestrator UI is then at `http://127.0.0.1:18000`.

- **From the repository:** `uv tool install git+https://github.com/VigilOSS/Vigil vigil` builds
  the frontend and report locally, so it needs Git, Node.js, and npm on `PATH`.
- **For development:** run `uv tool install --editable .` in a source checkout; the checkout
  supplies the application assets.

`vigil quickstart` changes nothing unless you pass `--install-host-tools`; `--json` prints a
machine-readable readiness report.

## Upgrade

1. Install the next release wheel: `uv tool install --force --from <wheel-url> vigil`.
2. Run `vigil install` to reconcile workspace metadata. Generated client files are preserved;
   explicit maintenance flags repair them.
3. Restart what `vigil status` or `vigil doctor` reports as stale.

Running services and client sessions keep their original release until restarted, and new
sessions use the current one. Starting a session refreshes that engagement's generated
entrypoints, so end any official client process on that engagement from the previous release
first. Freshness compares content digests, never timestamps; see
[`install-integrity.md`](install-integrity.md).

The frontend and report ship prebuilt. `vigil orchestrator build` reports their installed state;
to replace them, upgrade or reinstall the release.

## Workspace

Each release is materialized once in a persistent cache keyed by version and content digest;
changing directory does not switch releases.
Your private workspace holds only operator data and defaults to `~/vigil`; choose another with
`vigil --root <path>` or `vigil install <path>`. `vigil up` initializes it, and `vigil install`
initializes or adopts one explicitly:

```text
workspace.json       # registered private paths and application provenance
.env                 # operator configuration
engagements/         # engagement files and evidence
state/               # orchestrator database and backups
tenant-references/   # private tenant references
logs/                # service logs
cache/               # dependency environments and disposable build inputs
```

Existing workspaces are adopted in place: `workspace.json` registers their engagement, database,
and tenant-reference locations, and evidence, `.env`, and custom client files stay where they
are.

## Host recon tools on Docker Desktop

Most target-facing tools run inside the shared `vigil` container. On macOS and Windows Docker
Desktop, DNS-heavy and bulk-liveness recon runs on the host instead: Docker Desktop routes
container traffic through a userspace proxy (`com.docker.backend`) that tracks state per
destination IP, and a DNS brute or bulk `httpx` pass over thousands of hosts fills that table
and wedges the VM.

| Stage / tool | Runs | Why |
|---|---|---|
| `subfinder`, `dnsx`, `puredns` (+`massdns`), `shuffledns`, `alterx`, bulk `httpx` liveness | Host on Docker Desktop | DNS-heavy or bulk traffic would wedge the proxy in-container |
| `katana` crawl, `nuclei`, `ffuf`, exploit and authenticated HTTP | Container (always) | Authenticated and exploit traffic stays in the sandbox |

On native Linux or a remote Docker host everything runs in-container and the host tools are
optional. On Docker Desktop, `vigil assess recon` and `--runtime host` require them: a missing
binary fails the preflight instead of silently degrading. `vigil quickstart --install-host-tools`
installs them, `vigil doctor` reports what is missing in its `host-recon-tools` row, and
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

## ripgrep for code engagements

Install ripgrep (`rg`) before a code engagement. It is the code track's main search tool after
the ctags index and ships only in the runtime image, which code analysis does not use. Claude
and opencode bundle their own search, but Codex and goose specialists have only a shell: without
`rg`, their searches exit 127 and read as "no results". `vigil doctor` reports it and
`vigil engagement start` warns; neither blocks.

Runtime sizing, kernel limits, and orchestrator backups: [`operations.md`](operations.md).
