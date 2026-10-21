# Installation

Install detail behind the README [Quick start](../README.md#quick-start).

## Install

Install the versioned wheel from the
[GitHub release](https://github.com/VigilOSS/Vigil/releases/tag/v2.1.0), then initialize your
workspace:

```bash
uv tool install --from https://github.com/VigilOSS/Vigil/releases/download/v2.1.0/vigil-2.1.0-py3-none-any.whl vigil
vigil install
```

The release includes the CLI, backend, prompts, schemas, Docker definitions, documentation,
legal files, and prebuilt frontend and report. It needs neither Git nor Node. The selected engagement starts the managed backend as needed, with its UI at
`http://127.0.0.1:18000`. Source intake, indexing, and source investigation run on the host without Docker.
Compiling or running target code, runtime reproduction, and fuzzing need Docker. The first
audited command that needs Kali asks Vigil to prepare its image and start the container;
start Docker first. If the release includes a matching image pin, Vigil pulls it; otherwise it builds locally.
The initial pull or build can take time and prints progress. Capture is optional: use
`vigil mitmproxy start`, or `vigil up` to start the full stack explicitly.

Backend startup allows up to 600 seconds for health and readiness together. Upgrades can
back up and migrate a large engagement database before the HTTP server starts. The CLI
reports its remaining wait every 15 seconds; inspect `vigil logs orchestrator` for errors.
An exited backend fails immediately. For a larger database or slower disk, set a finite,
positive deadline in seconds before starting:

```bash
VIGIL_ORCHESTRATOR_START_TIMEOUT_SECONDS=1200 vigil orchestrator start
```

The same setting applies when engagement startup recovers the managed backend.

- **From the repository:** `uv tool install git+https://github.com/VigilOSS/Vigil vigil` builds
  the frontend and report locally, so it needs Git, Node.js, and npm on `PATH`.
- **For development:** run `uv tool install --editable .` in a source checkout; the checkout
  supplies the application assets.

Start your first engagement with the three commands in the README:
`vigil install`, `vigil engagement create`, and `vigil engagement start`.
Sign in to your selected native client first; API keys are only needed for a provider path
that uses them. `vigil doctor` checks workspace health and reports missing tools.
To preview optional host recon installation, run `vigil doctor --dry-run`; to install the
missing tools, run `vigil doctor --install-host-tools`. `--json` emits a machine-readable
report, and combining `--dry-run` with `--install-host-tools` never runs installers.

## Runtime delivery

Matched release artifacts can carry an exact multi-platform runtime image reference. Startup
checks the release's build-input digest, pulls the image by SHA256, validates its label, then
updates the local image tag. It does not restart an already running container. The image index
covers Linux AMD64 and ARM64. Source checkouts and changed runtime inputs build locally;
`vigil runtime build` is the explicit local-build path.

The runtime-release workflow builds both platforms, publishes the image, embeds its immutable
pin into the matched application wheel/sdist, and attaches those files to a draft GitHub release.
The checked-out source has no fabricated release digest; availability starts when that workflow
has successfully built and published a matched release. A failed pull reports recovery instead
of silently replacing the release image with a different build.

## Upgrade

1. Install the next release wheel: `uv tool install --force --from <wheel-url> vigil`.
2. Run `vigil install` to reconcile workspace metadata. Generated client files are preserved;
   explicit maintenance flags repair them.
3. Restart what `vigil status` or `vigil doctor` reports as stale.

Running services and client sessions keep their loaded release until restarted. You can
finish work in an open client while updating Vigil. To use updated prompts and helpers,
save a handoff, exit that client, then start the engagement again. Starting it refreshes
its generated client files; those files stay protected while another release uses them.
Pausing a client during a backend restart avoids requests during downtime, but does not
replace its inherited helper paths or instructions already in the conversation.
Freshness compares content digests, never timestamps; see
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
binary fails the preflight instead of silently degrading. `vigil doctor --install-host-tools`
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
the ctags index. The runtime image has its own copy, but host-side source investigation
needs a host copy. Claude and opencode bundle their own search, but Codex and goose specialists have only a shell: without
`rg`, their searches exit 127 and read as "no results". `vigil doctor` reports it and
`vigil engagement start` warns; neither blocks.

Runtime sizing, kernel limits, and orchestrator backups: [`operations.md`](operations.md).

## Moving a workspace

Fresh workspace metadata stores default private paths relative to its root. Explicit external
storage remains absolute. Stop clients and owned services before moving a workspace, then run
installation/preflight from the intended root to refresh managed pointers and restart services.
Historical evidence paths and original source origins remain recorded as they ran.

Recognized moved layouts can migrate coherently. If the earlier workspace still exists, or
metadata mixes roots such that defaults cannot be distinguished from explicit overrides, Vigil
refuses ambiguous adoption and names the required path decision. A copied process receipt does
not authorize stopping the original workspace's process. A copy of a running workspace is not
an independent live installation.

Source manifests retain the original source binding. Moving a workspace does not rewrite
historical evidence or source manifests. If validation reports an invalid sealed source
binding after a move, restore access to the original source and explicitly confirm a source
refresh before continuing source work.
