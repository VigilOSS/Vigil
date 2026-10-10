# Application integrity and restart requirements

Vigil 1.1 separates versioned application assets from private workspace state.
For setup and upgrade commands, see
[installation](installation.md#application-release-and-private-workspace).

## Release provenance

The release wheel contains a matched CLI, backend, agent corpus, schemas,
documentation, Docker definitions, and prebuilt frontend/report. `bundle.json`
records the release version, each file's SHA-256, the executable roster, and an
aggregate content digest. Application materialization validates the manifest and
restores normalized file modes into a persistent version/content-addressed cache.

The application root comes from an explicit application override, the packaged
bundle, or the actual checkout containing an editable CLI module. The current
directory and copied source in a private workspace do not select application code.
No Git fetch or version-tag source-cache fallback is part of consumer startup.

## Workspace adoption

`vigil install` initializes or adopts the selected workspace, records its private
paths and application provenance in `workspace.json`. Explicit maintenance flags repair
generated client entrypoints; ordinary adoption preserves them. `vigil up` performs the same initialization before starting services.
Existing engagement/database paths, evidence references, environment files,
tenant references, and custom client content are preserved in place. Old copied
application trees remain on disk but are no longer read as release assets.

Fresh workspaces hold private engagements, state, tenant references, logs, and
caches. The application bundle is outside that tree, so a CLI upgrade cannot
replace an engagement's evidence or database as part of an asset update.

## Running consumers

Launchers bind the session to its application release and matched helper CLI.
Persistent application caches keep those paths available across a package
upgrade. New client processes use the current release; already running sessions
keep their original assets until restarted.

Official client starts register their process ID, process birth identity, engagement, and
release provenance in private runtime state. A new release cannot refresh the same
engagement's shared client files while an older registered process is alive. End that
session before launching the new release on that engagement. PID reuse and dead processes
do not keep a stale session active; registry records are retained. Direct client/launcher
invocations bypass this binding and remain unsupported entrypoints.

Backend, runtime image, proxy image, frontend, and report freshness use declared
input sets and content digests. `vigil status` and `vigil doctor` report which
consumers require restart or rebuild, with the applicable commands. Content
changes drive these checks; timestamps do not. See the
[maintainer freshness recipe](maintainer-guide.md#freshness-and-restart-manifest-maintenance).

Upgrade with the next release wheel, then run `vigil install` to reconcile the
workspace metadata. New starts reconcile their selected engagement's generated entrypoints;
explicit maintenance repair also checks active release bindings. Apply the restart commands reported for
running consumers. Historical audit records continue to describe the release
and commands that actually ran.
