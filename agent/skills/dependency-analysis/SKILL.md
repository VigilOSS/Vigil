---
name: dependency-analysis
description: Derive a code repository's real dependency picture from its own manifests, lockfiles, build config and build output — what the build ships versus what it merely declares, and which shipped components the reviewed code reaches
origin: Vigil
---

# Dependency Analysis

## When to Activate

- A code engagement has a sealed repository and you need to know what third-party
  code actually runs inside it.
- A component looks interesting and you need to establish whether the build ships it
  before spending a dispatch on it.
- Someone hands you a Trivy/Grype/ECR report and you need to know which of its rows
  name an artifact this repository actually builds.
- A finding depends on a library version and you need the version the build resolves,
  not the range a manifest requests.

Not for: web-side CVE intake (that is the recon/intel track), mobile SDK inventory
(`sdk-supply-chain-security`), or CI/CD pipeline review (`cicd-security`).

## The Question This Skill Answers

A dependency list is not a finding. Two facts turn a component into work worth doing:

1. **The build ships it.** A `provided` jar, a `compileOnly` Gradle entry, a peer
   dependency, a `build-system.requires` entry and a `devDependency` are all declared
   and none of them are in the artifact. Conversely, a shaded jar ships under a name
   no manifest contains, and a vendored copy ships with no declaration at all.
2. **The reviewed code reaches it.** A shipped library nothing imports is a different
   risk from one the request path runs through.

Only the intersection is a lead. Reporting the whole dependency list is the failure
mode: it buries the two or three components that matter under hundreds that do not,
and it trains the operator to stop reading.

A clean picture — no shipped-and-reachable component with a known problem — is a
valid, complete result. Do not manufacture volume.

## Tools

- `vigil assess code-dependencies <repo-path>` — the derivation. Reads every
  dependency-declaring file in the tree and reports, per component, a shipment
  observation and a reachability observation. `--json` for the full record set,
  `--structural-index` to bring in import evidence, `--scan-report` to correlate a
  scanner report as a secondary input. Run `vigil assess contract code-dependencies`
  for the payload shape and `vigil assess code-dependencies --help` for flags.
- `vigil assess code-index build` — produces the import index the reachability pass
  consumes. Without it, every component comes back
  `unverified_reachability_unindexed`.
- `vigil assess code-ingest` — must have sealed the repository first; run the
  derivation against the sealed snapshot, not a live working tree.

## Nothing Here Is a Verdict

Every value the tool emits is prefixed `unverified_` and names an *observation*, not
a conclusion. That is structural, not stylistic: build files do not settle what a
built artifact contains. A Gradle script is a program. A Maven property can come from
a parent POM that is not in the tree. A distribution name is not an import name
(`PyYAML` imports as `yaml`). Reflection, service loaders, JNI and dynamic `require`
are invisible to an import index.

Three distinctions carry the honesty of this skill. Learn them before reading a
report:

| Observation | What it means | What it does NOT mean |
|---|---|---|
| `unverified_excluded_by_declared_scope` | A build file declared a scope that normally keeps the component out of the artifact | The bytes are absent. Confirm against the artifact. |
| `unverified_no_reference_observed` | The declaring module's own index, in a language that could import it, was read and nothing matched | The code does not use it. Reflection and dynamic loading are invisible here. |
| `unverified_reachability_unindexed` | The declaring module had no index to read, its index degraded or was unreadable, or it covers no language that could import this component | Anything at all. This is the absence of a measurement. |

`unverified_reachability_unindexed` is never evidence. If you see it on a component
you care about, build the index and re-run; do not reason from it.

Every record ships the `detection` marker naming the reader that produced it and the
verbatim evidence (file, line, exact text) it was derived from. Quote the evidence
when you record a finding. `gradle_script_regex` is the weakest reader in the set —
treat anything it produced as a prompt to read the build script yourself.

## Core Workflow

### 1. Seal and index first

Run against the sealed snapshot path from `code-ingest`, and build the structural
index before the derivation so reachability is a real measurement rather than a
blank. Reference repositories (`repo_role: reference`) are host/framework source —
their manifests describe someone else's build and carry no obligation here.

### 2. Derive the picture

```
vigil assess code-dependencies <sealed-source-path> \
  --structural-index <code-index generation>/manifest.json --json
```

Read the sections in order. The command puts the intersection first on purpose.

### 3. Work the lead set

For each shipped-and-reachable component: pull the version the build resolves (not
the declared range), check it against advisories, and — before recording anything —
confirm the reference sites actually sit on a path an attacker influences. A reached
import in a test helper is not the same as one in a request handler.

### 4. Read the gaps as findings about the review, not about the code

The `gaps in this picture` section is the part that decides whether the picture can
be trusted:

- `unparsed_ecosystem` — a recognized manifest with no reader (Composer, Bundler,
  Cargo, pnpm, Pipfile). That ecosystem's components are **absent from the picture,
  not absent from the build**. Read those files by hand before claiming coverage.
- `external_requirement_include` — part of a Python declaration lives in a file the
  reader followed no further.
- `unmatched_scanner_row` — a scanner row naming nothing this build declares or
  vendors. That is the interesting direction: it usually means the scan covered a
  base image or a different artifact than the repository builds.
- `unresolved_catalog_entry` — a Gradle version-catalog alias that resolves to no
  coordinate. Every `libs.<alias>` site naming it is unresolvable, so those build
  scripts declare more than the picture can show.
- `unnamed_requirement_reference` — a requirement installed from a URL, VCS or path
  that names no distribution. The install is real; the name is not derivable.
- `manifest_too_large`, `manifest_budget_exhausted`, `inventory_truncated` — bounds
  the run hit. Narrow the path and re-run.

### 5. The adversarial cases, and what each looks like in the output

- **Shaded / relocated jar.** `unverified_relocated_into_shaded_artifact` plus
  `unverified_relocation_declared`. The component ships under the shaded prefix, which
  appears in no manifest and in no naive scan. `module_prefixes` carries both the
  original and the shaded package root — search source for both.
- **`provided` that the container really does supply.** `unverified_expected_from_runtime`.
  This is usually correct and usually not a finding *for this repository* — but the
  container's version becomes the question, and that is a deployment question, not a
  source one. Say which you are asserting.
- **One transitive at two versions.** `unverified_duplicate_version_in_lock` on each
  copy, with the install path in the evidence. Which one loads is a classpath/resolution
  question the lockfile does not answer.
- **Lockfile disagreeing with its manifest.** `unverified_manifest_lock_divergence`,
  emitted only when the declared range is a form the checker fully understands. A
  `github:`, `file:` or `workspace:` specifier produces no claim at all — silence
  there means undecidable, not compatible.
- **Vendored copy with no manifest entry.** `unverified_present_without_declaration`
  with `observation_origin: build_output`. Nothing declares it, so nothing updates it.
- **Monorepo.** Every record carries `module_path`; the same coordinate at two
  versions in two modules is two rows, not a conflict.

### 6. Record what you found

Record a finding against the module that ships the component, quoting the evidence
citation and the version the build resolves. State the shipment and reachability
observations by name in the finding so the next reader knows exactly how strong the
claim is. Never write "not used" or "not shipped" into a finding — write the
observation the tool emitted and what you did to confirm it.

## Scanner Reports Are a Secondary Input

`--scan-report` accepts Trivy or Grype JSON. It annotates components the source
derivation already established and it never creates one, because a scan of an image
says nothing about what this repository's build produces. Rows that match nothing
become `unmatched_scanner_row` gaps — read them, they are often the most informative
part of the correlation.

Do not start a dependency review from a scan. Start from the source; use the scan to
cross-check.

## Division of Labor

| Task | Owner |
|------|-------|
| Seal the repository, build the structural index | Operator, before dispatch |
| Run the derivation and read the gaps | Specialist |
| Confirm a shipment exclusion against the real artifact | Specialist, by hand |
| Advisory lookup for a shipped-and-reachable version | Specialist |
| Record findings and variants | Specialist, through `vigil assess finding record` |

## Completion Criteria

- The derivation ran against the sealed snapshot with a structural index present.
- Every `unparsed_ecosystem` gap has been read by hand or explicitly deferred with a
  reason.
- Every shipped-and-reachable component has a version the build resolves, or an
  `unverified_version_unresolved` qualifier with a stated reason it could not be
  resolved.
- No finding restates an `unverified_` observation as a verdict.
