---
name: disclosure-deployment-shape-check
description: Pre-send audit checklist that catches deployment-shape blind spots in critical-severity disclosures — allocator dependence, build-flag gates, claim-vs-evidence fidelity, negative-control bundling, vendor-distro variation
origin: Vigil
---

# Disclosure Deployment-Shape Check

## Identity

A pre-send audit that runs on a critical-severity finding's disclosure bundle, hunting for the class of overstatement that source-only verification (`code-finding-verification`) does not catch — facts about the *runtime deployment* of the target that a source-grounded analyst misses because they aren't visible from the code alone.

The triggering incident: a confirmed pre-auth heap-OOB-to-RCE in Fluent Bit v5.0.5 was disclosed against `cr.fluentbit.io/fluent/fluent-bit:5.0.5`, but the upstream Docker image builds with `-DFLB_JEMALLOC=On` and the chain composes only under glibc malloc. The OOB write fires under jemalloc, but the size-class slab segregation and out-of-band metadata structurally prevent the finalizer-array overwrite — under jemalloc the chain degrades to DoS, not RCE. The bug was real; the deployment claim was overstated. This skill exists so the next disclosure does not have the same gap.

A second incident on the same engagement: a confirmed CRLF/multi-tenant escape claimed "operator's outbound TLS connection to Loki" but the PoC was run against a plain-HTTP mock-loki on port 13100. The bug works above TLS, but the claim was made without runtime evidence. Same class of mistake: source-correct, deployment-incorrect.

The categories below are derived from those two incidents and from the general "claim what you proved, not what you believe to be true" stance.

## When to Activate

- Before sending any disclosure with claimed CVSS ≥ 8.0
- Before adding an end-to-end RCE / auth-bypass / smuggling claim to a report's headline
- When `code-finding-verification` passes but the finding will be communicated externally (vendor email, GHSA, CERT/CC VINCE, BugCrowd, public CVE)
- During `report-writer` final-pass before the disclosure bundle is sealed
- When a reviewer asks "are we sure this is exploitable on the real product, not just the test harness?"

This skill does NOT replace `code-finding-verification` (which kills source-side false positives). It runs *after* — the verification protocol confirms the bug class is real and reachable from external input; this skill confirms the *claim about reach and impact* matches the deployment-shape evidence the bundle carries.

## The Eight Severity-Downgrader Categories

Every disclosure gets walked through these. For each category: ✓ verified-and-claim-matches, ✗ unverified-or-claim-overstates, or N/A. Anything but ✓ is either a re-run or a text qualification before send.

### 1. Allocator dependence

**Question**: Does the chain compose under the allocator(s) the deployed binaries actually use?

**Check**:
- Read the source tree's `cmake/options.cmake` (or equivalent build-system config) for the allocator default and the names of override flags (`FLB_JEMALLOC`, `USE_TCMALLOC`, `WITH_MIMALLOC`, etc.)
- Read the upstream Docker / packaging Dockerfiles for whether the allocator is overridden in production binaries
- If the chain depends on glibc-malloc-specific behavior (chunk metadata adjacency, tcache rescuing, safe-linking encoding, fastbin LIFO), test it under at least one other allocator (jemalloc 5.x, tcmalloc, mimalloc) OR document precisely why the structural property is allocator-portable
- If the chain is text-manipulation (CRLF injection, format-string, parser bug), tag as allocator-independent — but verify there's no hidden `flb_sds_create_len` / `malloc` path that the bug depends on

**Disclosure language**: "affects builds compiled with allocator X" — never "affects deployment Y" without naming the allocator deployment Y compiles with.

### 2. Plugin / module build-flag gate

**Question**: Is the vulnerable plugin compiled into the binaries the disclosure claims to affect?

**Check**:
- Find the CMake / Bazel / Meson option that controls compilation of the vulnerable plugin (`FLB_OUT_LOKI`, `FLB_IN_FORWARD`, etc.)
- Determine the upstream default and whether the production Dockerfile / packaging override it
- For vendor distros (aws-for-fluent-bit, Debian package, etc.) — verify the flag setting per distro
- If the plugin is opt-in by default, the disclosure must say so

**Disclosure language**: "affects builds with `FLB_X=On` (the default)" or "affects deployments that explicitly enable `FLB_X` (opt-in; the upstream default is `Off`)" — never just "affects the upstream image" without checking.

### 3. Default-config reach (minimum precondition)

**Question**: What is the *minimum* operator configuration where the chain fires?

**Check**:
- Trace every config key the chain touches from `flb_config_map_*` to its consumption site
- Distinguish between "always-on" (input plugin listening on a default port) and "operator-set" (a specific config key set to a specific value)
- For each operator-set precondition: is it the documented canonical configuration (e.g., `tenant_id_key` for multi-tenant Loki) or a niche tunable?
- If a config key has a default that is unsafe (e.g., `tls.verify_hostname Off`), the chain still depends on its presence

**Disclosure language**: state the minimum precondition explicitly. "Affects deployments with `out_loki` and `tenant_id_key` set" is honest. "Affects all multi-tenant Loki deployments" is an inference that the next reader will challenge.

### 4. Vendor-distro variation

**Question**: For every distribution the disclosure mentions or implies, has the specific build config been verified?

**Check**:
- Build a per-distro matrix: upstream Docker, upstream `.deb`, upstream `.rpm`, AWS / Azure / GCP fork, Alpine APKBUILD, Fedora spec, Helm chart values, Bottlerocket, OS-distro packages (Debian / Ubuntu / Fedora / Arch / Nix / Homebrew)
- For each: what does the packaging recipe set for the load-bearing flags (allocator, plugin gate, TLS defaults)?
- If a recipe is not publicly readable (private ECR, vendor-internal builds), say so and qualify the claim
- Distros that don't ship the product (e.g., Bottlerocket doesn't ship Fluent Bit) get N/A — record that too so a later reader doesn't re-check

**Disclosure language**: name the verified bucket and the unverified bucket explicitly. "Affects: A, B, C (verified). Status unknown for: D, E (vendor-internal builds)."

### 5. Architecture dependence

**Question**: Does the chain rely on x86_64 / aarch64 / riscv-specific behavior?

**Check**:
- Calibration constants (offsets, size-class bits, libc symbol offsets) are arch-specific by definition — note which arch the PoC was calibrated for
- Endianness — chain that depends on little-endian byte order needs to declare that
- Pointer size — chains that assume 8-byte pointers fail under 32-bit ARM
- SIMD-related allocator behavior (jemalloc page sizes differ on aarch64 vs x86_64)

**Disclosure language**: "calibrated on x86_64 / glibc 2.42 / Linux 6.1; structurally equivalent on aarch64 with re-calibration" is honest. "Cross-platform" without per-arch evidence is overstatement.

### 6. Version-range lower bound

**Question**: When was the bug introduced? When was the affected codepath added?

**Check**:
- `git log --follow` on the bug-site file
- If the source tree is a shallow clone (only the tag commit), pull the history from the upstream repo to bisect
- Look for refactors that may have introduced OR fixed the bug at an earlier version
- A claim of "affects v5.0.5" without a lower bound is read by users as "5.0.5 only" — almost always wrong

**Disclosure language**: "v5.0.5 confirmed; affected since X.Y based on git history" or honest "lower bound not established; maintainers will have the git history".

### 7. Claim-vs-evidence fidelity (TLS, auth, multi-tenant)

**Question**: Does every adjective in the disclosure language map to evidence the bundle carries?

**Check**:
- If the email says "operator's TLS-authenticated connection", does the PoC actually use TLS? Or did it run over plain HTTP?
- If the email says "pre-auth", does the bundle prove pre-auth, or did the PoC bypass auth via some operator misconfig?
- If the email says "multi-tenant", does the bundle prove cross-tenant impact, or just intra-tenant impact?
- If the email cites a specific evidence file path, does that file exist in the bundle (not just in the engagement working directory)?

This is the most common overstatement class. Pattern: the analyst proved it under condition X, knows it generalizes to condition Y, and writes the disclosure as if Y was proven. Don't.

**Disclosure language**: claim the version that was proven. If you believe it generalizes, say "proven under X; identical primitive applies to Y because [structural reason]" — make the generalization explicit so the reader can evaluate.

### 8. Negative-control bundling completeness

**Question**: Does the disclosure bundle contain every evidence file the email and writeup cite?

**Check**:
- Read the disclosure-email.md and writeup.md, list every `evidence/...` reference
- Ls the bundle's `evidence/` directory, list every file present
- Diff the two — every cited file must be present
- Negative-control files (the most important pieces of proof) are most often cited from the engagement working directory but never copied into the bundle
- If a citation says "produced by `run-chain.sh`" but the JSONLs aren't in the bundle, either copy them or rewrite the citation to match what's actually shipped

**Disclosure language**: cite what's actually in the bundle. Re-citing engagement-internal paths in an external disclosure is a tell that the bundle was assembled in a hurry.

## Output Contract

A passed disclosure-deployment-shape check produces:

| Item | Where |
|------|-------|
| Eight-category check table | Top of the disclosure's audit memo, one row per category with ✓/✗/N/A and citation |
| Per-distro deployment matrix | Section of the disclosure or the audit memo; rows per vendor distro × columns per load-bearing flag (allocator, plugin gate, key defaults) |
| Evidence-bundle citation diff | List of every `evidence/...` mention in email + writeup, paired with files actually present in the bundle |
| Required text edits | If any category is ✗, the specific lines in disclosure-email.md / writeup.md / README.md that need correction, plus the corrected text |
| Required runtime work | If a category is ✗ because evidence was claimed but not collected (e.g., TLS claimed, HTTP tested), the specific re-run required before send |

The audit memo lives at `tools/analysis-state/disclosure-shape-check-<slug>.md` and is referenced from the finding's `notes` field. A finding without a passed audit memo does not ship as a critical-severity disclosure.

## Severity Recalibration Against Categories

When a category fails, CVSS framing must update:

- Category 1 fail (allocator): "affects glibc-malloc builds" subset, document the DoS-only behavior under other allocators. Headline claim splits into RCE-bucket and DoS-bucket with separate CVSSes.
- Category 2 fail (plugin gate): only affected deployments are those with the plugin compiled in. Claim must say so.
- Category 3 fail (config reach): scope must shrink to "deployments with the precondition set" — the precondition becomes part of the CVSS Attack Complexity calibration (AC:L if it's a documented canonical config, AC:H if it's niche).
- Category 4 fail (vendor variation): name the verified distros explicitly.
- Category 7 fail (claim fidelity): the strongest claim must drop to what was actually proven, OR the missing evidence must be collected before send.
- Category 8 fail (negative-control bundling): not a severity issue — but a credibility issue. Triagers downgrade disclosures whose evidence references don't resolve.

## Worked Examples

### CH-018 (Fluent Bit Forward RCE) — what category 1 caught

- **Before audit**: "lands `uid=0(root)` on the live release binary (`cr.fluentbit.io/fluent/fluent-bit:5.0.5`)"
- **Category 1 (allocator)** check: `cmake/options.cmake:184` default is `FLB_JEMALLOC OFF`, but `dockerfiles/Dockerfile:83` overrides with `-DFLB_JEMALLOC=On`. The official image runs jemalloc. Chain composes only under glibc.
- **Category 4 (vendor variation)** confirms: upstream `.deb` / `.rpm`, aws-for-fluent-bit, Helm chart, Sumo Logic OpenShift all explicitly set `-DFLB_JEMALLOC=On`. RCE bucket is the long tail of source builds + OS-distro packages that omit the flag.
- **After audit**: split claim into "RCE 9.8 on glibc source builds" and "DoS 7.5 on builds with `-DFLB_JEMALLOC=On` (upstream image + mainstream packages)"

### CH-034 (Fluent Bit Loki tenant smuggling) — what categories 7 + 8 caught

- **Before audit**: "operator's outbound TLS connection to Loki", evidence-file citations include `negative-no-tenant-key-*` and `negative-with-crlf-filter-*` JSONLs
- **Category 7 (claim fidelity)** check: PoC config is `Host 127.0.0.1 / Port 13100` — plain HTTP. TLS was never demonstrated.
- **Category 8 (bundling)** check: bundle's `evidence/` contains 9 positive JSONLs + parser-confirmation. The 6 negative-control JSONLs cited by email/writeup exist only in `tools/exploit-state/...`, not in the bundle.
- **After audit**: either re-run under TLS (strongest version of claim) AND copy negative-control files into bundle; or qualify language and copy files. Don't send until both are resolved.

## Extended Resources

- `agent/skills/code-finding-verification/SKILL.md` — source-side FP elimination (runs first)
- `agent/skills/heap-rce-evidence-ladder/SKILL.md` — per-rung evidence bar (runs alongside)
- `agent/skills/exploit-playbook-authoring/SKILL.md` — playbook + lab-assist-equivalence (runs alongside)
- `agent/rules/reporting.md` — disclosure-language rules; this skill enforces them on the deployment-shape side
- `agent/agents/report-writer.md` — owning role; invokes this skill inline before sealing a critical-severity bundle
