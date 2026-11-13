---
name: disclosure-deployment-shape-check
description: Pre-send audit checklist that catches deployment-shape blind spots in critical-severity disclosures — allocator dependence, build-flag gates, claim-vs-evidence fidelity, negative-control bundling, vendor-distro variation
origin: Vigil
---

# Disclosure Deployment-Shape Check

## Identity

A pre-send audit of a high-severity finding's disclosure bundle, hunting the overstatement that
source-only verification (`code-finding-verification`) does not catch: facts about the target's
*runtime deployment* that are invisible from the code alone. The typical failure is source-correct,
deployment-incorrect — a real bug whose claimed reach (the official image, TLS, every multi-tenant
deployment) was never shown. The worked examples at the end calibrate it.

## When to Activate

- Before sending any disclosure with claimed CVSS ≥ 8.0, when the report-writer runs that finding's
  `agent/references/submission-format.md` checklist, or before an end-to-end RCE / auth-bypass /
  smuggling claim reaches a headline.
- When a reviewer asks whether the claim holds on the real product rather than the test harness.

It runs after `code-finding-verification`, which confirms the bug class is real and reachable; this
audit confirms the claim about reach and impact matches the deployment evidence the bundle carries.
The report-writer creates no proof, so a check it cannot settle from the finding, its linked runs and
artifacts, and the staged bundle becomes a "Required runtime work" item routed to the operator
(`QA BLOCKED`), not a test it runs.

## The Eight Severity-Downgrader Categories

Mark each ✓ (verified and the claim matches), ✗ (unverified or the claim overstates), or N/A. Anything
but ✓ needs a re-run or a text qualification before send.

### 1. Allocator dependence

Does the chain compose under the allocator the deployed binaries actually use? Read the build-system
default and override flags (`ACME_JEMALLOC`, `USE_TCMALLOC`, `WITH_MIMALLOC`, …) and whether the
upstream Dockerfile or packaging overrides them. A chain relying on glibc-malloc behaviour (chunk
metadata adjacency, tcache, safe-linking, fastbin LIFO) needs a run under another allocator (jemalloc
5.x, tcmalloc, mimalloc) or a precise argument that the structural property is allocator-portable. A
text-manipulation chain (CRLF, format string, parser bug) is allocator-independent only if no hidden
allocation path carries the bug.

**Disclosure language:** "affects builds compiled with allocator X", never "affects deployment Y"
without naming the allocator Y uses.

### 2. Plugin / module build-flag gate

Is the vulnerable plugin compiled into the binaries the disclosure names? Find the build option
(`ACME_OUT_SINK`, `ACME_IN_FORWARD`), its upstream default, and the production Dockerfile and
per-distro settings. An opt-in plugin must be called opt-in.

**Disclosure language:** "affects builds with `ACME_X=On` (the default)" or "affects deployments that
enable `ACME_X` (opt-in; upstream default `Off`)".

### 3. Default-config reach (minimum precondition)

What is the minimum operator configuration where the chain fires? Trace each config key the chain
touches from registration to consumption, separate always-on surfaces from operator-set values, and
say whether each operator-set precondition is the documented canonical configuration or a niche
tunable. An unsafe default (`tls.verify_hostname Off`) is still a precondition.

**Disclosure language:** "affects deployments with the sink plugin and its tenant key set", not
"affects all multi-tenant deployments".

### 4. Vendor-distro variation

For every distribution the disclosure names or implies, has its build config been checked? Build a
matrix over upstream Docker / `.deb` / `.rpm`, cloud-provider forks, Alpine, Fedora, Helm values,
Bottlerocket, and OS-distro packages, recording each recipe's load-bearing flags (allocator, plugin
gate, TLS defaults). Say so when a recipe is not public, and record N/A for distros that don't ship
the product so nobody re-checks.

**Disclosure language:** "Affects: A, B, C (verified). Status unknown for: D, E (vendor-internal
builds)."

### 5. Architecture dependence

Name the architecture the PoC was calibrated on: offsets, size-class bits, libc symbol offsets,
endianness, pointer size, and allocator page sizes differ across x86_64, aarch64, and 32-bit targets.

**Disclosure language:** "calibrated on x86_64 / glibc 2.42 / Linux 6.1; structurally equivalent on
aarch64 with re-calibration", not "cross-platform" without per-arch evidence.

### 6. Version-range lower bound

When was the bug introduced? A claim of "affects v2.4.1" with no lower bound reads as "2.4.1 only".
Use the bug-site file's history (pull upstream history when the tree is a shallow clone) and look for
refactors that introduced or fixed it earlier.

**Disclosure language:** "v2.4.1 confirmed; affected since X.Y based on git history", or "lower bound
not established; maintainers will have the history".

### 7. Claim-vs-evidence fidelity (TLS, auth, multi-tenant)

Does every adjective in the disclosure map to evidence the bundle carries? "TLS-authenticated
connection" needs a PoC over TLS, "pre-auth" needs pre-auth proof rather than an operator
misconfiguration, "multi-tenant" needs cross-tenant impact, and every cited evidence file must exist
in the bundle. This is the most common overstatement: proven under X, believed to generalize to Y,
written as if Y were proven.

**Disclosure language:** claim what was proven; to generalize, say "proven under X; the identical
primitive applies to Y because [structural reason]".

### 8. Negative-control bundling completeness

Does the bundle contain every evidence file the email and writeup cite? List every evidence reference
in the staged deliverables (`submissions/<slug>/submission.md`, `disclosure.txt`), list the files
actually staged or attached (`submissions/<slug>/`, the registered artifacts the export selects), and
diff them. Negative-control files are the ones most often cited from the engagement working directory
and never copied in; copy them or rewrite the citation to what ships.

**Disclosure language:** cite what is in the bundle. An engagement-internal path in an external
disclosure tells the reader the bundle was assembled in a hurry.

## Output Contract

| Item | Where |
|------|-------|
| Eight-category check table | Top of the audit memo, one row per category with ✓/✗/N/A and citation |
| Per-distro deployment matrix | The disclosure or the audit memo; rows per vendor distro × columns per load-bearing flag (allocator, plugin gate, key defaults) |
| Evidence-bundle citation diff | Every evidence reference in the staged deliverables, paired with the files actually staged or attached |
| Required text edits | For each ✗, the lines in `submission.md` / `disclosure.txt` that need correction, plus the corrected text |
| Required runtime work | For each ✗ caused by evidence claimed but not collected (TLS claimed, HTTP tested), the re-run required before send |

The audit memo lives at `tools/analysis-state/disclosure-shape-check-<slug>.md`, registered with
`vigil assess artifact register tools/analysis-state/disclosure-shape-check-<slug>.md --finding <slug>`
so it is attached to the finding (`agent/shared-specialist-core.md` "Output Hygiene"). A finding
without a passed audit memo does not ship as a critical-severity disclosure.

## Severity Recalibration Against Categories

- Category 1 fail (allocator): scope to "affects glibc-malloc builds" and document the DoS-only
  behaviour under other allocators; the headline splits into an RCE bucket and a DoS bucket with
  separate CVSS vectors.
- Category 2 fail (plugin gate): only deployments with the plugin compiled in are affected, and the
  claim says so.
- Category 3 fail (config reach): scope shrinks to deployments with the precondition set, which feeds
  Attack Complexity (`AC:L` for a documented canonical config, `AC:H` for a niche one).
- Category 4 fail (vendor variation): name the verified distros explicitly.
- Category 7 fail (claim fidelity): the strongest claim drops to what was proven, or the missing
  evidence is collected before send.
- Category 8 fail (bundling): a credibility issue rather than a severity one; triagers downgrade
  disclosures whose evidence references don't resolve.

## Worked Examples

Both on the fictional Acme LogShipper agent.

### Forward-input heap OOB to RCE — what category 1 caught

- **Before audit:** "lands `uid=0(root)` on the official release image".
- **Category 1 (allocator):** the build system defaults `ACME_JEMALLOC` to Off, but the official
  Dockerfile overrides it to On. Under jemalloc the OOB write still fires, but size-class slab
  segregation and out-of-band metadata prevent the finalizer-array overwrite, so the chain degrades to
  DoS; it composes only under glibc malloc.
- **Category 4 (vendor variation):** the upstream `.deb`/`.rpm`, the cloud-provider fork and the Helm
  chart all set jemalloc on; the RCE bucket is the long tail of source builds and OS-distro packages
  that omit the flag.
- **After audit:** split the claim into "RCE 9.8 on glibc source builds" and "DoS 7.5 on jemalloc
  builds (official image and mainstream packages)".

### Tenant smuggling via CRLF — what categories 7 + 8 caught

- **Before audit:** "the operator's outbound TLS connection to the log store", citing negative-control
  runs (no tenant key; CRLF filter enabled).
- **Category 7 (claim fidelity):** the PoC config pointed at a local plain-HTTP mock; TLS was never
  demonstrated, although the bug works above TLS.
- **Category 8 (bundling):** the staged evidence held the positive runs and parser confirmation; the
  cited negative-control runs existed only under `tools/exploit-state/`.
- **After audit:** re-run under TLS (the strongest version of the claim) and stage the negative
  controls, or qualify the language and stage them. Do not send until both are resolved.

## Extended Resources

- `agent/skills/code-finding-verification/SKILL.md` — source-side FP elimination (runs first)
- `agent/skills/heap-rce-evidence-ladder/SKILL.md` — per-rung evidence bar (runs alongside)
- `agent/skills/exploit-playbook-authoring/SKILL.md` — lab assists and their production equivalents
- `agent/rules/reporting.md` — disclosure-language rules; this skill applies them to deployment shape
