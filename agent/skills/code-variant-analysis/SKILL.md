---
name: code-variant-analysis
description: Systematic scanning for historical bug shapes and variants of current findings across the codebase
origin: Vigil
vuln_class: injection, web-app-injection, web-app-auth, web-app-data-exposure, deserialization, crypto-misuse, error-handling, algorithmic-dos, buffer-overflow, integer-overflow, format-string, null-dereference, use-after-free, uninitialized-memory, type-confusion
---

# Code Variant Analysis

Together with `agent/shared-constraints-code.md` §5, this skill owns code bug-shape abstraction:
derive a semantic pattern from historical evidence or a current finding, verify candidates,
assess each instance's own impact, and check composable chains. The role prompt owns the
mode-specific recording and receipt sequence. The web hunting rules are not required.

## When to Activate

- **Phase 2 discovery mode:** use supplied historical CVE/patch bug-shape evidence as an additive,
  non-covering discovery seed before the main hunt. This mode's packet has no
  `## Variant Receipt Authority` block and produces no variant-check receipts.
- **Phase 3 receipt-bearing mode:** use the exact frozen, non-empty current parent set registered on
  the dispatch to find siblings and account for every current admitted file with a receipt.
- Goal: maximize yield by finding semantic repeats without letting exploratory Phase 2 work claim
  Phase 3 completeness.

## Tools

`rg`, Read, Glob, and ctags (`grep '^<symbol>\t' "$ctags_path"` from the generation-bound Code
Source Identity) beneath the sealed `snapshot_path`: find every call site of the vulnerable function
and trace the incoming paths that reach the pattern.

## Required Dispatch Inputs

The operator supplies the current Code Source Identity, its matching structural-index manifest,
and the complete backend threat-model envelope only when `current: true` and its generation/digest
match that identity. Runtime Identity `authorized_phase` selects the mode:

- Phase 2 supplies historical CVE/patch bug-shape evidence (including vulnerable/fixed code when
  available) and a bounded search scope; its packet has no Variant Receipt Authority block.
- Phase 3's packet carries the `## Variant Receipt Authority` block `agent start` renders (the
  canonical sorted, non-empty `parent_finding_slugs` and the `--agent-id` receipt binding), plus
  the corresponding finding/pattern evidence and every current admitted file's identity.

Apply the malformed/partial-input stop in the role prompt before source reading. A clipped threat
summary is supplemental and never substitutes for the bound envelope.

## Methodology

### Step 1: Extract Abstract Pattern

From the historical vulnerable/fixed evidence (Phase 2) or the frozen current finding (Phase 3),
derive a pattern specific enough to yield a manageable candidate set (dozens, not thousands) and
general enough to catch renamed variables, wrappers, and restructured code. Start from the concrete
bug, identify its structural elements (an untrusted flow reaching a sink without its guard, or a
valid operation/state/lifetime sequence breaking an invariant), replace names with categories
(memcpy-like sink, untrusted size, missing bound; borrowed lifetime, persistent handle, missing
reset), and keep the distinguishing constraint — the specific reason the guard is missing or
insufficient.

| Original | Too specific | Too general | Just right |
|----------|-------------|-------------|------------|
| `memcpy(dst, src, untrusted_len)` unchecked | Same variable names | Any `memcpy` | `memcpy` whose length derives from network input with no prior `min(len, sizeof(dst))` |
| Off-by-one `for (i=0; i<=len; i++)` | Same loop variable | Any `<=` loop | `<=` bound with an untrusted-derived limit on a buffer indexed by the loop variable |
| `malloc(count * sizeof(item))` overflow | Same struct | Any multiplication in `malloc` | `malloc(A * B)` with A untrusted and no overflow check before the multiply |
| `uint16_t total = a + b` truncation | Same names | Any addition | Untrusted sum stored narrower than its operands, then used as a size or bound |
| Empty password authenticates | Same auth function | Any auth check | Auth functions where empty or null input returns success early |
| `access()`/`stat()` then `open()` | Same path | Any file-operation pair | Check-then-use on one path with no lock across both and no descriptor-based check (open first with per-component `O_NOFOLLOW` or `RESOLVE_NO_SYMLINKS`, then `fstat`) |

### Step 2: Generate Search Queries

Cast a wide net from the pattern: the sink itself; project wrappers that call it (including a
`safe_*` helper that is not safe) and macros that expand to it; size variables from the same
untrusted source (`strlen(untrusted)`, `header->length`, `ntohs(pkt->len)`); the arithmetic shapes
(`size + offset`, `len * count`); and the absence of guards — sinks with no preceding bounds check,
checks on one path only, and checks against a different variable than the sink uses.

### Step 3: Scan Systematically

In Phase 3, search-query matches control ordering, not the receipt inventory: process every current
admitted file. For a file that cannot instantiate, route, configure, or reach any frozen pattern,
perform a bounded pattern-inapplicability check and retain that rationale for its non-match receipt.
For each candidate match that survives that quick check:

1. **Read the candidate function** in full, with enough context for its call chain.
2. **Quick target-kind reachability check** (§5): the actor-controlled slot input for an application;
   a supported public API and valid invocation/state sequence for a library or framework (keep the
   consumer gap for impact grading); the shipped CLI input or registered plugin host contract. Skip
   only when no applicable product path exists, the trigger violates a documented precondition, or
   the value or state is genuinely trusted for the claim.
3. **Guard assessment** by the hunt skill's criteria: right variable, type, and bound, every path,
   before the dangerous operation, not bypassable.
4. **Classify**: true variant, properly guarded, or a different bug.

### Step 4: Record Variants

Each confirmed instance is recorded as a separate finding. In Phase 3, or when Phase 2 has an
actual canonical current parent, record explicit child ancestry with this `links` array entry:

```json
{"links": [{"link_kind": "variant_of", "target_kind": "finding", "target_ref": "AC-001"}]}
```

Use the parent's actual canonical slug. This relationship makes the new finding a child and excludes
it from the Phase 2 root set. Findings that merely share a CWE, bug class, or similar behavior while
remaining independent use `link_kind: "related"`; neither the finding's prefix nor the scanner role
determines ancestry. `details.variant_of` is informational attribution, not a substitute for this
relationship. Keep severity and verification independent for each finding.

The evidence description carries `Variant Of` (the canonical current parent; omitted in Phase 2
when none exists), `Link Kind`, file:lines, function, its own severity, trigger path (taint flow or
supported operation/state/lifetime sequence), guard failure (the original's structural issue or a
different one), its own impact, and an evidence snippet.

Each variant gets its own severity: more severe from a more exposed entry, a larger overflow, or a
more privileged context; less severe behind a partial guard or authentication; the same when the
exposure is structurally identical. Product and attacker reachability stay separate: missing
consumer or host context caps a supported-path variant's claim, and generic caller-selected
capability or correctness-only behavior still fails the shared net-new and impact gate. In Phase 2,
deduplicate against main-hunt findings first and omit the child relationship when no canonical
current parent exists; a historical CVE id is supporting evidence, not a Vigil finding relationship.

### Grep Idiom for Variant Scans

The search itself is yours to write; these are the habits that decide whether it returns the
variants or a confident empty result.

- **Always pass an explicit path root** — the sealed `snapshot_path`, or a subtree of it. A
  rootless `rg` searches the working directory, which on a code engagement is not the snapshot
  (`agent/shared-constraints-code.md` §3).
- **Search the module or import, not the call.** `child_process`, not `child_process.exec` —
  one import line names every aliased, destructured and wrapped call site downstream.
- **Search the registration, not the callee.** `@register(`, `@receiver(`, `bind(`,
  `addEventListener(` reach handlers whose own names you cannot guess.
- **Start with `-l` or `-c`, narrow, then `-n`.** A file list tells you the blast radius; line
  hits on an unnarrowed pattern bury it.
- **Case and word shape decide recall.** Exported Go identifiers are capitalised, Java
  annotations are not; `-i` or an explicit alternation, never a single lowercase spelling.
- **`rg` is line-oriented and `--type` is narrower than you think.** A sink split across lines by
  a formatter does not match, and `--type c` excludes `.cpp`/`.cc`/`.hpp`. When a pattern must
  span lines or types, widen the search (`rg -U`, explicit globs) or read the files. The structural
  index is line-based too, so a miss there is not proof either.

An empty result is evidence only after you have confirmed the root, the case and the file types.

## Scan Ordering

Process candidate files in this order:
1. **Sibling functions** — other functions in the same file as the original finding
2. **Sibling modules** — files in the same module performing similar operations
3. **Same slot type** — files with the same slot-type annotation across other modules
4. **Same sink type** — files using the same sink function anywhere in the codebase

This is scheduling, not eligibility. In Phase 3, sweep every current admitted file—including
low-priority and cross-language/declarative files—and prepare a receipt even when a bounded quick
check shows that the file cannot instantiate, route, configure, or reach the pattern. In
Phase 2, exhaust the bounded historical-evidence search scope, preserve unsearched gaps in the
handoff, and keep the result explicitly non-covering.

## Output Format

Per scan: the abstract pattern; the exact search commands run; candidates read and assessed;
confirmed instances as full finding records (the Step 4 child link only for a real canonical
parent, `related` for independent same-class findings); false positives with a brief reason ("12
guarded by the upstream bounds check in `validate_input()`"); in Phase 3, one engagement-owned
evidence artifact per current admitted file, clean and bounded non-matches included, ready for the
role's `code-record variant-check` step; and coverage — exact admitted-file completion in Phase 3,
or `non-covering discovery` with the bounded scope and gaps in Phase 2. Receipt shape and closing
order belong to `vigil assess contract code-record variant-check` and the `code-variant-hunter`
role prompt.

## Extended Resources

- **CWE pattern reference (REQUIRED once the pattern is extracted):** the
  `agent/references/code-vuln-patterns/*.md` file for the original finding's CWE. Its idioms and
  "What You're Hunting" section define what a variant of the class looks like; without it, variant
  scanning degrades to grepping for similar syntax.
- The seed evidence (historical vulnerable/fixed code in Phase 2, frozen finding details in
  Phase 3), the Phase 1 architecture map and call graph, and full sealed-source access.
