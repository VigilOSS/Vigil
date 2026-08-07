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
  non-covering discovery seed before the main hunt. This mode has no `variant_dispatch_id` or
  `parent_finding_slugs` and produces no variant-check receipts.
- **Phase 3 receipt-bearing mode:** use the exact frozen, non-empty current parent set registered on
  the dispatch to find siblings and account for every current admitted file with a receipt.
- Goal: maximize yield by finding semantic repeats without letting exploratory Phase 2 work claim
  Phase 3 completeness.

## Tools

- `rg` — pattern matching for function names, code shapes, and anti-patterns
- `Read` — inspect candidate files for detailed analysis
- `Glob` — locate files by naming or extension pattern

Cross-reference tools:
- **ctags index** — `grep '^<symbol>\t' <ctags_path>` using the generation-bound Code Source Identity path
- **rg** — find every call site of a vulnerable function across the entire codebase, trace incoming calls to identify all code paths that reach a vulnerable pattern

## Required Dispatch Inputs

The operator supplies the current Code Source Identity, its matching structural-index manifest,
and the complete backend threat-model envelope only when `current: true` and its generation/digest
match that identity. Runtime Identity `authorized_phase` selects the mode:

- Phase 2 supplies historical CVE/patch bug-shape evidence (including vulnerable/fixed code when
  available) and a bounded search scope while omitting both receipt-authority fields.
- Phase 3 supplies both the numeric `variant_dispatch_id` and canonical sorted, non-empty
  `parent_finding_slugs`, the corresponding finding/pattern evidence, and every current admitted
  file's identity.

Apply the malformed/partial-input stop in the role prompt before source reading. A clipped threat
summary is supplemental and never substitutes for the bound envelope.

## Methodology

### Step 1: Extract Abstract Pattern

From the historical vulnerable/fixed evidence (Phase 2) or frozen current finding (Phase 3), derive
a search pattern at the right level of abstraction. The pattern must be:

- **Specific enough** to produce a manageable candidate set (dozens, not thousands)
- **General enough** to catch all variants, including those using different variable names, wrapper functions, or slightly different code structure

**Abstraction process:**
1. Start with the concrete bug: exact function, exact variable, exact line
2. Identify the structural elements: either an untrusted-input flow reaches a sink without its guard, or a valid operation/state/lifetime sequence breaks a security invariant
3. Generalize those elements: replace names with categories such as memcpy-like sink/untrusted size/missing bound, or borrowed lifetime/persistent handle/missing state reset
4. Preserve the distinguishing constraint: the specific reason the guard is missing or insufficient

**Example abstraction levels:**

| Level | Pattern | Quality |
|-------|---------|---------|
| Too specific | `memcpy(header->value, raw, actual_len)` at line 270 of parser.c | Only finds the exact known bug |
| Too general | Any call to `memcpy` anywhere | Thousands of results, mostly false positives |
| Just right | `memcpy` where size argument derives from untrusted input via `strlen` arithmetic without subsequent bounds check against destination buffer size | Catches the structural pattern with manageable results |

### Step 2: Generate Search Queries

From the abstract pattern, generate multiple concrete search queries to cast a wide net:

**Function name queries:**
- The exact sink function: `memcpy`, `strcpy`, `sprintf`
- Project-specific wrappers: search for functions that call the sink internally (e.g., `my_buffer_copy`, `safe_strcpy` that is not actually safe)
- Macro wrappers: `#define COPY_BUFFER(...)` that expand to the sink

```bash
# Find all callers of the vulnerable sink
rg "memcpy\s*\(" --type c -l

# Find project-specific wrappers
rg "memcpy|memmove|bcopy" --type c -l  # files that use these
rg "void\s+\w+copy\w*\s*\(" --type c   # functions with "copy" in name
```

**Code shape queries:**
- Size variables derived from the same untrusted source: `strlen(untrusted)`, `header->length`, `ntohs(pkt->len)`
- Arithmetic patterns: `size + offset`, `len * count`, `base + strlen(str)`
- Missing guard patterns: sink call NOT preceded by bounds check in the same function

```bash
# Find strlen-derived size used in memcpy
rg "strlen\(.+\)" --type c -l
rg "len\s*=\s*strlen" --type c

# Find allocation-copy patterns (common source of mismatched sizes)
rg "malloc.*strlen" --type c -A5
```

**Anti-pattern queries (absence of guards):**
- Functions that use the sink but do NOT contain the expected bounds check
- Functions that check bounds on one path but not another (partial guard)
- Functions where the bounds check uses a different variable than the sink

### Step 3: Scan Systematically

In Phase 3, search-query matches control ordering, not the receipt inventory: process every current
admitted file. For a file that cannot instantiate, route, configure, or reach any frozen pattern,
perform a bounded pattern-inapplicability check and retain that rationale for its non-match receipt.
For each candidate match that survives that quick check:

1. **Read the candidate function** in full, including enough surrounding context to understand the call chain
2. **Quick target-kind reachability check**: Apply `agent/shared-constraints-code.md` §5. For an
   application, trace the actor-controlled slot input. For a library/framework, a supported public
   API and valid invocation/state sequence can establish the same intrinsic bug variant even when
   consumer source is absent; retain the consumer gap for impact grading. Use the shipped CLI input
   or registered plugin host contract for those surfaces. Skip only when no applicable product path
   exists, the trigger violates a documented precondition, or the value/state is genuinely trusted
   for the claim being tested.
3. **Guard assessment**: Are the guards present? Are they correct? Apply the same guard evaluation criteria from the vulnerability analysis protocol:
   - Right variable?
   - Right type?
   - Right bound?
   - All paths covered?
   - Before the dangerous operation?
   - Not bypassable?
4. **Classify**: Is this a true variant, a false positive (properly guarded), or a different bug entirely?

### Step 4: Record Variants

Each confirmed instance is recorded as a separate finding. In Phase 3, or when Phase 2 has an
actual canonical current parent, link it to that parent:

```
VARIANT FINDING: [CWE-XXX] [Brief title]
Variant Of: [assigned/canonical current parent ID; omit in Phase 2 when none exists]
Link Kind: variant_of
File: [path]:[start_line]-[end_line]
Function: [name]
Severity: [own severity assessment — variants may be more or less severe than the original]
Trigger Path: [taint flow OR supported operation/state/lifetime sequence]
Guard Failure: [same structural issue as original, or a different specific failure]
Impact: [concrete impact for THIS instance — may differ from original]
Evidence: [code snippet]
```

**Severity independence**: Variants receive their own severity assessment. A variant may be:
- **More severe** than the original (e.g., reachable from a more exposed entry point, larger overflow, in a more privileged context)
- **Less severe** (e.g., partially guarded, reachable only from authenticated context, smaller impact)
- **Same severity** (structurally identical exposure)

Product reachability and attacker reachability remain separate during this assessment. Missing
consumer/host context caps a supported-path variant's attacker claim and severity; generic
caller-selected capability or correctness-only behavior still fails the shared net-new/impact gate.
In Phase 2, deduplicate against main-hunt findings before recording and omit `variant_of` when no
canonical current parent exists; a historical CVE identifier is supporting evidence, not a Vigil
finding relationship.

## Abstraction Level Guide

### Buffer Overflow Variants

| Original | Too Specific | Too General | Just Right |
|----------|-------------|-------------|------------|
| `memcpy(dst, src, untrusted_len)` without check | Same exact variable names | Any `memcpy` | `memcpy` where third arg derives from network input without prior `min(len, sizeof(dst))` |
| Off-by-one in `for (i=0; i<=len; i++)` | Same loop variable | Any `<=` in loops | Loop bound uses `<=` with untrusted-derived limit on buffer indexed by loop variable |

### Integer Overflow Variants

| Original | Too Specific | Too General | Just Right |
|----------|-------------|-------------|------------|
| `malloc(count * sizeof(item))` overflow | Same struct type | Any multiplication in `malloc` | `malloc(A * B)` where A is untrusted and no overflow check before multiplication |
| `uint16_t total = a + b` truncation | Same variable names | Any addition | Addition of untrusted values stored in narrower type than operands, used as allocation size or bounds check |

### Logic Bug Variants

| Original | Too Specific | Too General | Just Right |
|----------|-------------|-------------|------------|
| Auth bypass via empty password | Same auth function | Any auth check | Authentication functions where empty/null input causes early success return instead of failure |
| TOCTOU in file check-then-use | Same file path | Any file operation pair | `access()`/`stat()` followed by `open()` on same path without O_NOFOLLOW or lock |

### Language-Specific Search Patterns

When scanning non-C/C++ codebases, use these language-idiomatic patterns instead of (or alongside) the C-focused examples above.

#### Python
```bash
# Dangerous sinks
rg "\.raw\(|\.extra\(|RawSQL|eval\(|exec\(|compile\(" --type py -l
rg "pickle\.(loads|load)\(|yaml\.load\(|subprocess.*shell\s*=\s*True" --type py -l
rg "__import__|getattr\(.*,\s*(user|req|param|input)" --type py -l

# Auth patterns
rg "login_required|permission_required|has_perm|is_authenticated" --type py -l
rg "@(csrf_exempt|require_http_methods)" --type py -l

# ORM with user input
rg "\.filter\(.*request\.|\.exclude\(.*request\." --type py -l
rg "order_by\(.*request\.|\.extra\(" --type py -l
```

#### JavaScript / TypeScript
```bash
# Dangerous sinks
rg "eval\(|Function\(|child_process|\.exec\(|\.execSync\(" --type js --type ts -l
rg "innerHTML|outerHTML|document\.write|\.html\(" --type js --type ts -l
rg "__proto__|constructor\[|prototype\[" --type js --type ts -l

# Auth patterns
rg "isAuthenticated|isAuthorized|requireAuth|passport\." --type js --type ts -l
rg "jwt\.verify|jwt\.decode|jsonwebtoken" --type js --type ts -l

# ORM/DB with user input
rg "\.findById\(req\.|\.findOne\(.*req\.|\.literal\(" --type js --type ts -l
rg "\$where|\$regex|\$ne|\$gt|\$lt" --type js --type ts -l
```

#### Java
```bash
# Dangerous sinks
rg "ObjectInputStream|Runtime\.getRuntime|ProcessBuilder" --type java -l
rg "createNativeQuery|createQuery\(.*\+|Statement\.execute" --type java -l
rg "XMLInputFactory|SAXParser|DocumentBuilder" --type java -l

# Auth patterns
rg "@PreAuthorize|@Secured|@RolesAllowed|hasRole|hasAuthority" --type java -l
rg "antMatchers|requestMatchers|authorizeRequests" --type java -l

# Deserialization
rg "readObject\(|readResolve\(|Serializable" --type java -l
rg "ObjectMapper.*enableDefaultTyping|@JsonTypeInfo" --type java -l
```

#### Go
```bash
# Dangerous sinks
rg "unsafe\.Pointer|exec\.Command|os\.StartProcess" --type go -l
rg "template\.HTML|template\.JS|template\.URL" --type go -l
rg "sql\.Query\(.*\+|sql\.Exec\(.*\+" --type go -l

# Auth patterns
rg "func.*middleware|func.*auth|jwt\.|ParseToken" --type go -l

# Type safety
rg "interface\{\}|\.\(type\)|reflect\." --type go -l
```

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

For each scan, produce:
1. **Pattern Summary**: abstract pattern derived from original finding
2. **Search Queries Used**: exact grep/rg commands run
3. **Candidates Examined**: count of files/functions read and assessed
4. **Confirmed Instances**: full finding records; include `variant_of` only for a real canonical
   parent, which is mandatory in Phase 3
5. **False Positives**: count with brief reasoning (e.g., "12 instances properly guarded by upstream bounds check in `validate_input()`")
6. **Per-File Evidence (Phase 3 only)**: one engagement-owned artifact per current admitted file,
   including clean and bounded non-match files, ready for the role's dispatch-bound `code-record variant-check` step
7. **Coverage Assessment**: Phase 3 reports exact admitted-file completion with no unassigned gap;
   Phase 2 labels the result `non-covering discovery` and reports its bounded search scope and gaps

Receipt payload shape and closing order belong to `vigil assess contract code-record variant-check`
and the `code-variant-hunter` role prompt; use those executable owners instead of copying the schema
into this skill.

## Extended Resources

- Historical CVE/patch evidence (Phase 2) or frozen current finding details (Phase 3) — the
  concrete bug shape that seeds the search
- Architecture map from Phase 1 — file classifications and module groupings for systematic scanning
- Call graph from Phase 1 — cross-module call chains for tracing untrusted data flow during quick taint checks
- Full sealed-source access — read source files beneath `snapshot_path` for pattern matching and taint verification
- **CWE pattern reference (REQUIRED)** — load the `agent/references/code-vuln-patterns/*.md` file matching the original finding's CWE. The pattern taxonomy, language-specific idioms, and "What You're Hunting" sections define what a variant looks like for this bug class. Without this, variant scanning degrades to grep-for-similar-syntax rather than hunting the underlying pattern.
