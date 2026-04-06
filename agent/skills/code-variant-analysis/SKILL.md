---
name: code-variant-analysis
description: Systematic scanning for variant instances of confirmed bug patterns across the codebase
origin: AI Threat Hunting
---

# Code Variant Analysis

## When to Activate

- Phase 4 of code analysis pipeline. Runs after vulnerability analysis has produced confirmed findings or suspicious patterns.
- Triggered once per confirmed finding or high-confidence suspicious pattern.
- Goal: maximize yield by finding every instance of a proven bug pattern across the entire codebase, not just the module where it was first discovered.

## Tools

- `rg` / `grep` — pattern matching for function names, code shapes, anti-patterns
- Host-side file reading (`cat`) — read candidate files for detailed analysis
- `find` — locate files matching naming or extension criteria

Cross-reference tools:
- **ctags index** — `grep '^<symbol>\t' <repo>/tags` to find definitions of vulnerable functions and their wrappers
- **grep / rg** — find every call site of a vulnerable function across the entire codebase, trace incoming calls to identify all code paths that reach a vulnerable pattern

## Methodology

### Step 1: Extract Abstract Pattern

From the confirmed finding, derive a search pattern at the right level of abstraction. The pattern must be:

- **Specific enough** to produce a manageable candidate set (dozens, not thousands)
- **General enough** to catch all variants, including those using different variable names, wrapper functions, or slightly different code structure

**Abstraction process:**
1. Start with the concrete bug: exact function, exact variable, exact line
2. Identify the structural elements: what makes this a bug? (untrusted input reaches sink without guard)
3. Generalize the structural elements: replace specific names with categories (any memcpy-like function, any untrusted-derived size, any missing bounds check)
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

For each candidate file identified by search queries:

1. **Read the candidate function** in full, including enough surrounding context to understand the call chain
2. **Quick taint check**: Does untrusted data (from any slot type) reach this instance of the pattern? If no untrusted data is involved, skip — this is not a variant.
3. **Guard assessment**: Are the guards present? Are they correct? Apply the same guard evaluation criteria from the vulnerability analysis protocol:
   - Right variable?
   - Right type?
   - Right bound?
   - All paths covered?
   - Before the dangerous operation?
   - Not bypassable?
4. **Classify**: Is this a true variant, a false positive (properly guarded), or a different bug entirely?

### Step 4: Record Variants

Each confirmed variant is recorded as a separate finding with a link to the original:

```
VARIANT FINDING: [CWE-XXX] [Brief title]
Variant Of: [original finding ID]
Link Kind: variant_of
File: [path]:[start_line]-[end_line]
Function: [name]
Severity: [own severity assessment — variants may be more or less severe than the original]
Taint Path: [entry] -> ... -> [sink]
Guard Failure: [same structural issue as original, or a different specific failure]
Impact: [concrete impact for THIS instance — may differ from original]
Evidence: [code snippet]
```

**Severity independence**: Variants receive their own severity assessment. A variant may be:
- **More severe** than the original (e.g., reachable from a more exposed entry point, larger overflow, in a more privileged context)
- **Less severe** (e.g., partially guarded, reachable only from authenticated context, smaller impact)
- **Same severity** (structurally identical exposure)

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

This ordering maximizes the chance of finding variants early, since code proximity correlates with pattern similarity.

## Output Format

For each variant scan, produce:
1. **Pattern Summary**: abstract pattern derived from original finding
2. **Search Queries Used**: exact grep/rg commands run
3. **Candidates Examined**: count of files/functions read and assessed
4. **Confirmed Variants**: full finding records with `variant_of` links
5. **False Positives**: count with brief reasoning (e.g., "12 instances properly guarded by upstream bounds check in `validate_input()`")
6. **Coverage Assessment**: estimate of what percentage of the codebase was scanned for this pattern

## Extended Resources

- Original finding details (provided in dispatch context) — the concrete bug that seeds the variant search
- Architecture map from Phase 1 — file classifications and module groupings for systematic scanning
- Context slices from Phase 2 — call graphs and data flow annotations for quick taint assessment
- **CWE pattern reference (REQUIRED)** — load the `agent/references/code-vuln-patterns/*.md` file matching the original finding's CWE. The pattern taxonomy, language-specific idioms, and "What You're Hunting" sections define what a variant looks like for this bug class. Without this, variant scanning degrades to grep-for-similar-syntax rather than hunting the underlying pattern.
