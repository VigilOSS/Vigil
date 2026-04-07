---
name: code-slicing
description: Assemble minimal source code slices for vulnerability analysis by extracting target functions with their callee chains, type definitions, and structural context
origin: AI Threat Hunting
---

# Code Slicing

## When to Activate

Phase 2 of code analysis pipeline. Runs after Phase 1 (code-architecture-mapping) has classified files, built the call graph, and generated attack hypotheses.

## Tools

Host-side file reading:
- `Read` / `cat` — read source files in full
- `grep` / `rg` — locate function definitions, call sites, type definitions, macro expansions
- `wc -l` — verify slice sizes stay within budget

Cross-reference tools:
- **ctags index**: `grep '^<symbol>\t' <repo>/tags` for definition lookup
- **grep/rg**: `rg '<function>\s*\(' --type c` for call site enumeration

## Division of Labor

- **Operator provides**: queue items (target function + file), call graph excerpt, repo root path, ctags path
- **Slicer reads**: source code directly from filesystem
- **Slicer produces**: assembled source code slices (actual code, not annotations)

## Methodology

### Step 1: Locate Target Function

For each queue item:
1. Use the file path and function name from the queue item
2. Read the target file, locate the function by name/line range
3. Extract the complete function body (from opening brace to closing brace)
4. Record: file path, start line, end line, function signature

If the function cannot be found at the expected location (refactored code):
1. Use ctags: `grep '^<function_name>\t' <repo>/tags`
2. If ctags fails: `rg '<function_name>\s*\(' --type c` to find definition
3. If still not found: record as UNRESOLVED and continue

### Step 2: Resolve Callees (2 Levels Deep)

For each function call within the target function body:

**Level 1 (direct callees):**
1. Identify all function calls in the target body
2. For each: locate definition via ctags (`grep '^<callee>\t' tags`)
3. Read the full callee function body
4. Record: file path, line range, signature

**Level 2 (callees of callees):**
1. For each Level 1 callee: identify function calls in its body
2. For each: locate definition via ctags, read full body
3. Record same metadata

**Priority order when callee tree is large** (most important first):
1. Functions that receive parameters derived from the target's untrusted inputs
2. Memory operations: `memcpy`, `memmove`, `malloc`, `realloc`, `free`, `alloca`
3. System calls: `exec*`, `system`, `popen`, `open`, `connect`, `bind`
4. String operations: `strcpy`, `strcat`, `sprintf`, `snprintf`, `strncpy`
5. Output operations: `write`, `send`, `printf`, `fprintf`, `fputs`
6. Comparison operations used for security decisions
7. Functions in the same module as the target
8. Cross-module functions

**Stop conditions:**
- Standard library functions (libc, POSIX) — note their known behavior instead
- Third-party library functions — note as external, model behavior from docs/headers
- Depth exceeds 2 — note the callee signature but do not inline body
- Already included in this slice — note "see above" reference

### Step 3: Resolve Callers (1 Level Up)

1. Use grep/rg to find all call sites of the target function:
   `rg '<target_function>\s*\(' --type c`
2. For each caller: read ~30 lines of context around the call site
3. Include: what arguments are passed, any guards applied before the call
4. This gives the hunter entry-point context for the target

### Step 4: Resolve Types and Macros

For each struct, enum, typedef, union used by the target and its callees:
1. Locate definition via ctags or grep
2. Include the complete type definition in the slice

For each macro used (identified by ALL_CAPS naming or `#define` reference):
1. Locate the `#define` via grep
2. Include the macro definition
3. If the macro contains control flow (`goto`, `return`, `break`), function calls,
   or memory operations — flag it with a comment:
   `// NOTE: This macro contains [control flow / memory op / function call]`

For each constant (`#define` values for sizes, limits, buffer bounds):
1. Include the definition
2. These are critical for the hunter to evaluate bounds checks

### Step 5: Assemble Slice

Concatenate all resolved code into a single structured document:

```
=== SLICE: <target_function> ===
Queue Item: <id> | Priority: <score>
Repository: <repo_path>
Generated: <timestamp>

--- TABLE OF CONTENTS ---
Target: <function> | <file>:<start>-<end>
Callees (d1): <list>
Callees (d2): <list>
Callers: <list>
Types: <list>
Macros: <list>
Unresolved: <list>

--- TARGET: <function> | <file>:<start>-<end> ---
<full function source code>

--- CALLEE [d1]: <function> | <file>:<start>-<end> ---
<full function source code>

--- CALLEE [d2]: <function> | <file>:<start>-<end> ---
<full function source code>

--- CALLER: <function> | <file>:<line_range> ---
<~30 lines of context around call site>

--- TYPE: <name> | <file>:<start>-<end> ---
<type definition>

--- MACRO: <name> | <file>:<line> ---
<macro definition>
// NOTE: Contains [control flow / memory op / etc.] if applicable

--- UNRESOLVED ---
- <function> (<reason>: external library / generated code / depth exceeded)
  Known behavior: <brief description if known>
```

### Step 6: Size Check and Trimming

After assembly, verify total lines:

- **2K-15K lines**: within budget, proceed
- **>15K lines**: trim in priority order (lowest priority removed first):
  1. Depth-2 callees — replace with signature + `// body at <file>:<line>`
  2. Caller context — reduce to call-site line only
  3. Low-priority depth-1 callees — replace with signature
  4. NEVER trim: target function body, type definitions, security-relevant macros
- **<2K lines**: the slice may be too narrow. Check if important callees were missed.
  Consider expanding callee depth to 3 for this slice.

Record final size and any trimming decisions in Assembly Metadata.

## Output Format

1. **Slice files**: one `.md` file per queue item, written to `analysis-state/` directory
2. **Assembly metadata**: JSON with file paths, line counts, callee depth, unresolved refs
3. **Coverage report**: which queue items have slices, which failed

## Extended Resources

None required — this is a mechanical assembly operation, not an analytical one.
The CWE pattern references are loaded by the hunter in Phase 3, not by the slicer.
