---
name: code-context-building
description: Extract function-level context slices with call graphs, data flow, and guard annotations
origin: AI Threat Hunting
---

# Code Context Building

## When to Activate

- Phase 2 of code analysis pipeline. Runs after code-architecture-mapping has completed file classification and module grouping.
- One dispatch per module batch (~15-20K lines). Large modules are split into sub-batches.
- Every critical and high file must pass through this phase before vulnerability analysis begins.

## Tools

Host-side file reading:
- `cat` — read full source files
- `grep` / `rg` — locate function definitions, call sites, type definitions, macro expansions
- `wc -l` — verify batch sizes stay within target

## Division of Labor

- **Operator** provides: module file list, header snippets from Phase 1, classification tier and slot-type annotations per file, priority ordering.
- **Builder** reads: full source code for assigned module batch plus relevant headers/type definitions. Produces: context slices with call graphs, data flow annotations, guard catalogs, and a prioritized analysis queue.

## Methodology

### Step 1: Read All Source Files in Module Batch

Read every source file in the assigned batch in full. Additionally read:
- Header files (`.h`, `.hpp`) included by batch files
- Type definition files (structs, enums, typedefs, interfaces) referenced by batch files
- Macro definition files that expand into code used by batch files
- Shared constants and configuration headers

If a referenced header is outside the current batch, read it but do not produce full context slices for it — record its signatures for cross-reference annotation only.

### Step 2: Extract Definitions

For every file in the batch, extract and catalog:

**Function signatures**:
- Name, return type, parameter types and names
- Visibility (public/exported, static/private, inline)
- Attributes/annotations (e.g., `__attribute__((nonnull))`, `unsafe`, `#[no_mangle]`)
- File path and line range (start_line, end_line)

**Struct/class definitions**:
- Name, fields with types and sizes
- Alignment and packing directives
- Nested types, unions, bitfields

**Enum definitions**:
- Name, variant names and values
- Whether used for state machines, error codes, or flags

**Macro definitions**:
- Name, parameters, expansion body
- Whether the macro generates code, performs arithmetic, or wraps a function call
- Mark macros that hide control flow (e.g., `CHECK()` macros that return/goto on failure)

### Step 3: Build Intra-Module Call Graph

For every function in the batch, trace all call sites:

```
function_A (file.c:100-150)
  calls function_B at line 112 (args: ptr, len)
  calls function_C at line 125 (args: buf, sizeof(buf))
  calls function_D at line 140 (args: user_input, user_len)  // untrusted
  called_by: function_E (file.c:200), function_F (other.c:50)
```

Record for each call:
- Caller function, callee function, call site line number
- Arguments passed (variable names, expressions, constants)
- Whether any argument carries untrusted data (from slot-type annotations)
- Call type: direct, indirect (function pointer), virtual (vtable), callback

### Step 4: Annotate Cross-Module Calls

For calls to functions outside the current batch:
- Record the callee function signature (from headers or type definitions read in Step 1)
- Record the slot-type annotations on parameters (inherited from architecture mapping)
- Mark as `cross_module_call` with the target module name
- Do NOT trace into the callee body — that will happen when its module batch is processed
- If the callee is in a system library or third-party dependency, record its known behavior (e.g., `memcpy(dst, src, n)` — copies n bytes, no bounds check)

### Step 5: Trace Data Flow and Annotate Guards and Sinks

For each function in critical and high files, perform detailed intra-procedural analysis:

**Untrusted data carriers**:
- Identify parameters that carry untrusted data (from slot-type annotations and caller analysis)
- Track local variables derived from untrusted parameters through assignments, casts, arithmetic
- Track structure field accesses on untrusted structs
- Mark derived size variables separately (e.g., `len = strlen(untrusted_str)`)

**Sinks** — catalog every operation that could cause harm if fed untrusted data:
- Memory writes: `memcpy`, `memmove`, `strcpy`, `sprintf`, array index writes, pointer arithmetic writes
- System calls: `exec*`, `system`, `popen`, `open`, `connect`, `bind`, `ioctl`
- Output operations: `write`, `send`, `printf`, `fprintf`, `syslog`, format string consumers
- Comparisons that control security decisions: authentication checks, authorization gates, bounds comparisons
- Allocations with attacker-influenced sizes: `malloc(user_size)`, `alloca(n)`, VLA declarations
- Type conversions: integer truncation, signed/unsigned conversion, pointer casts

**Guards** — catalog every protective check on the path to a sink:
- Bounds checks: `if (len > MAX)`, `if (index < array_size)`
- Sanitization: input validation, encoding, escaping, normalization
- Type enforcement: type checks, range validation, enum membership tests
- Null checks: `if (ptr == NULL)`, `if (!ptr)`
- Error handling: return code checks, exception handlers, `goto cleanup` patterns

For each guard, record:
- Which variable it checks
- Where it is relative to the sink (before/after, same function/caller)
- Whether it is on ALL paths to the sink or only some paths
- Whether it can be bypassed (e.g., integer overflow in the bounds check itself)

### Step 6: Produce Prioritized Analysis Queue

Score each function for vulnerability analysis priority:

```
function_priority = entry_point_proximity * slot_type_risk * sink_density * guard_sparsity
```

| Factor | Scoring |
|--------|---------|
| `entry_point_proximity` | direct entry=4, 1 hop=3, 2 hops=2, 3+ hops=1 |
| `slot_type_risk` | NETWORK-INPUT/PROTOCOL-FIELD=4, CMD-ARGUMENT/FILE-CONTENT=3, URL-COMPONENT/CALLBACK-DATA=2, ENV-VARIABLE=1 |
| `slot_type_risk` (multiple) | Use the highest applicable slot type |
| `sink_density` | 5+ sinks=4, 3-4=3, 1-2=2, 0=1 |
| `guard_sparsity` | no guards=4, partial guards=3, guards on most paths=2, all paths guarded=1 |

Functions scoring 48+ (max 256) are top priority. Functions scoring 16+ are standard priority. Below 16, analyze only if time permits.

## Context Slice Format

Each function produces one context slice as structured data:

```json
{
  "file_id": "src/http/parser.c",
  "function_name": "parse_header_value",
  "start_line": 245,
  "end_line": 312,
  "slot_types": ["NETWORK-INPUT", "PROTOCOL-FIELD"],
  "call_chain": {
    "callers": [
      {"function": "parse_headers", "file": "src/http/parser.c", "line": 180}
    ],
    "callees": [
      {"function": "copy_header_value", "file": "src/http/parser.c", "line": 268},
      {"function": "normalize_encoding", "file": "src/http/encoding.c", "line": 45}
    ]
  },
  "data_flow": {
    "untrusted_params": ["raw_value", "value_len"],
    "untrusted_locals": ["decoded_value", "trimmed"],
    "derived_sizes": ["actual_len", "alloc_size"]
  },
  "cross_refs": [
    {"function": "normalize_encoding", "module": "http-encoding", "signature": "int normalize_encoding(char *dst, const char *src, size_t len)"}
  ],
  "guard_annotations": [
    {
      "variable": "value_len",
      "check": "value_len <= MAX_HEADER_VALUE",
      "line": 252,
      "covers_all_paths": true,
      "bypassable": false
    }
  ],
  "sink_annotations": [
    {
      "type": "memory_write",
      "function": "memcpy",
      "line": 270,
      "args": ["header->value", "raw_value", "actual_len"],
      "untrusted_args": ["raw_value", "actual_len"]
    }
  ],
  "context_text": "/* full function source code here */"
}
```

### Field Descriptions

| Field | Purpose |
|-------|---------|
| `file_id` | Absolute or project-relative file path |
| `function_name` | Function name as declared |
| `start_line`, `end_line` | Line range in source file |
| `slot_types` | Shannon slot types from architecture mapping |
| `call_chain.callers` | Direct callers within analyzed scope |
| `call_chain.callees` | Direct callees from this function |
| `data_flow.untrusted_params` | Parameters carrying untrusted data |
| `data_flow.untrusted_locals` | Local variables derived from untrusted data |
| `data_flow.derived_sizes` | Size/length variables derived from untrusted data |
| `cross_refs` | Cross-module function references (signature only) |
| `guard_annotations` | Protective checks with completeness assessment |
| `sink_annotations` | Dangerous operations with untrusted argument flags |
| `context_text` | Full source text of the function for analyzer reference |

## Size Target

Each dispatch batch should contain approximately 15,000-20,000 lines of source code. This keeps context within effective analysis limits while providing enough surrounding code for meaningful call graph and data flow tracing.

For modules exceeding 20K lines:
- Split by sub-directory or logical grouping
- Ensure call graph edges at split boundaries are recorded as cross-references
- Process sub-batches in dependency order (callees before callers when possible)

For modules under 5K lines:
- Combine with related small modules into a single batch
- Maintain module boundaries in the output for clarity

## Output Format

Each batch dispatch produces:
1. **Definition Catalog**: all function signatures, struct/enum/macro definitions
2. **Call Graph**: intra-module calls with arguments and untrusted data flags
3. **Cross-Module Reference Table**: external calls with signatures and slot types
4. **Context Slices**: one per function in critical/high files (JSON format above)
5. **Analysis Queue**: prioritized function list for Phase 3 dispatch

## Critical: Macro Expansion (C/C++)

Macros can hide dangerous operations. The context builder MUST:

1. **Identify macro calls in function bodies** — any ALL_CAPS identifier or project-specific naming pattern that isn't a function or constant
2. **Find macro definitions** in header files (grep for `#define MACRO_NAME`)
3. **Record macro expansions as sink/guard annotations** when the macro contains:
   - Memory operations: `memcpy`, `malloc`, `free`, `realloc`
   - Format strings: `printf`, `fprintf`, `syslog`, `snprintf`
   - Control flow: `return`, `goto`, `break`, `continue`, `exit`
   - System calls: `system`, `exec`, `open`, `close`
4. **Annotate the context slice** with a `macro_expansions` field listing which macros are used and what they expand to

Without this, the vulnerability hunter will miss bugs hidden behind macros like `COPY(dst, src, len)` wrapping `memcpy`.

## Critical: Conditional Compilation Tracking (#ifdef)

Functions may behave differently depending on build flags:

1. **Record all #ifdef/#if/#ifndef blocks** within each function
2. **Annotate the context slice** with `ifdef_regions` listing the condition and line range
3. **Mark which branch is the default build** (consult CMakeLists.txt/Makefile for default flag values)
4. **Flag functions where security-relevant code differs between branches** — these need analysis of BOTH branches

Without this, the vulnerability hunter may analyze only one branch and miss a vulnerability in the other.

## Extended Resources

- Project header files (read during execution as needed based on include directives)
- Architecture map output from Phase 1 (file classifications, module groupings, trust boundaries)
- Build system files (CMakeLists.txt, Makefile, configure.ac) for default #ifdef flag resolution
