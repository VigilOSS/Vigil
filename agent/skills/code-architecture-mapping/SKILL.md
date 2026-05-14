---
name: code-architecture-mapping
description: Classify source code files, map modules, identify trust boundaries, build threat model
origin: AI Threat Hunting
---

# Code Architecture Mapping

## When to Activate

- Phase 1 of code analysis pipeline. This is the entry point before any vulnerability analysis begins.
- When a new repository or codebase needs classification, threat modeling, and prioritization before deep review.
- Must run to completion before dispatching code-vuln-hunter. Every subsequent phase depends on the file classification, call graph, file analysis queue, and attack hypotheses produced here.

## Tools

All host-side:
- `git log` — commit history, churn analysis, CVE-fixing commit identification
- `grep` / `rg` — pattern matching across project files
- `find` — directory tree enumeration, file discovery
- `wc -l` — line counts for size estimation
- `file` — file type identification for ambiguous extensions

## Methodology

### Step 1: Read Project Structure

Enumerate the full directory tree. Record file count and total line count per directory. Identify top-level organization pattern (flat, modular, monorepo, workspace).

```bash
find . -type f -not -path './.git/*' | head -500
find . -type d -not -path './.git/*' | sort
find . -type f -name '*.c' -o -name '*.h' -o -name '*.rs' -o -name '*.go' -o -name '*.py' -o -name '*.js' -o -name '*.ts' | xargs wc -l | tail -1
```

### Step 2: Read Build System Files

Identify the build system and dependency graph. Read these files in full:
- `Makefile`, `CMakeLists.txt`, `configure.ac`, `meson.build` (C/C++)
- `Cargo.toml`, `Cargo.lock` (Rust)
- `package.json`, `package-lock.json`, `tsconfig.json` (Node/JS/TS)
- `go.mod`, `go.sum` (Go)
- `pyproject.toml`, `setup.py`, `requirements.txt` (Python)
- `pom.xml`, `build.gradle` (Java)

Extract: project name, version, dependencies (especially native/unsafe ones), build targets, feature flags, compile-time options.

### Step 3: Read Project Documentation

Read in full if present:
- `README.md` / `README` — project purpose, architecture overview, deployment model
- `SECURITY.md` — security policy, threat model, known limitations
- `ARCHITECTURE.md` — module structure, design decisions
- `CONTRIBUTING.md` — code organization conventions, review requirements
- `CHANGELOG.md` — recent changes, security fixes
- `docs/` directory — API docs, protocol specifications

### Step 4: Read File Headers

For every source file, read the first ~50 lines to capture:
- Include/import statements (reveal dependencies and cross-module relationships)
- Module docstrings and file-level comments (reveal purpose)
- License headers (identify vendored/third-party code)
- Conditional compilation directives (`#ifdef`, `#[cfg(...)]`, `//go:build`)

Store as `header_snippet` per file for later reference.

### Step 5: Git Churn Analysis

If git history is available:

```bash
# Top 30 highest-churn files (most frequently modified)
git log --format=format: --name-only --since="2 years ago" | sort | uniq -c | sort -rn | head -30

# Files with CVE-fixing commits
git log --all --oneline --grep="CVE-" --grep="security" --grep="vulnerability" --grep="overflow" --grep="injection" --grep="use-after-free" --grep="race condition" | head -30

# Recent security-related commits with changed files
git log --all --oneline --diff-filter=M --grep="CVE-" --name-only --since="3 years ago" | head -50
```

High-churn files in security-relevant directories are priority targets. Files touched by CVE-fixing commits are strong indicators of historically vulnerable code.

### Step 6: Group Files into Logical Modules

Cluster files into modules using three signals:
1. **Directory structure** — files in the same directory usually form a module
2. **Naming conventions** — shared prefixes/suffixes (e.g., `http_parse.c`, `http_header.c`, `http_conn.c`)
3. **Include/import relationships** — files that include each other form a module even if in different directories

Produce a module map with explicit `module_key`, human-readable `name`, one-line
description, trust boundary, and repo-relative file list per module. The `module_key`
is persisted in the backend, so it must be meaningful and stable (`auth-reset-password`,
`media-upload`, `tenant-routing`) rather than generic (`module_1`, `<repo>_module_N`).

### Step 7: Identify Entry Points

Scan for entry points where execution begins or external interaction occurs:
- **main functions**: `main()`, `__main__`, `if __name__`, entry points in `package.json` scripts
- **Exported APIs**: public functions in shared libraries, HTTP route handlers, gRPC service implementations
- **Protocol handlers**: packet parsers, message dispatchers, frame decoders
- **Callback registrations**: event handlers, signal handlers, timer callbacks, hook registrations
- **CLI parsers**: argument parsing (`argparse`, `getopt`, `clap`, `cobra`, `flag`)
- **Plugin/extension entry points**: `init()` functions, module registration macros

#### Web Framework Entry Points

For web applications, identify framework-specific route handlers and middleware:

| Framework | Entry Point Pattern | Search Command |
|-----------|---|---|
| Django | `def view(request)`, `class ViewSet`, `path()`/`url()` in urls.py | `rg "def \w+\(request" --type py` and `rg "path\(\|url\(" urls.py` |
| Flask | `@app.route()`, `@blueprint.route()` | `rg "@\w+\.route\(" --type py` |
| FastAPI | `@app.get/post/put/delete()`, `@router.` | `rg "@(app\|router)\.(get\|post\|put\|delete\|patch)" --type py` |
| Express | `app.get/post()`, `router.get/post()` | `rg "(app\|router)\.(get\|post\|put\|delete\|patch)\(" --type js` |
| Next.js | `export default function` / `export async function GET` in route.ts/page.tsx | `rg "export.*(GET\|POST\|PUT\|DELETE\|default)" --type ts` |
| Spring | `@RestController`, `@GetMapping`, `@PostMapping` | `rg "@(Rest)?Controller\|@(Get\|Post\|Put\|Delete\|Patch)Mapping" --type java` |
| Rails | Controller actions, `resources :` in routes.rb | `rg "def (index\|show\|create\|update\|destroy\|new\|edit)" --type ruby` |
| Go net/http | `http.HandleFunc`, `mux.Handle`, `mux.HandleFunc` | `rg "(HandleFunc\|\.Handle)\(" --type go` |
| Gin (Go) | `r.GET/POST()`, `group.` | `rg "\.(GET\|POST\|PUT\|DELETE\|PATCH)\(" --type go` |

Also identify middleware/interceptor registration patterns — these control auth, CORS, rate limiting, and request parsing for all routes:

| Framework | Middleware Pattern | Search Command |
|-----------|---|---|
| Django | `MIDDLEWARE` in settings.py, `@decorator` on views | `rg "MIDDLEWARE" settings.py` |
| Express | `app.use()` | `rg "app\.use\(" --type js` |
| Spring | `@Component` + `Filter`/`HandlerInterceptor` | `rg "implements.*(Filter\|HandlerInterceptor)" --type java` |
| FastAPI | `Depends()`, `@app.middleware` | `rg "Depends\(\|@app\.middleware" --type py` |

### Step 8: Map Trust Boundaries

Identify every point where external (untrusted) data enters the system:
- **Network**: socket reads, HTTP request parsing, WebSocket frames, DNS responses, TLS handshake data
- **CLI**: command-line arguments, stdin
- **Files**: configuration file parsing, uploaded file handling, log file reading, certificate loading
- **Environment**: environment variables, system properties
- **APIs**: responses from external services, database query results (if attacker-influenced), IPC messages
- **Hardware/OS**: ioctl results, /proc or /sys reads, device driver data

For each boundary, record: entry function, data format, size constraints (if any), first consumer.

### Step 9: Classify Every File

Assign each file to exactly one classification tier:

**Critical** — Files that sit on or immediately behind a trust boundary and define what attacker-controlled data means.
- Decision: Does this file accept, parse, normalize, validate, deserialize, route, or semantically interpret untrusted input, or make authentication/authorization/crypto/state decisions from attacker-influenced values?
- Examples: TLS handshake parser, HTTP header parser, authentication module, certificate validator, access control checker, protocol state machine

**High** — Files that may not be the first parser but still transform, propagate, or act on attacker-influenced data in security-relevant ways.
- Decision: Does this file manipulate untrusted data or manage resources that attacker-influenced data can steer through control flow, resource bounds, filesystem paths, queries, commands, or security state?
- Examples: memory allocator, SQL query builder, XML parser, JSON deserializer, buffer management, helper validators, file/path handling utilities

**Medium** — Utility functions, string handling without direct untrusted input, platform abstraction layers, internal data structures.
- Decision: Does this file provide infrastructure that critical/high files depend on, but does not itself touch trust boundaries?
- Examples: logging framework, internal hash table, platform compatibility layer, thread pool

**Low** — Build system files, test infrastructure, example code, documentation generators, CI configuration.
- Decision: Does this file run only at build/test time or serve as documentation?
- Examples: test harness, build scripts, example programs, benchmark code

**Skip** — Generated code, test fixtures, documentation, vendored third-party code, asset files.
- Decision: Is this file not written by the project authors or not executable code?
- Examples: auto-generated protobuf stubs, test data files, vendored dependencies, images, fonts

### Step 10: Annotate Slot Types on Critical/High Files

For each critical and high file, annotate which Shannon slot types apply:

| Slot Type | Description | Example |
|-----------|-------------|---------|
| `NETWORK-INPUT` | Data arriving over network sockets | HTTP request body, TCP stream, UDP datagram |
| `URL-COMPONENT` | URL path, query params, fragments | `/api/users?id=1`, route parameters |
| `CMD-ARGUMENT` | Command-line arguments or shell command components | argv values, exec() arguments |
| `FILE-CONTENT` | Data read from files | Config file values, uploaded file contents, certificate fields |
| `ENV-VARIABLE` | Environment variable values | PATH, LD_PRELOAD, HTTP_PROXY |
| `CALLBACK-DATA` | Data arriving through callbacks, webhooks, events | Signal handler data, timer callback arguments, IPC payloads |
| `PROTOCOL-FIELD` | Structured protocol fields | TLS extension values, HTTP/2 frame fields, DNS record data |
| `SERIALIZED-DATA` | Binary/structured serialization formats | protobuf, ASN.1, flatbuffers, CBOR, MessagePack, BSON |
| `EXEC-POLICY` | Config defining execution behavior | Command templates, plugin loading, debug modes, crypto params, session policy |

A file may have multiple slot types. Record the primary slot type and any secondary ones.
Config files that define how commands are executed, what plugins load, what crypto parameters
apply, or what access policies are enforced should receive `EXEC-POLICY` and classification
`high` regardless of language.
Use a precise role label for each critical/high file because the backend derives additional
coverage families from role + language. Prefer labels like `auth_handler`, `crypto_impl`,
`error_handler`, `memory_allocator`, `graphql_resolver`, `llm_orchestrator`, and
`deserializer` over generic labels like `handler` or `utils`. If ingestion guessed the
language wrong, emit a `language` correction in the classification record.

## Classification Decision Framework

```
Is this file executable source code?
  No  -> SKIP (generated, fixtures, docs, vendored)
  Yes -> Does it run only at build/test time?
    Yes -> LOW (build, test infra, examples)
    No  -> Does it directly handle data from a trust boundary?
      Yes -> Does it make security-relevant decisions (auth, crypto, parsing, state)?
        Yes -> CRITICAL
        No  -> HIGH (memory, command building, file I/O, serialization)
      No  -> Does critical/high code depend on it?
        Yes -> MEDIUM (utility, platform abstraction)
        No  -> LOW
```

## Priority Scoring

Each file receives an `analysis_priority` score for analysis ordering. The code-classify
machine JSON field is named `analysis_priority`; do not emit `priority_score` or
`classification_tier` in classification artifacts. When building the Phase 2 file-analysis
queue, map this value to the queue item's `priority` field; the two names belong to different
helpers and should not be swapped.

```
priority = classification_base + git_churn_bonus + entry_point_proximity + past_cve_bonus
```

| Factor | Value |
|--------|-------|
| `classification_base` | critical=40, high=25, medium=10, low=0, skip=0 |
| `git_churn_bonus` | top-10 churn=15, top-20=10, top-30=5, other=0 |
| `entry_point_proximity` | direct entry point=15, one hop from entry=10, two hops=5, other=0 |
| `past_cve_bonus` | touched by CVE-fixing commit=20, touched by security commit=10, other=0 |

Files scoring 50+ are dispatched first. Files scoring 30-49 are second wave. Files below 30 are analyzed only if time permits.

### Step 11: Build Cross-Module Call Graph

The call graph is the navigational backbone for the entire pipeline. Without it,
the hunter cannot trace multi-function vulnerability chains across file boundaries.

When a structural index is available (`tools/analysis-state/structural-index/`), use the pre-computed function definitions and call sites as the starting point for call graph construction. The structural index provides exact function boundaries, call site locations, and import statements — use these to resolve call graph edges more accurately than header-only grep. The architect then adds security annotations (trust boundaries, untrusted data flow, module boundary crossings) that tree-sitter cannot provide.

Using ctags + grep (supplemented by structural index when available):

1. **Forward trace from entry points** (identified in Step 7):
   For each entry point function:
   a. Read the function body
   b. Identify all function calls
   c. For each call: resolve to definition via ctags (grep '^<function>\t' tags)
   d. Record edge: {caller: {function, file, line}, callee: {function, file, line}}
   e. Note which arguments carry untrusted data (from slot-type annotations in Step 10)
   f. Note if edge crosses a module boundary (from Step 6)
   g. Recurse into callee (up to depth 3 from entry point)

2. **Reverse trace from critical functions and security-relevant operations**:
   For each critical/high file's exported functions:
   a. grep/rg to find all callers across the codebase
   b. Record reverse edges
   c. This identifies which entry points can reach each critical function

3. **Build adjacency list**:
   ```json
   {
     "edges": [
       {
         "caller": {"function": "...", "file": "...", "line": N},
         "callee": {"function": "...", "file": "...", "line": N},
         "untrusted_args": ["arg1", "arg3"],
         "crosses_module": true/false,
         "edge_type": "direct|callback|vtable"
       }
     ],
    "entry_points": [...],
    "critical_targets": [...]
   }
   ```

4. **Mark indirect calls**:
   Function pointer calls, vtable dispatches, and callback invocations are
   harder to resolve. Mark these as edge_type "callback" or "vtable" and
   list the possible targets if determinable from type analysis.

Record every ctags/grep lookup used in audit_metadata.

### Step 12: Identify Entry-Point Chains

From the call graph, extract complete chains from entry points to security-relevant targets:

1. For each entry point: depth-first traversal following callee edges
2. At each node: check if it reaches a critical/high function, security-relevant decision, or harm-bearing operation
3. If yes: record the complete chain with untrusted data annotations
4. Rank chains by: impact severity x number of trust boundary crossings

Output format:
```json
{
  "chains": [
    {
      "entry": {"function": "handle", "file": "daemon.c", "trust_level": "untrusted_network"},
      "path": [
        {"function": "run_service", "file": "daemon.c", "untrusted_data": ["client_request"]},
        {"function": "upload_pack", "file": "upload-pack.c", "untrusted_data": ["pack_request"]},
        {"function": "receive_needs", "file": "upload-pack.c", "untrusted_data": ["shallow_lines"]}
      ],
      "target": {"function": "assign_shallow_commits_to_refs", "file": "shallow.c"},
      "target_type": "integer_arithmetic",
      "boundary_crossings": 2
    }
  ]
}
```

### Step 13: Generate Attack Hypotheses

For each entry-point chain with a high-severity decision point, state transition, or
harm-bearing operation, generate 2-3 specific
attack hypotheses. Hypotheses attach to file-analysis-queue entries as `guidance_hypotheses`. Files without hypotheses still appear in the queue with an empty array — the hunter provides unconstrained analysis first, then checks hypotheses. This prevents hypothesis anchoring where the analysis scope gets limited to what the architect predicted.

Each hypothesis specifies:
1. **Entry point**: where untrusted data enters and what the attacker controls
2. **Chain**: the sequence of functions through which data flows
3. **Target**: the specific decision point, state transition, or operation that could cause harm
4. **CWE**: the vulnerability class that would apply
5. **Concrete scenario**: "If the attacker sends [specific input], it reaches [function]
   where [specific operation] occurs without [specific guard], causing [specific harm]"

Prioritize by:
- entry_point_reachability: unauthenticated_network(4) > authenticated(3) > local_config(2) > CLI(1)
- impact_severity: code_execution(4) > memory_corruption(3) > auth_bypass(3) > state_corruption(2) > info_leak(2) > DoS(1)
- guard_absence: no_guard(4) > partial(3) > most_paths(2) > all_paths(1)

Score = reachability x impact_severity x guard_absence. Include hypotheses scoring >= 16.

## Output Format

Use `aith assess contract code-classify`, `aith assess contract code-record-modules`,
`aith assess contract code-record-threat-model`, and `aith assess contract code-dispatch`
as the canonical machine-artifact shape references. Cite those contract names in your handoff
instead of duplicating payload templates, because the operator records your outputs through those
helpers and their backend validation.

Produce a structured architecture map containing:
1. **Module Map**: module name, file list, description, primary slot types
2. **Entry Point Catalog**: function, file, line, type (main/API/handler/callback/CLI)
3. **Trust Boundary Map**: boundary name, entry function, data format, slot type
4. **File Classification Table**: records keyed by backend `file_id` (with `file_path` as helper context when useful), plus classification tier, slot types, and `analysis_priority`. Do not emit path-only classifications.
5. **File Analysis Queue**: flat ordered list of concrete files for Phase 2 (Hunt) dispatch, grouped by `batch_theme` for cross-file reasoning and using queue `priority` mapped from classification `analysis_priority`. Written to `tools/analysis-state/file-analysis-queue.json`. Every critical/high file appears regardless of whether a hypothesis names it. Emit one object per file with concrete `file_id` and `file_path` — no nested batch wrappers, no globs. Do not emit `context_id`; the queue is file-level and the supporting structure comes from metadata plus `tools/analysis-state/structural-index/`.
6. **Call Graph**: JSON adjacency list with edges, entry points, and critical targets. Written to `tools/analysis-state/call-graph.json`.
7. **Entry-Point Chains**: ranked list of complete data flow chains from entry to target.
8. **Attack Hypotheses**: prioritized list of specific vulnerability hypotheses. Each includes: entry point, chain, target, CWE, concrete scenario, score. Written to `tools/analysis-state/attack-hypotheses.json`.
9. **Structural Index Integration**: when `tools/analysis-state/structural-index/` exists, the call graph and entry-point chains incorporate tree-sitter-derived function definitions, call sites, and security-relevant operations for higher accuracy.

## Extended Resources

None — this skill works entirely from project metadata and source file headers.
