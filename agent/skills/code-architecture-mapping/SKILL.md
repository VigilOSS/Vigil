---
name: code-architecture-mapping
description: Classify source code files, map modules, identify trust boundaries, build threat model
origin: Vigil
---

# Code Architecture Mapping

Together with `agent/shared-constraints-code.md` §5, this skill owns the architecture portion of
the code hunting contract: enumerate every admitted file, distinguish shipped product reachability
from attacker control, map trust boundaries and complete entry chains, and queue rather than erase
ambiguous coverage. The web hunting rules are neither required nor a substitute for these outputs.

## When to Activate

- Phase 1 of code analysis pipeline. This is the entry point before any vulnerability analysis begins.
- When a new repository or codebase needs classification, threat modeling, and prioritization before deep review.
- Must run to completion before dispatching code-vuln-hunter. Every subsequent phase depends on the file classification, call graph, file analysis queue, and attack hypotheses produced here.

## Tools

All host-side:
- Backend repository envelope — ingest-time Git provenance and churn summary
- `grep` / `rg` — pattern matching beneath the sealed `snapshot_path`
- `find` — sealed-tree enumeration and file discovery
- `wc -l` — line counts for size estimation
- `file` — file type identification for ambiguous extensions

Run filesystem commands with `snapshot_path` as the explicit root or change into it first. Do not
run ambient Git against `source_origin_path`; it is a mutable provenance location, not analysis
state.

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

Also check for CI/CD pipeline definitions: `.github/workflows/*.yml`, `.gitlab-ci.yml`,
`Jenkinsfile`, `.circleci/config.yml`. These are a distinct supply-chain attack surface from
application source (expression injection, untrusted checkout, secret exfiltration, self-hosted
runner escalation) — flag them in the classification for a Phase 2 dispatch that loads
`agent/skills/cicd-security/SKILL.md` instead of the standard code-vulnerability-analysis
methodology, since the bug classes and evidence shape differ from application-source review.

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

### Step 5: Git Provenance and Churn Context

Use only the ingest-time Git fields and `code_repos.git_churn_json` supplied in dispatch context.
Do not reopen the mutable origin or infer current source identity from a commit hash: dirty and
untracked admitted files are covered by the sealed manifest instead. High-churn files in
security-relevant directories are priority signals, and files named by captured security-history
metadata warrant attention, but neither is proof of a vulnerability and neither limits the queue.

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

First classify each module's shipped product surface from sealed evidence:
`application/service`, `library/framework`, `CLI`, `plugin/extension`, or `mixed/unknown`. Use build
targets, package/export manifests, installed headers, registration code, and project documentation;
record the evidence and uncertainty. An example or test is behavioral evidence, not proof that its
call site is the production surface.

Then scan for the entry points appropriate to that surface:
- **main functions**: `main()`, `__main__`, `if __name__`, entry points in `package.json` scripts
- **Exported APIs**: installed/public functions, classes, parsers, callbacks, or codecs in libraries
  and frameworks; record the valid supported API sequences relevant to stateful behavior
- **Service APIs**: HTTP route handlers, gRPC service implementations, jobs, and event consumers
- **Protocol handlers**: packet parsers, message dispatchers, frame decoders
- **Callback registrations**: event handlers, signal handlers, timer callbacks, hook registrations
- **CLI parsers**: argument parsing (`argparse`, `getopt`, `clap`, `cobra`, `flag`)
- **Plugin/extension entry points**: manifests, exported hooks, `init()` functions, module
  registration macros, and host callbacks

An exported symbol is product reachability only when packaging, visibility, documentation, or a
registered host contract supports it. Keep product reachability distinct from attacker control:
the former establishes that a defect is on a supported product path, while the latter determines
who can trigger it and how the impact is scored (`agent/shared-constraints-code.md` §5).

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

Identify every point where external data or a supported product invocation enters the system:
- **Network**: socket reads, HTTP request parsing, WebSocket frames, DNS responses, TLS handshake data
- **CLI**: command-line arguments, stdin
- **Files**: configuration file parsing, uploaded file handling, log file reading, certificate loading
- **Environment**: environment variables, system properties
- **APIs**: responses from external services, database query results (if attacker-influenced), IPC messages
- **Hardware/OS**: ioctl results, /proc or /sys reads, device driver data

For each boundary, record: product surface kind, reachability basis, entry function, data format,
size constraints (if any), first consumer, what the caller/attacker can control, and which consumer
or host context remains unknown. A public library API can be product-reachable without proving that
a remote attacker controls every argument.

### Step 9: Classify Every File

Assign each file to exactly one classification tier:

**Critical** — Files on or immediately behind a trust/product boundary that define input meaning or
enforce a supported security invariant.
- Decision: Does this file accept, parse, normalize, validate, deserialize, route, or semantically
  interpret untrusted/caller-controlled input, or make authentication, authorization, crypto, or
  state decisions on a supported product path?
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

Each file receives an `analysis_priority` score for analysis ordering. The code-record classify
machine JSON field is named `analysis_priority`; do not emit `priority_score` or
`classification_tier` in classification artifacts. When building the Phase 2 file-analysis
queue, copy this value unchanged to the queue item's `priority` field: queue `priority` MUST
exactly equal classification `analysis_priority` for the same file.

```
raw_priority = classification_base + git_churn_bonus + entry_point_proximity + past_cve_bonus
analysis_priority = 0                                      if classification is skip
analysis_priority = min(raw_priority, classification_cap)  otherwise
```

| Classification | Base | Cap | Final `analysis_priority` |
|----------------|------|-----|---------------------------|
| critical | 80 | 100 | 80-100 |
| high | 50 | 79 | 50-79 |
| medium | 20 | 49 | 20-49 |
| low | 5 | 19 | 5-19 |
| skip | 0 | 0 | exactly 0 |

For non-`skip` files, add one mutually exclusive value from each bonus row before applying the
classification cap:

| Bonus | Value |
|-------|-------|
| `git_churn_bonus` | top-10 churn=15, top-20=10, top-30=5, other=0 |
| `entry_point_proximity` | direct entry point=15, one hop from entry=10, two hops=5, other=0 |
| `past_cve_bonus` | touched by CVE-fixing commit=20, touched by security commit=10, other=0 |

Do not apply bonuses to `skip`: its score remains exactly 0. The cap keeps bonuses inside the
classification tier, so they rank files within a tier and never promote a lower-tier file above a
higher-tier one. Sort queue work by descending `priority`; every admitted file still enters the
queue, because the score controls order only.

### Step 11: Build Cross-Module Call Graph

The call graph is the navigational backbone for the entire pipeline. Without it,
the hunter cannot trace multi-function vulnerability chains across file boundaries.

Open the exact `structural_index_manifest_path` from Code Source Identity and resolve per-file
indexes through its `path_to_index` map. Use those pre-computed function definitions and call sites
as the starting point for call-graph construction. The index supplies exact function boundaries,
call locations, and imports; the architect adds the trust-boundary, untrusted-flow, and
module-crossing semantics tree-sitter cannot provide.

Using ctags + grep (supplemented by structural index when available):

1. **Forward trace from entry points** (identified in Step 7):
   For each entry point function:
   a. Read the function body
   b. Identify all function calls
   c. For each call: resolve to definition via ctags (`grep '^<function>\t' "$ctags_path"`)
   d. Record the edge using the flat fields the operator spec and
      `agent/phases/code-phase-1-classify-map.md` "Cross-module call graph" expect:
      `caller_func`, `caller_file`, `caller_line`, `callee_func`, `callee_file`, `callee_line`,
      `crosses_trust_boundary` (bool, from Step 6's module-boundary map), `untrusted_data_label`
      (string naming which arguments carry untrusted data, from Step 10's slot-type annotations,
      or `null`)
   e. Recurse into the callee, tracing as deep as the chain actually runs — to a leaf function, a
      security-relevant decision, a state transition, or a sink, not to a fixed depth. If you stop
      before reaching one of those (context budget, unresolvable indirection), record where and
      why in `audit_metadata` rather than silently truncating.

2. **Reverse trace from critical functions and security-relevant operations**:
   For each critical/high file's exported functions:
   a. grep/rg to find all callers across the codebase
   b. Record reverse edges
   c. This identifies which entry points can reach each critical function

3. **Build adjacency list** — one edge per entry, flat fields only:
   ```json
   {
     "edges": [
       {
         "caller_func": "handle", "caller_file": "daemon.c", "caller_line": 887,
         "callee_func": "run_service", "callee_file": "daemon.c", "callee_line": 740,
         "crosses_trust_boundary": false,
         "untrusted_data_label": "client_addr, req_buf",
         "edge_type": "direct"
       }
     ],
    "entry_points": [...],
    "critical_targets": [...]
   }
   ```
   `edge_type` (`direct` / `callback` / `vtable`) is additive to the required flat fields above —
   keep it, it is the only signal that distinguishes a resolved direct call from an indirect one
   worth flagging as lower-confidence.

4. **Mark indirect calls**:
   Function pointer calls, vtable dispatches, and callback invocations are
   harder to resolve. Set `edge_type` to `"callback"` or `"vtable"` and
   list the possible targets in `untrusted_data_label` or a sibling note if determinable from type analysis.

Record every ctags/grep lookup used in audit_metadata.

### Step 12: Identify Entry-Point Chains

From the call graph, extract complete chains from entry points to security-relevant targets:

1. For each entry point: depth-first traversal following callee edges
2. At each node: check if it reaches a critical/high function, security-relevant decision, or harm-bearing operation
3. If yes: record the complete chain with untrusted data annotations
4. Rank chains by: impact severity x target-kind entry-reachability weight x
   `max(1, trust-boundary crossings)`. A supported public API/host entry remains rankable when the
   implementation has no additional internal boundary crossing.

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
1. **Entry point**: the target-kind product entry, its reachability basis, what the caller/attacker
   controls, and any missing consumer context
2. **Chain**: the sequence of functions through which data flows
3. **Target**: the specific decision point, state transition, or operation that could cause harm
4. **CWE**: the vulnerability class that would apply
5. **Concrete scenario**: "If [attacker input or a valid supported API sequence] reaches
   [function], [specific operation] occurs without [specific guard], causing [specific harm]"

Prioritize by:
- entry_point_reachability: unauthenticated_network(4) > authenticated(3) >
  supported_public_api_or_host_contract(2) > local_config(2) > CLI(1)
- impact_severity: code_execution(4) > memory_corruption(3) > auth_bypass(3) > state_corruption(2) > info_leak(2) > DoS(1)
- guard_absence: no_guard(4) > partial(3) > most_paths(2) > all_paths(1)

Score = reachability x impact_severity x guard_absence. Include hypotheses scoring >= 16.

## Output Format

Use `vigil assess contract code-record classify`, `vigil assess contract code-record modules`,
`vigil assess contract code-record threat-model`, and `vigil assess contract code-dispatch`
as the canonical machine-artifact shape references. Cite those contract names in your handoff
instead of duplicating payload templates, because the operator records your outputs through those
helpers and their backend validation.

Produce a structured architecture map containing:
1. **Module Map**: module name, file list, description, primary slot types
2. **Product Surface + Entry Point Catalog**: per-module surface kind and evidence, then function,
   file, line, type (main/API/handler/callback/CLI/plugin), reachability basis, caller/attacker
   control, and missing consumer/host context
3. **Trust Boundary Map**: boundary name, entry function, data format, slot type
4. **File Classification Table**: records keyed by backend `file_id` (with `file_path` as helper context when useful), plus classification tier, slot types, and `analysis_priority`. Do not emit path-only classifications.
5. **File Analysis Queue**: flat ordered list of every admitted file for Phase 2 (Hunt) dispatch, grouped by `batch_theme` for cross-file reasoning and with queue `priority` exactly equal to classification `analysis_priority` for the same file. Written to `tools/analysis-state/file-analysis-queue.json`. Classification controls order, not inclusion; even a `skip` classification appears so closeout must record an explicit reason. Emit one object per file with concrete `file_id` and `file_path` — no nested batch wrappers, no globs. Do not emit `context_id`; the queue is file-level and supporting structure resolves through the bound structural manifest.
6. **Call Graph**: JSON adjacency list with edges, entry points, and critical targets. Written to `tools/analysis-state/call-graph.json`.
7. **Entry-Point Chains**: ranked list of complete data flow chains from entry to target.
8. **Attack Hypotheses**: prioritized list of specific vulnerability hypotheses. Each includes: entry point, chain, target, CWE, concrete scenario, score. Written to `tools/analysis-state/attack-hypotheses.json`.
9. **Structural Index Integration**: the call graph and entry-point chains incorporate tree-sitter-derived function definitions, call sites, and security-relevant operations resolved through the Code Source Identity manifest.
10. **Historical CVE Bug Shapes (optional)**: when repository history/advisories expose a concrete
    vulnerable-to-fixed delta, write `tools/analysis-state/cve-bug-shapes.jsonl`, one compact JSON
    object per physical line with `shape_id`, `cwe`, `affected_paths`, `vulnerable_revision`,
    `fixed_revision`, `bug_pattern`, `guard_delta`, and `evidence_refs`. The two revision fields may
    name commits, tags, or advisory/source snapshots, but every record must contain enough cited
    vulnerable/fixed evidence to derive the semantic pattern. Omit the artifact rather than emit an
    identifier-only record; Phase 2 treats absence as not applicable, not as completed discovery.

## Extended Resources

None — this skill works entirely from project metadata and source file headers.
