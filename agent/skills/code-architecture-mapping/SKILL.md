---
name: code-architecture-mapping
description: Classify source code files, map modules, identify trust boundaries, build threat model
origin: AI Threat Hunting
---

# Code Architecture Mapping

## When to Activate

- Phase 1 of code analysis pipeline. This is the entry point before any vulnerability analysis begins.
- When a new repository or codebase needs classification, threat modeling, and prioritization before deep review.
- Must run to completion before dispatching code-context-building. Every subsequent phase depends on the file classification and module map produced here.

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

Produce a module map: `module_name -> [file_list]` with a one-line description per module.

### Step 7: Identify Entry Points

Scan for entry points where execution begins or external interaction occurs:
- **main functions**: `main()`, `__main__`, `if __name__`, entry points in `package.json` scripts
- **Exported APIs**: public functions in shared libraries, HTTP route handlers, gRPC service implementations
- **Protocol handlers**: packet parsers, message dispatchers, frame decoders
- **Callback registrations**: event handlers, signal handlers, timer callbacks, hook registrations
- **CLI parsers**: argument parsing (`argparse`, `getopt`, `clap`, `cobra`, `flag`)
- **Plugin/extension entry points**: `init()` functions, module registration macros

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

**Critical** — Parses untrusted input, authentication/authorization logic, cryptographic operations, protocol state machines, privilege boundary enforcement.
- Decision: Does this file directly handle data from a trust boundary AND make security-relevant decisions?
- Examples: TLS handshake parser, HTTP header parser, authentication module, certificate validator, access control checker

**High** — Memory management, command/query building, file I/O with external data, serialization/deserialization, string manipulation on untrusted input.
- Decision: Does this file manipulate untrusted data or manage resources that untrusted data flows through?
- Examples: memory allocator, SQL query builder, XML parser, JSON deserializer, buffer management

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

A file may have multiple slot types. Record the primary slot type and any secondary ones.

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

Each file receives a priority score for analysis ordering:

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

## Output Format

Produce a structured architecture map containing:
1. **Module Map**: module name, file list, description, primary slot types
2. **Entry Point Catalog**: function, file, line, type (main/API/handler/callback/CLI)
3. **Trust Boundary Map**: boundary name, entry function, data format, slot type
4. **File Classification Table**: file path, classification tier, slot types, priority score
5. **Analysis Queue**: ordered list of files/modules for Phase 2 dispatch, grouped into ~15-20K line batches

## Extended Resources

None — this skill works entirely from project metadata and source file headers.
