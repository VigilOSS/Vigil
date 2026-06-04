---
description: libFuzzer/AFL++ harness templates, sanitizer flag reference, seed corpus construction, harness antipatterns, crash triage checklist
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++
---

# Fuzz Harness Patterns

Reference for writing correct fuzz harnesses, compiling under sanitizers, and avoiding
common false-positive sources. Used by `code-fuzz-engineer` during Phase 4 (Fuzz).

## Sanitizer Reference

### Address Sanitizer (ASAN)

Detects: heap/stack/global buffer overflows, use-after-free, use-after-return, double-free,
memory leaks (optional).

```bash
# Compile flags
CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
LDFLAGS="-fsanitize=address"

# Runtime options (environment variable)
export ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1:symbolize=1:abort_on_error=1"
```

Key notes:
- `-O1` is preferred over `-O0` (avoids false positives from unoptimized code patterns)
- `detect_leaks=0` for fuzzing (leak detection is noisy and slow)
- `allocator_may_return_null=1` prevents ASAN from aborting on large allocations
- ASAN and MSAN cannot be combined in the same binary

### Undefined Behavior Sanitizer (UBSAN)

Detects: signed integer overflow, shift overflow, null pointer dereference, out-of-bounds
array index, misaligned pointer access, type mismatch.

```bash
CFLAGS="-fsanitize=undefined -g -O1 -fno-sanitize-recover=all"
```

Key notes:
- `-fno-sanitize-recover=all` makes UBSAN abort on first violation (required for fuzzing)
- Combine with ASAN: `-fsanitize=address,undefined`
- Integer overflow detection is critical for CWE-190 targets

### Memory Sanitizer (MSAN)

Detects: use of uninitialized memory.

```bash
CFLAGS="-fsanitize=memory -g -O1 -fno-omit-frame-pointer -fsanitize-memory-track-origins=2"
```

Key notes:
- Requires the ENTIRE program (including all libraries) to be compiled with MSAN
- Cannot combine with ASAN
- `-fsanitize-memory-track-origins=2` traces where the uninitialized memory was allocated
- Significantly slower than ASAN — use as a second-pass campaign

### Combined Fuzzer Build

```bash
# Primary build: ASAN + UBSAN + libFuzzer
# Use fuzzer-no-link for project objects so libFuzzer's main() only appears in the
# final fuzz binary, not in every .o. This matters when the project also builds
# normal executables or test binaries from the same objects.
CC=clang \
CFLAGS="-fsanitize=fuzzer-no-link,address,undefined -g -O1 -fno-omit-frame-pointer -fno-sanitize-recover=all" \
    make project_objects       # compile .o files with coverage instrumentation
CC=clang \
CFLAGS="-fsanitize=fuzzer,address,undefined -g -O1 -fno-omit-frame-pointer -fno-sanitize-recover=all" \
LDFLAGS="-fsanitize=fuzzer,address,undefined" \
    make fuzz_target           # link the fuzz binary (libFuzzer main linked here)
# If the build produces only the fuzz target (no other executables), a single
# -fsanitize=fuzzer,address,undefined in CFLAGS+LDFLAGS works for the whole build.

# AFL++ build: ASAN + UBSAN (no -fsanitize=fuzzer, AFL++ provides its own runtime)
# Use afl-clang-lto when available; Homebrew AFL++ on macOS may provide
# afl-clang-fast or afl-cc instead.
CC=afl-clang-fast \
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
CFLAGS="-g -O1 -fno-omit-frame-pointer" \
make fuzz_target_afl
```

## libFuzzer Harness Patterns

### Pattern 1: Basic Byte Array

For parsers that accept a raw byte buffer and length.

```c
#include "parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct parser_ctx ctx;
    parser_init(&ctx);
    
    /* Call the real parser entrypoint */
    parser_feed(&ctx, data, size);
    
    parser_cleanup(&ctx);
    return 0;
}
```

### Pattern 2: Minimum Size Gate

For formats with a mandatory header.

```c
#include "format.h"

#define MIN_HEADER 16  /* Match the real minimum header size */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < MIN_HEADER)
        return 0;  /* Real parser rejects too-small input; so should we */
    
    struct format_reader reader;
    format_reader_init(&reader, data, size);
    
    /* Process until EOF or error — both are normal */
    while (format_reader_next(&reader) == 0)
        ;
    
    format_reader_free(&reader);
    return 0;
}
```

### Pattern 3: Split Input (Multiple Fields)

When the target function takes multiple distinct buffers.

```c
#include "processor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Reserve first 4 bytes as split point control */
    if (size < 4)
        return 0;
    
    /* Use first 2 bytes to determine split ratio */
    uint16_t split = *(const uint16_t *)data;
    size_t remaining = size - 2;
    size_t first_len = split % (remaining + 1);
    size_t second_len = remaining - first_len;
    
    const uint8_t *first = data + 2;
    const uint8_t *second = first + first_len;
    
    process_pair(first, first_len, second, second_len);
    return 0;
}
```

### Pattern 4: File Descriptor Wrapper

When the target reads from a file descriptor.

```c
#include <unistd.h>
#include "file_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Create a temporary file with the fuzzed data */
    char tmpfile[] = "/tmp/fuzz-XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0)
        return 0;
    
    write(fd, data, size);
    lseek(fd, 0, SEEK_SET);
    
    struct file_ctx ctx;
    file_parser_init(&ctx);
    file_parser_read(&ctx, fd);
    file_parser_cleanup(&ctx);
    
    close(fd);
    unlink(tmpfile);
    return 0;
}
```

Note: For performance-sensitive fuzzing, prefer Pattern 1 (direct byte buffer) and refactor
the target to accept bytes instead of fd. Only use fd wrapper when the target's API requires it.

### Pattern 5: Stateful Multi-Call

When the parser requires multiple function calls in sequence.

```c
#include "protocol.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct connection conn;
    connection_init(&conn);
    
    /* Simulate receiving data in chunks */
    size_t offset = 0;
    while (offset < size) {
        /* Use a byte from the input to determine chunk size */
        size_t chunk = (offset < size) ? data[offset] % 256 + 1 : 0;
        offset++;
        if (chunk > size - offset)
            chunk = size - offset;
        
        int ret = connection_receive(&conn, data + offset, chunk);
        offset += chunk;
        
        if (ret < 0)
            break;  /* Parser error is normal */
    }
    
    connection_close(&conn);
    return 0;
}
```

## AFL++ Harness Pattern

AFL++ reads from stdin by default. Wrap the same logic:

```c
#include <stdio.h>
#include <stdlib.h>
#include "parser.h"

/* For AFL++ persistent mode (much faster than fork-per-input) */
__AFL_FUZZ_INIT();

int main(void) {
    __AFL_INIT();
    
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        struct parser_ctx ctx;
        parser_init(&ctx);
        parser_feed(&ctx, buf, len);
        parser_cleanup(&ctx);
    }
    
    return 0;
}
```

## Seed Corpus Construction

### Sources (in priority order)

1. **Project test fixtures** — `test/`, `t/`, `tests/`, `testdata/`, `fixtures/`
   ```bash
   find . -path '*/test*' -type f -name '*.bin' -o -name '*.dat' -o -name '*.raw'
   ```

2. **Generated minimal valid inputs** — Write a small program or script that produces
   the smallest valid input the parser accepts. This is the most valuable seed.

3. **Real-world samples** — If the format is public (PNG, PDF, ELF, etc.), grab
   small samples from public corpora or format specification test suites.

4. **Edge cases** — Generate these mechanically:
   - Empty file (0 bytes)
   - Single byte (each of 0x00, 0xFF, 0x41)
   - Valid header only (no body)
   - Valid header + single-byte body
   - Maximum valid field values in header
   - All-zero payload after valid header

### Seed Quality Checks

```bash
# Verify seeds parse without crashing (before fuzzing)
for seed in seeds/*; do
    ./fuzz_target "$seed" 2>/dev/null || echo "CRASH on seed: $seed"
done

# Measure seed coverage
./fuzz_target seeds/ -runs=0 -print_coverage=1
```

Good seeds should achieve 20-40% edge coverage before any mutation begins.

## Common Harness Antipatterns

### Antipattern 1: Stubbing Out Validation

```c
/* WRONG — real code checks magic bytes, harness skips check */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Skip header validation to reach the interesting code faster */
    struct block blk = {0};
    blk.data = (char *)data;
    blk.len = size;
    process_block_body(&blk);  /* Internal function, skips header check */
    return 0;
}
```

Any crash in `process_block_body` that depends on a valid header having been parsed
is a harness bug, not a real vulnerability.

**Fix:** Call `process_block` (the real entrypoint) which includes header validation.
Provide seeds with valid headers so the fuzzer can learn to produce valid-header inputs.

### Antipattern 2: Impossible State Construction

```c
/* WRONG — creates a reader with inconsistent internal state */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct reader r;
    r.buf = (char *)data;
    r.buf_len = size;
    r.pos = 0;
    r.refcount = 1;
    r.state = STATE_READY;  /* In real code, only set after init succeeds */
    reader_next_entry(&r);
    return 0;
}
```

**Fix:** Use `reader_open()` or `reader_init()` — whatever real callers use.

### Antipattern 3: Ignoring Return Values

```c
/* WRONG — ignores errors that real code handles */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct ctx *c = ctx_new();
    ctx_set_input(c, data, size);
    ctx_parse_header(c);     /* Returns error on invalid header */
    ctx_parse_body(c);       /* Called even if header parse failed */
    ctx_process_records(c);  /* Called even if body parse failed */
    ctx_free(c);
    return 0;
}
```

**Fix:** Check return values the same way real callers do:
```c
    if (ctx_parse_header(c) < 0) goto cleanup;
    if (ctx_parse_body(c) < 0) goto cleanup;
    ctx_process_records(c);
cleanup:
    ctx_free(c);
```

### Antipattern 4: Source File Copy-Paste

```bash
# WRONG — copies source into standalone compilation
cp parser.c harness_dir/
cp parser.h harness_dir/
cc -fsanitize=fuzzer harness.c harness_dir/parser.c -o fuzz_target
```

This misses: preprocessor defines from the build system, link-time dependencies,
platform-specific configuration, and build flags that affect code generation.

**Fix:** Link against the project's object files or library:
```bash
make parser.o  # Use the project's build system
cc -fsanitize=address,undefined,fuzzer harness.c parser.o -o fuzz_target
```

## Crash Triage Checklist

For every crash, evaluate in order:

| # | Gate | Check | Fail action |
|---|------|-------|-------------|
| 1 | Real entrypoint | Is the harness calling the same function that real code calls? | Fix harness → re-run |
| 2 | Deterministic | Does the minimized input crash 3/3 times with identical ASAN output? | Discard (likely timing or ASLR artifact) |
| 3 | Caller preconditions | Does the harness validate input the same way real callers do? | Fix harness → re-run |
| 4 | Attacker trace | Can you follow input bytes from the crash input file to the exact bad memory operation? | Investigate further or discard if untraceable |
| 5 | Feasible state | Could this crash happen with input delivered through a real code path? | Classify as HARNESS BUG |
| 6 | Not safe-API mediated | Is the crashing write NOT protected by a safe growth API on this specific path? | Classify as HARDENING-ONLY |

## AFL++ Quick Reference

```bash
# Basic campaign
afl-fuzz -i seeds/ -o output/ -- ./target @@

# With CmpLog (for magic bytes/checksums)
afl-fuzz -i seeds/ -o output/ -c ./target_cmplog -- ./target @@

# With dictionary
afl-fuzz -i seeds/ -o output/ -x dict.txt -- ./target @@

# Parallel mode (main + secondary)
afl-fuzz -i seeds/ -o output/ -M main -- ./target @@
afl-fuzz -i seeds/ -o output/ -S secondary1 -- ./target @@

# Status check
afl-whatsup output/

# Crash minimization
afl-tmin -i crash.raw -o crash.min -- ./target @@
```

### AFL++ CmpLog Levels

| Level | Flag | Use when |
|-------|------|----------|
| Level 1 | `-l 1` | Simple magic bytes |
| Level 2 | `-l 2` | Magic bytes + multi-byte comparisons |
| Level 2 + transforms | `-l 2AT` | Checksums, length fields |
| Level 3 | `-l 3` | Everything including floating point (slow) |

## libFuzzer Quick Reference

```bash
# Basic run
./fuzz_target corpus/ seeds/ -max_total_time=3600

# With crash directory
./fuzz_target -artifact_prefix=crashes/ corpus/ seeds/ -max_total_time=3600

# Minimize crash
./fuzz_target -minimize_crash=1 -exact_artifact_path=crash.min crash.raw

# Merge corpora (dedup)
./fuzz_target -merge=1 corpus_merged/ corpus1/ corpus2/ seeds/

# Print coverage after run
./fuzz_target corpus/ -runs=0 -print_coverage=1

# Useful flags
-max_len=65536          # Maximum input size
-detect_leaks=0         # Disable leak detection (noisy)
-print_final_stats=1    # Print stats on exit
-use_value_profile=1    # Track value comparisons (helps with magic bytes)
-dict=dict.txt          # Provide format-specific dictionary
```
