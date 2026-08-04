---
description: "Example: direct source-review submission for a fuzz-confirmed stack buffer overflow in a backup agent's pre-auth frame parser"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** Stack buffer overflow in pre-auth frame header parsing crashes the backup-agent listener

**Severity:** HIGH

**CVSS:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5)

**Asset:** file:src/proto/framing.c:50
**Run:** `./fuzz_frame_header -runs=1 crash-a171a648502797529213eb47a2edee514bbdc5db`
**Pass if:** the process aborts under ASAN with a stack-buffer-overflow WRITE

---

### Summary

Any network client that can reach the backup-agent listener port crashes it pre-auth, with a malformed check-in frame and no credentials. The frame header parser copies the attacker-controlled `label_len` field into a fixed 256-byte stack buffer with `memcpy`, with no bounds check against the buffer size. A short libFuzzer campaign against the parser (a few seconds, ~4M execs) found this crash on its own; ASAN confirms a stack-buffer-overflow WRITE. The write runs 64 bytes past the destination, into the ASAN redzone padding before the adjacent `session_nonce` slot, where ASAN catches the first out-of-bounds byte.

### Steps to Reproduce

1. [researcher] Build the attached harness against the vendor's own parser entrypoint, under ASAN+UBSAN+libFuzzer:
```
clang -fsanitize=address,undefined,fuzzer -fno-builtin -fno-optimize-sibling-calls \
  -g -O1 -Isrc/proto -Isrc/net \
  harness.c src/proto/framing.c src/net/server.c \
  -o fuzz_frame_header
```
(`-fno-builtin` and `-fno-optimize-sibling-calls` stop the toolchain from optimizing `memcpy` and `handle_client_frame` out of the trace. The bug still exists without them; the ASAN report just loses frames.)
2. [attacker] Run the attached crash input through the harness binary, a single deterministic run:
```
./fuzz_frame_header -runs=1 crash-a171a648502797529213eb47a2edee514bbdc5db
```
**Expect:** the process aborts under ASAN with a stack-buffer-overflow WRITE. Full trace in Evidence.

### Evidence

The 326-byte crash input sets the frame's `label_len` field (bytes 4-5, little-endian `u16`) to `0x0140` (320), 64 bytes past the 256-byte `label_buf[256]` destination. It is followed by 320 bytes of `0x41` filler as the label payload. `frame_parse_header()` trusts `label_len` and `memcpy`s the full 320 bytes without checking it against `sizeof(label_buf)`.

The harness (`harness.c`) calls `handle_client_frame()` with the fuzzer-supplied bytes standing in for the first frame read off a socket. `handle_client_frame()` (`src/net/server.c:26`) calls `frame_parse_header()` unchanged, and runs before `agent_authenticate()` on every accepted connection. The trace below is that real call path, not a stand-in:

```
==11954==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x00016f4362e0
  at pc 0x000100fc2fc4 bp 0x00016f4361b0 sp 0x00016f435960
WRITE of size 320 at 0x00016f4362e0 thread T0                    <-- attacker-controlled write past buffer
    #0 0x000100fc2fc0 in memcpy
    #1 0x0001009c8c00 in frame_parse_header framing.c:50         <-- unchecked memcpy(label_buf, label, label_len)
    #2 0x0001009c8de0 in handle_client_frame server.c:27
    #3 0x0001009c8948 in LLVMFuzzerTestOneInput harness.c:14

Address 0x00016f4362e0 is located in stack of thread T0 at offset 288 in frame:
    #0 0x0001009c89cc in frame_parse_header framing.c:29

  This frame has 2 object(s):
    [32, 288) 'label_buf' (line 30)                               <-- 256-byte destination
    [352, 388) 'session_nonce' (line 31) <== Memory access at offset 288 partially underflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow framing.c:50 in frame_parse_header
==11954==ABORTING
```

The crash is deterministic, not a race. I reran the same input three times; every run aborts at the identical source line and in-frame offset. Only the absolute addresses shift between runs — that's ASLR, not jitter in the bug itself.

### Attack Scenario

Any TCP client that can reach the listener port sends a check-in frame with `label_len` over 256, pre-auth. The oversized label overruns `label_buf`, crashing the accepting worker process — a denial of service against agent check-in.

### Impact

An unauthenticated client crashes the listener on demand, dropping in-flight check-ins and backup jobs for every agent connected until it restarts. The overflow write lands on adjacent stack memory instead of the destination buffer — a structural precondition for corruption beyond DoS, not demonstrated here.

### Remediation

Bounds-check `label_len` against `sizeof(label_buf)` before the `memcpy` in `frame_parse_header()`, rejecting or truncating frames past the buffer. The parser's `payload_len` field (elided from this excerpt) already receives that same validation further down. Separately, compile with `-fstack-protector-strong` (the shipped binary carries no stack canary today) and add this harness to CI as a regression target.

**Researcher:** Daniel Osei — daniel.osei@research.example
