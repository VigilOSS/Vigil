---
description: "Example: direct source-review submission for a fuzz-confirmed stack buffer overflow in a backup agent's pre-auth frame parser"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** Stack buffer overflow in pre-auth frame header parsing crashes the backup-agent listener

**Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5)

---

### Summary

Any network client that can reach the backup-agent listener port crashes it pre-auth, with a malformed check-in frame and no credentials. The frame header parser copies the attacker-controlled `label_len` field into a fixed 256-byte stack buffer with `memcpy`, with no bounds check against the buffer size. A libFuzzer campaign found the crash within seconds of a 60-second run; ASAN confirms a stack-buffer-overflow WRITE. The write clobbers the adjacent `session_nonce` buffer and the saved return address before the process aborts.

### Steps to Reproduce

1. [researcher] Build the fuzz harness against the real parser entrypoint, under ASAN+UBSAN:
```
clang -fsanitize=address,undefined -g -O1 \
  -Isrc/proto -Isrc/net \
  tools/fuzz-state/harnesses/frame_header/harness.c src/proto/framing.c \
  -o fuzz_frame_header
```
2. [attacker] Run the minimized crash input through the harness binary, a single deterministic run:
```
./fuzz_frame_header -runs=1 tools/fuzz-state/crashes/frame_header/crash-3f9a1c2b8e4d5f60a1b2c3d4e5f6a7b8c9d0e1f2
```
**Expect:** the process aborts under ASAN with a stack-buffer-overflow WRITE. Full trace in Evidence.

### Evidence

The 62-byte crash input sets the frame's `label_len` field (bytes 4-5, little-endian `u16`) to `0x0140` (320), 64 bytes past the 256-byte `label_buf[256]` destination. It is followed by 320 bytes of `0x41` filler as the label payload. `frame_parse_header()` trusts `label_len` and `memcpy`s the full 320 bytes without checking it against `sizeof(label_buf)`.

The harness (`tools/fuzz-state/harnesses/frame_header/harness.c`) calls `frame_parse_header()` directly on the fuzzer-supplied bytes. That is the same function `handle_client_frame()` in `src/net/server.c:212` calls on every accepted socket, before `agent_authenticate()` runs.

```
=================================================================
==48213==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd8a1b2ec0
  at pc 0x0000004b6a12 bp 0x7ffd8a1b2c40 sp 0x7ffd8a1b2438
WRITE of size 320 at 0x7ffd8a1b2ec0 thread T0                    <-- attacker-controlled write past buffer
    #0 0x4b6a11 in __asan_memcpy
    #1 0x4c9d33 in frame_parse_header src/proto/framing.c:187:5  <-- unchecked memcpy(label_buf, p, label_len)
    #2 0x4c8a02 in handle_client_frame src/net/server.c:212:9
    #3 0x4c7f18 in LLVMFuzzerTestOneInput tools/fuzz-state/harnesses/frame_header/harness.c:22:3

Address 0x7ffd8a1b2ec0 is located in stack of thread T0 at offset 352 in frame:
    #0 0x4c9b40 in frame_parse_header src/proto/framing.c:171

  This frame has 2 object(s):
    [32, 288) 'label_buf' (line 174)                              <-- 256-byte destination
    [304, 340) 'session_nonce' (line 176) <== Memory access at offset 352 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow src/proto/framing.c:187:5 in frame_parse_header
==48213==ABORTING
```

The crash is reproducible on every run against the same input — deterministic, not a race or timing-dependent flake. Three consecutive `-runs=1` invocations all abort at the identical PC and offset.

### Attack Scenario

Any TCP client that can reach the listener port sends a check-in frame with `label_len` over 256, pre-auth. The oversized label overruns `label_buf`, crashing the accepting worker process — a denial of service against agent check-in.

### Impact

An unauthenticated client crashes the listener on demand, dropping in-flight check-ins and backup jobs for every agent connected until it restarts. The overflow write lands on adjacent stack memory instead of the destination buffer — a structural precondition for corruption beyond DoS, not demonstrated here.

### Remediation

Bounds-check `label_len` against `sizeof(label_buf)` before the `memcpy` in `frame_parse_header()`, rejecting or truncating frames past the buffer, matching the sibling `payload_len` check at `framing.c:203`. As defense-in-depth, compile with `-fstack-protector-strong` — the shipped binary carries no stack canary today — and add this harness to CI as a regression target.

**Researcher:** Priya Natarajan — priya.natarajan@research.example
