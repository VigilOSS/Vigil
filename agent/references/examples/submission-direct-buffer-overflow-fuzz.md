---
description: "Example: direct source-review submission for a fuzz-confirmed stack buffer overflow in a backup agent's pre-auth frame parser"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** Stack buffer overflow in pre-auth frame header parsing crashes the backup-agent listener

**Severity:** High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5)

---

### Summary

The backup-agent listener's frame header parser copies an attacker-controlled `label_len` field from an incoming TCP frame into a fixed 256-byte stack buffer with `memcpy` and no bounds check against the buffer size. The check-in frame this field lives in is parsed before the agent handshake authenticates, so any network client that can reach the listener port can trigger the overflow with no credentials. A libFuzzer campaign against the parser found the crash within the first few seconds of a 60-second validation run; ASAN confirms a stack-buffer-overflow WRITE that clobbers the adjacent `session_nonce` buffer and the saved return address before the process aborts.

### Steps to Reproduce

1. Build the fuzz harness against the real parser entrypoint, under ASAN+UBSAN:
```
clang -fsanitize=address,undefined -g -O1 \
  -Isrc/proto -Isrc/net \
  tools/fuzz-state/harnesses/frame_header/harness.c src/proto/framing.c \
  -o fuzz_frame_header
```
The harness (`tools/fuzz-state/harnesses/frame_header/harness.c`) calls `frame_parse_header()`
directly on the fuzzer-supplied bytes — the same function `handle_client_frame()` in
`src/net/server.c:212` calls on every accepted socket, before `agent_authenticate()` runs.
2. Run the minimized crash input through the harness binary (this is the reproducing harness
   command — a single deterministic run, not a fuzzing loop):
```
./fuzz_frame_header -runs=1 tools/fuzz-state/crashes/frame_header/crash-3f9a1c2b8e4d5f60a1b2c3d4e5f6a7b8c9d0e1f2
```
3. The 62-byte crash input sets the frame's `label_len` field (bytes 4-5, little-endian `u16`) to
   `0x0140` (320) — 64 bytes past the 256-byte `label_buf[256]` destination — followed by 320 bytes
   of `0x41` filler as the label payload. `frame_parse_header()` trusts `label_len` and
   `memcpy(label_buf, p, label_len)`s the full 320 bytes without checking it against
   `sizeof(label_buf)`.
4. The process aborts under ASAN with a stack-buffer-overflow WRITE (see Evidence) — confirming
   the parser writes attacker-controlled bytes past the intended buffer on the pre-auth path.

### Evidence

```
$ ./fuzz_frame_header -runs=1 tools/fuzz-state/crashes/frame_header/crash-3f9a1c2b8e4d5f60a1b2c3d4e5f6a7b8c9d0e1f2
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

The crash is reproducible on every run against the same input (deterministic, not a race or
timing-dependent flake): three consecutive `-runs=1` invocations all abort at the identical PC and
offset.

### Attack Scenario

Any TCP client that can reach the backup-agent listener port sends a check-in frame with a
`label_len` field larger than 256 before the handshake authenticates the connection. The parser
copies the oversized label into `label_buf`, overrunning it into `session_nonce` and the saved
frame-pointer chain on the stack. This crashes the accepting worker process — confirmed here as a
denial of service against agent check-in — and because the overwritten region includes adjacent
stack data and control-flow metadata, an attacker who tunes the overflow length and content beyond
what this fuzz run explored has a memory-corruption write primitive on the pre-auth path, not just
a crash; this submission scopes its claimed impact to what the ASAN report proves.

### Impact

An unauthenticated network client crashes the backup-agent listener process on demand, dropping
in-flight check-ins and backup jobs for every agent connected to that listener until it restarts.
The overflow write lands on adjacent stack memory (`session_nonce`, saved frame pointer) rather
than being contained to the destination buffer, which is the structural precondition for
memory-corruption exploitation beyond DoS — not demonstrated here, but the reason this needs
priority remediation rather than being triaged as a simple crash.

### Remediation

Bounds-check `label_len` against `sizeof(label_buf)` in `frame_parse_header()` before the `memcpy`
— reject or truncate frames whose declared label length exceeds the buffer, matching how the
sibling `payload_len` field is already validated a few lines below at `framing.c:203`. As
defense-in-depth, compile the parser with `-fstack-protector-strong` in the release build (the
fuzz harness already builds under ASAN+UBSAN for testing, but the shipped binary does not carry a
stack canary) and add this harness as a permanent regression target in CI fuzzing so a future
change to the frame format can't reopen the same class of bug.

**Researcher:** Priya Natarajan — priya.natarajan@research.example
