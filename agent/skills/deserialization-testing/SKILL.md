---
name: deserialization-testing
description: Detect and exploit insecure deserialization in Java, PHP, Python, and .NET applications
origin: Vigil
vuln_class: deserialization
---

# Insecure Deserialization Testing

## When to Activate

- Binary or encoded blobs in cookies, parameters, hidden fields or message bodies (Java
  `rO0`/`aced`, .NET `AAEAAAD`/ViewState, PHP `O:`/`a:`, pickle, Ruby Marshal, YAML), or a stack
  that deserializes natively (Java RMI/JMX/T3, PHP, Python, .NET, Node `node-serialize`, Ruby).

`--technique RCE` (switch to `INFO-DISCLOSURE` for oracle or leak-only work); deliver via
`vigil assess kali exec --technique RCE --intent "<purpose>" --probe-kind payload --phase
consume-test --timeout 30 -- curl …`, `--probe-kind exploit` after execution is confirmed.
Detection signatures and per-language chains (ysoserial.net and Json.NET
`TypeNameHandling`, phpggc output flags and phar, PyYAML, Ruby Psych and SnakeYAML gadgets, Ruby
Marshal, node-serialize, ViewState with a known machineKey):
`agent/references/payloads/deserialization-payloads.md`. Gadget generators are host-side tools
and may not be installed; generate there and deliver through the wrapper. Seed tampering variants
with `vigil assess classify-payload <blob> --mutations`.

## Method

1. **Establish the sink without a gadget.** Java `URLDNS` (and equivalent DNS-only probes) fire
   on deserialization with no library dependency, so a hit proves the sink before choosing a
   chain; aim it at a minted host
   (`agent/references/offensive-tactics/frp-tunneling.md` "OOB Procedure (mint→poll→correlate)").
   No hit with healthy OOB can mean no egress, not no sink: try an error- or timing-based probe.
2. **Pick a chain that fits the classpath and runtime version.** CommonsCollections1 fails on
   JDK ≥ 8u71; PyYAML ≥ 5.4 `FullLoader`, Ruby Psych 4 `YAML.load` and SnakeYAML 2.0 are safe by
   default, so YAML gadgets need the unsafe loader. Rotate chains when the sink is proven and a
   chain stays silent.
3. **Make the command expand.** Java `Runtime.exec` runs no shell, so `$(whoami)` and quoting do
   not expand: wrap as `bash -c {echo,<base64>}|{base64,-d}|{bash,-i}`-style or use a chain that
   takes a shell; in host-side generators, put the minted host in double quotes, not single. The
   proof is a callback carrying the evaluated label (`$(whoami).$OOB_HOST`), not a bare hit.
4. **Data tampering** without RCE: role or privilege fields in a serialized session, object
   references to other users' data, prices and quantities — usually where the blob is unsigned.
5. **Framework checks:** Django pickle cache or session serializer; Rails `Marshal.load` and
   `cookies_serializer` (should be `:json`); Express `cookie-session` unsigned; Spring
   `DefaultSerializer` session persistence and RememberMe; Laravel cookie encryption with a leaked
   or default `APP_KEY`.

## What to Record

Endpoint and parameter, format and language, the chain and the library enabling it, and the proof:
command output or the labelled callback (`agent/rules/hunting.md` §2), or the tampered field that
was accepted and what it granted. Severity: `agent/references/finding-fp-and-severity-gate.md`;
format: `agent/references/runtime-guides/web-finding-recording.md`.
