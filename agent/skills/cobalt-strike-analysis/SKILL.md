---
name: cobalt-strike-analysis
description: Extract and analyze Cobalt Strike beacon configuration — C2 endpoints, watermarks, malleable profiles, and OPSEC indicators
origin: Vigil
---

# Cobalt Strike Beacon Analysis

## When to Activate

- Suspected Cobalt Strike beacon in memory dump, disk artifact, or network capture
- C2 infrastructure investigation
- Incident response requiring beacon configuration extraction
- Threat actor attribution via watermark analysis

## Tools

| Tool | Use |
|------|-----|
| dissect.cobaltstrike / CobaltStrikeParser | Parse beacon configs from PE binaries and memory dumps |
| 1768.py (Sentinel One) | Standalone beacon parser with config extraction |
| YARA rules | CS detection across disk and memory artifacts |
| Zeek / Wireshark | Network-level C2 traffic analysis and TLS fingerprinting |

## Methodology

### 1. Beacon Configuration Extraction

CS beacon configs are XOR-encrypted in the PE binary.

- **v3.x**: XOR key `0x69`, config starts after marker `0x0001` XOR'd with key
- **v4.x**: XOR key `0x2e`, same structure
- Config format: TLV (Type-Length-Value)
  - Type: 2 bytes (field ID)
  - Length: 2 bytes
  - Value: variable (short=2B, int=4B, string=variable)

### 2. Key Field Extraction (TLV Field IDs)

| Field ID | Name | Value |
|----------|------|-------|
| 0x0001 | BeaconType | 0=HTTP, 1=Hybrid HTTP/DNS, 8=HTTPS |
| 0x0002 | Port | Listener port |
| 0x0003 | SleepTime | Beacon interval (ms) |
| 0x0005 | Jitter | Jitter percentage (0-100) |
| 0x0008 | C2Server | Comma-separated C2 URLs |
| 0x0009 | UserAgent | HTTP User-Agent string |
| 0x000a | PostURI | HTTP POST path for data exfil |
| 0x000b | Malleable_C2 | Custom HTTP headers/transforms |
| 0x001a | SpawnTo_x86 | Process to spawn for post-ex (x86) |
| 0x001b | SpawnTo_x64 | Process to spawn for post-ex (x64) |
| 0x0025 | Watermark | 4-byte operator license hash (attribution) |
| 0x0036 | PipeName | Named pipe for SMB beacon |

### 3. OPSEC Assessment

Rate the operator's OPSEC based on config:

- **Jitter = 0**: POOR — perfectly regular beaconing, trivially detectable
- **Sleep < 30s**: POOR — high-frequency beaconing stands out
- **Default User-Agent** (Mozilla/5.0 with MSIE 7.0 or 8.0): POOR — known CS default
- **SpawnTo = rundll32.exe**: POOR — default, commonly monitored
- **Named pipe = \\.\pipe\msagent_***: POOR — known CS default pattern
- **Watermark = 0**: Cracked/trial version — common with criminal groups

### 4. Network Detection

- Default TLS certificate serial: `8bb00ee` — immediate CS indicator
- JA3S fingerprints for CS HTTPS listeners (varies by version/config)
- JARM fingerprint for CS teamserver
- Beacon interval analysis: calculate std_dev/mean ratio of connection timing
  - Regular interval with consistent jitter % = C2 beacon pattern

### 5. Watermark Attribution

- Watermark is a 4-byte hash of the CS license
- Same watermark across samples = same operator/group
- Cross-reference with threat intel databases (VirusTotal, MalwareBazaar)
- Watermark `0` = cracked version (no attribution value)

### 6. Malleable C2 Profile Analysis

- Extract HTTP GET/POST profiles from config
- Identify: custom headers, URI paths, data transforms (base64, netbios, mask)
- Generate network signatures from profile (Suricata/Snort rules)
- Common malleable profiles: amazon, bing, gmail, jquery — check against known public profiles

## What to Record

For each analyzed beacon, capture:

- **C2 endpoints**: full URLs, ports, beacon type (HTTP/HTTPS/DNS/SMB)
- **Timing**: sleep interval, jitter percentage, calculated beacon cadence
- **Watermark**: 4-byte value, known attribution if any
- **Malleable profile**: HTTP headers, URI paths, data transforms
- **OPSEC rating**: per-field assessment (poor/moderate/good) with reasoning
- **SpawnTo processes**: x86 and x64 post-exploitation targets
- **Named pipes**: pipe names for SMB lateral movement
- **Network indicators**: TLS cert serial, JA3/JA3S/JARM hashes, User-Agent
- **Sample hashes**: SHA256 of the beacon binary or memory dump

## Extended Resources

- `agent/references/payloads/yara-cobalt-strike.md` — YARA rules for CS beacon detection across PE, shellcode, and memory
- VirusTotal, MalwareBazaar, and ThreatFox for watermark and C2 cross-referencing
- Sentinel One CobaltStrikeParser: https://github.com/SentinelOne/CobaltStrikeParser
- dissect.cobaltstrike: https://github.com/fox-it/dissect.cobaltstrike
