---
description: YARA rules for Cobalt Strike beacon config, default cert, shellcode stager, XOR keys
skill: cobalt-strike-analysis
---

# Cobalt Strike YARA Detection Rules

## Beacon Configuration Detection
```yara
rule CobaltStrike_Beacon_Config {
    meta:
        description = "Detects Cobalt Strike beacon configuration block"
        author = "Vigil"
    strings:
        // Config TLV header (setting 0x0001 BeaconType, then 0x0002 port; type short, length 2),
        // XOR-encoded with the per-version single-byte key
        $config_v3 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? }  // v3.x, XOR 0x69
        $config_v4 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? }  // v4.x, XOR 0x2e
        // Default named pipe
        $pipe = "\\\\.\\pipe\\msagent_" ascii wide
        // Default User-Agent
        $ua_default = "Mozilla/5.0 (compatible; MSIE" ascii
    condition:
        any of ($config_*) or ($pipe and $ua_default)
}
```

## Network Indicators
```yara
rule CobaltStrike_Default_Cert {
    meta:
        description = "Detects default Cobalt Strike TLS certificate"
    strings:
        $serial = { 02 04 08 BB 00 EE }  // DER INTEGER, serial 146473198 (0x08BB00EE)
        $cn = "Major Cobalt Strike" ascii
    condition:
        any of them
}
```

## Shellcode Stager
```yara
rule CobaltStrike_Stager_x86 {
    meta:
        description = "Cobalt Strike x86 shellcode stager"
    strings:
        $api_hash_1 = { E8 ?? ?? ?? ?? EB ?? 5? 8B ??  }  // API hashing prologue
        $wininet = "wininet" ascii nocase
        $http_open = { 68 ?? ?? ?? ?? 68 00 00 00 00 68 03 00 00 00 }  // InternetOpenA setup
    condition:
        $api_hash_1 and ($wininet or $http_open)
}
```

## XOR Key Reference
| Version | XOR Key | Marker After XOR |
|---------|---------|-----------------|
| 3.x | 0x69 | `69 68 69 68 69 6B` (TLV header `00 01 00 01 00 02`) |
| 4.x | 0x2e | `2E 2F 2E 2F 2E 2C` (same header) |
