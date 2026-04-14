# Cobalt Strike YARA Detection Rules

## Beacon Configuration Detection
```yara
rule CobaltStrike_Beacon_Config {
    meta:
        description = "Detects Cobalt Strike beacon configuration block"
        author = "AI Threat Hunting"
    strings:
        // XOR'd config markers
        $config_v3 = { 00 01 00 01 00 02 ?? ?? 00 01 00 02 }  // v3.x after XOR 0x69
        $config_v4 = { 00 01 00 01 00 02 ?? ?? 00 01 00 02 }  // v4.x after XOR 0x2e
        // Default named pipe
        $pipe = "\\.\pipe\msagent_" ascii wide
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
        $serial = { 00 8b b0 0e e }  // Serial: 8bb00ee
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
| 3.x | 0x69 | Look for 0x69 XOR'd TLV header |
| 4.x | 0x2e | Look for 0x2e XOR'd TLV header |
