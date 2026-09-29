# 0xL0ADER

Shellcode loader generator with multiple encryption and execution modes. Single Go binary with embedded web UI.

## Features

- **Encryption**: ECL (SHA256-chain XOR stream cipher) or RSA (128-bit mini-gmp)
- **Execution modes**:
  - **Callback** — VirtualAlloc + VirtualProtect, dynamic API resolution with Caesar cipher obfuscation, ICO resource storage, DEFLATE compression (ECL mode), PE resources (manifest, version info, string table)
  - **x64** — Direct syscall via NtAllocateVirtualMemory stub
  - **x86** — Heaven's Gate (32-bit to 64-bit mode switch syscall)
- **Input**: Raw shellcode (.bin) or PE executable (.exe, auto-converted via Donut)
- **Key handling**: Embed key in binary or pass via command-line argument
- **Web UI**: Built-in browser interface on `localhost:9090`

## Quick Start

Download the latest release, place `0xu.exe` alongside the `0xUBypass/` directory, then run:

```
0xu.exe
```

Open `http://localhost:9090` in your browser.

## Build from Source

```bash
go build -o 0xu.exe .
```

## Requirements

- **MinGW g++** — `x86_64-w64-mingw32-g++` for x64/Callback modes, `i686-w64-mingw32-g++` for x86 mode
- **windres** — Required for Callback mode (icon resources)
- **Donut** (optional) — Required only for PE-to-shellcode conversion. Place `donut.exe` next to `0xu.exe` or in `tools/donut/`
- **0xUBypass/** — C++ source files for RSA and x86 modes. Must be in the same directory as `0xu.exe`

## Pipeline

### ECL Callback
```
PE → Donut → DEFLATE compress → ECL XOR encrypt → pixel dilute (32bpp RGBA) → ICO resources → MinGW compile
```

### RSA Callback
```
PE → Donut → RSA encrypt → pixel dilute (32bpp RGBA) → ICO resources → MinGW compile
```

### x64 / x86
```
PE → Donut → ECL/RSA encrypt → inline data split → MinGW compile
```

## Environment

Set `PORT` to change the listening port (default: `9090`).

## Tests

| Shellcode size | Number of positive | AV Manufacturer |
|---|---|---|
| **5 KB** | 4/75 | Symantec, Elastic, Kaspersky, Microsoft |
| **20 KB** | 2/74 | Symantec, Kaspersky |
| **40 KB** | 3/75 | Elastic, Kaspersky, Microsoft |
| **80 KB** | 2/75 | Kaspersky, Microsoft |
| **100 KB** | 3/75 | Elastic, Kaspersky, Microsoft |
| **200 KB** | 3/72 | Elastic, Kaspersky, Microsoft |
| **500 KB** | **1/60** | Microsoft |
| **1 MB** | 2/73 | Kaspersky, Microsoft |

**Analysis:**
- Detection is entirely based on ML/heuristics; there are no signature matches.
- Best result: 500KB file — only **1/60** (Microsoft Wacatac ML).
- Consistent detectors: **Kaspersky** (VHO:Convagent.gen) and **Microsoft** (Wacatac ML); the ML engines from both vendors are highly sensitive to MinGW statically linked PE files.
- Symantec and Elastic results are inconsistent, fluctuating based on payload size.
- All detection labels are generic ML classifications (e.g., `ML.Attribute`, `malicious (moderate confidence)`, `Wacatac.C!ml`); the file was not identified as a specific tool or malware family.

## License

MIT
