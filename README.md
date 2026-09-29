# 0xL0ADER

Standalone shellcode loader generator. Single Go binary with native GUI, no server dependency.

## Features

- **Encryption**: ECL (SHA256-chain XOR stream cipher) or RSA (128-bit mini-gmp)
- **Execution modes**:
  - **Callback** — VirtualAlloc + VirtualProtect, dynamic API resolution with Caesar cipher obfuscation, ICO resource storage, DEFLATE compression (ECL mode), PE resources (manifest, version info, string table)
  - **x64** — Direct syscall via NtAllocateVirtualMemory stub
  - **x86** — Heaven's Gate (32-bit to 64-bit mode switch syscall)
- **Input**: Raw shellcode (.bin) or PE executable (.exe, auto-converted via Donut)
- **Key handling**: Embed key in binary or pass via command-line argument
- **GUI**: Native application window (Edge/Chrome app mode), auto-opens on launch

## Quick Start

```powershell
# Install dependencies (MinGW, Donut)
.\install.ps1

# Run
.\0xL0ADER.exe
```

The GUI window opens automatically. Select encryption, mode, upload your file, and click Generate.

## Install Dependencies

Run `install.ps1` to automatically download and install all required tools into the `deps/` directory:

```powershell
.\install.ps1
```

This installs:
- **MinGW-w64 g++** (x86_64, UCRT) — C++ compiler and windres
- **Donut** — PE-to-shellcode converter

All dependencies are installed locally into `deps/`, no system-wide changes.

## Build from Source

```bash
go build -o 0xL0ADER.exe .
```

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

## Tests

### VirusTotal (ECL Callback, dummy shellcode)

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

- All detections are ML/heuristic-based, no signature matches
- Best result: 500KB — **1/60** (Microsoft Wacatac ML only)
- Not identified as any specific tool or malware family

### Functional Tests (19KB test PE → Donut → full pipeline → execute)

| Mode | Compile | Run | Payload Execution | Loader Size |
|---|---|---|---|---|
| ECL Callback | OK | OK | **PASS** | 130 KB |
| RSA Callback | OK | OK | **PASS** | 618 KB |
| ECL x64 | OK | OK | **PASS** | 100 KB |
| RSA x64 | OK | OK | **PASS** | 327 KB |

All 4 modes verified: test PE creates proof-of-execution files, loader runs and exits cleanly without crash.

## License

MIT
