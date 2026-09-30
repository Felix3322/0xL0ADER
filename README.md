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
- **GUI**: Win32 native window (lxn/walk), file dialog, build log

## Quick Start

```powershell
# Install dependencies (MinGW, Donut)
.\install.ps1

# Run
.\0xL0ADER.exe
```

Select encryption, mode, browse your file, and click Generate. A save dialog lets you choose the output path.

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
# Release (hides console window)
go build -ldflags="-H windowsgui" -o 0xL0ADER.exe .

# Development (shows console for debug output)
go build -o 0xL0ADER.exe .
```

Requires `rsrc` for manifest regeneration (already committed as `rsrc.syso`):
```bash
go install github.com/akavel/rsrc@latest
rsrc -manifest 0xL0ADER.manifest -o rsrc.syso
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

| Shellcode size | Number of positive | AV Manufacturer | VT Link |
|---|---|---|---|
| **5 KB** | 1/75 | Microsoft | [view](https://www.virustotal.com/gui/file/c057a9edf3b74b7f6c44d9e7a406ac2957e9947187e77b68184ae44b0434d756) |
| **20 KB** | 2/75 | Elastic, Microsoft | [view](https://www.virustotal.com/gui/file/ba540849a831c8823b6f5b73866ecd822c1c771e2fd2a46e83a4964b6a700f43) |
| **40 KB** | 3/75 | Elastic, DeepInstinct, Microsoft | [view](https://www.virustotal.com/gui/file/ad0ff2a3fc13eb7656c8ba91fe862ba837c934cde7538975fedde877feb37785) |
| **80 KB** | 2/75 | Microsoft, Elastic | [view](https://www.virustotal.com/gui/file/7a7c624adb25ef22ca780620e8ada0a3ecb212a5f35462a2873185c2a90f3a39) |
| **100 KB** | 2/75 | Microsoft, Elastic | [view](https://www.virustotal.com/gui/file/25156b7f55ae6365a2edb970031092e7220619ba823e43d413dce3c831ab2dd4) |
| **200 KB** | **1/75** | Microsoft | [view](https://www.virustotal.com/gui/file/111fe6e6b29fd32bdbfb5401418032875a2e36cfd433e2528d910924d42f86e2) |
| **500 KB** | 2/75 | APEX, Elastic | [view](https://www.virustotal.com/gui/file/e8ac9d9f860d93cf5967ff6bbcd66aa08f21e45c2e6989a7c0d4eed9c58e6d0d) |
| **1 MB** | 3/75 | Microsoft, Elastic, APEX | [view](https://www.virustotal.com/gui/file/dd409245f4e38def70017755bca47f94e5b52c12e9af8022a8bcd75b5d8b1f8c) |

- No Kaspersky, no ESET
- Best result: 200KB — **1/75** (Microsoft ML only)
- All detections are ML/heuristic-based, no signature matches
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
