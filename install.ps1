$ErrorActionPreference = "Stop"
$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DepsDir = Join-Path $BaseDir "deps"

Write-Host "`n[0xL0ADER] Dependency Installer" -ForegroundColor Red
Write-Host "Installing to: $DepsDir`n"

if (-not (Test-Path $DepsDir)) {
    New-Item -ItemType Directory -Path $DepsDir -Force | Out-Null
}

# --- MinGW-w64 (x86_64, UCRT, POSIX threads) ---
$MingwDir = Join-Path $DepsDir "mingw64"
$MingwGpp = Join-Path $MingwDir "bin\g++.exe"

if (Test-Path $MingwGpp) {
    Write-Host "[+] MinGW g++ already installed" -ForegroundColor Green
} else {
    Write-Host "[*] Downloading MinGW-w64 ..." -ForegroundColor Yellow
    $MingwVersion = "14.2.0-rt_v12-rev1"
    $MingwUrl = "https://github.com/niXman/mingw-builds-binaries/releases/download/$MingwVersion/x86_64-14.2.0-release-posix-seh-ucrt-rt_v12-rev1.7z"
    $MingwArchive = Join-Path $DepsDir "mingw64.7z"

    try {
        Invoke-WebRequest -Uri $MingwUrl -OutFile $MingwArchive -UseBasicParsing
    } catch {
        Write-Host "[!] Download failed. Trying alternative URL..." -ForegroundColor Red
        $MingwUrl = "https://github.com/niXman/mingw-builds-binaries/releases/latest/download/x86_64-14.2.0-release-posix-seh-ucrt-rt_v12-rev1.7z"
        Invoke-WebRequest -Uri $MingwUrl -OutFile $MingwArchive -UseBasicParsing
    }

    Write-Host "[*] Extracting MinGW-w64 ..." -ForegroundColor Yellow

    $7zPaths = @(
        "C:\Program Files\7-Zip\7z.exe",
        "C:\Program Files (x86)\7-Zip\7z.exe",
        (Get-Command 7z -ErrorAction SilentlyContinue).Source
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

    if ($7zPaths) {
        & $7zPaths x $MingwArchive "-o$DepsDir" -y | Out-Null
    } else {
        Write-Host "[!] 7-Zip not found. Trying tar..." -ForegroundColor Yellow
        tar -xf $MingwArchive -C $DepsDir 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] Cannot extract .7z — install 7-Zip first: winget install 7zip.7zip" -ForegroundColor Red
            Remove-Item $MingwArchive -Force
            exit 1
        }
    }

    Remove-Item $MingwArchive -Force -ErrorAction SilentlyContinue

    if (Test-Path $MingwGpp) {
        $ver = & $MingwGpp --version 2>&1 | Select-Object -First 1
        Write-Host "[+] MinGW g++ installed: $ver" -ForegroundColor Green
    } else {
        Write-Host "[!] MinGW extraction failed — g++.exe not found" -ForegroundColor Red
        exit 1
    }
}

# --- Donut ---
$DonutExe = Join-Path $DepsDir "donut.exe"

if (Test-Path $DonutExe) {
    Write-Host "[+] Donut already installed" -ForegroundColor Green
} else {
    Write-Host "[*] Downloading Donut ..." -ForegroundColor Yellow
    $DonutUrl = "https://github.com/TheWover/donut/releases/download/v1.0/donut_v1.0.zip"
    $DonutZip = Join-Path $DepsDir "donut.zip"
    $DonutTmp = Join-Path $DepsDir "donut_tmp"

    Invoke-WebRequest -Uri $DonutUrl -OutFile $DonutZip -UseBasicParsing
    Expand-Archive -Path $DonutZip -DestinationPath $DonutTmp -Force

    $found = Get-ChildItem -Path $DonutTmp -Filter "donut.exe" -Recurse | Select-Object -First 1
    if ($found) {
        Copy-Item $found.FullName $DonutExe
        Write-Host "[+] Donut installed: $DonutExe" -ForegroundColor Green
    } else {
        Write-Host "[!] donut.exe not found in archive" -ForegroundColor Red
    }

    Remove-Item $DonutZip -Force -ErrorAction SilentlyContinue
    Remove-Item $DonutTmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Verify ---
Write-Host "`n--- Verification ---" -ForegroundColor Cyan
$windres = Join-Path $MingwDir "bin\windres.exe"

$checks = @(
    @{ Name = "g++ (MinGW)"; Path = $MingwGpp },
    @{ Name = "windres";     Path = $windres },
    @{ Name = "donut";       Path = $DonutExe }
)

$allOk = $true
foreach ($c in $checks) {
    if (Test-Path $c.Path) {
        Write-Host "  [OK] $($c.Name)" -ForegroundColor Green
    } else {
        Write-Host "  [!!] $($c.Name) — not found" -ForegroundColor Red
        $allOk = $false
    }
}

if ($allOk) {
    Write-Host "`n[+] All dependencies installed. Run 0xL0ADER.exe to start.`n" -ForegroundColor Green
} else {
    Write-Host "`n[!] Some dependencies are missing.`n" -ForegroundColor Red
}
