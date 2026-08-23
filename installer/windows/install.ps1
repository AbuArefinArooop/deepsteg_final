# ============================================================
#  DeepSteg v4 — Windows 11 Installer
#  Developer  : Abu Arefin Aroop
#  Role       : AI-Assisted Cyber Security Engineer
#  Institution: Arslan Institute of Technology (AiT)
#  Reg. No.   : AiT-IP-2026-DS-0001
#  Copyright  : © 2026 Abu Arefin Aroop — All Rights Reserved
#  Protected  : WIPO Berne Convention | Bangladesh Copyright Act 2000
# ============================================================
#
# USAGE (run as Administrator in PowerShell):
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
#   .\installer\windows\install.ps1
# ============================================================

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\DeepSteg",
    [switch]$CreateDesktopShortcut = $true,
    [switch]$CreateStartMenuEntry  = $true,
    [switch]$Uninstall             = $false
)

$ErrorActionPreference = "Stop"
$APP_NAME    = "DeepSteg v4"
$APP_VERSION = "4.0.2"
$DEVELOPER   = "Abu Arefin Aroop"
$ORG         = "Arslan Institute of Technology (AiT)"
$REG_NO      = "AiT-IP-2026-DS-0001"
$MIN_PYTHON  = [version]"3.10"
$VENV_DIR    = Join-Path $InstallDir "venv"
$APP_DIR     = Join-Path $InstallDir "app"
$LOG_DIR     = Join-Path $env:APPDATA "DeepSteg\logs"

# ── Banner ────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  DeepSteg v4 — Windows 11 Installer                ║" -ForegroundColor Cyan
Write-Host "║  $DEVELOPER                           ║" -ForegroundColor Cyan
Write-Host "║  $ORG              ║" -ForegroundColor Cyan
Write-Host "║  © 2026 Abu Arefin Aroop — All Rights Reserved     ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($Uninstall) {
    Write-Host "[UNINSTALL] Removing DeepSteg v4..." -ForegroundColor Yellow
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
    $desktop   = [Environment]::GetFolderPath("Desktop")
    $startMenu = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\DeepSteg"
    if (Test-Path "$desktop\DeepSteg v4.lnk") { Remove-Item "$desktop\DeepSteg v4.lnk" }
    if (Test-Path $startMenu) { Remove-Item -Recurse -Force $startMenu }
    Write-Host "[OK] DeepSteg v4 uninstalled." -ForegroundColor Green
    exit 0
}

# ── Step 1: Check Python 3.10+ ────────────────────────────────
Write-Host "[1/7] Checking Python version..." -ForegroundColor Yellow

$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "(\d+\.\d+)") {
            $detected = [version]$Matches[1]
            if ($detected -ge $MIN_PYTHON) {
                $pythonCmd = $cmd
                Write-Host "      ✓ Found $ver (via '$cmd')" -ForegroundColor Green
                break
            }
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "      ✗ Python 3.10+ not found!" -ForegroundColor Red
    Write-Host "      Download: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "      Tick 'Add Python to PATH' during install." -ForegroundColor Yellow
    Read-Host "Press ENTER to exit"
    exit 1
}

# ── Step 2: Create directories ────────────────────────────────
Write-Host "[2/7] Creating installation directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $APP_DIR    | Out-Null
New-Item -ItemType Directory -Force -Path $LOG_DIR    | Out-Null
Write-Host "      ✓ $InstallDir" -ForegroundColor Green

# ── Step 3: Copy application files ───────────────────────────
Write-Host "[3/7] Copying application files..." -ForegroundColor Yellow
$SOURCE = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$items  = @("deepsteg_app.py","core","assets","tests","docs","__init__.py","requirements.txt")
foreach ($item in $items) {
    $src = Join-Path $SOURCE $item
    if (Test-Path $src) {
        Copy-Item -Recurse -Force $src $APP_DIR
        Write-Host "      ✓ Copied $item" -ForegroundColor Green
    }
}

# ── Step 4: Create virtual environment ────────────────────────
Write-Host "[4/7] Creating Python virtual environment..." -ForegroundColor Yellow
& $pythonCmd -m venv $VENV_DIR
$PIP = Join-Path $VENV_DIR "Scripts\pip.exe"
$PY  = Join-Path $VENV_DIR "Scripts\python.exe"
Write-Host "      ✓ venv at $VENV_DIR" -ForegroundColor Green

# ── Step 5: Install dependencies ─────────────────────────────
Write-Host "[5/7] Installing dependencies (may take 1-3 minutes)..." -ForegroundColor Yellow
$reqFile = Join-Path $APP_DIR "requirements.txt"
if (Test-Path $reqFile) {
    & $PIP install -r $reqFile --quiet
} else {
    # Fallback pinned list if requirements.txt wasn't copied for some reason
    $deps = @(
        "cryptography==42.0.8",
        "opencv-python==4.10.0.84",
        "numpy==1.26.4",
        "Pillow==10.3.0",
        "scikit-image==0.23.2",
        "matplotlib==3.9.0"
    )
    foreach ($dep in $deps) {
        Write-Host "      Installing $dep..." -ForegroundColor DarkCyan
        & $PIP install $dep --quiet
    }
}
Write-Host "      ✓ All dependencies installed" -ForegroundColor Green

# Optional: post-quantum KEM
Write-Host "      [Optional] Kyber-1024 post-quantum KEM..." -ForegroundColor DarkYellow
try {
    & $PIP install kyber-py --quiet 2>$null
    Write-Host "      ✓ kyber-py installed (Kyber-1024 active)" -ForegroundColor Green
} catch {
    Write-Host "      ℹ kyber-py unavailable — X25519 fallback active" -ForegroundColor DarkYellow
}

# ── Step 6: Create launcher scripts ──────────────────────────
Write-Host "[6/7] Creating launcher scripts..." -ForegroundColor Yellow

# .cmd launcher (callable from CMD or Run dialog)
$launcher = @"
@echo off
title DeepSteg v4 — Abu Arefin Aroop ^| AiT
cd /d "$APP_DIR"
"$PY" deepsteg_app.py %*
"@
$launcherPath = Join-Path $InstallDir "DeepSteg.cmd"
Set-Content -Path $launcherPath -Value $launcher -Encoding ASCII
Write-Host "      ✓ CMD launcher: $launcherPath" -ForegroundColor Green

# VBScript launcher (no console window flash)
$vbs = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run Chr(34) & "$PY" & Chr(34) & " " & Chr(34) & "$APP_DIR\deepsteg_app.py" & Chr(34), 1, False
"@
$vbsPath = Join-Path $InstallDir "DeepSteg.vbs"
Set-Content -Path $vbsPath -Value $vbs -Encoding ASCII

# ── Step 7: Create shortcuts ──────────────────────────────────
Write-Host "[7/7] Creating shortcuts..." -ForegroundColor Yellow
$wshShell = New-Object -ComObject WScript.Shell

if ($CreateDesktopShortcut) {
    $desktop  = [Environment]::GetFolderPath("Desktop")
    $lnkPath  = Join-Path $desktop "DeepSteg v4.lnk"
    $shortcut = $wshShell.CreateShortcut($lnkPath)
    $shortcut.TargetPath      = "wscript.exe"
    $shortcut.Arguments       = "`"$vbsPath`""
    $shortcut.WorkingDirectory= $APP_DIR
    $shortcut.Description     = "DeepSteg v4 by $DEVELOPER | $ORG"
    # Use logo as icon if available
    $icoSrc = Join-Path $APP_DIR "assets\AiT_Logo.png"
    if (Test-Path "$env:SystemRoot\System32\shell32.dll") {
        $shortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,47"
    }
    $shortcut.Save()
    Write-Host "      ✓ Desktop shortcut: $lnkPath" -ForegroundColor Green
}

if ($CreateStartMenuEntry) {
    $startDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\DeepSteg"
    New-Item -ItemType Directory -Force -Path $startDir | Out-Null
    $lnkSM    = Join-Path $startDir "DeepSteg v4.lnk"
    $sc2      = $wshShell.CreateShortcut($lnkSM)
    $sc2.TargetPath       = "wscript.exe"
    $sc2.Arguments        = "`"$vbsPath`""
    $sc2.WorkingDirectory = $APP_DIR
    $sc2.Description      = "DeepSteg v4 by $DEVELOPER | $ORG"
    $sc2.Save()
    Write-Host "      ✓ Start Menu entry: $lnkSM" -ForegroundColor Green
}

# ── Write registry entry (for Add/Remove Programs) ────────────
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DeepSteg"
New-Item  -Force -Path $regPath | Out-Null
Set-ItemProperty -Path $regPath -Name "DisplayName"     -Value "DeepSteg v4"
Set-ItemProperty -Path $regPath -Name "DisplayVersion"  -Value $APP_VERSION
Set-ItemProperty -Path $regPath -Name "Publisher"       -Value "$DEVELOPER, $ORG"
Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value $InstallDir
Set-ItemProperty -Path $regPath -Name "UninstallString" -Value "powershell -File `"$PSCommandPath`" -Uninstall"
Set-ItemProperty -Path $regPath -Name "NoModify"        -Value 1
Set-ItemProperty -Path $regPath -Name "NoRepair"        -Value 1
Write-Host "      ✓ Registry entry added (visible in Add/Remove Programs)" -ForegroundColor Green

# ── Run security test suite ───────────────────────────────────
Write-Host ""
Write-Host "Running security test suite..." -ForegroundColor Yellow
$testFile = Join-Path $APP_DIR "tests\test_security.py"
if (Test-Path $testFile) {
    $env:PYTHONPATH = $APP_DIR
    & $PY $testFile
}

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  ✅  DeepSteg v4 installed successfully!            ║" -ForegroundColor Green
Write-Host "║                                                      ║" -ForegroundColor Green
Write-Host "║  Launch: Double-click 'DeepSteg v4' on Desktop      ║" -ForegroundColor Green
Write-Host "║  Or run: $launcherPath" -ForegroundColor Green
Write-Host "║                                                      ║" -ForegroundColor Green
Write-Host "║  © 2026 Abu Arefin Aroop | AiT | $REG_NO  ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
