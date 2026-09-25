# Deploy TeleVault to a locked-down production folder (ADR-0001 item 16).
# Run from an ELEVATED PowerShell in the development folder:
#   Set-ExecutionPolicy -Scope Process Bypass -Force; .\scripts\deploy-production.ps1
#
# Why: SYSTEM tasks (backup, grant worker) must never run code that an ordinary account can
# edit. The development copy lives in a user profile; the production copy does not.
#
# What it does (safe to re-run for updates - code is replaced, data is never overwritten):
#   1. installs Python 3.12 for all users (C:\Program Files) if missing
#   2. copies the app code to $Target (no .venv, data, tests or caches)
#   3. builds $Target\.venv from the machine-wide Python and installs requirements
#   4. first run only: stops TeleVault and moves the live data\ folder to $Target\data
#      (the old one is renamed data.migrated-<date> so nothing is lost)
#   5. locks $Target: Administrators + SYSTEM full control, nobody else inherits anything;
#      install-boot.ps1 then adds televault-svc read-only (data\ modify)
#   6. runs $Target\scripts\install-boot.ps1 so every task points at the production copy,
#      and starts TeleVault from there
param(
    [string]$Target = "C:\TeleVault",
    [string]$SourceUser = $env:USERNAME
)
$ErrorActionPreference = "Stop"
$dev = Split-Path -Parent $PSScriptRoot
if ([IO.Path]::GetFullPath($dev).TrimEnd('\') -ieq [IO.Path]::GetFullPath($Target).TrimEnd('\')) {
    throw "Run this from the development copy, not from $Target."
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this from an elevated (Run as administrator) PowerShell." }

# 1. Machine-wide Python. 3.13, not 3.12: the per-user 3.12.10 used for development makes
#    the 3.12 installer try to convert that copy in place (it fails with 1603 and rolls back).
#    A different minor version installs cleanly side by side in Program Files.
$sysPy = @("$env:ProgramFiles\Python313\python.exe", "$env:ProgramFiles\Python312\python.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $sysPy) {
    Write-Host "Installing Python 3.13 for all users..."
    winget install --id Python.Python.3.13 -e --scope machine --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
    $sysPy = "$env:ProgramFiles\Python313\python.exe"
    if (-not (Test-Path $sysPy)) { throw "Python 3.13 was not installed at $sysPy (see the winget log path above)." }
}
Write-Host "Python: $sysPy ($(& $sysPy --version))"

# 2. Code
New-Item -ItemType Directory -Force $Target | Out-Null
foreach ($d in "televault", "scripts", "docs") {
    robocopy "$dev\$d" "$Target\$d" /MIR /XD __pycache__ /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Copy of $d failed (robocopy $LASTEXITCODE)" }
}
foreach ($f in "requirements.txt", "config.example.json", "README.md", ".gitignore") {
    if (Test-Path "$dev\$f") { Copy-Item "$dev\$f" "$Target\$f" -Force }
}
if (-not (Test-Path "$Target\config.json")) {
    Copy-Item "$dev\config.json" "$Target\config.json"
} else {
    # Keep every production value; only add settings introduced since the last deployment.
    $prod = Get-Content "$Target\config.json" -Raw | ConvertFrom-Json
    $devc = Get-Content "$dev\config.json" -Raw | ConvertFrom-Json
    $added = @()
    foreach ($p in $devc.PSObject.Properties) {
        if (-not ($prod.PSObject.Properties.Name -contains $p.Name)) {
            $prod | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value; $added += $p.Name
        }
    }
    if ($added) {
        [IO.File]::WriteAllText("$Target\config.json", ($prod | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
        Write-Host "config.json: added new settings $($added -join ', ') (existing values untouched)"
    }
}
Write-Host "Code copied to $Target"

# 3. Python environment
if (-not (Test-Path "$Target\.venv\Scripts\python.exe")) { & $sysPy -m venv "$Target\.venv" }
& "$Target\.venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -r "$Target\requirements.txt"
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
# Smoke check before touching the live service: the app must import and build.
Push-Location $Target
& "$Target\.venv\Scripts\python.exe" -c "import televault.main, televault.cli; print('app imports OK')"
$ok = $LASTEXITCODE -eq 0
Pop-Location
if (-not $ok) { throw "The production copy does not start (import failed). Live service left untouched." }

# 4. Data (first deployment only)
if (-not (Test-Path "$Target\data\televault.sqlite3")) {
    Write-Host "First deployment: moving live data to $Target\data (TeleVault stops briefly)..."
    Stop-ScheduledTask -TaskName "TeleVault" -ErrorAction SilentlyContinue
    Get-NetTCPConnection -LocalPort 8443 -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Start-Sleep 2
    robocopy "$dev\data" "$Target\data" /E /XD demo-drive tmp /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Copy of data failed (robocopy $LASTEXITCODE)" }
    New-Item -ItemType Directory -Force "$Target\data\tmp" | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    foreach ($f in Get-ChildItem "$dev\data" -File) { Rename-Item $f.FullName "$($f.Name).migrated-$stamp" }
    Write-Host "Old data files in $dev\data renamed *.migrated-$stamp (kept, not deleted)."
    # The demo recordings stay where they are; the demo customer still points at them.
}

# 5. Lock the folder: only Administrators and SYSTEM; install-boot adds the service account.
icacls $Target /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" /Q | Out-Null
icacls $Target /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
Write-Host "$Target locked: Administrators + SYSTEM only (service account added next)."

# 6. Point every task at the production copy and start it
& "$Target\scripts\install-boot.ps1" -SourceUser $SourceUser
Write-Host ""
Write-Host "Production copy: $Target   Development copy (not used by any task): $dev" -ForegroundColor Cyan
