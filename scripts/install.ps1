# TeleVault installer for the Archive PC (Windows 11).
# Run from an elevated PowerShell in the televault folder:
#   Set-ExecutionPolicy -Scope Process Bypass; .\scripts\install.ps1 -Hostname archive.example.local -Ip 192.168.1.50
#
# What it does:
#   1. creates .venv and installs requirements
#   2. initialises the database and a self-signed TLS certificate
#   3. prompts for the first superadmin
#   4. opens the firewall port
#   5. registers a Scheduled Task "TeleVault" that starts at boot (as SYSTEM unless -ServiceUser given)
#
# Recommended: create a local standard user (e.g. "televault-svc"), grant it READ-ONLY NTFS
# access to each customer drive, and pass -ServiceUser televault-svc. Then even a bug in the
# app cannot modify a recording.

param(
    [string]$Hostname = "televault.local",
    [string[]]$Ip = @(),
    [int]$Port = 8443,
    [string]$ServiceUser = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "== TeleVault install in $root" -ForegroundColor Cyan

if (-not (Test-Path ".venv")) {
    py -3.12 -m venv .venv
    if (-not $?) { throw "Python 3.12 not found. Install it from python.org (add to PATH) and re-run." }
}
& .\.venv\Scripts\python.exe -m pip install --upgrade pip -q
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt -q

if (-not (Test-Path "config.json")) {
    Copy-Item config.example.json config.json
    (Get-Content config.json) -replace '"port": 8443', ('"port": ' + $Port) | Set-Content -Encoding utf8 config.json
}

& .\.venv\Scripts\python.exe -m televault.cli init

$certArgs = @("make-cert", "--hostname", $Hostname)
foreach ($i in $Ip) { $certArgs += @("--ip", $i) }
& .\.venv\Scripts\python.exe -m televault.cli @certArgs

$hasAdmin = & .\.venv\Scripts\python.exe -c "import sqlite3,sys; from televault.config import load_config; c=sqlite3.connect(str(load_config().db_path)); print(c.execute(""select count(*) from users where role='superadmin'"").fetchone()[0])"
if ([int]$hasAdmin -eq 0) {
    $u = Read-Host "Superadmin username"
    & .\.venv\Scripts\python.exe -m televault.cli create-superadmin $u
}

# Firewall
if (-not (Get-NetFirewallRule -DisplayName "TeleVault HTTPS" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "TeleVault HTTPS" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    Write-Host "Firewall rule added for TCP $Port"
}

# Scheduled task at startup
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$root\scripts\run.ps1`"" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
if ($ServiceUser) {
    $principal = New-ScheduledTaskPrincipal -UserId $ServiceUser -LogonType S4U -RunLevel Limited
} else {
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
}
Unregister-ScheduledTask -TaskName "TeleVault" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "TeleVault" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "TeleVault call recording archive portal" | Out-Null
Start-ScheduledTask -TaskName "TeleVault"

Write-Host ""
Write-Host "TeleVault is running: https://${Hostname}:$Port  (or https://<this-pc-ip>:$Port)" -ForegroundColor Green
Write-Host "Next: sign in as the superadmin, open Customers, and add one customer per drive (e.g. slug acme, root D:\)."
Write-Host "Logs: data\televault.log"
