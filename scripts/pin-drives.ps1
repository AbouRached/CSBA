# Keep customer drive letters fixed across restarts. Run ELEVATED once:
#   Set-ExecutionPolicy -Scope Process Bypass -Force; .\scripts\pin-drives.ps1
#
# How letters work: Windows stores each volume's letter in the registry (MountedDevices) against
# that volume's identity, so a disk keeps its letter across restarts. A letter only moves when
# it is FREE at boot (the disk was missing) and a NEW disk arrives and is given it
# automatically. This script closes that gap:
#   1. disables automatic mounting of NEW volumes (mountvol /N): disks this PC has seen keep
#      their letters; a never-seen disk gets no letter until an admin assigns one in Disk
#      Management (right-click the volume -> Change Drive Letter and Paths). Undo: mountvol /E
#   2. saves the current letter -> label -> serial -> volume id table next to the backups, as
#      the reference to restore from if a letter ever has to be re-assigned by hand.
# TeleVault itself also refuses a different disk at a customer's letter (volume serial check).
param([string]$ReportDir = "C:\TeleVaultBackups")
$ErrorActionPreference = "Stop"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this from an elevated (Run as administrator) PowerShell." }

$vols = Get-CimInstance Win32_Volume | Where-Object { $_.DriveLetter } | Sort-Object DriveLetter |
    Select-Object DriveLetter, Label, @{n='SizeGB';e={[int]($_.Capacity/1GB)}},
                  @{n='Serial';e={'{0:X8}' -f [uint32]$_.SerialNumber}}, DeviceID
Write-Host "== Current drive letters" -ForegroundColor Cyan
$vols | Format-Table DriveLetter, Label, SizeGB, Serial -AutoSize | Out-String | Write-Host

mountvol /N
if ($LASTEXITCODE -ne 0) { throw "mountvol /N failed" }
Write-Host "Automatic letters for NEW disks: disabled (existing disks keep their letters)." -ForegroundColor Green

New-Item -ItemType Directory -Force $ReportDir | Out-Null
$file = Join-Path $ReportDir ("drive-letters-{0:yyyyMMdd-HHmm}.csv" -f (Get-Date))
$vols | Export-Csv -NoTypeInformation -Encoding UTF8 $file
Write-Host "Reference table saved: $file"
Write-Host ""
Write-Host "Adding a NEW customer disk from now on: plug it in, then Disk Management ->" -ForegroundColor Yellow
Write-Host "right-click its volume -> Change Drive Letter and Paths -> Add -> pick an unused letter." -ForegroundColor Yellow
