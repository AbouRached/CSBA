# Nightly backup (run by the "TeleVault Backup" task as SYSTEM).
# Database (online-consistent copy), mfa.key, TLS pair, and the Cloudflare tunnel credentials.
# Copy $Dest off this PC as well (NAS / cloud) - a backup on the same disk is not a backup.
param([string]$Dest = "C:\TeleVaultBackups", [int]$Keep = 14)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$out = & "$root\.venv\Scripts\python.exe" -m televault.cli backup $Dest --keep $Keep
$out
$folder = ($out | Select-String "Backup written: (.+)$").Matches[0].Groups[1].Value
$cf = "$env:WINDIR\System32\config\systemprofile\.cloudflared"
if ($folder -and (Test-Path $cf)) {
    New-Item -ItemType Directory -Force "$folder\cloudflared" | Out-Null
    Copy-Item "$cf\*.json", "$cf\*.yml", "$cf\cert.pem" "$folder\cloudflared" -ErrorAction SilentlyContinue
}
