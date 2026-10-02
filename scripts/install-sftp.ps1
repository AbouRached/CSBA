# Switches on the read-only SFTP feed (ADR-0001 item 18) and opens the Windows firewall for it,
# ONLY from the addresses listed on the active feeds in the admin UI (SFTP feeds page).
# Run from an ELEVATED PowerShell after creating or changing a feed's IP addresses:
#   Set-ExecutionPolicy -Scope Process Bypass; .\scripts\install-sftp.ps1            # port 2222
#   .\scripts\install-sftp.ps1 -Off                                                 # close it again
#
# It never opens the port to everyone: no active feed with addresses = no firewall rule.
# The router / internet firewall must forward the public port to this PC, also limited to
# the vendor's addresses.
param(
    [string]$Target = "C:\TeleVault",
    [int]$Port = 2222,
    [switch]$Off
)
$ErrorActionPreference = "Stop"
$ruleName = "TeleVault SFTP feed"
$cfgPath = "$Target\config.json"
$py = "$Target\.venv\Scripts\python.exe"
if (-not (Test-Path $cfgPath)) { throw "$cfgPath not found - deploy TeleVault first (deploy-production.ps1)." }

function Set-SftpPort([int]$value) {
    $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
    if ($cfg.PSObject.Properties.Name -contains "sftp_port") { $cfg.sftp_port = $value }
    else { $cfg | Add-Member -NotePropertyName sftp_port -NotePropertyValue $value }
    if (-not ($cfg.PSObject.Properties.Name -contains "sftp_host")) { $cfg | Add-Member -NotePropertyName sftp_host -NotePropertyValue "0.0.0.0" }
    [IO.File]::WriteAllText($cfgPath, ($cfg | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
}

function Restart-TeleVault {
    # run.ps1 (the TeleVault task) restarts the server with the new settings within seconds
    Get-NetTCPConnection -LocalPort 8443 -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    foreach ($i in 1..30) {
        Start-Sleep 1
        if (Get-NetTCPConnection -LocalPort 8443 -State Listen -ErrorAction SilentlyContinue) { return $true }
    }
    return $false
}

Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule

if ($Off) {
    Set-SftpPort 0
    $up = Restart-TeleVault
    Write-Host "SFTP feed switched off and firewall rule removed. TeleVault running: $up" -ForegroundColor Green
    return
}

# Addresses of every active feed, straight from the TeleVault database (read-only).
$code = @'
import json, sqlite3, sys
c = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
ips = set()
for (j,) in c.execute("SELECT allowed_ips_json FROM sftp_accounts WHERE active = 1"):
    ips.update(json.loads(j or "[]"))
print("\n".join(sorted(ips)))
'@
$tmp = [IO.Path]::GetTempFileName() + ".py"
[IO.File]::WriteAllText($tmp, $code)
try { $ips = @(& $py $tmp "$Target\data\televault.sqlite3" | Where-Object { $_ }) } finally { Remove-Item $tmp -Force }
if ($LASTEXITCODE -ne 0) { throw "Could not read the feed accounts from the database." }

Set-SftpPort $Port
if ($ips.Count -eq 0) {
    Write-Host "No active SFTP feed with IP addresses yet: the server will run but the firewall stays closed." -ForegroundColor Yellow
} else {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port `
        -RemoteAddress $ips -Profile Any -Description "Read-only SFTP feed for external systems (TeleVault ADR-0001 #18). Managed by install-sftp.ps1." | Out-Null
    Write-Host "Firewall: TCP $Port open only from $($ips -join ', ')" -ForegroundColor Green
}
$up = Restart-TeleVault
$listening = [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
Write-Host "TeleVault running: $up   SFTP listening on $Port`: $listening" -ForegroundColor $(if ($up -and $listening) { "Green" } else { "Red" })
$lan = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1).IPAddress
Write-Host ""
Write-Host "Router / internet firewall: forward public TCP $Port to $lan`:$Port, allowed only from: $($ips -join ', ')"
Write-Host "Host key fingerprint for the vendor: SFTP feeds page in TeleVault."
