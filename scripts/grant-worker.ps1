# TeleVault Grant Worker - runs as SYSTEM every minute ("TeleVault Grant Worker" task).
# Applies the read-only folder access that superadmins request from the Customers page.
#
# The web app (running as the unprivileged service account) can only QUEUE requests. This
# script is the security boundary and does not trust the request: every path must pass
# Test-GrantPath below before anything is changed.
#   - a local fixed or removable drive (no network paths, no CD/RAM disks)
#   - an existing folder, with no junction/symlink anywhere along the path
#   - NOT on the Windows system drive, unless an administrator listed it in
#     scripts\grant-allow.txt (that folder is read-only for the service account)
# So even a compromised web app cannot give itself read access to Windows, user profiles
# or TeleVault's own files.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:PYTHONPATH = $root
$py = "$root\.venv\Scripts\python.exe"
$allowFile = "$PSScriptRoot\grant-allow.txt"

function Test-GrantPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return "empty path" }
    if ($Path.StartsWith("\\") -or $Path.StartsWith("//")) { return "network paths are not allowed" }
    if ($Path -notmatch '^[A-Za-z]:\\') { return "not an absolute local path" }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { return "folder not found" }
    $drive = [IO.DriveInfo]::new($full.Substring(0, 3))
    if ($drive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) {
        return "drive type $($drive.DriveType) is not allowed"
    }
    # no reparse point (junction / symlink / mount) on the path or any parent
    $p = $full.TrimEnd('\')
    while ($p -and $p.Length -gt 3) {          # stop at the drive root (C:\)
        $item = Get-Item -LiteralPath $p -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return "path goes through a junction or link ($p)" }
        $p = Split-Path -Parent $p
    }
    # Windows drive: only folders an administrator allow-listed
    if ($full.Substring(0, 2) -ieq $env:SystemDrive) {
        $allowed = @()
        if (Test-Path $allowFile) {
            $allowed = Get-Content $allowFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") } |
                ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
        }
        $f = $full.TrimEnd('\')
        $ok = $allowed | Where-Object { $f -ieq $_ -or $f.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase) }
        if (-not $ok) { return "folders on the Windows drive ($env:SystemDrive) must be listed in scripts\grant-allow.txt by an administrator" }
    }
    return $null
}

$jobs = & $py -m televault.cli grant-queue take | ConvertFrom-Json
foreach ($j in @($jobs)) {
    if (-not $j) { continue }
    $reason = $null
    try { $reason = Test-GrantPath $j.path } catch { $reason = "check failed: $($_.Exception.Message)" }
    if ($reason) {
        & $py -m televault.cli grant-queue finish --id $j.id --status error --message "Refused: $reason" | Out-Null
        continue
    }
    try {
        & "$PSScriptRoot\grant-drive.ps1" -Path $j.path | Out-Null
        & $py -m televault.cli grant-queue finish --id $j.id --status done --message "read-only access applied" | Out-Null
    } catch {
        & $py -m televault.cli grant-queue finish --id $j.id --status error --message "Failed: $($_.Exception.Message)" | Out-Null
    }
}

# ---------------------------------------------------------------- SFTP feed firewall rule
# Superadmins switch the read-only SFTP feed on/off, pick its port and list each vendor's
# addresses in the web UI. The app can only STATE what it wants; this SYSTEM script
# re-validates it and touches nothing but its own inbound TCP rule (ADR-0001 #18):
#   - port 1024-65535 and never the web/MCP ports
#   - every address a single IP or a network no wider than /16 (IPv4) or /48 (IPv6), max 50
#   - switched off, or no active feed with addresses = no rule at all; on any doubt the rule
#     is removed (fail closed)
$fwName = "TeleVault SFTP feed"
function Test-FwAddress([string]$a) {
    $parts = $a.Split('/')
    if ($parts.Count -gt 2) { return $false }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ip)) { return $false }
    $max = 32; $min = 16
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { $max = 128; $min = 48 }
    $len = $max
    if ($parts.Count -eq 2 -and -not [int]::TryParse($parts[1], [ref]$len)) { return $false }
    return ($len -ge $min -and $len -le $max)
}
$fwState = "error"; $fwMsg = ""
try {
    $planJson = & $py -m televault.cli sftp-firewall plan
    if ($LASTEXITCODE -ne 0) { throw "could not read the SFTP settings" }
    $plan = $planJson | ConvertFrom-Json
    $port = [int]$plan.port
    $ips = @($plan.ips | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $existing = @(Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue)
    $bad = @($ips | Where-Object { -not (Test-FwAddress $_) })
    if ($port -lt 1024 -or $port -gt 65535 -or $port -in 8443, 8765) { throw "port $port is not allowed" }
    if ($bad.Count) { throw "refused addresses: $($bad -join ', ')" }
    if ($ips.Count -gt 50) { throw "more than 50 addresses" }
    if (-not $plan.enabled -or $ips.Count -eq 0) {
        $existing | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        $fwState = "closed"
        $fwMsg = if ($plan.enabled) { "no active feed with IP addresses yet" } elseif ($plan.mode -eq "tunnel") { "not needed: reached through the Cloudflare tunnel" } else { "SFTP feed is switched off" }
    } else {
        $desc = "TeleVault SFTP feed, managed by grant-worker.ps1. port=$port from=$($ips -join ',')"
        if (-not ($existing.Count -eq 1 -and $existing[0].Description -eq $desc -and "$($existing[0].Enabled)" -eq "True")) {
            $existing | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $fwName -Description $desc -Direction Inbound -Action Allow -Protocol TCP `
                -LocalPort $port -RemoteAddress $ips -Profile Any | Out-Null
        }
        $fwState = "open"; $fwMsg = "TCP $port open only from $($ips -join ', ')"
    }
} catch {
    Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $fwState = "error"; $fwMsg = "Rule removed: $($_.Exception.Message)"
}
& $py -m televault.cli sftp-firewall report --state $fwState --message $fwMsg | Out-Null
