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
