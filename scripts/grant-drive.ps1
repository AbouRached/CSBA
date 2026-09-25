# Give the TeleVault service account READ-ONLY access to a customer recording folder.
# Run elevated whenever a new customer drive/folder is added:
#   .\scripts\grant-drive.ps1 -Path J:\
# Read & Execute is granted and every write/delete/permission right is explicitly DENIED, so
# even if the drive gives "Authenticated Users: Modify" (the NTFS default on data drives) the
# portal still cannot alter a recording.
# The ACEs are built with .NET rather than icacls on purpose: icacls silently adds SYNCHRONIZE
# to a deny entry, and a denied SYNCHRONIZE makes files and folders impossible to open at all.
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$ServiceUser = "televault-svc",
    [switch]$Force   # re-apply (and re-propagate to every file) even if the folder is already set up
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Path)) { throw "Not found: $Path" }
$acct = New-Object System.Security.Principal.NTAccount("$env:COMPUTERNAME\$ServiceUser")
$R = [System.Security.AccessControl.FileSystemRights]
$inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
$prop = [System.Security.AccessControl.PropagationFlags]::None

$deny = $R::WriteData -bor $R::AppendData -bor $R::WriteExtendedAttributes -bor $R::WriteAttributes -bor `
        $R::Delete -bor $R::DeleteSubdirectoriesAndFiles -bor $R::ChangePermissions -bor $R::TakeOwnership

$acl = Get-Acl -LiteralPath $Path
# Already exactly right at the top? Then the files below inherited it when it was applied;
# re-applying would walk the whole drive again (hours on a large archive) for nothing.
$mine = @($acl.Access | Where-Object { -not $_.IsInherited -and $_.IdentityReference -eq $acct })
$hasAllow = $mine | Where-Object { $_.AccessControlType -eq "Allow" -and $_.FileSystemRights -eq ($R::ReadAndExecute -bor $R::Synchronize) -and $_.InheritanceFlags -eq $inherit }
$hasDeny  = $mine | Where-Object { $_.AccessControlType -eq "Deny" -and $_.FileSystemRights -eq $deny -and $_.InheritanceFlags -eq $inherit }
if (-not $Force -and $hasAllow -and $hasDeny -and $mine.Count -eq 2) {
    Write-Host "Already read-only for ${ServiceUser}: $Path (skipped; use -Force to re-apply)" -ForegroundColor Green
    return
}
Write-Host "Granting $acct read-only on $Path (Windows applies it to every file; a full drive takes a while)..."
# drop any explicit entries for the account from earlier runs (incl. the broken icacls deny)
foreach ($ace in @($acl.Access | Where-Object { -not $_.IsInherited -and $_.IdentityReference -eq $acct })) {
    [void]$acl.RemoveAccessRuleSpecific($ace)
}
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($acct, $R::ReadAndExecute, $inherit, $prop, "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($acct, $deny, $inherit, $prop, "Deny")))
Set-Acl -LiteralPath $Path -AclObject $acl
Write-Host "Done: $ServiceUser can read but not change $Path" -ForegroundColor Green
