# TeleVault PBX Pull - run by the "TeleVault PBX Pull" tasks (SYSTEM). COPY ONLY:
# fetches new recordings from each PBX (read-only SFTP key) into the customer's archive folder.
# By hand, from an elevated PowerShell in the TeleVault folder:
#   .\scripts\pbx-pull.ps1 -DryRun                 # only report what would be copied
#   .\scripts\pbx-pull.ps1 -Source acme-pbx        # one PBX
#   .\scripts\pbx-pull.ps1 -RecentDays 2           # only today's and yesterday's folders
param(
    [string]$Source = "",
    [double]$MaxHours = 0,
    [int]$RecentDays = 0,
    [switch]$DryRun,
    [switch]$Tick       # what the scheduled task runs: follow the PBX pull admin page
)
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:PYTHONPATH = $root
$py = "$root\.venv\Scripts\python.exe"
$a = @("-m", "televault.cli", "pbx-pull")
if ($Tick) { $a += "tick" }
if ($Source) { $a += @("--source", $Source) }
if ($MaxHours -gt 0) { $a += @("--max-hours", "$MaxHours") }
if ($RecentDays -gt 0) { $a += @("--recent-days", "$RecentDays") }
if ($DryRun) { $a += "--dry-run" }
& $py @a
exit $LASTEXITCODE
