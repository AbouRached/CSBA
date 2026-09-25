# Makes TeleVault + its Cloudflare Tunnel start at boot, hardened per ADR-0001.
# Run ONCE from an ELEVATED PowerShell in the televault folder:
#   Set-ExecutionPolicy -Scope Process Bypass; .\scripts\install-boot.ps1
#
# What it does:
#   1. creates the local account "televault-svc" (random password, never shown, not an admin)
#   2. gives it: Read & Execute on the app + Python, Modify on data\ only, and READ-ONLY
#      (write/delete denied) on every customer folder in the database
#   3. runs TeleVault as that account at startup (not SYSTEM), restarting on failure
#   4. registers the "TeleVault" Windows Event Log source (audit mirror)
#   5. nightly backup at 02:00 to C:\TeleVaultBackups (admins only)
#   6. removes any inbound firewall rule for 8443 (the app listens on 127.0.0.1 only)
#   7. installs cloudflared as a Windows service with the tunnel config
param(
    [string]$SourceUser = $env:USERNAME,
    [string]$ServiceUser = "televault-svc",
    [string]$BackupDir = "C:\TeleVaultBackups"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = "$root\.venv\Scripts\python.exe"
$acct = "$env:COMPUTERNAME\$ServiceUser"

# 1. Service account. A fresh random password is set on every run and handed straight to
#    Task Scheduler (step 3); it is never displayed or written anywhere else.
Add-Type -AssemblyName System.Web
$plainPw = [System.Web.Security.Membership]::GeneratePassword(32, 6)
$pw = ConvertTo-SecureString $plainPw -AsPlainText -Force
if (-not (Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $ServiceUser -Password $pw -PasswordNeverExpires -UserMayNotChangePassword `
        -AccountNeverExpires -Description "TeleVault service (read-only on recordings)" -ErrorAction Stop | Out-Null
    Write-Host "Created local account $ServiceUser"
} else {
    Set-LocalUser -Name $ServiceUser -Password $pw -ErrorAction Stop
    Write-Host "Local account $ServiceUser exists; password rotated"
}

# 1b. Logon rights: allowed to run as a batch job (the scheduled task), never to log on
#     interactively or over Remote Desktop. Set explicitly - Task Scheduler does not always.
$sid = (Get-LocalUser -Name $ServiceUser).SID.Value
$inf = Join-Path $env:TEMP "televault-rights.inf"
$sdb = Join-Path $env:TEMP "televault-rights.sdb"
secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
$lines = [System.Collections.Generic.List[string]](Get-Content $inf)
foreach ($right in "SeBatchLogonRight", "SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight") {
    $i = $lines.FindIndex([Predicate[string]]{ param($l) $l -like "$right *" })
    if ($i -ge 0) { if ($lines[$i] -notlike "*$sid*") { $lines[$i] = "$($lines[$i]),*$sid" } }
    else {
        $sec = $lines.FindIndex([Predicate[string]]{ param($l) $l -eq "[Privilege Rights]" })
        if ($sec -lt 0) { $lines.Add("[Privilege Rights]"); $sec = $lines.Count - 1 }
        $lines.Insert($sec + 1, "$right = *$sid")
    }
}
$lines | Set-Content -Encoding Unicode $inf
secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
Remove-Item $inf, $sdb -Force -ErrorAction SilentlyContinue
Write-Host "Logon rights set: batch job allowed; interactive and RDP logon denied for $ServiceUser"

# 2. File-system rights
$pyHome = ((Get-Content "$root\.venv\pyvenv.cfg" | Where-Object { $_ -like "home*" }) -split "=", 2)[1].Trim()
icacls $root /grant "${acct}:(OI)(CI)RX" /C /Q | Out-Null
icacls $pyHome /grant "${acct}:(OI)(CI)RX" /C /Q | Out-Null
icacls "$root\data" /grant "${acct}:(OI)(CI)M" /C /Q | Out-Null
$roots = & $py -c "import sqlite3; from televault.config import load_config; c=sqlite3.connect(str(load_config().db_path)); print('\n'.join(r[0] for r in c.execute('select root_path from customers')))"
foreach ($r in $roots) { if ($r -and (Test-Path $r)) { & "$PSScriptRoot\grant-drive.ps1" -Path $r -ServiceUser $ServiceUser } }

# 3. TeleVault task as the service account
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$root\scripts\run.ps1`"" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
# Password logon (not S4U): Task Scheduler stores the credential and grants the account
# "Log on as a batch job" itself; S4U fails with Access denied when that right is missing.
Unregister-ScheduledTask -TaskName "TeleVault" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "TeleVault" -Action $action -Trigger $trigger -Settings $settings `
    -User $acct -Password $plainPw -RunLevel Limited `
    -Description "TeleVault call recording archive portal" -ErrorAction Stop | Out-Null
$plainPw = $null
Write-Host "Scheduled Task 'TeleVault' registered (runs as $ServiceUser)."

# 4. Event Log source for the audit mirror
if (-not [System.Diagnostics.EventLog]::SourceExists("TeleVault")) {
    New-EventLog -LogName Application -Source TeleVault
    Write-Host "Event Log source 'TeleVault' registered (Application log)."
}

# 5. Nightly backup, folder readable by admins/SYSTEM only
New-Item -ItemType Directory -Force $BackupDir | Out-Null
icacls $BackupDir /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" /Q | Out-Null
$bAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$root\scripts\backup.ps1`" -Dest `"$BackupDir`"" -WorkingDirectory $root
$bTrigger = New-ScheduledTaskTrigger -Daily -At 2am
$bPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Unregister-ScheduledTask -TaskName "TeleVault Backup" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "TeleVault Backup" -Action $bAction -Trigger $bTrigger -Principal $bPrincipal -Description "Nightly TeleVault backup" -ErrorAction Stop | Out-Null
Write-Host "Nightly backup task registered -> $BackupDir"

# 5b. Grant worker: applies "Grant read-only access" requests from the Customers page.
#     SYSTEM, every minute; it re-checks every path itself (see grant-worker.ps1).
$gAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$root\scripts\grant-worker.ps1`"" -WorkingDirectory $root
$gTriggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1))
)
$gSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 6) -MultipleInstances IgnoreNew -StartWhenAvailable
Unregister-ScheduledTask -TaskName "TeleVault Grant Worker" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "TeleVault Grant Worker" -Action $gAction -Trigger $gTriggers -Settings $gSettings -Principal $bPrincipal `
    -Description "Applies read-only folder access requested in TeleVault's admin UI" -ErrorAction Stop | Out-Null
Write-Host "Grant worker task registered (every minute, SYSTEM)"

# 6. No inbound port: the tunnel is the only way in
Get-NetFirewallRule -DisplayName "TeleVault HTTPS" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
# One pass over the application filters (fast), then only the matching rules.
Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object { $_.Program -like "*televault*python*" } |
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq "Inbound" } |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

# 7. cloudflared service (runs as LocalSystem from the system profile copy of the config)
$cf = "${env:ProgramFiles(x86)}\cloudflared\cloudflared.exe"
if (-not (Test-Path $cf)) { $cf = (Get-Command cloudflared).Source }
$src = "C:\Users\$SourceUser\.cloudflared"
$dst = "$env:WINDIR\System32\config\systemprofile\.cloudflared"
New-Item -ItemType Directory -Force $dst | Out-Null
Copy-Item "$src\*.json", "$src\cert.pem" $dst -Force
# Written without a BOM: PowerShell 5.1's "-Encoding utf8" adds one, which the YAML reader rejects.
$yml = ((Get-Content "$src\config.yml" -Raw) -replace [regex]::Escape($src), $dst)
[IO.File]::WriteAllText("$dst\config.yml", $yml, (New-Object Text.UTF8Encoding $false))
if (-not (Get-Service cloudflared -ErrorAction SilentlyContinue)) { & $cf service install }
if (-not (Get-Service cloudflared -ErrorAction SilentlyContinue)) { throw "cloudflared service was not created." }
Stop-Service cloudflared -Force -ErrorAction SilentlyContinue
# "service install" registers the bare exe with no arguments, which exits at once (the crash
# loop seen in the System log). Point the service at the config and tell it to run the tunnel.
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Cloudflared" -Name ImagePath `
    -Value "`"$cf`" --config `"$dst\config.yml`" tunnel run" -ErrorAction Stop
Set-Service cloudflared -StartupType Automatic
& $cf --config "$dst\config.yml" tunnel ingress validate
if ($LASTEXITCODE -ne 0) { throw "Tunnel config in $dst is not valid." }
Write-Host "cloudflared service installed."

# 8. Hand over from any copies started by hand or from another folder, start the real ones, and check.
Stop-ScheduledTask -TaskName "TeleVault" -ErrorAction SilentlyContinue
# run.ps1 is a restart loop: stop the loops themselves (any install folder), not only the server they start
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match '\\scripts\\run\.ps1' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Get-NetTCPConnection -LocalPort 8443 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep 2
Get-Process cloudflared -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -ne 0 } |
    Stop-Process -Force -ErrorAction SilentlyContinue
# Failures here are reported in the Result section instead of aborting before it.
try { Start-ScheduledTask -TaskName "TeleVault" -ErrorAction Stop } catch { Write-Host "Start TeleVault task: $_" -ForegroundColor Red }
try { Start-Service cloudflared -ErrorAction Stop } catch { Write-Host "Start cloudflared: $_" -ForegroundColor Red }
foreach ($i in 1..20) {
    Start-Sleep 2
    if (Get-NetTCPConnection -LocalPort 8443 -State Listen -ErrorAction SilentlyContinue) { break }
}
Write-Host ""
Write-Host "== Result" -ForegroundColor Cyan
Get-ScheduledTask -TaskName "TeleVault*" | ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo
    "{0,-18} {1,-8} runs as {2,-28} last result 0x{3:X}" -f $_.TaskName, $_.State, $_.Principal.UserId, $info.LastTaskResult }
Get-Service cloudflared | ForEach-Object { "{0,-18} {1,-8} start {2}" -f $_.Name, $_.Status, $_.StartType }
if (Get-NetTCPConnection -LocalPort 8443 -State Listen -ErrorAction SilentlyContinue) {
    $owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$((Get-NetTCPConnection -LocalPort 8443 -State Listen)[0].OwningProcess)" |
        Invoke-CimMethod -MethodName GetOwner).User
    Write-Host "TeleVault listening on 127.0.0.1:8443 as $owner" -ForegroundColor Green
} else {
    Write-Host "TeleVault is NOT listening yet - check $root\data\televault.log" -ForegroundColor Red
    if (Test-Path "$root\data\televault.log") { Get-Content "$root\data\televault.log" -Tail 15 }
}
Get-WinEvent -LogName System -MaxEvents 30 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -eq "Service Control Manager" -and $_.Message -match "Cloudflared" -and $_.TimeCreated -gt (Get-Date).AddMinutes(-2) } |
    Select-Object -First 2 | ForEach-Object { Write-Host "SCM: $($_.Message)" -ForegroundColor Yellow }
Write-Host "New customer drive later?  .\scripts\grant-drive.ps1 -Path <drive-or-folder>"
