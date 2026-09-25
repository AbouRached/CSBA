# Starts TeleVault and keeps it running (used by the Scheduled Task; also fine by hand).
# If the server exits for any reason it is started again after 10 s - Task Scheduler's own
# "restart on failure" only covers a task that fails to launch, not one that exits later.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
[Environment]::CurrentDirectory = $root
# Import the package from this folder explicitly; under the service account the implicit
# "current directory" entry was not enough (ModuleNotFoundError: televault).
$env:PYTHONPATH = $root
$env:PYTHONIOENCODING = "utf-8"
New-Item -ItemType Directory -Force "$root\data" | Out-Null
$log = "$root\data\televault.log"
$py = "$root\.venv\Scripts\python.exe"

function Write-Log([string]$msg) {
    [IO.File]::AppendAllText($log, "$(Get-Date -Format s) $msg`r`n", (New-Object Text.UTF8Encoding $false))
}

while ($true) {
    # keep the log bounded (~20 MB)
    if ((Test-Path $log) -and ((Get-Item $log).Length -gt 20MB)) { Move-Item -Force $log "$log.1" }
    Write-Log "starting as $env:USERDOMAIN\$env:USERNAME in $root"
    # cmd does the redirection so Python's UTF-8 output lands in the log byte-for-byte
    # (PowerShell 5.1's *>> would re-encode it as UTF-16 and mix encodings in one file).
    cmd.exe /d /c "`"$py`" -m televault.cli serve >> `"$log`" 2>&1"
    Write-Log "server exited with code $LASTEXITCODE; restarting in 10 s"
    Start-Sleep -Seconds 10
}
