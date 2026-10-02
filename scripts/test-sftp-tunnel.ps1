# End-to-end check of the SFTP feed through Cloudflare (ADR-0001 #18), from this PC:
#   Cloudflare Access (service token) -> tunnel -> TeleVault SFTP on 127.0.0.1:<port>.
# It only reads the server's SSH greeting, so no feed account or SSH key is needed.
# Run from an ELEVATED PowerShell (it may add a temporary hosts-file line when the office DNS
# does not know the public hostname; the line is removed again at the end):
#   Set-ExecutionPolicy -Scope Process Bypass; .\scripts\test-sftp-tunnel.ps1
# You type the service token's Client ID and Secret at the prompts; they are passed to
# cloudflared through environment variables of this window only and never written to disk.
param(
    [string]$Hostname = "",
    [int]$LocalPort = 2299
)
$ErrorActionPreference = "Stop"
if (-not $Hostname) {
    try { $Hostname = (Get-Content "C:\TeleVault\config.json" -Raw | ConvertFrom-Json).sftp_public_host } catch {}
}
if (-not $Hostname) { throw "Pass -Hostname sftp.example.com" }
$cf = "${env:ProgramFiles(x86)}\cloudflared\cloudflared.exe"
if (-not (Test-Path $cf)) { $cf = (Get-Command cloudflared).Source }
$hosts = "$env:WINDIR\System32\drivers\etc\hosts"
$marker = "# televault-sftp-test"
$added = $false
$proc = $null

function Show([string]$text, [bool]$ok) { Write-Host $text -ForegroundColor $(if ($ok) { "Green" } else { "Red" }) }

try {
    # 1. Public DNS. The office DNS server may hold its own copy of the zone without this name.
    $public = @(Resolve-DnsName $Hostname -Server 1.1.1.1 -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
    if (-not $public) { throw "$Hostname has no public A record (Cloudflare DNS)." }
    Show "Public DNS: $Hostname -> $($public -join ', ')" $true
    $local = $null
    try { $local = Resolve-DnsName $Hostname -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } } catch {}
    if (-not $local) {
        Add-Content $hosts "`r`n$($public[0]) $Hostname $marker" -Encoding ASCII
        $added = $true
        Write-Host "Office DNS does not know $Hostname - temporary hosts entry added for this test."
    }

    # 2. Without a token Cloudflare Access must refuse
    $code = try { (Invoke-WebRequest "https://$Hostname/" -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop).StatusCode } catch { [int]$_.Exception.Response.StatusCode }
    Show "Without token: HTTP $code (expected 403)" ($code -eq 403)

    # 3. With the service token: open a local listener through Cloudflare and read the SSH greeting
    $env:TUNNEL_SERVICE_TOKEN_ID = Read-Host "Service token Client ID (ends with .access)"
    $sec = Read-Host "Service token Client Secret" -AsSecureString
    $env:TUNNEL_SERVICE_TOKEN_SECRET = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
    $proc = Start-Process $cf -ArgumentList "access", "tcp", "--hostname", $Hostname, "--url", "127.0.0.1:$LocalPort" -PassThru -WindowStyle Hidden
    Start-Sleep 3
    $banner = $null
    foreach ($i in 1..10) {
        try {
            $c = New-Object Net.Sockets.TcpClient("127.0.0.1", $LocalPort)
            $c.ReceiveTimeout = 8000
            $buf = New-Object byte[] 64
            $n = $c.GetStream().Read($buf, 0, 64)
            $c.Close()
            if ($n -gt 0) { $banner = [Text.Encoding]::ASCII.GetString($buf, 0, $n).Trim(); break }
        } catch { Start-Sleep 1 }
    }
    if ($banner -like "SSH-2.0-*") {
        Show "With token: reached the TeleVault SFTP server through Cloudflare ($banner)" $true
        Show "PASS - Cloudflare Access, the tunnel and the SFTP server all work. The vendor can connect." $true
    } else {
        Show "With token: no SSH greeting (got: '$banner')." $false
        Write-Host "Check: token matches the Access policy (Service Auth), TeleVault SFTP feeds page shows the server listening, cloudflared service running."
    }
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item Env:TUNNEL_SERVICE_TOKEN_ID, Env:TUNNEL_SERVICE_TOKEN_SECRET -ErrorAction SilentlyContinue
    if ($added) {
        $keep = Get-Content $hosts | Where-Object { $_ -notmatch [regex]::Escape($marker) }
        Set-Content $hosts $keep -Encoding ASCII
        Write-Host "Temporary hosts entry removed."
    }
}
