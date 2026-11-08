# LinkHelm-exp read-only egress comparison (architecture review §3).
# Does NOT change routes, DNS, firewall or registry. Just prints 5 samples of
# the phone's explicit SOCKS5 egress vs Windows' transparent egress.
#
#   powershell -ExecutionPolicy Bypass -File egress_compare.ps1 `
#       -PhoneIp 192.168.49.1 -Port 8080 -User u -Pass p
param(
    [string]$PhoneIp = "192.168.49.1",
    [int]$Port = 8080,
    [string]$User = "",
    [string]$Pass = ""
)
$ErrorActionPreference = "Continue"
$url = "https://api.ipify.org"
$n = 5

Write-Output "=== A. explicit phone SOCKS5 egress ==="
$cred = if ($User -ne "" -or $Pass -ne "") { "--proxy-user `"${User}:${Pass}`"" } else { "" }
for ($i = 1; $i -le $n; $i++) {
    $expr = "curl.exe -4 -s --max-time 12 --socks5-hostname ${PhoneIp}:${Port} $cred $url"
    $out = (& cmd /c $expr 2>&1 | Out-String).Trim()
    Write-Output ("  A{0}: {1}" -f $i, $out)
}

Write-Output "=== B. Windows transparent egress (no explicit proxy) ==="
for ($i = 1; $i -le $n; $i++) {
    $out = (& curl.exe -4 -s --max-time 12 --noproxy "*" $url 2>&1 | Out-String).Trim()
    Write-Output ("  B{0}: {1}" -f $i, $out)
}

Write-Output "=== interpretation ==="
Write-Output "  A stable, B flapping  -> traffic bypasses the engine / multi-uplink"
Write-Output "  A+B change together   -> phone cellular CGNAT rotation, not Windows"
Write-Output "  A ok, B fails         -> capture / TCP reflection / DNS path"
Write-Output "  B != A always         -> another native uplink still in use"

Write-Output "=== route snapshot (read only) ==="
Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in @("0.0.0.0/0","0.0.0.0/1","128.0.0.0/1") } |
    Format-Table DestinationPrefix, ifIndex, NextHop, RouteMetric -AutoSize
Get-NetAdapter | Format-Table Name, Status, ifIndex -AutoSize
