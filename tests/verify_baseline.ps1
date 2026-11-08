# LinkHelm EXP beta0.1.4 - read-only baseline verification (plan section 8 A).
# Run in an ELEVATED PowerShell BEFORE starting EXP. This script ONLY reads
# configuration: it never changes adapters, routes, DNS or firewall rules.
$ErrorActionPreference = 'Continue'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$p  = New-Object Security.Principal.WindowsPrincipal($id)
"ADMIN: " + $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

"--- adapters ---"
Get-NetAdapter | Format-Table Name, Status, ifIndex -AutoSize | Out-String

"--- IPv4 configuration ---"
Get-NetIPConfiguration -AddressFamily IPv4 |
    Format-List InterfaceAlias, IPv4Address, IPv4DefaultGateway | Out-String

"--- default routes ---"
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Format-Table ifIndex, InterfaceAlias, NextHop, RouteMetric -AutoSize | Out-String

"--- half-route residue (must be EMPTY) ---"
Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1', '128.0.0.0/1') } |
    Format-Table DestinationPrefix, InterfaceAlias, NextHop -AutoSize | Out-String

"--- route selection ---"
Find-NetRoute -RemoteIPAddress 1.1.1.1 | Format-Table -AutoSize | Out-String
Find-NetRoute -RemoteIPAddress 192.168.49.1 | Format-Table -AutoSize | Out-String

"--- legacy virtual adapter (clean EXP baseline should show none) ---"
Get-NetAdapter | Where-Object { $_.Name -match 'IwIP|Wintun|LinkHelm' } |
    Format-Table Name, Status, ifIndex -AutoSize | Out-String
