<#
.SYNOPSIS
  Post-reboot one-shot: rebuild (optional), relink MSI with service actions, install, enable + start services, and show logs.

.USAGE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\after-reboot-setup.ps1 [-SkipBuild]
#>
param(
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

function Ensure-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal $id
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Please run this script as Administrator.' -ForegroundColor Yellow
    exit 1
  }
}

Ensure-Elevated

Write-Host '=== Post-reboot: (re)build + relink + install + verify ==='
if (-not $SkipBuild) {
  & (Join-Path $PSScriptRoot 'tauri-msi-relink.ps1') -Build -Relink -Install -Verify
} else {
  & (Join-Path $PSScriptRoot 'tauri-msi-relink.ps1') -Relink -Install -Verify
}

# Make sure services are Auto and started
Write-Host '=== Enable + start services (best-effort) ==='
foreach ($n in 'HomeDnsService','HomeHttpService','HomeOidcService') {
  try { sc.exe config $n start= auto | Out-Null } catch {}
  try { sc.exe start  $n          | Out-Null } catch {}
}

Start-Sleep -Seconds 2
Get-Service HomeDnsService, HomeHttpService, HomeOidcService -ErrorAction SilentlyContinue |
  Select Name,Status,StartType | Format-Table -AutoSize | Out-String | Write-Host

# Tail logs for DNS
$dnsLog = 'C:\ProgramData\home-dns\logs\home-dns_rCURRENT.log'
if (Test-Path $dnsLog) {
  Write-Host '--- tail home-dns_rCURRENT.log ---'
  Get-Content $dnsLog -Tail 120 | ForEach-Object { $_ }
} else {
  Write-Host "Log file not found: $dnsLog"
}

$httpLog = 'C:\ProgramData\home-http\logs\home-http_rCURRENT.log'
if (Test-Path $httpLog) {
  Write-Host '--- tail home-http_rCURRENT.log ---'
  Get-Content $httpLog -Tail 120 | ForEach-Object { $_ }
} else {
  Write-Host "Log file not found: $httpLog"
}

$oidcLog = 'C:\ProgramData\home-oidc\oidc\logs\home-oidc_rCURRENT.log'
if (Test-Path $oidcLog) {
  Write-Host '--- tail home-oidc_rCURRENT.log ---'
  Get-Content $oidcLog -Tail 120 | ForEach-Object { $_ }
} else {
  Write-Host "Log file not found: $oidcLog"
}

Write-Host 'Done.'

