param(
  [switch]$UseMsi
)

function Ensure-Elevated {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal $id
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"$PSCommandPath")
    if ($UseMsi) { $args += '-UseMsi' }
    Write-Host 'Elevating with UAC prompt...'
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args | Out-Null
    exit
  }
}

Ensure-Elevated
$ErrorActionPreference = 'Stop'

function Get-RepoRoot {
  $scriptDir = Split-Path -Parent $PSCommandPath
  return (Resolve-Path (Join-Path $scriptDir '..'))
}

function Install-With-NSIS {
  param($exe)
  if (-not (Test-Path $exe)) { throw "NSIS setup not found: $exe" }
  Write-Host "Running NSIS setup: $exe"
  $p = Start-Process -FilePath $exe -ArgumentList '/S' -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "NSIS installer exit code $($p.ExitCode)" }
}

function Get-InstalledMsiProductCode {
  # Look up by DisplayName
  $paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  foreach ($path in $paths) {
    if (Test-Path $path) {
      Get-ChildItem $path | ForEach-Object {
        try {
          $dn = (Get-ItemProperty $_.PSPath -ErrorAction Stop).DisplayName
          if ($dn -eq 'home-lab') {
            $us = (Get-ItemProperty $_.PSPath).UninstallString
            if ($us -match '\{[0-9A-Fa-f-]{36}\}') { return $Matches[0] }
          }
        } catch {}
      }
    }
  }
  return $null
}

function Uninstall-MSI-IfPresent {
  $code = Get-InstalledMsiProductCode
  if ($null -ne $code) {
    Write-Host "Uninstalling existing MSI product $code ..."
    $p = Start-Process msiexec.exe -ArgumentList "/x $code /passive /norestart" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Uninstall failed with exit $($p.ExitCode)" }
  }
}

function Install-With-MSI {
  param($msi)
  if (-not (Test-Path $msi)) { throw "MSI not found: $msi" }
  # Try normal install; if product already present with same version, force reinstall
  Write-Host "Installing MSI: $msi"
  $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /passive /norestart" -Wait -PassThru
  if ($p.ExitCode -ne 0) {
    Write-Warning "msiexec returned $($p.ExitCode); retrying with REINSTALL=ALL"
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" REINSTALL=ALL REINSTALLMODE=amus /passive /norestart" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "MSI install failed with exit $($p.ExitCode)" }
  }
}

function Ensure-Service {
  param(
    [string]$Name,
    [string]$Exe,
    [string]$Args
  )
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if (-not $svc) {
    if (-not (Test-Path $Exe)) { throw "Service binary not found: $Exe" }
    Write-Host "Installing service $Name via: $Exe $Args"
    & $Exe $Args | Write-Host
  }
  try {
    Start-Service -Name $Name -ErrorAction Stop
  } catch {
    Write-Warning "Start-Service $Name failed: $($_.Exception.Message)"
  }
}

$root = Get-RepoRoot
$nsis = Join-Path $root 'target\release\bundle\nsis\home-lab_0.1.0_x64-setup.exe'
$msi  = Join-Path $root 'target\release\bundle\msi\home-lab_0.1.0_x64_en-US.msi'

if ($UseMsi) {
  Uninstall-MSI-IfPresent
  Install-With-MSI $msi
} else {
  Install-With-NSIS $nsis
}

# Ensure services are present and running
$bin = 'C:\Program Files\home-lab\bin'
Ensure-Service -Name 'HomeDnsService'  -Exe (Join-Path $bin 'home-dns.exe')  -Args 'install'
Ensure-Service -Name 'HomeHttpService' -Exe (Join-Path $bin 'home-http.exe') -Args 'install'
Ensure-Service -Name 'HomeOidcService' -Exe (Join-Path $bin 'home-oidc.exe') -Args 'install'

Write-Host "--- Service status ---"
Get-Service -Name HomeDnsService, HomeHttpService, HomeOidcService -ErrorAction SilentlyContinue |
  Select-Object Name, Status, StartType | Format-Table -AutoSize

Write-Host "--- Recent logs ---"
if (Test-Path 'C:\ProgramData\home-dns\logs\home-dns_rCURRENT.log') {
  Write-Host '[home-dns]'; Get-Content 'C:\ProgramData\home-dns\logs\home-dns_rCURRENT.log' -Tail 20
}
if (Test-Path 'C:\ProgramData\home-http\logs\home-http_rCURRENT.log') {
  Write-Host '[home-http]'; Get-Content 'C:\ProgramData\home-http\logs\home-http_rCURRENT.log' -Tail 20
}
if (Test-Path 'C:\ProgramData\home-oidc\oidc\logs\home-oidc_rCURRENT.log') {
  Write-Host '[home-oidc]'; Get-Content 'C:\ProgramData\home-oidc\oidc\logs\home-oidc_rCURRENT.log' -Tail 20
}

Write-Host "Done."

